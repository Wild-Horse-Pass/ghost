//! `wraithd` — Wraith Wallet daemon.
//!
//! Long-running process that holds module state and exposes a local IPC surface
//! to the CLI and GUI. Phase 0 (closed): IPC + lifecycle + multi-wallet keystore.
//! Phase 1 (in progress): chain (REST → ghost-pay), gsp (WebSocket → ghost-gsp).
//!
//! Wallet layout: `~/.wraith/wallets/<name>/keystore.bin`. The "active" wallet is
//! tracked in memory only — it is set on `WalletCreate`, `WalletUnlock`, or
//! `WalletSelect`, and lost when the daemon restarts. Wallet-scoped commands
//! (`WalletDerive`, `WalletAuthInfo`, `LightReceive`) target the active wallet.

#[cfg(not(unix))]
fn main() {
    eprintln!("wraithd: only Unix-like platforms are supported in phase 0");
    std::process::exit(1);
}

#[cfg(unix)]
fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(unix::serve())
}

#[cfg(unix)]
mod unix {
    use std::collections::HashMap;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Instant;

    use secrecy::SecretString;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::RwLock;
    use wraith_wallet_core::auth;
    use wraith_wallet_core::chain::{ChainClient, GhostPayClient};
    use wraith_wallet_core::gsp::GspClient;
    use wraith_wallet_core::keystore::{Keystore, KeystoreError};
    use wraith_wallet_core::light;
    use ghost_gsp_proto::{PaymentMode, SessionToken};
    use wraith_wallet_core::gsp::{
        spawn_session, GspError, SessionHandle, SessionPhase, SessionStatus,
    };
    use wraith_wallet_ipc::{
        default_socket_path, ChainStatusResponse, Envelope, ErrorResponse, GspAuthResponse,
        GspPingResponse, GspSessionStatusResponse, HealthResponse, LightBalanceResponse,
        LightHistoryEntry, LightHistoryResponse, LightReceiveResponse, LightSentResponse,
        LightUtxoEntry, LightUtxosResponse, LockEntry, LocksConfirmedResponse, LocksJumpedResponse,
        LocksListResponse, LocksPreparedResponse, Request, Response, WalletAuthInfoResponse,
        WalletCreateResponse, WalletDeriveResponse, WalletListEntry, WalletListResponse,
        WalletShowMnemonicResponse, WalletStatusResponse,
    };

    const DEFAULT_GHOST_PAY: &str = "http://127.0.0.1:8800";
    const DEFAULT_GSP: &str = "ws://127.0.0.1:8900/ws/v1";
    const GHOST_PAY_ENV: &str = "WRAITHD_GHOST_PAY";
    const GSP_ENV: &str = "WRAITHD_GSP";
    const WALLETS_DIR_ENV: &str = "WRAITHD_WALLETS_DIR";
    const NETWORK_ENV: &str = "WRAITHD_NETWORK";

    /// A `SessionToken` paired with the wallet name that produced it AND a live
    /// `SessionHandle` running the persistent authenticated WebSocket. Dropping
    /// the `StoredSession` aborts the session task (via `SessionHandle::Drop`).
    struct StoredSession {
        wallet_name: String,
        token: SessionToken,
        handle: SessionHandle,
    }

    struct DaemonState {
        started: Instant,
        chain: Arc<dyn ChainClient>,
        gsp: GspClient,
        /// GSP WS URLs in failover order — passed to spawn_session at gsp_auth time.
        gsp_urls: Vec<String>,
        wallets_dir: PathBuf,
        wallets: RwLock<HashMap<String, Keystore>>,
        active: RwLock<Option<String>>,
        session: RwLock<Option<StoredSession>>,
        network: bitcoin::Network,
    }

    fn default_wallets_dir() -> PathBuf {
        if let Ok(p) = std::env::var(WALLETS_DIR_ENV) {
            return PathBuf::from(p);
        }
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        home.join(".wraith").join("wallets")
    }

    fn parse_network(s: &str) -> Option<bitcoin::Network> {
        match s.trim().to_ascii_lowercase().as_str() {
            "mainnet" | "bitcoin" => Some(bitcoin::Network::Bitcoin),
            "testnet" => Some(bitcoin::Network::Testnet),
            "signet" => Some(bitcoin::Network::Signet),
            "regtest" => Some(bitcoin::Network::Regtest),
            _ => None,
        }
    }

    /// Reject names that would let a caller traverse outside `wallets_dir` or
    /// produce ambiguous on-disk paths.
    fn validate_wallet_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("wallet name must not be empty".into());
        }
        if name.len() > 64 {
            return Err("wallet name too long (max 64 chars)".into());
        }
        let allowed = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
        if !name.chars().all(allowed) {
            return Err(
                "wallet name must be ascii alphanumeric, '-', or '_' only".into(),
            );
        }
        Ok(())
    }

    fn keystore_path(wallets_dir: &Path, name: &str) -> PathBuf {
        wallets_dir.join(name).join("keystore.bin")
    }

    /// Enumerate every directory under `wallets_dir` that contains a `keystore.bin`.
    fn list_on_disk(wallets_dir: &Path) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(wallets_dir) else {
            return Vec::new();
        };
        let mut names = Vec::new();
        for entry in entries.flatten() {
            let name = match entry.file_name().into_string() {
                Ok(n) => n,
                Err(_) => continue,
            };
            if validate_wallet_name(&name).is_err() {
                continue;
            }
            if keystore_path(wallets_dir, &name).is_file() {
                names.push(name);
            }
        }
        names.sort();
        names
    }

    pub async fn serve() -> std::io::Result<()> {
        let socket_path = default_socket_path();
        // Both env vars accept a comma-separated list of URLs. Endpoints are tried
        // in order; failover is sticky-during-outage but resets to primary on success.
        let ghost_pay_raw =
            std::env::var(GHOST_PAY_ENV).unwrap_or_else(|_| DEFAULT_GHOST_PAY.to_string());
        let ghost_pay_urls = wraith_wallet_core::chain::GhostPayClient::parse_urls(&ghost_pay_raw);
        let gsp_raw = std::env::var(GSP_ENV).unwrap_or_else(|_| DEFAULT_GSP.to_string());
        let gsp_urls = wraith_wallet_core::gsp::GspClient::parse_urls(&gsp_raw);
        let wallets_dir = default_wallets_dir();
        let network = std::env::var(NETWORK_ENV)
            .ok()
            .and_then(|s| parse_network(&s))
            .unwrap_or(bitcoin::Network::Signet);
        tracing::info!(
            ghost_pay = ?ghost_pay_urls,
            gsp = ?gsp_urls,
            wallets_dir = %wallets_dir.display(),
            network = ?network,
            "node endpoints + wallets dir + network configured",
        );

        let state = Arc::new(DaemonState {
            started: Instant::now(),
            chain: Arc::new(GhostPayClient::with_urls(ghost_pay_urls)),
            gsp: GspClient::with_urls(gsp_urls.clone()),
            gsp_urls,
            wallets_dir,
            wallets: RwLock::new(HashMap::new()),
            active: RwLock::new(None),
            session: RwLock::new(None),
            network,
        });

        if socket_path.exists() {
            tracing::warn!(
                path = %socket_path.display(),
                "stale socket file present, removing"
            );
            fs::remove_file(&socket_path)?;
        }
        if let Some(parent) = socket_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        tracing::info!(path = %socket_path.display(), "wraithd listening");

        // Watch for SIGTERM / SIGINT (Ctrl-C) so we can drop the listener, kill
        // any active session task, and remove the socket file before exiting.
        let mut sigterm = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        )?;
        let mut sigint = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::interrupt(),
        )?;

        loop {
            tokio::select! {
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, _)) => {
                            let state = Arc::clone(&state);
                            tokio::spawn(handle_connection(stream, state));
                        }
                        Err(e) => {
                            tracing::warn!(?e, "accept failed");
                        }
                    }
                }
                _ = sigterm.recv() => {
                    tracing::info!("SIGTERM received, shutting down");
                    break;
                }
                _ = sigint.recv() => {
                    tracing::info!("SIGINT received, shutting down");
                    break;
                }
            }
        }

        // Drop the active GSP session (SessionHandle::Drop aborts the task).
        *state.session.write().await = None;
        // Wallets clear on drop (zeroized).
        state.wallets.write().await.clear();
        // Remove the socket so the next startup doesn't see a stale file.
        let _ = fs::remove_file(&socket_path);
        tracing::info!("wraithd stopped");
        Ok(())
    }

    async fn handle_connection(stream: UnixStream, state: Arc<DaemonState>) {
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let response = dispatch(&line, &state).await;
            let mut out = match serde_json::to_string(&response) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(?e, "failed to serialise response");
                    continue;
                }
            };
            out.push('\n');
            if let Err(e) = writer.write_all(out.as_bytes()).await {
                tracing::warn!(?e, "client write failed");
                return;
            }
        }
    }

    /// `GspAuth` orchestration: register-if-needed + session. Stores the resulting
    /// `SessionToken` in `state.session` so subsequent commits can use it to open
    /// a persistent authenticated WebSocket.
    async fn gsp_auth(state: &Arc<DaemonState>) -> Result<GspAuthResponse, String> {
        // 1. Get the auth keypair + active wallet name.
        let (active_name, kp) = {
            let active = state
                .active
                .read()
                .await
                .clone()
                .ok_or_else(|| "no active wallet".to_string())?;
            let wallets = state.wallets.read().await;
            let ks = wallets
                .get(&active)
                .ok_or_else(|| format!("active wallet '{active}' is not unlocked"))?;
            let kp = auth::auth_keypair(ks).map_err(|e| format!("auth keypair: {e}"))?;
            (active, kp)
        };
        let wallet_id = auth::wallet_id_hex(&kp);

        // 2. Register (idempotent — treat "already registered" server errors as success).
        let register_proof =
            auth::make_proof(&kp, "register").map_err(|e| format!("register proof: {e}"))?;
        let already_registered = match state.gsp.register(register_proof, None).await {
            Ok(_) => false,
            Err(GspError::Server(msg))
                if msg.to_ascii_lowercase().contains("already") =>
            {
                true
            }
            Err(e) => return Err(format!("register: {e}")),
        };

        // 3. Generate session_nonce + sign session proof + create session.
        use rand::RngCore;
        let mut nonce_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let session_nonce = hex::encode(nonce_bytes);

        let session_proof =
            auth::make_proof(&kp, "session").map_err(|e| format!("session proof: {e}"))?;
        let token = state
            .gsp
            .create_session(session_proof, Some(session_nonce))
            .await
            .map_err(|e| format!("session: {e}"))?;

        let token_prefix: String = token.token.chars().take(12).collect();
        let expires_at = token.expires_at;
        let jwt_for_session = token.token.clone();

        // 4. Stash the token + spawn a persistent authenticated session task.
        //    Replacing an existing slot drops the old SessionHandle, which aborts
        //    its task before the new one starts.
        let handle = spawn_session(state.gsp_urls.clone(), jwt_for_session);
        *state.session.write().await = Some(StoredSession {
            wallet_name: active_name,
            token,
            handle,
        });

        Ok(GspAuthResponse {
            wallet_id,
            already_registered,
            token_prefix,
            expires_at,
        })
    }

    /// Helpers shared by lock operations: pull the auth keypair from the session's wallet.
    /// Used so each lock op binds to the wallet that produced the session token.
    async fn auth_keypair_for_session(
        state: &Arc<DaemonState>,
    ) -> Result<bitcoin::secp256k1::Keypair, String> {
        let session = state.session.read().await;
        let session = session
            .as_ref()
            .ok_or_else(|| "no GSP session — run `wraith gsp auth` first".to_string())?;
        let wallets = state.wallets.read().await;
        let ks = wallets.get(&session.wallet_name).ok_or_else(|| {
            format!(
                "wallet '{}' (the session's wallet) is not unlocked",
                session.wallet_name
            )
        })?;
        wraith_wallet_core::auth::auth_keypair(ks).map_err(|e| format!("auth keypair: {e}"))
    }

    fn parse_jump_priority(s: &str) -> Result<String, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "normal" => Ok("normal".to_string()),
            "high" => Ok("high".to_string()),
            "urgent" => Ok("urgent".to_string()),
            other => Err(format!(
                "unknown jump priority '{other}' (try normal, high, urgent)"
            )),
        }
    }

    fn parse_payment_mode(s: &str) -> Result<PaymentMode, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "ghostpay" | "ghost-pay" | "ghost_pay" => Ok(PaymentMode::GhostPay),
            "wraith" => Ok(PaymentMode::Wraith),
            "confidential" => Ok(PaymentMode::Confidential),
            other => Err(format!(
                "unknown payment mode '{other}' (try ghostpay, wraith, confidential)"
            )),
        }
    }

    /// `LightSend` orchestration: PreparePayment → sign sighash with auth key → SubmitSignedPayment.
    /// Mirrors `ghost-light-wallet::payments::send::sign_and_submit` so wire format matches.
    async fn light_send(
        state: &Arc<DaemonState>,
        recipient: String,
        amount_sats: u64,
        mode_str: String,
        memo: Option<String>,
    ) -> Result<LightSentResponse, String> {
        let mode = parse_payment_mode(&mode_str)?;
        let mode_label = format!("{mode}");

        let session = state.session.read().await;
        let session = session
            .as_ref()
            .ok_or_else(|| "no GSP session — run `wraith gsp auth` first".to_string())?;

        // Get the auth keypair from the active wallet (must match the session's wallet).
        let kp = {
            let wallets = state.wallets.read().await;
            let ks = wallets
                .get(&session.wallet_name)
                .ok_or_else(|| {
                    format!(
                        "wallet '{}' (the session's wallet) is not unlocked",
                        session.wallet_name
                    )
                })?;
            wraith_wallet_core::auth::auth_keypair(ks)
                .map_err(|e| format!("auth keypair: {e}"))?
        };

        // 1. Sign a fresh `prepare_payment` proof.
        let proof = wraith_wallet_core::auth::make_proof(&kp, "prepare_payment")
            .map_err(|e| format!("prepare_payment proof: {e}"))?;

        // 2. PreparePayment over the persistent session.
        let prepared = session
            .handle
            .prepare_payment(recipient.clone(), amount_sats, mode, proof, memo.clone())
            .await
            .map_err(|e| format!("PreparePayment: {e}"))?;

        // 3. Sign the sighash with the auth key + tagged hash "Ghost/Data/v1"
        //    (matches ghost-light-wallet::signing::sign_data).
        let sighash_bytes = prepared
            .sighash_bytes()
            .map_err(|e| format!("decoding sighash hex: {e}"))?;
        let signature = wraith_wallet_core::auth::sign_data(&kp, &sighash_bytes);
        let pubkey = wraith_wallet_core::auth::xonly_pubkey_bytes(&kp);

        // 4. SubmitSignedPayment.
        let result = session
            .handle
            .submit_signed_payment(
                prepared.payment_id.clone(),
                hex::encode(signature),
                hex::encode(pubkey),
            )
            .await
            .map_err(|e| format!("SubmitSignedPayment: {e}"))?;

        Ok(LightSentResponse {
            payment_id: result.payment_id,
            txid: result.txid,
            recipient,
            amount_sats: prepared.amount_sats,
            fee_sats: prepared.fee_sats,
            mode: mode_label,
        })
    }

    fn phase_label(p: SessionPhase) -> &'static str {
        match p {
            SessionPhase::Disconnected => "disconnected",
            SessionPhase::Connecting => "connecting",
            SessionPhase::Authenticating => "authenticating",
            SessionPhase::Authenticated => "authenticated",
            SessionPhase::Backoff => "backoff",
        }
    }

    /// Snapshot the active wallet's name + keystore for read-only use.
    /// Returns Err with a user-friendly message if no wallet is active.
    async fn with_active_wallet<F, R>(state: &DaemonState, f: F) -> Result<R, String>
    where
        F: FnOnce(&str, &Keystore) -> Result<R, String>,
    {
        let active = state
            .active
            .read()
            .await
            .clone()
            .ok_or_else(|| {
                "no active wallet; run `wraith wallet unlock <name>` or \
                 `wraith wallet select <name>` first"
                    .to_string()
            })?;
        let wallets = state.wallets.read().await;
        let ks = wallets
            .get(&active)
            .ok_or_else(|| format!("active wallet '{active}' is not unlocked"))?;
        f(&active, ks)
    }

    async fn dispatch(line: &str, state: &Arc<DaemonState>) -> Envelope<Response> {
        let parsed: Result<Envelope<Request>, _> = serde_json::from_str(line);
        let (id, request) = match parsed {
            Ok(env) => (env.id, env.payload),
            Err(e) => {
                return Envelope::new(
                    0,
                    Response::Error(ErrorResponse {
                        message: format!("malformed request: {e}"),
                    }),
                );
            }
        };

        let response = match request {
            Request::Health => Response::Health(HealthResponse {
                daemon_version: env!("CARGO_PKG_VERSION").to_string(),
                uptime_secs: state.started.elapsed().as_secs(),
            }),
            Request::ChainStatus => match state.chain.status().await {
                Ok(s) => Response::ChainStatus(ChainStatusResponse {
                    backend_version: s.backend_version,
                    network: s.network,
                    has_keys: s.has_keys,
                    lock_count: s.lock_count,
                    active_sessions: s.active_sessions,
                }),
                Err(e) => Response::Error(ErrorResponse {
                    message: format!("chain: {e}"),
                }),
            },
            Request::GspPing => match state.gsp.ping().await {
                Ok(p) => Response::GspPing(GspPingResponse {
                    server_time: p.server_time,
                    round_trip_ms: p.round_trip_ms,
                }),
                Err(e) => Response::Error(ErrorResponse {
                    message: format!("gsp: {e}"),
                }),
            },
            Request::GspAuth => match gsp_auth(state).await {
                Ok(r) => Response::GspAuth(r),
                Err(message) => Response::Error(ErrorResponse { message }),
            },
            Request::GspSessionStatus => {
                let guard = state.session.read().await;
                match guard.as_ref() {
                    Some(s) => {
                        let snap: SessionStatus = s.handle.snapshot().await;
                        Response::GspSessionStatus(GspSessionStatusResponse {
                            have_token: true,
                            wallet_name: Some(s.wallet_name.clone()),
                            wallet_id: Some(s.token.wallet_id.0.clone()),
                            expires_at: Some(s.token.expires_at),
                            remaining_secs: Some(s.token.remaining_secs()),
                            phase: Some(phase_label(snap.phase).to_string()),
                            connect_count: Some(snap.connect_count),
                            last_error: snap.last_error,
                        })
                    }
                    None => Response::GspSessionStatus(GspSessionStatusResponse {
                        have_token: false,
                        wallet_name: None,
                        wallet_id: None,
                        expires_at: None,
                        remaining_secs: None,
                        phase: None,
                        connect_count: None,
                        last_error: None,
                    }),
                }
            }
            Request::LightBalance => {
                let guard = state.session.read().await;
                match guard.as_ref() {
                    None => Response::Error(ErrorResponse {
                        message: "no GSP session — run `wraith gsp auth` first".to_string(),
                    }),
                    Some(s) => {
                        let snap = s.handle.snapshot().await;
                        match snap.last_balance {
                            None => Response::LightBalance(LightBalanceResponse {
                                confirmed_sats: None,
                                unconfirmed_sats: None,
                                locked_sats: None,
                                received_at: None,
                            }),
                            Some(b) => Response::LightBalance(LightBalanceResponse {
                                confirmed_sats: Some(b.confirmed_sats),
                                unconfirmed_sats: Some(b.unconfirmed_sats),
                                locked_sats: Some(b.locked_sats),
                                received_at: Some(b.received_at),
                            }),
                        }
                    }
                }
            }
            Request::LightUtxos { min_confirmations } => {
                let guard = state.session.read().await;
                match guard.as_ref() {
                    None => Response::Error(ErrorResponse {
                        message: "no GSP session — run `wraith gsp auth` first".to_string(),
                    }),
                    Some(s) => match s.handle.get_utxos(min_confirmations).await {
                        Ok(result) => {
                            let utxos = result
                                .utxos
                                .into_iter()
                                .map(|u| LightUtxoEntry {
                                    txid: u.txid,
                                    vout: u.vout,
                                    amount_sats: u.amount_sats,
                                    confirmations: u.confirmations,
                                    script_type: u.script_type,
                                    spendable: u.spendable,
                                })
                                .collect();
                            Response::LightUtxos(LightUtxosResponse {
                                utxos,
                                total_sats: result.total_sats,
                            })
                        }
                        Err(e) => Response::Error(ErrorResponse {
                            message: format!("light utxos: {e}"),
                        }),
                    },
                }
            }
            Request::LightHistory { limit, offset } => {
                let guard = state.session.read().await;
                match guard.as_ref() {
                    None => Response::Error(ErrorResponse {
                        message: "no GSP session — run `wraith gsp auth` first".to_string(),
                    }),
                    Some(s) => match s.handle.get_transactions(limit, offset).await {
                        Ok(result) => {
                            let transactions = result
                                .transactions
                                .into_iter()
                                .map(|t| LightHistoryEntry {
                                    txid: t.txid,
                                    block_height: t.block_height,
                                    timestamp: t.timestamp,
                                    amount_sats: t.amount_sats,
                                    fee_sats: t.fee_sats,
                                    tx_type: t.tx_type,
                                    confirmations: t.confirmations,
                                    memo: t.memo,
                                })
                                .collect();
                            Response::LightHistory(LightHistoryResponse {
                                transactions,
                                total_count: result.total_count,
                            })
                        }
                        Err(e) => Response::Error(ErrorResponse {
                            message: format!("light history: {e}"),
                        }),
                    },
                }
            }
            Request::LightSend {
                recipient,
                amount_sats,
                mode,
                memo,
            } => match light_send(state, recipient, amount_sats, mode, memo).await {
                Ok(r) => Response::LightSent(r),
                Err(message) => Response::Error(ErrorResponse { message }),
            },
            Request::LocksPrepare { capacity_sats } => {
                let kp = match auth_keypair_for_session(state).await {
                    Ok(k) => k,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }));
                    }
                };
                let owner_pubkey =
                    hex::encode(wraith_wallet_core::auth::xonly_pubkey_bytes(&kp));
                let session = state.session.read().await;
                let session = session.as_ref().expect("just checked above");
                match session
                    .handle
                    .prepare_ghost_lock(owner_pubkey, capacity_sats)
                    .await
                {
                    Ok(r) => Response::LocksPrepared(LocksPreparedResponse {
                        lock_id: r.lock_id,
                        funding_address: r.funding_address,
                        required_sats: r.required_sats,
                    }),
                    Err(message) => Response::Error(ErrorResponse {
                        message: format!("locks prepare: {message}"),
                    }),
                }
            }
            Request::LocksConfirm {
                lock_id,
                funding_txid,
            } => {
                let kp = match auth_keypair_for_session(state).await {
                    Ok(k) => k,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }));
                    }
                };
                let proof = match wraith_wallet_core::auth::make_proof(&kp, "confirm_lock") {
                    Ok(p) => p,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("confirm_lock proof: {e}"),
                            }),
                        );
                    }
                };
                let session = state.session.read().await;
                let session = session.as_ref().expect("just checked above");
                match session
                    .handle
                    .confirm_ghost_lock_funding(lock_id, funding_txid, proof)
                    .await
                {
                    Ok(r) => Response::LocksConfirmed(LocksConfirmedResponse {
                        lock_id: r.lock_id,
                        txid: r.txid,
                        block_height: r.block_height,
                    }),
                    Err(message) => Response::Error(ErrorResponse {
                        message: format!("locks confirm: {message}"),
                    }),
                }
            }
            Request::LocksJump {
                lock_id,
                target_address,
                priority,
            } => {
                let priority = match parse_jump_priority(&priority) {
                    Ok(p) => p,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }));
                    }
                };
                let kp = match auth_keypair_for_session(state).await {
                    Ok(k) => k,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }));
                    }
                };
                let proof = match wraith_wallet_core::auth::make_proof(&kp, "request_jump") {
                    Ok(p) => p,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("request_jump proof: {e}"),
                            }),
                        );
                    }
                };
                let session = state.session.read().await;
                let session = session.as_ref().expect("just checked above");
                match session
                    .handle
                    .request_jump(lock_id, priority, target_address, proof)
                    .await
                {
                    Ok(r) => Response::LocksJumped(LocksJumpedResponse {
                        lock_id: r.lock_id,
                        jump_txid: r.jump_txid,
                    }),
                    Err(message) => Response::Error(ErrorResponse {
                        message: format!("locks jump: {message}"),
                    }),
                }
            }
            Request::LocksList => {
                let guard = state.session.read().await;
                match guard.as_ref() {
                    None => Response::Error(ErrorResponse {
                        message: "no GSP session — run `wraith gsp auth` first".to_string(),
                    }),
                    Some(s) => match s.handle.get_ghost_locks().await {
                        Ok(result) => {
                            let locks = result
                                .locks
                                .into_iter()
                                .map(|l| LockEntry {
                                    lock_id: l.lock_id,
                                    status: format!("{:?}", l.status).to_lowercase(),
                                    capacity_sats: l.capacity_sats,
                                    balance_sats: l.balance_sats,
                                    denomination: l.denomination,
                                    timelock_tier: l.timelock_tier,
                                    funding_address: l.funding_address,
                                    funding_txid: l.funding_txid,
                                    funding_vout: l.funding_vout,
                                    creation_height: l.creation_height,
                                })
                                .collect();
                            Response::LocksList(LocksListResponse {
                                locks,
                                total_locked_sats: result.total_locked_sats,
                            })
                        }
                        Err(e) => Response::Error(ErrorResponse {
                            message: format!("locks list: {e}"),
                        }),
                    },
                }
            }
            Request::WalletCreate { name, passphrase } => {
                if let Err(e) = validate_wallet_name(&name) {
                    Response::Error(ErrorResponse { message: e })
                } else {
                    let path = keystore_path(&state.wallets_dir, &name);
                    if path.exists() {
                        Response::Error(ErrorResponse {
                            message: format!(
                                "wallet '{name}' already exists at {}; refusing to overwrite",
                                path.display()
                            ),
                        })
                    } else {
                        let pass = SecretString::new(passphrase.into());
                        match Keystore::create() {
                            Ok((ks, mnemonic)) => match ks.save(&path, &pass) {
                                Ok(()) => {
                                    state.wallets.write().await.insert(name.clone(), ks);
                                    *state.active.write().await = Some(name.clone());
                                    Response::WalletCreate(WalletCreateResponse {
                                        name,
                                        mnemonic,
                                        path: path.display().to_string(),
                                    })
                                }
                                Err(e) => Response::Error(ErrorResponse {
                                    message: format!("save: {e}"),
                                }),
                            },
                            Err(e) => Response::Error(ErrorResponse {
                                message: format!("create: {e}"),
                            }),
                        }
                    }
                }
            }
            Request::WalletUnlock { name, passphrase } => {
                if let Err(e) = validate_wallet_name(&name) {
                    Response::Error(ErrorResponse { message: e })
                } else {
                    let path = keystore_path(&state.wallets_dir, &name);
                    if !path.exists() {
                        Response::Error(ErrorResponse {
                            message: format!("no wallet '{name}' at {}", path.display()),
                        })
                    } else {
                        let pass = SecretString::new(passphrase.into());
                        match Keystore::load(&path, &pass) {
                            Ok(ks) => {
                                state.wallets.write().await.insert(name.clone(), ks);
                                *state.active.write().await = Some(name.clone());
                                Response::WalletUnlocked
                            }
                            Err(KeystoreError::Decrypt) => Response::Error(ErrorResponse {
                                message: "wrong passphrase".to_string(),
                            }),
                            Err(e) => Response::Error(ErrorResponse {
                                message: format!("unlock: {e}"),
                            }),
                        }
                    }
                }
            }
            Request::WalletLock { name } => {
                let target = match name {
                    Some(n) => n,
                    None => match state.active.read().await.clone() {
                        Some(n) => n,
                        None => {
                            return Envelope::new(
                                id,
                                Response::Error(ErrorResponse {
                                    message: "no active wallet to lock".to_string(),
                                }),
                            );
                        }
                    },
                };
                let removed = state.wallets.write().await.remove(&target).is_some();
                if !removed {
                    Response::Error(ErrorResponse {
                        message: format!("wallet '{target}' is not unlocked"),
                    })
                } else {
                    let mut active = state.active.write().await;
                    if active.as_deref() == Some(target.as_str()) {
                        *active = None;
                    }
                    // Drop any GSP session bound to the wallet we just locked.
                    let mut session = state.session.write().await;
                    if session
                        .as_ref()
                        .is_some_and(|s| s.wallet_name == target)
                    {
                        *session = None;
                    }
                    Response::WalletLocked { name: target }
                }
            }
            Request::WalletList => {
                let on_disk = list_on_disk(&state.wallets_dir);
                let unlocked = state.wallets.read().await;
                let active = state.active.read().await.clone();
                let mut wallets: Vec<WalletListEntry> = on_disk
                    .into_iter()
                    .map(|name| WalletListEntry {
                        path: keystore_path(&state.wallets_dir, &name).display().to_string(),
                        unlocked: unlocked.contains_key(&name),
                        active: active.as_deref() == Some(name.as_str()),
                        name,
                    })
                    .collect();
                // Surface unlocked-but-not-on-disk wallets too (shouldn't happen, but
                // defensive — eg if disk file was deleted under us).
                for name in unlocked.keys() {
                    if !wallets.iter().any(|e| &e.name == name) {
                        wallets.push(WalletListEntry {
                            name: name.clone(),
                            path: keystore_path(&state.wallets_dir, name)
                                .display()
                                .to_string(),
                            unlocked: true,
                            active: active.as_deref() == Some(name.as_str()),
                        });
                    }
                }
                Response::WalletList(WalletListResponse { wallets })
            }
            Request::WalletSelect { name } => {
                if let Err(e) = validate_wallet_name(&name) {
                    Response::Error(ErrorResponse { message: e })
                } else if !state.wallets.read().await.contains_key(&name) {
                    Response::Error(ErrorResponse {
                        message: format!(
                            "wallet '{name}' is not unlocked; \
                             run `wraith wallet unlock {name}` first"
                        ),
                    })
                } else {
                    *state.active.write().await = Some(name.clone());
                    // Drop any GSP session that belongs to a different wallet.
                    let mut session = state.session.write().await;
                    if session
                        .as_ref()
                        .is_some_and(|s| s.wallet_name != name)
                    {
                        *session = None;
                    }
                    Response::WalletSelected { name }
                }
            }
            Request::WalletStatus => {
                let active = state.active.read().await.clone();
                let unlocked = active
                    .as_deref()
                    .map(|n| state.wallets.try_read().is_ok_and(|g| g.contains_key(n)))
                    .unwrap_or(false);
                let path = active
                    .as_ref()
                    .map(|n| keystore_path(&state.wallets_dir, n).display().to_string());
                Response::WalletStatus(WalletStatusResponse {
                    active,
                    path,
                    unlocked,
                })
            }
            Request::WalletDerive { path } => {
                match with_active_wallet(state, |_, ks| {
                    ks.derive_xprv(&path)
                        .map(|x| hex::encode(x.public_key().to_bytes()))
                        .map_err(|e| format!("derive: {e}"))
                })
                .await
                {
                    Ok(public_key_hex) => {
                        Response::WalletDerive(WalletDeriveResponse {
                            path,
                            public_key_hex,
                        })
                    }
                    Err(message) => Response::Error(ErrorResponse { message }),
                }
            }
            Request::WalletAuthInfo => {
                match with_active_wallet(state, |_, ks| {
                    let kp = auth::auth_keypair(ks).map_err(|e| format!("auth-info: {e}"))?;
                    Ok::<_, String>((
                        auth::wallet_id_hex(&kp),
                        hex::encode(auth::xonly_pubkey_bytes(&kp)),
                    ))
                })
                .await
                {
                    Ok((wallet_id, auth_public_key_hex)) => {
                        Response::WalletAuthInfo(WalletAuthInfoResponse {
                            wallet_id,
                            auth_public_key_hex,
                            derivation_path: "m/352'/0'/0'/0/0".to_string(),
                        })
                    }
                    Err(message) => Response::Error(ErrorResponse { message }),
                }
            }
            Request::WalletExport { name, to_path } => {
                if let Err(e) = validate_wallet_name(&name) {
                    Response::Error(ErrorResponse { message: e })
                } else {
                    let src = keystore_path(&state.wallets_dir, &name);
                    if !src.is_file() {
                        Response::Error(ErrorResponse {
                            message: format!("no wallet '{name}' at {}", src.display()),
                        })
                    } else {
                        let dst = std::path::PathBuf::from(&to_path);
                        if dst.exists() {
                            Response::Error(ErrorResponse {
                                message: format!(
                                    "refusing to overwrite existing file at {}",
                                    dst.display()
                                ),
                            })
                        } else {
                            if let Some(parent) = dst.parent() {
                                if let Err(e) = std::fs::create_dir_all(parent) {
                                    return Envelope::new(
                                        id,
                                        Response::Error(ErrorResponse {
                                            message: format!("create parent dir: {e}"),
                                        }),
                                    );
                                }
                            }
                            match std::fs::copy(&src, &dst) {
                                Ok(bytes) => {
                                    // Match the keystore's own owner-only permissions.
                                    use std::os::unix::fs::PermissionsExt;
                                    let _ = std::fs::set_permissions(
                                        &dst,
                                        std::fs::Permissions::from_mode(0o600),
                                    );
                                    Response::WalletExported {
                                        name,
                                        path: dst.display().to_string(),
                                        bytes,
                                    }
                                }
                                Err(e) => Response::Error(ErrorResponse {
                                    message: format!("copy: {e}"),
                                }),
                            }
                        }
                    }
                }
            }
            Request::WalletRestore { name, from_path } => {
                if let Err(e) = validate_wallet_name(&name) {
                    Response::Error(ErrorResponse { message: e })
                } else {
                    let src = std::path::PathBuf::from(&from_path);
                    if !src.is_file() {
                        Response::Error(ErrorResponse {
                            message: format!("no file at {}", src.display()),
                        })
                    } else {
                        let dst = keystore_path(&state.wallets_dir, &name);
                        if dst.exists() {
                            Response::Error(ErrorResponse {
                                message: format!(
                                    "wallet '{name}' already exists at {}; refusing to overwrite",
                                    dst.display()
                                ),
                            })
                        } else {
                            if let Some(parent) = dst.parent() {
                                if let Err(e) = std::fs::create_dir_all(parent) {
                                    return Envelope::new(
                                        id,
                                        Response::Error(ErrorResponse {
                                            message: format!("create wallet dir: {e}"),
                                        }),
                                    );
                                }
                            }
                            match std::fs::copy(&src, &dst) {
                                Ok(bytes) => {
                                    use std::os::unix::fs::PermissionsExt;
                                    let _ = std::fs::set_permissions(
                                        &dst,
                                        std::fs::Permissions::from_mode(0o600),
                                    );
                                    Response::WalletRestored {
                                        name,
                                        path: dst.display().to_string(),
                                        bytes,
                                    }
                                }
                                Err(e) => Response::Error(ErrorResponse {
                                    message: format!("copy: {e}"),
                                }),
                            }
                        }
                    }
                }
            }
            Request::WalletShowMnemonic { name, passphrase } => {
                if let Err(e) = validate_wallet_name(&name) {
                    Response::Error(ErrorResponse { message: e })
                } else {
                    let path = keystore_path(&state.wallets_dir, &name);
                    if !path.exists() {
                        Response::Error(ErrorResponse {
                            message: format!("no wallet '{name}' at {}", path.display()),
                        })
                    } else {
                        let pass = SecretString::new(passphrase.into());
                        match Keystore::load(&path, &pass) {
                            Ok(ks) => Response::WalletShowMnemonic(WalletShowMnemonicResponse {
                                mnemonic: ks.expose_mnemonic().to_string(),
                            }),
                            Err(KeystoreError::Decrypt) => Response::Error(ErrorResponse {
                                message: "wrong passphrase".to_string(),
                            }),
                            Err(e) => Response::Error(ErrorResponse {
                                message: format!("show-mnemonic: {e}"),
                            }),
                        }
                    }
                }
            }
            Request::LightReceive { index } => {
                let network = state.network;
                match with_active_wallet(state, |_, ks| {
                    light::receive_address(ks, index, network)
                        .map(|a| a.to_string())
                        .map_err(|e| format!("light receive: {e}"))
                })
                .await
                {
                    Ok(address) => Response::LightReceive(LightReceiveResponse {
                        address,
                        index,
                        network: format!("{:?}", state.network).to_lowercase(),
                        derivation_path: format!(
                            "m/86'/{}'/0'/0/{}",
                            light::GHOST_COIN_TYPE,
                            index
                        ),
                    }),
                    Err(message) => Response::Error(ErrorResponse { message }),
                }
            }
        };

        Envelope::new(id, response)
    }
}
