//! `wraithd` — Wraith Wallet daemon.
//!
//! Long-running process that holds module state and exposes a local IPC surface
//! to the CLI and GUI. Phase 0 (closed): IPC + lifecycle + keystore.
//! Phase 1 (in progress): chain (REST → ghost-pay), gsp (WebSocket → ghost-gsp).

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
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
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
    use wraith_wallet_ipc::{
        default_socket_path, ChainStatusResponse, Envelope, ErrorResponse, GspPingResponse,
        HealthResponse, LightReceiveResponse, Request, Response, WalletAuthInfoResponse,
        WalletCreateResponse, WalletDeriveResponse, WalletStatusResponse,
    };

    const DEFAULT_GHOST_PAY: &str = "http://127.0.0.1:8800";
    const DEFAULT_GSP: &str = "ws://127.0.0.1:8900/ws/v1";
    const GHOST_PAY_ENV: &str = "WRAITHD_GHOST_PAY";
    const GSP_ENV: &str = "WRAITHD_GSP";
    const WALLET_PATH_ENV: &str = "WRAITHD_WALLET";
    const NETWORK_ENV: &str = "WRAITHD_NETWORK";

    struct DaemonState {
        started: Instant,
        chain: Arc<dyn ChainClient>,
        gsp: GspClient,
        wallet: RwLock<Option<Keystore>>,
        wallet_path: PathBuf,
        network: bitcoin::Network,
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

    fn default_wallet_path() -> PathBuf {
        if let Ok(p) = std::env::var(WALLET_PATH_ENV) {
            return PathBuf::from(p);
        }
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        home.join(".wraith").join("wallet").join("keystore.bin")
    }

    pub async fn serve() -> std::io::Result<()> {
        let socket_path = default_socket_path();
        let ghost_pay_url =
            std::env::var(GHOST_PAY_ENV).unwrap_or_else(|_| DEFAULT_GHOST_PAY.to_string());
        let gsp_url = std::env::var(GSP_ENV).unwrap_or_else(|_| DEFAULT_GSP.to_string());
        let wallet_path = default_wallet_path();
        let network = std::env::var(NETWORK_ENV)
            .ok()
            .and_then(|s| parse_network(&s))
            .unwrap_or(bitcoin::Network::Signet);
        tracing::info!(
            ghost_pay = %ghost_pay_url,
            gsp = %gsp_url,
            wallet = %wallet_path.display(),
            network = ?network,
            "node endpoints + wallet path + network configured",
        );

        let state = Arc::new(DaemonState {
            started: Instant::now(),
            chain: Arc::new(GhostPayClient::new(ghost_pay_url)),
            gsp: GspClient::new(gsp_url),
            wallet: RwLock::new(None),
            wallet_path,
            network,
        });

        // Remove stale socket file if present.
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
        // Restrict socket to owner only.
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;

        tracing::info!(path = %socket_path.display(), "wraithd listening");

        loop {
            let (stream, _) = listener.accept().await?;
            let state = Arc::clone(&state);
            tokio::spawn(handle_connection(stream, state));
        }
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
                Ok(status) => Response::ChainStatus(ChainStatusResponse {
                    backend_version: status.backend_version,
                    network: status.network,
                    has_keys: status.has_keys,
                    lock_count: status.lock_count,
                    active_sessions: status.active_sessions,
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
            Request::WalletCreate { passphrase } => {
                if state.wallet_path.exists() {
                    Response::Error(ErrorResponse {
                        message: format!(
                            "wallet already exists at {}; refusing to overwrite",
                            state.wallet_path.display()
                        ),
                    })
                } else {
                    let pass = SecretString::new(passphrase.into());
                    match Keystore::create() {
                        Ok((ks, mnemonic)) => match ks.save(&state.wallet_path, &pass) {
                            Ok(()) => {
                                *state.wallet.write().await = Some(ks);
                                Response::WalletCreate(WalletCreateResponse {
                                    mnemonic,
                                    path: state.wallet_path.display().to_string(),
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
            Request::WalletUnlock { passphrase } => {
                if !state.wallet_path.exists() {
                    Response::Error(ErrorResponse {
                        message: format!(
                            "no wallet at {}; create one first",
                            state.wallet_path.display()
                        ),
                    })
                } else {
                    let pass = SecretString::new(passphrase.into());
                    match Keystore::load(&state.wallet_path, &pass) {
                        Ok(ks) => {
                            *state.wallet.write().await = Some(ks);
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
            Request::WalletLock => {
                *state.wallet.write().await = None;
                Response::WalletLocked
            }
            Request::WalletStatus => {
                let unlocked = state.wallet.read().await.is_some();
                Response::WalletStatus(WalletStatusResponse {
                    unlocked,
                    path: state.wallet_path.display().to_string(),
                    exists_on_disk: state.wallet_path.exists(),
                })
            }
            Request::WalletDerive { path } => {
                let guard = state.wallet.read().await;
                match guard.as_ref() {
                    None => Response::Error(ErrorResponse {
                        message: "wallet is locked; run `wraith wallet unlock` first"
                            .to_string(),
                    }),
                    Some(ks) => match ks.derive_xprv(&path) {
                        Ok(xprv) => {
                            let pubkey_bytes = xprv.public_key().to_bytes();
                            Response::WalletDerive(WalletDeriveResponse {
                                path,
                                public_key_hex: hex::encode(pubkey_bytes),
                            })
                        }
                        Err(e) => Response::Error(ErrorResponse {
                            message: format!("derive: {e}"),
                        }),
                    },
                }
            }
            Request::WalletAuthInfo => {
                let guard = state.wallet.read().await;
                match guard.as_ref() {
                    None => Response::Error(ErrorResponse {
                        message: "wallet is locked; run `wraith wallet unlock` first"
                            .to_string(),
                    }),
                    Some(ks) => match auth::auth_keypair(ks) {
                        Ok(kp) => Response::WalletAuthInfo(WalletAuthInfoResponse {
                            wallet_id: auth::wallet_id_hex(&kp),
                            auth_public_key_hex: hex::encode(auth::xonly_pubkey_bytes(&kp)),
                            derivation_path: "m/352'/0'/0'/0/0".to_string(),
                        }),
                        Err(e) => Response::Error(ErrorResponse {
                            message: format!("auth-info: {e}"),
                        }),
                    },
                }
            }
            Request::LightReceive { index } => {
                let guard = state.wallet.read().await;
                match guard.as_ref() {
                    None => Response::Error(ErrorResponse {
                        message: "wallet is locked; run `wraith wallet unlock` first"
                            .to_string(),
                    }),
                    Some(ks) => match light::receive_address(ks, index, state.network) {
                        Ok(addr) => Response::LightReceive(LightReceiveResponse {
                            address: addr.to_string(),
                            index,
                            network: format!("{:?}", state.network).to_lowercase(),
                            derivation_path: format!(
                                "m/86'/{}'/0'/0/{}",
                                light::GHOST_COIN_TYPE,
                                index
                            ),
                        }),
                        Err(e) => Response::Error(ErrorResponse {
                            message: format!("light receive: {e}"),
                        }),
                    },
                }
            }
        };

        Envelope::new(id, response)
    }
}
