//! Wraith Wallet — IPC types shared between `wraithd` and clients (CLI, GUI).
//!
//! Wire format: newline-delimited JSON-RPC 2.0. One request per line, one response per line.
//!
//! Methods are typed: each `Request::*` variant pairs with a `Response::*` variant of the same name.
//!
//! Trust model: the socket is bound at owner-only (0600) permissions, so the
//! channel is restricted to processes running as the same user as `wraithd`.
//! Passphrases travel in plaintext over the socket; do **not** log requests
//! verbatim. Phase 16 hardening tightens this surface.

use serde::{Deserialize, Serialize};

pub const JSONRPC_VERSION: &str = "2.0";

/// Default socket path discovery.
///
/// On Unix: `${XDG_RUNTIME_DIR:-/tmp}/wraithd-${UID}.sock`.
#[cfg(unix)]
pub fn default_socket_path() -> std::path::PathBuf {
    use std::path::PathBuf;
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let uid = unsafe { libc::getuid() };
    dir.join(format!("wraithd-{uid}.sock"))
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Request {
    Health,
    /// One-shot connectivity + health summary (daemon + ghost-pay + ghost-gsp + session).
    Doctor,
    ChainStatus,
    GspPing,
    /// Register the active wallet's auth identity with the configured GSP and create
    /// a session. Idempotent — already-registered wallets proceed straight to session.
    GspAuth,
    /// Inspect the daemon's stored GSP session token + persistent connection state.
    GspSessionStatus,
    /// Register the active wallet's BIP-352 scan public key with the GSP so the
    /// server can detect incoming silent payments on its behalf.
    GspRegisterScanKey,
    /// Read the active wallet's last-known on-chain balance from the persistent session.
    LightBalance,
    /// List the active wallet's UTXOs via the persistent GSP session.
    LightUtxos {
        /// Minimum number of confirmations. Default 1.
        min_confirmations: u32,
    },
    /// List the active wallet's transaction history via the persistent GSP session.
    LightHistory { limit: u32, offset: u32 },
    /// List BIP-352 silent-payment detections accumulated in the persistent
    /// session's local scanner since auth.
    LightDetected,
    /// Read-only snapshot of the daemon's configured environment — the URLs
    /// it talks to, the network it's bound to, where it stores wallets.
    /// Useful for diagnostics + the GUI's settings panel.
    DaemonEnv,
    /// Stream future BIP-352 silent-payment detections from the persistent
    /// session as they arrive. The daemon keeps the connection open and emits
    /// `Response::PaymentDetected` envelopes (id=0) until the client closes
    /// the socket. The initial reply on the request's own id is an
    /// acknowledgement (`Response::Watching`).
    WatchPayments,
    /// List the active wallet's Ghost Locks via the persistent GSP session.
    LocksList,
    /// Ask GSP to prepare a new ghost lock for the active wallet.
    /// Server returns a funding address and required-sats; client funds it externally.
    LocksPrepare { capacity_sats: u64 },
    /// Confirm that a previously-prepared lock has been funded on-chain.
    LocksConfirm {
        lock_id: String,
        funding_txid: String,
    },
    /// Initiate a jump (key rotation) for an existing lock.
    /// Priority is one of: "normal" (default), "high", "urgent".
    LocksJump {
        lock_id: String,
        target_address: String,
        priority: String,
    },
    /// Prepare + sign + submit an on-chain / L2 payment.
    /// Mode is one of: "ghostpay" (default), "wraith", "confidential".
    LightSend {
        recipient: String,
        amount_sats: u64,
        mode: String,
        memo: Option<String>,
    },
    /// Create a new named wallet on disk and add it to the daemon's unlocked set.
    WalletCreate { name: String, passphrase: String },
    /// Restore a wallet from an existing BIP-39 mnemonic. Equivalent to
    /// `WalletCreate` but with the seed supplied by the caller. The new
    /// keystore is encrypted under `passphrase` and added to the unlocked
    /// set; on success the daemon also makes it active.
    WalletImport {
        name: String,
        mnemonic: String,
        passphrase: String,
    },
    /// Unlock a named wallet by reading from disk + decrypting. Becomes active.
    WalletUnlock { name: String, passphrase: String },
    /// Drop a named wallet from the unlocked set (or the active one if name is None).
    WalletLock { name: Option<String> },
    /// List all on-disk wallets with unlocked / active status.
    WalletList,
    /// Set the active wallet (must already be unlocked).
    WalletSelect { name: String },
    /// Status of the active wallet (or "no active wallet" if none).
    WalletStatus,
    /// Derive a key at a BIP32 path from the active wallet's keystore.
    WalletDerive { path: String },
    /// Show the GSP auth identity (wallet_id + x-only auth pubkey) of the active wallet.
    WalletAuthInfo,
    /// Show the active wallet's BIP-352 Ghost ID (silent payment receive identity).
    WalletGhostId,
    /// Re-display a wallet's BIP39 mnemonic. Always re-prompts the passphrase.
    WalletShowMnemonic { name: String, passphrase: String },
    /// Copy the on-disk encrypted keystore for `name` to `to_path` (a regular file).
    /// The file is already encrypted with the wallet passphrase.
    WalletExport { name: String, to_path: String },
    /// Read an encrypted keystore from `from_path` and install it as wallet `name`.
    /// Refuses if `name` already exists on disk.
    WalletRestore { name: String, from_path: String },
    /// Derive a BIP86 taproot receive address at index `index` from the active wallet.
    LightReceive { index: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Health(HealthResponse),
    Doctor(DoctorResponse),
    ChainStatus(ChainStatusResponse),
    GspPing(GspPingResponse),
    GspAuth(GspAuthResponse),
    GspSessionStatus(GspSessionStatusResponse),
    GspScanKeyRegistered { wallet_id: String, scan_pubkey_hex: String },
    LightBalance(LightBalanceResponse),
    LightUtxos(LightUtxosResponse),
    LightHistory(LightHistoryResponse),
    LightDetected(LightDetectedResponse),
    DaemonEnv(DaemonEnvResponse),
    /// Acknowledgement of a `Request::WatchPayments`. Subsequent
    /// `PaymentDetected` envelopes (id=0) on the same connection are pushes,
    /// not replies.
    Watching,
    /// Unsolicited push: a new BIP-352 detection. Daemon sends with `id=0`.
    PaymentDetected(DetectedPaymentEntry),
    LocksList(LocksListResponse),
    LocksPrepared(LocksPreparedResponse),
    LocksConfirmed(LocksConfirmedResponse),
    LocksJumped(LocksJumpedResponse),
    LightSent(LightSentResponse),
    WalletCreate(WalletCreateResponse),
    /// Reply to `Request::WalletImport`. We don't echo the mnemonic back —
    /// the caller already has it.
    WalletImported { name: String, path: String },
    WalletUnlocked,
    WalletLocked { name: String },
    WalletList(WalletListResponse),
    WalletSelected { name: String },
    WalletStatus(WalletStatusResponse),
    WalletDerive(WalletDeriveResponse),
    WalletAuthInfo(WalletAuthInfoResponse),
    WalletGhostId(WalletGhostIdResponse),
    WalletShowMnemonic(WalletShowMnemonicResponse),
    WalletExported { name: String, path: String, bytes: u64 },
    WalletRestored { name: String, path: String, bytes: u64 },
    LightReceive(LightReceiveResponse),
    Error(ErrorResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub daemon_version: String,
    pub uptime_secs: u64,
}

/// One row in the `Doctor` summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorCheck {
    pub name: String,
    /// `"pass"` / `"fail"` / `"skip"`.
    pub status: String,
    /// Human-readable detail line.
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorResponse {
    pub checks: Vec<DoctorCheck>,
    pub all_pass: bool,
}

/// Status of the configured ghost-pay backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStatusResponse {
    pub backend_version: String,
    pub network: String,
    pub has_keys: bool,
    pub lock_count: u64,
    pub active_sessions: u64,
}

/// GSP WebSocket connectivity probe result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GspPingResponse {
    pub server_time: i64,
    pub round_trip_ms: Option<i64>,
}

/// Result of `GspAuth` (register-if-needed + create-session).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GspAuthResponse {
    pub wallet_id: String,
    /// Whether the register call returned "already registered".
    pub already_registered: bool,
    /// Truncated JWT (first 12 chars) for visibility — full token stays in the daemon.
    pub token_prefix: String,
    pub expires_at: i64,
}

/// Snapshot of the daemon's stored GSP session token + live connection state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GspSessionStatusResponse {
    pub have_token: bool,
    /// Wallet name the token belongs to (the wallet that was active at `gsp_auth` time).
    pub wallet_name: Option<String>,
    pub wallet_id: Option<String>,
    pub expires_at: Option<i64>,
    pub remaining_secs: Option<i64>,
    /// One of: "disconnected", "connecting", "authenticating", "authenticated", "backoff".
    pub phase: Option<String>,
    /// Number of successful WS connects (1 = first connect, >1 = reconnects).
    pub connect_count: Option<u64>,
    pub last_error: Option<String>,
}

/// Active-wallet balance snapshot. `None` fields mean "no data yet"
/// (session not authenticated or first BalanceUpdate not received).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightBalanceResponse {
    pub confirmed_sats: Option<u64>,
    pub unconfirmed_sats: Option<u64>,
    pub locked_sats: Option<u64>,
    pub received_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightUtxoEntry {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
    pub confirmations: u32,
    pub script_type: String,
    pub spendable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightUtxosResponse {
    pub utxos: Vec<LightUtxoEntry>,
    pub total_sats: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightHistoryEntry {
    pub txid: String,
    pub block_height: Option<u32>,
    pub timestamp: i64,
    /// Net satoshi change (positive = received, negative = sent).
    pub amount_sats: i64,
    pub fee_sats: Option<u64>,
    pub tx_type: String,
    pub confirmations: u32,
    pub memo: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightHistoryResponse {
    pub transactions: Vec<LightHistoryEntry>,
    pub total_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedPaymentEntry {
    pub txid: String,
    pub block_height: Option<u32>,
    pub vout: u32,
    pub amount_sats: Option<u64>,
    pub k: u32,
    pub received_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightDetectedResponse {
    pub detections: Vec<DetectedPaymentEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockEntry {
    pub lock_id: String,
    pub status: String,
    pub capacity_sats: u64,
    pub balance_sats: u64,
    pub denomination: String,
    pub timelock_tier: String,
    pub funding_address: String,
    pub funding_txid: Option<String>,
    pub funding_vout: Option<u32>,
    pub creation_height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocksListResponse {
    pub locks: Vec<LockEntry>,
    pub total_locked_sats: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocksPreparedResponse {
    pub lock_id: String,
    pub funding_address: String,
    pub required_sats: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocksConfirmedResponse {
    pub lock_id: String,
    pub txid: String,
    pub block_height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocksJumpedResponse {
    pub lock_id: String,
    /// Jump transaction id, if the server broadcast it.
    pub jump_txid: Option<String>,
}

/// Read-only daemon environment snapshot. Maps 1:1 to the WRAITHD_* env vars
/// that wraithd reads at startup, plus a couple of derived fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonEnvResponse {
    /// Comma-separated list of ghost-pay URLs in failover order.
    pub ghost_pay_urls: Vec<String>,
    /// Comma-separated list of GSP WebSocket URLs in failover order.
    pub gsp_urls: Vec<String>,
    /// Network the daemon is bound to: `mainnet` / `signet` / `testnet` / `regtest`.
    pub network: String,
    /// Absolute path to the encrypted-keystore directory.
    pub wallets_dir: String,
    /// SOCKS5(h) proxy URL if Tor is enabled, otherwise `None`.
    pub tor_proxy: Option<String>,
    /// Absolute path to the IPC socket the daemon is listening on.
    pub socket_path: String,
    /// Idle-lock threshold in seconds; 0 means auto-lock is disabled.
    pub idle_lock_secs: u64,
}

/// Result of `LightSend` (PreparePayment + sign + SubmitSignedPayment).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightSentResponse {
    pub payment_id: String,
    /// On-chain txid if the server broadcast the transaction. May be `None`
    /// for L2 payments that don't surface as a chain tx (e.g. ghostpay mode).
    pub txid: Option<String>,
    pub recipient: String,
    pub amount_sats: u64,
    pub fee_sats: u64,
    pub mode: String,
}

/// Returned after creating a fresh wallet — the mnemonic is shown once for backup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletCreateResponse {
    pub name: String,
    pub mnemonic: String,
    pub path: String,
}

/// Status of the active wallet, or `None` if no wallet is active.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletStatusResponse {
    pub active: Option<String>,
    pub path: Option<String>,
    pub unlocked: bool,
}

/// One entry in `WalletListResponse::wallets`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletListEntry {
    pub name: String,
    pub path: String,
    pub unlocked: bool,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletListResponse {
    pub wallets: Vec<WalletListEntry>,
}

/// Public key derived at a BIP32 path. Private material stays in the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletDeriveResponse {
    pub path: String,
    /// SEC1 compressed (33-byte) public key, hex-encoded.
    pub public_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightReceiveResponse {
    pub address: String,
    pub index: u32,
    pub network: String,
    pub derivation_path: String,
}

/// GSP authentication identity for the unlocked wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAuthInfoResponse {
    /// `SHA256(auth_pubkey)[0..16]` hex.
    pub wallet_id: String,
    /// X-only auth public key (32 bytes), hex.
    pub auth_public_key_hex: String,
    /// BIP32 path the auth keypair is derived at.
    pub derivation_path: String,
}

/// The wallet's BIP-352 Ghost ID — share this string to receive payments.
/// Derived deterministically from the seed; same seed across wallet
/// implementations yields the same Ghost ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletGhostIdResponse {
    pub ghost_id: String,
    pub network: String,
    /// Compressed (33-byte) scan public key, hex. Public — given to a GSP
    /// to scan for incoming payments.
    pub scan_public_key_hex: String,
    /// Compressed (33-byte) spend public key, hex.
    pub spend_public_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletShowMnemonicResponse {
    pub mnemonic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub jsonrpc: String,
    pub id: u64,
    #[serde(flatten)]
    pub payload: T,
}

impl<T> Envelope<T> {
    pub fn new(id: u64, payload: T) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T>(value: &T) -> T
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let s = serde_json::to_string(value).expect("serialize");
        serde_json::from_str(&s).expect("deserialize")
    }

    #[test]
    fn envelope_request_round_trip() {
        // Sample a representative selection across each subsystem so we catch
        // schema drift early. The full Request variant set is exercised by the
        // CLI and GUI integration tests.
        let cases = vec![
            Request::Health,
            Request::Doctor,
            Request::WalletList,
            Request::WalletStatus,
            Request::WalletUnlock {
                name: "test".into(),
                passphrase: "p".repeat(32),
            },
            Request::WalletImport {
                name: "restored".into(),
                mnemonic: "abandon ".repeat(11) + "about",
                passphrase: "long-enough-passphrase".into(),
            },
            Request::WalletLock { name: None },
            Request::WalletSelect { name: "test".into() },
            Request::LightBalance,
            Request::LightUtxos { min_confirmations: 1 },
            Request::LightHistory { limit: 50, offset: 0 },
            Request::LightReceive { index: 0 },
            Request::LightSend {
                recipient: "bc1qxyz".into(),
                amount_sats: 100_000,
                mode: "onchain".into(),
                memo: Some("test".into()),
            },
            Request::LocksList,
            Request::LocksPrepare { capacity_sats: 1_000_000 },
            Request::DaemonEnv,
        ];

        for req in cases {
            let env = Envelope::new(7, req.clone());
            let back: Envelope<Request> = roundtrip(&env);
            assert_eq!(back.id, 7);
            assert_eq!(back.jsonrpc, JSONRPC_VERSION);
            // Compare via JSON shape since Request doesn't impl PartialEq.
            assert_eq!(
                serde_json::to_value(&req).unwrap(),
                serde_json::to_value(&back.payload).unwrap()
            );
        }
    }

    #[test]
    fn malformed_envelopes_fail_cleanly() {
        // The dispatch loop relies on these being errors — never panics.
        let inputs = [
            "",
            "{",
            "null",
            "[]",
            "\"hello\"",
            "{\"jsonrpc\":\"2.0\"}",                       // missing method/id
            "{\"jsonrpc\":\"2.0\",\"id\":1}",              // missing method
            "{\"jsonrpc\":\"2.0\",\"id\":-1,\"method\":\"health\"}", // negative id
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"unknown_method_x\"}",
        ];
        for raw in inputs {
            let result: Result<Envelope<Request>, _> = serde_json::from_str(raw);
            assert!(result.is_err(), "expected error for input: {raw:?}");
        }
    }

    #[test]
    fn envelope_response_round_trip() {
        let cases = vec![
            Response::Health(HealthResponse {
                daemon_version: "1.8.0".into(),
                uptime_secs: 42,
            }),
            Response::WalletLocked { name: "default".into() },
            Response::WalletImported {
                name: "restored".into(),
                path: "/tmp/restored.json".into(),
            },
            Response::DaemonEnv(DaemonEnvResponse {
                ghost_pay_urls: vec!["http://127.0.0.1:8800".into()],
                gsp_urls: vec!["ws://127.0.0.1:8900/ws/v1".into()],
                network: "signet".into(),
                wallets_dir: "/home/test/.wraith/wallets".into(),
                tor_proxy: None,
                socket_path: "/tmp/wraithd.sock".into(),
                idle_lock_secs: 900,
            }),
            Response::WalletList(WalletListResponse {
                wallets: vec![WalletListEntry {
                    name: "default".into(),
                    path: "/tmp/x".into(),
                    unlocked: false,
                    active: false,
                }],
            }),
        ];
        for resp in cases {
            let env = Envelope::new(99, resp.clone());
            let back: Envelope<Response> = roundtrip(&env);
            assert_eq!(back.id, 99);
            assert_eq!(
                serde_json::to_value(&env.payload).unwrap(),
                serde_json::to_value(&back.payload).unwrap()
            );
        }
    }

    proptest::proptest! {
        // Parsing the IPC envelope from arbitrary bytes must NEVER panic.
        // The dispatch loop catches malformed JSON and returns an Error
        // envelope, but only if the underlying parser doesn't blow up first.
        // 4096 cases is plenty to catch obvious panics; raise via the
        // PROPTEST_CASES env var for ad-hoc deeper sweeps.
        #![proptest_config(proptest::test_runner::Config {
            cases: 4096,
            .. proptest::test_runner::Config::default()
        })]

        #[test]
        fn arbitrary_bytes_never_panic_envelope_request(bytes in proptest::collection::vec(0u8..=255, 0..1024)) {
            let _ = serde_json::from_slice::<Envelope<Request>>(&bytes);
        }

        #[test]
        fn arbitrary_strings_never_panic_envelope_request(s in ".{0,1024}") {
            let _ = serde_json::from_str::<Envelope<Request>>(&s);
        }

        // Round-trip stability: anything we ourselves serialise must
        // deserialise back to an equal value (via JSON-shape comparison,
        // since Request doesn't impl PartialEq). This catches accidental
        // schema drift introduced by serde annotations.
        #[test]
        fn well_formed_envelopes_round_trip(id in 0u64..=u64::MAX) {
            let env = Envelope::new(id, Request::Health);
            let s = serde_json::to_string(&env).unwrap();
            let back: Envelope<Request> = serde_json::from_str(&s).unwrap();
            proptest::prop_assert_eq!(back.id, id);
            proptest::prop_assert_eq!(
                serde_json::to_value(&env.payload).unwrap(),
                serde_json::to_value(&back.payload).unwrap()
            );
        }
    }

    #[test]
    fn passphrase_field_serialises_and_does_not_leak_into_other_variants() {
        // Sanity: a freshly-serialised WalletUnlock contains the passphrase
        // (we don't redact at the wire layer — the trust model relies on the
        // 0600 socket permissions instead). Make sure unrelated request
        // variants never carry that field, so a typo in dispatch can't ship
        // credentials by accident.
        let r = Request::WalletUnlock {
            name: "alice".into(),
            passphrase: "hunter2".into(),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("hunter2"));

        for clean in [Request::Health, Request::Doctor, Request::WalletList] {
            let s = serde_json::to_string(&clean).unwrap();
            assert!(!s.contains("passphrase"));
        }
    }
}
