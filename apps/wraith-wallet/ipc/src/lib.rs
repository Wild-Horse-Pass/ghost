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
    ChainStatus,
    GspPing,
    /// Create a new wallet at the daemon's configured path.
    WalletCreate { passphrase: String },
    /// Unlock the wallet by reading the file from disk and decrypting with `passphrase`.
    WalletUnlock { passphrase: String },
    /// Drop the unlocked keystore from daemon memory.
    WalletLock,
    /// Whether a wallet is currently unlocked.
    WalletStatus,
    /// Derive a key at a BIP32 path from the unlocked keystore.
    WalletDerive { path: String },
    /// Show the GSP auth identity (wallet_id + x-only auth pubkey).
    WalletAuthInfo,
    /// Re-display the BIP39 mnemonic. Requires the passphrase even when the
    /// wallet is unlocked, to avoid exposing the seed to anyone with IPC access.
    WalletShowMnemonic { passphrase: String },
    /// Derive a BIP86 taproot receive address at index `index`.
    LightReceive { index: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Health(HealthResponse),
    ChainStatus(ChainStatusResponse),
    GspPing(GspPingResponse),
    WalletCreate(WalletCreateResponse),
    WalletUnlocked,
    WalletLocked,
    WalletStatus(WalletStatusResponse),
    WalletDerive(WalletDeriveResponse),
    WalletAuthInfo(WalletAuthInfoResponse),
    WalletShowMnemonic(WalletShowMnemonicResponse),
    LightReceive(LightReceiveResponse),
    Error(ErrorResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub daemon_version: String,
    pub uptime_secs: u64,
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

/// Returned after creating a fresh wallet — the mnemonic is shown once for backup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletCreateResponse {
    pub mnemonic: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletStatusResponse {
    pub unlocked: bool,
    pub path: String,
    pub exists_on_disk: bool,
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
