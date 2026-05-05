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
    /// Register the active wallet's auth identity with the configured GSP and create
    /// a session. Idempotent — already-registered wallets proceed straight to session.
    GspAuth,
    /// Inspect the daemon's stored GSP session token (if any).
    GspSessionStatus,
    /// Create a new named wallet on disk and add it to the daemon's unlocked set.
    WalletCreate { name: String, passphrase: String },
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
    /// Re-display a wallet's BIP39 mnemonic. Always re-prompts the passphrase.
    WalletShowMnemonic { name: String, passphrase: String },
    /// Derive a BIP86 taproot receive address at index `index` from the active wallet.
    LightReceive { index: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Health(HealthResponse),
    ChainStatus(ChainStatusResponse),
    GspPing(GspPingResponse),
    GspAuth(GspAuthResponse),
    GspSessionStatus(GspSessionStatusResponse),
    WalletCreate(WalletCreateResponse),
    WalletUnlocked,
    WalletLocked { name: String },
    WalletList(WalletListResponse),
    WalletSelected { name: String },
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

/// Snapshot of the daemon's stored GSP session token (if any).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GspSessionStatusResponse {
    pub have_token: bool,
    /// Wallet name the token belongs to (the wallet that was active at `gsp_auth` time).
    pub wallet_name: Option<String>,
    pub wallet_id: Option<String>,
    pub expires_at: Option<i64>,
    pub remaining_secs: Option<i64>,
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
