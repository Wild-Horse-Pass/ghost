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
    /// Inspect the daemon's stored GSP session token + persistent connection state.
    GspSessionStatus,
    /// Read the active wallet's last-known on-chain balance from the persistent session.
    LightBalance,
    /// List the active wallet's UTXOs via the persistent GSP session.
    LightUtxos {
        /// Minimum number of confirmations. Default 1.
        min_confirmations: u32,
    },
    /// List the active wallet's transaction history via the persistent GSP session.
    LightHistory { limit: u32, offset: u32 },
    /// List the active wallet's Ghost Locks via the persistent GSP session.
    LocksList,
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
    ChainStatus(ChainStatusResponse),
    GspPing(GspPingResponse),
    GspAuth(GspAuthResponse),
    GspSessionStatus(GspSessionStatusResponse),
    LightBalance(LightBalanceResponse),
    LightUtxos(LightUtxosResponse),
    LightHistory(LightHistoryResponse),
    LocksList(LocksListResponse),
    LightSent(LightSentResponse),
    WalletCreate(WalletCreateResponse),
    WalletUnlocked,
    WalletLocked { name: String },
    WalletList(WalletListResponse),
    WalletSelected { name: String },
    WalletStatus(WalletStatusResponse),
    WalletDerive(WalletDeriveResponse),
    WalletAuthInfo(WalletAuthInfoResponse),
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
