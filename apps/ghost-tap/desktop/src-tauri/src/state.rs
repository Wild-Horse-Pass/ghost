use ghost_tap_core::merchant::wash_task::WashProcessorHandle;
use ghost_tap_core::merchant::wraith::WraithWasher;
use ghost_tap_core::network::connection::ConnectionManager;
use ghost_tap_core::storage::WalletStorage;
use ghost_tap_core::wallet::Wallet;
use parking_lot::Mutex;
use secrecy::SecretString;
use std::path::PathBuf;
use std::sync::Arc;

/// A fully-initialized wallet with its mnemonic and optional storage.
pub struct WalletInstance {
    pub wallet: Arc<std::sync::Mutex<Wallet>>,
    pub mnemonic: SecretString,
    pub storage: Arc<std::sync::Mutex<WalletStorage>>,
}

/// Application state managed by Tauri.
pub struct AppState {
    pub wallet: Mutex<Option<WalletInstance>>,
    pub connection: Arc<ConnectionManager>,
    pub washer: Arc<std::sync::Mutex<WraithWasher>>,
    pub wash_handle: Mutex<Option<WashProcessorHandle>>,
    /// SHA-256 hash of PIN (hex), or None if no PIN set.
    pub pin_hash: Mutex<Option<String>>,
    /// App data directory for wallet files.
    pub data_dir: PathBuf,
}

impl AppState {
    pub fn new() -> Self {
        let data_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("ghosttap");
        std::fs::create_dir_all(&data_dir).ok();

        // Load saved PIN hash if exists
        let pin_path = data_dir.join("pin.hash");
        let pin_hash = std::fs::read_to_string(&pin_path).ok();

        Self {
            wallet: Mutex::new(None),
            connection: Arc::new(ConnectionManager::new()),
            washer: Arc::new(std::sync::Mutex::new(WraithWasher::new())),
            wash_handle: Mutex::new(None),
            pin_hash: Mutex::new(pin_hash),
            data_dir,
        }
    }

    /// Path to the wallet database file.
    pub fn wallet_db_path(&self) -> PathBuf {
        self.data_dir.join("wallet.db")
    }

    /// Derive a 32-byte encryption key from a PIN using SHA-256.
    /// For wallet encryption at rest.
    pub fn derive_key(pin: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"ghosttap-wallet-key:");
        hasher.update(pin.as_bytes());
        hasher.finalize().into()
    }

    /// Hash a PIN for verification (different salt from key derivation).
    pub fn hash_pin(pin: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"ghosttap-pin-verify:");
        hasher.update(pin.as_bytes());
        hex::encode(hasher.finalize())
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
