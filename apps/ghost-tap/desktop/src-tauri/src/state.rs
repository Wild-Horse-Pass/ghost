use ghost_tap_core::merchant::wash_task::WashProcessorHandle;
use ghost_tap_core::merchant::wraith::WraithWasher;
use ghost_tap_core::network::connection::ConnectionManager;
use ghost_tap_core::storage::WalletStorage;
use ghost_tap_core::wallet::Wallet;
use parking_lot::Mutex;
use secrecy::SecretString;
use std::sync::Arc;

/// A fully-initialized wallet with its mnemonic and optional storage.
pub struct WalletInstance {
    pub wallet: Arc<std::sync::Mutex<Wallet>>,
    pub mnemonic: SecretString,
    pub storage: Option<Arc<std::sync::Mutex<WalletStorage>>>,
}

/// Application state managed by Tauri.
pub struct AppState {
    pub wallet: Mutex<Option<WalletInstance>>,
    pub connection: Arc<ConnectionManager>,
    pub washer: Arc<std::sync::Mutex<WraithWasher>>,
    pub wash_handle: Mutex<Option<WashProcessorHandle>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            wallet: Mutex::new(None),
            connection: Arc::new(ConnectionManager::new()),
            washer: Arc::new(std::sync::Mutex::new(WraithWasher::new())),
            wash_handle: Mutex::new(None),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
