//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: wallet.rs                                                                                                      |
//|======================================================================================================================|

//! Main LightWallet implementation

use std::path::PathBuf;
use std::sync::Arc;

use bitcoin::Network;
use parking_lot::RwLock;
use tracing::info;

use ghost_gsp_proto::WalletId;

use crate::confidential::{DiscoveredNote, NoteScanner, NoteSpendClientProver, NoteStore, ParamsCache};
use crate::error::{LightWalletError, WalletResult};
use crate::gsp::GspClient;
use crate::keys::MasterKey;
use crate::state::WalletCache;

/// Tree depth for NoteSpend circuits (matches ghost-zkp::NOTE_TREE_DEPTH)
const NOTE_TREE_DEPTH: usize = 20;

/// Wallet configuration
#[derive(Debug, Clone)]
pub struct WalletConfig {
    /// Data directory for wallet storage
    pub data_dir: PathBuf,

    /// Bitcoin network
    pub network: Network,

    /// List of GSP URLs for connection
    pub gsp_urls: Vec<String>,

    /// Enable automatic reconnection
    pub auto_reconnect: bool,

    /// Reconnection interval in seconds
    pub reconnect_interval_secs: u64,

    /// Ghost-pool node for downloading NoteSpend MPC params (host, port).
    /// Defaults to ("127.0.0.1", 8080) when None.
    pub params_node: Option<(String, u16)>,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./wallet-data"),
            network: Network::Regtest,
            gsp_urls: vec!["wss://localhost:8900/ws/v1".to_string()],
            auto_reconnect: true,
            reconnect_interval_secs: 5,
            params_node: None,
        }
    }
}

/// Wallet connection status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletStatus {
    /// Wallet is disconnected from GSP
    Disconnected,
    /// Wallet is connecting to GSP
    Connecting,
    /// Wallet is connected and authenticated
    Connected,
    /// Wallet is reconnecting after disconnect
    Reconnecting,
}

/// Wallet balance
#[derive(Debug, Clone, Copy, Default)]
pub struct WalletBalance {
    /// Confirmed balance in satoshis
    pub confirmed: u64,
    /// Unconfirmed balance in satoshis
    pub unconfirmed: u64,
    /// Amount locked in Ghost Locks
    pub locked: u64,
}

impl WalletBalance {
    /// Get total available balance (confirmed only)
    pub fn available(&self) -> u64 {
        self.confirmed
    }

    /// Get total balance (confirmed + unconfirmed)
    pub fn total(&self) -> u64 {
        self.confirmed + self.unconfirmed
    }
}

/// Light Wallet - main wallet interface
pub struct LightWallet {
    /// Master key (encrypted in storage)
    /// 2.5 HIGH: MasterKey is wrapped in Arc to allow sharing across async boundaries
    /// without cloning the secret key material. The Arc is cloned, not the key.
    master_key: Arc<RwLock<Option<Arc<MasterKey>>>>,

    /// Configuration
    config: WalletConfig,

    /// GSP client
    gsp_client: Arc<RwLock<Option<GspClient>>>,

    /// Local cache
    cache: Arc<WalletCache>,

    /// Current connection status
    status: Arc<RwLock<WalletStatus>>,

    /// Cached balance
    balance: Arc<RwLock<WalletBalance>>,

    /// NoteSpend MPC params cache (handles download + local storage)
    params_cache: ParamsCache,

    /// Lazily-initialized NoteSpend prover (loaded on first use)
    prover: Arc<RwLock<Option<NoteSpendClientProver>>>,

    /// Owned confidential note store (lazily initialized on first scan)
    note_store: Arc<RwLock<Option<NoteStore>>>,

    /// L2 transaction scanner for discovering owned notes (lazily initialized)
    scanner: Arc<RwLock<Option<NoteScanner>>>,
}

impl LightWallet {
    /// Create a new wallet from mnemonic
    pub fn from_mnemonic(
        mnemonic: &str,
        password: &str,
        config: WalletConfig,
    ) -> WalletResult<Self> {
        // Create data directory
        std::fs::create_dir_all(&config.data_dir)?;

        // Derive master key from mnemonic
        let master_key = MasterKey::from_mnemonic(mnemonic, config.network)?;

        // Create encrypted storage
        let cache_path = config.data_dir.join("wallet.db");
        let cache = WalletCache::open(&cache_path, password)?;

        // Save encrypted master key
        cache.save_master_key(&master_key, password)?;

        info!("Created new wallet from mnemonic");

        let params_cache = ParamsCache::new(config.data_dir.join("params"));

        // WalletCache contains rusqlite::Connection which is not Sync by design.
        // The Arc is still useful for shared ownership even in single-threaded async.
        #[allow(clippy::arc_with_non_send_sync)]
        Ok(Self {
            master_key: Arc::new(RwLock::new(Some(Arc::new(master_key)))),
            config,
            gsp_client: Arc::new(RwLock::new(None)),
            cache: Arc::new(cache),
            status: Arc::new(RwLock::new(WalletStatus::Disconnected)),
            balance: Arc::new(RwLock::new(WalletBalance::default())),
            params_cache,
            prover: Arc::new(RwLock::new(None)),
            note_store: Arc::new(RwLock::new(None)),
            scanner: Arc::new(RwLock::new(None)),
        })
    }

    /// Generate a new wallet with random mnemonic
    pub fn generate(password: &str, config: WalletConfig) -> WalletResult<(Self, String)> {
        // Generate random mnemonic
        let mnemonic = MasterKey::generate_mnemonic()?;
        let mnemonic_str = mnemonic.to_string();

        let wallet = Self::from_mnemonic(&mnemonic_str, password, config)?;

        Ok((wallet, mnemonic_str))
    }

    /// Open an existing wallet
    pub fn open(password: &str, config: WalletConfig) -> WalletResult<Self> {
        let cache_path = config.data_dir.join("wallet.db");

        if !cache_path.exists() {
            return Err(LightWalletError::NotInitialized);
        }

        let cache = WalletCache::open(&cache_path, password)?;
        let master_key = cache.load_master_key(password)?;

        info!("Opened existing wallet");

        let params_cache = ParamsCache::new(config.data_dir.join("params"));

        // WalletCache contains rusqlite::Connection which is not Sync by design.
        // The Arc is still useful for shared ownership even in single-threaded async.
        #[allow(clippy::arc_with_non_send_sync)]
        Ok(Self {
            master_key: Arc::new(RwLock::new(Some(Arc::new(master_key)))),
            config,
            gsp_client: Arc::new(RwLock::new(None)),
            cache: Arc::new(cache),
            status: Arc::new(RwLock::new(WalletStatus::Disconnected)),
            balance: Arc::new(RwLock::new(WalletBalance::default())),
            params_cache,
            prover: Arc::new(RwLock::new(None)),
            note_store: Arc::new(RwLock::new(None)),
            scanner: Arc::new(RwLock::new(None)),
        })
    }

    /// Get wallet ID
    pub fn wallet_id(&self) -> WalletResult<WalletId> {
        let key_guard = self.master_key.read();
        let master_key = key_guard.as_ref().ok_or(LightWalletError::NotInitialized)?;
        Ok(master_key.wallet_id())
    }

    /// Get Ghost ID for receiving payments
    pub fn ghost_id(&self) -> WalletResult<String> {
        let key_guard = self.master_key.read();
        let master_key = key_guard.as_ref().ok_or(LightWalletError::NotInitialized)?;
        Ok(master_key.ghost_id().to_string())
    }

    /// Connect to a GSP
    pub async fn connect(&self, gsp_url: &str) -> WalletResult<()> {
        *self.status.write() = WalletStatus::Connecting;

        // Get master key for authentication
        let wallet_id = self.wallet_id()?;

        // Create GSP client
        let client = GspClient::connect(gsp_url, &wallet_id).await?;

        *self.gsp_client.write() = Some(client);
        *self.status.write() = WalletStatus::Connected;

        info!(gsp = gsp_url, "Connected to GSP");

        // Fetch initial balance (use server default max_k on connect)
        self.refresh_balance(None).await?;

        Ok(())
    }

    /// Disconnect from GSP
    pub async fn disconnect(&self) {
        let client = self.gsp_client.write().take();
        if let Some(client) = client {
            client.close().await;
        }
        *self.status.write() = WalletStatus::Disconnected;
        info!("Disconnected from GSP");
    }

    /// Get current connection status
    pub fn status(&self) -> WalletStatus {
        *self.status.read()
    }

    /// Get current balance
    pub fn balance(&self) -> WalletBalance {
        *self.balance.read()
    }

    /// Refresh balance from GSP
    ///
    /// `max_k` controls how many Silent Payment derivation indices to scan.
    /// Default (None) uses the server's default (typically 10).
    pub async fn refresh_balance(&self, max_k: Option<u32>) -> WalletResult<WalletBalance> {
        // Clone the client to release the lock before await
        let client = {
            let client_guard = self.gsp_client.read();
            client_guard
                .as_ref()
                .ok_or(LightWalletError::NotConnected)?
                .clone()
        };

        let balance = client.get_balance(max_k).await?;

        let wallet_balance = WalletBalance {
            confirmed: balance.confirmed,
            unconfirmed: balance.unconfirmed,
            locked: balance.locked,
        };

        *self.balance.write() = wallet_balance;

        // Update cache
        self.cache.update_balance(&wallet_balance)?;

        Ok(wallet_balance)
    }

    /// Get cached balance (doesn't require GSP connection)
    pub fn cached_balance(&self) -> WalletResult<WalletBalance> {
        self.cache.get_balance()
    }

    /// Get network
    pub fn network(&self) -> Network {
        self.config.network
    }

    /// Check if wallet is connected
    pub fn is_connected(&self) -> bool {
        *self.status.read() == WalletStatus::Connected
    }

    /// Get configuration
    pub fn config(&self) -> &WalletConfig {
        &self.config
    }

    /// Lock the wallet (clear master key from memory)
    pub fn lock(&self) {
        *self.master_key.write() = None;
        info!("Wallet locked");
    }

    /// Unlock the wallet
    pub fn unlock(&self, password: &str) -> WalletResult<()> {
        let master_key = self.cache.load_master_key(password)?;
        *self.master_key.write() = Some(Arc::new(master_key));
        info!("Wallet unlocked");
        Ok(())
    }

    /// Check if wallet is locked
    pub fn is_locked(&self) -> bool {
        self.master_key.read().is_none()
    }

    /// Ensure the NoteSpend prover is initialized, downloading MPC params if needed.
    ///
    /// This is a lazy operation: the first call downloads params from the configured
    /// ghost-pool node (or uses cached params), deserializes them, and initializes the
    /// Groth16 prover. Subsequent calls are fast (returns immediately if prover exists).
    pub async fn ensure_prover(&self) -> WalletResult<()> {
        // Fast path: prover already loaded
        if self.prover.read().is_some() {
            return Ok(());
        }

        let (host, port) = self
            .config
            .params_node
            .as_ref()
            .map(|(h, p)| (h.as_str(), *p))
            .unwrap_or(("127.0.0.1", 8080));

        let params_path = self.params_cache.ensure_params(host, port).await?;

        let prover = NoteSpendClientProver::from_params_file(&params_path, NOTE_TREE_DEPTH)?;
        info!("NoteSpend prover initialized from MPC params");

        *self.prover.write() = Some(prover);
        Ok(())
    }

    /// Check if NoteSpend MPC params are cached locally (no download needed)
    pub fn has_cached_params(&self) -> bool {
        self.params_cache.has_cached_params()
    }

    /// Generate a receive address
    pub fn generate_address(
        &self,
        address_type: crate::payments::AddressType,
    ) -> WalletResult<crate::payments::PaymentAddress> {
        let key_guard = self.master_key.read();
        let master_key = key_guard.as_ref().ok_or(LightWalletError::NotInitialized)?;
        crate::payments::generate_address(master_key, address_type)
    }

    /// Prepare a payment
    pub async fn prepare_payment(
        &self,
        recipient: &str,
        amount_sats: u64,
        use_wraith: bool,
    ) -> WalletResult<ghost_gsp_proto::PreparedPayment> {
        // Clone the Arc to release locks before await (Arc clone, not key clone)
        let master_key = {
            let key_guard = self.master_key.read();
            Arc::clone(key_guard.as_ref().ok_or(LightWalletError::NotInitialized)?)
        };

        let client = {
            let client_guard = self.gsp_client.read();
            client_guard
                .as_ref()
                .ok_or(LightWalletError::NotConnected)?
                .clone()
        };

        let request = if use_wraith {
            crate::payments::PaymentRequest::wraith(recipient, amount_sats)
        } else {
            crate::payments::PaymentRequest::ghost_pay(recipient, amount_sats)
        };

        crate::payments::prepare_payment(&client, &master_key, &request).await
    }

    /// Sign and submit a prepared payment
    pub async fn submit_payment(
        &self,
        prepared: &ghost_gsp_proto::PreparedPayment,
    ) -> WalletResult<String> {
        // Clone the Arc to release locks before await (Arc clone, not key clone)
        let master_key = {
            let key_guard = self.master_key.read();
            Arc::clone(key_guard.as_ref().ok_or(LightWalletError::NotInitialized)?)
        };

        let client = {
            let client_guard = self.gsp_client.read();
            client_guard
                .as_ref()
                .ok_or(LightWalletError::NotConnected)?
                .clone()
        };

        crate::payments::sign_and_submit(&client, &master_key, prepared).await
    }

    /// Send a payment (prepare, sign, and submit in one step)
    pub async fn send_payment(
        &self,
        recipient: &str,
        amount_sats: u64,
        use_wraith: bool,
    ) -> WalletResult<String> {
        let prepared = self
            .prepare_payment(recipient, amount_sats, use_wraith)
            .await?;
        self.submit_payment(&prepared).await
    }

    // =========================================================================
    // Confidential Note Scanning
    // =========================================================================

    /// Scan recent L2 transactions for confidential notes belonging to this wallet.
    ///
    /// Lazily initializes the scanner and note store on first call using keys
    /// derived from the master key. Fetches transactions from the GSP since the
    /// last scanned height, attempts to decrypt each one, and adds discovered
    /// notes to the store.
    pub async fn scan_recent_notes(&self) -> WalletResult<Vec<DiscoveredNote>> {
        // 1. Get master key
        let master_key = {
            let key_guard = self.master_key.read();
            Arc::clone(key_guard.as_ref().ok_or(LightWalletError::NotInitialized)?)
        };

        // 2. Get scan secret and spending key from master key
        let scan_secret = master_key.ghost_keys().scan_secret().clone();
        let spending_key = *master_key.confidential_spending_key();

        // 3. Lazy-init scanner if None
        {
            let mut scanner_guard = self.scanner.write();
            if scanner_guard.is_none() {
                *scanner_guard = Some(NoteScanner::new(scan_secret));
            }
        }

        // 4. Lazy-init note_store if None
        {
            let mut store_guard = self.note_store.write();
            if store_guard.is_none() {
                *store_guard = Some(NoteStore::new(spending_key));
            }
        }

        // 5. Read last_scanned_height before the await (no lock held across await)
        let since_height = {
            let scanner_guard = self.scanner.read();
            scanner_guard.as_ref().unwrap().last_scanned_height()
        };

        // 6. Get GSP client (clone to release lock before await)
        let client = {
            let client_guard = self.gsp_client.read();
            client_guard
                .as_ref()
                .ok_or(LightWalletError::NotConnected)?
                .clone()
        };

        // 7. Fetch recent L2 transactions since last scanned height
        let (txs, latest_height) = client
            .get_recent_l2_transactions(since_height)
            .await?;

        // 8. Scan transactions (re-acquire lock after await)
        let discovered = {
            let mut scanner_guard = self.scanner.write();
            let scanner = scanner_guard.as_mut().unwrap();
            scanner.scan_transactions(&txs)
        };

        // 9. Read last_seen_epoch from scanner (separate lock acquisition)
        let last_seen_epoch = {
            let scanner_guard = self.scanner.read();
            scanner_guard.as_ref().unwrap().last_seen_epoch()
        };

        // 10. Add discovered notes to store and handle epoch transitions
        {
            let mut store_guard = self.note_store.write();
            let store = store_guard.as_mut().unwrap();

            for note in &discovered {
                store.add_note(note.note.clone());
            }

            if last_seen_epoch > store.current_epoch() {
                store.handle_epoch_transition(last_seen_epoch);
            }
        }

        // 11. Update last scanned height
        {
            let mut scanner_guard = self.scanner.write();
            let scanner = scanner_guard.as_mut().unwrap();
            scanner.set_last_scanned_height(latest_height);
        }

        Ok(discovered)
    }

    /// Get the current confidential (L2) balance from the note store.
    ///
    /// Returns 0 if the note store has not been initialized (no scan performed yet).
    pub fn confidential_balance(&self) -> WalletResult<u64> {
        let store_guard = self.note_store.read();
        match store_guard.as_ref() {
            Some(store) => Ok(store.confidential_balance()),
            None => Ok(0),
        }
    }

    // =========================================================================
    // Label Management
    // =========================================================================

    /// Create a new label and return its index
    pub fn create_label(&self, name: &str) -> WalletResult<u32> {
        let mut dict = self
            .cache
            .load_label_dictionary()?
            .unwrap_or_else(ghost_keys::LabelDictionary::new);

        let index = dict.create(name);
        self.cache.save_label_dictionary(&dict)?;

        info!(name = %name, index = index, "Created label");
        Ok(index)
    }

    /// Rename an existing label
    pub fn rename_label(&self, index: u32, new_name: &str) -> WalletResult<bool> {
        let mut dict = self
            .cache
            .load_label_dictionary()?
            .unwrap_or_else(ghost_keys::LabelDictionary::new);

        let success = dict.rename(index, new_name);
        if success {
            self.cache.save_label_dictionary(&dict)?;
            info!(index = index, new_name = %new_name, "Renamed label");
        }

        Ok(success)
    }

    /// Delete a label
    pub fn delete_label(&self, index: u32) -> WalletResult<bool> {
        let mut dict = self
            .cache
            .load_label_dictionary()?
            .unwrap_or_else(ghost_keys::LabelDictionary::new);

        let success = dict.delete(index);
        if success {
            self.cache.save_label_dictionary(&dict)?;
            info!(index = index, "Deleted label");
        }

        Ok(success)
    }

    /// List all labels
    pub fn list_labels(&self) -> WalletResult<Vec<(u32, String)>> {
        let dict = self
            .cache
            .load_label_dictionary()?
            .unwrap_or_else(ghost_keys::LabelDictionary::new);

        Ok(dict
            .list()
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect())
    }

    /// Look up a label name by index
    pub fn lookup_label(&self, index: u32) -> WalletResult<Option<String>> {
        let dict = self
            .cache
            .load_label_dictionary()?
            .unwrap_or_else(ghost_keys::LabelDictionary::new);

        Ok(dict.lookup(index).map(|s| s.to_string()))
    }

    /// Check if a label index is orphaned (was deleted but may still be referenced)
    pub fn is_label_orphaned(&self, index: u32) -> WalletResult<bool> {
        let dict = self
            .cache
            .load_label_dictionary()?
            .unwrap_or_else(ghost_keys::LabelDictionary::new);

        Ok(dict.is_orphaned(index))
    }

    /// Export label dictionary for backup
    pub fn export_label_backup(&self) -> WalletResult<ghost_keys::LabelBackup> {
        let dict = self
            .cache
            .load_label_dictionary()?
            .unwrap_or_else(ghost_keys::LabelDictionary::new);

        Ok(dict.to_backup())
    }

    /// Import label dictionary from backup
    pub fn import_label_backup(&self, backup: ghost_keys::LabelBackup) -> WalletResult<()> {
        let dict = ghost_keys::LabelDictionary::from_backup(backup);
        self.cache.save_label_dictionary(&dict)?;
        info!("Imported label dictionary from backup");
        Ok(())
    }

    /// Get recent transactions from cache
    pub fn get_recent_transactions(
        &self,
        limit: u32,
    ) -> WalletResult<Vec<crate::state::CachedTransaction>> {
        self.cache.get_recent_transactions(limit)
    }

    /// Get cached locks
    pub fn get_cached_locks(&self) -> WalletResult<Vec<crate::state::CachedLock>> {
        self.cache.get_locks()
    }

    /// Save a lock to the local cache
    pub fn save_lock(&self, lock: &crate::state::CachedLock) -> WalletResult<()> {
        self.cache.save_lock(lock)
    }

    /// Get transactions by label
    pub fn get_transactions_by_label(
        &self,
        label_index: u32,
    ) -> WalletResult<Vec<crate::state::CachedTransaction>> {
        self.cache.get_transactions_by_label(label_index)
    }

    /// Update transaction label information
    pub fn update_transaction_label(
        &self,
        txid: &str,
        label_index: u32,
        decrypted_memo: Option<&str>,
    ) -> WalletResult<()> {
        self.cache
            .update_transaction_label(txid, label_index, decrypted_memo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_config() -> (WalletConfig, TempDir) {
        let temp = TempDir::new().unwrap();
        let config = WalletConfig {
            data_dir: temp.path().to_path_buf(),
            network: Network::Regtest,
            gsp_urls: vec![],
            auto_reconnect: false,
            reconnect_interval_secs: 5,
            params_node: None,
        };
        (config, temp)
    }

    #[test]
    fn test_generate_wallet() {
        let (config, _temp) = test_config();
        let (wallet, mnemonic) = LightWallet::generate("password123", config).unwrap();

        assert!(!mnemonic.is_empty());
        assert!(wallet.ghost_id().is_ok());
        assert!(!wallet.is_locked());
    }

    #[test]
    fn test_wallet_lock_unlock() {
        let (config, _temp) = test_config();
        let (wallet, _) = LightWallet::generate("password123", config).unwrap();

        assert!(!wallet.is_locked());

        wallet.lock();
        assert!(wallet.is_locked());

        wallet.unlock("password123").unwrap();
        assert!(!wallet.is_locked());
    }

    #[test]
    fn test_wallet_balance() {
        let balance = WalletBalance {
            confirmed: 100_000,
            unconfirmed: 50_000,
            locked: 25_000,
        };

        assert_eq!(balance.available(), 100_000);
        assert_eq!(balance.total(), 150_000);
    }
}
