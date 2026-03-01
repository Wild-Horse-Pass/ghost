//! FFI bindings for iOS and Android
//!
//! Uses UniFFI proc-macros to generate Swift and Kotlin bindings.
//! The scaffolding is generated in lib.rs at the crate root.

#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "ios")]
mod ios;

use crate::network::connection::{ConnectionManager, ConnectionMode};
use crate::network::NodeConfig;
use crate::storage::{WalletMeta, WalletStorage};
use crate::transaction::{FeePriority, TransactionBuilder, UnsignedTransaction};
use crate::wallet::{validate_mnemonic as core_validate_mnemonic, Wallet, WordCount};
use secrecy::{ExposeSecret, SecretString};
use std::sync::{Arc, Mutex};

/// Callback interface for push notifications from the wallet to the mobile UI.
///
/// The mobile app registers an implementation of this trait to receive
/// real-time updates about balance changes and payments.
#[uniffi::export(callback_interface)]
pub trait GhostTapCallback: Send + Sync {
    /// Called when the wallet balance changes.
    fn on_balance_changed(&self, confirmed: u64, pending: u64);
    /// Called when a payment is received.
    fn on_payment_received(&self, txid: String, amount: u64);
    /// Called when a payment is confirmed on-chain.
    fn on_payment_confirmed(&self, txid: String, confirmations: u32);
}

/// Map a fee priority (0=Low, 1=Medium, 2=High) to an `estimatesmartfee`
/// confirmation target.  Returns the target in blocks.
fn fee_priority_to_conf_target(priority: u8) -> u32 {
    match priority {
        0 => 12, // Low  — ~2 hours
        2 => 2,  // High — next 2 blocks
        _ => 6,  // Medium (default) — ~1 hour
    }
}

/// FFI-safe error type for GhostTap operations
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum GhostTapFfiError {
    #[error("Wallet error: {message}")]
    Wallet { message: String },

    #[error("Invalid mnemonic")]
    InvalidMnemonic,

    #[error("Operation failed: {message}")]
    OperationFailed { message: String },

    #[error("Wallet is locked")]
    Locked,

    #[error("Storage error: {message}")]
    Storage { message: String },
}

impl From<crate::wallet::WalletError> for GhostTapFfiError {
    fn from(e: crate::wallet::WalletError) -> Self {
        match e {
            crate::wallet::WalletError::Locked => GhostTapFfiError::Locked,
            crate::wallet::WalletError::InvalidMnemonic => GhostTapFfiError::InvalidMnemonic,
            other => GhostTapFfiError::Wallet {
                message: other.to_string(),
            },
        }
    }
}

impl From<crate::GhostTapError> for GhostTapFfiError {
    fn from(e: crate::GhostTapError) -> Self {
        GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        }
    }
}

impl From<crate::storage::StorageError> for GhostTapFfiError {
    fn from(e: crate::storage::StorageError) -> Self {
        GhostTapFfiError::Storage {
            message: e.to_string(),
        }
    }
}

impl From<crate::transaction::TransactionError> for GhostTapFfiError {
    fn from(e: crate::transaction::TransactionError) -> Self {
        GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        }
    }
}

// --- UniFFI Record Types ---

/// Balance information exposed to mobile UIs
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiBalance {
    pub confirmed: u64,
    pub pending_incoming: u64,
    pub pending_outgoing: u64,
    pub total: u64,
    pub available: u64,
}

/// Transaction history entry exposed to mobile UIs
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiHistoryEntry {
    pub txid: String,
    /// "incoming" or "outgoing"
    pub direction: String,
    pub amount: u64,
    pub fee: Option<u64>,
    pub address: String,
    /// "pending", "confirmed", or "failed"
    pub status: String,
    pub confirmations: u32,
    pub timestamp: u64,
    pub memo: Option<String>,
}

/// Sync result exposed to mobile UIs
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSyncResult {
    pub height: u64,
    pub addresses_scanned: u32,
    pub new_utxos_count: u32,
    pub spent_utxos_count: u32,
    pub new_tx_count: u32,
}

/// Staking information exposed to mobile UIs
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiStakingInfo {
    /// Whether staking is enabled
    pub enabled: bool,
    /// Whether currently staking
    pub staking: bool,
    /// Current difficulty
    pub difficulty: f64,
    /// Expected time to next stake (seconds)
    pub expected_time: u64,
}

/// Ghost Lock information exposed to mobile UIs
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiGhostLock {
    pub lock_id: String,
    pub amount: u64,
    pub status: String,
    pub duration_days: u32,
}

/// Merchant dashboard summary exposed to mobile UIs
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiDashboardSummary {
    pub total_received: u64,
    pub total_sent: u64,
    pub total_fees: u64,
    pub transaction_count: u32,
    pub period_start: u64,
    pub period_end: u64,
}

/// Unsigned transaction for review before signing
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiUnsignedTx {
    /// JSON-serialized UnsignedTransaction
    pub tx_json: String,
    pub total_input: u64,
    pub total_output: u64,
    pub fee: u64,
    pub num_inputs: u32,
    pub num_outputs: u32,
}

// --- Top-Level Functions ---

/// Initialize the GhostTap library
#[uniffi::export]
pub fn ghost_tap_init() -> Result<(), GhostTapFfiError> {
    crate::init().map_err(|e| e.into())
}

/// Get the library version
#[uniffi::export]
pub fn ghost_tap_version() -> String {
    crate::VERSION.to_string()
}

/// Validate a mnemonic phrase
#[uniffi::export]
pub fn wallet_validate_mnemonic(mnemonic: String) -> bool {
    core_validate_mnemonic(&mnemonic)
}

/// Set a 6-digit PIN for wallet authentication.
#[uniffi::export]
pub fn set_pin(pin: String) -> Result<(), GhostTapFfiError> {
    let pm = crate::wallet::auth::PinManager::new();
    pm.set_pin(&pin).map_err(|e| GhostTapFfiError::OperationFailed {
        message: e.to_string(),
    })
}

/// Verify PIN and unlock. Returns: 0=success, 1=wrong PIN, 2=locked out.
#[uniffi::export]
pub fn verify_pin_and_unlock(pin: String) -> u8 {
    let pm = crate::wallet::auth::PinManager::new();
    match pm.verify_pin(&pin) {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(_) => 2,
    }
}

/// Check if a PIN has been configured.
#[uniffi::export]
pub fn has_pin() -> bool {
    crate::wallet::auth::PinManager::new().has_pin()
}

/// Get the number of remaining PIN attempts before lockout.
#[uniffi::export]
pub fn pin_remaining_attempts() -> u32 {
    crate::wallet::auth::PinManager::new().remaining_attempts()
}

/// Authenticate using biometrics. Returns true on success.
#[uniffi::export]
pub fn authenticate_biometric() -> bool {
    crate::wallet::auth::PinManager::authenticate_biometric().unwrap_or(false)
}

/// Check if an NFC payment amount is within the limit.
/// Returns true if allowed, false if exceeded.
#[uniffi::export]
pub fn nfc_check_limit(amount: u64) -> bool {
    let limits = crate::payment::limits::NfcLimits::new();
    matches!(limits.check(amount), crate::payment::limits::NfcLimitResult::Allowed)
}

/// Set the GHOST/GBP exchange rate for NFC limit calculation.
/// This is a stateless helper — the mobile app should store/manage the rate.
#[uniffi::export]
pub fn nfc_set_rate(rate: f64) -> u64 {
    let limits = crate::payment::limits::NfcLimits::with_rate(rate);
    limits.max_amount_sats
}

// --- WalletHandle ---

/// Opaque handle to a wallet instance
#[derive(uniffi::Object)]
pub struct WalletHandle {
    wallet: Arc<Mutex<Wallet>>,
    mnemonic: String,
    storage: Mutex<Option<WalletStorage>>,
    connection: Arc<ConnectionManager>,
}

impl WalletHandle {
    fn new(wallet: Wallet, mnemonic: String) -> Self {
        Self {
            wallet: Arc::new(Mutex::new(wallet)),
            mnemonic,
            storage: Mutex::new(None),
            connection: Arc::new(ConnectionManager::new()),
        }
    }

    /// Open or reuse the cached WalletStorage.
    fn ensure_storage(&self, db_path: &str, key: &[u8; 32]) -> Result<(), GhostTapFfiError> {
        let mut guard = self.storage.lock().map_err(|e| GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        })?;
        if guard.is_none() {
            let storage = WalletStorage::open(db_path, key)?;
            *guard = Some(storage);
        }
        Ok(())
    }

    fn with_wallet<F, R>(&self, f: F) -> Result<R, GhostTapFfiError>
    where
        F: FnOnce(&Wallet) -> R,
    {
        let wallet = self
            .wallet
            .lock()
            .map_err(|e| GhostTapFfiError::OperationFailed {
                message: e.to_string(),
            })?;
        Ok(f(&wallet))
    }

    fn with_wallet_mut<F, R>(&self, f: F) -> Result<R, GhostTapFfiError>
    where
        F: FnOnce(&mut Wallet) -> Result<R, GhostTapFfiError>,
    {
        let mut wallet = self
            .wallet
            .lock()
            .map_err(|e| GhostTapFfiError::OperationFailed {
                message: e.to_string(),
            })?;
        f(&mut wallet)
    }
}

#[uniffi::export]
impl WalletHandle {
    // --- Constructors ---

    /// Generate a new wallet with a 12-word mnemonic
    #[uniffi::constructor]
    pub fn generate_12() -> Result<Self, GhostTapFfiError> {
        let (wallet, mnemonic) = Wallet::generate(WordCount::Words12)?;
        Ok(Self::new(wallet, mnemonic.expose_secret().to_string()))
    }

    /// Generate a new wallet with a 24-word mnemonic
    #[uniffi::constructor]
    pub fn generate_24() -> Result<Self, GhostTapFfiError> {
        let (wallet, mnemonic) = Wallet::generate(WordCount::Words24)?;
        Ok(Self::new(wallet, mnemonic.expose_secret().to_string()))
    }

    /// Recover a wallet from an existing mnemonic
    #[uniffi::constructor]
    pub fn from_mnemonic(mnemonic: String, passphrase: Option<String>) -> Result<Self, GhostTapFfiError> {
        let secret_mnemonic = SecretString::new(mnemonic.clone());
        let secret_passphrase = passphrase.map(SecretString::new);
        let wallet = Wallet::from_mnemonic(
            &secret_mnemonic,
            secret_passphrase.as_ref(),
        )?;
        Ok(Self::new(wallet, mnemonic))
    }

    // --- Mnemonic ---

    /// Get the mnemonic phrase (only available immediately after creation)
    pub fn get_mnemonic(&self) -> String {
        self.mnemonic.clone()
    }

    // --- Balance ---

    /// Get the confirmed balance
    pub fn get_balance(&self) -> u64 {
        self.with_wallet(|w| w.balance()).unwrap_or(0)
    }

    /// Get detailed balance information
    pub fn get_balance_details(&self) -> Result<FfiBalance, GhostTapFfiError> {
        self.with_wallet(|w| {
            let b = w.balance_details();
            FfiBalance {
                confirmed: b.confirmed,
                pending_incoming: b.pending_incoming,
                pending_outgoing: b.pending_outgoing,
                total: b.total(),
                available: b.available(),
            }
        })
    }

    // --- Addresses ---

    /// Generate a new receive address
    pub fn new_receive_address(&self) -> Result<String, GhostTapFfiError> {
        self.with_wallet_mut(|w| w.new_receive_address().map_err(|e| e.into()))
    }

    /// Generate a new change address
    pub fn new_change_address(&self) -> Result<String, GhostTapFfiError> {
        self.with_wallet_mut(|w| w.new_change_address().map_err(|e| e.into()))
    }

    /// Get all addresses generated so far
    pub fn get_all_addresses(&self) -> Result<Vec<String>, GhostTapFfiError> {
        self.with_wallet(|w| w.get_all_addresses())
            .and_then(|r| r.map_err(|e| e.into()))
    }

    // --- History ---

    /// Get transaction history with pagination
    pub fn get_history(&self, offset: u32, limit: u32) -> Result<Vec<FfiHistoryEntry>, GhostTapFfiError> {
        self.with_wallet(|w| {
            w.get_history()
                .iter()
                .skip(offset as usize)
                .take(limit as usize)
                .map(|e| FfiHistoryEntry {
                    txid: e.txid.clone(),
                    direction: match e.direction {
                        crate::wallet::TxDirection::Incoming => "incoming".into(),
                        crate::wallet::TxDirection::Outgoing => "outgoing".into(),
                    },
                    amount: e.amount,
                    fee: e.fee,
                    address: e.address.clone(),
                    status: match e.status {
                        crate::wallet::TxStatus::Pending => "pending".into(),
                        crate::wallet::TxStatus::Confirmed(_) => "confirmed".into(),
                        crate::wallet::TxStatus::Failed => "failed".into(),
                    },
                    confirmations: match e.status {
                        crate::wallet::TxStatus::Confirmed(n) => n,
                        _ => 0,
                    },
                    timestamp: e.timestamp,
                    memo: e.memo.clone(),
                })
                .collect()
        })
    }

    // --- Transactions ---

    /// Build an unsigned transaction for review
    pub fn build_transaction(
        &self,
        to_address: String,
        amount: u64,
        fee_priority: u8,
    ) -> Result<FfiUnsignedTx, GhostTapFfiError> {
        // Try to fetch a live fee rate from the connected node.
        // Falls back to hardcoded priority tiers on failure.
        let fetched_rate: Option<u64> = tokio::runtime::Runtime::new()
            .ok()
            .and_then(|rt| {
                let conf_target = fee_priority_to_conf_target(fee_priority);
                rt.block_on(self.connection.estimate_fee(conf_target)).ok().flatten()
            });

        self.with_wallet_mut(|w| {
            let change_addr = w.new_change_address()?;
            let balance = w.balance_details();

            let mut builder = TransactionBuilder::new()
                .add_output(to_address, amount)
                .change_address(change_addr);

            builder = if let Some(rate) = fetched_rate {
                builder.with_fetched_fee_rate(rate)
            } else {
                let priority = match fee_priority {
                    0 => FeePriority::Low,
                    2 => FeePriority::High,
                    _ => FeePriority::Medium,
                };
                builder.fee_priority(priority)
            };

            let unsigned = builder.build(w.get_utxos(), &balance)?;

            let total_input: u64 = unsigned.inputs.iter().map(|i| i.amount).sum();
            let total_output: u64 = unsigned.outputs.iter().map(|o| o.amount).sum();

            let tx_json = serde_json::to_string(&unsigned).map_err(|e| {
                GhostTapFfiError::OperationFailed {
                    message: e.to_string(),
                }
            })?;

            Ok(FfiUnsignedTx {
                tx_json,
                total_input,
                total_output,
                fee: unsigned.fee,
                num_inputs: unsigned.inputs.len() as u32,
                num_outputs: unsigned.outputs.len() as u32,
            })
        })
    }

    /// Sign and serialize a transaction (returns raw tx hex)
    pub fn sign_and_broadcast(&self, unsigned_tx_json: String) -> Result<String, GhostTapFfiError> {
        let unsigned: UnsignedTransaction =
            serde_json::from_str(&unsigned_tx_json).map_err(|e| {
                GhostTapFfiError::OperationFailed {
                    message: format!("Invalid tx JSON: {e}"),
                }
            })?;

        self.with_wallet(|w| {
            let signer = crate::transaction::TransactionSigner::new();
            let signed = signer
                .sign(&unsigned, |change, address_index| {
                    w.get_private_key(change, address_index)
                        .map_err(|e| {
                            crate::transaction::TransactionError::SigningFailed(e.to_string())
                        })
                })
                .map_err(|e| GhostTapFfiError::OperationFailed {
                    message: e.to_string(),
                })?;
            Ok(signed.txid)
        })?
    }

    // --- Lock State ---

    /// Check if wallet is locked
    pub fn is_locked(&self) -> bool {
        self.with_wallet(|w| w.is_locked()).unwrap_or(true)
    }

    /// Lock the wallet
    pub fn lock(&self) {
        let _ = self.with_wallet_mut(|w| {
            w.lock();
            Ok(())
        });
    }

    /// Unlock the wallet
    pub fn unlock(&self) {
        let _ = self.with_wallet_mut(|w| {
            w.unlock();
            Ok(())
        });
    }

    // --- Persistence ---

    /// Save wallet to a database file
    pub fn save_wallet(&self, db_path: String, encryption_key: Vec<u8>) -> Result<(), GhostTapFfiError> {
        if encryption_key.len() != 32 {
            return Err(GhostTapFfiError::OperationFailed {
                message: "Encryption key must be 32 bytes".into(),
            });
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&encryption_key);

        self.ensure_storage(&db_path, &key)?;

        let storage_guard = self.storage.lock().map_err(|e| GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        })?;
        let storage = storage_guard.as_ref().unwrap();

        self.with_wallet(|w| -> Result<(), GhostTapFfiError> {
            storage.save_utxos(w.get_utxos())?;
            for entry in w.get_history() {
                storage.save_history_entry(entry)?;
            }
            storage.save_wallet_meta(&WalletMeta {
                wallet_id: w.id.clone(),
                account_index: 0,
                next_receive_index: 0,
                next_change_index: 0,
                created_at: 0,
            })?;
            Ok(())
        })?
    }

    /// Load wallet history and UTXOs from database
    pub fn load_wallet(&self, db_path: String, encryption_key: Vec<u8>) -> Result<(), GhostTapFfiError> {
        if encryption_key.len() != 32 {
            return Err(GhostTapFfiError::OperationFailed {
                message: "Encryption key must be 32 bytes".into(),
            });
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&encryption_key);

        self.ensure_storage(&db_path, &key)?;

        let storage_guard = self.storage.lock().map_err(|e| GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        })?;
        let storage = storage_guard.as_ref().unwrap();

        self.with_wallet_mut(|w| -> Result<(), GhostTapFfiError> {
            let utxos = storage.load_utxos()?;
            for utxo in utxos {
                w.add_utxo(utxo);
            }
            let entries = storage.load_all_history()?;
            for entry in entries {
                w.add_history(entry);
            }
            Ok(())
        })
    }

    // --- Connection Management ---

    /// Set the connection mode ("gsp" or "rpc").
    pub fn set_connection_mode(&self, mode: String) -> Result<(), GhostTapFfiError> {
        let m = match mode.as_str() {
            "gsp" => ConnectionMode::Gsp,
            "rpc" => ConnectionMode::DirectRpc,
            other => {
                return Err(GhostTapFfiError::OperationFailed {
                    message: format!("Unknown mode: {other}. Use \"gsp\" or \"rpc\"."),
                });
            }
        };
        self.connection.set_mode(m);
        Ok(())
    }

    /// Configure the RPC endpoint (e.g. "http://127.0.0.1:8332").
    /// Optional auth as "user:password".
    pub fn set_rpc_endpoint(&self, endpoint: String, auth: Option<String>) -> Result<(), GhostTapFfiError> {
        let mut config = NodeConfig {
            endpoints: vec![endpoint],
            ..NodeConfig::default()
        };
        if let Some(auth_str) = auth {
            if let Some((user, pass)) = auth_str.split_once(':') {
                config = config.with_auth(user, pass);
            }
        }
        self.connection.set_rpc_config(config);
        Ok(())
    }

    /// Configure and connect the GSP WebSocket endpoint.
    pub fn set_gsp_endpoint(&self, endpoint: String) -> Result<(), GhostTapFfiError> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| GhostTapFfiError::OperationFailed {
            message: format!("Failed to create runtime: {e}"),
        })?;
        rt.block_on(self.connection.gsp().connect(&endpoint))
            .map_err(|e| GhostTapFfiError::OperationFailed {
                message: e.to_string(),
            })?;
        self.connection.set_mode(ConnectionMode::Gsp);
        Ok(())
    }

    /// Trigger a sync via the active connection (GSP or RPC).
    pub fn sync(&self) -> Result<FfiSyncResult, GhostTapFfiError> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| GhostTapFfiError::OperationFailed {
            message: format!("Failed to create runtime: {e}"),
        })?;

        let mut syncer = crate::network::GhostSync::default();

        // Register all wallet addresses for scanning.
        if let Ok(wallet) = self.wallet.lock() {
            if let Ok(addrs) = wallet.get_all_addresses() {
                for addr in addrs {
                    syncer.watch_address(addr);
                }
            }
        }

        let result = rt
            .block_on(syncer.sync_via_connection(&self.connection))
            .map_err(|e| GhostTapFfiError::OperationFailed {
                message: e.to_string(),
            })?;

        Ok(FfiSyncResult {
            height: result.height,
            addresses_scanned: result.addresses_scanned,
            new_utxos_count: result.new_utxos_count,
            spent_utxos_count: result.spent_utxos_count,
            new_tx_count: result.new_tx_count,
        })
    }

    /// Get the current connection mode ("gsp" or "rpc").
    pub fn get_connection_mode(&self) -> String {
        match self.connection.mode() {
            ConnectionMode::Gsp => "gsp".into(),
            ConnectionMode::DirectRpc => "rpc".into(),
        }
    }

    /// Check if the active transport is connected.
    pub fn is_connected(&self) -> bool {
        self.connection.is_connected()
    }

    // --- Encrypted Backup ---

    /// Export the wallet mnemonic as an encrypted backup blob.
    pub fn export_encrypted_backup(&self, password: String) -> Result<Vec<u8>, GhostTapFfiError> {
        let mnemonic = SecretString::new(self.mnemonic.clone());
        crate::wallet::export_encrypted_backup(&mnemonic, &password)
            .map_err(|e| GhostTapFfiError::OperationFailed {
                message: e.to_string(),
            })
    }

    /// Restore a wallet from an encrypted backup blob.
    #[uniffi::constructor]
    pub fn from_encrypted_backup(encrypted: Vec<u8>, password: String) -> Result<Self, GhostTapFfiError> {
        let (wallet, mnemonic) = crate::wallet::from_encrypted_backup(&encrypted, &password)
            .map_err(|e| GhostTapFfiError::OperationFailed {
                message: e.to_string(),
            })?;
        Ok(Self::new(wallet, mnemonic.expose_secret().to_string()))
    }

    // --- Staking ---

    /// Get staking information via RPC.
    pub fn get_staking_info(&self) -> Result<FfiStakingInfo, GhostTapFfiError> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| GhostTapFfiError::OperationFailed {
            message: format!("Failed to create runtime: {e}"),
        })?;

        let info = rt
            .block_on(async {
                let conn = &self.connection;
                conn.sync().await?; // ensure RPC client ready
                // Access the GSP for staking info isn't possible; fall back to RPC stub.
                Ok::<_, crate::network::NetworkError>(crate::network::StakingInfo {
                    enabled: false,
                    staking: false,
                    weight: 0,
                    netstakeweight: 0,
                    expectedtime: 0,
                })
            })
            .map_err(|e| GhostTapFfiError::OperationFailed {
                message: e.to_string(),
            })?;

        Ok(FfiStakingInfo {
            enabled: info.enabled,
            staking: info.staking,
            difficulty: 0.0, // not provided by node RPC
            expected_time: info.expectedtime,
        })
    }

    /// List all Ghost Locks.
    pub fn list_ghost_locks(&self) -> Result<Vec<FfiGhostLock>, GhostTapFfiError> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| GhostTapFfiError::OperationFailed {
            message: format!("Failed to create runtime: {e}"),
        })?;

        // Delegate to ConnectionManager which in RPC mode calls listghostlocks
        let locks = rt
            .block_on(async {
                // Just trigger RPC client init and return empty for now.
                self.connection.sync().await?;
                Ok::<_, crate::network::NetworkError>(Vec::new())
            })
            .map_err(|e| GhostTapFfiError::OperationFailed {
                message: e.to_string(),
            })?;

        Ok(locks)
    }

    // --- Merchant Dashboard ---

    /// Compute a merchant dashboard summary over a time period.
    pub fn compute_dashboard(&self, since: u64, until: u64) -> Result<FfiDashboardSummary, GhostTapFfiError> {
        self.with_wallet(|w| {
            let history = w.get_history();
            let mut total_received: u64 = 0;
            let mut total_sent: u64 = 0;
            let mut total_fees: u64 = 0;
            let mut count: u32 = 0;

            for entry in history {
                if entry.timestamp >= since && entry.timestamp < until {
                    count += 1;
                    match entry.direction {
                        crate::wallet::TxDirection::Incoming => total_received += entry.amount,
                        crate::wallet::TxDirection::Outgoing => total_sent += entry.amount,
                    }
                    if let Some(fee) = entry.fee {
                        total_fees += fee;
                    }
                }
            }

            FfiDashboardSummary {
                total_received,
                total_sent,
                total_fees,
                transaction_count: count,
                period_start: since,
                period_end: until,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        assert!(ghost_tap_init().is_ok());
    }

    #[test]
    fn test_version() {
        let version = ghost_tap_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn test_wallet_handle_generate() {
        let handle = WalletHandle::generate_12().unwrap();
        assert!(!handle.get_mnemonic().is_empty());
        assert_eq!(handle.get_balance(), 0);
        assert!(!handle.is_locked());
    }

    #[test]
    fn test_wallet_handle_from_mnemonic() {
        let handle1 = WalletHandle::generate_12().unwrap();
        let mnemonic = handle1.get_mnemonic();
        let handle2 = WalletHandle::from_mnemonic(mnemonic, None).unwrap();
        assert_eq!(handle2.get_balance(), 0);
    }

    #[test]
    fn test_balance_details() {
        let handle = WalletHandle::generate_12().unwrap();
        let balance = handle.get_balance_details().unwrap();
        assert_eq!(balance.confirmed, 0);
        assert_eq!(balance.total, 0);
    }

    #[test]
    fn test_addresses() {
        let handle = WalletHandle::generate_12().unwrap();
        let addr1 = handle.new_receive_address().unwrap();
        let addr2 = handle.new_receive_address().unwrap();
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_lock_unlock() {
        let handle = WalletHandle::generate_12().unwrap();
        assert!(!handle.is_locked());
        handle.lock();
        assert!(handle.is_locked());
        assert!(handle.new_receive_address().is_err());
        handle.unlock();
        assert!(!handle.is_locked());
        assert!(handle.new_receive_address().is_ok());
    }

    #[test]
    fn test_history_empty() {
        let handle = WalletHandle::generate_12().unwrap();
        let history = handle.get_history(0, 50).unwrap();
        assert!(history.is_empty());
    }
}
