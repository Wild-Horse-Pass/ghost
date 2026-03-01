//! FFI bindings for iOS and Android
//!
//! Uses UniFFI proc-macros to generate Swift and Kotlin bindings.
//! The scaffolding is generated in lib.rs at the crate root.

#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "ios")]
mod ios;

use crate::storage::{WalletMeta, WalletStorage};
use crate::transaction::{FeePriority, TransactionBuilder, UnsignedTransaction};
use crate::wallet::{validate_mnemonic as core_validate_mnemonic, Wallet, WordCount};
use secrecy::{ExposeSecret, SecretString};
use std::sync::{Arc, Mutex};

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
    #[allow(dead_code)]
    storage: Option<Arc<Mutex<WalletStorage>>>,
}

impl WalletHandle {
    fn new(wallet: Wallet, mnemonic: String) -> Self {
        Self {
            wallet: Arc::new(Mutex::new(wallet)),
            mnemonic,
            storage: None,
        }
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
        self.with_wallet_mut(|w| {
            let priority = match fee_priority {
                0 => FeePriority::Low,
                1 => FeePriority::Medium,
                2 => FeePriority::High,
                _ => FeePriority::Medium,
            };

            let change_addr = w.new_change_address()?;
            let balance = w.balance_details();

            let unsigned = TransactionBuilder::new()
                .add_output(to_address, amount)
                .fee_priority(priority)
                .change_address(change_addr)
                .build(w.get_utxos(), &balance)?;

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

        let storage = WalletStorage::open(&db_path, &key)?;

        self.with_wallet(|w| -> Result<(), GhostTapFfiError> {
            // Save UTXOs
            storage.save_utxos(w.get_utxos())?;

            // Save history
            for entry in w.get_history() {
                storage.save_history_entry(entry)?;
            }

            // Save wallet metadata
            storage.save_wallet_meta(&WalletMeta {
                wallet_id: w.id.clone(),
                account_index: 0,
                next_receive_index: 0, // Would need accessor
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

        let storage = WalletStorage::open(&db_path, &key)?;

        self.with_wallet_mut(|w| -> Result<(), GhostTapFfiError> {
            // Load UTXOs
            let utxos = storage.load_utxos()?;
            for utxo in utxos {
                w.add_utxo(utxo);
            }

            // Load history
            let entries = storage.load_all_history()?;
            for entry in entries {
                w.add_history(entry);
            }

            Ok(())
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
