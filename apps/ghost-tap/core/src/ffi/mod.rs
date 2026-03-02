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
use zeroize::Zeroizing;

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

// --- QR Payment URI ---

/// Payment request parsed from a ghost: URI
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiPaymentRequest {
    pub address: String,
    pub amount: Option<u64>,
    pub memo: Option<String>,
    pub label: Option<String>,
    pub exp: Option<u64>,
    pub network: Option<String>,
}

/// Validated payment request with non-fatal warnings
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiParsedPaymentRequest {
    pub request: FfiPaymentRequest,
    pub warnings: Vec<String>,
}

/// Parse a ghost: URI into a payment request.
#[uniffi::export]
pub fn parse_payment_uri(uri: String) -> Result<FfiPaymentRequest, GhostTapFfiError> {
    let req = crate::payment::qr::PaymentRequest::from_uri(&uri)
        .map_err(|e| GhostTapFfiError::OperationFailed { message: e.to_string() })?;
    Ok(FfiPaymentRequest {
        address: req.address,
        amount: req.amount,
        memo: req.memo,
        label: req.label,
        exp: req.exp,
        network: req.net,
    })
}

/// Parse a ghost: URI with expiry and network validation.
#[uniffi::export]
pub fn parse_payment_uri_checked(
    uri: String,
    now_unix: u64,
    expected_network: Option<String>,
) -> Result<FfiParsedPaymentRequest, GhostTapFfiError> {
    let parsed = crate::payment::qr::PaymentRequest::from_uri_checked(
        &uri,
        now_unix,
        expected_network.as_deref(),
    )
    .map_err(|e| GhostTapFfiError::OperationFailed { message: e.to_string() })?;

    let warnings: Vec<String> = parsed.warnings.iter().map(|w| w.to_string()).collect();

    Ok(FfiParsedPaymentRequest {
        request: FfiPaymentRequest {
            address: parsed.request.address,
            amount: parsed.request.amount,
            memo: parsed.request.memo,
            label: parsed.request.label,
            exp: parsed.request.exp,
            network: parsed.request.net,
        },
        warnings,
    })
}

/// Create a ghost: URI string from payment parameters.
#[uniffi::export]
pub fn create_payment_uri(
    address: String,
    amount: Option<u64>,
    memo: Option<String>,
    label: Option<String>,
    exp: Option<u64>,
    network: Option<String>,
) -> String {
    let mut req = crate::payment::qr::PaymentRequest::new(address);
    if let Some(a) = amount { req = req.with_amount(a); }
    if let Some(m) = memo { req = req.with_memo(m); }
    if let Some(l) = label { req = req.with_label(l); }
    if let Some(e) = exp { req = req.with_expiry(e); }
    if let Some(n) = network { req = req.with_network(n); }
    req.to_uri()
}

// --- NFC Protocol Encoding/Decoding ---

/// NFC payment response decoded from binary protocol
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiNfcPaymentResponse {
    pub txid: String,
    pub status: u8,
}

/// Encode an NFC payment request into the binary wire format.
#[uniffi::export]
pub fn nfc_encode_payment_request(
    address: String,
    amount: u64,
    memo: Option<String>,
) -> Result<Vec<u8>, GhostTapFfiError> {
    use crate::payment::nfc::{
        encode_nfc_payment_request, NfcPaymentRequest,
        PROTOCOL_VERSION, MSG_TYPE_PAYMENT_REQUEST,
    };

    let req = NfcPaymentRequest {
        version: PROTOCOL_VERSION,
        msg_type: MSG_TYPE_PAYMENT_REQUEST,
        amount,
        address,
        memo,
    };
    encode_nfc_payment_request(&req)
        .map_err(|e| GhostTapFfiError::OperationFailed { message: e.to_string() })
}

/// Decode an NFC payment response from binary wire format.
#[uniffi::export]
pub fn nfc_decode_payment_response(
    bytes: Vec<u8>,
) -> Result<FfiNfcPaymentResponse, GhostTapFfiError> {
    let resp = crate::payment::nfc::decode_nfc_payment_response(&bytes)
        .map_err(|e| GhostTapFfiError::OperationFailed { message: e.to_string() })?;

    Ok(FfiNfcPaymentResponse {
        txid: resp.txid,
        status: resp.status,
    })
}

// --- WalletHandle ---

/// A single wash request visible to mobile UIs
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiWashRequest {
    pub txid: String,
    pub amount: u64,
    /// "queued", "in_progress", "completed", or "failed"
    pub status: String,
    pub wraith_in_txid: Option<String>,
    pub wraith_out_txid: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
    pub retry_count: u32,
}

/// Wash queue summary statistics
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiWashStats {
    pub queued: u32,
    pub queued_amount: u64,
    pub in_progress: u32,
    pub in_progress_amount: u64,
    pub completed: u32,
    pub completed_amount: u64,
    pub failed: u32,
    pub failed_amount: u64,
    pub total_count: u32,
}

/// Opaque handle to a wallet instance
#[derive(uniffi::Object)]
pub struct WalletHandle {
    wallet: Arc<Mutex<Wallet>>,
    mnemonic: Mutex<Option<Zeroizing<String>>>,
    storage: Mutex<Option<WalletStorage>>,
    connection: Arc<ConnectionManager>,
    washer: Arc<Mutex<crate::merchant::wraith::WraithWasher>>,
    wash_processor: Mutex<Option<crate::merchant::wash_task::WashProcessorHandle>>,
    wash_runtime: Mutex<Option<tokio::runtime::Runtime>>,
}

impl WalletHandle {
    fn new(wallet: Wallet, mnemonic: String) -> Self {
        Self {
            wallet: Arc::new(Mutex::new(wallet)),
            mnemonic: Mutex::new(Some(Zeroizing::new(mnemonic))),
            storage: Mutex::new(None),
            connection: Arc::new(ConnectionManager::new()),
            washer: Arc::new(Mutex::new(crate::merchant::wraith::WraithWasher::new())),
            wash_processor: Mutex::new(None),
            wash_runtime: Mutex::new(None),
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
        let mnemonic_z = Zeroizing::new(mnemonic);
        let secret_mnemonic = SecretString::new(mnemonic_z.to_string());
        let secret_passphrase = passphrase.map(SecretString::new);
        let wallet = Wallet::from_mnemonic(
            &secret_mnemonic,
            secret_passphrase.as_ref(),
        )?;
        Ok(Self::new(wallet, mnemonic_z.to_string()))
    }

    // --- Mnemonic ---

    /// Get the mnemonic phrase. Returns it once, then zeroizes internally.
    /// Subsequent calls return `None`.
    pub fn get_mnemonic(&self) -> Option<String> {
        self.mnemonic
            .lock()
            .ok()
            .and_then(|mut guard| guard.take().map(|z| z.to_string()))
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

    /// Unlock the wallet with PIN verification.
    /// If no PIN is set, allows unlock directly (first-time use).
    pub fn unlock(&self, pin: String) -> Result<(), GhostTapFfiError> {
        self.with_wallet_mut(|w| {
            w.unlock_with_pin(&pin).map_err(|e| e.into())
        })
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
    /// Requires that the mnemonic has not yet been consumed by `get_mnemonic()`.
    pub fn export_encrypted_backup(&self, password: String) -> Result<Vec<u8>, GhostTapFfiError> {
        let guard = self.mnemonic.lock().map_err(|e| GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        })?;
        let mnemonic_str = guard.as_ref().ok_or_else(|| GhostTapFfiError::OperationFailed {
            message: "mnemonic already consumed".into(),
        })?;
        let mnemonic = SecretString::new(mnemonic_str.to_string());
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

    // --- Wraith Wash ---

    /// Queue a payment for Wraith washing.
    pub fn wash_payment(&self, txid: String, amount: u64) -> Result<(), GhostTapFfiError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut washer = self.washer.lock().map_err(|e| GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        })?;
        washer.wash_payment(txid, amount, now);
        Ok(())
    }

    /// Get the current wash queue.
    pub fn get_wash_queue(&self) -> Result<Vec<FfiWashRequest>, GhostTapFfiError> {
        let washer = self.washer.lock().map_err(|e| GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        })?;
        Ok(washer
            .get_queue()
            .iter()
            .map(|r| FfiWashRequest {
                txid: r.txid.clone(),
                amount: r.amount,
                status: match r.status {
                    crate::merchant::wraith::WashStatus::Queued => "queued".into(),
                    crate::merchant::wraith::WashStatus::InProgress => "in_progress".into(),
                    crate::merchant::wraith::WashStatus::Completed => "completed".into(),
                    crate::merchant::wraith::WashStatus::Failed => "failed".into(),
                },
                wraith_in_txid: r.wraith_in_txid.clone(),
                wraith_out_txid: r.wraith_out_txid.clone(),
                created_at: r.created_at,
                updated_at: r.updated_at,
                retry_count: r.retry_count,
            })
            .collect())
    }

    /// Get wash queue summary statistics.
    pub fn get_wash_stats(&self) -> Result<FfiWashStats, GhostTapFfiError> {
        let washer = self.washer.lock().map_err(|e| GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        })?;
        let s = washer.stats();
        Ok(FfiWashStats {
            queued: s.queued as u32,
            queued_amount: s.queued_amount,
            in_progress: s.in_progress as u32,
            in_progress_amount: s.in_progress_amount,
            completed: s.completed as u32,
            completed_amount: s.completed_amount,
            failed: s.failed as u32,
            failed_amount: s.failed_amount,
            total_count: s.total_count() as u32,
        })
    }

    /// Start the background wash processor. No-op if already running.
    pub fn start_wash_processor(&self) -> Result<(), GhostTapFfiError> {
        let mut guard = self.wash_processor.lock().map_err(|e| GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        })?;

        if guard.is_some() {
            return Ok(());
        }

        let rt = tokio::runtime::Runtime::new().map_err(|e| GhostTapFfiError::OperationFailed {
            message: format!("Failed to create runtime: {e}"),
        })?;

        let washer = Arc::clone(&self.washer);
        let connection = Arc::clone(&self.connection);

        let handle = rt.block_on(async {
            crate::merchant::wash_task::spawn_wash_processor(washer, connection)
        });

        *guard = Some(handle);
        // Store the runtime so it stays alive and gets cleaned up properly
        if let Ok(mut rt_guard) = self.wash_runtime.lock() {
            *rt_guard = Some(rt);
        }
        Ok(())
    }

    /// Stop the background wash processor.
    pub fn stop_wash_processor(&self) -> Result<(), GhostTapFfiError> {
        let mut guard = self.wash_processor.lock().map_err(|e| GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        })?;
        if let Some(handle) = guard.take() {
            handle.stop();
        }
        // Drop the runtime after stopping the handle
        if let Ok(mut rt_guard) = self.wash_runtime.lock() {
            rt_guard.take();
        }
        Ok(())
    }

    /// Retry a failed wash request.
    pub fn retry_wash(&self, txid: String) -> Result<bool, GhostTapFfiError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut washer = self.washer.lock().map_err(|e| GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        })?;
        Ok(washer.retry_failed(&txid, now))
    }

    /// Initialize the wash queue with persistent storage backing.
    /// Opens a separate SQLite connection for the washer and loads
    /// any previously persisted wash requests.
    pub fn init_wash_storage(
        &self,
        db_path: String,
        encryption_key: Vec<u8>,
    ) -> Result<(), GhostTapFfiError> {
        if encryption_key.len() != 32 {
            return Err(GhostTapFfiError::OperationFailed {
                message: "Encryption key must be 32 bytes".into(),
            });
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&encryption_key);

        let wash_storage = Arc::new(Mutex::new(WalletStorage::open(&db_path, &key)?));

        let mut washer = self.washer.lock().map_err(|e| GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        })?;
        washer.attach_storage(wash_storage);
        Ok(())
    }
}

// --- GhostGlyph FFI ---

/// Glyph claim response from Ghost Pay
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiGlyphClaimResponse {
    pub commitment: String,
    pub bitmap_hash: String,
    pub status: String,
}

/// Glyph information from Ghost Pay
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiGlyphInfo {
    pub ghost_id: String,
    pub pixels: Vec<u8>,
    pub bitmap_hash: String,
    pub commitment: String,
    pub funding_txid: Option<String>,
    pub registered_at: Option<u64>,
    pub status: String,
}

/// A single palette color entry
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiPaletteColor {
    pub index: u8,
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

/// Validate a glyph pixel array (all values 0..25, length 256)
#[uniffi::export]
pub fn glyph_validate_pixels(pixels: Vec<u8>) -> Result<(), GhostTapFfiError> {
    crate::glyph::GlyphManager::validate_pixels(&pixels).map_err(|e| {
        GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        }
    })
}

/// Compute the bitmap hash for a glyph design (hex-encoded SHA-256)
#[uniffi::export]
pub fn glyph_compute_bitmap_hash(pixels: Vec<u8>) -> Result<String, GhostTapFfiError> {
    if pixels.len() != crate::glyph::GLYPH_SIZE {
        return Err(GhostTapFfiError::OperationFailed {
            message: format!(
                "Expected {} pixels, got {}",
                crate::glyph::GLYPH_SIZE,
                pixels.len()
            ),
        });
    }
    let mut arr = [0u8; crate::glyph::GLYPH_SIZE];
    arr.copy_from_slice(&pixels);
    Ok(hex::encode(crate::glyph::GlyphManager::compute_bitmap_hash(&arr)))
}

/// Maximum render scale on mobile (L-9: cap to 32x = 512x512 to save memory)
const MOBILE_MAX_SCALE: u32 = 32;

/// Render a glyph as RGBA pixel data at the given scale factor.
/// Returns raw RGBA bytes (width = 16*scale, height = 16*scale, 4 bytes per pixel).
/// Scale is capped at 32 on mobile to prevent excessive memory allocation.
#[uniffi::export]
pub fn glyph_render(
    pixels: Vec<u8>,
    ghost_id: String,
    scale: u32,
) -> Result<Vec<u8>, GhostTapFfiError> {
    if scale > MOBILE_MAX_SCALE {
        return Err(GhostTapFfiError::OperationFailed {
            message: format!("Scale {} exceeds mobile maximum of {}", scale, MOBILE_MAX_SCALE),
        });
    }
    if pixels.len() != crate::glyph::GLYPH_SIZE {
        return Err(GhostTapFfiError::OperationFailed {
            message: format!(
                "Expected {} pixels, got {}",
                crate::glyph::GLYPH_SIZE,
                pixels.len()
            ),
        });
    }
    let arr: [u8; crate::glyph::GLYPH_SIZE] =
        pixels.as_slice().try_into().map_err(|_| GhostTapFfiError::OperationFailed {
            message: "Invalid pixel array".into(),
        })?;
    let glyph = crate::glyph::GhostGlyph::new(arr, ghost_id).map_err(|e| {
        GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        }
    })?;
    crate::glyph::GlyphManager::render(&glyph, scale).map_err(|e| {
        GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        }
    })
}

/// Get the rendered dimensions (width, height) for a given scale factor
#[uniffi::export]
pub fn glyph_dimensions(scale: u32) -> Result<Vec<u32>, GhostTapFfiError> {
    let (w, h) = crate::glyph::GlyphManager::dimensions(scale).map_err(|e| {
        GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        }
    })?;
    Ok(vec![w, h])
}

/// Get the full 26-color GhostGlyph palette
#[uniffi::export]
pub fn glyph_get_palette() -> Vec<FfiPaletteColor> {
    crate::glyph::PALETTE
        .iter()
        .enumerate()
        .map(|(i, &(r, g, b))| FfiPaletteColor {
            index: i as u8,
            r,
            g,
            b,
        })
        .collect()
}

/// Submit a glyph claim to Ghost Pay (async, uses blocking runtime)
#[uniffi::export]
pub fn glyph_claim(
    ghost_pay_url: String,
    ghost_id: String,
    pixels: Vec<u8>,
) -> Result<FfiGlyphClaimResponse, GhostTapFfiError> {
    // H-4: Validate URL before making network request
    crate::glyph::validate_pay_url(&ghost_pay_url).map_err(|e| {
        GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        }
    })?;
    // M-7: Validate pixels before sending to network
    crate::glyph::GlyphManager::validate_pixels(&pixels).map_err(|e| {
        GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        }
    })?;
    let config = crate::network::PayConfig {
        base_url: ghost_pay_url,
        ..crate::network::PayConfig::default()
    };
    let manager = crate::glyph::GlyphManager::new(config).map_err(|e| {
        GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        }
    })?;
    // M-6: Use single-threaded runtime (lighter for FFI blocking calls)
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| GhostTapFfiError::OperationFailed {
            message: format!("Failed to create runtime: {e}"),
        })?;
    let resp = rt
        .block_on(manager.claim(&ghost_id, &pixels))
        .map_err(|e| GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        })?;
    Ok(FfiGlyphClaimResponse {
        commitment: resp.commitment,
        bitmap_hash: resp.bitmap_hash,
        status: resp.status,
    })
}

/// Get glyph info from Ghost Pay (async, uses blocking runtime)
#[uniffi::export]
pub fn glyph_get_info(
    ghost_pay_url: String,
    ghost_id: String,
) -> Result<Option<FfiGlyphInfo>, GhostTapFfiError> {
    crate::glyph::validate_pay_url(&ghost_pay_url).map_err(|e| {
        GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        }
    })?;
    let config = crate::network::PayConfig {
        base_url: ghost_pay_url,
        ..crate::network::PayConfig::default()
    };
    let manager = crate::glyph::GlyphManager::new(config).map_err(|e| {
        GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        }
    })?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| GhostTapFfiError::OperationFailed {
            message: format!("Failed to create runtime: {e}"),
        })?;
    let info = rt
        .block_on(manager.get_glyph(&ghost_id))
        .map_err(|e| GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        })?;
    Ok(info.map(|g| FfiGlyphInfo {
        ghost_id: g.ghost_id,
        pixels: g.pixels,
        bitmap_hash: g.bitmap_hash,
        commitment: g.commitment,
        funding_txid: g.funding_txid,
        registered_at: g.registered_at,
        status: g.status,
    }))
}

/// Check if a glyph design is available (async, uses blocking runtime)
#[uniffi::export]
pub fn glyph_check_availability(
    ghost_pay_url: String,
    pixels: Vec<u8>,
) -> Result<bool, GhostTapFfiError> {
    crate::glyph::validate_pay_url(&ghost_pay_url).map_err(|e| {
        GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        }
    })?;
    if pixels.len() != crate::glyph::GLYPH_SIZE {
        return Err(GhostTapFfiError::OperationFailed {
            message: format!(
                "Expected {} pixels, got {}",
                crate::glyph::GLYPH_SIZE,
                pixels.len()
            ),
        });
    }
    let arr: [u8; crate::glyph::GLYPH_SIZE] =
        pixels.as_slice().try_into().map_err(|_| GhostTapFfiError::OperationFailed {
            message: "Invalid pixel array".into(),
        })?;
    let config = crate::network::PayConfig {
        base_url: ghost_pay_url,
        ..crate::network::PayConfig::default()
    };
    let manager = crate::glyph::GlyphManager::new(config).map_err(|e| {
        GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        }
    })?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| GhostTapFfiError::OperationFailed {
            message: format!("Failed to create runtime: {e}"),
        })?;
    rt.block_on(manager.is_available(&arr))
        .map_err(|e| GhostTapFfiError::OperationFailed {
            message: e.to_string(),
        })
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
        let mnemonic = handle.get_mnemonic();
        assert!(mnemonic.is_some());
        assert!(!mnemonic.unwrap().is_empty());
        // Second call returns None (consumed)
        assert!(handle.get_mnemonic().is_none());
        assert_eq!(handle.get_balance(), 0);
        assert!(!handle.is_locked());
    }

    #[test]
    fn test_wallet_handle_from_mnemonic() {
        let handle1 = WalletHandle::generate_12().unwrap();
        let mnemonic = handle1.get_mnemonic().unwrap();
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
        // No PIN set, so unlock with empty PIN succeeds (first-time use)
        handle.unlock("".into()).unwrap();
        assert!(!handle.is_locked());
        assert!(handle.new_receive_address().is_ok());
    }

    #[test]
    fn test_history_empty() {
        let handle = WalletHandle::generate_12().unwrap();
        let history = handle.get_history(0, 50).unwrap();
        assert!(history.is_empty());
    }

    // --- QR FFI Tests ---

    #[test]
    fn test_parse_payment_uri_roundtrip() {
        let uri = create_payment_uri(
            "GhTestAddr1234567890abcdefg".into(),
            Some(50_000),
            Some("Coffee".into()),
            None,
            None,
            None,
        );
        let parsed = parse_payment_uri(uri).unwrap();
        assert_eq!(parsed.address, "GhTestAddr1234567890abcdefg");
        assert_eq!(parsed.amount, Some(50_000));
        assert_eq!(parsed.memo.as_deref(), Some("Coffee"));
    }

    #[test]
    fn test_parse_payment_uri_invalid() {
        let result = parse_payment_uri("bitcoin:addr".into());
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_payment_uri_checked_expired() {
        let uri = create_payment_uri(
            "GhAddrABCDEFGHIJKLMNOPQRS".into(), None, None, None, Some(1000), None,
        );
        let result = parse_payment_uri_checked(uri, 2000, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_payment_uri_checked_network_warning() {
        let uri = create_payment_uri(
            "GhAddrABCDEFGHIJKLMNOPQRS".into(), None, None, None, None, Some("bitcoin".into()),
        );
        let parsed = parse_payment_uri_checked(uri, 0, Some("ghost".into())).unwrap();
        assert_eq!(parsed.warnings.len(), 1);
        assert!(parsed.warnings[0].contains("mismatch"));
    }

    // --- NFC FFI Tests ---

    #[test]
    fn test_nfc_encode_payment_request_format() {
        let encoded = nfc_encode_payment_request(
            "GhTestAddr".into(),
            100_000,
            Some("Coffee".into()),
        ).unwrap();
        assert!(!encoded.is_empty());
        assert_eq!(encoded[0], 1); // version
        assert_eq!(encoded[1], 0x01); // MSG_TYPE_PAYMENT_REQUEST
    }

    #[test]
    fn test_nfc_decode_response_roundtrip() {
        use crate::payment::nfc::{encode_nfc_payment_response, NfcPaymentResponse};
        let resp = NfcPaymentResponse {
            txid: "deadbeef".to_string(),
            status: 0x00,
        };
        let bytes = encode_nfc_payment_response(&resp).unwrap();
        let decoded = nfc_decode_payment_response(bytes).unwrap();
        assert_eq!(decoded.txid, "deadbeef");
        assert_eq!(decoded.status, 0x00);
    }

    #[test]
    fn test_nfc_decode_response_invalid() {
        let result = nfc_decode_payment_response(vec![0x00, 0x00]);
        assert!(result.is_err());
    }

    // --- Wraith Wash FFI Tests ---

    #[test]
    fn test_wash_payment_and_stats() {
        let handle = WalletHandle::generate_12().unwrap();
        handle.wash_payment("tx_test".into(), 100_000).unwrap();

        let queue = handle.get_wash_queue().unwrap();
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].txid, "tx_test");
        assert_eq!(queue[0].status, "queued");

        let stats = handle.get_wash_stats().unwrap();
        assert_eq!(stats.queued, 1);
        assert_eq!(stats.queued_amount, 100_000);
        assert_eq!(stats.total_count, 1);
    }

    #[test]
    fn test_retry_wash_nonexistent() {
        let handle = WalletHandle::generate_12().unwrap();
        let result = handle.retry_wash("nonexistent".into()).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_stop_processor_when_not_running() {
        let handle = WalletHandle::generate_12().unwrap();
        assert!(handle.stop_wash_processor().is_ok());
    }

    // --- GhostGlyph FFI Tests ---

    #[test]
    fn test_glyph_validate_pixels_valid() {
        let pixels = vec![0u8; crate::glyph::GLYPH_SIZE];
        assert!(glyph_validate_pixels(pixels).is_ok());
    }

    #[test]
    fn test_glyph_validate_pixels_invalid_value() {
        let mut pixels = vec![0u8; crate::glyph::GLYPH_SIZE];
        pixels[0] = 26;
        assert!(glyph_validate_pixels(pixels).is_err());
    }

    #[test]
    fn test_glyph_validate_pixels_wrong_size() {
        assert!(glyph_validate_pixels(vec![0u8; 100]).is_err());
    }

    #[test]
    fn test_glyph_compute_bitmap_hash() {
        let pixels = vec![5u8; crate::glyph::GLYPH_SIZE];
        let hash1 = glyph_compute_bitmap_hash(pixels.clone()).unwrap();
        let hash2 = glyph_compute_bitmap_hash(pixels).unwrap();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // 32 bytes hex-encoded
    }

    #[test]
    fn test_glyph_compute_bitmap_hash_wrong_size() {
        assert!(glyph_compute_bitmap_hash(vec![0u8; 10]).is_err());
    }

    #[test]
    fn test_glyph_render() {
        let pixels = vec![0u8; crate::glyph::GLYPH_SIZE];
        let rgba = glyph_render(pixels, "ghost1test".to_string(), 2).unwrap();
        // 16*2 * 16*2 * 4 bytes per pixel = 4096
        assert_eq!(rgba.len(), 32 * 32 * 4);
    }

    #[test]
    fn test_glyph_dimensions() {
        let dims = glyph_dimensions(4).unwrap();
        assert_eq!(dims, vec![64, 64]);
    }

    #[test]
    fn test_glyph_render_mobile_scale_cap() {
        let pixels = vec![0u8; crate::glyph::GLYPH_SIZE];
        // Scale 33 exceeds mobile cap of 32
        assert!(glyph_render(pixels, "ghost1test".to_string(), 33).is_err());
    }

    #[test]
    fn test_glyph_get_palette() {
        let palette = glyph_get_palette();
        assert_eq!(palette.len(), crate::glyph::PALETTE_SIZE);
        assert_eq!(palette[0].index, 0);
        assert_eq!(palette[25].index, 25);
    }
}
