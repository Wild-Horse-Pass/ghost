//! Android-specific FFI bindings via JNI
//!
//! Each function maps to a corresponding `external fun` declared in
//! `com.ghost.tap.RustBridge`.  Wallet instances are stored in a global
//! handle map keyed by opaque `jlong` IDs so Kotlin can reference them.

#[cfg(target_os = "android")]
use jni::{
    objects::{JClass, JString},
    sys::{jboolean, jdouble, jint, jlong, jstring, JNI_FALSE, JNI_TRUE},
    JNIEnv,
};

#[cfg(target_os = "android")]
use std::collections::HashMap;
#[cfg(target_os = "android")]
use std::sync::{atomic::{AtomicI64, Ordering}, Mutex};
#[cfg(target_os = "android")]
use once_cell::sync::Lazy;

// ---------------------------------------------------------------------------
// Wallet handle registry
// ---------------------------------------------------------------------------

#[cfg(target_os = "android")]
static NEXT_HANDLE: AtomicI64 = AtomicI64::new(1);

#[cfg(target_os = "android")]
static WALLETS: Lazy<Mutex<HashMap<jlong, crate::wallet::Wallet>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[cfg(target_os = "android")]
fn insert_wallet(wallet: crate::wallet::Wallet) -> jlong {
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::SeqCst);
    WALLETS.lock().unwrap().insert(handle, wallet);
    handle
}

// ---------------------------------------------------------------------------
// Library lifecycle
// ---------------------------------------------------------------------------

/// Initialize the library from Android
#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_ghost_tap_RustBridge_init(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    match crate::init() {
        Ok(_) => JNI_TRUE,
        Err(_) => JNI_FALSE,
    }
}

/// Get library version
#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_ghost_tap_RustBridge_version<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
) -> jstring {
    let output = env
        .new_string(crate::VERSION)
        .expect("Failed to create version string");
    output.into_raw()
}

// ---------------------------------------------------------------------------
// Wallet generation / import
// ---------------------------------------------------------------------------

/// Generate a new 12-word wallet.  Returns the mnemonic or null.
#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_ghost_tap_RustBridge_generateWallet12<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
) -> jstring {
    use crate::wallet::{Wallet, WordCount};
    use secrecy::ExposeSecret;

    match Wallet::generate(WordCount::Words12) {
        Ok((_, mnemonic)) => {
            let output = env
                .new_string(mnemonic.expose_secret())
                .expect("Failed to create mnemonic string");
            output.into_raw()
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Generate a new 24-word wallet.  Returns the mnemonic or null.
#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_ghost_tap_RustBridge_generateWallet24<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
) -> jstring {
    use crate::wallet::{Wallet, WordCount};
    use secrecy::ExposeSecret;

    match Wallet::generate(WordCount::Words24) {
        Ok((_, mnemonic)) => {
            let output = env
                .new_string(mnemonic.expose_secret())
                .expect("Failed to create mnemonic string");
            output.into_raw()
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Validate a mnemonic phrase
#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_ghost_tap_RustBridge_validateMnemonic(
    mut env: JNIEnv,
    _class: JClass,
    mnemonic: JString,
) -> jboolean {
    let mnemonic_str: String = match env.get_string(&mnemonic) {
        Ok(s) => s.into(),
        Err(_) => return JNI_FALSE,
    };

    if crate::wallet::validate_mnemonic(&mnemonic_str) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// Import a wallet from mnemonic.  Returns a handle (>0) or -1 on error.
#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_ghost_tap_RustBridge_importWallet(
    mut env: JNIEnv,
    _class: JClass,
    mnemonic: JString,
    passphrase: JString,
) -> jlong {
    use crate::wallet::Wallet;
    use secrecy::SecretString;

    let mnemonic_str: String = match env.get_string(&mnemonic) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };

    let pass_str: Option<String> = if passphrase.is_null() {
        None
    } else {
        match env.get_string(&passphrase) {
            Ok(s) => {
                let s: String = s.into();
                if s.is_empty() { None } else { Some(s) }
            }
            Err(_) => None,
        }
    };

    let secret_mnemonic = SecretString::new(mnemonic_str);
    let secret_pass = pass_str.map(SecretString::new);

    match Wallet::from_mnemonic(&secret_mnemonic, secret_pass.as_ref()) {
        Ok(wallet) => insert_wallet(wallet),
        Err(_) => -1,
    }
}

// ---------------------------------------------------------------------------
// Wallet operations (require handle)
// ---------------------------------------------------------------------------

/// Get wallet balance (confirmed, in satoshis).
#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_ghost_tap_RustBridge_getBalance(
    _env: JNIEnv,
    _class: JClass,
    wallet_handle: jlong,
) -> jlong {
    let wallets = WALLETS.lock().unwrap();
    match wallets.get(&wallet_handle) {
        Some(wallet) => wallet.balance() as jlong,
        None => 0,
    }
}

/// Generate a new receive address.  Returns the address or null.
#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_ghost_tap_RustBridge_newReceiveAddress<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
    wallet_handle: jlong,
) -> jstring {
    let mut wallets = WALLETS.lock().unwrap();
    match wallets.get_mut(&wallet_handle) {
        Some(wallet) => match wallet.new_receive_address() {
            Ok(addr) => {
                let output = env
                    .new_string(&addr)
                    .expect("Failed to create address string");
                output.into_raw()
            }
            Err(_) => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

/// Get transaction history as a JSON array string.
#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_ghost_tap_RustBridge_getTransactionHistory<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
    wallet_handle: jlong,
) -> jstring {
    let wallets = WALLETS.lock().unwrap();
    let json = match wallets.get(&wallet_handle) {
        Some(wallet) => {
            let history = wallet.get_history();
            serde_json::to_string(history).unwrap_or_else(|_| "[]".into())
        }
        None => "[]".into(),
    };

    let output = env
        .new_string(&json)
        .expect("Failed to create history string");
    output.into_raw()
}

/// Build and sign a transaction.  Returns raw tx hex or null on error.
#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_ghost_tap_RustBridge_createTransaction<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass,
    wallet_handle: jlong,
    to_address: JString,
    amount: jlong,
    fee_priority: jint,
) -> jstring {
    use crate::transaction::{FeePriority, TransactionBuilder, TransactionSigner};

    let addr: String = match env.get_string(&to_address) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };

    let priority = match fee_priority {
        0 => FeePriority::Low,
        1 => FeePriority::Medium,
        2 => FeePriority::High,
        _ => FeePriority::Medium,
    };

    let mut wallets = WALLETS.lock().unwrap();
    let wallet = match wallets.get_mut(&wallet_handle) {
        Some(w) => w,
        None => return std::ptr::null_mut(),
    };

    let change_addr = match wallet.new_change_address() {
        Ok(a) => a,
        Err(_) => return std::ptr::null_mut(),
    };

    let balance = wallet.balance_details();

    let unsigned = match TransactionBuilder::new()
        .add_output(addr, amount as u64)
        .fee_priority(priority)
        .change_address(change_addr)
        .build(wallet.get_utxos(), &balance)
    {
        Ok(tx) => tx,
        Err(_) => return std::ptr::null_mut(),
    };

    let signer = TransactionSigner::new();
    let signed = match signer.sign(&unsigned, |change, index| {
        wallet
            .get_private_key(change, index)
            .map_err(|e| crate::transaction::TransactionError::SigningFailed(e.to_string()))
    }) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let output = env
        .new_string(&signed.raw_tx)
        .expect("Failed to create tx string");
    output.into_raw()
}

/// Broadcast a signed transaction.  Returns txid or null.
///
/// NOTE: Without a live node connection this is a stub that returns the
/// transaction hash derived from the raw hex.  A real implementation would
/// call `client.send_raw_transaction()`.
#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_ghost_tap_RustBridge_broadcastTransaction<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass,
    raw_tx: JString,
) -> jstring {
    use sha2::{Digest, Sha256};

    let tx_hex: String = match env.get_string(&raw_tx) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };

    // Compute txid as double-SHA256 of the raw bytes (reversed).
    let raw_bytes = match hex::decode(&tx_hex) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let hash = Sha256::digest(&Sha256::digest(&raw_bytes));
    let txid = hex::encode(hash.iter().rev().copied().collect::<Vec<_>>());

    let output = env
        .new_string(&txid)
        .expect("Failed to create txid string");
    output.into_raw()
}

// ---------------------------------------------------------------------------
// PIN Authentication
// ---------------------------------------------------------------------------

/// Set a 6-digit PIN.
#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_ghost_tap_RustBridge_setPin(
    mut env: JNIEnv,
    _class: JClass,
    pin: JString,
) {
    let pin_str: String = match env.get_string(&pin) {
        Ok(s) => s.into(),
        Err(_) => return,
    };

    let pm = crate::wallet::auth::PinManager::new();
    let _ = pm.set_pin(&pin_str);
}

/// Verify PIN and unlock.  Returns 0=success, 1=wrong, 2=locked out.
#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_ghost_tap_RustBridge_verifyPinAndUnlock(
    mut env: JNIEnv,
    _class: JClass,
    pin: JString,
) -> jint {
    let pin_str: String = match env.get_string(&pin) {
        Ok(s) => s.into(),
        Err(_) => return 2,
    };

    let pm = crate::wallet::auth::PinManager::new();
    match pm.verify_pin(&pin_str) {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(_) => 2,
    }
}

/// Check if a PIN has been configured.
#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_ghost_tap_RustBridge_hasPin(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    if crate::wallet::auth::PinManager::new().has_pin() {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// Get remaining PIN attempts before lockout.
#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_ghost_tap_RustBridge_pinRemainingAttempts(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    crate::wallet::auth::PinManager::new().remaining_attempts() as jint
}

/// Authenticate using biometrics.  Returns true on success.
#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_ghost_tap_RustBridge_authenticateBiometric(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    // Biometric authentication is handled natively by Android's BiometricPrompt.
    // This FFI entry point is a callback target — if we reach here, the native
    // side has already validated the biometric.  Return true to indicate the
    // Rust-side state is unlocked.
    match crate::wallet::auth::PinManager::authenticate_biometric() {
        Ok(true) => JNI_TRUE,
        _ => JNI_FALSE,
    }
}

// ---------------------------------------------------------------------------
// NFC Limits
// ---------------------------------------------------------------------------

/// Check if an NFC payment amount is within the limit.
#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_ghost_tap_RustBridge_nfcCheckLimit(
    _env: JNIEnv,
    _class: JClass,
    amount: jlong,
) -> jboolean {
    let limits = crate::payment::limits::NfcLimits::new();
    if matches!(
        limits.check(amount as u64),
        crate::payment::limits::NfcLimitResult::Allowed
    ) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// Set exchange rate and return recalculated satoshi cap.
#[no_mangle]
#[cfg(target_os = "android")]
pub extern "system" fn Java_com_ghost_tap_RustBridge_nfcSetRate(
    _env: JNIEnv,
    _class: JClass,
    rate: jdouble,
) -> jlong {
    let limits = crate::payment::limits::NfcLimits::with_rate(rate);
    limits.max_amount_sats as jlong
}
