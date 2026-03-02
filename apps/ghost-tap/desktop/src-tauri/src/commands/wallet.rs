use crate::error::{AppError, AppResult};
use crate::state::{AppState, WalletInstance};
use ghost_tap_core::storage::WalletStorage;
use ghost_tap_core::wallet::{Wallet, WordCount};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use std::sync::Arc;
use tauri::State;


#[derive(Serialize)]
pub struct BalanceResponse {
    pub confirmed: u64,
    pub pending: u64,
}

#[derive(Serialize)]
pub struct HistoryEntryResponse {
    pub txid: String,
    pub direction: String,
    pub amount: u64,
    pub fee: Option<u64>,
    pub address: String,
    pub status: String,
    pub timestamp: u64,
    pub memo: Option<String>,
}

/// Default PIN used when no PIN is set yet (wallet setup before PIN is chosen).
const DEFAULT_PIN: &str = "000000";

fn open_storage(state: &AppState, pin: &str) -> AppResult<Arc<std::sync::Mutex<WalletStorage>>> {
    let key = AppState::derive_key(pin);
    let db_path = state.wallet_db_path();
    let path_str = db_path
        .to_str()
        .ok_or_else(|| AppError::from("Invalid database path"))?;
    let storage = WalletStorage::open(path_str, &key)?;
    Ok(Arc::new(std::sync::Mutex::new(storage)))
}

#[tauri::command]
pub fn create_wallet(state: State<'_, AppState>, word_count: u8) -> AppResult<String> {
    let wc = match word_count {
        24 => WordCount::Words24,
        _ => WordCount::Words12,
    };

    let (wallet, mnemonic) = Wallet::generate(wc)?;
    let mnemonic_str = mnemonic.expose_secret().clone();

    // Open storage with default PIN (user sets real PIN after setup)
    let pin = state.pin_hash.lock();
    let actual_pin = if pin.is_some() {
        // Shouldn't happen during first create, but handle it
        return Err("Wallet already exists".into());
    } else {
        DEFAULT_PIN
    };
    drop(pin);

    let storage = open_storage(&state, actual_pin)?;

    // Save mnemonic encrypted
    {
        let s = storage.lock().map_err(|e| AppError::from(e.to_string()))?;
        s.set_encrypted("mnemonic", mnemonic_str.as_bytes())?;
    }

    // Attach storage to wash queue for persistence
    {
        let mut washer = state
            .washer
            .lock()
            .map_err(|e| AppError::from(e.to_string()))?;
        washer.attach_storage(storage.clone());
    }

    let instance = WalletInstance {
        wallet: Arc::new(std::sync::Mutex::new(wallet)),
        mnemonic,
        storage,
    };

    *state.wallet.lock() = Some(instance);
    Ok(mnemonic_str)
}

#[tauri::command]
pub fn restore_wallet(state: State<'_, AppState>, mnemonic: String) -> AppResult<()> {
    let secret = SecretString::new(mnemonic.clone());
    let wallet = Wallet::from_mnemonic(&secret, None)?;

    let pin = state.pin_hash.lock();
    let actual_pin = if pin.is_some() {
        return Err("Wallet already exists".into());
    } else {
        DEFAULT_PIN
    };
    drop(pin);

    let storage = open_storage(&state, actual_pin)?;

    // Save mnemonic encrypted
    {
        let s = storage.lock().map_err(|e| AppError::from(e.to_string()))?;
        s.set_encrypted("mnemonic", mnemonic.as_bytes())?;
    }

    // Attach storage to wash queue for persistence
    {
        let mut washer = state
            .washer
            .lock()
            .map_err(|e| AppError::from(e.to_string()))?;
        washer.attach_storage(storage.clone());
    }

    let instance = WalletInstance {
        wallet: Arc::new(std::sync::Mutex::new(wallet)),
        mnemonic: secret,
        storage,
    };

    *state.wallet.lock() = Some(instance);
    Ok(())
}

#[tauri::command]
pub fn get_mnemonic(state: State<'_, AppState>) -> AppResult<String> {
    let guard = state.wallet.lock();
    let instance = guard.as_ref().ok_or("No wallet loaded")?;
    Ok(instance.mnemonic.expose_secret().clone())
}

#[tauri::command]
pub async fn get_balance(state: State<'_, AppState>) -> AppResult<BalanceResponse> {
    let (confirmed, pending) = state.connection.get_balance().await?;
    Ok(BalanceResponse {
        confirmed,
        pending,
    })
}

#[tauri::command]
pub fn new_receive_address(state: State<'_, AppState>) -> AppResult<String> {
    let guard = state.wallet.lock();
    let instance = guard.as_ref().ok_or("No wallet loaded")?;
    let mut wallet = instance
        .wallet
        .lock()
        .map_err(|e| AppError::from(e.to_string()))?;
    let addr = wallet.new_receive_address()?;
    Ok(addr)
}

#[tauri::command]
pub fn get_all_addresses(state: State<'_, AppState>) -> AppResult<Vec<String>> {
    let guard = state.wallet.lock();
    let instance = guard.as_ref().ok_or("No wallet loaded")?;
    let wallet = instance
        .wallet
        .lock()
        .map_err(|e| AppError::from(e.to_string()))?;
    let addrs = wallet.get_all_addresses()?;
    Ok(addrs)
}

#[tauri::command]
pub fn get_history(
    state: State<'_, AppState>,
    offset: u32,
    limit: u32,
) -> AppResult<Vec<HistoryEntryResponse>> {
    let guard = state.wallet.lock();
    let instance = guard.as_ref().ok_or("No wallet loaded")?;
    let wallet = instance
        .wallet
        .lock()
        .map_err(|e| AppError::from(e.to_string()))?;

    let entries = wallet.get_history();
    let start = (offset as usize).min(entries.len());
    let end = (start + limit as usize).min(entries.len());

    let result: Vec<HistoryEntryResponse> = entries[start..end]
        .iter()
        .map(|e| HistoryEntryResponse {
            txid: e.txid.clone(),
            direction: format!("{:?}", e.direction),
            amount: e.amount,
            fee: e.fee,
            address: e.address.clone(),
            status: format!("{:?}", e.status),
            timestamp: e.timestamp,
            memo: e.memo.clone(),
        })
        .collect();

    Ok(result)
}

#[tauri::command]
pub fn lock_wallet(state: State<'_, AppState>) -> AppResult<()> {
    let guard = state.wallet.lock();
    let instance = guard.as_ref().ok_or("No wallet loaded")?;
    let mut wallet = instance
        .wallet
        .lock()
        .map_err(|e| AppError::from(e.to_string()))?;
    wallet.lock();
    Ok(())
}

#[tauri::command]
pub fn unlock_wallet(state: State<'_, AppState>) -> AppResult<()> {
    let guard = state.wallet.lock();
    let instance = guard.as_ref().ok_or("No wallet loaded")?;
    let mut wallet = instance
        .wallet
        .lock()
        .map_err(|e| AppError::from(e.to_string()))?;
    wallet.unlock_with_pin("").map_err(|e| AppError::from(e.to_string()))?;
    Ok(())
}

#[tauri::command]
pub fn is_locked(state: State<'_, AppState>) -> bool {
    let guard = state.wallet.lock();
    match guard.as_ref() {
        Some(instance) => instance
            .wallet
            .lock()
            .map(|w| w.is_locked())
            .unwrap_or(true),
        None => true,
    }
}

#[tauri::command]
pub fn has_wallet(state: State<'_, AppState>) -> bool {
    // Check in-memory first
    if state.wallet.lock().is_some() {
        return true;
    }
    // Check on disk
    state.wallet_db_path().exists()
}

// --- PIN Management ---

#[tauri::command]
pub fn set_pin(state: State<'_, AppState>, pin: String) -> AppResult<()> {
    if pin.len() != 6 || !pin.chars().all(|c| c.is_ascii_digit()) {
        return Err("PIN must be exactly 6 digits".into());
    }

    let new_hash = AppState::hash_pin(&pin);
    let new_key = AppState::derive_key(&pin);

    // Re-encrypt the wallet database with the new PIN-derived key
    let guard = state.wallet.lock();
    if let Some(instance) = guard.as_ref() {
        // Read the mnemonic from the current storage
        let mnemonic_bytes = {
            let s = instance
                .storage
                .lock()
                .map_err(|e| AppError::from(e.to_string()))?;
            s.get("mnemonic")?
        };

        // Open a new storage with the new key and re-save
        let db_path = state.wallet_db_path();
        let path_str = db_path
            .to_str()
            .ok_or_else(|| AppError::from("Invalid database path"))?;
        let new_storage = WalletStorage::open(path_str, &new_key)?;
        new_storage.set_encrypted("mnemonic", &mnemonic_bytes)?;
    }
    drop(guard);

    // Save PIN hash to disk
    let pin_path = state.data_dir.join("pin.hash");
    std::fs::write(&pin_path, &new_hash)
        .map_err(|e| AppError::from(format!("Failed to save PIN: {e}")))?;

    *state.pin_hash.lock() = Some(new_hash);
    Ok(())
}

#[tauri::command]
pub fn verify_pin(state: State<'_, AppState>, pin: String) -> AppResult<bool> {
    let stored = state.pin_hash.lock();
    match stored.as_ref() {
        Some(hash) => Ok(&AppState::hash_pin(&pin) == hash),
        None => Ok(true), // No PIN set, always valid
    }
}

#[tauri::command]
pub fn has_pin(state: State<'_, AppState>) -> bool {
    state.pin_hash.lock().is_some()
}

/// Load wallet from disk using PIN for decryption.
#[tauri::command]
pub fn load_wallet(state: State<'_, AppState>, pin: String) -> AppResult<()> {
    // Verify PIN first
    {
        let stored = state.pin_hash.lock();
        if let Some(hash) = stored.as_ref() {
            if AppState::hash_pin(&pin) != *hash {
                return Err("Invalid PIN".into());
            }
        }
    }

    let storage = open_storage(&state, &pin)?;

    // Load mnemonic from encrypted storage
    let mnemonic_bytes = {
        let s = storage.lock().map_err(|e| AppError::from(e.to_string()))?;
        s.get("mnemonic")?
    };

    let mnemonic_str = String::from_utf8(mnemonic_bytes)
        .map_err(|e| AppError::from(format!("Invalid mnemonic data: {e}")))?;

    let secret = SecretString::new(mnemonic_str);
    let mut wallet = Wallet::from_mnemonic(&secret, None)?;

    // Restore UTXOs and history from storage
    {
        let s = storage.lock().map_err(|e| AppError::from(e.to_string()))?;
        if let Ok(utxos) = s.load_utxos() {
            for utxo in utxos {
                wallet.add_utxo(utxo);
            }
        }
        if let Ok(entries) = s.load_all_history() {
            for entry in entries {
                wallet.add_history(entry);
            }
        }
    }

    // Attach storage to the wash queue so it loads persisted requests
    {
        let mut washer = state
            .washer
            .lock()
            .map_err(|e| AppError::from(e.to_string()))?;
        washer.attach_storage(storage.clone());
    }

    let instance = WalletInstance {
        wallet: Arc::new(std::sync::Mutex::new(wallet)),
        mnemonic: secret,
        storage,
    };

    *state.wallet.lock() = Some(instance);
    Ok(())
}
