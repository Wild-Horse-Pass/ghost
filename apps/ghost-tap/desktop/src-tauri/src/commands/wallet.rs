use crate::error::{AppError, AppResult};
use crate::state::{AppState, WalletInstance};
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

#[tauri::command]
pub fn create_wallet(state: State<'_, AppState>, word_count: u8) -> AppResult<String> {
    let wc = match word_count {
        24 => WordCount::Words24,
        _ => WordCount::Words12,
    };

    let (wallet, mnemonic) = Wallet::generate(wc)?;
    let mnemonic_str = mnemonic.expose_secret().clone();

    let instance = WalletInstance {
        wallet: Arc::new(std::sync::Mutex::new(wallet)),
        mnemonic,
        storage: None,
    };

    *state.wallet.lock() = Some(instance);
    Ok(mnemonic_str)
}

#[tauri::command]
pub fn restore_wallet(state: State<'_, AppState>, mnemonic: String) -> AppResult<()> {
    let secret = SecretString::new(mnemonic);
    let wallet = Wallet::from_mnemonic(&secret, None)?;

    let instance = WalletInstance {
        wallet: Arc::new(std::sync::Mutex::new(wallet)),
        mnemonic: secret,
        storage: None,
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
    wallet.unlock();
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
    state.wallet.lock().is_some()
}
