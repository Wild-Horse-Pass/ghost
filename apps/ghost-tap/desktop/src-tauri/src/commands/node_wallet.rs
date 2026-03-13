use crate::error::{AppError, AppResult};
use crate::state::AppState;
use tauri::State;

/// Encrypt the node wallet with a passphrase.
#[tauri::command]
pub async fn node_encrypt_wallet(
    state: State<'_, AppState>,
    passphrase: String,
) -> AppResult<()> {
    state.connection.encrypt_wallet(&passphrase).await?;
    Ok(())
}

/// Unlock the node wallet for a specified duration (seconds).
#[tauri::command]
pub async fn node_unlock_wallet(
    state: State<'_, AppState>,
    passphrase: String,
    timeout: u32,
) -> AppResult<()> {
    state
        .connection
        .wallet_passphrase(&passphrase, timeout)
        .await?;
    Ok(())
}

/// Lock the node wallet immediately.
#[tauri::command]
pub async fn node_lock_wallet(state: State<'_, AppState>) -> AppResult<()> {
    state.connection.wallet_lock_node().await?;
    Ok(())
}

/// Change the node wallet passphrase.
#[tauri::command]
pub async fn node_change_passphrase(
    state: State<'_, AppState>,
    old_passphrase: String,
    new_passphrase: String,
) -> AppResult<()> {
    state
        .connection
        .wallet_passphrase_change(&old_passphrase, &new_passphrase)
        .await?;
    Ok(())
}

/// Get node wallet info (encryption status, balance, tx count, etc.).
#[tauri::command]
pub async fn get_node_wallet_info(
    state: State<'_, AppState>,
) -> AppResult<serde_json::Value> {
    let info = state
        .connection
        .get_wallet_info()
        .await?
        .ok_or_else(|| AppError::from("Node wallet info not available (not in Full Node mode)"))?;
    Ok(info)
}
