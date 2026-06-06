use crate::error::{AppError, AppResult};
use crate::state::AppState;
use tauri::State;

/// List unspent transaction outputs (UTXOs).
#[tauri::command]
pub async fn list_unspent(state: State<'_, AppState>) -> AppResult<Vec<serde_json::Value>> {
    let utxos = state.connection.list_unspent(0, 9999999).await?;
    Ok(utxos)
}

/// Lock or unlock a specific unspent output.
#[tauri::command]
pub async fn lock_unspent_output(
    state: State<'_, AppState>,
    txid: String,
    vout: u32,
    lock: bool,
) -> AppResult<bool> {
    let output = serde_json::json!({ "txid": txid, "vout": vout });
    // lock_unspent(unlock, outputs): unlock=true means unlock, unlock=false means lock
    let result = state.connection.lock_unspent(!lock, vec![output]).await?;
    Ok(result)
}

/// List all currently locked unspent outputs.
#[tauri::command]
pub async fn list_locked_outputs(state: State<'_, AppState>) -> AppResult<Vec<serde_json::Value>> {
    let locked = state.connection.list_lock_unspent().await?;
    Ok(locked)
}

/// Build, sign, and broadcast a transaction using specific inputs.
#[tauri::command]
pub async fn send_with_inputs(
    state: State<'_, AppState>,
    inputs: Vec<serde_json::Value>,
    address: String,
    amount: u64,
    fee_rate: Option<f64>,
) -> AppResult<String> {
    // Build outputs: amount is in satoshis, convert to BTC for the RPC
    let btc_amount = amount as f64 / 100_000_000.0;
    let outputs = serde_json::json!([{ address: btc_amount }]);

    // Build the funded transaction
    let funded = state
        .connection
        .build_with_inputs(inputs, outputs, fee_rate)
        .await?;

    // Extract the hex from the funded transaction result
    let hex = funded
        .get("hex")
        .and_then(|h| h.as_str())
        .ok_or_else(|| AppError::from("No hex in funded transaction result"))?;

    // Sign and broadcast
    let txid = state.connection.sign_and_send_raw(hex).await?;
    Ok(txid)
}
