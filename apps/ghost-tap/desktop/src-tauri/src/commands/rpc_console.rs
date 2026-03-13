use crate::error::{AppError, AppResult};
use crate::state::AppState;
use tauri::State;

/// Execute an arbitrary RPC command against the connected node.
#[tauri::command]
pub async fn execute_rpc(
    state: State<'_, AppState>,
    method: String,
    params_json: String,
) -> AppResult<serde_json::Value> {
    let params: serde_json::Value = serde_json::from_str(&params_json)
        .map_err(|e| AppError::from(format!("Invalid JSON params: {}", e)))?;

    let result = state.connection.rpc_call(&method, params).await?;
    Ok(result)
}
