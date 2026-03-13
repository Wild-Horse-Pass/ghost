use crate::error::AppResult;
use crate::state::AppState;
use tauri::State;

/// Decode a PSBT and return its structure.
#[tauri::command]
pub async fn decode_psbt(
    state: State<'_, AppState>,
    psbt: String,
) -> AppResult<serde_json::Value> {
    let decoded = state.connection.decode_psbt(&psbt).await?;
    Ok(decoded)
}

/// Analyze a PSBT for completeness and signing status.
#[tauri::command]
pub async fn analyze_psbt(
    state: State<'_, AppState>,
    psbt: String,
) -> AppResult<serde_json::Value> {
    let analysis = state.connection.analyze_psbt(&psbt).await?;
    Ok(analysis)
}

/// Sign a PSBT with wallet keys (walletprocesspsbt).
#[tauri::command]
pub async fn sign_psbt(
    state: State<'_, AppState>,
    psbt: String,
) -> AppResult<serde_json::Value> {
    let signed = state.connection.wallet_process_psbt(&psbt).await?;
    Ok(signed)
}

/// Combine multiple partial PSBTs into one.
#[tauri::command]
pub async fn combine_psbts(
    state: State<'_, AppState>,
    psbts: Vec<String>,
) -> AppResult<String> {
    let combined = state.connection.combine_psbt(psbts).await?;
    Ok(combined)
}

/// Finalize a PSBT (make it ready for broadcast).
#[tauri::command]
pub async fn finalize_psbt(
    state: State<'_, AppState>,
    psbt: String,
) -> AppResult<serde_json::Value> {
    let finalized = state.connection.finalize_psbt(&psbt).await?;
    Ok(finalized)
}

/// Finalize and broadcast a PSBT, returning the txid.
#[tauri::command]
pub async fn broadcast_psbt(
    state: State<'_, AppState>,
    psbt: String,
) -> AppResult<String> {
    let txid = state.connection.broadcast_psbt(&psbt).await?;
    Ok(txid)
}
