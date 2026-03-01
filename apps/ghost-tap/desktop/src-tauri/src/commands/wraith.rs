use crate::error::{AppError, AppResult};
use crate::state::AppState;
use ghost_tap_core::merchant::wash_task::spawn_wash_processor;
use serde::Serialize;
use tauri::State;

#[derive(Serialize)]
pub struct WashRequestResponse {
    pub txid: String,
    pub amount: u64,
    pub status: String,
    pub wraith_in_txid: Option<String>,
    pub wraith_out_txid: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
    pub retry_count: u32,
}

#[derive(Serialize)]
pub struct WashStatsResponse {
    pub queued_count: usize,
    pub queued_amount: u64,
    pub in_progress_count: usize,
    pub in_progress_amount: u64,
    pub completed_count: usize,
    pub completed_amount: u64,
    pub failed_count: usize,
    pub failed_amount: u64,
    pub total_count: usize,
}

#[tauri::command]
pub fn wash_payment(state: State<'_, AppState>, txid: String, amount: u64) -> AppResult<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut washer = state
        .washer
        .lock()
        .map_err(|e| AppError::from(e.to_string()))?;
    washer.wash_payment(txid, amount, now);
    Ok(())
}

#[tauri::command]
pub fn get_wash_queue(state: State<'_, AppState>) -> AppResult<Vec<WashRequestResponse>> {
    let washer = state
        .washer
        .lock()
        .map_err(|e| AppError::from(e.to_string()))?;

    let queue: Vec<WashRequestResponse> = washer
        .get_queue()
        .iter()
        .map(|r| WashRequestResponse {
            txid: r.txid.clone(),
            amount: r.amount,
            status: r.status.to_string(),
            wraith_in_txid: r.wraith_in_txid.clone(),
            wraith_out_txid: r.wraith_out_txid.clone(),
            created_at: r.created_at,
            updated_at: r.updated_at,
            retry_count: r.retry_count,
        })
        .collect();

    Ok(queue)
}

#[tauri::command]
pub fn get_wash_stats(state: State<'_, AppState>) -> AppResult<WashStatsResponse> {
    let washer = state
        .washer
        .lock()
        .map_err(|e| AppError::from(e.to_string()))?;
    let stats = washer.stats();

    Ok(WashStatsResponse {
        queued_count: stats.queued,
        queued_amount: stats.queued_amount,
        in_progress_count: stats.in_progress,
        in_progress_amount: stats.in_progress_amount,
        completed_count: stats.completed,
        completed_amount: stats.completed_amount,
        failed_count: stats.failed,
        failed_amount: stats.failed_amount,
        total_count: stats.total_count(),
    })
}

#[tauri::command]
pub fn start_wash_processor(state: State<'_, AppState>) -> AppResult<()> {
    let mut handle_guard = state.wash_handle.lock();
    if handle_guard.is_some() {
        return Err("Wash processor already running".into());
    }

    let handle = spawn_wash_processor(state.washer.clone(), state.connection.clone());
    *handle_guard = Some(handle);
    Ok(())
}

#[tauri::command]
pub fn stop_wash_processor(state: State<'_, AppState>) -> AppResult<()> {
    let mut handle_guard = state.wash_handle.lock();
    if let Some(handle) = handle_guard.take() {
        handle.stop();
    }
    Ok(())
}

#[tauri::command]
pub fn retry_wash(state: State<'_, AppState>, txid: String) -> AppResult<bool> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut washer = state
        .washer
        .lock()
        .map_err(|e| AppError::from(e.to_string()))?;
    Ok(washer.retry_failed(&txid, now))
}
