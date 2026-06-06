use crate::error::{AppError, AppResult};
use crate::state::AppState;
use ghost_tap_core::network::ghost_pay::{
    CreateLockRequest, GhostPayClient, PayConfig, ReconcileRequest, SendL2PaymentRequest,
};
use tauri::State;

// =============================================================================
// Helper — build a GhostPayClient from AppState
// =============================================================================

fn ghost_pay_client(state: &AppState) -> AppResult<GhostPayClient> {
    let config = PayConfig {
        base_url: state
            .ghost_pay_url
            .lock()
            .clone()
            .unwrap_or_else(|| "http://127.0.0.1:8800".into()),
        timeout_ms: 30_000,
        api_secret: state.ghost_pay_secret.lock().clone(),
    };
    Ok(GhostPayClient::with_client(
        config,
        state.http_client.clone(),
    ))
}

// =============================================================================
// Lock Commands
// =============================================================================

/// List all ghost locks.
#[tauri::command]
pub async fn list_locks(state: State<'_, AppState>) -> AppResult<serde_json::Value> {
    let client = ghost_pay_client(&state)?;
    let locks = client
        .list_locks()
        .await
        .map_err(|e| AppError::from(e.to_string()))?;
    serde_json::to_value(locks).map_err(|e| AppError::from(e.to_string()))
}

/// Get details for a specific lock.
#[tauri::command]
pub async fn get_lock(state: State<'_, AppState>, lock_id: String) -> AppResult<serde_json::Value> {
    let client = ghost_pay_client(&state)?;
    let lock = client
        .get_lock(&lock_id)
        .await
        .map_err(|e| AppError::from(e.to_string()))?;
    serde_json::to_value(lock).map_err(|e| AppError::from(e.to_string()))
}

/// Create a new ghost lock.
#[tauri::command]
pub async fn create_lock(
    state: State<'_, AppState>,
    amount_sats: u64,
    timelock_tier: Option<String>,
) -> AppResult<serde_json::Value> {
    let client = ghost_pay_client(&state)?;
    let req = CreateLockRequest {
        amount_sats,
        timelock_tier,
        source: None,
    };
    let resp = client
        .create_lock(&req)
        .await
        .map_err(|e| AppError::from(e.to_string()))?;
    serde_json::to_value(resp).map_err(|e| AppError::from(e.to_string()))
}

/// Jump (renew) a ghost lock.
#[tauri::command]
pub async fn jump_lock(
    state: State<'_, AppState>,
    lock_id: String,
) -> AppResult<serde_json::Value> {
    let client = ghost_pay_client(&state)?;
    let resp = client
        .jump_lock(&lock_id)
        .await
        .map_err(|e| AppError::from(e.to_string()))?;
    serde_json::to_value(resp).map_err(|e| AppError::from(e.to_string()))
}

/// Reconcile (settle) a ghost lock.
#[tauri::command]
pub async fn reconcile_lock(
    state: State<'_, AppState>,
    lock_id: String,
    destination: String,
    settlement_class: Option<String>,
) -> AppResult<serde_json::Value> {
    let client = ghost_pay_client(&state)?;
    let req = ReconcileRequest {
        destination_address: destination,
        settlement_class,
    };
    let resp = client
        .reconcile_lock(&lock_id, &req)
        .await
        .map_err(|e| AppError::from(e.to_string()))?;
    serde_json::to_value(resp).map_err(|e| AppError::from(e.to_string()))
}

// =============================================================================
// Ghost ID Commands
// =============================================================================

/// Get the current ghost ID.
#[tauri::command]
pub async fn get_ghost_id(state: State<'_, AppState>) -> AppResult<serde_json::Value> {
    let client = ghost_pay_client(&state)?;
    let info = client
        .get_ghost_id()
        .await
        .map_err(|e| AppError::from(e.to_string()))?;
    serde_json::to_value(info).map_err(|e| AppError::from(e.to_string()))
}

/// Generate a new ghost ID.
#[tauri::command]
pub async fn generate_ghost_id(state: State<'_, AppState>) -> AppResult<serde_json::Value> {
    let client = ghost_pay_client(&state)?;
    let resp = client
        .generate_ghost_id()
        .await
        .map_err(|e| AppError::from(e.to_string()))?;
    serde_json::to_value(resp).map_err(|e| AppError::from(e.to_string()))
}

// =============================================================================
// L2 Payment Commands
// =============================================================================

/// Send an L2 payment.
#[tauri::command]
pub async fn send_l2_payment(
    state: State<'_, AppState>,
    recipient: String,
    amount_sats: u64,
    memo: Option<String>,
) -> AppResult<serde_json::Value> {
    let client = ghost_pay_client(&state)?;
    let req = SendL2PaymentRequest {
        recipient,
        amount_sats,
        memo,
    };
    let resp = client
        .send_l2_payment(&req)
        .await
        .map_err(|e| AppError::from(e.to_string()))?;
    serde_json::to_value(resp).map_err(|e| AppError::from(e.to_string()))
}

// =============================================================================
// Withdrawal Commands
// =============================================================================

/// List all withdrawals.
#[tauri::command]
pub async fn list_withdrawals(state: State<'_, AppState>) -> AppResult<serde_json::Value> {
    let client = ghost_pay_client(&state)?;
    let withdrawals = client
        .list_withdrawals()
        .await
        .map_err(|e| AppError::from(e.to_string()))?;
    serde_json::to_value(withdrawals).map_err(|e| AppError::from(e.to_string()))
}

/// Get details for a specific withdrawal.
#[tauri::command]
pub async fn get_withdrawal(state: State<'_, AppState>, id: u64) -> AppResult<serde_json::Value> {
    let client = ghost_pay_client(&state)?;
    let withdrawal = client
        .get_withdrawal(id)
        .await
        .map_err(|e| AppError::from(e.to_string()))?;
    serde_json::to_value(withdrawal).map_err(|e| AppError::from(e.to_string()))
}
