use crate::error::AppResult;
use crate::state::AppState;
use tauri::State;

/// Sign a message with an address's private key.
#[tauri::command]
pub async fn sign_message(
    state: State<'_, AppState>,
    address: String,
    message: String,
) -> AppResult<String> {
    let signature = state.connection.sign_message(&address, &message).await?;
    Ok(signature)
}

/// Verify a signed message against an address.
#[tauri::command]
pub async fn verify_message(
    state: State<'_, AppState>,
    address: String,
    signature: String,
    message: String,
) -> AppResult<bool> {
    let valid = state
        .connection
        .verify_message(&address, &signature, &message)
        .await?;
    Ok(valid)
}
