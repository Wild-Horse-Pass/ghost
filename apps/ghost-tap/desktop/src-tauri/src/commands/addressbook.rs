use crate::error::AppResult;
use crate::state::AppState;
use serde::Serialize;
use tauri::State;

#[derive(Serialize)]
pub struct AddressEntry {
    pub address: String,
    pub label: String,
    pub amount: f64,
    pub confirmations: u64,
}

/// List all address labels in the node wallet.
#[tauri::command]
pub async fn list_address_labels(state: State<'_, AppState>) -> AppResult<Vec<String>> {
    let labels = state.connection.list_labels().await?;
    Ok(labels)
}

/// Get all addresses associated with a given label.
#[tauri::command]
pub async fn get_addresses_for_label(
    state: State<'_, AppState>,
    label: String,
) -> AppResult<Vec<String>> {
    let val = state.connection.get_addresses_by_label(&label).await?;
    // The RPC returns an object with addresses as keys
    let addresses: Vec<String> = val
        .as_object()
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default();
    Ok(addresses)
}

/// Set a label for an address.
#[tauri::command]
pub async fn set_address_label(
    state: State<'_, AppState>,
    address: String,
    label: String,
) -> AppResult<()> {
    state.connection.set_label(&address, &label).await?;
    Ok(())
}

/// Validate an address and return detailed info.
#[tauri::command]
pub async fn validate_address_info(
    state: State<'_, AppState>,
    address: String,
) -> AppResult<serde_json::Value> {
    let info = state.connection.validate_address(&address).await?;
    Ok(info)
}

/// List all addresses that have received funds, with amounts and confirmations.
#[tauri::command]
pub async fn list_received_addresses(
    state: State<'_, AppState>,
) -> AppResult<Vec<AddressEntry>> {
    let received = state.connection.list_received_by_address(0, true).await?;
    let entries = received
        .into_iter()
        .map(|v| AddressEntry {
            address: v
                .get("address")
                .and_then(|a| a.as_str())
                .unwrap_or("")
                .to_string(),
            label: v
                .get("label")
                .and_then(|l| l.as_str())
                .unwrap_or("")
                .to_string(),
            amount: v
                .get("amount")
                .and_then(|a| a.as_f64())
                .unwrap_or(0.0),
            confirmations: v
                .get("confirmations")
                .and_then(|c| c.as_u64())
                .unwrap_or(0),
        })
        .collect();
    Ok(entries)
}
