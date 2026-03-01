use crate::error::{AppError, AppResult};
use crate::state::AppState;
use ghost_tap_core::network::connection::ConnectionMode;
use ghost_tap_core::network::NodeConfig;
use serde::Serialize;
use tauri::State;

#[derive(Serialize)]
pub struct ConnectionStatus {
    pub mode: String,
    pub connected: bool,
}

#[tauri::command]
pub fn set_connection_mode(state: State<'_, AppState>, mode: String) -> AppResult<()> {
    let conn_mode = match mode.as_str() {
        "gsp" => ConnectionMode::Gsp,
        _ => ConnectionMode::DirectRpc,
    };
    state.connection.set_mode(conn_mode);
    Ok(())
}

#[tauri::command]
pub fn set_rpc_config(
    state: State<'_, AppState>,
    host: String,
    port: u16,
    user: Option<String>,
    pass: Option<String>,
) -> AppResult<()> {
    let endpoint = format!("http://{}:{}", host, port);
    let config = NodeConfig {
        endpoints: vec![endpoint],
        rpc_user: user,
        rpc_password: pass,
        timeout_ms: 30_000,
        retry_count: 3,
        use_tls: false,
        pinned_cert_der: None,
    };
    state.connection.set_rpc_config(config);
    Ok(())
}

#[tauri::command]
pub fn get_connection_status(state: State<'_, AppState>) -> ConnectionStatus {
    ConnectionStatus {
        mode: state.connection.mode().to_string(),
        connected: state.connection.is_connected(),
    }
}

#[tauri::command]
pub async fn sync(state: State<'_, AppState>) -> AppResult<()> {
    state.connection.sync().await?;

    // Persist wallet state after sync
    let guard = state.wallet.lock();
    if let Some(instance) = guard.as_ref() {
        let wallet = instance
            .wallet
            .lock()
            .map_err(|e| AppError::from(e.to_string()))?;
        let storage = instance
            .storage
            .lock()
            .map_err(|e| AppError::from(e.to_string()))?;

        storage.save_utxos(wallet.get_utxos())?;
        for entry in wallet.get_history() {
            storage.save_history_entry(entry)?;
        }
    }

    Ok(())
}
