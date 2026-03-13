use crate::error::{AppError, AppResult};
use crate::state::AppState;
use ghost_tap_core::network::connection::ConnectionMode;
use ghost_tap_core::network::ghost_pay::PayConfig;
use ghost_tap_core::network::NodeConfig;
use serde::Serialize;
use tauri::State;

#[derive(Serialize)]
pub struct ConnectionStatus {
    pub mode: String,
    pub connected: bool,
}

/// Aggregated node info returned by `get_node_info` in Full Node mode.
#[derive(Serialize)]
pub struct NodeInfo {
    /// "light" or "fullnode"
    pub connection_mode: String,
    /// ghostd reachable
    pub ghostd_connected: bool,
    /// ghost-pay-node reachable
    pub ghost_pay_connected: bool,
    /// Current block height (0 if unavailable)
    pub block_height: u64,
    /// Header count (for sync progress)
    pub header_count: u64,
    /// Sync progress 0.0 – 1.0
    pub sync_progress: f64,
    /// Whether node is in initial block download
    pub initial_block_download: bool,
    /// Network name (signet, mainnet, etc.)
    pub network: String,
    /// Connected peer count
    pub peer_count: u32,
    /// ghostd version string
    pub node_version: String,
}

/// Result of testing both ghostd and ghost-pay-node connections.
#[derive(Serialize)]
pub struct ConnectionTestResult {
    pub ghostd_ok: bool,
    pub ghostd_error: Option<String>,
    pub ghost_pay_ok: bool,
    pub ghost_pay_error: Option<String>,
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

/// Configure the Ghost Pay (L2) connection endpoint.
#[tauri::command]
pub fn set_ghost_pay_config(
    state: State<'_, AppState>,
    host: String,
    port: u16,
    api_secret: Option<String>,
) -> AppResult<()> {
    let base_url = format!("http://{}:{}", host, port);
    // Store in AppState fields (used by l2.rs ghost_pay_client helper)
    *state.ghost_pay_url.lock() = Some(base_url.clone());
    *state.ghost_pay_secret.lock() = api_secret.clone();
    // Also update ConnectionManager's PayConfig
    state.connection.set_ghost_pay_config(PayConfig {
        base_url,
        timeout_ms: 30_000,
        api_secret,
    });
    Ok(())
}

#[tauri::command]
pub fn get_connection_status(state: State<'_, AppState>) -> ConnectionStatus {
    ConnectionStatus {
        mode: state.connection.mode().to_string(),
        connected: state.connection.is_connected(),
    }
}

/// Get aggregated node info (blockchain height, sync, peers, network).
/// Returns meaningful data only in Full Node (DirectRpc) mode.
#[tauri::command]
pub async fn get_node_info(state: State<'_, AppState>) -> AppResult<NodeInfo> {
    let mode = state.connection.mode();
    if mode == ConnectionMode::Gsp {
        return Ok(NodeInfo {
            connection_mode: "light".into(),
            ghostd_connected: false,
            ghost_pay_connected: false,
            block_height: 0,
            header_count: 0,
            sync_progress: 0.0,
            initial_block_download: false,
            network: String::new(),
            peer_count: 0,
            node_version: String::new(),
        });
    }

    // Query ghostd blockchain info
    let (ghostd_connected, block_height, header_count, sync_progress, ibd, network) =
        match state.connection.get_blockchain_info().await {
            Ok(Some(info)) => (
                true,
                info.blocks,
                info.headers,
                info.verificationprogress,
                info.initialblockdownload,
                info.chain,
            ),
            _ => (false, 0, 0, 0.0, false, String::new()),
        };

    // Query peer count
    let peer_count = match state.connection.get_peer_info().await {
        Ok(Some(val)) => val.as_array().map(|a| a.len() as u32).unwrap_or(0),
        _ => 0,
    };

    // Query node version
    let node_version = match state.connection.get_network_info().await {
        Ok(Some(val)) => val
            .get("subversion")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        _ => String::new(),
    };

    // Check ghost-pay-node connectivity
    let ghost_pay_connected = {
        let url = state.ghost_pay_url.lock().clone();
        match url {
            Some(base_url) => {
                let health_url = format!("{}/api/v1/health", base_url);
                state.http_client.get(&health_url).send().await.is_ok()
            }
            None => false,
        }
    };

    Ok(NodeInfo {
        connection_mode: "fullnode".into(),
        ghostd_connected,
        ghost_pay_connected,
        block_height,
        header_count,
        sync_progress,
        initial_block_download: ibd,
        network,
        peer_count,
        node_version,
    })
}

/// Test both ghostd RPC and ghost-pay-node connections independently.
#[tauri::command]
pub async fn test_connection(state: State<'_, AppState>) -> AppResult<ConnectionTestResult> {
    // Test ghostd
    let (ghostd_ok, ghostd_error) = match state.connection.sync().await {
        Ok(()) => (true, None),
        Err(e) => (false, Some(e.to_string())),
    };

    // Test ghost-pay-node
    let (ghost_pay_ok, ghost_pay_error) = {
        let url = state.ghost_pay_url.lock().clone();
        match url {
            Some(base_url) => {
                let health_url = format!("{}/api/v1/health", base_url);
                match state.http_client.get(&health_url).send().await {
                    Ok(resp) if resp.status().is_success() => (true, None),
                    Ok(resp) => (false, Some(format!("HTTP {}", resp.status()))),
                    Err(e) => (false, Some(e.to_string())),
                }
            }
            None => (false, Some("Ghost Pay URL not configured".into())),
        }
    };

    Ok(ConnectionTestResult {
        ghostd_ok,
        ghostd_error,
        ghost_pay_ok,
        ghost_pay_error,
    })
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
