//! Tauri shell for the Wraith Wallet GUI.
//!
//! Phase 14 first slice: scaffold + a single Tauri command (`gsp_health`)
//! that round-trips a `Request::Health` to a running `wraithd` over its
//! Unix socket. Frontend is a static `index.html` (no bundler needed) — a
//! React/Tauri/Vite migration can layer on top once the protocol surface
//! is fleshed out.

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::UnixStream;
use wraith_wallet_ipc::{default_socket_path, Envelope, Request, Response};

/// Tauri command: ask the daemon for its health and return a JSON-serializable
/// summary. Used by the frontend to render a "daemon up" badge.
#[tauri::command]
async fn daemon_health() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::Health).await?;
    Ok(serde_json::to_value(&resp).map_err(|e| e.to_string())?)
}

/// Tauri command: round-trip the daemon's `Doctor` summary so the GUI can
/// render a colour-coded checks list on the home view.
#[tauri::command]
async fn daemon_doctor() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::Doctor).await?;
    Ok(serde_json::to_value(&resp).map_err(|e| e.to_string())?)
}

/// Send a request to the running wraithd daemon over its local IPC socket.
/// Returns the parsed [`Response`] payload (without the JSON-RPC envelope).
#[cfg(unix)]
async fn call_daemon(request: Request) -> Result<Response, String> {
    let socket = default_socket_path();
    let stream = UnixStream::connect(&socket).await.map_err(|e| {
        format!(
            "could not connect to wraithd at {}: {e} (is the daemon running?)",
            socket.display()
        )
    })?;
    let (reader, mut writer) = stream.into_split();
    let mut line = serde_json::to_string(&Envelope::new(1, request))
        .map_err(|e| format!("serialise: {e}"))?;
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;
    writer
        .shutdown()
        .await
        .map_err(|e| format!("shutdown: {e}"))?;
    let mut response_line = String::new();
    BufReader::new(reader)
        .read_line(&mut response_line)
        .await
        .map_err(|e| format!("read: {e}"))?;
    let envelope: Envelope<Response> =
        serde_json::from_str(&response_line).map_err(|e| format!("decode: {e}"))?;
    Ok(envelope.payload)
}

#[cfg(not(unix))]
async fn call_daemon(_: Request) -> Result<Response, String> {
    Err("Wraith Wallet GUI currently only supports Unix-like platforms".to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![daemon_health, daemon_doctor])
        .run(tauri::generate_context!())
        .expect("error while running wraith-wallet-gui");
}
