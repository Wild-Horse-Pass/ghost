//! Tauri shell for the Wraith Wallet GUI.
//!
//! Phase 14 first slice: scaffold + a single Tauri command (`gsp_health`)
//! that round-trips a `Request::Health` to a running `wraithd` over its
//! Unix socket. Frontend is a static `index.html` (no bundler needed) — a
//! React/Tauri/Vite migration can layer on top once the protocol surface
//! is fleshed out.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, WindowEvent,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::UnixStream;
use wraith_wallet_ipc::{default_socket_path, Envelope, Request, Response};

/// Coordinates the long-lived watch task so we don't accidentally spawn a
/// second one if the frontend calls `start_watch()` twice. Frontends that need
/// per-window subscriptions should manage that themselves; this is a
/// daemon-wide singleton from the Rust side's perspective.
struct WatchState {
    running: AtomicBool,
}

impl WatchState {
    fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
        }
    }
}

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

#[tauri::command]
async fn wallet_list() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletList).await?;
    to_value(&resp)
}

#[tauri::command]
async fn wallet_status() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletStatus).await?;
    to_value(&resp)
}

#[tauri::command]
async fn wallet_unlock(name: String, passphrase: String) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletUnlock { name, passphrase }).await?;
    to_value(&resp)
}

#[tauri::command]
async fn wallet_lock(name: Option<String>) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletLock { name }).await?;
    to_value(&resp)
}

#[tauri::command]
async fn wallet_select(name: String) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletSelect { name }).await?;
    to_value(&resp)
}

#[tauri::command]
async fn wallet_create(name: String, passphrase: String) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletCreate { name, passphrase }).await?;
    to_value(&resp)
}

#[tauri::command]
async fn wallet_import(
    name: String,
    mnemonic: String,
    passphrase: String,
) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletImport {
        name,
        mnemonic,
        passphrase,
    })
    .await?;
    to_value(&resp)
}

#[tauri::command]
async fn wallet_show_mnemonic(
    name: String,
    passphrase: String,
) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletShowMnemonic { name, passphrase }).await?;
    to_value(&resp)
}

#[tauri::command]
async fn light_balance() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::LightBalance).await?;
    to_value(&resp)
}

#[tauri::command]
async fn light_receive(index: u32) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::LightReceive { index }).await?;
    to_value(&resp)
}

#[tauri::command]
async fn light_history(limit: u32, offset: u32) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::LightHistory { limit, offset }).await?;
    to_value(&resp)
}

#[tauri::command]
async fn daemon_env() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::DaemonEnv).await?;
    to_value(&resp)
}

#[tauri::command]
async fn wallet_ghost_id() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletGhostId).await?;
    to_value(&resp)
}

#[tauri::command]
async fn wallet_auth_info() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletAuthInfo).await?;
    to_value(&resp)
}

#[tauri::command]
async fn gsp_register_scan_key() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::GspRegisterScanKey).await?;
    to_value(&resp)
}

#[tauri::command]
async fn gsp_session_status() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::GspSessionStatus).await?;
    to_value(&resp)
}

#[tauri::command]
async fn gsp_auth() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::GspAuth).await?;
    to_value(&resp)
}

#[tauri::command]
async fn locks_list() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::LocksList).await?;
    to_value(&resp)
}

#[tauri::command]
async fn locks_prepare(capacity_sats: u64) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::LocksPrepare { capacity_sats }).await?;
    to_value(&resp)
}

#[tauri::command]
async fn locks_confirm(
    lock_id: String,
    funding_txid: String,
) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::LocksConfirm {
        lock_id,
        funding_txid,
    })
    .await?;
    to_value(&resp)
}

#[tauri::command]
async fn locks_jump(
    lock_id: String,
    target_address: String,
    priority: String,
) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::LocksJump {
        lock_id,
        target_address,
        priority,
    })
    .await?;
    to_value(&resp)
}

#[tauri::command]
async fn light_send(
    recipient: String,
    amount_sats: u64,
    mode: String,
    memo: Option<String>,
) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::LightSend {
        recipient,
        amount_sats,
        mode,
        memo,
    })
    .await?;
    to_value(&resp)
}

fn to_value(resp: &Response) -> Result<serde_json::Value, String> {
    serde_json::to_value(resp).map_err(|e| e.to_string())
}

/// Start the daemon watch subscription if it isn't already running.
/// Forwards each `PaymentDetected` push to the frontend as a Tauri event
/// named `wraith://payment-detected`. Idempotent — safe to call from
/// multiple windows.
#[tauri::command]
async fn start_watch(
    app: AppHandle,
    state: tauri::State<'_, Arc<WatchState>>,
) -> Result<(), String> {
    if state
        .running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Ok(()); // already running
    }
    let app = app.clone();
    let state = state.inner().clone();
    tokio::spawn(async move {
        if let Err(e) = run_watch_loop(&app).await {
            // Surface the failure to the frontend so it can show a banner.
            let _ = app.emit(
                "wraith://watch-error",
                serde_json::json!({ "message": e }),
            );
        }
        state.running.store(false, Ordering::SeqCst);
    });
    Ok(())
}

#[cfg(unix)]
async fn run_watch_loop(app: &AppHandle) -> Result<(), String> {
    let socket = default_socket_path();
    let stream = UnixStream::connect(&socket)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let (reader, mut writer) = stream.into_split();
    let mut line = serde_json::to_string(&Envelope::new(1, Request::WatchPayments))
        .map_err(|e| format!("serialise: {e}"))?;
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;
    let mut reader = BufReader::new(reader);
    loop {
        let mut buf = String::new();
        match reader.read_line(&mut buf).await {
            Ok(0) => return Ok(()), // daemon closed
            Ok(_) => {
                let env: Envelope<Response> = match serde_json::from_str(&buf) {
                    Ok(e) => e,
                    Err(_) => continue, // skip bad lines, keep stream alive
                };
                match env.payload {
                    Response::Watching => {}
                    Response::PaymentDetected(d) => {
                        let _ = app.emit(
                            "wraith://payment-detected",
                            serde_json::json!({
                                "txid": d.txid,
                                "block_height": d.block_height,
                                "vout": d.vout,
                                "amount_sats": d.amount_sats,
                                "k": d.k,
                                "received_at": d.received_at,
                            }),
                        );
                    }
                    Response::Error(e) => return Err(e.message),
                    _ => {}
                }
            }
            Err(e) => return Err(format!("read: {e}")),
        }
    }
}

#[cfg(not(unix))]
async fn run_watch_loop(_: &AppHandle) -> Result<(), String> {
    Err("watch only supported on unix".to_string())
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
        .manage(Arc::new(WatchState::new()))
        .setup(|app| {
            // Build a minimal tray menu — show / hide / quit. Daemon ("wraithd")
            // runs as a separate process, so quitting the GUI never stops the
            // wallet itself; the menu wording reflects that.
            let show = MenuItem::with_id(app, "show", "Show window", true, None::<&str>)?;
            let hide = MenuItem::with_id(app, "hide", "Hide window", true, None::<&str>)?;
            let quit_gui = MenuItem::with_id(
                app,
                "quit_gui",
                "Quit GUI (daemon keeps running)",
                true,
                None::<&str>,
            )?;
            let menu = Menu::with_items(app, &[&show, &hide, &quit_gui])?;

            let _tray = TrayIconBuilder::with_id("wraith-tray")
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("Wraith Wallet")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.unminimize();
                            let _ = w.set_focus();
                        }
                    }
                    "hide" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.hide();
                        }
                    }
                    "quit_gui" => {
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    // Single-click on the tray icon toggles the main window —
                    // matches the muscle memory most desktop wallets train.
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        if let Some(w) = tray.app_handle().get_webview_window("main") {
                            if w.is_visible().unwrap_or(false) {
                                let _ = w.hide();
                            } else {
                                let _ = w.show();
                                let _ = w.unminimize();
                                let _ = w.set_focus();
                            }
                        }
                    }
                })
                .build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window hides it instead of exiting; the user has to
            // pick "Quit GUI" from the tray to actually terminate this process.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            daemon_health,
            daemon_doctor,
            daemon_env,
            wallet_list,
            wallet_status,
            wallet_unlock,
            wallet_lock,
            wallet_select,
            wallet_create,
            wallet_import,
            wallet_show_mnemonic,
            light_balance,
            light_receive,
            light_history,
            light_send,
            wallet_ghost_id,
            wallet_auth_info,
            gsp_register_scan_key,
            gsp_session_status,
            gsp_auth,
            locks_list,
            locks_prepare,
            locks_confirm,
            locks_jump,
            start_watch,
        ])
        .run(tauri::generate_context!())
        .expect("error while running wraith-wallet-gui");
}
