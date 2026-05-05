//! Long-lived authenticated WebSocket session to a GSP.
//!
//! The daemon spawns one of these per active wallet's GSP session token. The task:
//!
//! 1. Opens a WebSocket to the GSP's `/ws/v1` endpoint.
//! 2. Sends `ClientMessage::Authenticate { token }`.
//! 3. Waits for `ServerMessage::AuthResult { success: true }`.
//! 4. Issues `ClientMessage::GetBalance` so the cache populates immediately.
//! 5. Reads incoming messages — `BalanceUpdate` updates the cached balance,
//!    other pushes are logged and ignored for now.
//! 6. Sends a `Ping` keepalive every 30 s.
//! 7. On any IO/protocol error, marks the session as `Backoff`, sleeps with
//!    exponential backoff (1 s, 2 s, 4 s, ..., capped at 60 s), and reconnects.
//!
//! Shutdown: the daemon drops the `SessionHandle`, which closes a `watch` channel
//! the task listens on. The task exits at the next opportunity.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use ghost_gsp_proto::{ClientMessage, ServerMessage};
use tokio::sync::{watch, RwLock};
use tokio::task::JoinHandle;
use tokio_tungstenite::{connect_async, tungstenite::Message};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionPhase {
    #[default]
    Disconnected,
    Connecting,
    Authenticating,
    Authenticated,
    Backoff,
}

/// Snapshot of a session's runtime state. Cheap to clone.
#[derive(Debug, Clone, Default)]
pub struct SessionStatus {
    pub phase: SessionPhase,
    /// Confirmed satoshi balance from the most recent `BalanceUpdate`.
    pub last_balance: Option<BalanceSnapshot>,
    /// Last error message, set on transport / protocol failure.
    pub last_error: Option<String>,
    /// Successful WS connection count (1 = connected first time, 2 = one reconnect, ...).
    pub connect_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BalanceSnapshot {
    pub confirmed_sats: u64,
    pub unconfirmed_sats: u64,
    pub locked_sats: u64,
    /// Unix seconds when this snapshot was received.
    pub received_at: i64,
}

/// Daemon-side handle to a running session task. Drop to stop the task.
pub struct SessionHandle {
    status: Arc<RwLock<SessionStatus>>,
    shutdown_tx: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl SessionHandle {
    pub async fn snapshot(&self) -> SessionStatus {
        self.status.read().await.clone()
    }
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
}

/// Spawn a long-lived authenticated session task. Returns a handle.
pub fn spawn_session(ws_url: String, jwt_token: String) -> SessionHandle {
    let status = Arc::new(RwLock::new(SessionStatus::default()));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let task = tokio::spawn(run(
        ws_url,
        jwt_token,
        status.clone(),
        shutdown_rx,
    ));

    SessionHandle {
        status,
        shutdown_tx,
        task: Some(task),
    }
}

const KEEPALIVE_SECS: u64 = 30;
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

async fn run(
    ws_url: String,
    jwt_token: String,
    status: Arc<RwLock<SessionStatus>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut backoff = BACKOFF_INITIAL;
    loop {
        if *shutdown.borrow() {
            tracing::debug!("gsp session: shutdown requested, exiting");
            return;
        }

        // === connect ===
        set_phase(&status, SessionPhase::Connecting).await;
        let (mut ws, _) = match connect_async(&ws_url).await {
            Ok(p) => p,
            Err(e) => {
                let msg = e.to_string();
                tracing::warn!(error = %msg, backoff = ?backoff, "gsp session: connect failed");
                set_error(&status, SessionPhase::Backoff, msg).await;
                if sleep_or_shutdown(backoff, &mut shutdown).await {
                    return;
                }
                backoff = (backoff * 2).min(BACKOFF_MAX);
                continue;
            }
        };
        backoff = BACKOFF_INITIAL;

        // === authenticate ===
        set_phase(&status, SessionPhase::Authenticating).await;
        let auth_msg = ClientMessage::Authenticate {
            token: jwt_token.clone(),
        };
        if let Err(e) = send_client(&mut ws, &auth_msg).await {
            set_error(&status, SessionPhase::Backoff, format!("send auth: {e}")).await;
            sleep_or_shutdown(backoff, &mut shutdown).await;
            continue;
        }

        // wait for AuthResult
        match read_until_auth_result(&mut ws).await {
            Ok(true) => {} // authenticated
            Ok(false) => {
                set_error(
                    &status,
                    SessionPhase::Backoff,
                    "server rejected authentication".into(),
                )
                .await;
                let _ = ws.close(None).await;
                if sleep_or_shutdown(backoff, &mut shutdown).await {
                    return;
                }
                continue;
            }
            Err(e) => {
                set_error(&status, SessionPhase::Backoff, format!("auth read: {e}")).await;
                let _ = ws.close(None).await;
                if sleep_or_shutdown(backoff, &mut shutdown).await {
                    return;
                }
                continue;
            }
        }

        {
            let mut s = status.write().await;
            s.phase = SessionPhase::Authenticated;
            s.connect_count += 1;
            s.last_error = None;
        }

        // bootstrap: ask for current balance
        let _ = send_client(&mut ws, &ClientMessage::GetBalance { max_k: None }).await;

        // === main loop: drain messages + keepalive ===
        let mut keepalive = tokio::time::interval(Duration::from_secs(KEEPALIVE_SECS));
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        keepalive.tick().await; // discard immediate tick

        let outcome = run_main_loop(&mut ws, &status, &mut shutdown, &mut keepalive).await;

        let _ = ws.close(None).await;
        match outcome {
            MainLoopOutcome::Shutdown => return,
            MainLoopOutcome::Disconnect(reason) => {
                tracing::warn!(reason = %reason, "gsp session: disconnected, will reconnect");
                set_error(&status, SessionPhase::Backoff, reason).await;
                if sleep_or_shutdown(backoff, &mut shutdown).await {
                    return;
                }
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
}

enum MainLoopOutcome {
    Shutdown,
    Disconnect(String),
}

async fn run_main_loop(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    status: &Arc<RwLock<SessionStatus>>,
    shutdown: &mut watch::Receiver<bool>,
    keepalive: &mut tokio::time::Interval,
) -> MainLoopOutcome {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return MainLoopOutcome::Shutdown;
                }
            }
            _ = keepalive.tick() => {
                let ping = ClientMessage::Ping {
                    timestamp: Some(now_unix_ms()),
                };
                if let Err(e) = send_client(ws, &ping).await {
                    return MainLoopOutcome::Disconnect(format!("send keepalive: {e}"));
                }
            }
            frame = ws.next() => {
                let frame = match frame {
                    Some(Ok(f)) => f,
                    Some(Err(e)) => {
                        return MainLoopOutcome::Disconnect(format!("read: {e}"));
                    }
                    None => return MainLoopOutcome::Disconnect("server closed".into()),
                };
                let text = match frame {
                    Message::Text(t) => t,
                    Message::Close(_) => {
                        return MainLoopOutcome::Disconnect("server closed".into());
                    }
                    _ => continue,
                };
                let parsed: ServerMessage = match serde_json::from_str(text.as_ref()) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(error = %e, raw = %text, "gsp session: bad server message");
                        continue;
                    }
                };
                handle_push(parsed, status).await;
            }
        }
    }
}

async fn handle_push(msg: ServerMessage, status: &Arc<RwLock<SessionStatus>>) {
    match msg {
        ServerMessage::BalanceUpdate {
            confirmed,
            unconfirmed,
            locked,
        } => {
            let snap = BalanceSnapshot {
                confirmed_sats: confirmed,
                unconfirmed_sats: unconfirmed,
                locked_sats: locked,
                received_at: now_unix_secs(),
            };
            tracing::debug!(?snap, "gsp session: balance update");
            status.write().await.last_balance = Some(snap);
        }
        ServerMessage::Pong { .. } => {
            tracing::trace!("gsp session: pong");
        }
        other => {
            tracing::trace!(?other, "gsp session: unhandled push");
        }
    }
}

/// Read frames until we see an `AuthResult`. Drops anything else.
async fn read_until_auth_result(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Result<bool, String> {
    let timeout = tokio::time::sleep(Duration::from_secs(15));
    tokio::pin!(timeout);
    loop {
        tokio::select! {
            _ = &mut timeout => return Err("timeout waiting for AuthResult".into()),
            frame = ws.next() => {
                let frame = frame
                    .ok_or_else(|| "server closed during auth".to_string())?
                    .map_err(|e| format!("ws error during auth: {e}"))?;
                let text = match frame {
                    Message::Text(t) => t,
                    Message::Close(_) => return Err("server closed during auth".into()),
                    _ => continue,
                };
                let parsed: ServerMessage = serde_json::from_str(text.as_ref())
                    .map_err(|e| format!("decoding ServerMessage: {e}"))?;
                match parsed {
                    ServerMessage::AuthResult { success, error, .. } => {
                        if !success {
                            tracing::warn!(error = ?error, "gsp session: auth rejected");
                        }
                        return Ok(success);
                    }
                    // Server may push errors before we authenticate; surface and keep waiting.
                    ServerMessage::Error { message, .. } => {
                        return Err(format!("server error during auth: {message}"));
                    }
                    _ => continue,
                }
            }
        }
    }
}

async fn send_client(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    msg: &ClientMessage,
) -> Result<(), String> {
    let json = serde_json::to_string(msg).map_err(|e| format!("encode: {e}"))?;
    ws.send(Message::Text(json.into()))
        .await
        .map_err(|e| format!("send: {e}"))
}

async fn set_phase(status: &Arc<RwLock<SessionStatus>>, phase: SessionPhase) {
    let mut s = status.write().await;
    s.phase = phase;
}

async fn set_error(status: &Arc<RwLock<SessionStatus>>, phase: SessionPhase, msg: String) {
    let mut s = status.write().await;
    s.phase = phase;
    s.last_error = Some(msg);
}

/// Sleep for `dur`, but return true early if shutdown was signalled.
async fn sleep_or_shutdown(dur: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(dur) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
