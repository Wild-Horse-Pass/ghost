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

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use ghost_gsp_proto::{
    ClientMessage, PaymentMode, PreparedPayment, ServerMessage, TransactionInfo, UtxoInfo,
    WalletProof,
};
use tokio::sync::{mpsc, oneshot, watch, RwLock};
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
    cmd_tx: mpsc::Sender<SessionCommand>,
    shutdown_tx: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl SessionHandle {
    pub async fn snapshot(&self) -> SessionStatus {
        self.status.read().await.clone()
    }

    /// Issue `GetUtxos` over the persistent session and await the matching `Utxos` reply.
    pub async fn get_utxos(&self, min_confirmations: u32) -> Result<UtxosResult, String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(SessionCommand::GetUtxos {
                min_confirmations,
                reply: tx,
            })
            .await
            .map_err(|_| "session task closed".to_string())?;
        rx.await.map_err(|_| "reply dropped".to_string())?
    }

    /// Issue `GetTransactions` and await the matching `Transactions` reply.
    pub async fn get_transactions(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<TransactionsResult, String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(SessionCommand::GetTransactions {
                limit,
                offset,
                reply: tx,
            })
            .await
            .map_err(|_| "session task closed".to_string())?;
        rx.await.map_err(|_| "reply dropped".to_string())?
    }

    /// Issue `GetGhostLocks` and await the matching `GhostLocks` reply.
    pub async fn get_ghost_locks(&self) -> Result<GhostLocksResult, String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(SessionCommand::GetGhostLocks { reply: tx })
            .await
            .map_err(|_| "session task closed".to_string())?;
        rx.await.map_err(|_| "reply dropped".to_string())?
    }

    /// Issue `PreparePayment` and await the matching `PaymentPrepared` reply.
    pub async fn prepare_payment(
        &self,
        recipient: String,
        amount_sats: u64,
        mode: PaymentMode,
        proof: WalletProof,
        memo: Option<String>,
    ) -> Result<PreparedPayment, String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(SessionCommand::PreparePayment {
                recipient,
                amount_sats,
                mode,
                proof,
                memo,
                reply: tx,
            })
            .await
            .map_err(|_| "session task closed".to_string())?;
        rx.await.map_err(|_| "reply dropped".to_string())?
    }

    /// Issue `SubmitSignedPayment` and await the matching `PaymentSubmitted` reply.
    pub async fn submit_signed_payment(
        &self,
        payment_id: String,
        signature_hex: String,
        public_key_hex: String,
    ) -> Result<SubmittedPaymentResult, String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(SessionCommand::SubmitSignedPayment {
                payment_id,
                signature: signature_hex,
                public_key: public_key_hex,
                reply: tx,
            })
            .await
            .map_err(|_| "session task closed".to_string())?;
        rx.await.map_err(|_| "reply dropped".to_string())?
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

/// Bag of replies the session task is waiting to deliver. Pending requests are
/// matched FIFO against incoming server messages of the corresponding shape.
enum PendingReply {
    Utxos(oneshot::Sender<Result<UtxosResult, String>>),
    Transactions(oneshot::Sender<Result<TransactionsResult, String>>),
    GhostLocks(oneshot::Sender<Result<GhostLocksResult, String>>),
    PaymentPrepared(oneshot::Sender<Result<PreparedPayment, String>>),
    PaymentSubmitted(oneshot::Sender<Result<SubmittedPaymentResult, String>>),
}

/// Commands the daemon can send into the session task.
pub enum SessionCommand {
    GetUtxos {
        min_confirmations: u32,
        reply: oneshot::Sender<Result<UtxosResult, String>>,
    },
    GetTransactions {
        limit: u32,
        offset: u32,
        reply: oneshot::Sender<Result<TransactionsResult, String>>,
    },
    GetGhostLocks {
        reply: oneshot::Sender<Result<GhostLocksResult, String>>,
    },
    PreparePayment {
        recipient: String,
        amount_sats: u64,
        mode: PaymentMode,
        proof: WalletProof,
        memo: Option<String>,
        reply: oneshot::Sender<Result<PreparedPayment, String>>,
    },
    SubmitSignedPayment {
        payment_id: String,
        signature: String,
        public_key: String,
        reply: oneshot::Sender<Result<SubmittedPaymentResult, String>>,
    },
}

#[derive(Debug, Clone)]
pub struct SubmittedPaymentResult {
    pub payment_id: String,
    pub txid: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UtxosResult {
    pub utxos: Vec<UtxoInfo>,
    pub total_sats: u64,
}

#[derive(Debug, Clone)]
pub struct TransactionsResult {
    pub transactions: Vec<TransactionInfo>,
    pub total_count: u32,
}

#[derive(Debug, Clone)]
pub struct GhostLocksResult {
    pub locks: Vec<ghost_gsp_proto::GhostLockInfo>,
    pub total_locked_sats: u64,
}

/// Spawn a long-lived authenticated session task. Returns a handle.
///
/// `ws_urls` is the failover list — the task tries them in order and rotates
/// on each reconnect attempt. Pass `vec![single_url]` for the single-endpoint case.
pub fn spawn_session(ws_urls: Vec<String>, jwt_token: String) -> SessionHandle {
    let status = Arc::new(RwLock::new(SessionStatus::default()));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (cmd_tx, cmd_rx) = mpsc::channel::<SessionCommand>(32);

    let task = tokio::spawn(run(
        ws_urls,
        jwt_token,
        status.clone(),
        shutdown_rx,
        cmd_rx,
    ));

    SessionHandle {
        status,
        cmd_tx,
        shutdown_tx,
        task: Some(task),
    }
}

const KEEPALIVE_SECS: u64 = 30;
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

async fn run(
    ws_urls: Vec<String>,
    jwt_token: String,
    status: Arc<RwLock<SessionStatus>>,
    mut shutdown: watch::Receiver<bool>,
    mut cmd_rx: mpsc::Receiver<SessionCommand>,
) {
    if ws_urls.is_empty() {
        tracing::error!("gsp session: no ws urls configured, exiting");
        return;
    }
    let mut backoff = BACKOFF_INITIAL;
    let mut url_idx: usize = 0;
    loop {
        if *shutdown.borrow() {
            tracing::debug!("gsp session: shutdown requested, exiting");
            return;
        }

        let ws_url = &ws_urls[url_idx % ws_urls.len()];

        // === connect ===
        set_phase(&status, SessionPhase::Connecting).await;
        let (mut ws, _) = match connect_async(ws_url).await {
            Ok(p) => p,
            Err(e) => {
                let msg = e.to_string();
                tracing::warn!(
                    url = %ws_url,
                    error = %msg,
                    backoff = ?backoff,
                    "gsp session: connect failed, will rotate endpoint"
                );
                set_error(&status, SessionPhase::Backoff, msg).await;
                // Advance to next URL for the next attempt.
                url_idx = url_idx.wrapping_add(1);
                if sleep_or_shutdown(backoff, &mut shutdown).await {
                    return;
                }
                backoff = (backoff * 2).min(BACKOFF_MAX);
                continue;
            }
        };
        // On a successful connect, reset backoff AND prefer the primary URL again
        // (so failover is sticky-during-outage, not permanent).
        backoff = BACKOFF_INITIAL;
        url_idx = 0;

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

        // === main loop: drain messages + keepalive + commands ===
        let mut keepalive = tokio::time::interval(Duration::from_secs(KEEPALIVE_SECS));
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        keepalive.tick().await; // discard immediate tick

        let mut pending: VecDeque<PendingReply> = VecDeque::new();
        let outcome = run_main_loop(
            &mut ws,
            &status,
            &mut shutdown,
            &mut keepalive,
            &mut cmd_rx,
            &mut pending,
        )
        .await;

        // On disconnect, fail any pending replies so callers don't hang.
        for p in pending.drain(..) {
            match p {
                PendingReply::Utxos(tx) => {
                    let _ = tx.send(Err("session disconnected".into()));
                }
                PendingReply::Transactions(tx) => {
                    let _ = tx.send(Err("session disconnected".into()));
                }
                PendingReply::GhostLocks(tx) => {
                    let _ = tx.send(Err("session disconnected".into()));
                }
                PendingReply::PaymentPrepared(tx) => {
                    let _ = tx.send(Err("session disconnected".into()));
                }
                PendingReply::PaymentSubmitted(tx) => {
                    let _ = tx.send(Err("session disconnected".into()));
                }
            }
        }

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
    cmd_rx: &mut mpsc::Receiver<SessionCommand>,
    pending: &mut VecDeque<PendingReply>,
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
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else {
                    // Sender dropped (shouldn't happen — handle owns it). Treat as shutdown.
                    return MainLoopOutcome::Shutdown;
                };
                match cmd {
                    SessionCommand::GetUtxos { min_confirmations, reply } => {
                        let msg = ClientMessage::GetUtxos { min_confirmations };
                        if let Err(e) = send_client(ws, &msg).await {
                            let _ = reply.send(Err(format!("send GetUtxos: {e}")));
                            return MainLoopOutcome::Disconnect(format!("send GetUtxos: {e}"));
                        }
                        pending.push_back(PendingReply::Utxos(reply));
                    }
                    SessionCommand::GetTransactions { limit, offset, reply } => {
                        let msg = ClientMessage::GetTransactions { limit, offset };
                        if let Err(e) = send_client(ws, &msg).await {
                            let _ = reply.send(Err(format!("send GetTransactions: {e}")));
                            return MainLoopOutcome::Disconnect(format!(
                                "send GetTransactions: {e}"
                            ));
                        }
                        pending.push_back(PendingReply::Transactions(reply));
                    }
                    SessionCommand::GetGhostLocks { reply } => {
                        let msg = ClientMessage::GetGhostLocks;
                        if let Err(e) = send_client(ws, &msg).await {
                            let _ = reply.send(Err(format!("send GetGhostLocks: {e}")));
                            return MainLoopOutcome::Disconnect(format!(
                                "send GetGhostLocks: {e}"
                            ));
                        }
                        pending.push_back(PendingReply::GhostLocks(reply));
                    }
                    SessionCommand::PreparePayment {
                        recipient,
                        amount_sats,
                        mode,
                        proof,
                        memo,
                        reply,
                    } => {
                        let msg = ClientMessage::PreparePayment {
                            recipient,
                            amount_sats,
                            mode,
                            proof,
                            memo,
                            encrypted_metadata: None,
                        };
                        if let Err(e) = send_client(ws, &msg).await {
                            let _ = reply.send(Err(format!("send PreparePayment: {e}")));
                            return MainLoopOutcome::Disconnect(format!(
                                "send PreparePayment: {e}"
                            ));
                        }
                        pending.push_back(PendingReply::PaymentPrepared(reply));
                    }
                    SessionCommand::SubmitSignedPayment {
                        payment_id,
                        signature,
                        public_key,
                        reply,
                    } => {
                        let msg = ClientMessage::SubmitSignedPayment {
                            payment_id,
                            signature,
                            public_key,
                        };
                        if let Err(e) = send_client(ws, &msg).await {
                            let _ = reply.send(Err(format!("send SubmitSignedPayment: {e}")));
                            return MainLoopOutcome::Disconnect(format!(
                                "send SubmitSignedPayment: {e}"
                            ));
                        }
                        pending.push_back(PendingReply::PaymentSubmitted(reply));
                    }
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
                handle_message(parsed, status, pending).await;
            }
        }
    }
}

async fn handle_message(
    msg: ServerMessage,
    status: &Arc<RwLock<SessionStatus>>,
    pending: &mut VecDeque<PendingReply>,
) {
    match msg {
        // Push: balance update.
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

        // Response to GetUtxos.
        ServerMessage::Utxos { utxos, total_sats } => {
            if let Some(idx) = pending.iter().position(|p| matches!(p, PendingReply::Utxos(_))) {
                if let Some(PendingReply::Utxos(tx)) = pending.remove(idx) {
                    let _ = tx.send(Ok(UtxosResult { utxos, total_sats }));
                    return;
                }
            }
            tracing::debug!("gsp session: unmatched Utxos message (no pending)");
        }

        // Response to GetTransactions.
        ServerMessage::Transactions {
            transactions,
            total_count,
        } => {
            if let Some(idx) = pending
                .iter()
                .position(|p| matches!(p, PendingReply::Transactions(_)))
            {
                if let Some(PendingReply::Transactions(tx)) = pending.remove(idx) {
                    let _ = tx.send(Ok(TransactionsResult {
                        transactions,
                        total_count,
                    }));
                    return;
                }
            }
            tracing::debug!("gsp session: unmatched Transactions message");
        }

        // Response to GetGhostLocks.
        ServerMessage::GhostLocks {
            locks,
            total_locked_sats,
        } => {
            if let Some(idx) = pending
                .iter()
                .position(|p| matches!(p, PendingReply::GhostLocks(_)))
            {
                if let Some(PendingReply::GhostLocks(tx)) = pending.remove(idx) {
                    let _ = tx.send(Ok(GhostLocksResult {
                        locks,
                        total_locked_sats,
                    }));
                    return;
                }
            }
            tracing::debug!("gsp session: unmatched GhostLocks message");
        }

        // Response to PreparePayment.
        ServerMessage::PaymentPrepared {
            success,
            payment,
            error,
        } => {
            if let Some(idx) = pending
                .iter()
                .position(|p| matches!(p, PendingReply::PaymentPrepared(_)))
            {
                if let Some(PendingReply::PaymentPrepared(tx)) = pending.remove(idx) {
                    let result = if success {
                        match payment {
                            Some(p) => Ok(p),
                            None => Err("server reported success but no payment".into()),
                        }
                    } else {
                        Err(error.unwrap_or_else(|| "PaymentPrepared failed".into()))
                    };
                    let _ = tx.send(result);
                    return;
                }
            }
            tracing::debug!("gsp session: unmatched PaymentPrepared message");
        }

        // Response to SubmitSignedPayment.
        ServerMessage::PaymentSubmitted {
            success,
            payment_id,
            txid,
            error,
        } => {
            if let Some(idx) = pending
                .iter()
                .position(|p| matches!(p, PendingReply::PaymentSubmitted(_)))
            {
                if let Some(PendingReply::PaymentSubmitted(tx)) = pending.remove(idx) {
                    let result = if success {
                        Ok(SubmittedPaymentResult { payment_id, txid })
                    } else {
                        Err(error.unwrap_or_else(|| "PaymentSubmitted failed".into()))
                    };
                    let _ = tx.send(result);
                    return;
                }
            }
            tracing::debug!("gsp session: unmatched PaymentSubmitted message");
        }

        // Server-side error — surface it on the head of the pending queue.
        ServerMessage::Error {
            code,
            message,
            request_id,
        } => {
            tracing::warn!(%code, %message, ?request_id, "gsp session: server error");
            if let Some(p) = pending.pop_front() {
                let err = format!("{code}: {message}");
                match p {
                    PendingReply::Utxos(tx) => {
                        let _ = tx.send(Err(err));
                    }
                    PendingReply::Transactions(tx) => {
                        let _ = tx.send(Err(err));
                    }
                    PendingReply::GhostLocks(tx) => {
                        let _ = tx.send(Err(err));
                    }
                    PendingReply::PaymentPrepared(tx) => {
                        let _ = tx.send(Err(err));
                    }
                    PendingReply::PaymentSubmitted(tx) => {
                        let _ = tx.send(Err(err));
                    }
                }
            }
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
