//! GSP (Ghost Service Provider) WebSocket client
//!
//! Provides a mobile-friendly WebSocket connection to a GSP node,
//! enabling real-time balance updates, payment submission, and push
//! notifications without polling.

use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use super::NetworkError;

// ---------------------------------------------------------------------------
// Wire-compatible GSP message types (defined locally, no proto dependency)
// ---------------------------------------------------------------------------

/// Requests sent from the mobile client to the GSP.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum GspRequest {
    /// Authenticate with the GSP using a wallet ID and session token.
    Authenticate { wallet_id: String, token: String },
    /// Request the current balance.
    GetBalance,
    /// Prepare a payment (returns an unsigned transaction for client signing).
    PreparePayment { to: String, amount: u64 },
    /// Submit a signed payment for broadcast.
    SubmitSignedPayment { signed_tx: String },
    /// Subscribe to real-time balance change notifications.
    SubscribeBalance,
    /// Subscribe to real-time payment notifications.
    SubscribePayments,
}

/// Responses from the GSP to the mobile client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum GspResponse {
    /// Authentication succeeded.
    Authenticated { session_id: String },
    /// Current balance snapshot.
    Balance { confirmed: u64, pending: u64 },
    /// An unsigned payment has been prepared server-side.
    PaymentPrepared { unsigned_tx: String, fee: u64 },
    /// A signed payment was accepted and broadcast.
    PaymentSubmitted { txid: String },
    /// Push notification: balance changed.
    BalanceUpdate { confirmed: u64, pending: u64 },
    /// Push notification: payment state changed.
    PaymentUpdate {
        txid: String,
        status: String,
        confirmations: u32,
    },
    /// An error occurred processing a request.
    Error { code: u32, message: String },
}

/// Push events delivered to the application layer via the event channel.
#[derive(Debug, Clone)]
pub enum GspEvent {
    /// Wallet balance has changed.
    BalanceChanged { confirmed: u64, pending: u64 },
    /// An incoming payment was detected.
    PaymentReceived { txid: String, amount: u64 },
    /// A payment reached the required confirmation depth.
    PaymentConfirmed { txid: String, confirmations: u32 },
    /// The connection lock state changed (connected / disconnected).
    LockStateChanged { connected: bool },
}

/// Internal connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Authenticated,
}

/// Mobile GSP WebSocket client.
///
/// Manages a persistent WebSocket connection to a GSP endpoint,
/// handles serialization of request/response messages, and delivers
/// push events to the application layer through an mpsc channel.
pub struct MobileGspClient {
    /// Current endpoint URL.
    endpoint: Arc<Mutex<String>>,
    /// Connection state.
    state: Arc<Mutex<ConnectionState>>,
    /// Channel for sending outbound messages to the write task.
    write_tx: Arc<Mutex<Option<mpsc::Sender<String>>>>,
    /// Channel for receiving push events in the application layer.
    event_rx: Arc<Mutex<Option<mpsc::Receiver<GspEvent>>>>,
    /// Sender side kept for cloning into the read task.
    event_tx: mpsc::Sender<GspEvent>,
    /// Channel for receiving RPC-style responses.
    response_rx: Arc<Mutex<Option<mpsc::Receiver<GspResponse>>>>,
    /// Sender side kept for the read task.
    response_tx: mpsc::Sender<GspResponse>,
    /// Handle to the background connection task (for cancellation).
    task_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Serialization lock: ensures send_request + recv_response are atomic
    /// so concurrent RPC calls cannot get misrouted responses.
    rpc_lock: Arc<tokio::sync::Mutex<()>>,
}

impl MobileGspClient {
    /// Create a new GSP client. Does not connect immediately.
    pub fn new() -> Self {
        let (event_tx, event_rx) = mpsc::channel(128);
        let (response_tx, response_rx) = mpsc::channel(64);

        Self {
            endpoint: Arc::new(Mutex::new(String::new())),
            state: Arc::new(Mutex::new(ConnectionState::Disconnected)),
            write_tx: Arc::new(Mutex::new(None)),
            event_rx: Arc::new(Mutex::new(Some(event_rx))),
            event_tx,
            response_rx: Arc::new(Mutex::new(Some(response_rx))),
            response_tx,
            task_handle: Arc::new(Mutex::new(None)),
            rpc_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Take the event receiver. Can only be called once; subsequent
    /// calls return `None`. The caller should poll this receiver in a
    /// loop to handle push events.
    pub fn take_event_receiver(&self) -> Option<mpsc::Receiver<GspEvent>> {
        self.event_rx.lock().take()
    }

    /// Connect to a GSP WebSocket endpoint.
    ///
    /// Spawns a background task that maintains the connection, reads
    /// incoming messages, and dispatches events.
    pub async fn connect(&self, endpoint: &str) -> Result<(), NetworkError> {
        // Store the endpoint.
        *self.endpoint.lock() = endpoint.to_string();
        *self.state.lock() = ConnectionState::Connecting;

        let url = endpoint.to_string();

        // Open the WebSocket connection.
        let (ws_stream, _) = tokio_tungstenite::connect_async(&url)
            .await
            .map_err(|e| NetworkError::WebSocket(format!("connect failed: {}", e)))?;

        let (mut ws_write, mut ws_read) = ws_stream.split();

        // Create an internal channel for outbound messages.
        let (write_tx, mut write_rx) = mpsc::channel::<String>(64);
        *self.write_tx.lock() = Some(write_tx);

        *self.state.lock() = ConnectionState::Connected;

        // Notify the app that we are connected.
        let _ = self
            .event_tx
            .send(GspEvent::LockStateChanged { connected: true })
            .await;

        let state = Arc::clone(&self.state);
        let event_tx = self.event_tx.clone();
        let response_tx = self.response_tx.clone();

        // Spawn a task that drives both read and write sides.
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Outbound: forward queued messages to the WebSocket.
                    Some(msg) = write_rx.recv() => {
                        if ws_write.send(Message::Text(msg)).await.is_err() {
                            break;
                        }
                    }
                    // Inbound: read from the WebSocket.
                    Some(Ok(msg)) = ws_read.next() => {
                        match msg {
                            Message::Text(text) => {
                                if let Ok(response) = serde_json::from_str::<GspResponse>(&text) {
                                    // Dispatch push events to the event channel and
                                    // RPC responses to the response channel.
                                    match &response {
                                        GspResponse::BalanceUpdate { confirmed, pending } => {
                                            let _ = event_tx
                                                .send(GspEvent::BalanceChanged {
                                                    confirmed: *confirmed,
                                                    pending: *pending,
                                                })
                                                .await;
                                        }
                                        GspResponse::PaymentUpdate {
                                            txid,
                                            status: _,
                                            confirmations,
                                        } => {
                                            let _ = event_tx
                                                .send(GspEvent::PaymentConfirmed {
                                                    txid: txid.clone(),
                                                    confirmations: *confirmations,
                                                })
                                                .await;
                                        }
                                        _ => {}
                                    }
                                    let _ = response_tx.send(response).await;
                                }
                            }
                            Message::Close(_) => break,
                            Message::Ping(data) => {
                                let _ = ws_write.send(Message::Pong(data)).await;
                            }
                            _ => {}
                        }
                    }
                    // WebSocket stream ended.
                    else => break,
                }
            }

            // Notify disconnected.
            *state.lock() = ConnectionState::Disconnected;
            let _ = event_tx
                .send(GspEvent::LockStateChanged { connected: false })
                .await;
        });

        *self.task_handle.lock() = Some(handle);
        Ok(())
    }

    /// Send a serialized request over the WebSocket.
    async fn send_request(&self, request: &GspRequest) -> Result<(), NetworkError> {
        let json = serde_json::to_string(request)
            .map_err(|e| NetworkError::RequestFailed(e.to_string()))?;

        let tx = self.write_tx.lock().clone();
        match tx {
            Some(tx) => tx
                .send(json)
                .await
                .map_err(|_| NetworkError::WebSocket("send channel closed".into())),
            None => Err(NetworkError::WebSocket("not connected".into())),
        }
    }

    /// Wait for the next RPC-style response from the GSP.
    async fn recv_response(&self) -> Result<GspResponse, NetworkError> {
        let mut rx_opt = self.response_rx.lock().take();
        match rx_opt.as_mut() {
            Some(rx) => {
                let result = rx
                    .recv()
                    .await
                    .ok_or_else(|| NetworkError::WebSocket("response channel closed".into()));
                // Put the receiver back
                *self.response_rx.lock() = rx_opt;
                result
            }
            None => Err(NetworkError::WebSocket(
                "response receiver already taken".into(),
            )),
        }
    }

    /// Authenticate with the GSP.
    pub async fn authenticate(&self, wallet_id: &str, token: &str) -> Result<String, NetworkError> {
        let _lock = self.rpc_lock.lock().await;
        self.send_request(&GspRequest::Authenticate {
            wallet_id: wallet_id.to_string(),
            token: token.to_string(),
        })
        .await?;

        match self.recv_response().await? {
            GspResponse::Authenticated { session_id } => {
                *self.state.lock() = ConnectionState::Authenticated;
                Ok(session_id)
            }
            GspResponse::Error { code, message } => Err(NetworkError::AuthenticationFailed(
                format!("code {}: {}", code, message),
            )),
            other => Err(NetworkError::InvalidResponse(format!(
                "expected Authenticated, got {:?}",
                other
            ))),
        }
    }

    /// Request the current wallet balance.
    pub async fn get_balance(&self) -> Result<(u64, u64), NetworkError> {
        self.require_authenticated()?;
        let _lock = self.rpc_lock.lock().await;
        self.send_request(&GspRequest::GetBalance).await?;

        match self.recv_response().await? {
            GspResponse::Balance { confirmed, pending } => Ok((confirmed, pending)),
            GspResponse::Error { code, message } => Err(NetworkError::RequestFailed(format!(
                "code {}: {}",
                code, message
            ))),
            other => Err(NetworkError::InvalidResponse(format!(
                "expected Balance, got {:?}",
                other
            ))),
        }
    }

    /// Request a payment to be prepared (returns unsigned tx for signing).
    pub async fn prepare_payment(
        &self,
        to: &str,
        amount: u64,
    ) -> Result<(String, u64), NetworkError> {
        self.require_authenticated()?;
        let _lock = self.rpc_lock.lock().await;
        self.send_request(&GspRequest::PreparePayment {
            to: to.to_string(),
            amount,
        })
        .await?;

        match self.recv_response().await? {
            GspResponse::PaymentPrepared { unsigned_tx, fee } => Ok((unsigned_tx, fee)),
            GspResponse::Error { code, message } => Err(NetworkError::RequestFailed(format!(
                "code {}: {}",
                code, message
            ))),
            other => Err(NetworkError::InvalidResponse(format!(
                "expected PaymentPrepared, got {:?}",
                other
            ))),
        }
    }

    /// Submit a signed transaction for broadcast.
    pub async fn submit_payment(&self, signed_tx: &str) -> Result<String, NetworkError> {
        self.require_authenticated()?;
        let _lock = self.rpc_lock.lock().await;
        self.send_request(&GspRequest::SubmitSignedPayment {
            signed_tx: signed_tx.to_string(),
        })
        .await?;

        match self.recv_response().await? {
            GspResponse::PaymentSubmitted { txid } => Ok(txid),
            GspResponse::Error { code, message } => Err(NetworkError::RequestFailed(format!(
                "code {}: {}",
                code, message
            ))),
            other => Err(NetworkError::InvalidResponse(format!(
                "expected PaymentSubmitted, got {:?}",
                other
            ))),
        }
    }

    /// Subscribe to balance change notifications.
    pub async fn subscribe_balance(&self) -> Result<(), NetworkError> {
        self.require_authenticated()?;
        self.send_request(&GspRequest::SubscribeBalance).await
    }

    /// Subscribe to payment notifications.
    pub async fn subscribe_payments(&self) -> Result<(), NetworkError> {
        self.require_authenticated()?;
        self.send_request(&GspRequest::SubscribePayments).await
    }

    /// Reject requests if not yet authenticated (except Authenticate itself).
    fn require_authenticated(&self) -> Result<(), NetworkError> {
        if !matches!(*self.state.lock(), ConnectionState::Authenticated) {
            return Err(NetworkError::AuthenticationFailed(
                "not authenticated".into(),
            ));
        }
        Ok(())
    }

    /// Check whether the client is currently connected.
    pub fn is_connected(&self) -> bool {
        let state = *self.state.lock();
        state == ConnectionState::Connected || state == ConnectionState::Authenticated
    }

    /// Check whether the client has authenticated.
    pub fn is_authenticated(&self) -> bool {
        *self.state.lock() == ConnectionState::Authenticated
    }

    /// Get the current endpoint URL.
    pub fn endpoint(&self) -> String {
        self.endpoint.lock().clone()
    }

    /// Disconnect from the GSP.
    ///
    /// Cancels the background task and drops the WebSocket channels.
    pub async fn disconnect(&self) {
        // Drop the write channel to signal the task to exit.
        *self.write_tx.lock() = None;

        // Take the handle out of the lock before awaiting.
        let handle = self.task_handle.lock().take();
        if let Some(handle) = handle {
            handle.abort();
            let _ = handle.await;
        }

        *self.state.lock() = ConnectionState::Disconnected;
    }
}

impl Default for MobileGspClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization() {
        let req = GspRequest::Authenticate {
            wallet_id: "w123".into(),
            token: "tok".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("Authenticate"));
        assert!(json.contains("w123"));
    }

    #[test]
    fn test_response_deserialization() {
        let json = r#"{"type":"Authenticated","payload":{"session_id":"sess_abc"}}"#;
        let resp: GspResponse = serde_json::from_str(json).unwrap();
        match resp {
            GspResponse::Authenticated { session_id } => {
                assert_eq!(session_id, "sess_abc");
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_balance_response() {
        let json = r#"{"type":"Balance","payload":{"confirmed":100000000,"pending":50000}}"#;
        let resp: GspResponse = serde_json::from_str(json).unwrap();
        match resp {
            GspResponse::Balance { confirmed, pending } => {
                assert_eq!(confirmed, 100_000_000);
                assert_eq!(pending, 50_000);
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_error_response() {
        let json = r#"{"type":"Error","payload":{"code":401,"message":"unauthorized"}}"#;
        let resp: GspResponse = serde_json::from_str(json).unwrap();
        match resp {
            GspResponse::Error { code, message } => {
                assert_eq!(code, 401);
                assert_eq!(message, "unauthorized");
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn test_client_initial_state() {
        let client = MobileGspClient::new();
        assert!(!client.is_connected());
        assert!(!client.is_authenticated());
    }

    #[test]
    fn test_prepare_payment_serialization() {
        let req = GspRequest::PreparePayment {
            to: "GhAddr123".into(),
            amount: 50_000_000,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("PreparePayment"));
        assert!(json.contains("GhAddr123"));
        assert!(json.contains("50000000"));
    }

    #[test]
    fn test_event_variants() {
        let evt = GspEvent::BalanceChanged {
            confirmed: 100,
            pending: 50,
        };
        match evt {
            GspEvent::BalanceChanged { confirmed, pending } => {
                assert_eq!(confirmed, 100);
                assert_eq!(pending, 50);
            }
            _ => panic!("wrong variant"),
        }
    }
}
