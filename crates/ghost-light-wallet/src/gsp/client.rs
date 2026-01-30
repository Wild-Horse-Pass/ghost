//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: gsp/client.rs                                                                                                  |
//|======================================================================================================================|

//! GSP WebSocket client

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use parking_lot::RwLock;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use tracing::{debug, error, info, warn};

use ghost_gsp_proto::{
    ClientMessage, InstantCapability, LockStateSnapshot, ServerMessage, SessionToken, WalletId,
};
use ghost_common::instant::LockSnapshot;

/// Balance information from GSP
#[derive(Debug, Clone, Default)]
pub struct GspBalance {
    /// Confirmed balance in satoshis
    pub confirmed: u64,
    /// Unconfirmed balance in satoshis
    pub unconfirmed: u64,
    /// Locked balance in satoshis (in Ghost Locks)
    pub locked: u64,
}

use crate::error::{LightWalletError, WalletResult};

/// Callback for lock state updates
pub type LockStateCallback = Arc<dyn Fn(String, LockStateSnapshot) + Send + Sync>;

/// GSP client for WebSocket communication
pub struct GspClient {
    /// GSP URL
    url: String,

    /// Wallet ID for authentication
    wallet_id: WalletId,

    /// Session token (after authentication)
    session_token: Arc<RwLock<Option<SessionToken>>>,

    /// Sender for outgoing messages
    tx: mpsc::Sender<ClientMessage>,

    /// Connection state
    connected: Arc<RwLock<bool>>,

    /// Pending instant capability requests (lock_id -> response channel)
    pending_instant_checks: Arc<RwLock<std::collections::HashMap<String, tokio::sync::oneshot::Sender<InstantCapability>>>>,

    /// Lock state subscriptions (lock_id -> callback)
    lock_state_callbacks: Arc<RwLock<std::collections::HashMap<String, LockStateCallback>>>,

    /// Last known lock state snapshots (for caching)
    lock_snapshots: Arc<RwLock<std::collections::HashMap<String, LockStateSnapshot>>>,
}

impl GspClient {
    /// Connect to a GSP
    pub async fn connect(url: &str, wallet_id: &WalletId) -> WalletResult<Self> {
        info!(url = url, "Connecting to GSP");

        // Connect WebSocket
        let (ws_stream, _response) = connect_async(url)
            .await
            .map_err(|e| LightWalletError::ConnectionFailed(e.to_string()))?;

        let (write, read) = ws_stream.split();

        // Create message channel
        let (tx, rx) = mpsc::channel::<ClientMessage>(32);

        let connected = Arc::new(RwLock::new(true));
        let session_token = Arc::new(RwLock::new(None));
        let pending_instant_checks = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let lock_state_callbacks = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let lock_snapshots = Arc::new(RwLock::new(std::collections::HashMap::new()));

        // Spawn write task
        let connected_clone = connected.clone();
        tokio::spawn(Self::write_task(rx, write, connected_clone));

        // Spawn read task
        let connected_clone = connected.clone();
        let session_clone = session_token.clone();
        let pending_checks_clone = pending_instant_checks.clone();
        let callbacks_clone = lock_state_callbacks.clone();
        let snapshots_clone = lock_snapshots.clone();
        tokio::spawn(Self::read_task(
            read,
            connected_clone,
            session_clone,
            pending_checks_clone,
            callbacks_clone,
            snapshots_clone,
        ));

        info!(url = url, "Connected to GSP");

        Ok(Self {
            url: url.to_string(),
            wallet_id: wallet_id.clone(),
            session_token,
            tx,
            connected,
            pending_instant_checks,
            lock_state_callbacks,
            lock_snapshots,
        })
    }

    /// Write task - sends messages to WebSocket
    async fn write_task(
        mut rx: mpsc::Receiver<ClientMessage>,
        mut write: futures_util::stream::SplitSink<
            WebSocketStream<MaybeTlsStream<TcpStream>>,
            Message,
        >,
        connected: Arc<RwLock<bool>>,
    ) {
        while let Some(msg) = rx.recv().await {
            let json = match serde_json::to_string(&msg) {
                Ok(j) => j,
                Err(e) => {
                    error!("Failed to serialize message: {}", e);
                    continue;
                }
            };

            if let Err(e) = write.send(Message::Text(json)).await {
                error!("Failed to send message: {}", e);
                *connected.write() = false;
                break;
            }
        }
    }

    /// Read task - receives messages from WebSocket
    async fn read_task(
        mut read: futures_util::stream::SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
        connected: Arc<RwLock<bool>>,
        _session_token: Arc<RwLock<Option<SessionToken>>>,
        pending_instant_checks: Arc<RwLock<std::collections::HashMap<String, tokio::sync::oneshot::Sender<InstantCapability>>>>,
        lock_state_callbacks: Arc<RwLock<std::collections::HashMap<String, LockStateCallback>>>,
        lock_snapshots: Arc<RwLock<std::collections::HashMap<String, LockStateSnapshot>>>,
    ) {
        while let Some(result) = read.next().await {
            match result {
                Ok(Message::Text(text)) => match serde_json::from_str::<ServerMessage>(&text) {
                    Ok(msg) => {
                        Self::handle_server_message_with_callbacks(
                            msg,
                            &pending_instant_checks,
                            &lock_state_callbacks,
                            &lock_snapshots,
                        )
                        .await;
                    }
                    Err(e) => {
                        warn!("Failed to parse server message: {}", e);
                    }
                },
                Ok(Message::Close(_)) => {
                    info!("GSP closed connection");
                    *connected.write() = false;
                    break;
                }
                Ok(Message::Ping(data)) => {
                    debug!("Received ping: {:?}", data);
                }
                Ok(_) => {}
                Err(e) => {
                    error!("WebSocket error: {}", e);
                    *connected.write() = false;
                    break;
                }
            }
        }
    }

    /// Handle incoming server message (legacy - for simple cases)
    async fn handle_server_message(msg: ServerMessage) {
        match msg {
            ServerMessage::BalanceUpdate {
                confirmed,
                unconfirmed,
                locked,
            } => {
                info!(
                    confirmed = confirmed,
                    unconfirmed = unconfirmed,
                    locked = locked,
                    "Balance update received"
                );
            }
            ServerMessage::PaymentReceived {
                payment_id,
                amount_sats,
                ..
            } => {
                info!(
                    payment_id = payment_id,
                    amount = amount_sats,
                    "Payment received"
                );
            }
            ServerMessage::PaymentConfirmed { payment_id, .. } => {
                info!(payment_id = payment_id, "Payment confirmed");
            }
            ServerMessage::LockConfirmed { lock_id, txid, .. } => {
                info!(lock_id = lock_id, txid = txid, "Lock confirmed");
            }
            ServerMessage::Error { code, message, .. } => {
                error!(code = code, message = message, "GSP error");
            }
            _ => {
                debug!("Received server message: {:?}", msg);
            }
        }
    }

    /// Handle incoming server message with callbacks for instant payments
    async fn handle_server_message_with_callbacks(
        msg: ServerMessage,
        pending_instant_checks: &Arc<RwLock<std::collections::HashMap<String, tokio::sync::oneshot::Sender<InstantCapability>>>>,
        lock_state_callbacks: &Arc<RwLock<std::collections::HashMap<String, LockStateCallback>>>,
        lock_snapshots: &Arc<RwLock<std::collections::HashMap<String, LockStateSnapshot>>>,
    ) {
        match msg {
            // Handle instant capability result
            ServerMessage::InstantCapabilityResult {
                lock_id,
                capable,
                max_instant_sats,
                confidence,
                valid_until_height,
                conditions_met,
                conditions_failed,
                error,
            } => {
                if let Some(err) = error {
                    warn!(lock_id = lock_id, error = err, "Instant capability check failed");
                }

                // Build capability response
                let capability = InstantCapability {
                    capable,
                    max_instant_sats,
                    confidence,
                    valid_until_height,
                    conditions_met: InstantCapability::from_bitmap(conditions_met),
                    conditions_failed: InstantCapability::from_bitmap(conditions_failed),
                };

                // Send to waiting request
                if let Some(tx) = pending_instant_checks.write().remove(&lock_id) {
                    let _ = tx.send(capability);
                }
            }

            // Handle lock state subscription confirmed
            ServerMessage::LockStateSubscribed { lock_id, snapshot } => {
                info!(lock_id = lock_id, "Lock state subscription confirmed");
                lock_snapshots.write().insert(lock_id, snapshot);
            }

            // Handle real-time lock state update
            ServerMessage::LockStateUpdate {
                lock_id,
                snapshot,
                change_type,
                timestamp: _,
            } => {
                debug!(
                    lock_id = lock_id,
                    change_type = ?change_type,
                    "Lock state update received"
                );

                // Update cached snapshot
                lock_snapshots.write().insert(lock_id.clone(), snapshot.clone());

                // Notify callback if registered
                if let Some(callback) = lock_state_callbacks.read().get(&lock_id) {
                    callback(lock_id, snapshot);
                }
            }

            // Handle instant payment accepted
            ServerMessage::InstantPaymentAccepted {
                payment_id,
                sender_lock_id,
                amount_sats,
                settlement_block,
                confidence,
                ..
            } => {
                info!(
                    payment_id = payment_id,
                    sender = sender_lock_id,
                    amount = amount_sats,
                    settlement_block = settlement_block,
                    confidence = confidence,
                    "Instant payment accepted"
                );
            }

            // Handle instant payment settled
            ServerMessage::InstantPaymentSettled {
                payment_id,
                settled_at_height,
                success,
            } => {
                if success {
                    info!(
                        payment_id = payment_id,
                        height = settled_at_height,
                        "Instant payment settled"
                    );
                } else {
                    warn!(
                        payment_id = payment_id,
                        height = settled_at_height,
                        "Instant payment settlement failed"
                    );
                }
            }

            // Delegate other messages to standard handler
            _ => Self::handle_server_message(msg).await,
        }
    }

    /// Authenticate with session token
    pub async fn authenticate(&self, token: &str) -> WalletResult<()> {
        let msg = ClientMessage::Authenticate {
            token: token.to_string(),
        };

        self.send_message(msg).await?;

        // Store session token
        let now = chrono::Utc::now().timestamp();
        *self.session_token.write() = Some(SessionToken {
            token: token.to_string(),
            wallet_id: self.wallet_id.clone(),
            created_at: now,
            expires_at: now + 86400,
        });

        Ok(())
    }

    /// Send a message to the GSP
    async fn send_message(&self, msg: ClientMessage) -> WalletResult<()> {
        if !*self.connected.read() {
            return Err(LightWalletError::NotConnected);
        }

        self.tx
            .send(msg)
            .await
            .map_err(|e| LightWalletError::ConnectionFailed(e.to_string()))?;

        Ok(())
    }

    /// Get balance from GSP
    pub async fn get_balance(&self) -> WalletResult<GspBalance> {
        self.send_message(ClientMessage::GetBalance).await?;

        // In a real implementation, we'd wait for the response
        // For now, return placeholder
        Ok(GspBalance {
            confirmed: 0,
            unconfirmed: 0,
            locked: 0,
        })
    }

    /// Get UTXOs
    pub async fn get_utxos(&self, min_confirmations: u32) -> WalletResult<()> {
        self.send_message(ClientMessage::GetUtxos { min_confirmations })
            .await
    }

    /// Get transactions
    pub async fn get_transactions(&self, limit: u32, offset: u32) -> WalletResult<()> {
        self.send_message(ClientMessage::GetTransactions { limit, offset })
            .await
    }

    /// Get Ghost Locks
    pub async fn get_ghost_locks(&self) -> WalletResult<()> {
        self.send_message(ClientMessage::GetGhostLocks).await
    }

    // =========================================================================
    // Instant Payment Methods
    // =========================================================================

    /// Check instant payment capability for a lock
    ///
    /// Returns the instant capability status including max amount and confidence.
    pub async fn check_instant_capability(
        &self,
        lock_id: &str,
        amount_sats: u64,
    ) -> WalletResult<InstantCapability> {
        // Create oneshot channel for response
        let (tx, rx) = tokio::sync::oneshot::channel();

        // Register pending request
        self.pending_instant_checks
            .write()
            .insert(lock_id.to_string(), tx);

        // Send request
        self.send_message(ClientMessage::CheckInstantCapability {
            lock_id: lock_id.to_string(),
            amount_sats,
        })
        .await?;

        // Wait for response with timeout
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
            Ok(Ok(capability)) => Ok(capability),
            Ok(Err(_)) => Err(LightWalletError::GspError(
                "Response channel closed".to_string(),
            )),
            Err(_) => {
                // Remove pending request on timeout
                self.pending_instant_checks.write().remove(lock_id);
                Err(LightWalletError::GspError(
                    "Instant capability check timed out".to_string(),
                ))
            }
        }
    }

    /// Query lock state for instant payment evaluation
    ///
    /// Returns a LockSnapshot that can be used to evaluate instant capability locally.
    pub async fn query_lock_state(&self, lock_id: &str) -> WalletResult<LockSnapshot> {
        // First, check if we have a cached snapshot
        if let Some(snapshot) = self.lock_snapshots.read().get(lock_id) {
            return Ok(self.convert_snapshot(lock_id, snapshot));
        }

        // Subscribe to get initial snapshot
        self.send_message(ClientMessage::SubscribeLockState {
            lock_id: lock_id.to_string(),
        })
        .await?;

        // Wait for subscription confirmation with snapshot
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Check cache again
        if let Some(snapshot) = self.lock_snapshots.read().get(lock_id) {
            Ok(self.convert_snapshot(lock_id, snapshot))
        } else {
            Err(LightWalletError::LockNotFound(lock_id.to_string()))
        }
    }

    /// Convert GSP snapshot to common LockSnapshot
    fn convert_snapshot(&self, lock_id: &str, snapshot: &LockStateSnapshot) -> LockSnapshot {
        // Determine denomination from balance
        let denomination = Self::denomination_from_balance(snapshot.balance_sats);

        LockSnapshot {
            lock_id: lock_id.to_string(),
            state: snapshot.state.clone(),
            balance_sats: snapshot.balance_sats,
            funding_height: 0, // Not provided in real-time snapshot
            confirmations: snapshot.confirmations,
            denomination,
            jump_urgency: snapshot.jump_urgency,
            recovery_blocks_remaining: 26280, // Default - would come from full lock info
            recovery_window_total: 52560,
            in_mempool: snapshot.in_mempool,
            pending_l2_sats: snapshot.pending_l2_sats,
        }
    }

    /// Determine denomination tier from balance
    fn denomination_from_balance(balance_sats: u64) -> String {
        match balance_sats {
            0..=10_000 => "Micro",
            10_001..=100_000 => "Tiny",
            100_001..=1_000_000 => "Small",
            1_000_001..=10_000_000 => "Medium",
            10_000_001..=100_000_000 => "Large",
            _ => "XL",
        }
        .to_string()
    }

    /// Subscribe to real-time lock state updates
    ///
    /// The callback will be invoked whenever the lock state changes.
    pub async fn subscribe_lock_state(
        &self,
        lock_id: &str,
        callback: LockStateCallback,
    ) -> WalletResult<()> {
        // Register callback
        self.lock_state_callbacks
            .write()
            .insert(lock_id.to_string(), callback);

        // Send subscription request
        self.send_message(ClientMessage::SubscribeLockState {
            lock_id: lock_id.to_string(),
        })
        .await
    }

    /// Unsubscribe from lock state updates
    pub async fn unsubscribe_lock_state(&self, lock_id: &str) -> WalletResult<()> {
        // Remove callback
        self.lock_state_callbacks.write().remove(lock_id);

        // Send unsubscribe request
        self.send_message(ClientMessage::UnsubscribeLockState {
            lock_id: lock_id.to_string(),
        })
        .await
    }

    /// Get cached lock snapshot (if available)
    pub fn get_cached_lock_state(&self, lock_id: &str) -> Option<LockStateSnapshot> {
        self.lock_snapshots.read().get(lock_id).cloned()
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        *self.connected.read()
    }

    /// Get GSP URL
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Close connection
    pub async fn close(&self) {
        *self.connected.write() = false;
        info!(url = self.url, "Closed GSP connection");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        // Basic test - actual connection requires running GSP
        let wallet_id = WalletId::from_pubkey(&[0u8; 32]);
        assert!(!wallet_id.to_string().is_empty());
    }
}
