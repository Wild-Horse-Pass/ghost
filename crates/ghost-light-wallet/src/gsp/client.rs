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
use tokio_tungstenite::{
    connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream,
};
use tracing::{debug, error, info, warn};

use ghost_gsp_proto::{
    ClientMessage, ServerMessage, SessionToken, WalletId,
};

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

        // Spawn write task
        let connected_clone = connected.clone();
        tokio::spawn(Self::write_task(rx, write, connected_clone));

        // Spawn read task
        let connected_clone = connected.clone();
        let session_clone = session_token.clone();
        tokio::spawn(Self::read_task(read, connected_clone, session_clone));

        info!(url = url, "Connected to GSP");

        Ok(Self {
            url: url.to_string(),
            wallet_id: wallet_id.clone(),
            session_token,
            tx,
            connected,
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
        mut read: futures_util::stream::SplitStream<
            WebSocketStream<MaybeTlsStream<TcpStream>>,
        >,
        connected: Arc<RwLock<bool>>,
        _session_token: Arc<RwLock<Option<SessionToken>>>,
    ) {
        while let Some(result) = read.next().await {
            match result {
                Ok(Message::Text(text)) => {
                    match serde_json::from_str::<ServerMessage>(&text) {
                        Ok(msg) => {
                            Self::handle_server_message(msg).await;
                        }
                        Err(e) => {
                            warn!("Failed to parse server message: {}", e);
                        }
                    }
                }
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

    /// Handle incoming server message
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
