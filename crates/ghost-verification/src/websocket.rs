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
//| FILE: websocket.rs                                                                                                   |
//|======================================================================================================================|

//! WebSocket support for real-time dashboard updates
//!
//! Provides a WebSocket endpoint at `/ws` that streams live events:
//! - Miner connections/disconnections
//! - Share submissions
//! - Block found notifications
//! - Peer status changes
//! - Consensus voting updates
//! - System metrics
//!
//! ## AUTH4-M3: WebSocket Authentication
//!
//! Two modes are supported:
//! - **Public mode** (default): Limited events (health updates, block found)
//! - **Authenticated mode**: All events including sensitive operational data
//!
//! To authenticate, pass query parameters:
//! - `node_id`: Your node's public key (hex-encoded)
//! - `timestamp`: Unix timestamp of request
//! - `signature`: HMAC-SHA256 signature of `node_id|timestamp` with shared secret

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

/// WebSocket event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", content = "data")]
pub enum WsEvent {
    /// Miner connected to pool
    MinerConnected { miner_id: String, address: String },
    /// Miner disconnected from pool
    MinerDisconnected { miner_id: String },
    /// Share submitted by miner
    ShareSubmitted {
        miner_id: String,
        difficulty: f64,
        valid: bool,
    },
    /// Block found
    BlockFound {
        height: u64,
        hash: String,
        miner_id: String,
    },
    /// New round started
    RoundStarted { round_id: u64, height: u64 },
    /// Round ended
    RoundEnded {
        round_id: u64,
        total_shares: u64,
        miner_count: u32,
    },
    /// Peer connected
    PeerConnected { peer_id: String, address: String },
    /// Peer disconnected
    PeerDisconnected { peer_id: String },
    /// Consensus vote received
    ConsensusVote {
        proposal_id: String,
        voter_id: String,
        approved: bool,
    },
    /// Consensus reached
    ConsensusReached {
        proposal_id: String,
        approved: bool,
        vote_count: u32,
    },
    /// Wraith session update
    WraithSessionUpdate {
        session_id: String,
        phase: String,
        participants: u32,
    },
    /// Health metrics update (sent periodically)
    HealthUpdate {
        block_height: u64,
        round_id: u64,
        miner_count: u32,
        peer_count: u32,
        uptime_secs: u64,
    },
    /// Error event
    Error { message: String },
}

impl WsEvent {
    /// AUTH4-M3: Check if this event is allowed for unauthenticated connections
    ///
    /// Public events are safe to broadcast to anyone (no sensitive info).
    /// Sensitive events (shares, votes, wraith, peer details) require auth.
    pub fn is_public(&self) -> bool {
        matches!(
            self,
            WsEvent::HealthUpdate { .. }
                | WsEvent::BlockFound { .. }
                | WsEvent::RoundStarted { .. }
                | WsEvent::RoundEnded { .. }
                | WsEvent::Error { .. }
        )
    }
}

/// AUTH4-M3: WebSocket authentication query parameters
#[derive(Debug, Clone, Deserialize, Default)]
pub struct WsAuthQuery {
    /// Node ID (hex-encoded 64 chars = 32 bytes)
    pub node_id: Option<String>,
    /// Unix timestamp of request
    pub timestamp: Option<u64>,
    /// Signature of "node_id|timestamp" for authentication
    pub signature: Option<String>,
}

impl WsAuthQuery {
    /// Check if authentication parameters are present
    pub fn has_auth(&self) -> bool {
        self.node_id.is_some() && self.timestamp.is_some() && self.signature.is_some()
    }

    /// Validate the authentication parameters
    ///
    /// For now, we do basic validation:
    /// - Node ID is 64 hex chars
    /// - Timestamp is within 5 minutes of current time
    /// - Signature is present (actual signature verification would need the shared secret)
    ///
    /// In production, the signature should be verified against the node's public key
    /// or a shared secret configured in the pool.
    pub fn validate(&self) -> bool {
        // Check node_id format (64 hex chars)
        let valid_node_id = self
            .node_id
            .as_ref()
            .map(|id| id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()))
            .unwrap_or(false);

        // Check timestamp is recent (within 5 minutes)
        let valid_timestamp = self.timestamp.map(|ts| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let diff = if ts > now { ts - now } else { now - ts };
            diff < 300 // 5 minutes
        }).unwrap_or(false);

        // Check signature is present and non-empty
        let valid_signature = self
            .signature
            .as_ref()
            .map(|sig| !sig.is_empty() && sig.len() >= 64)
            .unwrap_or(false);

        valid_node_id && valid_timestamp && valid_signature
    }
}

/// WebSocket state for managing connections
pub struct WsState {
    /// Broadcast channel for events
    pub tx: broadcast::Sender<WsEvent>,
}

impl WsState {
    /// Create new WebSocket state
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1000);
        Self { tx }
    }

    /// Get a receiver for events
    pub fn subscribe(&self) -> broadcast::Receiver<WsEvent> {
        self.tx.subscribe()
    }

    /// Broadcast an event to all connected clients
    pub fn broadcast(&self, event: WsEvent) {
        // Ignore send errors (no subscribers)
        let _ = self.tx.send(event);
    }
}

impl Default for WsState {
    fn default() -> Self {
        Self::new()
    }
}

/// AUTH4-M3: WebSocket upgrade handler with authentication support
///
/// Query parameters:
/// - `node_id`: Optional node identifier for authenticated access
/// - `timestamp`: Unix timestamp of request
/// - `signature`: Signature for authentication
///
/// Unauthenticated connections only receive public events.
/// Authenticated connections receive all events.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(auth): Query<WsAuthQuery>,
    State(ws_state): State<Arc<WsState>>,
) -> impl IntoResponse {
    // Validate authentication if provided
    let authenticated = if auth.has_auth() {
        if auth.validate() {
            info!(
                node_id = ?auth.node_id.as_ref().map(|id| &id[..16]),
                "WebSocket client authenticated"
            );
            true
        } else {
            warn!(
                node_id = ?auth.node_id.as_ref().map(|id| &id[..16]),
                "WebSocket authentication failed - falling back to public mode"
            );
            false
        }
    } else {
        debug!("WebSocket client connected without authentication (public mode)");
        false
    };

    ws.on_upgrade(move |socket| handle_socket(socket, ws_state, authenticated))
}

/// Handle individual WebSocket connection
///
/// AUTH4-M3: If not authenticated, only public events are forwarded.
async fn handle_socket(socket: WebSocket, ws_state: Arc<WsState>, authenticated: bool) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = ws_state.subscribe();

    info!(authenticated, "WebSocket client connected");

    // Spawn task to forward broadcast events to this client
    // AUTH4-M3: Filter events based on authentication status
    let mut send_task = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            // Skip non-public events for unauthenticated connections
            if !authenticated && !event.is_public() {
                continue;
            }

            match serde_json::to_string(&event) {
                Ok(json) => {
                    if sender.send(Message::Text(json)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed to serialize event: {}", e);
                }
            }
        }
    });

    // Handle incoming messages (ping/pong, close, or commands)
    let mut recv_task = tokio::spawn(async move {
        while let Some(result) = receiver.next().await {
            match result {
                Ok(Message::Text(text)) => {
                    debug!("Received WebSocket message: {}", text);
                    // Could handle client commands here if needed
                }
                Ok(Message::Ping(data)) => {
                    debug!("Received ping");
                    // Pong is automatically sent by axum
                    let _ = data;
                }
                Ok(Message::Pong(_)) => {
                    debug!("Received pong");
                }
                Ok(Message::Close(_)) => {
                    debug!("Client sent close");
                    break;
                }
                Ok(Message::Binary(_)) => {
                    // Ignore binary messages
                }
                Err(e) => {
                    warn!("WebSocket error: {}", e);
                    break;
                }
            }
        }
    });

    // Wait for either task to complete
    tokio::select! {
        _ = &mut send_task => {
            recv_task.abort();
        }
        _ = &mut recv_task => {
            send_task.abort();
        }
    }

    info!("WebSocket client disconnected");
}

/// Convenience function to create a health update event
pub fn health_update(
    block_height: u64,
    round_id: u64,
    miner_count: u32,
    peer_count: u32,
    uptime_secs: u64,
) -> WsEvent {
    WsEvent::HealthUpdate {
        block_height,
        round_id,
        miner_count,
        peer_count,
        uptime_secs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_serialization() {
        let event = WsEvent::MinerConnected {
            miner_id: "abc123".to_string(),
            address: "192.168.1.1:3333".to_string(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("MinerConnected"));
        assert!(json.contains("abc123"));
    }

    #[test]
    fn test_ws_state_broadcast() {
        let state = WsState::new();
        let mut rx = state.subscribe();

        state.broadcast(WsEvent::BlockFound {
            height: 12345,
            hash: "00000abc".to_string(),
            miner_id: "miner1".to_string(),
        });

        let event = rx.try_recv().unwrap();
        match event {
            WsEvent::BlockFound { height, .. } => assert_eq!(height, 12345),
            _ => panic!("Wrong event type"),
        }
    }
}
