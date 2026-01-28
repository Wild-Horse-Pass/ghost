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

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
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

/// WebSocket upgrade handler
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(ws_state): State<Arc<WsState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, ws_state))
}

/// Handle individual WebSocket connection
async fn handle_socket(socket: WebSocket, ws_state: Arc<WsState>) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = ws_state.subscribe();

    info!("WebSocket client connected");

    // Spawn task to forward broadcast events to this client
    let mut send_task = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
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
