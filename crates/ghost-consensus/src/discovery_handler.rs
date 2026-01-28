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
//| FILE: discovery_handler.rs                                                                                           |
//|======================================================================================================================|

//! Peer Discovery Handler
//!
//! Implements gossip-based peer discovery via PUB/SUB on port 8559.
//! Periodically broadcasts known peers and merges received peer lists.

use std::sync::Arc;
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use tracing::{debug, info};

use ghost_common::error::GhostResult;
use ghost_common::types::NodeId;

use crate::mesh::MessageHandler;
use crate::message::{DiscoveryMessage, MessageEnvelope, MessageType, PeerInfo};
use crate::peer::PeerManager;

/// Maximum peers to include in a discovery broadcast
const MAX_PEERS_PER_BROADCAST: usize = 20;

/// Callback for connecting to newly discovered peers
pub type ConnectCallback = Arc<dyn Fn(String) + Send + Sync>;

/// Handler for peer discovery messages
pub struct DiscoveryHandler {
    /// Our node ID
    node_id: NodeId,
    /// Our public address
    public_address: String,
    /// Peer manager (for getting connected peer info)
    #[allow(dead_code)]
    peers: Arc<PeerManager>,
    /// Known peer addresses (node_id -> address)
    known_addresses: RwLock<HashMap<NodeId, String>>,
    /// Callback to connect to new peers
    connect_callback: Option<ConnectCallback>,
}

impl DiscoveryHandler {
    /// Create a new discovery handler
    pub fn new(node_id: NodeId, public_address: String, peers: Arc<PeerManager>) -> Self {
        Self {
            node_id,
            public_address,
            peers,
            known_addresses: RwLock::new(HashMap::new()),
            connect_callback: None,
        }
    }

    /// Set callback for connecting to newly discovered peers
    pub fn with_connect_callback(mut self, callback: ConnectCallback) -> Self {
        self.connect_callback = Some(callback);
        self
    }

    /// Add a known peer address
    pub fn add_known_peer(&self, node_id: NodeId, address: String) {
        self.known_addresses.write().insert(node_id, address);
    }

    /// Get our discovery message to broadcast
    pub fn get_discovery_message(&self) -> DiscoveryMessage {
        let known_peers = self.get_peer_list();

        DiscoveryMessage {
            node_id: self.node_id,
            public_address: self.public_address.clone(),
            capabilities: ghost_common::types::NodeCapabilities::default(),
            known_peers,
        }
    }

    /// Get list of known peers for gossip
    fn get_peer_list(&self) -> Vec<PeerInfo> {
        let addresses = self.known_addresses.read();
        let now = chrono::Utc::now().timestamp_millis() as u64;

        addresses
            .iter()
            .take(MAX_PEERS_PER_BROADCAST)
            .map(|(node_id, addr)| PeerInfo {
                node_id: *node_id,
                public_address: addr.clone(),
                last_seen: now,
                capabilities: ghost_common::types::NodeCapabilities::default(),
            })
            .collect()
    }

    /// Handle a discovery message
    async fn handle_discovery(&self, envelope: &MessageEnvelope) -> GhostResult<()> {
        let discovery_msg: DiscoveryMessage = serde_json::from_slice(&envelope.payload)
            .map_err(|e| ghost_common::error::GhostError::P2PMessage(e.to_string()))?;

        let sender_id_hex = hex::encode(&envelope.sender[..8]);

        // Add the sender as a known peer
        if !discovery_msg.public_address.is_empty() {
            let is_new = {
                let mut addresses = self.known_addresses.write();
                let is_new = !addresses.contains_key(&envelope.sender);
                addresses.insert(envelope.sender, discovery_msg.public_address.clone());
                is_new
            };

            if is_new {
                info!(
                    node_id = %sender_id_hex,
                    address = %discovery_msg.public_address,
                    "Discovered new peer from gossip"
                );

                // Try to connect to the new peer
                if let Some(ref callback) = self.connect_callback {
                    callback(discovery_msg.public_address.clone());
                }
            }
        }

        // Process the peer list from the sender
        let mut new_peers = 0;
        for peer_info in discovery_msg.known_peers {
            // Skip ourselves
            if peer_info.node_id == self.node_id {
                continue;
            }

            // Skip if we already know this peer
            if self.known_addresses.read().contains_key(&peer_info.node_id) {
                continue;
            }

            // Skip if address is empty
            if peer_info.public_address.is_empty() {
                continue;
            }

            // Add the new peer
            self.known_addresses
                .write()
                .insert(peer_info.node_id, peer_info.public_address.clone());
            new_peers += 1;

            // Try to connect
            if let Some(ref callback) = self.connect_callback {
                callback(peer_info.public_address);
            }
        }

        if new_peers > 0 {
            debug!(
                from = %sender_id_hex,
                new_peers = new_peers,
                total_known = self.known_addresses.read().len(),
                "Added peers from discovery gossip"
            );
        }

        Ok(())
    }

    /// Get count of known peers
    pub fn known_peer_count(&self) -> usize {
        self.known_addresses.read().len()
    }
}

#[async_trait]
impl MessageHandler for DiscoveryHandler {
    async fn handle_message(&self, envelope: MessageEnvelope) -> GhostResult<()> {
        if envelope.msg_type == MessageType::Discovery {
            self.handle_discovery(&envelope).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_handler_creation() {
        let peers = Arc::new(PeerManager::new([1u8; 32], 100));
        let handler = DiscoveryHandler::new(
            [1u8; 32],
            "tcp://127.0.0.1:8559".to_string(),
            peers,
        );
        assert_eq!(handler.known_peer_count(), 0);
    }

    #[test]
    fn test_add_known_peer() {
        let peers = Arc::new(PeerManager::new([1u8; 32], 100));
        let handler = DiscoveryHandler::new(
            [1u8; 32],
            "tcp://127.0.0.1:8559".to_string(),
            peers,
        );

        handler.add_known_peer([2u8; 32], "tcp://192.168.1.2:8559".to_string());
        assert_eq!(handler.known_peer_count(), 1);

        let msg = handler.get_discovery_message();
        assert_eq!(msg.known_peers.len(), 1);
    }
}
