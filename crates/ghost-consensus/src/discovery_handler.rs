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

use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

use ghost_common::error::GhostResult;
use ghost_common::types::NodeId;

use crate::ban_manager::BanManager;
use crate::mesh::MessageHandler;
use crate::message::{DiscoveryMessage, MessageEnvelope, MessageType, PeerInfo};
use crate::peer::PeerManager;

/// Maximum peers to include in a discovery broadcast
const MAX_PEERS_PER_BROADCAST: usize = 20;

/// SEC-P2P-2: Validate a peer address for basic sanity
///
/// Rejects obviously invalid addresses that could indicate:
/// - Attempts to discover local/private network addresses
/// - Malformed addresses that could cause issues
/// - Addresses with invalid ports
fn validate_peer_address(address: &str) -> bool {
    // Must not be empty
    if address.is_empty() {
        return false;
    }

    // Must contain host:port format
    // Use rsplit to handle IPv6 addresses like [::1]:8555
    let parts: Vec<&str> = address.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return false;
    }

    let port_str = parts[0];
    let host = parts[1];

    // Port must be valid
    let port: u16 = match port_str.parse() {
        Ok(p) if p > 0 => p,
        _ => return false,
    };

    // Reject obviously invalid addresses
    if host.is_empty()
        || host == "0.0.0.0"
        || host == "127.0.0.1"
        || host == "localhost"
        || host == "::1"
        || host == "[::1]"
        || host.starts_with("192.168.")
        || host.starts_with("10.")
        || host.starts_with("172.16.")
        || host.starts_with("172.17.")
        || host.starts_with("172.18.")
        || host.starts_with("172.19.")
        || host.starts_with("172.2")
        || host.starts_with("172.30.")
        || host.starts_with("172.31.")
        || host.starts_with("169.254.")  // Link-local
    {
        return false;
    }

    // Reject unreasonable ports (below 1024 or above 65000)
    if port < 1024 || port > 65000 {
        warn!(address = %address, port = port, "Rejecting address with unusual port");
        return false;
    }

    true
}

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
    /// M-P2P-3: Shared ban manager for cross-handler enforcement
    ban_manager: Option<Arc<BanManager>>,
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
            ban_manager: None,
        }
    }

    /// Set callback for connecting to newly discovered peers
    pub fn with_connect_callback(mut self, callback: ConnectCallback) -> Self {
        self.connect_callback = Some(callback);
        self
    }

    /// M-P2P-3: Set the shared ban manager for cross-handler enforcement
    ///
    /// When set, discovery messages from banned nodes are silently ignored.
    pub fn with_ban_manager(mut self, ban_manager: Arc<BanManager>) -> Self {
        self.ban_manager = Some(ban_manager);
        self
    }

    /// M-P2P-3: Check if a node is currently banned
    fn is_banned(&self, node_id: &NodeId) -> bool {
        self.ban_manager
            .as_ref()
            .is_some_and(|bm| bm.is_banned(node_id))
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
        // M-P2P-3: Silently ignore discovery messages from banned nodes
        if self.is_banned(&envelope.sender) {
            return Ok(()); // Silently ignore banned nodes
        }

        let discovery_msg: DiscoveryMessage = serde_json::from_slice(&envelope.payload)
            .map_err(|e| ghost_common::error::GhostError::P2PMessage(e.to_string()))?;

        let sender_id_hex = hex::encode(&envelope.sender[..8]);

        // Add the sender as a known peer
        // SEC-P2P-3: Validate address before accepting
        if !discovery_msg.public_address.is_empty() {
            if !validate_peer_address(&discovery_msg.public_address) {
                warn!(
                    sender = %sender_id_hex,
                    address = %discovery_msg.public_address,
                    "Rejecting invalid peer address from discovery"
                );
            } else {
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

            // SEC-P2P-4: Validate addresses from peer list
            if !validate_peer_address(&peer_info.public_address) {
                warn!(
                    sender = %sender_id_hex,
                    peer_address = %peer_info.public_address,
                    "Rejecting invalid address from peer list"
                );
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
    use crate::ban_manager::BanReason;

    #[test]
    fn test_discovery_handler_creation() {
        let peers = Arc::new(PeerManager::new([1u8; 32], 100));
        let handler = DiscoveryHandler::new([1u8; 32], "tcp://127.0.0.1:8559".to_string(), peers);
        assert_eq!(handler.known_peer_count(), 0);
    }

    #[test]
    fn test_add_known_peer() {
        let peers = Arc::new(PeerManager::new([1u8; 32], 100));
        let handler = DiscoveryHandler::new([1u8; 32], "tcp://127.0.0.1:8559".to_string(), peers);

        handler.add_known_peer([2u8; 32], "tcp://192.168.1.2:8559".to_string());
        assert_eq!(handler.known_peer_count(), 1);

        let msg = handler.get_discovery_message();
        assert_eq!(msg.known_peers.len(), 1);
    }

    #[test]
    fn test_ban_manager_integration() {
        // M-P2P-3: Test that BanManager properly integrates with DiscoveryHandler
        let peers = Arc::new(PeerManager::new([1u8; 32], 100));
        let ban_manager = Arc::new(BanManager::new());
        let handler = DiscoveryHandler::new([1u8; 32], "tcp://127.0.0.1:8559".to_string(), peers)
            .with_ban_manager(ban_manager.clone());

        let node_id = [2u8; 32];

        // Initially not banned
        assert!(!handler.is_banned(&node_id));

        // Ban the node via shared manager
        ban_manager.ban(node_id, BanReason::Equivocation);

        // Now should be banned
        assert!(handler.is_banned(&node_id));

        // Unban
        ban_manager.unban(&node_id);
        assert!(!handler.is_banned(&node_id));
    }

    #[test]
    fn test_no_ban_manager_returns_false() {
        // Without a ban manager, is_banned should always return false
        let peers = Arc::new(PeerManager::new([1u8; 32], 100));
        let handler = DiscoveryHandler::new([1u8; 32], "tcp://127.0.0.1:8559".to_string(), peers);

        // Without ban manager, should never be considered banned
        assert!(!handler.is_banned(&[2u8; 32]));
    }
}
