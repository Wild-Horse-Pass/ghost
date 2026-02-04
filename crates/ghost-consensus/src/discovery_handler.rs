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
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use ghost_common::error::GhostResult;
use ghost_common::types::NodeId;

use crate::ban_manager::BanManager;
use crate::mesh::MessageHandler;
use crate::message::{DiscoveryMessage, MessageEnvelope, MessageType, PeerInfo};
use crate::peer::PeerManager;

/// M-16: Token bucket rate limiter for discovery messages
///
/// Prevents flooding attacks by limiting the rate of discovery messages
/// processed per sender.
struct RateLimiter {
    /// Tokens per sender (node_id -> (tokens, last_refill))
    buckets: RwLock<HashMap<NodeId, (f64, Instant)>>,
    /// Maximum tokens per bucket
    max_tokens: f64,
    /// Token refill rate per second
    refill_rate: f64,
    /// Maximum number of buckets to track (prevents memory exhaustion)
    max_buckets: usize,
}

impl RateLimiter {
    fn new(max_tokens: f64, refill_rate: f64, max_buckets: usize) -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
            max_tokens,
            refill_rate,
            max_buckets,
        }
    }

    /// Try to consume a token for the given sender
    /// Returns true if allowed, false if rate limited
    fn try_consume(&self, sender: &NodeId) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.write();

        // Evict oldest bucket if at capacity
        if !buckets.contains_key(sender) && buckets.len() >= self.max_buckets {
            // Find and remove the bucket with the oldest last_refill time
            if let Some(oldest_key) = buckets
                .iter()
                .min_by_key(|(_, (_, last_refill))| *last_refill)
                .map(|(k, _)| *k)
            {
                buckets.remove(&oldest_key);
            }
        }

        let (tokens, last_refill) = buckets
            .entry(*sender)
            .or_insert((self.max_tokens, now));

        // Refill tokens based on elapsed time
        let elapsed = now.duration_since(*last_refill).as_secs_f64();
        *tokens = (*tokens + elapsed * self.refill_rate).min(self.max_tokens);
        *last_refill = now;

        // Try to consume a token
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Cleanup old entries (call periodically to prevent memory growth)
    #[allow(dead_code)]
    fn cleanup(&self, max_age: Duration) {
        let cutoff = Instant::now() - max_age;
        let mut buckets = self.buckets.write();
        buckets.retain(|_, (_, last_refill)| *last_refill > cutoff);
    }
}

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
    if !(1024..=65000).contains(&port) {
        warn!(address = %address, port = port, "Rejecting address with unusual port");
        return false;
    }

    true
}

/// Callback for connecting to newly discovered peers
pub type ConnectCallback = Arc<dyn Fn(String) + Send + Sync>;

/// M-16: Default discovery message rate limit (messages per second)
const DISCOVERY_RATE_LIMIT: f64 = 2.0;
/// M-16: Maximum tokens (burst capacity)
const DISCOVERY_MAX_TOKENS: f64 = 10.0;
/// M-16: Maximum rate limiter buckets
const DISCOVERY_MAX_BUCKETS: usize = 1000;

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
    /// M-16: Rate limiter for discovery messages
    rate_limiter: RateLimiter,
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
            rate_limiter: RateLimiter::new(
                DISCOVERY_MAX_TOKENS,
                DISCOVERY_RATE_LIMIT,
                DISCOVERY_MAX_BUCKETS,
            ),
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

        // M-16: Apply rate limiting to prevent discovery flooding
        if !self.rate_limiter.try_consume(&envelope.sender) {
            debug!(
                sender = %hex::encode(&envelope.sender[..8]),
                "Discovery message rate limited"
            );
            return Ok(()); // Silently drop rate-limited messages
        }

        let discovery_msg: DiscoveryMessage = serde_json::from_slice(&envelope.payload)
            .map_err(|e| ghost_common::error::GhostError::P2PMessage(e.to_string()))?;

        let sender_id_hex = hex::encode(&envelope.sender[..8]);

        // H-3: Validate that discovery message node_id matches envelope sender
        // This prevents spoofing attacks where an attacker claims to be another node
        if discovery_msg.node_id != envelope.sender {
            warn!(
                msg_node_id = %hex::encode(&discovery_msg.node_id[..8]),
                envelope_sender = %sender_id_hex,
                "Discovery message node_id doesn't match envelope sender - rejecting"
            );
            return Ok(()); // Reject spoofed messages
        }

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

    /// SEC-DISC-TEST-1: Verify that invalid/malformed addresses are rejected
    #[test]
    fn test_invalid_address_rejected() {
        // Empty address
        assert!(!validate_peer_address(""), "Empty address should be rejected");

        // No port
        assert!(!validate_peer_address("1.2.3.4"), "Address without port should be rejected");

        // Invalid port (not a number)
        assert!(!validate_peer_address("1.2.3.4:abc"), "Non-numeric port should be rejected");

        // Port zero
        assert!(!validate_peer_address("1.2.3.4:0"), "Port zero should be rejected");

        // Port too low (privileged)
        assert!(!validate_peer_address("1.2.3.4:80"), "Privileged port should be rejected");

        // Port too high
        assert!(!validate_peer_address("1.2.3.4:65535"), "Port > 65000 should be rejected");

        // Valid public address should be accepted
        assert!(validate_peer_address("8.8.8.8:8559"), "Valid public address should be accepted");
    }

    /// SEC-DISC-TEST-2: Verify that loopback and private addresses are rejected
    #[test]
    fn test_loopback_address_rejected() {
        // Loopback addresses
        assert!(!validate_peer_address("127.0.0.1:8559"), "127.0.0.1 should be rejected");
        assert!(!validate_peer_address("localhost:8559"), "localhost should be rejected");

        // Private network addresses (RFC 1918)
        assert!(!validate_peer_address("192.168.1.1:8559"), "192.168.x.x should be rejected");
        assert!(!validate_peer_address("10.0.0.1:8559"), "10.x.x.x should be rejected");
        assert!(!validate_peer_address("172.16.0.1:8559"), "172.16.x.x should be rejected");

        // Bind-all address
        assert!(!validate_peer_address("0.0.0.0:8559"), "0.0.0.0 should be rejected");
    }

    /// H-3-TEST: Verify that discovery messages with mismatched node_id are rejected
    #[test]
    fn test_discovery_rejects_mismatched_node_id() {
        use crate::message::{DiscoveryMessage, MessageEnvelope, MessageType};
        use ghost_common::types::NodeCapabilities;

        let peers = Arc::new(PeerManager::new([1u8; 32], 100));
        let handler = DiscoveryHandler::new([1u8; 32], "tcp://8.8.8.8:8559".to_string(), peers);

        // Create a discovery message claiming to be node [3u8; 32]
        let discovery_msg = DiscoveryMessage {
            node_id: [3u8; 32], // Claims to be node 3
            public_address: "tcp://8.8.8.9:8559".to_string(),
            capabilities: NodeCapabilities::default(),
            known_peers: vec![],
        };

        // But the envelope says it's from node [2u8; 32] - MISMATCH!
        let envelope = MessageEnvelope {
            sender: [2u8; 32], // Actually from node 2
            msg_type: MessageType::Discovery,
            payload: serde_json::to_vec(&discovery_msg).unwrap(),
            signature: [0u8; 64],
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            sequence: 1,
        };

        // The handler should reject this message (returns Ok but doesn't add the peer)
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // Before: no known peers except potentially self
            let before_count = handler.known_peer_count();

            // Process the spoofed message
            let result = handler.handle_message(envelope).await;
            assert!(result.is_ok(), "Should not error on spoofed message (just silently reject)");

            // After: should still have same count (message was rejected)
            let after_count = handler.known_peer_count();
            assert_eq!(before_count, after_count, "Spoofed discovery message should not add any peers");
        });
    }

    /// H-3-TEST: Verify that discovery messages with matching node_id are accepted
    #[test]
    fn test_discovery_accepts_matching_node_id() {
        use crate::message::{DiscoveryMessage, MessageEnvelope, MessageType};
        use ghost_common::types::NodeCapabilities;

        let peers = Arc::new(PeerManager::new([1u8; 32], 100));
        let handler = DiscoveryHandler::new([1u8; 32], "tcp://8.8.8.8:8559".to_string(), peers);

        // Create a discovery message from node [2u8; 32]
        let discovery_msg = DiscoveryMessage {
            node_id: [2u8; 32],
            public_address: "tcp://8.8.8.9:8559".to_string(), // Valid public address
            capabilities: NodeCapabilities::default(),
            known_peers: vec![],
        };

        // Envelope sender matches the message node_id
        let envelope = MessageEnvelope {
            sender: [2u8; 32], // Matches msg.node_id
            msg_type: MessageType::Discovery,
            payload: serde_json::to_vec(&discovery_msg).unwrap(),
            signature: [0u8; 64],
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            sequence: 1,
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let before_count = handler.known_peer_count();

            let result = handler.handle_message(envelope).await;
            assert!(result.is_ok());

            // The peer should be added since node_id matches envelope sender
            let after_count = handler.known_peer_count();
            assert_eq!(after_count, before_count + 1, "Valid discovery message should add the peer");
        });
    }

    /// M-16-TEST: Verify that rate limiter works correctly
    #[test]
    fn test_rate_limiter_basic() {
        let limiter = RateLimiter::new(5.0, 1.0, 100);
        let node = [1u8; 32];

        // First 5 requests should succeed (burst)
        for _ in 0..5 {
            assert!(limiter.try_consume(&node), "Should allow burst");
        }

        // 6th request should be rate limited
        assert!(!limiter.try_consume(&node), "Should rate limit after burst");
    }

    /// M-16-TEST: Verify rate limiter enforces per-sender limits
    #[test]
    fn test_rate_limiter_per_sender() {
        let limiter = RateLimiter::new(2.0, 1.0, 100);
        let node1 = [1u8; 32];
        let node2 = [2u8; 32];

        // Node 1 uses its tokens
        assert!(limiter.try_consume(&node1));
        assert!(limiter.try_consume(&node1));
        assert!(!limiter.try_consume(&node1), "Node 1 should be limited");

        // Node 2 should still have its tokens
        assert!(limiter.try_consume(&node2), "Node 2 should not be affected by node 1");
        assert!(limiter.try_consume(&node2));
        assert!(!limiter.try_consume(&node2), "Node 2 should be limited now");
    }
}
