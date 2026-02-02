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
//| FILE: peer.rs                                                                                                        |
//|======================================================================================================================|

//! Peer management for the consensus mesh

use parking_lot::RwLock;
use std::collections::HashMap;

use ghost_common::types::{NodeCapabilities, NodeId};

/// Peer manager for tracking connected peers
#[derive(Debug)]
pub struct PeerManager {
    /// Known peers
    peers: RwLock<HashMap<NodeId, Peer>>,
    /// Our node ID
    our_node_id: NodeId,
    /// Maximum peers to maintain
    max_peers: usize,
}

impl PeerManager {
    /// Create a new peer manager
    pub fn new(our_node_id: NodeId, max_peers: usize) -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            our_node_id,
            max_peers,
        }
    }

    /// Add or update a peer
    pub fn upsert_peer(&self, peer: Peer) {
        let mut peers = self.peers.write();

        if peers.len() >= self.max_peers && !peers.contains_key(&peer.node_id) {
            // At capacity, only add if peer is better than worst peer
            // For now, just reject
            return;
        }

        peers.insert(peer.node_id, peer);
    }

    /// Get a peer by node ID
    pub fn get_peer(&self, node_id: &NodeId) -> Option<Peer> {
        self.peers.read().get(node_id).cloned()
    }

    /// Remove a peer
    pub fn remove_peer(&self, node_id: &NodeId) -> Option<Peer> {
        self.peers.write().remove(node_id)
    }

    /// Get all peers
    pub fn get_all_peers(&self) -> Vec<Peer> {
        self.peers.read().values().cloned().collect()
    }

    /// Get connected peers (recently seen)
    pub fn get_connected_peers(&self, max_age_secs: u64) -> Vec<Peer> {
        let now = chrono::Utc::now().timestamp() as u64;
        let cutoff = now.saturating_sub(max_age_secs);

        self.peers
            .read()
            .values()
            .filter(|p| p.last_seen >= cutoff && p.state == PeerState::Connected)
            .cloned()
            .collect()
    }

    /// Get elder peers
    pub fn get_elder_peers(&self) -> Vec<Peer> {
        self.peers
            .read()
            .values()
            .filter(|p| p.is_elder)
            .cloned()
            .collect()
    }

    /// Update peer last seen
    pub fn update_last_seen(&self, node_id: &NodeId) {
        if let Some(peer) = self.peers.write().get_mut(node_id) {
            peer.last_seen = chrono::Utc::now().timestamp() as u64;
            peer.state = PeerState::Connected;
        }
    }

    /// Mark peer as disconnected
    pub fn mark_disconnected(&self, node_id: &NodeId) {
        if let Some(peer) = self.peers.write().get_mut(node_id) {
            peer.state = PeerState::Disconnected;
        }
    }

    /// Get peer count (total entries in peer map)
    pub fn peer_count(&self) -> usize {
        self.peers.read().len()
    }

    /// Get unique peer count by address
    ///
    /// Returns count of unique IP addresses, which represents actual peer nodes.
    /// This avoids double-counting when temp and real node_ids exist for same peer.
    pub fn unique_peer_count(&self) -> usize {
        let peers = self.peers.read();
        let unique_hosts: std::collections::HashSet<&str> = peers
            .values()
            .filter(|p| !p.public_address.is_empty())
            .map(|p| {
                p.public_address
                    .split(':')
                    .next()
                    .unwrap_or(&p.public_address)
            })
            .collect();
        unique_hosts.len()
    }

    /// Get connected peer count
    pub fn connected_count(&self) -> usize {
        self.peers
            .read()
            .values()
            .filter(|p| p.state == PeerState::Connected)
            .count()
    }

    /// Our node ID
    pub fn our_node_id(&self) -> NodeId {
        self.our_node_id
    }
}

/// Peer information
#[derive(Debug, Clone)]
pub struct Peer {
    /// Node ID
    pub node_id: NodeId,
    /// Public address (IP:port)
    pub public_address: String,
    /// Display name
    pub display_name: Option<String>,
    /// First seen timestamp
    pub first_seen: u64,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Connection state
    pub state: PeerState,
    /// Is an elder
    pub is_elder: bool,
    /// Elder order (if elder)
    pub elder_order: Option<u32>,
    /// Node capabilities
    pub capabilities: NodeCapabilities,
    /// Latency in milliseconds
    pub latency_ms: Option<u32>,
    /// Messages received from this peer
    pub messages_received: u64,
    /// Messages sent to this peer
    pub messages_sent: u64,
}

impl Peer {
    /// Create a new peer
    pub fn new(node_id: NodeId, public_address: String) -> Self {
        let now = chrono::Utc::now().timestamp() as u64;
        Self {
            node_id,
            public_address,
            display_name: None,
            first_seen: now,
            last_seen: now,
            state: PeerState::Connecting,
            is_elder: false,
            elder_order: None,
            capabilities: NodeCapabilities::default(),
            latency_ms: None,
            messages_received: 0,
            messages_sent: 0,
        }
    }

    /// Node ID as hex string
    pub fn node_id_hex(&self) -> String {
        hex::encode(self.node_id)
    }

    /// Short node ID (first 8 chars)
    pub fn node_id_short(&self) -> String {
        self.node_id_hex()[..8].to_string()
    }

    /// Calculate uptime since first seen
    pub fn uptime_secs(&self) -> u64 {
        let now = chrono::Utc::now().timestamp() as u64;
        now.saturating_sub(self.first_seen)
    }

    /// Check if peer is stale (not seen recently)
    pub fn is_stale(&self, max_age_secs: u64) -> bool {
        let now = chrono::Utc::now().timestamp() as u64;
        now.saturating_sub(self.last_seen) > max_age_secs
    }
}

/// Peer connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Connecting to peer
    Connecting,
    /// Connected and healthy
    Connected,
    /// Temporarily disconnected
    Disconnected,
    /// Banned (misbehavior)
    Banned,
}

impl Default for PeerState {
    fn default() -> Self {
        Self::Connecting
    }
}

/// Peer scoring for selection
#[derive(Debug, Clone)]
pub struct PeerScore {
    /// Node ID
    pub node_id: NodeId,
    /// Overall score (higher is better)
    pub score: f64,
    /// Latency component
    pub latency_score: f64,
    /// Reliability component
    pub reliability_score: f64,
    /// Capability component
    pub capability_score: f64,
}

impl PeerScore {
    /// Calculate peer score
    pub fn calculate(peer: &Peer) -> Self {
        // Latency score (lower latency = higher score)
        let latency_score = match peer.latency_ms {
            Some(ms) if ms < 50 => 1.0,
            Some(ms) if ms < 100 => 0.8,
            Some(ms) if ms < 200 => 0.6,
            Some(ms) if ms < 500 => 0.4,
            Some(_) => 0.2,
            None => 0.5, // Unknown
        };

        // Reliability score based on uptime
        let uptime = peer.uptime_secs();
        let reliability_score = if uptime > 86400 * 30 {
            1.0 // 30+ days
        } else if uptime > 86400 * 7 {
            0.8 // 7+ days
        } else if uptime > 86400 {
            0.6 // 1+ day
        } else {
            0.4 // < 1 day
        };

        // Capability score
        let capability_score = peer.capabilities.total_shares() as f64 / 15.0;

        // Elder bonus
        let elder_bonus = if peer.is_elder { 0.2 } else { 0.0 };

        let score = (latency_score * 0.3)
            + (reliability_score * 0.3)
            + (capability_score * 0.2)
            + elder_bonus;

        Self {
            node_id: peer.node_id,
            score,
            latency_score,
            reliability_score,
            capability_score,
        }
    }
}

/// Select best peers for propagation
pub fn select_best_peers(peers: &[Peer], count: usize) -> Vec<&Peer> {
    let mut scored: Vec<_> = peers.iter().map(|p| (p, PeerScore::calculate(p))).collect();

    scored.sort_by(|a, b| {
        b.1.score
            .partial_cmp(&a.1.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    scored.into_iter().take(count).map(|(p, _)| p).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_manager() {
        let our_id = [1u8; 32];
        let manager = PeerManager::new(our_id, 100);

        let peer = Peer::new([2u8; 32], "127.0.0.1:8555".to_string());
        manager.upsert_peer(peer);

        assert_eq!(manager.peer_count(), 1);
    }

    #[test]
    fn test_peer_scoring() {
        let mut peer = Peer::new([1u8; 32], "127.0.0.1:8555".to_string());
        peer.latency_ms = Some(50);
        peer.is_elder = true;

        let score = PeerScore::calculate(&peer);
        assert!(score.score > 0.0);
        assert!(score.latency_score > 0.5);
    }
}
