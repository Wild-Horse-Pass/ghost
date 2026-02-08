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
//| FILE: reputation.rs                                                                                                  |
//|======================================================================================================================|

//! Peer reputation system
//!
//! Tracks peer behavior and assigns reputation scores to identify
//! and isolate misbehaving nodes. Uses a decay model where good
//! behavior slowly increases reputation and bad behavior causes
//! immediate penalties.

use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tracing::{info, warn};

use ghost_common::types::NodeId;

/// Initial reputation score for new peers
pub const INITIAL_REPUTATION: u8 = 50;

/// Maximum reputation score
pub const MAX_REPUTATION: u8 = 100;

/// Minimum reputation before disconnect
pub const DISCONNECT_THRESHOLD: u8 = 10;

/// Minimum reputation to be considered trusted
pub const TRUST_THRESHOLD: u8 = 70;

/// Minimum good messages before trusted status
pub const TRUST_MIN_GOOD_MESSAGES: u64 = 100;

/// Severity levels for bad behavior
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadBehavior {
    /// Malformed message (couldn't parse)
    MalformedMessage,
    /// Invalid signature (potential spoofing)
    InvalidSignature,
    /// Spam (too many messages too fast)
    Spam,
    /// Protocol violation (unexpected message type/state)
    ProtocolViolation,
    /// Invalid data (parsed but semantically wrong)
    InvalidData,
    /// Timeout (didn't respond in time)
    Timeout,
}

impl BadBehavior {
    /// Get the reputation penalty for this behavior
    pub fn penalty(&self) -> u8 {
        match self {
            BadBehavior::MalformedMessage => 5,
            BadBehavior::InvalidSignature => 25, // Severe - possible attack
            BadBehavior::Spam => 10,
            BadBehavior::ProtocolViolation => 15,
            BadBehavior::InvalidData => 5,
            BadBehavior::Timeout => 2,
        }
    }

    /// Should this immediately trigger investigation?
    pub fn is_suspicious(&self) -> bool {
        matches!(
            self,
            BadBehavior::InvalidSignature | BadBehavior::ProtocolViolation
        )
    }
}

/// Per-peer reputation data
#[derive(Debug, Clone)]
pub struct PeerReputation {
    /// Current reputation score (0-100)
    pub score: u8,
    /// Good messages received
    pub good_messages: u64,
    /// Bad messages received
    pub bad_messages: u64,
    /// Signature verification failures
    pub signature_failures: u64,
    /// Last activity time
    pub last_seen: Instant,
    /// First seen time
    pub first_seen: Instant,
    /// Recent bad behaviors (for pattern detection)
    recent_bad: Vec<(BadBehavior, Instant)>,
}

impl Default for PeerReputation {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            score: INITIAL_REPUTATION,
            good_messages: 0,
            bad_messages: 0,
            signature_failures: 0,
            last_seen: now,
            first_seen: now,
            recent_bad: Vec::new(),
        }
    }
}

impl PeerReputation {
    /// Record a good message
    pub fn record_good(&mut self) {
        self.good_messages += 1;
        self.last_seen = Instant::now();

        // Slow reputation increase for good behavior
        // Only increase every 10 good messages
        if self.good_messages.is_multiple_of(10) {
            self.score = self.score.saturating_add(1).min(MAX_REPUTATION);
        }
    }

    /// Record bad behavior
    pub fn record_bad(&mut self, behavior: BadBehavior) {
        self.bad_messages += 1;
        self.last_seen = Instant::now();

        if matches!(behavior, BadBehavior::InvalidSignature) {
            self.signature_failures += 1;
        }

        // Apply penalty
        let penalty = behavior.penalty();
        self.score = self.score.saturating_sub(penalty);

        // Track recent bad behaviors
        self.recent_bad.push((behavior, Instant::now()));

        // Keep only last 100 bad behaviors
        if self.recent_bad.len() > 100 {
            self.recent_bad.remove(0);
        }
    }

    /// Check if peer should be disconnected
    pub fn should_disconnect(&self) -> bool {
        self.score < DISCONNECT_THRESHOLD || self.signature_failures > 3
    }

    /// Check if peer is trusted
    pub fn is_trusted(&self) -> bool {
        self.score >= TRUST_THRESHOLD && self.good_messages >= TRUST_MIN_GOOD_MESSAGES
    }

    /// Get ratio of good to bad messages
    pub fn good_ratio(&self) -> f64 {
        let total = self.good_messages + self.bad_messages;
        if total == 0 {
            1.0
        } else {
            self.good_messages as f64 / total as f64
        }
    }

    /// Check for suspicious patterns in recent behavior
    pub fn detect_attack_pattern(&self) -> Option<&'static str> {
        let now = Instant::now();
        let recent_window = Duration::from_secs(60);

        // Count recent bad behaviors by type
        let recent: Vec<_> = self
            .recent_bad
            .iter()
            .filter(|(_, t)| now.duration_since(*t) < recent_window)
            .collect();

        // Multiple signature failures in short time = likely attack
        let sig_failures = recent
            .iter()
            .filter(|(b, _)| matches!(b, BadBehavior::InvalidSignature))
            .count();
        if sig_failures >= 2 {
            return Some("Multiple signature failures - possible spoofing attack");
        }

        // Many protocol violations = possibly fuzzing
        let protocol_violations = recent
            .iter()
            .filter(|(b, _)| matches!(b, BadBehavior::ProtocolViolation))
            .count();
        if protocol_violations >= 5 {
            return Some("Many protocol violations - possible fuzzing/probing");
        }

        // High rate of bad messages overall
        if recent.len() >= 10 {
            return Some("High rate of bad messages - misbehaving node");
        }

        None
    }

    /// Clean up old bad behavior records
    pub fn cleanup(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(3600);
        self.recent_bad.retain(|(_, t)| *t > cutoff);
    }
}

/// Reputation manager for all peers
pub struct ReputationManager {
    /// Per-peer reputation data
    peers: RwLock<HashMap<NodeId, PeerReputation>>,
    /// Permanently banned peers
    banned: RwLock<HashSet<NodeId>>,
}

impl ReputationManager {
    /// Create a new reputation manager
    pub fn new() -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            banned: RwLock::new(HashSet::new()),
        }
    }

    /// Check if a peer is banned
    pub fn is_banned(&self, node_id: &NodeId) -> bool {
        self.banned.read().contains(node_id)
    }

    /// Ban a peer permanently
    pub fn ban(&self, node_id: NodeId, reason: &str) {
        self.banned.write().insert(node_id);
        warn!(
            node_id = %hex::encode(&node_id[..8]),
            reason = reason,
            "Peer permanently banned"
        );
    }

    /// Unban a peer
    pub fn unban(&self, node_id: &NodeId) {
        if self.banned.write().remove(node_id) {
            info!(node_id = %hex::encode(&node_id[..8]), "Peer unbanned");
        }
    }

    /// Get or create peer reputation
    fn get_or_create(&self, node_id: &NodeId) -> PeerReputation {
        let peers = self.peers.read();
        peers.get(node_id).cloned().unwrap_or_default()
    }

    /// Update peer reputation
    fn update(&self, node_id: &NodeId, reputation: PeerReputation) {
        self.peers.write().insert(*node_id, reputation);
    }

    /// Record a good message from a peer
    pub fn record_good(&self, node_id: &NodeId) {
        if self.is_banned(node_id) {
            return;
        }

        let mut reputation = self.get_or_create(node_id);
        reputation.record_good();
        self.update(node_id, reputation);
    }

    /// Record bad behavior from a peer
    ///
    /// Returns true if the peer should be disconnected
    pub fn record_bad(&self, node_id: &NodeId, behavior: BadBehavior) -> bool {
        if self.is_banned(node_id) {
            return true;
        }

        let node_hex = hex::encode(&node_id[..8]);

        let mut reputation = self.get_or_create(node_id);
        reputation.record_bad(behavior);

        // Check for attack patterns
        if let Some(pattern) = reputation.detect_attack_pattern() {
            warn!(
                node_id = %node_hex,
                pattern = pattern,
                score = reputation.score,
                "Suspicious behavior detected"
            );
        }

        let should_disconnect = reputation.should_disconnect();

        if should_disconnect {
            warn!(
                node_id = %node_hex,
                score = reputation.score,
                bad_messages = reputation.bad_messages,
                sig_failures = reputation.signature_failures,
                "Peer reputation too low - disconnecting"
            );

            // Auto-ban if too many signature failures
            if reputation.signature_failures > 5 {
                self.ban(*node_id, "excessive signature failures");
            }
        }

        self.update(node_id, reputation);
        should_disconnect
    }

    /// Get peer reputation score
    pub fn get_score(&self, node_id: &NodeId) -> u8 {
        self.peers
            .read()
            .get(node_id)
            .map(|r| r.score)
            .unwrap_or(INITIAL_REPUTATION)
    }

    /// Check if peer is trusted
    pub fn is_trusted(&self, node_id: &NodeId) -> bool {
        if self.is_banned(node_id) {
            return false;
        }
        self.peers
            .read()
            .get(node_id)
            .map(|r| r.is_trusted())
            .unwrap_or(false)
    }

    /// Get all trusted peers
    pub fn get_trusted_peers(&self) -> Vec<NodeId> {
        self.peers
            .read()
            .iter()
            .filter(|(_, r)| r.is_trusted())
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get reputation statistics
    pub fn stats(&self) -> ReputationStats {
        let peers = self.peers.read();
        let banned = self.banned.read();

        let trusted_count = peers.values().filter(|r| r.is_trusted()).count();
        let low_rep_count = peers.values().filter(|r| r.score < 30).count();

        ReputationStats {
            total_peers: peers.len(),
            trusted_peers: trusted_count,
            low_reputation_peers: low_rep_count,
            banned_peers: banned.len(),
        }
    }

    /// Cleanup old data
    pub fn cleanup(&self) {
        let cutoff = Instant::now() - Duration::from_secs(86400); // 24 hours

        // Clean up inactive peers with neutral reputation
        let mut peers = self.peers.write();
        peers.retain(|_, rep| {
            // Keep if active recently
            if rep.last_seen > cutoff {
                return true;
            }
            // Keep if not neutral reputation
            if rep.score != INITIAL_REPUTATION {
                return true;
            }
            // Keep if has significant history
            if rep.good_messages > 100 || rep.bad_messages > 10 {
                return true;
            }
            false
        });

        // Cleanup internal state of remaining peers
        for rep in peers.values_mut() {
            rep.cleanup();
        }
    }
}

impl Default for ReputationManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Reputation statistics
#[derive(Debug, Clone, Default)]
pub struct ReputationStats {
    pub total_peers: usize,
    pub trusted_peers: usize,
    pub low_reputation_peers: usize,
    pub banned_peers: usize,
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    fn test_node_id() -> NodeId {
        [1u8; 32]
    }

    #[test]
    fn test_reputation_default() {
        let rep = PeerReputation::default();
        assert_eq!(rep.score, INITIAL_REPUTATION);
        assert!(!rep.is_trusted());
        assert!(!rep.should_disconnect());
    }

    #[test]
    fn test_good_message_increases_rep() {
        let mut rep = PeerReputation::default();
        let initial = rep.score;

        // Need 10 good messages for 1 point increase
        for _ in 0..10 {
            rep.record_good();
        }

        assert_eq!(rep.score, initial + 1);
        assert_eq!(rep.good_messages, 10);
    }

    #[test]
    fn test_bad_behavior_decreases_rep() {
        let mut rep = PeerReputation::default();
        let initial = rep.score;

        rep.record_bad(BadBehavior::MalformedMessage);

        assert_eq!(rep.score, initial - BadBehavior::MalformedMessage.penalty());
        assert_eq!(rep.bad_messages, 1);
    }

    #[test]
    fn test_signature_failure_severe() {
        let mut rep = PeerReputation::default();

        rep.record_bad(BadBehavior::InvalidSignature);
        rep.record_bad(BadBehavior::InvalidSignature);

        assert_eq!(rep.signature_failures, 2);
        // Should detect attack pattern
        assert!(rep.detect_attack_pattern().is_some());
    }

    #[test]
    fn test_disconnect_threshold() {
        let mut rep = PeerReputation::default();

        // Keep hitting with bad behavior until disconnect
        while !rep.should_disconnect() {
            rep.record_bad(BadBehavior::ProtocolViolation);
        }

        assert!(rep.score < DISCONNECT_THRESHOLD);
    }

    #[test]
    fn test_trusted_requires_history() {
        let mut rep = PeerReputation::default();
        rep.score = MAX_REPUTATION; // High score but no history

        assert!(!rep.is_trusted()); // Not trusted without message history

        rep.good_messages = TRUST_MIN_GOOD_MESSAGES;
        assert!(rep.is_trusted()); // Now trusted
    }

    #[test]
    fn test_reputation_manager() {
        let manager = ReputationManager::new();
        let node_id = test_node_id();

        // Record good messages
        for _ in 0..10 {
            manager.record_good(&node_id);
        }

        assert!(manager.get_score(&node_id) > INITIAL_REPUTATION);

        // Record bad behavior
        let should_disconnect = manager.record_bad(&node_id, BadBehavior::MalformedMessage);
        assert!(!should_disconnect); // Not enough bad behavior yet
    }

    #[test]
    fn test_ban() {
        let manager = ReputationManager::new();
        let node_id = test_node_id();

        assert!(!manager.is_banned(&node_id));

        manager.ban(node_id, "test");
        assert!(manager.is_banned(&node_id));

        manager.unban(&node_id);
        assert!(!manager.is_banned(&node_id));
    }
}
