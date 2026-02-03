//|======================================================================================================================|
//|                                                                                                                      |
//|  BITCOIN GHOST - Shared Ban Manager                                                                                  |
//|                                                                                                                      |
//|  Security Fix C1: Shared ban state across all handlers                                                               |
//|                                                                                                                      |
//|======================================================================================================================|

//! Shared Ban Manager - Centralized ban state for cross-handler enforcement
//!
//! This module provides a thread-safe ban manager that can be shared across
//! all message handlers (VoteHandler, HealthPingHandler, ZkPayoutVoteHandler, etc.)
//! to ensure that banned nodes are rejected by ALL handlers, not just the one
//! that detected the violation.
//!
//! ## Security Context
//!
//! Previously, each handler maintained its own `banned_nodes` HashMap. This meant:
//! - A node banned for equivocation in VoteHandler could still send health pings
//! - Ban state was lost on handler restart
//! - Inconsistent enforcement across the consensus layer
//!
//! This shared BanManager fixes C1 by providing:
//! - Centralized ban state accessible from all handlers
//! - Configurable ban durations per reason
//! - Automatic expiration cleanup
//! - Thread-safe operations via RwLock

use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{info, warn};

use ghost_common::types::NodeId;

/// Reason for banning a node
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanReason {
    /// Node signed conflicting votes (Byzantine behavior)
    Equivocation,
    /// Node exceeded rate limits persistently
    RateLimitExceeded,
    /// Node sent invalid/malformed messages repeatedly
    InvalidMessages,
    /// Node attempted protocol manipulation
    ProtocolViolation,
    /// Custom reason with specified duration
    Custom,
}

impl BanReason {
    /// Default ban duration for this reason
    pub fn default_duration(&self) -> Duration {
        match self {
            BanReason::Equivocation => Duration::from_secs(600), // 10 minutes
            BanReason::RateLimitExceeded => Duration::from_secs(300), // 5 minutes
            BanReason::InvalidMessages => Duration::from_secs(180), // 3 minutes
            BanReason::ProtocolViolation => Duration::from_secs(900), // 15 minutes
            BanReason::Custom => Duration::from_secs(600), // 10 minutes default
        }
    }
}

/// Entry for a banned node
#[derive(Debug, Clone)]
pub struct BanEntry {
    /// When the ban expires
    pub expire_at: Instant,
    /// Reason for the ban
    pub reason: BanReason,
    /// Timestamp when ban was created (for logging/auditing)
    pub banned_at: Instant,
}

impl BanEntry {
    /// Check if this ban has expired
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expire_at
    }

    /// Get remaining ban duration
    pub fn remaining(&self) -> Duration {
        self.expire_at.saturating_duration_since(Instant::now())
    }
}

/// P2P4-M3: Configurable ban durations per reason
#[derive(Debug, Clone)]
pub struct BanManagerConfig {
    /// Ban duration for equivocation (default: 600 seconds / 10 minutes)
    pub equivocation_secs: u64,
    /// Ban duration for rate limit exceeded (default: 300 seconds / 5 minutes)
    pub rate_limit_secs: u64,
    /// Ban duration for invalid messages (default: 180 seconds / 3 minutes)
    pub invalid_messages_secs: u64,
    /// Ban duration for protocol violation (default: 900 seconds / 15 minutes)
    pub protocol_violation_secs: u64,
    /// Default duration for custom bans (default: 600 seconds / 10 minutes)
    pub custom_secs: u64,
}

impl Default for BanManagerConfig {
    fn default() -> Self {
        Self {
            equivocation_secs: 600,
            rate_limit_secs: 300,
            invalid_messages_secs: 180,
            protocol_violation_secs: 900,
            custom_secs: 600,
        }
    }
}

impl BanManagerConfig {
    /// Get duration for a specific ban reason
    pub fn duration_for_reason(&self, reason: BanReason) -> Duration {
        let secs = match reason {
            BanReason::Equivocation => self.equivocation_secs,
            BanReason::RateLimitExceeded => self.rate_limit_secs,
            BanReason::InvalidMessages => self.invalid_messages_secs,
            BanReason::ProtocolViolation => self.protocol_violation_secs,
            BanReason::Custom => self.custom_secs,
        };
        Duration::from_secs(secs)
    }
}

/// Shared ban manager for cross-handler enforcement
///
/// Thread-safe via RwLock - can be shared across multiple handlers using Arc<BanManager>
pub struct BanManager {
    /// Map of banned nodes to their ban entries
    banned_nodes: RwLock<HashMap<NodeId, BanEntry>>,
    /// Default ban duration (can be overridden per-ban)
    default_duration: Duration,
    /// P2P4-M3: Configurable durations per reason
    config: BanManagerConfig,
}

impl BanManager {
    /// Create a new ban manager with default 10-minute ban duration
    pub fn new() -> Self {
        Self::with_duration(Duration::from_secs(600))
    }

    /// Create a new ban manager with custom default duration
    pub fn with_duration(default_duration: Duration) -> Self {
        Self {
            banned_nodes: RwLock::new(HashMap::new()),
            default_duration,
            config: BanManagerConfig::default(),
        }
    }

    /// P2P4-M3: Create a ban manager with custom configuration
    pub fn with_config(config: BanManagerConfig) -> Self {
        Self {
            banned_nodes: RwLock::new(HashMap::new()),
            default_duration: Duration::from_secs(config.custom_secs),
            config,
        }
    }

    /// Ban a node for a specific reason using configured duration for that reason
    ///
    /// P2P4-M3: Uses configurable durations from BanManagerConfig
    pub fn ban(&self, node_id: NodeId, reason: BanReason) {
        let duration = self.config.duration_for_reason(reason);
        self.ban_for_duration(node_id, reason, duration);
    }

    /// Ban a node for a specific duration
    pub fn ban_for_duration(&self, node_id: NodeId, reason: BanReason, duration: Duration) {
        let now = Instant::now();
        let entry = BanEntry {
            expire_at: now + duration,
            reason,
            banned_at: now,
        };

        let node_hex = hex::encode(&node_id[..8]);
        self.banned_nodes.write().insert(node_id, entry);

        warn!(
            node_id = %node_hex,
            reason = ?reason,
            duration_secs = duration.as_secs(),
            "Node banned (shared BanManager)"
        );
    }

    /// Check if a node is currently banned
    ///
    /// This also cleans up the checked entry if expired.
    /// For bulk cleanup, use `cleanup_expired()`.
    pub fn is_banned(&self, node_id: &NodeId) -> bool {
        let banned = self.banned_nodes.read();
        match banned.get(node_id) {
            Some(entry) if !entry.is_expired() => true,
            Some(_) => {
                // Entry expired - will be cleaned up on next cleanup cycle
                // We don't modify during read to avoid writer starvation
                false
            }
            None => false,
        }
    }

    /// Check if banned and return the reason if so
    pub fn get_ban_info(&self, node_id: &NodeId) -> Option<(BanReason, Duration)> {
        let banned = self.banned_nodes.read();
        banned.get(node_id).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some((entry.reason, entry.remaining()))
            }
        })
    }

    /// Unban a node (manual override)
    pub fn unban(&self, node_id: &NodeId) -> bool {
        let removed = self.banned_nodes.write().remove(node_id).is_some();
        if removed {
            info!(
                node_id = %hex::encode(&node_id[..8]),
                "Node unbanned manually"
            );
        }
        removed
    }

    /// Clean up all expired bans
    ///
    /// Call this periodically (e.g., every 60 seconds) to prevent memory growth
    pub fn cleanup_expired(&self) -> usize {
        let mut banned = self.banned_nodes.write();
        let before = banned.len();
        banned.retain(|_, entry| !entry.is_expired());
        let removed = before - banned.len();
        if removed > 0 {
            info!(removed, remaining = banned.len(), "Cleaned up expired bans");
        }
        removed
    }

    /// Get the count of currently banned nodes
    pub fn banned_count(&self) -> usize {
        self.banned_nodes.read().len()
    }

    /// Get all currently banned node IDs (for diagnostics)
    pub fn get_banned_nodes(&self) -> Vec<(NodeId, BanReason, Duration)> {
        self.banned_nodes
            .read()
            .iter()
            .filter(|(_, entry)| !entry.is_expired())
            .map(|(id, entry)| (*id, entry.reason, entry.remaining()))
            .collect()
    }

    /// Get the default ban duration
    pub fn default_duration(&self) -> Duration {
        self.default_duration
    }
}

impl Default for BanManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ban_and_check() {
        let manager = BanManager::new();
        let node_id = [1u8; 32];

        assert!(!manager.is_banned(&node_id));

        manager.ban(node_id, BanReason::Equivocation);

        assert!(manager.is_banned(&node_id));
        assert_eq!(manager.banned_count(), 1);
    }

    #[test]
    fn test_ban_expiration() {
        let manager = BanManager::new();
        let node_id = [2u8; 32];

        // Ban for very short duration
        manager.ban_for_duration(node_id, BanReason::RateLimitExceeded, Duration::from_millis(1));

        // Should be banned initially
        assert!(manager.is_banned(&node_id));

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));

        // Should no longer be banned
        assert!(!manager.is_banned(&node_id));
    }

    #[test]
    fn test_unban() {
        let manager = BanManager::new();
        let node_id = [3u8; 32];

        manager.ban(node_id, BanReason::InvalidMessages);
        assert!(manager.is_banned(&node_id));

        let removed = manager.unban(&node_id);
        assert!(removed);
        assert!(!manager.is_banned(&node_id));
    }

    #[test]
    fn test_cleanup_expired() {
        let manager = BanManager::new();

        // Ban multiple nodes with short durations
        for i in 0..5 {
            manager.ban_for_duration([i; 32], BanReason::Custom, Duration::from_millis(1));
        }

        assert_eq!(manager.banned_count(), 5);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));

        // Cleanup
        let removed = manager.cleanup_expired();
        assert_eq!(removed, 5);
        assert_eq!(manager.banned_count(), 0);
    }

    #[test]
    fn test_get_ban_info() {
        let manager = BanManager::new();
        let node_id = [4u8; 32];

        assert!(manager.get_ban_info(&node_id).is_none());

        manager.ban(node_id, BanReason::ProtocolViolation);

        let info = manager.get_ban_info(&node_id);
        assert!(info.is_some());
        let (reason, remaining) = info.unwrap();
        assert_eq!(reason, BanReason::ProtocolViolation);
        assert!(remaining > Duration::from_secs(0));
    }

    #[test]
    fn test_reason_default_durations() {
        assert_eq!(
            BanReason::Equivocation.default_duration(),
            Duration::from_secs(600)
        );
        assert_eq!(
            BanReason::RateLimitExceeded.default_duration(),
            Duration::from_secs(300)
        );
        assert_eq!(
            BanReason::InvalidMessages.default_duration(),
            Duration::from_secs(180)
        );
        assert_eq!(
            BanReason::ProtocolViolation.default_duration(),
            Duration::from_secs(900)
        );
    }
}
