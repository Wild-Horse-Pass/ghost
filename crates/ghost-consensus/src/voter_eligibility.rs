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
//| FILE: voter_eligibility.rs                                                                                           |
//|======================================================================================================================|

//! Sybil-resistant voter eligibility verification
//!
//! This module implements multiple layers of Sybil resistance for BFT voting:
//!
//! 1. **Proof-of-Work on Node ID**: Nodes must solve a PoW puzzle to register
//! 2. **Minimum Uptime**: Nodes must maintain consistent uptime to vote
//! 3. **Minimum Age**: Nodes must be registered for a minimum period
//! 4. **Stake/Bond**: Optional economic stake requirement
//!
//! # Security Model
//!
//! An attacker trying to Sybil the BFT consensus would need to:
//! - Generate multiple valid PoW proofs (CPU cost)
//! - Maintain multiple nodes with high uptime (infrastructure cost)
//! - Wait through the minimum age period (time cost)
//! - Optionally stake bonds for each node (economic cost)
//!
//! Combined with the 101 elder limit, these measures make Sybil attacks
//! economically and practically infeasible.

use std::collections::HashMap;
use thiserror::Error;
use tracing::info;

use ghost_common::identity::NodeIdProof;
use ghost_common::types::NodeId;

/// Minimum PoW difficulty for node ID (20 bits = ~1M hashes)
pub const MIN_POW_DIFFICULTY: u32 = 20;

/// Minimum uptime percentage to vote (95%)
pub const MIN_UPTIME_PERCENT: f64 = 95.0;

/// Minimum node age to vote (7 days in seconds)
pub const MIN_NODE_AGE_SECS: u64 = 7 * 24 * 60 * 60;

/// Uptime tracking window (30 days in seconds)
pub const UPTIME_WINDOW_SECS: u64 = 30 * 24 * 60 * 60;

/// Minimum consecutive online period to be considered "online" (5 minutes)
pub const MIN_ONLINE_PERIOD_SECS: u64 = 300;

/// Maximum offline period before uptime penalty (1 hour)
pub const MAX_OFFLINE_PERIOD_SECS: u64 = 3600;

/// Voter eligibility errors
#[derive(Debug, Error, Clone)]
pub enum EligibilityError {
    #[error("Node {0} not registered")]
    NotRegistered(String),

    #[error("Node {0} has no PoW proof")]
    NoPoWProof(String),

    #[error("Node {0} PoW difficulty {1} < minimum {MIN_POW_DIFFICULTY}")]
    InsufficientPoW(String, u32),

    #[error("Node {0} PoW proof invalid")]
    InvalidPoW(String),

    #[error("Node {0} uptime {1:.1}% < minimum {MIN_UPTIME_PERCENT}%")]
    InsufficientUptime(String, f64),

    #[error("Node {0} age {1}s < minimum {MIN_NODE_AGE_SECS}s")]
    TooYoung(String, u64),

    #[error("Node {0} is not an elder")]
    NotElder(String),

    #[error("Node {0} has insufficient bond: {1} < {2}")]
    InsufficientBond(String, u64, u64),
}

/// Eligibility requirements configuration
#[derive(Debug, Clone)]
pub struct EligibilityConfig {
    /// Minimum PoW difficulty bits
    pub min_pow_difficulty: u32,
    /// Minimum uptime percentage (0-100)
    pub min_uptime_percent: f64,
    /// Minimum node age in seconds
    pub min_node_age_secs: u64,
    /// Minimum bond in satoshis (0 = no bond required)
    pub min_bond_sats: u64,
    /// Whether to enforce PoW requirement
    pub require_pow: bool,
    /// Whether to enforce uptime requirement
    pub require_uptime: bool,
    /// Whether to enforce age requirement
    pub require_age: bool,
}

impl Default for EligibilityConfig {
    fn default() -> Self {
        Self {
            min_pow_difficulty: MIN_POW_DIFFICULTY,
            min_uptime_percent: MIN_UPTIME_PERCENT,
            min_node_age_secs: MIN_NODE_AGE_SECS,
            min_bond_sats: 0,
            require_pow: true,
            require_uptime: true,
            require_age: true,
        }
    }
}

impl EligibilityConfig {
    /// Strict configuration for mainnet
    pub fn mainnet() -> Self {
        Self {
            min_pow_difficulty: 20,
            min_uptime_percent: 95.0,
            min_node_age_secs: 7 * 24 * 60 * 60, // 7 days
            min_bond_sats: 100_000,              // 0.001 BTC
            require_pow: true,
            require_uptime: true,
            require_age: true,
        }
    }

    /// Relaxed configuration for testnet
    pub fn testnet() -> Self {
        Self {
            min_pow_difficulty: 10,
            min_uptime_percent: 50.0,
            min_node_age_secs: 60, // 1 minute
            min_bond_sats: 0,
            require_pow: true,
            require_uptime: false,
            require_age: true,
        }
    }

    /// Development configuration (no requirements)
    pub fn development() -> Self {
        Self {
            min_pow_difficulty: 1,
            min_uptime_percent: 0.0,
            min_node_age_secs: 0,
            min_bond_sats: 0,
            require_pow: false,
            require_uptime: false,
            require_age: false,
        }
    }
}

/// Node registration record
#[derive(Debug, Clone)]
pub struct NodeRecord {
    /// Node ID (public key)
    pub node_id: NodeId,
    /// PoW proof (nonce that satisfies difficulty)
    pub pow_proof: Option<NodeIdProof>,
    /// Registration timestamp (Unix seconds)
    pub registered_at: u64,
    /// Is this node an elder?
    pub is_elder: bool,
    /// Bond amount in satoshis
    pub bond_sats: u64,
    /// Uptime tracker
    pub uptime: UptimeTracker,
}

/// Tracks node uptime for eligibility
#[derive(Debug, Clone)]
pub struct UptimeTracker {
    /// Total online time in the tracking window (seconds)
    pub online_secs: u64,
    /// Total tracked time (seconds)
    pub tracked_secs: u64,
    /// Last heartbeat timestamp (Unix seconds)
    pub last_heartbeat: u64,
    /// Last online status
    pub is_online: bool,
    /// When tracking started (Unix seconds)
    pub tracking_start: u64,
}

impl UptimeTracker {
    /// Create a new uptime tracker
    pub fn new(now: u64) -> Self {
        Self {
            online_secs: 0,
            tracked_secs: 0,
            last_heartbeat: now,
            is_online: true,
            tracking_start: now,
        }
    }

    /// Record a heartbeat (node is alive)
    pub fn heartbeat(&mut self, now: u64) {
        let elapsed = now.saturating_sub(self.last_heartbeat);

        // If gap is too large, node was offline
        if elapsed > MAX_OFFLINE_PERIOD_SECS {
            // Only count up to max offline period as offline
            self.tracked_secs += MAX_OFFLINE_PERIOD_SECS;
            // Rest of the gap doesn't count (graceful handling of clock issues)
        } else {
            // Node was online during this period
            self.online_secs += elapsed;
            self.tracked_secs += elapsed;
        }

        self.last_heartbeat = now;
        self.is_online = true;
    }

    /// Mark node as offline
    pub fn mark_offline(&mut self, now: u64) {
        if self.is_online {
            // Finalize current online period
            let elapsed = now.saturating_sub(self.last_heartbeat);
            if elapsed <= MAX_OFFLINE_PERIOD_SECS {
                self.online_secs += elapsed;
            }
            self.tracked_secs += elapsed.min(MAX_OFFLINE_PERIOD_SECS);
        }
        self.is_online = false;
        self.last_heartbeat = now;
    }

    /// Calculate uptime percentage
    pub fn uptime_percent(&self) -> f64 {
        if self.tracked_secs == 0 {
            return 100.0; // No data yet, assume good
        }
        (self.online_secs as f64 / self.tracked_secs as f64) * 100.0
    }

    /// Get age since tracking started (seconds)
    pub fn age_secs(&self, now: u64) -> u64 {
        now.saturating_sub(self.tracking_start)
    }
}

/// Voter eligibility manager
pub struct VoterEligibility {
    /// Configuration
    config: EligibilityConfig,
    /// Registered nodes
    nodes: parking_lot::RwLock<HashMap<NodeId, NodeRecord>>,
}

impl VoterEligibility {
    /// Create a new eligibility manager
    pub fn new(config: EligibilityConfig) -> Self {
        Self {
            config,
            nodes: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    /// Register a node (must have valid PoW if required)
    pub fn register_node(
        &self,
        node_id: NodeId,
        pow_proof: Option<NodeIdProof>,
    ) -> Result<(), EligibilityError> {
        let node_hex = hex::encode(&node_id[..8]);

        // Validate PoW if provided and required
        if self.config.require_pow {
            let proof = pow_proof
                .as_ref()
                .ok_or_else(|| EligibilityError::NoPoWProof(node_hex.clone()))?;

            // Verify the proof (checks both validity and minimum difficulty)
            if !proof.verify(&node_id, self.config.min_pow_difficulty) {
                // Check if it's a difficulty issue or invalid proof
                if proof.difficulty < self.config.min_pow_difficulty {
                    return Err(EligibilityError::InsufficientPoW(
                        node_hex,
                        proof.difficulty,
                    ));
                }
                return Err(EligibilityError::InvalidPoW(node_hex));
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let record = NodeRecord {
            node_id,
            pow_proof,
            registered_at: now,
            is_elder: false,
            bond_sats: 0,
            uptime: UptimeTracker::new(now),
        };

        self.nodes.write().insert(node_id, record);

        info!(
            node = %hex::encode(&node_id[..8]),
            "Node registered for voting eligibility"
        );

        Ok(())
    }

    /// Promote a node to elder status
    pub fn set_elder(&self, node_id: &NodeId, is_elder: bool) {
        if let Some(record) = self.nodes.write().get_mut(node_id) {
            record.is_elder = is_elder;
        }
    }

    /// Set a node's bond amount
    pub fn set_bond(&self, node_id: &NodeId, bond_sats: u64) {
        if let Some(record) = self.nodes.write().get_mut(node_id) {
            record.bond_sats = bond_sats;
        }
    }

    /// Record a heartbeat for a node
    pub fn heartbeat(&self, node_id: &NodeId) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(record) = self.nodes.write().get_mut(node_id) {
            record.uptime.heartbeat(now);
        }
    }

    /// Check if a node is eligible to vote
    ///
    /// Returns Ok(()) if eligible, Err with reason otherwise.
    pub fn check_eligibility(&self, node_id: &NodeId) -> Result<(), EligibilityError> {
        let nodes = self.nodes.read();
        let node_hex = hex::encode(&node_id[..8]);

        let record = nodes
            .get(node_id)
            .ok_or_else(|| EligibilityError::NotRegistered(node_hex.clone()))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check elder status
        if !record.is_elder {
            return Err(EligibilityError::NotElder(node_hex));
        }

        // Check PoW
        if self.config.require_pow {
            match &record.pow_proof {
                None => return Err(EligibilityError::NoPoWProof(node_hex)),
                Some(proof) => {
                    if proof.difficulty < self.config.min_pow_difficulty {
                        return Err(EligibilityError::InsufficientPoW(
                            node_hex,
                            proof.difficulty,
                        ));
                    }
                    if !proof.verify(node_id, self.config.min_pow_difficulty) {
                        return Err(EligibilityError::InvalidPoW(node_hex));
                    }
                }
            }
        }

        // Check age
        if self.config.require_age {
            let age = now.saturating_sub(record.registered_at);
            if age < self.config.min_node_age_secs {
                return Err(EligibilityError::TooYoung(node_hex, age));
            }
        }

        // Check uptime
        if self.config.require_uptime {
            let uptime = record.uptime.uptime_percent();
            if uptime < self.config.min_uptime_percent {
                return Err(EligibilityError::InsufficientUptime(node_hex, uptime));
            }
        }

        // Check bond
        if self.config.min_bond_sats > 0 && record.bond_sats < self.config.min_bond_sats {
            return Err(EligibilityError::InsufficientBond(
                node_hex,
                record.bond_sats,
                self.config.min_bond_sats,
            ));
        }

        Ok(())
    }

    /// Get all eligible voters
    pub fn get_eligible_voters(&self) -> Vec<NodeId> {
        self.nodes
            .read()
            .keys()
            .filter(|node_id| self.check_eligibility(node_id).is_ok())
            .cloned()
            .collect()
    }

    /// Get eligibility status for a node
    pub fn get_status(&self, node_id: &NodeId) -> Option<EligibilityStatus> {
        let nodes = self.nodes.read();
        let record = nodes.get(node_id)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Some(EligibilityStatus {
            node_id: *node_id,
            is_elder: record.is_elder,
            has_pow: record.pow_proof.is_some(),
            pow_difficulty: record.pow_proof.as_ref().map(|p| p.difficulty).unwrap_or(0),
            uptime_percent: record.uptime.uptime_percent(),
            age_secs: now.saturating_sub(record.registered_at),
            bond_sats: record.bond_sats,
            is_eligible: self.check_eligibility(node_id).is_ok(),
            ineligibility_reason: self.check_eligibility(node_id).err().map(|e| e.to_string()),
        })
    }

    /// Remove a node
    pub fn remove_node(&self, node_id: &NodeId) {
        self.nodes.write().remove(node_id);
    }

    /// Get count of registered nodes
    pub fn node_count(&self) -> usize {
        self.nodes.read().len()
    }

    /// Get count of eligible voters
    pub fn eligible_count(&self) -> usize {
        self.get_eligible_voters().len()
    }
}

/// Eligibility status for a node
#[derive(Debug, Clone)]
pub struct EligibilityStatus {
    pub node_id: NodeId,
    pub is_elder: bool,
    pub has_pow: bool,
    pub pow_difficulty: u32,
    pub uptime_percent: f64,
    pub age_secs: u64,
    pub bond_sats: u64,
    pub is_eligible: bool,
    pub ineligibility_reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id() -> NodeId {
        [1u8; 32]
    }

    fn test_pow_proof(difficulty: u32) -> NodeIdProof {
        // Create a mock proof - in real code this would be mined
        NodeIdProof {
            nonce: 12345,
            difficulty,
        }
    }

    #[test]
    fn test_uptime_tracker() {
        let mut tracker = UptimeTracker::new(1000);

        // Heartbeat after 60 seconds
        tracker.heartbeat(1060);
        assert_eq!(tracker.online_secs, 60);
        assert_eq!(tracker.tracked_secs, 60);
        assert!((tracker.uptime_percent() - 100.0).abs() < 0.01);

        // Another heartbeat
        tracker.heartbeat(1120);
        assert_eq!(tracker.online_secs, 120);

        // Mark offline
        tracker.mark_offline(1180);
        assert_eq!(tracker.online_secs, 180); // Includes time to offline

        // Long gap (offline)
        tracker.heartbeat(5000);
        // Gap was too long, only MAX_OFFLINE_PERIOD_SECS counted
        assert!(tracker.uptime_percent() < 100.0);
    }

    #[test]
    fn test_eligibility_config() {
        let mainnet = EligibilityConfig::mainnet();
        assert_eq!(mainnet.min_pow_difficulty, 20);
        assert!(mainnet.require_pow);
        assert!(mainnet.require_uptime);

        let dev = EligibilityConfig::development();
        assert!(!dev.require_pow);
        assert!(!dev.require_uptime);
    }

    #[test]
    fn test_eligibility_manager_dev_mode() {
        let config = EligibilityConfig::development();
        let manager = VoterEligibility::new(config);

        let node_id = test_node_id();

        // Register without PoW (allowed in dev mode)
        manager.register_node(node_id, None).unwrap();

        // Set as elder
        manager.set_elder(&node_id, true);

        // Should be eligible (dev mode has no requirements)
        assert!(manager.check_eligibility(&node_id).is_ok());
    }

    #[test]
    fn test_eligibility_requires_elder() {
        let config = EligibilityConfig::development();
        let manager = VoterEligibility::new(config);

        let node_id = test_node_id();
        manager.register_node(node_id, None).unwrap();

        // Not an elder yet
        let result = manager.check_eligibility(&node_id);
        assert!(matches!(result, Err(EligibilityError::NotElder(_))));

        // Make elder
        manager.set_elder(&node_id, true);
        assert!(manager.check_eligibility(&node_id).is_ok());
    }

    #[test]
    fn test_eligibility_status() {
        let config = EligibilityConfig::development();
        let manager = VoterEligibility::new(config);

        let node_id = test_node_id();
        manager.register_node(node_id, None).unwrap();
        manager.set_elder(&node_id, true);
        manager.set_bond(&node_id, 50_000);

        let status = manager.get_status(&node_id).unwrap();
        assert!(status.is_elder);
        assert_eq!(status.bond_sats, 50_000);
        assert!(status.is_eligible);
    }
}
