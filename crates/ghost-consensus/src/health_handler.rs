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
//| FILE: health_handler.rs                                                                                              |
//|======================================================================================================================|

//! Health ping handler
//!
//! Handles incoming health pings and updates peer information in the database.
//! Also discovers elders dynamically from HealthPing capabilities.
//!
//! ## Security Features
//!
//! - **PoW Verification**: Nodes must provide valid proof-of-work to register as voters.
//!   This prevents Sybil attacks where attackers create unlimited fake nodes.
//!
//! - **Rate Limiting**: Limits health pings per node to prevent flooding attacks.
//!   Uses token bucket algorithm similar to VoteHandler.

use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

use ghost_common::error::GhostResult;
use ghost_common::identity::{NodeIdProof, NODE_ID_POW_DIFFICULTY};
use ghost_common::types::NodeId;
use ghost_storage::{Database, PeerRecord};

use crate::ban_manager::BanManager;
use crate::mesh::MessageHandler;
use crate::message::{HealthPingMessage, MessageEnvelope, MessageType};
use crate::peer::PeerManager;

/// Callback for registering discovered elders
pub type ElderCallback = Arc<dyn Fn(NodeId) + Send + Sync>;

/// Callback for registering node capabilities (for payout calculation)
pub type NodeCapabilitiesCallback =
    Arc<dyn Fn(NodeId, ghost_common::types::NodeCapabilities) + Send + Sync>;

/// Rate limit configuration for health pings
///
/// Default: 10 pings burst, 1/second sustained per node
/// Health pings are sent every 10 seconds normally, so 1/sec is generous
const HEALTH_RATE_LIMIT_MAX_TOKENS: u32 = 10;
const HEALTH_RATE_LIMIT_REFILL_RATE: u32 = 1;

/// Token bucket for rate limiting
#[derive(Clone)]
struct TokenBucket {
    tokens: f64,
    last_update: Instant,
}

/// Rate limiter for health pings
pub struct HealthRateLimiter {
    buckets: RwLock<HashMap<NodeId, TokenBucket>>,
    max_tokens: u32,
    refill_rate: u32,
}

impl HealthRateLimiter {
    /// Create a new rate limiter
    pub fn new(max_tokens: u32, refill_rate: u32) -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
            max_tokens,
            refill_rate,
        }
    }

    /// Check if a node is rate limited and consume a token if not
    ///
    /// Returns true if the ping should be allowed, false if rate limited
    pub fn check_and_consume(&self, node_id: &NodeId) -> bool {
        let mut buckets = self.buckets.write();
        let now = Instant::now();

        let bucket = buckets.entry(*node_id).or_insert_with(|| TokenBucket {
            tokens: self.max_tokens as f64,
            last_update: now,
        });

        // Refill tokens based on time elapsed
        let elapsed = now.duration_since(bucket.last_update).as_secs_f64();
        bucket.tokens =
            (bucket.tokens + elapsed * self.refill_rate as f64).min(self.max_tokens as f64);
        bucket.last_update = now;

        // Try to consume a token
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Clean up old buckets (call periodically)
    pub fn cleanup(&self, max_age_secs: u64) {
        let mut buckets = self.buckets.write();
        let now = Instant::now();
        buckets.retain(|_, bucket| now.duration_since(bucket.last_update).as_secs() < max_age_secs);
    }

    /// Get the number of tracked nodes
    pub fn bucket_count(&self) -> usize {
        self.buckets.read().len()
    }
}

/// Maximum timestamp drift allowed for health pings (H4 security fix)
const MAX_TIMESTAMP_DRIFT_SECS: u64 = 300; // 5 minutes

/// Default minimum uptime for voter registration (C2 security fix)
const DEFAULT_MIN_UPTIME_SECS: u64 = 7 * 24 * 60 * 60; // 7 days

/// Default registration cooldown (C2 security fix)
const DEFAULT_REGISTRATION_COOLDOWN_SECS: u64 = 3600; // 1 hour

/// Configuration for the health ping handler
#[derive(Debug, Clone)]
pub struct HealthHandlerConfig {
    /// Whether to require PoW for voter registration
    pub require_pow: bool,
    /// Required PoW difficulty (leading zero bits)
    pub pow_difficulty: u32,
    /// Rate limit max tokens per node
    pub rate_limit_max_tokens: u32,
    /// Rate limit refill rate (tokens per second)
    pub rate_limit_refill_rate: u32,
    /// Minimum uptime (seconds) required for voter registration (C2 security fix)
    pub min_uptime_for_voting_secs: u64,
    /// Cooldown between registration attempts (C2 security fix)
    pub registration_cooldown_secs: u64,
    /// Maximum timestamp drift for health pings (H4 security fix)
    pub max_timestamp_drift_secs: u64,
}

impl Default for HealthHandlerConfig {
    fn default() -> Self {
        Self {
            require_pow: true,
            pow_difficulty: NODE_ID_POW_DIFFICULTY,
            rate_limit_max_tokens: HEALTH_RATE_LIMIT_MAX_TOKENS,
            rate_limit_refill_rate: HEALTH_RATE_LIMIT_REFILL_RATE,
            min_uptime_for_voting_secs: DEFAULT_MIN_UPTIME_SECS,
            registration_cooldown_secs: DEFAULT_REGISTRATION_COOLDOWN_SECS,
            max_timestamp_drift_secs: MAX_TIMESTAMP_DRIFT_SECS,
        }
    }
}

/// Handler for health ping messages
pub struct HealthPingHandler {
    /// Peer manager for updating peer state
    peers: Arc<PeerManager>,
    /// Database for persisting peer info
    db: Option<Arc<Database>>,
    /// Callback to register discovered elders
    elder_callback: Option<ElderCallback>,
    /// Callback to register node capabilities for payout calculations
    node_capabilities_callback: Option<NodeCapabilitiesCallback>,
    /// Rate limiter for incoming pings
    rate_limiter: HealthRateLimiter,
    /// Configuration
    config: HealthHandlerConfig,
    /// Shared ban manager for cross-handler enforcement (C1 security fix)
    ban_manager: Option<Arc<BanManager>>,
    /// Last registration time per node (C2 security fix - cooldown tracking)
    last_registration: RwLock<HashMap<NodeId, Instant>>,
    /// First seen time per node (C2 security fix - uptime tracking)
    first_seen_times: RwLock<HashMap<NodeId, Instant>>,
}

impl HealthPingHandler {
    /// Create a new health ping handler with default configuration
    pub fn new(peers: Arc<PeerManager>, db: Option<Arc<Database>>) -> Self {
        Self::with_config(peers, db, HealthHandlerConfig::default())
    }

    /// Create a new health ping handler with custom configuration
    pub fn with_config(
        peers: Arc<PeerManager>,
        db: Option<Arc<Database>>,
        config: HealthHandlerConfig,
    ) -> Self {
        Self {
            peers,
            db,
            elder_callback: None,
            node_capabilities_callback: None,
            rate_limiter: HealthRateLimiter::new(
                config.rate_limit_max_tokens,
                config.rate_limit_refill_rate,
            ),
            config,
            ban_manager: None,
            last_registration: RwLock::new(HashMap::new()),
            first_seen_times: RwLock::new(HashMap::new()),
        }
    }

    /// Set the shared ban manager for cross-handler enforcement (C1 security fix)
    pub fn with_ban_manager(mut self, ban_manager: Arc<BanManager>) -> Self {
        self.ban_manager = Some(ban_manager);
        self
    }

    /// Set the database for persistence
    pub fn with_database(mut self, db: Arc<Database>) -> Self {
        self.db = Some(db);
        self
    }

    /// Set callback for elder discovery
    ///
    /// When a HealthPing is received from a node with elder_status=true,
    /// this callback will be invoked to register the elder.
    pub fn with_elder_callback(mut self, callback: ElderCallback) -> Self {
        self.elder_callback = Some(callback);
        self
    }

    /// Set callback for node capabilities registration
    ///
    /// When a HealthPing is received, this callback will be invoked to
    /// register the node's capabilities for payout calculations.
    pub fn with_node_capabilities_callback(mut self, callback: NodeCapabilitiesCallback) -> Self {
        self.node_capabilities_callback = Some(callback);
        self
    }

    /// Clean up rate limiter state (call periodically)
    pub fn cleanup_rate_limiter(&self) {
        self.rate_limiter.cleanup(300); // 5 minute TTL
    }

    /// Get rate limiter statistics
    pub fn rate_limiter_bucket_count(&self) -> usize {
        self.rate_limiter.bucket_count()
    }

    /// Verify the PoW proof from a health ping
    ///
    /// Returns true if:
    /// - PoW is not required (config.require_pow = false), OR
    /// - The ping contains a valid PoW proof with sufficient difficulty
    fn verify_pow(&self, node_id: &NodeId, pow_proof: Option<(u64, u32)>) -> bool {
        if !self.config.require_pow {
            return true;
        }

        match pow_proof {
            Some((nonce, difficulty)) => {
                let proof = NodeIdProof { nonce, difficulty };
                proof.verify(node_id, self.config.pow_difficulty)
            }
            None => false,
        }
    }

    /// Validate health ping timestamp (H4 security fix)
    ///
    /// Returns true if timestamp is within acceptable drift of current time.
    fn validate_timestamp(&self, timestamp: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let max_drift_ms = self.config.max_timestamp_drift_secs * 1000;
        let diff = if timestamp > now {
            timestamp - now
        } else {
            now - timestamp
        };
        diff <= max_drift_ms
    }

    /// Check if node can register as voter (C2 security fix)
    ///
    /// Implements two protections against validator set manipulation:
    /// 1. Minimum uptime requirement - node must be known for min_uptime_for_voting_secs
    /// 2. Registration cooldown - can't re-register within registration_cooldown_secs
    fn can_register_as_voter(&self, node_id: &NodeId) -> bool {
        let now = Instant::now();

        // Check registration cooldown
        {
            let last_reg = self.last_registration.read();
            if let Some(last_time) = last_reg.get(node_id) {
                let cooldown = Duration::from_secs(self.config.registration_cooldown_secs);
                if now.duration_since(*last_time) < cooldown {
                    debug!(
                        node_id = %hex::encode(&node_id[..8]),
                        "Registration cooldown not elapsed"
                    );
                    return false;
                }
            }
        }

        // Check minimum uptime requirement
        {
            let first_seen = self.first_seen_times.read();
            if let Some(first_time) = first_seen.get(node_id) {
                let min_uptime = Duration::from_secs(self.config.min_uptime_for_voting_secs);
                if now.duration_since(*first_time) < min_uptime {
                    debug!(
                        node_id = %hex::encode(&node_id[..8]),
                        elapsed_secs = now.duration_since(*first_time).as_secs(),
                        required_secs = min_uptime.as_secs(),
                        "Node has not met minimum uptime requirement for voting"
                    );
                    return false;
                }
            } else {
                // First time seeing this node - record it but don't allow registration yet
                drop(first_seen);
                self.first_seen_times.write().insert(*node_id, now);
                debug!(
                    node_id = %hex::encode(&node_id[..8]),
                    "First time seeing node - starting uptime tracking"
                );
                return false;
            }
        }

        true
    }

    /// Record a successful voter registration (C2 security fix)
    fn record_registration(&self, node_id: &NodeId) {
        self.last_registration.write().insert(*node_id, Instant::now());
    }

    /// Check if node is banned (uses shared BanManager if available)
    fn is_banned(&self, node_id: &NodeId) -> bool {
        if let Some(ref ban_manager) = self.ban_manager {
            ban_manager.is_banned(node_id)
        } else {
            false
        }
    }

    /// Handle a health ping message
    ///
    /// ## Security Note (H2 TOCTOU Mitigation)
    ///
    /// There is a theoretical TOCTOU race between the ban check and processing.
    /// However, health pings have no critical security impact:
    /// - They only update peer information and capabilities
    /// - Voter registration requires PoW + uptime requirements (C2)
    /// - One extra ping from a soon-to-be-banned node doesn't affect consensus
    ///
    /// The ban check is still performed for defense-in-depth.
    async fn handle_ping(&self, envelope: &MessageEnvelope) -> GhostResult<()> {
        let node_id_hex = hex::encode(envelope.sender);
        let short_id = node_id_hex[..8].to_string();

        // C1: Check if node is banned using shared BanManager
        if self.is_banned(&envelope.sender) {
            debug!(node_id = %short_id, "Ignoring health ping from banned node");
            return Ok(());
        }

        // Rate limit check - reject pings from nodes sending too fast
        if !self.rate_limiter.check_and_consume(&envelope.sender) {
            warn!(
                node_id = %short_id,
                "Rate limited health ping from peer"
            );
            return Err(ghost_common::error::GhostError::RateLimited(format!(
                "Node {} rate limited for health pings",
                short_id
            )));
        }

        // Deserialize the health ping
        let ping_msg: HealthPingMessage = serde_json::from_slice(&envelope.payload)
            .map_err(|e| ghost_common::error::GhostError::P2PMessage(e.to_string()))?;

        let ping = &ping_msg.ping;

        // H4: Validate timestamp to prevent replay attacks
        if !self.validate_timestamp(ping.timestamp) {
            warn!(
                node_id = %short_id,
                timestamp = ping.timestamp,
                "Rejected health ping with invalid timestamp"
            );
            return Err(ghost_common::error::GhostError::InvalidTimestamp(format!(
                "Health ping timestamp {} out of range",
                ping.timestamp
            )));
        }

        debug!(
            node_id = %short_id,
            block_height = ping.block_height,
            round_id = ping.round_id,
            miner_count = ping.miner_count,
            elder = ping.capabilities.elder_status,
            has_pow = ping.pow_proof.is_some(),
            "Received health ping"
        );

        // Verify PoW before registering as voter (Sybil resistance)
        let pow_valid = self.verify_pow(&envelope.sender, ping.pow_proof);

        if !pow_valid {
            warn!(
                node_id = %short_id,
                has_pow = ping.pow_proof.is_some(),
                "Rejected node without valid PoW - not registering as voter"
            );
            // Still update peer info but don't register as voter
        }

        // Register node as voter for BFT consensus ONLY if:
        // 1. PoW is valid (Sybil resistance)
        // 2. C2: Node meets uptime requirements and cooldown elapsed
        if pow_valid && self.can_register_as_voter(&envelope.sender) {
            if let Some(ref callback) = self.elder_callback {
                callback(envelope.sender);
                self.record_registration(&envelope.sender);
                debug!(node_id = %short_id, "Registered node as BFT voter from health ping (PoW verified, uptime met)");
            }

            // Register node capabilities for payout calculations (only with valid PoW)
            if let Some(ref callback) = self.node_capabilities_callback {
                callback(envelope.sender, ping.capabilities);
                debug!(node_id = %short_id, "Registered node capabilities for payout");
            }
        } else if pow_valid {
            // PoW valid but uptime/cooldown requirements not met
            debug!(
                node_id = %short_id,
                "Node has valid PoW but does not meet voter registration requirements"
            );
        }

        // Update peer's last seen time in memory (regardless of PoW - for tracking)
        // If the peer doesn't exist or has empty address, update with real info from ping
        let existing_peer = self.peers.get_peer(&envelope.sender);
        let needs_update = existing_peer
            .as_ref()
            .map(|p| p.public_address.is_empty())
            .unwrap_or(true);

        if needs_update && !ping.public_address.is_empty() {
            // Create/update peer with real node_id and real public address from the ping
            let mut peer = crate::peer::Peer::new(envelope.sender, ping.public_address.clone());
            peer.state = crate::peer::PeerState::Connected;
            // Preserve first_seen if peer existed
            if let Some(ref existing) = existing_peer {
                peer.first_seen = existing.first_seen;
            }
            self.peers.upsert_peer(peer);
            debug!(node_id = %short_id, address = %ping.public_address, "Updated peer address from health ping");
        }
        self.peers.update_last_seen(&envelope.sender);

        // Persist to database if available
        if let Some(ref db) = self.db {
            let now = chrono::Utc::now().timestamp();
            let capabilities_json = serde_json::to_string(&ping.capabilities).unwrap_or_default();

            // Create peer record for database
            let peer = PeerRecord {
                peer_id: node_id_hex.clone(),
                address: ping.public_address.clone(),
                port: 8555, // Default port
                node_id: Some(node_id_hex.clone()),
                first_seen: now,
                last_seen: now,
                last_success: Some(now),
                last_failure: None,
                connection_count: 1,
                failure_count: 0,
                is_banned: false,
                ban_until: None,
                capabilities: Some(capabilities_json),
                protocol_version: Some(1),
            };

            if let Err(e) = db.upsert_peer(&peer) {
                warn!(error = %e, peer_id = %short_id, "Failed to persist peer info");
            }

            // Record uptime sample - node is online since we received their health ping
            if let Err(e) = db.record_uptime_sample(&node_id_hex, now, true) {
                warn!(error = %e, peer_id = %short_id, "Failed to record uptime sample");
            }
        }

        Ok(())
    }
}

#[async_trait]
impl MessageHandler for HealthPingHandler {
    async fn handle_message(&self, envelope: MessageEnvelope) -> GhostResult<()> {
        if envelope.msg_type == MessageType::HealthPing {
            self.handle_ping(&envelope).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::identity::NodeIdProof;

    #[test]
    fn test_rate_limiter_allows_initial_requests() {
        let limiter = HealthRateLimiter::new(10, 1);
        let node_id = [1u8; 32];

        // Should allow up to max_tokens requests
        for _ in 0..10 {
            assert!(limiter.check_and_consume(&node_id));
        }

        // Should be rate limited after exhausting tokens
        assert!(!limiter.check_and_consume(&node_id));
    }

    #[test]
    fn test_rate_limiter_refills_tokens() {
        let limiter = HealthRateLimiter::new(2, 100); // High refill for testing
        let node_id = [1u8; 32];

        // Exhaust tokens
        assert!(limiter.check_and_consume(&node_id));
        assert!(limiter.check_and_consume(&node_id));
        assert!(!limiter.check_and_consume(&node_id));

        // Wait a bit for refill (in real test we'd mock time)
        std::thread::sleep(std::time::Duration::from_millis(20));

        // Should have refilled
        assert!(limiter.check_and_consume(&node_id));
    }

    #[test]
    fn test_rate_limiter_cleanup() {
        let limiter = HealthRateLimiter::new(10, 1);
        let node1 = [1u8; 32];
        let node2 = [2u8; 32];

        limiter.check_and_consume(&node1);
        limiter.check_and_consume(&node2);

        assert_eq!(limiter.bucket_count(), 2);

        // Cleanup with 0 age should remove all
        limiter.cleanup(0);
        assert_eq!(limiter.bucket_count(), 0);
    }

    #[test]
    fn test_pow_verification() {
        let our_node_id = [0u8; 32];
        let peers = Arc::new(PeerManager::new(our_node_id, 100));
        let handler = HealthPingHandler::new(peers, None);

        // Generate a node with valid PoW
        let test_key = [1u8; 32];
        let proof = NodeIdProof::mine(&test_key, 8).unwrap(); // Low difficulty for test

        // Create config that requires lower difficulty for testing
        let mut config = HealthHandlerConfig::default();
        config.pow_difficulty = 8;
        let peers2 = Arc::new(PeerManager::new(our_node_id, 100));
        let handler_low_diff = HealthPingHandler::with_config(peers2, None, config);

        // Valid PoW should pass
        assert!(handler_low_diff.verify_pow(&test_key, Some((proof.nonce, proof.difficulty))));

        // No PoW should fail
        assert!(!handler_low_diff.verify_pow(&test_key, None));

        // Wrong nonce should fail
        assert!(!handler_low_diff.verify_pow(&test_key, Some((999999999, 8))));

        // Wrong node_id should fail
        let wrong_key = [2u8; 32];
        assert!(!handler_low_diff.verify_pow(&wrong_key, Some((proof.nonce, proof.difficulty))));
    }

    #[test]
    fn test_pow_not_required_config() {
        let mut config = HealthHandlerConfig::default();
        config.require_pow = false;

        let our_node_id = [0u8; 32];
        let peers = Arc::new(PeerManager::new(our_node_id, 100));
        let handler = HealthPingHandler::with_config(peers, None, config);

        let node_id = [1u8; 32];

        // Should pass without PoW when not required
        assert!(handler.verify_pow(&node_id, None));
    }
}
