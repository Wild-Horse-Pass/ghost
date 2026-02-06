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
//| FILE: vote_handler.rs                                                                                                |
//|======================================================================================================================|

//! Vote Handler - Processes incoming votes and manages consensus
//!
//! Implements the MessageHandler trait for VoteMessage processing.
//! Integrates with VotingManager to track votes and determine outcomes.

use async_trait::async_trait;
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn};

use ghost_common::error::GhostResult;
use ghost_common::identity::NodeIdentity;
use ghost_common::types::{ConsensusResult, NodeId, PayoutProposal, RoundId, VoteType};

use crate::ban_manager::{BanManager, BanReason};
use crate::elder_list::CanonicalElderList;
use crate::mesh::MessageHandler;
use crate::message::{
    EquivocationProofMessage, MessageEnvelope, MessageType, PayoutProposalMessage, VoteMessage,
};
use crate::voting::{compute_vote_signing_message, Vote, VoteResult, VotingManager, VotingSession};

/// Rate limiter for P2P messages to prevent DoS attacks
///
/// Uses a token bucket algorithm per-node:
/// - Each node has a bucket that fills at `refill_rate` tokens/second
/// - Maximum bucket capacity is `max_tokens`
/// - Each message consumes 1 token
/// - Messages are rejected when bucket is empty
///
/// **Persistence**: State is periodically saved to the database to survive restarts.
/// This prevents attackers from bypassing rate limits by triggering node restarts.
pub struct RateLimiter {
    /// Tokens per node (bucket state)
    buckets: RwLock<HashMap<NodeId, TokenBucket>>,
    /// Maximum tokens per bucket
    max_tokens: u32,
    /// Tokens refilled per second
    refill_rate: u32,
}

/// Token bucket for rate limiting
///
/// H-14: Uses integer-based tokens with milli-token precision to avoid
/// floating-point precision issues. One token = 1000 millis.
/// This prevents subtle bugs from f64 rounding that could allow
/// rate limit bypass or unfair throttling.
#[derive(Clone)]
struct TokenBucket {
    /// Tokens * 1000 for sub-token precision without floating point
    tokens_millis: u64,
    last_update: Instant,
    /// Unix timestamp for persistence (Instant can't be serialized)
    last_update_unix: u64,
}

/// One token in millis (1000 millis = 1 token)
const MILLIS_PER_TOKEN: u64 = 1000;

/// Serializable state for persistence
#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedBucket {
    /// Stored as millis for consistency with runtime representation
    tokens_millis: u64,
    last_update_unix: u64,
}

/// Serializable rate limiter state
#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedRateLimiterState {
    buckets: Vec<(String, PersistedBucket)>, // node_id_hex -> bucket
    saved_at: u64,
}

impl RateLimiter {
    /// Create a new rate limiter
    ///
    /// # Arguments
    /// * `max_tokens` - Maximum burst capacity per node
    /// * `refill_rate` - Tokens refilled per second
    pub fn new(max_tokens: u32, refill_rate: u32) -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
            max_tokens,
            refill_rate,
        }
    }

    /// Create from persisted state (call at startup)
    ///
    /// Restores rate limit buckets from database, adjusting for time elapsed since save.
    /// H-14: Uses integer arithmetic for precision.
    pub fn from_persisted(max_tokens: u32, refill_rate: u32, json_state: &str) -> Self {
        let limiter = Self::new(max_tokens, refill_rate);

        if let Ok(state) = serde_json::from_str::<PersistedRateLimiterState>(json_state) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let now_instant = Instant::now();

            let mut buckets = limiter.buckets.write();
            for (node_id_hex, persisted) in state.buckets {
                if let Ok(bytes) = hex::decode(&node_id_hex) {
                    if bytes.len() == 32 {
                        let mut node_id = [0u8; 32];
                        node_id.copy_from_slice(&bytes);

                        // H-14: Calculate elapsed time and refill tokens using integer math
                        let elapsed_secs = now.saturating_sub(persisted.last_update_unix);
                        // refill_millis = elapsed_secs * refill_rate * 1000 millis/token
                        let refill_millis = elapsed_secs
                            .saturating_mul(refill_rate as u64)
                            .saturating_mul(MILLIS_PER_TOKEN);
                        let max_millis = (max_tokens as u64).saturating_mul(MILLIS_PER_TOKEN);
                        let tokens_millis = persisted
                            .tokens_millis
                            .saturating_add(refill_millis)
                            .min(max_millis);

                        // Only restore if bucket isn't full (still useful to track)
                        if tokens_millis < max_millis {
                            buckets.insert(
                                node_id,
                                TokenBucket {
                                    tokens_millis,
                                    last_update: now_instant,
                                    last_update_unix: now,
                                },
                            );
                        }
                    }
                }
            }

            if !buckets.is_empty() {
                debug!(
                    count = buckets.len(),
                    "Restored rate limiter state from persistence"
                );
            }
        }

        limiter
    }

    /// Check if a node is rate limited and consume a token if not
    ///
    /// Returns true if the message should be allowed, false if rate limited
    ///
    /// H-14: Uses integer arithmetic with milli-token precision to avoid
    /// floating-point precision issues.
    pub fn check_and_consume(&self, node_id: &NodeId) -> bool {
        let mut buckets = self.buckets.write();
        let now = Instant::now();
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let max_millis = (self.max_tokens as u64).saturating_mul(MILLIS_PER_TOKEN);

        let bucket = buckets.entry(*node_id).or_insert_with(|| TokenBucket {
            tokens_millis: max_millis,
            last_update: now,
            last_update_unix: now_unix,
        });

        // H-14: Refill tokens based on time elapsed using integer math
        // Cap elapsed time to 1 hour (3600 seconds) to prevent overflow
        let elapsed_ms = now
            .duration_since(bucket.last_update)
            .as_millis()
            .min(3_600_000) as u64;

        // refill_millis = elapsed_ms * refill_rate / 1000 (converting ms to seconds)
        // Reorder to avoid precision loss: (elapsed_ms * refill_rate * MILLIS_PER_TOKEN) / 1000
        let refill_millis = elapsed_ms
            .saturating_mul(self.refill_rate as u64)
            .saturating_mul(MILLIS_PER_TOKEN)
            / 1000;

        bucket.tokens_millis = bucket
            .tokens_millis
            .saturating_add(refill_millis)
            .min(max_millis);
        bucket.last_update = now;
        bucket.last_update_unix = now_unix;

        // Try to consume one token (1000 millis)
        if bucket.tokens_millis >= MILLIS_PER_TOKEN {
            bucket.tokens_millis -= MILLIS_PER_TOKEN;
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

    /// Serialize state for persistence (call periodically, e.g., every 60 seconds)
    ///
    /// Returns JSON that can be stored in kv_store with key "rate_limiter_state"
    /// H-14: Uses integer millis for persistence consistency.
    pub fn to_persisted(&self) -> String {
        let buckets = self.buckets.read();
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let max_millis = (self.max_tokens as u64).saturating_mul(MILLIS_PER_TOKEN);
        // 90% threshold in millis
        let threshold_millis = max_millis * 9 / 10;

        let persisted: Vec<(String, PersistedBucket)> = buckets
            .iter()
            // Only persist buckets that aren't full (they're the ones being rate limited)
            .filter(|(_, b)| b.tokens_millis < threshold_millis)
            .map(|(node_id, bucket)| {
                (
                    hex::encode(node_id),
                    PersistedBucket {
                        tokens_millis: bucket.tokens_millis,
                        last_update_unix: bucket.last_update_unix,
                    },
                )
            })
            .collect();

        let state = PersistedRateLimiterState {
            buckets: persisted,
            saved_at: now_unix,
        };

        serde_json::to_string(&state).unwrap_or_else(|_| "{}".to_string())
    }

    /// Get the count of tracked nodes
    pub fn bucket_count(&self) -> usize {
        self.buckets.read().len()
    }

    /// Persist rate limiter state to a file (C3 security fix)
    ///
    /// Call this periodically (e.g., every 60 seconds) to survive crashes.
    pub fn persist_to_file(&self, path: &std::path::Path) -> std::io::Result<()> {
        let json = self.to_persisted();
        std::fs::write(path, json)
    }

    /// Load rate limiter state from a file (C3 security fix)
    ///
    /// Call this at startup to restore state after crashes.
    pub fn from_persisted_file(
        max_tokens: u32,
        refill_rate: u32,
        path: &std::path::Path,
    ) -> std::io::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        Ok(Self::from_persisted(max_tokens, refill_rate, &json))
    }
}

// =============================================================================
// H-2: Persist Rate Limiter on Shutdown
// =============================================================================
// The Drop implementation ensures rate limiter state is persisted when the
// VoteHandler is dropped (e.g., during graceful shutdown). This prevents
// attackers from bypassing rate limits by triggering node restarts.

impl Drop for VoteHandler {
    fn drop(&mut self) {
        if let Some(ref path) = self.rate_limiter_persist_path {
            if let Err(e) = self.rate_limiter.persist_to_file(path) {
                tracing::error!(
                    path = %path.display(),
                    error = %e,
                    "Failed to persist rate limiter on shutdown"
                );
            } else {
                tracing::info!(
                    path = %path.display(),
                    "Persisted rate limiter state on shutdown"
                );
            }
        }
    }
}

/// Default voting timeout (5 minutes)
const DEFAULT_VOTE_TIMEOUT_MS: u64 = 5 * 60 * 1000;

/// Default stale proposal timeout (10 minutes)
const DEFAULT_STALE_PROPOSAL_MS: u64 = 10 * 60 * 1000;

/// Default maximum pending proposals
const DEFAULT_MAX_PENDING_PROPOSALS: usize = 1000;

/// Callback for broadcasting messages
pub type BroadcastFn = Arc<dyn Fn(MessageType, Vec<u8>) -> GhostResult<()> + Send + Sync>;

/// Callback for executing approved proposals
pub type ExecuteFn = Arc<dyn Fn(ConsensusResult) -> GhostResult<()> + Send + Sync>;

/// Rate limit configuration for P2P messages
///
/// Default: 100 messages burst, 20/second sustained per node
const RATE_LIMIT_MAX_TOKENS: u32 = 100;
const RATE_LIMIT_REFILL_RATE: u32 = 20;

/// Configuration for the vote handler
#[derive(Debug, Clone)]
pub struct VoteHandlerConfig {
    /// Voting timeout in milliseconds
    pub vote_timeout_ms: u64,
    /// Stale proposal timeout in milliseconds (proposals older than this are evicted)
    pub stale_proposal_ms: u64,
    /// Maximum number of pending proposals (prevents OOM)
    pub max_pending_proposals: usize,
    /// Rate limit max tokens per node
    pub rate_limit_max_tokens: u32,
    /// Rate limit refill rate (tokens per second)
    pub rate_limit_refill_rate: u32,
}

impl Default for VoteHandlerConfig {
    fn default() -> Self {
        Self {
            vote_timeout_ms: DEFAULT_VOTE_TIMEOUT_MS,
            stale_proposal_ms: DEFAULT_STALE_PROPOSAL_MS,
            max_pending_proposals: DEFAULT_MAX_PENDING_PROPOSALS,
            rate_limit_max_tokens: RATE_LIMIT_MAX_TOKENS,
            rate_limit_refill_rate: RATE_LIMIT_REFILL_RATE,
        }
    }
}

/// Pending proposal with timestamp for staleness tracking
struct PendingProposal {
    proposal: PayoutProposal,
    received_at: std::time::Instant,
}

/// Ban duration for equivocating nodes (10 minutes)
const EQUIVOCATION_BAN_DURATION_SECS: u64 = 600;

/// 4.4 SECURITY: Maximum allowed gap between proposal and known block height
const MAX_BLOCK_HEIGHT_GAP: u64 = 1000;

/// 4.4 SECURITY: Fallback max height when no current height is known
/// This is used during initial sync before we receive block updates
const FALLBACK_MAX_BLOCK_HEIGHT: u64 = 10_000_000;

/// Vote handler - processes votes and manages consensus sessions
pub struct VoteHandler {
    /// Our node identity
    identity: Arc<NodeIdentity>,
    /// Voting manager
    voting_manager: Arc<VotingManager>,
    /// Known elder nodes (eligible voters) - DEPRECATED: use canonical_elder_list
    elders: RwLock<HashSet<NodeId>>,
    /// 3.1 SECURITY: Canonical elder list for BFT-secure voting sessions
    /// This ensures all nodes agree on eligible voters through the canonical list.
    canonical_elder_list: RwLock<Option<CanonicalElderList>>,
    /// Pending proposals awaiting votes (with timestamps)
    pending_proposals: RwLock<std::collections::HashMap<[u8; 32], PendingProposal>>,
    /// Broadcast function
    broadcast_fn: Option<BroadcastFn>,
    /// Execute function (called when consensus reached)
    execute_fn: Option<ExecuteFn>,
    /// Rate limiter for incoming messages
    rate_limiter: Arc<RateLimiter>,
    /// Configuration
    config: VoteHandlerConfig,
    /// Shared ban manager for cross-handler enforcement (C1 security fix)
    /// If None, uses local ban tracking (legacy behavior for tests)
    ban_manager: Option<Arc<BanManager>>,
    /// Legacy: local banned nodes (only used if ban_manager is None)
    banned_nodes: RwLock<HashMap<NodeId, Instant>>,
    /// Ban duration for equivocating nodes
    ban_duration: std::time::Duration,
    /// P2P4-L7: Optional database for persisting equivocation proofs
    db: Option<Arc<ghost_storage::Database>>,
    /// M-P2P-2: Path for rate limiter persistence
    rate_limiter_persist_path: Option<PathBuf>,
    /// 4.4 SECURITY: Current known best block height for dynamic validation
    known_best_height: RwLock<Option<u64>>,
}

impl VoteHandler {
    /// Create a new vote handler with default configuration
    pub fn new(identity: Arc<NodeIdentity>, voting_manager: Arc<VotingManager>) -> Self {
        Self::with_config(identity, voting_manager, VoteHandlerConfig::default())
    }

    /// Create a new vote handler with custom configuration
    pub fn with_config(
        identity: Arc<NodeIdentity>,
        voting_manager: Arc<VotingManager>,
        config: VoteHandlerConfig,
    ) -> Self {
        Self {
            identity,
            voting_manager,
            elders: RwLock::new(HashSet::new()),
            canonical_elder_list: RwLock::new(None),
            pending_proposals: RwLock::new(std::collections::HashMap::new()),
            broadcast_fn: None,
            execute_fn: None,
            rate_limiter: Arc::new(RateLimiter::new(
                config.rate_limit_max_tokens,
                config.rate_limit_refill_rate,
            )),
            config,
            ban_manager: None,
            banned_nodes: RwLock::new(HashMap::new()),
            ban_duration: std::time::Duration::from_secs(EQUIVOCATION_BAN_DURATION_SECS),
            db: None,
            rate_limiter_persist_path: None,
            known_best_height: RwLock::new(None),
        }
    }

    /// 4.4 SECURITY: Update the known best block height for dynamic validation
    ///
    /// Call this when a new block is received to keep the validation bound current.
    /// Proposals with block heights outside (known_height - GAP, known_height + GAP) will be rejected.
    pub fn update_block_height(&self, height: u64) {
        let mut known = self.known_best_height.write();
        // Only update if new height is greater (prevent rollback attacks via stale data)
        if known.map_or(true, |h| height > h) {
            *known = Some(height);
        }
    }

    /// P2P4-L7: Set the database for persisting equivocation proofs
    ///
    /// When set, equivocation proofs are persisted for forensic analysis
    /// and potential slashing implementation.
    pub fn with_database(mut self, db: Arc<ghost_storage::Database>) -> Self {
        self.db = Some(db);
        self
    }

    /// Set the shared ban manager for cross-handler enforcement (C1 security fix)
    ///
    /// When set, bans are recorded in the shared BanManager and enforced by all handlers.
    /// Without this, bans are local to this handler only (legacy behavior).
    pub fn with_ban_manager(mut self, ban_manager: Arc<BanManager>) -> Self {
        self.ban_manager = Some(ban_manager);
        self
    }

    /// M-P2P-2: Enable rate limiter persistence to survive restarts
    ///
    /// When enabled:
    /// - Loads existing rate limiter state from file at initialization
    /// - Spawns a background task to persist state every 60 seconds
    ///
    /// This prevents attackers from bypassing rate limits by triggering node restarts.
    ///
    /// # Arguments
    /// * `persist_path` - Path to store the rate limiter state (e.g., "/var/lib/ghost/rate_limiter.json")
    ///
    /// # Returns
    /// Self with persistence enabled
    pub fn with_rate_limiter_persistence(mut self, persist_path: PathBuf) -> Self {
        // Load existing state if file exists
        if persist_path.exists() {
            match RateLimiter::from_persisted_file(
                self.config.rate_limit_max_tokens,
                self.config.rate_limit_refill_rate,
                &persist_path,
            ) {
                Ok(loaded_limiter) => {
                    info!(
                        path = %persist_path.display(),
                        buckets = loaded_limiter.bucket_count(),
                        "Loaded rate limiter state from persistence"
                    );
                    self.rate_limiter = Arc::new(loaded_limiter);
                }
                Err(e) => {
                    warn!(
                        path = %persist_path.display(),
                        error = %e,
                        "Failed to load rate limiter state, using fresh state"
                    );
                }
            }
        }

        self.rate_limiter_persist_path = Some(persist_path);
        self
    }

    /// M-P2P-2: Start the background persistence task for the rate limiter
    ///
    /// Call this after constructing the VoteHandler if persistence is enabled.
    /// The task will persist rate limiter state every 60 seconds.
    pub fn start_persistence_task(&self) {
        if let Some(ref persist_path) = self.rate_limiter_persist_path {
            let rate_limiter = Arc::clone(&self.rate_limiter);
            let path = persist_path.clone();

            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    if let Err(e) = rate_limiter.persist_to_file(&path) {
                        warn!(
                            path = %path.display(),
                            error = %e,
                            "Failed to persist rate limiter state"
                        );
                    } else {
                        debug!(
                            path = %path.display(),
                            buckets = rate_limiter.bucket_count(),
                            "Persisted rate limiter state"
                        );
                    }
                }
            });

            info!(
                path = %persist_path.display(),
                "Started rate limiter persistence task (60 second interval)"
            );
        }
    }

    /// Ban a node for equivocation
    ///
    /// Uses shared BanManager if available (C1 fix), otherwise local tracking.
    /// 3.2 SECURITY: Also invalidates any votes the node has cast in active sessions.
    fn ban_node(&self, node_id: NodeId) {
        if let Some(ref ban_manager) = self.ban_manager {
            // Use shared BanManager for cross-handler enforcement
            ban_manager.ban(node_id, BanReason::Equivocation);
        } else {
            // Legacy: local ban tracking
            let expire_at = Instant::now() + self.ban_duration;
            self.banned_nodes.write().insert(node_id, expire_at);
            warn!(
                node_id = %hex::encode(&node_id[..8]),
                duration_mins = 10,
                "Node banned for equivocation (local)"
            );
        }

        // 3.2 SECURITY: Invalidate the banned node's votes in all active sessions
        // This prevents their votes from counting toward consensus
        self.voting_manager.invalidate_voter_in_all_sessions(&node_id);
    }

    /// Check if a node is currently banned
    ///
    /// Checks shared BanManager if available (C1 fix), otherwise local tracking.
    fn is_banned(&self, node_id: &NodeId) -> bool {
        if let Some(ref ban_manager) = self.ban_manager {
            // Use shared BanManager
            ban_manager.is_banned(node_id)
        } else {
            // Legacy: local ban tracking
            let mut banned = self.banned_nodes.write();
            // Clean up expired bans
            banned.retain(|_, expire_at| *expire_at > Instant::now());
            banned.contains_key(node_id)
        }
    }

    /// P2P4-M1: Verify the signature on a message envelope
    ///
    /// The message signed is: payload + sequence (as per mesh.rs create_envelope)
    fn verify_envelope_signature(&self, envelope: &MessageEnvelope) -> bool {
        // Reconstruct the message that was signed (matches mesh.rs create_envelope)
        // Signed data is: payload_bytes + sequence.to_le_bytes()
        let mut signed_data = envelope.payload.clone();
        signed_data.extend_from_slice(&envelope.sequence.to_le_bytes());

        // Verify using the sender's public key (which is their NodeId)
        match ghost_common::identity::verify_signature(
            &envelope.sender,
            &signed_data,
            &envelope.signature,
        ) {
            Ok(true) => true,
            Ok(false) => {
                debug!(
                    sender = hex::encode(&envelope.sender[..8]),
                    "Signature verification returned false"
                );
                false
            }
            Err(e) => {
                debug!(
                    sender = hex::encode(&envelope.sender[..8]),
                    error = %e,
                    "Signature verification error"
                );
                false
            }
        }
    }

    /// Clean up rate limiter state (call periodically)
    pub fn cleanup_rate_limiter(&self) {
        self.rate_limiter.cleanup(300); // 5 minute TTL
    }

    /// Clean up stale proposals that have exceeded the timeout
    ///
    /// Returns the number of proposals evicted
    pub fn cleanup_stale_proposals(&self) -> usize {
        let stale_threshold = std::time::Duration::from_millis(self.config.stale_proposal_ms);
        let mut proposals = self.pending_proposals.write();
        let initial_count = proposals.len();

        proposals.retain(|_hash, pending| pending.received_at.elapsed() < stale_threshold);

        let evicted = initial_count - proposals.len();
        if evicted > 0 {
            debug!(
                evicted,
                remaining = proposals.len(),
                "Evicted stale proposals"
            );
        }
        evicted
    }

    /// Get the number of pending proposals
    pub fn pending_proposal_count(&self) -> usize {
        self.pending_proposals.read().len()
    }

    /// Set broadcast function
    pub fn with_broadcaster(mut self, f: BroadcastFn) -> Self {
        self.broadcast_fn = Some(f);
        self
    }

    /// Set execute function
    pub fn with_executor(mut self, f: ExecuteFn) -> Self {
        self.execute_fn = Some(f);
        self
    }

    /// Set elder nodes
    pub fn set_elders(&self, elders: HashSet<NodeId>) {
        *self.elders.write() = elders;
    }

    /// Add an elder node
    pub fn add_elder(&self, node_id: NodeId) {
        self.elders.write().insert(node_id);
    }

    /// Remove an elder node
    pub fn remove_elder(&self, node_id: &NodeId) {
        self.elders.write().remove(node_id);
    }

    /// Get current elder count
    pub fn elder_count(&self) -> usize {
        self.elders.read().len()
    }

    /// 3.1 SECURITY: Set canonical elder list for BFT-secure voting
    ///
    /// This MUST be called with a valid CanonicalElderList before any voting
    /// sessions are created. Using the canonical list ensures all nodes agree
    /// on eligible voters, which is required for BFT consensus security.
    pub fn set_canonical_elder_list(&self, elder_list: CanonicalElderList) {
        // Also update legacy elders for backwards compatibility
        let elder_ids: HashSet<NodeId> = elder_list.elders.iter().map(|e| e.node_id).collect();
        *self.elders.write() = elder_ids;
        *self.canonical_elder_list.write() = Some(elder_list);
    }

    /// Get the current canonical elder list epoch
    pub fn canonical_elder_epoch(&self) -> Option<u64> {
        self.canonical_elder_list.read().as_ref().map(|l| l.epoch)
    }

    /// Handle a payout proposal
    pub fn handle_proposal(&self, proposal: PayoutProposal) -> GhostResult<[u8; 32]> {
        // Compute proposal hash
        let proposal_hash = compute_proposal_hash(&proposal);

        // Check if we have too many pending proposals (OOM protection)
        {
            let proposals = self.pending_proposals.read();
            if proposals.len() >= self.config.max_pending_proposals {
                warn!(
                    count = proposals.len(),
                    max = self.config.max_pending_proposals,
                    "Too many pending proposals, rejecting new proposal"
                );
                return Err(ghost_common::error::GhostError::Internal(
                    "Too many pending proposals - resource exhausted".to_string(),
                ));
            }
        }

        // Store proposal with timestamp
        let pending = PendingProposal {
            proposal: proposal.clone(),
            received_at: std::time::Instant::now(),
        };
        self.pending_proposals
            .write()
            .insert(proposal_hash, pending);

        // 3.1 SECURITY: Create voting session using canonical elder list for BFT security
        // This ensures all nodes agree on eligible voters through the canonical list.
        let session = {
            let elder_list_guard = self.canonical_elder_list.read();
            if let Some(ref elder_list) = *elder_list_guard {
                // Use BFT-secure constructor with canonical elder list
                match VotingSession::from_elder_list(
                    proposal.round_id,
                    proposal_hash,
                    VoteType::PayoutApproval,
                    elder_list,
                    self.config.vote_timeout_ms,
                ) {
                    Ok(session) => session,
                    Err(e) => {
                        warn!(
                            error = %e,
                            "Failed to create voting session from canonical elder list"
                        );
                        return Err(e);
                    }
                }
            } else {
                // No canonical elder list set - this is a configuration error in production
                warn!(
                    "3.1 SECURITY: No canonical elder list set. \
                     VotingSession requires canonical elder list for BFT security. \
                     Call set_canonical_elder_list() before handling proposals."
                );
                return Err(ghost_common::error::GhostError::Internal(
                    "No canonical elder list configured for voting".to_string(),
                ));
            }
        };

        if self.voting_manager.start_session(session) {
            info!(
                round_id = proposal.round_id,
                hash = hex::encode(proposal_hash),
                "Started voting session for payout proposal"
            );
        }

        // Broadcast proposal to peers so they can also vote
        if let Some(ref broadcast) = self.broadcast_fn {
            let proposal_msg = PayoutProposalMessage {
                proposal: proposal.clone(),
            };

            let payload = serde_json::to_vec(&proposal_msg)
                .map_err(|e| ghost_common::error::GhostError::Serialization(e.to_string()))?;

            if let Err(e) = broadcast(MessageType::PayoutProposal, payload) {
                warn!(error = %e, "Failed to broadcast payout proposal");
            } else {
                info!(
                    round_id = proposal.round_id,
                    hash = hex::encode(proposal_hash),
                    "Broadcast payout proposal to peers"
                );
            }
        }

        // Cast our own vote (if we're an elder)
        if self.elders.read().contains(&self.identity.node_id()) {
            let approve = self.should_approve_proposal(&proposal);
            self.cast_vote(proposal.round_id, proposal_hash, approve)?;
        }

        Ok(proposal_hash)
    }

    /// Determine if we should approve a proposal
    fn should_approve_proposal(&self, proposal: &PayoutProposal) -> bool {
        // Validate proposal structure and amounts
        if let Err(reason) = self.validate_proposal(proposal) {
            warn!(
                round_id = proposal.round_id,
                reason = %reason,
                "Rejecting payout proposal"
            );
            return false;
        }
        true
    }

    /// Validate a payout proposal
    /// Returns Ok(()) if valid, Err with reason if invalid
    fn validate_proposal(&self, proposal: &PayoutProposal) -> Result<(), &'static str> {
        // 1. Must have valid subsidy
        if proposal.subsidy == 0 {
            return Err("zero subsidy");
        }

        // 2. Must have at least one miner payout
        if proposal.miner_payouts.is_empty() {
            return Err("no miner payouts");
        }

        // 3. Calculate total payout amounts
        let miner_total: u64 = proposal.miner_payouts.iter().map(|p| p.amount).sum();
        let node_total: u64 = proposal.node_payouts.iter().map(|p| p.amount).sum();
        let total_payouts = miner_total
            .saturating_add(node_total)
            .saturating_add(proposal.treasury_amount);

        // 4. Total payouts must not exceed available funds (subsidy + tx_fees)
        let available = proposal.subsidy.saturating_add(proposal.tx_fees);
        if total_payouts > available {
            return Err("payouts exceed available funds");
        }

        // 5. Check for zero amounts in payouts
        for payout in &proposal.miner_payouts {
            if payout.amount == 0 {
                return Err("zero miner payout amount");
            }
            // Validate address is non-empty
            if payout.address.is_empty() {
                return Err("empty miner payout address");
            }
        }

        for payout in &proposal.node_payouts {
            if payout.amount == 0 {
                return Err("zero node payout amount");
            }
            if payout.address.is_empty() {
                return Err("empty node payout address");
            }
        }

        // 6. Check for duplicate addresses (same address receiving multiple payouts)
        let mut seen_addresses = std::collections::HashSet::new();
        for payout in proposal
            .miner_payouts
            .iter()
            .chain(proposal.node_payouts.iter())
        {
            if !seen_addresses.insert(&payout.address) {
                return Err("duplicate payout address");
            }
        }

        // 7. Validate timestamp is reasonable (not too far in the past or future)
        // 4.2 SECURITY: Reduced to 30 minutes to limit replay attack window
        // Nodes should use NTP or similar time sync to stay within tolerance
        const TIMESTAMP_TOLERANCE_SECS: u64 = 1800; // 30 minutes
        let now = chrono::Utc::now().timestamp() as u64;
        let min_valid = now.saturating_sub(TIMESTAMP_TOLERANCE_SECS);
        let max_valid = now.saturating_add(TIMESTAMP_TOLERANCE_SECS);
        if proposal.timestamp < min_valid || proposal.timestamp > max_valid {
            return Err("proposal timestamp out of range");
        }

        // 8. Validate block height is reasonable
        // 4.4 SECURITY: Dynamic bound based on known block height
        let known_height = *self.known_best_height.read();
        if let Some(current) = known_height {
            // Dynamic validation: must be within MAX_BLOCK_HEIGHT_GAP of known height
            let min_valid = current.saturating_sub(MAX_BLOCK_HEIGHT_GAP);
            let max_valid = current.saturating_add(MAX_BLOCK_HEIGHT_GAP);
            if proposal.block_height < min_valid || proposal.block_height > max_valid {
                return Err("block height outside valid range");
            }
        } else {
            // Fallback: no known height yet, use static bound
            // This only happens during initial sync before receiving block updates
            if proposal.block_height > FALLBACK_MAX_BLOCK_HEIGHT {
                return Err("invalid block height");
            }
        }

        // 9. Validate miner payout distribution is proportional (basic sanity check)
        // Each miner's payout should be > dust threshold (546 satoshis for P2WPKH)
        const DUST_THRESHOLD: u64 = 546;
        for payout in &proposal.miner_payouts {
            if payout.amount < DUST_THRESHOLD {
                return Err("miner payout below dust threshold");
            }
        }

        for payout in &proposal.node_payouts {
            if payout.amount < DUST_THRESHOLD {
                return Err("node payout below dust threshold");
            }
        }

        Ok(())
    }

    /// Cast a vote on a proposal
    pub fn cast_vote(
        &self,
        round_id: RoundId,
        proposal_hash: [u8; 32],
        approve: bool,
    ) -> GhostResult<()> {
        // Sign with round_id included to prevent replay attacks
        // Format: H(round_id || proposal_hash || voter_id || decision)
        let voter_id = self.identity.node_id();
        let signing_message =
            compute_vote_signing_message(round_id, &proposal_hash, &voter_id, approve);
        let signature = self.identity.sign(&signing_message);

        // Create vote
        let vote = Vote::new(voter_id, approve, signature);

        // Submit to voting manager
        if let Some(result) = self
            .voting_manager
            .vote(round_id, proposal_hash, vote.clone())
        {
            match result {
                VoteResult::Decided(consensus_result) => {
                    self.handle_decision(round_id, proposal_hash, consensus_result)?;
                }
                _ => {
                    debug!(round_id, approve, "Vote recorded: {:?}", result);
                }
            }
        }

        // Broadcast vote to peers
        if let Some(ref broadcast) = self.broadcast_fn {
            let vote_msg = VoteMessage {
                round_id,
                proposal_hash,
                approve,
                signature,
            };

            let payload = serde_json::to_vec(&vote_msg)
                .map_err(|e| ghost_common::error::GhostError::Serialization(e.to_string()))?;

            broadcast(MessageType::Vote, payload)?;
        }

        Ok(())
    }

    /// Handle a vote from another node
    ///
    /// ## Security Note (H2 TOCTOU Mitigation)
    ///
    /// There is a theoretical TOCTOU race between the ban check in `handle_message()`
    /// and vote processing here. If a node is banned after the initial check but
    /// before this function completes, one vote could slip through.
    ///
    /// This is considered acceptable because:
    /// 1. The vote was valid at submission time (before equivocation was detected)
    /// 2. BFT consensus can tolerate f Byzantine votes - one extra doesn't break security
    /// 3. The node will be rejected for all subsequent messages
    ///
    /// For extra safety, we check ban status again before executing consensus decisions.
    fn handle_incoming_vote(&self, sender: NodeId, vote_msg: VoteMessage) -> GhostResult<()> {
        // Create vote from message
        let vote = Vote::new(sender, vote_msg.approve, vote_msg.signature);

        // Submit to voting manager
        if let Some(result) =
            self.voting_manager
                .vote(vote_msg.round_id, vote_msg.proposal_hash, vote)
        {
            match result {
                VoteResult::Decided(consensus_result) => {
                    // H2 TOCTOU mitigation: Re-check ban status before executing consensus
                    // This prevents executing decisions influenced by votes that arrived
                    // just before the sender was banned for equivocation
                    if self.is_banned(&sender) {
                        warn!(
                            sender = hex::encode(&sender[..8]),
                            round_id = vote_msg.round_id,
                            "Ignoring consensus decision - deciding vote was from now-banned node"
                        );
                        return Ok(());
                    }
                    self.handle_decision(
                        vote_msg.round_id,
                        vote_msg.proposal_hash,
                        consensus_result,
                    )?;
                }
                VoteResult::ApprovalRecorded | VoteResult::RejectionRecorded => {
                    // Log progress
                    if let Some(status) = self
                        .voting_manager
                        .get_session(vote_msg.round_id, vote_msg.proposal_hash)
                    {
                        debug!(
                            round_id = vote_msg.round_id,
                            approvals = status.approvals,
                            rejections = status.rejections,
                            threshold = status.threshold,
                            "Vote progress update"
                        );
                    }
                }
                VoteResult::DuplicateVote => {
                    debug!(sender = hex::encode(sender), "Duplicate vote ignored");
                }
                VoteResult::NotEligible => {
                    warn!(sender = hex::encode(sender), "Vote from non-eligible voter");
                }
                VoteResult::InvalidSignature => {
                    warn!(sender = hex::encode(sender), "Invalid vote signature");
                }
                VoteResult::AlreadyDecided => {
                    debug!("Vote received after decision");
                }
                VoteResult::Equivocation(proof) => {
                    // This is Byzantine behavior - voter signed conflicting votes
                    warn!(
                        sender = hex::encode(&sender[..8]),
                        round_id = vote_msg.round_id,
                        "EQUIVOCATION DETECTED: voter signed conflicting votes"
                    );
                    // Ban the equivocating node for 10 minutes
                    self.ban_node(sender);

                    // P2P4-L7: Persist equivocation proof to database
                    if let Some(ref db) = self.db {
                        // Serialize the proof for storage
                        let proof_data = serde_json::to_vec(&proof).unwrap_or_default();
                        if let Err(e) = db.store_equivocation_proof(
                            &sender,
                            &proof_data,
                            Some(vote_msg.round_id),
                            Some("payout_vote"),
                        ) {
                            warn!(
                                sender = hex::encode(&sender[..8]),
                                error = %e,
                                "Failed to persist equivocation proof"
                            );
                        } else {
                            info!(
                                sender = hex::encode(&sender[..8]),
                                round_id = vote_msg.round_id,
                                "Equivocation proof persisted to database"
                            );
                        }
                    }

                    // SEC-EQUIV-1: Broadcast equivocation proof to network for slashing
                    if let Some(ref broadcast) = self.broadcast_fn {
                        // Serialize the individual votes for the proof message
                        let vote1_data = serde_json::to_vec(&proof.vote1).unwrap_or_default();
                        let vote2_data = serde_json::to_vec(&proof.vote2).unwrap_or_default();

                        let mut proof_msg = EquivocationProofMessage::new(
                            sender,
                            vote_msg.round_id,
                            "payout_vote".to_string(),
                            vote1_data,
                            vote2_data,
                            self.identity.node_id(),
                        );

                        // Sign the proof
                        let signing_msg = proof_msg.signing_message();
                        proof_msg.reporter_signature = self.identity.sign(&signing_msg);

                        // Broadcast to network
                        match serde_json::to_vec(&proof_msg) {
                            Ok(payload) => {
                                if let Err(e) = broadcast(MessageType::EquivocationProof, payload) {
                                    warn!(
                                        error = %e,
                                        "Failed to broadcast equivocation proof"
                                    );
                                } else {
                                    info!(
                                        equivocator = %hex::encode(&sender[..8]),
                                        round_id = vote_msg.round_id,
                                        "Broadcast equivocation proof to network"
                                    );
                                }
                            }
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    "Failed to serialize equivocation proof for broadcast"
                                );
                            }
                        }
                    }

                    debug!(
                        "Equivocation proof: vote1.approve={}, vote2.approve={}",
                        proof.vote1.approve, proof.vote2.approve
                    );
                }
            }
        }

        Ok(())
    }

    /// Handle consensus decision
    fn handle_decision(
        &self,
        round_id: RoundId,
        proposal_hash: [u8; 32],
        result: ConsensusResult,
    ) -> GhostResult<()> {
        info!(
            round_id,
            hash = hex::encode(proposal_hash),
            "Consensus reached: {:?}",
            result
        );

        // Execute if approved
        if let ConsensusResult::Approved { .. } = &result {
            if let Some(ref execute) = self.execute_fn {
                execute(result.clone())?;
            }

            // Remove from pending
            self.pending_proposals.write().remove(&proposal_hash);
        }

        Ok(())
    }

    /// Cancel all proposals/votes for a round (called on reorg)
    ///
    /// This removes pending proposals and cancels active voting sessions.
    /// Returns Ok(()) on success.
    pub fn cancel_proposal_for_round(&self, round_id: RoundId) -> GhostResult<()> {
        // 1. Remove any pending proposals for this round
        let mut proposals = self.pending_proposals.write();
        let removed: Vec<_> = proposals
            .iter()
            .filter(|(_, p)| p.proposal.round_id == round_id)
            .map(|(hash, _)| *hash)
            .collect();

        for hash in &removed {
            proposals.remove(hash);
        }
        drop(proposals);

        // 2. Cancel any active voting sessions
        let sessions_cancelled = self.voting_manager.cancel_sessions_for_round(round_id);

        if removed.is_empty() && sessions_cancelled == 0 {
            debug!(
                round_id,
                "No proposals or sessions found to cancel for round"
            );
        } else {
            info!(
                round_id,
                proposals_removed = removed.len(),
                sessions_cancelled,
                "Cancelled proposals and sessions due to reorg"
            );
        }

        Ok(())
    }

    /// Check for timed out sessions
    pub fn check_timeouts(&self) -> Vec<ConsensusResult> {
        self.voting_manager.check_timeouts()
    }

    /// Get voting status for a round
    pub fn get_status(&self, round_id: RoundId, proposal_hash: [u8; 32]) -> Option<VotingStatus> {
        self.voting_manager
            .get_session(round_id, proposal_hash)
            .map(|s| VotingStatus {
                round_id: s.round_id,
                proposal_hash: s.proposal_hash,
                approvals: s.approvals,
                rejections: s.rejections,
                total_eligible: s.total_eligible,
                threshold: s.threshold,
                decided: s.is_decided,
                result: s.result,
            })
    }
}

#[async_trait]
impl MessageHandler for VoteHandler {
    async fn handle_message(&self, envelope: MessageEnvelope) -> GhostResult<()> {
        // P2P4-M1: Require non-zero signature
        if envelope.signature == [0u8; 64] {
            warn!(
                sender = hex::encode(&envelope.sender[..8]),
                msg_type = ?envelope.msg_type,
                "Rejecting message with zero signature"
            );
            return Err(ghost_common::error::GhostError::SignatureVerification(
                "Message has zero signature".to_string(),
            ));
        }

        // P2P4-M1: Verify signature before processing
        // The sender's public key is the NodeId, which is Ed25519 public key bytes
        if !self.verify_envelope_signature(&envelope) {
            warn!(
                sender = hex::encode(&envelope.sender[..8]),
                msg_type = ?envelope.msg_type,
                "Rejecting message with invalid signature"
            );
            return Err(ghost_common::error::GhostError::SignatureVerification(
                "Invalid message signature".to_string(),
            ));
        }

        // Check if node is banned for equivocation
        if self.is_banned(&envelope.sender) {
            return Err(ghost_common::error::GhostError::NodeBanned(format!(
                "Node {} temporarily banned for equivocation",
                hex::encode(&envelope.sender[..8])
            )));
        }

        // Rate limit check - reject messages from nodes sending too fast
        if !self.rate_limiter.check_and_consume(&envelope.sender) {
            warn!(
                sender = hex::encode(&envelope.sender[..8]),
                msg_type = ?envelope.msg_type,
                "Rate limited message from peer"
            );
            return Err(ghost_common::error::GhostError::RateLimited(format!(
                "Node {} rate limited",
                hex::encode(&envelope.sender[..8])
            )));
        }

        match envelope.msg_type {
            MessageType::Vote => {
                let vote_msg: VoteMessage = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| ghost_common::error::GhostError::Serialization(e.to_string()))?;

                self.handle_incoming_vote(envelope.sender, vote_msg)?;
            }

            MessageType::PayoutProposal => {
                let proposal_msg: PayoutProposalMessage = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| ghost_common::error::GhostError::Serialization(e.to_string()))?;

                self.handle_proposal(proposal_msg.proposal)?;
            }

            _ => {
                // Not our message type
            }
        }

        Ok(())
    }
}

/// Voting status summary
#[derive(Debug, Clone)]
pub struct VotingStatus {
    pub round_id: RoundId,
    pub proposal_hash: [u8; 32],
    pub approvals: u32,
    pub rejections: u32,
    pub total_eligible: u32,
    pub threshold: u32,
    pub decided: bool,
    pub result: Option<ConsensusResult>,
}

/// Compute hash of a payout proposal
///
/// C-6 Security Fix: This hash now includes ALL proposal fields that affect payouts,
/// including treasury fields. This prevents a malicious proposer from changing
/// treasury amounts without changing the hash that validators sign.
///
/// Version bumped from v1 to v2 to indicate the new hash format.
pub fn compute_proposal_hash(proposal: &PayoutProposal) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"PayoutProposal/v2"); // Version bump for new format (C-6)
    hasher.update(proposal.round_id.to_le_bytes());
    hasher.update(proposal.block_hash);
    hasher.update(proposal.subsidy.to_le_bytes());
    hasher.update(proposal.block_height.to_le_bytes());
    hasher.update(proposal.timestamp.to_le_bytes());
    hasher.update(proposal.proposer);

    // C-6: Include treasury fields (CRITICAL - was missing in v1)
    hasher.update(proposal.treasury_amount.to_le_bytes());
    hasher.update(&proposal.treasury_address);
    hasher.update(proposal.tx_fees.to_le_bytes());

    for payout in &proposal.miner_payouts {
        hasher.update(&payout.address);
        hasher.update(payout.amount.to_le_bytes());
    }

    for payout in &proposal.node_payouts {
        hasher.update(&payout.address);
        hasher.update(payout.amount.to_le_bytes());
    }

    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::types::{PayoutEntry, PayoutType};

    fn create_test_identity() -> Arc<NodeIdentity> {
        Arc::new(NodeIdentity::generate())
    }

    fn create_test_proposal() -> PayoutProposal {
        PayoutProposal {
            proposal_hash: [0u8; 32],
            round_id: 1,
            block_hash: [0u8; 32],
            block_height: 800_000,
            proposer: [1u8; 32],
            miner_payouts: vec![PayoutEntry {
                address: b"bc1q...".to_vec(),
                amount: 300_000_000,
                recipient_id: [1u8; 32],
                payout_type: PayoutType::Mining,
            }],
            node_payouts: vec![],
            treasury_amount: 25_000_000,
            treasury_address: b"bc1qtreasury".to_vec(), // H-MINE-3: snapshot address
            tx_fees: 10_000_000,
            subsidy: 625_000_000,
            timestamp: 1700000000,
            tx_fees_unallocated: 0,
        }
    }

    #[test]
    fn test_proposal_hash_deterministic() {
        let proposal = create_test_proposal();

        let hash1 = compute_proposal_hash(&proposal);
        let hash2 = compute_proposal_hash(&proposal);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_vote_handler_creation() {
        let identity = create_test_identity();
        let voting_manager = Arc::new(VotingManager::new(100));
        let handler = VoteHandler::new(identity, voting_manager);

        assert_eq!(handler.elder_count(), 0);
    }

    #[test]
    fn test_elder_management() {
        let identity = create_test_identity();
        let voting_manager = Arc::new(VotingManager::new(100));
        let handler = VoteHandler::new(identity, voting_manager);

        // Add elders
        handler.add_elder([1u8; 32]);
        handler.add_elder([2u8; 32]);
        handler.add_elder([3u8; 32]);

        assert_eq!(handler.elder_count(), 3);

        // Remove one
        handler.remove_elder(&[2u8; 32]);
        assert_eq!(handler.elder_count(), 2);
    }

    #[test]
    fn test_ban_manager_integration() {
        // H2: Test that shared BanManager works with VoteHandler
        let identity = create_test_identity();
        let voting_manager = Arc::new(VotingManager::new(100));
        let ban_manager = Arc::new(BanManager::new());

        let handler = VoteHandler::new(identity.clone(), voting_manager)
            .with_ban_manager(ban_manager.clone());

        let node_id = [1u8; 32];

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
    fn test_ban_reason_durations() {
        // Verify ban durations are reasonable
        assert_eq!(BanReason::Equivocation.default_duration().as_secs(), 600);
        assert_eq!(
            BanReason::RateLimitExceeded.default_duration().as_secs(),
            300
        );
        assert_eq!(BanReason::InvalidMessages.default_duration().as_secs(), 180);
        assert_eq!(
            BanReason::ProtocolViolation.default_duration().as_secs(),
            900
        );
    }

    // C-6: Tests for treasury field inclusion in proposal hash
    // These tests verify that changing treasury fields produces different hashes,
    // preventing a malicious proposer from modifying treasury amounts without detection.

    #[test]
    fn test_c6_different_treasury_amount_produces_different_hash() {
        let mut proposal1 = create_test_proposal();
        proposal1.treasury_amount = 25_000_000;

        let mut proposal2 = create_test_proposal();
        proposal2.treasury_amount = 50_000_000; // Different treasury amount

        let hash1 = compute_proposal_hash(&proposal1);
        let hash2 = compute_proposal_hash(&proposal2);

        assert_ne!(
            hash1, hash2,
            "C-6: Proposals with different treasury_amount must produce different hashes"
        );
    }

    #[test]
    fn test_c6_different_treasury_address_produces_different_hash() {
        let mut proposal1 = create_test_proposal();
        proposal1.treasury_address = b"bc1qtreasury_addr_1".to_vec();

        let mut proposal2 = create_test_proposal();
        proposal2.treasury_address = b"bc1qtreasury_addr_2".to_vec(); // Different treasury address

        let hash1 = compute_proposal_hash(&proposal1);
        let hash2 = compute_proposal_hash(&proposal2);

        assert_ne!(
            hash1, hash2,
            "C-6: Proposals with different treasury_address must produce different hashes"
        );
    }

    #[test]
    fn test_c6_different_tx_fees_produces_different_hash() {
        let mut proposal1 = create_test_proposal();
        proposal1.tx_fees = 10_000_000;

        let mut proposal2 = create_test_proposal();
        proposal2.tx_fees = 20_000_000; // Different tx_fees

        let hash1 = compute_proposal_hash(&proposal1);
        let hash2 = compute_proposal_hash(&proposal2);

        assert_ne!(
            hash1, hash2,
            "C-6: Proposals with different tx_fees must produce different hashes"
        );
    }

    #[test]
    fn test_c6_all_fields_included_in_hash() {
        // Verify that all critical fields affect the hash
        let base_proposal = create_test_proposal();
        let base_hash = compute_proposal_hash(&base_proposal);

        // Test each field that should affect the hash
        let test_cases = [
            ("round_id", {
                let mut p = create_test_proposal();
                p.round_id = 999;
                p
            }),
            ("block_hash", {
                let mut p = create_test_proposal();
                p.block_hash = [0xFFu8; 32];
                p
            }),
            ("subsidy", {
                let mut p = create_test_proposal();
                p.subsidy = 999_999_999;
                p
            }),
            ("block_height", {
                let mut p = create_test_proposal();
                p.block_height = 999_999;
                p
            }),
            ("timestamp", {
                let mut p = create_test_proposal();
                p.timestamp = 9999999999;
                p
            }),
            ("proposer", {
                let mut p = create_test_proposal();
                p.proposer = [0xFFu8; 32];
                p
            }),
            ("treasury_amount", {
                let mut p = create_test_proposal();
                p.treasury_amount = 999_999_999;
                p
            }),
            ("treasury_address", {
                let mut p = create_test_proposal();
                p.treasury_address = b"bc1qdifferent".to_vec();
                p
            }),
            ("tx_fees", {
                let mut p = create_test_proposal();
                p.tx_fees = 999_999_999;
                p
            }),
        ];

        for (field_name, modified_proposal) in test_cases {
            let modified_hash = compute_proposal_hash(&modified_proposal);
            assert_ne!(
                base_hash, modified_hash,
                "C-6: Changing {} must produce a different hash",
                field_name
            );
        }
    }
}
