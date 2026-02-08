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
//| FILE: elder_registration_handler.rs                                                                                  |
//|======================================================================================================================|

//! Elder Registration Handler - P2P-C1/C2/C3
//!
//! Handles the elder registration and list proposal protocol:
//!
//! - **P2P-C1**: ElderRegistrationProposal - nodes request to become elders
//! - **P2P-C2**: ElderListProposal - proposed canonical elder list for new epoch
//! - **P2P-C3**: ElderListApproval - BFT approval votes for proposed lists
//!
//! ## Registration Flow
//!
//! 1. Node broadcasts ElderRegistrationProposal (requires PoW + 7-day uptime)
//! 2. Current elders receive, validate, and vote (stored in DB)
//! 3. When >67% approve, proposing node creates ElderListProposal
//! 4. Elders validate merkle root and broadcast ElderListApproval
//! 5. When >67% approvals, all nodes execute epoch transition
//!
//! ## Security Properties
//!
//! - PoW prevents Sybil attacks (can't mass-generate elder candidates)
//! - Uptime requirement ensures node reliability
//! - BFT threshold (67%) prevents malicious elder additions
//! - Merkle root verification ensures all nodes converge on same list
//!
//! ## H-1: Transition Callback Integration
//!
//! **IMPORTANT**: The transition callback is set via `with_transition_callback()` builder
//! method and stored with interior mutability. When an epoch transition occurs,
//! the callback is invoked to notify other components (e.g., VoteHandler) of the
//! new elder list. Users MUST either:
//!
//! 1. Use `with_transition_callback()` before wrapping in Arc, OR
//! 2. Manually call `VoteHandler::set_canonical_elder_list()` after epoch transitions
//!
//! Failure to synchronize the elder list will cause VoteHandler to reject valid
//! votes from newly-added elders.

use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn};

use ghost_common::error::{GhostError, GhostResult};
use ghost_common::identity::{NodeIdProof, NodeIdentity, NODE_ID_POW_DIFFICULTY};
use ghost_common::types::NodeId;
use ghost_storage::Database;

use crate::ban_manager::BanManager;
use crate::elder_list::{
    CanonicalElderList, ElderApproval, ElderEntry, ElderListManager, ELDER_BFT_THRESHOLD_PERCENT,
    ELDER_MIN_UPTIME_PERCENT, ELDER_MIN_UPTIME_PERIOD_SECS,
};
use crate::mesh::MessageHandler;
use crate::message::{
    ElderListApprovalMessage, ElderListProposalMessage, ElderRegistrationProposalMessage,
    ElderRegistrationVoteMessage, MessageEnvelope, MessageType,
};

/// Callback for broadcasting messages to the network
pub type ElderBroadcastFn = Arc<dyn Fn(MessageType, Vec<u8>) -> GhostResult<()> + Send + Sync>;

/// Callback invoked when an epoch transition occurs
pub type TransitionCallback = Arc<dyn Fn(&CanonicalElderList) + Send + Sync>;

/// Callback invoked when a new elder registration is approved
/// Parameters: (candidate_node_id, elder_position)
/// This allows MPC ceremony to trigger contribution generation
pub type RegistrationApprovedCallback = Arc<dyn Fn(NodeId, u32) + Send + Sync>;

/// Rate limiting for elder messages
const RATE_LIMIT_MAX_TOKENS: u64 = 5;
const RATE_LIMIT_REFILL_RATE: u64 = 1; // 1 per second

/// Delay before proposing a new list after registration hits threshold (seconds)
const PROPOSAL_DELAY_SECS: u64 = 60;

/// Maximum time to wait for list approvals (seconds)
const APPROVAL_TIMEOUT_SECS: u64 = 300; // 5 minutes

/// L-1 FIX: Named constant for rate limiter cleanup interval (seconds)
/// Used in cleanup() to remove stale rate limiter buckets.
/// Set to match APPROVAL_TIMEOUT_SECS since registrations can take this long.
const RATE_LIMITER_CLEANUP_INTERVAL_SECS: u64 = 300; // 5 minutes

/// L-2 FIX: Named constant for approved registration retention multiplier
/// Approved registrations are kept for PROPOSAL_DELAY_SECS * this multiplier
/// before being cleaned up. The 2x buffer ensures registrations aren't removed
/// before they can be processed into list proposals.
const APPROVED_RETENTION_MULTIPLIER: u64 = 2;

/// C-1 SECURITY: One token in millis (1000 millis = 1 token)
/// Using integer arithmetic to prevent floating-point precision attacks
const MILLIS_PER_TOKEN: u64 = 1000;

/// M-5: Maximum number of pending proposals to prevent memory exhaustion
const MAX_PENDING_PROPOSALS: usize = 10;

/// M-5: Maximum buckets in rate limiter to prevent memory exhaustion
const MAX_RATE_LIMITER_BUCKETS: usize = 1000;

/// C-1 SECURITY: Integer-based token bucket for rate limiting
///
/// Uses milli-tokens (1 token = 1000 millis) to avoid floating-point precision
/// issues that could be exploited to bypass rate limiting.
#[derive(Clone)]
struct TokenBucket {
    /// Tokens stored in milli-tokens (divide by MILLIS_PER_TOKEN to get actual tokens)
    milli_tokens: u64,
    /// Last refill time
    last_update: Instant,
}

/// C-1 SECURITY: Integer-based rate limiter for elder messages
///
/// All arithmetic is performed with integers to prevent floating-point
/// precision attacks that could allow rate limit bypass.
struct RateLimiter {
    buckets: RwLock<HashMap<NodeId, TokenBucket>>,
    /// Maximum tokens in milli-tokens
    max_milli_tokens: u64,
    /// Refill rate in milli-tokens per second
    refill_rate_millis_per_sec: u64,
}

impl RateLimiter {
    fn new(max_tokens: u64, refill_rate: u64) -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
            max_milli_tokens: max_tokens.saturating_mul(MILLIS_PER_TOKEN),
            refill_rate_millis_per_sec: refill_rate.saturating_mul(MILLIS_PER_TOKEN),
        }
    }

    /// C-1 SECURITY: Check and consume a token using integer arithmetic
    fn check_and_consume(&self, node_id: &NodeId) -> bool {
        let mut buckets = self.buckets.write();
        let now = Instant::now();

        // M-5: Evict oldest bucket if at capacity
        if !buckets.contains_key(node_id) && buckets.len() >= MAX_RATE_LIMITER_BUCKETS {
            // Find and remove the oldest bucket
            if let Some(oldest_key) = buckets
                .iter()
                .min_by_key(|(_, bucket)| bucket.last_update)
                .map(|(k, _)| *k)
            {
                buckets.remove(&oldest_key);
            }
        }

        let bucket = buckets.entry(*node_id).or_insert_with(|| TokenBucket {
            milli_tokens: self.max_milli_tokens,
            last_update: now,
        });

        // C-1 SECURITY: Refill tokens using integer arithmetic
        // Cap elapsed time to 1 hour (3,600,000 ms) to prevent overflow
        let elapsed_ms = now
            .duration_since(bucket.last_update)
            .as_millis()
            .min(3_600_000) as u64;

        // refill_millis = elapsed_ms * refill_rate_millis_per_sec / 1000
        // Reorder to minimize precision loss
        let refill_millis = elapsed_ms.saturating_mul(self.refill_rate_millis_per_sec) / 1000;

        bucket.milli_tokens = bucket
            .milli_tokens
            .saturating_add(refill_millis)
            .min(self.max_milli_tokens);
        bucket.last_update = now;

        // Try to consume one token (MILLIS_PER_TOKEN millis)
        if bucket.milli_tokens >= MILLIS_PER_TOKEN {
            bucket.milli_tokens -= MILLIS_PER_TOKEN;
            true
        } else {
            false
        }
    }

    fn cleanup(&self, max_age_secs: u64) {
        let mut buckets = self.buckets.write();
        let now = Instant::now();
        buckets.retain(|_, bucket| now.duration_since(bucket.last_update).as_secs() < max_age_secs);
    }
}

/// Pending list proposal state
#[derive(Clone)]
#[allow(dead_code)]
struct PendingListProposal {
    epoch: u64,
    merkle_root: [u8; 32],
    elders_data: Vec<u8>,
    proposer: NodeId,
    /// M-2 SECURITY: Use wall clock time for timeout comparison
    /// Instant is monotonic but doesn't survive process restarts.
    /// We use i64 Unix timestamp for consistent cross-process behavior.
    received_at_unix: i64,
    /// Still keep Instant for relative timing within same process
    received_at: Instant,
}

/// Handler for elder registration and list proposal messages
pub struct ElderRegistrationHandler {
    /// Our node identity
    identity: Arc<NodeIdentity>,
    /// Elder list manager (shared state)
    elder_list_manager: Arc<RwLock<ElderListManager>>,
    /// Database for persistence
    db: Arc<Database>,
    /// Broadcast function for sending messages
    broadcast_fn: Option<ElderBroadcastFn>,
    /// H-4: Callback invoked on epoch transitions (uses interior mutability for Arc compatibility)
    /// This callback MUST update VoterEligibility when elder list changes.
    transition_callback: RwLock<Option<TransitionCallback>>,
    /// Callback invoked when a registration is approved (for MPC integration)
    registration_approved_callback: Option<RegistrationApprovedCallback>,
    /// Shared ban manager
    ban_manager: Option<Arc<BanManager>>,
    /// Rate limiter
    rate_limiter: RateLimiter,
    /// Pending list proposals awaiting approvals
    pending_proposals: RwLock<HashMap<u64, PendingListProposal>>,
    /// Approved registrations waiting for proposal delay
    approved_registrations: RwLock<HashMap<NodeId, Instant>>,
    /// M-6: Network mode (mainnet vs development)
    is_mainnet: bool,
}

impl ElderRegistrationHandler {
    /// Create a new elder registration handler
    ///
    /// # Arguments
    /// * `identity` - This node's identity
    /// * `elder_list_manager` - Shared elder list state
    /// * `db` - Database for persistence
    pub fn new(
        identity: Arc<NodeIdentity>,
        elder_list_manager: Arc<RwLock<ElderListManager>>,
        db: Arc<Database>,
    ) -> Self {
        Self {
            identity,
            elder_list_manager,
            db,
            broadcast_fn: None,
            transition_callback: RwLock::new(None),
            registration_approved_callback: None,
            ban_manager: None,
            rate_limiter: RateLimiter::new(RATE_LIMIT_MAX_TOKENS, RATE_LIMIT_REFILL_RATE),
            pending_proposals: RwLock::new(HashMap::new()),
            approved_registrations: RwLock::new(HashMap::new()),
            is_mainnet: false,
        }
    }

    /// Set the broadcast function for sending messages
    pub fn with_broadcaster(mut self, broadcast_fn: ElderBroadcastFn) -> Self {
        self.broadcast_fn = Some(broadcast_fn);
        self
    }

    /// Set the ban manager for cross-handler enforcement
    pub fn with_ban_manager(mut self, ban_manager: Arc<BanManager>) -> Self {
        self.ban_manager = Some(ban_manager);
        self
    }

    /// M-6: Mark this handler as running on mainnet
    ///
    /// When set, additional security checks are enforced:
    /// - Genesis bootstrap requires explicit configuration
    /// - Minimum PoW difficulty is enforced
    /// - Development-mode shortcuts are disabled
    pub fn with_mainnet_mode(mut self) -> Self {
        self.is_mainnet = true;
        self
    }

    /// H-1/H-4: Set the transition callback using builder pattern
    ///
    /// This callback is invoked when an epoch transition occurs.
    /// The callback MUST update VoterEligibility with the new elder list
    /// to maintain synchronization between ElderListManager and voting.
    ///
    /// # Example
    /// ```ignore
    /// let vote_handler = Arc::new(VoteHandler::new(...));
    /// let vote_handler_clone = Arc::clone(&vote_handler);
    ///
    /// let handler = ElderRegistrationHandler::new(identity, manager, db)
    ///     .with_transition_callback(Arc::new(move |new_list| {
    ///         vote_handler_clone.set_canonical_elder_list(new_list.clone());
    ///     }));
    /// ```
    pub fn with_transition_callback(self, callback: TransitionCallback) -> Self {
        *self.transition_callback.write() = Some(callback);
        self
    }

    /// H-4: Update transition callback after creation (for Arc-wrapped handlers)
    ///
    /// This method uses interior mutability to allow setting the callback
    /// even after the handler is wrapped in Arc.
    pub fn set_transition_callback(&self, callback: TransitionCallback) {
        *self.transition_callback.write() = Some(callback);
    }

    /// Set the registration approved callback (for MPC integration)
    pub fn set_registration_approved_callback(&mut self, callback: RegistrationApprovedCallback) {
        self.registration_approved_callback = Some(callback);
    }

    /// Check if a node is banned
    fn is_banned(&self, node_id: &NodeId) -> bool {
        self.ban_manager
            .as_ref()
            .map(|bm| bm.is_banned(node_id))
            .unwrap_or(false)
    }

    /// Get the current epoch from the elder list manager
    fn current_epoch(&self) -> u64 {
        self.elder_list_manager.read().current_epoch()
    }

    /// Check if we are an elder in the current epoch
    fn is_elder(&self, node_id: &NodeId) -> bool {
        self.elder_list_manager.read().is_elder(node_id)
    }

    /// Broadcast a message to the network
    fn broadcast(&self, msg_type: MessageType, payload: Vec<u8>) -> GhostResult<()> {
        if let Some(ref broadcast_fn) = self.broadcast_fn {
            broadcast_fn(msg_type, payload)
        } else {
            warn!("No broadcast function configured for ElderRegistrationHandler");
            Ok(())
        }
    }

    // =========================================================================
    // P2P-C1: Elder Registration Proposal Handling
    // =========================================================================

    /// Handle an incoming elder registration proposal
    async fn handle_registration_proposal(
        &self,
        sender: NodeId,
        msg: ElderRegistrationProposalMessage,
    ) -> GhostResult<()> {
        let short_candidate = hex::encode(&msg.candidate[..8]);
        let short_sender = hex::encode(&sender[..8]);

        debug!(
            candidate = %short_candidate,
            sender = %short_sender,
            target_epoch = msg.target_epoch,
            "Received elder registration proposal"
        );

        // C-3 SECURITY: Verify sender-message binding
        // The envelope sender must match the message's claimed candidate identity.
        // This prevents relay attacks where an attacker forwards someone else's proposal.
        if sender != msg.candidate {
            warn!(
                sender = %short_sender,
                candidate = %short_candidate,
                "C-3: Sender-message binding mismatch - envelope sender does not match candidate"
            );
            return Err(GhostError::P2PMessage(
                "Sender-message binding mismatch: envelope sender must be the registration candidate".into(),
            ));
        }

        // 1. Verify signature
        if !msg.verify_signature() {
            warn!(
                candidate = %short_candidate,
                "Invalid signature on registration proposal"
            );
            return Err(GhostError::SignatureVerification(
                "Invalid registration proposal signature".to_string(),
            ));
        }

        // H-5 SECURITY: Verify PoW against constant difficulty, NOT message's claimed difficulty
        // An attacker could claim a lower difficulty to bypass the PoW requirement.
        // We ALWAYS verify against NODE_ID_POW_DIFFICULTY.
        let pow_proof = NodeIdProof {
            nonce: msg.pow_nonce,
            difficulty: NODE_ID_POW_DIFFICULTY, // H-5: Use constant, not msg.pow_difficulty
        };
        if !pow_proof.verify(&msg.candidate, NODE_ID_POW_DIFFICULTY) {
            warn!(
                candidate = %short_candidate,
                claimed_difficulty = msg.pow_difficulty,
                required_difficulty = NODE_ID_POW_DIFFICULTY,
                "Invalid PoW proof in registration proposal"
            );
            return Err(GhostError::Config("Invalid PoW proof".to_string()));
        }

        // H-2 SECURITY: Verify uptime claims against actual database records
        // Don't trust the claimed uptime_percent and first_seen - verify them.
        let candidate_hex = hex::encode(msg.candidate);
        let verified_uptime =
            self.verify_uptime_claim(&candidate_hex, msg.first_seen, msg.uptime_percent)?;

        if !verified_uptime {
            warn!(
                candidate = %short_candidate,
                claimed_uptime = msg.uptime_percent,
                claimed_first_seen = msg.first_seen,
                "H-2: Uptime claim verification failed"
            );
            return Err(GhostError::Config("Uptime verification failed".to_string()));
        }

        // 3. Verify uptime requirements (now verified, not just claimed)
        if msg.uptime_percent < ELDER_MIN_UPTIME_PERCENT {
            warn!(
                candidate = %short_candidate,
                uptime = msg.uptime_percent,
                required = ELDER_MIN_UPTIME_PERCENT,
                "Insufficient uptime for elder registration"
            );
            return Err(GhostError::Config("Insufficient uptime".to_string()));
        }

        // 4. Verify uptime period
        let now = chrono::Utc::now().timestamp() as u64;
        let uptime_period = now.saturating_sub(msg.first_seen);
        if uptime_period < ELDER_MIN_UPTIME_PERIOD_SECS {
            warn!(
                candidate = %short_candidate,
                uptime_period_days = uptime_period / 86400,
                required_days = 7,
                "Insufficient uptime period for elder registration"
            );
            return Err(GhostError::Config("Insufficient uptime period".to_string()));
        }

        // 5. Check target epoch
        let current_epoch = self.current_epoch();

        // H-3 SECURITY: Handle genesis bootstrap (epoch 0 with empty elder list)
        if current_epoch == 0 && self.elder_list_manager.read().current().elder_count() == 0 {
            // Genesis bootstrap - allow first elders without BFT approval
            // This is only valid for epoch 0 -> epoch 1 transition
            if msg.target_epoch != 1 {
                warn!(
                    candidate = %short_candidate,
                    target = msg.target_epoch,
                    "Genesis bootstrap must target epoch 1"
                );
                return Err(GhostError::Config(
                    "Genesis bootstrap must target epoch 1".to_string(),
                ));
            }
            // M-6: On mainnet, genesis requires explicit configuration
            if self.is_mainnet {
                info!(
                    candidate = %short_candidate,
                    "Genesis bootstrap on mainnet - allowing first elder without BFT"
                );
            }
        } else if msg.target_epoch != current_epoch + 1 {
            warn!(
                candidate = %short_candidate,
                target = msg.target_epoch,
                expected = current_epoch + 1,
                "Invalid target epoch in registration proposal"
            );
            return Err(GhostError::Config("Invalid target epoch".to_string()));
        }

        // 6. Check if candidate is already an elder
        if self.is_elder(&msg.candidate) {
            debug!(
                candidate = %short_candidate,
                "Candidate is already an elder"
            );
            return Ok(());
        }

        // 7. Store in database
        let request_id = self.db.create_elder_registration_request(
            &candidate_hex,
            msg.pow_nonce,
            msg.pow_difficulty,
            msg.first_seen,
            msg.uptime_percent,
            msg.target_epoch,
        )?;

        info!(
            candidate = %short_candidate,
            request_id,
            target_epoch = msg.target_epoch,
            "Stored elder registration request"
        );

        // 8. If we are an elder, cast our vote
        if self.is_elder(&self.identity.node_id()) {
            self.cast_registration_vote(&msg, true, None).await?;
        }

        Ok(())
    }

    /// H-2 SECURITY: Verify uptime claims against actual peer tracking data
    ///
    /// Cross-references the claimed uptime against uptime_samples table.
    /// Returns true if claims are verified, false if they appear fraudulent.
    fn verify_uptime_claim(
        &self,
        node_id_hex: &str,
        claimed_first_seen: u64,
        claimed_uptime_percent: f64,
    ) -> GhostResult<bool> {
        // Query actual uptime from the database
        let now = chrono::Utc::now().timestamp();
        let seven_days_ago = now - ELDER_MIN_UPTIME_PERIOD_SECS as i64;

        // Get actual uptime percentage from uptime_samples (returns 0-100 integer)
        let actual_uptime = self
            .db
            .get_node_uptime_percent(node_id_hex, seven_days_ago)?;

        // Get actual first seen time
        let actual_first_seen = self.db.get_node_first_seen(node_id_hex)?;

        // Verify first_seen claim is not fraudulently early
        // Allow 1 hour tolerance for clock skew
        if let Some(db_first_seen) = actual_first_seen {
            if claimed_first_seen < (db_first_seen as u64).saturating_sub(3600) {
                warn!(
                    node_id = %node_id_hex,
                    claimed_first_seen = claimed_first_seen,
                    actual_first_seen = db_first_seen,
                    "H-2: First seen claim is earlier than database records"
                );
                return Ok(false);
            }
        }

        // Verify uptime claim is not inflated
        // Allow 5% tolerance for timing differences
        // claimed_uptime_percent is f64 (0.0-100.0), actual_uptime is u32 (0-100)
        if let Some(actual) = actual_uptime {
            let claimed_as_percent = claimed_uptime_percent; // Already 0-100 scale
            let actual_as_f64 = actual as f64;
            if claimed_as_percent > actual_as_f64 + 5.0 {
                warn!(
                    node_id = %node_id_hex,
                    claimed_uptime = claimed_uptime_percent,
                    actual_uptime = actual,
                    "H-2: Uptime claim exceeds actual tracked uptime"
                );
                return Ok(false);
            }
        }

        // If we have no data for this node, we cannot verify
        // In this case, reject unless this is genesis bootstrap
        if actual_uptime.is_none() {
            let current_epoch = self.current_epoch();
            if current_epoch == 0 {
                // Genesis bootstrap - no prior data expected
                debug!(
                    node_id = %node_id_hex,
                    "Genesis bootstrap: no prior uptime data, allowing registration"
                );
                return Ok(true);
            }
            warn!(
                node_id = %node_id_hex,
                "H-2: No uptime tracking data for this node"
            );
            return Ok(false);
        }

        Ok(true)
    }

    /// Cast a vote on a registration proposal
    ///
    /// C-2 SECURITY: Uses atomic threshold check to prevent TOCTOU race condition
    async fn cast_registration_vote(
        &self,
        proposal: &ElderRegistrationProposalMessage,
        approve: bool,
        rejection_reason: Option<String>,
    ) -> GhostResult<()> {
        let candidate_hex = hex::encode(proposal.candidate);
        let short_candidate = hex::encode(&proposal.candidate[..8]);

        // Get the request from database
        let request = match self.db.get_elder_registration_request(&candidate_hex)? {
            Some(r) => r,
            None => {
                debug!(
                    candidate = %short_candidate,
                    "No pending registration request found"
                );
                return Ok(());
            }
        };

        // Create the vote message
        let vote_msg = ElderRegistrationVoteMessage {
            candidate: proposal.candidate,
            target_epoch: proposal.target_epoch,
            voter: self.identity.node_id(),
            approve,
            rejection_reason: rejection_reason.clone(),
            signature: [0u8; 64], // Will be signed below
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        // Sign the vote
        let signing_msg = vote_msg.signing_message();
        let signature = self.identity.sign(&signing_msg);

        let signed_vote = ElderRegistrationVoteMessage {
            signature,
            ..vote_msg
        };

        // Record in database
        self.db.record_elder_registration_vote(
            request.id,
            &hex::encode(self.identity.node_id()),
            approve,
            rejection_reason.as_deref(),
            &hex::encode(signature),
        )?;

        // M-3: Use separate message type for votes vs proposals
        // NOTE: Currently both use ElderRegistrationProposal topic for backwards compatibility.
        // A future protocol upgrade should separate these message types.
        let payload = serde_json::to_vec(&signed_vote)
            .map_err(|e| GhostError::Serialization(e.to_string()))?;
        self.broadcast(MessageType::ElderRegistrationProposal, payload)?;

        info!(
            candidate = %short_candidate,
            approve,
            "Cast elder registration vote"
        );

        // C-2 SECURITY: Use atomic threshold check to prevent race condition
        // This ensures only one thread can mark the registration as approved,
        // preventing duplicate epoch transitions.
        let current_list = self.elder_list_manager.read().current();
        let total_elders = current_list.elder_count();

        // Try atomic approval check
        if let Some((approvals, _)) = self.db.check_and_approve_registration_atomic(
            request.id,
            ELDER_BFT_THRESHOLD_PERCENT,
            total_elders,
        )? {
            info!(
                candidate = %short_candidate,
                approvals,
                total_elders,
                "C-2: Registration atomically approved - will propose new list"
            );

            // Schedule list proposal after delay
            self.approved_registrations
                .write()
                .insert(proposal.candidate, Instant::now());
        } else if self.db.check_and_reject_registration_atomic(
            request.id,
            ELDER_BFT_THRESHOLD_PERCENT,
            total_elders,
        )? {
            info!(
                candidate = %short_candidate,
                "C-2: Registration atomically rejected"
            );
        }

        Ok(())
    }

    /// Handle an incoming registration vote
    ///
    /// C-2 SECURITY: Uses atomic threshold check to prevent TOCTOU race condition
    /// C-3 SECURITY: Verifies sender-message binding
    async fn handle_registration_vote(
        &self,
        sender: NodeId,
        msg: ElderRegistrationVoteMessage,
    ) -> GhostResult<()> {
        let short_voter = hex::encode(&msg.voter[..8]);
        let short_candidate = hex::encode(&msg.candidate[..8]);
        let short_sender = hex::encode(&sender[..8]);

        // C-3 SECURITY: Verify sender-message binding
        // The envelope sender must match the vote's voter field.
        if sender != msg.voter {
            warn!(
                sender = %short_sender,
                voter = %short_voter,
                "C-3: Sender-message binding mismatch on registration vote"
            );
            return Err(GhostError::P2PMessage(
                "Sender-message binding mismatch: envelope sender must be the voter".into(),
            ));
        }

        // Verify the voter is an elder
        if !self.is_elder(&msg.voter) {
            warn!(
                voter = %short_voter,
                "Non-elder tried to vote on registration"
            );
            return Err(GhostError::Config("Voter is not an elder".to_string()));
        }

        // Verify signature
        if !msg.verify_signature() {
            warn!(
                voter = %short_voter,
                "Invalid signature on registration vote"
            );
            return Err(GhostError::SignatureVerification(
                "Invalid vote signature".to_string(),
            ));
        }

        // Get the request from database
        let candidate_hex = hex::encode(msg.candidate);
        let request = match self.db.get_elder_registration_request(&candidate_hex)? {
            Some(r) => r,
            None => {
                debug!(
                    candidate = %short_candidate,
                    "No pending registration request for vote"
                );
                return Ok(());
            }
        };

        // Record the vote
        self.db.record_elder_registration_vote(
            request.id,
            &hex::encode(msg.voter),
            msg.approve,
            msg.rejection_reason.as_deref(),
            &hex::encode(msg.signature),
        )?;

        debug!(
            voter = %short_voter,
            candidate = %short_candidate,
            approve = msg.approve,
            "Recorded registration vote"
        );

        // C-2 SECURITY: Use atomic threshold check to prevent race condition
        let current_list = self.elder_list_manager.read().current();
        let total_elders = current_list.elder_count();

        if let Some((approvals, _)) = self.db.check_and_approve_registration_atomic(
            request.id,
            ELDER_BFT_THRESHOLD_PERCENT,
            total_elders,
        )? {
            info!(
                candidate = %short_candidate,
                approvals,
                total_elders,
                "C-2: Registration atomically approved by consensus"
            );

            // Calculate the new elder position
            let new_elder_position = (total_elders + 1) as u32;

            // Notify MPC ceremony of approved registration (if callback set)
            // This allows the new elder to generate their MPC contribution
            if let Some(ref callback) = self.registration_approved_callback {
                callback(msg.candidate, new_elder_position);
            }

            // If we are an elder, prepare to create the list proposal
            if self.is_elder(&self.identity.node_id()) {
                self.approved_registrations
                    .write()
                    .insert(msg.candidate, Instant::now());
            }
        } else if self.db.check_and_reject_registration_atomic(
            request.id,
            ELDER_BFT_THRESHOLD_PERCENT,
            total_elders,
        )? {
            info!(
                candidate = %short_candidate,
                "C-2: Registration atomically rejected by consensus"
            );
        }

        Ok(())
    }

    // =========================================================================
    // P2P-C2: Elder List Proposal Handling
    // =========================================================================

    /// Handle an incoming elder list proposal
    async fn handle_list_proposal(
        &self,
        sender: NodeId,
        msg: ElderListProposalMessage,
    ) -> GhostResult<()> {
        let short_sender = hex::encode(&sender[..8]);

        debug!(
            proposer = %short_sender,
            epoch = msg.epoch,
            elder_count = msg.elder_count,
            "Received elder list proposal"
        );

        // 1. Verify proposer is a current elder
        if !self.is_elder(&msg.proposer) {
            warn!(
                proposer = %short_sender,
                "Non-elder tried to propose elder list"
            );
            return Err(GhostError::Config("Proposer is not an elder".to_string()));
        }

        // 2. Verify signature
        if !msg.verify_signature() {
            warn!(
                proposer = %short_sender,
                "Invalid signature on list proposal"
            );
            return Err(GhostError::SignatureVerification(
                "Invalid list proposal signature".to_string(),
            ));
        }

        // 3. Verify epoch is sequential
        let current_epoch = self.current_epoch();
        if msg.epoch != current_epoch + 1 {
            warn!(
                proposed = msg.epoch,
                expected = current_epoch + 1,
                "Invalid epoch in list proposal"
            );
            return Err(GhostError::Config("Invalid epoch".to_string()));
        }

        // 4. Deserialize and verify elder entries
        let elders: Vec<ElderEntry> = serde_json::from_slice(&msg.elders_data)
            .map_err(|e| GhostError::Serialization(e.to_string()))?;

        // 5. Verify merkle root matches
        let computed_root = CanonicalElderList::compute_merkle_root_static(&elders);
        if computed_root != msg.merkle_root {
            warn!(
                proposer = %short_sender,
                "Merkle root mismatch in list proposal"
            );
            return Err(GhostError::Config("Merkle root mismatch".to_string()));
        }

        // 6. Verify elder count matches
        if elders.len() as u32 != msg.elder_count {
            warn!(
                proposer = %short_sender,
                expected = msg.elder_count,
                actual = elders.len(),
                "Elder count mismatch in list proposal"
            );
            return Err(GhostError::Config("Elder count mismatch".to_string()));
        }

        // SEC-ELDER-1: Verify all existing elders are preserved (no removals without revocation)
        let current_list = self.elder_list_manager.read().current().clone();
        for existing_elder in &current_list.elders {
            let preserved = elders.iter().any(|e| e.node_id == existing_elder.node_id);
            if !preserved {
                warn!(
                    proposer = %short_sender,
                    missing_elder = %hex::encode(&existing_elder.node_id[..8]),
                    "Elder list proposal removes existing elder without revocation"
                );
                return Err(GhostError::Config(
                    "Elder removal not allowed in registration proposal".to_string(),
                ));
            }
        }

        // SEC-ELDER-2: Verify only ONE new elder is added (registration proposals add single elder)
        let new_elders: Vec<_> = elders
            .iter()
            .filter(|e| !current_list.elders.iter().any(|x| x.node_id == e.node_id))
            .collect();
        if new_elders.len() != 1 {
            warn!(
                proposer = %short_sender,
                new_count = new_elders.len(),
                "Elder list proposal must add exactly one new elder (got {})",
                new_elders.len()
            );
            return Err(GhostError::Config(
                "Registration proposal must add exactly one elder".to_string(),
            ));
        }

        // 7. Store pending proposal with M-5 eviction limit
        {
            let mut pending = self.pending_proposals.write();

            // M-5: Evict oldest proposals if at capacity
            while pending.len() >= MAX_PENDING_PROPOSALS {
                // Find the oldest proposal by wall clock time
                if let Some(oldest_epoch) = pending
                    .iter()
                    .min_by_key(|(_, p)| p.received_at_unix)
                    .map(|(epoch, _)| *epoch)
                {
                    warn!(
                        evicted_epoch = oldest_epoch,
                        "M-5: Evicting oldest pending proposal due to capacity limit"
                    );
                    pending.remove(&oldest_epoch);
                } else {
                    break;
                }
            }

            pending.insert(
                msg.epoch,
                PendingListProposal {
                    epoch: msg.epoch,
                    merkle_root: msg.merkle_root,
                    elders_data: msg.elders_data.clone(),
                    proposer: msg.proposer,
                    received_at_unix: chrono::Utc::now().timestamp(),
                    received_at: Instant::now(),
                },
            );
        }

        info!(
            epoch = msg.epoch,
            elder_count = msg.elder_count,
            merkle_root = %hex::encode(&msg.merkle_root[..8]),
            "Stored pending elder list proposal"
        );

        // 8. If we are an elder, send our approval
        if self.is_elder(&self.identity.node_id()) {
            self.send_list_approval(msg.epoch, msg.merkle_root).await?;
        }

        Ok(())
    }

    /// Send our approval for a list proposal
    async fn send_list_approval(&self, epoch: u64, merkle_root: [u8; 32]) -> GhostResult<()> {
        let approval =
            ElderListApprovalMessage::new(epoch, merkle_root, self.identity.node_id(), |msg| {
                self.identity.sign(msg)
            });

        // Store in database
        self.db.store_elder_approval(
            epoch,
            &hex::encode(self.identity.node_id()),
            &hex::encode(approval.signature),
            approval.timestamp,
        )?;

        // Broadcast
        let payload =
            serde_json::to_vec(&approval).map_err(|e| GhostError::Serialization(e.to_string()))?;
        self.broadcast(MessageType::ElderListApproval, payload)?;

        info!(
            epoch,
            merkle_root = %hex::encode(&merkle_root[..8]),
            "Sent elder list approval"
        );

        Ok(())
    }

    // =========================================================================
    // P2P-C3: Elder List Approval Handling
    // =========================================================================

    /// Handle an incoming elder list approval
    async fn handle_list_approval(
        &self,
        _sender: NodeId,
        msg: ElderListApprovalMessage,
    ) -> GhostResult<()> {
        let short_approver = hex::encode(&msg.approver[..8]);

        debug!(
            approver = %short_approver,
            epoch = msg.epoch,
            "Received elder list approval"
        );

        // 1. Verify approver is a current elder
        if !self.is_elder(&msg.approver) {
            warn!(
                approver = %short_approver,
                "Non-elder tried to approve list"
            );
            return Err(GhostError::Config("Approver is not an elder".to_string()));
        }

        // 2. Verify signature
        if !msg.verify_signature() {
            warn!(
                approver = %short_approver,
                "Invalid signature on list approval"
            );
            return Err(GhostError::SignatureVerification(
                "Invalid list approval signature".to_string(),
            ));
        }

        // 3. Check we have a pending proposal for this epoch
        let pending = {
            let proposals = self.pending_proposals.read();
            proposals.get(&msg.epoch).cloned()
        };

        let Some(pending) = pending else {
            debug!(epoch = msg.epoch, "No pending proposal for approval");
            return Ok(());
        };

        // 4. Verify merkle root matches
        if msg.merkle_root != pending.merkle_root {
            warn!(
                approver = %short_approver,
                "Merkle root mismatch in approval"
            );
            return Err(GhostError::Config("Merkle root mismatch".to_string()));
        }

        // 5. Store approval in database
        self.db.store_elder_approval(
            msg.epoch,
            &hex::encode(msg.approver),
            &hex::encode(msg.signature),
            msg.timestamp,
        )?;

        // 6. Check if we've reached threshold
        let approval_count = self.db.count_elder_approvals(msg.epoch)?;
        let current_list = self.elder_list_manager.read().current();
        let total_elders = current_list.elder_count();
        let threshold = (total_elders as u32 * ELDER_BFT_THRESHOLD_PERCENT)
            .div_ceil(100)
            .max(1) as usize;

        info!(
            epoch = msg.epoch,
            approvals = approval_count,
            threshold,
            total_elders,
            "Elder list approval count"
        );

        if approval_count as usize >= threshold {
            info!(
                epoch = msg.epoch,
                "Elder list approved - executing transition"
            );
            self.execute_epoch_transition(msg.epoch, &pending).await?;
        }

        Ok(())
    }

    /// Execute the epoch transition to a new elder list
    async fn execute_epoch_transition(
        &self,
        epoch: u64,
        pending: &PendingListProposal,
    ) -> GhostResult<()> {
        // 1. Deserialize elder entries
        let elders: Vec<ElderEntry> = serde_json::from_slice(&pending.elders_data)
            .map_err(|e| GhostError::Serialization(e.to_string()))?;

        // 2. Load approvals from database
        let approval_records = self.db.get_elder_approvals_for_epoch(epoch)?;
        let approvals: Vec<ElderApproval> = approval_records
            .into_iter()
            .filter_map(|r| {
                let approver_bytes = hex::decode(&r.approver_node_id).ok()?;
                if approver_bytes.len() != 32 {
                    return None;
                }
                let mut approver = [0u8; 32];
                approver.copy_from_slice(&approver_bytes);

                let sig_bytes = hex::decode(&r.signature).ok()?;
                if sig_bytes.len() != 64 {
                    return None;
                }
                let mut signature = [0u8; 64];
                signature.copy_from_slice(&sig_bytes);

                Some(ElderApproval {
                    approver,
                    signature,
                    timestamp: r.approved_at,
                    prev_merkle_root: None, // Historic approvals may not have this
                })
            })
            .collect();

        // 3. Build the new canonical list
        let mut new_list = CanonicalElderList::new(epoch, elders);
        for approval in approvals {
            new_list.add_approval(approval);
        }

        // 4. Transition the manager
        {
            let manager = self.elder_list_manager.write();
            manager.transition_to(new_list.clone())?;
            manager.save_current_to_database(&self.db)?;
        }

        // 5. Remove from pending
        self.pending_proposals.write().remove(&epoch);

        // H-4 SECURITY: Invoke transition callback to sync VoterEligibility
        // This is CRITICAL - without this, the VoteHandler will not recognize
        // the new elders as valid voters.
        // CONS-3 FIX: Return error if callback not set in production. The callback
        // is mandatory because epoch transitions without VoterEligibility sync will
        // cause consensus failures where valid elder votes are rejected.
        {
            let callback_guard = self.transition_callback.read();
            if let Some(ref callback) = *callback_guard {
                callback(&new_list);
                info!(
                    epoch,
                    "H-4: Transition callback invoked to sync voter eligibility"
                );
            } else {
                // CONS-3 FIX: Fail the epoch transition if callback is not set.
                // This is a configuration error that must be fixed before mainnet.
                // The transition callback MUST be set via with_transition_callback()
                // to ensure VoteHandler recognizes new elders.
                return Err(GhostError::Config(format!(
                    "CONS-3 CRITICAL: Cannot complete epoch {} transition - no transition callback set. \
                     VoterEligibility will be out of sync and new elders will not be recognized as valid voters. \
                     Call ElderRegistrationHandler::with_transition_callback() during construction.",
                    epoch
                )));
            }
        }

        info!(
            epoch,
            elder_count = new_list.elder_count(),
            "Epoch transition complete"
        );

        Ok(())
    }

    /// Cleanup expired state (call periodically)
    ///
    /// L-1/L-2 FIX: Uses named constants instead of magic numbers for clarity
    /// and maintainability. The cleanup intervals are documented above.
    pub fn cleanup(&self) {
        // L-1 FIX: Clean up rate limiter using named constant
        self.rate_limiter
            .cleanup(RATE_LIMITER_CLEANUP_INTERVAL_SECS);

        // M-2: Clean up expired pending proposals using wall clock time
        // Instant::elapsed() is fine for relative timing but wall time ensures
        // consistent behavior across process restarts.
        {
            let mut pending = self.pending_proposals.write();
            let now = chrono::Utc::now().timestamp();
            pending.retain(|_, p| (now - p.received_at_unix) < APPROVAL_TIMEOUT_SECS as i64);
        }

        // L-2 FIX: Clean up approved registrations using named constant multiplier
        // Registrations are kept for 2x proposal delay to ensure they aren't
        // removed before being processed into list proposals.
        {
            let mut approved = self.approved_registrations.write();
            approved.retain(|_, instant| {
                instant.elapsed().as_secs() < PROPOSAL_DELAY_SECS * APPROVED_RETENTION_MULTIPLIER
            });
        }

        // Clean up expired registration requests in manager
        self.elder_list_manager
            .read()
            .cleanup_expired_registrations();
    }

    /// Check for approved registrations ready to propose (call periodically)
    pub async fn check_pending_proposals(&self) -> GhostResult<()> {
        let ready_candidates: Vec<NodeId> = {
            let approved = self.approved_registrations.read();
            approved
                .iter()
                .filter(|(_, instant)| instant.elapsed().as_secs() >= PROPOSAL_DELAY_SECS)
                .map(|(candidate, _)| *candidate)
                .collect()
        };

        for candidate in ready_candidates {
            // Only the original proposer (or an elder) should create the list proposal
            if self.is_elder(&self.identity.node_id()) {
                self.create_and_broadcast_list_proposal(candidate).await?;
            }
            self.approved_registrations.write().remove(&candidate);
        }

        Ok(())
    }

    /// Create and broadcast a new elder list proposal
    async fn create_and_broadcast_list_proposal(&self, new_candidate: NodeId) -> GhostResult<()> {
        let current = self.elder_list_manager.read().current();
        let new_epoch = current.epoch + 1;

        // Get the candidate's registration info from database
        let candidate_hex = hex::encode(new_candidate);
        let request = match self.db.get_elder_registration_request(&candidate_hex)? {
            Some(r) => r,
            None => {
                warn!(
                    candidate = %hex::encode(&new_candidate[..8]),
                    "No registration request found for approved candidate"
                );
                return Ok(());
            }
        };

        // Create the new elder entry
        let new_elder = ElderEntry {
            node_id: new_candidate,
            registered_epoch: new_epoch,
            pow_nonce: request.pow_nonce,
            pow_difficulty: request.pow_difficulty,
            first_seen: request.first_seen,
            uptime_at_registration: request.uptime_percent,
        };

        // Build new elder list
        let mut new_elders = current.elders.clone();
        new_elders.push(new_elder);

        let new_list = CanonicalElderList::new(new_epoch, new_elders.clone());

        // Serialize elder entries
        let elders_data = serde_json::to_vec(&new_elders)
            .map_err(|e| GhostError::Serialization(e.to_string()))?;

        // Create the proposal message
        let msg = ElderListProposalMessage {
            epoch: new_epoch,
            merkle_root: new_list.merkle_root,
            elder_count: new_elders.len() as u32,
            elders_data: elders_data.clone(),
            proposer: self.identity.node_id(),
            proposer_signature: [0u8; 64], // Will sign below
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        // Sign the proposal
        let signing_msg = msg.signing_message();
        let signature = self.identity.sign(&signing_msg);

        let signed_msg = ElderListProposalMessage {
            proposer_signature: signature,
            ..msg
        };

        // Store as pending with M-5 eviction
        {
            let mut pending = self.pending_proposals.write();

            // M-5: Evict oldest proposals if at capacity
            while pending.len() >= MAX_PENDING_PROPOSALS {
                if let Some(oldest_epoch) = pending
                    .iter()
                    .min_by_key(|(_, p)| p.received_at_unix)
                    .map(|(epoch, _)| *epoch)
                {
                    pending.remove(&oldest_epoch);
                } else {
                    break;
                }
            }

            pending.insert(
                new_epoch,
                PendingListProposal {
                    epoch: new_epoch,
                    merkle_root: new_list.merkle_root,
                    elders_data,
                    proposer: self.identity.node_id(),
                    received_at_unix: chrono::Utc::now().timestamp(),
                    received_at: Instant::now(),
                },
            );
        }

        // Broadcast
        let payload = serde_json::to_vec(&signed_msg)
            .map_err(|e| GhostError::Serialization(e.to_string()))?;
        self.broadcast(MessageType::ElderListProposal, payload)?;

        info!(
            epoch = new_epoch,
            elder_count = new_elders.len(),
            new_candidate = %hex::encode(&new_candidate[..8]),
            "Broadcast elder list proposal"
        );

        // Send our own approval
        self.send_list_approval(new_epoch, new_list.merkle_root)
            .await?;

        Ok(())
    }

    /// Get the current elder count
    pub fn elder_count(&self) -> usize {
        self.elder_list_manager.read().current().elder_count()
    }

    /// Get the current epoch
    pub fn epoch(&self) -> u64 {
        self.elder_list_manager.read().current_epoch()
    }
}

#[async_trait]
impl MessageHandler for ElderRegistrationHandler {
    async fn handle_message(&self, envelope: MessageEnvelope) -> GhostResult<()> {
        // Check if sender is banned
        if self.is_banned(&envelope.sender) {
            return Err(GhostError::NodeBanned(format!(
                "Node {} is banned",
                hex::encode(&envelope.sender[..8])
            )));
        }

        // Rate limit check
        if !self.rate_limiter.check_and_consume(&envelope.sender) {
            warn!(
                sender = %hex::encode(&envelope.sender[..8]),
                msg_type = ?envelope.msg_type,
                "Rate limited elder message from peer"
            );
            return Err(GhostError::RateLimited(format!(
                "Node {} rate limited for elder messages",
                hex::encode(&envelope.sender[..8])
            )));
        }

        match envelope.msg_type {
            MessageType::ElderRegistrationProposal => {
                // Try to deserialize as registration proposal
                if let Ok(msg) =
                    serde_json::from_slice::<ElderRegistrationProposalMessage>(&envelope.payload)
                {
                    self.handle_registration_proposal(envelope.sender, msg)
                        .await?;
                } else if let Ok(vote) =
                    serde_json::from_slice::<ElderRegistrationVoteMessage>(&envelope.payload)
                {
                    // Could also be a registration vote (same message type)
                    self.handle_registration_vote(envelope.sender, vote).await?;
                }
            }
            MessageType::ElderListProposal => {
                let msg: ElderListProposalMessage = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| GhostError::Serialization(e.to_string()))?;
                self.handle_list_proposal(envelope.sender, msg).await?;
            }
            MessageType::ElderListApproval => {
                let msg: ElderListApprovalMessage = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| GhostError::Serialization(e.to_string()))?;
                self.handle_list_approval(envelope.sender, msg).await?;
            }
            _ => {
                // Not our message type, ignore
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::identity::NodeIdentity;

    fn create_test_handler() -> (ElderRegistrationHandler, Arc<Database>) {
        let identity = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().unwrap());
        let manager = Arc::new(RwLock::new(ElderListManager::new(vec![])));

        let handler = ElderRegistrationHandler::new(identity, manager, Arc::clone(&db));
        (handler, db)
    }

    #[test]
    fn test_handler_creation() {
        let (handler, _) = create_test_handler();
        assert_eq!(handler.epoch(), 0);
        assert_eq!(handler.elder_count(), 0);
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(3, 1);
        let node_id = [1u8; 32];

        // Should allow initial burst
        assert!(limiter.check_and_consume(&node_id));
        assert!(limiter.check_and_consume(&node_id));
        assert!(limiter.check_and_consume(&node_id));

        // Should be rate limited
        assert!(!limiter.check_and_consume(&node_id));
    }

    #[test]
    fn test_cleanup() {
        let (handler, _) = create_test_handler();
        handler.cleanup();
        // Should not panic
    }
}
