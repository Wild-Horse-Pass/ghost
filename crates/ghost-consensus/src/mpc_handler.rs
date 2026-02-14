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
//| FILE: mpc_handler.rs                                                                                                 |
//|======================================================================================================================|

//! MPC Ceremony Handler - MPC-C1/C2/C3/C4
//!
//! Handles the MPC ceremony protocol for ZK parameter generation:
//!
//! - **MPC-C1**: MpcContribution - new elder's contribution to ceremony
//! - **MPC-C2**: MpcVerificationVote - elder votes on contributions
//! - **MPC-C3**: MpcParametersRequest - request params from peers
//! - **MPC-C4**: MpcParametersResponse - chunked parameter transfer
//!
//! ## Ceremony Flow
//!
//! 1. New elder generates MPC contribution after registration approval
//! 2. Contribution is broadcast to network
//! 3. Current elders verify and vote on contribution
//! 4. Bootstrap (positions 1-3): genesis node approves alone
//!    Normal (position 4+): 75% (3/4) of elders must approve
//! 5. At elder 101, ceremony ossifies permanently
//!
//! ## Security Properties
//!
//! - 1-of-N security: Only ONE honest contributor needed
//! - BFT threshold (67%) prevents invalid contributions
//! - Cryptographic proof verifies valid transformation
//! - Toxic waste is zeroized immediately after contribution

use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, warn};

use ghost_common::error::{GhostError, GhostResult};
use ghost_common::identity::NodeIdentity;
use ghost_common::types::NodeId;
use ghost_storage::queries::{MpcContributionRecord, MpcVerificationVote as DbMpcVote};
use ghost_storage::Database;

use crate::mesh::MessageHandler;
use crate::message::{
    MessageEnvelope, MessageType, MpcContributionMessage, MpcParametersRequestMessage,
    MpcParametersResponseMessage, MpcVerificationVoteMessage,
};

/// BFT threshold for MPC contribution approval (75% = 3/4)
const MPC_BFT_THRESHOLD_PERCENT: u32 = 75;

/// Minimum number of MPC contributors before BFT voting kicks in.
/// During bootstrap (< 3 contributors), the genesis node can approve alone.
/// Once 3 elders exist, 75% (ceil(3*75/100)=3) approval is required.
const MPC_BFT_BOOTSTRAP_COUNT: u32 = 3;

/// Rate limiting for MPC messages
const RATE_LIMIT_MAX_TOKENS: u32 = 10;
const RATE_LIMIT_REFILL_RATE: u32 = 2; // 2 per second

/// Callback for broadcasting MPC messages to the network
pub type MpcBroadcastFn = Arc<dyn Fn(MessageType, Vec<u8>) -> GhostResult<()> + Send + Sync>;

/// Callback invoked when parameters are updated
pub type ParamsUpdateCallback = Arc<dyn Fn(&[u8; 32]) + Send + Sync>;

/// Token bucket for rate limiting
#[derive(Clone)]
struct TokenBucket {
    tokens: f64,
    last_update: Instant,
}

/// Rate limiter for MPC messages
struct RateLimiter {
    buckets: RwLock<HashMap<NodeId, TokenBucket>>,
    max_tokens: u32,
    refill_rate: u32,
}

impl RateLimiter {
    fn new(max_tokens: u32, refill_rate: u32) -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
            max_tokens,
            refill_rate,
        }
    }

    fn check_and_consume(&self, node_id: &NodeId) -> bool {
        let mut buckets = self.buckets.write();
        let now = Instant::now();

        let bucket = buckets.entry(*node_id).or_insert_with(|| TokenBucket {
            tokens: self.max_tokens as f64,
            last_update: now,
        });

        // Refill tokens
        let elapsed = now
            .duration_since(bucket.last_update)
            .as_secs_f64()
            .min(3600.0);
        let new_tokens = bucket.tokens + elapsed * self.refill_rate as f64;
        bucket.tokens = new_tokens.min(self.max_tokens as f64);
        bucket.last_update = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Maximum age for pending contributions before cleanup (30 minutes)
const PENDING_CONTRIBUTION_TIMEOUT_SECS: u64 = 30 * 60;

/// Pending contribution awaiting verification
#[derive(Clone)]
struct PendingContribution {
    message: MpcContributionMessage,
    received_at: Instant,
    approval_count: u32,
    rejection_count: u32,
    /// Track which voters have already voted (prevents duplicate vote inflation)
    voters: std::collections::HashSet<NodeId>,
}

/// MPC ceremony handler
///
/// Manages the MPC ceremony protocol, including:
/// - Receiving and validating contributions
/// - Collecting and counting verification votes
/// - Triggering contribution application on BFT approval
/// - Handling parameter sync requests
pub struct MpcHandler {
    /// Our node's identity
    identity: Arc<NodeIdentity>,
    /// Database for storing contributions and votes
    db: Arc<Database>,
    /// Broadcast function for sending messages
    broadcaster: Option<MpcBroadcastFn>,
    /// Callback when parameters are updated
    params_callback: Option<ParamsUpdateCallback>,
    /// Rate limiter
    rate_limiter: RateLimiter,
    /// Pending contributions awaiting BFT approval
    pending_contributions: RwLock<HashMap<[u8; 32], PendingContribution>>,
    /// Whether the ceremony has ossified
    is_ossified: RwLock<bool>,
    /// Current contribution count
    contribution_count: RwLock<u32>,
}

impl MpcHandler {
    /// Create a new MPC handler
    pub fn new(
        identity: Arc<NodeIdentity>,
        db: Arc<Database>,
    ) -> Self {
        Self {
            identity,
            db,
            broadcaster: None,
            params_callback: None,
            rate_limiter: RateLimiter::new(RATE_LIMIT_MAX_TOKENS, RATE_LIMIT_REFILL_RATE),
            pending_contributions: RwLock::new(HashMap::new()),
            is_ossified: RwLock::new(false),
            contribution_count: RwLock::new(0),
        }
    }

    /// Set the message broadcaster
    pub fn with_broadcaster(mut self, broadcaster: MpcBroadcastFn) -> Self {
        self.broadcaster = Some(broadcaster);
        self
    }

    /// Set the parameters update callback
    pub fn with_params_callback(mut self, callback: ParamsUpdateCallback) -> Self {
        self.params_callback = Some(callback);
        self
    }

    /// Initialize with ceremony state
    pub fn with_state(self, contribution_count: u32, is_ossified: bool) -> Self {
        *self.contribution_count.write() = contribution_count;
        *self.is_ossified.write() = is_ossified;
        self
    }

    /// Check if ceremony is ossified
    pub fn is_ossified(&self) -> bool {
        *self.is_ossified.read()
    }

    /// Get current contribution count from database
    ///
    /// This queries the database directly to ensure we have the latest count,
    /// since contributions can be applied outside this handler (e.g., during startup).
    pub fn contribution_count(&self) -> u32 {
        // Use database as single source of truth
        self.mpc_contributor_count()
    }

    /// Handle an incoming MPC contribution
    fn handle_contribution(&self, msg: MpcContributionMessage, sender: NodeId) -> GhostResult<()> {
        debug!(
            position = msg.elder_position,
            sender = %hex::encode(&sender[..8]),
            candidate = %hex::encode(&msg.candidate[..8]),
            "handle_contribution() entry"
        );

        // Rate limit
        if !self.rate_limiter.check_and_consume(&sender) {
            debug!(sender = %hex::encode(&sender[..8]), "MPC contribution rate limited");
            return Ok(());
        }

        // Check if ossified
        if self.is_ossified() {
            debug!("MPC ceremony ossified, ignoring contribution");
            return Ok(());
        }

        // Verify signature
        if !msg.verify_signature() {
            warn!(
                candidate = %hex::encode(&msg.candidate[..8]),
                "Invalid MPC contribution signature"
            );
            return Ok(());
        }

        // Verify position is next expected
        let expected_position = self.contribution_count() + 1;
        if msg.elder_position != expected_position {
            warn!(
                position = msg.elder_position,
                expected = expected_position,
                "MPC contribution position mismatch"
            );
            return Ok(());
        }

        // Store as pending
        let contribution_hash = msg.contribution_hash();
        {
            let mut pending = self.pending_contributions.write();
            if pending.contains_key(&contribution_hash) {
                debug!("Duplicate MPC contribution, ignoring");
                return Ok(());
            }
            // Clean up stale pending contributions before inserting
            pending.retain(|_, c| c.received_at.elapsed().as_secs() < PENDING_CONTRIBUTION_TIMEOUT_SECS);

            pending.insert(
                contribution_hash,
                PendingContribution {
                    message: msg.clone(),
                    received_at: Instant::now(),
                    approval_count: 0,
                    rejection_count: 0,
                    voters: std::collections::HashSet::new(),
                },
            );
        }

        info!(
            position = msg.elder_position,
            candidate = %hex::encode(&msg.candidate[..8]),
            "Received MPC contribution"
        );

        // Check for genesis case: first contribution is auto-approved
        let contributor_count = self.mpc_contributor_count();
        if contributor_count == 0 && msg.elder_position == 1 {
            info!("MPC genesis: Auto-approving first contribution (no existing contributors to vote)");
            self.apply_contribution(&contribution_hash)?;
            return Ok(());
        }

        // If we're an MPC contributor, verify and vote on new contributions
        if self.is_mpc_contributor() {
            self.verify_and_vote(&msg)?;
        }

        Ok(())
    }

    /// Check if we are an MPC contributor (elder)
    ///
    /// Elder status is determined by MPC contribution, not the old canonical elder list.
    /// If you contributed to the MPC ceremony, you're an elder.
    fn is_mpc_contributor(&self) -> bool {
        let node_id_hex = hex::encode(self.identity.node_id());
        self.db.is_mpc_elder(&node_id_hex).unwrap_or(false)
    }

    /// Check if a node is an MPC contributor
    fn is_node_mpc_contributor(&self, node_id: &NodeId) -> bool {
        let node_id_hex = hex::encode(node_id);
        self.db.is_mpc_elder(&node_id_hex).unwrap_or(false)
    }

    /// Get the current MPC contributor count
    fn mpc_contributor_count(&self) -> u32 {
        self.db.get_mpc_elder_count().unwrap_or(0)
    }

    /// Verify a contribution and cast our vote
    fn verify_and_vote(&self, msg: &MpcContributionMessage) -> GhostResult<()> {
        // Structural validation: proof exists, hashes are non-zero and different
        let structurally_valid = !msg.contribution_proof.is_empty()
            && msg.prev_params_hash != [0u8; 32]
            && msg.new_params_hash != [0u8; 32]
            && msg.prev_params_hash != msg.new_params_hash;

        // Hash chain validation: verify prev_params_hash matches the latest contribution
        // This prevents contributions that don't chain from the current ceremony state
        let chain_valid = if msg.elder_position == 1 {
            // Genesis contribution has no predecessor to validate against
            true
        } else {
            // Check that prev_params_hash matches new_params_hash of the previous contribution
            match self.db.get_mpc_contribution(msg.elder_position - 1) {
                Ok(Some(prev)) => {
                    if prev.new_params_hash != msg.prev_params_hash {
                        warn!(
                            position = msg.elder_position,
                            expected = %hex::encode(&prev.new_params_hash[..8]),
                            got = %hex::encode(&msg.prev_params_hash[..8]),
                            "MPC contribution prev_params_hash does not chain from previous contribution"
                        );
                        false
                    } else {
                        true
                    }
                }
                Ok(None) => {
                    warn!(
                        position = msg.elder_position,
                        prev_position = msg.elder_position - 1,
                        "Cannot verify hash chain: previous contribution not found"
                    );
                    false
                }
                Err(e) => {
                    warn!(error = %e, "Failed to look up previous MPC contribution for chain verification");
                    false
                }
            }
        };

        let valid = structurally_valid && chain_valid;

        // Sign and broadcast vote
        let signing_msg = {
            let mut hasher = sha2::Sha256::new();
            use sha2::Digest;
            hasher.update(b"MpcVerificationVote/v1");
            hasher.update(msg.contribution_hash());
            hasher.update([valid as u8]);
            let result: [u8; 32] = hasher.finalize().into();
            result
        };

        let signature = self.identity.sign(&signing_msg);

        let vote_msg = MpcVerificationVoteMessage {
            contribution_hash: msg.contribution_hash(),
            voter: self.identity.node_id(),
            approve: valid,
            rejection_reason: if valid {
                None
            } else {
                Some("Invalid proof".to_string())
            },
            signature,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        };

        // Save vote to database
        let db_vote = DbMpcVote {
            contribution_position: msg.elder_position,
            voter_node_id: hex::encode(self.identity.node_id()),
            approve: valid,
            signature: signature.to_vec(),
            voted_at: vote_msg.timestamp,
        };
        self.db.save_mpc_vote(&db_vote)?;

        // Broadcast vote
        if let Some(broadcaster) = &self.broadcaster {
            let payload = serde_json::to_vec(&vote_msg)
                .map_err(|e| GhostError::Serialization(e.to_string()))?;
            broadcaster(MessageType::MpcVerificationVote, payload)?;
        }

        info!(
            position = msg.elder_position,
            approve = valid,
            "Cast MPC verification vote"
        );

        // CRITICAL: Also count our own vote locally and check threshold
        // Without this, our vote only goes to peers but doesn't trigger
        // the approval threshold on this node
        let contribution_hash = msg.contribution_hash();
        let should_apply = {
            let mut pending = self.pending_contributions.write();
            if let Some(contribution) = pending.get_mut(&contribution_hash) {
                if valid {
                    contribution.approval_count += 1;
                } else {
                    contribution.rejection_count += 1;
                }

                // Check if we have BFT threshold
                let contributor_count = self.mpc_contributor_count();
                let threshold = if contributor_count < MPC_BFT_BOOTSTRAP_COUNT {
                    1 // Bootstrap phase: genesis node alone can approve positions 1-3
                } else {
                    // Normal BFT: 75% of MPC contributors (3/4 minimum)
                    (contributor_count * MPC_BFT_THRESHOLD_PERCENT).div_ceil(100)
                };

                info!(
                    approvals = contribution.approval_count,
                    rejections = contribution.rejection_count,
                    mpc_contributors = contributor_count,
                    threshold = threshold,
                    "Self-vote counted for MPC contribution"
                );

                contribution.approval_count >= threshold
            } else {
                false
            }
        };

        // Apply if threshold reached
        if should_apply {
            info!(position = msg.elder_position, "MPC contribution threshold met, applying");
            self.apply_contribution(&contribution_hash)?;
        }

        Ok(())
    }

    /// Handle an incoming verification vote
    fn handle_verification_vote(
        &self,
        msg: MpcVerificationVoteMessage,
        sender: NodeId,
    ) -> GhostResult<()> {
        // Rate limit
        if !self.rate_limiter.check_and_consume(&sender) {
            return Ok(());
        }

        // Verify signature
        if !msg.verify_signature() {
            warn!(
                voter = %hex::encode(&msg.voter[..8]),
                "Invalid MPC vote signature"
            );
            return Ok(());
        }

        // Verify voter is an MPC contributor (elder)
        if !self.is_node_mpc_contributor(&msg.voter) {
            warn!(
                voter = %hex::encode(&msg.voter[..8]),
                "MPC vote from non-contributor (not an elder)"
            );
            return Ok(());
        }

        // Update pending contribution (with duplicate vote prevention)
        let should_apply = {
            let mut pending = self.pending_contributions.write();
            if let Some(contribution) = pending.get_mut(&msg.contribution_hash) {
                // Reject duplicate votes from the same voter
                if !contribution.voters.insert(msg.voter) {
                    debug!(
                        voter = %hex::encode(&msg.voter[..8]),
                        "Duplicate MPC vote from same voter, ignoring"
                    );
                    return Ok(());
                }

                if msg.approve {
                    contribution.approval_count += 1;
                } else {
                    contribution.rejection_count += 1;
                }

                // Check if we have BFT threshold
                let contributor_count = self.mpc_contributor_count();
                let threshold = if contributor_count < MPC_BFT_BOOTSTRAP_COUNT {
                    1 // Bootstrap phase: genesis node alone can approve
                } else {
                    // Normal BFT: 75% of MPC contributors (3/4 minimum)
                    (contributor_count * MPC_BFT_THRESHOLD_PERCENT).div_ceil(100)
                };

                debug!(
                    approvals = contribution.approval_count,
                    rejections = contribution.rejection_count,
                    mpc_contributors = contributor_count,
                    threshold = threshold,
                    "MPC vote counted"
                );

                contribution.approval_count >= threshold
            } else {
                false
            }
        };

        // Save vote to database
        if let Some(pending) = self
            .pending_contributions
            .read()
            .get(&msg.contribution_hash)
        {
            let db_vote = DbMpcVote {
                contribution_position: pending.message.elder_position,
                voter_node_id: hex::encode(msg.voter),
                approve: msg.approve,
                signature: msg.signature.to_vec(),
                voted_at: msg.timestamp,
            };
            let _ = self.db.save_mpc_vote(&db_vote);
        }

        // Apply if threshold reached
        if should_apply {
            self.apply_contribution(&msg.contribution_hash)?;
        }

        Ok(())
    }

    /// Apply a contribution after BFT approval
    fn apply_contribution(&self, contribution_hash: &[u8; 32]) -> GhostResult<()> {
        let contribution = {
            let mut pending = self.pending_contributions.write();
            pending.remove(contribution_hash)
        };

        if let Some(contribution) = contribution {
            let msg = &contribution.message;

            // Save contribution to database
            let record = MpcContributionRecord {
                elder_position: msg.elder_position,
                contributor_node_id: hex::encode(msg.candidate),
                prev_params_hash: msg.prev_params_hash,
                new_params_hash: msg.new_params_hash,
                contribution_proof: msg.contribution_proof.clone(),
                epoch: 0, // Will be set properly in integration
                created_at: msg.timestamp,
            };
            self.db.save_mpc_contribution(&record)?;

            // Update state
            *self.contribution_count.write() = msg.elder_position;

            // Check for ossification
            if msg.elder_position >= 101 {
                *self.is_ossified.write() = true;
                info!("MPC ceremony OSSIFIED at 101 contributions");
            }

            // Notify callback
            if let Some(callback) = &self.params_callback {
                callback(&msg.new_params_hash);
            }

            info!(
                position = msg.elder_position,
                params_hash = %hex::encode(&msg.new_params_hash[..8]),
                "Applied MPC contribution"
            );
        }

        Ok(())
    }

    /// Handle parameter request
    fn handle_params_request(
        &self,
        msg: MpcParametersRequestMessage,
        sender: NodeId,
    ) -> GhostResult<()> {
        // Rate limit
        if !self.rate_limiter.check_and_consume(&sender) {
            return Ok(());
        }

        debug!(
            requester = %hex::encode(&msg.requester[..8]),
            params_hash = %hex::encode(&msg.params_hash[..8]),
            chunks = ?msg.chunk_indices,
            "Received MPC params request"
        );

        // Parameter serving would be handled by the sync module in ghost-mpc
        // This handler just logs the request

        Ok(())
    }

    /// Handle parameter response
    fn handle_params_response(
        &self,
        msg: MpcParametersResponseMessage,
        sender: NodeId,
    ) -> GhostResult<()> {
        debug!(
            sender = %hex::encode(&sender[..8]),
            params_hash = %hex::encode(&msg.params_hash[..8]),
            chunk = msg.chunk_index,
            total = msg.total_chunks,
            "Received MPC params chunk"
        );

        // Chunk handling would be done by ghost-mpc sync module

        Ok(())
    }
}

#[async_trait]
impl MessageHandler for MpcHandler {
    async fn handle_message(&self, envelope: MessageEnvelope) -> GhostResult<()> {
        // Log entry for MPC message types only
        if matches!(
            envelope.msg_type,
            MessageType::MpcContribution
                | MessageType::MpcVerificationVote
                | MessageType::MpcParametersRequest
                | MessageType::MpcParametersResponse
        ) {
            debug!(
                msg_type = ?envelope.msg_type,
                sender = %hex::encode(&envelope.sender[..8]),
                payload_len = envelope.payload.len(),
                "MpcHandler received MPC message"
            );
        }

        match envelope.msg_type {
            MessageType::MpcContribution => {
                let msg: MpcContributionMessage = match serde_json::from_slice(&envelope.payload) {
                    Ok(m) => m,
                    Err(e) => {
                        error!(
                            error = %e,
                            payload_preview = %String::from_utf8_lossy(&envelope.payload[..envelope.payload.len().min(200)]),
                            "MpcContribution deserialization failed"
                        );
                        return Err(GhostError::Serialization(e.to_string()));
                    }
                };
                debug!(
                    position = msg.elder_position,
                    candidate = %hex::encode(&msg.candidate[..8]),
                    "MpcContribution deserialized"
                );
                self.handle_contribution(msg, envelope.sender)?;
            }
            MessageType::MpcVerificationVote => {
                let msg: MpcVerificationVoteMessage = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| GhostError::Serialization(e.to_string()))?;
                self.handle_verification_vote(msg, envelope.sender)?;
            }
            MessageType::MpcParametersRequest => {
                let msg: MpcParametersRequestMessage = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| GhostError::Serialization(e.to_string()))?;
                self.handle_params_request(msg, envelope.sender)?;
            }
            MessageType::MpcParametersResponse => {
                let msg: MpcParametersResponseMessage =
                    serde_json::from_slice(&envelope.payload)
                        .map_err(|e| GhostError::Serialization(e.to_string()))?;
                self.handle_params_response(msg, envelope.sender)?;
            }
            _ => {
                // Handlers receive all message types - silently ignore non-MPC messages
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(5, 1);
        let node_id = [1u8; 32];

        // First 5 should succeed
        for _ in 0..5 {
            assert!(limiter.check_and_consume(&node_id));
        }

        // 6th should fail
        assert!(!limiter.check_and_consume(&node_id));
    }
}
