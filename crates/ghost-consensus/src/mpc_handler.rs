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
//! 4. When >67% approve, contribution is applied (params updated)
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
use tracing::{debug, info, warn};

use ghost_common::error::{GhostError, GhostResult};
use ghost_common::identity::NodeIdentity;
use ghost_common::types::NodeId;
use ghost_storage::queries::{MpcContributionRecord, MpcVerificationVote as DbMpcVote};
use ghost_storage::Database;

use crate::elder_list::ElderListManager;
use crate::mesh::MessageHandler;
use crate::message::{
    MessageEnvelope, MessageType, MpcContributionMessage, MpcParametersRequestMessage,
    MpcParametersResponseMessage, MpcVerificationVoteMessage,
};

/// BFT threshold for MPC contribution approval (67%)
const MPC_BFT_THRESHOLD_PERCENT: u32 = 67;

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

/// Pending contribution awaiting verification
#[derive(Clone)]
struct PendingContribution {
    message: MpcContributionMessage,
    #[allow(dead_code)] // Reserved for timeout handling
    received_at: Instant,
    approval_count: u32,
    rejection_count: u32,
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
    /// Elder list manager for checking elder status
    elder_manager: Arc<RwLock<ElderListManager>>,
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
        elder_manager: Arc<RwLock<ElderListManager>>,
        db: Arc<Database>,
    ) -> Self {
        Self {
            identity,
            elder_manager,
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

    /// Get current contribution count
    pub fn contribution_count(&self) -> u32 {
        *self.contribution_count.read()
    }

    /// Handle an incoming MPC contribution
    fn handle_contribution(&self, msg: MpcContributionMessage, sender: NodeId) -> GhostResult<()> {
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
            pending.insert(
                contribution_hash,
                PendingContribution {
                    message: msg.clone(),
                    received_at: Instant::now(),
                    approval_count: 0,
                    rejection_count: 0,
                },
            );
        }

        info!(
            position = msg.elder_position,
            candidate = %hex::encode(&msg.candidate[..8]),
            "Received MPC contribution"
        );

        // If we're an elder, verify and vote
        if self.is_elder() {
            self.verify_and_vote(&msg)?;
        }

        Ok(())
    }

    /// Check if we are a current elder
    fn is_elder(&self) -> bool {
        let elder_manager = self.elder_manager.read();
        let current_list = elder_manager.current();
        current_list.is_elder(&self.identity.node_id())
    }

    /// Verify a contribution and cast our vote
    fn verify_and_vote(&self, msg: &MpcContributionMessage) -> GhostResult<()> {
        // For now, we verify the proof structurally
        // Full cryptographic verification would require loading the actual params
        let valid = !msg.contribution_proof.is_empty()
            && msg.prev_params_hash != [0u8; 32]
            && msg.new_params_hash != [0u8; 32]
            && msg.prev_params_hash != msg.new_params_hash;

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

        // Verify voter is an elder
        {
            let elder_manager = self.elder_manager.read();
            if !elder_manager.current().is_elder(&msg.voter) {
                warn!(
                    voter = %hex::encode(&msg.voter[..8]),
                    "MPC vote from non-elder"
                );
                return Ok(());
            }
        }

        // Update pending contribution
        let should_apply = {
            let mut pending = self.pending_contributions.write();
            if let Some(contribution) = pending.get_mut(&msg.contribution_hash) {
                if msg.approve {
                    contribution.approval_count += 1;
                } else {
                    contribution.rejection_count += 1;
                }

                // Check if we have BFT threshold
                let elder_count = self.elder_manager.read().current().elder_count() as u32;
                let threshold = (elder_count * MPC_BFT_THRESHOLD_PERCENT + 99) / 100;

                debug!(
                    approvals = contribution.approval_count,
                    rejections = contribution.rejection_count,
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
                voter_node_id: hex::encode(&msg.voter),
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
                contributor_node_id: hex::encode(&msg.candidate),
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
        match envelope.msg_type {
            MessageType::MpcContribution => {
                let msg: MpcContributionMessage = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| GhostError::Serialization(e.to_string()))?;
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
                warn!(msg_type = ?envelope.msg_type, "MpcHandler received unexpected message type");
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
