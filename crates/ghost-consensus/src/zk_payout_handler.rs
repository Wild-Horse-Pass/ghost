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
//| FILE: zk_payout_handler.rs                                                                                           |
//|======================================================================================================================|

//! ZK Payout Vote Handler - Processes ZK payout proposals and votes for ZK-BFT consensus
//!
//! This handler implements the ZK-BFT payout consensus protocol:
//! 1. Epoch settler generates ZK validity proof for payout distribution
//! 2. Settler broadcasts ZkPayoutProposal to validators
//! 3. Validators verify the ZK proof (~10ms) and vote
//! 4. Once 67% approve, payout is finalized and proof is discarded
//!
//! Settlement roles:
//! - Primary settler = proposer of the last block in the epoch
//! - Fallback settler = takes over after 5 minute timeout

use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use ghost_common::error::GhostResult;
use ghost_common::identity::NodeIdentity;
use ghost_common::types::NodeId;

use crate::ban_manager::{BanManager, BanReason};
use crate::vote_handler::RateLimiter;

use crate::epoch::{EpochTracker, SettlerRole};
use crate::mesh::MessageHandler;
use crate::message::{
    MessageEnvelope, MessageType, ZkPayoutConsensusResult, ZkPayoutProposalMessage,
    ZkPayoutRejectionReason, ZkPayoutVoteMessage,
};

/// Callback for broadcasting ZK payout messages
pub type ZkPayoutBroadcastFn = Arc<dyn Fn(MessageType, Vec<u8>) -> GhostResult<()> + Send + Sync>;

/// Callback for when a payout reaches consensus
pub type ZkPayoutConsensusCallback =
    Arc<dyn Fn(ZkPayoutConsensusResult) -> GhostResult<()> + Send + Sync>;

/// Callback for verifying ZK payout proofs
/// Arguments: (proof_bytes, total_available, miner_sum, node_sum, treasury_amount)
pub type ZkPayoutVerifyFn = Arc<dyn Fn(&[u8], u64, u64, u64, u64) -> bool + Send + Sync>;

/// Create a ZK payout verifier callback from a PayoutVerifier
///
/// This factory function wraps the ghost-zkp PayoutVerifier in a closure
/// compatible with ZkPayoutVoteHandler's verification interface.
///
/// # Arguments
/// * `verifier` - The PayoutVerifier initialized with Groth16 parameters
///
/// # Returns
/// A ZkPayoutVerifyFn that can be used with ZkPayoutVoteHandler::with_verifier()
#[cfg(feature = "zk-consensus")]
pub fn create_payout_verifier(
    verifier: std::sync::Arc<ghost_zkp::PayoutVerifier>,
) -> ZkPayoutVerifyFn {
    Arc::new(
        move |proof_bytes, total_available, miner_sum, node_sum, treasury_amount| {
            // Construct a PayoutProof for verification
            let proof = ghost_zkp::PayoutProof {
                epoch: 0, // Epoch is verified separately via proposal validation
                total_available,
                miner_count: 0, // Not part of cryptographic sum verification
                node_count: 0,
                miner_sum,
                node_sum,
                treasury_amount,
                proof: proof_bytes.to_vec(),
                prover_id: verifier.prover_id(), // Must match verifier's expected prover
            };
            verifier.verify(&proof).unwrap_or(false)
        },
    )
}

/// Rate limit max tokens for ZK payout messages (burst capacity)
/// 50 tokens max allows handling reorg scenarios where multiple proposals
/// arrive quickly. Normal operation uses ~1 per 10 minute round.
const ZK_PAYOUT_RATE_LIMIT_MAX_TOKENS: u32 = 50;

/// Rate limit refill rate for ZK payout messages (tokens per second)
/// 10/sec refill means full bucket refills in 5 seconds, allowing
/// rapid catch-up after network partitions while still limiting spam.
const ZK_PAYOUT_RATE_LIMIT_REFILL_RATE: u32 = 10;

/// Configuration for ZK payout vote handler
#[derive(Debug, Clone)]
pub struct ZkPayoutVoteHandlerConfig {
    /// Voting timeout in milliseconds (default: 60 seconds)
    pub vote_timeout_ms: u64,
    /// Maximum pending proposals (OOM protection)
    pub max_pending_proposals: usize,
    /// Minimum validators required (2f+1 where f is max byzantine)
    pub min_validators: u32,
    /// BFT threshold (67% = 2/3 + 1)
    pub bft_threshold_percent: u32,
    /// Rate limit max tokens per node (P2P-C3)
    pub rate_limit_max_tokens: u32,
    /// Rate limit refill rate - tokens per second (P2P-C3)
    pub rate_limit_refill_rate: u32,
    /// P2P4-L5: Rate limit window in seconds for cleanup (default: 300 / 5 minutes)
    pub rate_limit_window_secs: u64,
}

impl Default for ZkPayoutVoteHandlerConfig {
    fn default() -> Self {
        Self {
            vote_timeout_ms: 60_000, // 60 seconds (longer than block voting)
            max_pending_proposals: 50,
            min_validators: 4,         // Minimum for BFT (3f+1 where f=1)
            bft_threshold_percent: 67, // 2/3 majority
            rate_limit_max_tokens: ZK_PAYOUT_RATE_LIMIT_MAX_TOKENS,
            rate_limit_refill_rate: ZK_PAYOUT_RATE_LIMIT_REFILL_RATE,
            rate_limit_window_secs: 300, // P2P4-L5: 5 minutes default
        }
    }
}

/// State of a ZK payout proposal during voting
struct ZkPayoutProposalState {
    /// The proposal message
    proposal: ZkPayoutProposalMessage,
    /// Nodes that voted to approve
    approvals: HashSet<NodeId>,
    /// Nodes that voted to reject (with reasons)
    rejections: HashMap<NodeId, ZkPayoutRejectionReason>,
    /// When the proposal was received
    received_at: Instant,
    /// Whether consensus has been reached
    decided: bool,
    /// The consensus result (if decided)
    result: Option<ZkPayoutConsensusResult>,
}

impl ZkPayoutProposalState {
    fn new(proposal: ZkPayoutProposalMessage) -> Self {
        Self {
            proposal,
            approvals: HashSet::new(),
            rejections: HashMap::new(),
            received_at: Instant::now(),
            decided: false,
            result: None,
        }
    }

    #[allow(dead_code)]
    fn total_votes(&self) -> u32 {
        (self.approvals.len() + self.rejections.len()) as u32
    }
}

/// ZK Payout Vote Handler - manages ZK-BFT consensus for payout validity
pub struct ZkPayoutVoteHandler {
    /// Our node identity
    identity: Arc<NodeIdentity>,
    /// Epoch tracker for settler verification
    epoch_tracker: Option<Arc<EpochTracker>>,
    /// Set of eligible validators
    validators: RwLock<HashSet<NodeId>>,
    /// Pending proposals being voted on (epoch -> state)
    pending_proposals: RwLock<HashMap<u64, ZkPayoutProposalState>>,
    /// Broadcast function
    broadcast_fn: Option<ZkPayoutBroadcastFn>,
    /// Consensus callback
    consensus_callback: Option<ZkPayoutConsensusCallback>,
    /// ZK proof verification function
    verify_fn: Option<ZkPayoutVerifyFn>,
    /// Configuration
    config: ZkPayoutVoteHandlerConfig,
    /// Rate limiter for incoming messages (P2P-C3)
    rate_limiter: RateLimiter,
    /// Shared ban manager for cross-handler enforcement (C1 security fix)
    ban_manager: Option<Arc<BanManager>>,
}

impl ZkPayoutVoteHandler {
    /// Create a new ZK payout vote handler
    pub fn new(identity: Arc<NodeIdentity>) -> Self {
        Self::with_config(identity, ZkPayoutVoteHandlerConfig::default())
    }

    /// Create a new ZK payout vote handler with custom config
    pub fn with_config(identity: Arc<NodeIdentity>, config: ZkPayoutVoteHandlerConfig) -> Self {
        let rate_limiter =
            RateLimiter::new(config.rate_limit_max_tokens, config.rate_limit_refill_rate);
        Self {
            identity,
            epoch_tracker: None,
            validators: RwLock::new(HashSet::new()),
            pending_proposals: RwLock::new(HashMap::new()),
            broadcast_fn: None,
            consensus_callback: None,
            verify_fn: None,
            config,
            rate_limiter,
            ban_manager: None,
        }
    }

    /// Set the shared ban manager for cross-handler enforcement (C1 security fix)
    pub fn with_ban_manager(mut self, ban_manager: Arc<BanManager>) -> Self {
        self.ban_manager = Some(ban_manager);
        self
    }

    /// Ban a node for equivocation (H5 security fix)
    fn ban_node(&self, node_id: NodeId) {
        if let Some(ref ban_manager) = self.ban_manager {
            ban_manager.ban(node_id, BanReason::Equivocation);
        } else {
            warn!(
                node_id = %hex::encode(&node_id[..8]),
                "Node detected equivocating but no ban manager configured"
            );
        }
    }

    /// Check if node is banned
    fn is_banned(&self, node_id: &NodeId) -> bool {
        if let Some(ref ban_manager) = self.ban_manager {
            ban_manager.is_banned(node_id)
        } else {
            false
        }
    }

    /// Clean up rate limiter state (call periodically)
    ///
    /// P2P4-L5: Uses configurable window from config
    pub fn cleanup_rate_limiter(&self) {
        self.rate_limiter
            .cleanup(self.config.rate_limit_window_secs);
    }

    /// Set epoch tracker for settler verification
    pub fn with_epoch_tracker(mut self, tracker: Arc<EpochTracker>) -> Self {
        self.epoch_tracker = Some(tracker);
        self
    }

    /// Set broadcast function
    pub fn with_broadcaster(mut self, f: ZkPayoutBroadcastFn) -> Self {
        self.broadcast_fn = Some(f);
        self
    }

    /// Set consensus callback
    pub fn with_consensus_callback(mut self, f: ZkPayoutConsensusCallback) -> Self {
        self.consensus_callback = Some(f);
        self
    }

    /// Set ZK verification function
    pub fn with_verifier(mut self, f: ZkPayoutVerifyFn) -> Self {
        self.verify_fn = Some(f);
        self
    }

    /// Set validators
    pub fn set_validators(&self, validators: HashSet<NodeId>) {
        info!(count = validators.len(), "ZK payout validators updated");
        *self.validators.write() = validators;
    }

    /// Add a validator
    pub fn add_validator(&self, node_id: NodeId) {
        self.validators.write().insert(node_id);
    }

    /// Remove a validator
    pub fn remove_validator(&self, node_id: &NodeId) {
        self.validators.write().remove(node_id);
    }

    /// Get validator count
    pub fn validator_count(&self) -> usize {
        self.validators.read().len()
    }

    /// Calculate the threshold for BFT consensus
    fn calculate_threshold(&self) -> u32 {
        let total = self.validators.read().len() as u32;
        // 67% threshold (2/3 + 1)
        (total * self.config.bft_threshold_percent / 100).max(1)
    }

    /// Handle a new ZK payout proposal
    pub fn handle_proposal(&self, proposal: ZkPayoutProposalMessage) -> GhostResult<()> {
        let epoch = proposal.epoch;
        let proposal_hash = proposal.proposal_hash();

        // Validate proposal
        if let Err(reason) = self.validate_proposal(&proposal) {
            warn!(
                epoch,
                reason = ?reason,
                "Rejecting invalid ZK payout proposal"
            );
            return Ok(());
        }

        // Check if we already have a proposal for this epoch
        {
            let proposals = self.pending_proposals.read();
            if proposals.len() >= self.config.max_pending_proposals {
                warn!("Too many pending ZK payout proposals, rejecting");
                return Ok(());
            }
            if proposals.contains_key(&epoch) {
                debug!(epoch, "Already have payout proposal for this epoch");
                return Ok(());
            }
        }

        // Store the proposal
        {
            let mut proposals = self.pending_proposals.write();
            proposals.insert(epoch, ZkPayoutProposalState::new(proposal.clone()));
        }

        info!(
            epoch,
            proposal_hash = hex::encode(proposal_hash),
            total_available = proposal.total_available,
            miner_count = proposal.miner_count,
            node_count = proposal.node_count,
            "Received ZK payout proposal"
        );

        // If we're a validator, verify and vote
        if self.validators.read().contains(&self.identity.node_id()) {
            self.verify_and_vote(epoch, &proposal)?;
        }

        Ok(())
    }

    /// Validate a ZK payout proposal
    fn validate_proposal(
        &self,
        proposal: &ZkPayoutProposalMessage,
    ) -> Result<(), ZkPayoutRejectionReason> {
        // Verify settler authorization if epoch tracker is available
        if let Some(ref tracker) = self.epoch_tracker {
            let settler_role = tracker
                .is_settler(&proposal.proposer, proposal.epoch)
                .map_err(|_| {
                    ZkPayoutRejectionReason::Other("Failed to check settler".to_string())
                })?;

            if settler_role == SettlerRole::NotSettler {
                return Err(ZkPayoutRejectionReason::InvalidSettler);
            }
        }

        // Timestamp should be reasonable (within 5 minutes)
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let tolerance = 300_000; // 5 minutes
        if proposal.timestamp < now.saturating_sub(tolerance)
            || proposal.timestamp > now.saturating_add(tolerance)
        {
            return Err(ZkPayoutRejectionReason::Other(
                "Invalid timestamp".to_string(),
            ));
        }

        // Proof must not be empty
        if proposal.proof.is_empty() {
            return Err(ZkPayoutRejectionReason::InvalidProof);
        }

        // Sum must match
        let computed_sum = proposal
            .miner_sum
            .saturating_add(proposal.node_sum)
            .saturating_add(proposal.treasury_amount);

        if computed_sum != proposal.total_available {
            return Err(ZkPayoutRejectionReason::SumMismatch);
        }

        Ok(())
    }

    /// Verify the ZK proof and vote
    fn verify_and_vote(&self, epoch: u64, proposal: &ZkPayoutProposalMessage) -> GhostResult<()> {
        // Verify the ZK proof
        let proof_valid = if let Some(ref verify) = self.verify_fn {
            verify(
                &proposal.proof,
                proposal.total_available,
                proposal.miner_sum,
                proposal.node_sum,
                proposal.treasury_amount,
            )
        } else {
            // No verifier set - accept by default (for testing)
            warn!("No ZK payout verifier set, accepting proof by default");
            true
        };

        let (approve, rejection_reason) = if proof_valid {
            (true, None)
        } else {
            (false, Some(ZkPayoutRejectionReason::InvalidProof))
        };

        // Cast our vote
        self.cast_vote(epoch, proposal.proposal_hash(), approve, rejection_reason)?;

        Ok(())
    }

    /// Cast a vote on a payout proposal
    pub fn cast_vote(
        &self,
        epoch: u64,
        proposal_hash: [u8; 32],
        approve: bool,
        rejection_reason: Option<ZkPayoutRejectionReason>,
    ) -> GhostResult<()> {
        // Create vote message
        let vote = ZkPayoutVoteMessage::new(
            epoch,
            proposal_hash,
            approve,
            rejection_reason.clone(),
            self.identity.sign(
                &ZkPayoutVoteMessage::new(
                    epoch,
                    proposal_hash,
                    approve,
                    rejection_reason.clone(),
                    [0u8; 64],
                )
                .signing_message(),
            ),
        );

        // Record our own vote
        self.record_vote(self.identity.node_id(), &vote)?;

        // Broadcast to peers
        if let Some(ref broadcast) = self.broadcast_fn {
            let payload = serde_json::to_vec(&vote)
                .map_err(|e| ghost_common::error::GhostError::Serialization(e.to_string()))?;
            broadcast(MessageType::ZkPayoutVote, payload)?;
        }

        debug!(epoch, approve, "Cast ZK payout vote");
        Ok(())
    }

    /// Record a vote from any validator
    ///
    /// H5 security fix: Includes equivocation detection - if a voter has already
    /// voted differently, this is Byzantine behavior and they are banned.
    fn record_vote(&self, voter: NodeId, vote: &ZkPayoutVoteMessage) -> GhostResult<()> {
        let epoch = vote.epoch;

        // Check if voter is eligible
        if !self.validators.read().contains(&voter) {
            debug!(
                voter = hex::encode(&voter[..8]),
                "Payout vote from non-validator ignored"
            );
            return Ok(());
        }

        let mut proposals = self.pending_proposals.write();
        let state = match proposals.get_mut(&epoch) {
            Some(s) => s,
            None => {
                debug!(epoch, "Vote for unknown payout proposal epoch");
                return Ok(());
            }
        };

        // Check if already decided
        if state.decided {
            return Ok(());
        }

        // Check proposal hash matches
        if state.proposal.proposal_hash() != vote.proposal_hash {
            warn!(epoch, "Vote for wrong payout proposal hash");
            return Ok(());
        }

        // H5: Equivocation detection - check if voter already voted differently
        if vote.approve {
            // Trying to approve - check if they already rejected
            if state.rejections.contains_key(&voter) {
                // EQUIVOCATION: Voter already rejected, now trying to approve
                warn!(
                    epoch,
                    voter = %hex::encode(&voter[..8]),
                    "EQUIVOCATION DETECTED: voter already rejected, now trying to approve"
                );
                drop(proposals); // Release lock before banning
                self.ban_node(voter);
                return Ok(());
            }
        } else {
            // Trying to reject - check if they already approved
            if state.approvals.contains(&voter) {
                // EQUIVOCATION: Voter already approved, now trying to reject
                warn!(
                    epoch,
                    voter = %hex::encode(&voter[..8]),
                    "EQUIVOCATION DETECTED: voter already approved, now trying to reject"
                );
                drop(proposals); // Release lock before banning
                self.ban_node(voter);
                return Ok(());
            }
        }

        // Record the vote
        if vote.approve {
            if state.approvals.insert(voter) {
                debug!(
                    epoch,
                    voter = hex::encode(&voter[..8]),
                    "Payout approval recorded"
                );
            }
        } else if let std::collections::hash_map::Entry::Vacant(e) = state.rejections.entry(voter) {
            e.insert(
                vote.rejection_reason
                    .clone()
                    .unwrap_or(ZkPayoutRejectionReason::Other(
                        "No reason given".to_string(),
                    )),
            );
            debug!(
                epoch,
                voter = hex::encode(&voter[..8]),
                "Payout rejection recorded"
            );
        }

        // Check for consensus
        let threshold = self.calculate_threshold();
        let total_validators = self.validators.read().len() as u32;

        // Check if we reached consensus and prepare the result
        let consensus_result = if state.approvals.len() as u32 >= threshold {
            // Consensus reached - approved!
            let approvals_count = state.approvals.len() as u32;
            let result = ZkPayoutConsensusResult::Approved {
                epoch,
                proposal_hash: state.proposal.proposal_hash(),
                approvals: approvals_count,
                total_validators,
            };
            state.decided = true;
            state.result = Some(result.clone());

            info!(
                epoch,
                approvals = approvals_count,
                threshold,
                "ZK payout approved by consensus"
            );

            Some(result)
        } else if state.rejections.len() as u32 > total_validators - threshold {
            // Consensus reached - rejected!
            let primary_reason = state
                .rejections
                .values()
                .next()
                .cloned()
                .unwrap_or(ZkPayoutRejectionReason::Other("Unknown".to_string()));

            let rejections_count = state.rejections.len() as u32;
            let result = ZkPayoutConsensusResult::Rejected {
                epoch,
                rejections: rejections_count,
                total_validators,
                primary_reason,
            };
            state.decided = true;
            state.result = Some(result.clone());

            warn!(
                epoch,
                rejections = rejections_count,
                "ZK payout rejected by consensus"
            );

            Some(result)
        } else {
            None
        };

        // Drop the lock before callbacks
        drop(proposals);

        // Handle consensus result outside the lock
        if let Some(result) = consensus_result {
            // Notify callback
            if let Some(ref callback) = self.consensus_callback {
                let _ = callback(result);
            }
        }

        Ok(())
    }

    /// Handle incoming vote from another validator
    fn handle_incoming_vote(&self, sender: NodeId, vote: ZkPayoutVoteMessage) -> GhostResult<()> {
        // Verify vote signature
        let message = vote.signing_message();
        if !ghost_common::identity::verify_signature(&sender, &message, &vote.signature)? {
            warn!(
                sender = hex::encode(&sender[..8]),
                epoch = vote.epoch,
                "Invalid payout vote signature, ignoring"
            );
            return Ok(());
        }
        self.record_vote(sender, &vote)
    }

    /// Check for timed out proposals
    pub fn check_timeouts(&self) -> Vec<ZkPayoutConsensusResult> {
        let timeout = Duration::from_millis(self.config.vote_timeout_ms);
        let mut results = Vec::new();
        let total_validators = self.validators.read().len() as u32;

        let mut proposals = self.pending_proposals.write();
        for (epoch, state) in proposals.iter_mut() {
            if !state.decided && state.received_at.elapsed() > timeout {
                let result = ZkPayoutConsensusResult::Timeout {
                    epoch: *epoch,
                    approvals: state.approvals.len() as u32,
                    rejections: state.rejections.len() as u32,
                    total_validators,
                };
                state.decided = true;
                state.result = Some(result.clone());
                results.push(result);

                warn!(
                    epoch,
                    approvals = state.approvals.len(),
                    rejections = state.rejections.len(),
                    "ZK payout voting timed out"
                );
            }
        }

        // Clean up old decided proposals (keep last 10)
        if proposals.len() > 10 {
            let mut epochs: Vec<_> = proposals.keys().cloned().collect();
            epochs.sort();
            for epoch in epochs.iter().take(proposals.len().saturating_sub(10)) {
                if proposals.get(epoch).map(|s| s.decided).unwrap_or(false) {
                    proposals.remove(epoch);
                }
            }
        }

        results
    }

    /// Get voting status for an epoch
    pub fn get_status(&self, epoch: u64) -> Option<ZkPayoutVotingStatus> {
        let proposals = self.pending_proposals.read();
        proposals.get(&epoch).map(|state| ZkPayoutVotingStatus {
            epoch,
            proposal_hash: state.proposal.proposal_hash(),
            approvals: state.approvals.len() as u32,
            rejections: state.rejections.len() as u32,
            total_validators: self.validators.read().len() as u32,
            threshold: self.calculate_threshold(),
            decided: state.decided,
            result: state.result.clone(),
        })
    }

    /// Cancel a payout proposal for a specific epoch
    pub fn cancel_proposal(&self, epoch: u64) {
        let mut proposals = self.pending_proposals.write();
        if proposals.remove(&epoch).is_some() {
            info!(epoch, "Cancelled ZK payout proposal");
        }
    }
}

#[async_trait]
impl MessageHandler for ZkPayoutVoteHandler {
    async fn handle_message(&self, envelope: MessageEnvelope) -> GhostResult<()> {
        // C1: Check if node is banned using shared BanManager
        if self.is_banned(&envelope.sender) {
            return Err(ghost_common::error::GhostError::NodeBanned(format!(
                "Node {} is banned",
                hex::encode(&envelope.sender[..8])
            )));
        }

        // Rate limit check - reject messages from nodes sending too fast (P2P-C3)
        if !self.rate_limiter.check_and_consume(&envelope.sender) {
            warn!(
                sender = hex::encode(&envelope.sender[..8]),
                msg_type = ?envelope.msg_type,
                "Rate limited ZK payout message from peer"
            );
            return Err(ghost_common::error::GhostError::RateLimited(format!(
                "Rate limited ZK payout message from {}",
                hex::encode(&envelope.sender[..8])
            )));
        }

        match envelope.msg_type {
            MessageType::ZkPayoutProposal => {
                let proposal: ZkPayoutProposalMessage = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| {
                    ghost_common::error::GhostError::Serialization(e.to_string())
                })?;
                self.handle_proposal(proposal)?;
            }
            MessageType::ZkPayoutVote => {
                let vote: ZkPayoutVoteMessage = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| ghost_common::error::GhostError::Serialization(e.to_string()))?;
                self.handle_incoming_vote(envelope.sender, vote)?;
            }
            _ => {
                // Not our message type
            }
        }
        Ok(())
    }
}

/// ZK payout voting status summary
#[derive(Debug, Clone)]
pub struct ZkPayoutVotingStatus {
    pub epoch: u64,
    pub proposal_hash: [u8; 32],
    pub approvals: u32,
    pub rejections: u32,
    pub total_validators: u32,
    pub threshold: u32,
    pub decided: bool,
    pub result: Option<ZkPayoutConsensusResult>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_identity() -> Arc<NodeIdentity> {
        Arc::new(NodeIdentity::generate())
    }

    fn create_test_proposal(epoch: u64, proposer: NodeId) -> ZkPayoutProposalMessage {
        ZkPayoutProposalMessage {
            epoch,
            round_id: 1,
            block_hash: [1u8; 32],
            proposer,
            total_available: 1000,
            miner_count: 2,
            miner_sum: 500,
            node_count: 2,
            node_sum: 400,
            treasury_amount: 100,
            payout_merkle_root: [2u8; 32],
            proof: vec![0u8; 64],
            proposer_signature: [0u8; 64],
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        }
    }

    #[test]
    fn test_zk_payout_handler_creation() {
        let identity = create_test_identity();
        let handler = ZkPayoutVoteHandler::new(identity);

        assert_eq!(handler.validator_count(), 0);
    }

    #[test]
    fn test_validator_management() {
        let identity = create_test_identity();
        let handler = ZkPayoutVoteHandler::new(identity);

        handler.add_validator([1u8; 32]);
        handler.add_validator([2u8; 32]);
        handler.add_validator([3u8; 32]);
        assert_eq!(handler.validator_count(), 3);

        handler.remove_validator(&[2u8; 32]);
        assert_eq!(handler.validator_count(), 2);
    }

    #[test]
    fn test_threshold_calculation() {
        let identity = create_test_identity();
        let handler = ZkPayoutVoteHandler::new(identity);

        // Add 4 validators
        for i in 0..4 {
            handler.add_validator([i; 32]);
        }

        // 67% of 4 = 2.68, so threshold should be 2
        let threshold = handler.calculate_threshold();
        assert_eq!(threshold, 2);

        // Add more validators
        for i in 4..10 {
            handler.add_validator([i; 32]);
        }

        // 67% of 10 = 6.7, so threshold should be 6
        let threshold = handler.calculate_threshold();
        assert_eq!(threshold, 6);
    }

    #[test]
    fn test_proposal_validation() {
        let identity = create_test_identity();
        let handler = ZkPayoutVoteHandler::new(identity);

        let proposer = [0xABu8; 32];

        // Valid proposal
        let valid_proposal = create_test_proposal(1, proposer);
        assert!(handler.validate_proposal(&valid_proposal).is_ok());

        // Invalid sum
        let mut bad_sum = create_test_proposal(1, proposer);
        bad_sum.miner_sum = 999; // Sum won't match
        assert!(matches!(
            handler.validate_proposal(&bad_sum),
            Err(ZkPayoutRejectionReason::SumMismatch)
        ));

        // Empty proof
        let mut empty_proof = create_test_proposal(1, proposer);
        empty_proof.proof = vec![];
        assert!(matches!(
            handler.validate_proposal(&empty_proof),
            Err(ZkPayoutRejectionReason::InvalidProof)
        ));
    }

    #[test]
    fn test_proposal_handling() {
        let identity = create_test_identity();
        let handler = ZkPayoutVoteHandler::new(identity);

        // Add ourselves plus other validators (so we don't reach immediate consensus)
        let our_id = handler.identity.node_id();
        handler.add_validator(our_id);
        handler.add_validator([1u8; 32]);
        handler.add_validator([2u8; 32]);

        let proposer = [0xABu8; 32];
        let proposal = create_test_proposal(1, proposer);

        // Handle the proposal
        handler.handle_proposal(proposal.clone()).unwrap();

        // Should have the proposal stored
        let status = handler.get_status(1);
        assert!(status.is_some());
        let status = status.unwrap();
        assert_eq!(status.epoch, 1);
        // We have 1 approval (ours), threshold is 2, so not decided yet
        assert_eq!(status.approvals, 1);
        assert!(!status.decided);

        // Duplicate proposals should be ignored
        handler.handle_proposal(proposal).unwrap();
    }

    #[test]
    fn test_voting_consensus() {
        let identity = create_test_identity();
        let handler = ZkPayoutVoteHandler::new(identity);

        // Add validators (including ourselves)
        let our_id = handler.identity.node_id();
        handler.add_validator(our_id);
        handler.add_validator([1u8; 32]);
        handler.add_validator([2u8; 32]);

        let proposer = [0xABu8; 32];
        let proposal = create_test_proposal(1, proposer);
        let proposal_hash = proposal.proposal_hash();

        // Handle the proposal
        handler.handle_proposal(proposal).unwrap();

        // First vote (ours, auto-cast since we're a validator)
        let status = handler.get_status(1).unwrap();
        assert_eq!(status.approvals, 1);
        assert!(!status.decided);

        // Second vote
        let vote1 = ZkPayoutVoteMessage::new(1, proposal_hash, true, None, [0u8; 64]);
        handler.record_vote([1u8; 32], &vote1).unwrap();

        // Should have consensus now (2 out of 3, threshold = 67% = 2)
        let status = handler.get_status(1).unwrap();
        assert!(status.decided);
        assert!(matches!(
            status.result,
            Some(ZkPayoutConsensusResult::Approved { .. })
        ));
    }

    #[test]
    fn test_voting_rejection() {
        let identity = create_test_identity();
        let handler = ZkPayoutVoteHandler::new(identity.clone());

        // Add validators
        let our_id = handler.identity.node_id();
        handler.add_validator(our_id);
        handler.add_validator([1u8; 32]);
        handler.add_validator([2u8; 32]);

        let proposer = [0xABu8; 32];
        let proposal = create_test_proposal(1, proposer);
        let proposal_hash = proposal.proposal_hash();

        // Store proposal without auto-voting (to control the test)
        {
            let mut proposals = handler.pending_proposals.write();
            proposals.insert(1, ZkPayoutProposalState::new(proposal));
        }

        // All validators reject
        let vote1 = ZkPayoutVoteMessage::new(
            1,
            proposal_hash,
            false,
            Some(ZkPayoutRejectionReason::InvalidProof),
            [0u8; 64],
        );
        handler.record_vote(our_id, &vote1).unwrap();

        let vote2 = ZkPayoutVoteMessage::new(
            1,
            proposal_hash,
            false,
            Some(ZkPayoutRejectionReason::InvalidProof),
            [0u8; 64],
        );
        handler.record_vote([1u8; 32], &vote2).unwrap();

        // Should be rejected now (2 rejections > total - threshold = 3 - 2 = 1)
        let status = handler.get_status(1).unwrap();
        assert!(status.decided);
        assert!(matches!(
            status.result,
            Some(ZkPayoutConsensusResult::Rejected { .. })
        ));
    }

    #[test]
    fn test_timeout_handling() {
        let identity = create_test_identity();
        let mut config = ZkPayoutVoteHandlerConfig::default();
        config.vote_timeout_ms = 1; // Very short timeout for testing
        let handler = ZkPayoutVoteHandler::with_config(identity, config);

        handler.add_validator([1u8; 32]);

        let proposer = [0xABu8; 32];
        let proposal = create_test_proposal(1, proposer);

        // Store proposal manually to avoid voting
        {
            let mut proposals = handler.pending_proposals.write();
            proposals.insert(1, ZkPayoutProposalState::new(proposal));
        }

        // Wait for timeout
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Check timeouts
        let timeouts = handler.check_timeouts();
        assert_eq!(timeouts.len(), 1);
        assert!(matches!(
            &timeouts[0],
            ZkPayoutConsensusResult::Timeout { epoch: 1, .. }
        ));
    }

    #[test]
    fn test_cancel_proposal() {
        let identity = create_test_identity();
        let handler = ZkPayoutVoteHandler::new(identity);

        let proposer = [0xABu8; 32];
        let proposal = create_test_proposal(1, proposer);

        // Store proposal
        {
            let mut proposals = handler.pending_proposals.write();
            proposals.insert(1, ZkPayoutProposalState::new(proposal));
        }

        assert!(handler.get_status(1).is_some());

        // Cancel it
        handler.cancel_proposal(1);
        assert!(handler.get_status(1).is_none());
    }

    #[test]
    fn test_zk_payout_rate_limiting() {
        // P2P-C3: Rate limiting to prevent DoS
        let identity = create_test_identity();
        let config = ZkPayoutVoteHandlerConfig {
            rate_limit_max_tokens: 2,
            rate_limit_refill_rate: 1,
            ..Default::default()
        };
        let handler = ZkPayoutVoteHandler::with_config(identity, config);

        let test_node = [42u8; 32];

        // First two messages should pass
        assert!(handler.rate_limiter.check_and_consume(&test_node));
        assert!(handler.rate_limiter.check_and_consume(&test_node));

        // Third message should be rate limited
        assert!(!handler.rate_limiter.check_and_consume(&test_node));

        // Different node should not be affected
        let other_node = [43u8; 32];
        assert!(handler.rate_limiter.check_and_consume(&other_node));
    }
}
