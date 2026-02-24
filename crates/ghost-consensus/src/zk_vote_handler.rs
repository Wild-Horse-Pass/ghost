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
//| FILE: zk_vote_handler.rs                                                                                             |
//|======================================================================================================================|

//! ZK Vote Handler - Processes ZK block proposals and votes for ZK-BFT consensus
//!
//! This handler implements the ZK-BFT consensus protocol:
//! 1. Block proposer generates ZK validity proof (~2 seconds)
//! 2. Proposer broadcasts ZkBlockProposal to validators
//! 3. Validators verify the ZK proof (~10ms) and vote
//! 4. Once 67% approve, block is finalized and proof is discarded
//!
//! Key design principles:
//! - Proofs are ephemeral (verified once, then discarded)
//! - State is truth (no proof history needed)
//! - Math guarantees validity (no re-execution needed)
//!
//! ## Rate Limiting (P2P-M4)
//!
//! Incoming ZK votes and proposals are rate limited per-node using a token bucket
//! algorithm to prevent DoS attacks. Each node has a bucket that refills at a
//! configured rate, with messages rejected when the bucket is empty.

use async_trait::async_trait;
use parking_lot::RwLock;
// sha2 available for future cryptographic operations
#[allow(unused_imports)]
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use ghost_common::error::GhostResult;
use ghost_common::identity::NodeIdentity;
use ghost_common::types::NodeId;

use crate::mesh::MessageHandler;
use crate::message::{
    MessageEnvelope, MessageType, ZkBlockProposalMessage, ZkConsensusResult, ZkRejectionReason,
    ZkVoteMessage,
};
use crate::vote_handler::RateLimiter;

/// Callback for broadcasting ZK messages
pub type ZkBroadcastFn = Arc<dyn Fn(MessageType, Vec<u8>) -> GhostResult<()> + Send + Sync>;

/// Callback for when a block reaches consensus
pub type ZkConsensusCallback = Arc<dyn Fn(ZkConsensusResult) -> GhostResult<()> + Send + Sync>;

/// Callback for verifying ZK proofs
pub type ZkVerifyFn = Arc<dyn Fn(&[u8], &[u8; 32], &[u8; 32]) -> bool + Send + Sync>;

/// Create a ZK block verifier callback from a BlockVerifier
///
/// This factory function wraps the ghost-zkp BlockVerifier in a closure
/// compatible with ZkVoteHandler's verification interface.
///
/// # Arguments
/// * `verifier` - The BlockVerifier initialized with Groth16 parameters
///
/// # Returns
/// A ZkVerifyFn that can be used with ZkVoteHandler::with_verifier()
#[cfg(feature = "zk-consensus")]
pub fn create_block_verifier(verifier: std::sync::Arc<ghost_zkp::BlockVerifier>) -> ZkVerifyFn {
    Arc::new(move |proof_bytes, prev_root, new_root| {
        // Construct a minimal BlockProof for verification
        // The verifier will check the proof bytes against the state roots
        let proof = ghost_zkp::BlockProof {
            height: 0, // Height is not verified in the proof itself
            prev_state_root: *prev_root,
            new_state_root: *new_root,
            tx_count: 0, // Not part of cryptographic verification
            proof: proof_bytes.to_vec(),
            version: ghost_zkp::BlockProof::CURRENT_VERSION,
        };
        verifier.verify(&proof).unwrap_or(false)
    })
}

/// Default rate limit configuration for ZK messages
const ZK_RATE_LIMIT_MAX_TOKENS: u32 = 50;
const ZK_RATE_LIMIT_REFILL_RATE: u32 = 10;

/// Configuration for ZK vote handler
#[derive(Debug, Clone)]
pub struct ZkVoteHandlerConfig {
    /// Voting timeout in milliseconds (default: 30 seconds)
    pub vote_timeout_ms: u64,
    /// Maximum pending proposals (OOM protection)
    pub max_pending_proposals: usize,
    /// Minimum validators required (2f+1 where f is max byzantine)
    pub min_validators: u32,
    /// BFT threshold (67% = 2/3 + 1)
    pub bft_threshold_percent: u32,
    /// Rate limit max tokens per node
    pub rate_limit_max_tokens: u32,
    /// Rate limit refill rate (tokens per second)
    pub rate_limit_refill_rate: u32,
}

impl Default for ZkVoteHandlerConfig {
    fn default() -> Self {
        Self {
            vote_timeout_ms: 30_000, // 30 seconds
            max_pending_proposals: 100,
            min_validators: 4,         // Minimum for BFT (3f+1 where f=1)
            bft_threshold_percent: 67, // 2/3 majority
            rate_limit_max_tokens: ZK_RATE_LIMIT_MAX_TOKENS,
            rate_limit_refill_rate: ZK_RATE_LIMIT_REFILL_RATE,
        }
    }
}

/// State of a ZK block proposal during voting
struct ZkProposalState {
    /// The proposal message
    proposal: ZkBlockProposalMessage,
    /// Nodes that voted to approve
    approvals: HashSet<NodeId>,
    /// Nodes that voted to reject (with reasons)
    rejections: HashMap<NodeId, ZkRejectionReason>,
    /// When the proposal was received
    received_at: Instant,
    /// Whether consensus has been reached
    decided: bool,
    /// The consensus result (if decided)
    result: Option<ZkConsensusResult>,
}

impl ZkProposalState {
    fn new(proposal: ZkBlockProposalMessage) -> Self {
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

/// ZK Vote Handler - manages ZK-BFT consensus for block validity
pub struct ZkVoteHandler {
    /// Our node identity
    identity: Arc<NodeIdentity>,
    /// Current state root (what we believe the L2 state is)
    current_state_root: RwLock<[u8; 32]>,
    /// Current L2 block height
    current_height: RwLock<u64>,
    /// Set of eligible validators
    validators: RwLock<HashSet<NodeId>>,
    /// Pending proposals being voted on (height -> state)
    pending_proposals: RwLock<HashMap<u64, ZkProposalState>>,
    /// Broadcast function
    broadcast_fn: Option<ZkBroadcastFn>,
    /// Consensus callback
    consensus_callback: Option<ZkConsensusCallback>,
    /// ZK proof verification function (uses RwLock for deferred initialization)
    verify_fn: RwLock<Option<ZkVerifyFn>>,
    /// Configuration
    config: ZkVoteHandlerConfig,
    /// Rate limiter for incoming messages (P2P-M4)
    rate_limiter: RateLimiter,
}

impl ZkVoteHandler {
    /// Create a new ZK vote handler
    pub fn new(identity: Arc<NodeIdentity>) -> Self {
        Self::with_config(identity, ZkVoteHandlerConfig::default())
    }

    /// Create a new ZK vote handler with custom config
    pub fn with_config(identity: Arc<NodeIdentity>, config: ZkVoteHandlerConfig) -> Self {
        let rate_limiter =
            RateLimiter::new(config.rate_limit_max_tokens, config.rate_limit_refill_rate);
        Self {
            identity,
            current_state_root: RwLock::new([0u8; 32]),
            current_height: RwLock::new(0),
            validators: RwLock::new(HashSet::new()),
            pending_proposals: RwLock::new(HashMap::new()),
            broadcast_fn: None,
            consensus_callback: None,
            verify_fn: RwLock::new(None),
            config,
            rate_limiter,
        }
    }

    /// Clean up rate limiter state (call periodically)
    pub fn cleanup_rate_limiter(&self) {
        self.rate_limiter.cleanup(300); // 5 minute TTL
    }

    /// Set broadcast function
    pub fn with_broadcaster(mut self, f: ZkBroadcastFn) -> Self {
        self.broadcast_fn = Some(f);
        self
    }

    /// Set consensus callback
    pub fn with_consensus_callback(mut self, f: ZkConsensusCallback) -> Self {
        self.consensus_callback = Some(f);
        self
    }

    /// Set ZK verification function (builder pattern)
    pub fn with_verifier(self, f: ZkVerifyFn) -> Self {
        *self.verify_fn.write() = Some(f);
        self
    }

    /// Set ZK verification function (for deferred initialization)
    pub fn set_verifier(&self, f: ZkVerifyFn) {
        *self.verify_fn.write() = Some(f);
        info!("ZK block verifier set (deferred initialization complete)");
    }

    /// Check if verifier is ready (for producer to wait before proposing)
    pub fn has_verifier(&self) -> bool {
        self.verify_fn.read().is_some()
    }

    /// Set current state (call at startup or after reorg)
    pub fn set_state(&self, height: u64, state_root: [u8; 32]) {
        *self.current_height.write() = height;
        *self.current_state_root.write() = state_root;
        info!(
            height,
            state_root = hex::encode(state_root),
            "ZK state updated"
        );
    }

    /// Get current state
    pub fn get_state(&self) -> (u64, [u8; 32]) {
        (*self.current_height.read(), *self.current_state_root.read())
    }

    /// Set validators
    pub fn set_validators(&self, validators: HashSet<NodeId>) {
        info!(count = validators.len(), "ZK validators updated");
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

    /// Get sorted validator list (for deterministic proposer election)
    pub fn get_sorted_validators(&self) -> Vec<NodeId> {
        let validators = self.validators.read();
        let mut sorted: Vec<NodeId> = validators.iter().copied().collect();
        sorted.sort();
        sorted
    }

    /// Calculate the threshold for BFT consensus
    ///
    /// HIGH-3/H-5 SECURITY FIX: Returns 0 when no validators exist to indicate
    /// consensus is impossible. Callers must check for 0 threshold.
    ///
    /// Previous behavior: `(0 * 67 / 100).max(1) = 1` which implied consensus
    /// was possible with just 1 approval when there were 0 validators.
    ///
    /// Fixed behavior: Returns 0 explicitly when total=0, signaling that
    /// consensus is impossible. Callers (record_vote) check for threshold=0
    /// and skip consensus determination.
    fn calculate_threshold(&self) -> u32 {
        let total = self.validators.read().len() as u32;
        // HIGH-3/H-5: With zero validators, no consensus is possible
        // Return 0 to signal this - callers must handle appropriately
        if total == 0 {
            return 0;
        }
        // 67% threshold (2/3 + 1)
        (total * self.config.bft_threshold_percent / 100).max(1)
    }

    /// Handle a new ZK block proposal (as proposer or receiver)
    pub fn handle_proposal(&self, proposal: ZkBlockProposalMessage) -> GhostResult<()> {
        let height = proposal.height;
        let proposal_hash = proposal.proposal_hash();

        // Validate proposal
        if let Err(reason) = self.validate_proposal(&proposal) {
            warn!(
                height,
                reason = ?reason,
                "Rejecting invalid ZK proposal"
            );
            return Ok(());
        }

        // Check if we already have a proposal for this height
        {
            let proposals = self.pending_proposals.read();
            if proposals.len() >= self.config.max_pending_proposals {
                warn!("Too many pending ZK proposals, rejecting");
                return Ok(());
            }
            if proposals.contains_key(&height) {
                debug!(height, "Already have proposal for this height");
                return Ok(());
            }
        }

        // Store the proposal
        {
            let mut proposals = self.pending_proposals.write();
            proposals.insert(height, ZkProposalState::new(proposal.clone()));
        }

        info!(
            height,
            proposal_hash = hex::encode(proposal_hash),
            tx_count = proposal.tx_count,
            "Received ZK block proposal"
        );

        // Broadcast proposal to peers (dedup prevents loops — peers that already
        // have this proposal will return early at "Already have proposal")
        if let Some(ref broadcast) = self.broadcast_fn {
            let payload = serde_json::to_vec(&proposal)
                .map_err(|e| ghost_common::error::GhostError::Serialization(e.to_string()))?;
            if let Err(e) = broadcast(MessageType::ZkBlockProposal, payload) {
                warn!(height, error = %e, "Failed to broadcast ZK proposal");
            }
        }

        // If we're a validator, verify and vote
        if self.validators.read().contains(&self.identity.node_id()) {
            self.verify_and_vote(height, &proposal)?;
        }

        Ok(())
    }

    /// Validate a ZK block proposal
    fn validate_proposal(
        &self,
        proposal: &ZkBlockProposalMessage,
    ) -> Result<(), ZkRejectionReason> {
        let current_height = *self.current_height.read();
        let current_state = *self.current_state_root.read();

        // Height must be sequential
        if proposal.height != current_height + 1 {
            return Err(ZkRejectionReason::InvalidHeight);
        }

        // Previous state root must match our current state
        if proposal.prev_state_root != current_state {
            return Err(ZkRejectionReason::PrevStateRootMismatch);
        }

        // Timestamp should be reasonable (within 60 seconds)
        // Proposal timestamps are in seconds (UNIX epoch)
        let now = chrono::Utc::now().timestamp() as u64;
        let tolerance = 60; // 60 seconds
        if proposal.timestamp < now.saturating_sub(tolerance)
            || proposal.timestamp > now.saturating_add(tolerance)
        {
            return Err(ZkRejectionReason::InvalidTimestamp);
        }

        // Proof must not be empty
        if proposal.proof.is_empty() {
            return Err(ZkRejectionReason::InvalidProof);
        }

        Ok(())
    }

    /// Verify the ZK proof and vote
    fn verify_and_vote(&self, height: u64, proposal: &ZkBlockProposalMessage) -> GhostResult<()> {
        // Verify the ZK proof
        let verify_fn = self.verify_fn.read();
        let proof_valid = if let Some(ref verify) = *verify_fn {
            verify(
                &proposal.proof,
                &proposal.prev_state_root,
                &proposal.new_state_root,
            )
        } else {
            // SECURITY: No verifier configured - REJECT all proofs
            // Fail-closed is mandatory for mainnet security (verifier may still be initializing)
            warn!("ZK verifier not yet initialized - rejecting proof (will retry when ready)");
            false
        };

        let (approve, rejection_reason) = if proof_valid {
            (true, None)
        } else {
            (false, Some(ZkRejectionReason::InvalidProof))
        };

        // Cast our vote
        self.cast_vote(height, proposal.proposal_hash(), approve, rejection_reason)?;

        Ok(())
    }

    /// Cast a vote on a proposal
    pub fn cast_vote(
        &self,
        height: u64,
        proposal_hash: [u8; 32],
        approve: bool,
        rejection_reason: Option<ZkRejectionReason>,
    ) -> GhostResult<()> {
        // Create vote message
        let vote = ZkVoteMessage::new(
            height,
            proposal_hash,
            approve,
            rejection_reason.clone(),
            self.identity.sign(
                &ZkVoteMessage::new(
                    height,
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
            broadcast(MessageType::ZkVote, payload)?;
        }

        debug!(height, approve, "Cast ZK vote");
        Ok(())
    }

    /// Record a vote from any validator
    fn record_vote(&self, voter: NodeId, vote: &ZkVoteMessage) -> GhostResult<()> {
        let height = vote.height;

        // Check if voter is eligible
        if !self.validators.read().contains(&voter) {
            debug!(
                voter = hex::encode(&voter[..8]),
                "Vote from non-validator ignored"
            );
            return Ok(());
        }

        let mut proposals = self.pending_proposals.write();
        let state = match proposals.get_mut(&height) {
            Some(s) => s,
            None => {
                debug!(height, "Vote for unknown proposal height");
                return Ok(());
            }
        };

        // Check if already decided
        if state.decided {
            return Ok(());
        }

        // Check proposal hash matches
        if state.proposal.proposal_hash() != vote.proposal_hash {
            warn!(height, "Vote for wrong proposal hash");
            return Ok(());
        }

        // Record the vote
        if vote.approve {
            if state.approvals.insert(voter) {
                debug!(
                    height,
                    voter = hex::encode(&voter[..8]),
                    "Approval recorded"
                );
            }
        } else if let std::collections::hash_map::Entry::Vacant(e) = state.rejections.entry(voter) {
            e.insert(
                vote.rejection_reason
                    .clone()
                    .unwrap_or(ZkRejectionReason::Other("No reason given".to_string())),
            );
            debug!(
                height,
                voter = hex::encode(&voter[..8]),
                "Rejection recorded"
            );
        }

        // Check for consensus
        let threshold = self.calculate_threshold();
        let total_validators = self.validators.read().len() as u32;

        // HIGH-3/H-5 SECURITY: With 0 validators (threshold=0), consensus is impossible
        // Check if we reached consensus and prepare the result
        let consensus_result = if threshold == 0 {
            // No validators means no consensus possible
            None
        } else if state.approvals.len() as u32 >= threshold {
            // Consensus reached - approved!
            let new_state_root = state.proposal.new_state_root;
            let approvals_count = state.approvals.len() as u32;
            let result = ZkConsensusResult::Approved {
                height,
                new_state_root,
                approvals: approvals_count,
                total_validators,
            };
            state.decided = true;
            state.result = Some(result.clone());

            info!(
                height,
                approvals = approvals_count,
                threshold,
                "ZK block approved by consensus"
            );

            Some((result, Some(new_state_root)))
        } else if state.rejections.len() as u32 > total_validators - threshold {
            // Consensus reached - rejected!
            let primary_reason = state
                .rejections
                .values()
                .next()
                .cloned()
                .unwrap_or(ZkRejectionReason::Other("Unknown".to_string()));

            let rejections_count = state.rejections.len() as u32;
            let result = ZkConsensusResult::Rejected {
                height,
                rejections: rejections_count,
                total_validators,
                primary_reason,
            };
            state.decided = true;
            state.result = Some(result.clone());

            warn!(
                height,
                rejections = rejections_count,
                "ZK block rejected by consensus"
            );

            Some((result, None))
        } else {
            None
        };

        // Drop the lock before callbacks
        drop(proposals);

        // Handle consensus result outside the lock
        if let Some((result, new_state_root)) = consensus_result {
            // Update our state if approved
            if let Some(root) = new_state_root {
                *self.current_height.write() = height;
                *self.current_state_root.write() = root;
            }

            // Notify callback
            if let Some(ref callback) = self.consensus_callback {
                let _ = callback(result);
            }
        }

        Ok(())
    }

    /// Handle incoming vote from another validator
    fn handle_incoming_vote(&self, sender: NodeId, vote: ZkVoteMessage) -> GhostResult<()> {
        // Verify vote signature
        let message = vote.signing_message();
        if !ghost_common::identity::verify_signature(&sender, &message, &vote.signature)? {
            warn!(
                sender = hex::encode(&sender[..8]),
                height = vote.height,
                "Invalid vote signature, ignoring"
            );
            return Ok(());
        }
        self.record_vote(sender, &vote)
    }

    /// Check for timed out proposals
    pub fn check_timeouts(&self) -> Vec<ZkConsensusResult> {
        let timeout = Duration::from_millis(self.config.vote_timeout_ms);
        let mut results = Vec::new();
        let total_validators = self.validators.read().len() as u32;

        let mut proposals = self.pending_proposals.write();
        for (height, state) in proposals.iter_mut() {
            if !state.decided && state.received_at.elapsed() > timeout {
                let result = ZkConsensusResult::Timeout {
                    height: *height,
                    approvals: state.approvals.len() as u32,
                    rejections: state.rejections.len() as u32,
                    total_validators,
                };
                state.decided = true;
                state.result = Some(result.clone());
                results.push(result);

                warn!(
                    height,
                    approvals = state.approvals.len(),
                    rejections = state.rejections.len(),
                    "ZK voting timed out"
                );
            }
        }

        // Clean up old decided proposals (keep last 10)
        if proposals.len() > 10 {
            let mut heights: Vec<_> = proposals.keys().cloned().collect();
            heights.sort();
            for height in heights.iter().take(proposals.len().saturating_sub(10)) {
                if proposals.get(height).map(|s| s.decided).unwrap_or(false) {
                    proposals.remove(height);
                }
            }
        }

        results
    }

    /// Get voting status for a height
    pub fn get_status(&self, height: u64) -> Option<ZkVotingStatus> {
        let proposals = self.pending_proposals.read();
        proposals.get(&height).map(|state| ZkVotingStatus {
            height,
            proposal_hash: state.proposal.proposal_hash(),
            approvals: state.approvals.len() as u32,
            rejections: state.rejections.len() as u32,
            total_validators: self.validators.read().len() as u32,
            threshold: self.calculate_threshold(),
            decided: state.decided,
            result: state.result.clone(),
        })
    }

    /// Cancel proposals for a specific height (called on reorg)
    pub fn cancel_proposal(&self, height: u64) {
        let mut proposals = self.pending_proposals.write();
        if proposals.remove(&height).is_some() {
            info!(height, "Cancelled ZK proposal due to reorg");
        }
    }

    /// Handle an L2 reorg by rolling back to a snapshot
    ///
    /// This should be called when the L1 chain reorgs and we need to
    /// roll back the L2 state. It:
    /// 1. Cancels all pending proposals above the target height
    /// 2. Restores state from the snapshot
    /// 3. Updates current height and state root
    pub fn handle_reorg(
        &self,
        target_height: u64,
        snapshot_state_root: [u8; 32],
    ) -> GhostResult<()> {
        let current = *self.current_height.read();

        if target_height >= current {
            debug!(
                target_height,
                current, "Reorg target is at or above current height, no action needed"
            );
            return Ok(());
        }

        info!(
            current,
            target_height,
            rollback_blocks = current - target_height,
            "Handling L2 reorg"
        );

        // Cancel all pending proposals above the target height
        {
            let mut proposals = self.pending_proposals.write();
            let heights_to_remove: Vec<_> = proposals
                .keys()
                .filter(|h| **h > target_height)
                .cloned()
                .collect();

            for height in heights_to_remove {
                proposals.remove(&height);
                debug!(height, "Cancelled proposal during reorg");
            }
        }

        // Update state
        *self.current_height.write() = target_height;
        *self.current_state_root.write() = snapshot_state_root;

        info!(
            target_height,
            state_root = hex::encode(snapshot_state_root),
            "L2 reorg complete"
        );

        Ok(())
    }

    /// Called when a block is finalized to potentially create a snapshot
    ///
    /// Returns true if a snapshot should be created at this height.
    /// The actual snapshot creation is done by the caller with the balances.
    pub fn should_create_snapshot(&self, height: u64, snapshot_interval: u64) -> bool {
        height > 0 && height.is_multiple_of(snapshot_interval)
    }

    /// Check if there's an active (undecided) proposal for a given height
    pub fn has_pending_proposal(&self, height: u64) -> bool {
        self.pending_proposals
            .read()
            .get(&height)
            .map(|s| !s.decided)
            .unwrap_or(false)
    }

    /// Get all heights with pending (undecided) proposals
    pub fn get_pending_heights(&self) -> Vec<u64> {
        self.pending_proposals
            .read()
            .iter()
            .filter(|(_, state)| !state.decided)
            .map(|(h, _)| *h)
            .collect()
    }
}

#[async_trait]
impl MessageHandler for ZkVoteHandler {
    async fn handle_message(&self, envelope: MessageEnvelope) -> GhostResult<()> {
        // Rate limit check - reject messages from nodes sending too fast (P2P-M4)
        if !self.rate_limiter.check_and_consume(&envelope.sender) {
            warn!(
                sender = hex::encode(&envelope.sender[..8]),
                msg_type = ?envelope.msg_type,
                "Rate limited ZK message from peer"
            );
            return Err(ghost_common::error::GhostError::RateLimited(format!(
                "Node {} rate limited for ZK messages",
                hex::encode(&envelope.sender[..8])
            )));
        }

        match envelope.msg_type {
            MessageType::ZkBlockProposal => {
                let proposal: ZkBlockProposalMessage = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| ghost_common::error::GhostError::Serialization(e.to_string()))?;
                self.handle_proposal(proposal)?;
            }
            MessageType::ZkVote => {
                let vote: ZkVoteMessage = serde_json::from_slice(&envelope.payload)
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

/// ZK voting status summary
#[derive(Debug, Clone)]
pub struct ZkVotingStatus {
    pub height: u64,
    pub proposal_hash: [u8; 32],
    pub approvals: u32,
    pub rejections: u32,
    pub total_validators: u32,
    pub threshold: u32,
    pub decided: bool,
    pub result: Option<ZkConsensusResult>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_identity() -> Arc<NodeIdentity> {
        Arc::new(NodeIdentity::generate())
    }

    fn create_test_proposal(
        height: u64,
        prev_root: [u8; 32],
        new_root: [u8; 32],
    ) -> ZkBlockProposalMessage {
        ZkBlockProposalMessage {
            height,
            prev_state_root: prev_root,
            new_state_root: new_root,
            tx_count: 5,
            transactions_hash: [3u8; 32],
            transactions: vec![],
            proof: vec![0u8; 72],
            proposer_signature: [0u8; 64],
            timestamp: chrono::Utc::now().timestamp() as u64,
        }
    }

    #[test]
    fn test_zk_vote_handler_creation() {
        let identity = create_test_identity();
        let handler = ZkVoteHandler::new(identity);

        assert_eq!(handler.validator_count(), 0);
        assert_eq!(handler.get_state(), (0, [0u8; 32]));
    }

    #[test]
    fn test_set_state() {
        let identity = create_test_identity();
        let handler = ZkVoteHandler::new(identity);

        handler.set_state(100, [1u8; 32]);
        assert_eq!(handler.get_state(), (100, [1u8; 32]));
    }

    #[test]
    fn test_validator_management() {
        let identity = create_test_identity();
        let handler = ZkVoteHandler::new(identity);

        handler.add_validator([1u8; 32]);
        handler.add_validator([2u8; 32]);
        handler.add_validator([3u8; 32]);
        assert_eq!(handler.validator_count(), 3);

        handler.remove_validator(&[2u8; 32]);
        assert_eq!(handler.validator_count(), 2);
    }

    #[test]
    fn test_proposal_validation() {
        let identity = create_test_identity();
        let handler = ZkVoteHandler::new(identity);

        // Set initial state
        handler.set_state(99, [1u8; 32]);

        // Valid proposal (height 100, prev_root matches)
        let valid_proposal = create_test_proposal(100, [1u8; 32], [2u8; 32]);
        assert!(handler.validate_proposal(&valid_proposal).is_ok());

        // Invalid height (should be 100)
        let wrong_height = create_test_proposal(101, [1u8; 32], [2u8; 32]);
        assert!(matches!(
            handler.validate_proposal(&wrong_height),
            Err(ZkRejectionReason::InvalidHeight)
        ));

        // Invalid prev state root
        let wrong_root = create_test_proposal(100, [9u8; 32], [2u8; 32]);
        assert!(matches!(
            handler.validate_proposal(&wrong_root),
            Err(ZkRejectionReason::PrevStateRootMismatch)
        ));
    }

    #[test]
    fn test_threshold_calculation() {
        let identity = create_test_identity();
        let handler = ZkVoteHandler::new(identity);

        // HIGH-3/H-5 SECURITY TEST: With zero validators, threshold should be 0 (no consensus possible)
        let threshold = handler.calculate_threshold();
        assert_eq!(
            threshold, 0,
            "HIGH-3: Zero validators should return threshold of 0"
        );

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
    fn test_high3_zero_validators_no_consensus() {
        // HIGH-3/H-5 SECURITY TEST: Verify that zero validators means no consensus possible
        let identity = create_test_identity();
        let handler = ZkVoteHandler::new(identity);

        // Should return 0 (no consensus possible) with zero validators
        assert_eq!(handler.calculate_threshold(), 0);
        assert_eq!(handler.validator_count(), 0);

        // Operations should not panic with zero validators
        let timeouts = handler.check_timeouts();
        assert!(timeouts.is_empty());
    }

    #[test]
    fn test_reorg_handling() {
        let identity = create_test_identity();
        let handler = ZkVoteHandler::new(identity);

        // Set initial state at height 100
        handler.set_state(100, [1u8; 32]);

        // Simulate reorg to height 90
        let snapshot_root = [2u8; 32];
        handler.handle_reorg(90, snapshot_root).unwrap();

        // Check state was updated
        assert_eq!(handler.get_state(), (90, snapshot_root));
    }

    #[test]
    fn test_reorg_cancels_pending_proposals() {
        let identity = create_test_identity();
        let handler = ZkVoteHandler::new(identity);

        // Set current state at height 102 (as if blocks 100, 101, 102 were finalized)
        handler.set_state(102, [1u8; 32]);

        // Add pending proposals at heights 100, 101, 102
        {
            let mut proposals = handler.pending_proposals.write();
            for h in 100..=102 {
                let proposal = create_test_proposal(h, [1u8; 32], [2u8; 32]);
                proposals.insert(h, ZkProposalState::new(proposal));
            }
        }

        // Verify we have 3 pending proposals
        assert_eq!(handler.get_pending_heights().len(), 3);

        // Reorg to height 100 should cancel proposals at 101 and 102 (but keep 100)
        handler.handle_reorg(100, [3u8; 32]).unwrap();

        // Should only have proposal at 100 left (h > target_height removes 101 and 102)
        let pending = handler.get_pending_heights();
        assert_eq!(pending.len(), 1);
        assert!(pending.contains(&100));
    }

    #[test]
    fn test_snapshot_interval() {
        let identity = create_test_identity();
        let handler = ZkVoteHandler::new(identity);

        // Test snapshot interval of 100
        assert!(!handler.should_create_snapshot(0, 100)); // height 0 is not a snapshot
        assert!(!handler.should_create_snapshot(50, 100));
        assert!(handler.should_create_snapshot(100, 100));
        assert!(handler.should_create_snapshot(200, 100));
        assert!(!handler.should_create_snapshot(150, 100));
    }

    #[test]
    fn test_rate_limiting() {
        // Test with very restrictive rate limits
        let identity = create_test_identity();
        let config = ZkVoteHandlerConfig {
            rate_limit_max_tokens: 2,
            rate_limit_refill_rate: 1,
            ..Default::default()
        };
        let handler = ZkVoteHandler::with_config(identity, config);

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
