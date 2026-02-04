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

/// Rate limiting for elder messages
const RATE_LIMIT_MAX_TOKENS: u32 = 5;
const RATE_LIMIT_REFILL_RATE: u32 = 1; // 1 per second

/// Delay before proposing a new list after registration hits threshold (seconds)
const PROPOSAL_DELAY_SECS: u64 = 60;

/// Maximum time to wait for list approvals (seconds)
const APPROVAL_TIMEOUT_SECS: u64 = 300; // 5 minutes

/// Token bucket for rate limiting
#[derive(Clone)]
struct TokenBucket {
    tokens: f64,
    last_update: Instant,
}

/// Rate limiter for elder messages
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
    /// Callback invoked on epoch transitions
    transition_callback: Option<TransitionCallback>,
    /// Shared ban manager
    ban_manager: Option<Arc<BanManager>>,
    /// Rate limiter
    rate_limiter: RateLimiter,
    /// Pending list proposals awaiting approvals
    pending_proposals: RwLock<HashMap<u64, PendingListProposal>>,
    /// Approved registrations waiting for proposal delay
    approved_registrations: RwLock<HashMap<NodeId, Instant>>,
}

impl ElderRegistrationHandler {
    /// Create a new elder registration handler
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
            transition_callback: None,
            ban_manager: None,
            rate_limiter: RateLimiter::new(RATE_LIMIT_MAX_TOKENS, RATE_LIMIT_REFILL_RATE),
            pending_proposals: RwLock::new(HashMap::new()),
            approved_registrations: RwLock::new(HashMap::new()),
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

    /// Set the transition callback
    pub fn set_transition_callback(&mut self, callback: TransitionCallback) {
        self.transition_callback = Some(callback);
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

        // 2. Verify PoW proof
        let pow_proof = NodeIdProof {
            nonce: msg.pow_nonce,
            difficulty: msg.pow_difficulty,
        };
        if !pow_proof.verify(&msg.candidate, NODE_ID_POW_DIFFICULTY) {
            warn!(
                candidate = %short_candidate,
                "Invalid PoW proof in registration proposal"
            );
            return Err(GhostError::Config("Invalid PoW proof".to_string()));
        }

        // 3. Verify uptime requirements
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
        if msg.target_epoch != current_epoch + 1 {
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
        let candidate_hex = hex::encode(msg.candidate);
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

    /// Cast a vote on a registration proposal
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

        // Broadcast the vote (registration votes use the same topic as proposals)
        let payload = serde_json::to_vec(&signed_vote)
            .map_err(|e| GhostError::Serialization(e.to_string()))?;
        self.broadcast(MessageType::ElderRegistrationProposal, payload)?;

        info!(
            candidate = %short_candidate,
            approve,
            "Cast elder registration vote"
        );

        // Check if we've reached threshold
        let (approvals, rejections_count) =
            self.db.count_elder_registration_approvals(request.id)?;
        let current_list = self.elder_list_manager.read().current();
        let total_elders = current_list.elder_count();
        let threshold =
            (total_elders as u32 * ELDER_BFT_THRESHOLD_PERCENT).div_ceil(100).max(1) as usize;

        if approvals as usize >= threshold {
            info!(
                candidate = %short_candidate,
                approvals,
                threshold,
                "Registration approved - will propose new list"
            );

            // Mark as approved in database
            self.db
                .update_elder_registration_status(request.id, "approved")?;

            // Schedule list proposal after delay
            self.approved_registrations
                .write()
                .insert(proposal.candidate, Instant::now());
        } else if rejections_count as usize > (total_elders - threshold) {
            info!(
                candidate = %short_candidate,
                rejections = rejections_count,
                "Registration rejected"
            );
            self.db
                .update_elder_registration_status(request.id, "rejected")?;
        }

        Ok(())
    }

    /// Handle an incoming registration vote
    async fn handle_registration_vote(
        &self,
        sender: NodeId,
        msg: ElderRegistrationVoteMessage,
    ) -> GhostResult<()> {
        let short_voter = hex::encode(&msg.voter[..8]);
        let short_candidate = hex::encode(&msg.candidate[..8]);

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

        // Check if threshold reached
        let (approvals, _rejections) = self.db.count_elder_registration_approvals(request.id)?;
        let current_list = self.elder_list_manager.read().current();
        let total_elders = current_list.elder_count();
        let threshold =
            (total_elders as u32 * ELDER_BFT_THRESHOLD_PERCENT).div_ceil(100).max(1) as usize;

        if approvals as usize >= threshold && request.status == "pending" {
            info!(
                candidate = %short_candidate,
                approvals,
                threshold,
                "Registration approved by consensus"
            );

            self.db
                .update_elder_registration_status(request.id, "approved")?;

            // If we are the proposer, prepare to create the list proposal
            if sender == self.identity.node_id() {
                self.approved_registrations
                    .write()
                    .insert(msg.candidate, Instant::now());
            }
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

        // 7. Store pending proposal
        {
            let mut pending = self.pending_proposals.write();
            pending.insert(
                msg.epoch,
                PendingListProposal {
                    epoch: msg.epoch,
                    merkle_root: msg.merkle_root,
                    elders_data: msg.elders_data.clone(),
                    proposer: msg.proposer,
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
        let threshold =
            (total_elders as u32 * ELDER_BFT_THRESHOLD_PERCENT).div_ceil(100).max(1) as usize;

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

        // 6. Invoke transition callback
        if let Some(ref callback) = self.transition_callback {
            callback(&new_list);
        }

        info!(
            epoch,
            elder_count = new_list.elder_count(),
            "Epoch transition complete"
        );

        Ok(())
    }

    /// Cleanup expired state (call periodically)
    pub fn cleanup(&self) {
        // Clean up rate limiter
        self.rate_limiter.cleanup(300);

        // Clean up expired pending proposals
        {
            let mut pending = self.pending_proposals.write();
            pending.retain(|_, p| p.received_at.elapsed().as_secs() < APPROVAL_TIMEOUT_SECS);
        }

        // Clean up approved registrations that have passed proposal delay
        {
            let mut approved = self.approved_registrations.write();
            approved.retain(|_, instant| instant.elapsed().as_secs() < PROPOSAL_DELAY_SECS * 2);
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

        // Store as pending
        {
            let mut pending = self.pending_proposals.write();
            pending.insert(
                new_epoch,
                PendingListProposal {
                    epoch: new_epoch,
                    merkle_root: new_list.merkle_root,
                    elders_data,
                    proposer: self.identity.node_id(),
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
