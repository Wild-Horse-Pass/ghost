//! NullifierRouteHandler — L2 transaction validation + checkpoint BFT
//!
//! Replaces the old ZkVoteHandler for L2. All nodes validate transactions;
//! all active nodes participate in BFT checkpoint consensus.
//!
//! Flow:
//! 1. Sender submits tx with ZK proof → deterministically routed to validator
//! 2. Validator verifies proof (~5ms), confirms to sender, broadcasts
//! 3. Every 10s: proposer assembles checkpoint from confirmed pool
//! 4. All active nodes vote on checkpoint (67% BFT threshold)
//! 5. On finalization: persist, update tree, manage epochs

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use parking_lot::RwLock;
use tracing::{debug, info, warn};

use ghost_common::error::{GhostError, GhostResult};
use ghost_common::identity;
use ghost_common::types::NodeId;
use ghost_storage::Database;
use ghost_zkp::{NoteSpendPublicInputs, NoteVerifier};

use crate::epoch_manager::{EpochManager, PROPOSER_GRACE_SECS};
use crate::mesh::MessageHandler;
use crate::message::{
    L2CheckpointBlockMessage, L2CheckpointVoteMessage, L2ConfidentialTransferMessage,
    L2Transaction, L2TransferBroadcastMessage, L2TransferConfirmationMessage, L2TreeSyncRequest,
    L2TreeSyncResponse, MessageEnvelope, MessageType,
};
use crate::vote_handler::BroadcastFn;

// =============================================================================
// CONFIGURATION
// =============================================================================

/// BFT threshold for checkpoint approval (67%)
pub const BFT_THRESHOLD_PERCENT: u64 = 67;

/// Maximum transactions per checkpoint block
pub const MAX_TXS_PER_CHECKPOINT: usize = 10_000;

/// Max L2 messages per second per peer
const MAX_L2_MSG_PER_PEER_PER_SEC: u32 = 100;

/// Max L2 messages per second globally
const MAX_L2_MSG_GLOBAL_PER_SEC: u32 = 10_000;

/// Max checkpoints per tree sync response
const MAX_SYNC_CHECKPOINTS: usize = 100;

/// Min interval between sync requests from same peer (seconds)
const SYNC_REQUEST_COOLDOWN_SECS: u64 = 60;

/// Signing function type (matches NodeIdentity.sign() signature)
pub type SignFn = Arc<dyn Fn(&[u8]) -> [u8; 64] + Send + Sync>;

/// Configuration for the nullifier route handler
#[derive(Debug, Clone)]
pub struct NullifierRouteConfig {
    pub bft_threshold_percent: u64,
    pub max_txs_per_checkpoint: usize,
}

impl Default for NullifierRouteConfig {
    fn default() -> Self {
        Self {
            bft_threshold_percent: BFT_THRESHOLD_PERCENT,
            max_txs_per_checkpoint: MAX_TXS_PER_CHECKPOINT,
        }
    }
}

// =============================================================================
// VERIFIED VOTE NEWTYPE (S-6)
// =============================================================================

/// S-6: Newtype ensuring votes are only constructed after signature verification.
/// Can only be created via `VerifiedVote::new()` in `handle_message()` after
/// Ed25519 signature verification completes successfully.
pub(crate) struct VerifiedVote {
    voter: NodeId,
    approve: bool,
}

impl VerifiedVote {
    /// Create a verified vote. Only call after signature verification.
    pub(crate) fn new(voter: NodeId, approve: bool) -> Self {
        Self { voter, approve }
    }
}

// =============================================================================
// CHECKPOINT VOTE STATE
// =============================================================================

/// Tracks votes for a specific checkpoint height
#[derive(Debug)]
struct CheckpointVoteState {
    /// Hash of the proposed checkpoint
    checkpoint_hash: [u8; 32],
    /// Votes received (voter -> approve)
    votes: HashMap<NodeId, bool>,
    /// Whether this checkpoint has been finalized
    finalized: bool,
    /// The proposed checkpoint block (if we received it)
    proposal: Option<L2CheckpointBlockMessage>,
}

impl CheckpointVoteState {
    fn new(checkpoint_hash: [u8; 32]) -> Self {
        Self {
            checkpoint_hash,
            votes: HashMap::new(),
            finalized: false,
            proposal: None,
        }
    }

    /// Add a vote from a verified source. S-6: accepts VerifiedVote newtype
    /// to ensure only signature-verified votes can be added.
    fn add_vote(&mut self, vote: VerifiedVote) -> bool {
        self.votes.insert(vote.voter, vote.approve).is_none() // true if new vote
    }

    fn approval_count(&self) -> usize {
        self.votes.values().filter(|&&v| v).count()
    }

    fn has_quorum(&self, active_count: usize, threshold_percent: u64) -> bool {
        if active_count == 0 {
            return false;
        }
        let needed = (active_count as u64 * threshold_percent).div_ceil(100);
        self.approval_count() as u64 >= needed
    }
}

// =============================================================================
// NULLIFIER ROUTE HANDLER
// =============================================================================

/// Handles L2 transaction validation and checkpoint BFT consensus
pub struct NullifierRouteHandler {
    /// Our node ID
    our_id: NodeId,
    /// Epoch manager (tree, nullifiers, roots, proposer rotation)
    epoch_manager: Arc<EpochManager>,
    /// Note verifier (Groth16 proof verification)
    verifier: RwLock<Option<Arc<NoteVerifier>>>,
    /// Confirmed transactions waiting for next checkpoint
    confirmed_pool: RwLock<Vec<L2Transaction>>,
    /// S-4: O(1) nullifier dedup index for confirmed_pool (parallel HashSet)
    confirmed_nullifiers: RwLock<HashSet<[u8; 32]>>,
    /// Vote state per checkpoint height
    votes: RwLock<HashMap<u64, CheckpointVoteState>>,
    /// Database
    db: Arc<Database>,
    /// Configuration
    config: NullifierRouteConfig,
    /// Broadcast function (set after construction)
    broadcast_fn: RwLock<Option<BroadcastFn>>,
    /// Signing function for Ed25519 signatures (set after construction)
    sign_fn: RwLock<Option<SignFn>>,
    /// Time of last finalized checkpoint (for proposer timeout detection)
    last_checkpoint_time: RwLock<Instant>,
    /// Per-peer L2 message rate tracking: peer -> (window_start, count)
    peer_msg_rates: RwLock<HashMap<NodeId, (Instant, u32)>>,
    /// Global L2 message rate tracking: (window_start, count)
    global_msg_rate: RwLock<(Instant, u32)>,
    /// Last tree sync request per peer (for rate limiting)
    sync_requests: RwLock<HashMap<NodeId, Instant>>,
    /// C-2: Heights for which we (as proposer) already applied commitments during propose_checkpoint.
    /// Prevents double-applying commitments when finalize_checkpoint runs on the proposer node.
    proposed_heights: RwLock<HashSet<u64>>,
}

impl NullifierRouteHandler {
    /// Create a new handler
    pub fn new(
        our_id: NodeId,
        epoch_manager: Arc<EpochManager>,
        db: Arc<Database>,
        config: NullifierRouteConfig,
    ) -> Self {
        Self {
            our_id,
            epoch_manager,
            verifier: RwLock::new(None),
            confirmed_pool: RwLock::new(Vec::new()),
            confirmed_nullifiers: RwLock::new(HashSet::new()),
            votes: RwLock::new(HashMap::new()),
            db,
            config,
            broadcast_fn: RwLock::new(None),
            sign_fn: RwLock::new(None),
            last_checkpoint_time: RwLock::new(Instant::now()),
            peer_msg_rates: RwLock::new(HashMap::new()),
            global_msg_rate: RwLock::new((Instant::now(), 0)),
            sync_requests: RwLock::new(HashMap::new()),
            proposed_heights: RwLock::new(HashSet::new()),
        }
    }

    /// Create with default config
    pub fn with_defaults(
        our_id: NodeId,
        epoch_manager: Arc<EpochManager>,
        db: Arc<Database>,
    ) -> Self {
        Self::new(our_id, epoch_manager, db, NullifierRouteConfig::default())
    }

    /// Set the verifier (after MPC params are loaded)
    pub fn set_verifier(&self, verifier: Arc<NoteVerifier>) {
        *self.verifier.write() = Some(verifier);
    }

    /// Set the broadcast function
    pub fn set_broadcast_fn(&self, f: BroadcastFn) {
        *self.broadcast_fn.write() = Some(f);
    }

    /// Set the signing function (from NodeIdentity)
    pub fn set_sign_fn(&self, f: SignFn) {
        *self.sign_fn.write() = Some(f);
    }

    /// Sign a message using our signing function
    fn sign(&self, message: &[u8]) -> [u8; 64] {
        if let Some(ref f) = *self.sign_fn.read() {
            f(message)
        } else {
            [0u8; 64]
        }
    }

    /// Get our node ID
    pub fn our_id(&self) -> &NodeId {
        &self.our_id
    }

    /// Get the confirmed pool size
    pub fn confirmed_pool_size(&self) -> usize {
        self.confirmed_pool.read().len()
    }

    // =========================================================================
    // RATE LIMITING
    // =========================================================================

    /// Check per-peer and global rate limits for L2 messages.
    /// Returns Err if rate limit exceeded.
    fn check_rate_limit(&self, peer: &NodeId) -> GhostResult<()> {
        let now = Instant::now();

        // Per-peer rate limit
        {
            let mut rates = self.peer_msg_rates.write();
            let entry = rates.entry(*peer).or_insert((now, 0));
            if now.duration_since(entry.0).as_secs() >= 1 {
                // Reset window
                *entry = (now, 1);
            } else {
                entry.1 += 1;
                if entry.1 > MAX_L2_MSG_PER_PEER_PER_SEC {
                    return Err(GhostError::InvalidInput(format!(
                        "L2 rate limit exceeded: {} msgs/sec from peer {}",
                        entry.1,
                        hex::encode(&peer[..8])
                    )));
                }
            }
        }

        // Global rate limit
        {
            let mut global = self.global_msg_rate.write();
            if now.duration_since(global.0).as_secs() >= 1 {
                *global = (now, 1);
            } else {
                global.1 += 1;
                if global.1 > MAX_L2_MSG_GLOBAL_PER_SEC {
                    return Err(GhostError::InvalidInput(
                        "L2 global rate limit exceeded".into(),
                    ));
                }
            }
        }

        Ok(())
    }

    // =========================================================================
    // SIGNATURE VERIFICATION
    // =========================================================================

    /// Verify an Ed25519 signature from a peer
    fn verify_peer_signature(
        &self,
        peer_id: &NodeId,
        message: &[u8],
        signature: &[u8; 64],
    ) -> bool {
        match identity::verify_signature(peer_id, message, signature) {
            Ok(valid) => {
                if !valid {
                    warn!(
                        peer = %hex::encode(&peer_id[..8]),
                        "Invalid Ed25519 signature on L2 message"
                    );
                }
                valid
            }
            Err(e) => {
                warn!(
                    peer = %hex::encode(&peer_id[..8]),
                    error = %e,
                    "Signature verification error (invalid public key)"
                );
                false
            }
        }
    }

    // =========================================================================
    // TRANSACTION VALIDATION (per-tx, ~5ms target)
    // =========================================================================

    /// Handle an incoming confidential transfer submission
    ///
    /// Called when this node is the assigned validator for the transaction's nullifier.
    pub fn handle_transfer(
        &self,
        msg: &L2ConfidentialTransferMessage,
    ) -> GhostResult<Option<L2TransferConfirmationMessage>> {
        let tx = &msg.transaction;

        // 1. Check this node is the assigned validator
        if let Some(assigned) = self.epoch_manager.validator_for_nullifier(&tx.nullifier) {
            if assigned != self.our_id {
                debug!("Not assigned validator for this nullifier, ignoring");
                return Ok(None);
            }
        } else {
            return Err(GhostError::Internal("No active nodes for routing".into()));
        }

        // 2. Check commitment_root is valid
        if !self.epoch_manager.is_root_valid(&tx.commitment_root) {
            return Err(GhostError::InvalidInput(
                "Invalid commitment root — not in valid roots window".into(),
            ));
        }

        // 3. Check nullifier not already spent (fast-path read check)
        if self.epoch_manager.is_nullifier_spent(&tx.nullifier) {
            return Err(GhostError::InvalidInput(
                "Nullifier already spent — double-spend attempt".into(),
            ));
        }

        // 4. Verify Groth16 proof
        let verifier = self.verifier.read();
        if let Some(ref v) = *verifier {
            let public_inputs = NoteSpendPublicInputs {
                commitment_root: tx.commitment_root,
                nullifier: tx.nullifier,
                change_commitment: tx.change_commitment,
                recipient_commitment: tx.recipient_commitment,
            };
            let valid = v
                .verify_raw(&tx.proof, &public_inputs)
                .map_err(|e| GhostError::Internal(format!("Proof verification error: {}", e)))?;
            if !valid {
                return Err(GhostError::InvalidInput(
                    "Proof verification failed — invalid ZK proof".into(),
                ));
            }
        } else {
            return Err(GhostError::Internal(
                "No verifier available — MPC params not loaded".into(),
            ));
        }

        // 5. Record nullifier as spent (atomic check+insert)
        let height = self.epoch_manager.current_height();
        let spent = self.epoch_manager.spend_nullifier(tx.nullifier, height)?;
        if !spent {
            return Err(GhostError::InvalidInput(
                "Nullifier race: already spent by another thread".into(),
            ));
        }

        // 6. Add to confirmed pool
        {
            let mut pool = self.confirmed_pool.write();
            if pool.len() >= self.config.max_txs_per_checkpoint {
                warn!("Confirmed pool full, rejecting transaction");
                return Err(GhostError::Internal("Confirmed pool full".into()));
            }
            pool.push(tx.clone());
            self.confirmed_nullifiers.write().insert(tx.nullifier);
        }

        // 7. Create signed confirmation receipt
        let mut confirmation = L2TransferConfirmationMessage {
            nullifier: tx.nullifier,
            validator: self.our_id,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            signature: [0u8; 64],
        };
        let sign_msg = confirmation.signing_message();
        confirmation.signature = self.sign(&sign_msg);

        debug!(
            nullifier = %hex::encode(&tx.nullifier[..8]),
            pool_size = self.confirmed_pool_size(),
            "Transaction confirmed"
        );

        Ok(Some(confirmation))
    }

    /// Handle a broadcast of a confirmed transaction from another validator
    ///
    /// Other nodes add the transaction to their local view for checkpoint verification.
    pub fn handle_transfer_broadcast(&self, msg: &L2TransferBroadcastMessage) -> GhostResult<()> {
        let tx = &msg.transaction;

        // Validate root is known
        if !self.epoch_manager.is_root_valid(&tx.commitment_root) {
            warn!("Broadcast tx has unknown commitment root, ignoring");
            return Ok(());
        }

        // H-3: Verify ZK proof before accepting broadcast transactions.
        // Without this, a malicious validator could broadcast fabricated transactions
        // that bypass proof verification, corrupting the confirmed pool.
        let verifier = self.verifier.read();
        if let Some(ref v) = *verifier {
            let public_inputs = NoteSpendPublicInputs {
                commitment_root: tx.commitment_root,
                nullifier: tx.nullifier,
                change_commitment: tx.change_commitment,
                recipient_commitment: tx.recipient_commitment,
            };
            match v.verify_raw(&tx.proof, &public_inputs) {
                Ok(true) => {} // Valid proof, continue
                Ok(false) => {
                    warn!(
                        validator = %hex::encode(&msg.validator[..8]),
                        "H-3: Rejecting broadcast with invalid ZK proof"
                    );
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        validator = %hex::encode(&msg.validator[..8]),
                        error = %e,
                        "H-3: Proof verification error on broadcast, rejecting"
                    );
                    return Ok(());
                }
            }
        } else {
            // S-1: Fail-closed — reject broadcast if verifier is not loaded.
            // This matches handle_transfer() at line 360 which correctly rejects.
            warn!("Rejecting L2 broadcast — verifier not loaded");
            return Ok(());
        }

        // Record nullifier (if not already known)
        let height = self.epoch_manager.current_height();
        let _ = self.epoch_manager.spend_nullifier(tx.nullifier, height);

        // Add to confirmed pool (S-4: O(1) dedup via HashSet instead of linear scan)
        {
            let mut nullifiers = self.confirmed_nullifiers.write();
            if nullifiers.insert(tx.nullifier) {
                self.confirmed_pool.write().push(tx.clone());
            }
        }

        Ok(())
    }

    // =========================================================================
    // CHECKPOINT PROPOSAL (every 10s, with fallback timeout)
    // =========================================================================

    /// Create a checkpoint block if we are the designated proposer or fallback.
    ///
    /// Called periodically (every 10s). Returns the proposal if we should propose.
    /// Implements proposer timeout: if the primary proposer hasn't produced within
    /// PROPOSER_GRACE_SECS, the fallback proposer takes over.
    pub fn propose_checkpoint(&self) -> GhostResult<Option<L2CheckpointBlockMessage>> {
        let height = self.epoch_manager.current_height() + 1;

        // Check if we're the designated proposer
        let is_primary = self.epoch_manager.is_proposer(&self.our_id, height);

        // Check fallback: if primary is late, fallback proposer takes over
        let is_fallback = if !is_primary {
            let elapsed = self.last_checkpoint_time.read().elapsed();
            if elapsed.as_secs() > PROPOSER_GRACE_SECS {
                self.epoch_manager
                    .get_fallback_proposer(height)
                    .map(|fb| fb == self.our_id)
                    .unwrap_or(false)
            } else {
                false
            }
        } else {
            false
        };

        if !is_primary && !is_fallback {
            return Ok(None);
        }

        if is_fallback {
            info!(
                height,
                grace_secs = PROPOSER_GRACE_SECS,
                "Primary proposer timed out, acting as fallback"
            );
        }

        // Drain confirmed pool (S-4: clear nullifiers HashSet in sync)
        let transactions: Vec<L2Transaction> = {
            let mut pool = self.confirmed_pool.write();
            let txs: Vec<L2Transaction> = pool
                .drain(..)
                .take(self.config.max_txs_per_checkpoint)
                .collect();
            self.confirmed_nullifiers.write().clear();
            txs
        };

        // Get current root before appending
        let prev_root = self.epoch_manager.current_root()?;

        // Append new commitments to tree
        for tx in &transactions {
            self.epoch_manager
                .append_commitment(tx.change_commitment, height)?;
            self.epoch_manager
                .append_commitment(tx.recipient_commitment, height)?;
        }

        // C-2: Mark this height as already having commitments applied by the proposer.
        // finalize_checkpoint() will skip re-applying for this height.
        self.proposed_heights.write().insert(height);

        // Compute new root
        let new_root = self.epoch_manager.current_root()?;

        let mut proposal = L2CheckpointBlockMessage {
            height,
            epoch: self.epoch_manager.current_epoch(),
            prev_commitment_root: prev_root,
            new_commitment_root: new_root,
            transactions,
            active_node_count: self.epoch_manager.active_node_count() as u32,
            proposer: self.our_id,
            proposer_signature: [0u8; 64],
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            epoch_transition: None,
        };

        // Sign the proposal
        let signable = proposal.to_signable_bytes();
        proposal.proposer_signature = self.sign(&signable);

        info!(
            height,
            tx_count = proposal.transactions.len(),
            fallback = is_fallback,
            "Proposed checkpoint block"
        );

        Ok(Some(proposal))
    }

    // =========================================================================
    // CHECKPOINT VOTING (all-node BFT)
    // =========================================================================

    /// Handle a checkpoint block proposal
    ///
    /// Validates the proposal and casts a vote.
    /// Handle a checkpoint proposal after signature verification.
    ///
    /// # Prerequisite: Signature Already Verified
    ///
    /// The caller (handle_message) MUST verify the proposer's Ed25519 signature
    /// before calling this method. This ensures we do not waste CPU on root
    /// verification or voting for unsigned/invalid messages. The ordering is:
    ///
    /// 1. Verify proposer signature (in handle_message)
    /// 2. Validate proposer identity and root (this method)
    /// 3. Cast vote
    pub fn handle_checkpoint_proposal(
        &self,
        msg: &L2CheckpointBlockMessage,
    ) -> GhostResult<Option<L2CheckpointVoteMessage>> {
        let height = msg.height;
        let checkpoint_hash = msg.checkpoint_hash();

        // Validate proposer is correct for this height (primary or fallback)
        if let Some(expected) = self.epoch_manager.get_proposer(height) {
            if expected != msg.proposer {
                // Check fallback proposer
                let is_valid_fallback = self
                    .epoch_manager
                    .get_fallback_proposer(height)
                    .map(|fb| fb == msg.proposer)
                    .unwrap_or(false);

                if !is_valid_fallback {
                    warn!(
                        height,
                        expected = %hex::encode(&expected[..8]),
                        got = %hex::encode(&msg.proposer[..8]),
                        "Wrong proposer for checkpoint"
                    );
                    return Ok(None);
                }
            }
        }

        // Validate prev_commitment_root matches our current root
        let our_root = self.epoch_manager.current_root()?;
        if msg.prev_commitment_root != our_root {
            warn!(height, "Checkpoint prev_root doesn't match our tree root");
            // Still vote but reject
            let mut vote = L2CheckpointVoteMessage {
                height,
                checkpoint_hash,
                voter: self.our_id,
                approve: false,
                signature: [0u8; 64],
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
            };
            let sign_msg = vote.signing_message();
            vote.signature = self.sign(&sign_msg);
            return Ok(Some(vote));
        }

        // Store the proposal
        {
            let mut votes = self.votes.write();
            let state = votes
                .entry(height)
                .or_insert_with(|| CheckpointVoteState::new(checkpoint_hash));
            state.proposal = Some(msg.clone());
        }

        // Cast our signed vote (approve)
        let mut vote = L2CheckpointVoteMessage {
            height,
            checkpoint_hash,
            voter: self.our_id,
            approve: true,
            signature: [0u8; 64],
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };
        let sign_msg = vote.signing_message();
        vote.signature = self.sign(&sign_msg);

        debug!(height, "Cast checkpoint vote (approve)");
        Ok(Some(vote))
    }

    /// Handle a checkpoint vote
    ///
    /// Returns true if the checkpoint reached quorum and was finalized.
    pub fn handle_checkpoint_vote(&self, msg: &L2CheckpointVoteMessage) -> GhostResult<bool> {
        let height = msg.height;
        let active_count = self.epoch_manager.active_node_count();

        let (finalized, proposal) = {
            let mut votes = self.votes.write();
            let state = votes
                .entry(height)
                .or_insert_with(|| CheckpointVoteState::new(msg.checkpoint_hash));

            if state.finalized {
                return Ok(false); // Already finalized
            }

            // Verify vote is for the same checkpoint
            if state.checkpoint_hash != msg.checkpoint_hash {
                warn!(height, "Vote for different checkpoint hash, ignoring");
                return Ok(false);
            }

            state.add_vote(VerifiedVote::new(msg.voter, msg.approve));

            if state.has_quorum(active_count, self.config.bft_threshold_percent) {
                state.finalized = true;
                (true, state.proposal.clone())
            } else {
                (false, None)
            }
        };

        if finalized {
            info!(
                height,
                votes = active_count,
                "Checkpoint reached BFT quorum"
            );
            self.finalize_checkpoint(height, proposal.as_ref())?;
        }

        Ok(finalized)
    }

    /// Finalize a checkpoint after BFT approval
    fn finalize_checkpoint(
        &self,
        height: u64,
        proposal: Option<&L2CheckpointBlockMessage>,
    ) -> GhostResult<()> {
        // C-2: Only apply commitments if this node didn't already apply them as proposer.
        // The proposer applies commitments during propose_checkpoint(); non-proposer nodes
        // apply them here during finalization. Without this guard, the proposer would
        // double-insert every commitment into the tree.
        let already_applied = self.proposed_heights.read().contains(&height);
        if !already_applied {
            if let Some(block) = proposal {
                for tx in &block.transactions {
                    self.epoch_manager
                        .append_commitment(tx.change_commitment, height)?;
                    self.epoch_manager
                        .append_commitment(tx.recipient_commitment, height)?;
                }
            }
        }
        self.proposed_heights.write().remove(&height);

        // Compute and register new valid root
        let new_root = self.epoch_manager.current_root()?;
        self.epoch_manager.add_valid_root(new_root, height)?;

        // Persist checkpoint + nullifiers atomically in a single SQLite transaction.
        // If the process crashes mid-write, the entire checkpoint is rolled back.
        let tx_count = proposal.map(|p| p.transactions.len()).unwrap_or(0);
        let pending_nullifiers = self.epoch_manager.drain_pending_nullifiers();
        let record = ghost_storage::L2CheckpointRecord {
            height,
            epoch: self.epoch_manager.current_epoch(),
            commitment_root: new_root,
            tx_count: tx_count as u32,
            proposer_id: proposal
                .map(|p| hex::encode(p.proposer))
                .unwrap_or_default(),
            active_node_count: self.epoch_manager.active_node_count() as u32,
            block_data: proposal
                .and_then(|p| serde_json::to_vec(p).ok())
                .unwrap_or_default(),
        };
        self.db
            .persist_l2_checkpoint_atomic(&record, &pending_nullifiers)?;

        // Update last checkpoint time (for proposer timeout detection)
        *self.last_checkpoint_time.write() = Instant::now();

        // Check for epoch transition
        let compaction = self.epoch_manager.on_checkpoint_finalized(height)?;
        if let Some(result) = compaction {
            info!(
                new_epoch = result.new_epoch,
                notes_migrated = result.notes_migrated,
                "Epoch transition during checkpoint finalization"
            );
        }

        // Clean up old vote states
        self.prune_vote_states(height);

        debug!(height, tx_count, "Checkpoint finalized");
        Ok(())
    }

    /// Prune vote states older than the current height
    fn prune_vote_states(&self, current_height: u64) {
        let cutoff = current_height.saturating_sub(100);
        let mut votes = self.votes.write();
        votes.retain(|h, _| *h > cutoff);
        // S-5: Prune proposed_heights to prevent unbounded growth
        self.proposed_heights.write().retain(|h| *h > cutoff);
    }

    // =========================================================================
    // TREE SYNC (for new nodes joining the network)
    // =========================================================================

    /// Handle a tree sync request from a new node
    fn handle_tree_sync_request(
        &self,
        request: &L2TreeSyncRequest,
    ) -> GhostResult<Option<L2TreeSyncResponse>> {
        // Rate limit: max 1 request per peer per 60 seconds
        {
            let mut sync_reqs = self.sync_requests.write();
            if let Some(last) = sync_reqs.get(&request.requesting_node) {
                if last.elapsed().as_secs() < SYNC_REQUEST_COOLDOWN_SECS {
                    debug!(
                        peer = %hex::encode(&request.requesting_node[..8]),
                        "Tree sync request rate limited"
                    );
                    return Ok(None);
                }
            }
            sync_reqs.insert(request.requesting_node, Instant::now());
        }

        // Load checkpoints from requested height
        let checkpoints = self
            .db
            .get_l2_checkpoints_from_height(request.from_height, MAX_SYNC_CHECKPOINTS as u64)?;

        // Deserialize checkpoint blocks from stored data
        let mut checkpoint_blocks = Vec::new();
        let mut has_more = false;
        for record in &checkpoints {
            if checkpoint_blocks.len() >= MAX_SYNC_CHECKPOINTS {
                has_more = true;
                break;
            }
            if !record.block_data.is_empty() {
                if let Ok(block) =
                    serde_json::from_slice::<L2CheckpointBlockMessage>(&record.block_data)
                {
                    checkpoint_blocks.push(block);
                }
            }
        }

        let current_root = self.epoch_manager.current_root()?;

        let response = L2TreeSyncResponse {
            responding_node: self.our_id,
            checkpoints: checkpoint_blocks,
            current_epoch: self.epoch_manager.current_epoch(),
            commitment_root: current_root,
            has_more,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        info!(
            peer = %hex::encode(&request.requesting_node[..8]),
            from_height = request.from_height,
            checkpoints_sent = response.checkpoints.len(),
            "Responded to tree sync request"
        );

        Ok(Some(response))
    }

    /// Handle a tree sync response (replay checkpoints to catch up)
    fn handle_tree_sync_response(&self, response: &L2TreeSyncResponse) -> GhostResult<()> {
        if response.checkpoints.is_empty() {
            debug!("Empty tree sync response, nothing to replay");
            return Ok(());
        }

        info!(
            from = %hex::encode(&response.responding_node[..8]),
            checkpoints = response.checkpoints.len(),
            epoch = response.current_epoch,
            "Replaying tree sync response"
        );

        // Replay checkpoint blocks in order
        for block in &response.checkpoints {
            let height = block.height;

            // Append commitments from each transaction
            for tx in &block.transactions {
                self.epoch_manager
                    .append_commitment(tx.change_commitment, height)?;
                self.epoch_manager
                    .append_commitment(tx.recipient_commitment, height)?;
            }

            // Record nullifiers
            for tx in &block.transactions {
                let _ = self.epoch_manager.spend_nullifier(tx.nullifier, height);
            }

            // Add valid root
            let root = self.epoch_manager.current_root()?;
            self.epoch_manager.add_valid_root(root, height)?;

            // Process epoch transitions
            self.epoch_manager.on_checkpoint_finalized(height)?;
        }

        // Verify our root matches the peer's reported root
        let our_root = self.epoch_manager.current_root()?;
        if our_root != response.commitment_root {
            warn!(
                our_root = %hex::encode(&our_root[..8]),
                peer_root = %hex::encode(&response.commitment_root[..8]),
                "Root mismatch after tree sync — requesting more data"
            );
        } else {
            info!("Tree sync complete — root matches peer");
        }

        // Update last checkpoint time
        *self.last_checkpoint_time.write() = Instant::now();

        Ok(())
    }

    /// Request tree sync from peers (called on startup if current_height == 0)
    pub fn request_tree_sync(&self) -> GhostResult<()> {
        let current_height = self.epoch_manager.current_height();
        if current_height > 0 {
            return Ok(()); // Already synced
        }

        let request = L2TreeSyncRequest {
            requesting_node: self.our_id,
            from_height: 0,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        if let Some(ref broadcast) = *self.broadcast_fn.read() {
            let payload = serde_json::to_vec(&request)
                .map_err(|e| GhostError::Serialization(e.to_string()))?;
            broadcast(MessageType::L2TreeSync, payload)?;
            info!("Requested L2 tree sync from peers");
        }

        Ok(())
    }

    /// Get current epoch manager (for external use)
    pub fn epoch_manager(&self) -> &Arc<EpochManager> {
        &self.epoch_manager
    }

    /// Check if verifier is ready
    pub fn has_verifier(&self) -> bool {
        self.verifier.read().is_some()
    }
}

// =============================================================================
// MESSAGE HANDLER (mesh integration)
// =============================================================================

#[async_trait]
impl MessageHandler for NullifierRouteHandler {
    async fn handle_message(&self, envelope: Arc<MessageEnvelope>) -> GhostResult<()> {
        // Rate limit all L2 messages
        if matches!(
            envelope.msg_type,
            MessageType::L2ConfidentialTransfer
                | MessageType::L2TransferBroadcast
                | MessageType::L2CheckpointBlock
                | MessageType::L2CheckpointVote
        ) {
            if let Err(e) = self.check_rate_limit(&envelope.sender) {
                warn!(error = %e, "L2 message rate limited");
                return Err(e);
            }
        }

        match envelope.msg_type {
            MessageType::L2ConfidentialTransfer => {
                let msg: L2ConfidentialTransferMessage = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| GhostError::Serialization(e.to_string()))?;

                match self.handle_transfer(&msg)? {
                    Some(confirmation) => {
                        // Send confirmation back via broadcast
                        if let Some(ref broadcast) = *self.broadcast_fn.read() {
                            let payload = serde_json::to_vec(&confirmation)
                                .map_err(|e| GhostError::Serialization(e.to_string()))?;
                            broadcast(MessageType::L2TransferConfirmation, payload)?;
                        }

                        // Broadcast the confirmed tx to all nodes (signed)
                        let mut broadcast_msg = L2TransferBroadcastMessage {
                            transaction: msg.transaction,
                            validator: self.our_id,
                            signature: [0u8; 64],
                        };
                        let sign_msg = broadcast_msg.signing_message();
                        broadcast_msg.signature = self.sign(&sign_msg);

                        if let Some(ref broadcast) = *self.broadcast_fn.read() {
                            let payload = serde_json::to_vec(&broadcast_msg)
                                .map_err(|e| GhostError::Serialization(e.to_string()))?;
                            broadcast(MessageType::L2TransferBroadcast, payload)?;
                        }
                    }
                    None => {
                        // Not our responsibility or validation failed silently
                    }
                }
            }

            MessageType::L2TransferConfirmation => {
                // Confirmations are sent to the original sender — just log
                debug!("Received L2 transfer confirmation");
            }

            MessageType::L2TransferBroadcast => {
                let msg: L2TransferBroadcastMessage = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| GhostError::Serialization(e.to_string()))?;

                // M-5: Verify broadcast signature — reject if signing not available
                if self.sign_fn.read().is_none() {
                    warn!("M-5: Rejecting L2 broadcast — sign_fn not initialized (cannot verify signatures)");
                    return Ok(());
                }
                let sign_msg = msg.signing_message();
                if !self.verify_peer_signature(&msg.validator, &sign_msg, &msg.signature) {
                    warn!(
                        validator = %hex::encode(&msg.validator[..8]),
                        "Rejecting broadcast with invalid signature"
                    );
                    return Ok(());
                }

                self.handle_transfer_broadcast(&msg)?;
            }

            MessageType::L2CheckpointBlock => {
                let msg: L2CheckpointBlockMessage = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| GhostError::Serialization(e.to_string()))?;

                // M-5: Verify proposer signature — reject if signing not available
                if self.sign_fn.read().is_none() {
                    warn!("M-5: Rejecting L2 checkpoint — sign_fn not initialized (cannot verify signatures)");
                    return Ok(());
                }
                let signable = msg.to_signable_bytes();
                if !self.verify_peer_signature(
                    &msg.proposer,
                    &signable,
                    &msg.proposer_signature,
                ) {
                    warn!(
                        proposer = %hex::encode(&msg.proposer[..8]),
                        height = msg.height,
                        "Rejecting checkpoint with invalid proposer signature"
                    );
                    return Ok(());
                }

                // Update last checkpoint time on receiving any valid proposal
                *self.last_checkpoint_time.write() = Instant::now();

                if let Some(vote) = self.handle_checkpoint_proposal(&msg)? {
                    // Broadcast our vote
                    if let Some(ref broadcast) = *self.broadcast_fn.read() {
                        let payload = serde_json::to_vec(&vote)
                            .map_err(|e| GhostError::Serialization(e.to_string()))?;
                        broadcast(MessageType::L2CheckpointVote, payload)?;
                    }
                }
            }

            MessageType::L2CheckpointVote => {
                let msg: L2CheckpointVoteMessage = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| GhostError::Serialization(e.to_string()))?;

                // M-5: Verify voter signature — reject if signing not available
                if self.sign_fn.read().is_none() {
                    warn!("M-5: Rejecting L2 vote — sign_fn not initialized (cannot verify signatures)");
                    return Ok(());
                }
                let sign_msg = msg.signing_message();
                if !self.verify_peer_signature(&msg.voter, &sign_msg, &msg.signature) {
                    warn!(
                        voter = %hex::encode(&msg.voter[..8]),
                        height = msg.height,
                        "Rejecting vote with invalid signature"
                    );
                    return Ok(());
                }

                self.handle_checkpoint_vote(&msg)?;
            }

            MessageType::L2TreeSync => {
                // Try to parse as request first, then as response
                if let Ok(request) = serde_json::from_slice::<L2TreeSyncRequest>(&envelope.payload)
                {
                    if let Some(response) = self.handle_tree_sync_request(&request)? {
                        if let Some(ref broadcast) = *self.broadcast_fn.read() {
                            let payload = serde_json::to_vec(&response)
                                .map_err(|e| GhostError::Serialization(e.to_string()))?;
                            broadcast(MessageType::L2TreeSync, payload)?;
                        }
                    }
                } else if let Ok(response) =
                    serde_json::from_slice::<L2TreeSyncResponse>(&envelope.payload)
                {
                    self.handle_tree_sync_response(&response)?;
                } else {
                    debug!("Unrecognized L2TreeSync message format");
                }
            }

            _ => {
                // Not an L2 message — ignore
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch_manager::EpochManagerConfig;

    fn setup() -> (Arc<Database>, Arc<EpochManager>, NullifierRouteHandler) {
        let db = Arc::new(Database::in_memory().expect("Failed to create in-memory DB"));
        let config = EpochManagerConfig {
            epoch_length: 100,
            transition_window: 10,
            tree_depth: 4,
            max_valid_roots: 16,
        };
        let epoch_mgr = Arc::new(EpochManager::new(db.clone(), config));
        epoch_mgr.initialize_genesis().unwrap();

        let our_id = [0x01; 32];
        let handler = NullifierRouteHandler::with_defaults(our_id, epoch_mgr.clone(), db.clone());

        (db, epoch_mgr, handler)
    }

    #[test]
    fn test_handler_creation() {
        let (_db, _epoch_mgr, handler) = setup();
        assert_eq!(*handler.our_id(), [0x01; 32]);
        assert_eq!(handler.confirmed_pool_size(), 0);
    }

    #[test]
    fn test_transfer_rejected_without_verifier() {
        let (_db, epoch_mgr, handler) = setup();

        // Set ourselves as the only active node (so we're the validator)
        epoch_mgr.update_active_nodes(vec![[0x01; 32]]);

        // Add a valid root
        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 0).unwrap();

        let msg = L2ConfidentialTransferMessage {
            transaction: L2Transaction {
                epoch: 0,
                nullifier: [0x42; 32],
                change_commitment: [0u8; 32],
                recipient_commitment: [0u8; 32],
                commitment_root: root,
                proof: vec![0u8; 192],
                encrypted_change: vec![],
                encrypted_recipient: vec![],
                timestamp: 0,
            },
            sender: [0x99; 32],
        };

        // Should fail because no verifier is set
        let result = handler.handle_transfer(&msg);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No verifier available"));
    }

    #[test]
    fn test_transfer_rejected_invalid_root() {
        let (_db, epoch_mgr, handler) = setup();

        epoch_mgr.update_active_nodes(vec![[0x01; 32]]);

        let msg = L2ConfidentialTransferMessage {
            transaction: L2Transaction {
                epoch: 0,
                nullifier: [0x42; 32],
                change_commitment: [0u8; 32],
                recipient_commitment: [0u8; 32],
                commitment_root: [0xFF; 32], // Invalid root
                proof: vec![0u8; 192],
                encrypted_change: vec![],
                encrypted_recipient: vec![],
                timestamp: 0,
            },
            sender: [0x99; 32],
        };

        let result = handler.handle_transfer(&msg);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid commitment root"));
    }

    #[test]
    fn test_transfer_rejected_wrong_validator() {
        let (_db, epoch_mgr, handler) = setup();

        // Add another node as the only active node (we're NOT the validator)
        epoch_mgr.update_active_nodes(vec![[0x99; 32]]);

        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 0).unwrap();

        let msg = L2ConfidentialTransferMessage {
            transaction: L2Transaction {
                epoch: 0,
                nullifier: [0x42; 32],
                change_commitment: [0u8; 32],
                recipient_commitment: [0u8; 32],
                commitment_root: root,
                proof: vec![0u8; 192],
                encrypted_change: vec![],
                encrypted_recipient: vec![],
                timestamp: 0,
            },
            sender: [0x99; 32],
        };

        let result = handler.handle_transfer(&msg);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // Not our responsibility
    }

    #[test]
    fn test_checkpoint_proposal_not_proposer() {
        let (_db, epoch_mgr, handler) = setup();

        // Another node is the proposer
        epoch_mgr.update_active_nodes(vec![[0x99; 32]]);

        let result = handler.propose_checkpoint().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_checkpoint_proposal_as_proposer() {
        let (_db, epoch_mgr, handler) = setup();

        // We're the only active node (and thus the proposer)
        epoch_mgr.update_active_nodes(vec![[0x01; 32]]);

        let result = handler.propose_checkpoint().unwrap();
        assert!(result.is_some());

        let block = result.unwrap();
        assert_eq!(block.height, 1); // current_height(0) + 1
        assert_eq!(block.proposer, [0x01; 32]);
        assert_eq!(block.transactions.len(), 0); // No confirmed txs
    }

    #[test]
    fn test_checkpoint_vote_quorum() {
        let (_db, epoch_mgr, handler) = setup();

        // 4 active nodes — 67% of 4 = ceil(2.68) = 3 votes needed
        let node_a = [0x01; 32];
        let node_b = [0x02; 32];
        let node_c = [0x03; 32];
        let node_d = [0x04; 32];
        epoch_mgr.update_active_nodes(vec![node_a, node_b, node_c, node_d]);

        let hash = [0xAA; 32];

        // First vote (25% — not enough)
        let vote1 = L2CheckpointVoteMessage {
            height: 1,
            checkpoint_hash: hash,
            voter: node_a,
            approve: true,
            signature: [0u8; 64],
            timestamp: 0,
        };
        let finalized = handler.handle_checkpoint_vote(&vote1).unwrap();
        assert!(!finalized);

        // Second vote (50% — still not enough for 67%)
        let vote2 = L2CheckpointVoteMessage {
            height: 1,
            checkpoint_hash: hash,
            voter: node_b,
            approve: true,
            signature: [0u8; 64],
            timestamp: 0,
        };
        let finalized = handler.handle_checkpoint_vote(&vote2).unwrap();
        assert!(!finalized);

        // Third vote (75% — meets 67% threshold)
        let vote3 = L2CheckpointVoteMessage {
            height: 1,
            checkpoint_hash: hash,
            voter: node_c,
            approve: true,
            signature: [0u8; 64],
            timestamp: 0,
        };
        let finalized = handler.handle_checkpoint_vote(&vote3).unwrap();
        assert!(finalized);
    }

    #[test]
    fn test_checkpoint_vote_dedup() {
        let (_db, epoch_mgr, handler) = setup();

        epoch_mgr.update_active_nodes(vec![[0x01; 32], [0x02; 32]]);

        let hash = [0xAA; 32];
        let vote = L2CheckpointVoteMessage {
            height: 1,
            checkpoint_hash: hash,
            voter: [0x01; 32],
            approve: true,
            signature: [0u8; 64],
            timestamp: 0,
        };

        // First vote
        handler.handle_checkpoint_vote(&vote).unwrap();

        // Duplicate vote — should be ignored (not double-counted)
        handler.handle_checkpoint_vote(&vote).unwrap();

        // Check internal state
        let votes = handler.votes.read();
        let state = votes.get(&1).unwrap();
        assert_eq!(state.approval_count(), 1); // Only counted once
    }

    #[test]
    fn test_transfer_broadcast_dedup() {
        let (_db, epoch_mgr, handler) = setup();

        // S-1: Verifier must be set or broadcasts are rejected
        handler.set_verifier(test_verifier());

        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 0).unwrap();

        let broadcast = L2TransferBroadcastMessage {
            transaction: L2Transaction {
                epoch: 0,
                nullifier: [0x42; 32],
                change_commitment: [0u8; 32],
                recipient_commitment: [0u8; 32],
                commitment_root: root,
                proof: vec![0u8; 192],
                encrypted_change: vec![],
                encrypted_recipient: vec![],
                timestamp: 0,
            },
            validator: [0x99; 32],
            signature: [0u8; 64],
        };

        handler.handle_transfer_broadcast(&broadcast).unwrap();
        handler.handle_transfer_broadcast(&broadcast).unwrap(); // Duplicate

        assert_eq!(handler.confirmed_pool_size(), 1); // Only one copy
    }

    #[test]
    fn test_bft_threshold_calculation() {
        // div_ceil(3 * 67, 100) = div_ceil(201, 100) = 3 → all 3 must vote
        let mut state = CheckpointVoteState::new([0; 32]);
        state.add_vote(VerifiedVote::new([1; 32], true));
        state.add_vote(VerifiedVote::new([2; 32], true));
        assert!(!state.has_quorum(3, 67)); // 2/3 = 66.6% < 67%

        state.add_vote(VerifiedVote::new([3; 32], true));
        assert!(state.has_quorum(3, 67)); // 3/3 = 100% >= 67%

        // div_ceil(4 * 67, 100) = div_ceil(268, 100) = 3 → need 3 of 4
        let mut state2 = CheckpointVoteState::new([0; 32]);
        state2.add_vote(VerifiedVote::new([1; 32], true));
        state2.add_vote(VerifiedVote::new([2; 32], true));
        assert!(!state2.has_quorum(4, 67)); // 2/4 = 50% < 67%

        state2.add_vote(VerifiedVote::new([3; 32], true));
        assert!(state2.has_quorum(4, 67)); // 3/4 = 75% >= 67%

        // div_ceil(10 * 67, 100) = div_ceil(670, 100) = 7 → need 7 of 10
        let mut state3 = CheckpointVoteState::new([0; 32]);
        for i in 0..6 {
            state3.add_vote(VerifiedVote::new([i as u8; 32], true));
        }
        assert!(!state3.has_quorum(10, 67)); // 6/10 = 60% < 67%

        state3.add_vote(VerifiedVote::new([6; 32], true));
        assert!(state3.has_quorum(10, 67)); // 7/10 = 70% >= 67%

        // Edge: 0 active nodes
        assert!(!state3.has_quorum(0, 67));
    }

    #[test]
    fn test_rate_limiting() {
        let (_db, _epoch_mgr, handler) = setup();

        let peer = [0x42; 32];

        // Should allow up to MAX_L2_MSG_PER_PEER_PER_SEC messages
        for _ in 0..MAX_L2_MSG_PER_PEER_PER_SEC {
            assert!(handler.check_rate_limit(&peer).is_ok());
        }

        // Next message should be rate limited
        assert!(handler.check_rate_limit(&peer).is_err());

        // Different peer should still work
        let other_peer = [0x43; 32];
        assert!(handler.check_rate_limit(&other_peer).is_ok());
    }

    #[test]
    fn test_proposer_fallback() {
        let (_db, epoch_mgr, handler) = setup();

        let node_a = [0x01; 32]; // us
        let node_b = [0x02; 32];
        epoch_mgr.update_active_nodes(vec![node_a, node_b]);

        // With 2 sorted nodes [node_a, node_b]:
        //   height % 2 == 0 → node_a is proposer
        //   height % 2 == 1 → node_b is proposer
        // Fallback = (height + 1) % 2
        //   height 3: primary = node_b (3%2=1), fallback = node_a ((3+1)%2=0)

        // Advance current_height to 2 so next proposal targets height 3
        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 1).unwrap();
        epoch_mgr.on_checkpoint_finalized(1).unwrap();
        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 2).unwrap();
        epoch_mgr.on_checkpoint_finalized(2).unwrap();

        // Now current_height = 2, next = 3
        // Height 3: primary = node_b, fallback = node_a (us)
        assert!(!epoch_mgr.is_proposer(&node_a, 3));
        assert_eq!(epoch_mgr.get_fallback_proposer(3), Some(node_a));

        // With recent checkpoint, we should NOT propose
        *handler.last_checkpoint_time.write() = Instant::now();
        let result = handler.propose_checkpoint().unwrap();
        assert!(result.is_none());

        // With old checkpoint (proposer timeout), we SHOULD propose as fallback
        *handler.last_checkpoint_time.write() =
            Instant::now() - std::time::Duration::from_secs(PROPOSER_GRACE_SECS + 5);
        let result = handler.propose_checkpoint().unwrap();
        assert!(result.is_some());
    }

    /// Helper to create a verifier for tests (accepts all proofs unconditionally)
    fn test_verifier() -> Arc<ghost_zkp::NoteVerifier> {
        Arc::new(ghost_zkp::NoteVerifier::test_accept_all())
    }

    /// Test full checkpoint cycle: add txs → propose → vote → finalize
    #[test]
    fn test_checkpoint_full_cycle() {
        let (db, epoch_mgr, handler) = setup();

        // We're the only active node (proposer + validator)
        epoch_mgr.update_active_nodes(vec![[0x01; 32]]);

        // Set a sign function
        handler.set_sign_fn(Arc::new(|msg: &[u8]| {
            let mut sig = [0u8; 64];
            let len = msg.len().min(64);
            sig[..len].copy_from_slice(&msg[..len]);
            sig
        }));

        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 0).unwrap();

        // Inject 3 transactions directly into confirmed pool
        // (bypasses Groth16 verification which requires real MPC params)
        {
            let mut pool = handler.confirmed_pool.write();
            for i in 1u8..=3 {
                let mut change = [0u8; 32];
                change[0] = i * 10;
                let mut recipient = [0u8; 32];
                recipient[0] = i * 20;

                pool.push(L2Transaction {
                    epoch: 0,
                    nullifier: [i; 32],
                    change_commitment: change,
                    recipient_commitment: recipient,
                    commitment_root: root,
                    proof: vec![0u8; 192],
                    encrypted_change: vec![],
                    encrypted_recipient: vec![],
                    timestamp: 0,
                });
            }
        }

        assert_eq!(handler.confirmed_pool_size(), 3);

        // Propose checkpoint
        let proposal = handler.propose_checkpoint().unwrap().unwrap();
        assert_eq!(proposal.height, 1);
        assert_eq!(proposal.transactions.len(), 3);
        assert_eq!(proposal.proposer, [0x01; 32]);

        // Vote on the checkpoint (we're the only node, so 1 vote = quorum)
        let hash = proposal.checkpoint_hash();
        {
            let mut votes = handler.votes.write();
            let state = votes
                .entry(proposal.height)
                .or_insert_with(|| CheckpointVoteState::new(hash));
            state.proposal = Some(proposal.clone());
        }

        let vote = L2CheckpointVoteMessage {
            height: 1,
            checkpoint_hash: hash,
            voter: [0x01; 32],
            approve: true,
            signature: [0u8; 64],
            timestamp: 0,
        };
        let finalized = handler.handle_checkpoint_vote(&vote).unwrap();
        assert!(finalized, "Single node vote should finalize checkpoint");

        // Verify: tree root updated, confirmed pool empty
        let new_root = epoch_mgr.current_root().unwrap();
        assert_ne!(new_root, root, "Root should change after checkpoint");
        assert_eq!(
            handler.confirmed_pool_size(),
            0,
            "Confirmed pool should be drained after finalization"
        );
        assert_eq!(epoch_mgr.note_count(), 6); // 3 txs * 2 commitments each

        // Verify DB persisted the checkpoint
        let checkpoints = db
            .get_l2_checkpoints_from_height(0, 10)
            .unwrap();
        assert!(
            !checkpoints.is_empty(),
            "Checkpoint should be persisted to DB"
        );
    }

    /// Test tree sync request rate limiting
    #[test]
    fn test_tree_sync_request_rate_limiting() {
        let (_db, _epoch_mgr, handler) = setup();

        let peer = [0x42; 32];
        let request = L2TreeSyncRequest {
            requesting_node: peer,
            from_height: 0,
            timestamp: 0,
        };

        // First request should succeed
        let result1 = handler.handle_tree_sync_request(&request).unwrap();
        assert!(result1.is_some(), "First sync request should succeed");

        // Second request within 60s should be rate limited (returns None)
        let result2 = handler.handle_tree_sync_request(&request).unwrap();
        assert!(
            result2.is_none(),
            "Second request within cooldown should be rate limited"
        );

        // Different peer should still work
        let other_request = L2TreeSyncRequest {
            requesting_node: [0x43; 32],
            from_height: 0,
            timestamp: 0,
        };
        let result3 = handler.handle_tree_sync_request(&other_request).unwrap();
        assert!(
            result3.is_some(),
            "Different peer should not be rate limited"
        );
    }

    /// Test that tree sync replays checkpoints so a new peer's root matches the source
    #[test]
    fn test_tree_sync_replays_checkpoints() {
        // === Peer A: build a checkpoint ===
        let (_db_a, epoch_mgr_a, handler_a) = setup();
        epoch_mgr_a.update_active_nodes(vec![[0x01; 32]]);

        handler_a.set_sign_fn(Arc::new(|msg: &[u8]| {
            let mut sig = [0u8; 64];
            let len = msg.len().min(64);
            sig[..len].copy_from_slice(&msg[..len]);
            sig
        }));

        let root_a = epoch_mgr_a.current_root().unwrap();
        epoch_mgr_a.add_valid_root(root_a, 0).unwrap();

        // Inject 2 txs into A's confirmed pool
        {
            let mut pool = handler_a.confirmed_pool.write();
            for i in 1u8..=2 {
                let mut change = [0u8; 32];
                change[0] = i * 10;
                let mut recipient = [0u8; 32];
                recipient[0] = i * 20;
                pool.push(L2Transaction {
                    epoch: 0,
                    nullifier: [i; 32],
                    change_commitment: change,
                    recipient_commitment: recipient,
                    commitment_root: root_a,
                    proof: vec![],
                    encrypted_change: vec![],
                    encrypted_recipient: vec![],
                    timestamp: 0,
                });
            }
        }

        // Propose + vote to finalize checkpoint on A
        let proposal = handler_a.propose_checkpoint().unwrap().unwrap();
        let hash = proposal.checkpoint_hash();
        {
            let mut votes = handler_a.votes.write();
            let state = votes
                .entry(proposal.height)
                .or_insert_with(|| CheckpointVoteState::new(hash));
            state.proposal = Some(proposal.clone());
        }
        let vote = L2CheckpointVoteMessage {
            height: 1,
            checkpoint_hash: hash,
            voter: [0x01; 32],
            approve: true,
            signature: [0u8; 64],
            timestamp: 0,
        };
        handler_a.handle_checkpoint_vote(&vote).unwrap();

        let root_after_a = epoch_mgr_a.current_root().unwrap();
        assert_ne!(root_after_a, root_a, "A's root should change after checkpoint");

        // === Peer B: sync from A ===
        let db_b = Arc::new(Database::in_memory().expect("in-memory db"));
        let config_b = EpochManagerConfig {
            epoch_length: 100,
            transition_window: 10,
            tree_depth: 4,
            max_valid_roots: 16,
        };
        let epoch_mgr_b = Arc::new(EpochManager::new(db_b.clone(), config_b));
        epoch_mgr_b.initialize_genesis().unwrap();
        let handler_b =
            NullifierRouteHandler::with_defaults([0x02; 32], epoch_mgr_b.clone(), db_b.clone());

        // Build a sync response from A's persisted checkpoint data
        let request = L2TreeSyncRequest {
            requesting_node: [0x02; 32],
            from_height: 0,
            timestamp: 0,
        };
        let response = handler_a
            .handle_tree_sync_request(&request)
            .unwrap()
            .expect("Should produce sync response");

        assert!(
            !response.checkpoints.is_empty(),
            "Response should contain checkpoints"
        );
        assert_eq!(response.commitment_root, root_after_a);

        // B replays the checkpoints
        handler_b.handle_tree_sync_response(&response).unwrap();

        // Verify B's root matches A's
        let root_b = epoch_mgr_b.current_root().unwrap();
        assert_eq!(
            root_b, root_after_a,
            "Synced peer's root should match source peer"
        );
    }

    /// Test that a transfer with an invalid (wrong) commitment root is rejected
    #[test]
    fn test_transfer_with_wrong_root_rejected() {
        let (_db, epoch_mgr, handler) = setup();

        epoch_mgr.update_active_nodes(vec![[0x01; 32]]);
        handler.set_verifier(test_verifier());

        // Add a valid root
        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 0).unwrap();

        // Submit transfer with a WRONG commitment root
        let wrong_root = [0xFF; 32];
        let msg = L2ConfidentialTransferMessage {
            transaction: L2Transaction {
                epoch: 0,
                nullifier: [0x42; 32],
                change_commitment: [0u8; 32],
                recipient_commitment: [0u8; 32],
                commitment_root: wrong_root, // Not in valid roots
                proof: vec![0u8; 192],
                encrypted_change: vec![],
                encrypted_recipient: vec![],
                timestamp: 0,
            },
            sender: [0x99; 32],
        };

        let result = handler.handle_transfer(&msg);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("Invalid commitment root"),
            "Should reject wrong root"
        );
    }

    /// Test that a transfer with a corrupted proof is rejected when verifier has real VK
    /// This test requires Groth16 setup (~10-30s), so it's marked #[ignore]
    #[test]
    #[ignore]
    fn test_groth16_invalid_proof_rejected() {
        let (_db, epoch_mgr, handler) = setup();
        epoch_mgr.update_active_nodes(vec![[0x01; 32]]);

        // Create a real verifier with Groth16 VK
        let prover = ghost_zkp::note_prover::NoteProver::new_with_setup(4)
            .expect("Groth16 setup should succeed");
        let verifier = Arc::new(ghost_zkp::NoteVerifier::for_prover(&prover));
        handler.set_verifier(verifier);

        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 0).unwrap();

        // Submit with a corrupted proof (valid size but garbage bytes)
        let msg = L2ConfidentialTransferMessage {
            transaction: L2Transaction {
                epoch: 0,
                nullifier: [0x42; 32],
                change_commitment: [0u8; 32],
                recipient_commitment: [0u8; 32],
                commitment_root: root,
                proof: vec![0xFF; 192], // Garbage proof
                encrypted_change: vec![],
                encrypted_recipient: vec![],
                timestamp: 0,
            },
            sender: [0x99; 32],
        };

        let result = handler.handle_transfer(&msg);
        assert!(
            result.is_err(),
            "Corrupted proof should be rejected"
        );
    }

    #[test]
    fn test_signing_with_sign_fn() {
        let (_db, epoch_mgr, handler) = setup();

        // Set a dummy sign function
        handler.set_sign_fn(Arc::new(|msg: &[u8]| {
            let mut sig = [0u8; 64];
            // Use first 32 bytes of message as part of signature for testing
            let copy_len = msg.len().min(32);
            sig[..copy_len].copy_from_slice(&msg[..copy_len]);
            sig
        }));

        // We're the only active node (proposer)
        epoch_mgr.update_active_nodes(vec![[0x01; 32]]);

        let proposal = handler.propose_checkpoint().unwrap().unwrap();
        // Signature should NOT be all zeros (sign_fn was called)
        assert_ne!(proposal.proposer_signature, [0u8; 64]);
    }

    #[test]
    fn test_rate_limiting_per_peer() {
        let (_db, _epoch_mgr, handler) = setup();

        let peer = [0x42; 32];

        // Should allow exactly MAX_L2_MSG_PER_PEER_PER_SEC messages
        for i in 0..MAX_L2_MSG_PER_PEER_PER_SEC {
            assert!(
                handler.check_rate_limit(&peer).is_ok(),
                "Message {} should be accepted (within limit)",
                i
            );
        }

        // The 101st message (index 100) should be rate limited
        let result = handler.check_rate_limit(&peer);
        assert!(
            result.is_err(),
            "Message beyond per-peer limit should be rejected"
        );
        assert!(
            result.unwrap_err().to_string().contains("rate limit"),
            "Error should mention rate limit"
        );

        // A different peer should still be allowed (per-peer, not global at this count)
        let other_peer = [0x43; 32];
        assert!(
            handler.check_rate_limit(&other_peer).is_ok(),
            "Different peer should not be affected by first peer's rate limit"
        );
    }

    #[test]
    fn test_finalize_checkpoint_prevents_double_apply() {
        let (_db, epoch_mgr, handler) = setup();

        // We're the only active node (proposer)
        epoch_mgr.update_active_nodes(vec![[0x01; 32]]);

        // Add a transaction to the confirmed pool so the checkpoint has content
        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 0).unwrap();

        let mut change_commit = [0u8; 32];
        change_commit[0] = 0x10;
        let mut recipient_commit = [0u8; 32];
        recipient_commit[0] = 0x20;

        {
            let mut pool = handler.confirmed_pool.write();
            pool.push(L2Transaction {
                epoch: 0,
                nullifier: [0x42; 32],
                change_commitment: change_commit,
                recipient_commitment: recipient_commit,
                commitment_root: root,
                proof: vec![0u8; 192],
                encrypted_change: vec![],
                encrypted_recipient: vec![],
                timestamp: 0,
            });
        }

        // Propose checkpoint — this applies commitments to the tree as proposer
        let proposal = handler.propose_checkpoint().unwrap().unwrap();
        let note_count_after_propose = epoch_mgr.note_count();
        assert_eq!(note_count_after_propose, 2); // 1 change + 1 recipient

        // Verify the height is in proposed_heights (C-2 guard)
        assert!(handler.proposed_heights.read().contains(&proposal.height));

        // Now simulate checkpoint finalization on the SAME proposer node.
        // Without C-2 fix, this would double-apply commitments (adding 2 more notes).
        // With C-2 fix, finalize_checkpoint skips re-applying for this height.

        // First, set up the vote state with the proposal stored
        {
            let mut votes = handler.votes.write();
            let state = votes
                .entry(proposal.height)
                .or_insert_with(|| CheckpointVoteState::new(proposal.checkpoint_hash()));
            state.proposal = Some(proposal.clone());
        }

        // Call finalize directly (simulating quorum reached)
        handler
            .finalize_checkpoint(proposal.height, Some(&proposal))
            .unwrap();

        // Tree should still have exactly 2 notes, NOT 4 (no double-apply)
        let note_count_after_finalize = epoch_mgr.note_count();
        assert_eq!(
            note_count_after_finalize, 2,
            "C-2: Proposer should NOT double-apply commitments on finalization"
        );

        // proposed_heights should be cleaned up
        assert!(
            !handler
                .proposed_heights
                .read()
                .contains(&proposal.height),
            "C-2: Height should be removed from proposed_heights after finalization"
        );
    }

    /// S-1: Broadcast without verifier is rejected (fail-closed)
    #[test]
    fn test_broadcast_rejected_without_verifier() {
        let (_db, epoch_mgr, handler) = setup();

        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 0).unwrap();

        // Verifier is NOT set — should reject
        assert!(!handler.has_verifier());

        let broadcast = L2TransferBroadcastMessage {
            transaction: L2Transaction {
                epoch: 0,
                nullifier: [0x42; 32],
                change_commitment: [0u8; 32],
                recipient_commitment: [0u8; 32],
                commitment_root: root,
                proof: vec![0u8; 192],
                encrypted_change: vec![],
                encrypted_recipient: vec![],
                timestamp: 0,
            },
            validator: [0x99; 32],
            signature: [0u8; 64],
        };

        handler.handle_transfer_broadcast(&broadcast).unwrap();
        // S-1: confirmed_pool should remain empty since verifier is not loaded
        assert_eq!(
            handler.confirmed_pool_size(),
            0,
            "S-1: Broadcast without verifier should be rejected"
        );
    }

    /// S-1: Broadcast WITH verifier set is accepted
    #[test]
    fn test_broadcast_accepted_with_verifier() {
        let (_db, epoch_mgr, handler) = setup();

        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 0).unwrap();

        // Set a test verifier that accepts all proofs
        handler.set_verifier(test_verifier());

        let broadcast = L2TransferBroadcastMessage {
            transaction: L2Transaction {
                epoch: 0,
                nullifier: [0x42; 32],
                change_commitment: [0u8; 32],
                recipient_commitment: [0u8; 32],
                commitment_root: root,
                proof: vec![0u8; 192],
                encrypted_change: vec![],
                encrypted_recipient: vec![],
                timestamp: 0,
            },
            validator: [0x99; 32],
            signature: [0u8; 64],
        };

        handler.handle_transfer_broadcast(&broadcast).unwrap();
        assert_eq!(
            handler.confirmed_pool_size(),
            1,
            "S-1: Broadcast with verifier should be accepted"
        );
    }

    /// S-5: proposed_heights are pruned along with vote states
    #[test]
    fn test_proposed_heights_pruned() {
        let (_db, _epoch_mgr, handler) = setup();

        // Add 200 heights to proposed_heights
        {
            let mut heights = handler.proposed_heights.write();
            for h in 1..=200 {
                heights.insert(h);
            }
        }
        assert_eq!(handler.proposed_heights.read().len(), 200);

        // Prune at current_height=200, cutoff=100
        handler.prune_vote_states(200);

        // Only heights > 100 should remain
        let heights = handler.proposed_heights.read();
        assert_eq!(heights.len(), 100, "S-5: Should have pruned heights <= 100");
        assert!(!heights.contains(&100), "S-5: Height 100 should be pruned");
        assert!(heights.contains(&101), "S-5: Height 101 should remain");
        assert!(heights.contains(&200), "S-5: Height 200 should remain");
    }

    /// S-6: VerifiedVote newtype ensures type-safe vote construction
    #[test]
    fn test_verified_vote_newtype() {
        let mut state = CheckpointVoteState::new([0; 32]);

        // Create verified votes (simulating post-signature-verification)
        let vote1 = VerifiedVote::new([1; 32], true);
        let vote2 = VerifiedVote::new([2; 32], false);

        assert!(state.add_vote(vote1)); // New vote → true
        assert!(state.add_vote(vote2)); // New vote → true

        // Duplicate voter
        let vote_dup = VerifiedVote::new([1; 32], true);
        assert!(!state.add_vote(vote_dup)); // Duplicate → false

        assert_eq!(state.approval_count(), 1); // Only [1;32] approved
    }
}
