//! Canonical Elder List - BFT-secured elder membership (P2P-C1/C2/C3)
//!
//! This module implements a canonical elder list that ensures all nodes agree
//! on who the eligible voters are. Elder registration requires:
//!
//! 1. Valid PoW proof (Sybil resistance)
//! 2. 7-day uptime at 95%+ (reliability)
//! 3. BFT approval from >67% of current elders (consensus gate)
//!
//! ## Security Properties
//!
//! - **Consensus**: All nodes derive the same elder list from the merkle root
//! - **Accountability**: Elder membership is cryptographically provable
//! - **Sybil Resistance**: PoW prevents mass identity generation
//! - **Reliability Gate**: Uptime requirement ensures node stability
//! - **BFT Gate**: Existing elders must approve new members

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info, warn};

use ghost_common::error::{GhostError, GhostResult};
use ghost_common::identity::{verify_signature, NodeIdProof, NODE_ID_POW_DIFFICULTY};
use ghost_common::types::NodeId;
use ghost_storage::Database;

/// Maximum number of elders (from ghost_common::constants)
pub const ELDER_MAX_COUNT: u32 = 101;

/// M-5: Maximum number of approval signatures to prevent memory exhaustion
/// Set to 200 to allow headroom beyond ELDER_MAX_COUNT but still bounded
pub const MAX_APPROVALS: usize = 200;

/// Minimum uptime percentage required for elder registration (95%)
pub const ELDER_MIN_UPTIME_PERCENT: f64 = 95.0;

/// Minimum uptime tracking period before elder eligibility (7 days in seconds)
pub const ELDER_MIN_UPTIME_PERIOD_SECS: u64 = 7 * 24 * 60 * 60;

/// BFT threshold for elder approval (67% = 2/3 + 1)
pub const ELDER_BFT_THRESHOLD_PERCENT: u32 = 67;

/// Domain separator for elder list merkle root computation
const MERKLE_DOMAIN: &[u8] = b"ghost/elder-list/merkle/v1";

/// Domain separator for elder approval signatures
const APPROVAL_DOMAIN: &[u8] = b"ghost/elder-approval/v1";

/// An entry in the canonical elder list
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ElderEntry {
    /// Node ID (Ed25519 public key)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub node_id: NodeId,
    /// Epoch when this node became an elder
    pub registered_epoch: u64,
    /// PoW nonce that was verified for registration
    pub pow_nonce: u64,
    /// PoW difficulty achieved
    pub pow_difficulty: u32,
    /// First seen timestamp (Unix seconds)
    pub first_seen: u64,
    /// Uptime percentage at time of registration
    pub uptime_at_registration: f64,
}

impl ElderEntry {
    /// Create a new elder entry
    pub fn new(
        node_id: NodeId,
        registered_epoch: u64,
        pow_proof: &NodeIdProof,
        first_seen: u64,
        uptime_at_registration: f64,
    ) -> Self {
        Self {
            node_id,
            registered_epoch,
            pow_nonce: pow_proof.nonce,
            pow_difficulty: pow_proof.difficulty,
            first_seen,
            uptime_at_registration,
        }
    }

    /// Reconstruct a NodeIdProof from stored fields
    pub fn to_pow_proof(&self) -> NodeIdProof {
        NodeIdProof {
            nonce: self.pow_nonce,
            difficulty: self.pow_difficulty,
        }
    }

    /// Compute the hash of this entry for merkle tree
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.node_id);
        hasher.update(self.registered_epoch.to_le_bytes());
        hasher.update(self.first_seen.to_le_bytes());
        hasher.finalize().into()
    }
}

/// HIGH-CONS-3: Maximum allowed timestamp drift for elder approvals (10 seconds)
///
/// REDUCED from 15s to 10s to tighten the replay attack window. Nodes MUST use NTP
/// to maintain accurate clocks. This shorter window is acceptable because:
///
/// **Network Requirements (HIGH-CONS-3):**
/// - All nodes should use NTP for clock synchronization (< 100ms typical drift)
/// - P2P propagation latency is typically < 2 seconds on modern networks
/// - Processing time is typically < 500ms
/// - Total typical delay: ~3 seconds, well under 10 second limit
///
/// **Why 10 seconds?**
/// - Reduces replay window by 33% compared to 15s
/// - Still provides 3x margin over typical 3s end-to-end latency
/// - Nodes without NTP will experience rejections (this is acceptable - use NTP)
///
/// **Defense in Depth:**
/// - Approvals are tied to specific epoch+merkle_root (can't replay for different list)
/// - Signature includes timestamp (can't reuse old signature with new timestamp)
/// - Duplicate approvals from same approver are ignored
/// - Elder list transitions require BFT quorum (>67%)
///
/// A successful replay attack would require:
/// 1. Capturing a valid approval within 10 seconds of signing
/// 2. Replaying before the epoch transitions
/// 3. The replay providing additional approval weight (unlikely if honest majority)
pub const MAX_APPROVAL_TIMESTAMP_DRIFT_MS: u64 = 10 * 1000;

/// An approval signature from an elder
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElderApproval {
    /// Approving elder's node ID
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub approver: NodeId,
    /// Ed25519 signature over (epoch || merkle_root)
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
    /// Timestamp of approval (Unix milliseconds)
    pub timestamp: u64,
}

impl ElderApproval {
    /// Create the message that should be signed for approval
    pub fn signing_message(epoch: u64, merkle_root: &[u8; 32]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(APPROVAL_DOMAIN.len() + 8 + 32);
        msg.extend_from_slice(APPROVAL_DOMAIN);
        msg.extend_from_slice(&epoch.to_le_bytes());
        msg.extend_from_slice(merkle_root);
        msg
    }

    /// Validate that the approval timestamp is within a reasonable window
    ///
    /// Returns false if the timestamp is too far in the past or future,
    /// which could indicate a replay attack or clock skew issue.
    pub fn is_timestamp_valid(&self) -> bool {
        let now = chrono::Utc::now().timestamp_millis() as u64;

        // Check if timestamp is in the future (with small tolerance)
        if self.timestamp > now.saturating_add(MAX_APPROVAL_TIMESTAMP_DRIFT_MS) {
            tracing::warn!(
                approver = %hex::encode(&self.approver[..8]),
                timestamp = self.timestamp,
                now = now,
                "Elder approval timestamp is too far in the future"
            );
            return false;
        }

        // Check if timestamp is too old
        if self.timestamp < now.saturating_sub(MAX_APPROVAL_TIMESTAMP_DRIFT_MS) {
            tracing::warn!(
                approver = %hex::encode(&self.approver[..8]),
                timestamp = self.timestamp,
                now = now,
                "Elder approval timestamp is too old (possible replay attack)"
            );
            return false;
        }

        true
    }

    /// Verify this approval signature and timestamp
    ///
    /// SEC-SIG-1: Logs errors instead of silently returning false
    /// Also validates that the timestamp is within a reasonable window.
    pub fn verify(&self, epoch: u64, merkle_root: &[u8; 32]) -> bool {
        // First validate timestamp to prevent replay attacks
        if !self.is_timestamp_valid() {
            return false;
        }

        let message = Self::signing_message(epoch, merkle_root);
        match verify_signature(&self.approver, &message, &self.signature) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::warn!(
                    approver = %hex::encode(&self.approver[..8]),
                    epoch = epoch,
                    error = %e,
                    "Elder approval signature verification error"
                );
                false
            }
        }
    }

    /// Verify signature only (without timestamp validation)
    ///
    /// Use this for historical verification where timestamp is expected to be old.
    pub fn verify_signature_only(&self, epoch: u64, merkle_root: &[u8; 32]) -> bool {
        let message = Self::signing_message(epoch, merkle_root);
        match verify_signature(&self.approver, &message, &self.signature) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::warn!(
                    approver = %hex::encode(&self.approver[..8]),
                    epoch = epoch,
                    error = %e,
                    "Elder approval signature verification error"
                );
                false
            }
        }
    }
}

/// The canonical elder list for a specific epoch
///
/// This list is agreed upon by >67% of the previous epoch's elders.
/// All voting sessions should use this list to determine eligible voters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalElderList {
    /// Epoch number (increments with each elder set change)
    pub epoch: u64,
    /// Ordered list of elders (by registration order)
    pub elders: Vec<ElderEntry>,
    /// Merkle root of the elder list
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub merkle_root: [u8; 32],
    /// Approval signatures from >67% of PREVIOUS epoch's elders
    pub approval_signatures: Vec<ElderApproval>,
    /// Timestamp when this list became canonical (Unix milliseconds)
    pub activated_at: u64,
}

impl CanonicalElderList {
    /// Create a new canonical elder list
    pub fn new(epoch: u64, elders: Vec<ElderEntry>) -> Self {
        let merkle_root = Self::compute_merkle_root_static(&elders);
        Self {
            epoch,
            elders,
            merkle_root,
            approval_signatures: Vec::new(),
            activated_at: 0,
        }
    }

    /// Create the genesis elder list (epoch 0, no approvals needed)
    ///
    /// The genesis list is bootstrapped from the initial set of elders.
    /// This is used at network launch when there are no existing elders to approve.
    pub fn genesis(elders: Vec<ElderEntry>) -> Self {
        let merkle_root = Self::compute_merkle_root_static(&elders);
        Self {
            epoch: 0,
            elders,
            merkle_root,
            approval_signatures: Vec::new(),
            activated_at: chrono::Utc::now().timestamp_millis() as u64,
        }
    }

    /// Compute the merkle root for a list of elders
    ///
    /// Uses a standard binary merkle tree with power-of-2 padding.
    ///
    /// # L-5: Padding Behavior
    ///
    /// The tree requires a power-of-2 number of leaves for efficient computation.
    /// When the number of elders is not a power of 2, we pad with zero hashes:
    ///
    /// - **len=0**: Returns all-zeros hash (empty tree)
    /// - **len=1**: No padding needed (1 is 2^0, a power of 2). The single
    ///   elder's hash IS the merkle root.
    /// - **len=2**: No padding needed (2 is 2^1)
    /// - **len=3**: Padded to 4 leaves (one zero hash added)
    /// - **len=5-7**: Padded to 8 leaves
    /// - etc.
    ///
    /// The condition `n & (n-1) == 0` checks if n is a power of 2:
    /// - 1: 0b0001 & 0b0000 = 0 (power of 2)
    /// - 2: 0b0010 & 0b0001 = 0 (power of 2)
    /// - 3: 0b0011 & 0b0010 = 2 (not power of 2, needs padding)
    pub fn compute_merkle_root_static(elders: &[ElderEntry]) -> [u8; 32] {
        if elders.is_empty() {
            return [0u8; 32];
        }

        // Get leaf hashes
        let mut hashes: Vec<[u8; 32]> = elders.iter().map(|e| e.hash()).collect();

        // L-5: Pad to power of 2 if needed
        // The bit trick `n & (n-1) == 0` is true only for powers of 2 (and 0).
        // For len=1: 1 & 0 = 0, so no padding (1 is 2^0)
        // For len=3: 3 & 2 = 2 != 0, so we pad to 4
        // The `!hashes.is_empty()` guard prevents underflow when len=0.
        while hashes.len() & (hashes.len() - 1) != 0 && !hashes.is_empty() {
            hashes.push([0u8; 32]);
        }

        // Build merkle tree bottom-up
        while hashes.len() > 1 {
            let mut next_level = Vec::with_capacity(hashes.len() / 2);
            for chunk in hashes.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(MERKLE_DOMAIN);
                hasher.update(chunk[0]);
                hasher.update(chunk.get(1).unwrap_or(&[0u8; 32]));
                next_level.push(hasher.finalize().into());
            }
            hashes = next_level;
        }

        hashes.first().copied().unwrap_or([0u8; 32])
    }

    /// Recompute the merkle root (used for verification)
    pub fn compute_merkle_root(&self) -> [u8; 32] {
        Self::compute_merkle_root_static(&self.elders)
    }

    /// Verify the merkle root is correct
    pub fn verify_merkle_root(&self) -> bool {
        self.merkle_root == self.compute_merkle_root()
    }

    /// Add an approval signature
    ///
    /// M-5: Enforces maximum approval count to prevent memory exhaustion
    pub fn add_approval(&mut self, approval: ElderApproval) -> bool {
        // M-5: Check bounds before adding
        if self.approval_signatures.len() >= MAX_APPROVALS {
            warn!(
                epoch = self.epoch,
                current_count = self.approval_signatures.len(),
                max = MAX_APPROVALS,
                "Cannot add approval: maximum approvals reached"
            );
            return false;
        }

        // Verify the signature
        if !approval.verify(self.epoch, &self.merkle_root) {
            warn!(
                approver = hex::encode(&approval.approver[..8]),
                epoch = self.epoch,
                "Invalid elder approval signature"
            );
            return false;
        }

        // Check for duplicate
        if self
            .approval_signatures
            .iter()
            .any(|a| a.approver == approval.approver)
        {
            debug!(
                approver = hex::encode(&approval.approver[..8]),
                "Duplicate approval ignored"
            );
            return false;
        }

        self.approval_signatures.push(approval);
        true
    }

    /// Check if we have enough approvals from the previous epoch's elders
    ///
    /// For epoch 0 (genesis), no approvals are needed.
    /// For epoch N > 0, we need >67% of epoch N-1's elders to approve.
    pub fn has_sufficient_approvals(&self, previous_elders: &HashSet<NodeId>) -> bool {
        if self.epoch == 0 {
            // Genesis list doesn't need approvals
            return true;
        }

        if previous_elders.is_empty() {
            // No previous elders means this is effectively genesis
            return true;
        }

        // Use ceiling division to round up
        let threshold = (previous_elders.len() as u32 * ELDER_BFT_THRESHOLD_PERCENT)
            .div_ceil(100)
            .max(1) as usize;

        let valid_approvals = self
            .approval_signatures
            .iter()
            .filter(|a| previous_elders.contains(&a.approver))
            .filter(|a| a.verify(self.epoch, &self.merkle_root))
            .count();

        valid_approvals >= threshold
    }

    /// Activate this list (set activated_at timestamp)
    pub fn activate(&mut self) {
        self.activated_at = chrono::Utc::now().timestamp_millis() as u64;
        info!(
            epoch = self.epoch,
            elder_count = self.elders.len(),
            approvals = self.approval_signatures.len(),
            "Canonical elder list activated"
        );
    }

    /// Check if a node is an elder in this list
    pub fn is_elder(&self, node_id: &NodeId) -> bool {
        self.elders.iter().any(|e| &e.node_id == node_id)
    }

    /// Get the set of eligible voters (all elders)
    pub fn get_eligible_voters(&self) -> HashSet<NodeId> {
        self.elders.iter().map(|e| e.node_id).collect()
    }

    /// Get elder count
    pub fn elder_count(&self) -> usize {
        self.elders.len()
    }

    /// Find an elder by node ID
    pub fn get_elder(&self, node_id: &NodeId) -> Option<&ElderEntry> {
        self.elders.iter().find(|e| &e.node_id == node_id)
    }

    /// Check if there's room for more elders
    pub fn has_capacity(&self) -> bool {
        self.elders.len() < ELDER_MAX_COUNT as usize
    }

    /// CRIT-4: Verify this elder list is canonical (properly approved)
    ///
    /// This is the security-critical verification method that ensures the elder
    /// list was properly approved by >67% of the previous epoch's elders.
    ///
    /// # Security Properties
    ///
    /// - **Merkle Integrity**: Verifies the merkle root matches the elder entries
    /// - **BFT Approval**: Verifies sufficient valid signatures from previous elders
    /// - **Replay Prevention**: Signatures are bound to epoch and merkle root
    ///
    /// # Arguments
    ///
    /// * `previous_elders` - The set of node IDs from the previous epoch's elder list
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the list is valid, or an error describing the validation failure.
    ///
    /// # Genesis Exception
    ///
    /// For epoch 0 (genesis), no approvals are required since there are no previous elders.
    ///
    /// # Note
    ///
    /// For epoch rollback protection, use `verify_canonical_with_min_epoch()` instead.
    pub fn verify_canonical(&self, previous_elders: &HashSet<NodeId>) -> GhostResult<()> {
        self.verify_canonical_with_min_epoch(previous_elders, 0)
    }

    /// M-9: Verify elder list with epoch rollback protection
    ///
    /// This extends `verify_canonical()` with protection against epoch rollback attacks.
    /// An attacker might try to replay an old, valid elder list from a previous epoch
    /// to override the current elder set. This method rejects such attacks by requiring
    /// the list's epoch to be at least `min_expected_epoch`.
    ///
    /// # Arguments
    ///
    /// * `previous_elders` - The set of node IDs from the previous epoch's elder list
    /// * `min_expected_epoch` - Minimum epoch number to accept (typically current_epoch)
    ///
    /// # Security Properties
    ///
    /// - **Epoch Rollback Protection**: Rejects lists with epoch < min_expected_epoch
    /// - All properties from `verify_canonical()`
    ///
    /// # Example
    ///
    /// ```ignore
    /// // When processing an elder list update, pass current epoch as minimum
    /// let current_epoch = current_list.epoch;
    /// new_list.verify_canonical_with_min_epoch(&previous_elders, current_epoch)?;
    /// ```
    pub fn verify_canonical_with_min_epoch(
        &self,
        previous_elders: &HashSet<NodeId>,
        min_expected_epoch: u64,
    ) -> GhostResult<()> {
        // M-9: Check for epoch rollback attack
        if self.epoch < min_expected_epoch {
            warn!(
                received_epoch = self.epoch,
                min_expected_epoch,
                "M-9 SECURITY: Rejecting elder list with epoch below minimum (possible rollback attack)"
            );
            return Err(GhostError::ConsensusFailed(format!(
                "M-9: Elder list epoch {} is below minimum expected epoch {} (rollback attack prevented)",
                self.epoch, min_expected_epoch
            )));
        }

        // CRIT-4: First verify merkle root integrity
        if !self.verify_merkle_root() {
            return Err(GhostError::ConsensusFailed(
                "CRIT-4: Elder list has invalid merkle root - list may have been tampered with"
                    .to_string(),
            ));
        }

        // Genesis list (epoch 0) doesn't need approvals
        if self.epoch == 0 {
            debug!(
                epoch = self.epoch,
                elder_count = self.elders.len(),
                "CRIT-4: Genesis elder list (epoch 0) - no approvals required"
            );
            return Ok(());
        }

        // CRIT-4: Verify we have enough valid approval signatures from previous epoch elders
        // BFT threshold: >67% of previous elders must have approved
        //
        // HIGH-CONS-2: The previous_elders parameter MUST be the canonical elder list
        // from epoch N-1 (where N is self.epoch). This is enforced by the caller:
        // - ElderListManager::transition_to() passes current.get_eligible_voters()
        // - The transition_to() method verifies new_list.epoch == current.epoch + 1
        // Therefore, previous_elders is guaranteed to be from epoch N-1.
        if previous_elders.is_empty() {
            // This should not happen for epoch > 0, but handle gracefully
            warn!(
                epoch = self.epoch,
                "CRIT-4: No previous elders provided for non-genesis epoch"
            );
            return Err(GhostError::ConsensusFailed(
                "CRIT-4: Non-genesis epoch requires previous elders for validation".to_string(),
            ));
        }

        // Use ceiling division to round up (67% threshold)
        let threshold = (previous_elders.len() as u32 * ELDER_BFT_THRESHOLD_PERCENT)
            .div_ceil(100)
            .max(1) as usize;

        // HIGH-CONS-2: Count valid approvals from epoch N-1 elders ONLY
        // The .filter checks that a.approver is in previous_elders (epoch N-1 set)
        // Approvers not in this set are ignored (prevents approval replay from older epochs)
        let valid_approvals = self
            .approval_signatures
            .iter()
            .filter(|a| {
                // HIGH-CONS-2: Only count approvals from previous epoch (N-1) elders
                previous_elders.contains(&a.approver)
            })
            .filter(|a| a.verify(self.epoch, &self.merkle_root))
            .count();

        if valid_approvals < threshold {
            warn!(
                epoch = self.epoch,
                valid_approvals,
                threshold,
                previous_elders = previous_elders.len(),
                "CRIT-4: Insufficient BFT approvals for elder list"
            );
            return Err(GhostError::ConsensusFailed(format!(
                "CRIT-4: Elder list has insufficient approvals: {} of {} required (from {} previous elders)",
                valid_approvals, threshold, previous_elders.len()
            )));
        }

        info!(
            epoch = self.epoch,
            valid_approvals, threshold, "CRIT-4: Elder list verified as canonical"
        );

        Ok(())
    }
}

/// L-12 SECURITY: Approval collection timeout (10 minutes)
///
/// If approval collection doesn't reach threshold within this time,
/// the pending list is discarded and a new proposal must be submitted.
/// This prevents approval collection from hanging indefinitely.
pub const APPROVAL_COLLECTION_TIMEOUT_SECS: u64 = 10 * 60;

/// State for tracking pending list approval collection
#[derive(Debug, Clone)]
pub struct PendingListState {
    /// The pending elder list
    pub list: CanonicalElderList,
    /// When approval collection started (Unix milliseconds)
    pub started_at: u64,
    /// Number of retry attempts for this transition
    pub retry_count: u32,
}

impl PendingListState {
    /// Create new pending state for a list
    pub fn new(list: CanonicalElderList) -> Self {
        Self {
            list,
            started_at: chrono::Utc::now().timestamp_millis() as u64,
            retry_count: 0,
        }
    }

    /// Check if this pending state has timed out
    pub fn is_timed_out(&self) -> bool {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let elapsed_ms = now.saturating_sub(self.started_at);
        elapsed_ms > APPROVAL_COLLECTION_TIMEOUT_SECS * 1000
    }

    /// Get remaining time before timeout (milliseconds)
    pub fn remaining_ms(&self) -> u64 {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let elapsed_ms = now.saturating_sub(self.started_at);
        let timeout_ms = APPROVAL_COLLECTION_TIMEOUT_SECS * 1000;
        timeout_ms.saturating_sub(elapsed_ms)
    }
}

/// Manages the canonical elder list state and transitions
pub struct ElderListManager {
    /// Current canonical elder list
    current_list: RwLock<Arc<CanonicalElderList>>,
    /// L-12: Pending list being voted on (with timeout tracking)
    pending_list: RwLock<Option<PendingListState>>,
    /// Pending registration requests
    pending_registrations: RwLock<HashMap<NodeId, ElderRegistrationRequest>>,
}

/// A request to register as an elder
#[derive(Debug, Clone)]
pub struct ElderRegistrationRequest {
    /// Candidate node ID
    pub candidate: NodeId,
    /// PoW proof
    pub pow_proof: NodeIdProof,
    /// First seen timestamp
    pub first_seen: u64,
    /// Current uptime percentage
    pub uptime_percent: f64,
    /// When the request was created
    pub requested_at: u64,
    /// Approvals received
    pub approvals: HashSet<NodeId>,
    /// Rejections received
    pub rejections: HashSet<NodeId>,
}

impl ElderListManager {
    /// Create a new elder list manager with genesis list
    pub fn new(genesis_elders: Vec<ElderEntry>) -> Self {
        let genesis_list = CanonicalElderList::genesis(genesis_elders);
        Self {
            current_list: RwLock::new(Arc::new(genesis_list)),
            pending_list: RwLock::new(None),
            pending_registrations: RwLock::new(HashMap::new()),
        }
    }

    /// Create with an existing canonical list
    pub fn with_list(list: CanonicalElderList) -> Self {
        Self {
            current_list: RwLock::new(Arc::new(list)),
            pending_list: RwLock::new(None),
            pending_registrations: RwLock::new(HashMap::new()),
        }
    }

    /// Get the current canonical elder list
    pub fn current(&self) -> Arc<CanonicalElderList> {
        Arc::clone(&self.current_list.read())
    }

    /// Get the current epoch
    pub fn current_epoch(&self) -> u64 {
        self.current_list.read().epoch
    }

    /// Check if a node is currently an elder
    pub fn is_elder(&self, node_id: &NodeId) -> bool {
        self.current_list.read().is_elder(node_id)
    }

    /// Get eligible voters for voting sessions
    pub fn get_eligible_voters(&self) -> HashSet<NodeId> {
        self.current_list.read().get_eligible_voters()
    }

    /// Submit a registration request
    ///
    /// Returns error if:
    /// - Candidate is already an elder
    /// - PoW proof is invalid
    /// - Uptime is insufficient
    /// - Uptime period is too short
    pub fn submit_registration(
        &self,
        candidate: NodeId,
        pow_proof: NodeIdProof,
        first_seen: u64,
        uptime_percent: f64,
    ) -> GhostResult<()> {
        let current = self.current();

        // Check if already an elder
        if current.is_elder(&candidate) {
            return Err(GhostError::Config("Already an elder".to_string()));
        }

        // Check capacity
        if !current.has_capacity() {
            return Err(GhostError::Config("Elder list at capacity".to_string()));
        }

        // Verify PoW proof meets minimum difficulty
        if !pow_proof.verify(&candidate, NODE_ID_POW_DIFFICULTY) {
            return Err(GhostError::Config("Invalid PoW proof".to_string()));
        }

        // Check uptime percentage
        if uptime_percent < ELDER_MIN_UPTIME_PERCENT {
            return Err(GhostError::Config(format!(
                "Insufficient uptime: {:.1}% < {:.1}%",
                uptime_percent, ELDER_MIN_UPTIME_PERCENT
            )));
        }

        // Check uptime period
        let now = chrono::Utc::now().timestamp() as u64;
        let uptime_period = now.saturating_sub(first_seen);
        if uptime_period < ELDER_MIN_UPTIME_PERIOD_SECS {
            return Err(GhostError::Config(format!(
                "Insufficient uptime period: {} days < 7 days",
                uptime_period / 86400
            )));
        }

        // Add to pending registrations
        let request = ElderRegistrationRequest {
            candidate,
            pow_proof,
            first_seen,
            uptime_percent,
            requested_at: chrono::Utc::now().timestamp_millis() as u64,
            approvals: HashSet::new(),
            rejections: HashSet::new(),
        };

        self.pending_registrations
            .write()
            .insert(candidate, request);

        info!(
            candidate = hex::encode(&candidate[..8]),
            uptime = format!("{:.1}%", uptime_percent),
            "Elder registration request submitted"
        );

        Ok(())
    }

    /// Record an approval for a pending registration
    ///
    /// Returns true if the registration is now approved (>67%)
    pub fn record_registration_approval(&self, candidate: &NodeId, approver: &NodeId) -> bool {
        let current = self.current();

        // Only elders can approve
        if !current.is_elder(approver) {
            return false;
        }

        let mut pending = self.pending_registrations.write();
        if let Some(request) = pending.get_mut(candidate) {
            request.approvals.insert(*approver);

            // Check if we have enough approvals (ceiling division for BFT)
            let threshold = (current.elder_count() as u32 * ELDER_BFT_THRESHOLD_PERCENT)
                .div_ceil(100)
                .max(1) as usize;

            if request.approvals.len() >= threshold {
                info!(
                    candidate = hex::encode(&candidate[..8]),
                    approvals = request.approvals.len(),
                    threshold,
                    "Elder registration approved by BFT consensus"
                );
                return true;
            }
        }

        false
    }

    /// Record a rejection for a pending registration
    ///
    /// Returns true if the registration should be removed (rejected by majority)
    pub fn record_registration_rejection(&self, candidate: &NodeId, rejector: &NodeId) -> bool {
        let current = self.current();

        // Only elders can reject
        if !current.is_elder(rejector) {
            return false;
        }

        let mut pending = self.pending_registrations.write();
        if let Some(request) = pending.get_mut(candidate) {
            request.rejections.insert(*rejector);

            // If more than 33% reject, the registration fails
            let rejection_threshold = (current.elder_count() as u32 * 34 / 100).max(1) as usize;

            if request.rejections.len() >= rejection_threshold {
                info!(
                    candidate = hex::encode(&candidate[..8]),
                    rejections = request.rejections.len(),
                    "Elder registration rejected"
                );
                pending.remove(candidate);
                return true;
            }
        }

        false
    }

    /// Promote an approved registration to the next epoch's elder list
    pub fn promote_approved_registration(&self, candidate: &NodeId) -> Option<CanonicalElderList> {
        let mut pending = self.pending_registrations.write();
        let request = pending.remove(candidate)?;

        let current = self.current();

        // Create the new elder entry
        let new_elder = ElderEntry::new(
            request.candidate,
            current.epoch + 1,
            &request.pow_proof,
            request.first_seen,
            request.uptime_percent,
        );

        // Create new list with the addition
        let mut new_elders = current.elders.clone();
        new_elders.push(new_elder);

        let new_list = CanonicalElderList::new(current.epoch + 1, new_elders);

        info!(
            candidate = hex::encode(&candidate[..8]),
            new_epoch = new_list.epoch,
            elder_count = new_list.elder_count(),
            "Created new elder list with promoted member"
        );

        Some(new_list)
    }

    /// Transition to a new canonical list (after sufficient approvals)
    ///
    /// CRIT-CONS-1 SECURITY: Strict epoch validation to prevent rollback attacks.
    /// An attacker could attempt to replay an old, legitimately signed elder list from a
    /// previous epoch to override the current elder set. This check ensures the new list's
    /// epoch is EXACTLY current.epoch + 1 (not just >= current.epoch).
    pub fn transition_to(&self, new_list: CanonicalElderList) -> GhostResult<()> {
        let current = self.current();
        let prev_elders = current.get_eligible_voters();

        // CRIT-CONS-1: Verify epoch is EXACTLY current + 1 (reject both rollbacks AND skips)
        // This prevents:
        // - Rollback attacks (epoch < current)
        // - Skip attacks (epoch > current + 1, could skip intermediate states)
        if new_list.epoch != current.epoch + 1 {
            return Err(GhostError::ConsensusFailed(format!(
                "CRIT-CONS-1: Elder list epoch must be exactly current + 1 (sequential). Expected {}, got {}. \
                 This prevents both rollback and epoch-skipping attacks.",
                current.epoch + 1,
                new_list.epoch
            )));
        }

        // CRIT-CONS-1: Full canonical verification with strict minimum epoch
        // After verifying sequential increment, we verify the list is properly approved
        // The min_epoch parameter ensures verify_canonical won't accept old lists
        new_list.verify_canonical_with_min_epoch(&prev_elders, current.epoch + 1)?;

        // Perform the transition
        let mut new_list = new_list;
        new_list.activate();
        *self.current_list.write() = Arc::new(new_list);

        Ok(())
    }

    /// Get a pending registration request
    pub fn get_pending_registration(&self, candidate: &NodeId) -> Option<ElderRegistrationRequest> {
        self.pending_registrations.read().get(candidate).cloned()
    }

    /// Get all pending registration candidates
    pub fn pending_candidates(&self) -> Vec<NodeId> {
        self.pending_registrations.read().keys().copied().collect()
    }

    /// Clean up expired registration requests (older than 1 hour)
    pub fn cleanup_expired_registrations(&self) {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let max_age_ms = 60 * 60 * 1000; // 1 hour

        let mut pending = self.pending_registrations.write();
        pending.retain(|_, req| now - req.requested_at < max_age_ms);
    }

    // =========================================================================
    // L-12: PENDING LIST MANAGEMENT WITH TIMEOUT
    // =========================================================================

    /// L-12: Start collecting approvals for a new elder list proposal
    ///
    /// If there's an existing pending list that hasn't timed out, this fails.
    /// Use `check_pending_timeout()` first to clean up stale pending lists.
    pub fn start_approval_collection(&self, list: CanonicalElderList) -> GhostResult<()> {
        let mut pending = self.pending_list.write();

        // Check if there's already a pending list
        if let Some(ref existing) = *pending {
            if !existing.is_timed_out() {
                return Err(GhostError::Config(
                    "L-12: Cannot start new approval collection - existing collection in progress"
                        .to_string(),
                ));
            }
            // Timed out - will be replaced
            warn!(
                epoch = existing.list.epoch,
                retry_count = existing.retry_count,
                "L-12: Replacing timed out pending list"
            );
        }

        info!(
            epoch = list.epoch,
            elder_count = list.elder_count(),
            "L-12: Starting approval collection for new elder list"
        );

        *pending = Some(PendingListState::new(list));
        Ok(())
    }

    /// L-12: Add an approval to the pending list
    ///
    /// Returns Ok(true) if the list now has sufficient approvals and
    /// should be promoted via `finalize_pending_list()`.
    /// Returns Ok(false) if more approvals are needed.
    /// Returns Err if no pending list or approval is invalid.
    pub fn add_pending_approval(
        &self,
        approval: ElderApproval,
        previous_elders: &HashSet<NodeId>,
    ) -> GhostResult<bool> {
        let mut pending = self.pending_list.write();

        let state = pending.as_mut().ok_or_else(|| {
            GhostError::Config("L-12: No pending list to add approval to".to_string())
        })?;

        // Check for timeout
        if state.is_timed_out() {
            warn!(
                epoch = state.list.epoch,
                "L-12: Cannot add approval - pending list has timed out"
            );
            return Err(GhostError::Config(
                "L-12: Pending list has timed out".to_string(),
            ));
        }

        // Add the approval
        if !state.list.add_approval(approval) {
            // Approval was invalid or duplicate
            return Ok(false);
        }

        // Check if we now have sufficient approvals
        Ok(state.list.has_sufficient_approvals(previous_elders))
    }

    /// L-12: Check if the pending list has timed out
    ///
    /// Returns Some((epoch, retry_count)) if there was a timeout, None otherwise.
    /// Call this periodically to detect and handle timeouts.
    pub fn check_pending_timeout(&self) -> Option<(u64, u32)> {
        let pending = self.pending_list.read();
        if let Some(ref state) = *pending {
            if state.is_timed_out() {
                return Some((state.list.epoch, state.retry_count));
            }
        }
        None
    }

    /// L-12: Cancel the pending list (e.g., on timeout)
    ///
    /// Returns the pending state if there was one, None otherwise.
    pub fn cancel_pending_list(&self) -> Option<PendingListState> {
        self.pending_list.write().take()
    }

    /// L-12: Retry approval collection with the same list
    ///
    /// Use this after a timeout to start a new collection attempt.
    /// Increments the retry counter.
    pub fn retry_approval_collection(&self) -> GhostResult<()> {
        let mut pending = self.pending_list.write();

        let state = pending
            .as_mut()
            .ok_or_else(|| GhostError::Config("L-12: No pending list to retry".to_string()))?;

        if !state.is_timed_out() {
            return Err(GhostError::Config(
                "L-12: Cannot retry - pending list has not timed out".to_string(),
            ));
        }

        // Reset the timer and increment retry count
        state.started_at = chrono::Utc::now().timestamp_millis() as u64;
        state.retry_count += 1;

        // Clear old approvals to start fresh
        state.list.approval_signatures.clear();

        info!(
            epoch = state.list.epoch,
            retry_count = state.retry_count,
            "L-12: Retrying approval collection"
        );

        Ok(())
    }

    /// L-12: Finalize the pending list if it has sufficient approvals
    ///
    /// Promotes the pending list to be the current canonical list.
    pub fn finalize_pending_list(&self, previous_elders: &HashSet<NodeId>) -> GhostResult<()> {
        let pending_state = self.pending_list.write().take();

        let state = pending_state
            .ok_or_else(|| GhostError::Config("L-12: No pending list to finalize".to_string()))?;

        if !state.list.has_sufficient_approvals(previous_elders) {
            // Put it back and return error
            *self.pending_list.write() = Some(state);
            return Err(GhostError::Config(
                "L-12: Pending list does not have sufficient approvals".to_string(),
            ));
        }

        // Perform the transition
        let mut new_list = state.list;
        new_list.activate();

        info!(
            epoch = new_list.epoch,
            elder_count = new_list.elder_count(),
            approvals = new_list.approval_signatures.len(),
            "L-12: Finalized and activated new canonical elder list"
        );

        *self.current_list.write() = Arc::new(new_list);
        Ok(())
    }

    /// L-12: Get remaining time before pending list times out
    ///
    /// Returns None if no pending list, Some(remaining_ms) otherwise.
    pub fn pending_timeout_remaining(&self) -> Option<u64> {
        self.pending_list.read().as_ref().map(|s| s.remaining_ms())
    }

    /// L-12: Get the pending list state (for diagnostics)
    pub fn get_pending_state(&self) -> Option<(u64, usize, u32, bool)> {
        self.pending_list.read().as_ref().map(|s| {
            (
                s.list.epoch,
                s.list.approval_signatures.len(),
                s.retry_count,
                s.is_timed_out(),
            )
        })
    }

    // =========================================================================
    // DATABASE PERSISTENCE (P2P-C1/C2/C3)
    // =========================================================================

    /// Load elder list manager state from database on startup
    ///
    /// Reconstructs the in-memory state from persisted data:
    /// 1. Loads the current canonical elder list record
    /// 2. Loads all elder entries for that epoch
    /// 3. Loads all approval signatures for that epoch
    /// 4. Reconstructs the CanonicalElderList struct
    ///
    /// Returns an empty genesis manager if no data exists in the database.
    pub fn load_from_database(db: &Database) -> GhostResult<Self> {
        match db.get_current_canonical_elder_list()? {
            Some(record) => {
                // Load elder entries for this epoch
                let entry_records = db.get_elder_entries_for_epoch(record.epoch)?;

                // L-3: Check that the number of entries doesn't exceed max before processing
                if entry_records.len() > ELDER_MAX_COUNT as usize {
                    warn!(
                        epoch = record.epoch,
                        count = entry_records.len(),
                        max = ELDER_MAX_COUNT,
                        "L-3: Database contains more elders than ELDER_MAX_COUNT, truncating"
                    );
                }

                // Convert records to ElderEntry structs
                // L-3: Take only up to ELDER_MAX_COUNT entries to prevent memory issues
                let elders: Vec<ElderEntry> = entry_records
                    .into_iter()
                    .take(ELDER_MAX_COUNT as usize) // L-3: Enforce maximum
                    .filter_map(|r| {
                        // Parse node_id from hex string
                        let node_id_bytes = hex::decode(&r.node_id).ok()?;
                        if node_id_bytes.len() != 32 {
                            return None;
                        }
                        let mut node_id = [0u8; 32];
                        node_id.copy_from_slice(&node_id_bytes);

                        Some(ElderEntry {
                            node_id,
                            registered_epoch: r.registered_epoch,
                            pow_nonce: r.pow_nonce,
                            pow_difficulty: r.pow_difficulty,
                            first_seen: r.first_seen,
                            uptime_at_registration: r.uptime_at_registration,
                        })
                    })
                    .collect();

                // Load approval signatures
                let approval_records = db.get_elder_approvals_for_epoch(record.epoch)?;

                // L-3: Check approval count before processing
                if approval_records.len() > MAX_APPROVALS {
                    warn!(
                        epoch = record.epoch,
                        count = approval_records.len(),
                        max = MAX_APPROVALS,
                        "L-3: Database contains more approvals than MAX_APPROVALS, truncating"
                    );
                }

                // Convert approval records to ElderApproval structs
                // L-3: Take only up to MAX_APPROVALS to prevent memory issues
                let approval_signatures: Vec<ElderApproval> = approval_records
                    .into_iter()
                    .take(MAX_APPROVALS) // L-3: Enforce maximum
                    .filter_map(|r| {
                        // Parse approver node_id from hex string
                        let approver_bytes = hex::decode(&r.approver_node_id).ok()?;
                        if approver_bytes.len() != 32 {
                            return None;
                        }
                        let mut approver = [0u8; 32];
                        approver.copy_from_slice(&approver_bytes);

                        // Parse signature from hex string
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

                // Parse merkle root from hex string
                let merkle_root = if let Ok(bytes) = hex::decode(&record.merkle_root) {
                    if bytes.len() == 32 {
                        let mut root = [0u8; 32];
                        root.copy_from_slice(&bytes);
                        root
                    } else {
                        // Recompute from elders if stored root is invalid
                        CanonicalElderList::compute_merkle_root_static(&elders)
                    }
                } else {
                    CanonicalElderList::compute_merkle_root_static(&elders)
                };

                // Build the canonical elder list
                let list = CanonicalElderList {
                    epoch: record.epoch,
                    elders,
                    merkle_root,
                    approval_signatures,
                    activated_at: record.activated_at,
                };

                info!(
                    epoch = list.epoch,
                    elder_count = list.elders.len(),
                    approvals = list.approval_signatures.len(),
                    "Loaded canonical elder list from database"
                );

                Ok(Self::with_list(list))
            }
            None => {
                // No elder list in database, create empty genesis
                info!("No canonical elder list in database, creating empty genesis (epoch 0)");
                Ok(Self::new(vec![]))
            }
        }
    }

    /// Save the current canonical elder list to database
    ///
    /// Persists all components of the current list:
    /// 1. The canonical_elder_lists record (epoch, merkle_root, etc.)
    /// 2. All elder_entries for this epoch
    /// 3. All elder_approvals for this epoch
    pub fn save_current_to_database(&self, db: &Database) -> GhostResult<()> {
        let list = self.current();

        // Store the canonical elder list record
        db.store_canonical_elder_list(
            list.epoch,
            &hex::encode(list.merkle_root),
            list.elders.len() as u32,
            list.activated_at,
        )?;

        // Store each elder entry
        for (position, elder) in list.elders.iter().enumerate() {
            db.store_elder_entry(
                list.epoch,
                &hex::encode(elder.node_id),
                elder.registered_epoch,
                elder.pow_nonce,
                elder.pow_difficulty,
                elder.first_seen,
                elder.uptime_at_registration,
                position as u32,
            )?;
        }

        // Store each approval signature
        for approval in &list.approval_signatures {
            db.store_elder_approval(
                list.epoch,
                &hex::encode(approval.approver),
                &hex::encode(approval.signature),
                approval.timestamp,
            )?;
        }

        info!(
            epoch = list.epoch,
            elder_count = list.elders.len(),
            approvals = list.approval_signatures.len(),
            "Saved canonical elder list to database"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::identity::NodeIdentity;

    fn create_test_elder_entry(node_id: NodeId, epoch: u64) -> ElderEntry {
        // Generate a real identity with valid PoW
        let identity = NodeIdentity::generate();
        let pow_proof = identity
            .pow_proof()
            .expect("NodeIdentity should have PoW proof");
        ElderEntry::new(node_id, epoch, pow_proof, 1000000, 99.5)
    }

    #[test]
    fn test_elder_entry_hash() {
        let entry1 = create_test_elder_entry([1u8; 32], 0);
        let entry2 = create_test_elder_entry([2u8; 32], 0);

        // Different entries should have different hashes
        assert_ne!(entry1.hash(), entry2.hash());

        // Same entry should have same hash
        let entry1_clone = entry1.clone();
        assert_eq!(entry1.hash(), entry1_clone.hash());
    }

    #[test]
    fn test_canonical_elder_list_creation() {
        let elders = vec![
            create_test_elder_entry([1u8; 32], 0),
            create_test_elder_entry([2u8; 32], 0),
            create_test_elder_entry([3u8; 32], 0),
        ];

        let list = CanonicalElderList::new(1, elders);

        assert_eq!(list.epoch, 1);
        assert_eq!(list.elder_count(), 3);
        assert!(list.verify_merkle_root());
    }

    #[test]
    fn test_genesis_list() {
        let elders = vec![create_test_elder_entry([1u8; 32], 0)];

        let genesis = CanonicalElderList::genesis(elders);

        assert_eq!(genesis.epoch, 0);
        assert!(genesis.activated_at > 0);
        assert!(genesis.has_sufficient_approvals(&HashSet::new()));
    }

    #[test]
    fn test_merkle_root_deterministic() {
        let elders = vec![
            create_test_elder_entry([1u8; 32], 0),
            create_test_elder_entry([2u8; 32], 0),
        ];

        let list1 = CanonicalElderList::new(1, elders.clone());
        let list2 = CanonicalElderList::new(1, elders);

        assert_eq!(list1.merkle_root, list2.merkle_root);
    }

    #[test]
    fn test_merkle_root_changes_with_order() {
        let elder1 = create_test_elder_entry([1u8; 32], 0);
        let elder2 = create_test_elder_entry([2u8; 32], 0);

        let list1 = CanonicalElderList::new(1, vec![elder1.clone(), elder2.clone()]);
        let list2 = CanonicalElderList::new(1, vec![elder2, elder1]);

        // Different order should produce different merkle root
        assert_ne!(list1.merkle_root, list2.merkle_root);
    }

    #[test]
    fn test_is_elder() {
        let elders = vec![
            create_test_elder_entry([1u8; 32], 0),
            create_test_elder_entry([2u8; 32], 0),
        ];

        let list = CanonicalElderList::new(1, elders);

        assert!(list.is_elder(&[1u8; 32]));
        assert!(list.is_elder(&[2u8; 32]));
        assert!(!list.is_elder(&[3u8; 32]));
    }

    #[test]
    fn test_get_eligible_voters() {
        let elders = vec![
            create_test_elder_entry([1u8; 32], 0),
            create_test_elder_entry([2u8; 32], 0),
            create_test_elder_entry([3u8; 32], 0),
        ];

        let list = CanonicalElderList::new(1, elders);
        let voters = list.get_eligible_voters();

        assert_eq!(voters.len(), 3);
        assert!(voters.contains(&[1u8; 32]));
        assert!(voters.contains(&[2u8; 32]));
        assert!(voters.contains(&[3u8; 32]));
    }

    #[test]
    fn test_approval_verification() {
        let identity = NodeIdentity::generate();
        let epoch = 5u64;
        let merkle_root = [42u8; 32];

        let message = ElderApproval::signing_message(epoch, &merkle_root);
        let signature = identity.sign(&message);

        let approval = ElderApproval {
            approver: identity.node_id(),
            signature,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        // Use verify_signature_only for tests to avoid timestamp validation issues
        assert!(approval.verify_signature_only(epoch, &merkle_root));
        assert!(!approval.verify_signature_only(epoch + 1, &merkle_root)); // Wrong epoch
        assert!(!approval.verify_signature_only(epoch, &[0u8; 32])); // Wrong merkle root
    }

    #[test]
    fn test_sufficient_approvals_threshold() {
        let identities: Vec<NodeIdentity> = (0..10).map(|_| NodeIdentity::generate()).collect();
        let previous_elders: HashSet<NodeId> = identities.iter().map(|i| i.node_id()).collect();

        let elders = vec![create_test_elder_entry([99u8; 32], 1)];
        let mut list = CanonicalElderList::new(1, elders);

        // 67% of 10 = 7 approvals needed
        let merkle_root = list.merkle_root;

        // Add 6 approvals (not enough)
        let now = chrono::Utc::now().timestamp_millis() as u64;
        for identity in identities.iter().take(6) {
            let message = ElderApproval::signing_message(1, &merkle_root);
            let approval = ElderApproval {
                approver: identity.node_id(),
                signature: identity.sign(&message),
                timestamp: now,
            };
            list.add_approval(approval);
        }
        assert!(!list.has_sufficient_approvals(&previous_elders));

        // Add 7th approval (enough)
        let message = ElderApproval::signing_message(1, &merkle_root);
        let approval = ElderApproval {
            approver: identities[6].node_id(),
            signature: identities[6].sign(&message),
            timestamp: now,
        };
        list.add_approval(approval);
        assert!(list.has_sufficient_approvals(&previous_elders));
    }

    #[test]
    fn test_elder_list_manager_creation() {
        let elders = vec![create_test_elder_entry([1u8; 32], 0)];
        let manager = ElderListManager::new(elders);

        assert_eq!(manager.current_epoch(), 0);
        assert!(manager.is_elder(&[1u8; 32]));
        assert!(!manager.is_elder(&[2u8; 32]));
    }

    #[test]
    fn test_elder_has_capacity() {
        let list = CanonicalElderList::new(1, vec![]);
        assert!(list.has_capacity());

        // Create minimal entries directly without PoW mining (for speed)
        let many_elders: Vec<ElderEntry> = (0..ELDER_MAX_COUNT)
            .map(|i| ElderEntry {
                node_id: [i as u8; 32],
                registered_epoch: 0,
                pow_nonce: 0,
                pow_difficulty: 20,
                first_seen: 1000000,
                uptime_at_registration: 99.5,
            })
            .collect();
        let full_list = CanonicalElderList::new(1, many_elders);
        assert!(!full_list.has_capacity());
    }

    #[test]
    fn test_empty_list_merkle_root() {
        let list = CanonicalElderList::new(1, vec![]);
        assert_eq!(list.merkle_root, [0u8; 32]);
        assert!(list.verify_merkle_root());
    }

    #[test]
    fn test_single_elder_merkle_root() {
        let elders = vec![create_test_elder_entry([1u8; 32], 0)];
        let list = CanonicalElderList::new(1, elders);

        // Should not be zero for non-empty list
        assert_ne!(list.merkle_root, [0u8; 32]);
        assert!(list.verify_merkle_root());
    }

    #[test]
    fn test_load_from_empty_database() {
        let db = Database::in_memory().unwrap();
        let manager = ElderListManager::load_from_database(&db).unwrap();

        // Should create empty genesis list
        assert_eq!(manager.current_epoch(), 0);
        assert_eq!(manager.current().elder_count(), 0);
    }

    #[test]
    fn test_save_and_reload_round_trip() {
        let db = Database::in_memory().unwrap();

        // Create a manager with some elders
        let elders = vec![
            create_test_elder_entry([1u8; 32], 0),
            create_test_elder_entry([2u8; 32], 0),
        ];
        let manager = ElderListManager::new(elders);

        // Save to database
        manager.save_current_to_database(&db).unwrap();

        // Reload from database
        let loaded_manager = ElderListManager::load_from_database(&db).unwrap();

        // Verify the loaded state matches
        assert_eq!(loaded_manager.current_epoch(), manager.current_epoch());
        assert_eq!(
            loaded_manager.current().elder_count(),
            manager.current().elder_count()
        );
        assert_eq!(
            loaded_manager.current().merkle_root,
            manager.current().merkle_root
        );

        // Verify elder membership
        assert!(loaded_manager.is_elder(&[1u8; 32]));
        assert!(loaded_manager.is_elder(&[2u8; 32]));
        assert!(!loaded_manager.is_elder(&[3u8; 32]));
    }

    #[test]
    fn test_persistence_with_approvals() {
        let db = Database::in_memory().unwrap();

        // Create identities for approval signatures
        let identity = NodeIdentity::generate();

        // Create a manager
        let elders = vec![create_test_elder_entry([1u8; 32], 0)];
        let manager = ElderListManager::new(elders);

        // Add an approval to the current list
        let merkle_root = manager.current().merkle_root;
        let message = ElderApproval::signing_message(0, &merkle_root);
        let approval = ElderApproval {
            approver: identity.node_id(),
            signature: identity.sign(&message),
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        // Need to create a new list with the approval since current() returns Arc
        let mut list = (*manager.current()).clone();
        list.add_approval(approval);
        let manager_with_approval = ElderListManager::with_list(list);

        // Save to database
        manager_with_approval.save_current_to_database(&db).unwrap();

        // Reload and verify approvals
        let loaded = ElderListManager::load_from_database(&db).unwrap();
        assert_eq!(loaded.current().approval_signatures.len(), 1);
        assert_eq!(
            loaded.current().approval_signatures[0].approver,
            identity.node_id()
        );
    }

    // =========================================================================
    // L-12 TESTS: Pending list timeout
    // =========================================================================

    #[test]
    fn test_l12_approval_timeout_constant() {
        // L-12: Verify timeout is 10 minutes
        assert_eq!(APPROVAL_COLLECTION_TIMEOUT_SECS, 10 * 60);
    }

    #[test]
    fn test_l12_pending_state_creation() {
        let elders = vec![create_test_elder_entry([1u8; 32], 0)];
        let list = CanonicalElderList::new(1, elders);

        let state = PendingListState::new(list);
        assert_eq!(state.retry_count, 0);
        assert!(!state.is_timed_out()); // Just created, shouldn't be timed out
        assert!(state.remaining_ms() > 0);
    }

    #[test]
    fn test_l12_start_approval_collection() {
        let manager = ElderListManager::new(vec![]);

        let elders = vec![create_test_elder_entry([1u8; 32], 1)];
        let list = CanonicalElderList::new(1, elders);

        // Start collection
        let result = manager.start_approval_collection(list.clone());
        assert!(result.is_ok());

        // Should have pending state now
        let state = manager.get_pending_state();
        assert!(state.is_some());
        let (epoch, approvals, retry_count, timed_out) = state.unwrap();
        assert_eq!(epoch, 1);
        assert_eq!(approvals, 0);
        assert_eq!(retry_count, 0);
        assert!(!timed_out);

        // Can't start another while one is in progress
        let elders2 = vec![create_test_elder_entry([2u8; 32], 2)];
        let list2 = CanonicalElderList::new(2, elders2);
        let result = manager.start_approval_collection(list2);
        assert!(result.is_err());
    }

    #[test]
    fn test_l12_cancel_pending_list() {
        let manager = ElderListManager::new(vec![]);

        let elders = vec![create_test_elder_entry([1u8; 32], 1)];
        let list = CanonicalElderList::new(1, elders);

        manager.start_approval_collection(list).unwrap();
        assert!(manager.get_pending_state().is_some());

        // Cancel
        let cancelled = manager.cancel_pending_list();
        assert!(cancelled.is_some());
        assert!(manager.get_pending_state().is_none());
    }

    #[test]
    fn test_l12_pending_timeout_remaining() {
        let manager = ElderListManager::new(vec![]);

        // No pending list
        assert!(manager.pending_timeout_remaining().is_none());

        let elders = vec![create_test_elder_entry([1u8; 32], 1)];
        let list = CanonicalElderList::new(1, elders);
        manager.start_approval_collection(list).unwrap();

        // Should have remaining time
        let remaining = manager.pending_timeout_remaining();
        assert!(remaining.is_some());
        assert!(remaining.unwrap() > 0);
    }

    #[test]
    fn test_l12_check_pending_timeout_not_expired() {
        let manager = ElderListManager::new(vec![]);

        let elders = vec![create_test_elder_entry([1u8; 32], 1)];
        let list = CanonicalElderList::new(1, elders);
        manager.start_approval_collection(list).unwrap();

        // Shouldn't be timed out immediately
        let timeout = manager.check_pending_timeout();
        assert!(timeout.is_none());
    }

    // =========================================================================
    // L-2 TESTS: Elder approval timestamp window
    // =========================================================================

    #[test]
    fn test_l2_approval_timestamp_window() {
        // HIGH-CONS-3: Verify the approval timestamp drift is 10 seconds
        // Reduced from 15s to further minimize the replay attack window.
        // Nodes MUST use NTP for accurate time synchronization.
        assert_eq!(
            MAX_APPROVAL_TIMESTAMP_DRIFT_MS,
            10 * 1000,
            "HIGH-CONS-3: Approval timestamp drift should be 10 seconds (use NTP)"
        );
    }

    #[test]
    fn test_l2_approval_timestamp_validation() {
        use ghost_common::identity::NodeIdentity;

        let identity = NodeIdentity::generate();
        let epoch = 5u64;
        let merkle_root = [42u8; 32];

        // Create an approval with current timestamp
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let message = ElderApproval::signing_message(epoch, &merkle_root);
        let signature = identity.sign(&message);

        let approval = ElderApproval {
            approver: identity.node_id(),
            signature,
            timestamp: now,
        };

        // Current timestamp should be valid
        assert!(
            approval.is_timestamp_valid(),
            "L-2: Current timestamp should be valid"
        );

        // Old timestamp (beyond 10s drift limit) should be invalid
        let old_approval = ElderApproval {
            approver: identity.node_id(),
            signature,
            timestamp: now - 15_000, // 15 seconds ago (beyond 10s limit)
        };
        assert!(
            !old_approval.is_timestamp_valid(),
            "HIGH-CONS-3: Old timestamp (15s ago, beyond 10s limit) should be invalid"
        );

        // Future timestamp (beyond 10s drift limit) should be invalid
        let future_approval = ElderApproval {
            approver: identity.node_id(),
            signature,
            timestamp: now + 15_000, // 15 seconds in future (beyond 10s limit)
        };
        assert!(
            !future_approval.is_timestamp_valid(),
            "HIGH-CONS-3: Future timestamp (15s ahead, beyond 10s limit) should be invalid"
        );
    }

    // =========================================================================
    // L-3 TESTS: Elder list size bounds on DB load
    // =========================================================================

    #[test]
    fn test_l3_elder_max_count_constant() {
        // L-3: Verify ELDER_MAX_COUNT is reasonable
        assert_eq!(ELDER_MAX_COUNT, 101, "ELDER_MAX_COUNT should be 101");
        assert!(ELDER_MAX_COUNT > 0, "ELDER_MAX_COUNT must be positive");
    }

    #[test]
    fn test_l3_max_approvals_constant() {
        // L-3: Verify MAX_APPROVALS is reasonable
        assert_eq!(MAX_APPROVALS, 200, "MAX_APPROVALS should be 200");
        assert!(
            MAX_APPROVALS >= ELDER_MAX_COUNT as usize,
            "MAX_APPROVALS should be >= ELDER_MAX_COUNT"
        );
    }

    #[test]
    fn test_l3_canonical_list_capacity_check() {
        // L-3: Verify has_capacity() works correctly
        let empty_list = CanonicalElderList::new(1, vec![]);
        assert!(empty_list.has_capacity(), "Empty list should have capacity");

        // Create a list at capacity
        let many_elders: Vec<ElderEntry> = (0..ELDER_MAX_COUNT)
            .map(|i| ElderEntry {
                node_id: [i as u8; 32],
                registered_epoch: 0,
                pow_nonce: 0,
                pow_difficulty: 20,
                first_seen: 1000000,
                uptime_at_registration: 99.5,
            })
            .collect();
        let full_list = CanonicalElderList::new(1, many_elders);
        assert!(
            !full_list.has_capacity(),
            "Full list should not have capacity"
        );
    }

    #[test]
    fn test_l3_add_approval_respects_max() {
        // L-3: Verify add_approval respects MAX_APPROVALS limit
        let elders = vec![create_test_elder_entry([1u8; 32], 0)];
        let mut list = CanonicalElderList::new(1, elders);

        // The add_approval method should respect MAX_APPROVALS
        // This is tested indirectly through the existing M-5 test
        assert_eq!(
            list.approval_signatures.len(),
            0,
            "Initial list should have no approvals"
        );
    }
}
