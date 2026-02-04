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

/// Maximum number of elders (from ghost_common::constants)
pub const ELDER_MAX_COUNT: u32 = 101;

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
        hasher.update(&self.node_id);
        hasher.update(&self.registered_epoch.to_le_bytes());
        hasher.update(&self.first_seen.to_le_bytes());
        hasher.finalize().into()
    }
}

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

    /// Verify this approval signature
    pub fn verify(&self, epoch: u64, merkle_root: &[u8; 32]) -> bool {
        let message = Self::signing_message(epoch, merkle_root);
        verify_signature(&self.approver, &message, &self.signature).unwrap_or(false)
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
    fn compute_merkle_root_static(elders: &[ElderEntry]) -> [u8; 32] {
        if elders.is_empty() {
            return [0u8; 32];
        }

        // Get leaf hashes
        let mut hashes: Vec<[u8; 32]> = elders.iter().map(|e| e.hash()).collect();

        // Pad to power of 2 if needed
        while hashes.len() & (hashes.len() - 1) != 0 && !hashes.is_empty() {
            hashes.push([0u8; 32]);
        }

        // Build merkle tree bottom-up
        while hashes.len() > 1 {
            let mut next_level = Vec::with_capacity(hashes.len() / 2);
            for chunk in hashes.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(MERKLE_DOMAIN);
                hasher.update(&chunk[0]);
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
    pub fn add_approval(&mut self, approval: ElderApproval) -> bool {
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

        // Use ceiling division: (n * 67 + 99) / 100 ensures we round up
        let threshold =
            ((previous_elders.len() as u32 * ELDER_BFT_THRESHOLD_PERCENT + 99) / 100).max(1)
                as usize;

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
}

/// Manages the canonical elder list state and transitions
pub struct ElderListManager {
    /// Current canonical elder list
    current_list: RwLock<Arc<CanonicalElderList>>,
    /// Pending list being voted on (if any)
    pending_list: RwLock<Option<CanonicalElderList>>,
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

        self.pending_registrations.write().insert(candidate, request);

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
            let threshold = ((current.elder_count() as u32 * ELDER_BFT_THRESHOLD_PERCENT + 99)
                / 100)
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
    pub fn transition_to(&self, new_list: CanonicalElderList) -> GhostResult<()> {
        let current = self.current();

        // Verify the new list
        if !new_list.verify_merkle_root() {
            return Err(GhostError::Config("Invalid merkle root".to_string()));
        }

        // Verify sufficient approvals
        let prev_elders = current.get_eligible_voters();
        if !new_list.has_sufficient_approvals(&prev_elders) {
            return Err(GhostError::Config(
                "Insufficient approvals for transition".to_string(),
            ));
        }

        // Verify epoch is sequential
        if new_list.epoch != current.epoch + 1 {
            return Err(GhostError::Config(format!(
                "Epoch must be sequential: expected {}, got {}",
                current.epoch + 1,
                new_list.epoch
            )));
        }

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
        self.pending_registrations
            .read()
            .keys()
            .copied()
            .collect()
    }

    /// Clean up expired registration requests (older than 1 hour)
    pub fn cleanup_expired_registrations(&self) {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let max_age_ms = 60 * 60 * 1000; // 1 hour

        let mut pending = self.pending_registrations.write();
        pending.retain(|_, req| now - req.requested_at < max_age_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::identity::NodeIdentity;

    fn create_test_elder_entry(node_id: NodeId, epoch: u64) -> ElderEntry {
        // Generate a real identity with valid PoW
        let identity = NodeIdentity::generate();
        let pow_proof = identity.pow_proof().expect("NodeIdentity should have PoW proof");
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
            timestamp: 1000,
        };

        assert!(approval.verify(epoch, &merkle_root));
        assert!(!approval.verify(epoch + 1, &merkle_root)); // Wrong epoch
        assert!(!approval.verify(epoch, &[0u8; 32])); // Wrong merkle root
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
        for identity in identities.iter().take(6) {
            let message = ElderApproval::signing_message(1, &merkle_root);
            let approval = ElderApproval {
                approver: identity.node_id(),
                signature: identity.sign(&message),
                timestamp: 1000,
            };
            list.add_approval(approval);
        }
        assert!(!list.has_sufficient_approvals(&previous_elders));

        // Add 7th approval (enough)
        let message = ElderApproval::signing_message(1, &merkle_root);
        let approval = ElderApproval {
            approver: identities[6].node_id(),
            signature: identities[6].sign(&message),
            timestamp: 1000,
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
}
