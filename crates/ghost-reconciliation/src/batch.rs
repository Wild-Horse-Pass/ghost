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
//| FILE: batch.rs                                                                                                       |
//|======================================================================================================================|

//! Batch management for settlements

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{ReconciliationError, ReconciliationResult};
use crate::settlement::Settlement;
use crate::{DISPUTE_WINDOW_BLOCKS, MAX_BATCH_SIZE, MIN_BATCH_SIZE};

/// Batch state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BatchState {
    /// Collecting settlements
    Collecting,
    /// Ready for L1 submission
    Ready,
    /// Submitted to L1, awaiting confirmation
    Submitted,
    /// Confirmed on L1, in dispute window
    Confirming,
    /// Dispute window passed, finalized
    Finalized,
    /// Batch was disputed and rejected
    Rejected,
}

impl BatchState {
    /// Check if batch is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(self, BatchState::Finalized | BatchState::Rejected)
    }

    /// Get state name
    pub fn name(&self) -> &'static str {
        match self {
            BatchState::Collecting => "Collecting",
            BatchState::Ready => "Ready",
            BatchState::Submitted => "Submitted",
            BatchState::Confirming => "Confirming",
            BatchState::Finalized => "Finalized",
            BatchState::Rejected => "Rejected",
        }
    }
}

impl std::fmt::Display for BatchState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// A batch of settlements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Batch {
    /// Unique batch ID
    id: [u8; 32],
    /// Current state
    state: BatchState,
    /// Settlement hashes in this batch
    settlement_hashes: Vec<[u8; 32]>,
    /// Merkle root
    merkle_root: Option<[u8; 32]>,
    /// Total amount in batch
    total_amount_sats: u64,
    /// Total fees in batch
    total_fee_sats: u64,
    /// Created timestamp
    created_at: u64,
    /// Updated timestamp
    updated_at: u64,
    /// L1 transaction ID
    l1_txid: Option<String>,
    /// L1 confirmation height
    l1_height: Option<u32>,
    /// Dispute deadline height
    dispute_deadline: Option<u32>,
}

impl Batch {
    /// Create a new batch
    pub fn new() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Generate unique ID
        let mut hasher = Sha256::new();
        hasher.update(b"batch");
        hasher.update(now.to_le_bytes());
        hasher.update(rand_bytes());
        let id: [u8; 32] = hasher.finalize().into();

        Self {
            id,
            state: BatchState::Collecting,
            settlement_hashes: Vec::new(),
            merkle_root: None,
            total_amount_sats: 0,
            total_fee_sats: 0,
            created_at: now,
            updated_at: now,
            l1_txid: None,
            l1_height: None,
            dispute_deadline: None,
        }
    }

    /// Get batch ID
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// Get batch ID as hex
    pub fn id_hex(&self) -> String {
        hex::encode(self.id)
    }

    /// Get current state
    pub fn state(&self) -> BatchState {
        self.state
    }

    /// Get settlement count
    pub fn settlement_count(&self) -> usize {
        self.settlement_hashes.len()
    }

    /// Get settlement hashes
    pub fn settlement_hashes(&self) -> &[[u8; 32]] {
        &self.settlement_hashes
    }

    /// Get merkle root
    pub fn merkle_root(&self) -> Option<&[u8; 32]> {
        self.merkle_root.as_ref()
    }

    /// Get total amount
    pub fn total_amount_sats(&self) -> u64 {
        self.total_amount_sats
    }

    /// Get total fees
    pub fn total_fee_sats(&self) -> u64 {
        self.total_fee_sats
    }

    /// Get L1 transaction ID
    pub fn l1_txid(&self) -> Option<&str> {
        self.l1_txid.as_deref()
    }

    /// Get L1 confirmation height
    pub fn l1_height(&self) -> Option<u32> {
        self.l1_height
    }

    /// Get dispute deadline
    pub fn dispute_deadline(&self) -> Option<u32> {
        self.dispute_deadline
    }

    /// Check if batch can accept more settlements
    pub fn can_accept(&self) -> bool {
        self.state == BatchState::Collecting && self.settlement_hashes.len() < MAX_BATCH_SIZE
    }

    /// Check if batch has minimum settlements
    pub fn has_minimum(&self) -> bool {
        self.settlement_hashes.len() >= MIN_BATCH_SIZE
    }

    /// Check if batch is full
    pub fn is_full(&self) -> bool {
        self.settlement_hashes.len() >= MAX_BATCH_SIZE
    }

    /// Add a settlement to the batch
    pub fn add_settlement(&mut self, settlement: &Settlement) -> ReconciliationResult<()> {
        if !self.can_accept() {
            return Err(ReconciliationError::BatchTooLarge {
                size: self.settlement_hashes.len() + 1,
                maximum: MAX_BATCH_SIZE,
            });
        }

        self.settlement_hashes.push(settlement.hash());
        self.total_amount_sats += settlement.amount_sats();
        self.total_fee_sats += settlement.fee_sats();
        self.updated_at = Self::now();

        Ok(())
    }

    /// Seal the batch (compute merkle root)
    pub fn seal(&mut self) -> ReconciliationResult<()> {
        if self.state != BatchState::Collecting {
            return Err(ReconciliationError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Ready".to_string(),
            });
        }

        if !self.has_minimum() {
            return Err(ReconciliationError::BatchTooSmall {
                size: self.settlement_hashes.len(),
                minimum: MIN_BATCH_SIZE,
            });
        }

        // Compute merkle root
        self.merkle_root = Some(compute_merkle_root(&self.settlement_hashes));
        self.state = BatchState::Ready;
        self.updated_at = Self::now();

        Ok(())
    }

    /// Mark as submitted to L1
    pub fn mark_submitted(&mut self, l1_txid: String) -> ReconciliationResult<()> {
        if self.state != BatchState::Ready {
            return Err(ReconciliationError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Submitted".to_string(),
            });
        }

        self.state = BatchState::Submitted;
        self.l1_txid = Some(l1_txid);
        self.updated_at = Self::now();

        Ok(())
    }

    /// Mark as confirmed on L1
    pub fn mark_confirmed(&mut self, l1_height: u32) -> ReconciliationResult<()> {
        if self.state != BatchState::Submitted {
            return Err(ReconciliationError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Confirming".to_string(),
            });
        }

        self.state = BatchState::Confirming;
        self.l1_height = Some(l1_height);
        self.dispute_deadline = Some(l1_height + DISPUTE_WINDOW_BLOCKS);
        self.updated_at = Self::now();

        Ok(())
    }

    /// Mark as finalized
    pub fn mark_finalized(&mut self) -> ReconciliationResult<()> {
        if self.state != BatchState::Confirming {
            return Err(ReconciliationError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Finalized".to_string(),
            });
        }

        self.state = BatchState::Finalized;
        self.updated_at = Self::now();

        Ok(())
    }

    /// Mark as rejected (disputed)
    pub fn mark_rejected(&mut self) -> ReconciliationResult<()> {
        if self.state.is_terminal() {
            return Err(ReconciliationError::AlreadyFinalized { id: self.id_hex() });
        }

        self.state = BatchState::Rejected;
        self.updated_at = Self::now();

        Ok(())
    }

    /// Check if dispute window has passed at given height
    pub fn is_dispute_window_passed(&self, current_height: u32) -> bool {
        match self.dispute_deadline {
            Some(deadline) => current_height >= deadline,
            None => false,
        }
    }

    /// Get merkle proof for a settlement
    ///
    /// Returns (proof, index, leaf_count) if settlement found.
    /// The leaf_count is required for collision-resistant verification.
    pub fn get_merkle_proof(
        &self,
        settlement_hash: &[u8; 32],
    ) -> Option<(Vec<[u8; 32]>, usize, usize)> {
        let index = self
            .settlement_hashes
            .iter()
            .position(|h| h == settlement_hash)?;
        let proof = compute_merkle_proof(&self.settlement_hashes, index);
        let leaf_count = self.settlement_hashes.len();
        Some((proof, index, leaf_count))
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

impl Default for Batch {
    fn default() -> Self {
        Self::new()
    }
}

/// Domain separator for Ghost settlement merkle trees
const MERKLE_DOMAIN: &[u8] = b"GhostSettlementMerkle";

/// Compute merkle root from leaf hashes
///
/// This implementation is collision-resistant by:
/// 1. Including leaf count in the final hash (prevents [A,B,C] == [A,B,C,C])
/// 2. Using domain separation (prevents cross-protocol attacks)
/// 3. Carrying forward odd elements instead of duplicating (prevents internal collisions)
pub fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        // Empty tree has deterministic zero root with domain separation
        let mut hasher = Sha256::new();
        hasher.update(MERKLE_DOMAIN);
        hasher.update(0u64.to_le_bytes());
        return hasher.finalize().into();
    }

    if leaves.len() == 1 {
        // Single leaf: hash with domain and count
        let mut hasher = Sha256::new();
        hasher.update(MERKLE_DOMAIN);
        hasher.update(1u64.to_le_bytes());
        hasher.update(leaves[0]);
        return hasher.finalize().into();
    }

    // Store original count for final hash
    let leaf_count = leaves.len() as u64;

    let mut current_level = leaves.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();

        let mut i = 0;
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                // Two elements: hash them together
                let mut hasher = Sha256::new();
                hasher.update(current_level[i]);
                hasher.update(current_level[i + 1]);
                next_level.push(hasher.finalize().into());
                i += 2;
            } else {
                // Odd element: carry forward WITHOUT duplicating
                // This prevents [A,B,C] from colliding with [A,B,C,C]
                next_level.push(current_level[i]);
                i += 1;
            }
        }

        current_level = next_level;
    }

    // Final hash includes domain separator and leaf count
    // This makes roots unique per list length
    let mut final_hasher = Sha256::new();
    final_hasher.update(MERKLE_DOMAIN);
    final_hasher.update(leaf_count.to_le_bytes());
    final_hasher.update(current_level[0]);
    final_hasher.finalize().into()
}

/// Compute merkle proof for an element at given index
///
/// The proof includes sibling hashes needed to recompute the root.
/// For odd elements that are carried forward, we use a special marker.
pub fn compute_merkle_proof(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    if leaves.is_empty() || index >= leaves.len() {
        return vec![];
    }

    let mut proof = Vec::new();
    let mut current_level = leaves.to_vec();
    let mut idx = index;

    while current_level.len() > 1 {
        let sibling_idx = if idx.is_multiple_of(2) {
            idx + 1
        } else {
            idx - 1
        };

        if sibling_idx < current_level.len() {
            // Normal case: include sibling
            proof.push(current_level[sibling_idx]);
        }
        // If no sibling (odd element at end), don't add anything
        // The verifier will know to carry forward

        // Build next level (same algorithm as compute_merkle_root)
        let mut next_level = Vec::new();
        let mut i = 0;
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                let mut hasher = Sha256::new();
                hasher.update(current_level[i]);
                hasher.update(current_level[i + 1]);
                next_level.push(hasher.finalize().into());
                i += 2;
            } else {
                // Carry forward odd element
                next_level.push(current_level[i]);
                i += 1;
            }
        }

        current_level = next_level;
        idx /= 2;
    }

    proof
}

/// Verify a merkle proof
///
/// The proof must be verified against the original leaf count to prevent
/// collision attacks where [A,B,C] could be confused with [A,B,C,C].
pub fn verify_merkle_proof(
    leaf: &[u8; 32],
    proof: &[[u8; 32]],
    root: &[u8; 32],
    index: usize,
    leaf_count: usize,
) -> bool {
    if leaf_count == 0 || index >= leaf_count {
        return false;
    }

    let mut current = *leaf;
    let mut idx = index;
    let mut level_size = leaf_count;
    let mut proof_idx = 0;

    while level_size > 1 {
        let is_right = idx % 2 == 1;
        let has_sibling = if is_right {
            true // Right nodes always have a left sibling
        } else {
            idx + 1 < level_size // Left nodes only have sibling if not at end
        };

        if has_sibling {
            if proof_idx >= proof.len() {
                return false; // Proof too short
            }
            let sibling = &proof[proof_idx];
            proof_idx += 1;

            let mut hasher = Sha256::new();
            if is_right {
                hasher.update(sibling);
                hasher.update(current);
            } else {
                hasher.update(current);
                hasher.update(sibling);
            }
            current = hasher.finalize().into();
        }
        // If no sibling, current is carried forward unchanged

        idx /= 2;
        level_size = level_size.div_ceil(2);
    }

    // Final hash must include domain and leaf count
    let mut final_hasher = Sha256::new();
    final_hasher.update(MERKLE_DOMAIN);
    final_hasher.update((leaf_count as u64).to_le_bytes());
    final_hasher.update(current);
    let computed_root: [u8; 32] = final_hasher.finalize().into();

    &computed_root == root
}

fn rand_bytes() -> [u8; 8] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    (now as u64).to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_creation() {
        let batch = Batch::new();
        assert_eq!(batch.state(), BatchState::Collecting);
        assert_eq!(batch.settlement_count(), 0);
    }

    #[test]
    fn test_merkle_root() {
        let leaves: Vec<[u8; 32]> = (0..4).map(|i| [i; 32]).collect();
        let root = compute_merkle_root(&leaves);

        // Verify root is deterministic
        let root2 = compute_merkle_root(&leaves);
        assert_eq!(root, root2);
    }

    #[test]
    fn test_merkle_proof() {
        let leaves: Vec<[u8; 32]> = (0..8).map(|i| [i; 32]).collect();
        let root = compute_merkle_root(&leaves);

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = compute_merkle_proof(&leaves, i);
            assert!(verify_merkle_proof(leaf, &proof, &root, i, leaves.len()));
        }
    }

    #[test]
    fn test_merkle_proof_odd_count() {
        let leaves: Vec<[u8; 32]> = (0..5).map(|i| [i; 32]).collect();
        let root = compute_merkle_root(&leaves);

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = compute_merkle_proof(&leaves, i);
            assert!(verify_merkle_proof(leaf, &proof, &root, i, leaves.len()));
        }
    }

    #[test]
    fn test_merkle_collision_resistance() {
        // This test verifies the fix for CVE-2012-2459 style attacks
        // [A,B,C] and [A,B,C,C] must produce DIFFERENT roots

        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];

        let list1 = vec![a, b, c];
        let list2 = vec![a, b, c, c]; // C duplicated

        let root1 = compute_merkle_root(&list1);
        let root2 = compute_merkle_root(&list2);

        assert_ne!(
            root1, root2,
            "CRITICAL: Merkle roots must differ for different leaf counts"
        );

        // Also verify empty vs single element
        let empty_root = compute_merkle_root(&[]);
        let single_root = compute_merkle_root(&[a]);

        assert_ne!(empty_root, single_root, "Empty and single must differ");
        assert_ne!(single_root, a, "Single root must be hashed, not raw");
    }

    #[test]
    fn test_merkle_wrong_count_fails() {
        // Verify that proofs fail if wrong leaf count is used
        let leaves: Vec<[u8; 32]> = (0..4).map(|i| [i; 32]).collect();
        let root = compute_merkle_root(&leaves);
        let proof = compute_merkle_proof(&leaves, 0);

        // Correct count works
        assert!(verify_merkle_proof(&leaves[0], &proof, &root, 0, 4));

        // Wrong count fails
        assert!(!verify_merkle_proof(&leaves[0], &proof, &root, 0, 5));
        assert!(!verify_merkle_proof(&leaves[0], &proof, &root, 0, 3));
    }
}
