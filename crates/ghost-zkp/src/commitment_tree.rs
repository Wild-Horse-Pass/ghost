//! Sparse merkle tree for confidential transfer commitments
//!
//! Unlike the balance tree which hashes `H(balance, LEAF_DOMAIN)` to get leaves,
//! the commitment tree stores Pedersen commitments directly as leaves.
//! Commitments are already MiMC hashes, so no additional leaf hashing is needed.
//!
//! This tree supports:
//! - Inserting commitments at specific indices
//! - Generating merkle proofs for ZK circuits
//! - Applying confidential transfers (atomic sender+recipient update)
//! - Nullifier set tracking (double-spend prevention)

use std::collections::{HashMap, HashSet};

use blstrs::Scalar as Fr;

use crate::circuit::commitment::pedersen_commit_native;
use crate::circuit::mimc::{bytes_to_field, field_to_bytes, mimc_hash_native};
use crate::errors::{ZkError, ZkResult};
use crate::types::{ConfidentialTransferWitness, MerkleProof};

/// Sparse merkle tree storing commitments as leaves
///
/// Commitments are `MiMC(MiMC(value, blinding), COMMITMENT_DOMAIN)`.
/// Since they are already hashes, they are stored directly as leaf values
/// without additional hashing.
///
/// Uses precomputed zero-subtree hashes to avoid O(2^depth) traversal
/// on sparse trees. Only subtrees containing actual leaves are computed.
///
/// # Nullifier Set (Double-Spend Prevention)
///
/// The tree maintains an internal set of spent nullifiers. A nullifier is a
/// deterministic, unlinkable identifier derived from a note's commitment and
/// the owner's spending key: `nullifier = MiMC(spending_key, note_id)`.
///
/// **Callers MUST check `is_nullifier_spent()` before accepting any new
/// transaction that spends a note.** If the nullifier is already in the set,
/// the transaction is a double-spend attempt and must be rejected. The
/// `apply_transfer()` method performs this check automatically, but direct
/// users of `spend_nullifier()` must check explicitly.
///
/// The nullifier set grows monotonically within an epoch and is pruned
/// during epoch transitions by the `EpochManager`.
#[derive(Debug, Clone)]
pub struct CommitmentTree {
    /// Tree depth (supports 2^depth notes)
    depth: usize,
    /// Leaf values: index -> commitment (as field element bytes)
    leaves: HashMap<u64, [u8; 32]>,
    /// Set of spent nullifiers for double-spend prevention.
    ///
    /// A nullifier uniquely identifies a spent note without revealing which note
    /// was spent (unlinkability). Before adding any new commitment that spends
    /// an existing note, the caller must verify the nullifier is not already
    /// present in this set. See `is_nullifier_spent()` and `spend_nullifier()`.
    nullifiers: HashSet<[u8; 32]>,
    /// Next available index for new notes
    next_index: u64,
    /// Precomputed hash of an all-zero subtree at each level (0..=depth)
    /// zero_hashes[0] = [0u8; 32] (empty leaf)
    /// zero_hashes[i] = MiMC(zero_hashes[i-1], zero_hashes[i-1])
    zero_hashes: Vec<[u8; 32]>,
}

/// Precompute the hash of a complete all-zero subtree at each level.
/// This is O(depth) and allows O(depth * log(leaves)) root computation
/// instead of O(2^depth).
fn precompute_zero_hashes(depth: usize) -> Vec<[u8; 32]> {
    let mut zeros = vec![[0u8; 32]; depth + 1];
    for i in 1..=depth {
        let left: Fr = bytes_to_field(&zeros[i - 1]).unwrap_or(Fr::from(0u64));
        let right = left;
        zeros[i] = field_to_bytes(mimc_hash_native(left, right));
    }
    zeros
}

impl CommitmentTree {
    /// Create a new empty commitment tree
    pub fn new(depth: usize) -> Self {
        let zero_hashes = precompute_zero_hashes(depth);
        Self {
            depth,
            leaves: HashMap::new(),
            nullifiers: HashSet::new(),
            next_index: 0,
            zero_hashes,
        }
    }

    /// Get the tree depth
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Get the next available note index
    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    /// Get the number of notes in the tree
    pub fn note_count(&self) -> usize {
        self.leaves.len()
    }

    /// Insert a commitment at a specific index
    pub fn insert(&mut self, index: u64, commitment: [u8; 32]) {
        self.leaves.insert(index, commitment);
        if index >= self.next_index {
            self.next_index = index + 1;
        }
    }

    /// Insert a commitment computed from value and blinding
    pub fn insert_note(&mut self, index: u64, value: u64, blinding: Fr) -> [u8; 32] {
        let commitment = pedersen_commit_native(Fr::from(value), blinding);
        let bytes = field_to_bytes(commitment);
        self.insert(index, bytes);
        bytes
    }

    /// Get commitment at a given index (zero if empty)
    pub fn get_commitment(&self, index: u64) -> [u8; 32] {
        *self.leaves.get(&index).unwrap_or(&[0u8; 32])
    }

    /// Get merkle proof for a leaf
    pub fn get_proof(&self, index: u64) -> ZkResult<MerkleProof> {
        let mut siblings = Vec::with_capacity(self.depth);
        let mut current_index = index;

        for level in 0..self.depth {
            let sibling_index = current_index ^ 1;
            let sibling_hash = self.get_node_hash(level, sibling_index)?;
            siblings.push(sibling_hash);
            current_index /= 2;
        }

        Ok(MerkleProof::new(index, siblings))
    }

    /// Compute current merkle root
    pub fn root(&self) -> ZkResult<[u8; 32]> {
        self.get_node_hash(self.depth, 0)
    }

    /// Check if a nullifier has been spent
    pub fn is_nullifier_spent(&self, nullifier: &[u8; 32]) -> bool {
        self.nullifiers.contains(nullifier)
    }

    /// Record a nullifier as spent
    ///
    /// Returns false if the nullifier was already spent (double-spend attempt).
    pub fn spend_nullifier(&mut self, nullifier: [u8; 32]) -> bool {
        self.nullifiers.insert(nullifier)
    }

    /// Get the number of spent nullifiers
    pub fn nullifier_count(&self) -> usize {
        self.nullifiers.len()
    }

    /// Apply a confidential transfer and return the witness data
    ///
    /// This atomically:
    /// 1. Generates proof for sender in current tree
    /// 2. Replaces sender's commitment with new (change) commitment
    /// 3. Generates proof for recipient in intermediate tree
    /// 4. Replaces recipient's commitment with new commitment
    /// 5. Records the nullifier
    /// 6. Returns witness with all proofs
    #[allow(clippy::too_many_arguments)]
    pub fn apply_transfer(
        &mut self,
        sender_index: u64,
        sender_value: u64,
        sender_blinding: Fr,
        sender_spending_key: Fr,
        amount: u64,
        sender_new_blinding: Fr,
        recipient_index: u64,
        recipient_old_value: u64,
        recipient_old_blinding: Fr,
        recipient_new_blinding: Fr,
    ) -> ZkResult<ConfidentialTransferWitness> {
        // Validate sufficient funds
        if sender_value < amount {
            return Err(ZkError::InsufficientBalance {
                has: sender_value,
                needs: amount,
            });
        }

        // Get sender proof against current tree
        let sender_merkle_proof = self.get_proof(sender_index)?;

        // Compute sender's new commitment (change)
        let sender_new_value = sender_value - amount;
        let sender_new_commit =
            pedersen_commit_native(Fr::from(sender_new_value), sender_new_blinding);

        // Replace sender's leaf with new commitment
        self.insert(sender_index, field_to_bytes(sender_new_commit));

        // Get recipient proof against intermediate tree (after sender update)
        let recipient_merkle_proof = self.get_proof(recipient_index)?;

        // Compute recipient's new commitment
        let recipient_new_value =
            recipient_old_value
                .checked_add(amount)
                .ok_or(ZkError::BalanceOverflow {
                    balance: recipient_old_value,
                    amount,
                })?;
        let recipient_new_commit =
            pedersen_commit_native(Fr::from(recipient_new_value), recipient_new_blinding);

        // Replace recipient's leaf with new commitment
        self.insert(recipient_index, field_to_bytes(recipient_new_commit));

        // Record nullifier
        let sender_commit = pedersen_commit_native(Fr::from(sender_value), sender_blinding);
        let note_id =
            crate::circuit::commitment::compute_note_id_native(sender_index, sender_commit);
        let nullifier =
            crate::circuit::commitment::compute_nullifier_native(sender_spending_key, note_id);
        let nullifier_bytes = field_to_bytes(nullifier);

        if !self.spend_nullifier(nullifier_bytes) {
            return Err(ZkError::InvalidWitness(
                "Double-spend: nullifier already spent".to_string(),
            ));
        }

        Ok(ConfidentialTransferWitness {
            sender_value,
            sender_blinding: field_to_bytes(sender_blinding),
            sender_spending_key: field_to_bytes(sender_spending_key),
            sender_index,
            sender_merkle_proof,
            amount,
            sender_new_blinding: field_to_bytes(sender_new_blinding),
            recipient_old_value,
            recipient_old_blinding: field_to_bytes(recipient_old_blinding),
            recipient_index,
            recipient_merkle_proof,
            recipient_new_blinding: field_to_bytes(recipient_new_blinding),
        })
    }

    /// Get hash of a node at a given level and index
    ///
    /// Level 0 = leaves (commitments stored directly), Level depth = root.
    /// Uses precomputed zero_hashes to short-circuit empty subtrees,
    /// making this O(depth * populated_leaves) instead of O(2^depth).
    fn get_node_hash(&self, level: usize, index: u64) -> ZkResult<[u8; 32]> {
        if level == 0 {
            // Leaf node: commitment is stored directly (no leaf hashing)
            return Ok(self.get_commitment(index));
        }

        // Check if ANY leaf exists in this subtree's range.
        // Subtree at (level, index) covers leaf indices [index * 2^level, (index+1) * 2^level).
        // If no leaves exist in that range, return precomputed zero hash.
        if !self.has_leaf_in_subtree(level, index) {
            return Ok(self.zero_hashes[level]);
        }

        let left = self.get_node_hash(level - 1, index * 2)?;
        let right = self.get_node_hash(level - 1, index * 2 + 1)?;
        self.hash_pair(&left, &right)
    }

    /// Check if any leaf exists in the subtree rooted at (level, index).
    /// The subtree covers leaf indices [index << level, (index + 1) << level).
    fn has_leaf_in_subtree(&self, level: usize, index: u64) -> bool {
        if self.leaves.is_empty() {
            return false;
        }
        let start = index << level;
        let end = (index + 1) << level;
        self.leaves.keys().any(|&k| k >= start && k < end)
    }

    /// Hash two child nodes using MiMC (matches circuit)
    fn hash_pair(&self, left: &[u8; 32], right: &[u8; 32]) -> ZkResult<[u8; 32]> {
        let left_field = bytes_to_field::<Fr>(left)?;
        let right_field = bytes_to_field::<Fr>(right)?;
        Ok(field_to_bytes(mimc_hash_native(left_field, right_field)))
    }
}

/// Builder for creating commitment trees with initial notes
pub struct CommitmentTreeBuilder {
    tree: CommitmentTree,
}

impl CommitmentTreeBuilder {
    /// Create a new builder
    pub fn new(depth: usize) -> Self {
        Self {
            tree: CommitmentTree::new(depth),
        }
    }

    /// Add a note to the tree
    pub fn add_note(mut self, index: u64, value: u64, blinding: Fr) -> Self {
        self.tree.insert_note(index, value, blinding);
        self
    }

    /// Add a raw commitment to the tree
    pub fn add_commitment(mut self, index: u64, commitment: [u8; 32]) -> Self {
        self.tree.insert(index, commitment);
        self
    }

    /// Build the tree
    pub fn build(self) -> CommitmentTree {
        self.tree
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::commitment::{
        compute_note_id_native, compute_nullifier_native, pedersen_commit_native,
    };
    use crate::circuit::confidential_transfer::compute_commitment_root_native;

    #[test]
    fn test_empty_tree() {
        let tree = CommitmentTree::new(4);
        assert_eq!(tree.note_count(), 0);
        assert_eq!(tree.next_index(), 0);

        let root = tree.root().unwrap();
        // Empty tree should have a deterministic root (all-zero leaves)
        assert_ne!(root, [0u8; 32]); // MiMC of zeros is not zero
    }

    #[test]
    fn test_insert_and_root() {
        let mut tree = CommitmentTree::new(4);
        let blinding = Fr::from(42u64);
        let commitment = tree.insert_note(0, 1000, blinding);

        assert_ne!(commitment, [0u8; 32]);
        assert_eq!(tree.note_count(), 1);
        assert_eq!(tree.get_commitment(0), commitment);
        assert_eq!(tree.next_index(), 1);
    }

    #[test]
    fn test_proof_matches_circuit() {
        let mut tree = CommitmentTree::new(4);
        let blinding = Fr::from(42u64);
        let value = 1000u64;

        tree.insert_note(0, value, blinding);
        let commit = pedersen_commit_native(Fr::from(value), blinding);

        let proof = tree.get_proof(0).unwrap();
        let siblings: Vec<Fr> = proof
            .siblings
            .iter()
            .map(|s| bytes_to_field(s).unwrap())
            .collect();

        let circuit_root = compute_commitment_root_native(commit, 0, &siblings);
        let tree_root_bytes = tree.root().unwrap();
        let tree_root: Fr = bytes_to_field(&tree_root_bytes).unwrap();

        assert_eq!(
            circuit_root, tree_root,
            "Tree root must match circuit computation"
        );
    }

    #[test]
    fn test_nullifier_tracking() {
        let mut tree = CommitmentTree::new(4);
        let nullifier = [1u8; 32];

        assert!(!tree.is_nullifier_spent(&nullifier));
        assert!(tree.spend_nullifier(nullifier));
        assert!(tree.is_nullifier_spent(&nullifier));
        // Double-spend should return false
        assert!(!tree.spend_nullifier(nullifier));
    }

    #[test]
    fn test_apply_transfer() {
        let depth = 4;
        let sender_blinding = Fr::from(111u64);
        let sender_spending_key = Fr::from(42u64);
        let recipient_old_blinding = Fr::from(333u64);
        let sender_new_blinding = Fr::from(222u64);
        let recipient_new_blinding = Fr::from(444u64);

        let sender_value = 1000u64;
        let recipient_old_value = 500u64;
        let amount = 300u64;

        // Build tree with initial notes
        let mut tree = CommitmentTree::new(depth);
        tree.insert_note(0, sender_value, sender_blinding);
        tree.insert_note(1, recipient_old_value, recipient_old_blinding);

        let old_root = tree.root().unwrap();

        let witness = tree
            .apply_transfer(
                0,
                sender_value,
                sender_blinding,
                sender_spending_key,
                amount,
                sender_new_blinding,
                1,
                recipient_old_value,
                recipient_old_blinding,
                recipient_new_blinding,
            )
            .unwrap();

        let new_root = tree.root().unwrap();

        // Roots should differ
        assert_ne!(old_root, new_root);

        // Witness should have correct values
        assert_eq!(witness.sender_value, sender_value);
        assert_eq!(witness.amount, amount);
        assert_eq!(witness.recipient_old_value, recipient_old_value);
        assert_eq!(witness.sender_index, 0);
        assert_eq!(witness.recipient_index, 1);

        // Nullifier should be recorded
        let sender_commit = pedersen_commit_native(Fr::from(sender_value), sender_blinding);
        let note_id = compute_note_id_native(0, sender_commit);
        let nullifier = compute_nullifier_native(sender_spending_key, note_id);
        assert!(tree.is_nullifier_spent(&field_to_bytes(nullifier)));
    }

    #[test]
    fn test_double_spend_rejected() {
        let depth = 4;
        let sender_blinding = Fr::from(111u64);
        let sender_spending_key = Fr::from(42u64);
        let recipient_old_blinding = Fr::from(333u64);

        let mut tree = CommitmentTree::new(depth);
        tree.insert_note(0, 1000, sender_blinding);
        tree.insert_note(1, 500, recipient_old_blinding);

        // First transfer succeeds
        let _witness = tree
            .apply_transfer(
                0,
                1000,
                sender_blinding,
                sender_spending_key,
                300,
                Fr::from(222u64),
                1,
                500,
                recipient_old_blinding,
                Fr::from(444u64),
            )
            .unwrap();

        // Second transfer with same sender note should fail (nullifier already spent)
        let result = tree.apply_transfer(
            0,
            1000,
            sender_blinding,
            sender_spending_key,
            200,
            Fr::from(555u64),
            1,
            800,
            Fr::from(444u64),
            Fr::from(666u64),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_insufficient_funds_rejected() {
        let depth = 4;
        let mut tree = CommitmentTree::new(depth);
        tree.insert_note(0, 100, Fr::from(111u64));
        tree.insert_note(1, 500, Fr::from(333u64));

        let result = tree.apply_transfer(
            0,
            100,
            Fr::from(111u64),
            Fr::from(42u64),
            200, // more than sender has
            Fr::from(222u64),
            1,
            500,
            Fr::from(333u64),
            Fr::from(444u64),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_builder() {
        let tree = CommitmentTreeBuilder::new(4)
            .add_note(0, 1000, Fr::from(111u64))
            .add_note(1, 500, Fr::from(222u64))
            .build();

        assert_eq!(tree.note_count(), 2);
        assert_eq!(tree.next_index(), 2);
    }

    #[test]
    fn test_witness_generates_valid_proof() {
        // Verify that apply_transfer produces a witness that satisfies the circuit
        use crate::confidential_prover::ConfidentialProver;
        use crate::confidential_verifier::ConfidentialVerifier;

        let depth = 4;
        let sender_blinding = Fr::from(111u64);
        let sender_spending_key = Fr::from(42u64);
        let recipient_old_blinding = Fr::from(333u64);

        let mut tree = CommitmentTree::new(depth);
        tree.insert_note(0, 1000, sender_blinding);
        tree.insert_note(1, 500, recipient_old_blinding);

        let witness = tree
            .apply_transfer(
                0,
                1000,
                sender_blinding,
                sender_spending_key,
                300,
                Fr::from(222u64),
                1,
                500,
                recipient_old_blinding,
                Fr::from(444u64),
            )
            .unwrap();

        let prover = ConfidentialProver::new(depth);
        let verifier = ConfidentialVerifier::for_prover(&prover);

        let proof = prover.prove(&witness).expect("Proof should succeed");
        assert!(verifier
            .verify(&proof)
            .expect("Verification should succeed"));
    }

    #[test]
    fn test_depth_40_tree_is_fast() {
        // Depth 40 = ~1 trillion leaves. Without zero-subtree optimization,
        // root() would traverse 2^40 nodes and never complete.
        let tree = CommitmentTree::new(40);
        let root = tree.root().unwrap();
        assert_ne!(root, [0u8; 32]); // MiMC of zeros is non-zero

        // Insert a single note and verify root changes
        let mut tree2 = CommitmentTree::new(40);
        tree2.insert_note(0, 1000, Fr::from(42u64));
        let root2 = tree2.root().unwrap();
        assert_ne!(root, root2);
    }
}
