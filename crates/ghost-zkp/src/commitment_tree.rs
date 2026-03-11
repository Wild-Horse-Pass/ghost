//! Sparse merkle tree for confidential transfer commitments
//!
//! Unlike the balance tree which hashes `H(balance, LEAF_DOMAIN)` to get leaves,
//! the commitment tree stores Pedersen commitments directly as leaves.
//! Commitments are already MiMC hashes, so no additional leaf hashing is needed.
//!
//! This tree supports:
//! - Inserting commitments at specific indices
//! - Generating merkle proofs for ZK circuits
//! - Nullifier set tracking (double-spend prevention)

use std::collections::{HashMap, HashSet};

use blstrs::Scalar as Fr;

use crate::circuit::commitment::pedersen_commit_native;
use crate::circuit::mimc::{bytes_to_field, field_to_bytes, mimc_hash_native};
use crate::errors::ZkResult;
use crate::types::MerkleProof;

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
/// the transaction is a double-spend attempt and must be rejected. Users of
/// `spend_nullifier()` must check explicitly.
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

    /// Insert a commitment at a specific index.
    /// Uses check-before-overwrite to match the DB's INSERT OR IGNORE semantics:
    /// if a leaf already exists at this index, it is NOT overwritten.
    /// Returns true if the leaf was inserted, false if it already existed.
    pub fn insert(&mut self, index: u64, commitment: [u8; 32]) -> bool {
        use std::collections::hash_map::Entry;
        let inserted = match self.leaves.entry(index) {
            Entry::Occupied(_) => false,
            Entry::Vacant(e) => {
                e.insert(commitment);
                true
            }
        };
        if index >= self.next_index {
            self.next_index = index + 1;
        }
        inserted
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
    use crate::circuit::commitment::pedersen_commit_native;

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
    fn test_proof_verifies_against_root() {
        let mut tree = CommitmentTree::new(4);
        let blinding = Fr::from(42u64);
        let value = 1000u64;

        let commitment = tree.insert_note(0, value, blinding);

        let proof = tree.get_proof(0).unwrap();
        let tree_root = tree.root().unwrap();

        // The merkle proof should verify the commitment against the tree root
        assert!(
            proof.verify(commitment, tree_root),
            "Merkle proof must verify against tree root"
        );

        // Also verify that pedersen_commit_native matches the stored commitment
        let expected_commit = pedersen_commit_native(Fr::from(value), blinding);
        assert_eq!(
            commitment,
            field_to_bytes(expected_commit),
            "insert_note commitment must match pedersen_commit_native"
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
    fn test_builder() {
        let tree = CommitmentTreeBuilder::new(4)
            .add_note(0, 1000, Fr::from(111u64))
            .add_note(1, 500, Fr::from(222u64))
            .build();

        assert_eq!(tree.note_count(), 2);
        assert_eq!(tree.next_index(), 2);
    }

    #[test]
    fn test_depth_20_tree_is_fast() {
        // Depth 20 = ~1M leaves. Without zero-subtree optimization,
        // root() would traverse 2^20 nodes and never complete.
        let tree = CommitmentTree::new(20);
        let root = tree.root().unwrap();
        assert_ne!(root, [0u8; 32]); // MiMC of zeros is non-zero

        // Insert a single note and verify root changes
        let mut tree2 = CommitmentTree::new(20);
        tree2.insert_note(0, 1000, Fr::from(42u64));
        let root2 = tree2.root().unwrap();
        assert_ne!(root, root2);
    }
}
