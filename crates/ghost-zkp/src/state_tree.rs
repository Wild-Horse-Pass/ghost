//! Sparse merkle tree for balance state management
//!
//! Provides utilities for:
//! - Computing merkle roots from balance state
//! - Generating merkle proofs for individual accounts
//! - Applying payments and computing state transitions
//! - Generating witness data for ZK proofs

use std::collections::{BTreeMap, HashMap};

use blstrs::Scalar as Fr;

use crate::circuit::mimc::{bytes_to_field, field_to_bytes, mimc_hash_native};
use crate::errors::{ZkError, ZkResult};
use crate::types::{MerkleProof, PaymentTransitionWitness};

/// Sparse merkle tree for balance state
///
/// Efficiently stores and updates account balances with merkle proof generation.
/// Uses a sparse representation - only non-zero leaves are stored.
/// Precomputes empty subtree hashes and uses BTreeMap range queries to skip
/// empty subtrees, reducing root() from O(2^depth) to O(leaves * depth).
#[derive(Debug, Clone)]
pub struct BalanceTree {
    /// Tree depth (supports 2^depth accounts)
    depth: usize,
    /// Leaf values: index -> balance (BTreeMap for efficient range queries)
    leaves: BTreeMap<u64, u64>,
    /// Precomputed hash for an empty subtree at each level
    /// empty_hashes[0] = hash_leaf(0), empty_hashes[i] = hash_pair(empty_hashes[i-1], empty_hashes[i-1])
    empty_hashes: Vec<[u8; 32]>,
}

impl BalanceTree {
    /// Precompute empty subtree hashes for each level
    fn compute_empty_hashes(depth: usize) -> Vec<[u8; 32]> {
        let mut empty = Vec::with_capacity(depth + 1);
        // Level 0: hash of zero balance
        let balance_field = Fr::from(0u64);
        let domain_sep = Fr::from(0x4c454146u64);
        let leaf_hash = field_to_bytes(mimc_hash_native(balance_field, domain_sep));
        empty.push(leaf_hash);

        // Each higher level: hash_pair(empty[level-1], empty[level-1])
        for _ in 1..=depth {
            let prev = empty.last().unwrap();
            let left_field = bytes_to_field::<Fr>(prev).expect("empty hash must be valid field");
            let right_field = left_field;
            let pair_hash = field_to_bytes(mimc_hash_native(left_field, right_field));
            empty.push(pair_hash);
        }
        empty
    }

    /// Create a new empty balance tree
    pub fn new(depth: usize) -> Self {
        let empty_hashes = Self::compute_empty_hashes(depth);
        Self {
            depth,
            leaves: BTreeMap::new(),
            empty_hashes,
        }
    }

    /// Create a tree from existing balances
    pub fn from_balances(depth: usize, balances: HashMap<u64, u64>) -> Self {
        let empty_hashes = Self::compute_empty_hashes(depth);
        let leaves: BTreeMap<u64, u64> = balances.into_iter().filter(|(_, v)| *v != 0).collect();
        Self {
            depth,
            leaves,
            empty_hashes,
        }
    }

    /// Get the tree depth
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Get balance for an account
    pub fn get_balance(&self, index: u64) -> u64 {
        *self.leaves.get(&index).unwrap_or(&0)
    }

    /// Set balance for an account
    pub fn set_balance(&mut self, index: u64, balance: u64) {
        if balance == 0 {
            self.leaves.remove(&index);
        } else {
            self.leaves.insert(index, balance);
        }
    }

    /// Get merkle proof for a leaf
    pub fn get_proof(&self, index: u64) -> ZkResult<MerkleProof> {
        let mut siblings = Vec::with_capacity(self.depth);
        let mut current_index = index;

        for level in 0..self.depth {
            // Sibling is at index XOR 1
            let sibling_index = current_index ^ 1;
            let sibling_hash = self.get_node_hash(level, sibling_index)?;
            siblings.push(sibling_hash);

            // Move to parent
            current_index /= 2;
        }

        Ok(MerkleProof::new(index, siblings))
    }

    /// Update a leaf and return the new root
    pub fn update(&mut self, index: u64, new_balance: u64) -> ZkResult<[u8; 32]> {
        self.set_balance(index, new_balance);
        self.root()
    }

    /// Get current merkle root
    pub fn root(&self) -> ZkResult<[u8; 32]> {
        self.get_node_hash(self.depth, 0)
    }

    /// Apply a payment and return the transition witness
    ///
    /// This atomically:
    /// 1. Generates proof for sender in current state
    /// 2. Updates sender balance
    /// 3. Generates proof for recipient in intermediate state
    /// 4. Updates recipient balance
    /// 5. Returns witness with all proofs
    pub fn apply_payment(
        &mut self,
        sender_index: u64,
        recipient_index: u64,
        amount: u64,
    ) -> ZkResult<PaymentTransitionWitness> {
        // Reject self-payment: using stale recipient_balance_before after
        // updating sender would inflate the balance when sender == recipient
        if sender_index == recipient_index {
            return Err(ZkError::InvalidParams(
                "sender and recipient must be different accounts".into(),
            ));
        }

        // Get current balances
        let sender_balance_before = self.get_balance(sender_index);
        let recipient_balance_before = self.get_balance(recipient_index);

        // Validate
        if sender_balance_before < amount {
            return Err(ZkError::InsufficientBalance {
                has: sender_balance_before,
                needs: amount,
            });
        }

        // Get sender proof against current state
        let sender_merkle_proof = self.get_proof(sender_index)?;

        // Update sender balance
        let sender_balance_after = sender_balance_before - amount;
        self.set_balance(sender_index, sender_balance_after);

        // Get recipient proof against intermediate state (after sender update)
        let recipient_merkle_proof = self.get_proof(recipient_index)?;

        // Update recipient balance
        let recipient_balance_after =
            recipient_balance_before
                .checked_add(amount)
                .ok_or(ZkError::BalanceOverflow {
                    balance: recipient_balance_before,
                    amount,
                })?;
        self.set_balance(recipient_index, recipient_balance_after);

        Ok(PaymentTransitionWitness::new(
            sender_balance_before,
            recipient_balance_before,
            amount,
            sender_index,
            sender_merkle_proof,
            recipient_index,
            recipient_merkle_proof,
        ))
    }

    /// Check if any non-zero leaf exists in the subtree rooted at (level, index).
    /// The subtree covers leaf indices [index * 2^level, (index+1) * 2^level).
    fn has_leaves_in_subtree(&self, level: usize, index: u64) -> bool {
        let start = index << level;
        // Guard against overflow for large level values
        let end = match (index + 1).checked_shl(level as u32) {
            Some(e) => e,
            None => return !self.leaves.is_empty(), // subtree covers entire range
        };
        // BTreeMap range query: O(log n) to check if any key exists in range
        self.leaves.range(start..end).next().is_some()
    }

    /// Get hash of a node at a given level and index
    ///
    /// Level 0 = leaves, Level depth = root
    /// Uses precomputed empty subtree hashes to skip empty regions,
    /// reducing complexity from O(2^depth) to O(leaves * depth).
    fn get_node_hash(&self, level: usize, index: u64) -> ZkResult<[u8; 32]> {
        if level == 0 {
            // Leaf node: hash the balance
            let balance = self.get_balance(index);
            return Ok(self.hash_leaf(balance));
        }

        // If this entire subtree has no non-zero leaves, return precomputed empty hash
        if !self.has_leaves_in_subtree(level, index) {
            return Ok(self.empty_hashes[level]);
        }

        // Internal node with at least one non-zero descendant: hash children
        let left = self.get_node_hash(level - 1, index * 2)?;
        let right = self.get_node_hash(level - 1, index * 2 + 1)?;
        self.hash_pair(&left, &right)
    }

    /// Hash a leaf (balance value)
    ///
    /// Uses MiMC to match the circuit implementation:
    /// H(balance, domain_separator) where domain_separator = "LEAF" encoded
    fn hash_leaf(&self, balance: u64) -> [u8; 32] {
        let balance_field = Fr::from(balance);
        // Domain separator: "LEAF" as u32 = 0x4c454146
        let domain_sep = Fr::from(0x4c454146u64);
        let hash = mimc_hash_native(balance_field, domain_sep);
        field_to_bytes(hash)
    }

    /// Hash two child nodes
    ///
    /// Uses MiMC to match the circuit implementation:
    /// H(left, right)
    fn hash_pair(&self, left: &[u8; 32], right: &[u8; 32]) -> ZkResult<[u8; 32]> {
        let left_field = bytes_to_field::<Fr>(left)?;
        let right_field = bytes_to_field::<Fr>(right)?;
        Ok(field_to_bytes(mimc_hash_native(left_field, right_field)))
    }

    /// Get the number of non-zero accounts
    pub fn account_count(&self) -> usize {
        self.leaves.len()
    }

    /// Get all account indices with non-zero balances
    pub fn accounts(&self) -> Vec<u64> {
        self.leaves.keys().copied().collect()
    }

    /// Get all leaf balances (index → balance)
    pub fn balances(&self) -> &BTreeMap<u64, u64> {
        &self.leaves
    }

    /// Get total balance across all accounts
    pub fn total_balance(&self) -> u64 {
        self.leaves
            .values()
            .fold(0u64, |acc, &v| acc.saturating_add(v))
    }

    /// Clone the tree and apply a payment, returning the witness and new tree
    pub fn apply_payment_copy(
        &self,
        sender_index: u64,
        recipient_index: u64,
        amount: u64,
    ) -> ZkResult<(PaymentTransitionWitness, Self)> {
        let mut new_tree = self.clone();
        let witness = new_tree.apply_payment(sender_index, recipient_index, amount)?;
        Ok((witness, new_tree))
    }
}

/// In-circuit hash function matching the simple hash used in circuits
///
/// H(a, b) = a * b + a + b (NOT cryptographically secure)
/// This is for testing that circuit values match expected values.
pub fn circuit_simple_hash(a: u64, b: u64) -> u64 {
    // This will overflow for large values, matching field arithmetic behavior
    // In practice, we work with field elements
    a.wrapping_mul(b).wrapping_add(a).wrapping_add(b)
}

/// Compute merkle root using simple hash (for circuit testing)
pub fn compute_root_simple_hash(leaf: u64, index: u64, siblings: &[u64]) -> u64 {
    let mut current = leaf;
    let mut idx = index;

    for sibling in siblings {
        let (left, right) = if idx.is_multiple_of(2) {
            (current, *sibling)
        } else {
            (*sibling, current)
        };
        current = circuit_simple_hash(left, right);
        idx /= 2;
    }

    current
}

/// Builder for creating test trees with specific configurations
pub struct BalanceTreeBuilder {
    depth: usize,
    balances: HashMap<u64, u64>,
}

impl BalanceTreeBuilder {
    /// Create a new builder
    pub fn new(depth: usize) -> Self {
        Self {
            depth,
            balances: HashMap::new(),
        }
    }

    /// Set balance for an account
    pub fn with_balance(mut self, index: u64, balance: u64) -> Self {
        self.balances.insert(index, balance);
        self
    }

    /// Set balances for multiple accounts
    pub fn with_balances(mut self, balances: impl IntoIterator<Item = (u64, u64)>) -> Self {
        self.balances.extend(balances);
        self
    }

    /// Build the tree
    pub fn build(self) -> BalanceTree {
        // Convert HashMap to the internal BTreeMap via from_balances
        BalanceTree::from_balances(self.depth, self.balances)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let tree = BalanceTree::new(10);

        assert_eq!(tree.depth(), 10);
        assert_eq!(tree.account_count(), 0);
        assert_eq!(tree.total_balance(), 0);

        // Root should be deterministic for empty tree
        let root1 = tree.root().unwrap();
        let root2 = tree.root().unwrap();
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_set_get_balance() {
        let mut tree = BalanceTree::new(10);

        tree.set_balance(0, 1000);
        tree.set_balance(1, 500);

        assert_eq!(tree.get_balance(0), 1000);
        assert_eq!(tree.get_balance(1), 500);
        assert_eq!(tree.get_balance(2), 0); // Not set
        assert_eq!(tree.account_count(), 2);
        assert_eq!(tree.total_balance(), 1500);
    }

    #[test]
    fn test_update_changes_root() {
        let mut tree = BalanceTree::new(10);

        let root1 = tree.root().unwrap();
        tree.update(0, 1000).unwrap();
        let root2 = tree.root().unwrap();

        assert_ne!(root1, root2, "Root should change after update");
    }

    #[test]
    fn test_proof_generation() {
        let mut tree = BalanceTree::new(4);

        tree.set_balance(0, 1000);
        tree.set_balance(5, 500);

        let proof = tree.get_proof(0).unwrap();

        assert_eq!(proof.leaf_index, 0);
        assert_eq!(proof.depth(), 4);

        // Verify the proof
        let leaf_hash = tree.hash_leaf(1000);
        let computed_root = proof
            .compute_root(leaf_hash)
            .expect("compute_root should succeed");
        assert_eq!(computed_root, tree.root().unwrap());
    }

    #[test]
    fn test_apply_payment() {
        let mut tree = BalanceTree::new(10);

        tree.set_balance(0, 1000); // Sender
        tree.set_balance(1, 500); // Recipient

        let initial_root = tree.root().unwrap();

        let witness = tree.apply_payment(0, 1, 100).unwrap();

        assert_eq!(witness.sender_balance_before, 1000);
        assert_eq!(witness.recipient_balance_before, 500);
        assert_eq!(witness.amount, 100);
        assert_eq!(witness.sender_balance_after(), Some(900));
        assert_eq!(witness.recipient_balance_after(), Some(600));

        // Balances should be updated
        assert_eq!(tree.get_balance(0), 900);
        assert_eq!(tree.get_balance(1), 600);

        // Root should change
        assert_ne!(initial_root, tree.root().unwrap());
    }

    #[test]
    fn test_apply_payment_insufficient_balance() {
        let mut tree = BalanceTree::new(10);

        tree.set_balance(0, 50); // Only 50
        tree.set_balance(1, 500);

        let result = tree.apply_payment(0, 1, 100); // Trying to send 100

        assert!(result.is_err());
        match result {
            Err(ZkError::InsufficientBalance { has, needs }) => {
                assert_eq!(has, 50);
                assert_eq!(needs, 100);
            }
            _ => panic!("Expected InsufficientBalance error"),
        }
    }

    #[test]
    fn test_apply_payment_balance_overflow() {
        let mut tree = BalanceTree::new(10);

        tree.set_balance(0, 100); // Sender has 100
        tree.set_balance(1, u64::MAX - 1); // Recipient near max

        // Try to send 2 (would overflow recipient's balance)
        let result = tree.apply_payment(0, 1, 2);

        assert!(result.is_err());
        match result {
            Err(ZkError::BalanceOverflow { balance, amount }) => {
                assert_eq!(balance, u64::MAX - 1);
                assert_eq!(amount, 2);
            }
            _ => panic!("Expected BalanceOverflow error"),
        }
    }

    #[test]
    fn test_builder() {
        let tree = BalanceTreeBuilder::new(10)
            .with_balance(0, 1000)
            .with_balance(1, 500)
            .with_balances(vec![(2, 300), (3, 200)])
            .build();

        assert_eq!(tree.account_count(), 4);
        assert_eq!(tree.total_balance(), 2000);
    }

    #[test]
    fn test_simple_hash_computation() {
        // Test that our simple hash matches expected values
        let result = circuit_simple_hash(2, 3);
        // H(2, 3) = 2*3 + 2 + 3 = 11
        assert_eq!(result, 11);

        let result2 = circuit_simple_hash(100, 200);
        // H(100, 200) = 100*200 + 100 + 200 = 20300
        assert_eq!(result2, 20300);
    }

    #[test]
    fn test_compute_root_simple_hash() {
        // Simple 2-level tree
        let leaf = 42u64;
        let siblings = vec![100u64, 200u64];

        let root = compute_root_simple_hash(leaf, 0, &siblings);

        // Level 0: H(42, 100) = 42*100 + 42 + 100 = 4342
        // Level 1: H(4342, 200) = 4342*200 + 4342 + 200 = 872942
        let level0 = circuit_simple_hash(42, 100);
        assert_eq!(level0, 4342);

        let level1 = circuit_simple_hash(level0, 200);
        assert_eq!(root, level1);
    }

    #[test]
    fn test_proof_with_different_indices() {
        let mut tree = BalanceTree::new(4);

        // Set up some balances at different indices
        tree.set_balance(0, 100);
        tree.set_balance(3, 200);
        tree.set_balance(7, 300);
        tree.set_balance(15, 400);

        // Get proofs for each
        for &index in &[0u64, 3, 7, 15] {
            let proof = tree.get_proof(index).unwrap();
            let balance = tree.get_balance(index);
            let leaf_hash = tree.hash_leaf(balance);
            let computed_root = proof
                .compute_root(leaf_hash)
                .expect("compute_root should succeed");

            assert_eq!(
                computed_root,
                tree.root().unwrap(),
                "Proof for index {} should verify",
                index
            );
        }
    }

    #[test]
    fn test_multiple_payments() {
        let mut tree = BalanceTree::new(10);

        tree.set_balance(0, 1000);
        tree.set_balance(1, 1000);
        tree.set_balance(2, 1000);

        // Apply multiple payments
        let _ = tree.apply_payment(0, 1, 100).unwrap();
        let _ = tree.apply_payment(1, 2, 200).unwrap();
        let _ = tree.apply_payment(2, 0, 50).unwrap();

        // Final balances: 0=950, 1=900, 2=1150
        assert_eq!(tree.get_balance(0), 950);
        assert_eq!(tree.get_balance(1), 900);
        assert_eq!(tree.get_balance(2), 1150);
    }

    #[test]
    fn test_apply_payment_copy() {
        let tree = BalanceTreeBuilder::new(10)
            .with_balance(0, 1000)
            .with_balance(1, 500)
            .build();

        let original_root = tree.root().unwrap();

        let (witness, new_tree) = tree.apply_payment_copy(0, 1, 100).unwrap();

        // Original tree unchanged
        assert_eq!(tree.root().unwrap(), original_root);
        assert_eq!(tree.get_balance(0), 1000);

        // New tree updated
        assert_ne!(new_tree.root().unwrap(), original_root);
        assert_eq!(new_tree.get_balance(0), 900);
        assert_eq!(new_tree.get_balance(1), 600);

        // Witness correct
        assert_eq!(witness.sender_balance_before, 1000);
        assert_eq!(witness.recipient_balance_before, 500);
    }

    /// Brute-force root computation without the sparse optimization.
    /// Visits every node in the tree — O(2^depth). Used as reference.
    fn brute_force_root(tree: &BalanceTree) -> [u8; 32] {
        fn get_hash(tree: &BalanceTree, level: usize, index: u64) -> [u8; 32] {
            if level == 0 {
                let balance = tree.get_balance(index);
                tree.hash_leaf(balance)
            } else {
                let left = get_hash(tree, level - 1, index * 2);
                let right = get_hash(tree, level - 1, index * 2 + 1);
                tree.hash_pair(&left, &right).unwrap()
            }
        }
        get_hash(tree, tree.depth(), 0)
    }

    #[test]
    fn test_depth20_empty_tree_matches_brute_force() {
        // Depth 8 brute force is feasible (2^8 = 256 leaves)
        // Verify optimized root matches brute force for empty tree
        let tree = BalanceTree::new(8);
        let optimized = tree.root().unwrap();
        let reference = brute_force_root(&tree);
        assert_eq!(optimized, reference, "Empty tree root mismatch at depth 8");
    }

    #[test]
    fn test_depth8_single_leaf_matches_brute_force() {
        let mut tree = BalanceTree::new(8);
        tree.set_balance(42, 1_000_000);
        let optimized = tree.root().unwrap();
        let reference = brute_force_root(&tree);
        assert_eq!(optimized, reference, "Single leaf root mismatch");
    }

    #[test]
    fn test_depth8_many_leaves_matches_brute_force() {
        let mut tree = BalanceTree::new(8);
        // Scatter 50 leaves across the 256-leaf address space
        for i in 0..50 {
            tree.set_balance(i * 5, (i + 1) * 100);
        }
        let optimized = tree.root().unwrap();
        let reference = brute_force_root(&tree);
        assert_eq!(optimized, reference, "50-leaf root mismatch at depth 8");
    }

    #[test]
    fn test_depth8_payments_match_brute_force() {
        let mut tree = BalanceTree::new(8);
        // Set up 20 accounts with balances
        for i in 0..20 {
            tree.set_balance(i * 12, 10_000);
        }

        // Apply 15 payments and verify root after each
        for i in 0..15 {
            let sender = i * 12;
            let recipient = ((i + 1) % 20) * 12;
            tree.apply_payment(sender, recipient, 100).unwrap();
            let optimized = tree.root().unwrap();
            let reference = brute_force_root(&tree);
            assert_eq!(
                optimized, reference,
                "Root mismatch after payment {} (sender={}, recipient={})",
                i, sender, recipient
            );
        }
    }

    #[test]
    fn test_depth8_leaf_removal_matches_brute_force() {
        let mut tree = BalanceTree::new(8);
        // Add leaves then remove some (balance -> 0)
        for i in 0..30 {
            tree.set_balance(i * 8, 5000);
        }
        let root_before = tree.root().unwrap();

        // Remove half the leaves
        for i in 0..15 {
            tree.set_balance(i * 8, 0);
        }
        let optimized = tree.root().unwrap();
        let reference = brute_force_root(&tree);
        assert_eq!(optimized, reference, "Root mismatch after leaf removal");
        assert_ne!(root_before, optimized, "Root should change after removals");
    }

    #[test]
    fn test_depth20_sparse_root_deterministic() {
        // Depth 20 with sparse leaves — verifies the optimization doesn't
        // blow up at production depth. Can't brute-force compare (2^20 nodes)
        // but can verify determinism and that mutations change the root.
        let mut tree = BalanceTree::new(20);

        let empty_root = tree.root().unwrap();

        // Add 200 accounts spread across the address space
        for i in 0u64..200 {
            tree.set_balance(i * 5000, (i + 1) * 1000);
        }
        let root_200 = tree.root().unwrap();
        assert_ne!(empty_root, root_200, "Root should differ from empty");

        // Same tree built differently should give same root
        let mut tree2 = BalanceTree::new(20);
        for i in (0u64..200).rev() {
            tree2.set_balance(i * 5000, (i + 1) * 1000);
        }
        assert_eq!(
            root_200,
            tree2.root().unwrap(),
            "Insertion order shouldn't matter"
        );

        // Apply payments and verify root changes
        let mut prev_root = root_200;
        for i in 0..50 {
            let sender = i * 5000;
            let recipient = ((i + 1) % 200) * 5000;
            tree.apply_payment(sender, recipient, 100).unwrap();
            let new_root = tree.root().unwrap();
            assert_ne!(
                prev_root, new_root,
                "Root should change after payment {}",
                i
            );
            prev_root = new_root;
        }
    }

    #[test]
    fn test_depth20_proof_verification_with_sparse_tree() {
        let mut tree = BalanceTree::new(20);

        // Add 100 accounts at various positions including high indices
        let indices: Vec<u64> = (0..100).map(|i| i * 10_000).collect();
        for &idx in &indices {
            tree.set_balance(idx, 50_000);
        }

        // Verify proofs for a sample of accounts
        let root = tree.root().unwrap();
        for &idx in indices.iter().step_by(10) {
            let proof = tree.get_proof(idx).unwrap();
            let leaf_hash = tree.hash_leaf(50_000);
            let computed = proof.compute_root(leaf_hash).unwrap();
            assert_eq!(computed, root, "Proof failed for index {}", idx);
        }

        // Verify proof for an empty leaf
        let proof = tree.get_proof(999).unwrap();
        let leaf_hash = tree.hash_leaf(0);
        let computed = proof.compute_root(leaf_hash).unwrap();
        assert_eq!(computed, root, "Proof failed for empty leaf");
    }

    #[test]
    fn test_depth8_adjacent_leaves_matches_brute_force() {
        // Adjacent leaves share many internal nodes — tests the boundary
        // between populated and empty subtrees
        let mut tree = BalanceTree::new(8);
        tree.set_balance(0, 100);
        tree.set_balance(1, 200);
        tree.set_balance(2, 300);
        tree.set_balance(3, 400);
        tree.set_balance(254, 500);
        tree.set_balance(255, 600);

        let optimized = tree.root().unwrap();
        let reference = brute_force_root(&tree);
        assert_eq!(optimized, reference, "Adjacent leaf root mismatch");
    }

    #[test]
    fn test_hash_pair_invalid_field_returns_error() {
        let tree = BalanceTree::new(4);

        // Create bytes larger than the BLS12-381 scalar field modulus
        // The modulus is ~0x73eda753..., so 0xFF...FF will exceed it
        let invalid_bytes = [0xFF; 32];
        let valid_bytes = [0x01; 32];

        let result = tree.hash_pair(&invalid_bytes, &valid_bytes);
        assert!(
            result.is_err(),
            "Should reject bytes exceeding field modulus"
        );

        let result = tree.hash_pair(&valid_bytes, &invalid_bytes);
        assert!(
            result.is_err(),
            "Should reject bytes exceeding field modulus (right)"
        );
    }
}
