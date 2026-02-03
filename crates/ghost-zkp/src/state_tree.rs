//! Sparse merkle tree for balance state management
//!
//! Provides utilities for:
//! - Computing merkle roots from balance state
//! - Generating merkle proofs for individual accounts
//! - Applying payments and computing state transitions
//! - Generating witness data for ZK proofs

use std::collections::HashMap;

use blstrs::Scalar as Fr;
use ff::Field;
use tracing::warn;

use crate::circuit::mimc::{bytes_to_field, field_to_bytes, mimc_hash_native};
use crate::errors::{ZkError, ZkResult};
use crate::types::{MerkleProof, PaymentTransitionWitness};

/// Sparse merkle tree for balance state
///
/// Efficiently stores and updates account balances with merkle proof generation.
/// Uses a sparse representation - only non-zero leaves are stored.
#[derive(Debug, Clone)]
pub struct BalanceTree {
    /// Tree depth (supports 2^depth accounts)
    depth: usize,
    /// Leaf values: index -> balance
    leaves: HashMap<u64, u64>,
    /// Cached intermediate nodes for faster proof generation
    /// Key: (level, index), Value: hash
    #[allow(dead_code)]
    cache: HashMap<(usize, u64), [u8; 32]>,
    /// Whether the cache is valid
    #[allow(dead_code)]
    cache_valid: bool,
}

impl BalanceTree {
    /// Create a new empty balance tree
    pub fn new(depth: usize) -> Self {
        Self {
            depth,
            leaves: HashMap::new(),
            cache: HashMap::new(),
            cache_valid: false,
        }
    }

    /// Create a tree from existing balances
    pub fn from_balances(depth: usize, balances: HashMap<u64, u64>) -> Self {
        Self {
            depth,
            leaves: balances,
            cache: HashMap::new(),
            cache_valid: false,
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
        self.cache_valid = false;
    }

    /// Get merkle proof for a leaf
    pub fn get_proof(&self, index: u64) -> MerkleProof {
        let mut siblings = Vec::with_capacity(self.depth);
        let mut current_index = index;

        for level in 0..self.depth {
            // Sibling is at index XOR 1
            let sibling_index = current_index ^ 1;
            let sibling_hash = self.get_node_hash(level, sibling_index);
            siblings.push(sibling_hash);

            // Move to parent
            current_index /= 2;
        }

        MerkleProof::new(index, siblings)
    }

    /// Update a leaf and return the new root
    pub fn update(&mut self, index: u64, new_balance: u64) -> [u8; 32] {
        self.set_balance(index, new_balance);
        self.root()
    }

    /// Get current merkle root
    pub fn root(&self) -> [u8; 32] {
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
        let sender_merkle_proof = self.get_proof(sender_index);

        // Update sender balance
        let sender_balance_after = sender_balance_before - amount;
        self.set_balance(sender_index, sender_balance_after);

        // Get recipient proof against intermediate state (after sender update)
        let recipient_merkle_proof = self.get_proof(recipient_index);

        // Update recipient balance
        let recipient_balance_after = recipient_balance_before + amount;
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

    /// Get hash of a node at a given level and index
    ///
    /// Level 0 = leaves, Level depth = root
    fn get_node_hash(&self, level: usize, index: u64) -> [u8; 32] {
        if level == 0 {
            // Leaf node: hash the balance
            let balance = self.get_balance(index);
            self.hash_leaf(balance)
        } else {
            // Internal node: hash children
            let left = self.get_node_hash(level - 1, index * 2);
            let right = self.get_node_hash(level - 1, index * 2 + 1);
            self.hash_pair(&left, &right)
        }
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
    fn hash_pair(&self, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let left_field = bytes_to_field::<Fr>(left).unwrap_or_else(|| {
            warn!("Invalid left bytes in hash_pair, using zero");
            Fr::ZERO
        });
        let right_field = bytes_to_field::<Fr>(right).unwrap_or_else(|| {
            warn!("Invalid right bytes in hash_pair, using zero");
            Fr::ZERO
        });
        let hash = mimc_hash_native(left_field, right_field);
        field_to_bytes(hash)
    }

    /// Get the number of non-zero accounts
    pub fn account_count(&self) -> usize {
        self.leaves.len()
    }

    /// Get all account indices with non-zero balances
    pub fn accounts(&self) -> Vec<u64> {
        self.leaves.keys().copied().collect()
    }

    /// Get total balance across all accounts
    pub fn total_balance(&self) -> u64 {
        self.leaves.values().sum()
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
        let root1 = tree.root();
        let root2 = tree.root();
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

        let root1 = tree.root();
        tree.update(0, 1000);
        let root2 = tree.root();

        assert_ne!(root1, root2, "Root should change after update");
    }

    #[test]
    fn test_proof_generation() {
        let mut tree = BalanceTree::new(4);

        tree.set_balance(0, 1000);
        tree.set_balance(5, 500);

        let proof = tree.get_proof(0);

        assert_eq!(proof.leaf_index, 0);
        assert_eq!(proof.depth(), 4);

        // Verify the proof
        let leaf_hash = tree.hash_leaf(1000);
        let computed_root = proof.compute_root(leaf_hash);
        assert_eq!(computed_root, tree.root());
    }

    #[test]
    fn test_apply_payment() {
        let mut tree = BalanceTree::new(10);

        tree.set_balance(0, 1000); // Sender
        tree.set_balance(1, 500); // Recipient

        let initial_root = tree.root();

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
        assert_ne!(initial_root, tree.root());
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
            let proof = tree.get_proof(index);
            let balance = tree.get_balance(index);
            let leaf_hash = tree.hash_leaf(balance);
            let computed_root = proof.compute_root(leaf_hash);

            assert_eq!(
                computed_root,
                tree.root(),
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

        let original_root = tree.root();

        let (witness, new_tree) = tree.apply_payment_copy(0, 1, 100).unwrap();

        // Original tree unchanged
        assert_eq!(tree.root(), original_root);
        assert_eq!(tree.get_balance(0), 1000);

        // New tree updated
        assert_ne!(new_tree.root(), original_root);
        assert_eq!(new_tree.get_balance(0), 900);
        assert_eq!(new_tree.get_balance(1), 600);

        // Witness correct
        assert_eq!(witness.sender_balance_before, 1000);
        assert_eq!(witness.recipient_balance_before, 500);
    }
}
