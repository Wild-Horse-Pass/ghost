//! Merkle tree circuit components
//!
//! Provides circuits for verifying merkle inclusion proofs and
//! computing merkle root updates within the ZK circuit.
//!
//! # Hash Function
//!
//! This module uses a MiMC-style hash for merkle tree operations.
//! MiMC provides collision resistance through repeated cubing operations,
//! unlike simpler algebraic hashes which are trivially invertible.
//!
//! # Security Note
//!
//! The hash function MUST be collision-resistant to prevent merkle proof forgery.

use bellperson::{
    gadgets::boolean::{AllocatedBit, Boolean},
    gadgets::num::AllocatedNum,
    ConstraintSystem, SynthesisError,
};
use ff::PrimeField;

use super::mimc::mimc_hash;

/// Circuit for verifying a merkle inclusion proof
pub struct MerkleCircuit<F: PrimeField> {
    /// Leaf value (balance hash)
    pub leaf: Option<F>,
    /// Leaf index in the tree
    pub leaf_index: Option<u64>,
    /// Sibling hashes along the path
    pub siblings: Vec<Option<F>>,
    /// Expected root
    pub root: Option<F>,
}

impl<F: PrimeField> MerkleCircuit<F> {
    /// Create a new merkle circuit
    pub fn new(
        leaf: Option<F>,
        leaf_index: Option<u64>,
        siblings: Vec<Option<F>>,
        root: Option<F>,
    ) -> Self {
        Self {
            leaf,
            leaf_index,
            siblings,
            root,
        }
    }

    /// Create a dummy circuit for parameter generation
    pub fn dummy(depth: usize) -> Self {
        Self {
            leaf: None,
            leaf_index: None,
            siblings: vec![None; depth],
            root: None,
        }
    }

    /// Synthesize the merkle proof verification circuit
    pub fn synthesize<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> Result<AllocatedNum<F>, SynthesisError> {
        let depth = self.siblings.len();

        // Allocate leaf as private input
        let leaf = AllocatedNum::alloc(cs.namespace(|| "leaf"), || {
            self.leaf.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate leaf index bits
        let index_bits = self.alloc_index_bits(cs.namespace(|| "index_bits"), depth)?;

        // Allocate siblings
        let siblings: Vec<AllocatedNum<F>> = self
            .siblings
            .iter()
            .enumerate()
            .map(|(i, s)| {
                AllocatedNum::alloc(cs.namespace(|| format!("sibling_{}", i)), || {
                    s.ok_or(SynthesisError::AssignmentMissing)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Compute root by hashing up the tree
        let computed_root = self.compute_root(
            cs.namespace(|| "compute_root"),
            &leaf,
            &index_bits,
            &siblings,
        )?;

        // Allocate expected root as public input
        let expected_root = AllocatedNum::alloc_input(cs.namespace(|| "expected_root"), || {
            self.root.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Constrain computed root equals expected root
        cs.enforce(
            || "root matches",
            |lc| lc + computed_root.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + expected_root.get_variable(),
        );

        Ok(computed_root)
    }

    /// Allocate index bits from the leaf index
    fn alloc_index_bits<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        depth: usize,
    ) -> Result<Vec<Boolean>, SynthesisError> {
        let index = self.leaf_index.unwrap_or(0);

        let mut bits = Vec::with_capacity(depth);
        for i in 0..depth {
            let bit_value = ((index >> i) & 1) == 1;
            let bit =
                AllocatedBit::alloc(cs.namespace(|| format!("index_bit_{}", i)), Some(bit_value))?;
            bits.push(Boolean::from(bit));
        }

        Ok(bits)
    }

    /// Compute merkle root from leaf and siblings
    fn compute_root<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        leaf: &AllocatedNum<F>,
        index_bits: &[Boolean],
        siblings: &[AllocatedNum<F>],
    ) -> Result<AllocatedNum<F>, SynthesisError> {
        let mut current = leaf.clone();

        for (i, (bit, sibling)) in index_bits.iter().zip(siblings.iter()).enumerate() {
            // Hash(left || right) where position depends on index bit
            current = self.hash_pair(
                cs.namespace(|| format!("hash_level_{}", i)),
                &current,
                sibling,
                bit,
            )?;
        }

        Ok(current)
    }

    /// Hash a pair of nodes, ordering by index bit
    ///
    /// If bit is 0, current is left child: Hash(current || sibling)
    /// If bit is 1, current is right child: Hash(sibling || current)
    ///
    /// Uses MiMC-style hash for collision resistance.
    fn hash_pair<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        current: &AllocatedNum<F>,
        sibling: &AllocatedNum<F>,
        bit: &Boolean,
    ) -> Result<AllocatedNum<F>, SynthesisError> {
        // Select left and right based on bit
        // left = bit ? sibling : current
        // right = bit ? current : sibling
        let left = Self::select(cs.namespace(|| "select_left"), sibling, current, bit)?;

        let right = Self::select(cs.namespace(|| "select_right"), current, sibling, bit)?;

        // Use MiMC-style hash for collision resistance (from mimc module)
        mimc_hash(cs.namespace(|| "hash"), &left, &right)
    }

    /// Select between two values based on a boolean
    /// Returns if_true if bit is true, else if_false
    fn select<CS: ConstraintSystem<F>>(
        mut cs: CS,
        if_true: &AllocatedNum<F>,
        if_false: &AllocatedNum<F>,
        bit: &Boolean,
    ) -> Result<AllocatedNum<F>, SynthesisError> {
        // Handle constant case early
        if let Boolean::Constant(c) = bit {
            return if *c {
                Ok(if_true.clone())
            } else {
                Ok(if_false.clone())
            };
        }

        // result = bit * (if_true - if_false) + if_false
        let result = AllocatedNum::alloc(cs.namespace(|| "select_result"), || {
            let bit_val = match bit.get_value() {
                Some(true) => F::ONE,
                Some(false) => F::ZERO,
                None => return Err(SynthesisError::AssignmentMissing),
            };
            let if_true_val = if_true
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?;
            let if_false_val = if_false
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?;

            Ok(bit_val * (if_true_val - if_false_val) + if_false_val)
        })?;

        // Get the bit variable - for Is and Not, we can use the underlying AllocatedBit
        match bit {
            Boolean::Is(ref b) => {
                cs.enforce(
                    || "select constraint",
                    |lc| lc + b.get_variable(),
                    |lc| lc + if_true.get_variable() - if_false.get_variable(),
                    |lc| lc + result.get_variable() - if_false.get_variable(),
                );
            }
            Boolean::Not(ref b) => {
                // For Not(b), we want (1-b) * (if_true - if_false) = result - if_false
                // Rearranged: (if_true - if_false) - b*(if_true - if_false) = result - if_false
                cs.enforce(
                    || "select constraint (negated)",
                    |lc| lc + CS::one() - b.get_variable(),
                    |lc| lc + if_true.get_variable() - if_false.get_variable(),
                    |lc| lc + result.get_variable() - if_false.get_variable(),
                );
            }
            Boolean::Constant(_) => unreachable!(), // Handled above
        }

        Ok(result)
    }

    // MiMC hash is imported from super::mimc module (23 rounds, SHA256-derived constants)
}

/// Update a merkle tree and return the new root
pub struct MerkleUpdateCircuit<F: PrimeField> {
    /// Old leaf value
    pub old_leaf: Option<F>,
    /// New leaf value
    pub new_leaf: Option<F>,
    /// Leaf index
    pub leaf_index: Option<u64>,
    /// Siblings (same for old and new)
    pub siblings: Vec<Option<F>>,
    /// Old root (to verify)
    pub old_root: Option<F>,
    /// New root (computed)
    pub new_root: Option<F>,
}

impl<F: PrimeField> MerkleUpdateCircuit<F> {
    /// Synthesize merkle update verification
    ///
    /// Verifies:
    /// 1. old_leaf + siblings produces old_root
    /// 2. new_leaf + siblings produces new_root
    pub fn synthesize<CS: ConstraintSystem<F>>(
        self,
        mut cs: CS,
    ) -> Result<(AllocatedNum<F>, AllocatedNum<F>), SynthesisError> {
        // Verify old inclusion
        let old_circuit = MerkleCircuit::new(
            self.old_leaf,
            self.leaf_index,
            self.siblings.clone(),
            self.old_root,
        );
        let computed_old_root = old_circuit.synthesize(&mut cs.namespace(|| "old_inclusion"))?;

        // Compute new root with new leaf
        let new_circuit =
            MerkleCircuit::new(self.new_leaf, self.leaf_index, self.siblings, self.new_root);
        let computed_new_root = new_circuit.synthesize(&mut cs.namespace(|| "new_root"))?;

        Ok((computed_old_root, computed_new_root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;

    #[test]
    fn test_merkle_circuit_dummy() {
        let circuit = MerkleCircuit::<Fr>::dummy(10);
        assert_eq!(circuit.siblings.len(), 10);
    }

    /// MiMC hash for testing (must match circuit implementation)
    // mimc_hash_native is imported from super::mimc via super::*

    #[test]
    fn test_simple_merkle_proof() {
        // Create a simple 1-level tree
        let leaf = Fr::from(42u64);
        let sibling = Fr::from(100u64);

        // Compute expected root using MiMC hash from shared module
        // For index 0 (left child): root = H(leaf, sibling)
        use crate::circuit::mimc::mimc_hash_native;
        let expected_root = mimc_hash_native(leaf, sibling);

        let circuit = MerkleCircuit {
            leaf: Some(leaf),
            leaf_index: Some(0),
            siblings: vec![Some(sibling)],
            root: Some(expected_root),
        };

        let mut cs = TestConstraintSystem::<Fr>::new();
        circuit.synthesize(&mut cs).unwrap();

        assert!(cs.is_satisfied(), "Circuit should be satisfied");
    }
}
