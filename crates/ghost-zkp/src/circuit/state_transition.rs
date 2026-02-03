//! State transition circuit for ZK-proven state root changes
//!
//! Proves that a single payment correctly transitions state from one root
//! to another via sender and recipient merkle leaf updates.
//!
//! # Hash Function
//!
//! This circuit uses a Poseidon-based hash for merkle tree operations.
//! Poseidon is a ZK-friendly hash function that is algebraically structured
//! for efficient constraint generation.
//!
//! # Security Note
//!
//! The hash function used here MUST be collision-resistant in the circuit.
//! A weak hash (like simple multiplication) would allow attackers to forge
//! merkle proofs. The current implementation uses MiMC-style hashing which
//! provides adequate security for merkle tree operations.

use bellperson::{
    gadgets::boolean::{AllocatedBit, Boolean},
    gadgets::num::AllocatedNum,
    ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::PrimeField;

use super::mimc::{mimc_hash, mimc_hash_native};
use super::payment::{PaymentCircuit, PaymentCircuitError};

/// Circuit proving a single payment's state transition is valid
///
/// This circuit proves:
/// 1. Payment validity (balance arithmetic via PaymentCircuit)
/// 2. Sender's old balance exists in input_root
/// 3. Updating sender's balance produces intermediate_root
/// 4. Recipient's old balance exists in intermediate_root
/// 5. Updating recipient's balance produces output_root
pub struct PaymentStateTransitionCircuit<F: PrimeField> {
    /// Payment circuit for balance arithmetic
    pub payment: PaymentCircuit<F>,

    /// Sender's leaf index in the tree
    pub sender_index: Option<u64>,
    /// Sender's sibling hashes for merkle proof
    pub sender_siblings: Vec<Option<F>>,

    /// Recipient's leaf index in the tree
    pub recipient_index: Option<u64>,
    /// Recipient's old balance (for merkle proof in intermediate_root)
    pub recipient_old_balance: Option<u64>,
    /// Recipient's sibling hashes for merkle proof
    pub recipient_siblings: Vec<Option<F>>,

    /// Input state root (before this payment)
    pub input_root: Option<F>,
    /// Output state root (after this payment)
    pub output_root: Option<F>,

    /// Tree depth
    pub tree_depth: usize,
}

/// Outputs from state transition synthesis
pub struct StateTransitionOutputs<F: PrimeField> {
    /// Input root variable (constrained by parent)
    pub input_root: AllocatedNum<F>,
    /// Output root variable (constrained by parent)
    pub output_root: AllocatedNum<F>,
    /// Sender's balance after payment
    pub sender_after: AllocatedNum<F>,
    /// Recipient's balance after payment
    pub recipient_after: AllocatedNum<F>,
}

impl<F: PrimeField> std::fmt::Debug for StateTransitionOutputs<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateTransitionOutputs")
            .field("input_root", &self.input_root.get_value())
            .field("output_root", &self.output_root.get_value())
            .field("sender_after", &self.sender_after.get_value())
            .field("recipient_after", &self.recipient_after.get_value())
            .finish()
    }
}

impl<F: PrimeField> PaymentStateTransitionCircuit<F> {
    /// Create a new state transition circuit
    /// Returns an error if the payment would cause overflow or underflow
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sender_balance_before: Option<u64>,
        recipient_balance_before: Option<u64>,
        amount: Option<u64>,
        sender_index: Option<u64>,
        sender_siblings: Vec<Option<F>>,
        recipient_index: Option<u64>,
        recipient_siblings: Vec<Option<F>>,
        input_root: Option<F>,
        output_root: Option<F>,
        tree_depth: usize,
    ) -> Result<Self, PaymentCircuitError> {
        Ok(Self {
            payment: PaymentCircuit::new(sender_balance_before, recipient_balance_before, amount)?,
            sender_index,
            sender_siblings,
            recipient_index,
            recipient_old_balance: recipient_balance_before,
            recipient_siblings,
            input_root,
            output_root,
            tree_depth,
        })
    }

    /// Create a dummy circuit for parameter generation
    pub fn dummy(tree_depth: usize) -> Self {
        Self {
            payment: PaymentCircuit::dummy(),
            sender_index: Some(0),
            sender_siblings: vec![Some(F::ZERO); tree_depth],
            recipient_index: Some(1),
            recipient_old_balance: Some(0),
            recipient_siblings: vec![Some(F::ZERO); tree_depth],
            input_root: Some(F::ZERO),
            output_root: Some(F::ZERO),
            tree_depth,
        }
    }

    /// Synthesize the state transition circuit
    ///
    /// Returns the input and output roots for chaining.
    pub fn synthesize<CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> Result<StateTransitionOutputs<F>, SynthesisError> {
        // Save all values before any moves
        let sender_balance_before = self.payment.sender_balance_before;
        let sender_index = self.sender_index;
        let sender_siblings = self.sender_siblings;
        let recipient_index = self.recipient_index;
        let recipient_old_balance = self.recipient_old_balance;
        let recipient_siblings = self.recipient_siblings;
        let input_root_val = self.input_root;
        let output_root_val = self.output_root;
        let tree_depth = self.tree_depth;

        // 1. Prove payment validity (balance arithmetic)
        let payment_outputs = self.payment.synthesize(&mut cs.namespace(|| "payment"))?;

        // Get sender's old balance as field element
        let sender_old = AllocatedNum::alloc(cs.namespace(|| "sender_old_balance"), || {
            sender_balance_before
                .map(|b| F::from(b))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // 2. Allocate input root (will be constrained by parent or as public input)
        let input_root = AllocatedNum::alloc(cs.namespace(|| "input_root"), || {
            input_root_val.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // 3. Verify sender's old balance in input_root and compute intermediate_root
        let sender_index_bits =
            alloc_index_bits(cs.namespace(|| "sender_index"), sender_index, tree_depth)?;
        let sender_siblings_alloc =
            alloc_siblings(cs.namespace(|| "sender_siblings"), &sender_siblings)?;

        // Verify sender's balance is in input_root
        let computed_input_root = compute_root(
            cs.namespace(|| "verify_sender_in_input"),
            &sender_old,
            &sender_index_bits,
            &sender_siblings_alloc,
        )?;

        // Constrain: computed root from sender proof == input_root
        cs.enforce(
            || "sender_in_input_root",
            |lc| lc + computed_input_root.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + input_root.get_variable(),
        );

        // Compute intermediate_root after updating sender's balance
        let intermediate_root = compute_root(
            cs.namespace(|| "compute_intermediate_root"),
            &payment_outputs.sender_after,
            &sender_index_bits,
            &sender_siblings_alloc,
        )?;

        // 4. Allocate recipient's old balance
        let recipient_old = AllocatedNum::alloc(cs.namespace(|| "recipient_old_balance"), || {
            recipient_old_balance
                .map(|b| F::from(b))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate recipient merkle data
        let recipient_index_bits = alloc_index_bits(
            cs.namespace(|| "recipient_index"),
            recipient_index,
            tree_depth,
        )?;
        let recipient_siblings_alloc =
            alloc_siblings(cs.namespace(|| "recipient_siblings"), &recipient_siblings)?;

        // Verify recipient's old balance is in intermediate_root
        let computed_intermediate_root = compute_root(
            cs.namespace(|| "verify_recipient_in_intermediate"),
            &recipient_old,
            &recipient_index_bits,
            &recipient_siblings_alloc,
        )?;

        // Constrain: computed root from recipient proof == intermediate_root
        cs.enforce(
            || "recipient_in_intermediate_root",
            |lc| lc + computed_intermediate_root.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + intermediate_root.get_variable(),
        );

        // 5. Compute output_root after updating recipient's balance
        let computed_output_root = compute_root(
            cs.namespace(|| "compute_output_root"),
            &payment_outputs.recipient_after,
            &recipient_index_bits,
            &recipient_siblings_alloc,
        )?;

        // 6. Allocate output root (will be constrained by parent)
        let output_root = AllocatedNum::alloc(cs.namespace(|| "output_root"), || {
            output_root_val.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Constrain: computed output root == expected output root
        cs.enforce(
            || "output_root_matches",
            |lc| lc + computed_output_root.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + output_root.get_variable(),
        );

        Ok(StateTransitionOutputs {
            input_root,
            output_root,
            sender_after: payment_outputs.sender_after,
            recipient_after: payment_outputs.recipient_after,
        })
    }
}

/// Allocate index bits from a leaf index
fn alloc_index_bits<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    index: Option<u64>,
    tree_depth: usize,
) -> Result<Vec<Boolean>, SynthesisError> {
    let index_val = index.unwrap_or(0);

    let mut bits = Vec::with_capacity(tree_depth);
    for i in 0..tree_depth {
        let bit_value = ((index_val >> i) & 1) == 1;
        let bit = AllocatedBit::alloc(cs.namespace(|| format!("bit_{}", i)), Some(bit_value))?;
        bits.push(Boolean::from(bit));
    }

    Ok(bits)
}

/// Allocate sibling hashes
fn alloc_siblings<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    siblings: &[Option<F>],
) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    siblings
        .iter()
        .enumerate()
        .map(|(i, s)| {
            AllocatedNum::alloc(cs.namespace(|| format!("sibling_{}", i)), || {
                s.ok_or(SynthesisError::AssignmentMissing)
            })
        })
        .collect()
}

/// Compute merkle root from leaf and siblings
fn compute_root<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    leaf: &AllocatedNum<F>,
    index_bits: &[Boolean],
    siblings: &[AllocatedNum<F>],
) -> Result<AllocatedNum<F>, SynthesisError> {
    let mut current = leaf.clone();

    for (i, (bit, sibling)) in index_bits.iter().zip(siblings.iter()).enumerate() {
        current = hash_pair(
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
/// Uses MiMC-style hash for collision resistance in merkle tree operations.
fn hash_pair<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    current: &AllocatedNum<F>,
    sibling: &AllocatedNum<F>,
    bit: &Boolean,
) -> Result<AllocatedNum<F>, SynthesisError> {
    // Select left and right based on bit
    let left = select(cs.namespace(|| "select_left"), sibling, current, bit)?;
    let right = select(cs.namespace(|| "select_right"), current, sibling, bit)?;

    // Hash using MiMC-style function for collision resistance
    mimc_hash(cs.namespace(|| "hash"), &left, &right)
}

/// Select between two values based on a boolean
fn select<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    if_true: &AllocatedNum<F>,
    if_false: &AllocatedNum<F>,
    bit: &Boolean,
) -> Result<AllocatedNum<F>, SynthesisError> {
    if let Boolean::Constant(c) = bit {
        return if *c {
            Ok(if_true.clone())
        } else {
            Ok(if_false.clone())
        };
    }

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
            cs.enforce(
                || "select constraint (negated)",
                |lc| lc + CS::one() - b.get_variable(),
                |lc| lc + if_true.get_variable() - if_false.get_variable(),
                |lc| lc + result.get_variable() - if_false.get_variable(),
            );
        }
        Boolean::Constant(_) => unreachable!(),
    }

    Ok(result)
}

// MiMC hash is imported from super::mimc module (23 rounds, SHA256-derived constants)

/// Helper to convert a u64 balance to a field element
pub fn balance_to_field<F: PrimeField>(balance: Option<u64>) -> Option<F> {
    balance.map(|b| F::from(b))
}

/// Enforce that a value fits in the given number of bits (range proof)
pub fn enforce_fits_in_bits<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    value: &AllocatedNum<F>,
    num_bits: usize,
) -> Result<Vec<Boolean>, SynthesisError> {
    let value_bits = value.get_value().map(|v| {
        let bytes = v.to_repr();
        let mut result = 0u64;
        for (i, byte) in bytes.as_ref().iter().take(8).enumerate() {
            result |= (*byte as u64) << (i * 8);
        }
        result
    });

    let mut bits = Vec::with_capacity(num_bits);

    for i in 0..num_bits {
        let bit_value = value_bits.map(|v| ((v >> i) & 1) == 1);
        let bit = AllocatedBit::alloc(cs.namespace(|| format!("bit_{}", i)), bit_value)?;
        bits.push(Boolean::from(bit));
    }

    // Reconstruct and constrain
    let mut coeff = F::ONE;
    let mut lc_sum = LinearCombination::<F>::zero();

    for bit in bits.iter() {
        match bit {
            Boolean::Is(ref b) => {
                lc_sum = lc_sum + (coeff, b.get_variable());
            }
            Boolean::Not(ref b) => {
                lc_sum = lc_sum + (coeff, CS::one()) - (coeff, b.get_variable());
            }
            Boolean::Constant(c) => {
                if *c {
                    lc_sum = lc_sum + (coeff, CS::one());
                }
            }
        }
        coeff = coeff.double();
    }

    cs.enforce(
        || "reconstructed equals value",
        |_| lc_sum,
        |lc| lc + CS::one(),
        |lc| lc + value.get_variable(),
    );

    Ok(bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;

    // mimc_hash_native is imported from super::mimc via super::*

    /// Helper to compute merkle root using MiMC hash
    fn compute_test_root(leaf: Fr, index: u64, siblings: &[Fr]) -> Fr {
        let mut current = leaf;
        let mut idx = index;

        for sibling in siblings {
            let (left, right) = if idx % 2 == 0 {
                (current, *sibling)
            } else {
                (*sibling, current)
            };
            // MiMC hash (matches circuit implementation)
            current = mimc_hash_native(left, right);
            idx /= 2;
        }

        current
    }

    #[test]
    fn test_dummy_state_transition() {
        let circuit = PaymentStateTransitionCircuit::<Fr>::dummy(4);

        let mut cs = TestConstraintSystem::<Fr>::new();
        let result = circuit.synthesize(&mut cs);

        assert!(result.is_ok(), "Dummy circuit should synthesize");
        // Note: Dummy circuit may not satisfy due to zero roots not matching computed
    }

    #[test]
    fn test_valid_payment_transition() {
        // Simple 2-level tree for testing
        let tree_depth = 2;

        // Sender at index 0, recipient at index 2 (different subtrees)
        let sender_balance_before = 1000u64;
        let recipient_balance_before = 500u64;
        let amount = 100u64;

        let sender_balance_after = sender_balance_before - amount;
        let recipient_balance_after = recipient_balance_before + amount;

        let sender_leaf = Fr::from(sender_balance_before);
        let sender_new_leaf = Fr::from(sender_balance_after);
        let recipient_leaf = Fr::from(recipient_balance_before);
        let recipient_new_leaf = Fr::from(recipient_balance_after);

        // Tree structure:
        // Leaves: [sender(0), sibling_0(1), recipient(2), leaf_3(3)]
        // Level 1: [hash_01, hash_23]
        // Root: hash(hash_01, hash_23)

        let sibling_0 = Fr::from(100u64); // Leaf at index 1
        let leaf_3 = Fr::from(300u64); // Leaf at index 3
        let recipient_idx = 2u64;

        // Compute hashes using MiMC (matches circuit)
        // Initial state
        let hash_01_initial = mimc_hash_native(sender_leaf, sibling_0);
        let hash_23_initial = mimc_hash_native(recipient_leaf, leaf_3);
        let input_root = mimc_hash_native(hash_01_initial, hash_23_initial);

        // After sender update (intermediate state)
        let hash_01_after_sender = mimc_hash_native(sender_new_leaf, sibling_0);
        let intermediate_root = mimc_hash_native(hash_01_after_sender, hash_23_initial);

        // After recipient update (final state)
        let hash_23_final = mimc_hash_native(recipient_new_leaf, leaf_3);
        let output_root = mimc_hash_native(hash_01_after_sender, hash_23_final);

        // Sender at index 0: siblings = [sibling_0, hash_23_initial]
        let sender_siblings = vec![sibling_0, hash_23_initial];

        // Recipient at index 2: siblings = [leaf_3, hash_01_after_sender]
        let recipient_siblings = vec![leaf_3, hash_01_after_sender];

        // Verify our native computation matches what the circuit expects
        let check_input = compute_test_root(sender_leaf, 0, &sender_siblings);
        assert_eq!(
            check_input, input_root,
            "Input root computation should match"
        );

        let check_intermediate =
            compute_test_root(recipient_leaf, recipient_idx, &recipient_siblings);
        assert_eq!(
            check_intermediate, intermediate_root,
            "Intermediate root computation should match"
        );

        // Create the circuit
        let circuit = PaymentStateTransitionCircuit {
            payment: PaymentCircuit::new(
                Some(sender_balance_before),
                Some(recipient_balance_before),
                Some(amount),
            )
            .expect("Valid payment should succeed"),
            sender_index: Some(0),
            sender_siblings: sender_siblings.iter().map(|s| Some(*s)).collect(),
            recipient_index: Some(recipient_idx),
            recipient_old_balance: Some(recipient_balance_before),
            recipient_siblings: recipient_siblings.iter().map(|s| Some(*s)).collect(),
            input_root: Some(input_root),
            output_root: Some(output_root),
            tree_depth,
        };

        let mut cs = TestConstraintSystem::<Fr>::new();
        let result = circuit.synthesize(&mut cs);

        assert!(result.is_ok(), "Circuit should synthesize: {:?}", result);
        assert!(
            cs.is_satisfied(),
            "Valid payment transition should satisfy: {:?}",
            cs.which_is_unsatisfied()
        );

        println!(
            "State transition circuit constraints: {}",
            cs.num_constraints()
        );
    }

    #[test]
    fn test_insufficient_balance_fails() {
        // Sender trying to send more than they have
        let sender_balance_before = 50u64;
        let recipient_balance_before = 500u64;
        let amount = 100u64; // More than sender has!

        // Circuit creation should fail with checked arithmetic
        let result = PaymentCircuit::<Fr>::new(
            Some(sender_balance_before),
            Some(recipient_balance_before),
            Some(amount),
        );

        assert!(
            result.is_err(),
            "Insufficient balance should fail circuit creation"
        );
    }

    #[test]
    fn test_wrong_input_root_fails() {
        let tree_depth = 2;

        let sender_balance_before = 1000u64;
        let recipient_balance_before = 500u64;
        let amount = 100u64;

        let sibling_0 = Fr::from(100u64);
        let sibling_1 = Fr::from(200u64);

        // Compute actual input root
        let sender_leaf = Fr::from(sender_balance_before);
        let _actual_input_root = compute_test_root(sender_leaf, 0, &[sibling_0, sibling_1]);

        // Use wrong input root
        let wrong_input_root = Fr::from(999999u64);

        let circuit = PaymentStateTransitionCircuit {
            payment: PaymentCircuit::new(
                Some(sender_balance_before),
                Some(recipient_balance_before),
                Some(amount),
            )
            .expect("Valid payment should succeed"),
            sender_index: Some(0),
            sender_siblings: vec![Some(sibling_0), Some(sibling_1)],
            recipient_index: Some(2),
            recipient_old_balance: Some(recipient_balance_before),
            recipient_siblings: vec![Some(Fr::from(150u64)), Some(Fr::from(250u64))],
            input_root: Some(wrong_input_root),
            output_root: Some(Fr::from(1001u64)),
            tree_depth,
        };

        let mut cs = TestConstraintSystem::<Fr>::new();
        let _ = circuit.synthesize(&mut cs);

        // Should fail because input root doesn't match computed
        assert!(!cs.is_satisfied(), "Wrong input root should not satisfy");
    }

    #[test]
    fn test_constraint_count() {
        let circuit = PaymentStateTransitionCircuit::<Fr>::dummy(20);

        let mut cs = TestConstraintSystem::<Fr>::new();
        let _ = circuit.synthesize(&mut cs);

        println!(
            "State transition (depth=20) constraints: {}",
            cs.num_constraints()
        );

        // Should have constraints for:
        // - Payment circuit (~128 for range proofs)
        // - 4 merkle computations (2 for sender, 2 for recipient)
        // - Each level: ~3 constraints (select_left, select_right, hash)
        // Total per merkle: ~3 * depth constraints
        // Expected: ~128 + 4 * 3 * 20 = ~368 constraints
        assert!(
            cs.num_constraints() > 300,
            "Should have significant constraints"
        );
    }
}
