//! Confidential transfer circuit for privacy-preserving L2 transfers
//!
//! Proves a transfer is valid without revealing amounts:
//!
//! **Public inputs** (visible to validators):
//! 1. `old_commitment_root` — merkle root of commitment tree before transfer
//! 2. `new_commitment_root` — merkle root after transfer
//! 3. `nullifier` — prevents double-spend
//! 4. `sender_new_commitment` — commitment for sender's remaining balance
//! 5. `recipient_new_commitment` — commitment for recipient's new balance
//!
//! **Constraints** enforced:
//! 1. Sender note exists in old tree (merkle inclusion)
//! 2. Ownership via nullifier (spending key binds to note)
//! 3. Sufficient funds (range proof on change amount)
//! 4. Balance conservation (sender_old = change + amount; recipient_new = recipient_old + amount)
//! 5. New commitments are correctly formed
//! 6. Range proofs on all values (prevent field wrap-around)
//! 7. Tree update (new root reflects replaced commitments)
//!
//! Estimated ~6,200 constraints for tree_depth=20 — well within Groth16 feasibility.

use bellperson::{
    gadgets::boolean::{AllocatedBit, Boolean},
    gadgets::num::AllocatedNum,
    Circuit, ConstraintSystem, SynthesisError,
};
use ff::PrimeField;

use super::commitment::{pedersen_commit, NULLIFIER_DOMAIN_SEPARATOR};
use super::mimc::{mimc_hash, mimc_hash_native};
use super::range_proof::enforce_range;
use super::BALANCE_BITS;

/// Circuit proving a confidential transfer is valid
pub struct ConfidentialTransferCircuit<F: PrimeField> {
    // Public inputs
    pub old_commitment_root: Option<F>,
    pub new_commitment_root: Option<F>,
    pub nullifier: Option<F>,
    pub sender_new_commitment: Option<F>,
    pub recipient_new_commitment: Option<F>,

    // Private inputs — sender's existing note
    pub sender_value: Option<u64>,
    pub sender_blinding: Option<F>,
    pub sender_spending_key: Option<F>,
    pub sender_index: Option<u64>,
    pub sender_siblings: Vec<Option<F>>,

    // Private inputs — transfer
    pub amount: Option<u64>,

    // Private inputs — sender's new note (change)
    pub sender_new_blinding: Option<F>,

    // Private inputs — recipient's existing note
    pub recipient_old_value: Option<u64>,
    pub recipient_old_blinding: Option<F>,
    pub recipient_index: Option<u64>,
    pub recipient_siblings: Vec<Option<F>>,

    // Private inputs — recipient's new note
    pub recipient_new_blinding: Option<F>,

    pub tree_depth: usize,
}

impl<F: PrimeField> ConfidentialTransferCircuit<F> {
    /// Create a dummy circuit for MPC parameter generation
    ///
    /// Uses zero values that allow synthesis without errors.
    /// The circuit structure (constraint count/wiring) must be identical
    /// to real instances — only the witness values differ.
    pub fn dummy(tree_depth: usize) -> Self {
        Self {
            old_commitment_root: Some(F::ZERO),
            new_commitment_root: Some(F::ZERO),
            nullifier: Some(F::ZERO),
            sender_new_commitment: Some(F::ZERO),
            recipient_new_commitment: Some(F::ZERO),
            sender_value: Some(0),
            sender_blinding: Some(F::ZERO),
            sender_spending_key: Some(F::ZERO),
            sender_index: Some(0),
            sender_siblings: vec![Some(F::ZERO); tree_depth],
            amount: Some(0),
            sender_new_blinding: Some(F::ZERO),
            recipient_old_value: Some(0),
            recipient_old_blinding: Some(F::ZERO),
            recipient_index: Some(1),
            recipient_siblings: vec![Some(F::ZERO); tree_depth],
            recipient_new_blinding: Some(F::ZERO),
            tree_depth,
        }
    }
}

impl<F: PrimeField> Circuit<F> for ConfidentialTransferCircuit<F> {
    fn synthesize<CS: ConstraintSystem<F>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let tree_depth = self.tree_depth;

        // ====================================================================
        // 1. Allocate public inputs
        // ====================================================================

        let old_root = AllocatedNum::alloc_input(cs.namespace(|| "old_commitment_root"), || {
            self.old_commitment_root
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let new_root = AllocatedNum::alloc_input(cs.namespace(|| "new_commitment_root"), || {
            self.new_commitment_root
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let nullifier_pub = AllocatedNum::alloc_input(cs.namespace(|| "nullifier"), || {
            self.nullifier.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let sender_new_commit_pub =
            AllocatedNum::alloc_input(cs.namespace(|| "sender_new_commitment"), || {
                self.sender_new_commitment
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        let recipient_new_commit_pub =
            AllocatedNum::alloc_input(cs.namespace(|| "recipient_new_commitment"), || {
                self.recipient_new_commitment
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        // ====================================================================
        // 2. Allocate private inputs
        // ====================================================================

        let sender_value = AllocatedNum::alloc(cs.namespace(|| "sender_value"), || {
            self.sender_value
                .map(|v| F::from(v))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let sender_blinding = AllocatedNum::alloc(cs.namespace(|| "sender_blinding"), || {
            self.sender_blinding
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let sender_spending_key =
            AllocatedNum::alloc(cs.namespace(|| "sender_spending_key"), || {
                self.sender_spending_key
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        let amount = AllocatedNum::alloc(cs.namespace(|| "amount"), || {
            self.amount
                .map(|v| F::from(v))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let sender_new_blinding =
            AllocatedNum::alloc(cs.namespace(|| "sender_new_blinding"), || {
                self.sender_new_blinding
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        let recipient_old_value =
            AllocatedNum::alloc(cs.namespace(|| "recipient_old_value"), || {
                self.recipient_old_value
                    .map(|v| F::from(v))
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        let recipient_old_blinding =
            AllocatedNum::alloc(cs.namespace(|| "recipient_old_blinding"), || {
                self.recipient_old_blinding
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        let recipient_new_blinding =
            AllocatedNum::alloc(cs.namespace(|| "recipient_new_blinding"), || {
                self.recipient_new_blinding
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        // Allocate sender merkle data
        let sender_index_bits = alloc_index_bits(
            cs.namespace(|| "sender_index"),
            self.sender_index,
            tree_depth,
        )?;
        let sender_siblings =
            alloc_siblings(cs.namespace(|| "sender_siblings"), &self.sender_siblings)?;

        // Allocate recipient merkle data
        let recipient_index_bits = alloc_index_bits(
            cs.namespace(|| "recipient_index"),
            self.recipient_index,
            tree_depth,
        )?;
        let recipient_siblings = alloc_siblings(
            cs.namespace(|| "recipient_siblings"),
            &self.recipient_siblings,
        )?;

        // Allocate sender index as field element (for note_id computation)
        let sender_index_field =
            AllocatedNum::alloc(cs.namespace(|| "sender_index_field"), || {
                self.sender_index
                    .map(|v| F::from(v))
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        // ====================================================================
        // 3. Compute sender's commitment: C = MiMC(MiMC(value, blinding), domain)
        // ====================================================================

        let sender_commitment = pedersen_commit(
            cs.namespace(|| "sender_commitment"),
            &sender_value,
            &sender_blinding,
        )?;

        // ====================================================================
        // 4. Verify sender's commitment exists in old_root (merkle inclusion)
        // ====================================================================

        let computed_old_root = compute_commitment_root(
            cs.namespace(|| "verify_sender_in_old_root"),
            &sender_commitment,
            &sender_index_bits,
            &sender_siblings,
        )?;

        cs.enforce(
            || "sender_in_old_root",
            |lc| lc + computed_old_root.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + old_root.get_variable(),
        );

        // ====================================================================
        // 5. Compute and verify nullifier (proves ownership)
        //    nullifier = MiMC(MiMC(spending_key, note_id), NULLIFIER_DOMAIN)
        //    note_id = MiMC(sender_index, sender_commitment)
        // ====================================================================

        let note_id = mimc_hash(
            cs.namespace(|| "note_id"),
            &sender_index_field,
            &sender_commitment,
        )?;

        // Allocate nullifier domain separator
        let nullifier_domain_value = F::from(NULLIFIER_DOMAIN_SEPARATOR);
        let nullifier_domain = AllocatedNum::alloc(cs.namespace(|| "nullifier_domain"), || {
            Ok(nullifier_domain_value)
        })?;
        cs.enforce(
            || "nullifier_domain_constant",
            |lc| lc + nullifier_domain.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + (nullifier_domain_value, CS::one()),
        );

        let nullifier_inner = mimc_hash(
            cs.namespace(|| "nullifier_inner"),
            &sender_spending_key,
            &note_id,
        )?;
        let computed_nullifier = mimc_hash(
            cs.namespace(|| "nullifier_outer"),
            &nullifier_inner,
            &nullifier_domain,
        )?;

        cs.enforce(
            || "nullifier_matches",
            |lc| lc + computed_nullifier.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + nullifier_pub.get_variable(),
        );

        // ====================================================================
        // 6. Balance conservation
        //    sender_new_value = sender_value - amount
        //    recipient_new_value = recipient_old_value + amount
        // ====================================================================

        let sender_new_value = AllocatedNum::alloc(cs.namespace(|| "sender_new_value"), || {
            let sv = self.sender_value.ok_or(SynthesisError::AssignmentMissing)?;
            let a = self.amount.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(F::from(sv.saturating_sub(a)))
        })?;

        // Constrain: sender_value = sender_new_value + amount
        cs.enforce(
            || "sender_balance_conservation",
            |lc| lc + sender_new_value.get_variable() + amount.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + sender_value.get_variable(),
        );

        let recipient_new_value =
            AllocatedNum::alloc(cs.namespace(|| "recipient_new_value"), || {
                let rv = self
                    .recipient_old_value
                    .ok_or(SynthesisError::AssignmentMissing)?;
                let a = self.amount.ok_or(SynthesisError::AssignmentMissing)?;
                Ok(F::from(rv.saturating_add(a)))
            })?;

        // Constrain: recipient_new_value = recipient_old_value + amount
        cs.enforce(
            || "recipient_balance_conservation",
            |lc| lc + recipient_old_value.get_variable() + amount.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + recipient_new_value.get_variable(),
        );

        // ====================================================================
        // 7. Range proofs (prevent field wrap-around)
        // ====================================================================

        enforce_range(
            cs.namespace(|| "range_sender_new_value"),
            &sender_new_value,
            BALANCE_BITS,
        )?;
        enforce_range(
            cs.namespace(|| "range_recipient_new_value"),
            &recipient_new_value,
            BALANCE_BITS,
        )?;
        enforce_range(cs.namespace(|| "range_amount"), &amount, BALANCE_BITS)?;

        // ====================================================================
        // 8. Verify new commitments match public inputs
        // ====================================================================

        let computed_sender_new_commitment = pedersen_commit(
            cs.namespace(|| "sender_new_commitment_compute"),
            &sender_new_value,
            &sender_new_blinding,
        )?;

        cs.enforce(
            || "sender_new_commitment_matches",
            |lc| lc + computed_sender_new_commitment.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + sender_new_commit_pub.get_variable(),
        );

        let computed_recipient_new_commitment = pedersen_commit(
            cs.namespace(|| "recipient_new_commitment_compute"),
            &recipient_new_value,
            &recipient_new_blinding,
        )?;

        cs.enforce(
            || "recipient_new_commitment_matches",
            |lc| lc + computed_recipient_new_commitment.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + recipient_new_commit_pub.get_variable(),
        );

        // ====================================================================
        // 9. Verify recipient's old commitment in tree and compute tree updates
        // ====================================================================

        let recipient_old_commitment = pedersen_commit(
            cs.namespace(|| "recipient_old_commitment"),
            &recipient_old_value,
            &recipient_old_blinding,
        )?;

        // After replacing sender's old commitment with sender's new commitment,
        // we get an intermediate root. Verify recipient's old commitment is in
        // this intermediate root, then replace it to get the final new root.

        // Intermediate root: replace sender's commitment
        let intermediate_root = compute_commitment_root(
            cs.namespace(|| "intermediate_root_sender_new"),
            &computed_sender_new_commitment,
            &sender_index_bits,
            &sender_siblings,
        )?;

        // Verify recipient's old commitment in intermediate root
        let computed_intermediate_root = compute_commitment_root(
            cs.namespace(|| "verify_recipient_in_intermediate"),
            &recipient_old_commitment,
            &recipient_index_bits,
            &recipient_siblings,
        )?;

        cs.enforce(
            || "recipient_in_intermediate_root",
            |lc| lc + computed_intermediate_root.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + intermediate_root.get_variable(),
        );

        // Final root: replace recipient's old commitment with new
        let computed_new_root = compute_commitment_root(
            cs.namespace(|| "compute_new_root"),
            &computed_recipient_new_commitment,
            &recipient_index_bits,
            &recipient_siblings,
        )?;

        cs.enforce(
            || "new_root_matches",
            |lc| lc + computed_new_root.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + new_root.get_variable(),
        );

        Ok(())
    }
}

// ============================================================================
// Helper functions
// ============================================================================

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

/// Compute merkle root from a commitment leaf (no leaf hashing — commitment IS the leaf)
///
/// Unlike the balance tree which hashes `H(balance, LEAF_DOMAIN)` to get the leaf,
/// the commitment tree stores commitments directly as leaves. The commitment itself
/// is already a hash, so no additional leaf hashing is needed.
fn compute_commitment_root<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    commitment: &AllocatedNum<F>,
    index_bits: &[Boolean],
    siblings: &[AllocatedNum<F>],
) -> Result<AllocatedNum<F>, SynthesisError> {
    let mut current = commitment.clone();

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
fn hash_pair<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    current: &AllocatedNum<F>,
    sibling: &AllocatedNum<F>,
    bit: &Boolean,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let left = select(cs.namespace(|| "select_left"), sibling, current, bit)?;
    let right = select(cs.namespace(|| "select_right"), current, sibling, bit)?;
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

// ============================================================================
// Native helper for computing commitment tree root (test/witness generation)
// ============================================================================

/// Compute commitment tree root natively (for witness generation)
pub fn compute_commitment_root_native<F: PrimeField>(
    commitment: F,
    index: u64,
    siblings: &[F],
) -> F {
    let mut current = commitment;
    let mut idx = index;

    for sibling in siblings {
        let (left, right) = if idx.is_multiple_of(2) {
            (current, *sibling)
        } else {
            (*sibling, current)
        };
        current = mimc_hash_native(left, right);
        idx /= 2;
    }

    current
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::commitment::{
        compute_note_id_native, compute_nullifier_native, pedersen_commit_native,
    };
    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;
    use ff::Field;

    /// Build a valid confidential transfer circuit with consistent witness data
    fn build_valid_circuit(tree_depth: usize) -> ConfidentialTransferCircuit<Fr> {
        let sender_value = 1000u64;
        let sender_blinding = Fr::from(111u64);
        let sender_spending_key = Fr::from(42u64);
        let sender_index = 0u64;
        let amount = 300u64;
        let sender_new_value = sender_value - amount;
        let sender_new_blinding = Fr::from(222u64);
        let recipient_old_value = 500u64;
        let recipient_old_blinding = Fr::from(333u64);
        let recipient_index = 1u64;
        let recipient_new_value = recipient_old_value + amount;
        let recipient_new_blinding = Fr::from(444u64);

        // Compute commitments
        let sender_commit = pedersen_commit_native(Fr::from(sender_value), sender_blinding);
        let sender_new_commit =
            pedersen_commit_native(Fr::from(sender_new_value), sender_new_blinding);
        let recipient_old_commit =
            pedersen_commit_native(Fr::from(recipient_old_value), recipient_old_blinding);
        let recipient_new_commit =
            pedersen_commit_native(Fr::from(recipient_new_value), recipient_new_blinding);

        // Build initial tree with sender and recipient commitments
        // Use zero-value siblings for simplicity

        // Build tree bottom-up
        // Level 0: leaves = [sender_commit, recipient_old_commit, zero, zero, ...]
        // For sender at index 0, sibling at index 1 is recipient_old_commit
        // For recipient at index 1, sibling at index 0 is sender_commit

        // But we need siblings AFTER sender is updated for recipient's proof
        // So: sender's siblings are against the old tree, recipient's against intermediate

        // Simple tree: just 2 leaves at indices 0 and 1, rest zero
        // Sender (index 0) siblings: [recipient_old_commit at level 0, then zeros]
        // Old root computed from sender_commit
        let mut level_siblings_sender = vec![Fr::ZERO; tree_depth];
        let mut level_siblings_recipient = vec![Fr::ZERO; tree_depth];

        // Level 0 siblings
        level_siblings_sender[0] = recipient_old_commit; // sibling of sender is recipient
                                                         // After replacing sender, recipient's sibling at level 0 is sender_new_commit
        level_siblings_recipient[0] = sender_new_commit;

        // Higher levels: compute hash of the pair from previous level
        // For sender path: at level 0 the pair is (sender, recipient_old) -> hash01
        // At level 1: sibling is zero, hash = H(hash01, zero)
        // etc.
        // We need to propagate up for each level > 0

        // Compute old tree root
        let old_root =
            compute_commitment_root_native(sender_commit, sender_index, &level_siblings_sender);

        // Compute intermediate root (sender replaced)
        let intermediate_root =
            compute_commitment_root_native(sender_new_commit, sender_index, &level_siblings_sender);

        // Verify recipient_old exists in intermediate root
        let check_intermediate = compute_commitment_root_native(
            recipient_old_commit,
            recipient_index,
            &level_siblings_recipient,
        );
        assert_eq!(
            check_intermediate, intermediate_root,
            "Recipient must exist in intermediate root"
        );

        // Compute new root (recipient replaced)
        let new_root = compute_commitment_root_native(
            recipient_new_commit,
            recipient_index,
            &level_siblings_recipient,
        );

        // Compute nullifier
        let note_id = compute_note_id_native(sender_index, sender_commit);
        let nullifier = compute_nullifier_native(sender_spending_key, note_id);

        ConfidentialTransferCircuit {
            old_commitment_root: Some(old_root),
            new_commitment_root: Some(new_root),
            nullifier: Some(nullifier),
            sender_new_commitment: Some(sender_new_commit),
            recipient_new_commitment: Some(recipient_new_commit),
            sender_value: Some(sender_value),
            sender_blinding: Some(sender_blinding),
            sender_spending_key: Some(sender_spending_key),
            sender_index: Some(sender_index),
            sender_siblings: level_siblings_sender.iter().map(|s| Some(*s)).collect(),
            amount: Some(amount),
            sender_new_blinding: Some(sender_new_blinding),
            recipient_old_value: Some(recipient_old_value),
            recipient_old_blinding: Some(recipient_old_blinding),
            recipient_index: Some(recipient_index),
            recipient_siblings: level_siblings_recipient.iter().map(|s| Some(*s)).collect(),
            recipient_new_blinding: Some(recipient_new_blinding),
            tree_depth,
        }
    }

    #[test]
    fn test_dummy_circuit_synthesizes() {
        let circuit = ConfidentialTransferCircuit::<Fr>::dummy(20);
        let mut cs = TestConstraintSystem::<Fr>::new();
        let result = circuit.synthesize(&mut cs);
        assert!(
            result.is_ok(),
            "Dummy circuit should synthesize: {:?}",
            result.err()
        );
        // Dummy may not satisfy (zero roots won't match computed),
        // but it must synthesize for parameter generation
    }

    #[test]
    fn test_valid_transfer_satisfies() {
        let circuit = build_valid_circuit(4);
        let mut cs = TestConstraintSystem::<Fr>::new();
        let result = circuit.synthesize(&mut cs);

        assert!(
            result.is_ok(),
            "Valid circuit should synthesize: {:?}",
            result.err()
        );
        assert!(
            cs.is_satisfied(),
            "Valid transfer should satisfy all constraints: {:?}",
            cs.which_is_unsatisfied()
        );

        println!(
            "Confidential transfer circuit (depth=4) constraints: {}",
            cs.num_constraints()
        );
    }

    #[test]
    fn test_valid_transfer_depth_20() {
        let circuit = build_valid_circuit(20);
        let mut cs = TestConstraintSystem::<Fr>::new();
        let result = circuit.synthesize(&mut cs);

        assert!(result.is_ok(), "Circuit should synthesize");
        assert!(
            cs.is_satisfied(),
            "Valid transfer should satisfy: {:?}",
            cs.which_is_unsatisfied()
        );

        let num_constraints = cs.num_constraints();
        println!(
            "Confidential transfer circuit (depth=20) constraints: {}",
            num_constraints
        );
        // Expected ~6200 constraints
        assert!(
            num_constraints > 3000,
            "Should have significant constraints"
        );
        assert!(
            num_constraints < 15000,
            "Should be within Groth16 feasibility"
        );
    }

    #[test]
    fn test_insufficient_funds_fails() {
        // Try to send more than sender has
        let mut circuit = build_valid_circuit(4);
        circuit.amount = Some(2000); // sender only has 1000
        circuit.sender_value = Some(1000);

        let mut cs = TestConstraintSystem::<Fr>::new();
        let _ = circuit.synthesize(&mut cs);

        // Should fail because sender_new_value would be negative (wraps in field)
        // and the range proof on sender_new_value will catch it
        assert!(
            !cs.is_satisfied(),
            "Insufficient funds should NOT satisfy constraints"
        );
    }

    #[test]
    fn test_wrong_spending_key_fails() {
        let mut circuit = build_valid_circuit(4);
        // Use a different spending key than what generated the nullifier
        circuit.sender_spending_key = Some(Fr::from(99999u64));

        let mut cs = TestConstraintSystem::<Fr>::new();
        let _ = circuit.synthesize(&mut cs);

        assert!(
            !cs.is_satisfied(),
            "Wrong spending key should NOT satisfy constraints"
        );
    }

    #[test]
    fn test_wrong_merkle_proof_fails() {
        let mut circuit = build_valid_circuit(4);
        // Corrupt a sibling
        circuit.sender_siblings[0] = Some(Fr::from(99999u64));

        let mut cs = TestConstraintSystem::<Fr>::new();
        let _ = circuit.synthesize(&mut cs);

        assert!(
            !cs.is_satisfied(),
            "Wrong merkle proof should NOT satisfy constraints"
        );
    }

    #[test]
    fn test_wrong_commitment_root_fails() {
        let mut circuit = build_valid_circuit(4);
        circuit.old_commitment_root = Some(Fr::from(12345u64));

        let mut cs = TestConstraintSystem::<Fr>::new();
        let _ = circuit.synthesize(&mut cs);

        assert!(
            !cs.is_satisfied(),
            "Wrong old root should NOT satisfy constraints"
        );
    }

    #[test]
    fn test_zero_amount_transfer() {
        // Zero-amount transfer should be valid
        let tree_depth = 4;
        let sender_value = 1000u64;
        let sender_blinding = Fr::from(111u64);
        let sender_spending_key = Fr::from(42u64);
        let sender_index = 0u64;
        let amount = 0u64;
        let sender_new_value = sender_value;
        let sender_new_blinding = Fr::from(222u64);
        let recipient_old_value = 500u64;
        let recipient_old_blinding = Fr::from(333u64);
        let recipient_index = 1u64;
        let recipient_new_value = recipient_old_value;
        let recipient_new_blinding = Fr::from(444u64);

        let sender_commit = pedersen_commit_native(Fr::from(sender_value), sender_blinding);
        let sender_new_commit =
            pedersen_commit_native(Fr::from(sender_new_value), sender_new_blinding);
        let recipient_old_commit =
            pedersen_commit_native(Fr::from(recipient_old_value), recipient_old_blinding);
        let recipient_new_commit =
            pedersen_commit_native(Fr::from(recipient_new_value), recipient_new_blinding);

        let mut sender_siblings = vec![Fr::ZERO; tree_depth];
        let mut recipient_siblings = vec![Fr::ZERO; tree_depth];
        sender_siblings[0] = recipient_old_commit;
        recipient_siblings[0] = sender_new_commit;

        let old_root =
            compute_commitment_root_native(sender_commit, sender_index, &sender_siblings);
        let new_root = compute_commitment_root_native(
            recipient_new_commit,
            recipient_index,
            &recipient_siblings,
        );
        let note_id = compute_note_id_native(sender_index, sender_commit);
        let nullifier = compute_nullifier_native(sender_spending_key, note_id);

        let circuit = ConfidentialTransferCircuit {
            old_commitment_root: Some(old_root),
            new_commitment_root: Some(new_root),
            nullifier: Some(nullifier),
            sender_new_commitment: Some(sender_new_commit),
            recipient_new_commitment: Some(recipient_new_commit),
            sender_value: Some(sender_value),
            sender_blinding: Some(sender_blinding),
            sender_spending_key: Some(sender_spending_key),
            sender_index: Some(sender_index),
            sender_siblings: sender_siblings.iter().map(|s| Some(*s)).collect(),
            amount: Some(amount),
            sender_new_blinding: Some(sender_new_blinding),
            recipient_old_value: Some(recipient_old_value),
            recipient_old_blinding: Some(recipient_old_blinding),
            recipient_index: Some(recipient_index),
            recipient_siblings: recipient_siblings.iter().map(|s| Some(*s)).collect(),
            recipient_new_blinding: Some(recipient_new_blinding),
            tree_depth,
        };

        let mut cs = TestConstraintSystem::<Fr>::new();
        let result = circuit.synthesize(&mut cs);
        assert!(result.is_ok());
        assert!(
            cs.is_satisfied(),
            "Zero-amount transfer should satisfy: {:?}",
            cs.which_is_unsatisfied()
        );
    }

    #[test]
    fn test_full_balance_transfer() {
        // Transfer entire sender balance
        let tree_depth = 4;
        let sender_value = 1000u64;
        let sender_blinding = Fr::from(111u64);
        let sender_spending_key = Fr::from(42u64);
        let sender_index = 0u64;
        let amount = 1000u64;
        let sender_new_value = 0u64;
        let sender_new_blinding = Fr::from(222u64);
        let recipient_old_value = 500u64;
        let recipient_old_blinding = Fr::from(333u64);
        let recipient_index = 1u64;
        let recipient_new_value = 1500u64;
        let recipient_new_blinding = Fr::from(444u64);

        let sender_commit = pedersen_commit_native(Fr::from(sender_value), sender_blinding);
        let sender_new_commit =
            pedersen_commit_native(Fr::from(sender_new_value), sender_new_blinding);
        let recipient_old_commit =
            pedersen_commit_native(Fr::from(recipient_old_value), recipient_old_blinding);
        let recipient_new_commit =
            pedersen_commit_native(Fr::from(recipient_new_value), recipient_new_blinding);

        let mut sender_siblings = vec![Fr::ZERO; tree_depth];
        let mut recipient_siblings = vec![Fr::ZERO; tree_depth];
        sender_siblings[0] = recipient_old_commit;
        recipient_siblings[0] = sender_new_commit;

        let old_root =
            compute_commitment_root_native(sender_commit, sender_index, &sender_siblings);
        let new_root = compute_commitment_root_native(
            recipient_new_commit,
            recipient_index,
            &recipient_siblings,
        );
        let note_id = compute_note_id_native(sender_index, sender_commit);
        let nullifier = compute_nullifier_native(sender_spending_key, note_id);

        let circuit = ConfidentialTransferCircuit {
            old_commitment_root: Some(old_root),
            new_commitment_root: Some(new_root),
            nullifier: Some(nullifier),
            sender_new_commitment: Some(sender_new_commit),
            recipient_new_commitment: Some(recipient_new_commit),
            sender_value: Some(sender_value),
            sender_blinding: Some(sender_blinding),
            sender_spending_key: Some(sender_spending_key),
            sender_index: Some(sender_index),
            sender_siblings: sender_siblings.iter().map(|s| Some(*s)).collect(),
            amount: Some(amount),
            sender_new_blinding: Some(sender_new_blinding),
            recipient_old_value: Some(recipient_old_value),
            recipient_old_blinding: Some(recipient_old_blinding),
            recipient_index: Some(recipient_index),
            recipient_siblings: recipient_siblings.iter().map(|s| Some(*s)).collect(),
            recipient_new_blinding: Some(recipient_new_blinding),
            tree_depth,
        };

        let mut cs = TestConstraintSystem::<Fr>::new();
        let result = circuit.synthesize(&mut cs);
        assert!(result.is_ok());
        assert!(
            cs.is_satisfied(),
            "Full balance transfer should satisfy: {:?}",
            cs.which_is_unsatisfied()
        );
    }

    #[test]
    fn test_public_input_count() {
        let circuit = ConfidentialTransferCircuit::<Fr>::dummy(4);
        let mut cs = TestConstraintSystem::<Fr>::new();
        let _ = circuit.synthesize(&mut cs);

        // Should have exactly 5 public inputs:
        // old_commitment_root, new_commitment_root, nullifier,
        // sender_new_commitment, recipient_new_commitment
        // (+1 for the implicit ONE input)
        assert_eq!(cs.num_inputs(), 6); // 5 public inputs + 1 (CS::one)
    }
}
