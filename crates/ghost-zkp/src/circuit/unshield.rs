//! GhostUnshieldCircuit -- full withdrawal (L2 -> L1) Groth16 proof
//!
//! Proves that a note is being fully withdrawn from L2 to L1 settlement.
//! Unlike NoteSpend (which splits into change + recipient), unshield consumes
//! the entire note value and makes it publicly visible for L1 verification.
//!
//! **Public inputs (3):**
//! 1. `commitment_root` -- Merkle tree root at time of withdrawal
//! 2. `nullifier` -- prevents double-spend (same derivation as NoteSpend)
//! 3. `withdrawal_amount` -- value leaving L2 (public for L1 settlement)
//!
//! **Constraints (~2,800 for depth=20):**
//! 1. Spent note commitment correctly formed (MiMC Pedersen)
//! 2. Note ID incorporates index, epoch, and commitment
//! 3. Nullifier proves ownership via spending key
//! 4. Merkle inclusion in commitment tree (20 levels)
//! 5. Full withdrawal: withdrawal_amount == note_value
//! 6. Range proof on withdrawal_amount

use bellperson::{
    gadgets::boolean::{AllocatedBit, Boolean},
    gadgets::num::AllocatedNum,
    Circuit, ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::PrimeField;

use super::commitment::{pedersen_commit, NULLIFIER_DOMAIN_SEPARATOR};
use super::mimc::mimc_hash;
use super::range_proof::enforce_range;
use super::BALANCE_BITS;

/// Default tree depth for unshield commitment trees (2^20 ~ 1M notes per epoch)
pub const UNSHIELD_TREE_DEPTH: usize = 20;

/// Circuit proving a full note withdrawal (L2 -> L1) is valid
pub struct GhostUnshieldCircuit<F: PrimeField> {
    // Public inputs
    pub commitment_root: Option<F>,
    pub nullifier: Option<F>,
    pub withdrawal_amount: Option<F>,

    // Private inputs
    pub spending_key: Option<F>,
    pub note_value: Option<F>,
    pub note_blinding: Option<F>,
    pub note_index: Option<F>,
    pub epoch: Option<F>,
    pub merkle_siblings: Vec<Option<F>>,

    pub tree_depth: usize,

    /// CR-2: True for dummy circuits (MPC parameter generation only).
    /// Proof generation will panic if this is set.
    pub is_dummy: bool,
}

impl<F: PrimeField> GhostUnshieldCircuit<F> {
    /// Create a dummy circuit for MPC parameter generation.
    ///
    /// Witness values are zero but the constraint structure is identical
    /// to real instances -- required for Groth16 trusted setup.
    pub fn dummy(tree_depth: usize) -> Self {
        Self {
            commitment_root: Some(F::ZERO),
            nullifier: Some(F::ZERO),
            withdrawal_amount: Some(F::ZERO),
            spending_key: Some(F::ZERO),
            note_value: Some(F::ZERO),
            note_blinding: Some(F::ZERO),
            note_index: Some(F::ZERO),
            epoch: Some(F::ZERO),
            merkle_siblings: vec![Some(F::ZERO); tree_depth],
            tree_depth,
            is_dummy: true,
        }
    }
}

impl<F: PrimeField> Circuit<F> for GhostUnshieldCircuit<F> {
    fn synthesize<CS: ConstraintSystem<F>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let tree_depth = self.tree_depth;

        // ====================================================================
        // 1. Allocate public inputs (order matters for verification)
        // ====================================================================

        let commitment_root_pub =
            AllocatedNum::alloc_input(cs.namespace(|| "commitment_root"), || {
                self.commitment_root
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        let nullifier_pub = AllocatedNum::alloc_input(cs.namespace(|| "nullifier"), || {
            self.nullifier.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let withdrawal_amount_pub =
            AllocatedNum::alloc_input(cs.namespace(|| "withdrawal_amount"), || {
                self.withdrawal_amount
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        // ====================================================================
        // 2. Allocate private inputs
        // ====================================================================

        let spending_key = AllocatedNum::alloc(cs.namespace(|| "spending_key"), || {
            self.spending_key.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let note_value = AllocatedNum::alloc(cs.namespace(|| "note_value"), || {
            self.note_value.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let note_blinding = AllocatedNum::alloc(cs.namespace(|| "note_blinding"), || {
            self.note_blinding.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let note_index_field = AllocatedNum::alloc(cs.namespace(|| "note_index_field"), || {
            self.note_index.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let epoch_field = AllocatedNum::alloc(cs.namespace(|| "epoch_field"), || {
            self.epoch.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate merkle path
        let index_bits = alloc_index_bits(
            cs.namespace(|| "index_bits"),
            self.note_index.map(|f| {
                // Extract u64 from field element for bit decomposition
                let repr = f.to_repr();
                let bytes = repr.as_ref();
                u64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0u8; 8]))
            }),
            tree_depth,
        )?;
        let siblings = alloc_siblings(cs.namespace(|| "siblings"), &self.merkle_siblings)?;

        // Index bit-decomposition consistency: note_index_field == sum(bit_i * 2^i)
        {
            let mut coeff = F::ONE;
            let mut lc = LinearCombination::<F>::zero();
            for bit in &index_bits {
                lc = lc + &bit.lc(CS::one(), coeff);
                coeff = coeff.double();
            }
            cs.enforce(
                || "index_bits_consistency",
                |_| lc,
                |lc| lc + CS::one(),
                |lc| lc + note_index_field.get_variable(),
            );
        }

        // Range proof on note_value (prevent field wrap-around on input note)
        enforce_range(cs.namespace(|| "range_note_value"), &note_value, BALANCE_BITS)?;

        // ====================================================================
        // 3. Compute spent note commitment: C = MiMC(MiMC(value, blinding), COMT_DOMAIN)
        // ====================================================================

        let note_commitment = pedersen_commit(
            cs.namespace(|| "note_commitment"),
            &note_value,
            &note_blinding,
        )?;

        // ====================================================================
        // 4. Merkle inclusion: commitment exists in commitment_root
        //    Commitment IS the leaf (no additional hashing)
        // ====================================================================

        let computed_root = compute_commitment_root(
            cs.namespace(|| "merkle_inclusion"),
            &note_commitment,
            &index_bits,
            &siblings,
        )?;

        cs.enforce(
            || "root_matches",
            |lc| lc + computed_root.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + commitment_root_pub.get_variable(),
        );

        // ====================================================================
        // 5. Nullifier derivation and verification
        //    note_id = MiMC(MiMC(note_index, epoch), commitment)
        //    nullifier = MiMC(MiMC(spending_key, note_id), NULL_DOMAIN)
        // ====================================================================

        let index_epoch_hash = mimc_hash(
            cs.namespace(|| "index_epoch_hash"),
            &note_index_field,
            &epoch_field,
        )?;

        let note_id = mimc_hash(
            cs.namespace(|| "note_id"),
            &index_epoch_hash,
            &note_commitment,
        )?;

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

        let nullifier_inner =
            mimc_hash(cs.namespace(|| "nullifier_inner"), &spending_key, &note_id)?;

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
        // 6. Full withdrawal: withdrawal_amount == note_value
        // ====================================================================

        cs.enforce(
            || "full_withdrawal",
            |lc| lc + withdrawal_amount_pub.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + note_value.get_variable(),
        );

        // ====================================================================
        // 7. Range proof on withdrawal_amount
        // ====================================================================

        enforce_range(
            cs.namespace(|| "range_withdrawal_amount"),
            &withdrawal_amount_pub,
            BALANCE_BITS,
        )?;

        Ok(())
    }
}

// ============================================================================
// Circuit helper functions (copied from note_spend for modularity)
// ============================================================================

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::commitment::pedersen_commit_native;
    use crate::circuit::note_spend::{
        compute_note_root_native, compute_nullifier_with_epoch_native,
    };
    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;
    use ff::Field;

    /// Build a valid GhostUnshieldCircuit with consistent witness data
    fn build_valid_circuit(tree_depth: usize) -> GhostUnshieldCircuit<Fr> {
        let note_value = 1000u64;
        let note_blinding = Fr::from(111u64);
        let spending_key = Fr::from(42u64);
        let note_index = 0u64;
        let epoch = 1u64;

        // Compute note commitment
        let note_commitment = pedersen_commit_native(Fr::from(note_value), note_blinding);

        // Build simple tree: one note at index 0, rest zero
        let siblings = vec![Fr::ZERO; tree_depth];

        // Compute root
        let commitment_root = compute_note_root_native(note_commitment, note_index, &siblings);

        // Compute nullifier
        let nullifier =
            compute_nullifier_with_epoch_native(spending_key, note_index, epoch, note_commitment);

        GhostUnshieldCircuit {
            commitment_root: Some(commitment_root),
            nullifier: Some(nullifier),
            withdrawal_amount: Some(Fr::from(note_value)),
            spending_key: Some(spending_key),
            note_value: Some(Fr::from(note_value)),
            note_blinding: Some(note_blinding),
            note_index: Some(Fr::from(note_index)),
            epoch: Some(Fr::from(epoch)),
            merkle_siblings: siblings.iter().map(|s| Some(*s)).collect(),
            tree_depth,
            is_dummy: false,
        }
    }

    #[test]
    fn test_dummy_synthesizes() {
        let circuit = GhostUnshieldCircuit::<Fr>::dummy(20);
        let mut cs = TestConstraintSystem::<Fr>::new();
        let result = circuit.synthesize(&mut cs);
        assert!(
            result.is_ok(),
            "Dummy circuit must synthesize for MPC: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_valid_unshield_satisfies() {
        let circuit = build_valid_circuit(4);
        let mut cs = TestConstraintSystem::<Fr>::new();
        let result = circuit.synthesize(&mut cs);

        assert!(result.is_ok(), "Synthesize failed: {:?}", result.err());
        assert!(
            cs.is_satisfied(),
            "Valid unshield must satisfy: {:?}",
            cs.which_is_unsatisfied()
        );

        println!(
            "GhostUnshieldCircuit (depth=4) constraints: {}",
            cs.num_constraints()
        );
    }

    #[test]
    fn test_valid_unshield_depth_20() {
        let circuit = build_valid_circuit(20);
        let mut cs = TestConstraintSystem::<Fr>::new();
        let result = circuit.synthesize(&mut cs);

        assert!(result.is_ok());
        assert!(
            cs.is_satisfied(),
            "Valid unshield depth=20 must satisfy: {:?}",
            cs.which_is_unsatisfied()
        );

        let n = cs.num_constraints();
        println!("GhostUnshieldCircuit (depth=20) constraints: {}", n);
        // Simpler than NoteSpend (no change/recipient commitments), expect ~5000-15000
        assert!(n > 2000, "Expected > 2000 constraints, got {}", n);
        assert!(n < 15000, "Expected < 15000 constraints, got {}", n);
    }

    #[test]
    fn test_public_input_count() {
        let circuit = GhostUnshieldCircuit::<Fr>::dummy(4);
        let mut cs = TestConstraintSystem::<Fr>::new();
        let _ = circuit.synthesize(&mut cs);

        // 3 public inputs + 1 (CS::one) = 4
        assert_eq!(cs.num_inputs(), 4);
    }

    #[test]
    fn test_wrong_withdrawal_amount_fails() {
        let mut circuit = build_valid_circuit(4);
        // Try to claim more than the note value
        circuit.withdrawal_amount = Some(Fr::from(2000u64));

        let mut cs = TestConstraintSystem::<Fr>::new();
        let _ = circuit.synthesize(&mut cs);

        assert!(
            !cs.is_satisfied(),
            "Wrong withdrawal amount must NOT satisfy"
        );
    }

    #[test]
    fn test_partial_withdrawal_fails() {
        let mut circuit = build_valid_circuit(4);
        // Try partial withdrawal (unshield must be full)
        circuit.withdrawal_amount = Some(Fr::from(500u64));

        let mut cs = TestConstraintSystem::<Fr>::new();
        let _ = circuit.synthesize(&mut cs);

        assert!(
            !cs.is_satisfied(),
            "Partial withdrawal must NOT satisfy (unshield is full withdrawal)"
        );
    }

    #[test]
    fn test_wrong_spending_key_fails() {
        let mut circuit = build_valid_circuit(4);
        circuit.spending_key = Some(Fr::from(99999u64));

        let mut cs = TestConstraintSystem::<Fr>::new();
        let _ = circuit.synthesize(&mut cs);

        assert!(!cs.is_satisfied(), "Wrong spending key must NOT satisfy");
    }

    #[test]
    fn test_wrong_merkle_proof_fails() {
        let mut circuit = build_valid_circuit(4);
        circuit.merkle_siblings[0] = Some(Fr::from(99999u64));

        let mut cs = TestConstraintSystem::<Fr>::new();
        let _ = circuit.synthesize(&mut cs);

        assert!(!cs.is_satisfied(), "Wrong merkle proof must NOT satisfy");
    }

    #[test]
    fn test_wrong_root_fails() {
        let mut circuit = build_valid_circuit(4);
        circuit.commitment_root = Some(Fr::from(12345u64));

        let mut cs = TestConstraintSystem::<Fr>::new();
        let _ = circuit.synthesize(&mut cs);

        assert!(!cs.is_satisfied(), "Wrong commitment root must NOT satisfy");
    }

    #[test]
    fn test_zero_value_unshield() {
        let note_value = 0u64;
        let note_blinding = Fr::from(111u64);
        let spending_key = Fr::from(42u64);
        let note_index = 0u64;
        let epoch = 1u64;
        let tree_depth = 4;

        let note_commitment = pedersen_commit_native(Fr::from(note_value), note_blinding);
        let siblings = vec![Fr::ZERO; tree_depth];
        let commitment_root = compute_note_root_native(note_commitment, note_index, &siblings);
        let nullifier =
            compute_nullifier_with_epoch_native(spending_key, note_index, epoch, note_commitment);

        let circuit = GhostUnshieldCircuit {
            commitment_root: Some(commitment_root),
            nullifier: Some(nullifier),
            withdrawal_amount: Some(Fr::from(note_value)),
            spending_key: Some(spending_key),
            note_value: Some(Fr::from(note_value)),
            note_blinding: Some(note_blinding),
            note_index: Some(Fr::from(note_index)),
            epoch: Some(Fr::from(epoch)),
            merkle_siblings: siblings.iter().map(|s| Some(*s)).collect(),
            tree_depth,
            is_dummy: false,
        };

        let mut cs = TestConstraintSystem::<Fr>::new();
        let result = circuit.synthesize(&mut cs);
        assert!(result.is_ok());
        assert!(
            cs.is_satisfied(),
            "Zero-value unshield must satisfy: {:?}",
            cs.which_is_unsatisfied()
        );
    }
}
