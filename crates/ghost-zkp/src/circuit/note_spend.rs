//! GhostNoteSpendCircuit — sender-side Groth16 proof for spending a single note
//!
//! Part of the L2 note/UTXO model. Senders generate this proof locally (~2-3s)
//! before submitting transactions. Validators verify in ~5ms.
//!
//! **Public inputs (4):**
//! 1. `commitment_root` — merkle root of the commitment tree at time of spend
//! 2. `nullifier` — prevents double-spend, deterministically routes to validator
//! 3. `change_commitment` — sender's new note (remaining balance)
//! 4. `recipient_commitment` — recipient's new note (transfer amount)
//!
//! **Constraints (~3,700 for depth=20):**
//! 1. Spent note commitment correctly formed (MiMC Pedersen)
//! 2. Note ID incorporates index, epoch, and commitment
//! 3. Nullifier proves ownership via spending key
//! 4. Merkle inclusion in commitment tree (20 levels)
//! 5. Balance conservation: change + amount + fee = note_value (fee = 10 sats)
//! 6. Change and recipient commitments correctly formed
//! 7. Range proofs: amount in [0, 2^64), change in [0, 2^64)

use bellperson::{
    gadgets::boolean::{AllocatedBit, Boolean},
    gadgets::num::AllocatedNum,
    Circuit, ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::PrimeField;

use ghost_common::constants::L2_TRANSFER_FEE_SATS;

use super::commitment::{pedersen_commit, NULLIFIER_DOMAIN_SEPARATOR};
use super::mimc::{mimc_hash, mimc_hash_native};
use super::range_proof::enforce_range;
use super::BALANCE_BITS;

/// Default tree depth for note commitment trees (2^20 ~ 1M notes per epoch)
pub const NOTE_TREE_DEPTH: usize = 20;

/// Circuit proving a single note spend is valid
pub struct GhostNoteSpendCircuit<F: PrimeField> {
    // Public inputs
    pub commitment_root: Option<F>,
    pub nullifier: Option<F>,
    pub change_commitment: Option<F>,
    pub recipient_commitment: Option<F>,

    // Private inputs — spent note
    pub spending_key: Option<F>,
    pub note_value: Option<u64>,
    pub note_blinding: Option<F>,
    pub note_index: Option<u64>,
    pub epoch: Option<u64>,
    pub merkle_siblings: Vec<Option<F>>,

    // Private inputs — transfer
    pub amount: Option<u64>,

    // Private inputs — new notes
    pub change_blinding: Option<F>,
    pub recipient_blinding: Option<F>,

    pub tree_depth: usize,

    /// CR-2: True for dummy circuits (MPC parameter generation only).
    /// Proof generation will panic if this is set.
    pub is_dummy: bool,
}

impl<F: PrimeField> GhostNoteSpendCircuit<F> {
    /// Create a dummy circuit for MPC parameter generation.
    ///
    /// Witness values are zero but the constraint structure is identical
    /// to real instances — required for Groth16 trusted setup.
    pub fn dummy(tree_depth: usize) -> Self {
        Self {
            commitment_root: Some(F::ZERO),
            nullifier: Some(F::ZERO),
            change_commitment: Some(F::ZERO),
            recipient_commitment: Some(F::ZERO),
            spending_key: Some(F::ZERO),
            note_value: Some(0),
            note_blinding: Some(F::ZERO),
            note_index: Some(0),
            epoch: Some(0),
            merkle_siblings: vec![Some(F::ZERO); tree_depth],
            amount: Some(0),
            change_blinding: Some(F::ZERO),
            recipient_blinding: Some(F::ZERO),
            tree_depth,
            is_dummy: true,
        }
    }
}

impl<F: PrimeField> Circuit<F> for GhostNoteSpendCircuit<F> {
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

        let change_commitment_pub =
            AllocatedNum::alloc_input(cs.namespace(|| "change_commitment"), || {
                self.change_commitment
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        let recipient_commitment_pub =
            AllocatedNum::alloc_input(cs.namespace(|| "recipient_commitment"), || {
                self.recipient_commitment
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        // ====================================================================
        // 2. Allocate private inputs
        // ====================================================================

        let spending_key = AllocatedNum::alloc(cs.namespace(|| "spending_key"), || {
            self.spending_key.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let note_value = AllocatedNum::alloc(cs.namespace(|| "note_value"), || {
            self.note_value
                .map(F::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let note_blinding = AllocatedNum::alloc(cs.namespace(|| "note_blinding"), || {
            self.note_blinding.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let note_index_field = AllocatedNum::alloc(cs.namespace(|| "note_index_field"), || {
            self.note_index
                .map(F::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let epoch_field = AllocatedNum::alloc(cs.namespace(|| "epoch_field"), || {
            self.epoch
                .map(F::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let amount = AllocatedNum::alloc(cs.namespace(|| "amount"), || {
            self.amount
                .map(F::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let change_blinding = AllocatedNum::alloc(cs.namespace(|| "change_blinding"), || {
            self.change_blinding
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let recipient_blinding =
            AllocatedNum::alloc(cs.namespace(|| "recipient_blinding"), || {
                self.recipient_blinding
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        // Allocate merkle path
        let index_bits =
            alloc_index_bits(cs.namespace(|| "index_bits"), self.note_index, tree_depth)?;
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
        // 6. Balance conservation: change_value + amount + fee = note_value
        //    Fee is a protocol constant baked into the circuit (10 sats).
        //    No new public input — the fee is enforced by the constraint.
        // ====================================================================

        let fee_value = F::from(L2_TRANSFER_FEE_SATS);
        let fee = AllocatedNum::alloc(cs.namespace(|| "fee"), || Ok(fee_value))?;

        // Constrain fee to the protocol constant (prevents witness manipulation)
        cs.enforce(
            || "fee_is_constant",
            |lc| lc + fee.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + (fee_value, CS::one()),
        );

        let change_value = AllocatedNum::alloc(cs.namespace(|| "change_value"), || {
            let nv = self.note_value.ok_or(SynthesisError::AssignmentMissing)?;
            let a = self.amount.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(F::from(nv.saturating_sub(a).saturating_sub(L2_TRANSFER_FEE_SATS)))
        })?;

        cs.enforce(
            || "balance_conservation",
            |lc| lc + change_value.get_variable() + amount.get_variable() + fee.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + note_value.get_variable(),
        );

        // ====================================================================
        // 7. Range proofs (prevent field wrap-around attacks)
        // ====================================================================

        enforce_range(cs.namespace(|| "range_amount"), &amount, BALANCE_BITS)?;
        enforce_range(cs.namespace(|| "range_change"), &change_value, BALANCE_BITS)?;

        // ====================================================================
        // 8. Verify change commitment: C_change = Commit(change_value, change_blinding)
        // ====================================================================

        let computed_change = pedersen_commit(
            cs.namespace(|| "change_commitment_compute"),
            &change_value,
            &change_blinding,
        )?;

        cs.enforce(
            || "change_commitment_matches",
            |lc| lc + computed_change.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + change_commitment_pub.get_variable(),
        );

        // ====================================================================
        // 9. Verify recipient commitment: C_recipient = Commit(amount, recipient_blinding)
        // ====================================================================

        let computed_recipient = pedersen_commit(
            cs.namespace(|| "recipient_commitment_compute"),
            &amount,
            &recipient_blinding,
        )?;

        cs.enforce(
            || "recipient_commitment_matches",
            |lc| lc + computed_recipient.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + recipient_commitment_pub.get_variable(),
        );

        Ok(())
    }
}

// ============================================================================
// Native helper functions (witness generation)
// ============================================================================

/// Compute note_id incorporating index, epoch, and commitment.
///
/// `note_id = MiMC(MiMC(note_index, epoch), commitment)`
///
/// This ensures nullifiers are globally unique across epochs.
pub fn compute_note_id_with_epoch_native<F: PrimeField>(
    index: u64,
    epoch: u64,
    commitment: F,
) -> F {
    let index_epoch = mimc_hash_native(F::from(index), F::from(epoch));
    mimc_hash_native(index_epoch, commitment)
}

/// Compute nullifier for a note with epoch awareness.
///
/// `N = MiMC(MiMC(spending_key, note_id), NULL_DOMAIN)`
/// where `note_id = MiMC(MiMC(index, epoch), commitment)`
pub fn compute_nullifier_with_epoch_native<F: PrimeField>(
    spending_key: F,
    index: u64,
    epoch: u64,
    commitment: F,
) -> F {
    let note_id = compute_note_id_with_epoch_native(index, epoch, commitment);
    let domain = F::from(NULLIFIER_DOMAIN_SEPARATOR);
    mimc_hash_native(mimc_hash_native(spending_key, note_id), domain)
}

/// Compute commitment tree root natively (for witness generation).
///
/// Commitments are leaves — no additional leaf hashing needed.
pub fn compute_note_root_native<F: PrimeField>(commitment: F, index: u64, siblings: &[F]) -> F {
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

// ============================================================================
// Circuit helper functions (duplicated from confidential_transfer for modularity)
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
    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;
    use ff::Field;

    /// Build a valid GhostNoteSpendCircuit with consistent witness data
    fn build_valid_circuit(tree_depth: usize) -> GhostNoteSpendCircuit<Fr> {
        let note_value = 1000u64;
        let note_blinding = Fr::from(111u64);
        let spending_key = Fr::from(42u64);
        let note_index = 0u64;
        let epoch = 1u64;
        let amount = 300u64;
        let change_value = note_value - amount - L2_TRANSFER_FEE_SATS;
        let change_blinding = Fr::from(222u64);
        let recipient_blinding = Fr::from(333u64);

        // Compute note commitment
        let note_commitment = pedersen_commit_native(Fr::from(note_value), note_blinding);

        // Build simple tree: one note at index 0, rest zero
        let siblings = vec![Fr::ZERO; tree_depth];

        // Compute root
        let commitment_root = compute_note_root_native(note_commitment, note_index, &siblings);

        // Compute note_id and nullifier
        let nullifier =
            compute_nullifier_with_epoch_native(spending_key, note_index, epoch, note_commitment);

        // Compute output commitments
        let change_commitment_val = pedersen_commit_native(Fr::from(change_value), change_blinding);
        let recipient_commitment_val = pedersen_commit_native(Fr::from(amount), recipient_blinding);

        GhostNoteSpendCircuit {
            commitment_root: Some(commitment_root),
            nullifier: Some(nullifier),
            change_commitment: Some(change_commitment_val),
            recipient_commitment: Some(recipient_commitment_val),
            spending_key: Some(spending_key),
            note_value: Some(note_value),
            note_blinding: Some(note_blinding),
            note_index: Some(note_index),
            epoch: Some(epoch),
            merkle_siblings: siblings.iter().map(|s| Some(*s)).collect(),
            amount: Some(amount),
            change_blinding: Some(change_blinding),
            recipient_blinding: Some(recipient_blinding),
            tree_depth,
            is_dummy: false,
        }
    }

    #[test]
    fn test_dummy_synthesizes() {
        let circuit = GhostNoteSpendCircuit::<Fr>::dummy(20);
        let mut cs = TestConstraintSystem::<Fr>::new();
        let result = circuit.synthesize(&mut cs);
        assert!(
            result.is_ok(),
            "Dummy circuit must synthesize for MPC: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_valid_spend_satisfies() {
        let circuit = build_valid_circuit(4);
        let mut cs = TestConstraintSystem::<Fr>::new();
        let result = circuit.synthesize(&mut cs);

        assert!(result.is_ok(), "Synthesize failed: {:?}", result.err());
        assert!(
            cs.is_satisfied(),
            "Valid spend must satisfy: {:?}",
            cs.which_is_unsatisfied()
        );

        println!(
            "GhostNoteSpendCircuit (depth=4) constraints: {}",
            cs.num_constraints()
        );
    }

    #[test]
    fn test_valid_spend_depth_20() {
        let circuit = build_valid_circuit(20);
        let mut cs = TestConstraintSystem::<Fr>::new();
        let result = circuit.synthesize(&mut cs);

        assert!(result.is_ok());
        assert!(
            cs.is_satisfied(),
            "Valid spend depth=20 must satisfy: {:?}",
            cs.which_is_unsatisfied()
        );

        let n = cs.num_constraints();
        println!("GhostNoteSpendCircuit (depth=20) constraints: {}", n);
        // ~12,700 with 82-round MiMC, range proofs on note_value, and index_bits consistency
        assert!(n > 5000, "Expected > 5000 constraints, got {}", n);
        assert!(n < 20000, "Expected < 20000 constraints, got {}", n);
    }

    #[test]
    fn test_public_input_count() {
        let circuit = GhostNoteSpendCircuit::<Fr>::dummy(4);
        let mut cs = TestConstraintSystem::<Fr>::new();
        let _ = circuit.synthesize(&mut cs);

        // 4 public inputs + 1 (CS::one) = 5
        assert_eq!(cs.num_inputs(), 5);
    }

    #[test]
    fn test_insufficient_funds_fails() {
        let mut circuit = build_valid_circuit(4);
        circuit.amount = Some(2000); // more than note_value (1000)
        circuit.note_value = Some(1000);

        let mut cs = TestConstraintSystem::<Fr>::new();
        let _ = circuit.synthesize(&mut cs);

        assert!(
            !cs.is_satisfied(),
            "Insufficient funds must NOT satisfy (range proof catches wrap)"
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
    fn test_zero_amount_transfer() {
        let note_value = 1000u64;
        let note_blinding = Fr::from(111u64);
        let spending_key = Fr::from(42u64);
        let note_index = 0u64;
        let epoch = 1u64;
        let amount = 0u64;
        let change_value = note_value - amount - L2_TRANSFER_FEE_SATS;
        let change_blinding = Fr::from(222u64);
        let recipient_blinding = Fr::from(333u64);
        let tree_depth = 4;

        let note_commitment = pedersen_commit_native(Fr::from(note_value), note_blinding);
        let siblings = vec![Fr::ZERO; tree_depth];
        let commitment_root = compute_note_root_native(note_commitment, note_index, &siblings);
        let nullifier =
            compute_nullifier_with_epoch_native(spending_key, note_index, epoch, note_commitment);
        let change_commitment_val = pedersen_commit_native(Fr::from(change_value), change_blinding);
        let recipient_commitment_val = pedersen_commit_native(Fr::from(amount), recipient_blinding);

        let circuit = GhostNoteSpendCircuit {
            commitment_root: Some(commitment_root),
            nullifier: Some(nullifier),
            change_commitment: Some(change_commitment_val),
            recipient_commitment: Some(recipient_commitment_val),
            spending_key: Some(spending_key),
            note_value: Some(note_value),
            note_blinding: Some(note_blinding),
            note_index: Some(note_index),
            epoch: Some(epoch),
            merkle_siblings: siblings.iter().map(|s| Some(*s)).collect(),
            amount: Some(amount),
            change_blinding: Some(change_blinding),
            recipient_blinding: Some(recipient_blinding),
            tree_depth,
            is_dummy: false,
        };

        let mut cs = TestConstraintSystem::<Fr>::new();
        let result = circuit.synthesize(&mut cs);
        assert!(result.is_ok());
        assert!(
            cs.is_satisfied(),
            "Zero-amount must satisfy: {:?}",
            cs.which_is_unsatisfied()
        );
    }

    #[test]
    fn test_full_balance_transfer() {
        let note_value = 1000u64;
        let note_blinding = Fr::from(111u64);
        let spending_key = Fr::from(42u64);
        let note_index = 0u64;
        let epoch = 1u64;
        let amount = note_value - L2_TRANSFER_FEE_SATS; // Max transferable after fee
        let change_blinding = Fr::from(222u64);
        let recipient_blinding = Fr::from(333u64);
        let tree_depth = 4;

        let note_commitment = pedersen_commit_native(Fr::from(note_value), note_blinding);
        let siblings = vec![Fr::ZERO; tree_depth];
        let commitment_root = compute_note_root_native(note_commitment, note_index, &siblings);
        let nullifier =
            compute_nullifier_with_epoch_native(spending_key, note_index, epoch, note_commitment);
        let change_commitment_val = pedersen_commit_native(Fr::from(0u64), change_blinding);
        let recipient_commitment_val = pedersen_commit_native(Fr::from(amount), recipient_blinding);

        let circuit = GhostNoteSpendCircuit {
            commitment_root: Some(commitment_root),
            nullifier: Some(nullifier),
            change_commitment: Some(change_commitment_val),
            recipient_commitment: Some(recipient_commitment_val),
            spending_key: Some(spending_key),
            note_value: Some(note_value),
            note_blinding: Some(note_blinding),
            note_index: Some(note_index),
            epoch: Some(epoch),
            merkle_siblings: siblings.iter().map(|s| Some(*s)).collect(),
            amount: Some(amount),
            change_blinding: Some(change_blinding),
            recipient_blinding: Some(recipient_blinding),
            tree_depth,
            is_dummy: false,
        };

        let mut cs = TestConstraintSystem::<Fr>::new();
        let result = circuit.synthesize(&mut cs);
        assert!(result.is_ok());
        assert!(
            cs.is_satisfied(),
            "Full balance transfer must satisfy: {:?}",
            cs.which_is_unsatisfied()
        );
    }

    #[test]
    fn test_different_epochs_different_nullifiers() {
        let spending_key = Fr::from(42u64);
        let commitment = Fr::from(999u64);

        let null_e1 = compute_nullifier_with_epoch_native(spending_key, 0, 1, commitment);
        let null_e2 = compute_nullifier_with_epoch_native(spending_key, 0, 2, commitment);

        assert_ne!(
            null_e1, null_e2,
            "Same note in different epochs must have different nullifiers"
        );
    }

    #[test]
    fn test_native_note_id_consistency() {
        let commitment = pedersen_commit_native(Fr::from(1000u64), Fr::from(111u64));
        let note_id = compute_note_id_with_epoch_native(0, 1, commitment);

        // Same inputs must produce same note_id
        let note_id2 = compute_note_id_with_epoch_native(0, 1, commitment);
        assert_eq!(note_id, note_id2);

        // Different index produces different note_id
        let note_id3 = compute_note_id_with_epoch_native(1, 1, commitment);
        assert_ne!(note_id, note_id3);
    }

    #[test]
    fn test_amount_plus_fee_exceeds_note_fails() {
        // note_value = 1000, amount = 995, fee = 10 → change would be -5 (wraps in field)
        let mut circuit = build_valid_circuit(4);
        circuit.amount = Some(995);
        circuit.note_value = Some(1000);

        let mut cs = TestConstraintSystem::<Fr>::new();
        let _ = circuit.synthesize(&mut cs);

        assert!(
            !cs.is_satisfied(),
            "amount + fee > note_value must NOT satisfy (range proof catches wrap)"
        );
    }
}
