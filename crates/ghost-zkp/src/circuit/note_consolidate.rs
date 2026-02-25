//! NoteConsolidateCircuit — merge multiple notes into a single note
//!
//! Reduces note fragmentation from repeated small spends by allowing a user
//! to consume up to MAX_CONSOLIDATION_INPUTS notes and produce one output note
//! with the combined value. All input notes must belong to the same spending key.
//!
//! **Public inputs (1 + MAX_CONSOLIDATION_INPUTS + 1 = 6):**
//! 1. `commitment_root` — merkle root of the commitment tree
//! 2. `nullifier_0..nullifier_3` — one nullifier per input (zero for unused slots)
//! 3. `output_commitment` — merged output note
//!
//! Unused input slots use `is_real=false` with zero-valued witnesses.
//! The circuit has a fixed structure regardless of how many inputs are used.

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

/// Maximum number of notes that can be consolidated in one circuit
pub const MAX_CONSOLIDATION_INPUTS: usize = 4;

/// Circuit proving consolidation of multiple notes into one
pub struct NoteConsolidateCircuit<F: PrimeField> {
    // Public inputs
    pub commitment_root: Option<F>,
    pub nullifiers: Vec<Option<F>>, // MAX_CONSOLIDATION_INPUTS nullifiers
    pub output_commitment: Option<F>,

    // Per-input private data (MAX_CONSOLIDATION_INPUTS entries)
    pub is_real: Vec<Option<bool>>,
    pub spending_keys: Vec<Option<F>>, // must all be the same for real inputs
    pub note_values: Vec<Option<u64>>,
    pub note_blindings: Vec<Option<F>>,
    pub note_indices: Vec<Option<u64>>,
    pub epochs: Vec<Option<u64>>,
    pub merkle_siblings: Vec<Vec<Option<F>>>,

    // Output private data
    pub output_blinding: Option<F>,

    pub tree_depth: usize,
}

impl<F: PrimeField> NoteConsolidateCircuit<F> {
    /// Create a dummy circuit for MPC parameter generation
    pub fn dummy(tree_depth: usize) -> Self {
        let n = MAX_CONSOLIDATION_INPUTS;
        Self {
            commitment_root: Some(F::ZERO),
            nullifiers: vec![Some(F::ZERO); n],
            output_commitment: Some(F::ZERO),
            is_real: vec![Some(false); n],
            spending_keys: vec![Some(F::ZERO); n],
            note_values: vec![Some(0); n],
            note_blindings: vec![Some(F::ZERO); n],
            note_indices: vec![Some(0); n],
            epochs: vec![Some(0); n],
            merkle_siblings: vec![vec![Some(F::ZERO); tree_depth]; n],
            output_blinding: Some(F::ZERO),
            tree_depth,
        }
    }
}

impl<F: PrimeField> Circuit<F> for NoteConsolidateCircuit<F> {
    fn synthesize<CS: ConstraintSystem<F>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let tree_depth = self.tree_depth;
        let n = MAX_CONSOLIDATION_INPUTS;

        // ====================================================================
        // 1. Allocate public inputs
        // ====================================================================

        let commitment_root_pub =
            AllocatedNum::alloc_input(cs.namespace(|| "commitment_root"), || {
                self.commitment_root
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        let mut nullifier_pubs = Vec::with_capacity(n);
        for i in 0..n {
            let nul =
                AllocatedNum::alloc_input(cs.namespace(|| format!("nullifier_{}", i)), || {
                    self.nullifiers
                        .get(i)
                        .and_then(|v| *v)
                        .ok_or(SynthesisError::AssignmentMissing)
                })?;
            nullifier_pubs.push(nul);
        }

        let output_commitment_pub =
            AllocatedNum::alloc_input(cs.namespace(|| "output_commitment"), || {
                self.output_commitment
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        // ====================================================================
        // 2. Allocate per-input private data and process each input
        // ====================================================================

        let mut value_vars = Vec::with_capacity(n);
        let mut is_real_bools = Vec::with_capacity(n);
        let mut spending_key_vars: Vec<AllocatedNum<F>> = Vec::with_capacity(n);

        #[allow(clippy::needless_range_loop)]
        for i in 0..n {
            let mut ns = cs.namespace(|| format!("input_{}", i));

            // is_real flag
            let is_real_val = self.is_real.get(i).and_then(|v| *v).unwrap_or(false);
            let is_real_bit = AllocatedBit::alloc(ns.namespace(|| "is_real"), Some(is_real_val))?;
            let is_real_bool = Boolean::from(is_real_bit.clone());

            // Spending key
            let spending_key = AllocatedNum::alloc(ns.namespace(|| "spending_key"), || {
                self.spending_keys
                    .get(i)
                    .and_then(|v| *v)
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

            // Note value
            let note_value = AllocatedNum::alloc(ns.namespace(|| "note_value"), || {
                self.note_values
                    .get(i)
                    .and_then(|v| *v)
                    .map(F::from)
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

            // Note blinding
            let note_blinding = AllocatedNum::alloc(ns.namespace(|| "note_blinding"), || {
                self.note_blindings
                    .get(i)
                    .and_then(|v| *v)
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

            // Note index
            let note_index_field =
                AllocatedNum::alloc(ns.namespace(|| "note_index_field"), || {
                    self.note_indices
                        .get(i)
                        .and_then(|v| *v)
                        .map(F::from)
                        .ok_or(SynthesisError::AssignmentMissing)
                })?;

            // Epoch
            let epoch_field = AllocatedNum::alloc(ns.namespace(|| "epoch_field"), || {
                self.epochs
                    .get(i)
                    .and_then(|v| *v)
                    .map(F::from)
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

            // Merkle siblings
            let sibs = &self.merkle_siblings[i];
            let index_bits = alloc_index_bits(
                ns.namespace(|| "index_bits"),
                self.note_indices.get(i).and_then(|v| *v),
                tree_depth,
            )?;
            let siblings = alloc_siblings(ns.namespace(|| "siblings"), sibs)?;

            // Index bit-decomposition consistency: note_index_field == sum(bit_i * 2^i)
            {
                let mut coeff = F::ONE;
                let mut lc = LinearCombination::<F>::zero();
                for bit in &index_bits {
                    lc = lc + &bit.lc(CS::one(), coeff);
                    coeff = coeff.double();
                }
                ns.enforce(
                    || "index_bits_consistency",
                    |_| lc,
                    |lc| lc + CS::one(),
                    |lc| lc + note_index_field.get_variable(),
                );
            }

            // ================================================================
            // 3. Compute commitment and merkle root for this input
            // ================================================================

            let note_commitment = pedersen_commit(
                ns.namespace(|| "note_commitment"),
                &note_value,
                &note_blinding,
            )?;

            let computed_root = compute_commitment_root(
                ns.namespace(|| "merkle_root"),
                &note_commitment,
                &index_bits,
                &siblings,
            )?;

            // If is_real: computed_root must equal commitment_root_pub
            // Constraint: is_real * (computed_root - commitment_root_pub) == 0
            ns.enforce(
                || "root_check",
                |lc| lc + is_real_bit.get_variable(),
                |lc| lc + computed_root.get_variable() - commitment_root_pub.get_variable(),
                |lc| lc,
            );

            // ================================================================
            // 4. Compute nullifier
            // ================================================================

            let index_epoch_hash = mimc_hash(
                ns.namespace(|| "index_epoch_hash"),
                &note_index_field,
                &epoch_field,
            )?;

            let note_id = mimc_hash(
                ns.namespace(|| "note_id"),
                &index_epoch_hash,
                &note_commitment,
            )?;

            let nullifier_domain_value = F::from(NULLIFIER_DOMAIN_SEPARATOR);
            let nullifier_domain =
                AllocatedNum::alloc(ns.namespace(|| "nullifier_domain"), || {
                    Ok(nullifier_domain_value)
                })?;
            ns.enforce(
                || "nullifier_domain_constant",
                |lc| lc + nullifier_domain.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + (nullifier_domain_value, CS::one()),
            );

            let nullifier_inner =
                mimc_hash(ns.namespace(|| "nullifier_inner"), &spending_key, &note_id)?;

            let computed_nullifier = mimc_hash(
                ns.namespace(|| "nullifier_outer"),
                &nullifier_inner,
                &nullifier_domain,
            )?;

            // effective_nullifier = is_real ? computed_nullifier : 0
            let effective_nullifier = select_or_zero(
                ns.namespace(|| "effective_nullifier"),
                &computed_nullifier,
                &is_real_bool,
            )?;

            ns.enforce(
                || "nullifier_matches",
                |lc| lc + effective_nullifier.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + nullifier_pubs[i].get_variable(),
            );

            // ================================================================
            // 5. Range proof on note value
            // ================================================================

            enforce_range(ns.namespace(|| "range_value"), &note_value, BALANCE_BITS)?;

            // Store for cross-input constraints
            spending_key_vars.push(spending_key);
            value_vars.push(note_value);
            is_real_bools.push(is_real_bool);
        }

        // ====================================================================
        // 6. Enforce all real inputs share the same spending key
        //    For i > 0: is_real[i] * (spending_key[i] - spending_key[0]) == 0
        // ====================================================================

        if spending_key_vars.len() > 1 {
            let first_key = &spending_key_vars[0];
            for (i, key) in spending_key_vars.iter().enumerate().skip(1) {
                // Extract the is_real bit variable for this input
                match &is_real_bools[i] {
                    Boolean::Is(ref bit) => {
                        cs.enforce(
                            || format!("spending_key_eq_{}", i),
                            |lc| lc + bit.get_variable(),
                            |lc| lc + key.get_variable() - first_key.get_variable(),
                            |lc| lc,
                        );
                    }
                    _ => {
                        // Constant false: no constraint needed (input is not real)
                    }
                }
            }
        }

        // ====================================================================
        // 7. Sum conservation: output_value = sum(is_real_i * value_i)
        // ====================================================================

        // Compute total value from real inputs
        let output_value = AllocatedNum::alloc(cs.namespace(|| "output_value"), || {
            let mut total = 0u64;
            for i in 0..n {
                let is_real = self.is_real.get(i).and_then(|v| *v).unwrap_or(false);
                if is_real {
                    let val = self.note_values.get(i).and_then(|v| *v).unwrap_or(0);
                    total = total.saturating_add(val);
                }
            }
            Ok(F::from(total))
        })?;

        // Constrain: output_value = sum(is_real_i * value_i)
        // Build linear combination for the weighted sum
        {
            // We need is_real_i * value_i for each input. Since is_real is boolean
            // and value is a field element, their product is a quadratic term.
            // We allocate the product and constrain it.
            let mut product_vars = Vec::with_capacity(n);
            for i in 0..n {
                let product =
                    AllocatedNum::alloc(cs.namespace(|| format!("real_value_{}", i)), || {
                        let is_real = self.is_real.get(i).and_then(|v| *v).unwrap_or(false);
                        let val = self.note_values.get(i).and_then(|v| *v).unwrap_or(0);
                        if is_real {
                            Ok(F::from(val))
                        } else {
                            Ok(F::ZERO)
                        }
                    })?;

                // Constrain: product = is_real_bit * value
                match &is_real_bools[i] {
                    Boolean::Is(ref bit) => {
                        cs.enforce(
                            || format!("product_constraint_{}", i),
                            |lc| lc + bit.get_variable(),
                            |lc| lc + value_vars[i].get_variable(),
                            |lc| lc + product.get_variable(),
                        );
                    }
                    _ => {
                        // For constant false: product must be zero
                        cs.enforce(
                            || format!("product_zero_{}", i),
                            |lc| lc + product.get_variable(),
                            |lc| lc + CS::one(),
                            |lc| lc,
                        );
                    }
                }

                product_vars.push(product);
            }

            // Constrain: output_value = sum(product_i)
            let mut sum_lc = LinearCombination::<F>::zero();
            for p in &product_vars {
                sum_lc = sum_lc + p.get_variable();
            }

            cs.enforce(
                || "sum_conservation",
                |_| sum_lc,
                |lc| lc + CS::one(),
                |lc| lc + output_value.get_variable(),
            );
        }

        // ====================================================================
        // 8. Range proof on output value
        // ====================================================================

        enforce_range(cs.namespace(|| "range_output"), &output_value, BALANCE_BITS)?;

        // ====================================================================
        // 9. Output commitment: Commit(output_value, output_blinding)
        // ====================================================================

        let output_blinding = AllocatedNum::alloc(cs.namespace(|| "output_blinding"), || {
            self.output_blinding
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let computed_output = pedersen_commit(
            cs.namespace(|| "output_commitment_compute"),
            &output_value,
            &output_blinding,
        )?;

        cs.enforce(
            || "output_commitment_matches",
            |lc| lc + computed_output.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + output_commitment_pub.get_variable(),
        );

        Ok(())
    }
}

// ============================================================================
// Circuit helpers
// ============================================================================

/// Select value if condition is true, else zero: result = bit ? value : 0
fn select_or_zero<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    value: &AllocatedNum<F>,
    bit: &Boolean,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let result = AllocatedNum::alloc(cs.namespace(|| "select_or_zero_result"), || {
        let bit_val = match bit.get_value() {
            Some(true) => F::ONE,
            Some(false) => F::ZERO,
            None => return Err(SynthesisError::AssignmentMissing),
        };
        let val = value.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        Ok(bit_val * val)
    })?;

    match bit {
        Boolean::Is(ref b) => {
            // bit * value = result
            cs.enforce(
                || "select_or_zero",
                |lc| lc + b.get_variable(),
                |lc| lc + value.get_variable(),
                |lc| lc + result.get_variable(),
            );
        }
        Boolean::Not(ref b) => {
            // (1 - b) * value = result
            cs.enforce(
                || "select_or_zero_not",
                |lc| lc + CS::one() - b.get_variable(),
                |lc| lc + value.get_variable(),
                |lc| lc + result.get_variable(),
            );
        }
        Boolean::Constant(c) => {
            if *c {
                cs.enforce(
                    || "select_or_zero_const_true",
                    |lc| lc + value.get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + result.get_variable(),
                );
            } else {
                cs.enforce(
                    || "select_or_zero_const_false",
                    |lc| lc + result.get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc,
                );
            }
        }
    }

    Ok(result)
}

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
    use crate::circuit::mimc::mimc_hash_native;
    use crate::circuit::note_spend::{
        compute_note_root_native, compute_nullifier_with_epoch_native,
    };
    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;
    use ff::Field;

    /// Build a valid consolidation circuit merging `num_real` notes
    fn build_valid_circuit(tree_depth: usize, num_real: usize) -> NoteConsolidateCircuit<Fr> {
        assert!(num_real <= MAX_CONSOLIDATION_INPUTS);

        let spending_key = Fr::from(42u64);
        let epoch = 1u64;
        let output_blinding = Fr::from(999u64);

        let mut nullifiers = vec![Some(Fr::ZERO); MAX_CONSOLIDATION_INPUTS];
        let mut is_real = vec![Some(false); MAX_CONSOLIDATION_INPUTS];
        let mut spending_keys = vec![Some(Fr::ZERO); MAX_CONSOLIDATION_INPUTS];
        let mut note_values = vec![Some(0u64); MAX_CONSOLIDATION_INPUTS];
        let mut note_blindings = vec![Some(Fr::ZERO); MAX_CONSOLIDATION_INPUTS];
        let mut note_indices = vec![Some(0u64); MAX_CONSOLIDATION_INPUTS];
        let mut epochs = vec![Some(0u64); MAX_CONSOLIDATION_INPUTS];
        let mut merkle_siblings = vec![vec![Some(Fr::ZERO); tree_depth]; MAX_CONSOLIDATION_INPUTS];

        let mut total_value = 0u64;

        // Build tree with all real notes
        // Simple approach: each note at a different index, isolated from each other
        for i in 0..num_real {
            let value = (100 + i as u64) * 10; // 1000, 1010, 1020, 1030
            let blinding = Fr::from(100u64 + i as u64);
            let index = i as u64;

            let commitment = pedersen_commit_native(Fr::from(value), blinding);
            let siblings = vec![Fr::ZERO; tree_depth];

            // Each note lives in an independent tree (all-zero siblings)
            // This means the root is deterministic per-note
            let root = compute_note_root_native(commitment, index, &siblings);
            let nullifier =
                compute_nullifier_with_epoch_native(spending_key, index, epoch, commitment);

            // For simplicity, use the same root for all notes (index=0, all zero siblings)
            // In reality each would be in the same tree but here we verify independently
            let _ = root;

            is_real[i] = Some(true);
            spending_keys[i] = Some(spending_key);
            note_values[i] = Some(value);
            note_blindings[i] = Some(blinding);
            note_indices[i] = Some(index);
            epochs[i] = Some(epoch);
            merkle_siblings[i] = siblings.iter().map(|s| Some(*s)).collect();
            nullifiers[i] = Some(nullifier);

            total_value += value;
        }

        // All real notes must share the same tree root for the circuit to work.
        // Use a tree with all notes inserted at different indices.
        // For simplicity with index isolation, recompute a shared root:
        // Actually, the circuit verifies each note independently against commitment_root_pub.
        // All real notes must be in the SAME tree. Let's build properly.

        // Rebuild: create a commitment tree with all notes
        let mut tree_leaves: Vec<(u64, Fr)> = Vec::new();
        for i in 0..num_real {
            let value = (100 + i as u64) * 10;
            let blinding = Fr::from(100u64 + i as u64);
            let commitment = pedersen_commit_native(Fr::from(value), blinding);
            tree_leaves.push((i as u64, commitment));
        }

        // Build a simple sparse tree and compute root + per-note siblings
        let all_siblings = build_tree_siblings(tree_depth, &tree_leaves);
        let tree_root = compute_tree_root(tree_depth, &tree_leaves);

        for i in 0..num_real {
            merkle_siblings[i] = all_siblings[i].iter().map(|s| Some(*s)).collect();
        }

        // Compute output commitment
        let output_commitment_val = pedersen_commit_native(Fr::from(total_value), output_blinding);

        NoteConsolidateCircuit {
            commitment_root: Some(tree_root),
            nullifiers,
            output_commitment: Some(output_commitment_val),
            is_real,
            spending_keys,
            note_values,
            note_blindings,
            note_indices,
            epochs,
            merkle_siblings,
            output_blinding: Some(output_blinding),
            tree_depth,
        }
    }

    /// Build tree root from sparse leaves
    fn compute_tree_root(depth: usize, leaves: &[(u64, Fr)]) -> Fr {
        let leaf_map: std::collections::HashMap<u64, Fr> = leaves.iter().cloned().collect();
        compute_node(depth, 0, &leaf_map)
    }

    fn compute_node(level: usize, index: u64, leaves: &std::collections::HashMap<u64, Fr>) -> Fr {
        if level == 0 {
            return *leaves.get(&index).unwrap_or(&Fr::ZERO);
        }
        let left = compute_node(level - 1, index * 2, leaves);
        let right = compute_node(level - 1, index * 2 + 1, leaves);
        mimc_hash_native(left, right)
    }

    /// Build merkle siblings for each leaf
    fn build_tree_siblings(depth: usize, leaves: &[(u64, Fr)]) -> Vec<Vec<Fr>> {
        let leaf_map: std::collections::HashMap<u64, Fr> = leaves.iter().cloned().collect();

        leaves
            .iter()
            .map(|(index, _)| {
                let mut siblings = Vec::with_capacity(depth);
                let mut current_idx = *index;
                for level in 0..depth {
                    let sibling_idx = current_idx ^ 1;
                    let sibling_hash = compute_node(level, sibling_idx, &leaf_map);
                    siblings.push(sibling_hash);
                    current_idx /= 2;
                }
                siblings
            })
            .collect()
    }

    #[test]
    fn test_dummy_synthesizes() {
        let circuit = NoteConsolidateCircuit::<Fr>::dummy(40);
        let mut cs = TestConstraintSystem::<Fr>::new();
        let result = circuit.synthesize(&mut cs);
        assert!(
            result.is_ok(),
            "Dummy must synthesize for MPC: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_consolidate_two_notes() {
        let circuit = build_valid_circuit(4, 2);
        let mut cs = TestConstraintSystem::<Fr>::new();
        let result = circuit.synthesize(&mut cs);

        assert!(result.is_ok(), "Synthesize failed: {:?}", result.err());
        assert!(
            cs.is_satisfied(),
            "2-note consolidation must satisfy: {:?}",
            cs.which_is_unsatisfied()
        );

        println!(
            "NoteConsolidateCircuit (depth=4, 2 inputs) constraints: {}",
            cs.num_constraints()
        );
    }

    #[test]
    fn test_consolidate_four_notes() {
        let circuit = build_valid_circuit(4, 4);
        let mut cs = TestConstraintSystem::<Fr>::new();
        let result = circuit.synthesize(&mut cs);

        assert!(result.is_ok(), "Synthesize failed: {:?}", result.err());
        assert!(
            cs.is_satisfied(),
            "4-note consolidation must satisfy: {:?}",
            cs.which_is_unsatisfied()
        );

        println!(
            "NoteConsolidateCircuit (depth=4, 4 inputs) constraints: {}",
            cs.num_constraints()
        );
    }

    #[test]
    fn test_consolidate_single_note() {
        let circuit = build_valid_circuit(4, 1);
        let mut cs = TestConstraintSystem::<Fr>::new();
        let result = circuit.synthesize(&mut cs);

        assert!(result.is_ok());
        assert!(
            cs.is_satisfied(),
            "1-note consolidation must satisfy: {:?}",
            cs.which_is_unsatisfied()
        );
    }

    #[test]
    #[ignore] // Expensive: 4 inputs × depth-40 merkle paths
    fn test_consolidate_depth_40() {
        let circuit = build_valid_circuit(40, 2);
        let mut cs = TestConstraintSystem::<Fr>::new();
        let result = circuit.synthesize(&mut cs);

        assert!(result.is_ok());
        assert!(
            cs.is_satisfied(),
            "Depth-40 consolidation must satisfy: {:?}",
            cs.which_is_unsatisfied()
        );

        let n = cs.num_constraints();
        println!(
            "NoteConsolidateCircuit (depth=40, 2 inputs) constraints: {}",
            n
        );
        // 4 inputs * ~3700 constraints each + overhead ≈ 15000
        assert!(n > 5000, "Expected > 5000 constraints, got {}", n);
        assert!(n < 50000, "Expected < 50000 constraints, got {}", n);
    }

    #[test]
    fn test_public_input_count() {
        let circuit = NoteConsolidateCircuit::<Fr>::dummy(4);
        let mut cs = TestConstraintSystem::<Fr>::new();
        let _ = circuit.synthesize(&mut cs);

        // 1 (root) + 4 (nullifiers) + 1 (output) + 1 (CS::one) = 7
        assert_eq!(cs.num_inputs(), 7);
    }

    #[test]
    fn test_wrong_output_value_fails() {
        let mut circuit = build_valid_circuit(4, 2);
        // Tamper: change output commitment to wrong value
        let wrong_output = pedersen_commit_native(Fr::from(999999u64), Fr::from(999u64));
        circuit.output_commitment = Some(wrong_output);

        let mut cs = TestConstraintSystem::<Fr>::new();
        let _ = circuit.synthesize(&mut cs);
        assert!(!cs.is_satisfied(), "Wrong output value must NOT satisfy");
    }
}
