//! Consolidation proof generation
//!
//! Generates Groth16 proofs for merging up to 4 notes into a single output note.
//! This reduces note fragmentation from repeated small spends.
//!
//! # SECURITY WARNING: Trusted Setup Required
//!
//! **Groth16 requires a trusted setup ceremony (MPC).**
//! Production deployments MUST use `new_with_params` with MPC-generated parameters.

#[allow(unused_imports)]
use bellperson::{
    groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, Parameters,
        PreparedVerifyingKey, Proof,
    },
    util_cs::test_cs::TestConstraintSystem,
    Circuit,
};
use blstrs::{Bls12, Scalar as Fr};
use ff::Field;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Instant;
#[allow(unused_imports)]
use tracing::{debug, error, info, instrument, warn};

use crate::circuit::commitment::pedersen_commit_native;
use crate::circuit::mimc::field_to_bytes;
use crate::circuit::note_consolidate::{NoteConsolidateCircuit, MAX_CONSOLIDATION_INPUTS};
use crate::circuit::note_spend::{compute_note_root_native, compute_nullifier_with_epoch_native};
use crate::errors::{ZkError, ZkResult};
use crate::field_utils::bytes_to_field;
use crate::types::GROTH16_PROOF_SIZE;

/// Public inputs for a consolidation proof (6 field elements as bytes)
#[derive(Debug, Clone)]
pub struct ConsolidationPublicInputs {
    pub commitment_root: [u8; 32],
    pub nullifiers: [[u8; 32]; MAX_CONSOLIDATION_INPUTS],
    pub output_commitment: [u8; 32],
}

/// Per-input note data for consolidation witness
#[derive(Debug, Clone)]
pub struct ConsolidationInputNote {
    pub value: u64,
    pub blinding: [u8; 32],
    pub index: u64,
    pub epoch: u64,
    pub merkle_siblings: Vec<[u8; 32]>,
}

/// Witness data for generating a consolidation proof
#[derive(Debug, Clone)]
pub struct ConsolidationWitness {
    pub spending_key: [u8; 32],
    pub inputs: Vec<ConsolidationInputNote>,
    pub output_blinding: [u8; 32],
}

impl ConsolidationWitness {
    /// Validate witness data
    pub fn validate(&self) -> ZkResult<()> {
        if self.inputs.is_empty() {
            return Err(ZkError::InvalidWitness(
                "At least one input note required".to_string(),
            ));
        }
        if self.inputs.len() > MAX_CONSOLIDATION_INPUTS {
            return Err(ZkError::InvalidWitness(format!(
                "Too many inputs: {} > {}",
                self.inputs.len(),
                MAX_CONSOLIDATION_INPUTS
            )));
        }
        Ok(())
    }

    /// Compute total value of all input notes
    pub fn total_value(&self) -> u64 {
        self.inputs.iter().map(|n| n.value).sum()
    }
}

/// Proof of a valid note consolidation (192 bytes Groth16)
#[derive(Debug, Clone)]
pub struct ConsolidationProof {
    pub public_inputs: ConsolidationPublicInputs,
    pub proof: Vec<u8>,
    pub prover_id: [u8; 32],
}

impl ConsolidationProof {
    /// Check if this is a real Groth16 proof (192 bytes)
    pub fn is_real_proof(&self) -> bool {
        self.proof.len() == GROTH16_PROOF_SIZE
    }
}

/// Generates ZK proofs for note consolidation
pub struct GhostConsolidateProver {
    params: Option<Arc<Parameters<Bls12>>>,
    prepared_vk: Option<Arc<PreparedVerifyingKey<Bls12>>>,
    tree_depth: usize,
    prover_id: [u8; 32],
}

impl GhostConsolidateProver {
    /// Create a new consolidation prover without Groth16 parameters
    pub fn new(tree_depth: usize) -> Self {
        let prover_id = compute_prover_id(tree_depth);
        Self {
            params: None,
            prepared_vk: None,
            tree_depth,
            prover_id,
        }
    }

    /// Create a prover with MPC-generated parameters
    pub fn new_with_params(params: Arc<Parameters<Bls12>>, tree_depth: usize) -> Self {
        let prover_id = compute_prover_id(tree_depth);
        let prepared_vk = prepare_verifying_key(&params.vk);
        Self {
            params: Some(params),
            prepared_vk: Some(Arc::new(prepared_vk)),
            tree_depth,
            prover_id,
        }
    }

    /// Create a prover with full Groth16 setup (TESTING ONLY)
    #[cfg(not(feature = "zk-production"))]
    pub fn new_with_setup(tree_depth: usize) -> ZkResult<Self> {
        error!(
            "SECURITY WARNING: Using random trusted setup for NoteConsolidateCircuit. INSECURE."
        );
        let dummy_circuit = NoteConsolidateCircuit::<Fr>::dummy(tree_depth);
        let params =
            generate_random_parameters::<Bls12, _, _>(dummy_circuit, &mut rand::rngs::OsRng)
                .map_err(|e| {
                    ZkError::SetupError(format!("Parameter generation failed: {:?}", e))
                })?;
        let prepared_vk = prepare_verifying_key(&params.vk);
        let prover_id = compute_prover_id(tree_depth);

        Ok(Self {
            params: Some(Arc::new(params)),
            prepared_vk: Some(Arc::new(prepared_vk)),
            tree_depth,
            prover_id,
        })
    }

    #[cfg(feature = "zk-production")]
    pub fn new_with_setup(_tree_depth: usize) -> ZkResult<Self> {
        Err(ZkError::SetupError(
            "SECURITY: new_with_setup() is disabled in production builds. \
             Use new_with_params() with MPC-generated parameters."
                .to_string(),
        ))
    }

    pub fn prover_id(&self) -> [u8; 32] {
        self.prover_id
    }

    pub fn tree_depth(&self) -> usize {
        self.tree_depth
    }

    pub fn prepared_verifying_key(&self) -> Option<Arc<PreparedVerifyingKey<Bls12>>> {
        self.prepared_vk.clone()
    }

    pub fn has_groth16_params(&self) -> bool {
        self.params.is_some()
    }

    /// Generate a proof for a note consolidation
    #[instrument(skip_all)]
    pub fn prove(&self, witness: &ConsolidationWitness) -> ZkResult<ConsolidationProof> {
        let start = Instant::now();

        witness.validate()?;

        let circuit = self.build_circuit(witness)?;
        let public_inputs = self.compute_public_inputs(witness)?;

        debug_assert!(
            !circuit.is_dummy,
            "CR-2: Cannot generate proof with dummy circuit"
        );
        if circuit.is_dummy {
            return Err(ZkError::ProvingError(
                "CR-2: Cannot generate proof with dummy circuit".to_string(),
            ));
        }

        let proof_bytes = if let Some(ref params) = self.params {
            let proving_start = Instant::now();
            let proof: Proof<Bls12> =
                create_random_proof(circuit, params.as_ref(), &mut rand::rngs::OsRng).map_err(
                    |e| ZkError::ProvingError(format!("Groth16 proving failed: {:?}", e)),
                )?;

            debug!(
                "Groth16 consolidation proof in {:?}",
                proving_start.elapsed()
            );

            let mut bytes = Vec::with_capacity(GROTH16_PROOF_SIZE);
            bytes.extend_from_slice(&proof.a.to_compressed());
            bytes.extend_from_slice(&proof.b.to_compressed());
            bytes.extend_from_slice(&proof.c.to_compressed());
            bytes
        } else {
            #[cfg(not(test))]
            {
                return Err(ZkError::ProvingError(
                    "Groth16 parameters required but not available.".to_string(),
                ));
            }
            #[cfg(test)]
            {
                let test_circuit = self.build_circuit(witness)?;
                let mut cs = TestConstraintSystem::<Fr>::new();
                test_circuit
                    .synthesize(&mut cs)
                    .map_err(|e| ZkError::SynthesisError(format!("Synthesis failed: {:?}", e)))?;

                if !cs.is_satisfied() {
                    let unsatisfied = cs.which_is_unsatisfied();
                    return Err(ZkError::ProvingError(format!(
                        "Circuit constraints not satisfied: {:?}",
                        unsatisfied
                    )));
                }

                debug!(
                    "NoteConsolidateCircuit satisfied with {} constraints",
                    cs.num_constraints()
                );

                warn!("Using simulated proof (test mode only)");
                self.generate_simulated_proof(witness, cs.num_constraints())
            }
        };

        info!(
            "Consolidation proof generated in {:?}, size: {} bytes",
            start.elapsed(),
            proof_bytes.len()
        );

        Ok(ConsolidationProof {
            public_inputs,
            proof: proof_bytes,
            prover_id: self.prover_id,
        })
    }

    fn build_circuit(
        &self,
        witness: &ConsolidationWitness,
    ) -> ZkResult<NoteConsolidateCircuit<Fr>> {
        let spending_key: Fr = bytes_to_field(&witness.spending_key)?;

        let mut is_real = vec![Some(false); MAX_CONSOLIDATION_INPUTS];
        let mut spending_keys = vec![Some(Fr::ZERO); MAX_CONSOLIDATION_INPUTS];
        let mut note_values = vec![Some(0u64); MAX_CONSOLIDATION_INPUTS];
        let mut note_blindings = vec![Some(Fr::ZERO); MAX_CONSOLIDATION_INPUTS];
        let mut note_indices = vec![Some(0u64); MAX_CONSOLIDATION_INPUTS];
        let mut epochs = vec![Some(0u64); MAX_CONSOLIDATION_INPUTS];
        let mut merkle_siblings =
            vec![vec![Some(Fr::ZERO); self.tree_depth]; MAX_CONSOLIDATION_INPUTS];
        let mut nullifiers = vec![Some(Fr::ZERO); MAX_CONSOLIDATION_INPUTS];

        // Fill in real inputs
        for (i, input) in witness.inputs.iter().enumerate() {
            let blinding_fr: Fr = bytes_to_field(&input.blinding)?;
            let commitment = pedersen_commit_native(Fr::from(input.value), blinding_fr);
            let nullifier = compute_nullifier_with_epoch_native(
                spending_key,
                input.index,
                input.epoch,
                commitment,
            );

            is_real[i] = Some(true);
            spending_keys[i] = Some(spending_key);
            note_values[i] = Some(input.value);
            note_blindings[i] = Some(blinding_fr);
            note_indices[i] = Some(input.index);
            epochs[i] = Some(input.epoch);
            nullifiers[i] = Some(nullifier);

            let siblings: Vec<Option<Fr>> = input
                .merkle_siblings
                .iter()
                .map(|s| bytes_to_field(s).ok())
                .collect();
            merkle_siblings[i] = siblings;
        }

        // Compute commitment root from the first real input
        let first_input = &witness.inputs[0];
        let first_blinding: Fr = bytes_to_field(&first_input.blinding)?;
        let first_commitment = pedersen_commit_native(Fr::from(first_input.value), first_blinding);
        let first_siblings: Vec<Fr> = first_input
            .merkle_siblings
            .iter()
            .map(|s| bytes_to_field(s).unwrap_or(Fr::ZERO))
            .collect();
        let commitment_root =
            compute_note_root_native(first_commitment, first_input.index, &first_siblings);

        // Compute output
        let total_value: u64 = witness.inputs.iter().map(|n| n.value).sum();
        let output_blinding: Fr = bytes_to_field(&witness.output_blinding)?;
        let output_commitment = pedersen_commit_native(Fr::from(total_value), output_blinding);

        Ok(NoteConsolidateCircuit {
            commitment_root: Some(commitment_root),
            nullifiers,
            output_commitment: Some(output_commitment),
            is_real,
            spending_keys,
            note_values,
            note_blindings,
            note_indices,
            epochs,
            merkle_siblings,
            output_blinding: Some(output_blinding),
            tree_depth: self.tree_depth,
            is_dummy: false,
        })
    }

    fn compute_public_inputs(
        &self,
        witness: &ConsolidationWitness,
    ) -> ZkResult<ConsolidationPublicInputs> {
        let spending_key: Fr = bytes_to_field(&witness.spending_key)?;

        // Compute commitment root from first input
        let first_input = &witness.inputs[0];
        let first_blinding: Fr = bytes_to_field(&first_input.blinding)?;
        let first_commitment = pedersen_commit_native(Fr::from(first_input.value), first_blinding);
        let first_siblings: Vec<Fr> = first_input
            .merkle_siblings
            .iter()
            .map(|s| bytes_to_field(s).unwrap_or(Fr::ZERO))
            .collect();
        let commitment_root =
            compute_note_root_native(first_commitment, first_input.index, &first_siblings);

        // Compute nullifiers for each input (zero-padded for unused slots)
        let mut nullifiers = [[0u8; 32]; MAX_CONSOLIDATION_INPUTS];
        for (i, input) in witness.inputs.iter().enumerate() {
            let blinding_fr: Fr = bytes_to_field(&input.blinding)?;
            let commitment = pedersen_commit_native(Fr::from(input.value), blinding_fr);
            let nullifier = compute_nullifier_with_epoch_native(
                spending_key,
                input.index,
                input.epoch,
                commitment,
            );
            nullifiers[i] = field_to_bytes(nullifier);
        }

        // Compute output commitment
        let total_value: u64 = witness.inputs.iter().map(|n| n.value).sum();
        let output_blinding: Fr = bytes_to_field(&witness.output_blinding)?;
        let output_commitment = pedersen_commit_native(Fr::from(total_value), output_blinding);

        Ok(ConsolidationPublicInputs {
            commitment_root: field_to_bytes(commitment_root),
            nullifiers,
            output_commitment: field_to_bytes(output_commitment),
        })
    }

    #[cfg(test)]
    fn generate_simulated_proof(
        &self,
        witness: &ConsolidationWitness,
        num_constraints: usize,
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"ghost-zkp-consolidation-proof-v1");
        hasher.update(self.prover_id);
        hasher.update(witness.total_value().to_le_bytes());
        hasher.update((witness.inputs.len() as u64).to_le_bytes());
        hasher.update((num_constraints as u64).to_le_bytes());
        let hash: [u8; 32] = hasher.finalize().into();

        let mut proof = Vec::with_capacity(73);
        proof.extend_from_slice(&self.prover_id);
        proof.extend_from_slice(&hash);
        proof.extend_from_slice(&(num_constraints as u64).to_le_bytes());
        proof.push(4u8); // Mode flag: 4 = consolidation
        proof
    }
}

fn compute_prover_id(tree_depth: usize) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ghost-zkp-consolidation-prover-v1");
    hasher.update(tree_depth.to_le_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::mimc::mimc_hash_native;

    /// Build a tree from sparse leaves and return (root, per-leaf siblings)
    fn build_tree(depth: usize, leaves: &[(u64, Fr)]) -> (Fr, Vec<Vec<[u8; 32]>>) {
        let leaf_map: std::collections::HashMap<u64, Fr> = leaves.iter().cloned().collect();

        fn compute_node(
            level: usize,
            index: u64,
            leaves: &std::collections::HashMap<u64, Fr>,
        ) -> Fr {
            if level == 0 {
                return *leaves.get(&index).unwrap_or(&Fr::ZERO);
            }
            let left = compute_node(level - 1, index * 2, leaves);
            let right = compute_node(level - 1, index * 2 + 1, leaves);
            mimc_hash_native(left, right)
        }

        let root = compute_node(depth, 0, &leaf_map);

        let siblings = leaves
            .iter()
            .map(|(index, _)| {
                let mut sibs = Vec::with_capacity(depth);
                let mut current_idx = *index;
                for level in 0..depth {
                    let sibling_idx = current_idx ^ 1;
                    let sibling_hash = compute_node(level, sibling_idx, &leaf_map);
                    sibs.push(field_to_bytes(sibling_hash));
                    current_idx /= 2;
                }
                sibs
            })
            .collect();

        (root, siblings)
    }

    fn create_test_witness(tree_depth: usize, num_inputs: usize) -> ConsolidationWitness {
        let spending_key = field_to_bytes(Fr::from(42u64));

        // Build notes and insert into tree
        let mut tree_leaves = Vec::new();
        let mut inputs = Vec::new();

        for i in 0..num_inputs {
            let value = (100 + i as u64) * 10;
            let blinding = Fr::from(100u64 + i as u64);
            let commitment = pedersen_commit_native(Fr::from(value), blinding);
            tree_leaves.push((i as u64, commitment));
            inputs.push((value, blinding, i as u64));
        }

        let (_root, all_siblings) = build_tree(tree_depth, &tree_leaves);

        let input_notes: Vec<ConsolidationInputNote> = inputs
            .iter()
            .enumerate()
            .map(|(i, (value, blinding, index))| ConsolidationInputNote {
                value: *value,
                blinding: field_to_bytes(*blinding),
                index: *index,
                epoch: 1,
                merkle_siblings: all_siblings[i].clone(),
            })
            .collect();

        ConsolidationWitness {
            spending_key,
            inputs: input_notes,
            output_blinding: field_to_bytes(Fr::from(999u64)),
        }
    }

    #[test]
    fn test_prover_creation() {
        let prover = GhostConsolidateProver::new(20);
        assert_eq!(prover.tree_depth(), 20);
        assert!(!prover.has_groth16_params());
    }

    #[test]
    fn test_prove_two_notes() {
        let prover = GhostConsolidateProver::new(4);
        let witness = create_test_witness(4, 2);
        let result = prover.prove(&witness);
        assert!(result.is_ok(), "Proof should succeed: {:?}", result.err());
        let proof = result.unwrap();
        assert!(!proof.proof.is_empty());
    }

    #[test]
    fn test_prove_four_notes() {
        let prover = GhostConsolidateProver::new(4);
        let witness = create_test_witness(4, 4);
        let result = prover.prove(&witness);
        assert!(result.is_ok(), "Proof should succeed: {:?}", result.err());
    }

    #[test]
    fn test_prove_single_note() {
        let prover = GhostConsolidateProver::new(4);
        let witness = create_test_witness(4, 1);
        let result = prover.prove(&witness);
        assert!(result.is_ok(), "Proof should succeed: {:?}", result.err());
    }

    #[test]
    fn test_empty_inputs_rejected() {
        let prover = GhostConsolidateProver::new(4);
        let witness = ConsolidationWitness {
            spending_key: [42u8; 32],
            inputs: vec![],
            output_blinding: [0u8; 32],
        };
        let result = prover.prove(&witness);
        assert!(result.is_err());
    }

    #[test]
    fn test_too_many_inputs_rejected() {
        let prover = GhostConsolidateProver::new(4);
        let mut witness = create_test_witness(4, 4);
        // Add a 5th input
        witness.inputs.push(witness.inputs[0].clone());
        let result = prover.prove(&witness);
        assert!(result.is_err());
    }

    #[test]
    fn test_public_inputs_non_zero() {
        let prover = GhostConsolidateProver::new(4);
        let witness = create_test_witness(4, 2);
        let proof = prover.prove(&witness).unwrap();

        assert_ne!(proof.public_inputs.commitment_root, [0u8; 32]);
        assert_ne!(proof.public_inputs.nullifiers[0], [0u8; 32]);
        assert_ne!(proof.public_inputs.nullifiers[1], [0u8; 32]);
        // Unused slots should be zero
        assert_eq!(proof.public_inputs.nullifiers[2], [0u8; 32]);
        assert_eq!(proof.public_inputs.nullifiers[3], [0u8; 32]);
        assert_ne!(proof.public_inputs.output_commitment, [0u8; 32]);
    }

    #[test]
    #[ignore] // Expensive ~10-30s
    fn test_groth16_prove_roundtrip() {
        let prover = GhostConsolidateProver::new_with_setup(4).expect("Setup should succeed");
        assert!(prover.has_groth16_params());
        let witness = create_test_witness(4, 2);
        let proof = prover.prove(&witness).expect("Proof should succeed");
        assert!(proof.is_real_proof());
        assert_eq!(proof.proof.len(), GROTH16_PROOF_SIZE);
    }
}
