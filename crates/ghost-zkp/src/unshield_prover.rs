//! Unshield (L2 -> L1 withdrawal) proof generation
//!
//! Generates Groth16 proofs for full note withdrawals from L2 to L1.
//! The entire note value leaves L2 and becomes publicly visible for
//! L1 settlement verification.
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
use crate::circuit::note_spend::{compute_note_root_native, compute_nullifier_with_epoch_native};
use crate::circuit::unshield::GhostUnshieldCircuit;
use crate::errors::{ZkError, ZkResult};
use crate::field_utils::bytes_to_field;
use crate::types::GROTH16_PROOF_SIZE;

/// Witness data for generating an unshield proof
#[derive(Debug, Clone)]
pub struct UnshieldWitness {
    pub spending_key: [u8; 32],
    pub note_value: u64,
    pub note_blinding: [u8; 32],
    pub note_index: u64,
    pub epoch: u64,
    pub merkle_siblings: Vec<[u8; 32]>,
}

impl UnshieldWitness {
    /// Validate witness data
    pub fn validate(&self, tree_depth: usize) -> ZkResult<()> {
        if self.merkle_siblings.len() != tree_depth {
            return Err(ZkError::InvalidWitness(format!(
                "Merkle siblings count mismatch: {} != {}",
                self.merkle_siblings.len(),
                tree_depth
            )));
        }
        Ok(())
    }
}

/// Public inputs for an unshield proof (3 field elements as bytes)
#[derive(Debug, Clone)]
pub struct UnshieldPublicInputs {
    pub commitment_root: [u8; 32],
    pub nullifier: [u8; 32],
    pub withdrawal_amount: u64,
}

/// Proof of a valid full withdrawal (192 bytes Groth16)
#[derive(Debug, Clone)]
pub struct UnshieldProof {
    pub public_inputs: UnshieldPublicInputs,
    pub proof: Vec<u8>,
    pub prover_id: [u8; 32],
}

impl UnshieldProof {
    /// Check if this is a real Groth16 proof (192 bytes)
    pub fn is_real_proof(&self) -> bool {
        self.proof.len() == GROTH16_PROOF_SIZE
    }
}

/// Generates ZK proofs for note unshielding (L2 -> L1 withdrawal)
pub struct GhostUnshieldProver {
    params: Option<Arc<Parameters<Bls12>>>,
    prepared_vk: Option<Arc<PreparedVerifyingKey<Bls12>>>,
    tree_depth: usize,
    prover_id: [u8; 32],
}

impl GhostUnshieldProver {
    /// Create a new unshield prover without Groth16 parameters
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
        error!("SECURITY WARNING: Using random trusted setup for GhostUnshieldCircuit. INSECURE.");
        let dummy_circuit = GhostUnshieldCircuit::<Fr>::dummy(tree_depth);
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

    /// Generate a proof for a note unshield (full withdrawal)
    #[instrument(skip_all)]
    pub fn prove(&self, witness: &UnshieldWitness) -> ZkResult<UnshieldProof> {
        let start = Instant::now();

        witness.validate(self.tree_depth)?;

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

            debug!("Groth16 unshield proof in {:?}", proving_start.elapsed());

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
                    "GhostUnshieldCircuit satisfied with {} constraints",
                    cs.num_constraints()
                );

                warn!("Using simulated proof (test mode only)");
                self.generate_simulated_proof(witness, cs.num_constraints())
            }
        };

        info!(
            "Unshield proof generated in {:?}, size: {} bytes",
            start.elapsed(),
            proof_bytes.len()
        );

        Ok(UnshieldProof {
            public_inputs,
            proof: proof_bytes,
            prover_id: self.prover_id,
        })
    }

    fn build_circuit(
        &self,
        witness: &UnshieldWitness,
    ) -> ZkResult<GhostUnshieldCircuit<Fr>> {
        let spending_key: Fr = bytes_to_field(&witness.spending_key)?;
        let note_blinding: Fr = bytes_to_field(&witness.note_blinding)?;
        let note_value_fr = Fr::from(witness.note_value);

        // Compute commitment and root natively for the public inputs
        let commitment = pedersen_commit_native(note_value_fr, note_blinding);
        let siblings_fr: Vec<Fr> = witness
            .merkle_siblings
            .iter()
            .map(|s| bytes_to_field(s).unwrap_or(Fr::ZERO))
            .collect();
        let commitment_root =
            compute_note_root_native(commitment, witness.note_index, &siblings_fr);

        // Compute nullifier natively
        let nullifier = compute_nullifier_with_epoch_native(
            spending_key,
            witness.note_index,
            witness.epoch,
            commitment,
        );

        let siblings_opt: Vec<Option<Fr>> = witness
            .merkle_siblings
            .iter()
            .map(|s| bytes_to_field(s).ok())
            .collect();

        Ok(GhostUnshieldCircuit {
            commitment_root: Some(commitment_root),
            nullifier: Some(nullifier),
            withdrawal_amount: Some(note_value_fr),
            spending_key: Some(spending_key),
            note_value: Some(note_value_fr),
            note_blinding: Some(note_blinding),
            note_index: Some(Fr::from(witness.note_index)),
            epoch: Some(Fr::from(witness.epoch)),
            merkle_siblings: siblings_opt,
            tree_depth: self.tree_depth,
            is_dummy: false,
        })
    }

    fn compute_public_inputs(
        &self,
        witness: &UnshieldWitness,
    ) -> ZkResult<UnshieldPublicInputs> {
        let spending_key: Fr = bytes_to_field(&witness.spending_key)?;
        let note_blinding: Fr = bytes_to_field(&witness.note_blinding)?;
        let note_value_fr = Fr::from(witness.note_value);

        // Compute commitment
        let commitment = pedersen_commit_native(note_value_fr, note_blinding);

        // Compute root
        let siblings_fr: Vec<Fr> = witness
            .merkle_siblings
            .iter()
            .map(|s| bytes_to_field(s).unwrap_or(Fr::ZERO))
            .collect();
        let commitment_root =
            compute_note_root_native(commitment, witness.note_index, &siblings_fr);

        // Compute nullifier
        let nullifier = compute_nullifier_with_epoch_native(
            spending_key,
            witness.note_index,
            witness.epoch,
            commitment,
        );

        Ok(UnshieldPublicInputs {
            commitment_root: field_to_bytes(commitment_root),
            nullifier: field_to_bytes(nullifier),
            withdrawal_amount: witness.note_value,
        })
    }

    #[cfg(test)]
    fn generate_simulated_proof(
        &self,
        witness: &UnshieldWitness,
        num_constraints: usize,
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"ghost-zkp-unshield-proof-v1");
        hasher.update(self.prover_id);
        hasher.update(witness.note_value.to_le_bytes());
        hasher.update(witness.note_index.to_le_bytes());
        hasher.update((num_constraints as u64).to_le_bytes());
        let hash: [u8; 32] = hasher.finalize().into();

        let mut proof = Vec::with_capacity(73);
        proof.extend_from_slice(&self.prover_id);
        proof.extend_from_slice(&hash);
        proof.extend_from_slice(&(num_constraints as u64).to_le_bytes());
        proof.push(5u8); // Mode flag: 5 = unshield
        proof
    }
}

fn compute_prover_id(tree_depth: usize) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ghost-zkp-unshield-prover-v1");
    hasher.update(tree_depth.to_le_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::mimc::mimc_hash_native;

    /// Build a tree from sparse leaves and return (root, per-leaf siblings)
    fn build_tree(
        depth: usize,
        leaves: &[(u64, Fr)],
    ) -> (Fr, Vec<Vec<[u8; 32]>>) {
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

    fn create_test_witness(tree_depth: usize) -> UnshieldWitness {
        let spending_key = field_to_bytes(Fr::from(42u64));
        let value = 1000u64;
        let blinding = Fr::from(111u64);
        let commitment = pedersen_commit_native(Fr::from(value), blinding);

        let (_root, all_siblings) = build_tree(tree_depth, &[(0, commitment)]);

        UnshieldWitness {
            spending_key,
            note_value: value,
            note_blinding: field_to_bytes(blinding),
            note_index: 0,
            epoch: 1,
            merkle_siblings: all_siblings[0].clone(),
        }
    }

    #[test]
    fn test_prover_creation() {
        let prover = GhostUnshieldProver::new(20);
        assert_eq!(prover.tree_depth(), 20);
        assert!(!prover.has_groth16_params());
    }

    #[test]
    fn test_prove_unshield() {
        let prover = GhostUnshieldProver::new(4);
        let witness = create_test_witness(4);
        let result = prover.prove(&witness);
        assert!(result.is_ok(), "Proof should succeed: {:?}", result.err());
        let proof = result.unwrap();
        assert!(!proof.proof.is_empty());
    }

    #[test]
    fn test_wrong_siblings_count_rejected() {
        let prover = GhostUnshieldProver::new(4);
        let mut witness = create_test_witness(4);
        witness.merkle_siblings.push([0u8; 32]); // Add extra sibling
        let result = prover.prove(&witness);
        assert!(result.is_err());
    }

    #[test]
    fn test_public_inputs_non_zero() {
        let prover = GhostUnshieldProver::new(4);
        let witness = create_test_witness(4);
        let proof = prover.prove(&witness).unwrap();

        assert_ne!(proof.public_inputs.commitment_root, [0u8; 32]);
        assert_ne!(proof.public_inputs.nullifier, [0u8; 32]);
        assert_eq!(proof.public_inputs.withdrawal_amount, 1000);
    }

    #[test]
    fn test_prover_id_deterministic() {
        let prover1 = GhostUnshieldProver::new(20);
        let prover2 = GhostUnshieldProver::new(20);
        assert_eq!(prover1.prover_id(), prover2.prover_id());

        let prover3 = GhostUnshieldProver::new(4);
        assert_ne!(prover1.prover_id(), prover3.prover_id());
    }

    #[test]
    #[ignore] // Expensive ~10-30s
    fn test_groth16_prove_roundtrip() {
        let prover =
            GhostUnshieldProver::new_with_setup(4).expect("Setup should succeed");
        assert!(prover.has_groth16_params());
        let witness = create_test_witness(4);
        let proof = prover.prove(&witness).expect("Proof should succeed");
        assert!(proof.is_real_proof());
        assert_eq!(proof.proof.len(), GROTH16_PROOF_SIZE);
    }
}
