//! Sender-side proof generation for note spends
//!
//! Generates Groth16 proofs that a note spend is valid without revealing
//! the transfer amount, sender balance, or identities.
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
use crate::circuit::note_spend::{
    compute_note_root_native, compute_nullifier_with_epoch_native, NoteSpendCircuit,
};
use crate::errors::{ZkError, ZkResult};
use crate::field_utils::bytes_to_field;
use crate::types::GROTH16_PROOF_SIZE;

/// Public inputs for a note spend proof (4 field elements as bytes)
#[derive(Debug, Clone)]
pub struct NoteSpendPublicInputs {
    pub commitment_root: [u8; 32],
    pub nullifier: [u8; 32],
    pub change_commitment: [u8; 32],
    pub recipient_commitment: [u8; 32],
}

/// Witness data for generating a note spend proof
#[derive(Debug, Clone)]
pub struct NoteSpendWitness {
    pub spending_key: [u8; 32],
    pub note_value: u64,
    pub note_blinding: [u8; 32],
    pub note_index: u64,
    pub epoch: u64,
    pub merkle_siblings: Vec<[u8; 32]>,
    pub amount: u64,
    pub change_blinding: [u8; 32],
    pub recipient_blinding: [u8; 32],
}

impl NoteSpendWitness {
    /// Validate witness data
    pub fn validate(&self) -> ZkResult<()> {
        if self.amount > self.note_value {
            return Err(ZkError::InsufficientBalance {
                has: self.note_value,
                needs: self.amount,
            });
        }
        Ok(())
    }
}

/// Proof of a valid note spend (192 bytes Groth16)
#[derive(Debug, Clone)]
pub struct NoteSpendProof {
    pub public_inputs: NoteSpendPublicInputs,
    pub proof: Vec<u8>,
    pub prover_id: [u8; 32],
}

impl NoteSpendProof {
    /// Check if this is a real Groth16 proof (192 bytes)
    pub fn is_real_proof(&self) -> bool {
        self.proof.len() == GROTH16_PROOF_SIZE
    }
}

/// Generates ZK proofs for note spends
pub struct NoteProver {
    params: Option<Arc<Parameters<Bls12>>>,
    prepared_vk: Option<Arc<PreparedVerifyingKey<Bls12>>>,
    tree_depth: usize,
    prover_id: [u8; 32],
}

impl NoteProver {
    /// Create a new note prover without Groth16 parameters
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
        error!("SECURITY WARNING: Using random trusted setup for NoteSpendCircuit. INSECURE.");
        let dummy_circuit = NoteSpendCircuit::<Fr>::dummy(tree_depth);
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

    /// Generate a proof for a note spend
    #[instrument(skip_all)]
    pub fn prove(&self, witness: &NoteSpendWitness) -> ZkResult<NoteSpendProof> {
        let start = Instant::now();

        witness.validate()?;

        let circuit = self.build_circuit(witness)?;
        let public_inputs = self.compute_public_inputs(witness)?;

        // Verify constraints first
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
            "NoteSpendCircuit satisfied with {} constraints",
            cs.num_constraints()
        );

        // CR-2: Reject dummy circuits at proof generation time
        debug_assert!(
            !circuit.is_dummy,
            "CR-2: Cannot generate proof with dummy circuit — use real witness values"
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

            debug!("Groth16 note spend proof in {:?}", proving_start.elapsed());

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
                warn!("Using simulated proof (test mode only)");
                self.generate_simulated_proof(witness, cs.num_constraints())
            }
        };

        info!(
            "Note spend proof generated in {:?}, size: {} bytes",
            start.elapsed(),
            proof_bytes.len()
        );

        Ok(NoteSpendProof {
            public_inputs,
            proof: proof_bytes,
            prover_id: self.prover_id,
        })
    }

    fn build_circuit(&self, witness: &NoteSpendWitness) -> ZkResult<NoteSpendCircuit<Fr>> {
        let spending_key: Fr = bytes_to_field(&witness.spending_key)?;
        let note_blinding: Fr = bytes_to_field(&witness.note_blinding)?;
        let change_blinding: Fr = bytes_to_field(&witness.change_blinding)?;
        let recipient_blinding: Fr = bytes_to_field(&witness.recipient_blinding)?;

        let siblings: Vec<Option<Fr>> = witness
            .merkle_siblings
            .iter()
            .map(|s| bytes_to_field(s).ok())
            .collect();

        // Compute values for public inputs
        let note_commitment = pedersen_commit_native(Fr::from(witness.note_value), note_blinding);
        let change_value = witness.note_value - witness.amount;
        let change_commitment_val = pedersen_commit_native(Fr::from(change_value), change_blinding);
        let recipient_commitment_val =
            pedersen_commit_native(Fr::from(witness.amount), recipient_blinding);

        let sibling_fields: Vec<Fr> = siblings.iter().map(|s| s.unwrap_or(Fr::ZERO)).collect();
        let commitment_root =
            compute_note_root_native(note_commitment, witness.note_index, &sibling_fields);
        let nullifier = compute_nullifier_with_epoch_native(
            spending_key,
            witness.note_index,
            witness.epoch,
            note_commitment,
        );

        Ok(NoteSpendCircuit {
            commitment_root: Some(commitment_root),
            nullifier: Some(nullifier),
            change_commitment: Some(change_commitment_val),
            recipient_commitment: Some(recipient_commitment_val),
            spending_key: Some(spending_key),
            note_value: Some(witness.note_value),
            note_blinding: Some(note_blinding),
            note_index: Some(witness.note_index),
            epoch: Some(witness.epoch),
            merkle_siblings: siblings,
            amount: Some(witness.amount),
            change_blinding: Some(change_blinding),
            recipient_blinding: Some(recipient_blinding),
            tree_depth: self.tree_depth,
            is_dummy: false,
        })
    }

    fn compute_public_inputs(&self, witness: &NoteSpendWitness) -> ZkResult<NoteSpendPublicInputs> {
        let spending_key: Fr = bytes_to_field(&witness.spending_key)?;
        let note_blinding: Fr = bytes_to_field(&witness.note_blinding)?;
        let change_blinding: Fr = bytes_to_field(&witness.change_blinding)?;
        let recipient_blinding: Fr = bytes_to_field(&witness.recipient_blinding)?;

        let note_commitment = pedersen_commit_native(Fr::from(witness.note_value), note_blinding);
        let change_value = witness.note_value - witness.amount;
        let change_commitment_val = pedersen_commit_native(Fr::from(change_value), change_blinding);
        let recipient_commitment_val =
            pedersen_commit_native(Fr::from(witness.amount), recipient_blinding);

        let sibling_fields: Vec<Fr> = witness
            .merkle_siblings
            .iter()
            .map(|s| bytes_to_field(s).unwrap_or(Fr::ZERO))
            .collect();

        let commitment_root =
            compute_note_root_native(note_commitment, witness.note_index, &sibling_fields);
        let nullifier = compute_nullifier_with_epoch_native(
            spending_key,
            witness.note_index,
            witness.epoch,
            note_commitment,
        );

        Ok(NoteSpendPublicInputs {
            commitment_root: field_to_bytes(commitment_root),
            nullifier: field_to_bytes(nullifier),
            change_commitment: field_to_bytes(change_commitment_val),
            recipient_commitment: field_to_bytes(recipient_commitment_val),
        })
    }

    #[cfg(test)]
    fn generate_simulated_proof(
        &self,
        witness: &NoteSpendWitness,
        num_constraints: usize,
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"ghost-zkp-note-spend-proof-v1");
        hasher.update(self.prover_id);
        hasher.update(witness.note_value.to_le_bytes());
        hasher.update(witness.amount.to_le_bytes());
        hasher.update((num_constraints as u64).to_le_bytes());
        let hash: [u8; 32] = hasher.finalize().into();

        let mut proof = Vec::with_capacity(73);
        proof.extend_from_slice(&self.prover_id);
        proof.extend_from_slice(&hash);
        proof.extend_from_slice(&(num_constraints as u64).to_le_bytes());
        proof.push(3u8); // Mode flag: 3 = note spend
        proof
    }
}

fn compute_prover_id(tree_depth: usize) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ghost-zkp-note-prover-v1");
    hasher.update(tree_depth.to_le_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_witness(tree_depth: usize) -> NoteSpendWitness {
        let spending_key = Fr::from(42u64);
        let note_blinding = Fr::from(111u64);
        let change_blinding = Fr::from(222u64);
        let recipient_blinding = Fr::from(333u64);

        NoteSpendWitness {
            spending_key: field_to_bytes(spending_key),
            note_value: 1000,
            note_blinding: field_to_bytes(note_blinding),
            note_index: 0,
            epoch: 1,
            merkle_siblings: vec![[0u8; 32]; tree_depth],
            amount: 300,
            change_blinding: field_to_bytes(change_blinding),
            recipient_blinding: field_to_bytes(recipient_blinding),
        }
    }

    #[test]
    fn test_prover_creation() {
        let prover = NoteProver::new(40);
        assert_eq!(prover.tree_depth(), 40);
        assert!(!prover.has_groth16_params());
    }

    #[test]
    fn test_prove_valid_spend() {
        let prover = NoteProver::new(4);
        let witness = create_test_witness(4);
        let result = prover.prove(&witness);
        assert!(result.is_ok(), "Proof should succeed: {:?}", result.err());
        let proof = result.unwrap();
        assert!(!proof.proof.is_empty());
    }

    #[test]
    fn test_prove_insufficient_funds() {
        let prover = NoteProver::new(4);
        let mut witness = create_test_witness(4);
        witness.amount = 2000; // more than note_value
        let result = prover.prove(&witness);
        assert!(result.is_err());
    }

    #[test]
    fn test_public_inputs_non_zero() {
        let prover = NoteProver::new(4);
        let witness = create_test_witness(4);
        let proof = prover.prove(&witness).unwrap();

        assert_ne!(proof.public_inputs.commitment_root, [0u8; 32]);
        assert_ne!(proof.public_inputs.nullifier, [0u8; 32]);
        assert_ne!(proof.public_inputs.change_commitment, [0u8; 32]);
        assert_ne!(proof.public_inputs.recipient_commitment, [0u8; 32]);
    }

    #[test]
    #[ignore] // Expensive ~10-30s
    fn test_groth16_prove_roundtrip() {
        let prover = NoteProver::new_with_setup(4).expect("Setup should succeed");
        assert!(prover.has_groth16_params());
        let witness = create_test_witness(4);
        let proof = prover.prove(&witness).expect("Proof should succeed");
        assert!(proof.is_real_proof());
        assert_eq!(proof.proof.len(), GROTH16_PROOF_SIZE);
    }
}
