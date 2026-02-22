//! Confidential transfer proof generation
//!
//! Generates Groth16 proofs that a confidential transfer is valid
//! without revealing the transfer amount or account balances.
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

use crate::circuit::commitment::{
    compute_note_id_native, compute_nullifier_native, pedersen_commit_native,
};
use crate::circuit::confidential_transfer::{
    compute_commitment_root_native, ConfidentialTransferCircuit,
};
use crate::circuit::mimc::field_to_bytes;
use crate::errors::{ZkError, ZkResult};
use crate::field_utils::bytes_to_field;
use crate::types::{ConfidentialPublicInputs, ConfidentialTransferWitness, GROTH16_PROOF_SIZE};

/// Generates ZK proofs for confidential transfers
pub struct ConfidentialProver {
    /// Groth16 proving parameters
    params: Option<Arc<Parameters<Bls12>>>,
    /// Prepared verifying key for efficient verification
    prepared_vk: Option<Arc<PreparedVerifyingKey<Bls12>>>,
    /// Commitment tree depth
    tree_depth: usize,
    /// Prover ID (for verification key matching)
    prover_id: [u8; 32],
}

/// Proof of a valid confidential transfer (192 bytes Groth16)
#[derive(Debug, Clone)]
pub struct ConfidentialTransferProof {
    /// Public inputs visible to validators
    pub public_inputs: ConfidentialPublicInputs,
    /// Serialized Groth16 proof bytes (192 bytes)
    pub proof: Vec<u8>,
    /// Prover ID for verification key matching
    pub prover_id: [u8; 32],
}

impl ConfidentialTransferProof {
    /// Check if this is a real Groth16 proof (192 bytes)
    pub fn is_real_proof(&self) -> bool {
        self.proof.len() == GROTH16_PROOF_SIZE
    }
}

impl ConfidentialProver {
    /// Create a new confidential prover without Groth16 parameters
    ///
    /// Parameters must be loaded separately via `new_with_params` or MPC ceremony.
    pub fn new(tree_depth: usize) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"ghost-zkp-confidential-prover-v1");
        hasher.update(tree_depth.to_le_bytes());
        let prover_id: [u8; 32] = hasher.finalize().into();

        Self {
            params: None,
            prepared_vk: None,
            tree_depth,
            prover_id,
        }
    }

    /// Create a prover with MPC-generated parameters
    pub fn new_with_params(params: Arc<Parameters<Bls12>>, tree_depth: usize) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"ghost-zkp-confidential-prover-v1");
        hasher.update(tree_depth.to_le_bytes());
        let prover_id: [u8; 32] = hasher.finalize().into();

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
            "SECURITY WARNING: Using random trusted setup for confidential transfer circuit. \
             This is INSECURE for production."
        );

        let dummy_circuit = ConfidentialTransferCircuit::<Fr>::dummy(tree_depth);
        let params =
            generate_random_parameters::<Bls12, _, _>(dummy_circuit, &mut rand::rngs::OsRng)
                .map_err(|e| {
                    ZkError::SetupError(format!("Parameter generation failed: {:?}", e))
                })?;

        let prepared_vk = prepare_verifying_key(&params.vk);

        let mut hasher = Sha256::new();
        hasher.update(b"ghost-zkp-confidential-prover-v1");
        hasher.update(tree_depth.to_le_bytes());
        let prover_id: [u8; 32] = hasher.finalize().into();

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

    /// Get the prover ID
    pub fn prover_id(&self) -> [u8; 32] {
        self.prover_id
    }

    /// Get the tree depth
    pub fn tree_depth(&self) -> usize {
        self.tree_depth
    }

    /// Get the prepared verifying key
    pub fn prepared_verifying_key(&self) -> Option<Arc<PreparedVerifyingKey<Bls12>>> {
        self.prepared_vk.clone()
    }

    /// Check if Groth16 parameters are available
    pub fn has_groth16_params(&self) -> bool {
        self.params.is_some()
    }

    /// Generate a proof for a confidential transfer
    #[instrument(skip_all)]
    pub fn prove(
        &self,
        witness: &ConfidentialTransferWitness,
    ) -> ZkResult<ConfidentialTransferProof> {
        let start = Instant::now();

        // Validate witness
        witness
            .validate()
            .map_err(|e| ZkError::InvalidWitness(e.to_string()))?;

        // Build circuit from witness
        let circuit = self.build_circuit(witness)?;
        let public_inputs = self.compute_public_inputs(witness)?;

        // Verify constraints with TestConstraintSystem first
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
            "Confidential transfer circuit satisfied with {} constraints",
            cs.num_constraints()
        );

        // Generate proof bytes
        let proof_bytes = if let Some(ref params) = self.params {
            let proving_start = Instant::now();
            let proof: Proof<Bls12> =
                create_random_proof(circuit, params.as_ref(), &mut rand::rngs::OsRng).map_err(
                    |e| ZkError::ProvingError(format!("Groth16 proving failed: {:?}", e)),
                )?;

            debug!("Groth16 proof generated in {:?}", proving_start.elapsed());

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
            "Confidential transfer proof generated in {:?}, size: {} bytes",
            start.elapsed(),
            proof_bytes.len()
        );

        Ok(ConfidentialTransferProof {
            public_inputs,
            proof: proof_bytes,
            prover_id: self.prover_id,
        })
    }

    /// Build the circuit from a witness
    fn build_circuit(
        &self,
        witness: &ConfidentialTransferWitness,
    ) -> ZkResult<ConfidentialTransferCircuit<Fr>> {
        let sender_blinding: Fr = bytes_to_field(&witness.sender_blinding)?;
        let sender_spending_key: Fr = bytes_to_field(&witness.sender_spending_key)?;
        let sender_new_blinding: Fr = bytes_to_field(&witness.sender_new_blinding)?;
        let recipient_old_blinding: Fr = bytes_to_field(&witness.recipient_old_blinding)?;
        let recipient_new_blinding: Fr = bytes_to_field(&witness.recipient_new_blinding)?;

        let sender_siblings: Vec<Option<Fr>> = witness
            .sender_merkle_proof
            .siblings
            .iter()
            .map(|s| bytes_to_field(s).ok())
            .collect();

        let recipient_siblings: Vec<Option<Fr>> = witness
            .recipient_merkle_proof
            .siblings
            .iter()
            .map(|s| bytes_to_field(s).ok())
            .collect();

        // Compute all values for public inputs
        let sender_value = Fr::from(witness.sender_value);
        let sender_new_value = Fr::from(witness.sender_value - witness.amount);
        let recipient_new_value = Fr::from(witness.recipient_old_value + witness.amount);

        let sender_commit = pedersen_commit_native(sender_value, sender_blinding);
        let sender_new_commit = pedersen_commit_native(sender_new_value, sender_new_blinding);
        let _recipient_old_commit = pedersen_commit_native(
            Fr::from(witness.recipient_old_value),
            recipient_old_blinding,
        );
        let recipient_new_commit =
            pedersen_commit_native(recipient_new_value, recipient_new_blinding);

        // Compute roots
        let sender_sibs: Vec<Fr> = sender_siblings
            .iter()
            .map(|s| s.unwrap_or(Fr::ZERO))
            .collect();
        let recipient_sibs: Vec<Fr> = recipient_siblings
            .iter()
            .map(|s| s.unwrap_or(Fr::ZERO))
            .collect();

        let old_root =
            compute_commitment_root_native(sender_commit, witness.sender_index, &sender_sibs);
        let intermediate_root =
            compute_commitment_root_native(sender_new_commit, witness.sender_index, &sender_sibs);
        let _ = intermediate_root; // used implicitly in tree update verification
        let new_root = compute_commitment_root_native(
            recipient_new_commit,
            witness.recipient_index,
            &recipient_sibs,
        );

        // Compute nullifier
        let note_id = compute_note_id_native(witness.sender_index, sender_commit);
        let nullifier = compute_nullifier_native(sender_spending_key, note_id);

        Ok(ConfidentialTransferCircuit {
            old_commitment_root: Some(old_root),
            new_commitment_root: Some(new_root),
            nullifier: Some(nullifier),
            sender_new_commitment: Some(sender_new_commit),
            recipient_new_commitment: Some(recipient_new_commit),
            sender_value: Some(witness.sender_value),
            sender_blinding: Some(sender_blinding),
            sender_spending_key: Some(sender_spending_key),
            sender_index: Some(witness.sender_index),
            sender_siblings,
            amount: Some(witness.amount),
            sender_new_blinding: Some(sender_new_blinding),
            recipient_old_value: Some(witness.recipient_old_value),
            recipient_old_blinding: Some(recipient_old_blinding),
            recipient_index: Some(witness.recipient_index),
            recipient_siblings,
            recipient_new_blinding: Some(recipient_new_blinding),
            tree_depth: self.tree_depth,
        })
    }

    /// Compute the public inputs from a witness
    fn compute_public_inputs(
        &self,
        witness: &ConfidentialTransferWitness,
    ) -> ZkResult<ConfidentialPublicInputs> {
        let sender_blinding: Fr = bytes_to_field(&witness.sender_blinding)?;
        let sender_spending_key: Fr = bytes_to_field(&witness.sender_spending_key)?;
        let sender_new_blinding: Fr = bytes_to_field(&witness.sender_new_blinding)?;
        let _recipient_old_blinding: Fr = bytes_to_field(&witness.recipient_old_blinding)?;
        let recipient_new_blinding: Fr = bytes_to_field(&witness.recipient_new_blinding)?;

        let sender_value = Fr::from(witness.sender_value);
        let sender_new_value = Fr::from(witness.sender_value - witness.amount);
        let recipient_new_value = Fr::from(witness.recipient_old_value + witness.amount);

        let sender_commit = pedersen_commit_native(sender_value, sender_blinding);
        let sender_new_commit = pedersen_commit_native(sender_new_value, sender_new_blinding);
        let recipient_new_commit =
            pedersen_commit_native(recipient_new_value, recipient_new_blinding);

        let sender_sibs: Vec<Fr> = witness
            .sender_merkle_proof
            .siblings
            .iter()
            .map(|s| bytes_to_field(s).unwrap_or(Fr::ZERO))
            .collect();
        let recipient_sibs: Vec<Fr> = witness
            .recipient_merkle_proof
            .siblings
            .iter()
            .map(|s| bytes_to_field(s).unwrap_or(Fr::ZERO))
            .collect();

        let old_root =
            compute_commitment_root_native(sender_commit, witness.sender_index, &sender_sibs);
        let new_root = compute_commitment_root_native(
            recipient_new_commit,
            witness.recipient_index,
            &recipient_sibs,
        );

        let note_id = compute_note_id_native(witness.sender_index, sender_commit);
        let nullifier = compute_nullifier_native(sender_spending_key, note_id);

        Ok(ConfidentialPublicInputs {
            old_commitment_root: field_to_bytes(old_root),
            new_commitment_root: field_to_bytes(new_root),
            nullifier: field_to_bytes(nullifier),
            sender_new_commitment: field_to_bytes(sender_new_commit),
            recipient_new_commitment: field_to_bytes(recipient_new_commit),
        })
    }

    /// Generate simulated proof for testing
    #[cfg(test)]
    fn generate_simulated_proof(
        &self,
        witness: &ConfidentialTransferWitness,
        num_constraints: usize,
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"ghost-zkp-confidential-proof-v1");
        hasher.update(self.prover_id);
        hasher.update(witness.sender_value.to_le_bytes());
        hasher.update(witness.amount.to_le_bytes());
        hasher.update(witness.recipient_old_value.to_le_bytes());
        hasher.update((num_constraints as u64).to_le_bytes());
        let hash: [u8; 32] = hasher.finalize().into();

        let mut proof = Vec::with_capacity(73);
        proof.extend_from_slice(&self.prover_id);
        proof.extend_from_slice(&hash);
        proof.extend_from_slice(&(num_constraints as u64).to_le_bytes());
        proof.push(2u8); // Mode flag: 2 = confidential transfer
        proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::mimc::field_to_bytes;
    use crate::types::MerkleProof;

    fn create_test_witness(tree_depth: usize) -> ConfidentialTransferWitness {
        let sender_blinding = Fr::from(111u64);
        let sender_new_blinding = Fr::from(222u64);
        let recipient_old_blinding = Fr::from(333u64);
        let recipient_new_blinding = Fr::from(444u64);
        let sender_spending_key = Fr::from(42u64);

        let sender_value = 1000u64;
        let amount = 300u64;
        let recipient_old_value = 500u64;

        // Compute commitments for building sibling structure
        let sender_new_commit =
            pedersen_commit_native(Fr::from(sender_value - amount), sender_new_blinding);
        let recipient_old_commit =
            pedersen_commit_native(Fr::from(recipient_old_value), recipient_old_blinding);

        // Build sibling arrays
        let mut sender_siblings = vec![[0u8; 32]; tree_depth];
        let mut recipient_siblings = vec![[0u8; 32]; tree_depth];
        sender_siblings[0] = field_to_bytes(recipient_old_commit);
        recipient_siblings[0] = field_to_bytes(sender_new_commit);

        ConfidentialTransferWitness {
            sender_value,
            sender_blinding: field_to_bytes(sender_blinding),
            sender_spending_key: field_to_bytes(sender_spending_key),
            sender_index: 0,
            sender_merkle_proof: MerkleProof::new(0, sender_siblings),
            amount,
            sender_new_blinding: field_to_bytes(sender_new_blinding),
            recipient_old_value,
            recipient_old_blinding: field_to_bytes(recipient_old_blinding),
            recipient_index: 1,
            recipient_merkle_proof: MerkleProof::new(1, recipient_siblings),
            recipient_new_blinding: field_to_bytes(recipient_new_blinding),
        }
    }

    #[test]
    fn test_prover_creation() {
        let prover = ConfidentialProver::new(20);
        assert_eq!(prover.tree_depth(), 20);
        assert!(!prover.has_groth16_params());
    }

    #[test]
    fn test_prove_valid_transfer() {
        let prover = ConfidentialProver::new(4);
        let witness = create_test_witness(4);

        let result = prover.prove(&witness);
        assert!(
            result.is_ok(),
            "Proof generation should succeed: {:?}",
            result.err()
        );

        let proof = result.unwrap();
        assert!(!proof.proof.is_empty());
    }

    #[test]
    fn test_prove_invalid_witness() {
        let prover = ConfidentialProver::new(4);
        let mut witness = create_test_witness(4);
        witness.amount = 2000; // More than sender has

        let result = prover.prove(&witness);
        assert!(result.is_err(), "Invalid witness should be rejected");
    }

    #[test]
    fn test_public_inputs_computed() {
        let prover = ConfidentialProver::new(4);
        let witness = create_test_witness(4);

        let proof = prover.prove(&witness).unwrap();

        // Public inputs should be non-zero
        assert_ne!(proof.public_inputs.old_commitment_root, [0u8; 32]);
        assert_ne!(proof.public_inputs.new_commitment_root, [0u8; 32]);
        assert_ne!(proof.public_inputs.nullifier, [0u8; 32]);
        assert_ne!(proof.public_inputs.sender_new_commitment, [0u8; 32]);
        assert_ne!(proof.public_inputs.recipient_new_commitment, [0u8; 32]);
    }
}
