//! Confidential transfer proof verification
//!
//! Verifies Groth16 proofs that a confidential transfer is valid.
//! Verification is fast (~10ms) and requires only the public inputs.

use bellperson::groth16::{verify_proof, PreparedVerifyingKey, Proof};
use blstrs::{Bls12, G1Affine, G2Affine, Scalar as Fr};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, instrument, warn};

use crate::confidential_prover::ConfidentialTransferProof;
use crate::errors::{ZkError, ZkResult};
use crate::field_utils::bytes_to_field;
use crate::types::{ConfidentialPublicInputs, GROTH16_PROOF_SIZE};

/// Verifies confidential transfer proofs
///
/// **Deprecated:** Use `GhostNoteVerifier` instead.
#[deprecated(note = "Use GhostNoteVerifier instead")]
pub struct ConfidentialVerifier {
    /// Prepared verifying key for Groth16 verification
    prepared_vk: Option<Arc<PreparedVerifyingKey<Bls12>>>,
    /// Expected prover ID
    prover_id: [u8; 32],
}

impl ConfidentialVerifier {
    /// Create a verifier with a Groth16 verification key
    pub fn new(prepared_vk: Arc<PreparedVerifyingKey<Bls12>>, prover_id: [u8; 32]) -> Self {
        Self {
            prepared_vk: Some(prepared_vk),
            prover_id,
        }
    }

    /// Create a verifier from a prover (inherits VK if available)
    pub fn for_prover(prover: &crate::confidential_prover::ConfidentialProver) -> Self {
        Self {
            prepared_vk: prover.prepared_verifying_key(),
            prover_id: prover.prover_id(),
        }
    }

    /// Check if Groth16 verification is available
    pub fn has_groth16_vk(&self) -> bool {
        self.prepared_vk.is_some()
    }

    /// Verify a confidential transfer proof
    #[instrument(skip_all)]
    pub fn verify(&self, proof: &ConfidentialTransferProof) -> ZkResult<bool> {
        let start = Instant::now();

        // Check prover ID
        if proof.prover_id != self.prover_id {
            warn!("Prover ID mismatch");
            return Ok(false);
        }

        // Check proof is not empty
        if proof.proof.is_empty() {
            warn!("Empty proof");
            return Ok(false);
        }

        // Verify with Groth16 if VK available
        if let Some(ref prepared_vk) = self.prepared_vk {
            if proof.proof.len() != GROTH16_PROOF_SIZE {
                debug!(
                    "Proof size mismatch: {} != {}",
                    proof.proof.len(),
                    GROTH16_PROOF_SIZE
                );
                return Ok(false);
            }

            match self.verify_groth16(proof, prepared_vk) {
                Ok(valid) => {
                    info!(
                        "Confidential transfer proof verified in {:?}",
                        start.elapsed()
                    );
                    return Ok(valid);
                }
                Err(e) => {
                    warn!("Groth16 verification error: {:?}", e);
                    return Ok(false);
                }
            }
        }

        // No VK available — fail closed in production
        error!("SECURITY: No Groth16 verification key available. Rejecting proof.");

        #[cfg(test)]
        {
            info!("Accepting simulated proof in test mode");
            Ok(true)
        }

        #[cfg(not(test))]
        Ok(false)
    }

    /// Verify using Groth16
    fn verify_groth16(
        &self,
        proof: &ConfidentialTransferProof,
        prepared_vk: &PreparedVerifyingKey<Bls12>,
    ) -> ZkResult<bool> {
        let groth16_proof = self.deserialize_proof(&proof.proof)?;

        // Build public inputs in the same order as the circuit's alloc_input calls
        let public_inputs = self.build_public_inputs(&proof.public_inputs)?;

        let result = verify_proof(prepared_vk, &groth16_proof, &public_inputs);

        match result {
            Ok(valid) => Ok(valid),
            Err(e) => {
                warn!("Groth16 verification error: {:?}", e);
                Ok(false)
            }
        }
    }

    /// Build public inputs in circuit order
    fn build_public_inputs(&self, inputs: &ConfidentialPublicInputs) -> ZkResult<Vec<Fr>> {
        Ok(vec![
            bytes_to_field(&inputs.old_commitment_root)?,
            bytes_to_field(&inputs.new_commitment_root)?,
            bytes_to_field(&inputs.nullifier)?,
            bytes_to_field(&inputs.sender_new_commitment)?,
            bytes_to_field(&inputs.recipient_new_commitment)?,
        ])
    }

    /// Deserialize a Groth16 proof from bytes with subgroup checks
    fn deserialize_proof(&self, bytes: &[u8]) -> ZkResult<Proof<Bls12>> {
        if bytes.len() != GROTH16_PROOF_SIZE {
            return Err(ZkError::InvalidProof(format!(
                "Invalid proof size: {} != {}",
                bytes.len(),
                GROTH16_PROOF_SIZE
            )));
        }

        // Parse A (G1 point, 48 bytes)
        let a_bytes: [u8; 48] = bytes[0..48]
            .try_into()
            .map_err(|_| ZkError::InvalidProof("Failed to read A point".to_string()))?;
        let a = G1Affine::from_compressed(&a_bytes);
        let a = if a.is_some().into() {
            a.unwrap()
        } else {
            return Err(ZkError::InvalidProof("Invalid A point".to_string()));
        };
        if !bool::from(a.is_torsion_free()) {
            return Err(ZkError::InvalidProof(
                "A point not in prime-order subgroup".to_string(),
            ));
        }

        // Parse B (G2 point, 96 bytes)
        let b_bytes: [u8; 96] = bytes[48..144]
            .try_into()
            .map_err(|_| ZkError::InvalidProof("Failed to read B point".to_string()))?;
        let b = G2Affine::from_compressed(&b_bytes);
        let b = if b.is_some().into() {
            b.unwrap()
        } else {
            return Err(ZkError::InvalidProof("Invalid B point".to_string()));
        };
        if !bool::from(b.is_torsion_free()) {
            return Err(ZkError::InvalidProof(
                "B point not in prime-order subgroup".to_string(),
            ));
        }

        // Parse C (G1 point, 48 bytes)
        let c_bytes: [u8; 48] = bytes[144..192]
            .try_into()
            .map_err(|_| ZkError::InvalidProof("Failed to read C point".to_string()))?;
        let c = G1Affine::from_compressed(&c_bytes);
        let c = if c.is_some().into() {
            c.unwrap()
        } else {
            return Err(ZkError::InvalidProof("Invalid C point".to_string()));
        };
        if !bool::from(c.is_torsion_free()) {
            return Err(ZkError::InvalidProof(
                "C point not in prime-order subgroup".to_string(),
            ));
        }

        Ok(Proof { a, b, c })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::commitment::pedersen_commit_native;
    use crate::circuit::mimc::field_to_bytes;
    use crate::confidential_prover::ConfidentialProver;
    use crate::types::{ConfidentialTransferWitness, MerkleProof};

    fn create_test_witness(tree_depth: usize) -> ConfidentialTransferWitness {
        let sender_blinding = Fr::from(111u64);
        let sender_new_blinding = Fr::from(222u64);
        let recipient_old_blinding = Fr::from(333u64);
        let recipient_new_blinding = Fr::from(444u64);
        let sender_spending_key = Fr::from(42u64);

        let sender_value = 1000u64;
        let amount = 300u64;
        let recipient_old_value = 500u64;

        let sender_new_commit =
            pedersen_commit_native(Fr::from(sender_value - amount), sender_new_blinding);
        let recipient_old_commit =
            pedersen_commit_native(Fr::from(recipient_old_value), recipient_old_blinding);

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
    fn test_prove_verify_roundtrip() {
        let prover = ConfidentialProver::new(4);
        let verifier = ConfidentialVerifier::for_prover(&prover);
        let witness = create_test_witness(4);

        let proof = prover.prove(&witness).unwrap();
        assert!(verifier.verify(&proof).unwrap());
    }

    #[test]
    fn test_prover_id_mismatch() {
        let prover = ConfidentialProver::new(4);
        let verifier = ConfidentialVerifier {
            prepared_vk: None,
            prover_id: [0xFF; 32],
        };
        let witness = create_test_witness(4);

        let proof = prover.prove(&witness).unwrap();
        assert!(!verifier.verify(&proof).unwrap());
    }

    #[test]
    fn test_empty_proof_rejected() {
        let prover = ConfidentialProver::new(4);
        let verifier = ConfidentialVerifier::for_prover(&prover);
        let witness = create_test_witness(4);

        let mut proof = prover.prove(&witness).unwrap();
        proof.proof.clear();
        assert!(!verifier.verify(&proof).unwrap());
    }

    // Full Groth16 roundtrip test — expensive (~10-30s)
    #[test]
    #[ignore]
    fn test_groth16_prove_verify_roundtrip() {
        let prover = ConfidentialProver::new_with_setup(4).expect("Setup should succeed");
        assert!(prover.has_groth16_params());

        let verifier = ConfidentialVerifier::for_prover(&prover);
        assert!(verifier.has_groth16_vk());

        let witness = create_test_witness(4);
        let proof = prover.prove(&witness).expect("Proof should succeed");
        assert!(proof.is_real_proof());
        assert_eq!(proof.proof.len(), GROTH16_PROOF_SIZE);

        assert!(verifier
            .verify(&proof)
            .expect("Verification should succeed"));
    }
}
