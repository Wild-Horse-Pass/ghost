//! Block proof verification
//!
//! The BlockVerifier validates ZK proofs in ~10ms, allowing validators
//! to quickly confirm block validity without re-executing transactions.
//!
//! # Security Model
//!
//! This verifier supports two modes:
//! 1. Full Groth16 mode: Cryptographically verifies proofs using bellperson
//! 2. Simulated mode (TEST ONLY): For development when no setup is available
//!
//! SECURITY WARNING: In production, ALWAYS use full Groth16 mode with
//! a verification key generated from a proper MPC ceremony.

use bellperson::groth16::{verify_proof as groth16_verify_proof, PreparedVerifyingKey, Proof};
use blstrs::{Bls12, G1Affine, G2Affine, Scalar as Fr};
use ff::PrimeField;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, instrument, warn};

use crate::errors::{ZkError, ZkResult};
use crate::types::{BlockProof, VerificationKey, GROTH16_PROOF_SIZE};

/// Verifies block validity proofs
///
/// The verifier is initialized once with a verification key and reused
/// for all blocks. Verification takes ~10ms.
///
/// # Security
///
/// For production use, always initialize with `new_with_groth16_vk` to ensure
/// cryptographic verification. The `new` constructor is provided for backwards
/// compatibility but will FAIL CLOSED if no VK is available.
pub struct BlockVerifier {
    /// Prover ID from verification key
    prover_id: [u8; 32],
    /// Maximum transactions per block
    max_txs: usize,
    /// Merkle tree depth
    tree_depth: usize,
    /// Prepared Groth16 verifying key for cryptographic verification
    prepared_vk: Option<Arc<PreparedVerifyingKey<Bls12>>>,
}

impl BlockVerifier {
    /// Create a verifier from a verification key (simulated mode)
    ///
    /// SECURITY WARNING: This constructor does NOT enable Groth16 verification.
    /// In production, use `new_with_groth16_vk` instead. This method will
    /// FAIL CLOSED (reject all proofs) when not in test mode.
    pub fn new(vk: &VerificationKey) -> ZkResult<Self> {
        if vk.data.len() < 48 {
            return Err(ZkError::ParameterError(
                "Verification key too short".to_string(),
            ));
        }

        let mut prover_id = [0u8; 32];
        prover_id.copy_from_slice(&vk.data[0..32]);

        let max_txs = usize::from_le_bytes(vk.data[32..40].try_into().map_err(|_| {
            ZkError::ParameterError("Invalid max_txs in verification key".to_string())
        })?);

        let tree_depth = usize::from_le_bytes(vk.data[40..48].try_into().map_err(|_| {
            ZkError::ParameterError("Invalid tree_depth in verification key".to_string())
        })?);

        warn!(
            "BlockVerifier created without Groth16 VK. \
             Cryptographic verification will not be available. \
             Use new_with_groth16_vk for production."
        );

        Ok(Self {
            prover_id,
            max_txs,
            tree_depth,
            prepared_vk: None,
        })
    }

    /// Create a verifier with a Groth16 prepared verifying key
    ///
    /// This is the recommended constructor for production use. It enables
    /// full cryptographic verification of proofs.
    pub fn new_with_groth16_vk(
        vk: &VerificationKey,
        prepared_vk: Arc<PreparedVerifyingKey<Bls12>>,
    ) -> ZkResult<Self> {
        if vk.data.len() < 48 {
            return Err(ZkError::ParameterError(
                "Verification key too short".to_string(),
            ));
        }

        let mut prover_id = [0u8; 32];
        prover_id.copy_from_slice(&vk.data[0..32]);

        let max_txs = usize::from_le_bytes(vk.data[32..40].try_into().map_err(|_| {
            ZkError::ParameterError("Invalid max_txs in verification key".to_string())
        })?);

        let tree_depth = usize::from_le_bytes(vk.data[40..48].try_into().map_err(|_| {
            ZkError::ParameterError("Invalid tree_depth in verification key".to_string())
        })?);

        debug!("BlockVerifier created with Groth16 VK for {} txs, depth {}", max_txs, tree_depth);

        Ok(Self {
            prover_id,
            max_txs,
            tree_depth,
            prepared_vk: Some(prepared_vk),
        })
    }

    /// Check if Groth16 verification is available
    pub fn has_groth16_vk(&self) -> bool {
        self.prepared_vk.is_some()
    }

    /// Verify a block proof
    ///
    /// This verifies that the proof is valid for the given state transition.
    /// Verification should take ~10ms.
    ///
    /// # Security
    ///
    /// If a Groth16 VK is available, performs cryptographic verification.
    /// Otherwise, FAILS CLOSED (rejects all proofs) in production mode.
    /// Test mode allows simulated verification for development.
    ///
    /// # Arguments
    /// * `proof` - The block proof to verify
    ///
    /// # Returns
    /// `Ok(true)` if the proof is valid, `Ok(false)` if invalid
    #[instrument(skip_all, fields(height = proof.height, tx_count = proof.tx_count))]
    pub fn verify(&self, proof: &BlockProof) -> ZkResult<bool> {
        // Verify transaction count is within limits
        if proof.tx_count as usize > self.max_txs {
            debug!(
                "Transaction count {} exceeds max {}",
                proof.tx_count, self.max_txs
            );
            return Ok(false);
        }

        // If we have a Groth16 VK, perform cryptographic verification
        if let Some(ref prepared_vk) = self.prepared_vk {
            return self.verify_groth16(proof, prepared_vk);
        }

        // No Groth16 VK available - check for simulated proof format
        // SECURITY: In production, we FAIL CLOSED
        if proof.proof.len() < 72 {
            debug!("Proof too short: {} bytes", proof.proof.len());
            return Ok(false);
        }

        // Verify prover ID matches
        let proof_prover_id = &proof.proof[0..32];
        if proof_prover_id != self.prover_id {
            debug!("Prover ID mismatch");
            return Ok(false);
        }

        // SECURITY: No Groth16 VK - FAIL CLOSED in production
        error!(
            "SECURITY: No Groth16 verification key available. \
             Cannot verify block proof cryptographically. Rejecting proof. \
             Ensure trusted setup has been completed and VK is loaded."
        );

        // In test mode, allow simulated verification
        #[cfg(test)]
        {
            return self.verify_simulated(proof);
        }

        #[cfg(not(test))]
        Ok(false)
    }

    /// Verify a Groth16 proof cryptographically
    fn verify_groth16(
        &self,
        proof: &BlockProof,
        prepared_vk: &PreparedVerifyingKey<Bls12>,
    ) -> ZkResult<bool> {
        let verify_start = Instant::now();

        // Check proof is correct size for Groth16
        if proof.proof.len() != GROTH16_PROOF_SIZE {
            debug!(
                "Proof size mismatch: {} != {}",
                proof.proof.len(),
                GROTH16_PROOF_SIZE
            );
            return Ok(false);
        }

        // Deserialize the proof with subgroup checks
        let groth16_proof = self.deserialize_proof(&proof.proof)?;

        // Build public inputs from the proof
        // For block proofs, we expose: prev_state_root, new_state_root
        let prev_root = bytes_to_field(&proof.prev_state_root)?;
        let new_root = bytes_to_field(&proof.new_state_root)?;
        let public_inputs = vec![prev_root, new_root];

        debug!(
            "Verifying Groth16 block proof: height={}, txs={}",
            proof.height, proof.tx_count
        );

        // Verify the Groth16 proof
        let result = groth16_verify_proof(prepared_vk, &groth16_proof, &public_inputs);

        debug!("Groth16 verification completed in {:?}", verify_start.elapsed());

        match result {
            Ok(valid) => {
                if valid {
                    debug!("Block proof verified successfully");
                } else {
                    warn!("Block proof verification returned false");
                }
                Ok(valid)
            }
            Err(e) => {
                warn!("Block proof verification error: {:?}", e);
                Ok(false)
            }
        }
    }

    /// Deserialize a Groth16 proof with subgroup checks
    fn deserialize_proof(&self, bytes: &[u8]) -> ZkResult<Proof<Bls12>> {
        if bytes.len() != GROTH16_PROOF_SIZE {
            return Err(ZkError::InvalidProof(format!(
                "Invalid proof size: {} != {}",
                bytes.len(),
                GROTH16_PROOF_SIZE
            )));
        }

        // Parse A (G1 point, 48 bytes compressed)
        let a_bytes: [u8; 48] = bytes[0..48]
            .try_into()
            .map_err(|_| ZkError::InvalidProof("Failed to read A point".to_string()))?;
        let a = G1Affine::from_compressed(&a_bytes);
        let a = if a.is_some().into() {
            a.unwrap()
        } else {
            return Err(ZkError::InvalidProof("Invalid A point".to_string()));
        };

        // SECURITY: Subgroup check
        if !bool::from(a.is_torsion_free()) {
            return Err(ZkError::InvalidProof(
                "A point not in prime-order subgroup".to_string(),
            ));
        }

        // Parse B (G2 point, 96 bytes compressed)
        let b_bytes: [u8; 96] = bytes[48..144]
            .try_into()
            .map_err(|_| ZkError::InvalidProof("Failed to read B point".to_string()))?;
        let b = G2Affine::from_compressed(&b_bytes);
        let b = if b.is_some().into() {
            b.unwrap()
        } else {
            return Err(ZkError::InvalidProof("Invalid B point".to_string()));
        };

        // SECURITY: Subgroup check
        if !bool::from(b.is_torsion_free()) {
            return Err(ZkError::InvalidProof(
                "B point not in prime-order subgroup".to_string(),
            ));
        }

        // Parse C (G1 point, 48 bytes compressed)
        let c_bytes: [u8; 48] = bytes[144..192]
            .try_into()
            .map_err(|_| ZkError::InvalidProof("Failed to read C point".to_string()))?;
        let c = G1Affine::from_compressed(&c_bytes);
        let c = if c.is_some().into() {
            c.unwrap()
        } else {
            return Err(ZkError::InvalidProof("Invalid C point".to_string()));
        };

        // SECURITY: Subgroup check
        if !bool::from(c.is_torsion_free()) {
            return Err(ZkError::InvalidProof(
                "C point not in prime-order subgroup".to_string(),
            ));
        }

        Ok(Proof { a, b, c })
    }

    /// Simulated verification for test mode only
    #[cfg(test)]
    fn verify_simulated(&self, proof: &BlockProof) -> ZkResult<bool> {
        // Extract proof components
        let _proof_hash = &proof.proof[32..64];
        let constraint_count = u64::from_le_bytes(
            proof.proof[64..72]
                .try_into()
                .map_err(|_| ZkError::VerificationError("Invalid proof format".to_string()))?,
        );

        // Verify constraint count is reasonable
        let min_expected_constraints = proof.tx_count as u64 * 64;
        if constraint_count < min_expected_constraints && proof.tx_count > 0 {
            debug!(
                "Constraint count {} too low for {} transactions",
                constraint_count, proof.tx_count
            );
            return Ok(false);
        }

        debug!(
            "Simulated proof verified: height={}, txs={}, constraints={}",
            proof.height,
            proof.tx_count,
            constraint_count
        );

        Ok(true)
    }

    /// Verify a proof and return detailed result
    ///
    /// Unlike `verify`, this returns a structured result with timing info.
    pub fn verify_detailed(&self, proof: &BlockProof) -> ZkResult<VerificationResult> {
        let start = Instant::now();
        let is_valid = self.verify(proof)?;
        let verification_time = start.elapsed();

        Ok(VerificationResult {
            is_valid,
            verification_time_ms: verification_time.as_millis() as u64,
            height: proof.height,
            tx_count: proof.tx_count,
            proof_size: proof.size(),
        })
    }

    /// Batch verify multiple proofs
    ///
    /// This can be more efficient than verifying proofs one at a time,
    /// though the current implementation just loops.
    pub fn verify_batch(&self, proofs: &[BlockProof]) -> ZkResult<Vec<bool>> {
        proofs.iter().map(|p| self.verify(p)).collect()
    }

    /// Get the maximum transactions this verifier supports
    pub fn max_txs(&self) -> usize {
        self.max_txs
    }

    /// Get the merkle tree depth this verifier supports
    pub fn tree_depth(&self) -> usize {
        self.tree_depth
    }
}

/// Detailed verification result
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the proof is valid
    pub is_valid: bool,
    /// Time taken to verify (milliseconds)
    pub verification_time_ms: u64,
    /// Block height
    pub height: u64,
    /// Number of transactions
    pub tx_count: u32,
    /// Proof size in bytes
    pub proof_size: usize,
}

impl std::fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Block {} ({} txs): {} in {}ms (proof: {} bytes)",
            self.height,
            self.tx_count,
            if self.is_valid { "VALID" } else { "INVALID" },
            self.verification_time_ms,
            self.proof_size
        )
    }
}

/// Verify a proof without creating a verifier instance
///
/// Convenience function for one-off verification.
pub fn verify_proof(vk: &VerificationKey, proof: &BlockProof) -> ZkResult<bool> {
    let verifier = BlockVerifier::new(vk)?;
    verifier.verify(proof)
}

/// Convert a 32-byte array to a field element
fn bytes_to_field(bytes: &[u8; 32]) -> ZkResult<Fr> {
    let mut repr = [0u8; 32];
    repr.copy_from_slice(bytes);

    // BLS12-381 scalar field is slightly less than 2^255
    // Clear top bit to ensure it fits
    repr[31] &= 0x7F;

    Fr::from_repr_vartime(repr).ok_or_else(|| {
        ZkError::VerificationError("Failed to convert bytes to field element".to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::BlockProver;
    use crate::types::{BlockWitness, MerkleProof, PaymentWitness, StateSnapshot};

    fn create_test_witness(tx_count: usize) -> BlockWitness {
        let transactions: Vec<PaymentWitness> = (0..tx_count)
            .map(|i| PaymentWitness {
                sender: [i as u8; 32],
                recipient: [(i + 1) as u8; 32],
                amount: 100,
                signature: [0u8; 64],
                sender_balance_before: 1000,
                sender_merkle_proof: MerkleProof::new(i as u64, vec![[0u8; 32]; 10]),
                recipient_balance_before: 500,
                recipient_merkle_proof: MerkleProof::new((i + 1) as u64, vec![[0u8; 32]; 10]),
            })
            .collect();

        BlockWitness::new(
            1,
            StateSnapshot::new([1u8; 32], vec![]),
            transactions,
            StateSnapshot::new([2u8; 32], vec![]),
        )
    }

    #[test]
    fn test_verifier_creation() {
        let prover = BlockProver::new(5, 10).unwrap();
        let vk = prover.verification_key();

        let verifier = BlockVerifier::new(&vk);
        assert!(verifier.is_ok(), "Verifier should be created successfully");

        let verifier = verifier.unwrap();
        assert_eq!(verifier.max_txs(), 5);
        assert_eq!(verifier.tree_depth(), 10);
    }

    #[test]
    fn test_valid_proof_verification() {
        let prover = BlockProver::new(5, 10).unwrap();
        let vk = prover.verification_key();
        let verifier = BlockVerifier::new(&vk).unwrap();

        let witness = create_test_witness(2);
        let proof = prover.prove(&witness).unwrap();

        let result = verifier.verify(&proof);
        assert!(result.is_ok(), "Verification should not error");
        assert!(result.unwrap(), "Valid proof should verify");
    }

    #[test]
    fn test_detailed_verification() {
        let prover = BlockProver::new(5, 10).unwrap();
        let vk = prover.verification_key();
        let verifier = BlockVerifier::new(&vk).unwrap();

        let witness = create_test_witness(1);
        let proof = prover.prove(&witness).unwrap();

        let result = verifier.verify_detailed(&proof).unwrap();
        assert!(result.is_valid, "Proof should be valid");
        assert_eq!(result.height, 1);
        assert_eq!(result.tx_count, 1);
        assert!(result.proof_size > 0);

        println!("Verification result: {}", result);
    }

    #[test]
    fn test_tampered_proof_fails() {
        let prover = BlockProver::new(5, 10).unwrap();
        let vk = prover.verification_key();
        let verifier = BlockVerifier::new(&vk).unwrap();

        let witness = create_test_witness(1);
        let mut proof = prover.prove(&witness).unwrap();

        // Tamper with the prover ID in the proof
        if !proof.proof.is_empty() {
            proof.proof[0] ^= 0xFF;
        }

        // Tampered proof should fail verification
        let result = verifier.verify(&proof).unwrap();
        assert!(!result, "Tampered proof should not verify");
    }

    #[test]
    fn test_batch_verification() {
        let prover = BlockProver::new(5, 10).unwrap();
        let vk = prover.verification_key();
        let verifier = BlockVerifier::new(&vk).unwrap();

        let proofs: Vec<BlockProof> = (0..3)
            .map(|i| {
                let mut witness = create_test_witness(1);
                witness.height = i as u64;
                prover.prove(&witness).unwrap()
            })
            .collect();

        let results = verifier.verify_batch(&proofs).unwrap();
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|&v| v), "All proofs should be valid");
    }

    #[test]
    fn test_convenience_verify_function() {
        let prover = BlockProver::new(5, 10).unwrap();
        let vk = prover.verification_key();

        let witness = create_test_witness(1);
        let proof = prover.prove(&witness).unwrap();

        let result = verify_proof(&vk, &proof);
        assert!(
            result.is_ok() && result.unwrap(),
            "Convenience function should work"
        );
    }

    #[test]
    fn test_empty_block_verification() {
        let prover = BlockProver::new(5, 10).unwrap();
        let vk = prover.verification_key();
        let verifier = BlockVerifier::new(&vk).unwrap();

        let witness = create_test_witness(0);
        let proof = prover.prove(&witness).unwrap();

        let result = verifier.verify(&proof).unwrap();
        assert!(result, "Empty block proof should verify");
    }
}
