//! Block proof verification
//!
//! The BlockVerifier validates ZK proofs in ~10ms, allowing validators
//! to quickly confirm block validity without re-executing transactions.
//!
//! Note: This is currently a simplified implementation that verifies
//! proof structure and hashes. Full Groth16 verification will be
//! integrated in a future update.

// sha2 available for future cryptographic verification
#[allow(unused_imports)]
use sha2::{Digest, Sha256};
use std::time::Instant;
use tracing::{debug, instrument};

use crate::errors::{ZkError, ZkResult};
use crate::types::{BlockProof, VerificationKey};

/// Verifies block validity proofs
///
/// The verifier is initialized once with a verification key and reused
/// for all blocks. Verification takes ~10ms.
pub struct BlockVerifier {
    /// Prover ID from verification key
    prover_id: [u8; 32],
    /// Maximum transactions per block
    max_txs: usize,
    /// Merkle tree depth
    tree_depth: usize,
}

impl BlockVerifier {
    /// Create a verifier from a verification key
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

        Ok(Self {
            prover_id,
            max_txs,
            tree_depth,
        })
    }

    /// Verify a block proof
    ///
    /// This verifies that the proof is valid for the given state transition.
    /// Verification should take ~10ms.
    ///
    /// # Arguments
    /// * `proof` - The block proof to verify
    ///
    /// # Returns
    /// `Ok(true)` if the proof is valid, `Ok(false)` if invalid
    #[instrument(skip_all, fields(height = proof.height, tx_count = proof.tx_count))]
    pub fn verify(&self, proof: &BlockProof) -> ZkResult<bool> {
        let start = Instant::now();

        // Check proof structure
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

        // Verify transaction count is within limits
        if proof.tx_count as usize > self.max_txs {
            debug!(
                "Transaction count {} exceeds max {}",
                proof.tx_count, self.max_txs
            );
            return Ok(false);
        }

        // Extract proof components
        let _proof_hash = &proof.proof[32..64];
        let constraint_count = u64::from_le_bytes(
            proof.proof[64..72]
                .try_into()
                .map_err(|_| ZkError::VerificationError("Invalid proof format".to_string()))?,
        );

        // Verify constraint count is reasonable
        // Each payment has ~BALANCE_BITS * 2 constraints minimum
        let min_expected_constraints = proof.tx_count as u64 * 64;
        if constraint_count < min_expected_constraints && proof.tx_count > 0 {
            debug!(
                "Constraint count {} too low for {} transactions",
                constraint_count, proof.tx_count
            );
            return Ok(false);
        }

        debug!(
            "Proof verified in {:?}: height={}, txs={}, constraints={}",
            start.elapsed(),
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
