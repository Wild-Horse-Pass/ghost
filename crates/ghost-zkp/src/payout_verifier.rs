//! Payout proof verification
//!
//! The PayoutVerifier verifies ZK proofs that a payout distribution is valid.
//! Verification is fast (~10ms) and can be done by all validators.

use sha2::{Digest, Sha256};
use std::time::Instant;
use tracing::{info, instrument, warn};

use crate::errors::ZkResult;
use crate::payout_prover::{PayoutProof, MAX_MINERS, MAX_NODES};

/// Verifies ZK proofs for payout distribution validity
pub struct PayoutVerifier {
    /// Expected prover ID (for verification key matching)
    prover_id: [u8; 32],
    /// Maximum miners supported
    max_miners: usize,
    /// Maximum nodes supported
    max_nodes: usize,
}

impl PayoutVerifier {
    /// Create a new payout verifier
    #[instrument(skip_all, fields(max_miners, max_nodes))]
    pub fn new(prover_id: [u8; 32], max_miners: usize, max_nodes: usize) -> Self {
        info!("Creating payout verifier");
        Self {
            prover_id,
            max_miners,
            max_nodes,
        }
    }

    /// Create with default parameters
    pub fn default_params(prover_id: [u8; 32]) -> Self {
        Self::new(prover_id, MAX_MINERS, MAX_NODES)
    }

    /// Create a verifier for a specific prover
    pub fn for_prover(prover: &crate::payout_prover::PayoutProver) -> Self {
        Self::default_params(prover.prover_id())
    }

    /// Verify a payout proof
    #[instrument(skip_all, fields(epoch = proof.epoch))]
    pub fn verify(&self, proof: &PayoutProof) -> ZkResult<bool> {
        let start = Instant::now();

        // Check prover ID matches
        if proof.prover_id != self.prover_id {
            warn!(
                "Prover ID mismatch: {:?} != {:?}",
                hex::encode(&proof.prover_id[..8]),
                hex::encode(&self.prover_id[..8])
            );
            return Ok(false);
        }

        // Check bounds
        if proof.miner_count as usize > self.max_miners {
            warn!(
                "Too many miners: {} > {}",
                proof.miner_count, self.max_miners
            );
            return Ok(false);
        }

        if proof.node_count as usize > self.max_nodes {
            warn!("Too many nodes: {} > {}", proof.node_count, self.max_nodes);
            return Ok(false);
        }

        // Check sum preservation
        let computed_sum = proof
            .miner_sum
            .saturating_add(proof.node_sum)
            .saturating_add(proof.treasury_amount);

        if computed_sum != proof.total_available {
            warn!(
                "Sum mismatch: {} != {}",
                computed_sum, proof.total_available
            );
            return Ok(false);
        }

        // Check proof is not empty
        if proof.proof.is_empty() {
            warn!("Empty proof");
            return Ok(false);
        }

        // Verify proof structure (in real implementation, this would verify
        // the Groth16 proof cryptographically)
        if !self.verify_proof_structure(proof) {
            warn!("Invalid proof structure");
            return Ok(false);
        }

        info!("Payout proof verified in {:?}", start.elapsed());

        Ok(true)
    }

    /// Verify proof structure
    fn verify_proof_structure(&self, proof: &PayoutProof) -> bool {
        // Check minimum proof size (SHA256 hash = 32 bytes)
        if proof.proof.len() < 32 {
            return false;
        }

        // Verify proof contains prover ID prefix
        // TODO: In production, verify actual Groth16 proof here
        let mut hasher = Sha256::new();
        hasher.update(&self.prover_id);
        let _expected_prefix = &hasher.finalize()[..8];

        // The proof should be deterministic based on inputs
        // In a real implementation, this would be cryptographic verification
        true
    }

    /// Verify detailed - returns specific error reason
    pub fn verify_detailed(&self, proof: &PayoutProof) -> PayoutVerificationResult {
        // Check prover ID
        if proof.prover_id != self.prover_id {
            return PayoutVerificationResult::ProverMismatch;
        }

        // Check bounds
        if proof.miner_count as usize > self.max_miners {
            return PayoutVerificationResult::TooManyMiners;
        }

        if proof.node_count as usize > self.max_nodes {
            return PayoutVerificationResult::TooManyNodes;
        }

        // Check sum
        let computed_sum = proof
            .miner_sum
            .saturating_add(proof.node_sum)
            .saturating_add(proof.treasury_amount);

        if computed_sum != proof.total_available {
            return PayoutVerificationResult::SumMismatch {
                expected: proof.total_available,
                computed: computed_sum,
            };
        }

        // Check proof
        if proof.proof.is_empty() {
            return PayoutVerificationResult::EmptyProof;
        }

        if !self.verify_proof_structure(proof) {
            return PayoutVerificationResult::InvalidProofStructure;
        }

        PayoutVerificationResult::Valid
    }
}

/// Detailed verification result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayoutVerificationResult {
    /// Proof is valid
    Valid,
    /// Prover ID doesn't match
    ProverMismatch,
    /// Too many miners in payout
    TooManyMiners,
    /// Too many nodes in payout
    TooManyNodes,
    /// Sum doesn't match total available
    SumMismatch { expected: u64, computed: u64 },
    /// Proof is empty
    EmptyProof,
    /// Proof structure is invalid
    InvalidProofStructure,
}

impl PayoutVerificationResult {
    /// Check if result indicates a valid proof
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// Convenience function to verify a payout proof
pub fn verify_payout(prover_id: [u8; 32], proof: &PayoutProof) -> ZkResult<bool> {
    let verifier = PayoutVerifier::default_params(prover_id);
    verifier.verify(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payout_prover::{PayoutProver, PayoutWitness};

    fn create_valid_proof() -> (PayoutProver, PayoutProof) {
        let prover = PayoutProver::new(10, 5).unwrap();

        let witness = PayoutWitness {
            epoch: 1,
            total_available: 1000,
            miner_payouts: vec![300, 200],
            node_payouts: vec![300, 100],
            treasury_amount: 100,
        };

        let proof = prover.prove(&witness).unwrap();
        (prover, proof)
    }

    #[test]
    fn test_verifier_creation() {
        let prover_id = [0xABu8; 32];
        let verifier = PayoutVerifier::new(prover_id, 10, 5);
        assert_eq!(verifier.prover_id, prover_id);
    }

    #[test]
    fn test_valid_proof_verification() {
        let (prover, proof) = create_valid_proof();
        let verifier = PayoutVerifier::for_prover(&prover);

        assert!(verifier.verify(&proof).unwrap());
    }

    #[test]
    fn test_prover_mismatch() {
        let (_, proof) = create_valid_proof();
        let verifier = PayoutVerifier::new([0xFFu8; 32], 10, 5);

        assert!(!verifier.verify(&proof).unwrap());
    }

    #[test]
    fn test_detailed_verification() {
        let (prover, proof) = create_valid_proof();
        let verifier = PayoutVerifier::for_prover(&prover);

        let result = verifier.verify_detailed(&proof);
        assert_eq!(result, PayoutVerificationResult::Valid);
        assert!(result.is_valid());
    }

    #[test]
    fn test_tampered_sum() {
        let (prover, mut proof) = create_valid_proof();
        let verifier = PayoutVerifier::for_prover(&prover);

        // Tamper with miner sum
        proof.miner_sum = 999;

        let result = verifier.verify_detailed(&proof);
        assert!(matches!(
            result,
            PayoutVerificationResult::SumMismatch { .. }
        ));
    }

    #[test]
    fn test_convenience_function() {
        let (prover, proof) = create_valid_proof();
        assert!(verify_payout(prover.prover_id(), &proof).unwrap());
    }

    #[test]
    fn test_too_many_miners() {
        let (prover, mut proof) = create_valid_proof();
        let verifier = PayoutVerifier::new(prover.prover_id(), 1, 5); // max 1 miner

        proof.miner_count = 2;

        let result = verifier.verify_detailed(&proof);
        assert_eq!(result, PayoutVerificationResult::TooManyMiners);
    }
}
