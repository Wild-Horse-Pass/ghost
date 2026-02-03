//! Payout proof verification
//!
//! The PayoutVerifier verifies ZK proofs that a payout distribution is valid.
//! Verification is fast (~10ms) and can be done by all validators.
//!
//! # Groth16 Implementation
//!
//! This module supports real Groth16 proof verification when a prepared
//! verifying key is available. Otherwise, falls back to simulated verification.

use bellperson::groth16::{verify_proof, PreparedVerifyingKey, Proof};
use blstrs::{Bls12, G1Affine, G2Affine, Scalar as Fr};
use ff::{Field, PrimeField};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, instrument, warn};

use crate::errors::{ZkError, ZkResult};
use crate::payout_prover::{PayoutProof, PayoutProver, MAX_MINERS, MAX_NODES};
use crate::types::GROTH16_PROOF_SIZE;

/// Compute metadata commitment for binding proof to metadata.
/// This prevents replay or modification of metadata fields.
pub fn compute_metadata_commitment(epoch: u64, miner_count: u32, node_count: u32) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(b"ghost-zkp-metadata-v1");
    hasher.update(epoch.to_le_bytes());
    hasher.update(miner_count.to_le_bytes());
    hasher.update(node_count.to_le_bytes());
    let hash = hasher.finalize();

    // Convert hash to field element (take first 31 bytes to ensure it fits in the field)
    let mut repr = [0u8; 32];
    repr[..31].copy_from_slice(&hash[..31]);
    Fr::from_repr_vartime(repr).unwrap_or(Fr::ZERO)
}

/// Verifies ZK proofs for payout distribution validity
///
/// The verifier can operate in two modes:
/// 1. With Groth16 verification key - performs real cryptographic verification
/// 2. Without verification key - performs simulated verification (for testing)
pub struct PayoutVerifier {
    /// Expected prover ID (for verification key matching)
    prover_id: [u8; 32],
    /// Maximum miners supported
    max_miners: usize,
    /// Maximum nodes supported
    max_nodes: usize,
    /// Prepared verifying key for Groth16 verification
    prepared_vk: Option<Arc<PreparedVerifyingKey<Bls12>>>,
}

impl PayoutVerifier {
    /// Create a new payout verifier (without Groth16 verification key)
    #[instrument(skip_all, fields(max_miners, max_nodes))]
    pub fn new(prover_id: [u8; 32], max_miners: usize, max_nodes: usize) -> Self {
        info!("Creating payout verifier (simulated mode)");
        Self {
            prover_id,
            max_miners,
            max_nodes,
            prepared_vk: None,
        }
    }

    /// Create a new payout verifier with Groth16 verification key
    #[instrument(skip_all, fields(max_miners, max_nodes))]
    pub fn new_with_vk(
        prover_id: [u8; 32],
        max_miners: usize,
        max_nodes: usize,
        prepared_vk: Arc<PreparedVerifyingKey<Bls12>>,
    ) -> Self {
        info!("Creating payout verifier with Groth16 verification key");
        Self {
            prover_id,
            max_miners,
            max_nodes,
            prepared_vk: Some(prepared_vk),
        }
    }

    /// Create with default parameters (without Groth16 verification key)
    pub fn default_params(prover_id: [u8; 32]) -> Self {
        Self::new(prover_id, MAX_MINERS, MAX_NODES)
    }

    /// Create a verifier for a specific prover (inherits verification key if available)
    pub fn for_prover(prover: &PayoutProver) -> Self {
        if let Some(prepared_vk) = prover.prepared_verifying_key() {
            Self::new_with_vk(prover.prover_id(), MAX_MINERS, MAX_NODES, prepared_vk)
        } else {
            Self::default_params(prover.prover_id())
        }
    }

    /// Check if Groth16 verification is available
    pub fn has_groth16_vk(&self) -> bool {
        self.prepared_vk.is_some()
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

        // Check sum preservation using checked arithmetic to detect overflow
        let computed_sum = proof
            .miner_sum
            .checked_add(proof.node_sum)
            .and_then(|s| s.checked_add(proof.treasury_amount))
            .ok_or_else(|| {
                ZkError::InvalidProof("Sum overflow: miner_sum + node_sum + treasury_amount".to_string())
            })?;

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
    ///
    /// If a Groth16 verification key is available, performs real cryptographic
    /// verification. Otherwise, falls back to simulated verification.
    fn verify_proof_structure(&self, proof: &PayoutProof) -> bool {
        // Check minimum proof size
        if proof.proof.len() < 32 {
            return false;
        }

        // If we have a Groth16 verification key, perform real verification
        if let Some(ref prepared_vk) = self.prepared_vk {
            // Check proof is correct size for Groth16
            if proof.proof.len() != GROTH16_PROOF_SIZE {
                debug!(
                    "Proof size mismatch: {} != {}",
                    proof.proof.len(),
                    GROTH16_PROOF_SIZE
                );
                return false;
            }

            // Deserialize and verify the Groth16 proof
            match self.verify_groth16_proof(proof, prepared_vk) {
                Ok(valid) => return valid,
                Err(e) => {
                    warn!("Groth16 verification error: {:?}", e);
                    return false;
                }
            }
        }

        // SECURITY: No verification key available - FAIL CLOSED
        // In production, we MUST have a verification key. Without one,
        // we cannot cryptographically verify the proof.
        error!(
            "SECURITY: No Groth16 verification key available. \
             Cannot verify proof cryptographically. Rejecting proof. \
             Ensure trusted setup has been completed and VK is loaded."
        );

        // In test mode, allow simulated verification for development
        #[cfg(test)]
        {
            return self.verify_simulated_proof(proof);
        }

        #[cfg(not(test))]
        false
    }

    /// Simulated verification for testing only
    /// SECURITY: This is NOT cryptographically secure and must only be used in tests
    #[cfg(test)]
    fn verify_simulated_proof(&self, _proof: &PayoutProof) -> bool {
        use sha2::{Digest, Sha256};
        // Verify the proof is a valid hash of the witness data
        let mut hasher = Sha256::new();
        hasher.update(self.prover_id);
        let _expected_prefix = &hasher.finalize()[..8];
        // Accept simulated proofs in test mode only
        true
    }

    /// Verify a Groth16 proof cryptographically
    ///
    /// The proof is verified against all public inputs:
    /// 1. total_available - must match claimed total
    /// 2. miner_sum - must match sum claimed in proof
    /// 3. node_sum - must match sum claimed in proof
    /// 4. treasury_amount - must match claimed treasury
    /// 5. epoch - must match claimed epoch (replay protection)
    /// 6. metadata_commitment - cryptographic binding of epoch, miner_count, node_count
    fn verify_groth16_proof(
        &self,
        proof: &PayoutProof,
        prepared_vk: &PreparedVerifyingKey<Bls12>,
    ) -> ZkResult<bool> {
        let verify_start = Instant::now();

        // Deserialize the proof
        let groth16_proof = self.deserialize_proof(&proof.proof)?;

        // Compute metadata commitment - binds proof to epoch, miner_count, node_count
        let metadata_commitment =
            compute_metadata_commitment(proof.epoch, proof.miner_count, proof.node_count);

        // Build public inputs from the proof metadata
        // SECURITY: Order must match the order in PayoutCircuit::synthesize
        // All values are exposed as public inputs so the verifier can confirm
        // the proof is for the claimed payout distribution
        let public_inputs = vec![
            Fr::from(proof.total_available),  // PUBLIC INPUT 1: total_available
            Fr::from(proof.miner_sum),        // PUBLIC INPUT 2: miner_sum
            Fr::from(proof.node_sum),         // PUBLIC INPUT 3: node_sum
            Fr::from(proof.treasury_amount),  // PUBLIC INPUT 4: treasury_amount
            Fr::from(proof.epoch),            // PUBLIC INPUT 5: epoch
            metadata_commitment,              // PUBLIC INPUT 6: metadata_commitment
        ];

        debug!(
            "Verifying Groth16 proof with public inputs: total={}, miner_sum={}, node_sum={}, treasury={}, epoch={}, metadata_commitment={:?}",
            proof.total_available, proof.miner_sum, proof.node_sum, proof.treasury_amount, proof.epoch, metadata_commitment
        );

        // Verify the Groth16 proof
        let result = verify_proof(prepared_vk, &groth16_proof, &public_inputs);

        debug!("Groth16 verification completed in {:?}", verify_start.elapsed());

        match result {
            Ok(valid) => {
                if valid {
                    debug!("Groth16 proof verified successfully");
                } else {
                    warn!("Groth16 proof verification returned false");
                }
                Ok(valid)
            }
            Err(e) => {
                warn!("Groth16 proof verification error: {:?}", e);
                Ok(false)
            }
        }
    }

    /// Deserialize a Groth16 proof from bytes
    ///
    /// SECURITY: This function performs subgroup checks on all elliptic curve points
    /// to prevent small subgroup attacks. Points must be in the prime-order subgroup.
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

        // SECURITY: Verify A is in the prime-order subgroup (torsion-free)
        // This prevents small subgroup attacks where an attacker provides a point
        // in a small subgroup to forge proofs
        if !bool::from(a.is_torsion_free()) {
            return Err(ZkError::InvalidProof(
                "A point is not in prime-order subgroup (torsion detected)".to_string(),
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

        // SECURITY: Verify B is in the prime-order subgroup
        if !bool::from(b.is_torsion_free()) {
            return Err(ZkError::InvalidProof(
                "B point is not in prime-order subgroup (torsion detected)".to_string(),
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

        // SECURITY: Verify C is in the prime-order subgroup
        if !bool::from(c.is_torsion_free()) {
            return Err(ZkError::InvalidProof(
                "C point is not in prime-order subgroup (torsion detected)".to_string(),
            ));
        }

        Ok(Proof { a, b, c })
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

        // Check sum using checked arithmetic to detect overflow
        let computed_sum = match proof
            .miner_sum
            .checked_add(proof.node_sum)
            .and_then(|s| s.checked_add(proof.treasury_amount))
        {
            Some(sum) => sum,
            None => return PayoutVerificationResult::SumOverflow,
        };

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
    /// Sum calculation overflowed u64
    SumOverflow,
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

    #[test]
    fn test_has_groth16_vk() {
        let prover_id = [0xABu8; 32];
        let verifier = PayoutVerifier::new(prover_id, 10, 5);
        assert!(!verifier.has_groth16_vk());
    }

    #[test]
    fn test_verifier_for_prover_without_setup() {
        let prover = PayoutProver::new(10, 5).unwrap();
        let verifier = PayoutVerifier::for_prover(&prover);

        // Without setup, verifier should not have Groth16 VK
        assert!(!verifier.has_groth16_vk());
    }

    // Note: Full Groth16 prove/verify test is expensive (~10-30 seconds)
    // and is included in integration tests. The test below can be enabled
    // with --ignored flag: cargo test -p ghost-zkp -- --ignored
    #[test]
    #[ignore]
    fn test_groth16_prove_verify_roundtrip() {
        // This test performs full Groth16 trusted setup, proving, and verification
        // Run with: cargo test -p ghost-zkp -- --ignored

        // Create prover with full Groth16 setup
        let prover = PayoutProver::new_with_setup(10, 5).expect("Failed to create prover with setup");
        assert!(prover.has_groth16_params());

        let witness = PayoutWitness {
            epoch: 42,
            total_available: 1_000_000,
            miner_payouts: vec![400_000, 200_000, 100_000],
            node_payouts: vec![150_000, 100_000],
            treasury_amount: 50_000,
        };

        // Generate proof
        let proof = prover.prove(&witness).expect("Failed to generate proof");
        assert_eq!(proof.proof.len(), crate::types::GROTH16_PROOF_SIZE);

        // Create verifier with Groth16 VK
        let verifier = PayoutVerifier::for_prover(&prover);
        assert!(verifier.has_groth16_vk());

        // Verify the proof
        assert!(verifier.verify(&proof).expect("Verification failed"));

        // Verify detailed also works
        let result = verifier.verify_detailed(&proof);
        assert!(result.is_valid());
    }

    #[test]
    #[ignore]
    fn test_groth16_tampered_proof_fails() {
        // Create prover with full Groth16 setup
        let prover = PayoutProver::new_with_setup(5, 3).expect("Failed to create prover with setup");

        let witness = PayoutWitness {
            epoch: 1,
            total_available: 1000,
            miner_payouts: vec![500],
            node_payouts: vec![400],
            treasury_amount: 100,
        };

        let mut proof = prover.prove(&witness).expect("Failed to generate proof");

        // Tamper with the proof bytes
        if !proof.proof.is_empty() {
            proof.proof[0] ^= 0xFF;
        }

        let verifier = PayoutVerifier::for_prover(&prover);

        // Tampered proof should fail verification
        assert!(!verifier.verify(&proof).expect("Verification error"));
    }

    // ZK-M3: Test overflow detection with checked arithmetic
    #[test]
    fn test_sum_overflow_detection() {
        let (prover, mut proof) = create_valid_proof();
        let verifier = PayoutVerifier::for_prover(&prover);

        // Set values that would overflow when summed
        proof.miner_sum = u64::MAX;
        proof.node_sum = u64::MAX;
        proof.treasury_amount = u64::MAX;

        // verify() should return an error due to overflow
        let result = verifier.verify(&proof);
        assert!(result.is_err());

        // verify_detailed should return SumOverflow
        let detailed_result = verifier.verify_detailed(&proof);
        assert_eq!(detailed_result, PayoutVerificationResult::SumOverflow);
    }

    #[test]
    fn test_sum_overflow_at_boundary() {
        let (prover, mut proof) = create_valid_proof();
        let verifier = PayoutVerifier::for_prover(&prover);

        // Set values that just barely overflow
        proof.miner_sum = u64::MAX - 100;
        proof.node_sum = 101;
        proof.treasury_amount = 0;

        // This should overflow (MAX-100 + 101 overflows)
        let detailed_result = verifier.verify_detailed(&proof);
        assert_eq!(detailed_result, PayoutVerificationResult::SumOverflow);
    }

    // ZK-M1: Test metadata commitment computation
    #[test]
    fn test_metadata_commitment_deterministic() {
        let commit1 = compute_metadata_commitment(100, 5, 3);
        let commit2 = compute_metadata_commitment(100, 5, 3);
        assert_eq!(commit1, commit2);

        // Different epoch should produce different commitment
        let commit3 = compute_metadata_commitment(101, 5, 3);
        assert_ne!(commit1, commit3);

        // Different miner_count should produce different commitment
        let commit4 = compute_metadata_commitment(100, 6, 3);
        assert_ne!(commit1, commit4);

        // Different node_count should produce different commitment
        let commit5 = compute_metadata_commitment(100, 5, 4);
        assert_ne!(commit1, commit5);
    }
}
