//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: verifier.rs                                                                                                    |
//|======================================================================================================================|

//! M-14 FIX: Concurrent Proof Verification Limiter
//!
//! This module provides a semaphore-based limiter for concurrent Merkle proof
//! verifications to prevent CPU exhaustion attacks. A malicious client could
//! submit many complex proof verification requests simultaneously to exhaust
//! server CPU resources.
//!
//! The `ProofVerifier` wraps the synchronous verification functions and limits
//! the number of concurrent verifications using a semaphore.

use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::batch::verify_merkle_proof;
use crate::error::{ReconciliationError, ReconciliationResult};
use crate::proof::SettlementProof;

/// M-14 FIX: Maximum number of concurrent proof verifications
/// This prevents CPU exhaustion from parallel verification attacks
const MAX_CONCURRENT_PROOFS: usize = 10;

/// M-14 FIX: Proof verification timeout (milliseconds)
/// If a verification takes longer than this, something is wrong
const PROOF_VERIFICATION_TIMEOUT_MS: u64 = 5000;

/// M-14 FIX: Semaphore-limited proof verifier
///
/// Provides concurrency-limited proof verification to prevent DoS attacks
/// via CPU exhaustion. The verifier uses a semaphore to limit the number
/// of simultaneous proof verifications across all requests.
///
/// # Usage
///
/// ```rust,ignore
/// use ghost_reconciliation::ProofVerifier;
///
/// let verifier = ProofVerifier::new();
///
/// // Verify a settlement proof with concurrency limiting
/// let result = verifier.verify_settlement_proof(&proof).await?;
///
/// // Or verify a raw merkle proof
/// let is_valid = verifier.verify_merkle_proof(&leaf, &proof, &root, index, leaf_count).await?;
/// ```
pub struct ProofVerifier {
    /// Semaphore limiting concurrent verifications
    proof_semaphore: Arc<Semaphore>,
    /// Maximum concurrent verifications (for monitoring)
    max_concurrent: usize,
}

impl ProofVerifier {
    /// Create a new proof verifier with default concurrency limit
    pub fn new() -> Self {
        Self::with_max_concurrent(MAX_CONCURRENT_PROOFS)
    }

    /// Create a new proof verifier with custom concurrency limit
    pub fn with_max_concurrent(max_concurrent: usize) -> Self {
        Self {
            proof_semaphore: Arc::new(Semaphore::new(max_concurrent)),
            max_concurrent,
        }
    }

    /// Get the number of available permits (for monitoring)
    pub fn available_permits(&self) -> usize {
        self.proof_semaphore.available_permits()
    }

    /// Get the maximum concurrent verifications
    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    /// M-14 FIX: Verify a settlement proof with concurrency limiting
    ///
    /// Acquires a semaphore permit before verification to limit concurrent
    /// CPU-intensive operations. Returns an error if the semaphore cannot
    /// be acquired (all permits in use and timeout exceeded).
    pub async fn verify_settlement_proof(
        &self,
        proof: &SettlementProof,
    ) -> ReconciliationResult<()> {
        // Try to acquire permit with timeout
        let permit = tokio::time::timeout(
            std::time::Duration::from_millis(PROOF_VERIFICATION_TIMEOUT_MS),
            self.proof_semaphore.acquire(),
        )
        .await
        .map_err(|_| ReconciliationError::VerificationTimeout {
            reason: format!(
                "M-14: Proof verification queue full ({} concurrent verifications), request timed out",
                self.max_concurrent
            ),
        })?
        .map_err(|_| ReconciliationError::SemaphoreClosed)?;

        // Perform verification while holding permit
        // Use spawn_blocking for CPU-intensive work
        let proof_clone = proof.clone();
        let result = tokio::task::spawn_blocking(move || proof_clone.verify())
            .await
            .map_err(|e| ReconciliationError::InternalError {
                details: format!("Verification task panicked: {}", e),
            })?;

        // Release permit (implicit when permit drops)
        drop(permit);

        result
    }

    /// M-14 FIX: Verify a raw merkle proof with concurrency limiting
    ///
    /// Lower-level API for verifying merkle proofs directly.
    pub async fn verify_merkle(
        &self,
        leaf: &[u8; 32],
        proof: &[[u8; 32]],
        root: &[u8; 32],
        index: usize,
        leaf_count: usize,
    ) -> ReconciliationResult<bool> {
        // Try to acquire permit with timeout
        let permit = tokio::time::timeout(
            std::time::Duration::from_millis(PROOF_VERIFICATION_TIMEOUT_MS),
            self.proof_semaphore.acquire(),
        )
        .await
        .map_err(|_| ReconciliationError::VerificationTimeout {
            reason: format!(
                "M-14: Merkle verification queue full ({} concurrent verifications), request timed out",
                self.max_concurrent
            ),
        })?
        .map_err(|_| ReconciliationError::SemaphoreClosed)?;

        // Copy data for blocking task
        let leaf = *leaf;
        let proof_vec: Vec<[u8; 32]> = proof.to_vec();
        let root = *root;

        // Use spawn_blocking for CPU-intensive work
        let result = tokio::task::spawn_blocking(move || {
            verify_merkle_proof(&leaf, &proof_vec, &root, index, leaf_count)
        })
        .await
        .map_err(|e| ReconciliationError::InternalError {
            details: format!("Merkle verification task panicked: {}", e),
        })?;

        // Release permit (implicit when permit drops)
        drop(permit);

        Ok(result)
    }

    /// M-14 FIX: Batch verify multiple proofs with concurrency limiting
    ///
    /// Verifies multiple settlement proofs, limiting total concurrent verifications.
    /// Returns a vector of results corresponding to each input proof.
    pub async fn verify_batch(
        &self,
        proofs: &[SettlementProof],
    ) -> Vec<ReconciliationResult<()>> {
        let mut results = Vec::with_capacity(proofs.len());

        for proof in proofs {
            results.push(self.verify_settlement_proof(proof).await);
        }

        results
    }
}

impl Default for ProofVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ProofVerifier {
    fn clone(&self) -> Self {
        Self {
            proof_semaphore: Arc::clone(&self.proof_semaphore),
            max_concurrent: self.max_concurrent,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::{compute_merkle_proof, compute_merkle_root};

    #[tokio::test]
    async fn test_m14_proof_verifier_basic() {
        let verifier = ProofVerifier::new();

        // Should have max permits available
        assert_eq!(verifier.available_permits(), MAX_CONCURRENT_PROOFS);
        assert_eq!(verifier.max_concurrent(), MAX_CONCURRENT_PROOFS);
    }

    #[tokio::test]
    async fn test_m14_proof_verifier_custom_limit() {
        let verifier = ProofVerifier::with_max_concurrent(5);

        assert_eq!(verifier.available_permits(), 5);
        assert_eq!(verifier.max_concurrent(), 5);
    }

    #[tokio::test]
    async fn test_m14_merkle_verification() {
        let verifier = ProofVerifier::new();

        // Create a valid merkle tree
        let leaves: Vec<[u8; 32]> = (0..8).map(|i| [i; 32]).collect();
        let root = compute_merkle_root(&leaves);
        let proof = compute_merkle_proof(&leaves, 3);

        // Verify through the limiter
        let result = verifier.verify_merkle(&leaves[3], &proof, &root, 3, 8).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_m14_settlement_proof_verification() {
        let verifier = ProofVerifier::new();

        // Create a valid settlement proof
        let leaves: Vec<[u8; 32]> = (0..8).map(|i| [i; 32]).collect();
        let root = compute_merkle_root(&leaves);
        let merkle_proof = compute_merkle_proof(&leaves, 3);

        let proof = SettlementProof {
            settlement_hash: leaves[3],
            merkle_proof,
            index: 3,
            leaf_count: 8,
            merkle_root: root,
            batch_id: [0u8; 32],
            l1_txid: "test_txid".to_string(),
            l1_height: 800_000,
            l1_block_hash: "test_block".to_string(),
        };

        let result = verifier.verify_settlement_proof(&proof).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_m14_invalid_proof_rejected() {
        let verifier = ProofVerifier::new();

        // Create an invalid proof (wrong leaf count)
        let leaves: Vec<[u8; 32]> = (0..8).map(|i| [i; 32]).collect();
        let root = compute_merkle_root(&leaves);
        let merkle_proof = compute_merkle_proof(&leaves, 3);

        let proof = SettlementProof {
            settlement_hash: leaves[3],
            merkle_proof,
            index: 3,
            leaf_count: 10, // Wrong!
            merkle_root: root,
            batch_id: [0u8; 32],
            l1_txid: "test_txid".to_string(),
            l1_height: 800_000,
            l1_block_hash: "test_block".to_string(),
        };

        let result = verifier.verify_settlement_proof(&proof).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_m14_concurrent_limit_enforced() {
        let verifier = ProofVerifier::with_max_concurrent(2);

        // Create valid proof for testing
        let leaves: Vec<[u8; 32]> = (0..8).map(|i| [i; 32]).collect();
        let root = compute_merkle_root(&leaves);
        let proof = compute_merkle_proof(&leaves, 0);

        // Acquire permits manually to simulate concurrent load
        let _permit1 = verifier.proof_semaphore.acquire().await.unwrap();
        let _permit2 = verifier.proof_semaphore.acquire().await.unwrap();

        // Now all permits are held, available should be 0
        assert_eq!(verifier.available_permits(), 0);

        // Verification should timeout because no permits available
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            verifier.verify_merkle(&leaves[0], &proof, &root, 0, 8),
        )
        .await;

        // Should timeout waiting for permit
        assert!(result.is_err() || result.unwrap().is_err());
    }

    #[tokio::test]
    async fn test_m14_batch_verification() {
        let verifier = ProofVerifier::new();

        // Create valid proofs
        let leaves: Vec<[u8; 32]> = (0..8).map(|i| [i; 32]).collect();
        let root = compute_merkle_root(&leaves);

        let proofs: Vec<SettlementProof> = (0..3)
            .map(|i| {
                let merkle_proof = compute_merkle_proof(&leaves, i);
                SettlementProof {
                    settlement_hash: leaves[i],
                    merkle_proof,
                    index: i,
                    leaf_count: 8,
                    merkle_root: root,
                    batch_id: [0u8; 32],
                    l1_txid: format!("txid_{}", i),
                    l1_height: 800_000,
                    l1_block_hash: "test_block".to_string(),
                }
            })
            .collect();

        let results = verifier.verify_batch(&proofs).await;
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.is_ok()));
    }

    #[tokio::test]
    async fn test_m14_verifier_is_clone() {
        let verifier1 = ProofVerifier::new();
        let verifier2 = verifier1.clone();

        // Both should share the same semaphore
        let _permit = verifier1.proof_semaphore.acquire().await.unwrap();
        assert_eq!(verifier2.available_permits(), MAX_CONCURRENT_PROOFS - 1);
    }
}
