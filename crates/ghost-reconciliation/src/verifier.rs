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

use std::sync::atomic::{AtomicUsize, Ordering};
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

/// H-5 FIX: Maximum merkle proof size (number of hashes)
/// 64 hashes can represent a tree with 2^64 leaves, which is far more than any realistic use
const MAX_MERKLE_PROOF_SIZE: usize = 64;

/// M-8 FIX: Maximum pending verification requests before rejecting new ones
const MAX_PENDING_REQUESTS: usize = 100;

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
    /// M-8 FIX: Pending request counter for rate limiting
    pending_requests: Arc<AtomicUsize>,
    /// M-8 FIX: Maximum pending requests before rejection
    max_pending: usize,
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
            pending_requests: Arc::new(AtomicUsize::new(0)),
            max_pending: MAX_PENDING_REQUESTS,
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

    /// M-8 FIX: Get the current pending request count (for monitoring)
    pub fn pending_count(&self) -> usize {
        self.pending_requests.load(Ordering::SeqCst)
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
        // H-5 FIX: Validate proof size BEFORE cloning to prevent memory exhaustion
        if proof.merkle_proof.len() > MAX_MERKLE_PROOF_SIZE {
            return Err(ReconciliationError::ProofTooLarge {
                size: proof.merkle_proof.len(),
                max: MAX_MERKLE_PROOF_SIZE,
            });
        }

        // M-8 FIX: Check pending request count before proceeding
        let pending = self.pending_requests.fetch_add(1, Ordering::SeqCst);
        if pending >= self.max_pending {
            self.pending_requests.fetch_sub(1, Ordering::SeqCst);
            return Err(ReconciliationError::TooManyPendingVerifications {
                pending,
                max: self.max_pending,
            });
        }

        // M-8 FIX: Use scopeguard to ensure pending count is decremented on exit
        let pending_guard = scopeguard::guard((), |_| {
            self.pending_requests.fetch_sub(1, Ordering::SeqCst);
        });

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
        // H-5 FIX: Size already validated above, safe to clone now
        let proof_clone = proof.clone();

        // M-7 FIX: Add timeout to the verification task itself
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(PROOF_VERIFICATION_TIMEOUT_MS),
            tokio::task::spawn_blocking(move || proof_clone.verify()),
        )
        .await
        .map_err(|_| ReconciliationError::VerificationTimeout {
            reason: "M-7: Proof verification task timed out".to_string(),
        })?
        .map_err(|e| ReconciliationError::InternalError {
            details: format!("Verification task panicked: {}", e),
        })?;

        // Release permit (implicit when permit drops)
        drop(permit);

        // Pending guard will decrement on drop
        drop(pending_guard);

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
        // H-5 FIX: Validate proof size BEFORE cloning
        if proof.len() > MAX_MERKLE_PROOF_SIZE {
            return Err(ReconciliationError::ProofTooLarge {
                size: proof.len(),
                max: MAX_MERKLE_PROOF_SIZE,
            });
        }

        // M-8 FIX: Check pending request count before proceeding
        let pending = self.pending_requests.fetch_add(1, Ordering::SeqCst);
        if pending >= self.max_pending {
            self.pending_requests.fetch_sub(1, Ordering::SeqCst);
            return Err(ReconciliationError::TooManyPendingVerifications {
                pending,
                max: self.max_pending,
            });
        }

        // M-8 FIX: Use scopeguard to ensure pending count is decremented on exit
        let pending_guard = scopeguard::guard((), |_| {
            self.pending_requests.fetch_sub(1, Ordering::SeqCst);
        });

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

        // Copy data for blocking task (H-5: size already validated above)
        let leaf = *leaf;
        let proof_vec: Vec<[u8; 32]> = proof.to_vec();
        let root = *root;

        // M-7 FIX: Add timeout to the verification task itself
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(PROOF_VERIFICATION_TIMEOUT_MS),
            tokio::task::spawn_blocking(move || {
                verify_merkle_proof(&leaf, &proof_vec, &root, index, leaf_count)
            }),
        )
        .await
        .map_err(|_| ReconciliationError::VerificationTimeout {
            reason: "M-7: Merkle verification task timed out".to_string(),
        })?
        .map_err(|e| ReconciliationError::InternalError {
            details: format!("Merkle verification task panicked: {}", e),
        })?;

        // Release permit (implicit when permit drops)
        drop(permit);

        // Pending guard will decrement on drop
        drop(pending_guard);

        Ok(result)
    }

    /// H-4 FIX: Batch verify multiple proofs with parallel execution
    ///
    /// Verifies multiple settlement proofs in parallel using futures::join_all.
    /// Each individual verification is still rate-limited by the semaphore.
    /// Returns a vector of results corresponding to each input proof.
    pub async fn verify_batch(&self, proofs: &[SettlementProof]) -> Vec<ReconciliationResult<()>> {
        use futures::future::join_all;

        let futures: Vec<_> = proofs
            .iter()
            .map(|proof| self.verify_settlement_proof(proof))
            .collect();

        join_all(futures).await
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
            pending_requests: Arc::clone(&self.pending_requests),
            max_pending: self.max_pending,
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

    #[tokio::test]
    async fn test_h5_proof_size_limit() {
        // H-5 FIX: Test that oversized proofs are rejected before cloning
        let verifier = ProofVerifier::new();

        // Create a proof with too many hashes
        let oversized_proof: Vec<[u8; 32]> = (0..MAX_MERKLE_PROOF_SIZE + 1)
            .map(|i| [i as u8; 32])
            .collect();

        let proof = SettlementProof {
            settlement_hash: [0u8; 32],
            merkle_proof: oversized_proof.clone(),
            index: 0,
            leaf_count: 1,
            merkle_root: [0u8; 32],
            batch_id: [0u8; 32],
            l1_txid: "test".to_string(),
            l1_height: 0,
            l1_block_hash: "test".to_string(),
        };

        let result = verifier.verify_settlement_proof(&proof).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ReconciliationError::ProofTooLarge { size, max } => {
                assert_eq!(size, MAX_MERKLE_PROOF_SIZE + 1);
                assert_eq!(max, MAX_MERKLE_PROOF_SIZE);
            }
            e => panic!("Expected ProofTooLarge error, got: {:?}", e),
        }

        // Also test verify_merkle
        let result = verifier
            .verify_merkle(&[0u8; 32], &oversized_proof, &[0u8; 32], 0, 1)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ReconciliationError::ProofTooLarge { size, max } => {
                assert_eq!(size, MAX_MERKLE_PROOF_SIZE + 1);
                assert_eq!(max, MAX_MERKLE_PROOF_SIZE);
            }
            e => panic!("Expected ProofTooLarge error, got: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_h5_valid_size_proof_allowed() {
        // H-5: Verify that max-size proofs are still allowed
        let verifier = ProofVerifier::new();

        // Create a proof at exactly the limit
        let max_size_proof: Vec<[u8; 32]> =
            (0..MAX_MERKLE_PROOF_SIZE).map(|i| [i as u8; 32]).collect();

        // This should not fail due to size (may fail for other reasons, but not size)
        let result = verifier
            .verify_merkle(&[0u8; 32], &max_size_proof, &[0u8; 32], 0, 1)
            .await;

        // Should not be a ProofTooLarge error
        if let Err(ReconciliationError::ProofTooLarge { .. }) = result {
            panic!("Max size proof should not be rejected for size");
        }
    }

    #[tokio::test]
    async fn test_m8_pending_count() {
        // M-8 FIX: Test pending request tracking
        let verifier = ProofVerifier::new();

        // Initially pending count should be 0
        assert_eq!(verifier.pending_count(), 0);

        // Create a valid proof
        let leaves: Vec<[u8; 32]> = (0..8).map(|i| [i; 32]).collect();
        let root = compute_merkle_root(&leaves);
        let merkle_proof = compute_merkle_proof(&leaves, 0);

        let proof = SettlementProof {
            settlement_hash: leaves[0],
            merkle_proof,
            index: 0,
            leaf_count: 8,
            merkle_root: root,
            batch_id: [0u8; 32],
            l1_txid: "test".to_string(),
            l1_height: 800_000,
            l1_block_hash: "test".to_string(),
        };

        // After verification, pending count should return to 0
        let _ = verifier.verify_settlement_proof(&proof).await;
        assert_eq!(verifier.pending_count(), 0);
    }

    #[tokio::test]
    async fn test_h4_parallel_batch_verification() {
        // H-4 FIX: Test that batch verification runs in parallel
        let verifier = ProofVerifier::with_max_concurrent(5);

        // Create valid proofs
        let leaves: Vec<[u8; 32]> = (0..8).map(|i| [i; 32]).collect();
        let root = compute_merkle_root(&leaves);

        let proofs: Vec<SettlementProof> = (0..5)
            .map(|i| {
                let merkle_proof = compute_merkle_proof(&leaves, i % 8);
                SettlementProof {
                    settlement_hash: leaves[i % 8],
                    merkle_proof,
                    index: i % 8,
                    leaf_count: 8,
                    merkle_root: root,
                    batch_id: [0u8; 32],
                    l1_txid: format!("txid_{}", i),
                    l1_height: 800_000,
                    l1_block_hash: "test".to_string(),
                }
            })
            .collect();

        // Run batch verification - this should complete faster than sequential
        // because verifications run in parallel
        let start = std::time::Instant::now();
        let results = verifier.verify_batch(&proofs).await;
        let duration = start.elapsed();

        // All should succeed
        assert_eq!(results.len(), 5);
        assert!(results.iter().all(|r| r.is_ok()));

        // Pending count should be 0 after completion
        assert_eq!(verifier.pending_count(), 0);

        // Duration should be reasonable (parallel, not sequential)
        // This is a sanity check, not a strict timing test
        assert!(
            duration.as_secs() < 10,
            "Batch verification took too long: {:?}",
            duration
        );
    }
}
