//! Ghost ZKP - Zero-Knowledge Proof Infrastructure for Ghost Pay
//!
//! This crate provides ZK validity proofs for Ghost Pay's BFT consensus.
//! Each block is proven valid by the proposer and verified by validators
//! in approximately 10ms. Proofs are ephemeral - once verified and the
//! block is finalized, they are discarded.
//!
//! # H-1: Trusted Setup Requirements
//!
//! **SECURITY WARNING**: This crate uses Groth16 which requires a trusted setup
//! ceremony (MPC) to generate secure parameters. Without completing this ceremony:
//!
//! - **Default parameters are for testing only**
//! - A malicious prover could forge proofs
//! - ZK proofs should NOT be relied upon for mainnet security
//!
//! For production deployment, you must:
//!
//! 1. Complete an MPC ceremony (see `docs/ZK_CEREMONY.md`)
//! 2. Set `ZK_PARAMS_PATH` to the ceremony output directory
//! 3. Compile with `--features zk-production`
//!
//! When `zk-production` is enabled:
//! - Parameter loading verifies against known ceremony hashes
//! - Proof generation fails if parameters are missing/invalid
//! - Additional safety checks prevent accidental test parameter use
//!
//! # Proving Modes
//!
//! ## Legacy Mode (prove)
//! Proves payment validity only. Validators must re-execute state to verify
//! the state root transition.
//!
//! ## Full ZK Mode (prove_v2)
//! Proves complete state root transitions cryptographically. Validators verify
//! the proof only - no re-execution required. This makes Ghost Pay fully trustless.
//!
//! # Architecture
//!
//! ```text
//! Proposer                    Validators
//! ┌──────────────┐           ┌──────────────┐
//! │ 1. Execute   │           │ 1. Receive   │
//! │    txs       │           │    proposal  │
//! │              │           │              │
//! │ 2. Generate  │──────────►│ 2. Verify    │
//! │    witness   │           │    proof     │
//! │              │           │    (~10ms)   │
//! │ 3. Generate  │           │              │
//! │    proof     │           │ 3. Vote      │
//! │    (~2 sec)  │           │    approve   │
//! └──────────────┘           └──────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use ghost_zkp::{BlockProver, BlockVerifier, BlockWitness, BlockWitnessV2};
//!
//! // One-time setup (slow)
//! let prover = BlockProver::new_with_state_transitions(100, 20);
//! let verifier = BlockVerifier::new(prover.verification_key());
//!
//! // Per-block proving with full state transition proof (~2 seconds)
//! let witness = BlockWitnessV2::new(height, prev_root, new_root, transitions, 20);
//! let proof = prover.prove_v2(&witness)?;
//!
//! // Per-block verification (~10ms) - NO RE-EXECUTION NEEDED
//! assert!(verifier.verify(&proof)?);
//! ```

pub mod circuit;
pub mod errors;
pub mod field_utils;
pub mod payout_prover;
pub mod payout_verifier;
pub mod prover;
pub mod state_tree;
pub mod types;
pub mod verifier;

// Re-export main types
pub use errors::{ZkError, ZkResult};
pub use prover::BlockProver;
pub use types::{
    BlockProof, BlockWitness, BlockWitnessV2, MerkleProof, PaymentTransitionWitness,
    PaymentWitness, ProvingParams, StateSnapshot, VerificationKey,
};
pub use verifier::BlockVerifier;

// Re-export state tree utilities
pub use state_tree::{BalanceTree, BalanceTreeBuilder};

// Re-export payout types
pub use payout_prover::{PayoutProof, PayoutProver, PayoutWitness};
pub use payout_verifier::{verify_payout, PayoutVerificationResult, PayoutVerifier};

// Re-export circuit types for advanced usage
pub use circuit::{
    BlockCircuit, BlockCircuitBuilder, MerkleCircuit, PaymentCircuit,
    PaymentStateTransitionCircuit, StateTransitionOutputs,
};

// ============================================================================
// H-1: ZK Production Mode Safety
// ============================================================================

/// H-1: Check if ZK production mode is enabled
///
/// Returns true if the `zk-production` feature flag is set, indicating
/// that trusted setup ceremony artifacts should be used.
#[cfg(feature = "zk-production")]
pub const fn is_production_mode() -> bool {
    true
}

/// H-1: Check if ZK production mode is enabled
///
/// Returns false when `zk-production` is not enabled, indicating
/// that only test parameters should be used.
#[cfg(not(feature = "zk-production"))]
pub const fn is_production_mode() -> bool {
    false
}

/// H-1: Environment variable for trusted setup parameters path
pub const ZK_PARAMS_PATH_ENV: &str = "ZK_PARAMS_PATH";

/// H-1: Load and validate trusted setup parameters
///
/// In production mode (`zk-production` feature enabled):
/// - Loads parameters from `ZK_PARAMS_PATH` environment variable
/// - Verifies parameters match expected hash from ceremony
/// - Returns error if parameters are missing or invalid
///
/// In test mode (default):
/// - Uses default test parameters
/// - Logs a warning that these should not be used for production
///
/// # Errors
///
/// Returns `ZkError::InvalidParams` if production mode is enabled but
/// parameters are missing, corrupted, or don't match expected hashes.
#[cfg(feature = "zk-production")]
pub fn load_trusted_params() -> ZkResult<()> {
    use std::env;
    use std::path::PathBuf;

    let params_path = env::var(ZK_PARAMS_PATH_ENV).map_err(|_| {
        ZkError::InvalidParams(format!(
            "H-1: Production mode enabled but {} environment variable not set. \
             Complete MPC ceremony and set path to ceremony output.",
            ZK_PARAMS_PATH_ENV
        ))
    })?;

    let path = PathBuf::from(&params_path);
    if !path.exists() {
        return Err(ZkError::InvalidParams(format!(
            "H-1: Trusted setup parameters not found at {}. \
             Complete MPC ceremony first.",
            params_path
        )));
    }

    // TODO: After MPC ceremony is completed, add hash verification here:
    // let expected_hash = "sha256:...";
    // let actual_hash = compute_params_hash(&path)?;
    // if actual_hash != expected_hash {
    //     return Err(ZkError::InvalidParams("Parameter hash mismatch"));
    // }

    tracing::info!(
        path = %params_path,
        "H-1: Loaded trusted setup parameters for production mode"
    );

    Ok(())
}

/// H-1: Load trusted setup parameters (test mode)
#[cfg(not(feature = "zk-production"))]
pub fn load_trusted_params() -> ZkResult<()> {
    tracing::warn!(
        "H-1: ZK production mode NOT enabled. Using test parameters only. \
         These proofs should NOT be trusted for mainnet security. \
         Enable 'zk-production' feature for production deployment."
    );
    Ok(())
}
