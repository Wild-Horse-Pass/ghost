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

/// H-1: Environment variable for expected parameter hashes (from MPC ceremony)
///
/// Format: "BLOCK:sha256hex,PAYOUT:sha256hex"
/// Example: "BLOCK:abc123...,PAYOUT:def456..."
pub const ZK_PARAMS_HASH_ENV: &str = "ZK_PARAMS_HASH";

/// 2.4 HIGH: Compute SHA-256 hash of a parameters file
///
/// Streams the file to handle large parameter sets efficiently.
#[cfg(feature = "zk-production")]
fn compute_params_file_hash(path: &std::path::Path) -> ZkResult<[u8; 32]> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = std::fs::File::open(path).map_err(|e| {
        ZkError::InvalidParams(format!("Failed to open params file: {}", e))
    })?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer).map_err(|e| {
            ZkError::InvalidParams(format!("Failed to read params file: {}", e))
        })?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hasher.finalize().into())
}

/// 2.4 HIGH: Parse expected hashes from environment variable
#[cfg(feature = "zk-production")]
fn parse_expected_hashes() -> ZkResult<std::collections::HashMap<String, [u8; 32]>> {
    use std::env;

    let hash_env = env::var(ZK_PARAMS_HASH_ENV).map_err(|_| {
        ZkError::InvalidParams(format!(
            "2.4 HIGH: Production mode requires {} environment variable. \
             Set to ceremony output hashes in format: BLOCK:sha256hex,PAYOUT:sha256hex",
            ZK_PARAMS_HASH_ENV
        ))
    })?;

    let mut hashes = std::collections::HashMap::new();

    for pair in hash_env.split(',') {
        let parts: Vec<&str> = pair.split(':').collect();
        if parts.len() != 2 {
            return Err(ZkError::InvalidParams(format!(
                "Invalid hash format: {}. Expected TYPE:sha256hex",
                pair
            )));
        }

        let param_type = parts[0].to_uppercase();
        let hash_hex = parts[1];

        if hash_hex.len() != 64 {
            return Err(ZkError::InvalidParams(format!(
                "Invalid hash length for {}: expected 64 hex chars, got {}",
                param_type,
                hash_hex.len()
            )));
        }

        let hash_bytes: [u8; 32] = hex::decode(hash_hex)
            .map_err(|e| ZkError::InvalidParams(format!("Invalid hex in hash: {}", e)))?
            .try_into()
            .map_err(|_| ZkError::InvalidParams("Hash decode failed".to_string()))?;

        hashes.insert(param_type, hash_bytes);
    }

    Ok(hashes)
}

/// H-1: Load and validate trusted setup parameters
///
/// In production mode (`zk-production` feature enabled):
/// - Loads parameters from `ZK_PARAMS_PATH` environment variable
/// - Verifies parameters match expected hash from ceremony (2.4 HIGH)
/// - Returns error if parameters are missing, invalid, or tampered
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

    let base_path = PathBuf::from(&params_path);
    if !base_path.exists() {
        return Err(ZkError::InvalidParams(format!(
            "H-1: Trusted setup parameters not found at {}. \
             Complete MPC ceremony first.",
            params_path
        )));
    }

    // 2.4 HIGH: Verify parameter hashes against ceremony output
    let expected_hashes = parse_expected_hashes()?;

    // Check block parameters
    let block_params_path = base_path.join("block_params_current.bin");
    if block_params_path.exists() {
        let actual_hash = compute_params_file_hash(&block_params_path)?;
        if let Some(expected) = expected_hashes.get("BLOCK") {
            if &actual_hash != expected {
                return Err(ZkError::InvalidParams(format!(
                    "2.4 HIGH: Block parameter hash mismatch! \
                     Expected: {}, Got: {}. \
                     Parameters may be corrupted or tampered.",
                    hex::encode(expected),
                    hex::encode(actual_hash)
                )));
            }
            tracing::info!(
                hash = %hex::encode(actual_hash),
                "2.4 HIGH: Block parameters hash verified"
            );
        }
    }

    // Check payout parameters
    let payout_params_path = base_path.join("payout_params_current.bin");
    if payout_params_path.exists() {
        let actual_hash = compute_params_file_hash(&payout_params_path)?;
        if let Some(expected) = expected_hashes.get("PAYOUT") {
            if &actual_hash != expected {
                return Err(ZkError::InvalidParams(format!(
                    "2.4 HIGH: Payout parameter hash mismatch! \
                     Expected: {}, Got: {}. \
                     Parameters may be corrupted or tampered.",
                    hex::encode(expected),
                    hex::encode(actual_hash)
                )));
            }
            tracing::info!(
                hash = %hex::encode(actual_hash),
                "2.4 HIGH: Payout parameters hash verified"
            );
        }
    }

    tracing::info!(
        path = %params_path,
        "H-1: Loaded and verified trusted setup parameters for production mode"
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
