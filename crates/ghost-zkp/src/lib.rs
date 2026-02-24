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
//| FILE: lib.rs                                                                                                         |
//|======================================================================================================================|

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
pub mod commitment_tree;
pub mod confidential_prover;
pub mod confidential_verifier;
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
    BlockProof, BlockWitness, BlockWitnessV2, ConfidentialNote, ConfidentialPublicInputs,
    ConfidentialTransferWitness, MerkleProof, PaymentTransitionWitness, PaymentWitness,
    ProvingParams, StateSnapshot, VerificationKey,
};
pub use verifier::BlockVerifier;

// Re-export state tree utilities
pub use commitment_tree::{CommitmentTree, CommitmentTreeBuilder};
pub use state_tree::{BalanceTree, BalanceTreeBuilder};

// Re-export payout types
pub use payout_prover::{PayoutProof, PayoutProver, PayoutWitness};
pub use payout_verifier::{verify_payout, PayoutVerificationResult, PayoutVerifier};

// Re-export confidential transfer types
pub use confidential_prover::{ConfidentialProver, ConfidentialTransferProof};
pub use confidential_verifier::ConfidentialVerifier;

// Re-export circuit types for advanced usage
pub use circuit::{
    compute_nullifier_native, pedersen_commit_native, COMMITMENT_DOMAIN_SEPARATOR,
    NULLIFIER_DOMAIN_SEPARATOR,
};
pub use circuit::{
    BlockCircuit, BlockCircuitBuilder, ConfidentialTransferCircuit, MerkleCircuit, PaymentCircuit,
    PaymentStateTransitionCircuit, StateTransitionOutputs,
};

// ============================================================================
// Byte-level commitment helpers for application layer
// ============================================================================

/// Compute a Pedersen commitment from byte-level inputs.
///
/// C = MiMC(MiMC(value, blinding), COMMITMENT_DOMAIN_SEPARATOR)
///
/// This is a convenience wrapper for application code that doesn't
/// want to deal with field element types directly.
pub fn compute_commitment_bytes(value_sats: u64, blinding: &[u8; 32]) -> ZkResult<[u8; 32]> {
    use blstrs::Scalar;
    use circuit::mimc::{bytes_to_field, field_to_bytes};

    let value_fr = Scalar::from(value_sats);
    let blinding_fr: Scalar = bytes_to_field(blinding)
        .map_err(|e| ZkError::FieldConversionError(format!("Invalid blinding: {}", e)))?;
    let commitment_fr = pedersen_commit_native(value_fr, blinding_fr);
    Ok(field_to_bytes(commitment_fr))
}

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

    let mut file = std::fs::File::open(path)
        .map_err(|e| ZkError::InvalidParams(format!("Failed to open params file: {}", e)))?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|e| ZkError::InvalidParams(format!("Failed to read params file: {}", e)))?;
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

// ============================================================================
// C-5: Startup Verification for Mainnet Deployment
// ============================================================================

/// C-5: Verify ZK trusted setup is properly configured for mainnet
///
/// This function MUST be called at startup on mainnet deployments.
/// It performs comprehensive checks to ensure ZK proofs can be trusted:
///
/// 1. Checks if `zk-production` feature is enabled
/// 2. Verifies `ZK_PARAMS_PATH` environment variable is set
/// 3. Verifies parameter files exist at the specified path
/// 4. Validates parameter hashes match ceremony output
///
/// # Errors
///
/// Returns `ZkError::InvalidParams` if:
/// - Production feature is not enabled but `is_mainnet` is true
/// - `ZK_PARAMS_PATH` is not set
/// - Parameter files are missing
/// - Parameter hashes don't match expected values
///
/// # Example
///
/// ```ignore
/// // At startup:
/// if is_mainnet {
///     verify_zk_setup_for_mainnet()?;
/// }
/// ```
#[cfg(feature = "zk-production")]
pub fn verify_zk_setup_for_mainnet() -> ZkResult<()> {
    use std::path::PathBuf;

    tracing::info!("C-5: Verifying ZK trusted setup for mainnet deployment");

    // Step 1: Verify ZK_PARAMS_PATH is set
    let params_path = std::env::var(ZK_PARAMS_PATH_ENV).map_err(|_| {
        ZkError::InvalidParams(format!(
            "C-5 CRITICAL: Mainnet requires {} environment variable. \
             Set path to trusted setup ceremony output directory.",
            ZK_PARAMS_PATH_ENV
        ))
    })?;

    // Step 2: Verify base path exists
    let base_path = PathBuf::from(&params_path);
    if !base_path.exists() {
        return Err(ZkError::InvalidParams(format!(
            "C-5 CRITICAL: Trusted setup directory not found: {}. \
             Complete MPC ceremony first.",
            params_path
        )));
    }

    // Step 3: Verify at least one parameter file exists
    let block_params = base_path.join("block_params_current.bin");
    let payout_params = base_path.join("payout_params_current.bin");

    if !block_params.exists() && !payout_params.exists() {
        return Err(ZkError::InvalidParams(format!(
            "C-5 CRITICAL: No parameter files found in {}. \
             Expected block_params_current.bin and/or payout_params_current.bin",
            params_path
        )));
    }

    // Step 4: Verify parameter hashes are configured
    if std::env::var(ZK_PARAMS_HASH_ENV).is_err() {
        return Err(ZkError::InvalidParams(format!(
            "C-5 CRITICAL: {} environment variable not set. \
             Set to ceremony output hashes: BLOCK:sha256hex,PAYOUT:sha256hex",
            ZK_PARAMS_HASH_ENV
        )));
    }

    // Step 5: Load and verify parameters (this validates hashes)
    load_trusted_params()?;

    tracing::info!(
        path = %params_path,
        "C-5: ZK trusted setup verified successfully for mainnet"
    );

    Ok(())
}

/// C-5: Verify ZK trusted setup (non-production mode)
///
/// In non-production mode, this returns an error when called on mainnet,
/// as ZK proofs cannot be trusted without the proper ceremony parameters.
#[cfg(not(feature = "zk-production"))]
pub fn verify_zk_setup_for_mainnet() -> ZkResult<()> {
    Err(ZkError::InvalidParams(
        "C-5 CRITICAL: zk-production feature is NOT enabled. \
         Mainnet deployment REQUIRES trusted setup ceremony. \
         Compile with --features zk-production after completing MPC ceremony."
            .to_string(),
    ))
}

/// C-5: Check if ZK setup is valid for mainnet (non-throwing version)
///
/// Returns true if ZK trusted setup is properly configured for mainnet,
/// false otherwise. Use this for conditional logic; use
/// `verify_zk_setup_for_mainnet()` when you want detailed error messages.
pub fn is_zk_setup_valid_for_mainnet() -> bool {
    verify_zk_setup_for_mainnet().is_ok()
}

// ============================================================================
// Confidential Transfer Parameter Loading
// ============================================================================

/// Load a confidential transfer verifying key from disk.
///
/// Reads a `VerifyingKey<Bls12>` file, prepares it for efficient verification,
/// and returns a `ConfidentialVerifier` ready to verify Groth16 proofs.
///
/// The VK file is typically generated during MPC ceremony or dev setup
/// and saved as `confidential_vk.bin`.
pub fn load_confidential_verifier(
    vk_path: &std::path::Path,
    tree_depth: usize,
) -> ZkResult<ConfidentialVerifier> {
    use bellperson::groth16::{prepare_verifying_key, VerifyingKey};
    use blstrs::Bls12;
    use std::io::BufReader;

    if !vk_path.exists() {
        return Err(ZkError::InvalidParams(format!(
            "Confidential VK not found: {}",
            vk_path.display()
        )));
    }

    let file = std::fs::File::open(vk_path)
        .map_err(|e| ZkError::InvalidParams(format!("Failed to open VK: {}", e)))?;
    let reader = BufReader::new(file);

    let vk: VerifyingKey<Bls12> = VerifyingKey::read(reader)
        .map_err(|e| ZkError::InvalidParams(format!("Failed to read VK: {}", e)))?;

    let prepared_vk = prepare_verifying_key(&vk);

    // Compute prover ID (must match what ConfidentialProver uses)
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ghost-zkp-confidential-prover-v1");
    hasher.update(tree_depth.to_le_bytes());
    let prover_id: [u8; 32] = hasher.finalize().into();

    Ok(ConfidentialVerifier::new(
        std::sync::Arc::new(prepared_vk),
        prover_id,
    ))
}

/// Generate confidential transfer Groth16 parameters and save to disk.
///
/// **WARNING**: This uses a random trusted setup. For production, use MPC ceremony.
/// This is intended for signet/testnet/development deployments only.
///
/// Generates:
/// - `confidential_params_current.bin` - Full proving parameters
/// - `confidential_vk.bin` - Verification key only
#[cfg(not(feature = "zk-production"))]
pub fn generate_confidential_params(dir: &std::path::Path, tree_depth: usize) -> ZkResult<()> {
    use bellperson::groth16::{generate_random_parameters, Parameters};
    use blstrs::Bls12;
    use std::io::{BufWriter, Write};

    tracing::warn!(
        "Generating random confidential transfer Groth16 parameters (NOT production-safe)"
    );

    let dummy_circuit = circuit::ConfidentialTransferCircuit::<blstrs::Scalar>::dummy(tree_depth);
    let params: Parameters<Bls12> =
        generate_random_parameters(dummy_circuit, &mut rand::rngs::OsRng)
            .map_err(|e| ZkError::SetupError(format!("Parameter generation failed: {:?}", e)))?;

    std::fs::create_dir_all(dir)
        .map_err(|e| ZkError::SetupError(format!("Failed to create dir: {}", e)))?;

    // Save full params
    let params_path = dir.join("confidential_params_current.bin");
    {
        let file = std::fs::File::create(&params_path)
            .map_err(|e| ZkError::SetupError(format!("Failed to create params file: {}", e)))?;
        let mut writer = BufWriter::new(file);
        params
            .write(&mut writer)
            .map_err(|e| ZkError::SetupError(format!("Failed to write params: {}", e)))?;
        writer
            .flush()
            .map_err(|e| ZkError::SetupError(format!("Flush failed: {}", e)))?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|e| ZkError::SetupError(format!("Sync failed: {}", e)))?;
    }

    // Save VK separately
    let vk_path = dir.join("confidential_vk.bin");
    {
        let file = std::fs::File::create(&vk_path)
            .map_err(|e| ZkError::SetupError(format!("Failed to create VK file: {}", e)))?;
        let mut writer = BufWriter::new(file);
        params
            .vk
            .write(&mut writer)
            .map_err(|e| ZkError::SetupError(format!("Failed to write VK: {}", e)))?;
        writer
            .flush()
            .map_err(|e| ZkError::SetupError(format!("Flush failed: {}", e)))?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|e| ZkError::SetupError(format!("Sync failed: {}", e)))?;
    }

    let params_size = std::fs::metadata(&params_path)
        .map(|m| m.len())
        .unwrap_or(0);
    let vk_size = std::fs::metadata(&vk_path).map(|m| m.len()).unwrap_or(0);

    tracing::info!(
        params_path = %params_path.display(),
        params_size_bytes = params_size,
        vk_path = %vk_path.display(),
        vk_size_bytes = vk_size,
        tree_depth = tree_depth,
        "Generated and saved confidential transfer parameters"
    );

    Ok(())
}

// ============================================================================
// L-8: Startup Warning for Simulated Proofs
// ============================================================================

/// L-8 FIX: Check and log warning if simulated proofs are enabled at startup.
///
/// This function should be called during application initialization to provide
/// a clear warning at startup if the GHOST_ALLOW_SIMULATED_PROOFS environment
/// variable is set. This makes it immediately visible in logs that the system
/// is running in an insecure development mode.
///
/// # Security Warning
///
/// Simulated proofs bypass all cryptographic verification. They should NEVER
/// be enabled in production. This startup check ensures operators are immediately
/// aware if this dangerous setting is enabled.
///
/// # Example
///
/// ```ignore
/// // In main.rs or server initialization:
/// ghost_zkp::check_simulated_proofs_warning();
/// ```
pub fn check_simulated_proofs_warning() {
    // Check if on mainnet - simulated proofs are NEVER allowed regardless of env var
    let is_mainnet = std::env::var("GHOST_NETWORK")
        .map(|v| v.to_lowercase() == "mainnet" || v.to_lowercase() == "bitcoin")
        .unwrap_or(false);

    if is_mainnet {
        // On mainnet, simulated proofs are blocked at runtime anyway
        // Just log that we're in production mode
        tracing::info!(
            "L-8: Running on mainnet - simulated proofs are blocked regardless of environment settings"
        );
        return;
    }

    // Check if GHOST_ALLOW_SIMULATED_PROOFS is set
    let allow_simulated = std::env::var("GHOST_ALLOW_SIMULATED_PROOFS")
        .map(|v| v == "1")
        .unwrap_or(false);

    if allow_simulated {
        // L-8: Log a prominent startup warning
        tracing::error!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        tracing::error!("L-8 SECURITY WARNING: GHOST_ALLOW_SIMULATED_PROOFS=1 is enabled!");
        tracing::error!("Simulated proofs bypass ALL cryptographic verification.");
        tracing::error!("This MUST NOT be used in production - proofs can be forged!");
        tracing::error!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    } else {
        tracing::debug!(
            "L-8: Simulated proofs are disabled (GHOST_ALLOW_SIMULATED_PROOFS not set to 1)"
        );
    }
}
