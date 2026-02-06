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
//| FILE: script.rs                                                                                                      |
//|======================================================================================================================|

//! P2TR script building for Ghost Locks
//!
//! Ghost Locks use Taproot outputs with:
//! - Key path: Normal spending with Ghost Key (efficient, private)
//! - Script path: Two-leaf tree with normal and recovery scripts
//!
//! # Script Structure (matches C++ implementation)
//!
//! The Taproot tree has two leaves at depth 1:
//! - Leaf 0: `<lock_pubkey> OP_CHECKSIG` (normal spending)
//! - Leaf 1: `<timelock> OP_CHECKSEQUENCEVERIFY OP_DROP <recovery_pubkey> OP_CHECKSIG`
//!
//! # nSequence Requirements
//!
//! When spending via the recovery script path (CSV), the transaction input's
//! nSequence field must be set correctly:
//! - nSequence must be < 0xFFFFFFFF (final) to enable CSV
//! - Use [`RECOVERY_NSEQUENCE`] (0xFFFFFFFE) for recovery transactions
//! - The relative timelock is encoded in blocks (not time-based)

use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::{Builder, ScriptBuf};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{PublicKey, Secp256k1, XOnlyPublicKey};
use bitcoin::taproot::{TaprootBuilder, TaprootSpendInfo};

use crate::error::GhostLockError;
use crate::TimelockTier;

/// nSequence value for recovery transactions spending via CSV.
///
/// When spending a Ghost Lock via the recovery script path, the transaction
/// input's nSequence must be set to this value (or lower) to enable
/// OP_CHECKSEQUENCEVERIFY. A value of 0xFFFFFFFF would disable all timelocks.
///
/// This value (0xFFFFFFFE) enables:
/// - Relative timelock validation (CSV)
/// - Opt-in RBF (Replace-By-Fee)
pub const RECOVERY_NSEQUENCE: u32 = 0xFFFFFFFE;

/// Build the normal spending script for a Ghost Lock (Leaf 0)
///
/// Script structure:
/// ```text
/// <lock_pubkey> OP_CHECKSIG
/// ```
///
/// This is used as a backup for script-path spending if key-path is unavailable.
pub fn build_normal_script(lock_pubkey: &XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(lock_pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Build the recovery script for a Ghost Lock (Leaf 1)
///
/// Script structure:
/// ```text
/// <timelock> OP_CHECKSEQUENCEVERIFY OP_DROP
/// <recovery_pubkey> OP_CHECKSIG
/// ```
///
/// # Arguments
/// * `recovery_pubkey` - The recovery public key
/// * `recovery_blocks` - Relative timelock in blocks (NOT absolute height)
///
/// # nSequence Requirement
///
/// When spending via this script path, the transaction input's nSequence
/// must be set to enable CSV validation. Use [`RECOVERY_NSEQUENCE`] (0xFFFFFFFE).
///
/// # Panics
/// Panics if recovery_blocks exceeds BIP-68 maximum (65535 blocks, ~455 days).
pub fn build_recovery_script(recovery_pubkey: &XOnlyPublicKey, recovery_blocks: u32) -> ScriptBuf {
    // SECURITY: Validate recovery_blocks is within BIP-68 limits
    // BIP-68 uses 16 bits for block count, max is 65535 (~455 days)
    assert!(
        recovery_blocks <= 65535,
        "recovery_blocks {} exceeds BIP-68 maximum of 65535",
        recovery_blocks
    );

    Builder::new()
        // Relative timelock first (must be satisfied before signature check)
        // CSV uses relative block count, not absolute height
        .push_int(recovery_blocks as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        // Then verify signature
        .push_x_only_key(recovery_pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Build the complete P2TR output for a Ghost Lock
///
/// Returns the taproot spend info containing:
/// - Internal key (lock_pubkey for key path spending)
/// - Script tree with two leaves at depth 1 (matches C++ implementation)
///
/// # Taproot Tree Structure
///
/// ```text
///        [root]
///        /    \
///   [normal]  [recovery]
///   depth 1   depth 1
/// ```
///
/// - Leaf 0 (depth 1): Normal script `<lock_pubkey> OP_CHECKSIG`
/// - Leaf 1 (depth 1): Recovery script `<timelock> OP_CSV OP_DROP <recovery_pubkey> OP_CHECKSIG`
///
/// # Arguments
/// * `lock_pubkey` - The lock public key (also used as internal key)
/// * `recovery_pubkey` - The recovery public key
/// * `_creation_height` - Block height when created (unused, kept for API compatibility)
/// * `timelock_tier` - The timelock tier determining relative block count
pub fn build_lock_script(
    lock_pubkey: &XOnlyPublicKey,
    recovery_pubkey: &XOnlyPublicKey,
    _creation_height: u32,
    timelock_tier: TimelockTier,
) -> Result<TaprootSpendInfo, GhostLockError> {
    let secp = Secp256k1::new();

    // Get relative block count for CSV (NOT absolute height)
    let recovery_blocks = timelock_tier.recovery_blocks();

    // Build both scripts for the two-leaf tree
    let normal_script = build_normal_script(lock_pubkey);
    let recovery_script = build_recovery_script(recovery_pubkey, recovery_blocks);

    // Build taproot tree with TWO leaves at depth 1 (balanced tree)
    // This matches the C++ implementation:
    //   builder.Add(1, normal_script, TAPROOT_LEAF_TAPSCRIPT);
    //   builder.Add(1, recovery_script, TAPROOT_LEAF_TAPSCRIPT);
    let builder = TaprootBuilder::new()
        .add_leaf(1, normal_script)
        .map_err(|e| GhostLockError::ScriptError(format!("Failed to add normal leaf: {:?}", e)))?
        .add_leaf(1, recovery_script)
        .map_err(|e| {
            GhostLockError::ScriptError(format!("Failed to add recovery leaf: {:?}", e))
        })?;

    // Finalize with internal key
    let spend_info = builder
        .finalize(&secp, *lock_pubkey)
        .map_err(|e| GhostLockError::ScriptError(format!("Failed to finalize: {:?}", e)))?;

    Ok(spend_info)
}

/// Compute the taproot output key (the actual scriptPubKey)
pub fn compute_output_key(
    lock_pubkey: &XOnlyPublicKey,
    recovery_pubkey: &XOnlyPublicKey,
    creation_height: u32,
    timelock_tier: TimelockTier,
) -> Result<XOnlyPublicKey, GhostLockError> {
    let spend_info =
        build_lock_script(lock_pubkey, recovery_pubkey, creation_height, timelock_tier)?;
    Ok(spend_info.output_key().to_x_only_public_key())
}

/// Convert a secp256k1 PublicKey to x-only format
pub fn to_x_only(pubkey: &PublicKey) -> XOnlyPublicKey {
    XOnlyPublicKey::from(*pubkey)
}

/// Parameters for building a recovery transaction input.
///
/// Use this to ensure correct nSequence value when spending via CSV.
#[derive(Debug, Clone, Copy)]
pub struct RecoveryInputParams {
    /// The nSequence value to use (should be RECOVERY_NSEQUENCE)
    pub nsequence: u32,
    /// The relative timelock in blocks that must have passed
    pub timelock_blocks: u32,
}

impl RecoveryInputParams {
    /// Create recovery input parameters for a given timelock tier.
    ///
    /// # Example
    /// ```
    /// use ghost_locks::{TimelockTier, RecoveryInputParams, RECOVERY_NSEQUENCE};
    ///
    /// let params = RecoveryInputParams::for_tier(TimelockTier::Standard);
    /// assert_eq!(params.nsequence, RECOVERY_NSEQUENCE);
    /// assert_eq!(params.timelock_blocks, 52_560); // ~1 year
    /// ```
    pub fn for_tier(tier: TimelockTier) -> Self {
        Self {
            nsequence: RECOVERY_NSEQUENCE,
            timelock_blocks: tier.recovery_blocks(),
        }
    }

    /// Check if the given nSequence value would enable CSV validation.
    ///
    /// For CSV to work, nSequence must be < 0xFFFFFFFF.
    pub fn is_valid_nsequence(nsequence: u32) -> bool {
        nsequence != u32::MAX
    }
}

/// Compute the tagged hash for Ghost Lock ID
pub fn ghost_lock_id(
    lock_pubkey: &XOnlyPublicKey,
    recovery_pubkey: &XOnlyPublicKey,
    creation_height: u32,
    denomination_sats: u64,
) -> [u8; 32] {
    let tag = b"GhostLock/v1";

    // Create tagged hash
    let mut engine = sha256::Hash::engine();

    // Tag hash (BIP-340 style)
    let tag_hash = sha256::Hash::hash(tag);
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);

    // Lock data
    engine.input(&lock_pubkey.serialize());
    engine.input(&recovery_pubkey.serialize());
    engine.input(&creation_height.to_le_bytes());
    engine.input(&denomination_sats.to_le_bytes());

    sha256::Hash::from_engine(engine).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use rand::RngCore;

    fn generate_x_only_key() -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        let secret = SecretKey::from_slice(&secret_bytes).expect("32 bytes, within curve order");
        let pubkey = PublicKey::from_secret_key(&secp, &secret);
        XOnlyPublicKey::from(pubkey)
    }

    #[test]
    fn test_build_recovery_script_uses_csv() {
        let recovery_pubkey = generate_x_only_key();
        // Use relative block count, not absolute height
        let recovery_blocks = 52_560u32; // ~1 year

        let script = build_recovery_script(&recovery_pubkey, recovery_blocks);

        // Should contain CSV (not CLTV!) and CHECKSIG
        let asm = script.to_asm_string();
        assert!(
            asm.contains("OP_CSV"),
            "Recovery script must use OP_CSV for relative timelock"
        );
        assert!(
            !asm.contains("OP_CLTV"),
            "Recovery script must NOT use OP_CLTV"
        );
        assert!(asm.contains("OP_CHECKSIG"));
        assert!(asm.contains("OP_DROP"));
    }

    #[test]
    fn test_build_normal_script() {
        let lock_pubkey = generate_x_only_key();
        let script = build_normal_script(&lock_pubkey);

        let asm = script.to_asm_string();
        assert!(asm.contains("OP_CHECKSIG"));
        // Should be simple: <pubkey> OP_CHECKSIG
        assert!(!asm.contains("OP_CSV"));
        assert!(!asm.contains("OP_CLTV"));
    }

    #[test]
    fn test_build_lock_script_two_leaves() {
        let lock_pubkey = generate_x_only_key();
        let recovery_pubkey = generate_x_only_key();

        let result = build_lock_script(
            &lock_pubkey,
            &recovery_pubkey,
            800_000,
            TimelockTier::Standard,
        );

        assert!(result.is_ok());
        let spend_info = result.unwrap();

        // Should have output key
        let _output_key = spend_info.output_key();

        // Should have TWO scripts in the script map (normal + recovery)
        let script_map = spend_info.script_map();
        assert!(!script_map.is_empty(), "Script map should not be empty");

        // Verify we have two script leaves by checking total scripts
        let total_scripts: usize = script_map.values().map(|v| v.len()).sum();
        assert_eq!(
            total_scripts, 2,
            "Should have exactly 2 script leaves (normal + recovery)"
        );
    }

    #[test]
    fn test_taproot_tree_structure_matches_cpp() {
        // This test verifies that the same keys produce the same output
        // regardless of creation_height (since we use relative timelocks)
        let lock_pubkey = generate_x_only_key();
        let recovery_pubkey = generate_x_only_key();

        let result1 = build_lock_script(
            &lock_pubkey,
            &recovery_pubkey,
            800_000,
            TimelockTier::Standard,
        )
        .unwrap();

        let result2 = build_lock_script(
            &lock_pubkey,
            &recovery_pubkey,
            900_000, // Different creation height
            TimelockTier::Standard,
        )
        .unwrap();

        // Output keys should be EQUAL since we use relative timelocks
        // (creation_height doesn't affect the script anymore)
        assert_eq!(
            result1.output_key().to_x_only_public_key(),
            result2.output_key().to_x_only_public_key(),
            "Output keys should match regardless of creation height (CSV uses relative blocks)"
        );
    }

    #[test]
    fn test_nsequence_constant() {
        // Verify nSequence is correct for CSV
        assert_eq!(RECOVERY_NSEQUENCE, 0xFFFFFFFE);
        assert!(RecoveryInputParams::is_valid_nsequence(RECOVERY_NSEQUENCE));
        assert!(!RecoveryInputParams::is_valid_nsequence(u32::MAX));
    }

    #[test]
    fn test_recovery_input_params() {
        let params = RecoveryInputParams::for_tier(TimelockTier::Standard);
        assert_eq!(params.nsequence, RECOVERY_NSEQUENCE);
        assert_eq!(params.timelock_blocks, 52_560); // ~1 year

        let short_params = RecoveryInputParams::for_tier(TimelockTier::Short);
        assert_eq!(short_params.timelock_blocks, 26_280); // ~6 months

        let long_params = RecoveryInputParams::for_tier(TimelockTier::Long);
        assert_eq!(long_params.timelock_blocks, 105_120); // ~2 years
    }

    #[test]
    fn test_ghost_lock_id_deterministic() {
        let lock_pubkey = generate_x_only_key();
        let recovery_pubkey = generate_x_only_key();

        let id1 = ghost_lock_id(&lock_pubkey, &recovery_pubkey, 800_000, 1_000_000);
        let id2 = ghost_lock_id(&lock_pubkey, &recovery_pubkey, 800_000, 1_000_000);

        assert_eq!(id1, id2);

        // Different inputs = different ID
        let id3 = ghost_lock_id(&lock_pubkey, &recovery_pubkey, 800_001, 1_000_000);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_to_x_only() {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        let secret = SecretKey::from_slice(&secret_bytes).expect("32 bytes, within curve order");
        let pubkey = PublicKey::from_secret_key(&secp, &secret);

        let x_only = to_x_only(&pubkey);
        assert_eq!(x_only.serialize().len(), 32);
    }
}
