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

//! P2WSH script building for Ghost Locks (Quantum-Safe)
//!
//! Ghost Locks use P2WSH (Pay-to-Witness-Script-Hash) outputs for quantum safety.
//! Unlike P2TR which exposes the public key on-chain, P2WSH only reveals a hash
//! until spending time.
//!
//! # Quantum Safety
//!
//! P2TR: `OP_1 <32-byte x-only pubkey>` - QUANTUM VULNERABLE (pubkey exposed)
//! P2WSH: `OP_0 <32-byte script hash>` - QUANTUM SAFE (pubkey hidden until spend)
//!
//! # Script Structure
//!
//! The witness script has two spending paths using IF/ELSE:
//!
//! ```text
//! OP_IF
//!     <lock_pubkey>           (33-byte compressed)
//!     OP_CHECKSIG
//! OP_ELSE
//!     <timelock_blocks>       (CSV sequence)
//!     OP_CHECKSEQUENCEVERIFY
//!     OP_DROP
//!     <recovery_pubkey>       (33-byte compressed)
//!     OP_CHECKSIG
//! OP_ENDIF
//! ```
//!
//! # Spending
//!
//! - Normal: `<signature> <1> <witness_script>`
//! - Recovery: `<signature> <0> <witness_script>` (after timelock)
//!
//! # nSequence Requirements
//!
//! When spending via the recovery path (CSV), the transaction input's
//! nSequence field must be set correctly:
//! - nSequence must be < 0xFFFFFFFF (final) to enable CSV
//! - Use [`RECOVERY_NSEQUENCE`] (0xFFFFFFFE) for recovery transactions
//! - The relative timelock is encoded in blocks (not time-based)

use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::{Builder, ScriptBuf};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::PublicKey;
use bitcoin::WScriptHash;

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

/// Build the P2WSH witness script for a Ghost Lock (two-path spending)
///
/// Script structure:
/// ```text
/// OP_IF
///     <lock_pubkey> OP_CHECKSIG
/// OP_ELSE
///     <timelock> OP_CHECKSEQUENCEVERIFY OP_DROP
///     <recovery_pubkey> OP_CHECKSIG
/// OP_ENDIF
/// ```
///
/// # Arguments
/// * `lock_pubkey` - The lock public key (33-byte compressed)
/// * `recovery_pubkey` - The recovery public key (33-byte compressed)
/// * `recovery_blocks` - Relative timelock in blocks (NOT absolute height)
///
/// # Panics
/// Panics if recovery_blocks exceeds BIP-68 maximum (65535 blocks, ~455 days).
pub fn build_wsh_witness_script(
    lock_pubkey: &PublicKey,
    recovery_pubkey: &PublicKey,
    recovery_blocks: u32,
) -> ScriptBuf {
    // SECURITY: Validate recovery_blocks is within BIP-68 limits
    // BIP-68 uses 16 bits for block count, max is 65535 (~455 days)
    assert!(
        recovery_blocks <= 65535,
        "recovery_blocks {} exceeds BIP-68 maximum of 65535",
        recovery_blocks
    );

    Builder::new()
        // IF branch: Normal spending with lock key
        .push_opcode(OP_IF)
        .push_slice(lock_pubkey.serialize())
        .push_opcode(OP_CHECKSIG)
        // ELSE branch: Recovery spending after timelock
        .push_opcode(OP_ELSE)
        .push_int(recovery_blocks as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_slice(recovery_pubkey.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ENDIF)
        .into_script()
}

/// Compute the SHA256 hash of a witness script (for P2WSH)
pub fn compute_wsh_script_hash(witness_script: &ScriptBuf) -> WScriptHash {
    WScriptHash::hash(witness_script.as_bytes())
}

/// Build the P2WSH scriptPubKey from a witness script
///
/// Result: `OP_0 <32-byte SHA256(witness_script)>`
pub fn build_p2wsh_script_pubkey(witness_script: &ScriptBuf) -> ScriptBuf {
    let script_hash = compute_wsh_script_hash(witness_script);
    let hash_bytes: &[u8; 32] = script_hash.as_ref();
    Builder::new()
        .push_opcode(OP_PUSHBYTES_0)
        .push_slice(hash_bytes)
        .into_script()
}

/// Build the complete P2WSH output info for a Ghost Lock
///
/// Returns (witness_script, script_pubkey) where:
/// - witness_script: The full script needed to spend (must be stored by client)
/// - script_pubkey: The P2WSH output script (OP_0 <hash>)
///
/// # Arguments
/// * `lock_pubkey` - The lock public key (33-byte compressed)
/// * `recovery_pubkey` - The recovery public key (33-byte compressed)
/// * `_creation_height` - Block height when created (unused, kept for API compatibility)
/// * `timelock_tier` - The timelock tier determining relative block count
pub fn build_lock_script(
    lock_pubkey: &PublicKey,
    recovery_pubkey: &PublicKey,
    _creation_height: u32,
    timelock_tier: TimelockTier,
) -> Result<(ScriptBuf, ScriptBuf), GhostLockError> {
    // Get relative block count for CSV (NOT absolute height)
    let recovery_blocks = timelock_tier.recovery_blocks();

    // Build the witness script
    let witness_script = build_wsh_witness_script(lock_pubkey, recovery_pubkey, recovery_blocks);

    // Build the P2WSH scriptPubKey
    let script_pubkey = build_p2wsh_script_pubkey(&witness_script);

    Ok((witness_script, script_pubkey))
}

/// Build witness stack for normal spend (IF branch)
///
/// Witness: `<signature> <1> <witness_script>`
pub fn build_normal_witness(signature: &[u8], witness_script: &ScriptBuf) -> Vec<Vec<u8>> {
    vec![
        signature.to_vec(),       // Signature
        vec![0x01],               // OP_TRUE (take IF branch)
        witness_script.to_bytes(), // The witness script
    ]
}

/// Build witness stack for recovery spend (ELSE branch)
///
/// Witness: `<signature> <0> <witness_script>`
///
/// Note: The transaction input's nSequence must be set to [`RECOVERY_NSEQUENCE`]
/// for CSV to validate properly.
pub fn build_recovery_witness(signature: &[u8], witness_script: &ScriptBuf) -> Vec<Vec<u8>> {
    vec![
        signature.to_vec(),       // Signature
        vec![],                   // Empty (OP_FALSE, take ELSE branch)
        witness_script.to_bytes(), // The witness script
    ]
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
    lock_pubkey: &PublicKey,
    recovery_pubkey: &PublicKey,
    creation_height: u32,
    denomination_sats: u64,
) -> [u8; 32] {
    let tag = b"GhostLock/v2"; // Updated version for P2WSH

    // Create tagged hash
    let mut engine = sha256::Hash::engine();

    // Tag hash (BIP-340 style)
    let tag_hash = sha256::Hash::hash(tag);
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);

    // Lock data (using full 33-byte compressed pubkeys)
    engine.input(&lock_pubkey.serialize());
    engine.input(&recovery_pubkey.serialize());
    engine.input(&creation_height.to_le_bytes());
    engine.input(&denomination_sats.to_le_bytes());

    sha256::Hash::from_engine(engine).to_byte_array()
}

/// Check if a scriptPubKey is a P2WSH output
///
/// P2WSH: exactly 34 bytes, starts with OP_0 (0x00) + PUSH32 (0x20)
pub fn is_p2wsh(script: &ScriptBuf) -> bool {
    let bytes = script.as_bytes();
    bytes.len() == 34 && bytes[0] == 0x00 && bytes[1] == 0x20
}

/// Check if a scriptPubKey is a P2TR output (quantum-vulnerable)
///
/// P2TR: exactly 34 bytes, starts with OP_1 (0x51) + PUSH32 (0x20)
pub fn is_p2tr(script: &ScriptBuf) -> bool {
    let bytes = script.as_bytes();
    bytes.len() == 34 && bytes[0] == 0x51 && bytes[1] == 0x20
}

/// Validate that a script is NOT P2TR (quantum-safe enforcement)
pub fn validate_no_p2tr(script: &ScriptBuf) -> Result<(), GhostLockError> {
    if is_p2tr(script) {
        return Err(GhostLockError::QuantumUnsafe(
            "P2TR outputs rejected for quantum safety. Use P2WSH instead.".into(),
        ));
    }
    Ok(())
}

/// Check if a Bitcoin address string is quantum-safe
///
/// P2WPKH: bc1q... (42 chars, 20-byte program) - SAFE
/// P2WSH:  bc1q... (62 chars, 32-byte program) - SAFE
/// P2TR:   bc1p... (62 chars) - QUANTUM VULNERABLE (rejected)
///
/// Returns true for P2WPKH and P2WSH addresses, false for P2TR.
pub fn is_quantum_safe_address(addr: &str) -> bool {
    // P2TR addresses start with bc1p (mainnet) or tb1p (testnet/signet)
    if addr.starts_with("bc1p") || addr.starts_with("tb1p") || addr.starts_with("bcrt1p") {
        return false; // P2TR - quantum vulnerable
    }
    // P2WPKH and P2WSH addresses start with bc1q (mainnet) or tb1q (testnet/signet)
    if addr.starts_with("bc1q")
        || addr.starts_with("tb1q")
        || addr.starts_with("bcrt1q")
        || addr.starts_with("1")  // Legacy P2PKH - safe (hash-based)
        || addr.starts_with("3")  // Legacy P2SH - safe (hash-based)
        || addr.starts_with("m")  // Testnet P2PKH
        || addr.starts_with("n")  // Testnet P2PKH
        || addr.starts_with("2")  // Testnet P2SH
    {
        return true; // Hash-based - quantum safe
    }
    false // Unknown format
}

/// Error message for P2TR rejection
pub const P2TR_REJECTION_MSG: &str =
    "Rejected: P2TR addresses (bc1p...) are quantum-vulnerable. Use P2WPKH (bc1q...) for safety.";

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use rand::RngCore;

    fn generate_pubkey() -> PublicKey {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        let secret = SecretKey::from_slice(&secret_bytes).expect("32 bytes, within curve order");
        PublicKey::from_secret_key(&secp, &secret)
    }

    #[test]
    fn test_wsh_witness_script_structure() {
        let lock_pubkey = generate_pubkey();
        let recovery_pubkey = generate_pubkey();
        let recovery_blocks = 52_560u32; // ~1 year

        let script = build_wsh_witness_script(&lock_pubkey, &recovery_pubkey, recovery_blocks);
        let asm = script.to_asm_string();

        // Should contain IF/ELSE/ENDIF structure
        assert!(asm.contains("OP_IF"), "Script must contain OP_IF");
        assert!(asm.contains("OP_ELSE"), "Script must contain OP_ELSE");
        assert!(asm.contains("OP_ENDIF"), "Script must contain OP_ENDIF");

        // Should contain CSV for recovery path
        assert!(
            asm.contains("OP_CSV"),
            "Recovery path must use OP_CSV for relative timelock"
        );
        assert!(
            !asm.contains("OP_CLTV"),
            "Must NOT use OP_CLTV (absolute timelock)"
        );

        // Should contain CHECKSIG for both paths
        let checksig_count = asm.matches("OP_CHECKSIG").count();
        assert_eq!(checksig_count, 2, "Should have 2 CHECKSIG opcodes");
    }

    #[test]
    fn test_p2wsh_script_pubkey_format() {
        let lock_pubkey = generate_pubkey();
        let recovery_pubkey = generate_pubkey();

        let witness_script =
            build_wsh_witness_script(&lock_pubkey, &recovery_pubkey, 52_560);
        let script_pubkey = build_p2wsh_script_pubkey(&witness_script);

        // P2WSH: OP_0 <32-byte hash>
        let bytes = script_pubkey.as_bytes();
        assert_eq!(bytes.len(), 34, "P2WSH scriptPubKey must be 34 bytes");
        assert_eq!(bytes[0], 0x00, "First byte must be OP_0");
        assert_eq!(bytes[1], 0x20, "Second byte must be PUSH32");

        // Verify it's recognized as P2WSH
        assert!(is_p2wsh(&script_pubkey), "Should be recognized as P2WSH");
        assert!(!is_p2tr(&script_pubkey), "Should NOT be recognized as P2TR");
    }

    #[test]
    fn test_wsh_hash_deterministic() {
        let lock_pubkey = generate_pubkey();
        let recovery_pubkey = generate_pubkey();

        let script1 = build_wsh_witness_script(&lock_pubkey, &recovery_pubkey, 52_560);
        let script2 = build_wsh_witness_script(&lock_pubkey, &recovery_pubkey, 52_560);

        assert_eq!(script1, script2, "Same inputs must produce same script");

        let hash1 = compute_wsh_script_hash(&script1);
        let hash2 = compute_wsh_script_hash(&script2);

        assert_eq!(hash1, hash2, "Same script must produce same hash");
    }

    #[test]
    fn test_build_lock_script() {
        let lock_pubkey = generate_pubkey();
        let recovery_pubkey = generate_pubkey();

        let result = build_lock_script(
            &lock_pubkey,
            &recovery_pubkey,
            800_000,
            TimelockTier::Standard,
        );

        assert!(result.is_ok());
        let (witness_script, script_pubkey) = result.unwrap();

        // Witness script should be non-empty
        assert!(!witness_script.is_empty());

        // Script pubkey should be P2WSH format
        assert!(is_p2wsh(&script_pubkey));
    }

    #[test]
    fn test_creation_height_does_not_affect_output() {
        let lock_pubkey = generate_pubkey();
        let recovery_pubkey = generate_pubkey();

        let (_, script1) = build_lock_script(
            &lock_pubkey,
            &recovery_pubkey,
            800_000,
            TimelockTier::Standard,
        )
        .unwrap();

        let (_, script2) = build_lock_script(
            &lock_pubkey,
            &recovery_pubkey,
            900_000, // Different creation height
            TimelockTier::Standard,
        )
        .unwrap();

        // Script pubkeys should be EQUAL since we use relative timelocks
        assert_eq!(
            script1, script2,
            "P2WSH output should be identical regardless of creation height"
        );
    }

    #[test]
    fn test_normal_witness_stack() {
        let signature = vec![0x30; 64]; // Mock signature
        let lock_pubkey = generate_pubkey();
        let recovery_pubkey = generate_pubkey();
        let witness_script =
            build_wsh_witness_script(&lock_pubkey, &recovery_pubkey, 52_560);

        let witness = build_normal_witness(&signature, &witness_script);

        assert_eq!(witness.len(), 3, "Normal witness should have 3 elements");
        assert_eq!(witness[0], signature, "First element should be signature");
        assert_eq!(witness[1], vec![0x01], "Second element should be 0x01 (IF branch)");
        assert_eq!(witness[2], witness_script.to_bytes(), "Third element should be witness script");
    }

    #[test]
    fn test_recovery_witness_stack() {
        let signature = vec![0x30; 64]; // Mock signature
        let lock_pubkey = generate_pubkey();
        let recovery_pubkey = generate_pubkey();
        let witness_script =
            build_wsh_witness_script(&lock_pubkey, &recovery_pubkey, 52_560);

        let witness = build_recovery_witness(&signature, &witness_script);

        assert_eq!(witness.len(), 3, "Recovery witness should have 3 elements");
        assert_eq!(witness[0], signature, "First element should be signature");
        assert!(witness[1].is_empty(), "Second element should be empty (ELSE branch)");
        assert_eq!(witness[2], witness_script.to_bytes(), "Third element should be witness script");
    }

    #[test]
    fn test_nsequence_constant() {
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
        assert_eq!(long_params.timelock_blocks, 65_535); // BIP-68 max (~455 days)
    }

    #[test]
    fn test_ghost_lock_id_deterministic() {
        let lock_pubkey = generate_pubkey();
        let recovery_pubkey = generate_pubkey();

        let id1 = ghost_lock_id(&lock_pubkey, &recovery_pubkey, 800_000, 1_000_000);
        let id2 = ghost_lock_id(&lock_pubkey, &recovery_pubkey, 800_000, 1_000_000);

        assert_eq!(id1, id2);

        // Different inputs = different ID
        let id3 = ghost_lock_id(&lock_pubkey, &recovery_pubkey, 800_001, 1_000_000);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_quantum_safe_address_detection() {
        // P2WPKH and P2WSH are safe
        assert!(is_quantum_safe_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
        assert!(is_quantum_safe_address("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"));
        assert!(is_quantum_safe_address("bcrt1qw508d6qejxtdg4y5r3zarvaryvg6kdaj"));

        // P2TR is NOT safe
        assert!(!is_quantum_safe_address("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"));
        assert!(!is_quantum_safe_address("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c"));

        // Legacy addresses are safe (hash-based)
        assert!(is_quantum_safe_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));
        assert!(is_quantum_safe_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"));
    }

    #[test]
    fn test_validate_no_p2tr() {
        let lock_pubkey = generate_pubkey();
        let recovery_pubkey = generate_pubkey();

        // P2WSH should pass
        let witness_script = build_wsh_witness_script(&lock_pubkey, &recovery_pubkey, 52_560);
        let p2wsh = build_p2wsh_script_pubkey(&witness_script);
        assert!(validate_no_p2tr(&p2wsh).is_ok());

        // Simulated P2TR should fail
        let fake_p2tr = Builder::new()
            .push_opcode(OP_PUSHNUM_1)
            .push_slice(&[0u8; 32])
            .into_script();
        assert!(validate_no_p2tr(&fake_p2tr).is_err());
    }
}
