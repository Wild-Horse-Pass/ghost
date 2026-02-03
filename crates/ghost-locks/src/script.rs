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
//! - Script path: Recovery after timelock expires

use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::{Builder, ScriptBuf};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{PublicKey, Secp256k1, XOnlyPublicKey};
use bitcoin::taproot::{TaprootBuilder, TaprootSpendInfo};

use crate::error::GhostLockError;
use crate::TimelockTier;

/// Build the recovery script for a Ghost Lock
///
/// Script structure:
/// ```text
/// <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP
/// <recovery_pubkey> OP_CHECKSIG
/// ```
pub fn build_recovery_script(recovery_pubkey: &XOnlyPublicKey, recovery_height: u32) -> ScriptBuf {
    Builder::new()
        // Timelock first (must be satisfied before signature check)
        .push_int(recovery_height as i64)
        .push_opcode(OP_CLTV)
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
/// - Script tree with recovery leaf
pub fn build_lock_script(
    lock_pubkey: &XOnlyPublicKey,
    recovery_pubkey: &XOnlyPublicKey,
    creation_height: u32,
    timelock_tier: TimelockTier,
) -> Result<TaprootSpendInfo, GhostLockError> {
    let secp = Secp256k1::new();

    // Recovery height = creation + timelock duration
    let recovery_height = timelock_tier.recovery_height(creation_height);

    // Build recovery script
    let recovery_script = build_recovery_script(recovery_pubkey, recovery_height);

    // Build taproot tree with single recovery leaf
    let builder = TaprootBuilder::new()
        .add_leaf(0, recovery_script)
        .map_err(|e| GhostLockError::ScriptError(format!("Failed to add leaf: {:?}", e)))?;

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
    use bitcoin::secp256k1::{rand::rngs::OsRng, Secp256k1, SecretKey};

    fn generate_x_only_key() -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let secret = SecretKey::new(&mut OsRng);
        let pubkey = PublicKey::from_secret_key(&secp, &secret);
        XOnlyPublicKey::from(pubkey)
    }

    #[test]
    fn test_build_recovery_script() {
        let recovery_pubkey = generate_x_only_key();
        let recovery_height = 850_000u32;

        let script = build_recovery_script(&recovery_pubkey, recovery_height);

        // Should contain CLTV and CHECKSIG
        let asm = script.to_asm_string();
        assert!(asm.contains("OP_CLTV"));
        assert!(asm.contains("OP_CHECKSIG"));
    }

    #[test]
    fn test_build_lock_script() {
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

        // Should have script path
        assert!(!spend_info.script_map().is_empty());
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
        let secret = SecretKey::new(&mut OsRng);
        let pubkey = PublicKey::from_secret_key(&secp, &secret);

        let x_only = to_x_only(&pubkey);
        assert_eq!(x_only.serialize().len(), 32);
    }
}
