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
//| FILE: derivation.rs                                                                                                  |
//|======================================================================================================================|

//! Key derivation utilities for Ghost Keys
//!
//! Implements ECDH-based shared secret derivation and address tweaking.

use secp256k1::{ecdh::SharedSecret, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

use crate::error::GhostKeyError;

/// Derive shared secret using ECDH
///
/// shared_secret = SHA256(secret_key * public_key)
pub fn derive_shared_secret(secret_key: &SecretKey, public_key: &PublicKey) -> [u8; 32] {
    let shared = SharedSecret::new(public_key, secret_key);
    let mut hasher = Sha256::new();
    hasher.update(shared.as_ref());
    hasher.finalize().into()
}

/// Derive payment address from Ghost ID components
///
/// Given receiver's keys and sender's ephemeral key, derive the output pubkey.
///
/// # Arguments
/// * `spend_pubkey` - Receiver's spend public key
/// * `shared_secret` - ECDH shared secret
/// * `index` - Output index in transaction
/// * `nonce` - Random nonce for additional unlinkability
///
/// # Returns
/// (output_pubkey, tweak) where output_pubkey = spend_pubkey + tweak*G
pub fn derive_payment_address(
    spend_pubkey: &PublicKey,
    shared_secret: &[u8; 32],
    index: u32,
    nonce: u16,
) -> Result<(PublicKey, [u8; 32]), GhostKeyError> {
    let secp = Secp256k1::new();

    // Compute tweak: SHA256(shared_secret || index || nonce)
    let tweak = compute_tweak(shared_secret, index, nonce);

    // Compute output pubkey: spend_pubkey + tweak*G
    let tweak_secret = SecretKey::from_slice(&tweak)?;
    let tweak_pubkey = PublicKey::from_secret_key(&secp, &tweak_secret);
    let output_pubkey = spend_pubkey.combine(&tweak_pubkey)?;

    Ok((output_pubkey, tweak))
}

/// Compute the tweak for address derivation
///
/// tweak = SHA256(shared_secret || index || nonce)
pub fn compute_tweak(shared_secret: &[u8; 32], index: u32, nonce: u16) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    hasher.update(index.to_le_bytes());
    hasher.update(nonce.to_le_bytes());
    hasher.finalize().into()
}

/// Derive the spend key for a received payment
///
/// spend_key = spend_secret + tweak
pub fn derive_spend_key(
    spend_secret: &SecretKey,
    tweak: &[u8; 32],
) -> Result<SecretKey, GhostKeyError> {
    let tweak_secret = SecretKey::from_slice(tweak)?;
    let result = spend_secret.add_tweak(&secp256k1::Scalar::from(tweak_secret))?;
    Ok(result)
}

/// Tagged hash for domain separation (similar to BIP-340)
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_ecdh_symmetric() {
        let secp = Secp256k1::new();
        let (secret_a, pubkey_a) = secp.generate_keypair(&mut OsRng);
        let (secret_b, pubkey_b) = secp.generate_keypair(&mut OsRng);

        // A computes shared secret with B's pubkey
        let shared_ab = derive_shared_secret(&secret_a, &pubkey_b);

        // B computes shared secret with A's pubkey
        let shared_ba = derive_shared_secret(&secret_b, &pubkey_a);

        // Should be equal (ECDH property)
        assert_eq!(shared_ab, shared_ba);
    }

    #[test]
    fn test_tweak_deterministic() {
        let shared_secret = [42u8; 32];

        let tweak1 = compute_tweak(&shared_secret, 0, 0);
        let tweak2 = compute_tweak(&shared_secret, 0, 0);
        let tweak3 = compute_tweak(&shared_secret, 0, 1);
        let tweak4 = compute_tweak(&shared_secret, 1, 0);

        assert_eq!(tweak1, tweak2);
        assert_ne!(tweak1, tweak3);
        assert_ne!(tweak1, tweak4);
    }

    #[test]
    fn test_payment_derivation() {
        let secp = Secp256k1::new();
        let (spend_secret, spend_pubkey) = secp.generate_keypair(&mut OsRng);
        let shared_secret = [1u8; 32];

        let (output_pubkey, tweak) =
            derive_payment_address(&spend_pubkey, &shared_secret, 0, 0).unwrap();

        // Verify we can derive the spend key
        let derived_spend = derive_spend_key(&spend_secret, &tweak).unwrap();
        let derived_pubkey = PublicKey::from_secret_key(&secp, &derived_spend);

        assert_eq!(output_pubkey, derived_pubkey);
    }

    #[test]
    fn test_tagged_hash() {
        let hash1 = tagged_hash("GhostPay/test", b"data");
        let hash2 = tagged_hash("GhostPay/test", b"data");
        let hash3 = tagged_hash("GhostPay/other", b"data");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }
}
