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
/// Uses counter-based k instead of output position, safe for output shuffling.
///
/// # Arguments
/// * `spend_pubkey` - Receiver's spend public key
/// * `shared_secret` - ECDH shared secret
/// * `k` - Sequential counter for multiple outputs to same recipient
///
/// # Returns
/// (output_pubkey, tweak) where output_pubkey = spend_pubkey + tweak*G
pub fn derive_payment_address_v2(
    spend_pubkey: &PublicKey,
    shared_secret: &[u8; 32],
    k: u32,
) -> Result<(PublicKey, [u8; 32]), GhostKeyError> {
    let secp = Secp256k1::new();

    // Compute tweak using v2 (position-independent)
    let tweak = compute_tweak_v2(shared_secret, k);

    // Compute output pubkey: spend_pubkey + tweak*G
    let tweak_secret = SecretKey::from_slice(&tweak)?;
    let tweak_pubkey = PublicKey::from_secret_key(&secp, &tweak_secret);
    let output_pubkey = spend_pubkey.combine(&tweak_pubkey)?;

    Ok((output_pubkey, tweak))
}

/// Compute the tweak for address derivation
///
/// tweak = SHA256(domain_separator || shared_secret || k)
///
/// This version uses a sequential counter k instead of output position,
/// making it safe to shuffle outputs (critical for Wraith Protocol).
///
/// # Arguments
/// * `shared_secret` - ECDH shared secret between sender and receiver
/// * `k` - Sequential counter (0, 1, 2, ...) for multiple outputs to same recipient
///
/// # Security
///
/// - Domain separator prevents collision with v1 tweaks
/// - k is independent of output position, so shuffling is safe
/// - Receiver can always recover by increasing max_k and re-scanning
pub fn compute_tweak_v2(shared_secret: &[u8; 32], k: u32) -> [u8; 32] {
    use crate::DOMAIN_SEPARATOR_V2;

    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_SEPARATOR_V2);
    hasher.update(shared_secret);
    hasher.update(k.to_le_bytes());
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
    hasher.update(tag_hash);
    hasher.update(tag_hash);
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
    fn test_tagged_hash() {
        let hash1 = tagged_hash("GhostPay/test", b"data");
        let hash2 = tagged_hash("GhostPay/test", b"data");
        let hash3 = tagged_hash("GhostPay/other", b"data");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_tweak_deterministic() {
        let shared_secret = [42u8; 32];

        let tweak1 = compute_tweak_v2(&shared_secret, 0);
        let tweak2 = compute_tweak_v2(&shared_secret, 0);

        assert_eq!(tweak1, tweak2, "Same inputs must produce same output");
    }

    #[test]
    fn test_tweak_unique_k() {
        let shared_secret = [42u8; 32];

        let tweak0 = compute_tweak_v2(&shared_secret, 0);
        let tweak1 = compute_tweak_v2(&shared_secret, 1);
        let tweak2 = compute_tweak_v2(&shared_secret, 2);
        let tweak100 = compute_tweak_v2(&shared_secret, 100);

        assert_ne!(tweak0, tweak1, "Different k must produce different tweaks");
        assert_ne!(tweak1, tweak2);
        assert_ne!(tweak0, tweak100);
    }

    #[test]
    fn test_tweak_domain_separator() {
        use crate::DOMAIN_SEPARATOR_V2;

        let shared_secret = [42u8; 32];

        // v2 tweak with domain separator
        let tweak_v2 = compute_tweak_v2(&shared_secret, 0);

        // Manual computation without domain separator (shouldn't match)
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        hasher.update(0u32.to_le_bytes());
        let tweak_no_domain: [u8; 32] = hasher.finalize().into();

        assert_ne!(
            tweak_v2, tweak_no_domain,
            "Domain separator must change the output"
        );

        // Verify domain separator is actually used
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_SEPARATOR_V2);
        hasher.update(shared_secret);
        hasher.update(0u32.to_le_bytes());
        let tweak_with_domain: [u8; 32] = hasher.finalize().into();

        assert_eq!(tweak_v2, tweak_with_domain);
    }

    #[test]
    fn test_tweak_endianness() {
        let shared_secret = [42u8; 32];

        // k=256 in little-endian: [0x00, 0x01, 0x00, 0x00]
        let tweak_256 = compute_tweak_v2(&shared_secret, 256);

        // k=1 in little-endian: [0x01, 0x00, 0x00, 0x00]
        let tweak_1 = compute_tweak_v2(&shared_secret, 1);

        assert_ne!(
            tweak_256, tweak_1,
            "Little-endian encoding must differentiate values"
        );
    }

    #[test]
    fn test_payment_derivation() {
        let secp = Secp256k1::new();
        let (spend_secret, spend_pubkey) = secp.generate_keypair(&mut OsRng);
        let shared_secret = [1u8; 32];

        let (output_pubkey, tweak) =
            derive_payment_address_v2(&spend_pubkey, &shared_secret, 0).unwrap();

        // Verify we can derive the spend key
        let derived_spend = derive_spend_key(&spend_secret, &tweak).unwrap();
        let derived_pubkey = PublicKey::from_secret_key(&secp, &derived_spend);

        assert_eq!(output_pubkey, derived_pubkey);
    }

    #[test]
    fn test_payment_derivation_multiple_k() {
        let secp = Secp256k1::new();
        let (_, spend_pubkey) = secp.generate_keypair(&mut OsRng);
        let shared_secret = [1u8; 32];

        let (addr0, _) = derive_payment_address_v2(&spend_pubkey, &shared_secret, 0).unwrap();
        let (addr1, _) = derive_payment_address_v2(&spend_pubkey, &shared_secret, 1).unwrap();
        let (addr2, _) = derive_payment_address_v2(&spend_pubkey, &shared_secret, 2).unwrap();

        assert_ne!(addr0, addr1, "Different k must produce different addresses");
        assert_ne!(addr1, addr2);
        assert_ne!(addr0, addr2);
    }
}
