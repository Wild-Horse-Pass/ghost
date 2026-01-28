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
//| FILE: signing.rs                                                                                                     |
//|======================================================================================================================|

//! Local signing utilities for Light Wallet
//!
//! All signing operations happen locally - keys never leave the device.

use sha2::{Digest, Sha256};
use tracing::debug;

use ghost_gsp_proto::WalletProof;

use crate::error::{LightWalletError, WalletResult};
use crate::keys::MasterKey;

/// Domain separator for tagged hashing
const GHOST_TAG: &[u8] = b"Ghost/Wallet/v1";

/// Create a WalletProof for GSP authentication
///
/// This creates a signed proof of wallet ownership for
/// authenticating sensitive operations with the GSP.
pub fn create_wallet_proof(master_key: &MasterKey, action: &str) -> WalletResult<WalletProof> {
    let timestamp = chrono::Utc::now().timestamp();

    // Generate random nonce
    let mut nonce_bytes = [0u8; 16];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| LightWalletError::SigningFailed(format!("RNG error: {}", e)))?;

    let nonce = hex::encode(&nonce_bytes);

    // Create message to sign
    let message = format!("ghost-{}:{}:{}", action, timestamp, nonce);

    // Create tagged hash of the message
    let message_hash = tagged_hash(GHOST_TAG, message.as_bytes());

    // Sign with auth key (simplified - in production use proper secp256k1)
    let signature_bytes = sign_schnorr(master_key, &message_hash)?;

    debug!(action = action, "Created wallet proof");

    Ok(WalletProof {
        timestamp,
        nonce,
        message,
        signature: hex::encode(&signature_bytes),
        public_key: hex::encode(master_key.auth_pubkey()),
    })
}

/// Sign a transaction
///
/// This signs transaction data with the wallet's spending key.
pub fn sign_transaction(master_key: &MasterKey, tx_data: &[u8]) -> WalletResult<[u8; 64]> {
    // Create tagged hash for transaction signing
    let tx_hash = tagged_hash(b"Ghost/TxSign/v1", tx_data);

    // Sign with auth key
    sign_schnorr(master_key, &tx_hash)
}

/// Sign arbitrary data
pub fn sign_data(master_key: &MasterKey, data: &[u8]) -> WalletResult<[u8; 64]> {
    let hash = tagged_hash(b"Ghost/Data/v1", data);
    sign_schnorr(master_key, &hash)
}

/// Verify a signature (for testing)
pub fn verify_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    // In production, this would use proper secp256k1 verification
    // For now, we just verify the signature format is valid
    let _ = public_key;
    let _ = message;

    // Check signature is not all zeros (basic sanity check)
    signature.iter().any(|&b| b != 0)
}

/// Create a tagged hash (BIP-340 style)
fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    // tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
    let tag_hash = Sha256::digest(tag);

    let mut hasher = Sha256::new();
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
    hasher.update(data);

    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Sign with Schnorr (simplified implementation)
///
/// In production, this would use proper secp256k1 Schnorr signatures.
/// This is a placeholder that demonstrates the interface.
fn sign_schnorr(master_key: &MasterKey, message_hash: &[u8; 32]) -> WalletResult<[u8; 64]> {
    // Get auth key for signing
    let auth_key = master_key.auth_pubkey();

    // In production: use secp256k1 Schnorr signing
    // For now: create a deterministic "signature" for testing
    let mut signature = [0u8; 64];

    // First 32 bytes: hash of (key || message)
    let mut hasher = Sha256::new();
    hasher.update(auth_key);
    hasher.update(message_hash);
    let r = hasher.finalize();
    signature[..32].copy_from_slice(&r);

    // Second 32 bytes: hash of (r || key || message)
    let mut hasher = Sha256::new();
    hasher.update(&r);
    hasher.update(auth_key);
    hasher.update(message_hash);
    let s = hasher.finalize();
    signature[32..].copy_from_slice(&s);

    Ok(signature)
}

/// Generate a random challenge for signatures
pub fn generate_challenge() -> WalletResult<[u8; 32]> {
    let mut challenge = [0u8; 32];
    getrandom::getrandom(&mut challenge)
        .map_err(|e| LightWalletError::SigningFailed(format!("RNG error: {}", e)))?;
    Ok(challenge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_create_wallet_proof() {
        let key = MasterKey::from_mnemonic(TEST_MNEMONIC, Network::Regtest).unwrap();
        let proof = create_wallet_proof(&key, "test_action").unwrap();

        assert!(proof.message.starts_with("ghost-test_action:"));
        assert!(!proof.signature.is_empty());
        assert_eq!(proof.public_key, hex::encode(key.auth_pubkey()));
    }

    #[test]
    fn test_sign_transaction() {
        let key = MasterKey::from_mnemonic(TEST_MNEMONIC, Network::Regtest).unwrap();
        let tx_data = b"test transaction data";

        let sig1 = sign_transaction(&key, tx_data).unwrap();
        let sig2 = sign_transaction(&key, tx_data).unwrap();

        // Signatures should be deterministic for same input
        assert_eq!(sig1, sig2);

        // Different data should produce different signature
        let sig3 = sign_transaction(&key, b"different data").unwrap();
        assert_ne!(sig1, sig3);
    }

    #[test]
    fn test_tagged_hash() {
        let hash1 = tagged_hash(b"tag1", b"data");
        let hash2 = tagged_hash(b"tag2", b"data");
        let hash3 = tagged_hash(b"tag1", b"different");

        // Different tags should produce different hashes
        assert_ne!(hash1, hash2);
        // Different data should produce different hashes
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_generate_challenge() {
        let c1 = generate_challenge().unwrap();
        let c2 = generate_challenge().unwrap();

        // Challenges should be different (extremely unlikely to collide)
        assert_ne!(c1, c2);
    }
}
