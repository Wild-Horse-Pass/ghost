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
//! Uses BIP-340 Schnorr signatures for all signing operations.

use secp256k1::{Keypair, Message, Secp256k1, XOnlyPublicKey};
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

    let nonce = hex::encode(nonce_bytes);

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
        signature: hex::encode(signature_bytes),
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

/// Verify a BIP-340 Schnorr signature
///
/// Uses the secp256k1 library for proper cryptographic verification.
/// This function applies tagged hashing to the message before verification.
pub fn verify_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    // Create tagged hash of the message (same as signing uses GHOST_TAG)
    let message_hash = tagged_hash(GHOST_TAG, message);
    verify_signature_raw(public_key, &message_hash, signature)
}

/// Verify a BIP-340 Schnorr signature with a pre-hashed message
///
/// Uses the secp256k1 library for proper cryptographic verification.
/// This function expects the message to already be a 32-byte hash.
pub fn verify_signature_raw(public_key: &[u8; 32], message_hash: &[u8; 32], signature: &[u8; 64]) -> bool {
    let secp = Secp256k1::verification_only();

    // Parse the x-only public key
    let xonly_pubkey = match XOnlyPublicKey::from_slice(public_key) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // Parse the signature
    let schnorr_sig = match secp256k1::schnorr::Signature::from_slice(signature) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    // Create message from the hash
    let msg = Message::from_digest(*message_hash);

    // Verify the signature
    secp.verify_schnorr(&schnorr_sig, &msg, &xonly_pubkey).is_ok()
}

/// Create a tagged hash (BIP-340 style)
fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    // tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
    let tag_hash = Sha256::digest(tag);

    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(data);

    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Sign with BIP-340 Schnorr signature
///
/// Uses the secp256k1 library for proper cryptographic signing.
/// The signature is created using the auth secret key from the master key.
fn sign_schnorr(master_key: &MasterKey, message_hash: &[u8; 32]) -> WalletResult<[u8; 64]> {
    let secp = Secp256k1::new();

    // Get the auth secret key for signing
    let auth_secret = master_key.auth_secret();

    // Create a keypair from the secret key (required for Schnorr signing)
    let keypair = Keypair::from_secret_key(&secp, auth_secret);

    // Create the message from the hash
    let message = Message::from_digest(*message_hash);

    // Sign with BIP-340 Schnorr using a secure RNG
    let mut rng = rand::thread_rng();
    let signature = secp.sign_schnorr_with_rng(&message, &keypair, &mut rng);

    Ok(signature.serialize())
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

        // Sign the transaction
        let sig = sign_transaction(&key, tx_data).unwrap();

        // Verify the signature is not empty (64 bytes)
        assert_eq!(sig.len(), 64);
        assert!(sig.iter().any(|&b| b != 0), "Signature should not be all zeros");

        // Verify the signature using the verify function
        // Note: sign_transaction uses b"Ghost/TxSign/v1" tag internally
        let tx_hash = tagged_hash(b"Ghost/TxSign/v1", tx_data);
        let verify_result = verify_signature_raw(key.auth_pubkey(), &tx_hash, &sig);
        assert!(verify_result, "Signature should verify against the auth public key");

        // Different data should produce different signature
        let sig2 = sign_transaction(&key, b"different data").unwrap();
        assert_ne!(sig, sig2);
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
