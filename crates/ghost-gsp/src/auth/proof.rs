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
//| FILE: auth/proof.rs                                                                                                  |
//|======================================================================================================================|

//! WalletProof verification using Schnorr signatures
//!
//! This module provides secure verification of wallet proofs including:
//! - Schnorr signature verification (BIP-340)
//! - Wallet ID derivation validation (public key -> wallet ID)
//! - Timestamp validation
//! - Structure validation
//!
//! # H-12: L2-First Wallet Registration Design
//!
//! Ghost GSP intentionally does NOT require on-chain Bitcoin ownership for wallet
//! registration. This is a deliberate architectural decision for the following reasons:
//!
//! ## Why No On-Chain Proof Required
//!
//! 1. **L2-First User Experience**: New users should be able to create a wallet and
//!    receive L2 instant payments immediately, without needing to first acquire L1 Bitcoin.
//!    Requiring on-chain proof creates a chicken-and-egg problem for new users.
//!
//! 2. **Schnorr Signature Is Proof of Key Ownership**: The WalletProof mechanism already
//!    proves the user controls the private key corresponding to their wallet ID. This is
//!    cryptographically binding - the wallet ID is `SHA256(pubkey)[0:16]`, so only the key
//!    holder can create valid proofs.
//!
//! 3. **Ghost Locks Handle L1 Security**: When users want to send funds that require L1
//!    settlement (e.g., instant payments above the optimistic threshold), they must create
//!    a Ghost Lock which DOES require on-chain Bitcoin. The H-11 L1 UTXO verification
//!    ensures the lock exists and has sufficient confirmations before accepting instant
//!    payments.
//!
//! 4. **Cost-Free Attack Prevention**: Sybil attacks on registration are prevented by:
//!    - Rate limiting per IP (H-3)
//!    - Proof-of-work or CAPTCHA can be added at the API layer if needed
//!    - Registration without funds grants no economic benefit
//!    - All valuable operations (payments, locks) require actual funds
//!
//! ## Security Model
//!
//! | Operation | Requires L1 Funds? | Why |
//! |-----------|-------------------|-----|
//! | Registration | No | Just creates wallet ID mapping |
//! | Session creation | No | Just proves key ownership |
//! | Receive L2 payment | No | Receiving is always safe |
//! | Send L2 payment | No (from lock) | Deducted from sender's Ghost Lock |
//! | Create Ghost Lock | Yes | Must fund lock on L1 (H-11 verifies) |
//! | Accept instant payment | Yes | Sender's lock verified on L1 (H-11) |
//!
//! This design allows maximum accessibility while maintaining security where it matters:
//! at the point where actual value is transferred.

use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256};

use ghost_gsp_proto::{WalletId, WalletProof};

use crate::error::{GspError, GspResult};

/// Verify a Schnorr signature proof
///
/// This performs cryptographic signature verification only.
/// For full verification including wallet ID validation, use `verify_proof_with_wallet_id`.
pub fn verify_schnorr_proof(proof: &WalletProof) -> GspResult<bool> {
    let secp = Secp256k1::verification_only();

    // Get public key
    let pubkey_bytes = proof
        .public_key_bytes()
        .map_err(|e| GspError::SignatureVerification(format!("Invalid public key: {}", e)))?;

    let pubkey = XOnlyPublicKey::from_slice(&pubkey_bytes).map_err(|e| {
        GspError::SignatureVerification(format!("Invalid X-only public key: {}", e))
    })?;

    // Get signature
    let sig_bytes = proof
        .signature_bytes()
        .map_err(|e| GspError::SignatureVerification(format!("Invalid signature: {}", e)))?;

    let signature = Signature::from_slice(&sig_bytes).map_err(|e| {
        GspError::SignatureVerification(format!("Invalid Schnorr signature: {}", e))
    })?;

    // Create message hash (BIP-340 style)
    let msg_hash = tagged_hash("GhostGSP/proof", proof.message.as_bytes());
    let message = Message::from_digest(msg_hash);

    // Verify signature
    secp.verify_schnorr(&signature, &message, &pubkey)
        .map_err(|e| {
            GspError::SignatureVerification(format!("Signature verification failed: {}", e))
        })?;

    Ok(true)
}

/// Verify that a public key derives to the expected wallet ID
///
/// Wallet ID is computed as `SHA256(pubkey)[0:16]` encoded as hex (32 chars).
/// This prevents an attacker from providing a valid signature with a different
/// key than the one associated with the claimed wallet.
pub fn verify_wallet_ownership(proof: &WalletProof, claimed_wallet_id: &WalletId) -> GspResult<()> {
    // Get the public key bytes from the proof
    let pubkey_bytes = proof
        .public_key_bytes()
        .map_err(|e| GspError::SignatureVerification(format!("Invalid public key: {}", e)))?;

    // Derive wallet ID from the public key
    let derived_wallet_id = WalletId::from_pubkey(&pubkey_bytes);

    // Compare with claimed wallet ID
    if derived_wallet_id != *claimed_wallet_id {
        return Err(GspError::WalletIdMismatch);
    }

    Ok(())
}

/// Verify a wallet proof with full validation
///
/// This performs comprehensive verification:
/// 1. Structure validation (lengths, format)
/// 2. Timestamp validation (within tolerance)
/// 3. Schnorr signature verification
/// 4. Wallet ID derivation validation (pubkey -> wallet ID)
///
/// Use this for operations where wallet ownership must be proven.
pub fn verify_proof_with_wallet_id(
    proof: &WalletProof,
    expected_wallet_id: &WalletId,
) -> GspResult<()> {
    // 1. Validate structure
    proof
        .validate_structure()
        .map_err(|e| GspError::BadRequest(format!("Invalid proof structure: {}", e)))?;

    // 2. Validate timestamp
    if !proof.is_timestamp_valid() {
        return Err(GspError::BadRequest(
            "Proof timestamp expired or too far in future".to_string(),
        ));
    }

    // 3. Verify Schnorr signature
    verify_schnorr_proof(proof)?;

    // 4. Verify wallet ID derivation - critical for security!
    // This ensures the public key in the proof actually corresponds to the claimed wallet
    verify_wallet_ownership(proof, expected_wallet_id)?;

    Ok(())
}

/// Verify a proof and extract the derived wallet ID
///
/// This is useful for registration where we don't have an expected wallet ID yet.
/// Returns the wallet ID derived from the proof's public key.
pub fn verify_proof_and_extract_wallet_id(proof: &WalletProof) -> GspResult<WalletId> {
    // 1. Validate structure
    proof
        .validate_structure()
        .map_err(|e| GspError::BadRequest(format!("Invalid proof structure: {}", e)))?;

    // 2. Validate timestamp
    if !proof.is_timestamp_valid() {
        return Err(GspError::BadRequest(
            "Proof timestamp expired or too far in future".to_string(),
        ));
    }

    // 3. Verify Schnorr signature
    verify_schnorr_proof(proof)?;

    // 4. Derive and return wallet ID from public key
    let pubkey_bytes = proof
        .public_key_bytes()
        .map_err(|e| GspError::SignatureVerification(format!("Invalid public key: {}", e)))?;

    Ok(WalletId::from_pubkey(&pubkey_bytes))
}

/// Create a BIP-340 style tagged hash
fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(msg);

    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tagged_hash() {
        let hash = tagged_hash("test", b"message");
        assert_eq!(hash.len(), 32);

        // Same input should give same output
        let hash2 = tagged_hash("test", b"message");
        assert_eq!(hash, hash2);

        // Different tag should give different output
        let hash3 = tagged_hash("other", b"message");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_wallet_ownership_verification() {
        // Create a test public key
        let pubkey = [1u8; 32];
        let correct_wallet_id = WalletId::from_pubkey(&pubkey);
        let wrong_wallet_id = WalletId::from("0000000000000000000000000000dead".to_string());

        // Create a minimal proof for testing wallet ownership (not signature)
        let proof = WalletProof {
            timestamp: chrono::Utc::now().timestamp(),
            nonce: hex::encode([0u8; 16]),
            message: format!(
                "ghost-test:{}:{}",
                chrono::Utc::now().timestamp(),
                hex::encode([0u8; 16])
            ),
            signature: hex::encode([0u8; 64]), // Dummy signature
            public_key: hex::encode(pubkey),
        };

        // Correct wallet ID should pass
        assert!(verify_wallet_ownership(&proof, &correct_wallet_id).is_ok());

        // Wrong wallet ID should fail
        let result = verify_wallet_ownership(&proof, &wrong_wallet_id);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GspError::WalletIdMismatch));
    }

    #[test]
    fn test_wallet_id_derivation_consistency() {
        // Ensure wallet ID derivation is consistent
        let pubkey = [42u8; 32];
        let wallet_id_1 = WalletId::from_pubkey(&pubkey);
        let wallet_id_2 = WalletId::from_pubkey(&pubkey);

        assert_eq!(wallet_id_1, wallet_id_2);

        // Different pubkey should give different wallet ID
        let other_pubkey = [43u8; 32];
        let other_wallet_id = WalletId::from_pubkey(&other_pubkey);
        assert_ne!(wallet_id_1, other_wallet_id);
    }
}
