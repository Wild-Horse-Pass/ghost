//! GSP authentication primitives.
//!
//! Implements the wallet side of the WalletProof Schnorr challenge-response scheme
//! used to authenticate to a Ghost Service Provider. Mirrors the shape consumed by
//! `crates/ghost-gsp/src/auth/proof.rs` on the server.
//!
//! Auth keypair derivation path: `m/352'/0'/0'/2'` — matches `ghost-light-wallet`'s
//! canonical layout (same seed across implementations → same wallet_id).
//! The path comment in `ghost-gsp-proto/auth.rs` (`m/352'/0'/0'/0/0`) is stale.
//! Wallet ID: `SHA256(x_only_pubkey)[0..16]` as hex.
//! Signature: BIP-340 Schnorr over `tagged_hash("GhostGSP/proof", message)`.

use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
use ghost_gsp_proto::WalletProof;
use sha2::{Digest, Sha256};

use crate::keystore::{Keystore, KeystoreError};
use crate::signer::{Signer, SignerError};

pub const AUTH_DERIVATION_PATH: &str = "m/352'/0'/0'/2'";

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error(transparent)]
    Keystore(#[from] KeystoreError),
    #[error(transparent)]
    Signer(#[from] SignerError),
    #[error("gsp proto: {0}")]
    GspProto(String),
    #[error("secp: {0}")]
    Secp(String),
}

/// Derive the GSP auth keypair from the unlocked keystore.
pub fn auth_keypair(keystore: &Keystore) -> Result<Keypair, AuthError> {
    let xprv = keystore.derive_xprv(AUTH_DERIVATION_PATH)?;
    let secp = Secp256k1::new();
    let priv_bytes = xprv.to_bytes();
    let priv_slice: &[u8] = &priv_bytes[..];
    Keypair::from_seckey_slice(&secp, priv_slice).map_err(|e| AuthError::Secp(e.to_string()))
}

/// 32-byte x-only public key for the auth keypair.
pub fn xonly_pubkey_bytes(keypair: &Keypair) -> [u8; 32] {
    keypair.x_only_public_key().0.serialize()
}

/// `SHA256(x_only_pubkey)[0..16]` hex — the static (non-rotating) wallet ID.
pub fn wallet_id_hex(keypair: &Keypair) -> String {
    let pk = xonly_pubkey_bytes(keypair);
    let hash = Sha256::digest(pk);
    hex::encode(&hash[0..16])
}

/// BIP-340 tagged hash. Matches `tagged_hash` in `ghost-gsp/src/auth/proof.rs`.
fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(msg);
    hasher.finalize().into()
}

/// Build and Schnorr-sign a `WalletProof` for a given action (e.g. `"register"`, `"session"`).
pub fn make_proof(keypair: &Keypair, action: &str) -> Result<WalletProof, AuthError> {
    let pk = xonly_pubkey_bytes(keypair);
    let mut proof =
        WalletProof::new(action, &pk).map_err(|e| AuthError::GspProto(e.to_string()))?;
    let msg_hash = tagged_hash("GhostGSP/proof", proof.message.as_bytes());
    let msg = Message::from_digest(msg_hash);
    let secp = Secp256k1::new();
    let sig = secp.sign_schnorr_no_aux_rand(&msg, keypair);
    proof.signature = hex::encode(sig.as_ref());
    Ok(proof)
}

/// Sign arbitrary `data` with the auth keypair using BIP-340 Schnorr.
///
/// Mirrors `ghost-light-wallet::signing::sign_data`: applies tagged hash
/// `"Ghost/Data/v1"` over the input bytes before signing. Used to sign the
/// `sighash` returned by ghost-pay's `PreparePayment` flow.
pub fn sign_data(keypair: &Keypair, data: &[u8]) -> [u8; 64] {
    let h = tagged_hash("Ghost/Data/v1", data);
    let msg = Message::from_digest(h);
    let secp = Secp256k1::new();
    let sig = secp.sign_schnorr_no_aux_rand(&msg, keypair);
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.as_ref());
    out
}

// ---------------------------------------------------------------------------
// Signer-trait API
// ---------------------------------------------------------------------------
//
// Phase 13: the keypair-based functions above hand out raw private material
// (a `Keypair`), which is fundamentally incompatible with hardware backings.
// The Signer-based variants below do the same work but only ever ask the
// signer for two things: the x-only pubkey and a Schnorr signature over a
// 32-byte digest. Both are operations a hardware device can perform without
// the secret leaving the device.
//
// The keypair-based functions are kept as-is so existing callers (and tests)
// don't churn — the daemon will migrate to these gradually.

/// 32-byte x-only auth pubkey for this signer.
pub fn xonly_pubkey_signer(signer: &dyn Signer) -> Result<[u8; 32], AuthError> {
    Ok(signer.xonly_pubkey_at(AUTH_DERIVATION_PATH)?)
}

/// `SHA256(x_only_pubkey)[0..16]` hex — the static (non-rotating) wallet ID.
pub fn wallet_id_hex_signer(signer: &dyn Signer) -> Result<String, AuthError> {
    let pk = xonly_pubkey_signer(signer)?;
    let hash = Sha256::digest(pk);
    Ok(hex::encode(&hash[0..16]))
}

/// Build and Schnorr-sign a `WalletProof` for a given action via a signer.
///
/// On a hardware backing this triggers a "confirm signing on device" prompt;
/// on the software backing it returns near-instantly. Either way the wire
/// shape of the proof is identical to `make_proof()`.
pub fn make_proof_signer(signer: &dyn Signer, action: &str) -> Result<WalletProof, AuthError> {
    let pk = xonly_pubkey_signer(signer)?;
    let mut proof =
        WalletProof::new(action, &pk).map_err(|e| AuthError::GspProto(e.to_string()))?;
    let msg_hash = tagged_hash("GhostGSP/proof", proof.message.as_bytes());
    let sig = signer.sign_schnorr_at(AUTH_DERIVATION_PATH, &msg_hash)?;
    proof.signature = hex::encode(sig);
    Ok(proof)
}

/// Sign arbitrary `data` via the auth signer using BIP-340 Schnorr,
/// applying the `"Ghost/Data/v1"` tagged hash like `sign_data` does.
pub fn sign_data_signer(signer: &dyn Signer, data: &[u8]) -> Result<[u8; 64], AuthError> {
    let h = tagged_hash("Ghost/Data/v1", data);
    Ok(signer.sign_schnorr_at(AUTH_DERIVATION_PATH, &h)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{schnorr::Signature, XOnlyPublicKey};

    const VECTOR_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn auth_keypair_is_deterministic() {
        let ks1 = Keystore::from_mnemonic(VECTOR_MNEMONIC).unwrap();
        let ks2 = Keystore::from_mnemonic(VECTOR_MNEMONIC).unwrap();
        let kp1 = auth_keypair(&ks1).unwrap();
        let kp2 = auth_keypair(&ks2).unwrap();
        assert_eq!(kp1.secret_bytes(), kp2.secret_bytes());
    }

    #[test]
    fn wallet_id_is_16_bytes_hex() {
        let ks = Keystore::from_mnemonic(VECTOR_MNEMONIC).unwrap();
        let kp = auth_keypair(&ks).unwrap();
        let id = wallet_id_hex(&kp);
        assert_eq!(id.len(), 32, "wallet_id must be 16 bytes = 32 hex chars");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn make_proof_signs_and_verifies() {
        let ks = Keystore::from_mnemonic(VECTOR_MNEMONIC).unwrap();
        let kp = auth_keypair(&ks).unwrap();
        let proof = make_proof(&kp, "register").unwrap();

        // Structural validation per ghost-gsp-proto.
        proof.validate_structure().expect("proof structure");

        // Reconstruct the message hash and verify the Schnorr signature using the
        // same code paths the GSP server uses (see ghost-gsp/src/auth/proof.rs).
        let msg_hash = tagged_hash("GhostGSP/proof", proof.message.as_bytes());
        let msg = Message::from_digest(msg_hash);
        let sig_bytes = hex::decode(&proof.signature).unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        let pk_bytes = hex::decode(&proof.public_key).unwrap();
        let pk = XOnlyPublicKey::from_slice(&pk_bytes).unwrap();
        let secp = Secp256k1::verification_only();
        secp.verify_schnorr(&sig, &msg, &pk)
            .expect("server-side verification path must accept this proof");
    }

    #[test]
    fn each_proof_has_a_unique_nonce() {
        let ks = Keystore::from_mnemonic(VECTOR_MNEMONIC).unwrap();
        let kp = auth_keypair(&ks).unwrap();
        let p1 = make_proof(&kp, "register").unwrap();
        let p2 = make_proof(&kp, "register").unwrap();
        assert_ne!(p1.nonce, p2.nonce);
        assert_ne!(p1.signature, p2.signature);
    }

    // Signer-trait path: same outputs as the keypair path, accessed via
    // &dyn Signer. The point of these tests is to prove the trait is
    // load-bearing — a hardware backend implementing Signer must produce
    // byte-identical proofs and ids to the software path.

    #[test]
    fn signer_path_xonly_matches_keypair_path() {
        use crate::signer::SoftwareSigner;
        let ks = Keystore::from_mnemonic(VECTOR_MNEMONIC).unwrap();
        let signer: &dyn Signer = &SoftwareSigner::new(&ks);
        let kp = auth_keypair(&ks).unwrap();
        assert_eq!(
            xonly_pubkey_signer(signer).unwrap(),
            xonly_pubkey_bytes(&kp)
        );
    }

    #[test]
    fn signer_path_wallet_id_matches_keypair_path() {
        use crate::signer::SoftwareSigner;
        let ks = Keystore::from_mnemonic(VECTOR_MNEMONIC).unwrap();
        let signer: &dyn Signer = &SoftwareSigner::new(&ks);
        let kp = auth_keypair(&ks).unwrap();
        assert_eq!(wallet_id_hex_signer(signer).unwrap(), wallet_id_hex(&kp));
    }

    #[test]
    fn signer_path_make_proof_verifies_under_server_path() {
        use crate::signer::SoftwareSigner;
        use bitcoin::secp256k1::schnorr::Signature;
        let ks = Keystore::from_mnemonic(VECTOR_MNEMONIC).unwrap();
        let signer: &dyn Signer = &SoftwareSigner::new(&ks);
        let proof = make_proof_signer(signer, "register").unwrap();
        proof.validate_structure().expect("proof structure");

        // Verify the Schnorr signature using the same code paths the GSP
        // server uses — proves the trait-based path produces a proof the
        // server will accept.
        let msg_hash = tagged_hash("GhostGSP/proof", proof.message.as_bytes());
        let msg = Message::from_digest(msg_hash);
        let sig_bytes = hex::decode(&proof.signature).unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        let pk_bytes = hex::decode(&proof.public_key).unwrap();
        let pk = XOnlyPublicKey::from_slice(&pk_bytes).unwrap();
        let secp = Secp256k1::verification_only();
        secp.verify_schnorr(&sig, &msg, &pk)
            .expect("server-side verification path must accept this proof");
    }

    #[test]
    fn signer_path_sign_data_verifies() {
        use crate::signer::SoftwareSigner;
        use bitcoin::secp256k1::schnorr::Signature;
        let ks = Keystore::from_mnemonic(VECTOR_MNEMONIC).unwrap();
        let signer: &dyn Signer = &SoftwareSigner::new(&ks);
        let data = b"some sighash bytes";
        let sig_bytes = sign_data_signer(signer, data).unwrap();

        // Re-derive the digest the same way sign_data_signer does and verify.
        let h = tagged_hash("Ghost/Data/v1", data);
        let msg = Message::from_digest(h);
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        let kp = auth_keypair(&ks).unwrap();
        let pk = kp.x_only_public_key().0;
        let secp = Secp256k1::verification_only();
        secp.verify_schnorr(&sig, &msg, &pk)
            .expect("sign_data_signer signature must verify");
    }
}
