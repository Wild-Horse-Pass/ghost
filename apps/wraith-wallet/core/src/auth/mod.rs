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

pub const AUTH_DERIVATION_PATH: &str = "m/352'/0'/0'/2'";

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error(transparent)]
    Keystore(#[from] KeystoreError),
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
}
