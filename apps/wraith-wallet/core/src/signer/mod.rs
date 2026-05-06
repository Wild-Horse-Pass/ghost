//! Signer abstraction for the wallet.
//!
//! Defines a trait that hides the difference between an in-memory software
//! keystore and a future hardware wallet (Coldcard, Ledger, Trezor, …). All
//! signing-relevant code can hold a `&dyn Signer` and stay agnostic.
//!
//! Phase 13 first slice: trait definition + a thin software implementation
//! over [`Keystore`]. Existing call sites in [`auth`](crate::auth) and
//! [`light`](crate::light) keep using `Keystore` directly for now — they'll
//! migrate to `Signer` when a real hardware backend lands. Hardware-specific
//! impls (e.g. `LedgerSigner`) live in their own crates and are gated behind
//! cargo features.

use bitcoin::secp256k1::{Keypair, Message, Secp256k1, XOnlyPublicKey};

use crate::keystore::{Keystore, KeystoreError};

/// What the host knows about a signer at runtime — useful for the GUI to render
/// "Hardware (Ledger Nano X)" vs "Software (in-memory)".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerInfo {
    /// `"software"` for the in-memory keystore, vendor identifier (e.g.
    /// `"ledger"`, `"coldcard"`) for hardware.
    pub kind: String,
    /// Free-form human-readable identifier — model name, serial, etc.
    pub label: String,
    /// True if signing requires user approval on a separate device.
    pub interactive: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error(transparent)]
    Keystore(#[from] KeystoreError),
    #[error("secp error: {0}")]
    Secp(String),
    #[error("hardware error: {0}")]
    Hardware(String),
    #[error("operation not supported by this signer: {0}")]
    Unsupported(&'static str),
}

/// Capabilities every wallet signer must provide.
///
/// Object-safe (no generic methods, no `Self` in arg/return positions other
/// than `&self`) so callers can hold `Arc<dyn Signer>` or `&dyn Signer`.
pub trait Signer: Send + Sync {
    /// Static description of this signer (for UI / logs).
    fn info(&self) -> SignerInfo;

    /// 33-byte SEC1 compressed pubkey at the given BIP32 path.
    fn sec1_pubkey_at(&self, path: &str) -> Result<[u8; 33], SignerError>;

    /// 32-byte x-only pubkey at the given BIP32 path (for Schnorr / Taproot).
    fn xonly_pubkey_at(&self, path: &str) -> Result<[u8; 32], SignerError>;

    /// BIP-340 Schnorr-sign a 32-byte message digest with the key at `path`.
    /// Returns the 64-byte signature.
    fn sign_schnorr_at(
        &self,
        path: &str,
        message_digest: &[u8; 32],
    ) -> Result<[u8; 64], SignerError>;
}

/// Software signer backed by an unlocked [`Keystore`].
///
/// Wraps the existing BIP32 derivation + Schnorr signing already in the
/// keystore, exposing them through the [`Signer`] trait. Holds a reference
/// to the keystore so the daemon can drop both together.
pub struct SoftwareSigner<'a> {
    keystore: &'a Keystore,
}

impl<'a> SoftwareSigner<'a> {
    pub fn new(keystore: &'a Keystore) -> Self {
        Self { keystore }
    }
}

impl<'a> Signer for SoftwareSigner<'a> {
    fn info(&self) -> SignerInfo {
        SignerInfo {
            kind: "software".into(),
            label: "in-memory keystore".into(),
            interactive: false,
        }
    }

    fn sec1_pubkey_at(&self, path: &str) -> Result<[u8; 33], SignerError> {
        let xprv = self.keystore.derive_xprv(path)?;
        Ok(xprv.public_key().to_bytes())
    }

    fn xonly_pubkey_at(&self, path: &str) -> Result<[u8; 32], SignerError> {
        let xprv = self.keystore.derive_xprv(path)?;
        let secp = Secp256k1::new();
        let sec1: [u8; 33] = xprv.public_key().to_bytes();
        // Drop parity byte for x-only.
        XOnlyPublicKey::from_slice(&sec1[1..])
            .map(|x| x.serialize())
            .or_else(|_| {
                // Fall back through Keypair for the rare case the parity bit needs flipping.
                let priv_bytes = xprv.to_bytes();
                let priv_slice: &[u8] = &priv_bytes[..];
                let kp = Keypair::from_seckey_slice(&secp, priv_slice)
                    .map_err(|e| SignerError::Secp(e.to_string()))?;
                Ok(kp.x_only_public_key().0.serialize())
            })
    }

    fn sign_schnorr_at(
        &self,
        path: &str,
        message_digest: &[u8; 32],
    ) -> Result<[u8; 64], SignerError> {
        let xprv = self.keystore.derive_xprv(path)?;
        let secp = Secp256k1::new();
        let priv_bytes = xprv.to_bytes();
        let priv_slice: &[u8] = &priv_bytes[..];
        let kp = Keypair::from_seckey_slice(&secp, priv_slice)
            .map_err(|e| SignerError::Secp(e.to_string()))?;
        let msg = Message::from_digest(*message_digest);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
        let mut out = [0u8; 64];
        out.copy_from_slice(sig.as_ref());
        Ok(out)
    }
}

/// Placeholder hardware signer. Currently rejects every operation with
/// [`SignerError::Unsupported`]. Real vendor backends (Coldcard, Ledger,
/// Trezor, …) implement [`Signer`] in their own crates and are wired in
/// behind cargo features when they exist.
pub struct HardwareSignerStub {
    pub vendor: String,
    pub label: String,
}

impl Signer for HardwareSignerStub {
    fn info(&self) -> SignerInfo {
        SignerInfo {
            kind: self.vendor.clone(),
            label: self.label.clone(),
            interactive: true,
        }
    }

    fn sec1_pubkey_at(&self, _: &str) -> Result<[u8; 33], SignerError> {
        Err(SignerError::Unsupported("hardware signer not yet implemented"))
    }

    fn xonly_pubkey_at(&self, _: &str) -> Result<[u8; 32], SignerError> {
        Err(SignerError::Unsupported("hardware signer not yet implemented"))
    }

    fn sign_schnorr_at(&self, _: &str, _: &[u8; 32]) -> Result<[u8; 64], SignerError> {
        Err(SignerError::Unsupported("hardware signer not yet implemented"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{schnorr::Signature, Secp256k1, XOnlyPublicKey};

    const VECTOR_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn software_signer_round_trips_sign_verify() {
        let ks = Keystore::from_mnemonic(VECTOR_MNEMONIC).unwrap();
        let signer = SoftwareSigner::new(&ks);

        let path = "m/352'/0'/0'/2'";
        let xonly = signer.xonly_pubkey_at(path).unwrap();
        let digest = [0x42u8; 32];
        let sig = signer.sign_schnorr_at(path, &digest).unwrap();

        // Verify with the same secp the GSP server uses.
        let secp = Secp256k1::verification_only();
        let pk = XOnlyPublicKey::from_slice(&xonly).unwrap();
        let sig = Signature::from_slice(&sig).unwrap();
        let msg = Message::from_digest(digest);
        secp.verify_schnorr(&sig, &msg, &pk)
            .expect("software signer's Schnorr signature must verify");
    }

    #[test]
    fn software_signer_pubkey_paths_are_consistent() {
        let ks = Keystore::from_mnemonic(VECTOR_MNEMONIC).unwrap();
        let signer = SoftwareSigner::new(&ks);

        let path = "m/86'/531'/0'/0/0";
        let sec1 = signer.sec1_pubkey_at(path).unwrap();
        let xonly = signer.xonly_pubkey_at(path).unwrap();
        // x-only = SEC1 with parity byte stripped (when parity is even) — the
        // signer's `xonly_pubkey_at` always returns the canonical form.
        // What we can always check: same path → bytes 1..33 of SEC1 match xonly
        // when parity is even (0x02), or differ when parity is odd (0x03).
        assert!(sec1[0] == 0x02 || sec1[0] == 0x03);
        if sec1[0] == 0x02 {
            assert_eq!(&sec1[1..], &xonly[..]);
        }
    }

    #[test]
    fn software_signer_info() {
        let ks = Keystore::from_mnemonic(VECTOR_MNEMONIC).unwrap();
        let signer = SoftwareSigner::new(&ks);
        let info = signer.info();
        assert_eq!(info.kind, "software");
        assert!(!info.interactive);
    }

    #[test]
    fn hardware_stub_returns_unsupported() {
        let stub = HardwareSignerStub {
            vendor: "ledger".into(),
            label: "Nano X".into(),
        };
        assert_eq!(stub.info().kind, "ledger");
        assert!(stub.info().interactive);
        assert!(matches!(
            stub.sign_schnorr_at("m/0", &[0u8; 32]),
            Err(SignerError::Unsupported(_))
        ));
        assert!(matches!(
            stub.sec1_pubkey_at("m/0"),
            Err(SignerError::Unsupported(_))
        ));
    }

    #[test]
    fn signer_object_safe_via_dyn() {
        // Compile-time check: the trait is object-safe (`dyn Signer` works).
        let ks = Keystore::from_mnemonic(VECTOR_MNEMONIC).unwrap();
        let signer = SoftwareSigner::new(&ks);
        let dyn_signer: &dyn Signer = &signer;
        let _ = dyn_signer.info();
    }
}
