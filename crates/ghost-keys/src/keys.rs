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
//| FILE: keys.rs                                                                                                        |
//|======================================================================================================================|

//! Ghost Keys - Scan and spend keypairs
//!
//! GhostKeys holds the private keys needed to receive and spend payments.

use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::derivation::{compute_tweak, derive_shared_secret, derive_spend_key};
use crate::error::GhostKeyError;
use crate::ghost_id::GhostId;

/// Maximum nonce to try when detecting payments
pub const MAX_DETECTION_NONCE: u16 = 100;

/// H-2: Wrapper for secret key bytes that gets zeroed on drop
///
/// This wrapper ensures the raw secret key bytes are properly zeroed when dropped.
/// While `secp256k1::SecretKey` has `non_secure_erase()`, using the `zeroize` crate
/// provides more reliable memory clearing with compiler barriers to prevent
/// optimization from removing the zeroing operation.
#[derive(Clone)]
struct ZeroizingSecretBytes([u8; 32]);

impl ZeroizingSecretBytes {
    fn from_secret_key(sk: &SecretKey) -> Self {
        Self(sk.secret_bytes())
    }
}

impl Zeroize for ZeroizingSecretBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for ZeroizingSecretBytes {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Ghost Keys - Private keys for Ghost Pay
///
/// Consists of:
/// - Scan key: Used to detect incoming payments via ECDH
/// - Spend key: Used to spend received funds
///
/// # Security (H-2: Secure Secret Key Erasure)
///
/// This struct uses the `zeroize` crate to securely erase secret key bytes
/// from memory when dropped. The `ZeroizingSecretBytes` wrapper ensures:
/// - Memory barriers prevent compiler from optimizing away the zeroing
/// - Both scan and spend secret bytes are cleared on drop
///
/// Note: While `zeroize` provides best-effort secure erasure, complete memory
/// zeroing cannot be absolutely guaranteed due to potential compiler-generated
/// copies. This is a defense-in-depth measure. See the [`zeroize`](https://docs.rs/zeroize)
/// crate documentation for detailed discussion.
#[derive(Clone)]
pub struct GhostKeys {
    /// H-2: Wrapped in ZeroizingSecretBytes for secure erasure on drop
    /// These fields exist solely to be zeroed when the struct is dropped
    #[allow(dead_code)]
    scan_secret_bytes: ZeroizingSecretBytes,
    #[allow(dead_code)]
    spend_secret_bytes: ZeroizingSecretBytes,
    /// Cached SecretKey for crypto operations
    scan_secret: SecretKey,
    spend_secret: SecretKey,
    scan_pubkey: PublicKey,
    spend_pubkey: PublicKey,
}

impl GhostKeys {
    /// Generate new random Ghost Keys
    ///
    /// # Security Note (M-CRYPTO-2)
    ///
    /// This operation involves cryptographic key generation which is computationally
    /// expensive. Public APIs calling this method should implement rate limiting to
    /// prevent resource exhaustion attacks. Consider:
    ///
    /// - Limiting key generation requests per IP/user
    /// - Adding delays between consecutive generation requests
    /// - Implementing CAPTCHA or proof-of-work for untrusted callers
    ///
    /// This function uses the system's CSPRNG (OsRng) for key material.
    pub fn generate() -> Self {
        let secp = Secp256k1::new();
        let (scan_secret, scan_pubkey) = secp.generate_keypair(&mut OsRng);
        let (spend_secret, spend_pubkey) = secp.generate_keypair(&mut OsRng);

        Self {
            scan_secret_bytes: ZeroizingSecretBytes::from_secret_key(&scan_secret),
            spend_secret_bytes: ZeroizingSecretBytes::from_secret_key(&spend_secret),
            scan_secret,
            spend_secret,
            scan_pubkey,
            spend_pubkey,
        }
    }

    /// Create from existing secret keys
    pub fn from_secrets(scan_secret: SecretKey, spend_secret: SecretKey) -> Self {
        let secp = Secp256k1::new();
        let scan_pubkey = PublicKey::from_secret_key(&secp, &scan_secret);
        let spend_pubkey = PublicKey::from_secret_key(&secp, &spend_secret);

        Self {
            scan_secret_bytes: ZeroizingSecretBytes::from_secret_key(&scan_secret),
            spend_secret_bytes: ZeroizingSecretBytes::from_secret_key(&spend_secret),
            scan_secret,
            spend_secret,
            scan_pubkey,
            spend_pubkey,
        }
    }

    /// Create from raw secret bytes
    pub fn from_bytes(
        scan_bytes: &[u8; 32],
        spend_bytes: &[u8; 32],
    ) -> Result<Self, GhostKeyError> {
        let scan_secret = SecretKey::from_slice(scan_bytes)?;
        let spend_secret = SecretKey::from_slice(spend_bytes)?;
        Ok(Self::from_secrets(scan_secret, spend_secret))
    }

    /// Get the scan secret key
    pub fn scan_secret(&self) -> &SecretKey {
        &self.scan_secret
    }

    /// Get the spend secret key
    pub fn spend_secret(&self) -> &SecretKey {
        &self.spend_secret
    }

    /// Get the scan public key
    pub fn scan_pubkey(&self) -> &PublicKey {
        &self.scan_pubkey
    }

    /// Get the spend public key
    pub fn spend_pubkey(&self) -> &PublicKey {
        &self.spend_pubkey
    }

    /// Get the Ghost ID (public identifier) for sharing
    pub fn ghost_id(&self) -> GhostId {
        GhostId::new(self.scan_pubkey, self.spend_pubkey)
    }

    /// Detect if a payment belongs to us
    ///
    /// Given an ephemeral pubkey from a transaction and an output pubkey,
    /// determine if the output belongs to us and return the spend key if so.
    ///
    /// # Arguments
    /// * `ephemeral_pubkey` - The ephemeral pubkey from OP_RETURN
    /// * `output_pubkey` - The output's public key
    /// * `index` - The output index
    ///
    /// # Returns
    /// - `Ok(Some(spend_key))` if the payment belongs to us
    /// - `Ok(None)` if the payment does not belong to us (normal case)
    /// - `Err(GhostKeyError)` if a cryptographic operation failed during detection
    ///
    /// # SEC-KEY-1
    /// This function now returns errors for cryptographic failures instead of
    /// silently returning None. This prevents funds from being marked as
    /// "not ours" when they actually are (but derivation failed).
    pub fn detect_payment(
        &self,
        ephemeral_pubkey: &PublicKey,
        output_pubkey: &PublicKey,
        index: u32,
    ) -> Result<Option<SecretKey>, GhostKeyError> {
        let secp = Secp256k1::new();

        // Compute shared secret
        let shared_secret = derive_shared_secret(&self.scan_secret, ephemeral_pubkey);

        // Try different nonces
        for nonce in 0..=MAX_DETECTION_NONCE {
            let tweak = compute_tweak(&shared_secret, index, nonce);

            // Expected pubkey = spend_pubkey + tweak*G
            if let Ok(tweak_secret) = SecretKey::from_slice(&tweak) {
                let tweak_pubkey = PublicKey::from_secret_key(&secp, &tweak_secret);
                if let Ok(expected_pubkey) = self.spend_pubkey.combine(&tweak_pubkey) {
                    // M-CRYPTO-3: Use constant-time comparison to prevent timing attacks
                    if expected_pubkey
                        .serialize()
                        .ct_eq(&output_pubkey.serialize())
                        .into()
                    {
                        // Found it! Derive spend key
                        // SEC-KEY-1: Return error instead of silently failing
                        match derive_spend_key(&self.spend_secret, &tweak) {
                            Ok(spend_key) => return Ok(Some(spend_key)),
                            Err(e) => {
                                // Payment detected but derivation failed - this is critical
                                return Err(GhostKeyError::DerivationError(format!(
                                    "Payment detected at index {} nonce {} but spend key derivation failed: {}",
                                    index, nonce, e
                                )));
                            }
                        }
                    }
                }
            }
        }

        // Not our payment (normal case)
        Ok(None)
    }

    /// Export secret keys as bytes
    pub fn export_secrets(&self) -> ([u8; 32], [u8; 32]) {
        (
            self.scan_secret.secret_bytes(),
            self.spend_secret.secret_bytes(),
        )
    }

    /// Export as a public-facing structure
    pub fn export(&self) -> GhostKeysPublicExport {
        GhostKeysPublicExport {
            scan_pubkey_hex: hex::encode(self.scan_pubkey.serialize()),
            spend_pubkey_hex: hex::encode(self.spend_pubkey.serialize()),
            ghost_id: self.ghost_id().to_string(),
        }
    }

    /// Derive a lock pubkey for a specific index
    ///
    /// This is used to create new Ghost Locks. Each lock gets a unique
    /// key derived from the spend key.
    ///
    /// # Errors
    ///
    /// Returns `GhostKeyError::DerivationError` if the derived tweak produces
    /// an invalid secret key or if the pubkey combination fails. This should
    /// be extremely rare in practice (only if SHA256 output happens to be 0 or
    /// \>= curve order), but callers must handle the error to avoid silent
    /// address reuse. See L-CRYPTO-2.
    pub fn derive_lock_pubkey(&self, index: u32) -> Result<[u8; 33], GhostKeyError> {
        use sha2::{Digest, Sha256};

        let secp = Secp256k1::new();

        // Derive tweak: SHA256("ghost_lock" || spend_pubkey || index)
        let mut hasher = Sha256::new();
        hasher.update(b"ghost_lock");
        hasher.update(self.spend_pubkey.serialize());
        hasher.update(index.to_le_bytes());
        let tweak: [u8; 32] = hasher.finalize().into();

        // Derive lock pubkey = spend_pubkey + tweak*G
        let tweak_secret = SecretKey::from_slice(&tweak).map_err(|e| {
            GhostKeyError::DerivationError(format!("Invalid tweak for lock pubkey: {}", e))
        })?;
        let tweak_pubkey = PublicKey::from_secret_key(&secp, &tweak_secret);
        let lock_pubkey = self.spend_pubkey.combine(&tweak_pubkey).map_err(|e| {
            GhostKeyError::DerivationError(format!("Failed to combine pubkeys for lock: {}", e))
        })?;

        Ok(lock_pubkey.serialize())
    }

    /// Derive a recovery pubkey for a specific index
    ///
    /// Recovery keys are used for timelock recovery paths.
    ///
    /// # Errors
    ///
    /// Returns `GhostKeyError::DerivationError` if the derived tweak produces
    /// an invalid secret key or if the pubkey combination fails. This should
    /// be extremely rare in practice (only if SHA256 output happens to be 0 or
    /// \>= curve order), but callers must handle the error to avoid silent
    /// address reuse. See L-CRYPTO-2.
    pub fn derive_recovery_pubkey(&self, index: u32) -> Result<[u8; 33], GhostKeyError> {
        use sha2::{Digest, Sha256};

        let secp = Secp256k1::new();

        // Derive tweak: SHA256("ghost_recovery" || scan_pubkey || index)
        let mut hasher = Sha256::new();
        hasher.update(b"ghost_recovery");
        hasher.update(self.scan_pubkey.serialize());
        hasher.update(index.to_le_bytes());
        let tweak: [u8; 32] = hasher.finalize().into();

        // Derive recovery pubkey = scan_pubkey + tweak*G
        let tweak_secret = SecretKey::from_slice(&tweak).map_err(|e| {
            GhostKeyError::DerivationError(format!("Invalid tweak for recovery pubkey: {}", e))
        })?;
        let tweak_pubkey = PublicKey::from_secret_key(&secp, &tweak_secret);
        let recovery_pubkey = self.scan_pubkey.combine(&tweak_pubkey).map_err(|e| {
            GhostKeyError::DerivationError(format!("Failed to combine pubkeys for recovery: {}", e))
        })?;

        Ok(recovery_pubkey.serialize())
    }

    /// Derive the secret key for a specific lock index
    pub fn derive_lock_secret(&self, index: u32) -> Result<SecretKey, GhostKeyError> {
        use sha2::{Digest, Sha256};

        // Same tweak as derive_lock_pubkey
        let mut hasher = Sha256::new();
        hasher.update(b"ghost_lock");
        hasher.update(self.spend_pubkey.serialize());
        hasher.update(index.to_le_bytes());
        let tweak: [u8; 32] = hasher.finalize().into();

        // lock_secret = spend_secret + tweak
        derive_spend_key(&self.spend_secret, &tweak)
    }

    /// Derive the recovery secret key for a specific lock index
    pub fn derive_recovery_secret(&self, index: u32) -> Result<SecretKey, GhostKeyError> {
        use sha2::{Digest, Sha256};

        // Same tweak as derive_recovery_pubkey
        let mut hasher = Sha256::new();
        hasher.update(b"ghost_recovery");
        hasher.update(self.scan_pubkey.serialize());
        hasher.update(index.to_le_bytes());
        let tweak: [u8; 32] = hasher.finalize().into();

        // recovery_secret = scan_secret + tweak
        derive_spend_key(&self.scan_secret, &tweak)
    }
}

/// H-2: Implement Drop to securely erase secret keys from memory.
///
/// Uses the `zeroize` crate for reliable memory clearing with compiler barriers.
/// The ZeroizingSecretBytes wrapper handles the raw bytes, and we also call
/// secp256k1's non_secure_erase as an additional layer of defense-in-depth.
impl Drop for GhostKeys {
    fn drop(&mut self) {
        // H-2: The ZeroizingSecretBytes fields are automatically zeroed via their Drop impl.
        // We also call non_secure_erase on the SecretKeys for belt-and-suspenders.
        self.scan_secret.non_secure_erase();
        self.spend_secret.non_secure_erase();
        // Note: scan_secret_bytes and spend_secret_bytes are zeroed by their own Drop
    }
}

/// Public export of Ghost Keys (no secrets)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostKeysPublicExport {
    pub scan_pubkey_hex: String,
    pub spend_pubkey_hex: String,
    pub ghost_id: String,
}

/// Serializable representation of Ghost Keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostKeysExport {
    pub scan_secret: String,
    pub spend_secret: String,
}

impl From<&GhostKeys> for GhostKeysExport {
    fn from(keys: &GhostKeys) -> Self {
        Self {
            scan_secret: hex::encode(keys.scan_secret.secret_bytes()),
            spend_secret: hex::encode(keys.spend_secret.secret_bytes()),
        }
    }
}

impl TryFrom<GhostKeysExport> for GhostKeys {
    type Error = GhostKeyError;

    fn try_from(export: GhostKeysExport) -> Result<Self, Self::Error> {
        let scan_bytes = hex::decode(&export.scan_secret)
            .map_err(|e| GhostKeyError::InvalidSecretKey(e.to_string()))?;
        let spend_bytes = hex::decode(&export.spend_secret)
            .map_err(|e| GhostKeyError::InvalidSecretKey(e.to_string()))?;

        if scan_bytes.len() != 32 || spend_bytes.len() != 32 {
            return Err(GhostKeyError::InvalidSecretKey(
                "Invalid key length".to_string(),
            ));
        }

        let scan_array: [u8; 32] = scan_bytes.try_into().unwrap();
        let spend_array: [u8; 32] = spend_bytes.try_into().unwrap();

        GhostKeys::from_bytes(&scan_array, &spend_array)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keys() {
        let keys = GhostKeys::generate();
        assert!(keys.scan_secret().secret_bytes().len() == 32);
        assert!(keys.spend_secret().secret_bytes().len() == 32);
    }

    #[test]
    fn test_from_bytes() {
        let keys1 = GhostKeys::generate();
        let (scan, spend) = keys1.export_secrets();

        let keys2 = GhostKeys::from_bytes(&scan, &spend).unwrap();
        assert_eq!(keys1.scan_pubkey(), keys2.scan_pubkey());
        assert_eq!(keys1.spend_pubkey(), keys2.spend_pubkey());
    }

    #[test]
    fn test_ghost_id() {
        let keys = GhostKeys::generate();
        let ghost_id = keys.ghost_id();
        assert_eq!(ghost_id.scan_pubkey(), keys.scan_pubkey());
        assert_eq!(ghost_id.spend_pubkey(), keys.spend_pubkey());
    }

    #[test]
    fn test_export_import() {
        let keys = GhostKeys::generate();
        let export = GhostKeysExport::from(&keys);
        let imported = GhostKeys::try_from(export).unwrap();

        assert_eq!(keys.scan_pubkey(), imported.scan_pubkey());
        assert_eq!(keys.spend_pubkey(), imported.spend_pubkey());
    }
}
