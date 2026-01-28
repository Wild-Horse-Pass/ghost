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

use crate::derivation::{compute_tweak, derive_shared_secret, derive_spend_key};
use crate::error::GhostKeyError;
use crate::ghost_id::GhostId;

/// Maximum nonce to try when detecting payments
pub const MAX_DETECTION_NONCE: u16 = 100;

/// Ghost Keys - Private keys for Ghost Pay
///
/// Consists of:
/// - Scan key: Used to detect incoming payments via ECDH
/// - Spend key: Used to spend received funds
#[derive(Clone)]
pub struct GhostKeys {
    scan_secret: SecretKey,
    spend_secret: SecretKey,
    scan_pubkey: PublicKey,
    spend_pubkey: PublicKey,
}

impl GhostKeys {
    /// Generate new random Ghost Keys
    pub fn generate() -> Self {
        let secp = Secp256k1::new();
        let (scan_secret, scan_pubkey) = secp.generate_keypair(&mut OsRng);
        let (spend_secret, spend_pubkey) = secp.generate_keypair(&mut OsRng);

        Self {
            scan_secret,
            spend_secret,
            scan_pubkey,
            spend_pubkey,
        }
    }

    /// Create from existing secret keys
    pub fn from_secrets(
        scan_secret: SecretKey,
        spend_secret: SecretKey,
    ) -> Self {
        let secp = Secp256k1::new();
        let scan_pubkey = PublicKey::from_secret_key(&secp, &scan_secret);
        let spend_pubkey = PublicKey::from_secret_key(&secp, &spend_secret);

        Self {
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
    /// The spend key for this output if it belongs to us, None otherwise
    pub fn detect_payment(
        &self,
        ephemeral_pubkey: &PublicKey,
        output_pubkey: &PublicKey,
        index: u32,
    ) -> Option<SecretKey> {
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
                    if &expected_pubkey == output_pubkey {
                        // Found it! Derive spend key
                        if let Ok(spend_key) = derive_spend_key(&self.spend_secret, &tweak) {
                            return Some(spend_key);
                        }
                    }
                }
            }
        }

        None
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
    pub fn derive_lock_pubkey(&self, index: u32) -> [u8; 33] {
        use sha2::{Sha256, Digest};

        let secp = Secp256k1::new();

        // Derive tweak: SHA256("ghost_lock" || spend_pubkey || index)
        let mut hasher = Sha256::new();
        hasher.update(b"ghost_lock");
        hasher.update(self.spend_pubkey.serialize());
        hasher.update(index.to_le_bytes());
        let tweak: [u8; 32] = hasher.finalize().into();

        // Derive lock pubkey = spend_pubkey + tweak*G
        if let Ok(tweak_secret) = SecretKey::from_slice(&tweak) {
            let tweak_pubkey = PublicKey::from_secret_key(&secp, &tweak_secret);
            if let Ok(lock_pubkey) = self.spend_pubkey.combine(&tweak_pubkey) {
                return lock_pubkey.serialize();
            }
        }

        // Fallback to spend pubkey if derivation fails
        self.spend_pubkey.serialize()
    }

    /// Derive a recovery pubkey for a specific index
    ///
    /// Recovery keys are used for timelock recovery paths.
    pub fn derive_recovery_pubkey(&self, index: u32) -> [u8; 33] {
        use sha2::{Sha256, Digest};

        let secp = Secp256k1::new();

        // Derive tweak: SHA256("ghost_recovery" || scan_pubkey || index)
        let mut hasher = Sha256::new();
        hasher.update(b"ghost_recovery");
        hasher.update(self.scan_pubkey.serialize());
        hasher.update(index.to_le_bytes());
        let tweak: [u8; 32] = hasher.finalize().into();

        // Derive recovery pubkey = scan_pubkey + tweak*G
        if let Ok(tweak_secret) = SecretKey::from_slice(&tweak) {
            let tweak_pubkey = PublicKey::from_secret_key(&secp, &tweak_secret);
            if let Ok(recovery_pubkey) = self.scan_pubkey.combine(&tweak_pubkey) {
                return recovery_pubkey.serialize();
            }
        }

        // Fallback to scan pubkey if derivation fails
        self.scan_pubkey.serialize()
    }

    /// Derive the secret key for a specific lock index
    pub fn derive_lock_secret(&self, index: u32) -> Result<SecretKey, GhostKeyError> {
        use sha2::{Sha256, Digest};

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
        use sha2::{Sha256, Digest};

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
            return Err(GhostKeyError::InvalidSecretKey("Invalid key length".to_string()));
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
