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
//| FILE: ghost_id.rs                                                                                                    |
//|======================================================================================================================|

//! Ghost ID - Public identifier for receiving Ghost Pay payments
//!
//! A Ghost ID is the public component shared with senders. It contains
//! the scan pubkey and spend pubkey encoded in bech32 format.

use bech32::{Bech32m, Hrp};
use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::derivation::{derive_payment_address_v2, derive_shared_secret};
use crate::error::GhostKeyError;
use crate::GHOST_ID_HRP;

/// Ghost ID - Public identifier for receiving payments
///
/// Contains scan_pubkey and spend_pubkey, encoded as bech32m.
/// Format: ghost1<bech32m_encoded_data>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhostId {
    scan_pubkey: PublicKey,
    spend_pubkey: PublicKey,
}

impl GhostId {
    /// Create a new Ghost ID from public keys
    pub fn new(scan_pubkey: PublicKey, spend_pubkey: PublicKey) -> Self {
        Self {
            scan_pubkey,
            spend_pubkey,
        }
    }

    /// Create from raw bytes
    pub fn from_bytes(
        scan_bytes: &[u8; 33],
        spend_bytes: &[u8; 33],
    ) -> Result<Self, GhostKeyError> {
        let scan_pubkey = PublicKey::from_slice(scan_bytes)?;
        let spend_pubkey = PublicKey::from_slice(spend_bytes)?;
        Ok(Self::new(scan_pubkey, spend_pubkey))
    }

    /// Get the scan public key
    pub fn scan_pubkey(&self) -> &PublicKey {
        &self.scan_pubkey
    }

    /// Get the spend public key
    pub fn spend_pubkey(&self) -> &PublicKey {
        &self.spend_pubkey
    }

    /// Encode as bech32m string
    pub fn encode(&self) -> String {
        let hrp = Hrp::parse(GHOST_ID_HRP).expect("valid HRP");

        // Concatenate scan and spend pubkeys (66 bytes total)
        let mut data = Vec::with_capacity(66);
        data.extend_from_slice(&self.scan_pubkey.serialize());
        data.extend_from_slice(&self.spend_pubkey.serialize());

        bech32::encode::<Bech32m>(hrp, &data).expect("valid encoding")
    }

    /// Decode from bech32m string
    pub fn decode(s: &str) -> Result<Self, GhostKeyError> {
        let (hrp, data) =
            bech32::decode(s).map_err(|e| GhostKeyError::Bech32Error(e.to_string()))?;

        if hrp.as_str() != GHOST_ID_HRP {
            return Err(GhostKeyError::InvalidGhostId(format!(
                "Expected HRP '{}', got '{}'",
                GHOST_ID_HRP,
                hrp.as_str()
            )));
        }

        if data.len() != 66 {
            return Err(GhostKeyError::InvalidGhostId(format!(
                "Expected 66 bytes, got {}",
                data.len()
            )));
        }

        let scan_bytes: [u8; 33] = data[0..33]
            .try_into()
            .map_err(|_| GhostKeyError::InvalidGhostId("Invalid scan pubkey".to_string()))?;
        let spend_bytes: [u8; 33] = data[33..66]
            .try_into()
            .map_err(|_| GhostKeyError::InvalidGhostId("Invalid spend pubkey".to_string()))?;

        Self::from_bytes(&scan_bytes, &spend_bytes)
    }

    /// Derive a payment address for sending to this Ghost ID (v2 - position-independent)
    ///
    /// Uses counter-based k instead of output position, safe for shuffled outputs.
    ///
    /// # Arguments
    /// * `k` - Sequential counter for multiple outputs to same recipient (usually 0)
    ///
    /// # Returns
    /// (output_pubkey, ephemeral_pubkey) - The output key and ephemeral key to include in OP_RETURN
    pub fn derive_payment_address_v2(
        &self,
        k: u32,
    ) -> Result<(PublicKey, PublicKey), GhostKeyError> {
        let (output, ephemeral, _tweak) = self.derive_payment_address_v2_full(k)?;
        Ok((output, ephemeral))
    }

    /// Derive payment address with full details (v2 - position-independent)
    ///
    /// # Arguments
    /// * `k` - Sequential counter for multiple outputs to same recipient
    ///
    /// # Returns
    /// (output_pubkey, ephemeral_pubkey, tweak)
    pub fn derive_payment_address_v2_full(
        &self,
        k: u32,
    ) -> Result<(PublicKey, PublicKey, [u8; 32]), GhostKeyError> {
        let secp = Secp256k1::new();

        // Generate ephemeral keypair
        let ephemeral_secret = SecretKey::new(&mut OsRng);
        let ephemeral_pubkey = PublicKey::from_secret_key(&secp, &ephemeral_secret);

        // Compute shared secret
        let shared_secret = derive_shared_secret(&ephemeral_secret, &self.scan_pubkey);

        // Derive output pubkey using v2 (position-independent)
        let (output_pubkey, tweak) =
            derive_payment_address_v2(&self.spend_pubkey, &shared_secret, k)?;

        Ok((output_pubkey, ephemeral_pubkey, tweak))
    }

    /// Derive payment address with a specific ephemeral secret (v2 - for testing/determinism)
    pub fn derive_payment_address_v2_with_ephemeral(
        &self,
        ephemeral_secret: &SecretKey,
        k: u32,
    ) -> Result<(PublicKey, PublicKey, [u8; 32]), GhostKeyError> {
        let secp = Secp256k1::new();
        let ephemeral_pubkey = PublicKey::from_secret_key(&secp, ephemeral_secret);

        // Compute shared secret
        let shared_secret = derive_shared_secret(ephemeral_secret, &self.scan_pubkey);

        // Derive output pubkey using v2
        let (output_pubkey, tweak) =
            derive_payment_address_v2(&self.spend_pubkey, &shared_secret, k)?;

        Ok((output_pubkey, ephemeral_pubkey, tweak))
    }

    /// Export as raw bytes (66 bytes: scan || spend)
    pub fn to_bytes(&self) -> [u8; 66] {
        let mut bytes = [0u8; 66];
        bytes[0..33].copy_from_slice(&self.scan_pubkey.serialize());
        bytes[33..66].copy_from_slice(&self.spend_pubkey.serialize());
        bytes
    }
}

impl fmt::Display for GhostId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.encode())
    }
}

impl FromStr for GhostId {
    type Err = GhostKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::decode(s)
    }
}

/// Serializable Ghost ID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostIdExport {
    pub encoded: String,
}

impl From<&GhostId> for GhostIdExport {
    fn from(id: &GhostId) -> Self {
        Self {
            encoded: id.encode(),
        }
    }
}

impl TryFrom<GhostIdExport> for GhostId {
    type Error = GhostKeyError;

    fn try_from(export: GhostIdExport) -> Result<Self, Self::Error> {
        GhostId::decode(&export.encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let secp = Secp256k1::new();
        let (_, scan_pubkey) = secp.generate_keypair(&mut OsRng);
        let (_, spend_pubkey) = secp.generate_keypair(&mut OsRng);

        let id = GhostId::new(scan_pubkey, spend_pubkey);
        let encoded = id.encode();

        assert!(encoded.starts_with("ghost1"));

        let decoded = GhostId::decode(&encoded).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn test_from_str() {
        let secp = Secp256k1::new();
        let (_, scan_pubkey) = secp.generate_keypair(&mut OsRng);
        let (_, spend_pubkey) = secp.generate_keypair(&mut OsRng);

        let id = GhostId::new(scan_pubkey, spend_pubkey);
        let encoded = id.to_string();

        let parsed: GhostId = encoded.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_derive_payment_address_v2() {
        let secp = Secp256k1::new();
        let (_, scan_pubkey) = secp.generate_keypair(&mut OsRng);
        let (_, spend_pubkey) = secp.generate_keypair(&mut OsRng);

        let id = GhostId::new(scan_pubkey, spend_pubkey);

        let (output, ephemeral) = id.derive_payment_address_v2(0).unwrap();

        // Output should be different from spend pubkey
        assert_ne!(output, spend_pubkey);

        // Different k values should produce different outputs
        let (output2, _) = id.derive_payment_address_v2(1).unwrap();
        assert_ne!(output, output2);

        // Ephemeral pubkey should be valid
        assert!(ephemeral.serialize().len() == 33);
    }

    #[test]
    fn test_derive_payment_address_v2_multiple_k() {
        let secp = Secp256k1::new();
        let (_, scan_pubkey) = secp.generate_keypair(&mut OsRng);
        let (_, spend_pubkey) = secp.generate_keypair(&mut OsRng);

        let id = GhostId::new(scan_pubkey, spend_pubkey);

        // Generate addresses for k=0, 1, 2
        let (addr0, _) = id.derive_payment_address_v2(0).unwrap();
        let (addr1, _) = id.derive_payment_address_v2(1).unwrap();
        let (addr2, _) = id.derive_payment_address_v2(2).unwrap();

        // All addresses should be unique
        assert_ne!(addr0, addr1);
        assert_ne!(addr1, addr2);
        assert_ne!(addr0, addr2);
    }

    #[test]
    fn test_to_bytes() {
        let secp = Secp256k1::new();
        let (_, scan_pubkey) = secp.generate_keypair(&mut OsRng);
        let (_, spend_pubkey) = secp.generate_keypair(&mut OsRng);

        let id = GhostId::new(scan_pubkey, spend_pubkey);
        let bytes = id.to_bytes();

        let scan_bytes: [u8; 33] = bytes[0..33].try_into().unwrap();
        let spend_bytes: [u8; 33] = bytes[33..66].try_into().unwrap();

        let id2 = GhostId::from_bytes(&scan_bytes, &spend_bytes).unwrap();
        assert_eq!(id, id2);
    }

}
