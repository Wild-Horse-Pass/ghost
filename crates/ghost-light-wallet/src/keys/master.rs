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
//| FILE: keys/master.rs                                                                                                 |
//|======================================================================================================================|

//! Master key derivation and management

use bip39::{Language, Mnemonic};
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::Network;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use ghost_gsp_proto::WalletId;
use ghost_keys::{GhostId, GhostKeys};

use crate::error::{LightWalletError, WalletResult};

/// Master key for the light wallet
///
/// Derived from BIP-39 mnemonic using BIP-32 HD key derivation.
/// All keys are derived from the master seed following BIP-352 paths.
///
/// # Security
///
/// 2.5 HIGH: Clone is NOT implemented to prevent secret key duplication.
/// Use Arc<MasterKey> for shared access across async tasks.
pub struct MasterKey {
    /// Ghost Keys for payments
    ghost_keys: GhostKeys,

    /// Auth secret key for GSP authentication (derived at m/352'/0'/0'/2')
    auth_secret: SecretKey,

    /// Auth public key (x-only, 32 bytes) for verification
    auth_pubkey: [u8; 32],

    /// Confidential spending key for nullifier computation (derived at m/352'/0'/0'/3')
    confidential_spending_key: [u8; 32],

    /// Bitcoin network
    network: Network,
}

impl MasterKey {
    /// Generate a new random mnemonic
    pub fn generate_mnemonic() -> WalletResult<Mnemonic> {
        // Generate 32 bytes of entropy for 24-word mnemonic
        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy)
            .map_err(|e| LightWalletError::KeyDerivation(format!("RNG error: {}", e)))?;

        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|e| LightWalletError::KeyDerivation(e.to_string()))?;
        Ok(mnemonic)
    }

    /// Create master key from mnemonic using BIP-32 HD key derivation
    ///
    /// Derivation paths (BIP-352 style):
    /// - m/352'/0'/0'/0' - Scan key for detecting payments
    /// - m/352'/0'/0'/1' - Spend key for spending funds
    /// - m/352'/0'/0'/2' - Auth key for GSP authentication
    /// - m/352'/0'/0'/3' - Confidential spending key (nullifier computation)
    pub fn from_mnemonic(mnemonic_str: &str, network: Network) -> WalletResult<Self> {
        let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_str)?;
        let secp = Secp256k1::new();

        // Derive seed from mnemonic (no passphrase)
        // CR-H2: Design Decision - BIP-39 Passphrase Not Supported
        //
        // Ghost wallets intentionally do not support BIP-39 passphrases for the following reasons:
        // 1. Simplified UX: Passphrases add complexity and risk of permanent fund loss if forgotten
        // 2. Recovery consistency: Without passphrase, mnemonic alone is sufficient for recovery
        // 3. Silent payments: BIP-352 derivation paths don't benefit from additional passphrase entropy
        // 4. Attack surface: Passphrase entry creates additional side-channel risks
        //
        // The mnemonic's 256 bits of entropy (24 words) provides sufficient security.
        // Users requiring additional protection should use encrypted storage instead.
        let seed = mnemonic.to_seed("");

        // Create master extended private key
        let master = Xpriv::new_master(network, &seed).map_err(|e| {
            LightWalletError::KeyDerivation(format!("Failed to create master key: {}", e))
        })?;

        // BIP-352 base path: m/352'/0'/0'
        // Using coin_type=0 for Bitcoin mainnet compatibility
        let base_path: DerivationPath = vec![
            ChildNumber::from_hardened_idx(352).expect("valid index"),
            ChildNumber::from_hardened_idx(0).expect("valid index"),
            ChildNumber::from_hardened_idx(0).expect("valid index"),
        ]
        .into();

        let base_xpriv = master.derive_priv(&secp, &base_path).map_err(|e| {
            LightWalletError::KeyDerivation(format!("Failed to derive base path: {}", e))
        })?;

        // Derive scan key at m/352'/0'/0'/0'
        let scan_path = vec![ChildNumber::from_hardened_idx(0).expect("valid index")];
        let scan_xpriv = base_xpriv.derive_priv(&secp, &scan_path).map_err(|e| {
            LightWalletError::KeyDerivation(format!("Failed to derive scan key: {}", e))
        })?;
        let scan_secret = scan_xpriv.private_key;

        // Derive spend key at m/352'/0'/0'/1'
        let spend_path = vec![ChildNumber::from_hardened_idx(1).expect("valid index")];
        let spend_xpriv = base_xpriv.derive_priv(&secp, &spend_path).map_err(|e| {
            LightWalletError::KeyDerivation(format!("Failed to derive spend key: {}", e))
        })?;
        let spend_secret = spend_xpriv.private_key;

        // Derive auth key at m/352'/0'/0'/2'
        let auth_path = vec![ChildNumber::from_hardened_idx(2).expect("valid index")];
        let auth_xpriv = base_xpriv.derive_priv(&secp, &auth_path).map_err(|e| {
            LightWalletError::KeyDerivation(format!("Failed to derive auth key: {}", e))
        })?;
        let auth_secret = auth_xpriv.private_key;

        // Derive confidential spending key at m/352'/0'/0'/3'
        let confidential_path = vec![ChildNumber::from_hardened_idx(3).expect("valid index")];
        let confidential_xpriv =
            base_xpriv
                .derive_priv(&secp, &confidential_path)
                .map_err(|e| {
                    LightWalletError::KeyDerivation(format!(
                        "Failed to derive confidential key: {}",
                        e
                    ))
                })?;
        let mut confidential_spending_key = confidential_xpriv.private_key.secret_bytes();
        // Ensure valid BLS12-381 scalar by clearing top 2 bits (~255 bit field)
        confidential_spending_key[31] &= 0x3F;

        // Create Ghost Keys from the derived scan and spend secrets
        let scan_bytes = scan_secret.secret_bytes();
        let spend_bytes = spend_secret.secret_bytes();
        let ghost_keys = GhostKeys::from_bytes(&scan_bytes, &spend_bytes)
            .map_err(|e| LightWalletError::KeyDerivation(e.to_string()))?;

        // Convert auth secret to secp256k1::SecretKey for signing
        let auth_secret = SecretKey::from_slice(&auth_secret.secret_bytes())
            .map_err(|e| LightWalletError::KeyDerivation(format!("Invalid auth key: {}", e)))?;

        // Derive auth public key (x-only, 32 bytes) for BIP-340 Schnorr
        let auth_pubkey_full = PublicKey::from_secret_key(&secp, &auth_secret);
        let (auth_xonly, _parity) = auth_pubkey_full.x_only_public_key();
        let auth_pubkey = auth_xonly.serialize();

        Ok(Self {
            ghost_keys,
            auth_secret,
            auth_pubkey,
            confidential_spending_key,
            network,
        })
    }

    /// Get the Ghost ID for receiving payments
    pub fn ghost_id(&self) -> GhostId {
        self.ghost_keys.ghost_id()
    }

    /// Get the wallet ID (derived from auth pubkey)
    pub fn wallet_id(&self) -> WalletId {
        WalletId::from_pubkey(&self.auth_pubkey)
    }

    /// Get the auth public key (x-only, 32 bytes)
    pub fn auth_pubkey(&self) -> &[u8; 32] {
        &self.auth_pubkey
    }

    /// Get the auth secret key for signing
    pub fn auth_secret(&self) -> &SecretKey {
        &self.auth_secret
    }

    /// Get reference to ghost keys
    pub fn ghost_keys(&self) -> &GhostKeys {
        &self.ghost_keys
    }

    /// Get the confidential spending key (for nullifier computation)
    pub fn confidential_spending_key(&self) -> &[u8; 32] {
        &self.confidential_spending_key
    }

    /// Get network
    pub fn network(&self) -> Network {
        self.network
    }

    /// Export secret bytes for encrypted storage
    pub fn export_secrets(&self) -> MasterKeyExport {
        let (scan, spend) = self.ghost_keys.export_secrets();
        MasterKeyExport {
            // M-15 FIX: Dereference Zeroizing wrapper to get inner bytes
            // The Zeroizing wrapper will zeroize when dropped at end of function
            scan_secret: *scan,
            spend_secret: *spend,
            auth_secret: self.auth_secret.secret_bytes(),
            auth_pubkey: self.auth_pubkey,
            confidential_spending_key: self.confidential_spending_key,
            network: self.network,
        }
    }

    /// Import from exported secrets
    pub fn from_export(export: MasterKeyExport) -> WalletResult<Self> {
        let ghost_keys = GhostKeys::from_bytes(&export.scan_secret, &export.spend_secret)
            .map_err(|e| LightWalletError::KeyDerivation(e.to_string()))?;

        let auth_secret = SecretKey::from_slice(&export.auth_secret)
            .map_err(|e| LightWalletError::KeyDerivation(format!("Invalid auth secret: {}", e)))?;

        Ok(Self {
            ghost_keys,
            auth_secret,
            auth_pubkey: export.auth_pubkey,
            confidential_spending_key: export.confidential_spending_key,
            network: export.network,
        })
    }
}

/// Exportable master key data (for encrypted storage)
///
/// SECURITY: Implements ZeroizeOnDrop to securely erase secret key material
/// from memory when the struct is dropped.
///
/// M-9 FIX: Clone is intentionally NOT derived to prevent accidental duplication
/// of secret key material. If cloning is absolutely necessary, use `clone_with_warning()`
/// which logs a security warning.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct MasterKeyExport {
    pub scan_secret: [u8; 32],
    pub spend_secret: [u8; 32],
    pub auth_secret: [u8; 32],
    pub auth_pubkey: [u8; 32],
    pub confidential_spending_key: [u8; 32],
    #[zeroize(skip)]
    pub network: Network,
}

impl MasterKeyExport {
    /// Clone the export data with a security warning.
    ///
    /// M-9 SECURITY: Cloning secret key material creates another copy in memory
    /// that must be securely erased. Only use when absolutely necessary (e.g., backup).
    /// The cloned instance also implements ZeroizeOnDrop.
    #[must_use]
    pub fn clone_with_warning(&self) -> Self {
        tracing::warn!(
            "M-9: Cloning MasterKeyExport - secret key material duplicated in memory. \
             Ensure the clone is properly dropped to trigger secure erasure."
        );
        Self {
            scan_secret: self.scan_secret,
            spend_secret: self.spend_secret,
            auth_secret: self.auth_secret,
            auth_pubkey: self.auth_pubkey,
            confidential_spending_key: self.confidential_spending_key,
            network: self.network,
        }
    }

    /// Serialize to bytes
    /// Format: scan_secret(32) || spend_secret(32) || auth_secret(32) || auth_pubkey(32)
    ///         || confidential_spending_key(32) || network(1)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(161);
        bytes.extend_from_slice(&self.scan_secret);
        bytes.extend_from_slice(&self.spend_secret);
        bytes.extend_from_slice(&self.auth_secret);
        bytes.extend_from_slice(&self.auth_pubkey);
        bytes.extend_from_slice(&self.confidential_spending_key);
        bytes.push(network_to_byte(self.network));
        bytes
    }

    /// Deserialize from bytes
    ///
    /// Supports both v1 (129 bytes, no confidential key) and v2 (161 bytes) formats.
    pub fn from_bytes(bytes: &[u8]) -> WalletResult<Self> {
        if bytes.len() != 129 && bytes.len() != 161 {
            return Err(LightWalletError::KeyDerivation(
                "Invalid export data length".to_string(),
            ));
        }

        let mut scan_secret = [0u8; 32];
        let mut spend_secret = [0u8; 32];
        let mut auth_secret = [0u8; 32];
        let mut auth_pubkey = [0u8; 32];

        scan_secret.copy_from_slice(&bytes[0..32]);
        spend_secret.copy_from_slice(&bytes[32..64]);
        auth_secret.copy_from_slice(&bytes[64..96]);
        auth_pubkey.copy_from_slice(&bytes[96..128]);

        if bytes.len() == 161 {
            // v2 format: includes confidential spending key
            let mut confidential_spending_key = [0u8; 32];
            confidential_spending_key.copy_from_slice(&bytes[128..160]);
            let network = byte_to_network(bytes[160])?;

            Ok(Self {
                scan_secret,
                spend_secret,
                auth_secret,
                auth_pubkey,
                confidential_spending_key,
                network,
            })
        } else {
            // v1 format: derive confidential key from auth secret
            // (backwards compatible - existing wallets re-derive on unlock)
            let network = byte_to_network(bytes[128])?;
            let confidential_spending_key = [0u8; 32];

            Ok(Self {
                scan_secret,
                spend_secret,
                auth_secret,
                auth_pubkey,
                confidential_spending_key,
                network,
            })
        }
    }
}

fn network_to_byte(network: Network) -> u8 {
    match network {
        Network::Bitcoin => 0,
        Network::Testnet => 1,
        Network::Signet => 2,
        Network::Regtest => 3,
        _ => 0,
    }
}

fn byte_to_network(byte: u8) -> WalletResult<Network> {
    match byte {
        0 => Ok(Network::Bitcoin),
        1 => Ok(Network::Testnet),
        2 => Ok(Network::Signet),
        3 => Ok(Network::Regtest),
        _ => Err(LightWalletError::KeyDerivation(
            "Invalid network byte".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_from_mnemonic() {
        let key = MasterKey::from_mnemonic(TEST_MNEMONIC, Network::Regtest).unwrap();
        assert!(!key.ghost_id().to_string().is_empty());
        assert!(!key.wallet_id().to_string().is_empty());
    }

    #[test]
    fn test_deterministic_derivation() {
        let key1 = MasterKey::from_mnemonic(TEST_MNEMONIC, Network::Regtest).unwrap();
        let key2 = MasterKey::from_mnemonic(TEST_MNEMONIC, Network::Regtest).unwrap();

        assert_eq!(key1.ghost_id().to_string(), key2.ghost_id().to_string());
        assert_eq!(key1.wallet_id().to_string(), key2.wallet_id().to_string());
    }

    #[test]
    fn test_export_import() {
        let key = MasterKey::from_mnemonic(TEST_MNEMONIC, Network::Regtest).unwrap();
        let export = key.export_secrets();

        let imported = MasterKey::from_export(export).unwrap();

        assert_eq!(key.ghost_id().to_string(), imported.ghost_id().to_string());
        assert_eq!(
            key.wallet_id().to_string(),
            imported.wallet_id().to_string()
        );
    }

    #[test]
    fn test_export_serialization() {
        let key = MasterKey::from_mnemonic(TEST_MNEMONIC, Network::Testnet).unwrap();
        let export = key.export_secrets();

        let bytes = export.to_bytes();
        assert_eq!(bytes.len(), 161);

        let restored = MasterKeyExport::from_bytes(&bytes).unwrap();
        assert_eq!(export.scan_secret, restored.scan_secret);
        assert_eq!(export.spend_secret, restored.spend_secret);
        assert_eq!(export.auth_secret, restored.auth_secret);
        assert_eq!(export.auth_pubkey, restored.auth_pubkey);
        assert_eq!(
            export.confidential_spending_key,
            restored.confidential_spending_key
        );
        assert_eq!(export.network, restored.network);
    }

    #[test]
    fn test_export_v1_backward_compat() {
        // Build a v1-style 129-byte export (no confidential key)
        let key = MasterKey::from_mnemonic(TEST_MNEMONIC, Network::Regtest).unwrap();
        let export = key.export_secrets();
        let full_bytes = export.to_bytes();

        // Truncate to v1 format (129 bytes)
        let mut v1_bytes = Vec::with_capacity(129);
        v1_bytes.extend_from_slice(&full_bytes[0..128]);
        v1_bytes.push(full_bytes[160]); // network byte
        assert_eq!(v1_bytes.len(), 129);

        let restored = MasterKeyExport::from_bytes(&v1_bytes).unwrap();
        assert_eq!(export.scan_secret, restored.scan_secret);
        assert_eq!(export.auth_pubkey, restored.auth_pubkey);
        assert_eq!(restored.confidential_spending_key, [0u8; 32]);
    }

    #[test]
    fn test_confidential_spending_key_derivation() {
        let key1 = MasterKey::from_mnemonic(TEST_MNEMONIC, Network::Regtest).unwrap();
        let key2 = MasterKey::from_mnemonic(TEST_MNEMONIC, Network::Regtest).unwrap();

        // Deterministic
        assert_eq!(
            key1.confidential_spending_key(),
            key2.confidential_spending_key()
        );
        // Non-zero
        assert_ne!(*key1.confidential_spending_key(), [0u8; 32]);
        // Different from auth key
        assert_ne!(
            key1.confidential_spending_key(),
            &key1.auth_secret.secret_bytes()
        );
        // Top 2 bits cleared (valid BLS12-381 scalar)
        assert_eq!(key1.confidential_spending_key()[31] & 0xC0, 0);
    }

    #[test]
    fn test_generate_mnemonic() {
        let mnemonic = MasterKey::generate_mnemonic().unwrap();
        let mnemonic_str = mnemonic.to_string();
        let words: Vec<&str> = mnemonic_str.split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }
}
