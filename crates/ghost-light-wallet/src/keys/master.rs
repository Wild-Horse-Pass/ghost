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
use bitcoin::Network;
use sha2::{Digest, Sha256};

use ghost_gsp_proto::WalletId;
use ghost_keys::{GhostId, GhostKeys};

use crate::error::{LightWalletError, WalletResult};

/// Master key for the light wallet
///
/// Derived from BIP-39 mnemonic and manages all sub-keys.
pub struct MasterKey {
    /// Ghost Keys for payments
    ghost_keys: GhostKeys,

    /// Auth key for GSP authentication (derived at m/352'/0'/0'/0/0)
    auth_pubkey: [u8; 32],

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

    /// Create master key from mnemonic
    pub fn from_mnemonic(mnemonic_str: &str, network: Network) -> WalletResult<Self> {
        let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_str)?;

        // Derive seed
        let seed = mnemonic.to_seed("");

        // Derive Ghost Keys from seed
        // In production, this would use proper BIP-32 derivation
        let mut scan_seed = [0u8; 32];
        let mut spend_seed = [0u8; 32];

        let scan_hash = Sha256::digest([&seed[..], b"ghost_scan"].concat());
        let spend_hash = Sha256::digest([&seed[..], b"ghost_spend"].concat());

        scan_seed.copy_from_slice(&scan_hash);
        spend_seed.copy_from_slice(&spend_hash);

        let ghost_keys = GhostKeys::from_bytes(&scan_seed, &spend_seed)
            .map_err(|e| LightWalletError::KeyDerivation(e.to_string()))?;

        // Derive auth key for GSP authentication
        let auth_hash = Sha256::digest([&seed[..], b"ghost_auth"].concat());
        let mut auth_pubkey = [0u8; 32];
        auth_pubkey.copy_from_slice(&auth_hash);

        Ok(Self {
            ghost_keys,
            auth_pubkey,
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

    /// Get the auth public key
    pub fn auth_pubkey(&self) -> &[u8; 32] {
        &self.auth_pubkey
    }

    /// Get reference to ghost keys
    pub fn ghost_keys(&self) -> &GhostKeys {
        &self.ghost_keys
    }

    /// Get network
    pub fn network(&self) -> Network {
        self.network
    }

    /// Export secret bytes for encrypted storage
    pub fn export_secrets(&self) -> MasterKeyExport {
        let (scan, spend) = self.ghost_keys.export_secrets();
        MasterKeyExport {
            scan_secret: scan,
            spend_secret: spend,
            auth_pubkey: self.auth_pubkey,
            network: self.network,
        }
    }

    /// Import from exported secrets
    pub fn from_export(export: MasterKeyExport) -> WalletResult<Self> {
        let ghost_keys = GhostKeys::from_bytes(&export.scan_secret, &export.spend_secret)
            .map_err(|e| LightWalletError::KeyDerivation(e.to_string()))?;

        Ok(Self {
            ghost_keys,
            auth_pubkey: export.auth_pubkey,
            network: export.network,
        })
    }
}

/// Exportable master key data (for encrypted storage)
#[derive(Debug, Clone)]
pub struct MasterKeyExport {
    pub scan_secret: [u8; 32],
    pub spend_secret: [u8; 32],
    pub auth_pubkey: [u8; 32],
    pub network: Network,
}

impl MasterKeyExport {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(97);
        bytes.extend_from_slice(&self.scan_secret);
        bytes.extend_from_slice(&self.spend_secret);
        bytes.extend_from_slice(&self.auth_pubkey);
        bytes.push(network_to_byte(self.network));
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> WalletResult<Self> {
        if bytes.len() != 97 {
            return Err(LightWalletError::KeyDerivation(
                "Invalid export data length".to_string(),
            ));
        }

        let mut scan_secret = [0u8; 32];
        let mut spend_secret = [0u8; 32];
        let mut auth_pubkey = [0u8; 32];

        scan_secret.copy_from_slice(&bytes[0..32]);
        spend_secret.copy_from_slice(&bytes[32..64]);
        auth_pubkey.copy_from_slice(&bytes[64..96]);
        let network = byte_to_network(bytes[96])?;

        Ok(Self {
            scan_secret,
            spend_secret,
            auth_pubkey,
            network,
        })
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
        _ => Err(LightWalletError::KeyDerivation("Invalid network byte".to_string())),
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
        assert_eq!(key.wallet_id().to_string(), imported.wallet_id().to_string());
    }

    #[test]
    fn test_export_serialization() {
        let key = MasterKey::from_mnemonic(TEST_MNEMONIC, Network::Testnet).unwrap();
        let export = key.export_secrets();

        let bytes = export.to_bytes();
        assert_eq!(bytes.len(), 97);

        let restored = MasterKeyExport::from_bytes(&bytes).unwrap();
        assert_eq!(export.scan_secret, restored.scan_secret);
        assert_eq!(export.spend_secret, restored.spend_secret);
        assert_eq!(export.auth_pubkey, restored.auth_pubkey);
        assert_eq!(export.network, restored.network);
    }

    #[test]
    fn test_generate_mnemonic() {
        let mnemonic = MasterKey::generate_mnemonic().unwrap();
        let mnemonic_str = mnemonic.to_string();
        let words: Vec<&str> = mnemonic_str.split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }
}
