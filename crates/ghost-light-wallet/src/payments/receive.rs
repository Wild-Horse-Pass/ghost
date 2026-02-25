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
//| FILE: payments/receive.rs                                                                                            |
//|======================================================================================================================|

//! Receive payment operations - address generation

use bitcoin::Network;
use tracing::debug;

use ghost_keys::{GhostId, GhostNetwork};

use crate::error::{LightWalletError, WalletResult};
use crate::keys::MasterKey;

/// Address type for receiving payments
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    /// Ghost ID for Ghost Pay (off-chain)
    GhostPay,

    /// BIP-352 Silent Payment address
    SilentPayment,
}

/// A payment address with metadata
#[derive(Debug, Clone)]
pub struct PaymentAddress {
    /// The address string
    pub address: String,

    /// Address type
    pub address_type: AddressType,

    /// Derivation index (for standard addresses)
    pub index: Option<u32>,

    /// Optional label
    pub label: Option<String>,

    /// Creation timestamp
    pub created_at: i64,
}

impl PaymentAddress {
    /// Create a new Ghost Pay address
    pub fn ghost_pay(ghost_id: &GhostId) -> Self {
        Self {
            address: ghost_id.to_string(),
            address_type: AddressType::GhostPay,
            index: None,
            label: None,
            created_at: chrono::Utc::now().timestamp(),
        }
    }

    /// Add a label to the address
    pub fn with_label(mut self, label: &str) -> Self {
        self.label = Some(label.to_string());
        self
    }
}

/// Generate a payment address
pub fn generate_address(
    master_key: &MasterKey,
    address_type: AddressType,
) -> WalletResult<PaymentAddress> {
    debug!(address_type = ?address_type, "Generating address");

    match address_type {
        AddressType::GhostPay => {
            // Return the Ghost ID for Ghost Pay
            let ghost_id = master_key.ghost_id();
            Ok(PaymentAddress::ghost_pay(&ghost_id))
        }
        AddressType::SilentPayment => {
            let ghost_id = master_key.ghost_id();
            let ghost_network = bitcoin_to_ghost_network(master_key.network());
            let encoded = ghost_id.encode_for_network(ghost_network).map_err(|e| {
                LightWalletError::KeyDerivation(format!("Ghost ID encoding failed: {}", e))
            })?;
            debug!(address = %encoded, "Generated BIP-352 Silent Payment address");
            Ok(PaymentAddress {
                address: encoded,
                address_type: AddressType::SilentPayment,
                index: None,
                label: None,
                created_at: chrono::Utc::now().timestamp(),
            })
        }
    }
}

/// Generate the primary Ghost ID for receiving
pub fn get_ghost_id(master_key: &MasterKey) -> String {
    master_key.ghost_id().to_string()
}

/// Map bitcoin::Network to GhostNetwork for encoding
fn bitcoin_to_ghost_network(network: Network) -> GhostNetwork {
    match network {
        Network::Bitcoin => GhostNetwork::Mainnet,
        Network::Testnet => GhostNetwork::Testnet,
        Network::Signet => GhostNetwork::Signet,
        Network::Regtest => GhostNetwork::Regtest,
        _ => GhostNetwork::Mainnet,
    }
}

/// Check if an address belongs to this wallet
pub fn is_my_address(master_key: &MasterKey, address: &str) -> bool {
    // Check Ghost ID
    if address == master_key.ghost_id().to_string() {
        return true;
    }

    // Check if it matches our auth pubkey (simplified)
    let pubkey_prefix = hex::encode(&master_key.auth_pubkey()[..20]);
    if address.contains(&pubkey_prefix) {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_generate_ghost_pay_address() {
        let key = MasterKey::from_mnemonic(TEST_MNEMONIC, Network::Regtest).unwrap();
        let addr = generate_address(&key, AddressType::GhostPay).unwrap();

        assert_eq!(addr.address_type, AddressType::GhostPay);
        assert!(!addr.address.is_empty());
    }

    #[test]
    fn test_address_with_label() {
        let key = MasterKey::from_mnemonic(TEST_MNEMONIC, Network::Regtest).unwrap();
        let addr = generate_address(&key, AddressType::GhostPay)
            .unwrap()
            .with_label("Donations");

        assert_eq!(addr.label, Some("Donations".to_string()));
    }

    #[test]
    fn test_is_my_address() {
        let key = MasterKey::from_mnemonic(TEST_MNEMONIC, Network::Regtest).unwrap();
        let ghost_id = key.ghost_id().to_string();

        assert!(is_my_address(&key, &ghost_id));
        assert!(!is_my_address(&key, "random_address"));
    }

    #[test]
    fn test_silent_payment_address() {
        let key = MasterKey::from_mnemonic(TEST_MNEMONIC, Network::Regtest).unwrap();
        let addr = generate_address(&key, AddressType::SilentPayment).unwrap();

        assert_eq!(addr.address_type, AddressType::SilentPayment);
        assert!(
            addr.address.starts_with("rghost1"),
            "Regtest SP address should start with rghost1, got: {}",
            addr.address
        );
    }

    #[test]
    fn test_silent_payment_address_signet() {
        let key = MasterKey::from_mnemonic(TEST_MNEMONIC, Network::Signet).unwrap();
        let addr = generate_address(&key, AddressType::SilentPayment).unwrap();

        assert!(
            addr.address.starts_with("sghost1"),
            "Signet SP address should start with sghost1, got: {}",
            addr.address
        );
    }

    #[test]
    fn test_silent_payment_deterministic() {
        let key1 = MasterKey::from_mnemonic(TEST_MNEMONIC, Network::Regtest).unwrap();
        let key2 = MasterKey::from_mnemonic(TEST_MNEMONIC, Network::Regtest).unwrap();
        let addr1 = generate_address(&key1, AddressType::SilentPayment).unwrap();
        let addr2 = generate_address(&key2, AddressType::SilentPayment).unwrap();

        assert_eq!(addr1.address, addr2.address);
    }
}
