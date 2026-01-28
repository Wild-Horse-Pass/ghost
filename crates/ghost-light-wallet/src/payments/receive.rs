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

use tracing::debug;

use ghost_keys::GhostId;

use crate::error::WalletResult;
use crate::keys::MasterKey;

/// Address type for receiving payments
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    /// Ghost ID for Ghost Pay (off-chain)
    GhostPay,

    /// BIP-352 Silent Payment address
    SilentPayment,

    /// Standard P2TR (Taproot) address
    Taproot,
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
            // Generate Silent Payment address (BIP-352)
            // This uses the Ghost Keys' scan and spend pubkeys
            let ghost_id = master_key.ghost_id();
            Ok(PaymentAddress {
                address: format!("sp1{}", ghost_id), // Simplified - actual SP has different encoding
                address_type: AddressType::SilentPayment,
                index: None,
                label: None,
                created_at: chrono::Utc::now().timestamp(),
            })
        }
        AddressType::Taproot => {
            // Generate standard Taproot address
            // In production, this would use proper BIP-86 derivation
            let pubkey = master_key.auth_pubkey();
            let address = format!("bc1p{}", hex::encode(&pubkey[..20]));
            Ok(PaymentAddress {
                address,
                address_type: AddressType::Taproot,
                index: Some(0),
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
}
