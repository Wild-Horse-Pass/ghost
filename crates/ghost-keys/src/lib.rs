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
//| FILE: lib.rs                                                                                                         |
//|======================================================================================================================|

//! Ghost Keys - Privacy-preserving key derivation for Ghost Pay
//!
//! Ghost Keys are the identity foundation of Ghost Pay. Based on BIP-352 Silent Payments,
//! they enable unlinkable stealth addresses where each payment creates a unique address
//! that only the recipient can detect.
//!
//! # Key Components
//!
//! - **Scan Key**: Used to detect incoming payments (shared secret derivation)
//! - **Spend Key**: Used to spend received funds
//! - **Ghost ID**: Public identifier (scan_pubkey + spend_pubkey) shared to receive payments
//!
//! # Example
//!
//! ```
//! use ghost_keys::{GhostKeys, GhostId};
//!
//! // Generate new Ghost Keys
//! let keys = GhostKeys::generate();
//!
//! // Get Ghost ID to share with senders
//! let ghost_id = keys.ghost_id();
//!
//! // Sender derives payment address (returns Result due to potential crypto errors)
//! let (address, ephemeral_pubkey) = ghost_id.derive_payment_address(0).unwrap();
//! ```

mod derivation;
mod error;
mod ghost_id;
mod keys;
pub mod labels;
pub mod metadata;
mod scanning;

pub use derivation::{
    compute_tweak, derive_payment_address, derive_shared_secret, derive_spend_key, tagged_hash,
};
pub use error::GhostKeyError;
pub use ghost_id::GhostId;
pub use keys::{GhostKeys, GhostKeysExport};
pub use scanning::{BatchScanner, PaymentDetector, ScannedPayment};
pub use labels::{LabelBackup, LabelDictionary};
pub use metadata::{
    decrypt_metadata, encrypt_metadata, PaymentMetadata,
    DEFAULT_LABEL, MAX_MEMO_LENGTH, METADATA_CIPHERTEXT_SIZE, METADATA_PLAINTEXT_SIZE,
};

/// Human-readable part for Ghost ID bech32 encoding
pub const GHOST_ID_HRP: &str = "ghost";

/// Derivation path prefix for Ghost Keys (m/777'/...)
pub const GHOST_DERIVATION_PREFIX: u32 = 777;

/// OP_RETURN marker for Ghost Pay Ghost Lock
pub const GHOST_LOCK_MARKER: &[u8] = b"GPGL";

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_key_generation() {
        let keys = GhostKeys::generate();
        let ghost_id = keys.ghost_id();

        // Verify keys are valid
        assert!(keys.scan_secret().secret_bytes().len() == 32);
        assert!(keys.spend_secret().secret_bytes().len() == 32);

        // Verify Ghost ID encodes correctly
        let encoded = ghost_id.to_string();
        assert!(encoded.starts_with("ghost1"));

        // Verify round-trip
        let decoded = GhostId::from_str(&encoded).unwrap();
        assert_eq!(ghost_id.scan_pubkey(), decoded.scan_pubkey());
        assert_eq!(ghost_id.spend_pubkey(), decoded.spend_pubkey());
    }

    #[test]
    fn test_payment_derivation() {
        let receiver_keys = GhostKeys::generate();
        let ghost_id = receiver_keys.ghost_id();

        // Sender derives payment address
        let (address, ephemeral_pubkey, _tweak) =
            ghost_id.derive_payment_address_full(0, 0).unwrap();

        // Receiver can detect and spend
        // SEC-KEY-1: detect_payment now returns Result<Option<SecretKey>>
        let detected = receiver_keys.detect_payment(&ephemeral_pubkey, &address, 0).unwrap();
        assert!(detected.is_some());

        let spend_key = detected.unwrap();
        // Verify spend key matches
        assert!(spend_key.secret_bytes().len() == 32);
    }

    #[test]
    fn test_unlinkable_addresses() {
        let keys = GhostKeys::generate();
        let ghost_id = keys.ghost_id();

        // Multiple payments create different addresses
        let (addr1, _, _) = ghost_id.derive_payment_address_full(0, 0).unwrap();
        let (addr2, _, _) = ghost_id.derive_payment_address_full(0, 1).unwrap();
        let (addr3, _, _) = ghost_id.derive_payment_address_full(1, 0).unwrap();

        assert_ne!(addr1, addr2);
        assert_ne!(addr1, addr3);
        assert_ne!(addr2, addr3);
    }
}
