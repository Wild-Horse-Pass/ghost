//! Integration tests for GhostTap

#[cfg(test)]
mod wallet_tests {
    use ghost_tap_core::wallet::{validate_mnemonic, WordCount, Wallet};
    use secrecy::{ExposeSecret, SecretString};

    #[test]
    fn test_full_wallet_lifecycle() {
        // Generate wallet
        let (wallet, mnemonic) = Wallet::generate(WordCount::Words12).unwrap();

        // Validate mnemonic
        assert!(validate_mnemonic(mnemonic.expose_secret()));

        // Check initial state
        assert_eq!(wallet.balance(), 0);
        assert!(!wallet.is_locked());
    }

    #[test]
    fn test_wallet_recovery() {
        // Generate a wallet
        let (_, mnemonic) = Wallet::generate(WordCount::Words12).unwrap();

        // Recover from mnemonic
        let recovered = Wallet::from_mnemonic(&mnemonic, None).unwrap();

        // Should have same initial state
        assert_eq!(recovered.balance(), 0);
    }

    #[test]
    fn test_invalid_mnemonic_rejected() {
        let invalid = SecretString::new("invalid mnemonic phrase here".into());
        let result = Wallet::from_mnemonic(&invalid, None);
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod crypto_tests {
    use ghost_tap_core::crypto::{encrypt_aes_gcm, decrypt_aes_gcm, random_bytes};

    #[test]
    fn test_encryption_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"Ghost Pay secret data";

        let ciphertext = encrypt_aes_gcm(plaintext, &key).unwrap();
        let decrypted = decrypt_aes_gcm(&ciphertext, &key).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let plaintext = b"secret";

        let ciphertext = encrypt_aes_gcm(plaintext, &key1).unwrap();
        let result = decrypt_aes_gcm(&ciphertext, &key2);

        assert!(result.is_err());
    }

    #[test]
    fn test_random_bytes_unique() {
        let a = random_bytes(32).unwrap();
        let b = random_bytes(32).unwrap();
        assert_ne!(a, b);
    }
}

#[cfg(test)]
mod transaction_tests {
    use ghost_tap_core::wallet::{Utxo, UtxoSet};
    use ghost_tap_core::transaction::{TransactionBuilder, FeePriority};

    #[test]
    fn test_transaction_building() {
        let mut utxo_set = UtxoSet::new();
        utxo_set.add(Utxo {
            txid: "abc123".into(),
            vout: 0,
            amount: 100_000,
            confirmations: 6,
            address: "ghost1abc".into(),
            address_index: 0,
            change: 0,
        });

        let balance = utxo_set.balance();

        let result = TransactionBuilder::new()
            .add_output("ghost1recipient".into(), 50_000)
            .fee_priority(FeePriority::Medium)
            .change_address("ghost1change".into())
            .build(utxo_set.all(), &balance);

        assert!(result.is_ok());
        let tx = result.unwrap();
        assert_eq!(tx.inputs.len(), 1);
        assert!(tx.outputs.len() >= 1);
    }
}

#[cfg(test)]
mod network_tests {
    use ghost_tap_core::network::{NodeConfig, NodeClient};

    #[tokio::test]
    async fn test_node_client_creation() {
        let config = NodeConfig::default();
        let client = NodeClient::new(config);
        assert!(client.is_ok());
    }

    // Note: Live network tests would go here with a test node
}
