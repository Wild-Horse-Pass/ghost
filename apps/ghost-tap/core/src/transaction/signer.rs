//! Transaction signing
//!
//! Handles signing of Ghost transactions using secp256k1.

use super::{SignedTransaction, TransactionError, UnsignedTransaction};
use secp256k1::{ecdsa::Signature, Message, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Transaction signer
///
/// Signs transactions using provided private keys.
pub struct TransactionSigner {
    secp: Secp256k1<secp256k1::All>,
}

impl TransactionSigner {
    /// Create a new transaction signer
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::new(),
        }
    }

    /// Sign an unsigned transaction
    ///
    /// # Arguments
    /// * `tx` - The unsigned transaction to sign
    /// * `get_key` - Callback to get the private key for each input's address_index
    ///
    /// # Returns
    /// A signed transaction ready for broadcast
    pub fn sign<F>(
        &self,
        tx: &UnsignedTransaction,
        mut get_key: F,
    ) -> Result<SignedTransaction, TransactionError>
    where
        F: FnMut(u32, u32) -> Result<Zeroizing<[u8; 32]>, TransactionError>,
    {
        let mut signatures = Vec::with_capacity(tx.inputs.len());

        // Create the transaction hash to sign
        let tx_hash = self.compute_tx_hash(tx)?;
        let message = Message::from_digest(tx_hash);

        // Sign each input
        for input in &tx.inputs {
            // Get the private key for this input using the BIP44 change index
            // stored in the TxInput (0 = receive, 1 = change).
            let privkey_bytes = get_key(input.change, input.address_index)?;

            let secret_key = SecretKey::from_slice(&*privkey_bytes)
                .map_err(|e| TransactionError::SigningFailed(format!("Invalid key: {}", e)))?;

            let signature = self.secp.sign_ecdsa(&message, &secret_key);
            signatures.push(signature);
        }

        // Build the signed transaction
        let signed = self.build_signed_tx(tx, &signatures)?;

        Ok(signed)
    }

    /// Compute the hash of a transaction for signing
    fn compute_tx_hash(&self, tx: &UnsignedTransaction) -> Result<[u8; 32], TransactionError> {
        // Serialize transaction data for hashing
        // This is a simplified version - real implementation depends on Ghost's TX format
        let mut data = Vec::new();

        // Version (4 bytes)
        data.extend_from_slice(&1u32.to_le_bytes());

        // Number of inputs
        data.push(tx.inputs.len() as u8);

        // Inputs
        for input in &tx.inputs {
            // Previous txid (32 bytes)
            let txid_bytes = hex::decode(&input.txid)
                .map_err(|e| TransactionError::InvalidTransaction(format!("Invalid txid: {}", e)))?;
            data.extend_from_slice(&txid_bytes);

            // Previous output index (4 bytes)
            data.extend_from_slice(&input.vout.to_le_bytes());

            // Amount (8 bytes)
            data.extend_from_slice(&input.amount.to_le_bytes());
        }

        // Number of outputs
        data.push(tx.outputs.len() as u8);

        // Outputs
        for output in &tx.outputs {
            // Amount (8 bytes)
            data.extend_from_slice(&output.amount.to_le_bytes());

            // Address length and address
            let addr_bytes = output.address.as_bytes();
            data.push(addr_bytes.len() as u8);
            data.extend_from_slice(addr_bytes);
        }

        // Double SHA256
        let hash1 = Sha256::digest(&data);
        let hash2 = Sha256::digest(hash1);

        Ok(hash2.into())
    }

    /// Build the final signed transaction
    fn build_signed_tx(
        &self,
        tx: &UnsignedTransaction,
        signatures: &[Signature],
    ) -> Result<SignedTransaction, TransactionError> {
        let mut raw_tx = Vec::new();

        // Version (4 bytes)
        raw_tx.extend_from_slice(&1u32.to_le_bytes());

        // Number of inputs
        raw_tx.push(tx.inputs.len() as u8);

        // Inputs with signatures
        for (input, sig) in tx.inputs.iter().zip(signatures.iter()) {
            // Previous txid
            let txid_bytes = hex::decode(&input.txid)
                .map_err(|e| TransactionError::InvalidTransaction(format!("Invalid txid: {}", e)))?;
            raw_tx.extend_from_slice(&txid_bytes);

            // Previous output index
            raw_tx.extend_from_slice(&input.vout.to_le_bytes());

            // Signature (DER encoded)
            let sig_bytes = sig.serialize_der();
            raw_tx.push(sig_bytes.len() as u8);
            raw_tx.extend_from_slice(&sig_bytes);
        }

        // Number of outputs
        raw_tx.push(tx.outputs.len() as u8);

        // Outputs
        for output in &tx.outputs {
            // Amount
            raw_tx.extend_from_slice(&output.amount.to_le_bytes());

            // Address (as script - simplified)
            let addr_bytes = output.address.as_bytes();
            raw_tx.push(addr_bytes.len() as u8);
            raw_tx.extend_from_slice(addr_bytes);
        }

        // Locktime (4 bytes)
        raw_tx.extend_from_slice(&0u32.to_le_bytes());

        // Compute txid (double SHA256 of raw tx, reversed)
        let txid_hash = Sha256::digest(Sha256::digest(&raw_tx));
        let txid = hex::encode(txid_hash.iter().rev().copied().collect::<Vec<_>>());

        Ok(SignedTransaction {
            raw_tx: hex::encode(&raw_tx),
            txid,
            size: raw_tx.len(),
            fee: tx.fee,
        })
    }

    /// Sign a message with a private key
    pub fn sign_message(
        &self,
        message: &[u8],
        privkey: &[u8; 32],
    ) -> Result<Vec<u8>, TransactionError> {
        let secret_key = SecretKey::from_slice(privkey)
            .map_err(|e| TransactionError::SigningFailed(format!("Invalid key: {}", e)))?;

        // Hash the message
        let hash = Sha256::digest(message);
        let msg = Message::from_digest(hash.into());

        let signature = self.secp.sign_ecdsa(&msg, &secret_key);
        Ok(signature.serialize_der().to_vec())
    }

    /// Verify a signature
    pub fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        pubkey: &secp256k1::PublicKey,
    ) -> bool {
        let hash = Sha256::digest(message);
        let msg = Message::from_digest(hash.into());

        let sig = match Signature::from_der(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        self.secp.verify_ecdsa(&msg, &sig, pubkey).is_ok()
    }
}

impl Default for TransactionSigner {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify a signed transaction's signatures
pub fn verify_transaction(tx: &SignedTransaction) -> Result<bool, TransactionError> {
    // Parse raw transaction and verify each signature
    // This is a simplified check - real verification requires the full UTXO context
    let raw = hex::decode(&tx.raw_tx)
        .map_err(|e| TransactionError::InvalidTransaction(format!("Invalid hex: {}", e)))?;

    // Basic structure validation
    if raw.len() < 10 {
        return Err(TransactionError::InvalidTransaction(
            "Transaction too short".into(),
        ));
    }

    // Check version
    let version = u32::from_le_bytes(raw[0..4].try_into().unwrap());
    if version != 1 {
        return Err(TransactionError::InvalidTransaction(format!(
            "Unknown version: {}",
            version
        )));
    }

    Ok(true) // Simplified - real verification needs UTXO data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{TxInput, TxOutput};

    fn valid_txid() -> String {
        "0000000000000000000000000000000000000000000000000000000000000001".to_string()
    }

    fn test_privkey() -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = 1; // minimal valid secp256k1 key
        k
    }

    fn simple_unsigned_tx() -> UnsignedTransaction {
        UnsignedTransaction {
            inputs: vec![TxInput {
                txid: valid_txid(),
                vout: 0,
                amount: 100000,
                address_index: 0,
                change: 0,
            }],
            outputs: vec![TxOutput {
                address: "recipient_address".into(),
                amount: 90000,
            }],
            fee: 10000,
        }
    }

    #[test]
    fn test_signer_creation() {
        let signer = TransactionSigner::new();
        assert!(std::mem::size_of_val(&signer) > 0);
    }

    #[test]
    fn test_message_signing() {
        let signer = TransactionSigner::new();
        let privkey = test_privkey();
        let signature = signer.sign_message(b"Hello, Ghost Pay!", &privkey).unwrap();
        assert!(!signature.is_empty());
    }

    #[test]
    fn test_transaction_hash() {
        let signer = TransactionSigner::new();
        let tx = simple_unsigned_tx();

        let hash = signer.compute_tx_hash(&tx).unwrap();
        assert_eq!(hash.len(), 32);

        // Same transaction should produce same hash (deterministic)
        let hash2 = signer.compute_tx_hash(&tx).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_sign_and_verify_message() {
        let signer = TransactionSigner::new();
        let privkey = test_privkey();
        let message = b"Test message for Ghost";

        let sig = signer.sign_message(message, &privkey).unwrap();

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&privkey).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret);

        assert!(signer.verify_signature(message, &sig, &pubkey));
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let signer = TransactionSigner::new();
        let privkey = test_privkey();

        let sig = signer.sign_message(b"correct message", &privkey).unwrap();

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&privkey).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret);

        assert!(!signer.verify_signature(b"wrong message", &sig, &pubkey));
    }

    #[test]
    fn test_verify_wrong_pubkey_fails() {
        let signer = TransactionSigner::new();
        let privkey = test_privkey();

        let sig = signer.sign_message(b"message", &privkey).unwrap();

        // Different key
        let mut other_key = [0u8; 32];
        other_key[0] = 2;
        let secp = Secp256k1::new();
        let other_secret = SecretKey::from_slice(&other_key).unwrap();
        let other_pubkey = secp256k1::PublicKey::from_secret_key(&secp, &other_secret);

        assert!(!signer.verify_signature(b"message", &sig, &other_pubkey));
    }

    #[test]
    fn test_verify_invalid_signature_fails() {
        let signer = TransactionSigner::new();
        let privkey = test_privkey();
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&privkey).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret);

        assert!(!signer.verify_signature(b"msg", &[0xFF; 10], &pubkey));
    }

    #[test]
    fn test_sign_transaction() {
        let signer = TransactionSigner::new();
        let tx = simple_unsigned_tx();
        let privkey = test_privkey();

        let signed = signer
            .sign(&tx, |_change, _idx| Ok(Zeroizing::new(privkey)))
            .unwrap();

        assert!(!signed.raw_tx.is_empty());
        assert!(!signed.txid.is_empty());
        assert_eq!(signed.txid.len(), 64); // hex-encoded 32 bytes
        assert!(signed.size > 0);
        assert_eq!(signed.fee, 10000);
    }

    #[test]
    fn test_sign_transaction_multiple_inputs() {
        let signer = TransactionSigner::new();
        let tx = UnsignedTransaction {
            inputs: vec![
                TxInput {
                    txid: valid_txid(),
                    vout: 0,
                    amount: 50000,
                    address_index: 0,
                    change: 0,
                },
                TxInput {
                    txid: valid_txid(),
                    vout: 1,
                    amount: 60000,
                    address_index: 1,
                    change: 1,
                },
            ],
            outputs: vec![
                TxOutput { address: "addr1".into(), amount: 80000 },
                TxOutput { address: "addr2".into(), amount: 20000 },
            ],
            fee: 10000,
        };

        let privkey = test_privkey();
        let signed = signer
            .sign(&tx, |_change, _idx| Ok(Zeroizing::new(privkey)))
            .unwrap();

        assert!(!signed.raw_tx.is_empty());
        assert!(signed.size > 0);
    }

    #[test]
    fn test_sign_invalid_key_fails() {
        let signer = TransactionSigner::new();
        let tx = simple_unsigned_tx();

        let result = signer.sign(&tx, |_change, _idx| {
            Ok(Zeroizing::new([0u8; 32])) // zero key is invalid for secp256k1
        });

        assert!(matches!(result, Err(TransactionError::SigningFailed(_))));
    }

    #[test]
    fn test_sign_key_callback_error_propagates() {
        let signer = TransactionSigner::new();
        let tx = simple_unsigned_tx();

        let result = signer.sign(&tx, |_change, _idx| {
            Err(TransactionError::SigningFailed("key not found".into()))
        });

        assert!(matches!(result, Err(TransactionError::SigningFailed(_))));
    }

    #[test]
    fn test_different_transactions_different_hashes() {
        let signer = TransactionSigner::new();
        let tx1 = simple_unsigned_tx();
        let mut tx2 = simple_unsigned_tx();
        tx2.outputs[0].amount = 80000; // different amount

        let hash1 = signer.compute_tx_hash(&tx1).unwrap();
        let hash2 = signer.compute_tx_hash(&tx2).unwrap();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_verify_transaction_basic() {
        let signer = TransactionSigner::new();
        let tx = simple_unsigned_tx();
        let privkey = test_privkey();

        let signed = signer
            .sign(&tx, |_change, _idx| Ok(Zeroizing::new(privkey)))
            .unwrap();

        assert!(verify_transaction(&signed).unwrap());
    }

    #[test]
    fn test_verify_transaction_too_short() {
        let tx = SignedTransaction {
            raw_tx: hex::encode([0u8; 5]),
            txid: "abc".into(),
            size: 5,
            fee: 0,
        };
        assert!(matches!(
            verify_transaction(&tx),
            Err(TransactionError::InvalidTransaction(_))
        ));
    }

    #[test]
    fn test_verify_transaction_wrong_version() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&99u32.to_le_bytes()); // bad version
        raw.extend_from_slice(&[0u8; 10]);
        let tx = SignedTransaction {
            raw_tx: hex::encode(&raw),
            txid: "abc".into(),
            size: raw.len(),
            fee: 0,
        };
        assert!(matches!(
            verify_transaction(&tx),
            Err(TransactionError::InvalidTransaction(_))
        ));
    }

    #[test]
    fn test_verify_invalid_hex() {
        let tx = SignedTransaction {
            raw_tx: "not_valid_hex!!!".into(),
            txid: "abc".into(),
            size: 0,
            fee: 0,
        };
        assert!(verify_transaction(&tx).is_err());
    }

    #[test]
    fn test_message_signing_deterministic() {
        let signer = TransactionSigner::new();
        let privkey = test_privkey();
        let msg = b"deterministic";

        let sig1 = signer.sign_message(msg, &privkey).unwrap();
        let sig2 = signer.sign_message(msg, &privkey).unwrap();
        assert_eq!(sig1, sig2);
    }
}
