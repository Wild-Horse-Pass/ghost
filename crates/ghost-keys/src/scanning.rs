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
//| FILE: scanning.rs                                                                                                    |
//|======================================================================================================================|

//! Payment scanning for Ghost Keys
//!
//! Receivers scan transactions to detect payments made to their Ghost ID.
//! This involves checking each output against possible derived addresses.

use rayon::prelude::*;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;

use crate::derivation::{compute_tweak, derive_shared_secret, derive_spend_key};
use crate::GhostKeys;

/// Transaction data for batch scanning: (ephemeral_pubkey, outputs)
/// where outputs are (output_pubkey, optional_amount)
pub type TransactionOutputs = (PublicKey, Vec<(PublicKey, Option<u64>)>);

/// Maximum nonce to try when scanning (100 possibilities should be plenty)
pub const MAX_SCAN_NONCE: u16 = 100;

// Custom serde for [u8; 33] using hex encoding
mod pubkey_hex {
    use super::*;

    pub fn serialize<S>(data: &[u8; 33], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(data))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 33], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 33 bytes"))
    }
}

/// A detected payment that belongs to us
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedPayment {
    /// The output pubkey (hex-encoded for serde)
    #[serde(with = "pubkey_hex")]
    pub output_pubkey: [u8; 33],
    /// The output index in the transaction
    pub output_index: u32,
    /// The nonce used for derivation
    pub nonce: u16,
    /// The tweak used to derive this address
    pub tweak: [u8; 32],
    /// The derived spend key for this output
    pub spend_key: [u8; 32],
    /// Amount in satoshis (if known)
    pub amount: Option<u64>,
}

/// Payment detector for scanning transactions
pub struct PaymentDetector<'a> {
    keys: &'a GhostKeys,
    secp: Secp256k1<secp256k1::All>,
}

impl<'a> PaymentDetector<'a> {
    /// Create a new payment detector
    pub fn new(keys: &'a GhostKeys) -> Self {
        Self {
            keys,
            secp: Secp256k1::new(),
        }
    }

    /// Scan a transaction for payments to us
    ///
    /// # Arguments
    /// * `ephemeral_pubkey` - The ephemeral pubkey from OP_RETURN
    /// * `outputs` - List of (output_pubkey, amount) pairs
    ///
    /// # Returns
    /// List of detected payments
    pub fn scan_transaction(
        &self,
        ephemeral_pubkey: &PublicKey,
        outputs: &[(PublicKey, Option<u64>)],
    ) -> Vec<ScannedPayment> {
        let mut found = Vec::new();

        // Compute shared secret once
        let shared_secret = derive_shared_secret(self.keys.scan_secret(), ephemeral_pubkey);

        // Check each output
        for (index, (output_pubkey, amount)) in outputs.iter().enumerate() {
            if let Some(payment) =
                self.check_output(&shared_secret, output_pubkey, index as u32, *amount)
            {
                found.push(payment);
            }
        }

        found
    }

    /// Check if a single output belongs to us
    fn check_output(
        &self,
        shared_secret: &[u8; 32],
        output_pubkey: &PublicKey,
        index: u32,
        amount: Option<u64>,
    ) -> Option<ScannedPayment> {
        // Try all possible nonces
        for nonce in 0..=MAX_SCAN_NONCE {
            let tweak = compute_tweak(shared_secret, index, nonce);

            // Expected pubkey = spend_pubkey + tweak*G
            if let Ok(tweak_secret) = SecretKey::from_slice(&tweak) {
                let tweak_pubkey = PublicKey::from_secret_key(&self.secp, &tweak_secret);
                if let Ok(expected_pubkey) = self.keys.spend_pubkey().combine(&tweak_pubkey) {
                    // M-CRYPTO-3: Use constant-time comparison to prevent timing attacks
                    if expected_pubkey
                        .serialize()
                        .ct_eq(&output_pubkey.serialize())
                        .into()
                    {
                        // Found it! Compute spend key
                        if let Ok(spend_key) = derive_spend_key(self.keys.spend_secret(), &tweak) {
                            return Some(ScannedPayment {
                                output_pubkey: output_pubkey.serialize(),
                                output_index: index,
                                nonce,
                                tweak,
                                spend_key: spend_key.secret_bytes(),
                                amount,
                            });
                        }
                    }
                }
            }
        }

        None
    }

    /// Quick check if an output might belong to us (first nonce only)
    ///
    /// Use this for fast filtering before doing full scan
    pub fn quick_check(
        &self,
        ephemeral_pubkey: &PublicKey,
        output_pubkey: &PublicKey,
        index: u32,
    ) -> bool {
        let shared_secret = derive_shared_secret(self.keys.scan_secret(), ephemeral_pubkey);
        let tweak = compute_tweak(&shared_secret, index, 0);

        if let Ok(tweak_secret) = SecretKey::from_slice(&tweak) {
            let tweak_pubkey = PublicKey::from_secret_key(&self.secp, &tweak_secret);
            if let Ok(expected_pubkey) = self.keys.spend_pubkey().combine(&tweak_pubkey) {
                // M-CRYPTO-3: Use constant-time comparison to prevent timing attacks
                return expected_pubkey
                    .serialize()
                    .ct_eq(&output_pubkey.serialize())
                    .into();
            }
        }

        false
    }
}

/// Parallel scanner for batch processing
///
/// Used for L1 Silent Payment scanning where we need to check blockchain
/// outputs against our keys using ECDH.
pub struct BatchScanner {
    /// Number of worker threads
    num_workers: usize,
}

impl BatchScanner {
    /// Create a new batch scanner with specified parallelism
    pub fn new(num_workers: usize) -> Self {
        Self {
            num_workers: num_workers.max(1),
        }
    }

    /// Get the number of workers
    pub fn num_workers(&self) -> usize {
        self.num_workers
    }

    /// Scan multiple transactions in parallel using rayon
    ///
    /// Returns (tx_index, Vec<ScannedPayment>) for each transaction with found payments
    pub fn scan_batch(
        &self,
        keys: &GhostKeys,
        transactions: &[TransactionOutputs],
    ) -> Vec<(usize, Vec<ScannedPayment>)> {
        transactions
            .par_iter()
            .enumerate()
            .filter_map(|(idx, (ephemeral, outputs))| {
                // Create detector per thread to avoid sharing Secp256k1 context
                let detector = PaymentDetector::new(keys);
                let found = detector.scan_transaction(ephemeral, outputs);
                if found.is_empty() {
                    None
                } else {
                    Some((idx, found))
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_scan_own_payment() {
        let keys = GhostKeys::generate();
        let ghost_id = keys.ghost_id();

        // Create a payment
        let (output_pubkey, ephemeral_pubkey, _) =
            ghost_id.derive_payment_address_full(0, 0).unwrap();

        // Scan for it
        let detector = PaymentDetector::new(&keys);
        let found = detector.scan_transaction(&ephemeral_pubkey, &[(output_pubkey, Some(100_000))]);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].output_index, 0);
        assert_eq!(found[0].nonce, 0);
        assert_eq!(found[0].amount, Some(100_000));
    }

    #[test]
    fn test_scan_multiple_outputs() {
        let keys = GhostKeys::generate();
        let ghost_id = keys.ghost_id();

        // Create ephemeral key for this transaction using random entropy
        // CR-C2: Never use hardcoded keys, even in tests
        let secp = Secp256k1::new();
        let (ephemeral_secret, _) = secp.generate_keypair(&mut OsRng);

        // Create outputs at their actual positions in the outputs vec
        let (out0, ephemeral, _) = ghost_id
            .derive_payment_address_with_ephemeral(&ephemeral_secret, 0, 0)
            .unwrap();
        let (out2, _, _) = ghost_id
            .derive_payment_address_with_ephemeral(&ephemeral_secret, 2, 0)
            .unwrap();

        // Add a random output that's not ours (at index 1)
        let (_, random_pubkey) = secp.generate_keypair(&mut OsRng);

        let outputs = vec![
            (out0, Some(50_000)),           // index 0
            (random_pubkey, Some(100_000)), // index 1
            (out2, Some(75_000)),           // index 2
        ];

        let detector = PaymentDetector::new(&keys);
        let found = detector.scan_transaction(&ephemeral, &outputs);

        assert_eq!(found.len(), 2);
        assert!(found
            .iter()
            .any(|p| p.output_index == 0 && p.amount == Some(50_000)));
        assert!(found
            .iter()
            .any(|p| p.output_index == 2 && p.amount == Some(75_000)));
    }

    #[test]
    fn test_scan_not_ours() {
        let keys = GhostKeys::generate();
        let other_keys = GhostKeys::generate();

        // Payment to someone else
        let (output_pubkey, ephemeral_pubkey, _) = other_keys
            .ghost_id()
            .derive_payment_address_full(0, 0)
            .unwrap();

        // We shouldn't find it
        let detector = PaymentDetector::new(&keys);
        let found = detector.scan_transaction(&ephemeral_pubkey, &[(output_pubkey, Some(100_000))]);

        assert!(found.is_empty());
    }

    #[test]
    fn test_quick_check() {
        let keys = GhostKeys::generate();
        let ghost_id = keys.ghost_id();

        let (output_pubkey, ephemeral_pubkey, _) =
            ghost_id.derive_payment_address_full(0, 0).unwrap();

        let detector = PaymentDetector::new(&keys);

        // Our payment
        assert!(detector.quick_check(&ephemeral_pubkey, &output_pubkey, 0));

        // Someone else's
        let secp = Secp256k1::new();
        let (_, random) = secp.generate_keypair(&mut OsRng);
        assert!(!detector.quick_check(&ephemeral_pubkey, &random, 0));
    }

    #[test]
    fn test_batch_scanner() {
        let keys = GhostKeys::generate();
        let ghost_id = keys.ghost_id();

        // Create multiple transactions
        let (out1, eph1, _) = ghost_id.derive_payment_address_full(0, 0).unwrap();
        let (out2, eph2, _) = ghost_id.derive_payment_address_full(0, 0).unwrap();

        let transactions = vec![
            (eph1, vec![(out1, Some(100_000))]),
            (eph2, vec![(out2, Some(200_000))]),
        ];

        let scanner = BatchScanner::new(4);
        let results = scanner.scan_batch(&keys, &transactions);

        assert_eq!(results.len(), 2);
    }
}
