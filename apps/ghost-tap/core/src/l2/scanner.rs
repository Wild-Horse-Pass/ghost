//! Note scanning for L2 confidential transfer discovery
//!
//! Scans L2 transactions by attempting ECIES decryption of encrypted
//! change and recipient fields. If decryption succeeds and the commitment
//! matches, the note belongs to this wallet.

use super::note_store::{NoteStore, OwnedNote};
use serde::Deserialize;

/// A note discovered during scanning
#[derive(Debug, Clone)]
pub struct DiscoveredNote {
    pub note: OwnedNote,
    pub is_change: bool,
    pub checkpoint_height: u64,
}

/// L2 transaction info returned from ghost-pay API (for scanning)
#[derive(Debug, Clone, Deserialize)]
pub struct L2TransactionInfo {
    pub tx_type: String,
    pub checkpoint_height: u64,
    pub epoch: u64,
    #[serde(default)]
    pub encrypted_change: Option<String>,
    #[serde(default)]
    pub change_commitment: Option<String>,
    #[serde(default)]
    pub encrypted_recipient: Option<String>,
    #[serde(default)]
    pub recipient_commitment: Option<String>,
    #[serde(default)]
    pub encrypted_output: Option<String>,
    #[serde(default)]
    pub output_commitment: Option<String>,
}

/// Scans L2 transactions for notes belonging to this wallet.
pub struct NoteScanner {
    secret_key: secp256k1::SecretKey,
    last_scanned_height: u64,
    last_seen_epoch: u64,
}

impl NoteScanner {
    pub fn new(secret_key: secp256k1::SecretKey) -> Self {
        Self {
            secret_key,
            last_scanned_height: 0,
            last_seen_epoch: 0,
        }
    }

    pub fn new_from_height(secret_key: secp256k1::SecretKey, last_scanned_height: u64) -> Self {
        Self {
            secret_key,
            last_scanned_height,
            last_seen_epoch: 0,
        }
    }

    pub fn last_scanned_height(&self) -> u64 {
        self.last_scanned_height
    }

    pub fn set_last_scanned_height(&mut self, height: u64) {
        self.last_scanned_height = height;
    }

    pub fn last_seen_epoch(&self) -> u64 {
        self.last_seen_epoch
    }

    /// Scan a batch of L2 transactions for owned notes.
    pub fn scan_transactions(&mut self, txs: &[L2TransactionInfo]) -> Vec<DiscoveredNote> {
        let mut discovered = Vec::new();

        for tx in txs {
            if tx.epoch > self.last_seen_epoch {
                self.last_seen_epoch = tx.epoch;
            }

            // Try change output (NoteSpend transfers)
            if let (Some(encrypted_hex), Some(commitment_hex)) =
                (&tx.encrypted_change, &tx.change_commitment)
            {
                if let Some(note) = self.try_decrypt(
                    encrypted_hex,
                    commitment_hex,
                    tx.checkpoint_height,
                    tx.epoch,
                ) {
                    discovered.push(DiscoveredNote {
                        note,
                        is_change: true,
                        checkpoint_height: tx.checkpoint_height,
                    });
                }
            }

            // Try recipient output (NoteSpend transfers)
            if let (Some(encrypted_hex), Some(commitment_hex)) =
                (&tx.encrypted_recipient, &tx.recipient_commitment)
            {
                if let Some(note) = self.try_decrypt(
                    encrypted_hex,
                    commitment_hex,
                    tx.checkpoint_height,
                    tx.epoch,
                ) {
                    discovered.push(DiscoveredNote {
                        note,
                        is_change: false,
                        checkpoint_height: tx.checkpoint_height,
                    });
                }
            }

            // Try consolidated output (consolidation transactions)
            if let (Some(encrypted_hex), Some(commitment_hex)) =
                (&tx.encrypted_output, &tx.output_commitment)
            {
                if let Some(note) = self.try_decrypt(
                    encrypted_hex,
                    commitment_hex,
                    tx.checkpoint_height,
                    tx.epoch,
                ) {
                    discovered.push(DiscoveredNote {
                        note,
                        is_change: false,
                        checkpoint_height: tx.checkpoint_height,
                    });
                }
            }
        }

        discovered
    }

    fn try_decrypt(
        &self,
        encrypted_hex: &str,
        commitment_hex: &str,
        block_height: u64,
        epoch: u64,
    ) -> Option<OwnedNote> {
        let encrypted_bytes = hex::decode(encrypted_hex).ok()?;
        let commitment_bytes: [u8; 32] = hex::decode(commitment_hex).ok()?.try_into().ok()?;
        NoteStore::try_decrypt_received_note(
            &self.secret_key,
            &encrypted_bytes,
            &commitment_bytes,
            block_height,
            epoch,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let key = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let scanner = NoteScanner::new(key);
        assert_eq!(scanner.last_scanned_height(), 0);
        assert_eq!(scanner.last_seen_epoch(), 0);
    }

    #[test]
    fn test_scanner_height_tracking() {
        let key = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let mut scanner = NoteScanner::new_from_height(key, 100);
        assert_eq!(scanner.last_scanned_height(), 100);
        scanner.set_last_scanned_height(200);
        assert_eq!(scanner.last_scanned_height(), 200);
    }

    #[test]
    fn test_scan_empty() {
        let key = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let mut scanner = NoteScanner::new(key);
        let discovered = scanner.scan_transactions(&[]);
        assert!(discovered.is_empty());
    }

    #[test]
    fn test_scan_wrong_key_no_discovery() {
        let key = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let mut scanner = NoteScanner::new(key);

        // Encrypted with a different key — should not decrypt
        let txs = vec![L2TransactionInfo {
            tx_type: "transfer".into(),
            checkpoint_height: 10,
            epoch: 0,
            encrypted_change: Some("deadbeef".into()),
            change_commitment: Some("00".repeat(32)),
            encrypted_recipient: None,
            recipient_commitment: None,
            encrypted_output: None,
            output_commitment: None,
        }];

        let discovered = scanner.scan_transactions(&txs);
        assert!(discovered.is_empty());
    }

    #[test]
    fn test_epoch_tracking() {
        let key = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let mut scanner = NoteScanner::new(key);

        let txs = vec![L2TransactionInfo {
            tx_type: "transfer".into(),
            checkpoint_height: 10,
            epoch: 5,
            encrypted_change: None,
            change_commitment: None,
            encrypted_recipient: None,
            recipient_commitment: None,
            encrypted_output: None,
            output_commitment: None,
        }];

        scanner.scan_transactions(&txs);
        assert_eq!(scanner.last_seen_epoch(), 5);
    }
}
