//! Note scanning for confidential transfer discovery
//!
//! The scanner decrypts L2 transaction encrypted fields using the wallet's
//! secret key. If decryption succeeds and the commitment matches, the note
//! is owned by this wallet and should be added to the NoteStore.

use ghost_gsp_proto::L2TransactionInfo;

use super::notes::{NoteStore, OwnedNote};

/// A note discovered by scanning L2 transactions
#[derive(Debug, Clone)]
pub struct DiscoveredNote {
    /// The owned note with value and blinding
    pub note: OwnedNote,
    /// Whether this is a change note (true) or recipient note (false)
    pub is_change: bool,
    /// Checkpoint height where this note was found
    pub checkpoint_height: u64,
}

/// Scans L2 transactions to discover notes owned by this wallet
pub struct NoteScanner {
    secret_key: secp256k1::SecretKey,
    last_scanned_height: u64,
    last_seen_epoch: u64,
}

impl NoteScanner {
    /// Create a new scanner with the wallet's secret key
    pub fn new(secret_key: secp256k1::SecretKey) -> Self {
        Self {
            secret_key,
            last_scanned_height: 0,
            last_seen_epoch: 0,
        }
    }

    /// Create a scanner resuming from a previous height
    pub fn new_from_height(secret_key: secp256k1::SecretKey, last_scanned_height: u64) -> Self {
        Self {
            secret_key,
            last_scanned_height,
            last_seen_epoch: 0,
        }
    }

    /// Get the last scanned checkpoint height
    pub fn last_scanned_height(&self) -> u64 {
        self.last_scanned_height
    }

    /// Update the last scanned height after processing
    pub fn set_last_scanned_height(&mut self, height: u64) {
        self.last_scanned_height = height;
    }

    /// Get the last epoch seen during scanning
    pub fn last_seen_epoch(&self) -> u64 {
        self.last_seen_epoch
    }

    /// Scan a batch of L2 transactions for notes belonging to this wallet.
    ///
    /// For each transaction, attempts to decrypt both the change and recipient
    /// encrypted fields. If decryption succeeds and the commitment matches,
    /// the note is returned as a `DiscoveredNote`.
    ///
    /// If an epoch change is detected (tx.epoch > last seen), `epoch_changed()`
    /// will return the new epoch after scanning completes.
    pub fn scan_transactions(&mut self, txs: &[L2TransactionInfo]) -> Vec<DiscoveredNote> {
        let mut discovered = Vec::new();

        for tx in txs {
            // Detect epoch transitions
            if tx.epoch > self.last_seen_epoch {
                self.last_seen_epoch = tx.epoch;
            }

            // Try decrypting the change note (sender's change)
            if let Some(encrypted_hex) = &tx.encrypted_change {
                if let Some(note) = self.try_decrypt(
                    encrypted_hex,
                    &tx.change_commitment,
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

            // Try decrypting the recipient note
            if let Some(encrypted_hex) = &tx.encrypted_recipient {
                if let Some(note) = self.try_decrypt(
                    encrypted_hex,
                    &tx.recipient_commitment,
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

    /// Try to decrypt an encrypted note field and verify the commitment.
    fn try_decrypt(
        &self,
        encrypted_hex: &str,
        commitment_hex: &str,
        block_height: u64,
        epoch: u64,
    ) -> Option<OwnedNote> {
        let encrypted_bytes = hex::decode(encrypted_hex).ok()?;
        let commitment_bytes: [u8; 32] = hex::decode(commitment_hex)
            .ok()?
            .try_into()
            .ok()?;

        NoteStore::try_decrypt_received_note_with_epoch(
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

    fn make_test_keys() -> (secp256k1::SecretKey, secp256k1::PublicKey) {
        let sk_bytes = [1u8; 32];
        let sk = secp256k1::SecretKey::from_slice(&sk_bytes).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key_global(&sk);
        (sk, pk)
    }

    fn make_other_keys() -> (secp256k1::SecretKey, secp256k1::PublicKey) {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[0] = 2;
        let sk = secp256k1::SecretKey::from_slice(&sk_bytes).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key_global(&sk);
        (sk, pk)
    }

    fn encrypt_note(
        value: u64,
        blinding: [u8; 32],
        note_index: u64,
        pubkey: &secp256k1::PublicKey,
    ) -> (String, String) {
        let note_data = ghost_keys::NoteData {
            value,
            blinding,
            note_index,
        };
        let encrypted = note_data.encrypt(pubkey).expect("encryption should work");
        let encrypted_hex = hex::encode(&encrypted);

        let commitment =
            ghost_zkp::compute_commitment_bytes(value, &blinding).expect("commitment should work");
        let commitment_hex = hex::encode(commitment);

        (encrypted_hex, commitment_hex)
    }

    #[test]
    fn test_discover_recipient_note() {
        let (sk, pk) = make_test_keys();
        let blinding = [10u8; 32];
        let (encrypted_hex, commitment_hex) = encrypt_note(5000, blinding, 3, &pk);

        let tx = L2TransactionInfo {
            checkpoint_height: 100,
            epoch: 1,
            nullifier: "aa".repeat(32),
            change_commitment: "bb".repeat(32),
            recipient_commitment: commitment_hex,
            encrypted_change: None,
            encrypted_recipient: Some(encrypted_hex),
        };

        let mut scanner = NoteScanner::new(sk);
        let discovered = scanner.scan_transactions(&[tx]);

        assert_eq!(discovered.len(), 1);
        assert!(!discovered[0].is_change);
        assert_eq!(discovered[0].note.value, 5000);
        assert_eq!(discovered[0].note.blinding, blinding);
        assert_eq!(discovered[0].note.index, 3);
        assert_eq!(discovered[0].checkpoint_height, 100);
    }

    #[test]
    fn test_discover_change_note() {
        let (sk, pk) = make_test_keys();
        let blinding = [20u8; 32];
        let (encrypted_hex, commitment_hex) = encrypt_note(3000, blinding, 7, &pk);

        let tx = L2TransactionInfo {
            checkpoint_height: 200,
            epoch: 1,
            nullifier: "aa".repeat(32),
            change_commitment: commitment_hex,
            recipient_commitment: "cc".repeat(32),
            encrypted_change: Some(encrypted_hex),
            encrypted_recipient: None,
        };

        let mut scanner = NoteScanner::new(sk);
        let discovered = scanner.scan_transactions(&[tx]);

        assert_eq!(discovered.len(), 1);
        assert!(discovered[0].is_change);
        assert_eq!(discovered[0].note.value, 3000);
    }

    #[test]
    fn test_ignore_wrong_key_transactions() {
        let (sk, _pk) = make_test_keys();
        let (_other_sk, other_pk) = make_other_keys();

        // Encrypt for a different key
        let blinding = [30u8; 32];
        let (encrypted_hex, commitment_hex) = encrypt_note(1000, blinding, 1, &other_pk);

        let tx = L2TransactionInfo {
            checkpoint_height: 300,
            epoch: 1,
            nullifier: "aa".repeat(32),
            change_commitment: "bb".repeat(32),
            recipient_commitment: commitment_hex,
            encrypted_change: None,
            encrypted_recipient: Some(encrypted_hex),
        };

        let mut scanner = NoteScanner::new(sk);
        let discovered = scanner.scan_transactions(&[tx]);

        assert_eq!(discovered.len(), 0, "Should not discover notes encrypted for other keys");
    }

    #[test]
    fn test_self_transfer_discovers_both() {
        let (sk, pk) = make_test_keys();

        let change_blinding = [40u8; 32];
        let (change_enc, change_commit) = encrypt_note(7000, change_blinding, 10, &pk);

        let recipient_blinding = [50u8; 32];
        let (recipient_enc, recipient_commit) = encrypt_note(3000, recipient_blinding, 11, &pk);

        let tx = L2TransactionInfo {
            checkpoint_height: 400,
            epoch: 1,
            nullifier: "aa".repeat(32),
            change_commitment: change_commit,
            recipient_commitment: recipient_commit,
            encrypted_change: Some(change_enc),
            encrypted_recipient: Some(recipient_enc),
        };

        let mut scanner = NoteScanner::new(sk);
        let discovered = scanner.scan_transactions(&[tx]);

        assert_eq!(discovered.len(), 2);
        let change = discovered.iter().find(|d| d.is_change).unwrap();
        let recipient = discovered.iter().find(|d| !d.is_change).unwrap();
        assert_eq!(change.note.value, 7000);
        assert_eq!(recipient.note.value, 3000);
    }

    #[test]
    fn test_epoch_detection() {
        let (sk, pk) = make_test_keys();
        let blinding = [10u8; 32];
        let (encrypted_hex, commitment_hex) = encrypt_note(5000, blinding, 3, &pk);

        let tx = L2TransactionInfo {
            checkpoint_height: 100,
            epoch: 5,
            nullifier: "aa".repeat(32),
            change_commitment: "bb".repeat(32),
            recipient_commitment: commitment_hex,
            encrypted_change: None,
            encrypted_recipient: Some(encrypted_hex),
        };

        let mut scanner = NoteScanner::new(sk);
        assert_eq!(scanner.last_seen_epoch(), 0);

        let discovered = scanner.scan_transactions(&[tx]);
        assert_eq!(discovered.len(), 1);
        assert_eq!(scanner.last_seen_epoch(), 5);
        assert_eq!(discovered[0].note.epoch, 5);
    }

    #[test]
    fn test_epoch_tracked_on_discovered_notes() {
        let (sk, pk) = make_test_keys();
        let blinding = [10u8; 32];
        let (encrypted_hex, commitment_hex) = encrypt_note(2000, blinding, 7, &pk);

        let tx = L2TransactionInfo {
            checkpoint_height: 200,
            epoch: 3,
            nullifier: "aa".repeat(32),
            change_commitment: "bb".repeat(32),
            recipient_commitment: commitment_hex,
            encrypted_change: None,
            encrypted_recipient: Some(encrypted_hex),
        };

        let mut scanner = NoteScanner::new(sk);
        let discovered = scanner.scan_transactions(&[tx]);

        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].note.epoch, 3, "Note should carry the epoch from the transaction");
    }
}
