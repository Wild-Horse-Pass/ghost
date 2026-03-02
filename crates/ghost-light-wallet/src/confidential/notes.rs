//! Owned note tracking for confidential transfers
//!
//! Manages the wallet's confidential notes (commitments with known
//! values and blindings). Notes are persisted encrypted in the wallet
//! cache database.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::error::{LightWalletError, WalletResult};

/// Result of selecting notes for a transfer
#[derive(Debug, Clone)]
pub enum NoteSelection {
    /// A single note has sufficient value for the transfer
    Direct { note_index: u64 },
    /// No single note suffices — notes must be consolidated first
    NeedsConsolidation { plan: ConsolidationPlan },
}

/// Plan for consolidating multiple notes into one
#[derive(Debug, Clone)]
pub struct ConsolidationPlan {
    /// Indices of notes to consolidate (up to 4)
    pub input_indices: Vec<u64>,
    /// Total value after consolidation
    pub total_value: u64,
}

/// A confidential note owned by this wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnedNote {
    /// Index in the commitment tree
    pub index: u64,
    /// Value in satoshis (known only to the wallet)
    pub value: u64,
    /// Blinding factor (32 bytes, known only to the wallet)
    pub blinding: [u8; 32],
    /// Whether this note has been spent
    pub spent: bool,
    /// Block height when created
    pub created_height: u64,
    /// Epoch when this note was created (for nullifier computation)
    #[serde(default)]
    pub epoch: u64,
}

/// Store for owned confidential notes
///
/// Tracks all notes where the wallet knows the value and blinding.
/// The spending key is derived from the wallet's master key and used
/// for nullifier computation.
#[derive(Debug, ZeroizeOnDrop)]
pub struct NoteStore {
    /// Notes indexed by tree position
    #[zeroize(skip)]
    notes: HashMap<u64, OwnedNote>,
    /// Spending key for nullifier computation (derived from m/352'/0'/0'/3')
    spending_key: [u8; 32],
    /// Current epoch from the server (increments after compaction)
    #[zeroize(skip)]
    current_epoch: u64,
}

impl NoteStore {
    /// Create a new note store with the given spending key
    pub fn new(spending_key: [u8; 32]) -> Self {
        Self {
            notes: HashMap::new(),
            spending_key,
            current_epoch: 0,
        }
    }

    /// Get the spending key bytes
    pub fn spending_key(&self) -> &[u8; 32] {
        &self.spending_key
    }

    /// Get the current epoch
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Update the current epoch from the server.
    ///
    /// If the epoch has changed, marks all notes from the old epoch as stale
    /// (they need re-scanning since tree indices may have changed after compaction).
    /// Returns true if the epoch actually changed.
    pub fn handle_epoch_transition(&mut self, new_epoch: u64) -> bool {
        if new_epoch <= self.current_epoch {
            return false;
        }
        let old_epoch = self.current_epoch;
        self.current_epoch = new_epoch;

        // Mark old-epoch notes as spent (their tree positions are no longer valid
        // after compaction — the wallet must re-scan to discover new positions)
        let mut invalidated = 0;
        for note in self.notes.values_mut() {
            if note.epoch < new_epoch && !note.spent {
                note.spent = true;
                invalidated += 1;
            }
        }

        if invalidated > 0 {
            tracing::warn!(
                old_epoch,
                new_epoch,
                invalidated,
                "Epoch transition: invalidated old-epoch notes (re-scan needed)"
            );
        }

        true
    }

    /// Remove notes from epochs older than current.
    /// Call after re-scanning has discovered the new positions.
    pub fn prune_old_epoch_notes(&mut self) {
        let current = self.current_epoch;
        self.notes.retain(|_, note| note.epoch >= current);
    }

    /// Add a new note to the store
    pub fn add_note(&mut self, note: OwnedNote) {
        self.notes.insert(note.index, note);
    }

    /// Mark a note as spent
    pub fn mark_spent(&mut self, index: u64) -> bool {
        if let Some(note) = self.notes.get_mut(&index) {
            note.spent = true;
            true
        } else {
            false
        }
    }

    /// Get a note by index
    pub fn get_note(&self, index: u64) -> Option<&OwnedNote> {
        self.notes.get(&index)
    }

    /// Get all unspent notes
    pub fn unspent_notes(&self) -> Vec<&OwnedNote> {
        self.notes.values().filter(|n| !n.spent).collect()
    }

    /// Get total unspent confidential balance
    pub fn confidential_balance(&self) -> u64 {
        self.notes
            .values()
            .filter(|n| !n.spent)
            .map(|n| n.value)
            .sum()
    }

    /// Select a note with sufficient balance for a transfer
    pub fn select_note_for_transfer(&self, amount: u64) -> WalletResult<&OwnedNote> {
        self.notes
            .values()
            .filter(|n| !n.spent && n.value >= amount)
            .min_by_key(|n| n.value)
            .ok_or(LightWalletError::InsufficientBalance {
                required: amount,
                available: self.confidential_balance(),
            })
    }

    /// Get number of notes (total, including spent)
    pub fn count(&self) -> usize {
        self.notes.len()
    }

    /// Get number of unspent notes
    pub fn unspent_count(&self) -> usize {
        self.notes.values().filter(|n| !n.spent).count()
    }

    /// Compute nullifier for a note: N = MiMC(MiMC(spending_key, note_id), NULL_DOMAIN)
    /// where note_id = MiMC(MiMC(index, epoch), commitment)
    ///
    /// The nullifier uniquely identifies a spent note and is published on-chain
    /// to prevent double-spending. Different epochs produce different nullifiers
    /// for the same note (because note_id incorporates epoch).
    pub fn compute_nullifier(&self, note: &OwnedNote, epoch: u64) -> WalletResult<[u8; 32]> {
        use blstrs::Scalar;
        use ghost_zkp::{bytes_to_field, field_to_bytes};

        let spending_key_fr: Scalar = bytes_to_field(&self.spending_key).map_err(|e| {
            LightWalletError::Internal(format!("Invalid spending key field element: {:?}", e))
        })?;

        // Compute commitment: pedersen_commit(value, blinding)
        let value_fr = Scalar::from(note.value);
        let blinding_fr: Scalar = bytes_to_field(&note.blinding).map_err(|e| {
            LightWalletError::Internal(format!("Invalid blinding field element: {:?}", e))
        })?;
        let commitment = ghost_zkp::pedersen_commit_native(value_fr, blinding_fr);

        // Compute nullifier with epoch
        let nullifier = ghost_zkp::compute_nullifier_with_epoch_native(
            spending_key_fr,
            note.index,
            epoch,
            commitment,
        );

        Ok(field_to_bytes(nullifier))
    }

    /// Check if a note's nullifier appears in a set of known nullifiers
    pub fn is_note_nullified(
        &self,
        note: &OwnedNote,
        epoch: u64,
        known_nullifiers: &HashSet<[u8; 32]>,
    ) -> WalletResult<bool> {
        let nullifier = self.compute_nullifier(note, epoch)?;
        Ok(known_nullifiers.contains(&nullifier))
    }

    /// Select notes for a transfer, returning either a single note (direct spend)
    /// or a consolidation plan if no single note has sufficient balance.
    ///
    /// Strategy:
    /// 1. Try single note (existing `select_note_for_transfer` logic) -> `Direct`
    /// 2. Check total balance >= amount, else `InsufficientBalance`
    /// 3. Sort unspent by value desc, greedily select up to 4 notes -> `NeedsConsolidation`
    pub fn select_notes_for_transfer(&self, amount: u64) -> WalletResult<NoteSelection> {
        // Try single note first (most efficient — no consolidation needed)
        if let Ok(note) = self.select_note_for_transfer(amount) {
            return Ok(NoteSelection::Direct {
                note_index: note.index,
            });
        }

        // Check total balance
        let total = self.confidential_balance();
        if total < amount {
            return Err(LightWalletError::InsufficientBalance {
                required: amount,
                available: total,
            });
        }

        // Sort unspent notes by value descending, greedily select up to 4
        let mut unspent: Vec<&OwnedNote> = self.notes.values().filter(|n| !n.spent).collect();
        unspent.sort_by(|a, b| b.value.cmp(&a.value));

        let mut selected_indices = Vec::new();
        let mut running_total = 0u64;

        for note in &unspent {
            selected_indices.push(note.index);
            running_total += note.value;
            if running_total >= amount {
                break;
            }
            if selected_indices.len() >= 4 {
                break;
            }
        }

        if running_total >= amount {
            return Ok(NoteSelection::NeedsConsolidation {
                plan: ConsolidationPlan {
                    input_indices: selected_indices,
                    total_value: running_total,
                },
            });
        }

        // Need multiple consolidation rounds (>4 notes required)
        // For now, consolidate the top 4 notes first, then retry
        let top_4: Vec<u64> = unspent.iter().take(4).map(|n| n.index).collect();
        let top_4_total: u64 = unspent.iter().take(4).map(|n| n.value).sum();

        Ok(NoteSelection::NeedsConsolidation {
            plan: ConsolidationPlan {
                input_indices: top_4,
                total_value: top_4_total,
            },
        })
    }

    /// Try to decrypt an encrypted note and verify it matches the on-chain commitment.
    ///
    /// Attempts ECIES decryption with the wallet's secret key. If decryption succeeds,
    /// verifies that `pedersen_commit(value, blinding) == commitment`. Returns an
    /// `OwnedNote` on match, or `None` if decryption fails or commitment doesn't match.
    ///
    /// This is the core of wallet-side note discovery: scan L2 transactions,
    /// try decrypting each encrypted field, and add matching notes to the store.
    pub fn try_decrypt_received_note(
        secret_key: &secp256k1::SecretKey,
        encrypted: &[u8],
        commitment: &[u8; 32],
        block_height: u64,
    ) -> Option<OwnedNote> {
        Self::try_decrypt_received_note_with_epoch(secret_key, encrypted, commitment, block_height, 0)
    }

    /// Like `try_decrypt_received_note` but also records the epoch on the note.
    pub fn try_decrypt_received_note_with_epoch(
        secret_key: &secp256k1::SecretKey,
        encrypted: &[u8],
        commitment: &[u8; 32],
        block_height: u64,
        epoch: u64,
    ) -> Option<OwnedNote> {
        let note_data = ghost_keys::NoteData::decrypt(secret_key, encrypted).ok()?;

        // Verify commitment: pedersen_commit(value, blinding) should match
        let computed = ghost_zkp::compute_commitment_bytes(note_data.value, &note_data.blinding).ok()?;
        if &computed != commitment {
            return None;
        }

        Some(OwnedNote {
            index: note_data.note_index,
            value: note_data.value,
            blinding: note_data.blinding,
            spent: false,
            created_height: block_height,
            epoch,
        })
    }

    /// Serialize the note store to JSON for encrypted storage
    pub fn to_json(&self) -> WalletResult<String> {
        let notes: Vec<&OwnedNote> = self.notes.values().collect();
        serde_json::to_string(&notes)
            .map_err(|e| LightWalletError::Storage(format!("Failed to serialize notes: {}", e)))
    }

    /// Deserialize notes from JSON (spending key provided separately)
    pub fn from_json(json: &str, spending_key: [u8; 32]) -> WalletResult<Self> {
        let notes: Vec<OwnedNote> = serde_json::from_str(json).map_err(|e| {
            LightWalletError::Storage(format!("Failed to deserialize notes: {}", e))
        })?;

        let mut store = Self::new(spending_key);
        for note in notes {
            store.notes.insert(note.index, note);
        }
        Ok(store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_spending_key() -> [u8; 32] {
        [42u8; 32]
    }

    #[test]
    fn test_note_store_basic() {
        let mut store = NoteStore::new(test_spending_key());
        assert_eq!(store.count(), 0);
        assert_eq!(store.confidential_balance(), 0);

        store.add_note(OwnedNote {
            index: 0,
            value: 1000,
            blinding: [1u8; 32],
            spent: false,
            created_height: 100,
            epoch: 0,
        });

        assert_eq!(store.count(), 1);
        assert_eq!(store.unspent_count(), 1);
        assert_eq!(store.confidential_balance(), 1000);
    }

    #[test]
    fn test_mark_spent() {
        let mut store = NoteStore::new(test_spending_key());
        store.add_note(OwnedNote {
            index: 0,
            value: 1000,
            blinding: [1u8; 32],
            spent: false,
            created_height: 100,
            epoch: 0,
        });

        assert!(store.mark_spent(0));
        assert_eq!(store.unspent_count(), 0);
        assert_eq!(store.confidential_balance(), 0);
        assert!(!store.mark_spent(99)); // non-existent
    }

    #[test]
    fn test_select_note_for_transfer() {
        let mut store = NoteStore::new(test_spending_key());
        store.add_note(OwnedNote {
            index: 0,
            value: 500,
            blinding: [1u8; 32],
            spent: false,
            created_height: 100,
            epoch: 0,
        });
        store.add_note(OwnedNote {
            index: 1,
            value: 1000,
            blinding: [2u8; 32],
            spent: false,
            created_height: 101,
            epoch: 0,
        });

        // Should select smallest sufficient note
        let note = store.select_note_for_transfer(600).unwrap();
        assert_eq!(note.index, 1);

        // Should select smaller note when both work
        let note = store.select_note_for_transfer(400).unwrap();
        assert_eq!(note.index, 0);

        // Should fail when insufficient
        let result = store.select_note_for_transfer(2000);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut store = NoteStore::new(test_spending_key());
        store.add_note(OwnedNote {
            index: 0,
            value: 1000,
            blinding: [1u8; 32],
            spent: false,
            created_height: 100,
            epoch: 0,
        });
        store.add_note(OwnedNote {
            index: 5,
            value: 2000,
            blinding: [2u8; 32],
            spent: true,
            created_height: 200,
            epoch: 0,
        });

        let json = store.to_json().unwrap();
        let restored = NoteStore::from_json(&json, test_spending_key()).unwrap();

        assert_eq!(restored.count(), 2);
        assert_eq!(restored.unspent_count(), 1);
        assert_eq!(restored.confidential_balance(), 1000);

        let note = restored.get_note(5).unwrap();
        assert!(note.spent);
        assert_eq!(note.value, 2000);
    }

    #[test]
    fn test_nullifier_roundtrip_matches_circuit() {
        use blstrs::Scalar;
        use ghost_zkp::{bytes_to_field, field_to_bytes};

        let store = NoteStore::new(test_spending_key());
        let note = OwnedNote {
            index: 0,
            value: 1000,
            blinding: [1u8; 32],
            spent: false,
            created_height: 100,
            epoch: 0,
        };
        let epoch = 1u64;

        // Compute via NoteStore
        let nullifier = store.compute_nullifier(&note, epoch).unwrap();

        // Compute directly using the same circuit native functions
        let sk: Scalar = bytes_to_field(&test_spending_key()).unwrap();
        let blinding_fr: Scalar = bytes_to_field(&[1u8; 32]).unwrap();
        let commitment = ghost_zkp::pedersen_commit_native(Scalar::from(1000u64), blinding_fr);
        let expected =
            ghost_zkp::compute_nullifier_with_epoch_native(sk, 0, epoch, commitment);
        let expected_bytes = field_to_bytes(expected);

        assert_eq!(nullifier, expected_bytes);
    }

    #[test]
    fn test_different_epochs_different_nullifiers() {
        let store = NoteStore::new(test_spending_key());
        let note = OwnedNote {
            index: 0,
            value: 1000,
            blinding: [1u8; 32],
            spent: false,
            created_height: 100,
            epoch: 0,
        };

        let null_epoch_1 = store.compute_nullifier(&note, 1).unwrap();
        let null_epoch_2 = store.compute_nullifier(&note, 2).unwrap();

        assert_ne!(
            null_epoch_1, null_epoch_2,
            "Same note in different epochs must produce different nullifiers"
        );
    }

    #[test]
    fn test_different_keys_different_nullifiers() {
        let store_a = NoteStore::new([10u8; 32]);
        let store_b = NoteStore::new([20u8; 32]);
        let note = OwnedNote {
            index: 0,
            value: 1000,
            blinding: [1u8; 32],
            spent: false,
            created_height: 100,
            epoch: 0,
        };

        let null_a = store_a.compute_nullifier(&note, 1).unwrap();
        let null_b = store_b.compute_nullifier(&note, 1).unwrap();

        assert_ne!(
            null_a, null_b,
            "Different spending keys must produce different nullifiers"
        );
    }

    #[test]
    fn test_is_note_nullified() {
        let store = NoteStore::new(test_spending_key());
        let note = OwnedNote {
            index: 0,
            value: 1000,
            blinding: [1u8; 32],
            spent: false,
            created_height: 100,
            epoch: 0,
        };

        let nullifier = store.compute_nullifier(&note, 1).unwrap();
        let mut known = HashSet::new();
        known.insert(nullifier);

        assert!(store.is_note_nullified(&note, 1, &known).unwrap());
        assert!(!store.is_note_nullified(&note, 2, &known).unwrap());
    }

    #[test]
    fn test_select_notes_direct() {
        let mut store = NoteStore::new(test_spending_key());
        store.add_note(OwnedNote {
            index: 0,
            value: 1000,
            blinding: [1u8; 32],
            spent: false,
            created_height: 100,
            epoch: 0,
        });
        store.add_note(OwnedNote {
            index: 1,
            value: 500,
            blinding: [2u8; 32],
            spent: false,
            created_height: 101,
            epoch: 0,
        });

        // Single note suffices
        match store.select_notes_for_transfer(800).unwrap() {
            NoteSelection::Direct { note_index } => assert_eq!(note_index, 0),
            _ => panic!("Expected Direct selection"),
        }
    }

    #[test]
    fn test_select_notes_needs_consolidation() {
        let mut store = NoteStore::new(test_spending_key());
        store.add_note(OwnedNote {
            index: 0,
            value: 400,
            blinding: [1u8; 32],
            spent: false,
            created_height: 100,
            epoch: 0,
        });
        store.add_note(OwnedNote {
            index: 1,
            value: 300,
            blinding: [2u8; 32],
            spent: false,
            created_height: 101,
            epoch: 0,
        });
        store.add_note(OwnedNote {
            index: 2,
            value: 200,
            blinding: [3u8; 32],
            spent: false,
            created_height: 102,
            epoch: 0,
        });

        // No single note has 600, but total = 900
        match store.select_notes_for_transfer(600).unwrap() {
            NoteSelection::NeedsConsolidation { plan } => {
                assert!(plan.total_value >= 600);
                assert!(plan.input_indices.len() >= 2);
                assert!(plan.input_indices.len() <= 4);
            }
            _ => panic!("Expected NeedsConsolidation"),
        }
    }

    #[test]
    fn test_select_notes_insufficient() {
        let mut store = NoteStore::new(test_spending_key());
        store.add_note(OwnedNote {
            index: 0,
            value: 100,
            blinding: [1u8; 32],
            spent: false,
            created_height: 100,
            epoch: 0,
        });

        let result = store.select_notes_for_transfer(500);
        assert!(result.is_err());
    }

    #[test]
    fn test_epoch_transition_invalidates_old_notes() {
        let mut store = NoteStore::new(test_spending_key());
        store.add_note(OwnedNote {
            index: 0,
            value: 1000,
            blinding: [1u8; 32],
            spent: false,
            created_height: 100,
            epoch: 0,
        });
        store.add_note(OwnedNote {
            index: 1,
            value: 500,
            blinding: [2u8; 32],
            spent: false,
            created_height: 200,
            epoch: 1,
        });

        assert_eq!(store.unspent_count(), 2);
        assert_eq!(store.confidential_balance(), 1500);

        // Transition to epoch 2 — notes from epoch 0 and 1 become stale
        let changed = store.handle_epoch_transition(2);
        assert!(changed);
        assert_eq!(store.current_epoch(), 2);
        assert_eq!(store.unspent_count(), 0, "All old-epoch notes should be invalidated");
        assert_eq!(store.confidential_balance(), 0);
    }

    #[test]
    fn test_epoch_transition_no_change() {
        let mut store = NoteStore::new(test_spending_key());
        store.add_note(OwnedNote {
            index: 0,
            value: 1000,
            blinding: [1u8; 32],
            spent: false,
            created_height: 100,
            epoch: 0,
        });

        // Same epoch — no change
        let changed = store.handle_epoch_transition(0);
        assert!(!changed);
        assert_eq!(store.unspent_count(), 1);
    }

    #[test]
    fn test_new_epoch_notes_survive_transition() {
        let mut store = NoteStore::new(test_spending_key());
        store.add_note(OwnedNote {
            index: 0,
            value: 1000,
            blinding: [1u8; 32],
            spent: false,
            created_height: 100,
            epoch: 2,
        });

        // Transition to epoch 2 — note at epoch 2 survives
        let changed = store.handle_epoch_transition(2);
        assert!(changed);
        assert_eq!(store.unspent_count(), 1);
    }

    #[test]
    fn test_prune_old_epoch_notes() {
        let mut store = NoteStore::new(test_spending_key());
        store.add_note(OwnedNote {
            index: 0,
            value: 1000,
            blinding: [1u8; 32],
            spent: false,
            created_height: 100,
            epoch: 0,
        });
        store.add_note(OwnedNote {
            index: 1,
            value: 500,
            blinding: [2u8; 32],
            spent: false,
            created_height: 200,
            epoch: 2,
        });

        store.handle_epoch_transition(2);
        assert_eq!(store.count(), 2); // Both still stored

        store.prune_old_epoch_notes();
        assert_eq!(store.count(), 1); // Only epoch-2 note remains
        assert!(store.get_note(1).is_some());
    }

    #[test]
    fn test_serialization_backward_compat_no_epoch() {
        // Simulate old JSON without epoch field
        let json = r#"[{"index":0,"value":1000,"blinding":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"spent":false,"created_height":100}]"#;
        let store = NoteStore::from_json(json, test_spending_key()).unwrap();
        assert_eq!(store.count(), 1);
        let note = store.get_note(0).unwrap();
        assert_eq!(note.epoch, 0, "Missing epoch should default to 0");
    }
}
