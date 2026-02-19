//! Owned note tracking for confidential transfers
//!
//! Manages the wallet's confidential notes (commitments with known
//! values and blindings). Notes are persisted encrypted in the wallet
//! cache database.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::error::{LightWalletError, WalletResult};

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
}

impl NoteStore {
    /// Create a new note store with the given spending key
    pub fn new(spending_key: [u8; 32]) -> Self {
        Self {
            notes: HashMap::new(),
            spending_key,
        }
    }

    /// Get the spending key bytes
    pub fn spending_key(&self) -> &[u8; 32] {
        &self.spending_key
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

    /// Serialize the note store to JSON for encrypted storage
    pub fn to_json(&self) -> WalletResult<String> {
        let notes: Vec<&OwnedNote> = self.notes.values().collect();
        serde_json::to_string(&notes)
            .map_err(|e| LightWalletError::Storage(format!("Failed to serialize notes: {}", e)))
    }

    /// Deserialize notes from JSON (spending key provided separately)
    pub fn from_json(json: &str, spending_key: [u8; 32]) -> WalletResult<Self> {
        let notes: Vec<OwnedNote> = serde_json::from_str(json)
            .map_err(|e| LightWalletError::Storage(format!("Failed to deserialize notes: {}", e)))?;

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
        });
        store.add_note(OwnedNote {
            index: 1,
            value: 1000,
            blinding: [2u8; 32],
            spent: false,
            created_height: 101,
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
        });
        store.add_note(OwnedNote {
            index: 5,
            value: 2000,
            blinding: [2u8; 32],
            spent: true,
            created_height: 200,
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
}
