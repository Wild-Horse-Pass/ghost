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
//| FILE: labels.rs                                                                                                      |
//|======================================================================================================================|

//! Label dictionary for categorizing payments
//!
//! Labels are local-only metadata that help users organize their transactions.
//! The dictionary maps numeric indices (used in encrypted metadata) to human-readable
//! names stored only on the user's device.
//!
//! # Design
//!
//! - Index 0 is reserved for "Uncategorized" and cannot be deleted or renamed
//! - Indices are never reused - deleted labels become "orphaned"
//! - The dictionary is client-side only - label names never leave the device
//! - Backup/restore preserves the full mapping for data portability

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::metadata::DEFAULT_LABEL;

/// Current backup format version
const BACKUP_VERSION: u32 = 1;

/// Default name for the uncategorized label
const DEFAULT_LABEL_NAME: &str = "Uncategorized";

/// Label dictionary for mapping indices to human-readable names
///
/// This is a client-side only structure. Label names are never transmitted
/// over the network or included in transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelDictionary {
    /// Mapping from label index to name
    labels: HashMap<u32, String>,
    /// Next index to assign (monotonically increasing)
    next_index: u32,
}

impl Default for LabelDictionary {
    fn default() -> Self {
        Self::new()
    }
}

impl LabelDictionary {
    /// Create a new label dictionary with only the default label
    pub fn new() -> Self {
        let mut labels = HashMap::new();
        labels.insert(DEFAULT_LABEL, DEFAULT_LABEL_NAME.to_string());

        Self {
            labels,
            next_index: 1, // Start at 1 since 0 is reserved
        }
    }

    /// Create a new label and return its index
    ///
    /// Labels are assigned monotonically increasing indices that are never reused.
    pub fn create(&mut self, name: &str) -> u32 {
        let index = self.next_index;
        self.labels.insert(index, name.to_string());
        self.next_index += 1;
        index
    }

    /// Rename an existing label
    ///
    /// Returns false if the label doesn't exist or is the default label (index 0).
    pub fn rename(&mut self, index: u32, new_name: &str) -> bool {
        // Cannot rename the default label
        if index == DEFAULT_LABEL {
            return false;
        }

        if let std::collections::hash_map::Entry::Occupied(mut e) = self.labels.entry(index) {
            e.insert(new_name.to_string());
            true
        } else {
            false
        }
    }

    /// Delete a label
    ///
    /// Returns false if the label doesn't exist or is the default label (index 0).
    /// Note: The index is never reused, so existing transactions referencing
    /// this label will show as "orphaned".
    pub fn delete(&mut self, index: u32) -> bool {
        // Cannot delete the default label
        if index == DEFAULT_LABEL {
            return false;
        }

        self.labels.remove(&index).is_some()
    }

    /// Look up a label name by index
    ///
    /// Returns None if the label has been deleted (orphaned).
    pub fn lookup(&self, index: u32) -> Option<&str> {
        self.labels.get(&index).map(|s| s.as_str())
    }

    /// Check if a label index is orphaned (was deleted but may still be referenced)
    ///
    /// Returns true if the index was once valid but the label has been deleted.
    pub fn is_orphaned(&self, index: u32) -> bool {
        // An index is orphaned if it's within the allocated range but not in the map
        // (and it's not the default label)
        index != DEFAULT_LABEL && index < self.next_index && !self.labels.contains_key(&index)
    }

    /// List all labels sorted by index
    ///
    /// Returns tuples of (index, name) for all existing labels.
    pub fn list(&self) -> Vec<(u32, &str)> {
        let mut labels: Vec<_> = self
            .labels
            .iter()
            .map(|(k, v)| (*k, v.as_str()))
            .collect();
        labels.sort_by_key(|(k, _)| *k);
        labels
    }

    /// Get the number of labels (including default)
    pub fn len(&self) -> usize {
        self.labels.len()
    }

    /// Check if the dictionary only contains the default label
    pub fn is_empty(&self) -> bool {
        self.labels.len() <= 1
    }

    /// Get the next index that will be assigned
    pub fn next_index(&self) -> u32 {
        self.next_index
    }

    /// Create a backup of the label dictionary
    pub fn to_backup(&self) -> LabelBackup {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        LabelBackup {
            labels: self.labels.clone(),
            next_index: self.next_index,
            version: BACKUP_VERSION,
            created_at,
        }
    }

    /// Restore from a backup
    ///
    /// This replaces the current dictionary contents with the backup.
    pub fn from_backup(backup: LabelBackup) -> Self {
        // Ensure default label exists
        let mut labels = backup.labels;
        labels
            .entry(DEFAULT_LABEL)
            .or_insert_with(|| DEFAULT_LABEL_NAME.to_string());

        // Ensure next_index is at least 1
        let next_index = backup.next_index.max(1);

        Self { labels, next_index }
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize from JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Backup format for label dictionary
///
/// Includes version number for forward compatibility and timestamp
/// for tracking when the backup was created.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelBackup {
    /// Label index to name mapping
    pub labels: HashMap<u32, String>,
    /// Next index to assign
    pub next_index: u32,
    /// Backup format version
    pub version: u32,
    /// Unix timestamp when backup was created
    pub created_at: u64,
}

impl LabelBackup {
    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_dictionary() {
        let dict = LabelDictionary::new();
        assert_eq!(dict.len(), 1);
        assert_eq!(dict.lookup(DEFAULT_LABEL), Some("Uncategorized"));
        assert_eq!(dict.next_index(), 1);
    }

    #[test]
    fn test_create_label() {
        let mut dict = LabelDictionary::new();

        let idx1 = dict.create("Work");
        assert_eq!(idx1, 1);
        assert_eq!(dict.lookup(1), Some("Work"));

        let idx2 = dict.create("Personal");
        assert_eq!(idx2, 2);
        assert_eq!(dict.lookup(2), Some("Personal"));

        assert_eq!(dict.len(), 3);
    }

    #[test]
    fn test_rename_label() {
        let mut dict = LabelDictionary::new();
        let idx = dict.create("Old Name");

        assert!(dict.rename(idx, "New Name"));
        assert_eq!(dict.lookup(idx), Some("New Name"));
    }

    #[test]
    fn test_cannot_rename_default() {
        let mut dict = LabelDictionary::new();
        assert!(!dict.rename(DEFAULT_LABEL, "Custom"));
        assert_eq!(dict.lookup(DEFAULT_LABEL), Some("Uncategorized"));
    }

    #[test]
    fn test_delete_label() {
        let mut dict = LabelDictionary::new();
        let idx = dict.create("Temporary");

        assert!(dict.delete(idx));
        assert_eq!(dict.lookup(idx), None);
        assert!(dict.is_orphaned(idx));
    }

    #[test]
    fn test_cannot_delete_default() {
        let mut dict = LabelDictionary::new();
        assert!(!dict.delete(DEFAULT_LABEL));
        assert_eq!(dict.lookup(DEFAULT_LABEL), Some("Uncategorized"));
    }

    #[test]
    fn test_orphaned_detection() {
        let mut dict = LabelDictionary::new();

        // Index 0 is never orphaned (it's the default)
        assert!(!dict.is_orphaned(0));

        // Index 100 is not orphaned (never allocated)
        assert!(!dict.is_orphaned(100));

        // Create and delete a label
        let idx = dict.create("Test");
        assert!(!dict.is_orphaned(idx));

        dict.delete(idx);
        assert!(dict.is_orphaned(idx));
    }

    #[test]
    fn test_list_labels() {
        let mut dict = LabelDictionary::new();
        dict.create("B Label");
        dict.create("A Label");

        let list = dict.list();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0], (0, "Uncategorized"));
        assert_eq!(list[1], (1, "B Label"));
        assert_eq!(list[2], (2, "A Label"));
    }

    #[test]
    fn test_backup_restore() {
        let mut dict = LabelDictionary::new();
        dict.create("Work");
        dict.create("Personal");
        dict.delete(1); // Delete "Work"

        let backup = dict.to_backup();
        assert_eq!(backup.version, BACKUP_VERSION);
        assert!(backup.created_at > 0);

        let restored = LabelDictionary::from_backup(backup);
        assert_eq!(restored.len(), 2); // Default + Personal
        assert_eq!(restored.lookup(0), Some("Uncategorized"));
        assert_eq!(restored.lookup(1), None);
        assert_eq!(restored.lookup(2), Some("Personal"));
        assert!(restored.is_orphaned(1));
    }

    #[test]
    fn test_json_roundtrip() {
        let mut dict = LabelDictionary::new();
        dict.create("Test Label");

        let json = dict.to_json().unwrap();
        let restored = LabelDictionary::from_json(&json).unwrap();

        assert_eq!(restored.len(), dict.len());
        assert_eq!(restored.lookup(1), Some("Test Label"));
    }

    #[test]
    fn test_backup_json_roundtrip() {
        let mut dict = LabelDictionary::new();
        dict.create("Test");

        let backup = dict.to_backup();
        let json = backup.to_json().unwrap();
        let restored_backup = LabelBackup::from_json(&json).unwrap();

        assert_eq!(restored_backup.version, backup.version);
        assert_eq!(restored_backup.next_index, backup.next_index);
        assert_eq!(restored_backup.labels, backup.labels);
    }

    #[test]
    fn test_indices_never_reused() {
        let mut dict = LabelDictionary::new();

        let idx1 = dict.create("First");
        dict.delete(idx1);

        let idx2 = dict.create("Second");
        assert_ne!(idx1, idx2);
        assert!(idx2 > idx1);
    }

    #[test]
    fn test_restore_ensures_default_label() {
        // Create a backup without the default label
        let backup = LabelBackup {
            labels: HashMap::from([(5, "Custom".to_string())]),
            next_index: 6,
            version: 1,
            created_at: 0,
        };

        let restored = LabelDictionary::from_backup(backup);
        assert_eq!(restored.lookup(DEFAULT_LABEL), Some("Uncategorized"));
        assert_eq!(restored.lookup(5), Some("Custom"));
    }
}
