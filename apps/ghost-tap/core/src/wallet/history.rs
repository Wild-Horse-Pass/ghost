//! Transaction history management

use serde::{Deserialize, Serialize};

/// Transaction direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxDirection {
    Incoming,
    Outgoing,
}

/// Transaction status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxStatus {
    Pending,
    Confirmed(u32), // confirmation count
    Failed,
}

/// A transaction in the wallet history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Transaction ID
    pub txid: String,
    /// Direction (incoming/outgoing)
    pub direction: TxDirection,
    /// Amount transferred (excluding fees for outgoing)
    pub amount: u64,
    /// Fee paid (only for outgoing)
    pub fee: Option<u64>,
    /// Counterparty address
    pub address: String,
    /// Transaction status
    pub status: TxStatus,
    /// Unix timestamp
    pub timestamp: u64,
    /// Optional memo/note
    pub memo: Option<String>,
}

/// Transaction history manager
#[derive(Debug, Default)]
pub struct TransactionHistory {
    entries: Vec<HistoryEntry>,
}

impl TransactionHistory {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a transaction to history
    pub fn add(&mut self, entry: HistoryEntry) {
        // Insert in chronological order (newest first)
        let pos = self
            .entries
            .iter()
            .position(|e| e.timestamp < entry.timestamp)
            .unwrap_or(self.entries.len());
        self.entries.insert(pos, entry);
    }

    /// Update transaction status
    pub fn update_status(&mut self, txid: &str, status: TxStatus) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.txid == txid) {
            entry.status = status;
        }
    }

    /// Get all entries
    pub fn all(&self) -> &[HistoryEntry] {
        &self.entries
    }

    /// Get entries with pagination
    pub fn paginated(&self, offset: usize, limit: usize) -> &[HistoryEntry] {
        let start = offset.min(self.entries.len());
        let end = (start + limit).min(self.entries.len());
        &self.entries[start..end]
    }

    /// Get pending transactions
    pub fn pending(&self) -> Vec<&HistoryEntry> {
        self.entries
            .iter()
            .filter(|e| matches!(e.status, TxStatus::Pending))
            .collect()
    }

    /// Find transaction by ID
    pub fn find(&self, txid: &str) -> Option<&HistoryEntry> {
        self.entries.iter().find(|e| e.txid == txid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_history_ordering() {
        let mut history = TransactionHistory::new();

        history.add(HistoryEntry {
            txid: "tx1".into(),
            direction: TxDirection::Incoming,
            amount: 100,
            fee: None,
            address: "addr1".into(),
            status: TxStatus::Confirmed(6),
            timestamp: 1000,
            memo: None,
        });

        history.add(HistoryEntry {
            txid: "tx2".into(),
            direction: TxDirection::Outgoing,
            amount: 50,
            fee: Some(1),
            address: "addr2".into(),
            status: TxStatus::Pending,
            timestamp: 2000,
            memo: None,
        });

        // Newest should be first
        assert_eq!(history.all()[0].txid, "tx2");
        assert_eq!(history.all()[1].txid, "tx1");
    }
}
