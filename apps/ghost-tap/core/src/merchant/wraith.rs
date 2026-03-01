//! Wraith wash integration for merchant payments
//!
//! Provides a queue-based system for washing received public payments
//! through the Wraith Protocol (public -> private -> public) to enhance
//! transaction privacy.

use crate::storage::WalletStorage;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

/// Current status of a wash request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WashStatus {
    /// Waiting in the queue to be processed.
    Queued,
    /// Currently being washed (public -> private leg submitted).
    InProgress,
    /// Wash cycle complete (private -> public leg confirmed).
    Completed,
    /// Wash failed at some stage.
    Failed,
}

impl std::fmt::Display for WashStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WashStatus::Queued => write!(f, "Queued"),
            WashStatus::InProgress => write!(f, "In Progress"),
            WashStatus::Completed => write!(f, "Completed"),
            WashStatus::Failed => write!(f, "Failed"),
        }
    }
}

/// A single wash request tracking one payment through the Wraith cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WashRequest {
    /// Transaction ID of the original public payment.
    pub txid: String,
    /// Amount to be washed (satoshis).
    pub amount: u64,
    /// Current status of the wash.
    pub status: WashStatus,
    /// Transaction ID of the public -> private leg (set when InProgress).
    pub wraith_in_txid: Option<String>,
    /// Transaction ID of the private -> public leg (set when Completed).
    pub wraith_out_txid: Option<String>,
    /// Unix timestamp when this request was created.
    pub created_at: u64,
    /// Unix timestamp when this request was last updated.
    pub updated_at: u64,
    /// Number of retry attempts if the wash has failed.
    pub retry_count: u32,
}

impl WashRequest {
    /// Create a new wash request in the Queued state.
    pub(crate) fn new(txid: impl Into<String>, amount: u64, now: u64) -> Self {
        Self {
            txid: txid.into(),
            amount,
            status: WashStatus::Queued,
            wraith_in_txid: None,
            wraith_out_txid: None,
            created_at: now,
            updated_at: now,
            retry_count: 0,
        }
    }
}

/// Manages a queue of Wraith wash requests.
///
/// The wash flow is: receive a public payment, send it to a private
/// (anon) stealth address, then send it back to a fresh public address.
/// This breaks the on-chain link between the payer and the merchant.
pub struct WraithWasher {
    /// The wash queue.
    queue: Vec<WashRequest>,
    /// Maximum number of concurrent in-progress washes.
    max_concurrent: usize,
    /// Optional persistent storage backend.
    storage: Option<Arc<Mutex<WalletStorage>>>,
}

impl WraithWasher {
    /// Create a new washer with default settings.
    pub fn new() -> Self {
        Self {
            queue: Vec::new(),
            max_concurrent: 3,
            storage: None,
        }
    }

    /// Create a new washer with a custom concurrency limit.
    pub fn with_max_concurrent(max_concurrent: usize) -> Self {
        Self {
            queue: Vec::new(),
            max_concurrent,
            storage: None,
        }
    }

    /// Create a new washer with persistent storage.
    ///
    /// Loads any existing wash requests from the database on construction.
    pub fn with_storage(storage: Arc<Mutex<WalletStorage>>) -> Self {
        let queue = storage
            .lock()
            .ok()
            .and_then(|s| s.load_wash_queue().ok())
            .unwrap_or_default();

        Self {
            queue,
            max_concurrent: 3,
            storage: Some(storage),
        }
    }

    /// Persist a wash request to the database (if storage is attached).
    fn persist(storage: &Option<Arc<Mutex<WalletStorage>>>, req: &WashRequest) {
        if let Some(ref storage) = storage {
            if let Ok(s) = storage.lock() {
                let _ = s.save_wash_request(req);
            }
        }
    }

    /// Delete a wash request from the database (if storage is attached).
    fn persist_delete(storage: &Option<Arc<Mutex<WalletStorage>>>, txid: &str) {
        if let Some(ref storage) = storage {
            if let Ok(s) = storage.lock() {
                let _ = s.delete_wash_request(txid);
            }
        }
    }

    /// Immediately create a wash request for a payment.
    ///
    /// The request is added to the queue in the `Queued` state. A
    /// background processor should pick it up and drive it through
    /// the `InProgress` -> `Completed` states.
    ///
    /// `now` should be the current unix timestamp.
    pub fn wash_payment(
        &mut self,
        txid: impl Into<String>,
        amount: u64,
        now: u64,
    ) -> &WashRequest {
        let request = WashRequest::new(txid, amount, now);
        self.queue.push(request);
        let req = self.queue.last().unwrap();
        Self::persist(&self.storage, req);
        req
    }

    /// Add a payment to the background wash queue.
    ///
    /// This is a convenience alias for `wash_payment` for callers that
    /// want to emphasise the async/background nature.
    pub fn queue_wash(
        &mut self,
        txid: impl Into<String>,
        amount: u64,
        now: u64,
    ) -> &WashRequest {
        self.wash_payment(txid, amount, now)
    }

    /// Get all wash requests (all statuses).
    pub fn get_queue(&self) -> &[WashRequest] {
        &self.queue
    }

    /// Get only the pending (Queued + InProgress) wash requests.
    pub fn get_pending(&self) -> Vec<&WashRequest> {
        self.queue
            .iter()
            .filter(|r| r.status == WashStatus::Queued || r.status == WashStatus::InProgress)
            .collect()
    }

    /// Get only the queued requests that are ready to start.
    pub fn get_ready(&self) -> Vec<&WashRequest> {
        let in_progress_count = self
            .queue
            .iter()
            .filter(|r| r.status == WashStatus::InProgress)
            .count();

        if in_progress_count >= self.max_concurrent {
            return Vec::new();
        }

        let available_slots = self.max_concurrent - in_progress_count;

        self.queue
            .iter()
            .filter(|r| r.status == WashStatus::Queued)
            .take(available_slots)
            .collect()
    }

    /// Get completed wash requests.
    pub fn get_completed(&self) -> Vec<&WashRequest> {
        self.queue
            .iter()
            .filter(|r| r.status == WashStatus::Completed)
            .collect()
    }

    /// Get failed wash requests.
    pub fn get_failed(&self) -> Vec<&WashRequest> {
        self.queue
            .iter()
            .filter(|r| r.status == WashStatus::Failed)
            .collect()
    }

    /// Mark a wash request as in-progress (public -> private leg submitted).
    ///
    /// Sets the `wraith_in_txid` to the txid of the public-to-private
    /// transaction.
    pub fn mark_in_progress(
        &mut self,
        txid: &str,
        wraith_in_txid: impl Into<String>,
        now: u64,
    ) -> bool {
        if let Some(req) = self.queue.iter_mut().find(|r| r.txid == txid) {
            req.status = WashStatus::InProgress;
            req.wraith_in_txid = Some(wraith_in_txid.into());
            req.updated_at = now;
            Self::persist(&self.storage, req);
            true
        } else {
            false
        }
    }

    /// Mark a wash request as completed (private -> public leg confirmed).
    ///
    /// Sets the `wraith_out_txid` to the txid of the private-to-public
    /// transaction.
    pub fn mark_completed(
        &mut self,
        txid: &str,
        wraith_out_txid: impl Into<String>,
        now: u64,
    ) -> bool {
        if let Some(req) = self.queue.iter_mut().find(|r| r.txid == txid) {
            req.status = WashStatus::Completed;
            req.wraith_out_txid = Some(wraith_out_txid.into());
            req.updated_at = now;
            Self::persist(&self.storage, req);
            true
        } else {
            false
        }
    }

    /// Mark a wash request as failed.
    pub fn mark_failed(&mut self, txid: &str, now: u64) -> bool {
        if let Some(req) = self.queue.iter_mut().find(|r| r.txid == txid) {
            req.status = WashStatus::Failed;
            req.retry_count += 1;
            req.updated_at = now;
            Self::persist(&self.storage, req);
            true
        } else {
            false
        }
    }

    /// Re-queue a failed wash request for another attempt.
    pub fn retry_failed(&mut self, txid: &str, now: u64) -> bool {
        if let Some(req) = self.queue.iter_mut().find(|r| {
            r.txid == txid && r.status == WashStatus::Failed
        }) {
            req.status = WashStatus::Queued;
            req.wraith_in_txid = None;
            req.wraith_out_txid = None;
            req.updated_at = now;
            Self::persist(&self.storage, req);
            true
        } else {
            false
        }
    }

    /// Attach persistent storage after construction.
    ///
    /// Loads any existing wash requests from the database and merges
    /// them into the current queue. Future mutations will be persisted.
    pub fn attach_storage(&mut self, storage: Arc<Mutex<WalletStorage>>) {
        let persisted = storage
            .lock()
            .ok()
            .and_then(|s| s.load_wash_queue().ok())
            .unwrap_or_default();

        // Merge: add persisted items not already in our queue
        for req in persisted {
            if !self.queue.iter().any(|r| r.txid == req.txid) {
                self.queue.push(req);
            }
        }

        self.storage = Some(storage);
    }

    /// Remove completed and failed requests older than `max_age` seconds.
    pub fn prune(&mut self, now: u64, max_age: u64) {
        // Collect txids to delete from DB
        let to_delete: Vec<String> = self
            .queue
            .iter()
            .filter(|r| {
                matches!(r.status, WashStatus::Completed | WashStatus::Failed)
                    && now.saturating_sub(r.updated_at) >= max_age
            })
            .map(|r| r.txid.clone())
            .collect();

        for txid in &to_delete {
            Self::persist_delete(&self.storage, txid);
        }

        self.queue.retain(|r| {
            match r.status {
                WashStatus::Completed | WashStatus::Failed => {
                    now.saturating_sub(r.updated_at) < max_age
                }
                _ => true,
            }
        });
    }

    /// Summary statistics for the wash queue.
    pub fn stats(&self) -> WashStats {
        let mut stats = WashStats::default();
        for req in &self.queue {
            match req.status {
                WashStatus::Queued => {
                    stats.queued += 1;
                    stats.queued_amount += req.amount;
                }
                WashStatus::InProgress => {
                    stats.in_progress += 1;
                    stats.in_progress_amount += req.amount;
                }
                WashStatus::Completed => {
                    stats.completed += 1;
                    stats.completed_amount += req.amount;
                }
                WashStatus::Failed => {
                    stats.failed += 1;
                    stats.failed_amount += req.amount;
                }
            }
        }
        stats
    }
}

impl Default for WraithWasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary statistics for the wash queue.
#[derive(Debug, Clone, Default)]
pub struct WashStats {
    pub queued: usize,
    pub queued_amount: u64,
    pub in_progress: usize,
    pub in_progress_amount: u64,
    pub completed: usize,
    pub completed_amount: u64,
    pub failed: usize,
    pub failed_amount: u64,
}

impl WashStats {
    /// Total number of requests across all statuses.
    pub fn total_count(&self) -> usize {
        self.queued + self.in_progress + self.completed + self.failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wash_lifecycle() {
        let mut washer = WraithWasher::new();

        // Queue a wash
        let req = washer.wash_payment("tx_original", 100_000_000, 1000);
        assert_eq!(req.status, WashStatus::Queued);
        assert_eq!(req.amount, 100_000_000);

        // Mark in progress
        assert!(washer.mark_in_progress("tx_original", "tx_wraith_in", 2000));
        let pending = washer.get_pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].status, WashStatus::InProgress);
        assert_eq!(pending[0].wraith_in_txid.as_deref(), Some("tx_wraith_in"));

        // Mark completed
        assert!(washer.mark_completed("tx_original", "tx_wraith_out", 3000));
        let completed = washer.get_completed();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].wraith_out_txid.as_deref(), Some("tx_wraith_out"));

        // Pending should now be empty
        assert!(washer.get_pending().is_empty());
    }

    #[test]
    fn test_wash_failure_and_retry() {
        let mut washer = WraithWasher::new();
        washer.wash_payment("tx1", 50_000_000, 1000);

        washer.mark_in_progress("tx1", "tx_in", 2000);
        washer.mark_failed("tx1", 3000);

        let failed = washer.get_failed();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].retry_count, 1);

        // Retry
        assert!(washer.retry_failed("tx1", 4000));
        let ready = washer.get_ready();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].status, WashStatus::Queued);
    }

    #[test]
    fn test_concurrency_limit() {
        let mut washer = WraithWasher::with_max_concurrent(2);

        washer.wash_payment("tx1", 100, 1000);
        washer.wash_payment("tx2", 200, 1000);
        washer.wash_payment("tx3", 300, 1000);

        // All three are ready initially
        assert_eq!(washer.get_ready().len(), 2); // limited to max_concurrent

        washer.mark_in_progress("tx1", "in1", 2000);
        washer.mark_in_progress("tx2", "in2", 2000);

        // Now at max concurrent, no more ready
        assert_eq!(washer.get_ready().len(), 0);

        // Complete one
        washer.mark_completed("tx1", "out1", 3000);

        // Now one slot available
        assert_eq!(washer.get_ready().len(), 1);
        assert_eq!(washer.get_ready()[0].txid, "tx3");
    }

    #[test]
    fn test_prune() {
        let mut washer = WraithWasher::new();

        washer.wash_payment("tx_old", 100, 1000);
        washer.mark_in_progress("tx_old", "in", 2000);
        washer.mark_completed("tx_old", "out", 3000);

        washer.wash_payment("tx_recent", 200, 9000);
        washer.mark_in_progress("tx_recent", "in2", 9500);
        washer.mark_completed("tx_recent", "out2", 10000);

        // Prune items older than 5000 seconds at now=12000
        // tx_old completed at 3000, age = 9000 > 5000 => pruned
        // tx_recent completed at 10000, age = 2000 < 5000 => kept
        washer.prune(12000, 5000);
        assert_eq!(washer.get_queue().len(), 1);
        assert_eq!(washer.get_queue()[0].txid, "tx_recent");
    }

    #[test]
    fn test_stats() {
        let mut washer = WraithWasher::new();

        washer.wash_payment("tx1", 100, 0);
        washer.wash_payment("tx2", 200, 0);
        washer.wash_payment("tx3", 300, 0);

        washer.mark_in_progress("tx2", "in2", 1);
        washer.mark_in_progress("tx3", "in3", 1);
        washer.mark_completed("tx3", "out3", 2);

        let stats = washer.stats();
        assert_eq!(stats.queued, 1);
        assert_eq!(stats.queued_amount, 100);
        assert_eq!(stats.in_progress, 1);
        assert_eq!(stats.in_progress_amount, 200);
        assert_eq!(stats.completed, 1);
        assert_eq!(stats.completed_amount, 300);
        assert_eq!(stats.total_count(), 3);
    }

    #[test]
    fn test_queue_wash_alias() {
        let mut washer = WraithWasher::new();
        let req = washer.queue_wash("tx_q", 999, 42);
        assert_eq!(req.txid, "tx_q");
        assert_eq!(req.amount, 999);
        assert_eq!(req.status, WashStatus::Queued);
    }

    #[test]
    fn test_persist_and_reload() {
        let storage = Arc::new(Mutex::new(
            WalletStorage::open(":memory:", &[42u8; 32]).unwrap(),
        ));

        // Create washer with storage and add items
        {
            let mut washer = WraithWasher::with_storage(Arc::clone(&storage));
            washer.wash_payment("tx_persist", 100_000, 1000);
            washer.mark_in_progress("tx_persist", "wraith_in_1", 2000);
            assert_eq!(washer.get_queue().len(), 1);
        }

        // Create a new washer from the same storage — should reload
        {
            let washer = WraithWasher::with_storage(Arc::clone(&storage));
            assert_eq!(washer.get_queue().len(), 1);
            assert_eq!(washer.get_queue()[0].txid, "tx_persist");
            assert_eq!(washer.get_queue()[0].status, WashStatus::InProgress);
            assert_eq!(
                washer.get_queue()[0].wraith_in_txid.as_deref(),
                Some("wraith_in_1")
            );
        }
    }

    #[test]
    fn test_prune_persists() {
        let storage = Arc::new(Mutex::new(
            WalletStorage::open(":memory:", &[42u8; 32]).unwrap(),
        ));

        {
            let mut washer = WraithWasher::with_storage(Arc::clone(&storage));
            washer.wash_payment("tx_old", 100, 1000);
            washer.mark_in_progress("tx_old", "in", 2000);
            washer.mark_completed("tx_old", "out", 3000);
            washer.prune(12000, 5000);
            assert!(washer.get_queue().is_empty());
        }

        // After reload, pruned item should be gone
        {
            let washer = WraithWasher::with_storage(Arc::clone(&storage));
            assert!(washer.get_queue().is_empty());
        }
    }

    #[test]
    fn test_backward_compat_without_storage() {
        // Existing tests use no storage — should still work identically
        let mut washer = WraithWasher::new();
        washer.wash_payment("tx1", 100, 0);
        washer.mark_in_progress("tx1", "in1", 1);
        washer.mark_completed("tx1", "out1", 2);
        assert_eq!(washer.get_completed().len(), 1);
    }
}
