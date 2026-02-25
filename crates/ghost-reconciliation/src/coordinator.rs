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
//| FILE: coordinator.rs                                                                                                 |
//|======================================================================================================================|

//! Settlement Coordinator - Manages epoch settlement lifecycle
//!
//! Coordinates the settlement process for each epoch:
//! 1. Detects epoch boundaries
//! 2. Determines if we are the primary or fallback settler
//! 3. Initiates settlement as primary or waits for timeout as fallback
//! 4. Integrates with BatchExecutor for actual settlement execution
//!
//! Settlement roles:
//! - Primary settler = proposer of the last block in the epoch (block N*2160)
//! - Fallback settler = proposer of the second-to-last block (block N*2160 - 1)
//! - Fallback takes over after 5 minute timeout

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use ghost_common::error::GhostResult;
use ghost_common::identity::NodeIdentity;
use ghost_common::types::NodeId;
use ghost_consensus::{EpochTracker, SettlerRole, SETTLEMENT_TIMEOUT_SECS};

use crate::broadcaster::L1Broadcaster;
use crate::error::{ReconciliationError, ReconciliationResult};
use crate::executor::BatchExecutor;

/// Settlement coordinator state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordinatorState {
    /// Waiting for epoch boundary
    Idle,
    /// We are the primary settler, preparing settlement
    PrimarySettling,
    /// We are the fallback settler, waiting for primary timeout
    WaitingForPrimary,
    /// Fallback has taken over settlement
    FallbackSettling,
    /// Settlement complete for this epoch
    Completed,
}

/// Settlement record for an epoch
#[derive(Debug, Clone)]
pub struct EpochSettlement {
    /// Epoch number
    pub epoch: u64,
    /// Our role in this settlement
    pub role: SettlerRole,
    /// Current state
    pub state: CoordinatorState,
    /// When settlement started
    pub started_at: Instant,
    /// Deadline for primary settler
    pub deadline: Instant,
    /// Batch ID if created
    pub batch_id: Option<u32>,
    /// Error message if failed
    pub error: Option<String>,
}

impl EpochSettlement {
    fn new(epoch: u64, role: SettlerRole) -> Self {
        let now = Instant::now();
        Self {
            epoch,
            role,
            state: CoordinatorState::Idle,
            started_at: now,
            deadline: now + Duration::from_secs(SETTLEMENT_TIMEOUT_SECS),
            batch_id: None,
            error: None,
        }
    }

    /// Check if the primary has timed out
    pub fn is_primary_timed_out(&self) -> bool {
        Instant::now() > self.deadline
    }
}

/// Callback for settlement completion
pub type SettlementCallback = Arc<dyn Fn(u64, bool) -> GhostResult<()> + Send + Sync>;

/// Settlement Coordinator - manages epoch settlement lifecycle
pub struct SettlementCoordinator {
    /// Our node identity
    identity: Arc<NodeIdentity>,
    /// Epoch tracker for settler determination
    epoch_tracker: Arc<EpochTracker>,
    /// Active settlements (epoch -> settlement record)
    settlements: RwLock<HashMap<u64, EpochSettlement>>,
    /// Settlement completion callback
    on_complete: Option<SettlementCallback>,
    /// Maximum concurrent settlements
    max_concurrent: usize,
    /// Batch executor for settlement execution
    executor: Option<RwLock<BatchExecutor>>,
    /// L1 broadcaster for submitting settlement transactions
    broadcaster: Option<Arc<dyn L1Broadcaster>>,
}

impl SettlementCoordinator {
    /// Create a new settlement coordinator
    pub fn new(identity: Arc<NodeIdentity>, epoch_tracker: Arc<EpochTracker>) -> Self {
        Self {
            identity,
            epoch_tracker,
            settlements: RwLock::new(HashMap::new()),
            on_complete: None,
            max_concurrent: 3,
            executor: None,
            broadcaster: None,
        }
    }

    /// Set settlement completion callback
    pub fn with_callback(mut self, callback: SettlementCallback) -> Self {
        self.on_complete = Some(callback);
        self
    }

    /// Set maximum concurrent settlements
    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent = max;
        self
    }

    /// Attach a batch executor for settlement execution
    pub fn with_executor(mut self, executor: BatchExecutor) -> Self {
        self.executor = Some(RwLock::new(executor));
        self
    }

    /// Attach an L1 broadcaster for submitting settlement transactions
    pub fn with_broadcaster(mut self, broadcaster: Arc<dyn L1Broadcaster>) -> Self {
        self.broadcaster = Some(broadcaster);
        self
    }

    /// Get our node ID
    pub fn node_id(&self) -> NodeId {
        self.identity.node_id()
    }

    /// Called at epoch boundary to initiate settlement
    pub fn on_epoch_end(&self, epoch: u64) -> GhostResult<Option<SettlerRole>> {
        // Check if we're already handling this epoch
        if self.settlements.read().contains_key(&epoch) {
            debug!(epoch, "Already handling settlement for this epoch");
            return Ok(None);
        }

        // Check max concurrent
        let active_count = self
            .settlements
            .read()
            .values()
            .filter(|s| s.state != CoordinatorState::Completed && s.state != CoordinatorState::Idle)
            .count();

        if active_count >= self.max_concurrent {
            warn!(
                epoch,
                active_count,
                max = self.max_concurrent,
                "Too many concurrent settlements"
            );
            return Ok(None);
        }

        // Determine our role
        let role = self
            .epoch_tracker
            .is_settler(&self.identity.node_id(), epoch)?;

        if role == SettlerRole::NotSettler {
            debug!(epoch, "We are not a settler for this epoch");
            return Ok(None);
        }

        // Create settlement record
        let mut settlement = EpochSettlement::new(epoch, role);

        // M-5 SECURITY FIX: Handle all SettlerRole variants gracefully instead of
        // using unreachable!(). While the early return above filters NotSettler,
        // we handle it explicitly to avoid panics if enum variants are added or
        // if there's a race condition between the check and this match.
        match role {
            SettlerRole::Primary => {
                info!(epoch, "We are the PRIMARY settler for this epoch");
                settlement.state = CoordinatorState::PrimarySettling;
            }
            SettlerRole::Fallback => {
                info!(epoch, "We are the FALLBACK settler for this epoch");
                settlement.state = CoordinatorState::WaitingForPrimary;
            }
            SettlerRole::NotSettler => {
                // This should never happen due to the early return above, but handle
                // gracefully rather than panicking. Log a warning and return None.
                warn!(
                    epoch,
                    "M-5: Unexpected NotSettler role after filtering - returning None"
                );
                return Ok(None);
            }
        }

        self.settlements.write().insert(epoch, settlement);
        Ok(Some(role))
    }

    /// Check if we should take over as fallback
    pub fn check_fallback_timeout(&self) -> Vec<u64> {
        let mut epochs_to_takeover = Vec::new();

        for (epoch, settlement) in self.settlements.read().iter() {
            if settlement.state == CoordinatorState::WaitingForPrimary
                && settlement.is_primary_timed_out()
            {
                epochs_to_takeover.push(*epoch);
            }
        }

        epochs_to_takeover
    }

    /// Activate fallback for an epoch
    pub fn activate_fallback(&self, epoch: u64) -> GhostResult<bool> {
        let mut settlements = self.settlements.write();

        if let Some(settlement) = settlements.get_mut(&epoch) {
            if settlement.state == CoordinatorState::WaitingForPrimary
                && settlement.is_primary_timed_out()
            {
                info!(epoch, "Fallback settler taking over");
                settlement.state = CoordinatorState::FallbackSettling;
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Mark settlement as in progress (with batch ID)
    pub fn mark_in_progress(&self, epoch: u64, batch_id: u32) -> GhostResult<()> {
        let mut settlements = self.settlements.write();

        if let Some(settlement) = settlements.get_mut(&epoch) {
            settlement.batch_id = Some(batch_id);
            debug!(epoch, batch_id, "Settlement in progress");
        }

        Ok(())
    }

    /// Mark settlement as completed
    pub fn mark_completed(&self, epoch: u64) -> GhostResult<()> {
        let mut settlements = self.settlements.write();

        if let Some(settlement) = settlements.get_mut(&epoch) {
            settlement.state = CoordinatorState::Completed;
            info!(
                epoch,
                batch_id = ?settlement.batch_id,
                elapsed_ms = settlement.started_at.elapsed().as_millis(),
                "Settlement completed"
            );

            // Call completion callback
            if let Some(ref callback) = self.on_complete {
                drop(settlements); // Release lock before callback
                let _ = callback(epoch, true);
            }
        }

        Ok(())
    }

    /// Mark settlement as failed
    pub fn mark_failed(&self, epoch: u64, error: String) -> GhostResult<()> {
        let mut settlements = self.settlements.write();

        if let Some(settlement) = settlements.get_mut(&epoch) {
            settlement.state = CoordinatorState::Completed;
            settlement.error = Some(error.clone());
            warn!(epoch, error = %error, "Settlement failed");

            // Call completion callback
            if let Some(ref callback) = self.on_complete {
                drop(settlements);
                let _ = callback(epoch, false);
            }
        }

        Ok(())
    }

    /// Get settlement status for an epoch
    pub fn get_status(&self, epoch: u64) -> Option<EpochSettlement> {
        self.settlements.read().get(&epoch).cloned()
    }

    /// Get all active settlements
    pub fn get_active_settlements(&self) -> Vec<EpochSettlement> {
        self.settlements
            .read()
            .values()
            .filter(|s| s.state != CoordinatorState::Completed)
            .cloned()
            .collect()
    }

    /// Check if we are the settler for an epoch
    pub fn is_settler_for_epoch(&self, epoch: u64) -> GhostResult<SettlerRole> {
        self.epoch_tracker
            .is_settler(&self.identity.node_id(), epoch)
    }

    /// Verify a settler ID is authorized for an epoch
    pub fn verify_settler(&self, settler_id: &NodeId, epoch: u64) -> GhostResult<bool> {
        let role = self.epoch_tracker.is_settler(settler_id, epoch)?;
        Ok(role != SettlerRole::NotSettler)
    }

    /// Execute settlement for an epoch using the attached executor and broadcaster.
    ///
    /// This method orchestrates the full settlement flow:
    /// 1. Check if there are enough pending settlements to form a batch
    /// 2. Form a batch from pending settlements
    /// 3. Build the L1 reconciliation transaction
    /// 4. Broadcast to L1 via the attached broadcaster
    /// 5. Update coordinator and executor state
    ///
    /// Requires both `with_executor()` and `with_broadcaster()` to have been called.
    pub fn execute_settlement(&self, epoch: u64, fee_rate: u64) -> ReconciliationResult<()> {
        let executor_lock = self
            .executor
            .as_ref()
            .ok_or_else(|| ReconciliationError::InvalidState("No executor configured".into()))?;
        let broadcaster = self
            .broadcaster
            .as_ref()
            .ok_or_else(|| ReconciliationError::InvalidState("No broadcaster configured".into()))?;

        // 1. Check if batch should be formed
        let mut exec = executor_lock.write();
        if !exec.should_form_batch() {
            debug!(epoch, "No batch to form - insufficient pending settlements");
            return Ok(());
        }

        // 2. Form batch
        let batch = exec.form_batch()?;
        let batch_id_hex = batch.id_hex();
        info!(epoch, batch_id = %batch_id_hex, "Formed settlement batch");

        // Use a monotonic batch counter for coordinator tracking
        let batch_seq = batch.settlement_count() as u32;
        let _ = self.mark_in_progress(epoch, batch_seq);

        // 3. Build transaction
        let batch_tx = match exec.build_transaction(&batch, fee_rate) {
            Ok(tx) => tx,
            Err(e) => {
                let _ = self.mark_failed(epoch, e.to_string());
                return Err(e);
            }
        };

        // 4. Broadcast to L1
        let tx_bytes = bitcoin::consensus::encode::serialize(&batch_tx.transaction);
        let tx_hex = hex::encode(&tx_bytes);

        match broadcaster.broadcast(&tx_hex) {
            Ok(txid_str) => {
                // Parse txid for executor tracking
                let txid: bitcoin::Txid = txid_str.parse().map_err(|e| {
                    ReconciliationError::L1TransactionError(format!(
                        "Invalid txid returned from broadcast: {}",
                        e
                    ))
                })?;

                exec.mark_submitted(&batch_id_hex, txid)?;
                let _ = self.mark_completed(epoch);

                info!(
                    epoch,
                    batch_id = %batch_id_hex,
                    txid = %txid_str,
                    "Settlement broadcast successful"
                );
                Ok(())
            }
            Err(e) => {
                exec.cancel_batch(&batch_id_hex)?;
                let _ = self.mark_failed(epoch, e.clone());
                Err(ReconciliationError::BroadcastFailed(e))
            }
        }
    }

    /// Cleanup old completed settlements
    pub fn cleanup_old(&self, keep_last: usize) {
        let mut settlements = self.settlements.write();

        // Get completed epochs sorted
        let mut completed: Vec<u64> = settlements
            .iter()
            .filter(|(_, s)| s.state == CoordinatorState::Completed)
            .map(|(e, _)| *e)
            .collect();
        completed.sort();

        // Remove old ones
        let to_remove = completed.len().saturating_sub(keep_last);
        for epoch in completed.into_iter().take(to_remove) {
            settlements.remove(&epoch);
            debug!(epoch, "Cleaned up old settlement record");
        }
    }

    /// Get coordinator statistics
    pub fn stats(&self) -> CoordinatorStats {
        let settlements = self.settlements.read();
        let mut stats = CoordinatorStats::default();

        for settlement in settlements.values() {
            match settlement.state {
                CoordinatorState::Idle => stats.idle += 1,
                CoordinatorState::PrimarySettling => stats.primary_settling += 1,
                CoordinatorState::WaitingForPrimary => stats.waiting_for_primary += 1,
                CoordinatorState::FallbackSettling => stats.fallback_settling += 1,
                CoordinatorState::Completed => {
                    if settlement.error.is_some() {
                        stats.failed += 1;
                    } else {
                        stats.completed += 1;
                    }
                }
            }
        }

        stats
    }
}

/// Coordinator statistics
#[derive(Debug, Clone, Default)]
pub struct CoordinatorStats {
    pub idle: u32,
    pub primary_settling: u32,
    pub waiting_for_primary: u32,
    pub fallback_settling: u32,
    pub completed: u32,
    pub failed: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_storage::{Database, SnapshotManager};

    fn setup_test() -> (Arc<NodeIdentity>, Arc<EpochTracker>) {
        let db = Database::in_memory().unwrap();
        let snapshot_mgr = Arc::new(SnapshotManager::new(db, 100, 50));
        let epoch_tracker = Arc::new(EpochTracker::new(snapshot_mgr));
        let identity = Arc::new(NodeIdentity::generate());
        (identity, epoch_tracker)
    }

    #[test]
    fn test_coordinator_creation() {
        let (identity, epoch_tracker) = setup_test();
        let coordinator = SettlementCoordinator::new(identity.clone(), epoch_tracker);

        assert_eq!(coordinator.node_id(), identity.node_id());
    }

    #[test]
    fn test_epoch_end_not_settler() {
        let (identity, epoch_tracker) = setup_test();
        let coordinator = SettlementCoordinator::new(identity, epoch_tracker);

        // We are not the settler for epoch 0 (no proposers recorded)
        let role = coordinator.on_epoch_end(0).unwrap();
        assert!(role.is_none());
    }

    #[test]
    fn test_epoch_end_as_primary() {
        let (identity, epoch_tracker) = setup_test();

        // Record our identity as the proposer of the last block of epoch 0
        let our_id = identity.node_id();
        let state_root = [0u8; 32];
        epoch_tracker
            .record_proposer(2160, &our_id, &state_root)
            .unwrap();

        let coordinator = SettlementCoordinator::new(identity, epoch_tracker);

        let role = coordinator.on_epoch_end(0).unwrap();
        assert_eq!(role, Some(SettlerRole::Primary));

        // Check status
        let status = coordinator.get_status(0).unwrap();
        assert_eq!(status.role, SettlerRole::Primary);
        assert_eq!(status.state, CoordinatorState::PrimarySettling);
    }

    #[test]
    fn test_epoch_end_as_fallback() {
        let (identity, epoch_tracker) = setup_test();

        // Record another node as primary proposer
        let primary_id = [0xAAu8; 32];
        let state_root = [0u8; 32];
        epoch_tracker
            .record_proposer(2160, &primary_id, &state_root)
            .unwrap();

        // Record our identity as fallback proposer
        let our_id = identity.node_id();
        epoch_tracker
            .record_proposer(2159, &our_id, &state_root)
            .unwrap();

        let coordinator = SettlementCoordinator::new(identity, epoch_tracker);

        let role = coordinator.on_epoch_end(0).unwrap();
        assert_eq!(role, Some(SettlerRole::Fallback));

        // Check status
        let status = coordinator.get_status(0).unwrap();
        assert_eq!(status.role, SettlerRole::Fallback);
        assert_eq!(status.state, CoordinatorState::WaitingForPrimary);
    }

    #[test]
    fn test_fallback_timeout() {
        let (identity, epoch_tracker) = setup_test();

        let our_id = identity.node_id();
        let state_root = [0u8; 32];

        // Set up as fallback
        let primary_id = [0xAAu8; 32];
        epoch_tracker
            .record_proposer(2160, &primary_id, &state_root)
            .unwrap();
        epoch_tracker
            .record_proposer(2159, &our_id, &state_root)
            .unwrap();

        let coordinator = SettlementCoordinator::new(identity, epoch_tracker);
        coordinator.on_epoch_end(0).unwrap();

        // Initially no timeout
        assert!(coordinator.check_fallback_timeout().is_empty());

        // Manually set deadline to past
        {
            let mut settlements = coordinator.settlements.write();
            if let Some(settlement) = settlements.get_mut(&0) {
                settlement.deadline = Instant::now() - Duration::from_secs(1);
            }
        }

        // Now should detect timeout
        let timeouts = coordinator.check_fallback_timeout();
        assert_eq!(timeouts, vec![0]);

        // Activate fallback
        let activated = coordinator.activate_fallback(0).unwrap();
        assert!(activated);

        let status = coordinator.get_status(0).unwrap();
        assert_eq!(status.state, CoordinatorState::FallbackSettling);
    }

    #[test]
    fn test_settlement_lifecycle() {
        let (identity, epoch_tracker) = setup_test();

        let our_id = identity.node_id();
        let state_root = [0u8; 32];
        epoch_tracker
            .record_proposer(2160, &our_id, &state_root)
            .unwrap();

        let coordinator = SettlementCoordinator::new(identity, epoch_tracker);
        coordinator.on_epoch_end(0).unwrap();

        // Mark in progress
        coordinator.mark_in_progress(0, 1).unwrap();
        let status = coordinator.get_status(0).unwrap();
        assert_eq!(status.batch_id, Some(1));

        // Mark completed
        coordinator.mark_completed(0).unwrap();
        let status = coordinator.get_status(0).unwrap();
        assert_eq!(status.state, CoordinatorState::Completed);
        assert!(status.error.is_none());
    }

    #[test]
    fn test_settlement_failure() {
        let (identity, epoch_tracker) = setup_test();

        let our_id = identity.node_id();
        let state_root = [0u8; 32];
        epoch_tracker
            .record_proposer(2160, &our_id, &state_root)
            .unwrap();

        let coordinator = SettlementCoordinator::new(identity, epoch_tracker);
        coordinator.on_epoch_end(0).unwrap();

        // Mark failed
        coordinator
            .mark_failed(0, "Test error".to_string())
            .unwrap();
        let status = coordinator.get_status(0).unwrap();
        assert_eq!(status.state, CoordinatorState::Completed);
        assert_eq!(status.error, Some("Test error".to_string()));
    }

    #[test]
    fn test_coordinator_stats() {
        let (identity, epoch_tracker) = setup_test();

        let our_id = identity.node_id();
        let state_root = [0u8; 32];

        // Set up for multiple epochs
        for epoch in 0..3 {
            let end_block = (epoch + 1) * 2160;
            epoch_tracker
                .record_proposer(end_block, &our_id, &state_root)
                .unwrap();
        }

        let coordinator = SettlementCoordinator::new(identity, epoch_tracker);

        coordinator.on_epoch_end(0).unwrap();
        coordinator.on_epoch_end(1).unwrap();
        coordinator.on_epoch_end(2).unwrap();

        coordinator.mark_completed(0).unwrap();
        coordinator.mark_failed(1, "Error".to_string()).unwrap();

        let stats = coordinator.stats();
        assert_eq!(stats.completed, 1);
        assert_eq!(stats.failed, 1);
        assert_eq!(stats.primary_settling, 1); // epoch 2 still settling
    }

    #[test]
    fn test_cleanup() {
        let (identity, epoch_tracker) = setup_test();

        let our_id = identity.node_id();
        let state_root = [0u8; 32];

        // Set up for multiple epochs
        for epoch in 0..5 {
            let end_block = (epoch + 1) * 2160;
            epoch_tracker
                .record_proposer(end_block, &our_id, &state_root)
                .unwrap();
        }

        let coordinator = SettlementCoordinator::new(identity, epoch_tracker);

        // Create and complete settlements
        for epoch in 0..5 {
            coordinator.on_epoch_end(epoch).unwrap();
            coordinator.mark_completed(epoch).unwrap();
        }

        // Should have 5 completed
        assert_eq!(coordinator.settlements.read().len(), 5);

        // Cleanup, keep last 2
        coordinator.cleanup_old(2);
        assert_eq!(coordinator.settlements.read().len(), 2);

        // Should have kept epochs 3 and 4
        assert!(coordinator.get_status(3).is_some());
        assert!(coordinator.get_status(4).is_some());
        assert!(coordinator.get_status(0).is_none());
    }

    // ========================================================================
    // Phase 5: Coordinator → Executor wiring tests
    // ========================================================================

    #[test]
    fn test_coordinator_with_executor_builder() {
        let (identity, epoch_tracker) = setup_test();

        let executor = BatchExecutor::new(bitcoin::Network::Regtest, "bcrt1qtest".to_string());

        let coordinator =
            SettlementCoordinator::new(identity.clone(), epoch_tracker).with_executor(executor);

        assert!(coordinator.executor.is_some());
        assert!(coordinator.broadcaster.is_none());
        assert_eq!(coordinator.node_id(), identity.node_id());
    }

    #[test]
    fn test_coordinator_with_broadcaster_builder() {
        use crate::broadcaster::L1Broadcaster;

        struct TestBroadcaster;
        impl L1Broadcaster for TestBroadcaster {
            fn broadcast(&self, _tx_hex: &str) -> Result<String, String> {
                Ok("0000000000000000000000000000000000000000000000000000000000000001".to_string())
            }
            fn get_block_height(&self) -> Result<u64, String> {
                Ok(100)
            }
            fn is_confirmed(&self, _txid: &str) -> Result<Option<u32>, String> {
                Ok(None)
            }
        }

        let (identity, epoch_tracker) = setup_test();
        let broadcaster: Arc<dyn L1Broadcaster> = Arc::new(TestBroadcaster);

        let coordinator =
            SettlementCoordinator::new(identity, epoch_tracker).with_broadcaster(broadcaster);

        assert!(coordinator.broadcaster.is_some());
        assert!(coordinator.executor.is_none());
    }

    #[test]
    fn test_coordinator_full_builder_chain() {
        use crate::broadcaster::L1Broadcaster;

        struct TestBroadcaster;
        impl L1Broadcaster for TestBroadcaster {
            fn broadcast(&self, _tx_hex: &str) -> Result<String, String> {
                Ok("0000000000000000000000000000000000000000000000000000000000000001".to_string())
            }
            fn get_block_height(&self) -> Result<u64, String> {
                Ok(100)
            }
            fn is_confirmed(&self, _txid: &str) -> Result<Option<u32>, String> {
                Ok(None)
            }
        }

        let (identity, epoch_tracker) = setup_test();
        let executor = BatchExecutor::new(bitcoin::Network::Regtest, "bcrt1qtest".to_string());
        let broadcaster: Arc<dyn L1Broadcaster> = Arc::new(TestBroadcaster);

        let coordinator = SettlementCoordinator::new(identity, epoch_tracker)
            .with_executor(executor)
            .with_broadcaster(broadcaster)
            .with_max_concurrent(5);

        assert!(coordinator.executor.is_some());
        assert!(coordinator.broadcaster.is_some());
        assert_eq!(coordinator.max_concurrent, 5);
    }

    #[test]
    fn test_execute_settlement_no_executor() {
        let (identity, epoch_tracker) = setup_test();
        let coordinator = SettlementCoordinator::new(identity, epoch_tracker);

        let result = coordinator.execute_settlement(0, 1);
        assert!(result.is_err());
        match result.unwrap_err() {
            ReconciliationError::InvalidState(msg) => {
                assert!(msg.contains("No executor configured"));
            }
            other => panic!("Expected InvalidState, got {:?}", other),
        }
    }

    #[test]
    fn test_execute_settlement_no_broadcaster() {
        let (identity, epoch_tracker) = setup_test();
        let executor = BatchExecutor::new(bitcoin::Network::Regtest, "bcrt1qtest".to_string());

        let coordinator =
            SettlementCoordinator::new(identity, epoch_tracker).with_executor(executor);

        let result = coordinator.execute_settlement(0, 1);
        assert!(result.is_err());
        match result.unwrap_err() {
            ReconciliationError::InvalidState(msg) => {
                assert!(msg.contains("No broadcaster configured"));
            }
            other => panic!("Expected InvalidState, got {:?}", other),
        }
    }

    #[test]
    fn test_execute_settlement_nothing_pending() {
        use crate::broadcaster::L1Broadcaster;

        struct TestBroadcaster;
        impl L1Broadcaster for TestBroadcaster {
            fn broadcast(&self, _tx_hex: &str) -> Result<String, String> {
                panic!("Should not be called when nothing to settle");
            }
            fn get_block_height(&self) -> Result<u64, String> {
                Ok(100)
            }
            fn is_confirmed(&self, _txid: &str) -> Result<Option<u32>, String> {
                Ok(None)
            }
        }

        let (identity, epoch_tracker) = setup_test();
        let executor = BatchExecutor::new(bitcoin::Network::Regtest, "bcrt1qtest".to_string());
        let broadcaster: Arc<dyn L1Broadcaster> = Arc::new(TestBroadcaster);

        let coordinator = SettlementCoordinator::new(identity, epoch_tracker)
            .with_executor(executor)
            .with_broadcaster(broadcaster);

        // Nothing pending, should return Ok(()) without calling broadcaster
        let result = coordinator.execute_settlement(0, 1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_settlement_broadcast_failure() {
        use crate::broadcaster::L1Broadcaster;
        use crate::executor::ReconciliationInput;
        use crate::settlement::Settlement;

        struct FailingBroadcaster;
        impl L1Broadcaster for FailingBroadcaster {
            fn broadcast(&self, _tx_hex: &str) -> Result<String, String> {
                Err("Connection refused".to_string())
            }
            fn get_block_height(&self) -> Result<u64, String> {
                Ok(100)
            }
            fn is_confirmed(&self, _txid: &str) -> Result<Option<u32>, String> {
                Ok(None)
            }
        }

        let (identity, epoch_tracker) = setup_test();
        let treasury_addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        let mut executor = BatchExecutor::new(bitcoin::Network::Regtest, treasury_addr.to_string());

        // Add 10 settlements (minimum batch size) with matching inputs
        let output_addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        for i in 0..10u8 {
            let settlement = Settlement::new(
                format!("ghost1user{}", i),
                [i; 32],
                output_addr.to_string(),
                10_000,
            )
            .unwrap();
            #[allow(deprecated)]
            executor.add_settlement(settlement).unwrap();

            let input = ReconciliationInput {
                txid: format!(
                    "000000000000000000000000000000000000000000000000000000000000{:04x}",
                    i
                )
                .parse()
                .unwrap(),
                vout: 0,
                amount: 20_000,
                ghost_id: format!("ghost1user{}", i),
                lock_id: Some([i; 32]),
                confirmations: 100,
            };
            executor.add_input(input);
        }

        let broadcaster: Arc<dyn L1Broadcaster> = Arc::new(FailingBroadcaster);

        let coordinator = SettlementCoordinator::new(identity, epoch_tracker)
            .with_executor(executor)
            .with_broadcaster(broadcaster);

        let result = coordinator.execute_settlement(0, 1);
        assert!(result.is_err());
        match result.unwrap_err() {
            ReconciliationError::BroadcastFailed(msg) => {
                assert!(msg.contains("Connection refused"));
            }
            other => panic!("Expected BroadcastFailed, got {:?}", other),
        }
    }

    #[test]
    fn test_execute_settlement_success() {
        use crate::broadcaster::L1Broadcaster;
        use crate::executor::ReconciliationInput;
        use crate::settlement::Settlement;
        use std::sync::atomic::{AtomicBool, Ordering};

        struct SuccessBroadcaster {
            was_called: AtomicBool,
        }
        impl L1Broadcaster for SuccessBroadcaster {
            fn broadcast(&self, _tx_hex: &str) -> Result<String, String> {
                self.was_called.store(true, Ordering::SeqCst);
                Ok("a000000000000000000000000000000000000000000000000000000000000001".to_string())
            }
            fn get_block_height(&self) -> Result<u64, String> {
                Ok(100)
            }
            fn is_confirmed(&self, _txid: &str) -> Result<Option<u32>, String> {
                Ok(None)
            }
        }

        let (identity, epoch_tracker) = setup_test();
        let treasury_addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        let mut executor = BatchExecutor::new(bitcoin::Network::Regtest, treasury_addr.to_string());

        // Add 10 settlements with matching inputs
        let output_addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        for i in 0..10u8 {
            let settlement = Settlement::new(
                format!("ghost1user{}", i),
                [i; 32],
                output_addr.to_string(),
                10_000,
            )
            .unwrap();
            #[allow(deprecated)]
            executor.add_settlement(settlement).unwrap();

            let input = ReconciliationInput {
                txid: format!(
                    "000000000000000000000000000000000000000000000000000000000000{:04x}",
                    i
                )
                .parse()
                .unwrap(),
                vout: 0,
                amount: 20_000,
                ghost_id: format!("ghost1user{}", i),
                lock_id: Some([i; 32]),
                confirmations: 100,
            };
            executor.add_input(input);
        }

        let broadcaster = Arc::new(SuccessBroadcaster {
            was_called: AtomicBool::new(false),
        });
        let broadcaster_clone = broadcaster.clone();

        let coordinator = SettlementCoordinator::new(identity, epoch_tracker)
            .with_executor(executor)
            .with_broadcaster(broadcaster_clone as Arc<dyn L1Broadcaster>);

        let result = coordinator.execute_settlement(0, 1);
        assert!(
            result.is_ok(),
            "Settlement should succeed: {:?}",
            result.err()
        );

        // Verify broadcaster was actually called
        assert!(broadcaster.was_called.load(Ordering::SeqCst));

        // Verify executor has no more pending settlements
        let exec = coordinator.executor.as_ref().unwrap().read();
        assert_eq!(exec.pending_count(), 0);
    }
}
