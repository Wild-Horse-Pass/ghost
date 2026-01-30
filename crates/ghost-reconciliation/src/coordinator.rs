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

// Note: ReconciliationError and BatchExecutor will be used when settlement execution is implemented

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
            .filter(|s| {
                s.state != CoordinatorState::Completed && s.state != CoordinatorState::Idle
            })
            .count();

        if active_count >= self.max_concurrent {
            warn!(
                epoch,
                active_count, max = self.max_concurrent, "Too many concurrent settlements"
            );
            return Ok(None);
        }

        // Determine our role
        let role = self.epoch_tracker.is_settler(&self.identity.node_id(), epoch)?;

        if role == SettlerRole::NotSettler {
            debug!(epoch, "We are not a settler for this epoch");
            return Ok(None);
        }

        // Create settlement record
        let mut settlement = EpochSettlement::new(epoch, role);

        match role {
            SettlerRole::Primary => {
                info!(epoch, "We are the PRIMARY settler for this epoch");
                settlement.state = CoordinatorState::PrimarySettling;
            }
            SettlerRole::Fallback => {
                info!(epoch, "We are the FALLBACK settler for this epoch");
                settlement.state = CoordinatorState::WaitingForPrimary;
            }
            SettlerRole::NotSettler => unreachable!(),
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
        self.epoch_tracker.is_settler(&self.identity.node_id(), epoch)
    }

    /// Verify a settler ID is authorized for an epoch
    pub fn verify_settler(&self, settler_id: &NodeId, epoch: u64) -> GhostResult<bool> {
        let role = self.epoch_tracker.is_settler(settler_id, epoch)?;
        Ok(role != SettlerRole::NotSettler)
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
}
