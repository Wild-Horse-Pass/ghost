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
//| FILE: epoch.rs                                                                                                       |
//|======================================================================================================================|

//! Epoch tracking for ZK-BFT settlement
//!
//! Tracks L2 epochs and manages settler selection:
//! - Primary settler = proposer of the last block in an epoch (block N*2160)
//! - Fallback settler = proposer of the second-to-last block (block N*2160 - 1)

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use ghost_common::error::{GhostError, GhostResult};
use ghost_common::types::NodeId;
use ghost_storage::SnapshotManager;

/// L2 blocks per epoch (~6 hours at 10 seconds/block)
pub const L2_EPOCH_BLOCKS: u64 = 2160;

/// Settlement timeout in seconds (5 minutes)
pub const SETTLEMENT_TIMEOUT_SECS: u64 = 300;

/// Role of a node in epoch settlement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettlerRole {
    /// Primary settler - proposer of the last block in the epoch
    Primary,
    /// Fallback settler - proposer of the second-to-last block
    Fallback,
    /// Not a settler for this epoch
    NotSettler,
}

/// Tracks L2 epochs and manages settler selection
pub struct EpochTracker {
    /// Snapshot manager for proposer lookups
    snapshot_manager: Arc<SnapshotManager>,
    /// Current epoch (derived from block height)
    current_epoch: RwLock<u64>,
    /// In-memory cache of recent proposers (height -> proposer_id)
    proposers_cache: RwLock<HashMap<u64, NodeId>>,
    /// Maximum cache size
    cache_size: usize,
}

impl EpochTracker {
    /// Create a new epoch tracker
    pub fn new(snapshot_manager: Arc<SnapshotManager>) -> Self {
        Self {
            snapshot_manager,
            current_epoch: RwLock::new(0),
            proposers_cache: RwLock::new(HashMap::new()),
            cache_size: 4320, // 2 epochs worth
        }
    }

    /// Create with custom cache size
    pub fn with_cache_size(snapshot_manager: Arc<SnapshotManager>, cache_size: usize) -> Self {
        Self {
            snapshot_manager,
            current_epoch: RwLock::new(0),
            proposers_cache: RwLock::new(HashMap::new()),
            cache_size,
        }
    }

    /// Get epoch number for a block height
    pub fn epoch_for_height(height: u64) -> u64 {
        height / L2_EPOCH_BLOCKS
    }

    /// Get the first block of an epoch
    pub fn epoch_start_block(epoch: u64) -> u64 {
        epoch * L2_EPOCH_BLOCKS
    }

    /// Get the last block of an epoch
    pub fn epoch_end_block(epoch: u64) -> u64 {
        (epoch + 1) * L2_EPOCH_BLOCKS
    }

    /// Check if a height is the last block of an epoch
    pub fn is_epoch_boundary(height: u64) -> bool {
        height > 0 && height % L2_EPOCH_BLOCKS == 0
    }

    /// Get current epoch
    pub fn current_epoch(&self) -> u64 {
        *self.current_epoch.read()
    }

    /// Update current epoch based on block height
    pub fn update_epoch(&self, height: u64) {
        let epoch = Self::epoch_for_height(height);
        *self.current_epoch.write() = epoch;
    }

    /// Record a block proposer
    pub fn record_proposer(
        &self,
        height: u64,
        proposer_id: &NodeId,
        state_root: &[u8; 32],
    ) -> GhostResult<()> {
        // Update in-memory cache
        {
            let mut cache = self.proposers_cache.write();
            cache.insert(height, *proposer_id);

            // Prune old entries if cache is too large
            if cache.len() > self.cache_size {
                let min_height = height.saturating_sub(self.cache_size as u64);
                cache.retain(|h, _| *h >= min_height);
            }
        }

        // Persist to database
        self.snapshot_manager
            .record_proposer(height, proposer_id, state_root)?;

        // Update current epoch
        self.update_epoch(height);

        debug!(
            height,
            epoch = Self::epoch_for_height(height),
            "Recorded block proposer"
        );
        Ok(())
    }

    /// Get the proposer at a specific height
    pub fn get_proposer_at(&self, height: u64) -> GhostResult<Option<NodeId>> {
        // Check cache first
        if let Some(proposer) = self.proposers_cache.read().get(&height) {
            return Ok(Some(*proposer));
        }

        // Fall back to database
        if let Some(record) = self.snapshot_manager.get_proposer_at(height)? {
            let proposer_bytes = hex::decode(&record.proposer_id)
                .map_err(|e| GhostError::Serialization(e.to_string()))?;
            if proposer_bytes.len() == 32 {
                let mut proposer = [0u8; 32];
                proposer.copy_from_slice(&proposer_bytes);
                return Ok(Some(proposer));
            }
        }

        Ok(None)
    }

    /// Get the primary settler for an epoch (proposer of the last block)
    pub fn get_primary_settler(&self, epoch: u64) -> GhostResult<Option<NodeId>> {
        let end_block = Self::epoch_end_block(epoch);
        self.get_proposer_at(end_block)
    }

    /// Get the fallback settler for an epoch (proposer of second-to-last block)
    pub fn get_fallback_settler(&self, epoch: u64) -> GhostResult<Option<NodeId>> {
        let end_block = Self::epoch_end_block(epoch);
        if end_block == 0 {
            return Ok(None);
        }
        self.get_proposer_at(end_block - 1)
    }

    /// Determine if a node is a settler for the given epoch
    pub fn is_settler(&self, our_id: &NodeId, epoch: u64) -> GhostResult<SettlerRole> {
        // Check primary settler
        if let Some(primary) = self.get_primary_settler(epoch)? {
            if &primary == our_id {
                return Ok(SettlerRole::Primary);
            }
        }

        // Check fallback settler
        if let Some(fallback) = self.get_fallback_settler(epoch)? {
            if &fallback == our_id {
                return Ok(SettlerRole::Fallback);
            }
        }

        Ok(SettlerRole::NotSettler)
    }

    /// Get the deadline for settlement (timestamp when fallback should take over)
    pub fn settlement_deadline(epoch_end_time: u64) -> u64 {
        epoch_end_time + SETTLEMENT_TIMEOUT_SECS
    }

    /// Check if an epoch is ready for settlement (epoch boundary reached)
    pub fn is_epoch_ready_for_settlement(&self, height: u64) -> bool {
        Self::is_epoch_boundary(height)
    }

    /// Get info about the current and next epochs
    pub fn get_epoch_info(&self, height: u64) -> EpochInfo {
        let current_epoch = Self::epoch_for_height(height);
        let blocks_in_epoch = height % L2_EPOCH_BLOCKS;
        let blocks_remaining = L2_EPOCH_BLOCKS - blocks_in_epoch;

        EpochInfo {
            current_epoch,
            blocks_in_epoch,
            blocks_remaining,
            epoch_start_height: Self::epoch_start_block(current_epoch),
            epoch_end_height: Self::epoch_end_block(current_epoch),
            is_boundary: Self::is_epoch_boundary(height),
        }
    }
}

/// Information about the current epoch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochInfo {
    /// Current epoch number
    pub current_epoch: u64,
    /// Blocks processed in this epoch
    pub blocks_in_epoch: u64,
    /// Blocks remaining until epoch end
    pub blocks_remaining: u64,
    /// First block height of this epoch
    pub epoch_start_height: u64,
    /// Last block height of this epoch
    pub epoch_end_height: u64,
    /// Whether current height is an epoch boundary
    pub is_boundary: bool,
}

/// Settlement state machine
#[derive(Debug, Clone)]
pub struct SettlementState {
    /// Epoch being settled
    pub epoch: u64,
    /// Our role in this settlement
    pub role: SettlerRole,
    /// When settlement started
    pub started_at: Instant,
    /// Deadline for primary settler
    pub deadline: Instant,
    /// Whether fallback has taken over
    pub fallback_active: bool,
}

impl SettlementState {
    /// Create a new settlement state
    pub fn new(epoch: u64, role: SettlerRole) -> Self {
        let now = Instant::now();
        Self {
            epoch,
            role,
            started_at: now,
            deadline: now + Duration::from_secs(SETTLEMENT_TIMEOUT_SECS),
            fallback_active: false,
        }
    }

    /// Check if the settlement has timed out
    pub fn is_timed_out(&self) -> bool {
        Instant::now() > self.deadline
    }

    /// Check if we should take over as fallback
    pub fn should_fallback_take_over(&self) -> bool {
        self.role == SettlerRole::Fallback && self.is_timed_out() && !self.fallback_active
    }

    /// Mark fallback as active
    pub fn activate_fallback(&mut self) {
        self.fallback_active = true;
        info!(epoch = self.epoch, "Fallback settler taking over");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_storage::Database;

    fn setup_test() -> (Database, Arc<SnapshotManager>) {
        let db = Database::in_memory().unwrap();
        let snapshot_mgr = Arc::new(SnapshotManager::new(db.clone(), 100, 50));
        (db, snapshot_mgr)
    }

    #[test]
    fn test_epoch_calculation() {
        assert_eq!(EpochTracker::epoch_for_height(0), 0);
        assert_eq!(EpochTracker::epoch_for_height(1), 0);
        assert_eq!(EpochTracker::epoch_for_height(2159), 0);
        assert_eq!(EpochTracker::epoch_for_height(2160), 1);
        assert_eq!(EpochTracker::epoch_for_height(2161), 1);
        assert_eq!(EpochTracker::epoch_for_height(4320), 2);
    }

    #[test]
    fn test_epoch_boundaries() {
        assert_eq!(EpochTracker::epoch_start_block(0), 0);
        assert_eq!(EpochTracker::epoch_end_block(0), 2160);
        assert_eq!(EpochTracker::epoch_start_block(1), 2160);
        assert_eq!(EpochTracker::epoch_end_block(1), 4320);

        assert!(!EpochTracker::is_epoch_boundary(0));
        assert!(!EpochTracker::is_epoch_boundary(2159));
        assert!(EpochTracker::is_epoch_boundary(2160));
        assert!(!EpochTracker::is_epoch_boundary(2161));
        assert!(EpochTracker::is_epoch_boundary(4320));
    }

    #[test]
    fn test_record_and_get_proposer() {
        let (_db, snapshot_mgr) = setup_test();
        let tracker = EpochTracker::new(snapshot_mgr);

        let proposer = [0xABu8; 32];
        let state_root = [0xCDu8; 32];

        tracker
            .record_proposer(100, &proposer, &state_root)
            .unwrap();

        let retrieved = tracker.get_proposer_at(100).unwrap().unwrap();
        assert_eq!(retrieved, proposer);

        // Non-existent
        assert!(tracker.get_proposer_at(50).unwrap().is_none());
    }

    #[test]
    fn test_settler_selection() {
        let (_db, snapshot_mgr) = setup_test();
        let tracker = EpochTracker::new(snapshot_mgr);

        let primary_proposer = [0x11u8; 32];
        let fallback_proposer = [0x22u8; 32];
        let other_node = [0x33u8; 32];
        let state_root = [0xCDu8; 32];

        // Record proposers for epoch 0
        // Block 2160 is the last block of epoch 0
        tracker
            .record_proposer(2159, &fallback_proposer, &state_root)
            .unwrap();
        tracker
            .record_proposer(2160, &primary_proposer, &state_root)
            .unwrap();

        // Check primary settler
        let primary = tracker.get_primary_settler(0).unwrap().unwrap();
        assert_eq!(primary, primary_proposer);

        // Check fallback settler
        let fallback = tracker.get_fallback_settler(0).unwrap().unwrap();
        assert_eq!(fallback, fallback_proposer);

        // Check roles
        assert_eq!(
            tracker.is_settler(&primary_proposer, 0).unwrap(),
            SettlerRole::Primary
        );
        assert_eq!(
            tracker.is_settler(&fallback_proposer, 0).unwrap(),
            SettlerRole::Fallback
        );
        assert_eq!(
            tracker.is_settler(&other_node, 0).unwrap(),
            SettlerRole::NotSettler
        );
    }

    #[test]
    fn test_epoch_info() {
        let (_db, snapshot_mgr) = setup_test();
        let tracker = EpochTracker::new(snapshot_mgr);

        let info = tracker.get_epoch_info(100);
        assert_eq!(info.current_epoch, 0);
        assert_eq!(info.blocks_in_epoch, 100);
        assert_eq!(info.blocks_remaining, 2060);
        assert!(!info.is_boundary);

        let info = tracker.get_epoch_info(2160);
        assert_eq!(info.current_epoch, 1);
        assert_eq!(info.blocks_in_epoch, 0);
        assert_eq!(info.blocks_remaining, 2160);
        assert!(info.is_boundary);
    }

    #[test]
    fn test_settlement_state() {
        let state = SettlementState::new(0, SettlerRole::Primary);
        assert!(!state.is_timed_out());
        assert!(!state.should_fallback_take_over());

        let mut fallback_state = SettlementState::new(0, SettlerRole::Fallback);
        assert!(!fallback_state.should_fallback_take_over()); // Not timed out yet

        // Simulate timeout
        fallback_state.deadline = Instant::now() - Duration::from_secs(1);
        assert!(fallback_state.is_timed_out());
        assert!(fallback_state.should_fallback_take_over());

        fallback_state.activate_fallback();
        assert!(!fallback_state.should_fallback_take_over()); // Already active
    }

    #[test]
    fn test_cache_pruning() {
        let (_db, snapshot_mgr) = setup_test();
        let tracker = EpochTracker::with_cache_size(snapshot_mgr, 10);

        let state_root = [0xCDu8; 32];

        // Insert more than cache size
        for i in 0..20 {
            let proposer = [i as u8; 32];
            tracker.record_proposer(i, &proposer, &state_root).unwrap();
        }

        // Cache should be pruned (not all 20 entries)
        let cache = tracker.proposers_cache.read();
        assert!(cache.len() < 20, "Cache should have been pruned");

        // Old entries should be gone, recent ones should remain
        assert!(!cache.contains_key(&0), "Very old entries should be pruned");
        assert!(cache.contains_key(&19), "Recent entries should be kept");
    }
}
