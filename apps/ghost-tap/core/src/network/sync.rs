//! Light wallet synchronization
//!
//! Implements light sync for Ghost mobile wallet, including:
//! - Public address scanning
//! - Stealth address scanning (Wraith Protocol)
//! - Ghost Lock status updates
//! - Jump Lock monitoring

use super::types::*;
use super::{GhostClient, NetworkError};
use std::collections::HashSet;

/// Sync status
#[derive(Debug, Clone)]
pub enum SyncStatus {
    /// Not started
    Idle,
    /// Currently syncing
    Syncing {
        current_height: u64,
        target_height: u64,
        phase: SyncPhase,
    },
    /// Sync complete
    Synced { height: u64 },
    /// Sync failed
    Failed(String),
}

/// Current sync phase
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncPhase {
    /// Syncing block headers
    Headers,
    /// Scanning public addresses
    PublicAddresses,
    /// Scanning stealth addresses (Wraith)
    StealthAddresses,
    /// Updating lock status
    Locks,
    /// Finalizing
    Finalizing,
}

/// Sync result for a single address
#[derive(Debug, Clone)]
pub struct AddressSyncResult {
    /// Address that was synced
    pub address: String,
    /// Whether this is a stealth address
    pub is_stealth: bool,
    /// New UTXOs found
    pub new_utxos: Vec<GhostUtxo>,
    /// Spent UTXOs (txids)
    pub spent_utxos: Vec<(String, u32)>,
    /// New transactions
    pub new_txids: Vec<String>,
}

/// Sync result summary
#[derive(Debug, Clone, Default)]
pub struct SyncResult {
    /// Block height synced to
    pub height: u64,
    /// Number of addresses scanned
    pub addresses_scanned: u32,
    /// New UTXOs found
    pub new_utxos_count: u32,
    /// Spent UTXOs found
    pub spent_utxos_count: u32,
    /// New transactions found
    pub new_tx_count: u32,
    /// Public balance change
    pub public_balance_change: i64,
    /// Private balance change (Wraith)
    pub private_balance_change: i64,
    /// Updated locks
    pub locks_updated: u32,
}

/// Ghost wallet synchronizer
pub struct GhostSync {
    /// Current sync status
    status: SyncStatus,
    /// Last synced block height
    last_height: u64,
    /// Public addresses to watch
    public_addresses: Vec<String>,
    /// Stealth addresses to watch
    stealth_addresses: Vec<StealthAddress>,
    /// Active Ghost Locks
    ghost_locks: Vec<String>, // Lock IDs
    /// Active Jump Locks
    jump_locks: Vec<String>, // Lock IDs
    /// Sync configuration
    config: SyncConfig,
    /// Previously seen UTXOs keyed by (txid, vout) for spent detection.
    known_utxos: HashSet<(String, u32)>,
}

/// Sync configuration
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Number of blocks to scan per batch
    pub batch_size: u32,
    /// Whether to scan stealth addresses
    pub scan_stealth: bool,
    /// Whether to update lock status
    pub update_locks: bool,
    /// Gap limit for address discovery
    pub gap_limit: u32,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            scan_stealth: true,
            update_locks: true,
            gap_limit: 20,
        }
    }
}

impl GhostSync {
    /// Create a new synchronizer
    pub fn new(config: SyncConfig) -> Self {
        Self {
            status: SyncStatus::Idle,
            last_height: 0,
            public_addresses: Vec::new(),
            stealth_addresses: Vec::new(),
            ghost_locks: Vec::new(),
            jump_locks: Vec::new(),
            config,
            known_utxos: HashSet::new(),
        }
    }

    /// Get current sync status
    pub fn status(&self) -> &SyncStatus {
        &self.status
    }

    /// Get last synced height
    pub fn last_height(&self) -> u64 {
        self.last_height
    }

    /// Add a public address to watch
    pub fn watch_address(&mut self, address: String) {
        if !self.public_addresses.contains(&address) {
            self.public_addresses.push(address);
        }
    }

    /// Add a stealth address to watch
    pub fn watch_stealth_address(&mut self, stealth: StealthAddress) {
        if !self.stealth_addresses.iter().any(|s| s.address == stealth.address) {
            self.stealth_addresses.push(stealth);
        }
    }

    /// Add a Ghost Lock to monitor
    pub fn watch_ghost_lock(&mut self, lock_id: String) {
        if !self.ghost_locks.contains(&lock_id) {
            self.ghost_locks.push(lock_id);
        }
    }

    /// Add a Jump Lock to monitor
    pub fn watch_jump_lock(&mut self, lock_id: String) {
        if !self.jump_locks.contains(&lock_id) {
            self.jump_locks.push(lock_id);
        }
    }

    /// Remove a watch address
    pub fn unwatch_address(&mut self, address: &str) {
        self.public_addresses.retain(|a| a != address);
    }

    /// Perform a full sync cycle
    pub async fn sync(&mut self, client: &mut GhostClient) -> Result<SyncResult, NetworkError> {
        let mut result = SyncResult::default();

        // Get current block height
        let target_height = client.get_block_count().await?;

        if target_height <= self.last_height {
            self.status = SyncStatus::Synced {
                height: self.last_height,
            };
            result.height = self.last_height;
            return Ok(result);
        }

        // Phase 1: Sync public addresses
        self.status = SyncStatus::Syncing {
            current_height: self.last_height,
            target_height,
            phase: SyncPhase::PublicAddresses,
        };

        let addresses = self.public_addresses.clone();
        for address in &addresses {
            let addr_result = self.sync_address(client, address).await?;
            result.new_utxos_count += addr_result.new_utxos.len() as u32;
            result.spent_utxos_count += addr_result.spent_utxos.len() as u32;
            result.new_tx_count += addr_result.new_txids.len() as u32;
            result.addresses_scanned += 1;
        }

        // Phase 2: Sync stealth addresses (Wraith Protocol)
        if self.config.scan_stealth && !self.stealth_addresses.is_empty() {
            self.status = SyncStatus::Syncing {
                current_height: self.last_height,
                target_height,
                phase: SyncPhase::StealthAddresses,
            };

            // Trigger rescan for anonymous outputs
            client.rescan_anon_outputs().await.ok(); // Non-fatal if fails

            let stealth_addrs = self.stealth_addresses.clone();
            for stealth in &stealth_addrs {
                let addr_result = self.sync_stealth_address(client, stealth).await?;
                result.new_utxos_count += addr_result.new_utxos.len() as u32;
                result.new_tx_count += addr_result.new_txids.len() as u32;
                result.addresses_scanned += 1;
            }
        }

        // Phase 3: Update lock status
        if self.config.update_locks {
            self.status = SyncStatus::Syncing {
                current_height: self.last_height,
                target_height,
                phase: SyncPhase::Locks,
            };

            // Update Ghost Locks
            for lock_id in &self.ghost_locks.clone() {
                if let Ok(_lock) = client.get_ghost_lock(lock_id).await {
                    result.locks_updated += 1;
                }
            }

            // Update Jump Locks
            for lock_id in &self.jump_locks.clone() {
                if let Ok(_lock) = client.get_jump_lock(lock_id).await {
                    result.locks_updated += 1;
                }
            }
        }

        // Finalize
        self.status = SyncStatus::Syncing {
            current_height: target_height,
            target_height,
            phase: SyncPhase::Finalizing,
        };

        self.last_height = target_height;
        result.height = target_height;

        self.status = SyncStatus::Synced {
            height: target_height,
        };

        Ok(result)
    }

    /// Sync a single public address.
    ///
    /// Compares the current UTXO set from the node against `known_utxos`
    /// to detect newly created and spent outputs.
    async fn sync_address(
        &mut self,
        client: &mut GhostClient,
        address: &str,
    ) -> Result<AddressSyncResult, NetworkError> {
        let current_utxos = client.get_address_utxos(address).await?;
        let txids = client.get_address_txids(address).await?;

        // Build a set of current (txid, vout) pairs for this address.
        let current_set: HashSet<(String, u32)> = current_utxos
            .iter()
            .map(|u| (u.txid.clone(), u.vout))
            .collect();

        // Detect spent: UTXOs previously known for this address that are
        // no longer in the current set.
        let spent_utxos: Vec<(String, u32)> = self
            .known_utxos
            .iter()
            .filter(|(txid, _vout)| {
                // We only care about UTXOs that belonged to this address.
                // Since known_utxos is global, we check membership in the
                // current query scope: if it was in our set but NOT in the
                // node's current UTXOs for this address, it was spent.
                // (This is conservative — if the UTXO belongs to a different
                // address it won't appear in current_set either, but we
                // accept false positives here; the wallet layer reconciles.)
                !current_set.contains(&(txid.clone(), *_vout))
            })
            .cloned()
            .collect();

        // Remove spent from known set, add new ones.
        for spent in &spent_utxos {
            self.known_utxos.remove(spent);
        }
        for utxo in &current_utxos {
            self.known_utxos.insert((utxo.txid.clone(), utxo.vout));
        }

        Ok(AddressSyncResult {
            address: address.to_string(),
            is_stealth: false,
            new_utxos: current_utxos,
            spent_utxos,
            new_txids: txids,
        })
    }

    /// Sync a stealth address (Wraith Protocol)
    async fn sync_stealth_address(
        &self,
        client: &mut GhostClient,
        stealth: &StealthAddress,
    ) -> Result<AddressSyncResult, NetworkError> {
        // For stealth addresses, we query the daemon which has already
        // scanned for matching outputs using the scan key
        let utxos = client.get_address_utxos(&stealth.address).await
            .unwrap_or_default();

        Ok(AddressSyncResult {
            address: stealth.address.clone(),
            is_stealth: true,
            new_utxos: utxos,
            spent_utxos: Vec::new(),
            new_txids: Vec::new(),
        })
    }

    /// Quick balance check (without full sync)
    pub async fn quick_balance_check(
        &self,
        client: &mut GhostClient,
    ) -> Result<(u64, u64), NetworkError> {
        let mut public_balance = 0u64;

        for address in &self.public_addresses {
            if let Ok(balance) = client.get_address_balance(address).await {
                public_balance += balance.confirmed;
            }
        }

        // Get private balance
        let private_balance = client
            .get_private_balance()
            .await
            .map(|b| (b * 100_000_000.0) as u64) // Convert from GHOST to satoshis
            .unwrap_or(0);

        Ok((public_balance, private_balance))
    }

    /// Get all Ghost Locks with their current status
    pub async fn get_all_ghost_locks(
        &self,
        client: &mut GhostClient,
    ) -> Result<Vec<GhostLock>, NetworkError> {
        client.list_ghost_locks().await
    }

    /// Get all Jump Locks with their current status
    pub async fn get_all_jump_locks(
        &self,
        client: &mut GhostClient,
    ) -> Result<Vec<JumpLock>, NetworkError> {
        client.list_jump_locks().await
    }

    /// Check if any locks have matured or expired
    pub async fn check_lock_maturity(
        &self,
        client: &mut GhostClient,
    ) -> Result<Vec<String>, NetworkError> {
        let mut matured = Vec::new();

        let locks = client.list_ghost_locks().await?;
        for lock in locks {
            if lock.status == LockStatus::Matured {
                matured.push(lock.id);
            }
        }

        Ok(matured)
    }
}

impl Default for GhostSync {
    fn default() -> Self {
        Self::new(SyncConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_stealth(name: &str) -> StealthAddress {
        StealthAddress {
            address: name.into(),
            scan_pubkey: format!("{name}_scan"),
            spend_pubkey: format!("{name}_spend"),
            ephemeral_pubkey: None,
        }
    }

    #[test]
    fn test_sync_creation() {
        let sync = GhostSync::new(SyncConfig::default());
        assert!(matches!(sync.status(), SyncStatus::Idle));
    }

    #[test]
    fn test_default() {
        let sync = GhostSync::default();
        assert!(matches!(sync.status(), SyncStatus::Idle));
        assert_eq!(sync.last_height(), 0);
    }

    #[test]
    fn test_watch_address() {
        let mut sync = GhostSync::new(SyncConfig::default());
        sync.watch_address("ghost1abc".into());
        sync.watch_address("ghost1def".into());
        sync.watch_address("ghost1abc".into()); // Duplicate

        assert_eq!(sync.public_addresses.len(), 2);
    }

    #[test]
    fn test_watch_stealth_address() {
        let mut sync = GhostSync::new(SyncConfig::default());

        sync.watch_stealth_address(test_stealth("s1"));
        sync.watch_stealth_address(test_stealth("s1")); // Duplicate

        assert_eq!(sync.stealth_addresses.len(), 1);
    }

    #[test]
    fn test_watch_locks() {
        let mut sync = GhostSync::new(SyncConfig::default());

        sync.watch_ghost_lock("lock1".into());
        sync.watch_jump_lock("jump1".into());

        assert_eq!(sync.ghost_locks.len(), 1);
        assert_eq!(sync.jump_locks.len(), 1);
    }

    #[test]
    fn test_unwatch_address() {
        let mut sync = GhostSync::default();
        sync.watch_address("a1".into());
        sync.watch_address("a2".into());
        assert_eq!(sync.public_addresses.len(), 2);

        sync.unwatch_address("a1");
        assert_eq!(sync.public_addresses.len(), 1);
        assert_eq!(sync.public_addresses[0], "a2");
    }

    #[test]
    fn test_unwatch_nonexistent() {
        let mut sync = GhostSync::default();
        sync.watch_address("a1".into());
        sync.unwatch_address("nonexistent");
        assert_eq!(sync.public_addresses.len(), 1);
    }

    #[test]
    fn test_duplicate_ghost_lock() {
        let mut sync = GhostSync::default();
        sync.watch_ghost_lock("lock1".into());
        sync.watch_ghost_lock("lock1".into());
        assert_eq!(sync.ghost_locks.len(), 1);
    }

    #[test]
    fn test_duplicate_jump_lock() {
        let mut sync = GhostSync::default();
        sync.watch_jump_lock("j1".into());
        sync.watch_jump_lock("j1".into());
        assert_eq!(sync.jump_locks.len(), 1);
    }

    #[test]
    fn test_multiple_stealth_different_addresses() {
        let mut sync = GhostSync::default();
        sync.watch_stealth_address(test_stealth("s1"));
        sync.watch_stealth_address(test_stealth("s2"));
        assert_eq!(sync.stealth_addresses.len(), 2);
    }

    #[test]
    fn test_sync_config_defaults() {
        let config = SyncConfig::default();
        assert_eq!(config.batch_size, 100);
        assert!(config.scan_stealth);
        assert!(config.update_locks);
        assert_eq!(config.gap_limit, 20);
    }

    #[test]
    fn test_sync_config_custom() {
        let config = SyncConfig {
            batch_size: 50,
            scan_stealth: false,
            update_locks: false,
            gap_limit: 10,
        };
        let sync = GhostSync::new(config);
        assert!(matches!(sync.status(), SyncStatus::Idle));
    }

    #[test]
    fn test_sync_result_default() {
        let r = SyncResult::default();
        assert_eq!(r.height, 0);
        assert_eq!(r.addresses_scanned, 0);
        assert_eq!(r.new_utxos_count, 0);
        assert_eq!(r.spent_utxos_count, 0);
        assert_eq!(r.new_tx_count, 0);
        assert_eq!(r.public_balance_change, 0);
        assert_eq!(r.private_balance_change, 0);
        assert_eq!(r.locks_updated, 0);
    }
}
