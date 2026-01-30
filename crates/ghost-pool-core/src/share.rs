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
//| FILE: share.rs                                                                              |
//|======================================================================================================================|

//! Share submission and validation.
//!
//! Shares are proof-of-work submissions from miners that may or may not
//! meet the full network difficulty. Valid shares prove the miner is
//! contributing work.

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::num::NonZeroUsize;
use lru::LruCache;

use ghost_primitives::BlockHash;
use crate::job::{JobId, MiningJob};
use crate::miner::MinerId;
use crate::error::PoolError;

// =============================================================================
// Timestamp Validation Constants (Fix 6)
// =============================================================================

/// Maximum time in future a share timestamp can be (2 minutes).
pub const MAX_FUTURE_TIME_SECS: u32 = 120;

/// Maximum time in past relative to job template (10 minutes).
pub const MAX_PAST_TIME_SECS: u32 = 600;

/// Bitcoin genesis block timestamp (2009-01-03).
pub const GENESIS_TIME: u32 = 1231006505;

// =============================================================================
// Share Size Limits (Critical Security Fix)
// =============================================================================

// Re-export shared constant from ghost-primitives for backwards compatibility
// SECURITY: Using shared constant ensures consistent validation between ghost-pool and ghostd
pub use ghost_primitives::MAX_EXTRANONCE2_SIZE;

/// Minimum block version (must be at least 1).
pub const MIN_BLOCK_VERSION: u32 = 1;

/// Maximum block version (BIP9 allows up to 0x3FFFFFFF).
pub const MAX_BLOCK_VERSION: u32 = 0x3FFFFFFF;

/// Configuration for timestamp validation.
#[derive(Debug, Clone)]
pub struct TimestampValidationConfig {
    /// Maximum seconds in future a share timestamp can be.
    pub max_future_secs: u32,
    /// Maximum seconds in past relative to job ntime.
    pub max_past_secs: u32,
}

impl Default for TimestampValidationConfig {
    fn default() -> Self {
        Self {
            max_future_secs: MAX_FUTURE_TIME_SECS,
            max_past_secs: MAX_PAST_TIME_SECS,
        }
    }
}

/// A share submission from a miner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareSubmission {
    /// Miner who submitted the share.
    pub miner_id: MinerId,
    /// Job ID the share is for.
    pub job_id: JobId,
    /// Extranonce2 used by miner.
    pub extranonce2: Vec<u8>,
    /// Nonce found.
    pub nonce: u32,
    /// Timestamp used.
    pub ntime: u32,
    /// Version bits (for version rolling).
    pub version: Option<u32>,
}

/// Result of share validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareResult {
    /// The share hash (block hash if it were a valid block).
    pub hash: [u8; 32],
    /// Difficulty of this share.
    pub difficulty: f64,
    /// Whether share meets pool difficulty.
    pub meets_pool_difficulty: bool,
    /// Whether share meets network difficulty (valid block!).
    pub meets_network_difficulty: bool,
    /// Validation timestamp.
    pub validated_at: i64,
}

impl ShareResult {
    /// Check if this share is a valid block.
    pub fn is_block(&self) -> bool {
        self.meets_network_difficulty
    }
}

/// A validated share record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedShare {
    /// Share submission.
    pub submission: ShareSubmission,
    /// Validation result.
    pub result: ShareResult,
    /// Extranonce1 that was assigned to the miner.
    pub extranonce1: Vec<u8>,
    /// Pool difficulty target.
    pub pool_difficulty: f64,
}

/// Share validator.
pub struct ShareValidator {
    /// Network difficulty.
    pub network_difficulty: f64,
    /// Submitted share tracking (LRU cache for duplicate detection).
    /// Using LRU ensures we keep tracking recent shares while automatically
    /// evicting oldest entries when the cache is full.
    submitted_hashes: LruCache<[u8; 32], ()>,
    /// Timestamp validation configuration.
    timestamp_config: TimestampValidationConfig,
}

impl Default for ShareValidator {
    fn default() -> Self {
        Self::new(1.0)
    }
}

impl ShareValidator {
    /// Create a new share validator.
    pub fn new(network_difficulty: f64) -> Self {
        Self::with_capacity(network_difficulty, 100_000)
    }

    /// Minimum cache capacity.
    ///
    /// # Safety
    /// This is safe because 1 is always a valid non-zero value.
    /// Using new_unchecked avoids the Option wrapper for a compile-time constant.
    const MIN_CAPACITY: NonZeroUsize = unsafe { NonZeroUsize::new_unchecked(1) };

    /// Create a share validator with custom capacity.
    pub fn with_capacity(network_difficulty: f64, capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity).unwrap_or(Self::MIN_CAPACITY);
        Self {
            network_difficulty,
            submitted_hashes: LruCache::new(cap),
            timestamp_config: TimestampValidationConfig::default(),
        }
    }

    /// Set timestamp validation configuration.
    pub fn set_timestamp_config(&mut self, config: TimestampValidationConfig) {
        self.timestamp_config = config;
    }

    /// Set network difficulty.
    pub fn set_network_difficulty(&mut self, difficulty: f64) {
        self.network_difficulty = difficulty;
    }

    /// Validate share timestamp.
    ///
    /// Checks that the timestamp:
    /// 1. Is not before Bitcoin genesis
    /// 2. Is not too far in the future
    /// 3. Is not too far in the past relative to the job
    ///
    /// This prevents:
    /// - Time manipulation attacks
    /// - Replay of old shares
    /// - DoS via invalid timestamps
    fn validate_timestamp(
        &self,
        share_ntime: u32,
        job_ntime: u32,
        current_time: u32,
    ) -> Result<(), PoolError> {
        // Check not before Bitcoin genesis
        if share_ntime < GENESIS_TIME {
            return Err(PoolError::InvalidShare(format!(
                "ntime before Bitcoin genesis: {}",
                share_ntime
            )));
        }

        // Check not too far in future (use >= to include boundary)
        if share_ntime >= current_time + self.timestamp_config.max_future_secs {
            return Err(PoolError::InvalidShare(format!(
                "ntime too far in future: {} >= {} + {}",
                share_ntime, current_time, self.timestamp_config.max_future_secs
            )));
        }

        // Check not too far in past relative to job
        if share_ntime < job_ntime.saturating_sub(self.timestamp_config.max_past_secs) {
            return Err(PoolError::InvalidShare(format!(
                "ntime too old relative to job: {} < {} - {}",
                share_ntime, job_ntime, self.timestamp_config.max_past_secs
            )));
        }

        Ok(())
    }

    /// Validate extranonce2 size.
    ///
    /// SECURITY: Prevents memory exhaustion attacks by limiting extranonce2 to
    /// a reasonable size. Attackers could send 1GB+ extranonce2 values to crash
    /// the pool via memory exhaustion during hash computation.
    fn validate_extranonce2(&self, extranonce2: &[u8]) -> Result<(), PoolError> {
        if extranonce2.len() > MAX_EXTRANONCE2_SIZE {
            return Err(PoolError::InvalidShare(format!(
                "extranonce2 too large: {} bytes > {} max",
                extranonce2.len(),
                MAX_EXTRANONCE2_SIZE
            )));
        }
        if extranonce2.is_empty() {
            return Err(PoolError::InvalidShare(
                "extranonce2 cannot be empty".into(),
            ));
        }
        Ok(())
    }

    /// Validate block version.
    ///
    /// SECURITY: Prevents invalid block versions that would cause block rejection.
    /// Malicious miners could submit shares with invalid versions to waste pool
    /// resources or cause invalid block submissions.
    fn validate_version(&self, version: Option<u32>, job_version: u32) -> Result<u32, PoolError> {
        let version = version.unwrap_or(job_version);

        if version < MIN_BLOCK_VERSION {
            return Err(PoolError::InvalidShare(format!(
                "block version too low: {} < {}",
                version, MIN_BLOCK_VERSION
            )));
        }

        if version > MAX_BLOCK_VERSION {
            return Err(PoolError::InvalidShare(format!(
                "block version too high: {} > {}",
                version, MAX_BLOCK_VERSION
            )));
        }

        Ok(version)
    }

    /// Validate a share submission.
    ///
    /// Performs comprehensive validation including:
    /// - Extranonce2 size check (Critical: prevents memory exhaustion)
    /// - Version validation (Critical: prevents invalid blocks)
    /// - Job expiration check
    /// - Timestamp validation (Fix 6)
    /// - Duplicate detection
    /// - Difficulty check
    pub fn validate(
        &mut self,
        submission: &ShareSubmission,
        job: &MiningJob,
        extranonce1: &[u8],
        pool_difficulty: f64,
    ) -> Result<ShareResult, PoolError> {
        // CRITICAL: Validate extranonce2 size first to prevent memory exhaustion
        self.validate_extranonce2(&submission.extranonce2)?;

        // CRITICAL: Validate version to prevent invalid blocks
        let _validated_version = self.validate_version(submission.version, job.version)?;

        // Check job not expired
        if job.is_expired() {
            return Err(PoolError::StaleShare(submission.job_id.to_string()));
        }

        // Validate timestamp (Fix 6)
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(GENESIS_TIME);

        self.validate_timestamp(submission.ntime, job.ntime, current_time)?;

        // Compute the block header hash
        let hash = self.compute_share_hash(submission, job, extranonce1)?;

        // SECURITY: Reject all-zero hashes as they indicate manipulation or error
        // A legitimate hash will never be all zeros (cryptographically impossible)
        if hash.iter().all(|&b| b == 0) {
            return Err(PoolError::InvalidShare(
                "all-zero hash indicates manipulation or computation error".into(),
            ));
        }

        // Check for duplicate using LRU cache
        // contains() also promotes the entry to most-recently-used
        if self.submitted_hashes.contains(&hash) {
            return Err(PoolError::DuplicateShare);
        }

        // Calculate share difficulty
        let difficulty = self.hash_to_difficulty(&hash);

        // Check if meets pool difficulty
        let meets_pool = difficulty >= pool_difficulty;
        if !meets_pool {
            return Err(PoolError::BelowDifficulty);
        }

        // Check if meets network difficulty
        let meets_network = difficulty >= self.network_difficulty;

        // Track this share hash in LRU cache
        // LRU cache automatically evicts oldest entry when at capacity,
        // ensuring we don't lose recent duplicate detection capability
        self.submitted_hashes.put(hash, ());

        Ok(ShareResult {
            hash,
            difficulty,
            meets_pool_difficulty: meets_pool,
            meets_network_difficulty: meets_network,
            validated_at: chrono::Utc::now().timestamp(),
        })
    }

    /// Compute the share hash (would be block hash if valid).
    fn compute_share_hash(
        &self,
        submission: &ShareSubmission,
        job: &MiningJob,
        extranonce1: &[u8],
    ) -> Result<[u8; 32], PoolError> {
        // Compute coinbase hash
        let coinbase_hash = job.coinbase_hash(extranonce1, &submission.extranonce2);

        // Compute merkle root
        let merkle_root = job.merkle_root(&coinbase_hash);

        // Build block header
        let version = submission.version.unwrap_or(job.version);
        let header = self.build_header(
            version,
            &job.prev_block_hash,
            &merkle_root,
            submission.ntime,
            job.nbits,
            submission.nonce,
        );

        // Double SHA256
        let first = Sha256::digest(header);
        let hash = Sha256::digest(first);

        Ok(hash.into())
    }

    /// Build block header bytes.
    fn build_header(
        &self,
        version: u32,
        prev_hash: &BlockHash,
        merkle_root: &[u8; 32],
        ntime: u32,
        nbits: u32,
        nonce: u32,
    ) -> [u8; 80] {
        let mut header = [0u8; 80];

        // Version (4 bytes, little-endian)
        header[0..4].copy_from_slice(&version.to_le_bytes());

        // Previous block hash (32 bytes)
        header[4..36].copy_from_slice(prev_hash.as_bytes());

        // Merkle root (32 bytes)
        header[36..68].copy_from_slice(merkle_root);

        // Timestamp (4 bytes, little-endian)
        header[68..72].copy_from_slice(&ntime.to_le_bytes());

        // Bits (4 bytes, little-endian)
        header[72..76].copy_from_slice(&nbits.to_le_bytes());

        // Nonce (4 bytes, little-endian)
        header[76..80].copy_from_slice(&nonce.to_le_bytes());

        header
    }

    /// Convert a hash to difficulty.
    fn hash_to_difficulty(&self, hash: &[u8; 32]) -> f64 {
        // Bitcoin difficulty calculation
        // difficulty = max_target / current_target
        // where max_target is the easiest possible target (difficulty 1)

        // Convert hash to a number (treating as big-endian)
        let mut value = 0u128;
        for (i, &byte) in hash.iter().rev().take(16).enumerate() {
            value |= (byte as u128) << (i * 8);
        }

        if value == 0 {
            return f64::MAX;
        }

        // max_target for difficulty 1
        let max_target = 0x00000000FFFF_u128 << 208_u32.saturating_sub(128);

        (max_target as f64) / (value as f64)
    }

    /// Clear tracked shares.
    pub fn clear_tracking(&mut self) {
        self.submitted_hashes.clear();
    }

    /// Get the number of tracked share hashes.
    pub fn tracked_count(&self) -> usize {
        self.submitted_hashes.len()
    }

    /// Export tracked share hashes for persistence.
    ///
    /// HIGH: Call this before shutdown to prevent replay attacks on restart.
    /// The returned hashes should be persisted and loaded via `import_hashes`.
    pub fn export_hashes(&self) -> Vec<[u8; 32]> {
        self.submitted_hashes
            .iter()
            .map(|(hash, _)| *hash)
            .collect()
    }

    /// Import previously tracked share hashes.
    ///
    /// HIGH: Call this on startup with hashes from `export_hashes` to prevent
    /// replay attacks. Hashes from the last ~10 minutes should be persisted.
    pub fn import_hashes(&mut self, hashes: impl IntoIterator<Item = [u8; 32]>) {
        for hash in hashes {
            self.submitted_hashes.put(hash, ());
        }
    }

    /// Get share hashes that are recent (for persistence).
    ///
    /// Returns only hashes that should be persisted (most recent up to count).
    pub fn recent_hashes(&self, count: usize) -> Vec<[u8; 32]> {
        self.submitted_hashes
            .iter()
            .take(count)
            .map(|(hash, _)| *hash)
            .collect()
    }
}

/// Share aggregator for tracking work by miner.
#[derive(Debug, Default)]
pub struct ShareAggregator {
    /// Shares by miner.
    shares: std::collections::HashMap<MinerId, MinerShareStats>,
    /// Total work.
    total_work: f64,
}

/// Statistics for a miner's shares.
#[derive(Debug, Clone, Default)]
pub struct MinerShareStats {
    /// Number of shares submitted.
    pub share_count: u64,
    /// Total work (sum of difficulties).
    pub total_work: f64,
    /// Last share timestamp.
    pub last_share_at: Option<i64>,
    /// Number of stale shares.
    pub stale_count: u64,
    /// Number of invalid shares.
    pub invalid_count: u64,
}

impl ShareAggregator {
    /// Create a new share aggregator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a valid share.
    pub fn record_share(&mut self, miner_id: MinerId, difficulty: f64) {
        let stats = self.shares.entry(miner_id).or_default();
        stats.share_count += 1;
        stats.total_work += difficulty;
        stats.last_share_at = Some(chrono::Utc::now().timestamp());
        self.total_work += difficulty;
    }

    /// Record a stale share.
    pub fn record_stale(&mut self, miner_id: MinerId) {
        let stats = self.shares.entry(miner_id).or_default();
        stats.stale_count += 1;
    }

    /// Record an invalid share.
    pub fn record_invalid(&mut self, miner_id: MinerId) {
        let stats = self.shares.entry(miner_id).or_default();
        stats.invalid_count += 1;
    }

    /// Get stats for a miner.
    pub fn get_miner_stats(&self, miner_id: &MinerId) -> Option<&MinerShareStats> {
        self.shares.get(miner_id)
    }

    /// Get total work.
    pub fn total_work(&self) -> f64 {
        self.total_work
    }

    /// Get work share for a miner (0.0 to 1.0).
    pub fn miner_work_share(&self, miner_id: &MinerId) -> f64 {
        if self.total_work == 0.0 {
            return 0.0;
        }
        self.shares
            .get(miner_id)
            .map(|s| s.total_work / self.total_work)
            .unwrap_or(0.0)
    }

    /// Get all miners sorted by work.
    pub fn miners_by_work(&self) -> Vec<(MinerId, f64)> {
        let mut miners: Vec<_> = self
            .shares
            .iter()
            .map(|(id, stats)| (*id, stats.total_work))
            .collect();
        miners.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        miners
    }

    /// Reset statistics (for new round).
    pub fn reset(&mut self) {
        self.shares.clear();
        self.total_work = 0.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    

    #[test]
    fn test_share_aggregator() {
        let mut agg = ShareAggregator::new();

        let miner1 = MinerId::new(1);
        let miner2 = MinerId::new(2);

        agg.record_share(miner1, 1.0);
        agg.record_share(miner1, 1.0);
        agg.record_share(miner2, 2.0);

        assert_eq!(agg.total_work(), 4.0);
        assert_eq!(agg.miner_work_share(&miner1), 0.5);
        assert_eq!(agg.miner_work_share(&miner2), 0.5);

        let stats1 = agg.get_miner_stats(&miner1).unwrap();
        assert_eq!(stats1.share_count, 2);
    }

    #[test]
    fn test_hash_to_difficulty() {
        let validator = ShareValidator::new(1.0);

        // All zeros = max difficulty
        let hash = [0u8; 32];
        let diff = validator.hash_to_difficulty(&hash);
        assert!(diff == f64::MAX);

        // All ones = very low difficulty
        let hash = [0xFF; 32];
        let diff = validator.hash_to_difficulty(&hash);
        assert!(diff < 1.0);
    }

    #[test]
    fn test_lru_duplicate_detection() {
        // Create validator with small capacity to test LRU eviction
        let mut validator = ShareValidator::with_capacity(1.0, 3);

        // Insert three hashes
        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];
        let hash3 = [3u8; 32];

        validator.submitted_hashes.put(hash1, ());
        validator.submitted_hashes.put(hash2, ());
        validator.submitted_hashes.put(hash3, ());

        assert_eq!(validator.tracked_count(), 3);

        // All three should be detected as duplicates
        assert!(validator.submitted_hashes.contains(&hash1));
        assert!(validator.submitted_hashes.contains(&hash2));
        assert!(validator.submitted_hashes.contains(&hash3));

        // Insert a fourth hash - should evict hash1 (oldest)
        let hash4 = [4u8; 32];
        validator.submitted_hashes.put(hash4, ());

        assert_eq!(validator.tracked_count(), 3);
        assert!(!validator.submitted_hashes.contains(&hash1)); // Evicted
        assert!(validator.submitted_hashes.contains(&hash2));
        assert!(validator.submitted_hashes.contains(&hash3));
        assert!(validator.submitted_hashes.contains(&hash4));
    }

    #[test]
    fn test_lru_access_promotes_entry() {
        // Test that accessing an entry moves it to most-recently-used
        let mut validator = ShareValidator::with_capacity(1.0, 3);

        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];
        let hash3 = [3u8; 32];

        validator.submitted_hashes.put(hash1, ());
        validator.submitted_hashes.put(hash2, ());
        validator.submitted_hashes.put(hash3, ());

        // Access hash1, making it most-recently-used
        validator.submitted_hashes.get(&hash1);

        // Insert a new hash - should evict hash2 (now oldest)
        let hash4 = [4u8; 32];
        validator.submitted_hashes.put(hash4, ());

        assert!(validator.submitted_hashes.contains(&hash1)); // Still present (was accessed)
        assert!(!validator.submitted_hashes.contains(&hash2)); // Evicted
        assert!(validator.submitted_hashes.contains(&hash3));
        assert!(validator.submitted_hashes.contains(&hash4));
    }

    #[test]
    fn test_clear_tracking() {
        let mut validator = ShareValidator::new(1.0);

        validator.submitted_hashes.put([1u8; 32], ());
        validator.submitted_hashes.put([2u8; 32], ());
        assert_eq!(validator.tracked_count(), 2);

        validator.clear_tracking();
        assert_eq!(validator.tracked_count(), 0);
    }

    // =========================================================================
    // Critical Security Tests
    // =========================================================================

    #[test]
    fn test_extranonce2_size_limit() {
        let validator = ShareValidator::new(1.0);

        // Valid size (4 bytes typical)
        assert!(validator.validate_extranonce2(&[0u8; 4]).is_ok());

        // Valid size (maximum allowed)
        assert!(validator.validate_extranonce2(&[0u8; MAX_EXTRANONCE2_SIZE]).is_ok());

        // Empty not allowed
        assert!(validator.validate_extranonce2(&[]).is_err());

        // Too large (CRITICAL: prevents memory exhaustion)
        assert!(validator.validate_extranonce2(&[0u8; MAX_EXTRANONCE2_SIZE + 1]).is_err());

        // Way too large (attack simulation)
        assert!(validator.validate_extranonce2(&[0u8; 1024]).is_err());
    }

    #[test]
    fn test_version_validation() {
        let validator = ShareValidator::new(1.0);
        let job_version = 0x20000000;

        // No override - use job version
        assert!(validator.validate_version(None, job_version).is_ok());
        assert_eq!(validator.validate_version(None, job_version).unwrap(), job_version);

        // Valid override
        assert!(validator.validate_version(Some(1), job_version).is_ok());
        assert!(validator.validate_version(Some(0x20000000), job_version).is_ok());
        assert!(validator.validate_version(Some(MAX_BLOCK_VERSION), job_version).is_ok());

        // Invalid: version 0
        assert!(validator.validate_version(Some(0), job_version).is_err());

        // Invalid: version too high
        assert!(validator.validate_version(Some(MAX_BLOCK_VERSION + 1), job_version).is_err());
        assert!(validator.validate_version(Some(0xFFFFFFFF), job_version).is_err());
    }

    #[test]
    fn test_timestamp_boundary_exact() {
        let validator = ShareValidator::new(1.0);
        let current_time = GENESIS_TIME + 1_000_000;
        let job_ntime = current_time - 60;

        // Exactly at future boundary should fail (>= not >)
        let at_boundary = current_time + MAX_FUTURE_TIME_SECS;
        let result = validator.validate_timestamp(at_boundary, job_ntime, current_time);
        assert!(result.is_err(), "Timestamp exactly at boundary should fail");

        // Just before boundary should pass
        let before_boundary = current_time + MAX_FUTURE_TIME_SECS - 1;
        let result = validator.validate_timestamp(before_boundary, job_ntime, current_time);
        assert!(result.is_ok(), "Timestamp just before boundary should pass");
    }

    #[test]
    fn test_hash_export_import() {
        let mut validator1 = ShareValidator::with_capacity(1.0, 100);

        // Add some hashes
        validator1.submitted_hashes.put([1u8; 32], ());
        validator1.submitted_hashes.put([2u8; 32], ());
        validator1.submitted_hashes.put([3u8; 32], ());

        // Export
        let exported = validator1.export_hashes();
        assert_eq!(exported.len(), 3);

        // Import into new validator (simulates restart)
        let mut validator2 = ShareValidator::with_capacity(1.0, 100);
        validator2.import_hashes(exported);

        assert_eq!(validator2.tracked_count(), 3);
        assert!(validator2.submitted_hashes.contains(&[1u8; 32]));
        assert!(validator2.submitted_hashes.contains(&[2u8; 32]));
        assert!(validator2.submitted_hashes.contains(&[3u8; 32]));
    }

    #[test]
    fn test_recent_hashes_limit() {
        let mut validator = ShareValidator::with_capacity(1.0, 100);

        // Add 10 hashes
        for i in 0..10u8 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            validator.submitted_hashes.put(hash, ());
        }

        // Get only 5 recent
        let recent = validator.recent_hashes(5);
        assert_eq!(recent.len(), 5);
    }
}
