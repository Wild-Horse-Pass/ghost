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
//| FILE: difficulty.rs                                                                         |
//|======================================================================================================================|

//! Difficulty adjustment for miners.
//!
//! Implements vardiff (variable difficulty) to target a specific
//! share submission rate per miner.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Configuration for difficulty adjustment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifficultyConfig {
    /// Minimum difficulty.
    pub min_difficulty: f64,
    /// Maximum difficulty.
    pub max_difficulty: f64,
    /// Initial difficulty for new miners.
    pub initial_difficulty: f64,
    /// Target shares per minute.
    pub target_shares_per_minute: f64,
    /// Retarget interval in seconds.
    pub retarget_interval_secs: i64,
    /// Maximum difficulty change factor per retarget.
    pub max_change_factor: f64,
    /// Minimum shares before retarget.
    pub min_shares_for_retarget: u32,
}

impl Default for DifficultyConfig {
    fn default() -> Self {
        Self {
            min_difficulty: 0.001,
            max_difficulty: 1_000_000.0,
            initial_difficulty: 1.0,
            target_shares_per_minute: 20.0,
            retarget_interval_secs: 60,
            max_change_factor: 4.0,
            min_shares_for_retarget: 10,
        }
    }
}

/// Difficulty tracker for a single miner.
#[derive(Debug, Clone)]
pub struct MinerDifficulty {
    /// Current difficulty.
    pub current: f64,
    /// Share timestamps.
    share_times: VecDeque<i64>,
    /// Last retarget time.
    last_retarget: i64,
    /// Configuration.
    config: DifficultyConfig,
}

impl MinerDifficulty {
    /// Create a new miner difficulty tracker.
    pub fn new(config: DifficultyConfig) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            current: config.initial_difficulty,
            share_times: VecDeque::new(),
            last_retarget: now,
            config,
        }
    }

    /// Create with specific starting difficulty.
    pub fn with_difficulty(config: DifficultyConfig, difficulty: f64) -> Self {
        let mut tracker = Self::new(config);
        tracker.current = difficulty.clamp(tracker.config.min_difficulty, tracker.config.max_difficulty);
        tracker
    }

    /// Record a share submission.
    pub fn record_share(&mut self) {
        let now = chrono::Utc::now().timestamp();
        self.share_times.push_back(now);

        // Keep only shares from the last retarget interval
        let cutoff = now - self.config.retarget_interval_secs;
        while let Some(&front) = self.share_times.front() {
            if front < cutoff {
                self.share_times.pop_front();
            } else {
                break;
            }
        }
    }

    /// Check if retarget is needed and calculate new difficulty.
    pub fn check_retarget(&mut self) -> Option<f64> {
        let now = chrono::Utc::now().timestamp();

        // Check if enough time has passed
        if now - self.last_retarget < self.config.retarget_interval_secs {
            return None;
        }

        // Check if we have enough shares
        if self.share_times.len() < self.config.min_shares_for_retarget as usize {
            self.last_retarget = now;
            return None;
        }

        // Calculate actual share rate
        let shares_in_window = self.share_times.len() as f64;
        let minutes = self.config.retarget_interval_secs as f64 / 60.0;
        let actual_rate = shares_in_window / minutes;

        // Calculate new difficulty
        let ratio = actual_rate / self.config.target_shares_per_minute;
        let clamped_ratio = ratio.clamp(
            1.0 / self.config.max_change_factor,
            self.config.max_change_factor,
        );

        let new_difficulty = self.current * clamped_ratio;
        let clamped = new_difficulty.clamp(
            self.config.min_difficulty,
            self.config.max_difficulty,
        );

        // Only update if significantly different
        if (clamped - self.current).abs() / self.current > 0.05 {
            self.current = clamped;
            self.last_retarget = now;
            self.share_times.clear();
            Some(clamped)
        } else {
            self.last_retarget = now;
            None
        }
    }

    /// Force set difficulty.
    pub fn set_difficulty(&mut self, difficulty: f64) {
        self.current = difficulty.clamp(
            self.config.min_difficulty,
            self.config.max_difficulty,
        );
        self.last_retarget = chrono::Utc::now().timestamp();
        self.share_times.clear();
    }

    /// Get current share rate (shares per minute).
    pub fn current_share_rate(&self) -> f64 {
        if self.share_times.is_empty() {
            return 0.0;
        }

        let now = chrono::Utc::now().timestamp();
        let first = self.share_times.front().copied().unwrap_or(now);
        let duration_secs = (now - first).max(1) as f64;
        let minutes = duration_secs / 60.0;

        self.share_times.len() as f64 / minutes
    }
}

/// Difficulty adjuster managing multiple miners.
pub struct DifficultyAdjuster {
    /// Configuration.
    config: DifficultyConfig,
    /// Per-miner trackers.
    trackers: std::collections::HashMap<u64, MinerDifficulty>,
}

impl Default for DifficultyAdjuster {
    fn default() -> Self {
        Self::new(DifficultyConfig::default())
    }
}

impl DifficultyAdjuster {
    /// Create a new difficulty adjuster.
    pub fn new(config: DifficultyConfig) -> Self {
        Self {
            config,
            trackers: std::collections::HashMap::new(),
        }
    }

    /// Get or create tracker for a miner.
    pub fn get_tracker(&mut self, miner_id: u64) -> &mut MinerDifficulty {
        self.trackers
            .entry(miner_id)
            .or_insert_with(|| MinerDifficulty::new(self.config.clone()))
    }

    /// Record share for a miner.
    pub fn record_share(&mut self, miner_id: u64) {
        self.get_tracker(miner_id).record_share();
    }

    /// Check retarget for a miner.
    pub fn check_retarget(&mut self, miner_id: u64) -> Option<f64> {
        self.get_tracker(miner_id).check_retarget()
    }

    /// Get current difficulty for a miner.
    pub fn get_difficulty(&mut self, miner_id: u64) -> f64 {
        self.get_tracker(miner_id).current
    }

    /// Set difficulty for a miner.
    pub fn set_difficulty(&mut self, miner_id: u64, difficulty: f64) {
        self.get_tracker(miner_id).set_difficulty(difficulty);
    }

    /// Remove a miner's tracker.
    pub fn remove_miner(&mut self, miner_id: u64) {
        self.trackers.remove(&miner_id);
    }

    /// Get initial difficulty for new miners.
    pub fn initial_difficulty(&self) -> f64 {
        self.config.initial_difficulty
    }
}

/// Calculate target from difficulty for pool mining.
///
/// The target is a 256-bit number that a block hash must be less than.
/// Lower difficulty = bigger target (easier), higher difficulty = smaller target (harder).
///
/// For pool difficulty, we use the standard pool difficulty model:
/// - Difficulty 1 corresponds to a target with 0xFFFF at the appropriate bit position
/// - The formula is: target = base_target / difficulty
/// - Where base_target = 0xFFFF * 2^208 (difficulty 1 target)
///
/// This differs from Bitcoin network difficulty which uses nbits compact format.
/// Pool difficulty is typically much lower and doesn't need the compact encoding.
pub fn difficulty_to_target(difficulty: f64) -> [u8; 32] {
    let mut bytes = [0u8; 32];

    if difficulty <= 0.0 {
        // Invalid difficulty, return max target (easiest)
        bytes.fill(0xFF);
        bytes[0..4].fill(0);
        return bytes;
    }

    // Pool difficulty model:
    // difficulty 1 = target with 0xFFFF at bytes 4-5
    // difficulty N = target with 0xFFFF/N at appropriate position

    // Calculate the target value as a u128 to handle the range
    // Base is 0xFFFF shifted to fit in the target
    let base_value: f64 = (0xFFFF_u64 as f64) * 2.0_f64.powi(208);
    let target_f64 = base_value / difficulty;

    // Clamp to valid range
    if target_f64 < 1.0 {
        return bytes; // All zeros (impossibly high difficulty)
    }

    // Fill bytes from most significant to least significant
    // We'll work with f64 and shift through the bytes
    let mut remaining = target_f64;

    for (i, byte) in bytes.iter_mut().enumerate() {
        // Scale remaining value to get the byte value at position i
        let shift = (31 - i) * 8;
        let divisor = 2.0_f64.powi(shift as i32);

        if remaining >= divisor {
            let byte_val = (remaining / divisor).min(255.0) as u8;
            *byte = byte_val;
            remaining -= (byte_val as f64) * divisor;
        }
    }

    bytes
}

/// Calculate difficulty from target.
///
/// Converts a 256-bit target back to a pool difficulty value.
pub fn target_to_difficulty(target: &[u8; 32]) -> f64 {
    // Convert target bytes to f64 value
    let mut target_f64: f64 = 0.0;

    for (i, &byte) in target.iter().enumerate() {
        let shift = (31 - i) * 8;
        target_f64 += (byte as f64) * 2.0_f64.powi(shift as i32);
    }

    if target_f64 == 0.0 {
        return f64::MAX;
    }

    // Base target for difficulty 1
    let base_value: f64 = (0xFFFF_u64 as f64) * 2.0_f64.powi(208);

    base_value / target_f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_difficulty_config_default() {
        let config = DifficultyConfig::default();
        assert_eq!(config.target_shares_per_minute, 20.0);
        assert_eq!(config.initial_difficulty, 1.0);
    }

    #[test]
    fn test_miner_difficulty_tracking() {
        let config = DifficultyConfig {
            min_shares_for_retarget: 2,
            ..Default::default()
        };
        let mut tracker = MinerDifficulty::new(config);

        // Record shares
        tracker.record_share();
        tracker.record_share();
        tracker.record_share();

        let rate = tracker.current_share_rate();
        assert!(rate > 0.0);
    }

    #[test]
    fn test_difficulty_to_target() {
        let target = difficulty_to_target(1.0);
        assert!(target[0..4] == [0, 0, 0, 0]); // Leading zeros

        let target_high = difficulty_to_target(1000.0);
        let target_low = difficulty_to_target(0.001);

        // Higher difficulty = smaller target
        assert!(target_high < target);
        // Lower difficulty = larger target
        assert!(target_low > target);
    }

    #[test]
    fn test_difficulty_adjuster() {
        let mut adjuster = DifficultyAdjuster::default();

        let d1 = adjuster.get_difficulty(1);
        assert_eq!(d1, adjuster.initial_difficulty());

        adjuster.set_difficulty(1, 2.0);
        assert_eq!(adjuster.get_difficulty(1), 2.0);
    }

    #[test]
    fn test_difficulty_target_roundtrip() {
        // Test that difficulty -> target -> difficulty roundtrip works
        let test_difficulties = [0.001, 0.1, 1.0, 10.0, 100.0, 1000.0, 10000.0];

        for &diff in &test_difficulties {
            let target = difficulty_to_target(diff);
            let recovered = target_to_difficulty(&target);

            // Allow 1% error due to floating point
            let error = (recovered - diff).abs() / diff;
            assert!(
                error < 0.01,
                "Roundtrip failed for difficulty {}: got {} (error {}%)",
                diff,
                recovered,
                error * 100.0
            );
        }
    }

    #[test]
    fn test_difficulty_ordering() {
        // Verify that higher difficulty means smaller target
        let targets: Vec<_> = [0.01, 0.1, 1.0, 10.0, 100.0]
            .iter()
            .map(|&d| difficulty_to_target(d))
            .collect();

        // Each target should be smaller than the previous (higher difficulty = smaller target)
        for i in 1..targets.len() {
            assert!(
                targets[i] < targets[i - 1],
                "Target ordering violated at index {}",
                i
            );
        }
    }

    #[test]
    fn test_extreme_difficulties() {
        // Very low difficulty = very large target
        let target_low = difficulty_to_target(0.0001);
        // Should have non-zero values (larger target)
        assert!(target_low.iter().any(|&b| b > 0));

        // Very high difficulty = smaller target
        let target_high = difficulty_to_target(1_000_000.0);
        // Target should be smaller than difficulty 1 target
        let target_one = difficulty_to_target(1.0);
        assert!(target_high < target_one);

        // At difficulty 1,000,000, first few bytes should be zero
        assert!(target_high[0..4].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_target_to_difficulty_edge_cases() {
        // All zeros = max difficulty
        let zeros = [0u8; 32];
        let diff = target_to_difficulty(&zeros);
        assert_eq!(diff, f64::MAX);

        // Small non-zero target = high difficulty
        let mut small = [0u8; 32];
        small[31] = 1; // Just the least significant byte
        let diff = target_to_difficulty(&small);
        assert!(diff > 1_000_000.0);
    }
}
