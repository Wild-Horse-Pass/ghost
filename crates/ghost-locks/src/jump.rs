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
//| FILE: jump.rs                                                                                                        |
//|======================================================================================================================|

//! Jump Locks - Risk-tiered key rotation
//!
//! Jump Locks provide proactive security through automatic key rotation
//! based on balance-at-risk tiers.

use serde::{Deserialize, Serialize};

use crate::Denomination;

/// Risk tiers for jump lock rotation scheduling
///
/// Higher balances warrant more frequent key rotation to limit
/// the window of exposure if a key is compromised.
///
/// Deadlines are randomized within a range per tier to prevent timing
/// fingerprinting. An observer cannot predict exactly when a jump will occur.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JumpRiskTier {
    /// Low risk: < 0.1 BTC, rotate every 30-60 days
    Low,
    /// Medium risk: 0.1 - 1 BTC, rotate every 14-30 days
    Medium,
    /// High risk: > 1 BTC, rotate every 7-14 days
    High,
}

impl JumpRiskTier {
    /// Blocks per day (assuming 10-minute blocks)
    const BLOCKS_PER_DAY: u32 = 144;

    /// Threshold for medium risk tier (0.1 BTC)
    const MEDIUM_THRESHOLD_SATS: u64 = 10_000_000;

    /// Threshold for high risk tier (1 BTC)
    const HIGH_THRESHOLD_SATS: u64 = 100_000_000;

    /// Determine risk tier from satoshi balance
    pub fn from_sats(sats: u64) -> Self {
        if sats >= Self::HIGH_THRESHOLD_SATS {
            JumpRiskTier::High
        } else if sats >= Self::MEDIUM_THRESHOLD_SATS {
            JumpRiskTier::Medium
        } else {
            JumpRiskTier::Low
        }
    }

    /// Alias for from_sats
    pub fn from_balance(sats: u64) -> Self {
        Self::from_sats(sats)
    }

    /// Determine risk tier from denomination
    pub fn from_denomination(denom: Denomination) -> Self {
        Self::from_sats(denom.sats())
    }

    /// Get the minimum rotation period in blocks for this tier
    pub fn min_rotation_blocks(&self) -> u32 {
        match self {
            JumpRiskTier::High => Self::BLOCKS_PER_DAY * 7,     // 7 days = 1,008 blocks
            JumpRiskTier::Medium => Self::BLOCKS_PER_DAY * 14,  // 14 days = 2,016 blocks
            JumpRiskTier::Low => Self::BLOCKS_PER_DAY * 30,     // 30 days = 4,320 blocks
        }
    }

    /// Get the maximum rotation period in blocks for this tier
    pub fn max_rotation_blocks(&self) -> u32 {
        match self {
            JumpRiskTier::High => Self::BLOCKS_PER_DAY * 14,    // 14 days = 2,016 blocks
            JumpRiskTier::Medium => Self::BLOCKS_PER_DAY * 30,  // 30 days = 4,320 blocks
            JumpRiskTier::Low => Self::BLOCKS_PER_DAY * 60,     // 60 days = 8,640 blocks
        }
    }

    /// Get the fixed rotation period in blocks (midpoint of range, for urgency calculation)
    pub fn rotation_blocks(&self) -> u32 {
        (self.min_rotation_blocks() + self.max_rotation_blocks()) / 2
    }

    /// Get the rotation period range in days
    pub fn rotation_days_range(&self) -> (u32, u32) {
        (
            self.min_rotation_blocks() / Self::BLOCKS_PER_DAY,
            self.max_rotation_blocks() / Self::BLOCKS_PER_DAY,
        )
    }

    /// Get the rotation period in days (midpoint of range)
    pub fn rotation_days(&self) -> u32 {
        self.rotation_blocks() / Self::BLOCKS_PER_DAY
    }

    /// Get the tier name
    pub fn name(&self) -> &'static str {
        match self {
            JumpRiskTier::Low => "Low",
            JumpRiskTier::Medium => "Medium",
            JumpRiskTier::High => "High",
        }
    }

    /// Get the tier description
    pub fn description(&self) -> &'static str {
        match self {
            JumpRiskTier::Low => "Low risk (< 0.1 BTC): 30-60 day rotation",
            JumpRiskTier::Medium => "Medium risk (0.1-1 BTC): 14-30 day rotation",
            JumpRiskTier::High => "High risk (> 1 BTC): 7-14 day rotation",
        }
    }

    /// Generate a random deadline within the tier's block range using CSPRNG
    pub fn random_deadline(&self, creation_height: u32) -> u32 {
        let min_blocks = self.min_rotation_blocks();
        let max_blocks = self.max_rotation_blocks();
        let range = max_blocks - min_blocks;

        let jitter = if range == 0 {
            0
        } else {
            csprng_u32_bounded(range + 1)
        };

        creation_height.saturating_add(min_blocks + jitter)
    }

    /// Calculate next jump deadline from creation height (fixed, uses midpoint)
    ///
    /// For new locks, prefer `random_deadline()` which generates a CSPRNG-randomized
    /// deadline within the tier's range.
    pub fn jump_deadline(&self, creation_height: u32) -> u32 {
        creation_height.saturating_add(self.rotation_blocks())
    }

    /// Check if jump is needed at current height
    pub fn needs_jump(&self, creation_height: u32, current_height: u32) -> bool {
        current_height >= self.jump_deadline(creation_height)
    }

    /// Get blocks until jump is needed
    pub fn blocks_until_jump(&self, creation_height: u32, current_height: u32) -> u32 {
        let deadline = self.jump_deadline(creation_height);
        deadline.saturating_sub(current_height)
    }

    /// Get urgency level (0.0 = just created, 1.0 = needs jump now)
    pub fn urgency(&self, creation_height: u32, current_height: u32) -> f64 {
        let elapsed = current_height.saturating_sub(creation_height) as f64;
        let period = self.rotation_blocks() as f64;
        (elapsed / period).min(1.0)
    }

    /// Get warning threshold (blocks before deadline to start warning)
    pub fn warning_threshold_blocks(&self) -> u32 {
        // Warn at 20% of minimum rotation period
        self.min_rotation_blocks() / 5
    }

    /// Check if we should warn about upcoming jump
    pub fn should_warn(&self, creation_height: u32, current_height: u32) -> bool {
        let remaining = self.blocks_until_jump(creation_height, current_height);
        remaining > 0 && remaining <= self.warning_threshold_blocks()
    }
}

/// Generate a CSPRNG-bounded u32 in [0, bound) using rejection sampling
fn csprng_u32_bounded(bound: u32) -> u32 {
    if bound <= 1 {
        return 0;
    }

    let max_valid = u32::MAX - (u32::MAX % bound);

    loop {
        let mut bytes = [0u8; 4];
        if getrandom::getrandom(&mut bytes).is_err() {
            // Fallback to midpoint on RNG failure (should never happen)
            return bound / 2;
        }
        let value = u32::from_le_bytes(bytes);
        if value < max_valid {
            return value % bound;
        }
    }
}

impl std::fmt::Display for JumpRiskTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// Jump schedule for a lock
///
/// Uses CSPRNG-randomized deadlines within the tier's range to prevent
/// timing fingerprinting. Each lock gets a unique random deadline at creation
/// and after each jump.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JumpSchedule {
    /// Risk tier
    pub tier: JumpRiskTier,
    /// Creation height
    pub creation_height: u32,
    /// Next jump deadline height (randomized within tier range)
    pub deadline_height: u32,
    /// Number of jumps completed
    pub jumps_completed: u32,
}

impl JumpSchedule {
    /// Create a new jump schedule with a randomized deadline
    pub fn new(tier: JumpRiskTier, creation_height: u32) -> Self {
        Self {
            tier,
            creation_height,
            deadline_height: tier.random_deadline(creation_height),
            jumps_completed: 0,
        }
    }

    /// Create from denomination with a randomized deadline
    pub fn from_denomination(denom: Denomination, creation_height: u32) -> Self {
        let tier = JumpRiskTier::from_denomination(denom);
        Self::new(tier, creation_height)
    }

    /// Update schedule after a jump — generates a fresh random deadline
    pub fn after_jump(&self, new_creation_height: u32) -> Self {
        Self {
            tier: self.tier,
            creation_height: new_creation_height,
            deadline_height: self.tier.random_deadline(new_creation_height),
            jumps_completed: self.jumps_completed + 1,
        }
    }

    /// Check if jump is needed at current height
    pub fn needs_jump(&self, current_height: u32) -> bool {
        current_height >= self.deadline_height
    }

    /// Get blocks until jump deadline
    pub fn blocks_until_jump(&self, current_height: u32) -> u32 {
        self.deadline_height.saturating_sub(current_height)
    }

    /// Get urgency level (0.0 = just created, 1.0 = at/past deadline)
    pub fn urgency(&self, current_height: u32) -> f64 {
        let total = self.deadline_height.saturating_sub(self.creation_height) as f64;
        if total <= 0.0 {
            return 1.0;
        }
        let elapsed = current_height.saturating_sub(self.creation_height) as f64;
        (elapsed / total).min(1.0)
    }

    /// Check if warning should be shown (within 20% of remaining time)
    pub fn should_warn(&self, current_height: u32) -> bool {
        let remaining = self.blocks_until_jump(current_height);
        let threshold = self.tier.warning_threshold_blocks();
        remaining > 0 && remaining <= threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_from_sats() {
        assert_eq!(JumpRiskTier::from_sats(5_000_000), JumpRiskTier::Low);
        assert_eq!(JumpRiskTier::from_sats(50_000_000), JumpRiskTier::Medium);
        assert_eq!(JumpRiskTier::from_sats(500_000_000), JumpRiskTier::High);
    }

    #[test]
    fn test_rotation_ranges() {
        // High: 7-14 days
        assert_eq!(JumpRiskTier::High.min_rotation_blocks(), 144 * 7);
        assert_eq!(JumpRiskTier::High.max_rotation_blocks(), 144 * 14);
        // Medium: 14-30 days
        assert_eq!(JumpRiskTier::Medium.min_rotation_blocks(), 144 * 14);
        assert_eq!(JumpRiskTier::Medium.max_rotation_blocks(), 144 * 30);
        // Low: 30-60 days
        assert_eq!(JumpRiskTier::Low.min_rotation_blocks(), 144 * 30);
        assert_eq!(JumpRiskTier::Low.max_rotation_blocks(), 144 * 60);
    }

    #[test]
    fn test_random_deadline_within_range() {
        let creation = 800_000u32;
        for tier in [JumpRiskTier::High, JumpRiskTier::Medium, JumpRiskTier::Low] {
            let min = creation + tier.min_rotation_blocks();
            let max = creation + tier.max_rotation_blocks();
            for _ in 0..100 {
                let deadline = tier.random_deadline(creation);
                assert!(
                    deadline >= min && deadline <= max,
                    "{:?}: deadline {} not in [{}, {}]",
                    tier,
                    deadline,
                    min,
                    max
                );
            }
        }
    }

    #[test]
    fn test_random_deadlines_vary() {
        // Over 50 samples, a CSPRNG should produce at least 2 distinct values
        let creation = 800_000u32;
        let tier = JumpRiskTier::High; // 1008-block range
        let deadlines: std::collections::HashSet<u32> =
            (0..50).map(|_| tier.random_deadline(creation)).collect();
        assert!(
            deadlines.len() > 1,
            "Random deadlines should vary across calls"
        );
    }

    #[test]
    fn test_needs_jump_with_fixed_deadline() {
        // Uses midpoint-based jump_deadline() for backwards compat
        let tier = JumpRiskTier::High; // midpoint = (1008+2016)/2 = 1512
        let creation = 800_000;
        let midpoint = tier.rotation_blocks(); // 1512

        assert!(!tier.needs_jump(creation, creation));
        assert!(!tier.needs_jump(creation, creation + midpoint - 1));
        assert!(tier.needs_jump(creation, creation + midpoint));
        assert!(tier.needs_jump(creation, creation + 3000));
    }

    #[test]
    fn test_schedule_uses_random_deadline() {
        let creation = 800_000u32;
        let schedule = JumpSchedule::from_denomination(Denomination::Large, creation);
        assert_eq!(schedule.tier, JumpRiskTier::High);
        assert_eq!(schedule.jumps_completed, 0);

        // Deadline should be within High tier range
        let min = creation + JumpRiskTier::High.min_rotation_blocks();
        let max = creation + JumpRiskTier::High.max_rotation_blocks();
        assert!(schedule.deadline_height >= min && schedule.deadline_height <= max);
    }

    #[test]
    fn test_schedule_after_jump_regenerates_deadline() {
        let schedule = JumpSchedule::from_denomination(Denomination::Large, 800_000);
        let new_creation = 801_500u32;
        let new_schedule = schedule.after_jump(new_creation);

        assert_eq!(new_schedule.jumps_completed, 1);
        assert_eq!(new_schedule.creation_height, new_creation);

        let min = new_creation + JumpRiskTier::High.min_rotation_blocks();
        let max = new_creation + JumpRiskTier::High.max_rotation_blocks();
        assert!(new_schedule.deadline_height >= min && new_schedule.deadline_height <= max);
    }

    #[test]
    fn test_schedule_needs_jump_uses_stored_deadline() {
        let creation = 800_000u32;
        let schedule = JumpSchedule::new(JumpRiskTier::High, creation);

        // Not at deadline yet
        assert!(!schedule.needs_jump(creation));
        // At the stored deadline
        assert!(schedule.needs_jump(schedule.deadline_height));
        // Past the stored deadline
        assert!(schedule.needs_jump(schedule.deadline_height + 1));
    }

    #[test]
    fn test_schedule_urgency() {
        let creation = 800_000u32;
        let schedule = JumpSchedule::new(JumpRiskTier::High, creation);

        assert!((schedule.urgency(creation) - 0.0).abs() < 0.01);
        assert!((schedule.urgency(schedule.deadline_height) - 1.0).abs() < 0.01);

        // Midpoint
        let mid = creation + (schedule.deadline_height - creation) / 2;
        assert!((schedule.urgency(mid) - 0.5).abs() < 0.05);
    }

    #[test]
    fn test_csprng_u32_bounded() {
        // Edge cases
        assert_eq!(csprng_u32_bounded(0), 0);
        assert_eq!(csprng_u32_bounded(1), 0);

        // All values should be < bound
        for _ in 0..100 {
            let val = csprng_u32_bounded(10);
            assert!(val < 10, "csprng_u32_bounded(10) returned {}", val);
        }
    }
}
