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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JumpRiskTier {
    /// Low risk: < 0.1 BTC, rotate every 30 days
    Low,
    /// Medium risk: 0.1 - 1 BTC, rotate every 14 days
    Medium,
    /// High risk: > 1 BTC, rotate every 7 days
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

    /// Get the rotation period in blocks
    pub fn rotation_blocks(&self) -> u32 {
        match self {
            JumpRiskTier::Low => Self::BLOCKS_PER_DAY * 30, // 30 days
            JumpRiskTier::Medium => Self::BLOCKS_PER_DAY * 14, // 14 days
            JumpRiskTier::High => Self::BLOCKS_PER_DAY * 7, // 7 days
        }
    }

    /// Get the rotation period in days
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
            JumpRiskTier::Low => "Low risk (< 0.1 BTC): 30-day rotation",
            JumpRiskTier::Medium => "Medium risk (0.1-1 BTC): 14-day rotation",
            JumpRiskTier::High => "High risk (> 1 BTC): 7-day rotation",
        }
    }

    /// Calculate next jump deadline from creation height
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
        // Warn at 20% of remaining time
        self.rotation_blocks() / 5
    }

    /// Check if we should warn about upcoming jump
    pub fn should_warn(&self, creation_height: u32, current_height: u32) -> bool {
        let remaining = self.blocks_until_jump(creation_height, current_height);
        remaining > 0 && remaining <= self.warning_threshold_blocks()
    }
}

impl std::fmt::Display for JumpRiskTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// Jump schedule for a lock
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JumpSchedule {
    /// Risk tier
    pub tier: JumpRiskTier,
    /// Creation height
    pub creation_height: u32,
    /// Next jump deadline height
    pub deadline_height: u32,
    /// Number of jumps completed
    pub jumps_completed: u32,
}

impl JumpSchedule {
    /// Create a new jump schedule
    pub fn new(tier: JumpRiskTier, creation_height: u32) -> Self {
        Self {
            tier,
            creation_height,
            deadline_height: tier.jump_deadline(creation_height),
            jumps_completed: 0,
        }
    }

    /// Create from denomination
    pub fn from_denomination(denom: Denomination, creation_height: u32) -> Self {
        let tier = JumpRiskTier::from_denomination(denom);
        Self::new(tier, creation_height)
    }

    /// Update schedule after a jump
    pub fn after_jump(&self, new_creation_height: u32) -> Self {
        Self {
            tier: self.tier,
            creation_height: new_creation_height,
            deadline_height: self.tier.jump_deadline(new_creation_height),
            jumps_completed: self.jumps_completed + 1,
        }
    }

    /// Check if jump is needed
    pub fn needs_jump(&self, current_height: u32) -> bool {
        self.tier.needs_jump(self.creation_height, current_height)
    }

    /// Get blocks until jump
    pub fn blocks_until_jump(&self, current_height: u32) -> u32 {
        self.tier
            .blocks_until_jump(self.creation_height, current_height)
    }

    /// Get urgency level
    pub fn urgency(&self, current_height: u32) -> f64 {
        self.tier.urgency(self.creation_height, current_height)
    }

    /// Check if warning should be shown
    pub fn should_warn(&self, current_height: u32) -> bool {
        self.tier.should_warn(self.creation_height, current_height)
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
    fn test_rotation_periods() {
        assert_eq!(JumpRiskTier::Low.rotation_days(), 30);
        assert_eq!(JumpRiskTier::Medium.rotation_days(), 14);
        assert_eq!(JumpRiskTier::High.rotation_days(), 7);
    }

    #[test]
    fn test_rotation_blocks() {
        assert_eq!(JumpRiskTier::Low.rotation_blocks(), 144 * 30);
        assert_eq!(JumpRiskTier::Medium.rotation_blocks(), 144 * 14);
        assert_eq!(JumpRiskTier::High.rotation_blocks(), 144 * 7);
    }

    #[test]
    fn test_needs_jump() {
        let tier = JumpRiskTier::High; // 7 days = 1008 blocks
        let creation = 800_000;

        assert!(!tier.needs_jump(creation, creation));
        assert!(!tier.needs_jump(creation, creation + 500));
        assert!(tier.needs_jump(creation, creation + 1008));
        assert!(tier.needs_jump(creation, creation + 2000));
    }

    #[test]
    fn test_urgency() {
        let tier = JumpRiskTier::High;
        let creation = 800_000;

        assert!((tier.urgency(creation, creation) - 0.0).abs() < 0.01);
        assert!((tier.urgency(creation, creation + 504) - 0.5).abs() < 0.01);
        assert!((tier.urgency(creation, creation + 1008) - 1.0).abs() < 0.01);
        assert!((tier.urgency(creation, creation + 2000) - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_jump_schedule() {
        let schedule = JumpSchedule::from_denomination(Denomination::Large, 800_000);

        assert_eq!(schedule.tier, JumpRiskTier::High);
        assert_eq!(schedule.jumps_completed, 0);

        let new_schedule = schedule.after_jump(801_008);
        assert_eq!(new_schedule.jumps_completed, 1);
        assert_eq!(new_schedule.creation_height, 801_008);
    }

    #[test]
    fn test_should_warn() {
        let tier = JumpRiskTier::High;
        let creation = 800_000;
        let warning_start = creation + tier.rotation_blocks() - tier.warning_threshold_blocks();

        assert!(!tier.should_warn(creation, creation));
        assert!(!tier.should_warn(creation, warning_start - 1));
        assert!(tier.should_warn(creation, warning_start));
        assert!(tier.should_warn(creation, warning_start + 50));
        assert!(!tier.should_warn(creation, creation + tier.rotation_blocks()));
        // Past deadline
    }
}
