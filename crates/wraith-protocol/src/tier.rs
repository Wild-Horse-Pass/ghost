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
//| FILE: tier.rs                                                                                                        |
//|======================================================================================================================|

//! Participant tiers for Wraith sessions
//!
//! Tiers are designed around Bitcoin L1 transaction constraints:
//! - Maximum transaction size: ~100KB (we target 80KB for safety)
//! - Input cost: ~57.5 vbytes per P2TR input
//! - Output cost: ~43 vbytes per P2TR output
//!
//! With variable input amounts, multiple outputs per participant are needed
//! for denomination mixing to prevent amount correlation attacks.
//!
//! Trade-off: More participants = larger anonymity set, but fewer outputs per user.
//! Tiers are organized by balance range to optimize this trade-off.

use serde::{Deserialize, Serialize};

/// Maximum transaction size budget in vbytes (safe margin under 100KB limit)
pub const MAX_TX_VBYTES: usize = 80_000;

/// vbytes per P2TR input
pub const VBYTES_PER_INPUT: usize = 58; // Rounded up from 57.5

/// vbytes per P2TR output
pub const VBYTES_PER_OUTPUT: usize = 43;

/// Participant tier for Wraith mixing sessions
///
/// Tiers are organized by balance range. Smaller balances get more participants
/// (larger anonymity set) with fewer outputs. Larger balances get more outputs
/// for denomination mixing but fewer participants.
///
/// All tiers are designed to fit within 80KB transaction size limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ParticipantTier {
    /// 0.001-0.01 BTC: 400 participants, 3 outputs each
    Micro,
    /// 0.01-0.1 BTC: 340 participants, 4 outputs each
    Small,
    /// 0.1-1 BTC: 290 participants, 5 outputs each
    #[default]
    Medium,
    /// 1-10 BTC: 250 participants, 6 outputs each
    Standard,
    /// 10-50 BTC: 195 participants, 8 outputs each
    Large,
    /// 50+ BTC: 160 participants, 10 outputs each
    Whale,
}

impl ParticipantTier {
    /// Get the minimum number of participants for this tier
    pub fn min_participants(&self) -> usize {
        match self {
            ParticipantTier::Micro => 400,
            ParticipantTier::Small => 340,
            ParticipantTier::Medium => 290,
            ParticipantTier::Standard => 250,
            ParticipantTier::Large => 195,
            ParticipantTier::Whale => 160,
        }
    }

    /// Get the maximum participants (10% over minimum for flexibility)
    pub fn max_participants(&self) -> usize {
        (self.min_participants() * 11) / 10
    }

    /// Get the number of outputs per participant for this tier
    pub fn outputs_per_participant(&self) -> usize {
        match self {
            ParticipantTier::Micro => 3,
            ParticipantTier::Small => 4,
            ParticipantTier::Medium => 5,
            ParticipantTier::Standard => 6,
            ParticipantTier::Large => 8,
            ParticipantTier::Whale => 10,
        }
    }

    /// Get the balance range for this tier in satoshis (min, max)
    pub fn balance_range_sats(&self) -> (u64, u64) {
        match self {
            ParticipantTier::Micro => (100_000, 1_000_000), // 0.001-0.01 BTC
            ParticipantTier::Small => (1_000_000, 10_000_000), // 0.01-0.1 BTC
            ParticipantTier::Medium => (10_000_000, 100_000_000), // 0.1-1 BTC
            ParticipantTier::Standard => (100_000_000, 1_000_000_000), // 1-10 BTC
            ParticipantTier::Large => (1_000_000_000, 5_000_000_000), // 10-50 BTC
            ParticipantTier::Whale => (5_000_000_000, u64::MAX), // 50+ BTC
        }
    }

    /// Select the appropriate tier based on user's balance
    pub fn for_balance(sats: u64) -> Self {
        match sats {
            0..=999_999 => ParticipantTier::Micro,
            1_000_000..=9_999_999 => ParticipantTier::Small,
            10_000_000..=99_999_999 => ParticipantTier::Medium,
            100_000_000..=999_999_999 => ParticipantTier::Standard,
            1_000_000_000..=4_999_999_999 => ParticipantTier::Large,
            _ => ParticipantTier::Whale,
        }
    }

    /// Get the tier name
    pub fn name(&self) -> &'static str {
        match self {
            ParticipantTier::Micro => "Micro",
            ParticipantTier::Small => "Small",
            ParticipantTier::Medium => "Medium",
            ParticipantTier::Standard => "Standard",
            ParticipantTier::Large => "Large",
            ParticipantTier::Whale => "Whale",
        }
    }

    /// Get the tier description
    pub fn description(&self) -> &'static str {
        match self {
            ParticipantTier::Micro => "Micro balance (0.001-0.01 BTC): 400 participants, 3 outputs",
            ParticipantTier::Small => "Small balance (0.01-0.1 BTC): 340 participants, 4 outputs",
            ParticipantTier::Medium => "Medium balance (0.1-1 BTC): 290 participants, 5 outputs",
            ParticipantTier::Standard => "Standard balance (1-10 BTC): 250 participants, 6 outputs",
            ParticipantTier::Large => "Large balance (10-50 BTC): 195 participants, 8 outputs",
            ParticipantTier::Whale => "Whale balance (50+ BTC): 160 participants, 10 outputs",
        }
    }

    /// Get the expected wait time in approximate hours
    ///
    /// Wait time depends on how quickly the tier fills up.
    /// Smaller balances are more common, so Micro/Small fill faster.
    pub fn expected_wait_hours(&self) -> u32 {
        match self {
            ParticipantTier::Micro => 2,
            ParticipantTier::Small => 4,
            ParticipantTier::Medium => 8,
            ParticipantTier::Standard => 24,
            ParticipantTier::Large => 48,
            ParticipantTier::Whale => 168, // 1 week
        }
    }

    /// Calculate the estimated transaction size in vbytes
    pub fn estimated_tx_vbytes(&self) -> usize {
        let participants = self.min_participants();
        let outputs = self.outputs_per_participant();
        (participants * VBYTES_PER_INPUT) + (participants * outputs * VBYTES_PER_OUTPUT)
    }

    /// Get all tiers
    pub fn all() -> &'static [ParticipantTier] {
        &[
            ParticipantTier::Micro,
            ParticipantTier::Small,
            ParticipantTier::Medium,
            ParticipantTier::Standard,
            ParticipantTier::Large,
            ParticipantTier::Whale,
        ]
    }

    /// Check if participant count meets minimum
    pub fn meets_minimum(&self, count: usize) -> bool {
        count >= self.min_participants()
    }

    /// Calculate fill percentage
    pub fn fill_percentage(&self, count: usize) -> f64 {
        (count as f64 / self.min_participants() as f64 * 100.0).min(100.0)
    }

    /// Validate that this tier's transaction fits within size limits
    pub fn validate_tx_size(&self) -> bool {
        self.estimated_tx_vbytes() <= MAX_TX_VBYTES
    }
}

impl std::fmt::Display for ParticipantTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_min_participants() {
        assert_eq!(ParticipantTier::Micro.min_participants(), 400);
        assert_eq!(ParticipantTier::Small.min_participants(), 340);
        assert_eq!(ParticipantTier::Medium.min_participants(), 290);
        assert_eq!(ParticipantTier::Standard.min_participants(), 250);
        assert_eq!(ParticipantTier::Large.min_participants(), 195);
        assert_eq!(ParticipantTier::Whale.min_participants(), 160);
    }

    #[test]
    fn test_outputs_per_participant() {
        assert_eq!(ParticipantTier::Micro.outputs_per_participant(), 3);
        assert_eq!(ParticipantTier::Small.outputs_per_participant(), 4);
        assert_eq!(ParticipantTier::Medium.outputs_per_participant(), 5);
        assert_eq!(ParticipantTier::Standard.outputs_per_participant(), 6);
        assert_eq!(ParticipantTier::Large.outputs_per_participant(), 8);
        assert_eq!(ParticipantTier::Whale.outputs_per_participant(), 10);
    }

    #[test]
    fn test_all_tiers_fit_in_80kb() {
        for tier in ParticipantTier::all() {
            let vbytes = tier.estimated_tx_vbytes();
            assert!(
                vbytes <= MAX_TX_VBYTES,
                "Tier {:?} exceeds 80KB: {} vbytes",
                tier,
                vbytes
            );
        }
    }

    #[test]
    fn test_tier_tx_sizes() {
        // Verify all tiers fit within 80KB budget (MAX_TX_VBYTES)
        for tier in ParticipantTier::all() {
            let size = tier.estimated_tx_vbytes();
            assert!(
                size <= MAX_TX_VBYTES,
                "{:?} tx size {} exceeds max {}",
                tier,
                size,
                MAX_TX_VBYTES
            );
        }

        // Verify specific sizes match design calculations:
        // Micro: 400 * 58 + 400 * 3 * 43 = 74,800
        // Small: 340 * 58 + 340 * 4 * 43 = 78,200
        // Medium: 290 * 58 + 290 * 5 * 43 = 79,170
        // Standard: 250 * 58 + 250 * 6 * 43 = 79,000
        // Large: 195 * 58 + 195 * 8 * 43 = 78,390
        // Whale: 160 * 58 + 160 * 10 * 43 = 78,080
        assert_eq!(ParticipantTier::Micro.estimated_tx_vbytes(), 74_800);
        assert_eq!(ParticipantTier::Small.estimated_tx_vbytes(), 78_200);
        assert_eq!(ParticipantTier::Medium.estimated_tx_vbytes(), 79_170);
        assert_eq!(ParticipantTier::Standard.estimated_tx_vbytes(), 79_000);
        assert_eq!(ParticipantTier::Large.estimated_tx_vbytes(), 78_390);
        assert_eq!(ParticipantTier::Whale.estimated_tx_vbytes(), 78_080);
    }

    #[test]
    fn test_tier_selection_by_balance() {
        // Micro: 0.001-0.01 BTC (100k-1M sats)
        assert_eq!(
            ParticipantTier::for_balance(100_000),
            ParticipantTier::Micro
        );
        assert_eq!(
            ParticipantTier::for_balance(500_000),
            ParticipantTier::Micro
        );

        // Small: 0.01-0.1 BTC (1M-10M sats)
        assert_eq!(
            ParticipantTier::for_balance(1_000_000),
            ParticipantTier::Small
        );
        assert_eq!(
            ParticipantTier::for_balance(5_000_000),
            ParticipantTier::Small
        );

        // Medium: 0.1-1 BTC (10M-100M sats)
        assert_eq!(
            ParticipantTier::for_balance(10_000_000),
            ParticipantTier::Medium
        );
        assert_eq!(
            ParticipantTier::for_balance(50_000_000),
            ParticipantTier::Medium
        );

        // Standard: 1-10 BTC (100M-1B sats)
        assert_eq!(
            ParticipantTier::for_balance(100_000_000),
            ParticipantTier::Standard
        );
        assert_eq!(
            ParticipantTier::for_balance(500_000_000),
            ParticipantTier::Standard
        );

        // Large: 10-50 BTC (1B-5B sats)
        assert_eq!(
            ParticipantTier::for_balance(1_000_000_000),
            ParticipantTier::Large
        );
        assert_eq!(
            ParticipantTier::for_balance(3_000_000_000),
            ParticipantTier::Large
        );

        // Whale: 50+ BTC (5B+ sats)
        assert_eq!(
            ParticipantTier::for_balance(5_000_000_000),
            ParticipantTier::Whale
        );
        assert_eq!(
            ParticipantTier::for_balance(100_000_000_000),
            ParticipantTier::Whale
        );
    }

    #[test]
    fn test_minimum_anonymity_set() {
        // All tiers must have at least 160 participants (Whale minimum)
        for tier in ParticipantTier::all() {
            assert!(
                tier.min_participants() >= 160,
                "Tier {:?} has fewer than 160 participants",
                tier
            );
        }
    }

    #[test]
    fn test_meets_minimum() {
        assert!(ParticipantTier::Micro.meets_minimum(400));
        assert!(!ParticipantTier::Micro.meets_minimum(399));
        assert!(ParticipantTier::Whale.meets_minimum(160));
        assert!(!ParticipantTier::Whale.meets_minimum(159));
    }

    #[test]
    fn test_fill_percentage() {
        assert!((ParticipantTier::Micro.fill_percentage(200) - 50.0).abs() < 0.1);
        assert!((ParticipantTier::Micro.fill_percentage(400) - 100.0).abs() < 0.1);
        // Capped at 100%
        assert!((ParticipantTier::Micro.fill_percentage(500) - 100.0).abs() < 0.1);
    }

    #[test]
    fn test_max_participants() {
        // 10% over minimum
        assert_eq!(ParticipantTier::Micro.max_participants(), 440);
        assert_eq!(ParticipantTier::Whale.max_participants(), 176);
    }
}
