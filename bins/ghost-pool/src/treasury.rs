//! Treasury decay calculator per ECONOMICS.md
//!
//! Once treasury reaches 21 BTC, allocation decays over 5 years:
//! - Pre-threshold: 0.5% treasury, 0.5% nodes
//! - Year 1: 0.4% treasury, 0.6% nodes
//! - Year 2: 0.3% treasury, 0.7% nodes
//! - Year 3: 0.2% treasury, 0.8% nodes
//! - Year 4: 0.1% treasury, 0.9% nodes
//! - Year 5+: 0.0% treasury, 1.0% nodes

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Treasury threshold in satoshis (21 BTC)
pub const TREASURY_THRESHOLD_SATS: u64 = 21 * 100_000_000;

/// Total pool fee as fraction of subsidy (1%)
pub const POOL_FEE_PERCENT: f64 = 0.01;

/// Decay rates by year: (treasury_rate, node_rate) as fractions of the 1% pool fee
const DECAY_SCHEDULE: [(f64, f64); 6] = [
    (0.5, 0.5), // Pre-threshold / Year 0
    (0.4, 0.6), // Year 1
    (0.3, 0.7), // Year 2
    (0.2, 0.8), // Year 3
    (0.1, 0.9), // Year 4
    (0.0, 1.0), // Year 5+
];

/// Treasury state for decay calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryState {
    /// Current treasury balance in satoshis
    pub balance_sats: u64,
    /// Timestamp when threshold was reached (None if not yet reached)
    pub threshold_reached_at: Option<DateTime<Utc>>,
}

impl Default for TreasuryState {
    fn default() -> Self {
        Self::new()
    }
}

impl TreasuryState {
    pub fn new() -> Self {
        Self {
            balance_sats: 0,
            threshold_reached_at: None,
        }
    }

    /// Create from stored values
    pub fn from_stored(balance_sats: u64, threshold_reached_at: Option<DateTime<Utc>>) -> Self {
        Self {
            balance_sats,
            threshold_reached_at,
        }
    }

    /// Update balance and check threshold
    pub fn add_funds(&mut self, amount: u64) -> bool {
        self.balance_sats = self.balance_sats.saturating_add(amount);

        // Check if we just crossed threshold
        if self.threshold_reached_at.is_none() && self.balance_sats >= TREASURY_THRESHOLD_SATS {
            self.threshold_reached_at = Some(Utc::now());
            tracing::info!(
                balance = self.balance_sats,
                threshold = TREASURY_THRESHOLD_SATS,
                "Treasury threshold reached - decay begins"
            );
            return true; // Threshold just crossed
        }
        false
    }

    /// Check if threshold has been reached
    pub fn threshold_reached(&self) -> bool {
        self.threshold_reached_at.is_some()
    }

    /// Calculate years since threshold was reached
    pub fn years_since_threshold(&self) -> u32 {
        match self.threshold_reached_at {
            None => 0,
            Some(threshold_time) => {
                let elapsed = Utc::now().signed_duration_since(threshold_time);
                let days = elapsed.num_days().max(0) as u32;
                days / 365 // Approximate years
            }
        }
    }

    /// Get current fee split rates (treasury_rate, node_rate)
    /// Both rates are fractions of the 1% pool fee
    pub fn get_fee_split(&self) -> (f64, f64) {
        if self.threshold_reached_at.is_none() {
            return DECAY_SCHEDULE[0]; // Pre-threshold
        }

        let years = self.years_since_threshold() as usize;
        let index = (years + 1).min(DECAY_SCHEDULE.len() - 1);
        DECAY_SCHEDULE[index]
    }

    /// Get the current decay year (0 = pre-threshold, 1-5 = decay years)
    pub fn decay_year(&self) -> u32 {
        if self.threshold_reached_at.is_none() {
            0
        } else {
            (self.years_since_threshold() + 1).min(5)
        }
    }
}

/// Calculate fee distribution for a block
#[derive(Debug, Clone)]
pub struct FeeDistribution {
    /// TX fees go 100% to block finder
    pub tx_fees_to_block_finder: u64,
    /// Treasury allocation (decays over time)
    pub treasury_amount: u64,
    /// Node reward pool (increases as treasury decays)
    pub node_reward_pool: u64,
    /// Miner pool (99% of subsidy)
    pub miner_pool: u64,
    /// Total pool fee (1% of subsidy)
    pub pool_fee: u64,
    /// Treasury rate used (for logging)
    pub treasury_rate: f64,
    /// Node rate used (for logging)
    pub node_rate: f64,
}

impl FeeDistribution {
    /// Calculate fee distribution for a block based on current treasury state
    pub fn calculate(subsidy_sats: u64, tx_fees_sats: u64, treasury_state: &TreasuryState) -> Self {
        // TX fees go 100% to block finder
        let tx_fees_to_block_finder = tx_fees_sats;

        // Pool fee is 1% of subsidy only (not TX fees)
        let pool_fee = (subsidy_sats as f64 * POOL_FEE_PERCENT) as u64;

        // Split pool fee between treasury and nodes based on decay schedule
        let (treasury_rate, node_rate) = treasury_state.get_fee_split();
        let treasury_amount = (pool_fee as f64 * treasury_rate) as u64;
        let node_reward_pool = pool_fee.saturating_sub(treasury_amount);

        // Miner pool is 99% of subsidy (subsidy minus pool fee)
        let miner_pool = subsidy_sats.saturating_sub(pool_fee);

        Self {
            tx_fees_to_block_finder,
            treasury_amount,
            node_reward_pool,
            miner_pool,
            pool_fee,
            treasury_rate,
            node_rate,
        }
    }

    /// Total amount distributed (should equal subsidy + tx_fees)
    pub fn total(&self) -> u64 {
        self.tx_fees_to_block_finder + self.treasury_amount + self.node_reward_pool + self.miner_pool
    }

    /// Verify distribution adds up correctly
    pub fn verify(&self, subsidy_sats: u64, tx_fees_sats: u64) -> bool {
        let expected = subsidy_sats + tx_fees_sats;
        let actual = self.total();
        // Allow for small rounding differences (up to 10 sats)
        actual >= expected.saturating_sub(10) && actual <= expected.saturating_add(10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_treasury_threshold_constant() {
        assert_eq!(TREASURY_THRESHOLD_SATS, 2_100_000_000); // 21 BTC
    }

    #[test]
    fn test_pre_threshold_split() {
        let state = TreasuryState::new();
        let (treasury, node) = state.get_fee_split();
        assert_eq!(treasury, 0.5);
        assert_eq!(node, 0.5);
        assert_eq!(state.decay_year(), 0);
    }

    #[test]
    fn test_threshold_detection() {
        let mut state = TreasuryState::new();

        // Add funds below threshold
        state.add_funds(1_000_000_000); // 10 BTC
        assert!(!state.threshold_reached());

        // Cross threshold
        let crossed = state.add_funds(1_500_000_000); // +15 BTC = 25 BTC total
        assert!(crossed);
        assert!(state.threshold_reached());
        assert!(state.threshold_reached_at.is_some());
    }

    #[test]
    fn test_fee_distribution_pre_threshold() {
        let state = TreasuryState::new();
        let dist = FeeDistribution::calculate(
            312_500_000, // 3.125 BTC subsidy
            10_000_000,  // 0.1 BTC fees
            &state,
        );

        // TX fees go to block finder
        assert_eq!(dist.tx_fees_to_block_finder, 10_000_000);

        // Pool fee is 1% of subsidy = 3,125,000
        assert_eq!(dist.pool_fee, 3_125_000);

        // Treasury gets 0.5% of subsidy = 1,562,500
        assert_eq!(dist.treasury_amount, 1_562_500);

        // Node pool gets 0.5% of subsidy = 1,562,500
        assert_eq!(dist.node_reward_pool, 1_562_500);

        // Miner pool gets 99% of subsidy = 309,375,000
        assert_eq!(dist.miner_pool, 309_375_000);

        // Verify totals
        assert!(dist.verify(312_500_000, 10_000_000));
    }

    #[test]
    fn test_fee_distribution_no_tx_fees() {
        let state = TreasuryState::new();
        let dist = FeeDistribution::calculate(
            312_500_000, // 3.125 BTC subsidy
            0,           // No TX fees
            &state,
        );

        assert_eq!(dist.tx_fees_to_block_finder, 0);
        assert_eq!(dist.treasury_amount, 1_562_500);
        assert_eq!(dist.node_reward_pool, 1_562_500);
        assert_eq!(dist.miner_pool, 309_375_000);
        assert!(dist.verify(312_500_000, 0));
    }

    #[test]
    fn test_decay_schedule_values() {
        // Verify the decay schedule matches ECONOMICS.md
        assert_eq!(DECAY_SCHEDULE[0], (0.5, 0.5)); // Pre-threshold
        assert_eq!(DECAY_SCHEDULE[1], (0.4, 0.6)); // Year 1
        assert_eq!(DECAY_SCHEDULE[2], (0.3, 0.7)); // Year 2
        assert_eq!(DECAY_SCHEDULE[3], (0.2, 0.8)); // Year 3
        assert_eq!(DECAY_SCHEDULE[4], (0.1, 0.9)); // Year 4
        assert_eq!(DECAY_SCHEDULE[5], (0.0, 1.0)); // Year 5+
    }

    #[test]
    fn test_year_5_full_decay() {
        // Simulate year 5+ after threshold
        let threshold_time = Utc::now() - chrono::Duration::days(365 * 6); // 6 years ago
        let state = TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));

        let (treasury, node) = state.get_fee_split();
        assert_eq!(treasury, 0.0);
        assert_eq!(node, 1.0);

        let dist = FeeDistribution::calculate(312_500_000, 10_000_000, &state);

        // Treasury gets nothing
        assert_eq!(dist.treasury_amount, 0);

        // Node pool gets full 1% = 3,125,000
        assert_eq!(dist.node_reward_pool, 3_125_000);
    }

    #[test]
    fn test_year_3_decay() {
        // Simulate year 3 after threshold (2-3 years)
        let threshold_time = Utc::now() - chrono::Duration::days(365 * 2 + 100); // ~2.3 years ago
        let state = TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));

        let (treasury, node) = state.get_fee_split();
        assert_eq!(treasury, 0.2);
        assert_eq!(node, 0.8);

        let dist = FeeDistribution::calculate(312_500_000, 10_000_000, &state);

        // Pool fee is 3,125,000
        // Treasury gets 0.2 * 3,125,000 = 625,000
        assert_eq!(dist.treasury_amount, 625_000);

        // Node pool gets 0.8 * 3,125,000 = 2,500,000
        assert_eq!(dist.node_reward_pool, 2_500_000);
    }
}
