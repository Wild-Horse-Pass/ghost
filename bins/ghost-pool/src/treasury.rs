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

// Re-export shared types from ghost-reconciliation
pub use ghost_reconciliation::fee_distribution::{
    distribute_to_nodes, L2FeeDistribution, TreasuryState, DECAY_SCHEDULE_BPS,
    TREASURY_THRESHOLD_SATS,
};

/// Total pool fee in basis points (100 bps = 1% of subsidy)
/// SECURITY: Use the canonical constant from ghost-common to avoid inconsistency.
pub const POOL_FEE_BASIS_POINTS: u64 = ghost_common::constants::POOL_FEE_BASIS_POINTS;

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
    /// Treasury rate in basis points (for logging)
    pub treasury_rate_bps: u64,
    /// Node rate in basis points (for logging)
    pub node_rate_bps: u64,
    /// Treasury rate used (for logging) - DEPRECATED, use treasury_rate_bps
    pub treasury_rate: f64,
    /// Node rate used (for logging) - DEPRECATED, use node_rate_bps
    pub node_rate: f64,
}

impl FeeDistribution {
    /// Calculate fee distribution for a block based on current treasury state
    ///
    /// SECURITY: Uses integer arithmetic with explicit remainder handling to ensure:
    /// 1. treasury_amount + node_reward_pool == pool_fee (no satoshis lost)
    /// 2. miner_pool + pool_fee == subsidy (no satoshis lost)
    ///
    /// M-5 SECURITY: Takes a block_timestamp to ensure deterministic decay calculation.
    pub fn calculate(
        subsidy_sats: u64,
        tx_fees_sats: u64,
        treasury_state: &TreasuryState,
        block_timestamp: DateTime<Utc>,
    ) -> Self {
        let tx_fees_to_block_finder = tx_fees_sats;

        // Pool fee is 1% of subsidy only (not TX fees)
        let pool_fee = subsidy_sats * POOL_FEE_BASIS_POINTS / 10000;

        // Split pool fee between treasury and nodes based on decay schedule
        let (treasury_rate_bps, node_rate_bps) = treasury_state.get_fee_split_bps(block_timestamp);
        let treasury_amount = (pool_fee as u128 * treasury_rate_bps as u128 / 10000) as u64;
        // Explicit remainder handling - node pool gets everything not going to treasury
        let node_reward_pool = pool_fee.saturating_sub(treasury_amount);

        // Miner pool is 99% of subsidy (subsidy minus pool fee)
        let miner_pool = subsidy_sats.saturating_sub(pool_fee);

        // Convert bps to f64 for backward compatibility with logging
        let treasury_rate = treasury_rate_bps as f64 / 10000.0;
        let node_rate = node_rate_bps as f64 / 10000.0;

        // M-01: Runtime invariant checks
        if treasury_amount + node_reward_pool != pool_fee {
            tracing::error!(
                treasury_amount,
                node_reward_pool,
                pool_fee,
                "M-01 CRITICAL: Treasury split invariant violated"
            );
            return Self {
                tx_fees_to_block_finder,
                treasury_amount: 0,
                node_reward_pool: 0,
                miner_pool: 0,
                pool_fee: 0,
                treasury_rate_bps,
                node_rate_bps,
                treasury_rate,
                node_rate,
            };
        }
        if miner_pool + pool_fee != subsidy_sats {
            tracing::error!(
                miner_pool,
                pool_fee,
                subsidy_sats,
                "M-01 CRITICAL: Miner pool + pool fee invariant violated"
            );
            return Self {
                tx_fees_to_block_finder,
                treasury_amount: 0,
                node_reward_pool: 0,
                miner_pool: 0,
                pool_fee: 0,
                treasury_rate_bps,
                node_rate_bps,
                treasury_rate,
                node_rate,
            };
        }

        Self {
            tx_fees_to_block_finder,
            treasury_amount,
            node_reward_pool,
            miner_pool,
            pool_fee,
            treasury_rate_bps,
            node_rate_bps,
            treasury_rate,
            node_rate,
        }
    }

    /// Total amount distributed (should equal subsidy + tx_fees)
    pub fn total(&self) -> u64 {
        self.tx_fees_to_block_finder
            + self.treasury_amount
            + self.node_reward_pool
            + self.miner_pool
    }

    /// Verify distribution adds up correctly.
    ///
    /// F-3: Exact match required — integer arithmetic is precise, no tolerance needed.
    pub fn verify(&self, subsidy_sats: u64, tx_fees_sats: u64) -> bool {
        let expected = subsidy_sats + tx_fees_sats;
        let actual = self.total();

        if actual != expected {
            tracing::warn!(
                expected = expected,
                actual = actual,
                diff = (actual as i128 - expected as i128),
                "F-3: Fee distribution mismatch — integer arithmetic should be exact"
            );
        }
        actual == expected
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
        let now = Utc::now();
        let (treasury_bps, node_bps) = state.get_fee_split_bps(now);
        assert_eq!(treasury_bps, 5000); // 50%
        assert_eq!(node_bps, 5000); // 50%
        assert_eq!(state.decay_year(now), 0);
    }

    #[test]
    fn test_threshold_detection() {
        let mut state = TreasuryState::new();

        state.add_funds(1_000_000_000); // 10 BTC
        assert!(!state.threshold_reached());

        let crossed = state.add_funds(1_500_000_000); // +15 BTC = 25 BTC total
        assert!(crossed);
        assert!(state.threshold_reached());
        assert!(state.threshold_reached_at.is_some());
    }

    #[test]
    fn test_fee_distribution_pre_threshold() {
        let state = TreasuryState::new();
        let now = Utc::now();
        let dist = FeeDistribution::calculate(312_500_000, 10_000_000, &state, now);

        assert_eq!(dist.tx_fees_to_block_finder, 10_000_000);
        assert_eq!(dist.pool_fee, 3_125_000);
        assert_eq!(dist.treasury_amount, 1_562_500);
        assert_eq!(dist.node_reward_pool, 1_562_500);
        assert_eq!(dist.miner_pool, 309_375_000);
        assert!(dist.verify(312_500_000, 10_000_000));
    }

    #[test]
    fn test_fee_distribution_no_tx_fees() {
        let state = TreasuryState::new();
        let now = Utc::now();
        let dist = FeeDistribution::calculate(312_500_000, 0, &state, now);

        assert_eq!(dist.tx_fees_to_block_finder, 0);
        assert_eq!(dist.treasury_amount, 1_562_500);
        assert_eq!(dist.node_reward_pool, 1_562_500);
        assert_eq!(dist.miner_pool, 309_375_000);
        assert!(dist.verify(312_500_000, 0));
    }

    #[test]
    fn test_decay_schedule_bps_values() {
        assert_eq!(DECAY_SCHEDULE_BPS[0], (5000, 5000));
        assert_eq!(DECAY_SCHEDULE_BPS[1], (4000, 6000));
        assert_eq!(DECAY_SCHEDULE_BPS[2], (3000, 7000));
        assert_eq!(DECAY_SCHEDULE_BPS[3], (2000, 8000));
        assert_eq!(DECAY_SCHEDULE_BPS[4], (1000, 9000));
        assert_eq!(DECAY_SCHEDULE_BPS[5], (0, 10000));
    }

    #[test]
    fn test_year_5_full_decay() {
        let now = Utc::now();
        let threshold_time = now - chrono::Duration::days(365 * 6);
        let state = TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));

        let (treasury_bps, node_bps) = state.get_fee_split_bps(now);
        assert_eq!(treasury_bps, 0);
        assert_eq!(node_bps, 10000);

        let dist = FeeDistribution::calculate(312_500_000, 10_000_000, &state, now);

        assert_eq!(dist.treasury_amount, 0);
        assert_eq!(dist.node_reward_pool, 3_125_000);
    }

    #[test]
    fn test_year_3_decay() {
        let now = Utc::now();
        let threshold_time = now - chrono::Duration::days(365 * 2 + 100);
        let state = TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));

        let (treasury_bps, node_bps) = state.get_fee_split_bps(now);
        assert_eq!(treasury_bps, 2000);
        assert_eq!(node_bps, 8000);

        let dist = FeeDistribution::calculate(312_500_000, 10_000_000, &state, now);

        assert_eq!(dist.treasury_amount, 625_000);
        assert_eq!(dist.node_reward_pool, 2_500_000);
    }

    #[test]
    fn test_pool_fee_basis_points_matches_common() {
        assert_eq!(
            POOL_FEE_BASIS_POINTS,
            ghost_common::constants::POOL_FEE_BASIS_POINTS
        );
        assert_eq!(POOL_FEE_BASIS_POINTS, 100);
    }

    #[test]
    fn test_integer_arithmetic_no_rounding_error() {
        let state = TreasuryState::new();
        let now = Utc::now();

        let test_subsidies = [
            312_500_000u64,
            625_000_000,
            156_250_000,
            78_125_000,
            39_062_500,
        ];

        for subsidy in test_subsidies {
            let dist = FeeDistribution::calculate(subsidy, 0, &state, now);

            let expected_pool_fee = subsidy / 100;
            assert_eq!(dist.pool_fee, expected_pool_fee);

            let expected_miner_pool = subsidy - expected_pool_fee;
            assert_eq!(dist.miner_pool, expected_miner_pool);

            assert_eq!(dist.treasury_amount + dist.node_reward_pool, dist.pool_fee,);

            assert_eq!(
                dist.treasury_amount + dist.node_reward_pool + dist.miner_pool,
                subsidy,
            );
        }
    }

    #[test]
    fn test_decay_schedule_bps_sum_100_percent() {
        for (i, (bps_treasury, bps_node)) in DECAY_SCHEDULE_BPS.iter().enumerate() {
            assert_eq!(
                bps_treasury + bps_node,
                10000,
                "BPS sum not 100% at index {}",
                i
            );
        }
    }

    #[test]
    fn test_get_fee_split_bps() {
        let state = TreasuryState::new();
        let now = Utc::now();

        let (treasury_bps, node_bps) = state.get_fee_split_bps(now);
        assert_eq!(treasury_bps, 5000);
        assert_eq!(node_bps, 5000);

        let threshold_time = now - chrono::Duration::days(365 * 6);
        let decayed_state =
            TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));
        let (treasury_bps, node_bps) = decayed_state.get_fee_split_bps(now);
        assert_eq!(treasury_bps, 0);
        assert_eq!(node_bps, 10000);
    }

    #[test]
    fn test_treasury_rounding_exact_split() {
        let state = TreasuryState::new();
        let now = Utc::now();

        let test_subsidies = [
            312_500_000u64,
            312_500_001,
            312_500_003,
            999_999_999,
            1,
            100,
        ];

        for subsidy in test_subsidies {
            let dist = FeeDistribution::calculate(subsidy, 0, &state, now);

            assert_eq!(dist.treasury_amount + dist.node_reward_pool, dist.pool_fee,);

            assert_eq!(dist.miner_pool + dist.pool_fee, subsidy,);
        }
    }

    #[test]
    fn test_treasury_rounding_at_decay_years() {
        let subsidy = 312_500_001u64;
        let now = Utc::now();

        let state0 = TreasuryState::new();
        let dist0 = FeeDistribution::calculate(subsidy, 0, &state0, now);
        assert_eq!(
            dist0.treasury_amount + dist0.node_reward_pool,
            dist0.pool_fee
        );

        let threshold_time = now - chrono::Duration::days(365 * 2 + 100);
        let state3 = TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));
        let dist3 = FeeDistribution::calculate(subsidy, 0, &state3, now);
        assert_eq!(
            dist3.treasury_amount + dist3.node_reward_pool,
            dist3.pool_fee
        );

        let threshold_time = now - chrono::Duration::days(365 * 6);
        let state5 = TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));
        let dist5 = FeeDistribution::calculate(subsidy, 0, &state5, now);
        assert_eq!(
            dist5.treasury_amount + dist5.node_reward_pool,
            dist5.pool_fee
        );
        assert_eq!(dist5.treasury_amount, 0);
    }

    #[test]
    fn test_m5_deterministic_decay_calculation() {
        let threshold_time = Utc::now() - chrono::Duration::days(365 * 2 + 100);
        let state = TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));

        let block_timestamp = Utc::now();

        let first_years = state.years_since_threshold(block_timestamp);
        let first_split = state.get_fee_split_bps(block_timestamp);

        for _ in 0..1000 {
            assert_eq!(state.years_since_threshold(block_timestamp), first_years);
            assert_eq!(state.get_fee_split_bps(block_timestamp), first_split);
        }
    }

    #[test]
    fn test_m5_different_timestamps_different_results() {
        let threshold_time = Utc::now() - chrono::Duration::days(365 * 2);
        let state = TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));

        let before_2_years = threshold_time + chrono::Duration::days(364 * 2);
        let years_before = state.years_since_threshold(before_2_years);

        let after_2_years = threshold_time + chrono::Duration::days(365 * 2 + 1);
        let years_after = state.years_since_threshold(after_2_years);

        assert!(years_after > years_before);
    }

    // L2 Fee Distribution Tests

    #[test]
    fn test_l2_fee_distribution_pre_threshold() {
        let state = TreasuryState::new();
        let now = Utc::now();
        let nodes = vec![
            ("node1".to_string(), "addr1".to_string(), 4),
            ("node2".to_string(), "addr2".to_string(), 4),
        ];

        let dist = L2FeeDistribution::calculate(1000, &state, now, &nodes);

        assert_eq!(dist.treasury_amount, 500);
        assert_eq!(dist.node_pool, 500);
        assert_eq!(dist.treasury_amount + dist.node_pool, dist.total_fee_pool);
    }

    #[test]
    fn test_l2_fee_distribution_year5() {
        let now = Utc::now();
        let threshold_time = now - chrono::Duration::days(365 * 6);
        let state = TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));
        let nodes = vec![("node1".to_string(), "addr1".to_string(), 4)];

        let dist = L2FeeDistribution::calculate(1000, &state, now, &nodes);

        assert_eq!(dist.treasury_amount, 0);
        assert_eq!(dist.node_pool, 1000);
    }

    #[test]
    fn test_l2_fee_distribution_no_nodes() {
        let state = TreasuryState::new();
        let now = Utc::now();

        let dist = L2FeeDistribution::calculate(1000, &state, now, &[]);

        assert_eq!(dist.treasury_amount, 500);
        assert_eq!(dist.node_pool, 500);
        assert!(dist.node_payouts.is_empty());
    }

    #[test]
    fn test_l2_fee_distribution_dust_redirect() {
        let state = TreasuryState::new();
        let now = Utc::now();
        let nodes = vec![
            ("node1".to_string(), "addr1".to_string(), 100),
            ("node2".to_string(), "addr2".to_string(), 1),
        ];

        let dist = L2FeeDistribution::calculate(1000, &state, now, &nodes);

        assert_eq!(dist.node_payouts.len(), 1);
        assert_eq!(dist.node_payouts[0].0, "node1");
        assert_eq!(dist.node_payouts[0].2, 500);
    }

    #[test]
    fn test_l2_fee_distribution_zero_pool() {
        let state = TreasuryState::new();
        let now = Utc::now();
        let nodes = vec![("node1".to_string(), "addr1".to_string(), 4)];

        let dist = L2FeeDistribution::calculate(0, &state, now, &nodes);

        assert_eq!(dist.treasury_amount, 0);
        assert_eq!(dist.node_pool, 0);
        assert!(dist.node_payouts.is_empty());
    }
}
