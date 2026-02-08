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

/// Total pool fee in basis points (100 bps = 1% of subsidy)
/// SECURITY: Use the canonical constant from ghost-common to avoid inconsistency.
/// This must match ghost_common::constants::POOL_FEE_BASIS_POINTS.
pub const POOL_FEE_BASIS_POINTS: u64 = ghost_common::constants::POOL_FEE_BASIS_POINTS;

/// Decay rates by year: (treasury_rate, node_rate) as fractions of the 1% pool fee
/// DEPRECATED: Use DECAY_SCHEDULE_BPS for integer arithmetic
const DECAY_SCHEDULE: [(f64, f64); 6] = [
    (0.5, 0.5), // Pre-threshold / Year 0
    (0.4, 0.6), // Year 1
    (0.3, 0.7), // Year 2
    (0.2, 0.8), // Year 3
    (0.1, 0.9), // Year 4
    (0.0, 1.0), // Year 5+
];

/// Decay rates by year in basis points: (treasury_bps, node_bps) as fractions of pool fee
/// SECURITY: Use integer arithmetic to avoid floating point rounding errors.
/// 5000 bps = 50% of the pool fee, 10000 bps = 100% of the pool fee
const DECAY_SCHEDULE_BPS: [(u64, u64); 6] = [
    (5000, 5000), // Pre-threshold / Year 0: 50/50
    (4000, 6000), // Year 1: 40/60
    (3000, 7000), // Year 2: 30/70
    (2000, 8000), // Year 3: 20/80
    (1000, 9000), // Year 4: 10/90
    (0, 10000),   // Year 5+: 0/100
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
    ///
    /// M-5 SECURITY: Takes a reference timestamp instead of using Utc::now().
    /// This ensures all nodes calculate the same decay year for a given block,
    /// eliminating TOCTOU (time-of-check to time-of-use) vulnerabilities where
    /// nodes might calculate different decay years due to clock drift or
    /// processing time differences.
    ///
    /// # Arguments
    /// * `reference_time` - The block timestamp to use for calculation. All nodes
    ///   use the same block timestamp, ensuring deterministic decay calculation.
    pub fn years_since_threshold(&self, reference_time: DateTime<Utc>) -> u32 {
        match self.threshold_reached_at {
            None => 0,
            Some(threshold_time) => {
                let elapsed = reference_time.signed_duration_since(threshold_time);
                let days = elapsed.num_days().max(0) as u32;
                // L-2 DOCUMENTATION: Using 365-day years as intentional approximation.
                // This is acceptable because:
                // 1. Decay schedule granularity is yearly - a few days difference has no impact
                // 2. Leap years would only shift transitions by ~1 day per 4 years
                // 3. Determinism across nodes is ensured by using the same calculation
                // 4. The decay schedule spans 5 years, so cumulative drift is <2 days
                // Using chrono's precise calendar math would add complexity without benefit.
                days / 365
            }
        }
    }

    /// Get current fee split rates (treasury_rate, node_rate)
    /// Both rates are fractions of the 1% pool fee
    /// DEPRECATED: Use get_fee_split_bps for integer arithmetic
    ///
    /// M-5 SECURITY: Takes a reference timestamp for deterministic calculation.
    /// CRIT-PANIC-5: Use saturating arithmetic and .get() for safe array access.
    pub fn get_fee_split(&self, reference_time: DateTime<Utc>) -> (f64, f64) {
        // Pre-threshold: return first entry (50/50 split)
        // Use .get() with fallback to handle potential array access issues
        let pre_threshold = *DECAY_SCHEDULE.first().unwrap_or(&(0.5, 0.5));
        if self.threshold_reached_at.is_none() {
            return pre_threshold;
        }

        let years = self.years_since_threshold(reference_time) as usize;
        // Use saturating_add to prevent overflow, then bound to array length
        let index = years
            .saturating_add(1)
            .min(DECAY_SCHEDULE.len().saturating_sub(1));
        // Use .get() with fallback to last valid entry (0% treasury, 100% nodes)
        *DECAY_SCHEDULE.get(index).unwrap_or(&(0.0, 1.0))
    }

    /// Get current fee split rates in basis points (treasury_bps, node_bps)
    /// SECURITY: Use basis points to avoid floating point rounding errors.
    /// Returns (treasury_bps, node_bps) where each is a fraction of the pool fee.
    /// Example: (5000, 5000) means 50% to treasury, 50% to nodes
    ///
    /// M-5 SECURITY: Takes a reference timestamp for deterministic calculation.
    /// CRIT-PANIC-5: Use saturating arithmetic and .get() for safe array access.
    pub fn get_fee_split_bps(&self, reference_time: DateTime<Utc>) -> (u64, u64) {
        // Pre-threshold: return first entry (50/50 split in bps)
        let pre_threshold = *DECAY_SCHEDULE_BPS.first().unwrap_or(&(5000, 5000));
        if self.threshold_reached_at.is_none() {
            return pre_threshold;
        }

        let years = self.years_since_threshold(reference_time) as usize;
        // Use saturating_add to prevent overflow, then bound to array length
        let index = years
            .saturating_add(1)
            .min(DECAY_SCHEDULE_BPS.len().saturating_sub(1));
        // Use .get() with fallback to last valid entry (0% treasury, 100% nodes)
        *DECAY_SCHEDULE_BPS.get(index).unwrap_or(&(0, 10000))
    }

    /// Get the current decay year (0 = pre-threshold, 1-5 = decay years)
    ///
    /// M-5 SECURITY: Takes a reference timestamp for deterministic calculation.
    pub fn decay_year(&self, reference_time: DateTime<Utc>) -> u32 {
        if self.threshold_reached_at.is_none() {
            0
        } else {
            (self.years_since_threshold(reference_time) + 1).min(5)
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
    /// All nodes use the same block timestamp, preventing TOCTOU vulnerabilities.
    pub fn calculate(
        subsidy_sats: u64,
        tx_fees_sats: u64,
        treasury_state: &TreasuryState,
        block_timestamp: DateTime<Utc>,
    ) -> Self {
        // TX fees go 100% to block finder
        let tx_fees_to_block_finder = tx_fees_sats;

        // Pool fee is 1% of subsidy only (not TX fees)
        // SECURITY: Use integer arithmetic with basis points to avoid float rounding errors
        let pool_fee = subsidy_sats * POOL_FEE_BASIS_POINTS / 10000;

        // Split pool fee between treasury and nodes based on decay schedule
        // SECURITY: Use integer arithmetic with explicit remainder handling
        // The remainder from truncation goes to the node_reward_pool (benefits nodes)
        // M-5: Use block_timestamp for deterministic calculation across all nodes
        let (treasury_rate_bps, node_rate_bps) = treasury_state.get_fee_split_bps(block_timestamp);
        let treasury_amount = (pool_fee as u128 * treasury_rate_bps as u128 / 10000) as u64;
        // SECURITY: Explicit remainder handling - node pool gets everything not going to treasury
        // This ensures treasury_amount + node_reward_pool == pool_fee exactly
        let node_reward_pool = pool_fee.saturating_sub(treasury_amount);

        // Miner pool is 99% of subsidy (subsidy minus pool fee)
        let miner_pool = subsidy_sats.saturating_sub(pool_fee);

        // Convert bps to f64 for backward compatibility with logging
        let treasury_rate = treasury_rate_bps as f64 / 10000.0;
        let node_rate = node_rate_bps as f64 / 10000.0;

        // SECURITY: Debug assertion to verify no satoshis are lost
        debug_assert_eq!(
            treasury_amount + node_reward_pool,
            pool_fee,
            "Treasury split must equal pool fee"
        );
        debug_assert_eq!(
            miner_pool + pool_fee,
            subsidy_sats,
            "Miner pool + pool fee must equal subsidy"
        );

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

    /// Verify distribution adds up correctly
    ///
    /// SEC-TREAS-1: Tightened tolerance from ±10 sats to ±1 sat.
    /// Integer arithmetic should be precise - any larger variance indicates a bug.
    pub fn verify(&self, subsidy_sats: u64, tx_fees_sats: u64) -> bool {
        let expected = subsidy_sats + tx_fees_sats;
        let actual = self.total();

        // Exact match is expected - integer arithmetic should be precise
        if actual != expected {
            tracing::warn!(
                expected = expected,
                actual = actual,
                diff = (actual as i128 - expected as i128),
                "Fee distribution mismatch detected"
            );
            // Allow ±1 satoshi only for documented rounding in basis point calculation
            return actual >= expected.saturating_sub(1) && actual <= expected.saturating_add(1);
        }
        true
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
        let (treasury, node) = state.get_fee_split(now);
        assert_eq!(treasury, 0.5);
        assert_eq!(node, 0.5);
        assert_eq!(state.decay_year(now), 0);
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
        let now = Utc::now();
        let dist = FeeDistribution::calculate(
            312_500_000, // 3.125 BTC subsidy
            10_000_000,  // 0.1 BTC fees
            &state,
            now,
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
        let now = Utc::now();
        let dist = FeeDistribution::calculate(
            312_500_000, // 3.125 BTC subsidy
            0,           // No TX fees
            &state,
            now,
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
        let now = Utc::now();
        let threshold_time = now - chrono::Duration::days(365 * 6); // 6 years ago
        let state = TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));

        let (treasury, node) = state.get_fee_split(now);
        assert_eq!(treasury, 0.0);
        assert_eq!(node, 1.0);

        let dist = FeeDistribution::calculate(312_500_000, 10_000_000, &state, now);

        // Treasury gets nothing
        assert_eq!(dist.treasury_amount, 0);

        // Node pool gets full 1% = 3,125,000
        assert_eq!(dist.node_reward_pool, 3_125_000);
    }

    #[test]
    fn test_year_3_decay() {
        // Simulate year 3 after threshold (2-3 years)
        let now = Utc::now();
        let threshold_time = now - chrono::Duration::days(365 * 2 + 100); // ~2.3 years ago
        let state = TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));

        let (treasury, node) = state.get_fee_split(now);
        assert_eq!(treasury, 0.2);
        assert_eq!(node, 0.8);

        let dist = FeeDistribution::calculate(312_500_000, 10_000_000, &state, now);

        // Pool fee is 3,125,000
        // Treasury gets 0.2 * 3,125,000 = 625,000
        assert_eq!(dist.treasury_amount, 625_000);

        // Node pool gets 0.8 * 3,125,000 = 2,500,000
        assert_eq!(dist.node_reward_pool, 2_500_000);
    }

    #[test]
    fn test_pool_fee_basis_points_matches_common() {
        // SECURITY TEST: Verify our local constant matches ghost-common
        assert_eq!(
            POOL_FEE_BASIS_POINTS,
            ghost_common::constants::POOL_FEE_BASIS_POINTS
        );
        assert_eq!(POOL_FEE_BASIS_POINTS, 100); // 1% = 100 bps
    }

    #[test]
    fn test_integer_arithmetic_no_rounding_error() {
        // SECURITY TEST: Verify integer arithmetic produces exact results
        let state = TreasuryState::new();
        let now = Utc::now();

        // Test with various subsidy values to ensure no rounding errors
        let test_subsidies = [
            312_500_000u64, // 3.125 BTC (current)
            625_000_000,    // 6.25 BTC
            156_250_000,    // 1.5625 BTC
            78_125_000,     // 0.78125 BTC
            39_062_500,     // 0.390625 BTC
        ];

        for subsidy in test_subsidies {
            let dist = FeeDistribution::calculate(subsidy, 0, &state, now);

            // Pool fee should be exactly 1% of subsidy
            let expected_pool_fee = subsidy / 100;
            assert_eq!(
                dist.pool_fee, expected_pool_fee,
                "Pool fee incorrect for subsidy {}",
                subsidy
            );

            // Miner pool should be exactly 99% of subsidy
            let expected_miner_pool = subsidy - expected_pool_fee;
            assert_eq!(
                dist.miner_pool, expected_miner_pool,
                "Miner pool incorrect for subsidy {}",
                subsidy
            );

            // Treasury + node pool should equal pool fee
            assert_eq!(
                dist.treasury_amount + dist.node_reward_pool,
                dist.pool_fee,
                "Treasury + node pool doesn't equal pool fee for subsidy {}",
                subsidy
            );

            // Total distribution should equal subsidy (no TX fees in this test)
            assert_eq!(
                dist.treasury_amount + dist.node_reward_pool + dist.miner_pool,
                subsidy,
                "Total distribution doesn't equal subsidy for {}",
                subsidy
            );
        }
    }

    #[test]
    fn test_decay_schedule_bps_matches_f64() {
        // SECURITY TEST: Verify BPS schedule produces same results as f64 schedule
        for (i, (f64_treasury, f64_node)) in DECAY_SCHEDULE.iter().enumerate() {
            let (bps_treasury, bps_node) = DECAY_SCHEDULE_BPS[i];

            // Convert f64 to bps for comparison
            let expected_treasury_bps = (*f64_treasury * 10000.0) as u64;
            let expected_node_bps = (*f64_node * 10000.0) as u64;

            assert_eq!(
                bps_treasury, expected_treasury_bps,
                "Treasury BPS mismatch at index {}",
                i
            );
            assert_eq!(
                bps_node, expected_node_bps,
                "Node BPS mismatch at index {}",
                i
            );

            // Sum should always be 10000 (100%)
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

        // Pre-threshold should return 50/50
        let (treasury_bps, node_bps) = state.get_fee_split_bps(now);
        assert_eq!(treasury_bps, 5000);
        assert_eq!(node_bps, 5000);

        // Test year 5+ (full decay to nodes)
        let threshold_time = now - chrono::Duration::days(365 * 6);
        let decayed_state =
            TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));
        let (treasury_bps, node_bps) = decayed_state.get_fee_split_bps(now);
        assert_eq!(treasury_bps, 0);
        assert_eq!(node_bps, 10000);
    }

    #[test]
    fn test_treasury_rounding_exact_split() {
        // SECURITY TEST: Verify treasury + node pool == pool fee (no satoshis lost)
        let state = TreasuryState::new();
        let now = Utc::now();

        // Test with various subsidy values including ones that could cause rounding issues
        let test_subsidies = [
            312_500_000u64, // 3.125 BTC (current)
            312_500_001,    // +1 sat (odd)
            312_500_003,    // +3 sat (causes 3-way split issue)
            999_999_999,    // Large odd number
            1,              // Minimum
            100,            // Small
        ];

        for subsidy in test_subsidies {
            let dist = FeeDistribution::calculate(subsidy, 0, &state, now);

            // CRITICAL: Treasury + Node pool MUST equal pool fee
            assert_eq!(
                dist.treasury_amount + dist.node_reward_pool,
                dist.pool_fee,
                "Treasury split failed for subsidy {}: {} + {} != {}",
                subsidy,
                dist.treasury_amount,
                dist.node_reward_pool,
                dist.pool_fee
            );

            // CRITICAL: Miner pool + pool fee MUST equal subsidy
            assert_eq!(
                dist.miner_pool + dist.pool_fee,
                subsidy,
                "Total split failed for subsidy {}: {} + {} != {}",
                subsidy,
                dist.miner_pool,
                dist.pool_fee,
                subsidy
            );
        }
    }

    #[test]
    fn test_treasury_rounding_at_decay_years() {
        // Test rounding at each decay year to ensure exact splits
        let subsidy = 312_500_001u64; // Odd number to stress test rounding
        let now = Utc::now();

        // Pre-threshold
        let state0 = TreasuryState::new();
        let dist0 = FeeDistribution::calculate(subsidy, 0, &state0, now);
        assert_eq!(
            dist0.treasury_amount + dist0.node_reward_pool,
            dist0.pool_fee
        );

        // Year 3 (20% treasury, 80% nodes)
        let threshold_time = now - chrono::Duration::days(365 * 2 + 100);
        let state3 = TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));
        let dist3 = FeeDistribution::calculate(subsidy, 0, &state3, now);
        assert_eq!(
            dist3.treasury_amount + dist3.node_reward_pool,
            dist3.pool_fee
        );

        // Year 5+ (0% treasury, 100% nodes)
        let threshold_time = now - chrono::Duration::days(365 * 6);
        let state5 = TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));
        let dist5 = FeeDistribution::calculate(subsidy, 0, &state5, now);
        assert_eq!(
            dist5.treasury_amount + dist5.node_reward_pool,
            dist5.pool_fee
        );
        assert_eq!(dist5.treasury_amount, 0); // Full decay
    }

    #[test]
    fn test_m5_deterministic_decay_calculation() {
        // M-5 SECURITY TEST: Verify that decay calculation is deterministic
        // when using a fixed reference timestamp.
        let threshold_time = Utc::now() - chrono::Duration::days(365 * 2 + 100);
        let state = TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));

        // Use a fixed reference timestamp (simulating a block timestamp)
        let block_timestamp = Utc::now();

        // Calculate 1000 times - should always be the same
        let first_years = state.years_since_threshold(block_timestamp);
        let first_split = state.get_fee_split_bps(block_timestamp);

        for _ in 0..1000 {
            assert_eq!(
                state.years_since_threshold(block_timestamp),
                first_years,
                "years_since_threshold should be deterministic"
            );
            assert_eq!(
                state.get_fee_split_bps(block_timestamp),
                first_split,
                "get_fee_split_bps should be deterministic"
            );
        }
    }

    #[test]
    fn test_m5_different_timestamps_different_results() {
        // M-5: Verify that different block timestamps can produce different results
        // when they cross year boundaries
        let threshold_time = Utc::now() - chrono::Duration::days(365 * 2); // Exactly 2 years ago
        let state = TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));

        // Just before 2 years: should be year 2 (index 2)
        let before_2_years = threshold_time + chrono::Duration::days(364 * 2);
        let years_before = state.years_since_threshold(before_2_years);

        // Just after 2 years: should be year 3 (index 3)
        let after_2_years = threshold_time + chrono::Duration::days(365 * 2 + 1);
        let years_after = state.years_since_threshold(after_2_years);

        assert!(
            years_after > years_before,
            "Crossing year boundary should change the year: {} vs {}",
            years_before,
            years_after
        );
    }
}
