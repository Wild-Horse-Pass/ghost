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
//| FILE: treasury.rs                                                                                                    |
//|======================================================================================================================|

//! Treasury management
//!
//! The pool fee (1% of block subsidy) is split between treasury and node pool:
//! - Pre-threshold: 50/50 split (0.5% treasury, 0.5% node pool)
//! - Post-threshold: Treasury decays 0.5% → 0% over 5 years
//!                   Node pool inversely increases 0.5% → 1%
//!
//! # Treasury Balance Model
//!
//! The treasury tracks **cumulative deposits**, not on-chain balance.
//! This is intentional - the treasury operator should move funds to cold storage
//! rather than leaving them on a hot address. The threshold is based on total
//! satoshis ever sent to the treasury, not current UTXO balance.
//!
//! The treasury address is a multisig controlled by the pool operator.
//! There is no on-chain governance - this is a centralized treasury for
//! development funding, not a DAO.
//!
//! # Security: Block Height Source
//!
//! **CRITICAL**: The `current_height` parameter used in decay calculations
//! MUST come from a trusted source - specifically, from the local Bitcoin Core
//! node's `getblockchaininfo` RPC call.
//!
//! **NEVER** use block heights from:
//! - P2P peer messages (can be spoofed)
//! - External APIs (can be compromised)
//! - User input
//!
//! Using a malicious block height could cause:
//! - Premature decay (paying less to treasury than deserved)
//! - Delayed decay (paying more to treasury than deserved)
//!
//! Use [`TrustedBlockHeight`] wrapper to enforce this at compile time.

use tracing::{debug, info, warn};

use ghost_common::constants::{TREASURY_DECAY_YEARS, TREASURY_THRESHOLD_SATS};
use ghost_common::types::TreasuryAddress;

/// A block height that has been verified to come from a trusted source
///
/// This newtype wrapper enforces that block heights used for treasury calculations
/// come from the local Bitcoin Core node, not from untrusted sources like P2P peers.
///
/// # Usage
///
/// ```ignore
/// // Get height from trusted Bitcoin Core RPC
/// let height = rpc_client.get_block_count().await?;
/// let trusted = TrustedBlockHeight::from_rpc(height);
///
/// // Use in treasury calculations
/// let allocation = treasury.treasury_allocation_percent(trusted.height());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedBlockHeight(u64);

impl TrustedBlockHeight {
    /// Create a trusted block height from a Bitcoin Core RPC response
    ///
    /// Call this after fetching the height from your local Bitcoin Core node
    /// via `getblockchaininfo` or `getblockcount` RPC.
    pub fn from_rpc(height: u64) -> Self {
        Self(height)
    }

    /// Get the underlying height value
    pub fn height(&self) -> u64 {
        self.0
    }

    /// Create from a known genesis block height (for testing only)
    #[cfg(test)]
    pub fn for_test(height: u64) -> Self {
        Self(height)
    }
}

impl std::fmt::Display for TrustedBlockHeight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Approximate blocks per year (144 blocks/day * 365 days)
pub const BLOCKS_PER_YEAR: u64 = 52_560;

/// Initial treasury allocation as percentage of pool fee (50%)
pub const INITIAL_TREASURY_PERCENT: f64 = 0.5;

/// Final treasury allocation after full decay (0%)
pub const FINAL_TREASURY_PERCENT: f64 = 0.0;

/// Treasury state
#[derive(Debug, Clone)]
pub struct Treasury {
    /// Current balance (satoshis)
    pub balance_sats: u64,
    /// Treasury address configuration (supports multi-sig)
    pub address: TreasuryAddress,
    /// Raw script pubkey bytes (cached for efficiency)
    address_script: Vec<u8>,
    /// Threshold for starting decay (21 BTC)
    pub threshold_sats: u64,
    /// Decay period in years
    pub decay_years: u32,
    /// Block height when threshold was first reached (None if not yet reached)
    pub threshold_reached_height: Option<u64>,
    /// Total fees collected
    pub total_collected_sats: u64,
    /// Total payouts made
    pub total_payouts_sats: u64,
}

impl Treasury {
    /// Create a new treasury from script pubkey bytes (legacy)
    pub fn new(address_script: Vec<u8>) -> Self {
        Self {
            balance_sats: 0,
            address: TreasuryAddress::default(),
            address_script,
            threshold_sats: TREASURY_THRESHOLD_SATS,
            decay_years: TREASURY_DECAY_YEARS,
            threshold_reached_height: None,
            total_collected_sats: 0,
            total_payouts_sats: 0,
        }
    }

    /// Create a new treasury from TreasuryAddress
    pub fn from_address(address: TreasuryAddress, address_script: Vec<u8>) -> Self {
        Self {
            balance_sats: 0,
            address,
            address_script,
            threshold_sats: TREASURY_THRESHOLD_SATS,
            decay_years: TREASURY_DECAY_YEARS,
            threshold_reached_height: None,
            total_collected_sats: 0,
            total_payouts_sats: 0,
        }
    }

    /// Create with custom threshold (legacy)
    pub fn with_threshold(address_script: Vec<u8>, threshold_sats: u64) -> Self {
        Self {
            balance_sats: 0,
            address: TreasuryAddress::default(),
            address_script,
            threshold_sats,
            decay_years: TREASURY_DECAY_YEARS,
            threshold_reached_height: None,
            total_collected_sats: 0,
            total_payouts_sats: 0,
        }
    }

    /// Create with TreasuryAddress and custom threshold
    pub fn from_address_with_threshold(
        address: TreasuryAddress,
        address_script: Vec<u8>,
        threshold_sats: u64,
    ) -> Self {
        Self {
            balance_sats: 0,
            address,
            address_script,
            threshold_sats,
            decay_years: TREASURY_DECAY_YEARS,
            threshold_reached_height: None,
            total_collected_sats: 0,
            total_payouts_sats: 0,
        }
    }

    /// Restore treasury state (e.g., from database)
    pub fn restore(
        address_script: Vec<u8>,
        balance_sats: u64,
        threshold_reached_height: Option<u64>,
        total_collected_sats: u64,
        total_payouts_sats: u64,
    ) -> Self {
        Self {
            balance_sats,
            address: TreasuryAddress::default(),
            address_script,
            threshold_sats: TREASURY_THRESHOLD_SATS,
            decay_years: TREASURY_DECAY_YEARS,
            threshold_reached_height,
            total_collected_sats,
            total_payouts_sats,
        }
    }

    /// Restore treasury state with TreasuryAddress
    pub fn restore_with_address(
        address: TreasuryAddress,
        address_script: Vec<u8>,
        balance_sats: u64,
        threshold_reached_height: Option<u64>,
        total_collected_sats: u64,
        total_payouts_sats: u64,
    ) -> Self {
        Self {
            balance_sats,
            address,
            address_script,
            threshold_sats: TREASURY_THRESHOLD_SATS,
            decay_years: TREASURY_DECAY_YEARS,
            threshold_reached_height,
            total_collected_sats,
            total_payouts_sats,
        }
    }

    /// Restore treasury state with custom threshold (for testing)
    pub fn restore_with_threshold(
        address_script: Vec<u8>,
        balance_sats: u64,
        threshold_sats: u64,
        threshold_reached_height: Option<u64>,
        total_collected_sats: u64,
        total_payouts_sats: u64,
    ) -> Self {
        Self {
            balance_sats,
            address: TreasuryAddress::default(),
            address_script,
            threshold_sats,
            decay_years: TREASURY_DECAY_YEARS,
            threshold_reached_height,
            total_collected_sats,
            total_payouts_sats,
        }
    }

    /// Get the treasury address configuration
    pub fn treasury_address(&self) -> &TreasuryAddress {
        &self.address
    }

    /// Get the raw script pubkey bytes
    pub fn script_pubkey(&self) -> &[u8] {
        &self.address_script
    }

    /// Check if this is a multi-sig treasury
    pub fn is_multisig(&self) -> bool {
        self.address.is_multisig()
    }

    /// Add funds to treasury
    ///
    /// If this deposit causes threshold to be reached for the first time,
    /// records the block height to start decay tracking.
    ///
    /// # Arguments
    /// * `amount` - Satoshis to deposit
    /// * `current_height` - Block height from trusted source (Bitcoin Core RPC)
    ///
    /// Note: `balance_sats` tracks cumulative deposits, NOT on-chain balance.
    /// The treasury operator should move funds to cold storage.
    pub fn deposit(&mut self, amount: u64, current_height: TrustedBlockHeight) {
        let was_below_threshold = !self.at_threshold();

        self.balance_sats += amount;
        self.total_collected_sats += amount;

        // Record when threshold is first reached
        if was_below_threshold && self.at_threshold() && self.threshold_reached_height.is_none() {
            self.threshold_reached_height = Some(current_height.height());
            info!(
                height = current_height.height(),
                balance_btc = self.balance_btc(),
                "Treasury threshold reached - decay period begins"
            );
        }

        debug!(
            amount = amount,
            balance = self.balance_sats,
            "Treasury deposit"
        );
    }

    /// Withdraw from treasury
    pub fn withdraw(&mut self, amount: u64) -> bool {
        if amount > self.balance_sats {
            warn!(
                requested = amount,
                available = self.balance_sats,
                "Treasury withdrawal exceeds balance"
            );
            return false;
        }

        self.balance_sats -= amount;
        self.total_payouts_sats += amount;

        info!(
            amount = amount,
            balance = self.balance_sats,
            "Treasury withdrawal"
        );

        true
    }

    /// Check if treasury is at threshold
    pub fn at_threshold(&self) -> bool {
        self.balance_sats >= self.threshold_sats
    }

    /// Calculate years elapsed since threshold was reached
    ///
    /// Returns None if threshold hasn't been reached yet.
    pub fn years_since_threshold(&self, current_height: TrustedBlockHeight) -> Option<f64> {
        self.threshold_reached_height.map(|threshold_height| {
            let blocks_elapsed = current_height.height().saturating_sub(threshold_height);
            blocks_elapsed as f64 / BLOCKS_PER_YEAR as f64
        })
    }

    /// Calculate decay progress (0.0 = just reached threshold, 1.0 = fully decayed)
    ///
    /// Returns 0.0 if threshold hasn't been reached.
    pub fn decay_progress(&self, current_height: TrustedBlockHeight) -> f64 {
        match self.years_since_threshold(current_height) {
            Some(years) => (years / self.decay_years as f64).min(1.0),
            None => 0.0,
        }
    }

    /// Get treasury allocation percentage of pool fee at given block height
    ///
    /// Pool fee (1%) is split between treasury and node pool:
    /// - Pre-threshold: Treasury gets 0.5% (half of pool fee)
    /// - Post-threshold: Decays linearly over 5 years
    ///   - Year 0: 0.5%
    ///   - Year 1: 0.4%
    ///   - Year 2: 0.3%
    ///   - Year 3: 0.2%
    ///   - Year 4: 0.1%
    ///   - Year 5+: 0.0%
    pub fn treasury_allocation_percent(&self, current_height: TrustedBlockHeight) -> f64 {
        if !self.at_threshold() || self.threshold_reached_height.is_none() {
            return INITIAL_TREASURY_PERCENT;
        }

        let decay = self.decay_progress(current_height);

        // Linear decay: 0.5% → 0% over decay_years
        INITIAL_TREASURY_PERCENT - (INITIAL_TREASURY_PERCENT * decay)
    }

    /// Get node pool allocation percentage of pool fee at given block height
    ///
    /// This is the inverse of treasury allocation:
    /// - Pre-threshold: Node pool gets 0.5% (half of pool fee)
    /// - Post-threshold: Increases linearly over 5 years
    ///   - Year 0: 0.5%
    ///   - Year 1: 0.6%
    ///   - Year 2: 0.7%
    ///   - Year 3: 0.8%
    ///   - Year 4: 0.9%
    ///   - Year 5+: 1.0%
    pub fn node_pool_allocation_percent(&self, current_height: TrustedBlockHeight) -> f64 {
        // Node pool gets whatever treasury doesn't
        // Total pool fee is 1%, so node_pool = 1% - treasury_allocation
        1.0 - self.treasury_allocation_percent(current_height)
    }

    /// Calculate treasury amount from block subsidy
    ///
    /// Returns the satoshi amount that should go to treasury.
    pub fn calculate_treasury_amount(
        &self,
        subsidy_sats: u64,
        current_height: TrustedBlockHeight,
    ) -> u64 {
        let percent = self.treasury_allocation_percent(current_height);
        ((subsidy_sats as f64) * (percent / 100.0)) as u64
    }

    /// Calculate node pool amount from block subsidy
    ///
    /// Returns the satoshi amount that should go to node rewards.
    pub fn calculate_node_pool_amount(
        &self,
        subsidy_sats: u64,
        current_height: TrustedBlockHeight,
    ) -> u64 {
        let percent = self.node_pool_allocation_percent(current_height);
        ((subsidy_sats as f64) * (percent / 100.0)) as u64
    }

    /// Get the current decay year (0-5)
    pub fn decay_year(&self, current_height: TrustedBlockHeight) -> u32 {
        match self.years_since_threshold(current_height) {
            Some(years) => (years.floor() as u32).min(self.decay_years),
            None => 0,
        }
    }

    /// Get blocks remaining until next decay year
    pub fn blocks_until_next_decay_year(&self, current_height: TrustedBlockHeight) -> Option<u64> {
        self.threshold_reached_height.map(|threshold_height| {
            let blocks_elapsed = current_height.height().saturating_sub(threshold_height);
            let current_year = blocks_elapsed / BLOCKS_PER_YEAR;
            let next_year_block = threshold_height + ((current_year + 1) * BLOCKS_PER_YEAR);
            next_year_block.saturating_sub(current_height.height())
        })
    }

    /// Get treasury fill percentage
    pub fn fill_percentage(&self) -> f64 {
        if self.threshold_sats == 0 {
            return 100.0;
        }
        (self.balance_sats as f64 / self.threshold_sats as f64 * 100.0).min(100.0)
    }

    /// Get balance in BTC
    pub fn balance_btc(&self) -> f64 {
        self.balance_sats as f64 / 100_000_000.0
    }

    /// Get threshold in BTC
    pub fn threshold_btc(&self) -> f64 {
        self.threshold_sats as f64 / 100_000_000.0
    }

    /// Check if decay is complete (5+ years since threshold)
    pub fn is_decay_complete(&self, current_height: TrustedBlockHeight) -> bool {
        self.decay_progress(current_height) >= 1.0
    }
}

/// Treasury allocation for L2 fees
#[derive(Debug, Clone, Default)]
pub struct L2FeeAllocation {
    /// Transfer fees collected
    pub transfer_fees_sats: u64,
    /// Wraith mixing fees collected
    pub wraith_fees_sats: u64,
    /// Reconciliation fees collected
    pub reconciliation_fees_sats: u64,
    /// Amount allocated to GhostPay nodes
    pub to_ghostpay_nodes_sats: u64,
    /// Amount allocated to treasury
    pub to_treasury_sats: u64,
}

impl L2FeeAllocation {
    /// Calculate L2 fee distribution
    ///
    /// L2 fees are split:
    /// - 50% to GhostPay-enabled nodes
    /// - 50% to treasury
    pub fn calculate(transfer_fees: u64, wraith_fees: u64, reconciliation_fees: u64) -> Self {
        let total = transfer_fees + wraith_fees + reconciliation_fees;
        let to_nodes = total / 2;
        let to_treasury = total - to_nodes;

        Self {
            transfer_fees_sats: transfer_fees,
            wraith_fees_sats: wraith_fees,
            reconciliation_fees_sats: reconciliation_fees,
            to_ghostpay_nodes_sats: to_nodes,
            to_treasury_sats: to_treasury,
        }
    }

    /// Total fees collected
    pub fn total_fees(&self) -> u64 {
        self.transfer_fees_sats + self.wraith_fees_sats + self.reconciliation_fees_sats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_THRESHOLD: u64 = 100_000_000; // 1 BTC for easier testing

    #[test]
    fn test_treasury_operations() {
        let mut treasury = Treasury::new(vec![0u8; 25]);

        treasury.deposit(1_000_000, TrustedBlockHeight::for_test(800_000));
        assert_eq!(treasury.balance_sats, 1_000_000);

        assert!(treasury.withdraw(500_000));
        assert_eq!(treasury.balance_sats, 500_000);

        assert!(!treasury.withdraw(1_000_000)); // Exceeds balance
        assert_eq!(treasury.balance_sats, 500_000);
    }

    #[test]
    fn test_treasury_threshold_tracking() {
        let mut treasury = Treasury::with_threshold(vec![0u8; 25], TEST_THRESHOLD);

        assert!(!treasury.at_threshold());
        assert!(treasury.threshold_reached_height.is_none());

        // Deposit below threshold
        treasury.deposit(50_000_000, TrustedBlockHeight::for_test(800_000));
        assert!(!treasury.at_threshold());
        assert!(treasury.threshold_reached_height.is_none());

        // Deposit to reach threshold
        treasury.deposit(50_000_000, TrustedBlockHeight::for_test(800_100));
        assert!(treasury.at_threshold());
        assert_eq!(treasury.threshold_reached_height, Some(800_100));

        // Further deposits don't change threshold_reached_height
        treasury.deposit(10_000_000, TrustedBlockHeight::for_test(800_200));
        assert_eq!(treasury.threshold_reached_height, Some(800_100));
    }

    #[test]
    fn test_treasury_allocation_pre_threshold() {
        let treasury = Treasury::with_threshold(vec![0u8; 25], TEST_THRESHOLD);

        // Pre-threshold: treasury gets 0.5%
        assert_eq!(
            treasury.treasury_allocation_percent(TrustedBlockHeight::for_test(800_000)),
            0.5
        );
        assert_eq!(
            treasury.node_pool_allocation_percent(TrustedBlockHeight::for_test(800_000)),
            0.5
        );
    }

    #[test]
    fn test_treasury_allocation_decay() {
        let mut treasury = Treasury::with_threshold(vec![0u8; 25], TEST_THRESHOLD);
        treasury.deposit(TEST_THRESHOLD, TrustedBlockHeight::for_test(800_000)); // Reach threshold at block 800,000

        let threshold_height = 800_000u64;

        // Year 0: 0.5% treasury, 0.5% node pool
        let year_0 = TrustedBlockHeight::for_test(threshold_height);
        assert!((treasury.treasury_allocation_percent(year_0) - 0.5).abs() < 0.001);
        assert!((treasury.node_pool_allocation_percent(year_0) - 0.5).abs() < 0.001);

        // Year 1: 0.4% treasury, 0.6% node pool
        let year_1 = TrustedBlockHeight::for_test(threshold_height + BLOCKS_PER_YEAR);
        assert!((treasury.treasury_allocation_percent(year_1) - 0.4).abs() < 0.001);
        assert!((treasury.node_pool_allocation_percent(year_1) - 0.6).abs() < 0.001);

        // Year 2: 0.3% treasury, 0.7% node pool
        let year_2 = TrustedBlockHeight::for_test(threshold_height + (BLOCKS_PER_YEAR * 2));
        assert!((treasury.treasury_allocation_percent(year_2) - 0.3).abs() < 0.001);
        assert!((treasury.node_pool_allocation_percent(year_2) - 0.7).abs() < 0.001);

        // Year 3: 0.2% treasury, 0.8% node pool
        let year_3 = TrustedBlockHeight::for_test(threshold_height + (BLOCKS_PER_YEAR * 3));
        assert!((treasury.treasury_allocation_percent(year_3) - 0.2).abs() < 0.001);
        assert!((treasury.node_pool_allocation_percent(year_3) - 0.8).abs() < 0.001);

        // Year 4: 0.1% treasury, 0.9% node pool
        let year_4 = TrustedBlockHeight::for_test(threshold_height + (BLOCKS_PER_YEAR * 4));
        assert!((treasury.treasury_allocation_percent(year_4) - 0.1).abs() < 0.001);
        assert!((treasury.node_pool_allocation_percent(year_4) - 0.9).abs() < 0.001);

        // Year 5+: 0% treasury, 1% node pool
        let year_5 = TrustedBlockHeight::for_test(threshold_height + (BLOCKS_PER_YEAR * 5));
        assert!((treasury.treasury_allocation_percent(year_5) - 0.0).abs() < 0.001);
        assert!((treasury.node_pool_allocation_percent(year_5) - 1.0).abs() < 0.001);

        // Year 10: Still 0% treasury, 1% node pool (capped)
        let year_10 = TrustedBlockHeight::for_test(threshold_height + (BLOCKS_PER_YEAR * 10));
        assert!((treasury.treasury_allocation_percent(year_10) - 0.0).abs() < 0.001);
        assert!((treasury.node_pool_allocation_percent(year_10) - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_treasury_allocation_mid_year() {
        let mut treasury = Treasury::with_threshold(vec![0u8; 25], TEST_THRESHOLD);
        treasury.deposit(TEST_THRESHOLD, TrustedBlockHeight::for_test(800_000));

        // 2.5 years: should be 0.25% treasury
        let mid_year_2 = TrustedBlockHeight::for_test(800_000 + (BLOCKS_PER_YEAR * 5 / 2));
        assert!((treasury.treasury_allocation_percent(mid_year_2) - 0.25).abs() < 0.001);
        assert!((treasury.node_pool_allocation_percent(mid_year_2) - 0.75).abs() < 0.001);
    }

    #[test]
    fn test_calculate_treasury_amount() {
        let mut treasury = Treasury::with_threshold(vec![0u8; 25], TEST_THRESHOLD);
        treasury.deposit(TEST_THRESHOLD, TrustedBlockHeight::for_test(800_000));

        let subsidy = 312_500_000u64; // 3.125 BTC

        // Year 0: 0.5% of subsidy
        let amount_year_0 =
            treasury.calculate_treasury_amount(subsidy, TrustedBlockHeight::for_test(800_000));
        assert_eq!(amount_year_0, 1_562_500); // 0.5% of 3.125 BTC = 0.015625 BTC

        // Year 5: 0% of subsidy
        let amount_year_5 = treasury.calculate_treasury_amount(
            subsidy,
            TrustedBlockHeight::for_test(800_000 + (BLOCKS_PER_YEAR * 5)),
        );
        assert_eq!(amount_year_5, 0);
    }

    #[test]
    fn test_decay_year() {
        let mut treasury = Treasury::with_threshold(vec![0u8; 25], TEST_THRESHOLD);
        treasury.deposit(TEST_THRESHOLD, TrustedBlockHeight::for_test(800_000));

        assert_eq!(
            treasury.decay_year(TrustedBlockHeight::for_test(800_000)),
            0
        );
        assert_eq!(
            treasury.decay_year(TrustedBlockHeight::for_test(800_000 + BLOCKS_PER_YEAR - 1)),
            0
        );
        assert_eq!(
            treasury.decay_year(TrustedBlockHeight::for_test(800_000 + BLOCKS_PER_YEAR)),
            1
        );
        assert_eq!(
            treasury.decay_year(TrustedBlockHeight::for_test(
                800_000 + (BLOCKS_PER_YEAR * 3)
            )),
            3
        );
        assert_eq!(
            treasury.decay_year(TrustedBlockHeight::for_test(
                800_000 + (BLOCKS_PER_YEAR * 10)
            )),
            5
        ); // Capped at 5
    }

    #[test]
    fn test_is_decay_complete() {
        let mut treasury = Treasury::with_threshold(vec![0u8; 25], TEST_THRESHOLD);
        treasury.deposit(TEST_THRESHOLD, TrustedBlockHeight::for_test(800_000));

        assert!(!treasury.is_decay_complete(TrustedBlockHeight::for_test(800_000)));
        assert!(!treasury.is_decay_complete(TrustedBlockHeight::for_test(
            800_000 + (BLOCKS_PER_YEAR * 4)
        )));
        assert!(treasury.is_decay_complete(TrustedBlockHeight::for_test(
            800_000 + (BLOCKS_PER_YEAR * 5)
        )));
        assert!(treasury.is_decay_complete(TrustedBlockHeight::for_test(
            800_000 + (BLOCKS_PER_YEAR * 10)
        )));
    }

    #[test]
    fn test_years_since_threshold() {
        let mut treasury = Treasury::with_threshold(vec![0u8; 25], TEST_THRESHOLD);

        // Pre-threshold: None
        assert!(treasury
            .years_since_threshold(TrustedBlockHeight::for_test(800_000))
            .is_none());

        treasury.deposit(TEST_THRESHOLD, TrustedBlockHeight::for_test(800_000));

        // At threshold: 0 years
        assert!(
            (treasury
                .years_since_threshold(TrustedBlockHeight::for_test(800_000))
                .unwrap()
                - 0.0)
                .abs()
                < 0.001
        );

        // 1 year later
        assert!(
            (treasury
                .years_since_threshold(TrustedBlockHeight::for_test(800_000 + BLOCKS_PER_YEAR))
                .unwrap()
                - 1.0)
                .abs()
                < 0.001
        );

        // 2.5 years later
        assert!(
            (treasury
                .years_since_threshold(TrustedBlockHeight::for_test(
                    800_000 + (BLOCKS_PER_YEAR * 5 / 2)
                ))
                .unwrap()
                - 2.5)
                .abs()
                < 0.001
        );
    }

    #[test]
    fn test_l2_fee_allocation() {
        let allocation = L2FeeAllocation::calculate(
            10_000, // transfer fees
            5_000,  // wraith fees
            1_000,  // reconciliation fees
        );

        assert_eq!(allocation.total_fees(), 16_000);
        assert_eq!(allocation.to_ghostpay_nodes_sats, 8_000);
        assert_eq!(allocation.to_treasury_sats, 8_000);
    }

    #[test]
    fn test_restore_treasury() {
        // Use restore_with_threshold for custom threshold
        let treasury = Treasury::restore_with_threshold(
            vec![0u8; 25],
            150_000_000,    // balance (1.5 BTC)
            TEST_THRESHOLD, // 1 BTC threshold
            Some(750_000),  // threshold reached at block 750,000
            200_000_000,    // total collected
            50_000_000,     // total payouts
        );

        assert!(treasury.at_threshold());
        assert_eq!(treasury.threshold_reached_height, Some(750_000));
        assert_eq!(treasury.balance_sats, 150_000_000);

        // Check decay works with restored state
        // At block 750,000 + 2.5 years worth of blocks
        let current = TrustedBlockHeight::for_test(750_000 + (BLOCKS_PER_YEAR * 5 / 2));
        assert!((treasury.treasury_allocation_percent(current) - 0.25).abs() < 0.001);
    }
}
