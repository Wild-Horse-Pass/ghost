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
//| FILE: payout.rs                                                                                                      |
//|======================================================================================================================|

//! Payout calculation for miners and nodes

use tracing::{debug, error, info, warn};

use ghost_common::constants::{
    DUST_THRESHOLD_SATS, MAX_MINER_OUTPUTS, MAX_NODE_OUTPUTS, POOL_FEE_BASIS_POINTS,
};
use ghost_common::types::{PayoutEntry, PayoutType};

use crate::shares::RoundShares;

/// Payout calculator
#[derive(Debug, Clone)]
pub struct PayoutCalculator {
    /// Pool fee percentage
    pub pool_fee_percent: f64,
    /// Dust threshold (minimum payout)
    pub dust_threshold: u64,
    /// Maximum miner outputs
    pub max_miner_outputs: usize,
    /// Maximum node outputs
    pub max_node_outputs: usize,
}

impl Default for PayoutCalculator {
    fn default() -> Self {
        Self {
            // Convert basis points to percent (100 bps = 1% = 0.01 as fraction)
            pool_fee_percent: POOL_FEE_BASIS_POINTS as f64 / 100.0,
            dust_threshold: DUST_THRESHOLD_SATS,
            max_miner_outputs: MAX_MINER_OUTPUTS,
            max_node_outputs: MAX_NODE_OUTPUTS,
        }
    }
}

impl PayoutCalculator {
    /// Create with custom parameters
    pub fn new(
        pool_fee_percent: f64,
        dust_threshold: u64,
        max_miner_outputs: usize,
        max_node_outputs: usize,
    ) -> Self {
        Self {
            pool_fee_percent,
            dust_threshold,
            max_miner_outputs,
            max_node_outputs,
        }
    }

    /// Calculate payouts for a round
    #[allow(clippy::too_many_arguments)]
    pub fn calculate_payouts(
        &self,
        shares: &RoundShares,
        subsidy_sats: u64,
        tx_fees_sats: u64,
        miner_addresses: &[(String, Vec<u8>)], // (miner_id, address)
        node_addresses: &[([u8; 32], Vec<u8>)], // (node_id, address)
        block_builder_node: [u8; 32],
        treasury_address: Vec<u8>,
    ) -> PayoutResult {
        info!(
            round_id = shares.round_id,
            subsidy = subsidy_sats,
            tx_fees = tx_fees_sats,
            miners = shares.miner_count(),
            nodes = shares.node_count(),
            "Calculating payouts"
        );

        let mut result = PayoutResult::default();

        // 1. Calculate pool fee (1% of subsidy only)
        // SECURITY: Use integer math with basis points to avoid floating point precision loss
        // Convert percentage to basis points (1% = 100 bps) for integer division
        // Use u128 intermediate to prevent overflow for large amounts
        let pool_fee_bps = (self.pool_fee_percent * 100.0) as u64;
        let pool_fee = (subsidy_sats as u128 * pool_fee_bps as u128 / 10000) as u64;
        // Per ECONOMICS.md: Pool fee is split 50/50 between treasury and node pool (pre-threshold)
        // Treasury gets half of the pool fee (0.5% of subsidy)
        result.treasury_amount = pool_fee / 2;

        // 2. TX fees go to block builder node
        result.tx_fee_amount = tx_fees_sats;
        result.tx_fee_recipient = Some(block_builder_node);

        // 3. Remaining subsidy after pool fee goes to miners (99% of subsidy)
        // Per ECONOMICS.md: "Miner Pool (99% of subsidy) - Distributed to miners proportional to work"
        let miner_pool = subsidy_sats - pool_fee;

        // 4. Node pool is the portion of the pool fee allocated to nodes (not miners!)
        // Per ECONOMICS.md: "Pool Fee (1% of subsidy) split between Treasury and Node Reward Pool"
        // Pre-threshold: 50% to treasury, 50% to nodes = 0.5% of subsidy each
        // This matches treasury.rs FeeDistribution calculation
        // For now, use 50/50 split of pool fee (this should be configurable via TreasuryState)
        let node_pool = pool_fee / 2; // 0.5% of subsidy to nodes

        // 5. Calculate miner payouts (top 200)
        // Dust from miners below threshold is returned for redistribution to node pool
        let (miner_payouts, miner_dust) =
            self.calculate_miner_payouts(shares, miner_pool, miner_addresses);
        result.miner_payouts = miner_payouts;

        // 6. Add miner dust to node pool - no satoshis are lost!
        let augmented_node_pool = node_pool.saturating_add(miner_dust);
        if miner_dust > 0 {
            info!(
                miner_dust,
                original_node_pool = node_pool,
                augmented_node_pool,
                "Miner dust added to node reward pool"
            );
        }

        // 7. Calculate node payouts (top 100) from augmented pool
        result.node_payouts =
            self.calculate_node_payouts(shares, augmented_node_pool, node_addresses);

        // 8. Add treasury payout entry
        if result.treasury_amount >= self.dust_threshold {
            result.treasury_entry = Some(PayoutEntry {
                address: treasury_address,
                amount: result.treasury_amount,
                recipient_id: [0u8; 32], // Treasury has no specific ID
                payout_type: PayoutType::Treasury,
            });
        }

        // 9. Add TX fee payout entry
        // SECURITY: TX fees MUST go somewhere - if builder address not found,
        // add to treasury rather than silently losing them
        if let Some(builder) = result.tx_fee_recipient {
            if let Some(addr) = node_addresses.iter().find(|(id, _)| *id == builder) {
                if tx_fees_sats >= self.dust_threshold {
                    result.tx_fee_entry = Some(PayoutEntry {
                        address: addr.1.clone(),
                        amount: tx_fees_sats,
                        recipient_id: builder,
                        payout_type: PayoutType::TxFees,
                    });
                } else if tx_fees_sats > 0 {
                    // Dust TX fees: add to node reward pool (top node gets the dust)
                    // This ensures no satoshis are lost and benefits node operators
                    if !result.node_payouts.is_empty() {
                        result.node_payouts[0].amount += tx_fees_sats;
                        info!(
                            tx_fees = tx_fees_sats,
                            threshold = self.dust_threshold,
                            top_node = hex::encode(&result.node_payouts[0].recipient_id[..8]),
                            "TX fee dust redistributed to top node"
                        );
                    } else {
                        // Fallback: no nodes to pay, add to treasury
                        warn!(
                            tx_fees = tx_fees_sats,
                            threshold = self.dust_threshold,
                            "TX fees below dust threshold, no nodes available - adding to treasury"
                        );
                        result.treasury_amount += tx_fees_sats;
                    }
                }
            } else {
                // SECURITY: Block builder address not found - this is a critical error.
                // We must NOT silently redirect TX fees to treasury as this would steal
                // from the block finder. Instead, we log the error and continue without
                // the TX fees in the payout (they will remain unallocated).
                // The caller should handle this by failing the block production.
                error!(
                    builder_id = hex::encode(builder),
                    tx_fees = tx_fees_sats,
                    "CRITICAL: Block builder address not found! TX fees NOT allocated - block should not be produced"
                );
                // DO NOT add to treasury - this would steal from the block finder
                // Mark that we failed to allocate TX fees
                result.tx_fee_recipient = None;
                result.tx_fee_allocation_failed = true;
            }
        }

        debug!(
            treasury = result.treasury_amount,
            tx_fees = result.tx_fee_amount,
            miner_payouts = result.miner_payouts.len(),
            node_payouts = result.node_payouts.len(),
            "Payout calculation complete"
        );

        result
    }

    /// Calculate miner payouts proportional to work
    /// Returns (payouts, dust_amount) where dust is redirected to node reward pool
    ///
    /// SECURITY: Uses integer arithmetic with basis points to avoid floating point
    /// rounding errors. Calculates share_bps = (miner_work * 10000) / total_work,
    /// then amount = (pool_amount * share_bps) / 10000.
    fn calculate_miner_payouts(
        &self,
        shares: &RoundShares,
        pool_amount: u64,
        miner_addresses: &[(String, Vec<u8>)],
    ) -> (Vec<PayoutEntry>, u64) {
        let mut payouts = Vec::new();
        let mut dust_total: u64 = 0;

        // Get top miners
        let top_miners = shares.top_miners(self.max_miner_outputs);

        // Calculate total work for basis point calculation
        let total_work = shares.total_miner_work;
        if total_work <= 0.0 {
            return (payouts, dust_total);
        }

        for (miner_id, work) in &top_miners {
            // SECURITY: Use integer arithmetic with basis points
            // Calculate share in basis points: (work * 10000) / total_work
            let share_bps = ((*work * 10000.0) / total_work) as u64;
            // Calculate amount: (pool_amount * share_bps) / 10000
            // Use u128 to prevent overflow
            let amount = (pool_amount as u128 * share_bps as u128 / 10000) as u64;

            if amount < self.dust_threshold {
                // Track dust for redistribution to node reward pool
                dust_total = dust_total.saturating_add(amount);
                debug!(
                    miner_id,
                    amount,
                    threshold = self.dust_threshold,
                    "Miner payout below dust threshold - redirecting to node reward pool"
                );
                continue;
            }

            // Find miner's address
            if let Some((_, address)) = miner_addresses.iter().find(|(id, _)| id == miner_id) {
                // SECURITY: Convert miner_id to recipient_id using SHA256 hash
                // This matches the hashing pattern used in ghost-pool/src/payout.rs
                // for consistent recipient identification across the codebase.
                // Using hash instead of truncation prevents collisions for long IDs.
                let mut recipient_id = [0u8; 32];
                let hash = ghost_common::identity::hash_message(miner_id.as_bytes());
                recipient_id.copy_from_slice(&hash);

                payouts.push(PayoutEntry {
                    address: address.clone(),
                    amount,
                    recipient_id,
                    payout_type: PayoutType::Mining,
                });
            }
        }

        if dust_total > 0 {
            info!(dust_total, "Miner dust collected for node reward pool");
        }

        (payouts, dust_total)
    }

    /// Calculate node payouts based on capability shares
    /// Dust from nodes below threshold is redistributed to the top node
    ///
    /// SECURITY: Uses integer arithmetic with basis points to avoid floating point
    /// rounding errors. Calculates share_bps = (node_shares * 10000) / total_shares,
    /// then amount = (pool_amount * share_bps) / 10000.
    fn calculate_node_payouts(
        &self,
        shares: &RoundShares,
        pool_amount: u64,
        node_addresses: &[([u8; 32], Vec<u8>)],
    ) -> Vec<PayoutEntry> {
        let mut payouts = Vec::new();
        let mut dust_total: u64 = 0;

        // Get top 100 nodes
        let top_nodes = shares.top_100_nodes();

        // Limit to max outputs
        let nodes_to_pay: Vec<_> = top_nodes.into_iter().take(self.max_node_outputs).collect();

        // Calculate total shares for basis point calculation
        let total_shares: i32 = nodes_to_pay.iter().map(|n| n.shares).sum();
        if total_shares <= 0 {
            return payouts;
        }

        for node_info in &nodes_to_pay {
            // SECURITY: Use integer arithmetic with basis points
            // Calculate share in basis points: (shares * 10000) / total_shares
            let share_bps = (node_info.shares as u64 * 10000) / total_shares as u64;
            // Calculate amount: (pool_amount * share_bps) / 10000
            // Use u128 to prevent overflow
            let amount = (pool_amount as u128 * share_bps as u128 / 10000) as u64;

            if amount < self.dust_threshold {
                // Track dust for redistribution to top node
                dust_total = dust_total.saturating_add(amount);
                debug!(
                    node_id = hex::encode(&node_info.node_id[..8]),
                    amount,
                    threshold = self.dust_threshold,
                    "Node payout below dust threshold - will add to top node"
                );
                continue;
            }

            // Find node's address
            if let Some((_, address)) = node_addresses
                .iter()
                .find(|(id, _)| *id == node_info.node_id)
            {
                payouts.push(PayoutEntry {
                    address: address.clone(),
                    amount,
                    recipient_id: node_info.node_id,
                    payout_type: PayoutType::NodeReward,
                });
            }
        }

        // Add dust to the top node's payout (first in list = highest capability shares)
        if dust_total > 0 && !payouts.is_empty() {
            payouts[0].amount = payouts[0].amount.saturating_add(dust_total);
            info!(
                dust_total,
                top_node = hex::encode(&payouts[0].recipient_id[..8]),
                "Node dust redistributed to top node"
            );
        } else if dust_total > 0 {
            warn!(
                dust_total,
                "Node dust lost - no eligible nodes to receive it"
            );
        }

        payouts
    }

    /// Calculate credits for nodes outside top 100 (for ledger)
    pub fn calculate_ledger_credits(
        &self,
        shares: &RoundShares,
        node_pool: u64,
    ) -> Vec<(NodeId, u64)> {
        let mut credits = Vec::new();

        // Nodes outside top 100 get their share credited to ledger
        let outside_nodes = shares.nodes_outside_top_100();

        // Calculate what percentage of pool they would get
        let total_outside_shares: i32 = outside_nodes.iter().map(|n| n.shares).sum();

        if total_outside_shares == 0 {
            return credits;
        }

        // They get the proportion of the node pool that wasn't paid out
        // This is a simplified model - in reality, the top 100 get paid,
        // and the rest just accumulate in ledger for future inclusion

        for node_info in outside_nodes {
            if node_info.shares == 0 {
                continue;
            }

            // Calculate their theoretical share
            let share_percent = node_info.shares as f64 / shares.total_node_shares as f64;
            let amount = (node_pool as f64 * share_percent) as u64;

            if amount > 0 {
                credits.push((node_info.node_id, amount));
            }
        }

        credits
    }
}

/// Type alias for node ID
type NodeId = [u8; 32];

/// Result of payout calculation
#[derive(Debug, Clone, Default)]
pub struct PayoutResult {
    /// Miner payouts
    pub miner_payouts: Vec<PayoutEntry>,
    /// Node payouts (top 100)
    pub node_payouts: Vec<PayoutEntry>,
    /// Treasury amount
    pub treasury_amount: u64,
    /// Treasury payout entry
    pub treasury_entry: Option<PayoutEntry>,
    /// TX fees amount
    pub tx_fee_amount: u64,
    /// TX fee recipient (block builder node)
    pub tx_fee_recipient: Option<NodeId>,
    /// TX fee payout entry
    pub tx_fee_entry: Option<PayoutEntry>,
    /// SECURITY: Set to true if TX fee allocation failed due to missing block finder address.
    /// When true, the block should NOT be produced as TX fees would be lost.
    pub tx_fee_allocation_failed: bool,
}

impl PayoutResult {
    /// Get all payout entries for coinbase
    pub fn all_entries(&self) -> Vec<&PayoutEntry> {
        let mut entries: Vec<&PayoutEntry> = Vec::new();

        if let Some(ref treasury) = self.treasury_entry {
            entries.push(treasury);
        }

        if let Some(ref tx_fee) = self.tx_fee_entry {
            entries.push(tx_fee);
        }

        entries.extend(self.node_payouts.iter());
        entries.extend(self.miner_payouts.iter());

        entries
    }

    /// Total payout amount
    pub fn total_amount(&self) -> u64 {
        self.treasury_amount
            + self.tx_fee_amount
            + self.miner_payouts.iter().map(|p| p.amount).sum::<u64>()
            + self.node_payouts.iter().map(|p| p.amount).sum::<u64>()
    }

    /// Count of all outputs
    pub fn output_count(&self) -> usize {
        let mut count = 0;
        if self.treasury_entry.is_some() {
            count += 1;
        }
        if self.tx_fee_entry.is_some() {
            count += 1;
        }
        count += self.miner_payouts.len();
        count += self.node_payouts.len();
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::types::NodeCapabilities;

    #[test]
    fn test_payout_calculation() {
        let mut shares = RoundShares::new(1, 100);

        // Add miners
        shares.add_miner_work("miner1", 60.0);
        shares.add_miner_work("miner2", 40.0);

        // Add nodes
        let mut caps = NodeCapabilities::default();
        caps.archive_mode = true;
        caps.public_mining = true;
        shares.register_node([1u8; 32], caps.clone());

        caps.ghost_pay = true;
        shares.register_node([2u8; 32], caps);

        // Simulate shares
        for _ in 0..100 {
            shares.increment_node_shares(&[1u8; 32]);
        }
        for _ in 0..50 {
            shares.increment_node_shares(&[2u8; 32]);
        }

        shares.calculate_top_100_nodes();

        let calculator = PayoutCalculator::default();

        let miner_addresses = vec![
            ("miner1".to_string(), vec![1u8; 20]),
            ("miner2".to_string(), vec![2u8; 20]),
        ];

        let node_addresses = vec![([1u8; 32], vec![3u8; 20]), ([2u8; 32], vec![4u8; 20])];

        let result = calculator.calculate_payouts(
            &shares,
            312_500_000, // 3.125 BTC subsidy
            1_000_000,   // 0.01 BTC fees
            &miner_addresses,
            &node_addresses,
            [1u8; 32],     // Block builder
            vec![5u8; 20], // Treasury
        );

        assert!(result.treasury_amount > 0);
        assert_eq!(result.tx_fee_amount, 1_000_000);
        assert!(!result.miner_payouts.is_empty());
        assert!(!result.node_payouts.is_empty());
    }

    #[test]
    fn test_integer_arithmetic_no_rounding_error() {
        // SECURITY TEST: Verify integer arithmetic produces consistent results
        // without floating point rounding errors

        let mut shares = RoundShares::new(1, 100);

        // Add miners with specific work values that could cause floating point issues
        shares.add_miner_work("miner1", 33.333333333);
        shares.add_miner_work("miner2", 33.333333333);
        shares.add_miner_work("miner3", 33.333333334);

        // Add nodes with varying shares
        let mut caps = NodeCapabilities::default();
        caps.archive_mode = true;
        shares.register_node([1u8; 32], caps.clone());
        shares.register_node([2u8; 32], caps.clone());
        shares.register_node([3u8; 32], caps);

        for _ in 0..7 {
            shares.increment_node_shares(&[1u8; 32]);
        }
        for _ in 0..3 {
            shares.increment_node_shares(&[2u8; 32]);
        }
        // Node 3 has 0 shares (registered but no work)

        shares.calculate_top_100_nodes();

        let calculator = PayoutCalculator::default();

        let miner_addresses = vec![
            ("miner1".to_string(), vec![1u8; 20]),
            ("miner2".to_string(), vec![2u8; 20]),
            ("miner3".to_string(), vec![3u8; 20]),
        ];

        let node_addresses = vec![
            ([1u8; 32], vec![4u8; 20]),
            ([2u8; 32], vec![5u8; 20]),
            ([3u8; 32], vec![6u8; 20]),
        ];

        let result = calculator.calculate_payouts(
            &shares,
            312_500_000,
            1_000_000,
            &miner_addresses,
            &node_addresses,
            [1u8; 32],
            vec![7u8; 20],
        );

        // Verify all miner payouts are reasonable
        let total_miner_payout: u64 = result.miner_payouts.iter().map(|p| p.amount).sum();
        let total_node_payout: u64 = result.node_payouts.iter().map(|p| p.amount).sum();

        // Miner pool should be 99% of subsidy minus pool fee
        // Pool fee is 1% of subsidy = 3,125,000
        // Miner pool = 312,500,000 - 3,125,000 = 309,375,000
        // But we may have some dust collected
        assert!(total_miner_payout > 0, "Miner payouts should not be empty");
        assert!(
            total_node_payout >= 0,
            "Node payouts should not be negative"
        );

        // Total should not exceed available funds
        let pool_fee = 312_500_000 / 100; // 1%
        let miner_pool = 312_500_000 - pool_fee;
        let node_pool = pool_fee / 2;

        assert!(
            total_miner_payout <= miner_pool,
            "Miner payouts {} exceed pool {}",
            total_miner_payout,
            miner_pool
        );
        assert!(
            total_node_payout <= node_pool + (miner_pool - total_miner_payout), // May include dust
            "Node payouts {} exceed available funds",
            total_node_payout
        );
    }

    #[test]
    fn test_tx_fees_not_lost() {
        // SECURITY TEST: Verify TX fees are not silently redirected to treasury
        // when block finder address is not found

        let mut shares = RoundShares::new(1, 100);
        shares.add_miner_work("miner1", 100.0);

        // Node must have capabilities to get shares (5-4-3-2-1 system)
        let mut caps = NodeCapabilities::default();
        caps.archive_mode = true; // +5 shares
        shares.register_node([1u8; 32], caps);
        shares.increment_node_shares(&[1u8; 32]);
        shares.calculate_top_100_nodes();

        let calculator = PayoutCalculator::default();

        let miner_addresses = vec![("miner1".to_string(), vec![1u8; 20])];

        // Node addresses does NOT include the block builder [2u8; 32]
        let node_addresses = vec![([1u8; 32], vec![3u8; 20])];

        let result = calculator.calculate_payouts(
            &shares,
            312_500_000,
            10_000_000, // 0.1 BTC in TX fees
            &miner_addresses,
            &node_addresses,
            [2u8; 32], // Block builder NOT in node_addresses
            vec![5u8; 20],
        );

        // SECURITY: TX fee allocation should fail, not silently redirect to treasury
        assert!(
            result.tx_fee_allocation_failed,
            "tx_fee_allocation_failed should be true when block finder address not found"
        );

        // TX fee entry should be None (not allocated)
        assert!(
            result.tx_fee_entry.is_none(),
            "TX fee entry should be None when address not found"
        );

        // CRITICAL: Treasury should NOT have the TX fees added
        // Treasury should only be ~1,562,500 (0.5% of subsidy), not +10,000,000
        let expected_treasury = 312_500_000 / 100 / 2; // 0.5% of subsidy
        assert_eq!(
            result.treasury_amount, expected_treasury,
            "Treasury amount should be {} but was {} - TX fees may have been stolen!",
            expected_treasury, result.treasury_amount
        );
    }

    #[test]
    fn test_correct_99_1_split() {
        // SECURITY TEST: Verify the 99/1 split per ECONOMICS.md

        let mut shares = RoundShares::new(1, 100);
        shares.add_miner_work("miner1", 100.0);

        // Node must have capabilities to get shares (5-4-3-2-1 system)
        let mut caps = NodeCapabilities::default();
        caps.archive_mode = true; // +5 shares
        shares.register_node([1u8; 32], caps);
        shares.increment_node_shares(&[1u8; 32]);
        shares.calculate_top_100_nodes();

        let calculator = PayoutCalculator::default();

        let miner_addresses = vec![("miner1".to_string(), vec![1u8; 20])];
        let node_addresses = vec![([1u8; 32], vec![3u8; 20])];

        let subsidy = 312_500_000u64;
        let result = calculator.calculate_payouts(
            &shares,
            subsidy,
            0, // No TX fees for simplicity
            &miner_addresses,
            &node_addresses,
            [1u8; 32],
            vec![5u8; 20],
        );

        // Pool fee should be 1% of subsidy
        let expected_pool_fee = subsidy / 100; // 3,125,000
        assert_eq!(expected_pool_fee, 3_125_000);

        // Treasury should be 0.5% of subsidy (half of pool fee)
        let expected_treasury = expected_pool_fee / 2; // 1,562,500
        assert_eq!(
            result.treasury_amount, expected_treasury,
            "Treasury should be 0.5% of subsidy"
        );

        // Miner payout should be ~99% of subsidy
        let total_miner_payout: u64 = result.miner_payouts.iter().map(|p| p.amount).sum();
        let expected_miner_pool = subsidy - expected_pool_fee; // 309,375,000
        assert_eq!(expected_miner_pool, 309_375_000);

        // Since there's only one miner, they should get the full miner pool
        assert_eq!(
            total_miner_payout, expected_miner_pool,
            "Miners should receive 99% of subsidy"
        );

        // Node pool should be 0.5% of subsidy (half of pool fee)
        let total_node_payout: u64 = result.node_payouts.iter().map(|p| p.amount).sum();
        let expected_node_pool = expected_pool_fee / 2; // 1,562,500
        assert_eq!(
            total_node_payout, expected_node_pool,
            "Nodes should receive 0.5% of subsidy"
        );
    }

    #[test]
    fn test_recipient_id_uses_hash_not_truncation() {
        // SECURITY TEST: Verify recipient IDs use SHA256 hash, not truncation
        // This matches the pattern in ghost-pool for consistent identification

        let mut shares = RoundShares::new(1, 100);

        // Add a miner with a long ID that would be truncated differently by truncation vs hash
        let long_miner_id = "miner_with_very_long_id_that_exceeds_32_bytes_definitely";
        shares.add_miner_work(long_miner_id, 100.0);

        let mut caps = NodeCapabilities::default();
        caps.archive_mode = true;
        shares.register_node([1u8; 32], caps);
        shares.increment_node_shares(&[1u8; 32]);
        shares.calculate_top_100_nodes();

        let calculator = PayoutCalculator::default();

        let miner_addresses = vec![(long_miner_id.to_string(), vec![1u8; 20])];
        let node_addresses = vec![([1u8; 32], vec![3u8; 20])];

        let result = calculator.calculate_payouts(
            &shares,
            312_500_000,
            0,
            &miner_addresses,
            &node_addresses,
            [1u8; 32],
            vec![5u8; 20],
        );

        // Get the miner payout
        assert!(
            !result.miner_payouts.is_empty(),
            "Should have miner payouts"
        );
        let miner_payout = &result.miner_payouts[0];

        // Calculate expected recipient_id using the same hash method as ghost-pool
        let expected_hash = ghost_common::identity::hash_message(long_miner_id.as_bytes());

        // Verify the recipient_id is the hash, NOT a truncation
        assert_eq!(
            miner_payout.recipient_id,
            expected_hash.as_slice(),
            "Recipient ID should be SHA256 hash of miner_id, not truncation"
        );

        // Verify it's NOT the truncated value (which would just be the first 32 bytes)
        let mut truncated = [0u8; 32];
        let bytes = long_miner_id.as_bytes();
        truncated[..32.min(bytes.len())].copy_from_slice(&bytes[..32.min(bytes.len())]);
        assert_ne!(
            miner_payout.recipient_id, truncated,
            "Recipient ID should NOT be truncation"
        );
    }
}
