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
    DUST_THRESHOLD_SATS, MAX_MINER_OUTPUTS, MAX_NODE_OUTPUTS, POOL_FEE_PERCENT,
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
            pool_fee_percent: POOL_FEE_PERCENT,
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
        // SECURITY: Use integer math to avoid floating point precision loss
        // Convert percentage to basis points (1% = 100 bps) for integer division
        let pool_fee_bps = (self.pool_fee_percent * 100.0) as u64;
        let pool_fee = subsidy_sats * pool_fee_bps / 10000;
        result.treasury_amount = pool_fee;

        // 2. TX fees go to block builder node
        result.tx_fee_amount = tx_fees_sats;
        result.tx_fee_recipient = Some(block_builder_node);

        // 3. Remaining subsidy after pool fee
        let remaining_subsidy = subsidy_sats - pool_fee;

        // 4. Split 50/50 between miners and nodes
        let miner_pool = remaining_subsidy / 2;
        let node_pool = remaining_subsidy - miner_pool;

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
                // CRITICAL: Block builder address not found - this should not happen
                // Add TX fees to treasury to prevent fund loss
                error!(
                    builder_id = hex::encode(builder),
                    tx_fees = tx_fees_sats,
                    "Block builder address not found! TX fees redirected to treasury"
                );
                result.treasury_amount += tx_fees_sats;
                result.tx_fee_recipient = None; // Clear since we couldn't pay them
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

        for (miner_id, _work) in top_miners {
            let share_percent = shares.miner_share_percent(miner_id);
            let amount = (pool_amount as f64 * share_percent) as u64;

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
                // Convert miner_id to 32 bytes
                let mut recipient_id = [0u8; 32];
                let id_bytes = miner_id.as_bytes();
                let len = std::cmp::min(id_bytes.len(), 32);
                recipient_id[..len].copy_from_slice(&id_bytes[..len]);

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

        for node_info in nodes_to_pay {
            let share_percent = shares.node_share_percent(&node_info.node_id);
            let amount = (pool_amount as f64 * share_percent) as u64;

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
}
