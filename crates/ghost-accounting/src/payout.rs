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
use ghost_common::error::{GhostError, GhostResult};
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
    ///
    /// # Arguments
    /// - `pool_fee_percent`: Pool fee as a percentage (0.0-100.0). Values outside this range
    ///   will be clamped to prevent overflow.
    ///
    /// # CRIT-POOL-1: pool_fee_percent is validated to be in [0, 100] range
    /// This prevents integer overflow when converting to basis points.
    pub fn new(
        pool_fee_percent: f64,
        dust_threshold: u64,
        max_miner_outputs: usize,
        max_node_outputs: usize,
    ) -> Self {
        // CRIT-POOL-1: Validate and clamp pool_fee_percent to prevent overflow
        // Valid range is 0-100 (representing 0% to 100%)
        let validated_fee = if !pool_fee_percent.is_finite() || pool_fee_percent < 0.0 {
            warn!(
                pool_fee_percent,
                "CRIT-POOL-1: Invalid pool_fee_percent (negative or non-finite), clamping to 0"
            );
            0.0
        } else if pool_fee_percent > 100.0 {
            warn!(
                pool_fee_percent,
                "CRIT-POOL-1: pool_fee_percent exceeds 100%, clamping to 100"
            );
            100.0
        } else {
            pool_fee_percent
        };

        Self {
            pool_fee_percent: validated_fee,
            dust_threshold,
            max_miner_outputs,
            max_node_outputs,
        }
    }

    /// Calculate payouts for a round
    ///
    /// # SECURITY: TX Fee Allocation Enforcement (CRIT-3)
    ///
    /// This function returns `Err(GhostError::TxFeeAllocationFailed)` if the block builder's
    /// payout address cannot be found. This is a CRITICAL security measure:
    ///
    /// - TX fees (~5-50M sats per block) MUST go to the block builder node
    /// - If the builder address is not found, we CANNOT proceed with block production
    /// - The caller MUST NOT produce a block when this error is returned
    /// - Silently redirecting TX fees to treasury would be theft from the block finder
    ///
    /// # Returns
    ///
    /// - `Ok(PayoutResult)` - All payouts calculated successfully, safe to produce block
    /// - `Err(TxFeeAllocationFailed)` - Block builder address not found, MUST NOT produce block
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
    ) -> GhostResult<PayoutResult> {
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
        //
        // CRIT-POOL-1: Validate pool_fee_percent is in valid range before conversion
        // This is defense-in-depth; the constructor also validates.
        let clamped_fee_percent = self.pool_fee_percent.clamp(0.0, 100.0);
        if clamped_fee_percent != self.pool_fee_percent {
            warn!(
                original = self.pool_fee_percent,
                clamped = clamped_fee_percent,
                "CRIT-POOL-1: pool_fee_percent was out of range, clamped"
            );
        }
        // CRIT-POOL-1: Use checked multiplication to prevent overflow
        // pool_fee_bps is now guaranteed to be 0-10000 (0% to 100%)
        let pool_fee_bps = (clamped_fee_percent * 100.0) as u64;
        debug_assert!(pool_fee_bps <= 10000, "pool_fee_bps should be <= 10000 (100%)");
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
        // PAY-M4: Unallocated node dust is returned to be added to treasury
        let (node_payouts, node_dust_unallocated) =
            self.calculate_node_payouts(shares, augmented_node_pool, node_addresses);
        result.node_payouts = node_payouts;

        // Add any unallocated node dust to treasury (PAY-M4)
        if node_dust_unallocated > 0 {
            result.treasury_amount = result.treasury_amount.saturating_add(node_dust_unallocated);
            info!(
                node_dust_unallocated,
                new_treasury_amount = result.treasury_amount,
                "Unallocated node dust added to treasury"
            );
        }

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
                // SECURITY (CRIT-3): Block builder address not found - CRITICAL ERROR.
                // We MUST NOT:
                // 1. Silently redirect TX fees to treasury (that would steal from block finder)
                // 2. Continue with block production (TX fees would be permanently lost)
                // 3. Just log and continue (the flag was ignored by callers)
                //
                // We MUST return an error to FORCE the caller to halt block production.
                // TX fees can be 5-50M sats per block - this is not acceptable to lose.
                error!(
                    builder_id = hex::encode(builder),
                    tx_fees = tx_fees_sats,
                    "CRITICAL: Block builder address not found! Failing payout calculation to prevent fund loss"
                );
                return Err(GhostError::TxFeeAllocationFailed {
                    node_id: hex::encode(builder),
                    tx_fees: tx_fees_sats,
                });
            }
        }

        debug!(
            treasury = result.treasury_amount,
            tx_fees = result.tx_fee_amount,
            miner_payouts = result.miner_payouts.len(),
            node_payouts = result.node_payouts.len(),
            "Payout calculation complete"
        );

        Ok(result)
    }

    /// Calculate miner payouts proportional to work
    /// Returns (payouts, dust_amount) where dust is redirected to node reward pool
    ///
    /// HIGH-POOL-2 SECURITY: Uses pure integer arithmetic to avoid floating point
    /// precision loss. We use the scaled u128 work values directly instead of
    /// converting through f64. Formula: amount = (pool_amount * miner_work) / total_work
    /// This "multiply first, divide last" approach maximizes precision.
    fn calculate_miner_payouts(
        &self,
        shares: &RoundShares,
        pool_amount: u64,
        miner_addresses: &[(String, Vec<u8>)],
    ) -> (Vec<PayoutEntry>, u64) {
        let mut payouts = Vec::new();
        let mut dust_total: u64 = 0;

        // Get top miners (still uses f64 for sorting, but we'll use scaled values for calculation)
        let top_miners = shares.top_miners(self.max_miner_outputs);

        // HIGH-POOL-2: Use scaled integer work values for calculation
        // This avoids f64 precision loss in the payout calculation
        let total_work_scaled = shares.total_work_scaled();
        if total_work_scaled == 0 {
            return (payouts, dust_total);
        }

        for (miner_id, _) in &top_miners {
            // HIGH-POOL-2: Get the scaled u128 work value directly
            let work_scaled = shares.miner_work_scaled(miner_id);
            if work_scaled == 0 {
                continue;
            }

            // HIGH-POOL-2: Pure integer arithmetic - multiply first, divide last
            // Formula: amount = (pool_amount * work_scaled) / total_work_scaled
            // Using u128 for the intermediate result to prevent overflow
            // pool_amount is u64 (max ~21 BTC in sats), work_scaled is u128, both fit in u128
            let amount = ((pool_amount as u128 * work_scaled) / total_work_scaled) as u64;

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
            // HIGH-POOL-1: Miners must have valid addresses to receive payouts
            match miner_addresses.iter().find(|(id, _)| id == miner_id) {
                Some((original_id, address)) if !address.is_empty() => {
                    // MED-POOL-3: Convert miner_id to recipient_id using SHA256 hash
                    // This matches the hashing pattern used in ghost-pool/src/payout.rs
                    // for consistent recipient identification across the codebase.
                    //
                    // MED-POOL-3 SECURITY ANALYSIS:
                    // SHA256 is collision-resistant (no known practical collision attack).
                    // The probability of two different miner IDs having the same hash is
                    // approximately 1/2^128 (birthday paradox). With ~10^6 miners over the
                    // pool's lifetime, the collision probability is still negligible (~10^-26).
                    //
                    // We verify the original_id matches miner_id as defense-in-depth,
                    // ensuring we're paying the correct miner even if somehow we found
                    // a different entry with the same address.
                    debug_assert_eq!(
                        original_id, miner_id,
                        "MED-POOL-3: Miner ID lookup mismatch"
                    );

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
                Some((_, _)) => {
                    // HIGH-POOL-1: Empty address - log error and add to dust pool
                    // This ensures the satoshis go to node reward pool rather than being lost
                    warn!(
                        miner_id,
                        amount,
                        "HIGH-POOL-1: Miner has empty payout address - redirecting to node pool"
                    );
                    dust_total = dust_total.saturating_add(amount);
                }
                None => {
                    // HIGH-POOL-1: Miner not in address list - log error and add to dust pool
                    // This ensures the satoshis go to node reward pool rather than being lost
                    warn!(
                        miner_id,
                        amount,
                        "HIGH-POOL-1: Miner has no registered payout address - redirecting to node pool"
                    );
                    dust_total = dust_total.saturating_add(amount);
                }
            }
        }

        if dust_total > 0 {
            info!(dust_total, "Miner dust collected for node reward pool");
        }

        (payouts, dust_total)
    }

    /// Calculate node payouts based on capability shares
    /// Dust from nodes below threshold is redistributed to the top node
    /// PAY-M4: Returns (payouts, unallocated_dust) where unallocated_dust is non-zero
    /// only when no nodes qualify for payouts, so it can be redirected to treasury.
    ///
    /// SECURITY: Uses integer arithmetic with basis points to avoid floating point
    /// rounding errors. Calculates share_bps = (node_shares * 10000) / total_shares,
    /// then amount = (pool_amount * share_bps) / 10000.
    fn calculate_node_payouts(
        &self,
        shares: &RoundShares,
        pool_amount: u64,
        node_addresses: &[([u8; 32], Vec<u8>)],
    ) -> (Vec<PayoutEntry>, u64) {
        let mut payouts = Vec::new();
        let mut dust_total: u64 = 0;

        // Get top 100 nodes
        let top_nodes = shares.top_100_nodes();

        // Limit to max outputs
        let nodes_to_pay: Vec<_> = top_nodes.into_iter().take(self.max_node_outputs).collect();

        // Calculate total shares for basis point calculation
        let total_shares: i32 = nodes_to_pay.iter().map(|n| n.shares).sum();
        if total_shares <= 0 {
            return (payouts, 0);
        }

        for node_info in &nodes_to_pay {
            // HIGH-POOL-2 / LOW-POOL-1: Use direct integer division without basis points
            // This eliminates the precision loss from the intermediate basis point calculation.
            // Formula: amount = (pool_amount * shares) / total_shares
            // Using u128 to prevent overflow in the multiplication
            let amount = ((pool_amount as u128 * node_info.shares as u128) / total_shares as u128) as u64;

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
            (payouts, 0)
        } else if dust_total > 0 {
            // PAY-M4: No eligible nodes to receive dust - return it to be added to treasury
            info!(
                dust_total,
                "No eligible nodes for dust - will be redirected to treasury"
            );
            (payouts, dust_total)
        } else {
            (payouts, 0)
        }
    }

    /// Calculate credits for nodes outside top 100 (for ledger)
    ///
    /// M-12: Uses integer arithmetic with basis points to avoid floating point errors.
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

        if total_outside_shares <= 0 {
            return credits;
        }

        // They get the proportion of the node pool that wasn't paid out
        // This is a simplified model - in reality, the top 100 get paid,
        // and the rest just accumulate in ledger for future inclusion

        for node_info in outside_nodes {
            if node_info.shares <= 0 {
                continue;
            }

            // M-12: Use integer arithmetic with basis points instead of floating point
            // Calculate share in basis points: (shares * 10000) / total_shares
            let share_bps = (node_info.shares as u64 * 10000) / total_outside_shares as u64;
            // Calculate amount: (pool * share_bps) / 10000
            // Use u128 to prevent overflow
            let amount = (node_pool as u128 * share_bps as u128 / 10000) as u64;

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
    // NOTE: tx_fee_allocation_failed field was REMOVED as part of CRIT-3 fix.
    // Instead of setting a flag that callers could ignore, calculate_payouts()
    // now returns Err(TxFeeAllocationFailed) which FORCES callers to handle it.
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

        let result = calculator
            .calculate_payouts(
                &shares,
                312_500_000, // 3.125 BTC subsidy
                1_000_000,   // 0.01 BTC fees
                &miner_addresses,
                &node_addresses,
                [1u8; 32],     // Block builder
                vec![5u8; 20], // Treasury
            )
            .expect("calculate_payouts should succeed when all addresses are found");

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

        let result = calculator
            .calculate_payouts(
                &shares,
                312_500_000,
                1_000_000,
                &miner_addresses,
                &node_addresses,
                [1u8; 32],
                vec![7u8; 20],
            )
            .expect("calculate_payouts should succeed when all addresses are found");

        // Verify all miner payouts are reasonable
        let total_miner_payout: u64 = result.miner_payouts.iter().map(|p| p.amount).sum();
        let total_node_payout: u64 = result.node_payouts.iter().map(|p| p.amount).sum();

        // Miner pool should be 99% of subsidy minus pool fee
        // Pool fee is 1% of subsidy = 3,125,000
        // Miner pool = 312,500,000 - 3,125,000 = 309,375,000
        // But we may have some dust collected
        assert!(total_miner_payout > 0, "Miner payouts should not be empty");
        // total_node_payout is u64, can't be negative

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
    fn test_tx_fee_allocation_failure_prevents_block_production() {
        // SECURITY TEST (CRIT-3): Verify that when block finder address is not found,
        // calculate_payouts returns an ERROR, not just a flag. This ensures the caller
        // CANNOT proceed with block production when TX fees are unallocated.

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
            10_000_000, // 0.1 BTC in TX fees - WOULD BE LOST if we continued
            &miner_addresses,
            &node_addresses,
            [2u8; 32], // Block builder NOT in node_addresses - THIS IS THE PROBLEM
            vec![5u8; 20],
        );

        // SECURITY (CRIT-3): Function MUST return an error, not Ok with a flag
        assert!(
            result.is_err(),
            "calculate_payouts MUST return Err when block builder address not found"
        );

        // Verify it's the correct error type
        let err = result.unwrap_err();
        match err {
            GhostError::TxFeeAllocationFailed { node_id, tx_fees } => {
                // Verify the error contains the correct information
                assert_eq!(
                    tx_fees, 10_000_000,
                    "Error should contain the TX fee amount"
                );
                assert!(
                    !node_id.is_empty(),
                    "Error should contain the block builder node ID"
                );
            }
            _ => panic!("Expected TxFeeAllocationFailed error, got: {:?}", err),
        }
    }

    #[test]
    fn test_valid_block_production_proceeds_normally() {
        // SECURITY TEST (CRIT-3): Verify that when all addresses are found,
        // calculate_payouts returns Ok with proper TX fee allocation.

        let mut shares = RoundShares::new(1, 100);
        shares.add_miner_work("miner1", 100.0);

        let mut caps = NodeCapabilities::default();
        caps.archive_mode = true;
        shares.register_node([1u8; 32], caps);
        shares.increment_node_shares(&[1u8; 32]);
        shares.calculate_top_100_nodes();

        let calculator = PayoutCalculator::default();

        let miner_addresses = vec![("miner1".to_string(), vec![1u8; 20])];

        // Node addresses INCLUDES the block builder [1u8; 32]
        let node_addresses = vec![([1u8; 32], vec![3u8; 20])];

        let result = calculator.calculate_payouts(
            &shares,
            312_500_000,
            10_000_000, // 0.1 BTC in TX fees
            &miner_addresses,
            &node_addresses,
            [1u8; 32], // Block builder IS in node_addresses
            vec![5u8; 20],
        );

        // SECURITY (CRIT-3): Function MUST return Ok when all addresses are found
        assert!(
            result.is_ok(),
            "calculate_payouts should return Ok when all addresses are found"
        );

        let payout = result.unwrap();

        // TX fee entry should be present with correct amount
        assert!(
            payout.tx_fee_entry.is_some(),
            "TX fee entry should be present when address is found"
        );
        assert_eq!(
            payout.tx_fee_entry.as_ref().unwrap().amount,
            10_000_000,
            "TX fee amount should be fully allocated"
        );

        // Treasury should NOT have TX fees added (only pool fee portion)
        let expected_treasury = 312_500_000 / 100 / 2; // 0.5% of subsidy
        assert_eq!(
            payout.treasury_amount, expected_treasury,
            "Treasury amount should be {} (pool fee only), not include TX fees",
            expected_treasury
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
        let result = calculator
            .calculate_payouts(
                &shares,
                subsidy,
                0, // No TX fees for simplicity
                &miner_addresses,
                &node_addresses,
                [1u8; 32],
                vec![5u8; 20],
            )
            .expect("calculate_payouts should succeed when all addresses are found");

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

        let result = calculator
            .calculate_payouts(
                &shares,
                312_500_000,
                0,
                &miner_addresses,
                &node_addresses,
                [1u8; 32],
                vec![5u8; 20],
            )
            .expect("calculate_payouts should succeed when all addresses are found");

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
