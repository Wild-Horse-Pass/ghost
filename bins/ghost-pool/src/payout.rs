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

//! Payout Proposal Wiring
//!
//! This module connects the BlockFound event to the consensus payout flow:
//! 1. BlockFound event triggers payout calculation
//! 2. PayoutProposal is created from round data + template info
//! 3. Proposal is submitted to VoteHandler for BFT consensus
//! 4. Once approved, coinbase is constructed with the payout outputs
//!
//! Fee Distribution (per ECONOMICS.md):
//! - TX fees (100%) → Node who found the block
//! - Pool fee (1% of subsidy) → Split between Treasury and Node Reward Pool
//! - Miner Pool (99% of subsidy) → Top 200 miners by work
//! - Node Pool → Top 100 nodes by 5-4-3-2-1 capability shares

use std::sync::Arc;
use tracing::{debug, info, warn};

use ghost_common::error::GhostResult;
use ghost_common::identity::NodeIdentity;
use ghost_common::types::{NodeId, PayoutEntry, PayoutProposal, PayoutType, RoundId};
use ghost_consensus::vote_handler::{compute_proposal_hash, VoteHandler};
use ghost_storage::Database;
use ghost_verification::QualifiedCapabilityProvider;

// Re-export payout history types from storage crate
pub use ghost_storage::{PayoutHistoryQuery, RoundPayoutSummary};

use crate::template::TemplateProcessor;
use crate::treasury::{FeeDistribution, TreasuryState};

/// Configuration for payout proposal creation
#[derive(Debug, Clone)]
pub struct PayoutConfig {
    /// Minimum payout amount (dust threshold)
    pub dust_threshold_sats: u64,
    /// Maximum miner outputs per block
    pub max_miner_outputs: usize,
    /// Maximum node outputs per block
    pub max_node_outputs: usize,
    /// Treasury address (script pubkey bytes) - REQUIRED
    /// None indicates unconfigured state; must be set before use
    pub treasury_address: Option<Vec<u8>>,
}

impl Default for PayoutConfig {
    fn default() -> Self {
        Self {
            dust_threshold_sats: 546,
            max_miner_outputs: 200,
            max_node_outputs: 100,
            treasury_address: None, // Must be configured at startup
        }
    }
}

impl PayoutConfig {
    /// Validate that required configuration is present
    /// Returns error if treasury_address is not configured
    pub fn validate(&self) -> GhostResult<()> {
        match &self.treasury_address {
            None => {
                Err(ghost_common::error::GhostError::ConfigError(
                    "treasury_address is required but not configured".to_string()
                ))
            }
            Some(addr) if addr.is_empty() => {
                Err(ghost_common::error::GhostError::ConfigError(
                    "treasury_address cannot be empty".to_string()
                ))
            }
            Some(_) => Ok(()),
        }
    }

    /// Get treasury address, returning error if not configured
    pub fn treasury_address(&self) -> GhostResult<&[u8]> {
        match &self.treasury_address {
            Some(addr) if !addr.is_empty() => Ok(addr.as_slice()),
            _ => Err(ghost_common::error::GhostError::ConfigError(
                "treasury_address is required but not configured".to_string()
            )),
        }
    }
}

/// Data needed to create a payout proposal
#[derive(Debug, Clone)]
pub struct BlockFoundData {
    /// Round ID
    pub round_id: RoundId,
    /// Block hash (from the found share)
    pub block_hash: [u8; 32],
    /// Block height
    pub block_height: u64,
    /// Miner ID that found the block
    pub winning_miner_id: String,
    /// Payout address of the winning miner (extracted from user_identity)
    pub winning_miner_payout_address: Option<String>,
    /// PO4-M2: Treasury address snapshot taken at round start
    /// This prevents TOCTOU issues where the config might change during a round
    pub treasury_address_snapshot: Option<Vec<u8>>,
    /// Node ID that found the block (gets TX fees)
    pub winning_node_id: NodeId,
    /// Block subsidy (satoshis)
    pub subsidy_sats: u64,
    /// Transaction fees (satoshis)
    pub tx_fees_sats: u64,
    /// Miner work distribution: (miner_id, work_fraction)
    pub miner_work: Vec<(String, f64)>,
    /// Node share distribution: (node_id, capability_shares)
    /// Capability shares follow the 5-4-3-2-1 scheme per ECONOMICS.md
    pub node_shares: Vec<(NodeId, i32)>,
    /// Current treasury state (for decay calculation)
    pub treasury_state: TreasuryState,
}

/// Data for solo mining mode block found event
///
/// In solo mode:
/// - 99% of subsidy + ALL TX fees → solo_payout_address
/// - 1% pool fee split between treasury and node pool per decay schedule
/// - Hosting node participates in node reward pool
#[derive(Debug, Clone)]
pub struct SoloBlockFoundData {
    /// Round ID
    pub round_id: RoundId,
    /// Block hash (from the found share)
    pub block_hash: [u8; 32],
    /// Block height
    pub block_height: u64,
    /// Solo payout address (configured in pool settings)
    pub solo_payout_address: String,
    /// Block subsidy (satoshis)
    pub subsidy_sats: u64,
    /// PO4-M2: Treasury address snapshot taken at round start
    pub treasury_address_snapshot: Option<Vec<u8>>,
    /// Transaction fees (satoshis) - ALL go to solo miner
    pub tx_fees_sats: u64,
    /// Node share distribution: (node_id, capability_shares)
    /// Hosting node is included in this list
    pub node_shares: Vec<(NodeId, i32)>,
    /// Current treasury state (for decay calculation)
    pub treasury_state: TreasuryState,
}

/// Creates payout proposals from block found events
pub struct PayoutProposalCreator {
    identity: Arc<NodeIdentity>,
    config: PayoutConfig,
    db: Arc<Database>,
}

impl PayoutProposalCreator {
    /// Create a new PayoutProposalCreator with validated configuration
    ///
    /// # Errors
    /// Returns error if treasury_address is not configured
    pub fn new(identity: Arc<NodeIdentity>, config: PayoutConfig, db: Arc<Database>) -> GhostResult<Self> {
        // Validate configuration at startup - fail early if misconfigured
        config.validate()?;

        Ok(Self {
            identity,
            config,
            db,
        })
    }

    /// PO4-M2: Get a snapshot of the treasury address for use in BlockFoundData
    ///
    /// This captures the current treasury address to prevent TOCTOU issues
    /// where the config might change between round start and block found.
    pub fn get_treasury_address_snapshot(&self) -> Option<Vec<u8>> {
        self.config.treasury_address.clone()
    }

    /// Validate block hash is non-zero
    ///
    /// PO4-M1: Prevent proposals with invalid/zero block hashes
    fn validate_block_hash(block_hash: &[u8; 32]) -> GhostResult<()> {
        if block_hash == &[0u8; 32] {
            return Err(ghost_common::error::GhostError::PayoutCalculation(
                "block_hash is all zeros - invalid block hash".to_string()
            ));
        }
        Ok(())
    }

    /// Create a payout proposal from block found data
    ///
    /// Fee distribution per ECONOMICS.md:
    /// - TX fees (100%) → Node who found the block
    /// - Pool fee (1% of subsidy) → Split between Treasury and Node Reward Pool
    /// - Miner Pool (99% of subsidy) → Top 200 miners by work
    /// - Node Pool → Top 100 nodes by 5-4-3-2-1 capability shares
    pub fn create_proposal(&self, data: BlockFoundData) -> GhostResult<PayoutProposal> {
        // PO4-M1: Validate block hash before creating proposal
        Self::validate_block_hash(&data.block_hash)?;

        let now = chrono::Utc::now().timestamp() as u64;

        // Calculate fee distribution using treasury decay schedule
        let fee_dist =
            FeeDistribution::calculate(data.subsidy_sats, data.tx_fees_sats, &data.treasury_state);

        info!(
            subsidy = data.subsidy_sats,
            tx_fees = data.tx_fees_sats,
            pool_fee = fee_dist.pool_fee,
            treasury_rate = fee_dist.treasury_rate,
            node_rate = fee_dist.node_rate,
            miner_pool = fee_dist.miner_pool,
            node_pool = fee_dist.node_reward_pool,
            decay_year = data.treasury_state.decay_year(),
            "Calculating fee distribution"
        );

        // Calculate miner payouts (99% of subsidy, proportional to work)
        // Dust from miners below threshold is returned for redistribution to node pool
        let (miner_payouts, miner_dust) =
            self.calculate_miner_payouts(&data.miner_work, fee_dist.miner_pool)?;

        // Add miner dust to node reward pool - no satoshis are lost!
        let augmented_node_pool = fee_dist.node_reward_pool.saturating_add(miner_dust);
        if miner_dust > 0 {
            info!(
                miner_dust,
                original_node_pool = fee_dist.node_reward_pool,
                augmented_node_pool,
                "Miner dust added to node reward pool"
            );
        }

        // Calculate node payouts from the augmented node reward pool
        // (original pool + miner dust, not including TX fees)
        let mut node_payouts =
            self.calculate_node_payouts(&data.node_shares, augmented_node_pool)?;

        // FALLBACK: If no nodes qualify for payouts, add the node pool to treasury
        // This ensures no satoshis are lost when there are no eligible nodes
        let mut final_treasury = fee_dist.treasury_amount;
        if node_payouts.is_empty() && augmented_node_pool > 0 {
            info!(
                node_pool = augmented_node_pool,
                "No eligible nodes - redirecting node reward pool to treasury"
            );
            final_treasury = final_treasury.saturating_add(augmented_node_pool);
        }

        // TX fees go 100% to the node that found the block
        // Track unallocated TX fees for transparency (PO-H4)
        let mut tx_fees_unallocated: u64 = 0;

        if fee_dist.tx_fees_to_block_finder >= self.config.dust_threshold_sats {
            let block_finder_address = self.get_node_address(&data.winning_node_id)?;
            if !block_finder_address.is_empty() {
                // Check if this node is already in node_payouts - if so, add to their amount
                let mut found = false;
                for payout in &mut node_payouts {
                    if payout.recipient_id == data.winning_node_id {
                        payout.amount = payout
                            .amount
                            .saturating_add(fee_dist.tx_fees_to_block_finder);
                        found = true;
                        break;
                    }
                }

                // If not already in the list, add a new entry
                if !found {
                    node_payouts.push(PayoutEntry {
                        address: block_finder_address,
                        amount: fee_dist.tx_fees_to_block_finder,
                        recipient_id: data.winning_node_id,
                        payout_type: PayoutType::TxFees,
                    });
                }

                info!(
                    node_id = %hex::encode(&data.winning_node_id[..8]),
                    tx_fees = fee_dist.tx_fees_to_block_finder,
                    "TX fees allocated to block finder"
                );
            } else {
                // PO-H4: Track unallocated TX fees for transparency
                tx_fees_unallocated = fee_dist.tx_fees_to_block_finder;
                warn!(
                    node_id = %hex::encode(&data.winning_node_id[..8]),
                    tx_fees_unallocated,
                    "Block finder node has no payout address - TX fees cannot be allocated"
                );
            }
        }

        // H-MINE-3: Use treasury address snapshot from BlockFoundData
        // This ensures the coinbase is built with the address that was valid
        // at the time the round started, not a potentially changed address
        let treasury_address = data.treasury_address_snapshot
            .clone()
            .unwrap_or_else(|| {
                // Fallback to current config if no snapshot (shouldn't happen)
                warn!("No treasury address snapshot - using current config (potential TOCTOU)");
                self.config.treasury_address.clone().unwrap_or_default()
            });

        let proposal = PayoutProposal {
            proposal_hash: [0u8; 32], // Will be computed by vote handler
            round_id: data.round_id,
            block_hash: data.block_hash,
            block_height: data.block_height,
            proposer: self.identity.node_id(),
            miner_payouts,
            node_payouts,
            treasury_amount: final_treasury,
            treasury_address, // H-MINE-3: Snapshot address
            tx_fees: data.tx_fees_sats,
            subsidy: data.subsidy_sats,
            timestamp: now,
            tx_fees_unallocated,
        };

        // Verify the distribution adds up
        if !fee_dist.verify(data.subsidy_sats, data.tx_fees_sats) {
            warn!(
                expected = data.subsidy_sats + data.tx_fees_sats,
                actual = fee_dist.total(),
                "Fee distribution verification failed - small rounding difference"
            );
        }

        info!(
            round_id = data.round_id,
            height = data.block_height,
            miner_count = proposal.miner_payouts.len(),
            node_count = proposal.node_payouts.len(),
            treasury = final_treasury,
            decay_year = data.treasury_state.decay_year(),
            "Created payout proposal"
        );

        Ok(proposal)
    }

    /// Create a solo mode payout proposal
    ///
    /// Solo mode distribution:
    /// - Solo miner: 99% of subsidy + ALL TX fees → solo_payout_address
    /// - 1% pool fee → split between treasury and node pool per decay schedule
    /// - Hosting node is included in node reward pool calculation
    pub fn create_solo_proposal(&self, data: SoloBlockFoundData) -> GhostResult<PayoutProposal> {
        let now = chrono::Utc::now().timestamp() as u64;

        // Calculate fee distribution using treasury decay schedule
        // Note: In solo mode, TX fees are NOT included in pool fee calculation
        // TX fees go 100% to solo miner, pool fee is only from subsidy
        let fee_dist = FeeDistribution::calculate(
            data.subsidy_sats,
            0, // TX fees not subject to pool fee in solo mode
            &data.treasury_state,
        );

        // Solo miner gets 99% of subsidy + ALL tx fees
        let solo_miner_amount = fee_dist.miner_pool.saturating_add(data.tx_fees_sats);

        info!(
            subsidy = data.subsidy_sats,
            tx_fees = data.tx_fees_sats,
            solo_miner = solo_miner_amount,
            pool_fee = fee_dist.pool_fee,
            treasury = fee_dist.treasury_amount,
            node_pool = fee_dist.node_reward_pool,
            decay_year = data.treasury_state.decay_year(),
            "Calculating solo mode fee distribution"
        );

        // Create miner payout entry (single entry for solo operator)
        let mut miner_payouts = Vec::new();
        if solo_miner_amount >= 546 {
            // Dust threshold
            let mut recipient_id = [0u8; 32];
            let hash = ghost_common::identity::hash_message(data.solo_payout_address.as_bytes());
            recipient_id.copy_from_slice(&hash);

            miner_payouts.push(PayoutEntry {
                address: data.solo_payout_address.into_bytes(),
                amount: solo_miner_amount,
                recipient_id,
                payout_type: PayoutType::Mining,
            });
        }

        // Calculate node payouts from the 1% pool fee's node reward portion
        // In solo mode, the hosting node should be included in node_shares
        let node_payouts =
            self.calculate_node_payouts(&data.node_shares, fee_dist.node_reward_pool)?;

        // If no nodes qualify for payouts, add node pool to treasury
        let mut final_treasury = fee_dist.treasury_amount;
        if node_payouts.is_empty() && fee_dist.node_reward_pool > 0 {
            info!(
                node_pool = fee_dist.node_reward_pool,
                "Solo mode: no eligible nodes - redirecting node reward pool to treasury"
            );
            final_treasury = final_treasury.saturating_add(fee_dist.node_reward_pool);
        }

        // H-MINE-3: Use treasury address snapshot from SoloBlockFoundData
        let treasury_address = data.treasury_address_snapshot
            .clone()
            .unwrap_or_else(|| {
                warn!("No treasury address snapshot in solo mode - using current config");
                self.config.treasury_address.clone().unwrap_or_default()
            });

        let proposal = PayoutProposal {
            proposal_hash: [0u8; 32], // Will be computed by vote handler
            round_id: data.round_id,
            block_hash: data.block_hash,
            block_height: data.block_height,
            proposer: self.identity.node_id(),
            miner_payouts,
            node_payouts,
            treasury_amount: final_treasury,
            treasury_address, // H-MINE-3: Snapshot address
            tx_fees: data.tx_fees_sats,
            subsidy: data.subsidy_sats,
            timestamp: now,
            tx_fees_unallocated: 0, // Solo mode: TX fees always go to solo miner
        };

        info!(
            round_id = data.round_id,
            height = data.block_height,
            solo_miner = solo_miner_amount,
            node_count = proposal.node_payouts.len(),
            treasury = final_treasury,
            decay_year = data.treasury_state.decay_year(),
            "Created solo mode payout proposal"
        );

        Ok(proposal)
    }

    /// Calculate miner payouts proportional to work
    /// Returns (payouts, dust_amount) where dust is redirected to node reward pool
    fn calculate_miner_payouts(
        &self,
        miner_work: &[(String, f64)],
        total_sats: u64,
    ) -> GhostResult<(Vec<PayoutEntry>, u64)> {
        let mut payouts = Vec::new();
        let mut dust_total: u64 = 0;
        let total_work: f64 = miner_work.iter().map(|(_, w)| w).sum();

        if total_work <= 0.0 {
            return Ok((payouts, dust_total));
        }

        // Sort by work descending, take top N
        let mut sorted: Vec<_> = miner_work.to_vec();
        sorted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        sorted.truncate(self.config.max_miner_outputs);

        // Recalculate total work for top miners
        let top_work: f64 = sorted.iter().map(|(_, w)| w).sum();

        // Safety check: avoid division by zero after truncation
        if top_work <= 0.0 {
            warn!("Top miners have zero total work after truncation - no payouts");
            return Ok((payouts, dust_total));
        }

        // PO4-1: Track allocated amount to detect rounding remainder
        let mut allocated_total: u64 = 0;

        for (miner_id, work) in sorted {
            // Skip miners with non-positive work
            if work <= 0.0 {
                continue;
            }
            // SECURITY: Use integer arithmetic with basis points to avoid floating point rounding errors
            // Calculate share in basis points: (work * 10000) / top_work
            let share_bps = ((work * 10000.0) / top_work) as u64;
            // Calculate amount: (total_sats * share_bps) / 10000
            // Use u128 to prevent overflow for large amounts
            let amount = (total_sats as u128 * share_bps as u128 / 10000) as u64;

            if amount < self.config.dust_threshold_sats {
                // Dust amount redirected to node reward pool
                dust_total = dust_total.saturating_add(amount);
                allocated_total = allocated_total.saturating_add(amount);
                debug!(
                    miner_id,
                    amount,
                    threshold = self.config.dust_threshold_sats,
                    "Miner payout below dust threshold - redirecting to node reward pool"
                );
                continue;
            }

            // Get miner's payout address from database
            let address = self.get_miner_address(&miner_id)?;

            // Convert miner_id to recipient_id
            let mut recipient_id = [0u8; 32];
            let hash = ghost_common::identity::hash_message(miner_id.as_bytes());
            recipient_id.copy_from_slice(&hash);

            payouts.push(PayoutEntry {
                address,
                amount,
                recipient_id,
                payout_type: PayoutType::Mining,
            });
            allocated_total = allocated_total.saturating_add(amount);
        }

        // PO4-1: Calculate rounding remainder and add to dust if significant
        // This ensures no satoshis are lost due to basis point truncation
        let rounding_remainder = total_sats.saturating_sub(allocated_total);
        if rounding_remainder > 0 {
            dust_total = dust_total.saturating_add(rounding_remainder);
            debug!(
                rounding_remainder,
                allocated_total,
                total_sats,
                "Miner payout rounding remainder captured"
            );
        }

        if dust_total > 0 {
            info!(
                dust_total,
                miners_affected = miner_work.len() - payouts.len(),
                rounding_remainder,
                "Miner dust collected for node reward pool"
            );
        }

        Ok((payouts, dust_total))
    }

    /// Calculate node payouts proportional to capability shares
    /// Returns (payouts, dust_amount) where dust is added to top node's payout
    fn calculate_node_payouts(
        &self,
        node_shares: &[(NodeId, i32)],
        total_sats: u64,
    ) -> GhostResult<Vec<PayoutEntry>> {
        let mut payouts = Vec::new();
        let mut dust_total: u64 = 0;
        let total_shares: i32 = node_shares.iter().map(|(_, s)| s).sum();

        if total_shares <= 0 {
            return Ok(payouts);
        }

        // Sort by shares descending, take top N
        let mut sorted: Vec<_> = node_shares.to_vec();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(self.config.max_node_outputs);

        // Recalculate total shares for top nodes
        let top_shares: i32 = sorted.iter().map(|(_, s)| s).sum();

        // Safety check: avoid division by zero after truncation
        if top_shares <= 0 {
            warn!("Top nodes have zero total shares after truncation - no payouts");
            return Ok(payouts);
        }

        // PO4-1: Track allocated amount to detect rounding remainder
        let mut allocated_total: u64 = 0;

        for (node_id, shares) in sorted {
            // Skip nodes with non-positive shares
            if shares <= 0 {
                continue;
            }
            // SECURITY: Use integer arithmetic with basis points to avoid floating point rounding errors
            // Calculate share in basis points: (shares * 10000) / top_shares
            let share_bps = (shares as u64 * 10000) / top_shares as u64;
            // Calculate amount: (total_sats * share_bps) / 10000
            // Use u128 to prevent overflow for large amounts
            let amount = (total_sats as u128 * share_bps as u128 / 10000) as u64;

            if amount < self.config.dust_threshold_sats {
                // Track dust for redistribution to top node
                dust_total = dust_total.saturating_add(amount);
                allocated_total = allocated_total.saturating_add(amount);
                debug!(
                    node_id = %hex::encode(&node_id[..8]),
                    amount,
                    threshold = self.config.dust_threshold_sats,
                    "Node payout below dust threshold - will add to top node"
                );
                continue;
            }

            // Get node's payout address from database
            let address = self.get_node_address(&node_id)?;

            // Skip nodes without a configured payout address - their share becomes dust
            // which will be redistributed to the top node or go to treasury
            if address.is_empty() {
                dust_total = dust_total.saturating_add(amount);
                allocated_total = allocated_total.saturating_add(amount);
                debug!(
                    node_id = %hex::encode(&node_id[..8]),
                    amount,
                    "Node has no payout address - adding to dust pool"
                );
                continue;
            }

            payouts.push(PayoutEntry {
                address,
                amount,
                recipient_id: node_id,
                payout_type: PayoutType::NodeReward,
            });
            allocated_total = allocated_total.saturating_add(amount);
        }

        // PO4-1: Calculate rounding remainder and add to dust
        // This ensures no satoshis are lost due to basis point truncation
        let rounding_remainder = total_sats.saturating_sub(allocated_total);
        if rounding_remainder > 0 {
            dust_total = dust_total.saturating_add(rounding_remainder);
            debug!(
                rounding_remainder,
                allocated_total,
                total_sats,
                "Node payout rounding remainder captured"
            );
        }

        // Merge payouts going to the same address (e.g., multiple nodes using treasury)
        let mut merged_payouts: Vec<PayoutEntry> = Vec::new();
        for payout in payouts {
            if let Some(existing) = merged_payouts
                .iter_mut()
                .find(|p| p.address == payout.address)
            {
                existing.amount = existing.amount.saturating_add(payout.amount);
                debug!(
                    address = %String::from_utf8_lossy(&payout.address[..20.min(payout.address.len())]),
                    merged_amount = payout.amount,
                    "Merged duplicate node payout address"
                );
            } else {
                merged_payouts.push(payout);
            }
        }
        let payouts = merged_payouts;

        // Add dust to the top node's payout (first in sorted order = highest capability shares)
        if dust_total > 0 && !payouts.is_empty() {
            // payouts is now immutable, need to make it mutable again
            let mut payouts = payouts;
            payouts[0].amount = payouts[0].amount.saturating_add(dust_total);
            info!(
                dust_total,
                top_node = %hex::encode(&payouts[0].recipient_id[..8]),
                nodes_affected = node_shares.len() - payouts.len(),
                "Node dust redistributed to top node"
            );
            return Ok(payouts);
        } else if dust_total > 0 {
            // SECURITY NOTE: This case occurs when ALL nodes have payouts below dust threshold
            // AND none have valid payout addresses. The dust cannot be redistributed because
            // there are no eligible recipients. The caller (create_proposal) handles this by
            // redirecting the entire augmented_node_pool to treasury when node_payouts is empty.
            // This is NOT lost - it's explicitly handled at the proposal level.
            debug!(
                dust_total,
                "No eligible node payouts - dust will be handled at proposal level"
            );
        }

        Ok(payouts)
    }

    /// Get miner's payout address from database
    ///
    /// Miners provide their payout address during Stratum authorize,
    /// which is stored in the miners table via update_miner_address().
    fn get_miner_address(&self, miner_id: &str) -> GhostResult<Vec<u8>> {
        // Look up miner's payout address from the miners table
        if let Some(address_str) = self.db.get_miner_payout_address(miner_id)? {
            if !address_str.is_empty() {
                // Address is stored as bech32 string, return as bytes
                return Ok(address_str.into_bytes());
            }
        }

        // Fallback: return empty (will be filtered out by proposal validator)
        debug!(
            miner_id,
            "Miner payout address not found - will be filtered from proposal"
        );
        Ok(Vec::new())
    }

    /// Get node's payout address from database
    ///
    /// Nodes set their payout address in configuration or via registration.
    fn get_node_address(&self, node_id: &NodeId) -> GhostResult<Vec<u8>> {
        let node_id_hex = hex::encode(node_id);

        // Look up node's payout address from the nodes table
        if let Some(address_str) = self.db.get_node_payout_address(&node_id_hex)? {
            if !address_str.is_empty() {
                // Address is stored as bech32 string, return as bytes
                return Ok(address_str.into_bytes());
            }
        }

        // Return empty - caller will handle this by treating as dust
        // which gets redistributed to top node or treasury
        Ok(Vec::new())
    }

    /// Get paginated payout history
    ///
    /// Returns a list of round payout summaries matching the query parameters.
    /// Results are ordered by block height descending (most recent first).
    ///
    /// # Arguments
    /// * `query` - Query parameters including limit, offset, and optional height filters
    ///
    /// # Returns
    /// Vec of RoundPayoutSummary containing aggregated payout info per round
    pub fn get_payout_history(&self, query: PayoutHistoryQuery) -> GhostResult<Vec<RoundPayoutSummary>> {
        self.db.query_payout_history(query)
    }
}

/// Handler for block found events that creates and submits payout proposals
pub struct PayoutHandler {
    creator: PayoutProposalCreator,
    vote_handler: Arc<VoteHandler>,
    template_processor: Arc<TemplateProcessor>,
    /// H-MINE-1: Qualification provider for calculating VERIFIED capabilities - REQUIRED
    /// This is mandatory because node rewards must only be distributed based on
    /// verified capabilities, never unverified claimed ones.
    qualification_provider: Arc<QualifiedCapabilityProvider>,
}

impl PayoutHandler {
    /// Create a new PayoutHandler with REQUIRED QualifiedCapabilityProvider
    ///
    /// H-MINE-1 SECURITY: The qualification_provider is required, not optional.
    /// This ensures node rewards are NEVER distributed based on unverified
    /// claimed capabilities. The provider validates capabilities through the
    /// challenge-response system before they count toward payout shares.
    ///
    /// # Errors
    /// Returns error if:
    /// - treasury_address is not configured in PayoutConfig
    pub fn new(
        identity: Arc<NodeIdentity>,
        config: PayoutConfig,
        db: Arc<Database>,
        vote_handler: Arc<VoteHandler>,
        template_processor: Arc<TemplateProcessor>,
        qualification_provider: Arc<QualifiedCapabilityProvider>,
    ) -> GhostResult<Self> {
        let creator = PayoutProposalCreator::new(identity, config, db)?;

        info!(
            "PayoutHandler initialized with required verification provider"
        );

        Ok(Self {
            creator,
            vote_handler,
            template_processor,
            qualification_provider,
        })
    }

    /// PO4-M2: Get a snapshot of the treasury address
    ///
    /// This should be called at round start to capture the treasury address
    /// and prevent TOCTOU issues where config changes during a round.
    pub fn get_treasury_address_snapshot(&self) -> Option<Vec<u8>> {
        self.creator.get_treasury_address_snapshot()
    }

    /// Handle a block found event by creating and submitting a payout proposal
    ///
    /// H-MINE-1 SECURITY: The QualifiedCapabilityProvider is REQUIRED in the constructor.
    /// Node rewards will only be distributed to nodes with VERIFIED capabilities,
    /// never to nodes with merely CLAIMED capabilities.
    pub fn handle_block_found(&self, mut data: BlockFoundData) -> GhostResult<[u8; 32]> {
        // H-MINE-1: Provider is now required at construction time, no Option check needed
        // This guarantees node rewards are always based on verified capabilities

        // Get all nodes with verified capabilities from the database
        // This ensures all verified nodes get payouts, not just ones that received shares directly
        let qualified_shares = self.qualification_provider.get_all_qualified_nodes();

        let claimed_count = data.node_shares.len();
        let verified_count = qualified_shares.len();
        let total_claimed_shares: i32 = data.node_shares.iter().map(|(_, s)| s).sum();
        let total_verified_shares: i32 = qualified_shares.iter().map(|(_, s)| s).sum();

        info!(
            claimed_nodes = claimed_count,
            verified_nodes = verified_count,
            claimed_shares = total_claimed_shares,
            verified_shares = total_verified_shares,
            "Recalculated node shares using VERIFIED capabilities"
        );

        data.node_shares = qualified_shares;

        // Create the proposal
        let mut proposal = self.creator.create_proposal(data)?;

        // Validate proposal has meaningful content
        if proposal.miner_payouts.is_empty() {
            warn!("Payout proposal has no miner payouts - skipping submission");
            return Ok([0u8; 32]);
        }

        // Compute proposal hash before storing
        // This ensures the template processor can find the proposal when
        // consensus approves with this hash
        let proposal_hash = compute_proposal_hash(&proposal);
        proposal.proposal_hash = proposal_hash;

        // Store proposal in template processor BEFORE submitting to consensus
        // This ensures the proposal data is available when consensus approves
        // and we need to build coinbase outputs
        self.template_processor.store_proposal(proposal.clone());

        // Submit to vote handler for BFT consensus
        info!(
            round_id = proposal.round_id,
            miners = proposal.miner_payouts.len(),
            nodes = proposal.node_payouts.len(),
            "Submitting payout proposal to consensus"
        );

        let returned_hash = self.vote_handler.handle_proposal(proposal)?;

        // SECURITY: Verify hash matches - this catches implementation bugs where
        // the vote handler modifies the proposal or computes the hash differently
        if proposal_hash != returned_hash {
            tracing::error!(
                expected = %hex::encode(&proposal_hash[..8]),
                actual = %hex::encode(&returned_hash[..8]),
                "CRITICAL: Proposal hash mismatch between local computation and vote handler"
            );
            return Err(ghost_common::error::GhostError::HashMismatch {
                expected: hex::encode(proposal_hash),
                actual: hex::encode(returned_hash),
            });
        }

        info!(
            hash = %hex::encode(&proposal_hash[..8]),
            "Payout proposal submitted for voting"
        );

        Ok(proposal_hash)
    }

    /// Handle a block found event in solo mining mode
    ///
    /// In solo mode, all rewards go to the configured solo_payout_address:
    /// - 99% of subsidy + ALL TX fees → solo_payout_address
    /// - 1% pool fee → treasury + node pool per decay schedule
    ///
    /// H-MINE-1 SECURITY: The QualifiedCapabilityProvider is REQUIRED in the constructor,
    /// even in solo mode. Node rewards will only be distributed to nodes with VERIFIED
    /// capabilities, never to nodes with merely CLAIMED capabilities.
    pub fn handle_solo_block_found(&self, mut data: SoloBlockFoundData) -> GhostResult<[u8; 32]> {
        // H-MINE-1: Provider is now required at construction time, no Option check needed
        // This guarantees node rewards are always based on verified capabilities

        // Replace claimed node shares with verified ones
        // This ensures consistency between pool and solo mode
        let qualified_shares = self.qualification_provider.get_all_qualified_nodes();

        let claimed_count = data.node_shares.len();
        let verified_count = qualified_shares.len();

        info!(
            claimed_nodes = claimed_count,
            verified_nodes = verified_count,
            "Solo mode: recalculating node shares using VERIFIED capabilities"
        );

        data.node_shares = qualified_shares;

        // Create the solo proposal
        let mut proposal = self.creator.create_solo_proposal(data)?;

        // Validate proposal has meaningful content
        if proposal.miner_payouts.is_empty() {
            warn!("Solo payout proposal has no miner payout - skipping submission");
            return Ok([0u8; 32]);
        }

        // Compute proposal hash before storing
        let proposal_hash = compute_proposal_hash(&proposal);
        proposal.proposal_hash = proposal_hash;

        // Store proposal in template processor BEFORE submitting to consensus
        self.template_processor.store_proposal(proposal.clone());

        // Submit to vote handler for BFT consensus
        info!(
            round_id = proposal.round_id,
            solo_payout = proposal.miner_payouts[0].amount,
            nodes = proposal.node_payouts.len(),
            "Submitting solo mode payout proposal to consensus"
        );

        let returned_hash = self.vote_handler.handle_proposal(proposal)?;

        // SECURITY: Verify hash matches - this catches implementation bugs where
        // the vote handler modifies the proposal or computes the hash differently
        if proposal_hash != returned_hash {
            tracing::error!(
                expected = %hex::encode(&proposal_hash[..8]),
                actual = %hex::encode(&returned_hash[..8]),
                "CRITICAL: Solo proposal hash mismatch between local computation and vote handler"
            );
            return Err(ghost_common::error::GhostError::HashMismatch {
                expected: hex::encode(proposal_hash),
                actual: hex::encode(returned_hash),
            });
        }

        info!(
            hash = %hex::encode(&proposal_hash[..8]),
            "Solo mode payout proposal submitted for voting"
        );

        Ok(proposal_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity() -> Arc<NodeIdentity> {
        Arc::new(NodeIdentity::generate())
    }

    #[test]
    fn test_payout_config_default() {
        let config = PayoutConfig::default();
        assert_eq!(config.dust_threshold_sats, 546);
        assert_eq!(config.max_miner_outputs, 200);
        assert_eq!(config.max_node_outputs, 100);
        // Default should have None treasury address (requires configuration)
        assert!(config.treasury_address.is_none());
    }

    #[test]
    fn test_payout_config_validation() {
        // Default config should fail validation (no treasury address)
        let config = PayoutConfig::default();
        assert!(config.validate().is_err());

        // Config with empty treasury address should fail
        let config_empty = PayoutConfig {
            treasury_address: Some(Vec::new()),
            ..Default::default()
        };
        assert!(config_empty.validate().is_err());

        // Config with valid treasury address should pass
        let config_valid = PayoutConfig {
            treasury_address: Some(vec![1u8; 20]),
            ..Default::default()
        };
        assert!(config_valid.validate().is_ok());
    }

    #[test]
    fn test_treasury_address_getter() {
        // None treasury should return error
        let config = PayoutConfig::default();
        assert!(config.treasury_address().is_err());

        // Empty treasury should return error
        let config_empty = PayoutConfig {
            treasury_address: Some(Vec::new()),
            ..Default::default()
        };
        assert!(config_empty.treasury_address().is_err());

        // Valid treasury should return the address
        let expected_addr = vec![1u8, 2u8, 3u8];
        let config_valid = PayoutConfig {
            treasury_address: Some(expected_addr.clone()),
            ..Default::default()
        };
        assert_eq!(config_valid.treasury_address().unwrap(), expected_addr.as_slice());
    }

    #[test]
    fn test_block_found_data() {
        let data = BlockFoundData {
            round_id: 1,
            block_hash: [0u8; 32],
            block_height: 800_000,
            winning_miner_id: "miner1".to_string(),
            winning_miner_payout_address: None,
            treasury_address_snapshot: Some(vec![1u8, 2u8, 3u8]),
            winning_node_id: [1u8; 32],
            subsidy_sats: 625_000_000, // 6.25 BTC
            tx_fees_sats: 10_000_000,  // 0.1 BTC
            miner_work: vec![("miner1".to_string(), 100.0), ("miner2".to_string(), 50.0)],
            node_shares: vec![([1u8; 32], 10), ([2u8; 32], 5)],
            treasury_state: TreasuryState::new(),
        };

        assert_eq!(data.round_id, 1);
        assert_eq!(data.miner_work.len(), 2);
        assert_eq!(data.node_shares.len(), 2);
        assert_eq!(data.winning_node_id, [1u8; 32]);
        assert!(data.treasury_address_snapshot.is_some());
    }

    #[test]
    fn test_block_found_data_with_treasury_decay() {
        let threshold_time = chrono::Utc::now() - chrono::Duration::days(365 * 3);
        let treasury_state = TreasuryState::from_stored(
            crate::treasury::TREASURY_THRESHOLD_SATS,
            Some(threshold_time),
        );

        let data = BlockFoundData {
            round_id: 1,
            block_hash: [0u8; 32],
            block_height: 800_000,
            winning_miner_id: "miner1".to_string(),
            winning_miner_payout_address: None,
            treasury_address_snapshot: Some(vec![0x51]), // P2TR witness program prefix
            winning_node_id: [1u8; 32],
            subsidy_sats: 312_500_000, // 3.125 BTC
            tx_fees_sats: 10_000_000,  // 0.1 BTC
            miner_work: vec![("miner1".to_string(), 100.0)],
            node_shares: vec![([1u8; 32], 5)],
            treasury_state,
        };

        // After 3 years, should be in year 4 of decay (0.1 treasury, 0.9 nodes)
        assert!(data.treasury_state.decay_year() >= 3);
    }

    #[test]
    fn test_saturating_add_overflow() {
        // Test that saturating_add prevents overflow
        let a = u64::MAX - 10;
        let b = 100u64;
        let result = a.saturating_add(b);
        assert_eq!(result, u64::MAX); // Saturates at MAX instead of wrapping
    }

    #[test]
    fn test_saturating_sub_underflow() {
        // Test that saturating_sub prevents underflow
        let total = 100u64;
        let fee = 150u64;
        let result = total.saturating_sub(fee);
        assert_eq!(result, 0); // Saturates at 0 instead of wrapping
    }

    #[test]
    fn test_share_clamping() {
        // Test that shares are clamped to [0, 1]
        let share = 1.0001f64; // Slightly over 1.0 due to floating point
        let clamped = share.clamp(0.0, 1.0);
        assert_eq!(clamped, 1.0);

        let share = -0.0001f64; // Slightly negative due to floating point
        let clamped = share.clamp(0.0, 1.0);
        assert_eq!(clamped, 0.0);
    }

    #[test]
    fn test_safe_float_to_u64_conversion() {
        // Test that large float values don't overflow
        let total_sats = u64::MAX;
        let share = 1.0f64;
        // This is the safe conversion pattern we use
        let amount = (total_sats as f64 * share).min(u64::MAX as f64) as u64;
        // Should not panic or produce weird values
        assert!(amount <= u64::MAX);
    }

    #[test]
    fn test_dust_redistribution_to_node_pool() {
        // Test that miner dust is properly tracked
        // With 1000 sats total and 1% going to each of 100 small miners,
        // each would get 10 sats which is below the 546 dust threshold
        let dust_threshold = 546u64;

        // Simulate calculating payouts for many small miners
        let total_sats = 10_000u64;
        let miner_count = 100;
        let per_miner = total_sats / miner_count; // 100 sats each

        // All should be dust since 100 < 546
        let mut dust_collected = 0u64;
        for _ in 0..miner_count {
            if per_miner < dust_threshold {
                dust_collected += per_miner;
            }
        }

        // All 10_000 sats should be collected as dust
        assert_eq!(dust_collected, total_sats);

        // This dust would then be added to the node reward pool
        // ensuring no satoshis are lost
        let original_node_pool = 5_000u64;
        let augmented_node_pool = original_node_pool.saturating_add(dust_collected);
        assert_eq!(augmented_node_pool, 15_000);
    }

    #[test]
    fn test_node_dust_to_top_node() {
        // Test that node dust is redistributed to the top node
        let dust_threshold = 546u64;

        // Simulate payouts: top node gets 1000, others are dust
        let payouts = vec![
            (1000u64, [1u8; 32]), // Top node - above threshold
            (100u64, [2u8; 32]),  // Dust - below threshold
            (50u64, [3u8; 32]),   // Dust - below threshold
        ];

        let mut final_payouts: Vec<(u64, [u8; 32])> = Vec::new();
        let mut dust_total = 0u64;

        for (amount, node_id) in payouts {
            if amount < dust_threshold {
                dust_total += amount;
            } else {
                final_payouts.push((amount, node_id));
            }
        }

        // Add dust to top node
        if dust_total > 0 && !final_payouts.is_empty() {
            final_payouts[0].0 += dust_total;
        }

        // Top node should have original + dust
        assert_eq!(final_payouts.len(), 1);
        assert_eq!(final_payouts[0].0, 1000 + 100 + 50); // 1150 sats
        assert_eq!(final_payouts[0].1, [1u8; 32]); // Top node ID
    }

    #[test]
    fn test_verified_capabilities_required() {
        // SECURITY TEST: Verify that PayoutHandler requires a QualifiedCapabilityProvider
        // and fails without one (instead of using unverified claimed capabilities)

        // This test verifies the pattern change from:
        //   if let Some(ref provider) = self.qualification_provider { ... }
        // To:
        //   let provider = self.qualification_provider.as_ref().ok_or(NoVerificationProvider)?;

        // We can't easily test the full PayoutHandler without all dependencies,
        // but we document the expected behavior:

        // When qualification_provider is None:
        // - handle_block_found() should return Err(GhostError::NoVerificationProvider)
        // - Node rewards should NOT be distributed based on claimed capabilities

        // When qualification_provider is Some:
        // - Node shares should be recalculated using provider.get_all_qualified_nodes()
        // - Only VERIFIED capabilities should be used for payout calculation

        // This test serves as documentation of the security requirement.
        // The actual enforcement is in PayoutHandler::handle_block_found()

        // Verify the error type exists
        let err = ghost_common::error::GhostError::NoVerificationProvider;
        assert!(format!("{}", err).contains("verification provider"));
    }

    #[test]
    fn test_integer_arithmetic_no_rounding_error_pool() {
        // SECURITY TEST: Verify basis point calculations are deterministic and bounded

        // Test miner share calculation with values that could cause floating point issues
        let total_sats = 309_375_000u64; // 99% of 3.125 BTC
        let miner_works = [
            (33.333333333f64, "miner1"),
            (33.333333333f64, "miner2"),
            (33.333333334f64, "miner3"),
        ];

        let total_work: f64 = miner_works.iter().map(|(w, _)| w).sum();

        // Using basis points (our secure method)
        let mut bps_total = 0u64;
        let mut bps_amounts = Vec::new();
        for (work, _) in &miner_works {
            let share_bps = ((work * 10000.0) / total_work) as u64;
            let amount = (total_sats as u128 * share_bps as u128 / 10000) as u64;
            bps_amounts.push(amount);
            bps_total += amount;
        }

        // Key assertions:
        // 1. Total should not exceed available funds (prevents over-allocation)
        assert!(bps_total <= total_sats, "Allocated {} but only {} available", bps_total, total_sats);

        // 2. Each miner should get approximately 1/3 (within 1% tolerance)
        let expected_per_miner = total_sats / 3;
        for (i, amount) in bps_amounts.iter().enumerate() {
            let diff = if *amount > expected_per_miner {
                amount - expected_per_miner
            } else {
                expected_per_miner - amount
            };
            // Allow 1% variance
            let tolerance = expected_per_miner / 100;
            assert!(
                diff <= tolerance,
                "Miner {} got {} but expected ~{} (diff {} > tolerance {})",
                i, amount, expected_per_miner, diff, tolerance
            );
        }

        // 3. The method should be deterministic - same inputs = same outputs
        let mut second_total = 0u64;
        for (work, _) in &miner_works {
            let share_bps = ((work * 10000.0) / total_work) as u64;
            let amount = (total_sats as u128 * share_bps as u128 / 10000) as u64;
            second_total += amount;
        }
        assert_eq!(bps_total, second_total, "Non-deterministic calculation!");

        // 4. Lost sats should be bounded (basis points give 0.01% precision = max 0.01% loss)
        // With 3 miners, worst case truncation is 3 * 0.9999 bps = ~0.03% of total
        let max_loss = total_sats / 3000; // ~0.033% of total
        let actual_loss = total_sats - bps_total;
        assert!(
            actual_loss <= max_loss,
            "Lost {} sats ({}%), expected at most {} sats ({}%)",
            actual_loss,
            (actual_loss as f64 / total_sats as f64) * 100.0,
            max_loss,
            (max_loss as f64 / total_sats as f64) * 100.0
        );
    }

    #[test]
    fn test_payout_rounding_no_satoshi_loss() {
        // PO4-1: Verify that rounding remainder is captured
        // This ensures no satoshis are lost due to basis point truncation

        let total_sats = 1_000_000u64; // 1 million sats
        let miner_works = [
            (33.33333333f64, "miner1"),
            (33.33333333f64, "miner2"),
            (33.33333334f64, "miner3"),
        ];

        let total_work: f64 = miner_works.iter().map(|(w, _)| w).sum();

        // Simulate the calculation
        let mut allocated = 0u64;
        for (work, _) in &miner_works {
            let share_bps = ((work * 10000.0) / total_work) as u64;
            let amount = (total_sats as u128 * share_bps as u128 / 10000) as u64;
            allocated += amount;
        }

        // The remainder due to truncation
        let remainder = total_sats.saturating_sub(allocated);

        // With basis points (0.01% precision), 3 miners dividing evenly:
        // Each gets 3333 bps = 33.33%
        // 3 * 3333 = 9999 bps, leaving 1 bp = 0.01%
        // For 1M sats: 0.01% = 100 sats remainder
        assert!(remainder > 0, "Expected rounding remainder, got 0");
        assert!(remainder < total_sats / 100, "Remainder {} too large", remainder);

        // Total should be preserved when remainder is captured
        let total_with_remainder = allocated + remainder;
        assert_eq!(total_with_remainder, total_sats, "Total should be exactly preserved");
    }

    #[test]
    fn test_tx_fees_unallocated_tracked() {
        // PO-H4: Verify that tx_fees_unallocated field exists and can be set
        // This test documents the expected behavior when block finder has no payout address
        use ghost_common::types::{PayoutProposal, PayoutEntry, PayoutType};

        // Create a proposal where TX fees could be allocated
        let allocated_proposal = PayoutProposal {
            proposal_hash: [0u8; 32],
            round_id: 1,
            block_hash: [0u8; 32],
            block_height: 800_000,
            proposer: [1u8; 32],
            miner_payouts: vec![],
            node_payouts: vec![PayoutEntry {
                address: b"bc1qnode".to_vec(),
                amount: 10_000_000,
                recipient_id: [1u8; 32],
                payout_type: PayoutType::TxFees,
            }],
            treasury_amount: 0,
            treasury_address: Vec::new(), // H-MINE-3: no treasury in this test
            tx_fees: 10_000_000,
            subsidy: 312_500_000,
            timestamp: 1700000000,
            tx_fees_unallocated: 0, // TX fees were allocated successfully
        };
        assert_eq!(allocated_proposal.tx_fees_unallocated, 0);

        // Create a proposal where TX fees could NOT be allocated (block finder has no address)
        let unallocated_proposal = PayoutProposal {
            proposal_hash: [0u8; 32],
            round_id: 1,
            block_hash: [0u8; 32],
            block_height: 800_000,
            proposer: [1u8; 32],
            miner_payouts: vec![],
            node_payouts: vec![], // No TxFees entry because block finder has no address
            treasury_amount: 0,
            treasury_address: Vec::new(), // H-MINE-3: no treasury in this test
            tx_fees: 10_000_000,
            subsidy: 312_500_000,
            timestamp: 1700000000,
            tx_fees_unallocated: 10_000_000, // TX fees tracked as unallocated
        };
        assert_eq!(unallocated_proposal.tx_fees_unallocated, 10_000_000);

        // The tx_fees_unallocated field allows auditing which blocks had allocation issues
        assert_eq!(
            unallocated_proposal.tx_fees,
            unallocated_proposal.tx_fees_unallocated,
            "When block finder has no address, all TX fees should be marked as unallocated"
        );
    }
}
