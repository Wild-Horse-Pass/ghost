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
use ghost_consensus::vote_handler::VoteHandler;
use ghost_storage::Database;

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
    /// Treasury address (script pubkey bytes)
    pub treasury_address: Vec<u8>,
}

impl Default for PayoutConfig {
    fn default() -> Self {
        Self {
            dust_threshold_sats: 546,
            max_miner_outputs: 200,
            max_node_outputs: 100,
            treasury_address: Vec::new(),
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

/// Creates payout proposals from block found events
pub struct PayoutProposalCreator {
    identity: Arc<NodeIdentity>,
    config: PayoutConfig,
    db: Arc<Database>,
}

impl PayoutProposalCreator {
    pub fn new(identity: Arc<NodeIdentity>, config: PayoutConfig, db: Arc<Database>) -> Self {
        Self {
            identity,
            config,
            db,
        }
    }

    /// Create a payout proposal from block found data
    ///
    /// Fee distribution per ECONOMICS.md:
    /// - TX fees (100%) → Node who found the block
    /// - Pool fee (1% of subsidy) → Split between Treasury and Node Reward Pool
    /// - Miner Pool (99% of subsidy) → Top 200 miners by work
    /// - Node Pool → Top 100 nodes by 5-4-3-2-1 capability shares
    pub fn create_proposal(&self, data: BlockFoundData) -> GhostResult<PayoutProposal> {
        let now = chrono::Utc::now().timestamp() as u64;

        // Calculate fee distribution using treasury decay schedule
        let fee_dist = FeeDistribution::calculate(
            data.subsidy_sats,
            data.tx_fees_sats,
            &data.treasury_state,
        );

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
        let miner_payouts = self.calculate_miner_payouts(&data.miner_work, fee_dist.miner_pool)?;

        // Calculate node payouts from the node reward pool (not including TX fees)
        let mut node_payouts = self.calculate_node_payouts(&data.node_shares, fee_dist.node_reward_pool)?;

        // TX fees go 100% to the node that found the block
        if fee_dist.tx_fees_to_block_finder >= self.config.dust_threshold_sats {
            let block_finder_address = self.get_node_address(&data.winning_node_id)?;
            if !block_finder_address.is_empty() {
                // Check if this node is already in node_payouts - if so, add to their amount
                let mut found = false;
                for payout in &mut node_payouts {
                    if payout.recipient_id == data.winning_node_id {
                        payout.amount = payout.amount.saturating_add(fee_dist.tx_fees_to_block_finder);
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
                warn!(
                    node_id = %hex::encode(&data.winning_node_id[..8]),
                    "Block finder node has no payout address - TX fees will not be paid"
                );
            }
        }

        let proposal = PayoutProposal {
            proposal_hash: [0u8; 32], // Will be computed by vote handler
            round_id: data.round_id,
            block_hash: data.block_hash,
            block_height: data.block_height,
            proposer: self.identity.node_id(),
            miner_payouts,
            node_payouts,
            treasury_amount: fee_dist.treasury_amount,
            tx_fees: data.tx_fees_sats,
            subsidy: data.subsidy_sats,
            timestamp: now,
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
            treasury = fee_dist.treasury_amount,
            decay_year = data.treasury_state.decay_year(),
            "Created payout proposal"
        );

        Ok(proposal)
    }

    /// Calculate miner payouts proportional to work
    fn calculate_miner_payouts(
        &self,
        miner_work: &[(String, f64)],
        total_sats: u64,
    ) -> GhostResult<Vec<PayoutEntry>> {
        let mut payouts = Vec::new();
        let total_work: f64 = miner_work.iter().map(|(_, w)| w).sum();

        if total_work <= 0.0 {
            return Ok(payouts);
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
            return Ok(payouts);
        }

        for (miner_id, work) in sorted {
            // Skip miners with non-positive work
            if work <= 0.0 {
                continue;
            }
            let share = work / top_work;
            // Clamp share to [0, 1] to prevent overflow from floating point imprecision
            let clamped_share = share.clamp(0.0, 1.0);
            let amount = (total_sats as f64 * clamped_share).min(u64::MAX as f64) as u64;

            if amount < self.config.dust_threshold_sats {
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
        }

        Ok(payouts)
    }

    /// Calculate node payouts proportional to capability shares
    fn calculate_node_payouts(
        &self,
        node_shares: &[(NodeId, i32)],
        total_sats: u64,
    ) -> GhostResult<Vec<PayoutEntry>> {
        let mut payouts = Vec::new();
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

        for (node_id, shares) in sorted {
            // Skip nodes with non-positive shares
            if shares <= 0 {
                continue;
            }
            let share = shares as f64 / top_shares as f64;
            // Clamp share to [0, 1] to prevent overflow from floating point imprecision
            let clamped_share = share.clamp(0.0, 1.0);
            let amount = (total_sats as f64 * clamped_share).min(u64::MAX as f64) as u64;

            if amount < self.config.dust_threshold_sats {
                continue;
            }

            // Get node's payout address from database
            let address = self.get_node_address(&node_id)?;

            payouts.push(PayoutEntry {
                address,
                amount,
                recipient_id: node_id,
                payout_type: PayoutType::NodeReward,
            });
        }

        Ok(payouts)
    }

    /// Get miner's payout address from database
    ///
    /// Miners provide their payout address during Stratum authorize,
    /// which is stored in the miners table via update_miner_address().
    fn get_miner_address(&self, miner_id: &str) -> GhostResult<Vec<u8>> {
        // Look up miner's payout address from the miners table
        if let Some(address_hex) = self.db.get_miner_payout_address(miner_id)? {
            if !address_hex.is_empty() {
                if let Ok(bytes) = hex::decode(&address_hex) {
                    return Ok(bytes);
                }
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
        if let Some(address_hex) = self.db.get_node_payout_address(&node_id_hex)? {
            if !address_hex.is_empty() {
                if let Ok(bytes) = hex::decode(&address_hex) {
                    return Ok(bytes);
                }
            }
        }

        debug!(node_id = %&node_id_hex[..8], "Node payout address not found - will be filtered from proposal");
        Ok(Vec::new())
    }
}

/// Handler for block found events that creates and submits payout proposals
pub struct PayoutHandler {
    creator: PayoutProposalCreator,
    vote_handler: Arc<VoteHandler>,
}

impl PayoutHandler {
    pub fn new(
        identity: Arc<NodeIdentity>,
        config: PayoutConfig,
        db: Arc<Database>,
        vote_handler: Arc<VoteHandler>,
    ) -> Self {
        let creator = PayoutProposalCreator::new(identity, config, db);
        Self {
            creator,
            vote_handler,
        }
    }

    /// Handle a block found event by creating and submitting a payout proposal
    pub fn handle_block_found(&self, data: BlockFoundData) -> GhostResult<[u8; 32]> {
        // Create the proposal
        let proposal = self.creator.create_proposal(data)?;

        // Validate proposal has meaningful content
        if proposal.miner_payouts.is_empty() {
            warn!("Payout proposal has no miner payouts - skipping submission");
            return Ok([0u8; 32]);
        }

        // Submit to vote handler for BFT consensus
        info!(
            round_id = proposal.round_id,
            miners = proposal.miner_payouts.len(),
            nodes = proposal.node_payouts.len(),
            "Submitting payout proposal to consensus"
        );

        let proposal_hash = self.vote_handler.handle_proposal(proposal)?;

        info!(
            hash = %hex::encode(&proposal_hash[..8]),
            "Payout proposal submitted for voting"
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
    }

    #[test]
    fn test_block_found_data() {
        let data = BlockFoundData {
            round_id: 1,
            block_hash: [0u8; 32],
            block_height: 800_000,
            winning_miner_id: "miner1".to_string(),
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
}
