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
//| FILE: shares.rs                                                                                                      |
//|======================================================================================================================|

//! Share accounting for mining rewards

use std::collections::HashMap;
use tracing::{debug, error, trace};

use ghost_common::types::{NodeCapabilities, NodeId, RoundId};

/// Work scaling factor for integer arithmetic (H7 security fix)
/// Using 10^12 gives 12 decimal places of precision while fitting in u128
pub const WORK_SCALE: u128 = 1_000_000_000_000;

/// Share accounting for a round
///
/// H7 security fix: Work values are stored as scaled u128 internally
/// to prevent floating-point precision errors that could benefit attackers.
/// External APIs still accept f64 for compatibility but convert immediately.
#[derive(Debug, Clone, Default)]
pub struct RoundShares {
    /// Round ID
    pub round_id: RoundId,
    /// Block height
    pub block_height: u64,
    /// Miner shares (miner_id -> scaled work as u128)
    miner_shares_scaled: HashMap<String, u128>,
    /// Miner shares (miner_id -> work) - f64 view for compatibility
    pub miner_shares: HashMap<String, f64>,
    /// Node shares (node_id -> capability shares)
    pub node_shares: HashMap<NodeId, NodeShareInfo>,
    /// Total miner work (scaled as u128)
    total_miner_work_scaled: u128,
    /// Total miner work - f64 view for compatibility
    pub total_miner_work: f64,
    /// Total node capability shares
    pub total_node_shares: i32,
}

/// Node share information
#[derive(Debug, Clone)]
pub struct NodeShareInfo {
    /// Node ID
    pub node_id: NodeId,
    /// Capability shares (0-15)
    pub shares: i32,
    /// Capabilities breakdown
    pub capabilities: NodeCapabilities,
    /// Shares received count
    pub shares_received: u64,
    /// Is in top 100 for this round
    pub in_top_100: bool,
}

impl RoundShares {
    /// Create a new round shares tracker
    pub fn new(round_id: RoundId, block_height: u64) -> Self {
        Self {
            round_id,
            block_height,
            miner_shares_scaled: HashMap::new(),
            miner_shares: HashMap::new(),
            node_shares: HashMap::new(),
            total_miner_work_scaled: 0,
            total_miner_work: 0.0,
            total_node_shares: 0,
        }
    }

    /// Add miner work (H7 security fix)
    ///
    /// Internally stores as scaled u128 to prevent floating-point accumulation errors.
    /// The f64 view is updated for compatibility with existing code.
    ///
    /// Returns false if the work value is invalid (negative, NaN, or Inf).
    pub fn add_miner_work(&mut self, miner_id: &str, work: f64) -> bool {
        // SEC-SHARE-1: Validate work is non-negative
        if work < 0.0 {
            error!(
                miner = %miner_id,
                work = work,
                "Rejected negative work value - potential attack or bug"
            );
            return false;
        }

        // SEC-SHARE-2: Validate work is finite (not NaN or Inf)
        if !work.is_finite() {
            error!(
                miner = %miner_id,
                work = work,
                "Rejected non-finite work value (NaN/Inf) - potential attack or bug"
            );
            return false;
        }

        trace!(miner = %miner_id, work = work, "Adding miner work");

        // Convert to scaled integer (H7 security fix)
        let work_scaled = (work * WORK_SCALE as f64) as u128;

        // Update scaled storage
        *self
            .miner_shares_scaled
            .entry(miner_id.to_string())
            .or_insert(0) += work_scaled;
        self.total_miner_work_scaled += work_scaled;

        // Update f64 view from scaled values (ensures consistency)
        let miner_total_scaled = *self.miner_shares_scaled.get(miner_id).unwrap_or(&0);
        self.miner_shares.insert(
            miner_id.to_string(),
            miner_total_scaled as f64 / WORK_SCALE as f64,
        );
        self.total_miner_work = self.total_miner_work_scaled as f64 / WORK_SCALE as f64;

        true
    }

    /// Get miner work as scaled integer (for precise calculations)
    pub fn miner_work_scaled(&self, miner_id: &str) -> u128 {
        *self.miner_shares_scaled.get(miner_id).unwrap_or(&0)
    }

    /// Get total work as scaled integer (for precise calculations)
    pub fn total_work_scaled(&self) -> u128 {
        self.total_miner_work_scaled
    }

    /// Register a node's capabilities
    pub fn register_node(&mut self, node_id: NodeId, capabilities: NodeCapabilities) {
        let shares = capabilities.total_shares();

        self.node_shares.insert(
            node_id,
            NodeShareInfo {
                node_id,
                shares,
                capabilities,
                shares_received: 0,
                in_top_100: false, // Will be calculated later
            },
        );
    }

    /// Increment node's received share count
    pub fn increment_node_shares(&mut self, node_id: &NodeId) {
        if let Some(info) = self.node_shares.get_mut(node_id) {
            info.shares_received += 1;
        }
    }

    /// Calculate top 100 nodes (by shares received)
    pub fn calculate_top_100_nodes(&mut self) {
        // Sort nodes by shares received and collect their IDs with ranking
        let mut nodes: Vec<_> = self
            .node_shares
            .iter()
            .map(|(id, info)| (*id, info.shares_received))
            .collect();
        nodes.sort_by(|a, b| b.1.cmp(&a.1));

        // Collect top 100 node IDs
        let top_100_ids: Vec<NodeId> = nodes.iter().take(100).map(|(id, _)| *id).collect();

        // Reset all nodes, then mark top 100
        for info in self.node_shares.values_mut() {
            info.in_top_100 = false;
        }
        for id in &top_100_ids {
            if let Some(info) = self.node_shares.get_mut(id) {
                info.in_top_100 = true;
            }
        }

        // Calculate total shares for top 100
        self.total_node_shares = self
            .node_shares
            .values()
            .filter(|n| n.in_top_100)
            .map(|n| n.shares)
            .sum();

        debug!(
            round_id = self.round_id,
            total_nodes = self.node_shares.len(),
            top_100_shares = self.total_node_shares,
            "Calculated top 100 nodes"
        );
    }

    /// Get miner's share of total work (0.0 - 1.0)
    pub fn miner_share_percent(&self, miner_id: &str) -> f64 {
        if self.total_miner_work == 0.0 {
            return 0.0;
        }

        self.miner_shares
            .get(miner_id)
            .map(|w| w / self.total_miner_work)
            .unwrap_or(0.0)
    }

    /// Get node's share of total node shares (0.0 - 1.0)
    pub fn node_share_percent(&self, node_id: &NodeId) -> f64 {
        if self.total_node_shares == 0 {
            return 0.0;
        }

        self.node_shares
            .get(node_id)
            .filter(|n| n.in_top_100)
            .map(|n| n.shares as f64 / self.total_node_shares as f64)
            .unwrap_or(0.0)
    }

    /// Get top N miners by work
    pub fn top_miners(&self, n: usize) -> Vec<(&str, f64)> {
        let mut miners: Vec<_> = self
            .miner_shares
            .iter()
            .map(|(id, work)| (id.as_str(), *work))
            .collect();

        miners.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        miners.truncate(n);
        miners
    }

    /// Get top 100 nodes by shares received
    pub fn top_100_nodes(&self) -> Vec<&NodeShareInfo> {
        self.node_shares.values().filter(|n| n.in_top_100).collect()
    }

    /// Get nodes outside top 100 (for ledger credits)
    pub fn nodes_outside_top_100(&self) -> Vec<&NodeShareInfo> {
        self.node_shares
            .values()
            .filter(|n| !n.in_top_100)
            .collect()
    }

    /// Get miner count
    pub fn miner_count(&self) -> usize {
        self.miner_shares.len()
    }

    /// Get node count
    pub fn node_count(&self) -> usize {
        self.node_shares.len()
    }
}

/// Work difficulty calculator
#[derive(Debug, Clone)]
pub struct DifficultyCalculator {
    /// Target difficulty for pool shares
    pub share_difficulty: f64,
    /// Network difficulty
    pub network_difficulty: f64,
}

impl DifficultyCalculator {
    /// Create a new calculator
    pub fn new(share_difficulty: f64, network_difficulty: f64) -> Self {
        Self {
            share_difficulty,
            network_difficulty,
        }
    }

    /// Calculate work from a share
    pub fn calculate_work(&self, share_difficulty: f64) -> f64 {
        // Work is proportional to difficulty
        share_difficulty / self.share_difficulty
    }

    /// Check if share meets pool difficulty
    pub fn meets_share_difficulty(&self, difficulty: f64) -> bool {
        difficulty >= self.share_difficulty
    }

    /// Check if share is a valid block
    pub fn is_valid_block(&self, difficulty: f64) -> bool {
        difficulty >= self.network_difficulty
    }

    /// Calculate difficulty from a hash
    ///
    /// Bitcoin difficulty is calculated as:
    /// difficulty = (0xFFFF * 2^208) / hash_as_number
    ///
    /// Lower hash values = higher difficulty
    pub fn difficulty_from_hash(hash: &[u8; 32]) -> f64 {
        // Bitcoin uses little-endian, but hashes are typically displayed big-endian
        // The hash is treated as a 256-bit number

        // Find the first non-zero byte (counting leading zeros)
        let mut leading_zeros = 0;
        for byte in hash.iter().rev() {
            if *byte == 0 {
                leading_zeros += 8;
            } else {
                leading_zeros += byte.leading_zeros() as usize;
                break;
            }
        }

        // If all zeros (shouldn't happen), return max difficulty
        if leading_zeros >= 256 {
            return f64::MAX;
        }

        // Calculate approximate difficulty
        // Each leading zero bit doubles the difficulty
        // Base difficulty 1 corresponds to target with 32 leading zero bits (4 zero bytes)
        let diff_bits = leading_zeros as i32 - 32;

        if diff_bits >= 0 {
            2.0_f64.powi(diff_bits)
        } else {
            1.0 / 2.0_f64.powi(-diff_bits)
        }
    }

    /// Verify that a share hash meets the claimed difficulty
    ///
    /// This is the cryptographic verification that the miner actually did the work
    pub fn verify_share_difficulty(&self, hash: &[u8; 32], claimed_difficulty: f64) -> bool {
        let actual_difficulty = Self::difficulty_from_hash(hash);
        // Allow 1% tolerance for floating point imprecision
        actual_difficulty >= claimed_difficulty * 0.99
    }

    /// Verify that a share hash meets the pool's minimum difficulty
    pub fn verify_share_meets_pool_target(&self, hash: &[u8; 32]) -> bool {
        let actual_difficulty = Self::difficulty_from_hash(hash);
        actual_difficulty >= self.share_difficulty
    }

    /// Verify that a hash meets network difficulty (is a valid block)
    pub fn verify_block_hash(&self, hash: &[u8; 32]) -> bool {
        let actual_difficulty = Self::difficulty_from_hash(hash);
        actual_difficulty >= self.network_difficulty
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_shares() {
        let mut shares = RoundShares::new(1, 100);

        shares.add_miner_work("miner1", 100.0);
        shares.add_miner_work("miner2", 50.0);
        shares.add_miner_work("miner1", 50.0); // Additional work

        assert_eq!(shares.miner_count(), 2);
        assert_eq!(shares.total_miner_work, 200.0);
        assert_eq!(shares.miner_share_percent("miner1"), 0.75);
        assert_eq!(shares.miner_share_percent("miner2"), 0.25);
    }

    #[test]
    fn test_node_shares() {
        let mut shares = RoundShares::new(1, 100);

        let mut caps1 = NodeCapabilities::default();
        caps1.archive_mode = true; // +5
        caps1.public_mining = true; // +3

        let mut caps2 = NodeCapabilities::default();
        caps2.ghost_pay = true; // +4

        shares.register_node([1u8; 32], caps1);
        shares.register_node([2u8; 32], caps2);

        // Simulate share reception
        for _ in 0..10 {
            shares.increment_node_shares(&[1u8; 32]);
        }
        for _ in 0..5 {
            shares.increment_node_shares(&[2u8; 32]);
        }

        shares.calculate_top_100_nodes();

        assert_eq!(shares.total_node_shares, 12); // 8 + 4
    }

    #[test]
    fn test_difficulty_calculator() {
        let calc = DifficultyCalculator::new(1000.0, 1_000_000.0);

        assert!(calc.meets_share_difficulty(1500.0));
        assert!(!calc.meets_share_difficulty(500.0));
        assert!(!calc.is_valid_block(500_000.0));
        assert!(calc.is_valid_block(1_500_000.0));
    }
}
