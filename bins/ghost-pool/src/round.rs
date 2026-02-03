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
//| FILE: round.rs                                                                                                       |
//|======================================================================================================================|

//! Round management for share tracking
//!
//! Tracks mining rounds, share submissions, and triggers payout proposals.

use parking_lot::RwLock;
use std::collections::HashMap;
use tokio::sync::broadcast;
use tracing::{debug, info};

use ghost_accounting::shares::{DifficultyCalculator, RoundShares};
use ghost_common::config::MiningMode;
use ghost_common::types::{NodeCapabilities, NodeId, RoundId, ShareProof};

/// Round manager configuration
#[derive(Debug, Clone)]
pub struct RoundConfig {
    /// Pool share difficulty (target)
    pub share_difficulty: f64,
    /// Network difficulty
    pub network_difficulty: f64,
    /// Maximum shares per round (memory protection)
    pub max_shares_per_round: usize,
    /// Round history to keep
    pub rounds_to_keep: usize,
    /// Mining mode (affects payout flow)
    pub mining_mode: MiningMode,
}

impl Default for RoundConfig {
    fn default() -> Self {
        Self {
            share_difficulty: 1000.0,
            network_difficulty: 1_000_000.0,
            max_shares_per_round: 1_000_000,
            rounds_to_keep: 10,
            mining_mode: MiningMode::PublicPool,
        }
    }
}

/// Events emitted by the round manager
#[derive(Debug, Clone)]
pub enum RoundEvent {
    /// New round started
    RoundStarted {
        round_id: RoundId,
        block_height: u64,
    },
    /// Share submitted
    ShareSubmitted {
        round_id: RoundId,
        miner_id: String,
        work: f64,
    },
    /// Block found!
    BlockFound {
        round_id: RoundId,
        block_hash: [u8; 32],
        miner_id: String,
    },
    /// Round ended
    RoundEnded {
        round_id: RoundId,
        total_shares: u64,
        total_work: f64,
    },
}

/// Manages mining rounds and share accounting
pub struct RoundManager {
    /// Configuration
    config: RoundConfig,
    /// Current round ID
    current_round: RwLock<RoundId>,
    /// Current block height
    current_height: RwLock<u64>,
    /// Active rounds (current and recent)
    rounds: RwLock<HashMap<RoundId, RoundShares>>,
    /// Difficulty calculator
    difficulty: RwLock<DifficultyCalculator>,
    /// Registered nodes and their capabilities
    nodes: RwLock<HashMap<NodeId, NodeCapabilities>>,
    /// Event broadcaster
    event_tx: broadcast::Sender<RoundEvent>,
    /// Our node ID
    our_node_id: NodeId,
    /// Submitted share hashes per round (for duplicate detection)
    submitted_shares: RwLock<HashMap<RoundId, std::collections::HashSet<[u8; 32]>>>,
}

impl RoundManager {
    /// Create a new round manager
    pub fn new(our_node_id: NodeId, config: RoundConfig) -> Self {
        let difficulty =
            DifficultyCalculator::new(config.share_difficulty, config.network_difficulty);

        let (event_tx, _) = broadcast::channel(1000);

        Self {
            config,
            current_round: RwLock::new(0),
            current_height: RwLock::new(0),
            rounds: RwLock::new(HashMap::new()),
            difficulty: RwLock::new(difficulty),
            nodes: RwLock::new(HashMap::new()),
            event_tx,
            our_node_id,
            submitted_shares: RwLock::new(HashMap::new()),
        }
    }

    /// Subscribe to round events
    pub fn subscribe(&self) -> broadcast::Receiver<RoundEvent> {
        self.event_tx.subscribe()
    }

    /// Start a new round (called on new block template)
    pub fn start_round(&self, block_height: u64) -> RoundId {
        let round_id = {
            let mut current = self.current_round.write();
            *current += 1;
            *current
        };

        *self.current_height.write() = block_height;

        // Create new round shares tracker
        let mut rounds = self.rounds.write();
        rounds.insert(round_id, RoundShares::new(round_id, block_height));

        // Register all known nodes into the new round
        let nodes = self.nodes.read();
        if let Some(round) = rounds.get_mut(&round_id) {
            for (node_id, caps) in nodes.iter() {
                round.register_node(*node_id, *caps);
            }
        }

        // Cleanup old rounds
        let to_remove: Vec<_> = rounds
            .keys()
            .filter(|&r| *r + self.config.rounds_to_keep as u64 <= round_id)
            .cloned()
            .collect();

        for old_round in &to_remove {
            rounds.remove(old_round);
        }

        // Also cleanup submitted shares for old rounds
        {
            let mut submitted = self.submitted_shares.write();
            for old_round in to_remove {
                submitted.remove(&old_round);
            }
        }

        info!(
            round_id = round_id,
            block_height = block_height,
            "Started new round"
        );

        let _ = self.event_tx.send(RoundEvent::RoundStarted {
            round_id,
            block_height,
        });

        round_id
    }

    /// Submit a share
    pub fn submit_share(
        &self,
        miner_id: &str,
        difficulty: f64,
        share_hash: [u8; 32],
    ) -> Result<ShareSubmitResult, ShareError> {
        let round_id = *self.current_round.read();
        if round_id == 0 {
            return Err(ShareError::NoActiveRound);
        }

        let diff_calc = self.difficulty.read();

        // Check claimed difficulty meets pool minimum
        if !diff_calc.meets_share_difficulty(difficulty) {
            return Err(ShareError::DifficultyTooLow {
                got: difficulty,
                needed: diff_calc.share_difficulty,
            });
        }

        // Cryptographic verification: verify the hash actually meets the claimed difficulty
        if !diff_calc.verify_share_difficulty(&share_hash, difficulty) {
            return Err(ShareError::InvalidShareHash);
        }

        // Check for duplicate share submission
        {
            let mut submitted = self.submitted_shares.write();
            let round_shares = submitted.entry(round_id).or_default();
            if !round_shares.insert(share_hash) {
                return Err(ShareError::DuplicateShare);
            }
        }

        // Calculate work value
        let work = diff_calc.calculate_work(difficulty);

        // Add to round
        let mut rounds = self.rounds.write();
        let round = rounds
            .get_mut(&round_id)
            .ok_or(ShareError::RoundNotFound(round_id))?;

        if round.miner_shares.len() >= self.config.max_shares_per_round {
            return Err(ShareError::RoundFull);
        }

        round.add_miner_work(miner_id, work);

        // Increment node shares (for our node since we received this)
        round.increment_node_shares(&self.our_node_id);

        debug!(
            round_id = round_id,
            miner = %miner_id,
            difficulty = difficulty,
            work = work,
            "Share submitted"
        );

        let _ = self.event_tx.send(RoundEvent::ShareSubmitted {
            round_id,
            miner_id: miner_id.to_string(),
            work,
        });

        // Check if this is a block
        let is_block = diff_calc.is_valid_block(difficulty);
        if is_block {
            info!(
                round_id = round_id,
                miner = %miner_id,
                difficulty = difficulty,
                "BLOCK FOUND!"
            );

            let _ = self.event_tx.send(RoundEvent::BlockFound {
                round_id,
                block_hash: share_hash,
                miner_id: miner_id.to_string(),
            });
        }

        Ok(ShareSubmitResult {
            round_id,
            work,
            is_block,
            share_hash,
        })
    }

    /// Handle a share proof from the P2P network
    pub fn handle_share_proof(&self, proof: ShareProof) -> Result<(), ShareError> {
        let mut rounds = self.rounds.write();

        // Find or create round
        let round = rounds
            .entry(proof.round_id)
            .or_insert_with(|| RoundShares::new(proof.round_id, 0));

        // Add miner work
        let miner_id = hex::encode(&proof.miner_id[..8]);
        round.add_miner_work(&miner_id, proof.work);

        // Credit the node that received it
        round.increment_node_shares(&proof.received_by);

        debug!(
            round_id = proof.round_id,
            miner = %miner_id,
            work = proof.work,
            from_node = ?hex::encode(&proof.received_by[..4]),
            "Processed share proof"
        );

        Ok(())
    }

    /// Register a node's capabilities
    pub fn register_node(&self, node_id: NodeId, capabilities: NodeCapabilities) {
        self.nodes.write().insert(node_id, capabilities);

        // Also register in current round
        let round_id = *self.current_round.read();
        if round_id > 0 {
            if let Some(round) = self.rounds.write().get_mut(&round_id) {
                round.register_node(node_id, capabilities);
            }
        }
    }

    /// End current round and prepare payout data
    pub fn end_round(&self) -> Option<RoundSummary> {
        let round_id = *self.current_round.read();
        if round_id == 0 {
            return None;
        }

        let mut rounds = self.rounds.write();
        let round = rounds.get_mut(&round_id)?;

        // Calculate top 100 nodes
        round.calculate_top_100_nodes();

        let summary = RoundSummary {
            round_id,
            block_height: round.block_height,
            total_miner_work: round.total_miner_work,
            total_node_shares: round.total_node_shares,
            miner_count: round.miner_count(),
            node_count: round.node_count(),
            top_miners: round
                .top_miners(10)
                .into_iter()
                .map(|(id, w)| (id.to_string(), w))
                .collect(),
        };

        info!(
            round_id = round_id,
            total_work = summary.total_miner_work,
            miners = summary.miner_count,
            nodes = summary.node_count,
            "Round ended"
        );

        let _ = self.event_tx.send(RoundEvent::RoundEnded {
            round_id,
            total_shares: summary.miner_count as u64,
            total_work: summary.total_miner_work,
        });

        Some(summary)
    }

    /// Get current round ID
    pub fn current_round_id(&self) -> RoundId {
        *self.current_round.read()
    }

    /// Get current block height
    pub fn current_height(&self) -> u64 {
        *self.current_height.read()
    }

    /// Get round statistics
    pub fn round_stats(&self, round_id: RoundId) -> Option<RoundStats> {
        let rounds = self.rounds.read();
        let round = rounds.get(&round_id)?;

        Some(RoundStats {
            round_id,
            block_height: round.block_height,
            total_work: round.total_miner_work,
            miner_count: round.miner_count(),
            node_count: round.node_count(),
        })
    }

    /// Update network difficulty
    pub fn update_difficulty(&self, network_difficulty: f64) {
        let mut diff = self.difficulty.write();
        diff.network_difficulty = network_difficulty;
        info!(
            difficulty = network_difficulty,
            "Updated network difficulty"
        );
    }

    /// Update share difficulty
    pub fn update_share_difficulty(&self, share_difficulty: f64) {
        let mut diff = self.difficulty.write();
        diff.share_difficulty = share_difficulty;
        info!(difficulty = share_difficulty, "Updated share difficulty");
    }

    /// Record a share forwarded from SRI (already validated by SRI)
    /// Used when ghost-pool runs in TDP-only mode without direct stratum access
    pub fn record_share(
        &self,
        miner_id: &str,
        work: f64,
        receiving_node: NodeId,
    ) -> Result<(), ShareError> {
        let round_id = *self.current_round.read();
        if round_id == 0 {
            return Err(ShareError::NoActiveRound);
        }

        let mut rounds = self.rounds.write();
        let round = rounds
            .get_mut(&round_id)
            .ok_or(ShareError::RoundNotFound(round_id))?;

        if round.miner_shares.len() >= self.config.max_shares_per_round {
            return Err(ShareError::RoundFull);
        }

        // Add miner work
        round.add_miner_work(miner_id, work);

        // Credit the node that received the share
        round.increment_node_shares(&receiving_node);

        debug!(
            round_id = round_id,
            miner = %miner_id,
            work = work,
            from_node = ?hex::encode(&receiving_node[..4]),
            "Recorded share from SRI"
        );

        let _ = self.event_tx.send(RoundEvent::ShareSubmitted {
            round_id,
            miner_id: miner_id.to_string(),
            work,
        });

        Ok(())
    }

    /// Get a miner's share percentage in current round
    pub fn miner_share_percent(&self, miner_id: &str) -> f64 {
        let round_id = *self.current_round.read();
        let rounds = self.rounds.read();
        rounds
            .get(&round_id)
            .map(|r| r.miner_share_percent(miner_id))
            .unwrap_or(0.0)
    }

    /// Get a node's share percentage in current round
    pub fn node_share_percent(&self, node_id: &NodeId) -> f64 {
        let round_id = *self.current_round.read();
        let rounds = self.rounds.read();
        rounds
            .get(&round_id)
            .map(|r| r.node_share_percent(node_id))
            .unwrap_or(0.0)
    }

    /// Get miner work distribution for a round
    /// Returns Vec<(miner_id, work_fraction)>
    pub fn get_miner_work(&self, round_id: RoundId) -> Vec<(String, f64)> {
        let rounds = self.rounds.read();
        rounds
            .get(&round_id)
            .map(|r| {
                r.top_miners(200) // Get top 200 miners
                    .into_iter()
                    .map(|(id, work)| (id.to_string(), work))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get node share distribution for a round
    /// Returns Vec<(node_id, shares)>
    pub fn get_node_shares(&self, round_id: RoundId) -> Vec<(NodeId, i32)> {
        let mut rounds = self.rounds.write();
        if let Some(round) = rounds.get_mut(&round_id) {
            // Ensure top 100 is calculated before returning
            round.calculate_top_100_nodes();
            round
                .top_100_nodes()
                .into_iter()
                .map(|n| (n.node_id, n.shares))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get the configured mining mode
    pub fn mining_mode(&self) -> MiningMode {
        self.config.mining_mode
    }

    /// Check if we're in solo mining mode
    pub fn is_solo_mode(&self) -> bool {
        matches!(self.config.mining_mode, MiningMode::PrivateSolo)
    }
}

/// Result of submitting a share
#[derive(Debug, Clone)]
pub struct ShareSubmitResult {
    pub round_id: RoundId,
    pub work: f64,
    pub is_block: bool,
    pub share_hash: [u8; 32],
}

/// Share submission errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum ShareError {
    #[error("No active round")]
    NoActiveRound,

    #[error("Round not found: {0}")]
    RoundNotFound(RoundId),

    #[error("Difficulty too low: got {got}, needed {needed}")]
    DifficultyTooLow { got: f64, needed: f64 },

    #[error("Invalid share hash: hash does not meet claimed difficulty")]
    InvalidShareHash,

    #[error("Round is full")]
    RoundFull,

    #[error("Duplicate share")]
    DuplicateShare,
}

/// Round statistics
#[derive(Debug, Clone)]
pub struct RoundStats {
    pub round_id: RoundId,
    pub block_height: u64,
    pub total_work: f64,
    pub miner_count: usize,
    pub node_count: usize,
}

/// Round summary for payout calculation
#[derive(Debug, Clone)]
pub struct RoundSummary {
    pub round_id: RoundId,
    pub block_height: u64,
    pub total_miner_work: f64,
    pub total_node_shares: i32,
    pub miner_count: usize,
    pub node_count: usize,
    pub top_miners: Vec<(String, f64)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_lifecycle() {
        let node_id = [1u8; 32];
        let manager = RoundManager::new(node_id, RoundConfig::default());

        // Start round
        let round_id = manager.start_round(100);
        assert_eq!(round_id, 1);
        assert_eq!(manager.current_round_id(), 1);
        assert_eq!(manager.current_height(), 100);

        // Submit shares
        let result = manager.submit_share("miner1", 1500.0, [0u8; 32]);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.round_id, 1);
        assert!(!result.is_block);
    }

    #[test]
    fn test_difficulty_check() {
        let node_id = [1u8; 32];
        let manager = RoundManager::new(node_id, RoundConfig::default());
        manager.start_round(100);

        // Too low difficulty
        let result = manager.submit_share("miner1", 500.0, [0u8; 32]);
        assert!(result.is_err());
    }
}
