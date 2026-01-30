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
//| FILE: types.rs                                                                                                       |
//|======================================================================================================================|

//! Common types used across Bitcoin Ghost

use serde::{Deserialize, Serialize};

/// 32-byte Node ID (Ed25519 public key)
pub type NodeId = [u8; 32];

/// 32-byte block hash
pub type BlockHash = [u8; 32];

/// 32-byte transaction ID
pub type Txid = [u8; 32];

/// 64-byte Ed25519 signature
pub type Signature = [u8; 64];

/// Round identifier
pub type RoundId = u64;

/// Block height
pub type BlockHeight = u64;

/// Amount in satoshis
pub type Satoshis = u64;

/// Node capabilities flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct NodeCapabilities {
    /// Archive mode enabled (+5 shares)
    pub archive_mode: bool,
    /// Ghost Pay L2 enabled (+4 shares)
    pub ghost_pay: bool,
    /// Public mining enabled (+3 shares)
    pub public_mining: bool,
    /// Bitcoin Pure policy enabled (+2 shares)
    pub bitcoin_pure: bool,
    /// Elder status (+1 share)
    pub elder_status: bool,
}

impl NodeCapabilities {
    /// Create new capabilities with all disabled
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculate total shares (0-15)
    pub fn total_shares(&self) -> i32 {
        let mut shares = 0;
        if self.archive_mode {
            shares += crate::constants::ARCHIVE_MODE_SHARES;
        }
        if self.ghost_pay {
            shares += crate::constants::GHOST_PAY_SHARES;
        }
        if self.public_mining {
            shares += crate::constants::PUBLIC_MINING_SHARES;
        }
        if self.bitcoin_pure {
            // Bitcoin Pure works with both private and public mining
            shares += crate::constants::BITCOIN_PURE_SHARES;
        }
        if self.elder_status {
            shares += crate::constants::ELDER_STATUS_SHARES;
        }
        shares
    }

    /// Check if node has any capabilities
    pub fn has_any(&self) -> bool {
        self.archive_mode
            || self.ghost_pay
            || self.public_mining
            || self.bitcoin_pure
            || self.elder_status
    }
}

/// Capacity state for load balancing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityState {
    /// Below 50% capacity
    Healthy,
    /// 50-75% capacity
    Normal,
    /// 75-90% capacity
    SoftLimit,
    /// Above 90% capacity
    HardLimit,
}

impl CapacityState {
    /// Calculate from current/max miners
    pub fn from_load(current: u32, max: u32) -> Self {
        if max == 0 {
            return Self::HardLimit;
        }
        let percent = (current as f64 / max as f64) * 100.0;
        if percent < 50.0 {
            Self::Healthy
        } else if percent < 75.0 {
            Self::Normal
        } else if percent < 90.0 {
            Self::SoftLimit
        } else {
            Self::HardLimit
        }
    }

    /// Get load penalty for scoring
    pub fn load_penalty(&self) -> f64 {
        match self {
            Self::Healthy => 0.0,
            Self::Normal => 0.1,
            Self::SoftLimit => 0.3,
            Self::HardLimit => 1.0,
        }
    }
}

/// Consensus result types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusResult {
    /// Proposal approved by 67%+
    Approved {
        proposal_hash: [u8; 32],
        approval_count: u32,
        total_nodes: u32,
    },
    /// Proposal rejected by 67%+
    Rejected {
        proposal_hash: [u8; 32],
        rejection_count: u32,
        total_nodes: u32,
        reason: Option<String>,
    },
    /// Voting timed out
    Timeout {
        proposal_hash: [u8; 32],
        approvals: u32,
        rejections: u32,
        total_nodes: u32,
    },
    /// Error during consensus
    Error(String),
}

/// Vote type for consensus
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteType {
    /// Vote on payout proposal
    PayoutApproval,
    /// Vote on elder revocation
    ElderRevocation,
    /// Vote on share allocation
    ShareAllocation,
}

/// Revocation reason for elders
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationReason {
    /// Offline for 7+ days
    ExtendedOffline { offline_days: u64 },
    /// Malicious behavior detected
    MaliciousBehavior { description: String },
    /// Voluntary resignation
    Voluntary,
}

/// Block found event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockFoundEvent {
    /// Block hash
    pub block_hash: BlockHash,
    /// Block height
    pub block_height: BlockHeight,
    /// Round ID
    pub round_id: RoundId,
    /// Winning miner pubkey hash
    pub winning_miner: [u8; 32],
    /// Node that found the block
    pub found_by_node: NodeId,
    /// Transaction fees in satoshis
    pub tx_fees_satoshis: Satoshis,
    /// Block subsidy in satoshis
    pub subsidy_satoshis: Satoshis,
    /// Timestamp
    pub timestamp: u64,
}

/// Share proof for P2P propagation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareProof {
    /// Round ID
    pub round_id: RoundId,
    /// Miner pubkey hash
    pub miner_id: [u8; 32],
    /// Share difficulty met
    pub difficulty: f64,
    /// Work value
    pub work: f64,
    /// Share hash
    pub share_hash: [u8; 32],
    /// Timestamp
    pub timestamp: u64,
    /// Node that received the share
    pub received_by: NodeId,
}

/// Payout proposal for consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutProposal {
    /// Proposal hash (for voting)
    pub proposal_hash: [u8; 32],
    /// Round ID
    pub round_id: RoundId,
    /// Block hash
    pub block_hash: BlockHash,
    /// Block height
    pub block_height: BlockHeight,
    /// Proposing node
    pub proposer: NodeId,
    /// Miner payouts
    pub miner_payouts: Vec<PayoutEntry>,
    /// Node reward payouts
    pub node_payouts: Vec<PayoutEntry>,
    /// Treasury amount
    pub treasury_amount: Satoshis,
    /// TX fees (to node operator)
    pub tx_fees: Satoshis,
    /// Total subsidy
    pub subsidy: Satoshis,
    /// Timestamp
    pub timestamp: u64,
}

/// Single payout entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutEntry {
    /// Recipient address (script pubkey)
    pub address: Vec<u8>,
    /// Amount in satoshis
    pub amount: Satoshis,
    /// Recipient identifier (miner_id or node_id)
    pub recipient_id: [u8; 32],
    /// Payout type
    pub payout_type: PayoutType,
}

/// Type of payout
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayoutType {
    /// Mining reward
    Mining,
    /// Node capability reward
    NodeReward,
    /// Treasury allocation
    Treasury,
    /// TX fees to node operator
    TxFees,
}

/// Health ping message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthPing {
    /// Sender node ID
    pub node_id: NodeId,
    /// Public address for P2P connections
    pub public_address: String,
    /// Current block height
    pub block_height: BlockHeight,
    /// Current round ID
    pub round_id: RoundId,
    /// Node capabilities
    pub capabilities: NodeCapabilities,
    /// Connected miners count
    pub miner_count: u32,
    /// Timestamp
    pub timestamp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_capabilities_shares() {
        let mut caps = NodeCapabilities::new();
        assert_eq!(caps.total_shares(), 0);

        caps.archive_mode = true;
        assert_eq!(caps.total_shares(), 5);

        caps.public_mining = true;
        assert_eq!(caps.total_shares(), 8); // 5 + 3

        caps.bitcoin_pure = true;
        assert_eq!(caps.total_shares(), 10); // 5 + 3 + 2

        caps.ghost_pay = true;
        caps.elder_status = true;
        assert_eq!(caps.total_shares(), 15); // 5 + 3 + 2 + 4 + 1
    }

    #[test]
    fn test_bitcoin_pure_works_independently() {
        // Bitcoin Pure works with private mining (no public_mining flag)
        let mut caps = NodeCapabilities::new();
        caps.bitcoin_pure = true;
        assert_eq!(caps.total_shares(), 2); // Bitcoin Pure alone counts

        // Also works with public mining
        caps.public_mining = true;
        assert_eq!(caps.total_shares(), 5); // 2 + 3
    }

    #[test]
    fn test_capacity_state() {
        assert_eq!(CapacityState::from_load(10, 100), CapacityState::Healthy);
        assert_eq!(CapacityState::from_load(60, 100), CapacityState::Normal);
        assert_eq!(CapacityState::from_load(80, 100), CapacityState::SoftLimit);
        assert_eq!(CapacityState::from_load(95, 100), CapacityState::HardLimit);
    }
}
