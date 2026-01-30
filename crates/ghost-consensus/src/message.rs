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
//| FILE: message.rs                                                                                                     |
//|======================================================================================================================|

//! Consensus message types

use serde::{Deserialize, Serialize};

use ghost_common::types::{
    BlockFoundEvent, HealthPing, NodeCapabilities, NodeId, PayoutProposal, RoundId, ShareProof,
};

/// Topic prefixes for ZMQ messages
pub mod topics {
    /// Share propagation topic
    pub const SHARE: &[u8] = b"share";
    /// Block announcement topic
    pub const BLOCK: &[u8] = b"block";
    /// Payout proposal topic
    pub const PAYOUT_PROPOSAL: &[u8] = b"payout";
    /// Vote topic
    pub const VOTE: &[u8] = b"vote";
    /// Health ping topic
    pub const HEALTH: &[u8] = b"health";
    /// Discovery topic
    pub const DISCOVERY: &[u8] = b"discovery";
    /// Elder management topic
    pub const ELDER: &[u8] = b"elder";
    /// ZK block proposal topic
    pub const ZK_PROPOSAL: &[u8] = b"zkproposal";
    /// ZK vote topic
    pub const ZK_VOTE: &[u8] = b"zkvote";
    /// ZK payout proposal topic
    pub const ZK_PAYOUT_PROPOSAL: &[u8] = b"zkpayout";
    /// ZK payout vote topic
    pub const ZK_PAYOUT_VOTE: &[u8] = b"zkpvote";
}

/// Consensus message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    /// Message type
    pub msg_type: MessageType,
    /// Sender node ID
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub sender: NodeId,
    /// Message timestamp
    pub timestamp: u64,
    /// Message sequence number (for dedup)
    pub sequence: u64,
    /// Signature of payload
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
    /// Message payload (JSON)
    pub payload: Vec<u8>,
}

impl MessageEnvelope {
    /// Create a new message envelope
    pub fn new(
        msg_type: MessageType,
        sender: NodeId,
        payload: Vec<u8>,
        sequence: u64,
        signature: [u8; 64],
    ) -> Self {
        Self {
            msg_type,
            sender,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            sequence,
            signature,
            payload,
        }
    }

    /// Get the topic for this message
    pub fn topic(&self) -> &[u8] {
        self.msg_type.topic()
    }

    /// Serialize for transmission
    pub fn serialize(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

/// Message type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// Share proof propagation
    ShareProof,
    /// Block found announcement
    BlockFound,
    /// Payout proposal
    PayoutProposal,
    /// Vote on proposal
    Vote,
    /// Health ping
    HealthPing,
    /// Peer discovery
    Discovery,
    /// Elder status update
    ElderUpdate,
    /// Share convergence request
    ShareConvergence,
    /// ZK block proposal (includes proof)
    ZkBlockProposal,
    /// ZK vote on block validity
    ZkVote,
    /// ZK payout proposal (includes proof)
    ZkPayoutProposal,
    /// ZK payout vote
    ZkPayoutVote,
}

impl MessageType {
    /// Get the ZMQ topic for this message type
    pub fn topic(&self) -> &[u8] {
        match self {
            Self::ShareProof => topics::SHARE,
            Self::BlockFound => topics::BLOCK,
            Self::PayoutProposal => topics::PAYOUT_PROPOSAL,
            Self::Vote => topics::VOTE,
            Self::HealthPing => topics::HEALTH,
            Self::Discovery => topics::DISCOVERY,
            Self::ElderUpdate => topics::ELDER,
            Self::ShareConvergence => topics::SHARE,
            Self::ZkBlockProposal => topics::ZK_PROPOSAL,
            Self::ZkVote => topics::ZK_VOTE,
            Self::ZkPayoutProposal => topics::ZK_PAYOUT_PROPOSAL,
            Self::ZkPayoutVote => topics::ZK_PAYOUT_VOTE,
        }
    }
}

/// Share proof message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareProofMessage {
    /// Share proof data
    pub proof: ShareProof,
}

/// Block found message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockFoundMessage {
    /// Block event data
    pub event: BlockFoundEvent,
    /// Preliminary payout proposal (pre-consensus)
    pub preliminary_proposal: Option<PayoutProposal>,
}

/// Payout proposal message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutProposalMessage {
    /// Full payout proposal
    pub proposal: PayoutProposal,
}

/// Vote message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteMessage {
    /// Round ID
    pub round_id: RoundId,
    /// Proposal hash being voted on
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub proposal_hash: [u8; 32],
    /// Vote (true = approve, false = reject)
    pub approve: bool,
    /// Voter's signature on the proposal hash
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
}

/// Health ping message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthPingMessage {
    /// Health ping data
    pub ping: HealthPing,
}

/// Discovery message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryMessage {
    /// Requesting node
    pub node_id: NodeId,
    /// Node's public address
    pub public_address: String,
    /// Node's capabilities
    pub capabilities: NodeCapabilities,
    /// Known peers (for gossip)
    pub known_peers: Vec<PeerInfo>,
}

/// Peer information for discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Node ID
    pub node_id: NodeId,
    /// Public address
    pub public_address: String,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Capabilities
    pub capabilities: NodeCapabilities,
}

/// Elder update message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElderUpdateMessage {
    /// Node ID
    pub node_id: NodeId,
    /// Is now an elder
    pub is_elder: bool,
    /// Elder registration order
    pub elder_order: Option<u32>,
    /// Reason for update
    pub reason: ElderUpdateReason,
}

/// Reason for elder status change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ElderUpdateReason {
    /// New elder registration
    Registration,
    /// Elder resigned
    Resignation,
    /// Elder revoked by consensus
    Revocation { votes_for: u32, votes_against: u32 },
    /// Elder offline too long
    OfflineTimeout { offline_days: u64 },
}

/// Share convergence request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareConvergenceMessage {
    /// Round ID to converge
    pub round_id: RoundId,
    /// Requesting node's share count
    pub share_count: u64,
    /// Requesting node's total work
    pub total_work: f64,
    /// Share hashes (for comparison)
    #[serde(with = "ghost_common::serde_hex::vec_bytes32")]
    pub share_hashes: Vec<[u8; 32]>,
}

/// Share convergence response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareConvergenceResponse {
    /// Round ID
    pub round_id: RoundId,
    /// Responding node's share count
    pub share_count: u64,
    /// Responding node's total work
    pub total_work: f64,
    /// Missing share hashes (shares the requestor doesn't have)
    pub missing_shares: Vec<ShareProof>,
}

// =============================================================================
// ZK-BFT Message Types
// =============================================================================

/// ZK Block Proposal - includes the block data and validity proof
///
/// Proposers generate this every 10 seconds. The proof demonstrates
/// that all transactions in the block are valid without validators
/// needing to re-execute them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkBlockProposalMessage {
    /// L2 block height
    pub height: u64,
    /// Previous state root (merkle root of balances before block)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub prev_state_root: [u8; 32],
    /// New state root (merkle root of balances after block)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub new_state_root: [u8; 32],
    /// Number of transactions in the block
    pub tx_count: u32,
    /// Hash of the block transactions (for reference)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub transactions_hash: [u8; 32],
    /// Serialized block transactions (can be empty if not broadcasting full block)
    pub transactions: Vec<u8>,
    /// ZK validity proof bytes
    pub proof: Vec<u8>,
    /// Proposer's signature on the proposal
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub proposer_signature: [u8; 64],
    /// Timestamp of proposal
    pub timestamp: u64,
}

impl ZkBlockProposalMessage {
    /// Compute the proposal hash (used for voting)
    pub fn proposal_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"ZkBlockProposal/v1");
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.prev_state_root);
        hasher.update(&self.new_state_root);
        hasher.update(&self.tx_count.to_le_bytes());
        hasher.update(&self.transactions_hash);
        hasher.finalize().into()
    }
}

/// ZK Vote - validator's vote on a ZK block proposal
///
/// Validators verify the ZK proof (~10ms) and vote to approve or reject.
/// Once 67% of validators approve, the block is finalized and the proof
/// is discarded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkVoteMessage {
    /// Block height being voted on
    pub height: u64,
    /// Proposal hash (computed from ZkBlockProposalMessage)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub proposal_hash: [u8; 32],
    /// Vote (true = approve, false = reject)
    pub approve: bool,
    /// Rejection reason (if any)
    pub rejection_reason: Option<ZkRejectionReason>,
    /// Voter's signature on (height || proposal_hash || approve)
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
    /// Timestamp of vote
    pub timestamp: u64,
}

impl ZkVoteMessage {
    /// Create a new ZK vote
    pub fn new(
        height: u64,
        proposal_hash: [u8; 32],
        approve: bool,
        rejection_reason: Option<ZkRejectionReason>,
        signature: [u8; 64],
    ) -> Self {
        Self {
            height,
            proposal_hash,
            approve,
            rejection_reason,
            signature,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        }
    }

    /// Get the message that was signed
    pub fn signing_message(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"ZkVote/v1");
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.proposal_hash);
        hasher.update(&[if self.approve { 1u8 } else { 0u8 }]);
        hasher.finalize().into()
    }
}

/// Reason for rejecting a ZK block proposal
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ZkRejectionReason {
    /// The ZK proof failed verification
    InvalidProof,
    /// State root doesn't match local computation
    StateRootMismatch,
    /// Block height is wrong (not sequential)
    InvalidHeight,
    /// Previous state root doesn't match current state
    PrevStateRootMismatch,
    /// Proposal came from non-eligible proposer
    InvalidProposer,
    /// Proposer signature is invalid
    InvalidSignature,
    /// Proposal timestamp is too old or in the future
    InvalidTimestamp,
    /// Block contains invalid transactions
    InvalidTransactions,
    /// Other validation failure
    Other(String),
}

/// ZK consensus result for a block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZkConsensusResult {
    /// Block approved by consensus
    Approved {
        height: u64,
        new_state_root: [u8; 32],
        approvals: u32,
        total_validators: u32,
    },
    /// Block rejected by consensus
    Rejected {
        height: u64,
        rejections: u32,
        total_validators: u32,
        primary_reason: ZkRejectionReason,
    },
    /// Consensus timed out
    Timeout {
        height: u64,
        approvals: u32,
        rejections: u32,
        total_validators: u32,
    },
}

// =============================================================================
// ZK Payout Message Types
// =============================================================================

/// ZK Payout Proposal - includes the payout distribution and validity proof
///
/// Generated by the epoch settler to prove fair distribution of rewards.
/// The proof demonstrates that all payouts are proportional to work without
/// validators needing to re-calculate shares.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkPayoutProposalMessage {
    /// Epoch being settled
    pub epoch: u64,
    /// Round ID (for compatibility with existing payout system)
    pub round_id: RoundId,
    /// Block hash that was found
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub block_hash: [u8; 32],
    /// Proposer node ID
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub proposer: NodeId,
    /// Total available for distribution (subsidy + fees)
    pub total_available: u64,
    /// Number of miners in the payout
    pub miner_count: u32,
    /// Sum of miner payouts
    pub miner_sum: u64,
    /// Number of nodes in the payout
    pub node_count: u32,
    /// Sum of node payouts
    pub node_sum: u64,
    /// Treasury (pool fee) amount
    pub treasury_amount: u64,
    /// Merkle root of the payout list
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub payout_merkle_root: [u8; 32],
    /// ZK validity proof bytes
    pub proof: Vec<u8>,
    /// Proposer's signature on the proposal
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub proposer_signature: [u8; 64],
    /// Timestamp of proposal
    pub timestamp: u64,
}

impl ZkPayoutProposalMessage {
    /// Compute the proposal hash (used for voting)
    pub fn proposal_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"ZkPayoutProposal/v1");
        hasher.update(&self.epoch.to_le_bytes());
        hasher.update(&self.round_id.to_le_bytes());
        hasher.update(&self.block_hash);
        hasher.update(&self.total_available.to_le_bytes());
        hasher.update(&self.miner_sum.to_le_bytes());
        hasher.update(&self.node_sum.to_le_bytes());
        hasher.update(&self.treasury_amount.to_le_bytes());
        hasher.update(&self.payout_merkle_root);
        hasher.finalize().into()
    }
}

/// ZK Payout Vote - validator's vote on a ZK payout proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkPayoutVoteMessage {
    /// Epoch being voted on
    pub epoch: u64,
    /// Proposal hash (computed from ZkPayoutProposalMessage)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub proposal_hash: [u8; 32],
    /// Vote (true = approve, false = reject)
    pub approve: bool,
    /// Rejection reason (if any)
    pub rejection_reason: Option<ZkPayoutRejectionReason>,
    /// Voter's signature
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
    /// Timestamp of vote
    pub timestamp: u64,
}

impl ZkPayoutVoteMessage {
    /// Create a new ZK payout vote
    pub fn new(
        epoch: u64,
        proposal_hash: [u8; 32],
        approve: bool,
        rejection_reason: Option<ZkPayoutRejectionReason>,
        signature: [u8; 64],
    ) -> Self {
        Self {
            epoch,
            proposal_hash,
            approve,
            rejection_reason,
            signature,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        }
    }

    /// Get the message that was signed
    pub fn signing_message(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"ZkPayoutVote/v1");
        hasher.update(&self.epoch.to_le_bytes());
        hasher.update(&self.proposal_hash);
        hasher.update(&[if self.approve { 1u8 } else { 0u8 }]);
        hasher.finalize().into()
    }
}

/// Reason for rejecting a ZK payout proposal
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ZkPayoutRejectionReason {
    /// The ZK proof failed verification
    InvalidProof,
    /// Sum doesn't match total available
    SumMismatch,
    /// Proportionality check failed
    ProportionalityError,
    /// Settler is not authorized for this epoch
    InvalidSettler,
    /// Epoch doesn't match current epoch
    EpochMismatch,
    /// Proposer signature is invalid
    InvalidSignature,
    /// Payout merkle root doesn't match
    MerkleRootMismatch,
    /// Other validation failure
    Other(String),
}

/// ZK payout consensus result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZkPayoutConsensusResult {
    /// Payout approved by consensus
    Approved {
        epoch: u64,
        proposal_hash: [u8; 32],
        approvals: u32,
        total_validators: u32,
    },
    /// Payout rejected by consensus
    Rejected {
        epoch: u64,
        rejections: u32,
        total_validators: u32,
        primary_reason: ZkPayoutRejectionReason,
    },
    /// Consensus timed out
    Timeout {
        epoch: u64,
        approvals: u32,
        rejections: u32,
        total_validators: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization() {
        let msg = VoteMessage {
            round_id: 1,
            proposal_hash: [0u8; 32],
            approve: true,
            signature: [0u8; 64],
        };

        let json = serde_json::to_vec(&msg).unwrap();
        let decoded: VoteMessage = serde_json::from_slice(&json).unwrap();

        assert_eq!(decoded.round_id, 1);
        assert!(decoded.approve);
    }

    #[test]
    fn test_message_topics() {
        assert_eq!(MessageType::ShareProof.topic(), topics::SHARE);
        assert_eq!(MessageType::BlockFound.topic(), topics::BLOCK);
        assert_eq!(MessageType::Vote.topic(), topics::VOTE);
        assert_eq!(MessageType::ZkBlockProposal.topic(), topics::ZK_PROPOSAL);
        assert_eq!(MessageType::ZkVote.topic(), topics::ZK_VOTE);
    }

    #[test]
    fn test_zk_proposal_hash() {
        let proposal = ZkBlockProposalMessage {
            height: 100,
            prev_state_root: [1u8; 32],
            new_state_root: [2u8; 32],
            tx_count: 5,
            transactions_hash: [3u8; 32],
            transactions: vec![],
            proof: vec![0u8; 72],
            proposer_signature: [0u8; 64],
            timestamp: 1700000000,
        };

        let hash1 = proposal.proposal_hash();
        let hash2 = proposal.proposal_hash();
        assert_eq!(hash1, hash2, "Proposal hash should be deterministic");
    }

    #[test]
    fn test_zk_vote_message() {
        let vote = ZkVoteMessage::new(
            100,
            [1u8; 32],
            true,
            None,
            [0u8; 64],
        );

        assert_eq!(vote.height, 100);
        assert!(vote.approve);
        assert!(vote.rejection_reason.is_none());
    }

    #[test]
    fn test_zk_vote_rejection() {
        let vote = ZkVoteMessage::new(
            100,
            [1u8; 32],
            false,
            Some(ZkRejectionReason::InvalidProof),
            [0u8; 64],
        );

        assert!(!vote.approve);
        assert_eq!(vote.rejection_reason, Some(ZkRejectionReason::InvalidProof));
    }
}
