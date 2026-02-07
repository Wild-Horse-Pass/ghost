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
    /// Verification result topic
    pub const VERIFICATION: &[u8] = b"verify";
    /// P2P-H3: Equivocation proof topic for Byzantine behavior evidence
    pub const EQUIVOCATION: &[u8] = b"equivoc";
    /// MPC ceremony messages (contribution, verification vote, parameter sync)
    pub const MPC: &[u8] = b"mpc";
}

/// Default TTL for gossip messages (number of hops before message is dropped)
pub const DEFAULT_MESSAGE_TTL: u8 = 8;

/// Minimum TTL for messages to be forwarded (messages with TTL 0 are not forwarded)
pub const MIN_FORWARD_TTL: u8 = 1;

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
    /// Time-to-live: number of hops remaining before message is dropped.
    /// Decremented on each forward. Messages with TTL 0 are processed locally but not forwarded.
    /// Defaults to DEFAULT_MESSAGE_TTL for backwards compatibility with older messages.
    #[serde(default = "default_ttl")]
    pub ttl: u8,
}

/// Default TTL value for deserialization of messages without TTL field
fn default_ttl() -> u8 {
    DEFAULT_MESSAGE_TTL
}

impl MessageEnvelope {
    /// Create a new message envelope with default TTL
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
            ttl: DEFAULT_MESSAGE_TTL,
        }
    }

    /// Create a new message envelope with custom TTL
    pub fn with_ttl(
        msg_type: MessageType,
        sender: NodeId,
        payload: Vec<u8>,
        sequence: u64,
        signature: [u8; 64],
        ttl: u8,
    ) -> Self {
        Self {
            msg_type,
            sender,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            sequence,
            signature,
            payload,
            ttl,
        }
    }

    /// Decrement TTL and return whether the message should be forwarded
    ///
    /// Returns true if the message should be forwarded (TTL was > 0 before decrement)
    /// Returns false if the message should not be forwarded (TTL was already 0)
    pub fn decrement_ttl(&mut self) -> bool {
        if self.ttl > 0 {
            self.ttl = self.ttl.saturating_sub(1);
            true
        } else {
            false
        }
    }

    /// Check if this message should be forwarded to other peers
    pub fn should_forward(&self) -> bool {
        self.ttl >= MIN_FORWARD_TTL
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
    /// Capability verification result
    VerificationResult,
    /// P2P-H3: Equivocation proof broadcast for Byzantine behavior evidence
    EquivocationProof,
    /// P2P-C1: Elder registration proposal (new elder candidate)
    ElderRegistrationProposal,
    /// P2P-C2: Elder list proposal (proposed canonical list for new epoch)
    ElderListProposal,
    /// P2P-C3: Elder list approval (vote for proposed list)
    ElderListApproval,
    /// MPC-C1: MPC contribution (new elder's contribution to ceremony)
    MpcContribution,
    /// MPC-C2: MPC verification vote (elder's vote on contribution)
    MpcVerificationVote,
    /// MPC-C3: MPC parameters request (request params from peer)
    MpcParametersRequest,
    /// MPC-C4: MPC parameters response (chunked parameter data)
    MpcParametersResponse,
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
            Self::VerificationResult => topics::VERIFICATION,
            Self::EquivocationProof => topics::EQUIVOCATION,
            Self::ElderRegistrationProposal => topics::ELDER,
            Self::ElderListProposal => topics::ELDER,
            Self::ElderListApproval => topics::ELDER,
            Self::MpcContribution => topics::MPC,
            Self::MpcVerificationVote => topics::MPC,
            Self::MpcParametersRequest => topics::MPC,
            Self::MpcParametersResponse => topics::MPC,
        }
    }

    /// M-P2P-1: Get the topic as a string for validation
    ///
    /// Used to validate that a message received on a topic actually matches
    /// the message type declared in the envelope.
    pub fn topic_str(&self) -> &'static str {
        match self {
            Self::ShareProof | Self::ShareConvergence => "share",
            Self::BlockFound => "block",
            Self::PayoutProposal => "payout",
            Self::Vote => "vote",
            Self::HealthPing => "health",
            Self::Discovery => "discovery",
            Self::ElderUpdate => "elder",
            Self::ZkBlockProposal => "zkproposal",
            Self::ZkVote => "zkvote",
            Self::ZkPayoutProposal => "zkpayout",
            Self::ZkPayoutVote => "zkpvote",
            Self::VerificationResult => "verify",
            Self::EquivocationProof => "equivoc",
            Self::ElderRegistrationProposal => "elder",
            Self::ElderListProposal => "elder",
            Self::ElderListApproval => "elder",
            Self::MpcContribution => "mpc",
            Self::MpcVerificationVote => "mpc",
            Self::MpcParametersRequest => "mpc",
            Self::MpcParametersResponse => "mpc",
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
// CAPABILITY VERIFICATION Messages
// =============================================================================

/// Capability type for verification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityType {
    /// Archive mode capability
    Archive,
    /// Policy (Bitcoin Pure) capability
    Policy,
    /// Stratum (Public Mining) capability
    Stratum,
    /// Ghost Pay capability
    GhostPay,
}

impl CapabilityType {
    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::Policy => "policy",
            Self::Stratum => "stratum",
            Self::GhostPay => "ghostpay",
        }
    }

    /// Parse from string
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "archive" => Some(Self::Archive),
            "policy" => Some(Self::Policy),
            "stratum" => Some(Self::Stratum),
            "ghostpay" => Some(Self::GhostPay),
            _ => None,
        }
    }
}

/// Verification result message - broadcast when a node verifies another's capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResultMessage {
    /// Node ID being verified (target)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub target_node_id: NodeId,
    /// Node ID that issued the challenge (challenger)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub challenger_id: NodeId,
    /// Capability being verified
    pub capability: CapabilityType,
    /// Whether the verification passed
    pub passed: bool,
    /// Challenge details (JSON, capability-specific)
    pub challenge_data: String,
    /// Response details (JSON, capability-specific)
    pub response_data: Option<String>,
    /// Timestamp when challenge was issued
    pub timestamp: i64,
    /// Challenger's signature over (target_node_id || capability || passed || timestamp)
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
}

impl VerificationResultMessage {
    /// Get the data that should be signed
    pub fn signing_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.target_node_id);
        data.extend_from_slice(self.capability.as_str().as_bytes());
        data.push(if self.passed { 1 } else { 0 });
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data
    }
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
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.prev_state_root);
        hasher.update(self.new_state_root);
        hasher.update(self.tx_count.to_le_bytes());
        hasher.update(self.transactions_hash);
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
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.proposal_hash);
        hasher.update([if self.approve { 1u8 } else { 0u8 }]);
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
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.round_id.to_le_bytes());
        hasher.update(self.block_hash);
        hasher.update(self.total_available.to_le_bytes());
        hasher.update(self.miner_sum.to_le_bytes());
        hasher.update(self.node_sum.to_le_bytes());
        hasher.update(self.treasury_amount.to_le_bytes());
        hasher.update(self.payout_merkle_root);
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
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.proposal_hash);
        hasher.update([if self.approve { 1u8 } else { 0u8 }]);
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

/// P2P-H3: Equivocation proof message for Byzantine behavior evidence
///
/// Broadcast when a node is detected voting for conflicting proposals in the same round.
/// Receiving nodes should:
/// 1. Verify the proof (both signatures must be valid for the claimed node)
/// 2. Ban the equivocating node
/// 3. Persist the proof for forensic analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivocationProofMessage {
    /// Node ID of the equivocating node
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub equivocator: [u8; 32],
    /// Round in which equivocation occurred
    pub round_id: u64,
    /// Type of vote (e.g., "payout_vote", "zk_vote")
    pub vote_type: String,
    /// First vote (serialized VoteMessage or similar)
    pub vote1_data: Vec<u8>,
    /// Second conflicting vote
    pub vote2_data: Vec<u8>,
    /// Node that detected the equivocation
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub reporter: [u8; 32],
    /// Reporter's signature over the proof
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub reporter_signature: [u8; 64],
    /// Timestamp when equivocation was detected
    pub timestamp: u64,
}

impl EquivocationProofMessage {
    /// Create a new equivocation proof message
    pub fn new(
        equivocator: [u8; 32],
        round_id: u64,
        vote_type: String,
        vote1_data: Vec<u8>,
        vote2_data: Vec<u8>,
        reporter: [u8; 32],
    ) -> Self {
        Self {
            equivocator,
            round_id,
            vote_type,
            vote1_data,
            vote2_data,
            reporter,
            reporter_signature: [0u8; 64], // Must be set via sign()
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        }
    }

    /// Get the message to be signed by the reporter
    pub fn signing_message(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"EquivocationProof/v1");
        hasher.update(self.equivocator);
        hasher.update(self.round_id.to_le_bytes());
        hasher.update(self.vote_type.as_bytes());
        hasher.update(&self.vote1_data);
        hasher.update(&self.vote2_data);
        hasher.update(self.reporter);
        hasher.finalize().into()
    }

    /// Sign the proof with the reporter's identity
    pub fn sign(&mut self, sign_fn: impl FnOnce(&[u8]) -> [u8; 64]) {
        let message = self.signing_message();
        self.reporter_signature = sign_fn(&message);
    }

    /// Verify the reporter's signature
    ///
    /// SEC-SIG-3: Logs errors instead of silently returning false
    pub fn verify_reporter_signature(&self) -> bool {
        let message = self.signing_message();
        match ghost_common::identity::verify_signature(
            &self.reporter,
            &message,
            &self.reporter_signature,
        ) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::warn!(
                    reporter = %hex::encode(&self.reporter[..8]),
                    error = %e,
                    "Equivocation proof signature verification error"
                );
                false
            }
        }
    }
}

// =============================================================================
// P2P-C1/C2/C3: CANONICAL ELDER LIST Messages
// =============================================================================

/// P2P-C1: Elder registration proposal message
///
/// Sent when a node wants to register as an elder. Requires PoW proof
/// and 7-day uptime at 95%+. Current elders vote on the proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElderRegistrationProposalMessage {
    /// Candidate's node ID
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub candidate: NodeId,
    /// PoW nonce that was mined
    pub pow_nonce: u64,
    /// PoW difficulty achieved
    pub pow_difficulty: u32,
    /// Candidate's first seen timestamp (Unix seconds)
    pub first_seen: u64,
    /// Current uptime percentage (must be >= 95%)
    pub uptime_percent: f64,
    /// Proposer's node ID (the candidate or an elder nominating them)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub proposer: NodeId,
    /// Proposer's signature over the proposal data
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub proposer_signature: [u8; 64],
    /// Target epoch (current epoch + 1)
    pub target_epoch: u64,
    /// Timestamp of proposal (Unix milliseconds)
    pub timestamp: u64,
}

impl ElderRegistrationProposalMessage {
    /// Get the message to be signed
    pub fn signing_message(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"ElderRegistrationProposal/v1");
        hasher.update(self.candidate);
        hasher.update(self.pow_nonce.to_le_bytes());
        hasher.update(self.pow_difficulty.to_le_bytes());
        hasher.update(self.first_seen.to_le_bytes());
        hasher.update(self.uptime_percent.to_le_bytes());
        hasher.update(self.target_epoch.to_le_bytes());
        hasher.finalize().into()
    }

    /// Verify the proposer's signature
    ///
    /// SEC-SIG-4: Logs errors instead of silently returning false
    pub fn verify_signature(&self) -> bool {
        let message = self.signing_message();
        match ghost_common::identity::verify_signature(
            &self.proposer,
            &message,
            &self.proposer_signature,
        ) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::warn!(
                    proposer = %hex::encode(&self.proposer[..8]),
                    candidate = %hex::encode(&self.candidate[..8]),
                    error = %e,
                    "Elder registration proposal signature verification error"
                );
                false
            }
        }
    }
}

/// P2P-C2: Elder list proposal message
///
/// Proposes a new canonical elder list for a new epoch. Contains all
/// elders and the merkle root. Requires >67% approval from current elders.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElderListProposalMessage {
    /// Proposed epoch number
    pub epoch: u64,
    /// Merkle root of the elder list
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub merkle_root: [u8; 32],
    /// Number of elders in the list
    pub elder_count: u32,
    /// Serialized elder entries (for nodes that need the full list)
    pub elders_data: Vec<u8>,
    /// Proposer's node ID
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub proposer: NodeId,
    /// Proposer's signature
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub proposer_signature: [u8; 64],
    /// Timestamp (Unix milliseconds)
    pub timestamp: u64,
}

impl ElderListProposalMessage {
    /// Get the message to be signed
    pub fn signing_message(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"ElderListProposal/v1");
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.merkle_root);
        hasher.update(self.elder_count.to_le_bytes());
        hasher.finalize().into()
    }

    /// Verify the proposer's signature
    ///
    /// SEC-SIG-5: Logs errors instead of silently returning false
    pub fn verify_signature(&self) -> bool {
        let message = self.signing_message();
        match ghost_common::identity::verify_signature(
            &self.proposer,
            &message,
            &self.proposer_signature,
        ) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::warn!(
                    proposer = %hex::encode(&self.proposer[..8]),
                    epoch = self.epoch,
                    error = %e,
                    "Elder list proposal signature verification error"
                );
                false
            }
        }
    }
}

/// P2P-C3: Elder list approval message
///
/// An approval vote from an elder for a proposed elder list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElderListApprovalMessage {
    /// Epoch being approved
    pub epoch: u64,
    /// Merkle root being approved
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub merkle_root: [u8; 32],
    /// Approver's node ID (must be an elder in current epoch)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub approver: NodeId,
    /// Approver's signature over (epoch || merkle_root)
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
    /// Timestamp (Unix milliseconds)
    pub timestamp: u64,
}

impl ElderListApprovalMessage {
    /// Get the message to be signed
    pub fn signing_message(epoch: u64, merkle_root: &[u8; 32]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(48); // 8 + 8 + 32
        msg.extend_from_slice(b"ElderListApproval/v1");
        msg.extend_from_slice(&epoch.to_le_bytes());
        msg.extend_from_slice(merkle_root);
        msg
    }

    /// Create a new approval message
    pub fn new(
        epoch: u64,
        merkle_root: [u8; 32],
        approver: NodeId,
        sign_fn: impl FnOnce(&[u8]) -> [u8; 64],
    ) -> Self {
        let message = Self::signing_message(epoch, &merkle_root);
        let signature = sign_fn(&message);
        Self {
            epoch,
            merkle_root,
            approver,
            signature,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        }
    }

    /// Verify the approver's signature
    ///
    /// SEC-SIG-6: Logs errors instead of silently returning false
    pub fn verify_signature(&self) -> bool {
        let message = Self::signing_message(self.epoch, &self.merkle_root);
        match ghost_common::identity::verify_signature(&self.approver, &message, &self.signature) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::warn!(
                    approver = %hex::encode(&self.approver[..8]),
                    epoch = self.epoch,
                    error = %e,
                    "Elder list approval signature verification error"
                );
                false
            }
        }
    }
}

/// Elder registration vote message
///
/// An elder's vote on whether to approve a new elder registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElderRegistrationVoteMessage {
    /// Candidate being voted on
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub candidate: NodeId,
    /// Target epoch
    pub target_epoch: u64,
    /// Voter's node ID (must be current elder)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub voter: NodeId,
    /// Approve (true) or reject (false)
    pub approve: bool,
    /// Rejection reason if not approved
    pub rejection_reason: Option<String>,
    /// Voter's signature
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
    /// Timestamp (Unix milliseconds)
    pub timestamp: u64,
}

impl ElderRegistrationVoteMessage {
    /// Get the message to be signed
    pub fn signing_message(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"ElderRegistrationVote/v1");
        hasher.update(self.candidate);
        hasher.update(self.target_epoch.to_le_bytes());
        hasher.update([self.approve as u8]);
        hasher.finalize().into()
    }

    /// Verify the voter's signature
    ///
    /// SEC-SIG-7: Logs errors instead of silently returning false
    pub fn verify_signature(&self) -> bool {
        let message = self.signing_message();
        match ghost_common::identity::verify_signature(&self.voter, &message, &self.signature) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::warn!(
                    voter = %hex::encode(&self.voter[..8]),
                    candidate = %hex::encode(&self.candidate[..8]),
                    error = %e,
                    "Elder registration vote signature verification error"
                );
                false
            }
        }
    }
}

// =============================================================================
// MPC-C1/C2/C3/C4: MPC CEREMONY Messages
// =============================================================================

/// MPC-C1: MPC contribution message
///
/// Sent by a node becoming an elder to contribute to the MPC ceremony.
/// Contains the new parameters hash and proof of valid transformation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcContributionMessage {
    /// Candidate's node ID (must match pending registration)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub candidate: NodeId,
    /// Elder position (1-101)
    pub elder_position: u32,
    /// Hash of the previous parameters (chain link)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub prev_params_hash: [u8; 32],
    /// Hash of the new parameters after contribution
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub new_params_hash: [u8; 32],
    /// Proof of valid contribution (Schnorr proof data)
    pub contribution_proof: Vec<u8>,
    /// Candidate's signature over the contribution
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
    /// Timestamp (Unix milliseconds)
    pub timestamp: u64,
}

impl MpcContributionMessage {
    /// Get the message to be signed
    pub fn signing_message(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"MpcContribution/v1");
        hasher.update(self.candidate);
        hasher.update(self.elder_position.to_le_bytes());
        hasher.update(self.prev_params_hash);
        hasher.update(self.new_params_hash);
        hasher.update(sha2::Sha256::digest(&self.contribution_proof));
        hasher.finalize().into()
    }

    /// Get a hash of this contribution for voting reference
    pub fn contribution_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"MpcContributionHash/v1");
        hasher.update(self.candidate);
        hasher.update(self.elder_position.to_le_bytes());
        hasher.update(self.new_params_hash);
        hasher.finalize().into()
    }

    /// Verify the candidate's signature
    pub fn verify_signature(&self) -> bool {
        let message = self.signing_message();
        match ghost_common::identity::verify_signature(&self.candidate, &message, &self.signature) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::warn!(
                    candidate = %hex::encode(&self.candidate[..8]),
                    position = self.elder_position,
                    error = %e,
                    "MPC contribution signature verification error"
                );
                false
            }
        }
    }
}

/// MPC-C2: MPC verification vote message
///
/// Sent by current elders to vote on an MPC contribution.
/// Requires >67% approval before contribution is applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcVerificationVoteMessage {
    /// Hash of the contribution being voted on
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub contribution_hash: [u8; 32],
    /// Voter's node ID (must be current elder)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub voter: NodeId,
    /// Approve (true) or reject (false)
    pub approve: bool,
    /// Rejection reason if not approved
    pub rejection_reason: Option<String>,
    /// Voter's signature
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
    /// Timestamp (Unix milliseconds)
    pub timestamp: u64,
}

impl MpcVerificationVoteMessage {
    /// Get the message to be signed
    pub fn signing_message(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"MpcVerificationVote/v1");
        hasher.update(self.contribution_hash);
        hasher.update([self.approve as u8]);
        hasher.finalize().into()
    }

    /// Verify the voter's signature
    pub fn verify_signature(&self) -> bool {
        let message = self.signing_message();
        match ghost_common::identity::verify_signature(&self.voter, &message, &self.signature) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::warn!(
                    voter = %hex::encode(&self.voter[..8]),
                    contribution = %hex::encode(&self.contribution_hash[..8]),
                    error = %e,
                    "MPC verification vote signature verification error"
                );
                false
            }
        }
    }
}

/// MPC-C3: MPC parameters request message
///
/// Request parameter files from peers. Used during node startup
/// when local parameters are missing or outdated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcParametersRequestMessage {
    /// Requester's node ID
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub requester: NodeId,
    /// Hash of parameters being requested
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub params_hash: [u8; 32],
    /// Specific chunk indices to request (empty = all)
    pub chunk_indices: Vec<u32>,
    /// Timestamp (Unix milliseconds)
    pub timestamp: u64,
}

/// MPC-C4: MPC parameters response message
///
/// Response containing chunked parameter data.
/// Parameters are ~200MB, so must be transferred in chunks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcParametersResponseMessage {
    /// Hash of the parameters being sent
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub params_hash: [u8; 32],
    /// Total size of parameters in bytes
    pub total_size: u64,
    /// Total number of chunks
    pub total_chunks: u32,
    /// Index of this chunk (0-based)
    pub chunk_index: u32,
    /// Chunk data (up to 1MB per chunk)
    pub chunk_data: Vec<u8>,
    /// Sender's node ID
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub sender: NodeId,
    /// Timestamp (Unix milliseconds)
    pub timestamp: u64,
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
    fn test_message_topic_str() {
        // M-P2P-1: Test that topic_str() returns correct string for each message type
        assert_eq!(MessageType::ShareProof.topic_str(), "share");
        assert_eq!(MessageType::ShareConvergence.topic_str(), "share");
        assert_eq!(MessageType::BlockFound.topic_str(), "block");
        assert_eq!(MessageType::PayoutProposal.topic_str(), "payout");
        assert_eq!(MessageType::Vote.topic_str(), "vote");
        assert_eq!(MessageType::HealthPing.topic_str(), "health");
        assert_eq!(MessageType::Discovery.topic_str(), "discovery");
        assert_eq!(MessageType::ElderUpdate.topic_str(), "elder");
        assert_eq!(MessageType::ZkBlockProposal.topic_str(), "zkproposal");
        assert_eq!(MessageType::ZkVote.topic_str(), "zkvote");
        assert_eq!(MessageType::ZkPayoutProposal.topic_str(), "zkpayout");
        assert_eq!(MessageType::ZkPayoutVote.topic_str(), "zkpvote");
        assert_eq!(MessageType::VerificationResult.topic_str(), "verify");
    }

    #[test]
    fn test_topic_str_matches_topic_bytes() {
        // M-P2P-1: Verify that topic_str() is consistent with topic() bytes
        // This ensures the validation logic works correctly
        let message_types = [
            MessageType::ShareProof,
            MessageType::BlockFound,
            MessageType::PayoutProposal,
            MessageType::Vote,
            MessageType::HealthPing,
            MessageType::Discovery,
            MessageType::ElderUpdate,
            MessageType::ZkBlockProposal,
            MessageType::ZkVote,
            MessageType::ZkPayoutProposal,
            MessageType::ZkPayoutVote,
            MessageType::VerificationResult,
        ];

        for msg_type in message_types {
            let topic_bytes = msg_type.topic();
            let topic_str = msg_type.topic_str();
            assert_eq!(
                topic_bytes,
                topic_str.as_bytes(),
                "topic() and topic_str() mismatch for {:?}",
                msg_type
            );
        }
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
        let vote = ZkVoteMessage::new(100, [1u8; 32], true, None, [0u8; 64]);

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
