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
    }
}
