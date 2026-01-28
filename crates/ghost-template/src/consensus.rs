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
//| FILE: consensus.rs                                                                                                   |
//|======================================================================================================================|

//! Consensus integration for block templates
//!
//! This module connects block template processing with BFT voting.
//! Before a block is mined, the payout proposal must reach consensus.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::FilteredTemplate;

/// Consensus status for a block template
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusStatus {
    /// Awaiting pre-consensus vote
    AwaitingVote,
    /// Pre-consensus approved
    Approved,
    /// Pre-consensus rejected
    Rejected,
    /// Timeout (use fallback)
    Timeout,
    /// Not required (solo mining)
    NotRequired,
}

impl ConsensusStatus {
    /// Check if template can be distributed to miners
    pub fn can_distribute(&self) -> bool {
        matches!(
            self,
            ConsensusStatus::Approved | ConsensusStatus::NotRequired
        )
    }

    /// Get status name
    pub fn name(&self) -> &'static str {
        match self {
            ConsensusStatus::AwaitingVote => "Awaiting Vote",
            ConsensusStatus::Approved => "Approved",
            ConsensusStatus::Rejected => "Rejected",
            ConsensusStatus::Timeout => "Timeout",
            ConsensusStatus::NotRequired => "Not Required",
        }
    }
}

/// Block template with consensus tracking
#[derive(Debug, Clone)]
pub struct ConsensusTemplate {
    /// The filtered template
    pub template: FilteredTemplate,
    /// Payout proposal hash
    pub proposal_hash: [u8; 32],
    /// Current consensus status
    pub status: ConsensusStatus,
    /// Round ID for voting
    pub round_id: u64,
    /// Created timestamp
    pub created_at: u64,
    /// Consensus deadline (Unix timestamp)
    pub deadline: u64,
}

impl ConsensusTemplate {
    /// Create a new consensus template
    pub fn new(template: FilteredTemplate, round_id: u64, timeout_secs: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Compute proposal hash from template
        let proposal_hash = compute_proposal_hash(&template);

        Self {
            template,
            proposal_hash,
            status: ConsensusStatus::AwaitingVote,
            round_id,
            created_at: now,
            deadline: now + timeout_secs,
        }
    }

    /// Create a template that doesn't require consensus (solo mining)
    pub fn solo(template: FilteredTemplate) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            proposal_hash: compute_proposal_hash(&template),
            template,
            status: ConsensusStatus::NotRequired,
            round_id: 0,
            created_at: now,
            deadline: now,
        }
    }

    /// Mark as approved
    pub fn approve(&mut self) {
        self.status = ConsensusStatus::Approved;
    }

    /// Mark as rejected
    pub fn reject(&mut self) {
        self.status = ConsensusStatus::Rejected;
    }

    /// Mark as timed out
    pub fn timeout(&mut self) {
        self.status = ConsensusStatus::Timeout;
    }

    /// Check if consensus deadline has passed
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now >= self.deadline
    }

    /// Get remaining time until deadline
    pub fn remaining_secs(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.deadline.saturating_sub(now)
    }

    /// Get proposal hash as hex
    pub fn proposal_hash_hex(&self) -> String {
        hex::encode(self.proposal_hash)
    }

    /// Get the merkle root
    pub fn merkle_root(&self) -> &[u8; 32] {
        &self.template.merkle_root
    }

    /// Get block height
    pub fn height(&self) -> u64 {
        self.template.original.height
    }

    /// Get total coinbase value
    pub fn coinbase_value(&self) -> u64 {
        self.template.original.coinbasevalue
    }
}

/// Compute proposal hash from filtered template
pub fn compute_proposal_hash(template: &FilteredTemplate) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Include template identifying info
    hasher.update(b"ghost_proposal_v1");
    hasher.update(&template.original.height.to_le_bytes());
    hasher.update(&template.merkle_root);
    hasher.update(&template.original.coinbasevalue.to_le_bytes());
    hasher.update(&template.total_fee.to_le_bytes());

    // Include transaction count
    hasher.update(&(template.included_indices.len() as u32).to_le_bytes());

    hasher.finalize().into()
}

/// Pre-consensus payout proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutProposal {
    /// Proposal hash
    pub hash: [u8; 32],
    /// Block height
    pub height: u64,
    /// Total coinbase value (subsidy + fees)
    pub coinbase_value: u64,
    /// Pool fee amount
    pub pool_fee: u64,
    /// Miner payouts
    pub payouts: Vec<PayoutEntry>,
    /// Merkle root of filtered template
    pub merkle_root: [u8; 32],
    /// Created timestamp
    pub created_at: u64,
}

impl PayoutProposal {
    /// Create from consensus template
    pub fn from_template(
        template: &ConsensusTemplate,
        payouts: Vec<PayoutEntry>,
        pool_fee: u64,
    ) -> Self {
        Self {
            hash: template.proposal_hash,
            height: template.height(),
            coinbase_value: template.coinbase_value(),
            pool_fee,
            payouts,
            merkle_root: *template.merkle_root(),
            created_at: template.created_at,
        }
    }

    /// Compute the proposal hash
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"ghost_payout_v1");
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.coinbase_value.to_le_bytes());
        hasher.update(&self.pool_fee.to_le_bytes());
        hasher.update(&self.merkle_root);

        // Include payout merkle
        for payout in &self.payouts {
            hasher.update(&payout.hash());
        }

        hasher.finalize().into()
    }

    /// Verify the proposal hash
    pub fn verify_hash(&self) -> bool {
        self.hash == self.compute_hash()
    }

    /// Total payout amount
    pub fn total_payout(&self) -> u64 {
        self.payouts.iter().map(|p| p.amount).sum()
    }

    /// Verify amounts add up
    pub fn verify_amounts(&self) -> bool {
        self.total_payout() + self.pool_fee == self.coinbase_value
    }
}

/// Single payout entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutEntry {
    /// Recipient address (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
    pub address: String,
    /// Amount in satoshis
    pub amount: u64,
    /// Share percentage
    pub share_percent: f64,
}

impl PayoutEntry {
    /// Create a new payout entry
    pub fn new(address: String, amount: u64, share_percent: f64) -> Self {
        Self {
            address,
            amount,
            share_percent,
        }
    }

    /// Hash for merkle tree
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.address.as_bytes());
        hasher.update(&self.amount.to_le_bytes());
        hasher.finalize().into()
    }
}

/// Block flow state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockFlowState {
    /// Waiting for new block template
    WaitingForTemplate,
    /// Template received, filtering
    Filtering,
    /// Filtered, building payout proposal
    BuildingProposal,
    /// Proposal built, awaiting consensus
    AwaitingConsensus,
    /// Consensus reached, distributing to miners
    Distributing,
    /// Block found, verifying
    Verifying,
    /// Block submitted to network
    Submitted,
}

impl BlockFlowState {
    /// Get state name
    pub fn name(&self) -> &'static str {
        match self {
            BlockFlowState::WaitingForTemplate => "Waiting for Template",
            BlockFlowState::Filtering => "Filtering",
            BlockFlowState::BuildingProposal => "Building Proposal",
            BlockFlowState::AwaitingConsensus => "Awaiting Consensus",
            BlockFlowState::Distributing => "Distributing",
            BlockFlowState::Verifying => "Verifying",
            BlockFlowState::Submitted => "Submitted",
        }
    }

    /// Check if in a processing state
    pub fn is_processing(&self) -> bool {
        !matches!(
            self,
            BlockFlowState::WaitingForTemplate | BlockFlowState::Submitted
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::{BlockTemplate, CoinbaseAux};

    fn create_test_template() -> FilteredTemplate {
        FilteredTemplate {
            original: BlockTemplate {
                version: 0x20000000,
                previousblockhash: "0".repeat(64),
                transactions: vec![],
                coinbaseaux: CoinbaseAux::default(),
                coinbasevalue: 625_000_000,
                bits: "1d00ffff".to_string(),
                height: 800_000,
                curtime: 0,
                mintime: 0,
                mutable: vec![],
                noncerange: "".to_string(),
                sigoplimit: 80000,
                sizelimit: 4000000,
                weightlimit: 4000000,
                longpollid: None,
                target: "0".repeat(64),
            },
            included_indices: vec![],
            rejected_indices: vec![],
            merkle_root: [0u8; 32],
            total_fee: 0,
            total_weight: 0,
        }
    }

    #[test]
    fn test_consensus_template() {
        let template = create_test_template();
        let consensus = ConsensusTemplate::new(template, 1, 30);

        assert_eq!(consensus.status, ConsensusStatus::AwaitingVote);
        assert!(!consensus.status.can_distribute());
    }

    #[test]
    fn test_consensus_approval() {
        let template = create_test_template();
        let mut consensus = ConsensusTemplate::new(template, 1, 30);

        consensus.approve();
        assert_eq!(consensus.status, ConsensusStatus::Approved);
        assert!(consensus.status.can_distribute());
    }

    #[test]
    fn test_payout_proposal() {
        let template = create_test_template();
        let consensus = ConsensusTemplate::new(template, 1, 30);

        let payouts = vec![
            PayoutEntry::new("bc1qtest".to_string(), 600_000_000, 96.0),
            PayoutEntry::new("bc1qpool".to_string(), 25_000_000, 4.0),
        ];

        let proposal = PayoutProposal::from_template(&consensus, payouts, 0);
        assert_eq!(proposal.height, 800_000);
        assert_eq!(proposal.coinbase_value, 625_000_000);
    }
}
