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
//| FILE: voting.rs                                                                                                      |
//|======================================================================================================================|

//! BFT voting implementation
//!
//! Implements Byzantine Fault Tolerant voting with 67% threshold.
//!
//! # Time Handling
//!
//! Voting sessions use monotonic time (std::time::Instant) for timeout tracking.
//! This ensures timeouts work correctly even if the system clock is adjusted.
//!
//! # Security Features
//!
//! - **Equivocation Detection**: Detects when a voter signs both approve AND reject
//!   for the same proposal. This is Byzantine behavior and produces VoteEquivocationProof.
//!
//! - **Replay Prevention**: Votes are signed over `H(round_id || proposal_hash || voter_id || decision)`
//!   to prevent replaying votes from one round in another.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use tracing::{debug, error, info, warn};

use ghost_common::constants::BFT_THRESHOLD_PERCENT;
use ghost_common::identity::verify_signature;
use ghost_common::types::{ConsensusResult, NodeId, RoundId, VoteType};

use crate::elder_list::CanonicalElderList;

/// Proof of equivocation - a voter signing conflicting votes
///
/// This proves that a node voted both approve AND reject for the same proposal,
/// which is Byzantine behavior. This proof can be broadcast to other nodes to
/// justify slashing/banning the equivocating node.
///
/// P2P4-L7: Serializable for database persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteEquivocationProof {
    /// The equivocating voter's node ID
    #[serde(with = "hash_bytes")]
    pub voter: NodeId,
    /// The round ID where equivocation occurred
    pub round_id: RoundId,
    /// The proposal hash that was voted on
    #[serde(with = "hash_bytes")]
    pub proposal_hash: [u8; 32],
    /// The first vote (with signature)
    pub vote1: Vote,
    /// The second, conflicting vote (with signature)
    pub vote2: Vote,
}

/// Serde helper for serializing/deserializing [u8; 32] as hex
mod hash_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        hex::encode(bytes).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("hash must be 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

impl VoteEquivocationProof {
    /// Create an equivocation proof from two conflicting votes
    pub fn from_votes(
        round_id: RoundId,
        proposal_hash: [u8; 32],
        vote1: &Vote,
        vote2: &Vote,
    ) -> Self {
        debug_assert_eq!(vote1.voter, vote2.voter, "Votes must be from same voter");
        debug_assert_ne!(
            vote1.approve, vote2.approve,
            "Votes must have different decisions"
        );

        Self {
            voter: vote1.voter,
            round_id,
            proposal_hash,
            vote1: vote1.clone(),
            vote2: vote2.clone(),
        }
    }

    /// Verify that this proof is valid
    ///
    /// Checks that:
    /// 1. Both votes are from the same voter
    /// 2. Both votes have different decisions
    /// 3. Both signatures are valid
    pub fn verify(&self) -> bool {
        // Both votes must be from the same voter
        if self.vote1.voter != self.vote2.voter {
            return false;
        }

        // Must have different decisions
        if self.vote1.approve == self.vote2.approve {
            return false;
        }

        // Verify both signatures
        let valid1 = verify_vote_signature_with_round(
            &self.vote1,
            self.round_id,
            &self.proposal_hash,
            &self.vote1.voter,
        );
        let valid2 = verify_vote_signature_with_round(
            &self.vote2,
            self.round_id,
            &self.proposal_hash,
            &self.vote2.voter,
        );

        valid1 && valid2
    }
}

/// Voting session for a specific proposal
#[derive(Debug)]
pub struct VotingSession {
    /// Round ID
    pub round_id: RoundId,
    /// Proposal hash
    pub proposal_hash: [u8; 32],
    /// Vote type
    pub vote_type: VoteType,
    /// Session start time (monotonic, for timeout calculation)
    pub started: Instant,
    /// Timeout (milliseconds)
    pub timeout_ms: u64,
    /// Eligible voters (node IDs)
    pub eligible_voters: HashSet<NodeId>,
    /// Votes received (stores full vote including signature for equivocation detection)
    pub votes: HashMap<NodeId, Vote>,
    /// Result (if decided)
    pub result: Option<ConsensusResult>,
    /// Detected equivocations
    pub equivocations: Vec<VoteEquivocationProof>,
}

impl VotingSession {
    /// Create a new voting session
    ///
    /// SEC-VOTE-3: This constructor is crate-private. External code should use
    /// from_elder_list() to ensure all nodes agree on eligible voters through
    /// the canonical elder list for BFT security.
    ///
    /// Within the crate, this can be used during the transition period while
    /// vote_handler.rs is being migrated to use CanonicalElderList.
    pub(crate) fn new(
        round_id: RoundId,
        proposal_hash: [u8; 32],
        vote_type: VoteType,
        eligible_voters: HashSet<NodeId>,
        timeout_ms: u64,
    ) -> Self {
        Self {
            round_id,
            proposal_hash,
            vote_type,
            started: Instant::now(),
            timeout_ms,
            eligible_voters,
            votes: HashMap::new(),
            result: None,
            equivocations: Vec::new(),
        }
    }

    /// Create a new voting session using a canonical elder list
    ///
    /// P2P-C1/C2/C3: This constructor uses the canonical elder list to determine
    /// eligible voters, ensuring all nodes agree on who can vote.
    ///
    /// SEC-VOTE-4: This is the ONLY public constructor for production use.
    pub fn from_elder_list(
        round_id: RoundId,
        proposal_hash: [u8; 32],
        vote_type: VoteType,
        elder_list: &CanonicalElderList,
        timeout_ms: u64,
    ) -> Self {
        let eligible_voters = elder_list.get_eligible_voters();

        // SEC-VOTE-5: Warn if quorum is too small for BFT
        if eligible_voters.len() < 3 {
            warn!(
                epoch = elder_list.epoch,
                voters = eligible_voters.len(),
                "Voting session created with fewer than 3 eligible voters - BFT requires n >= 3f+1"
            );
        }

        info!(
            round_id,
            epoch = elder_list.epoch,
            eligible_count = eligible_voters.len(),
            "Created voting session from canonical elder list"
        );
        Self::new(
            round_id,
            proposal_hash,
            vote_type,
            eligible_voters,
            timeout_ms,
        )
    }

    /// Test-only constructor for creating voting sessions with arbitrary voters
    ///
    /// SEC-VOTE-6: This is intentionally only available in test builds.
    /// Production code MUST use from_elder_list() to ensure BFT security.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_for_testing(
        round_id: RoundId,
        proposal_hash: [u8; 32],
        vote_type: VoteType,
        eligible_voters: HashSet<NodeId>,
        timeout_ms: u64,
    ) -> Self {
        Self::new(round_id, proposal_hash, vote_type, eligible_voters, timeout_ms)
    }

    /// Add a vote to the session
    pub fn add_vote(&mut self, vote: Vote) -> VoteResult {
        // Check if already decided
        if self.result.is_some() {
            return VoteResult::AlreadyDecided;
        }

        // Check if voter is eligible
        if !self.eligible_voters.contains(&vote.voter) {
            return VoteResult::NotEligible;
        }

        // Verify signature (includes round_id to prevent replay)
        if !verify_vote_signature_with_round(&vote, self.round_id, &self.proposal_hash, &vote.voter)
        {
            return VoteResult::InvalidSignature;
        }

        // Check for existing vote - this is where we detect equivocation
        if let Some(existing) = self.votes.get(&vote.voter) {
            // Same decision = duplicate vote (benign)
            if existing.approve == vote.approve {
                return VoteResult::DuplicateVote;
            }

            // Different decision = EQUIVOCATION (Byzantine behavior!)
            let proof = VoteEquivocationProof::from_votes(
                self.round_id,
                self.proposal_hash,
                existing,
                &vote,
            );

            warn!(
                voter = %hex::encode(&vote.voter[..8]),
                round_id = self.round_id,
                "EQUIVOCATION DETECTED: voter signed both approve and reject"
            );

            self.equivocations.push(proof.clone());

            return VoteResult::Equivocation(Box::new(proof));
        }

        // Record vote
        let approved = vote.approve;
        self.votes.insert(vote.voter, vote);

        debug!(
            round_id = self.round_id,
            total_votes = self.votes.len(),
            eligible = self.eligible_voters.len(),
            "Vote recorded"
        );

        // Check if we've reached a decision
        if let Some(result) = self.check_decision() {
            self.result = Some(result.clone());
            return VoteResult::Decided(result);
        }

        if approved {
            VoteResult::ApprovalRecorded
        } else {
            VoteResult::RejectionRecorded
        }
    }

    /// Check if a decision has been reached
    fn check_decision(&self) -> Option<ConsensusResult> {
        // SEC-VOTE-7: Protect against overflow for extremely large voter sets
        let voter_count = self.eligible_voters.len();
        let total = if voter_count > u32::MAX as usize {
            error!(
                voter_count = voter_count,
                "Voter count exceeds u32::MAX - capping"
            );
            u32::MAX
        } else {
            voter_count as u32
        };

        // Use ceiling division: (total * 67 + 99) / 100 to round up
        // For 4 nodes: (4 * 67 + 99) / 100 = 367 / 100 = 3
        // SEC-VOTE-8: Use checked_mul to detect overflow
        let threshold = (total as u64)
            .checked_mul(BFT_THRESHOLD_PERCENT)
            .map(|v| v.div_ceil(100) as u32)
            .unwrap_or(total); // Fallback: require all voters if overflow

        let approvals = self.votes.values().filter(|v| v.approve).count() as u32;
        let rejections = self.votes.values().filter(|v| !v.approve).count() as u32;

        // Check for approval
        if approvals >= threshold {
            return Some(ConsensusResult::Approved {
                proposal_hash: self.proposal_hash,
                approval_count: approvals,
                total_nodes: total,
            });
        }

        // Check for rejection
        if rejections >= threshold {
            return Some(ConsensusResult::Rejected {
                proposal_hash: self.proposal_hash,
                rejection_count: rejections,
                total_nodes: total,
                reason: None,
            });
        }

        // Check if mathematically impossible to reach threshold
        let remaining = total - (approvals + rejections);
        if approvals + remaining < threshold && rejections + remaining < threshold {
            // Neither side can win
            return Some(ConsensusResult::Timeout {
                proposal_hash: self.proposal_hash,
                approvals,
                rejections,
                total_nodes: total,
            });
        }

        None
    }

    /// Check if session has timed out (uses monotonic time)
    pub fn is_timed_out(&self) -> bool {
        self.started.elapsed().as_millis() as u64 > self.timeout_ms
    }

    /// Force timeout result
    pub fn timeout(&mut self) -> ConsensusResult {
        let total = self.eligible_voters.len() as u32;
        let approvals = self.votes.values().filter(|v| v.approve).count() as u32;
        let rejections = self.votes.values().filter(|v| !v.approve).count() as u32;

        let result = ConsensusResult::Timeout {
            proposal_hash: self.proposal_hash,
            approvals,
            rejections,
            total_nodes: total,
        };

        self.result = Some(result.clone());
        result
    }

    /// Get current vote counts
    pub fn vote_counts(&self) -> (u32, u32, u32) {
        let approvals = self.votes.values().filter(|v| v.approve).count() as u32;
        let rejections = self.votes.values().filter(|v| !v.approve).count() as u32;
        let total = self.eligible_voters.len() as u32;
        (approvals, rejections, total)
    }

    /// Get required threshold
    pub fn threshold(&self) -> u32 {
        let total = self.eligible_voters.len() as u64;
        // Use ceiling division to ensure proper 67% threshold
        (total * BFT_THRESHOLD_PERCENT).div_ceil(100) as u32
    }

    /// Get detected equivocations
    pub fn get_equivocations(&self) -> &[VoteEquivocationProof] {
        &self.equivocations
    }
}

/// A single vote
///
/// P2P4-L7: Serializable for equivocation proof persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    /// Voter node ID
    #[serde(with = "hash_bytes")]
    pub voter: NodeId,
    /// Approve or reject
    pub approve: bool,
    /// Signature over H(round_id || proposal_hash || voter_id || decision)
    /// Note: Using Vec<u8> wrapper for serde compatibility
    #[serde(with = "signature_bytes")]
    pub signature: [u8; 64],
    /// Timestamp
    pub timestamp: u64,
}

/// Serde helper for serializing/deserializing [u8; 64] as hex
mod signature_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        hex::encode(bytes).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("signature must be 64 bytes"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

impl Vote {
    /// Create a new vote
    pub fn new(voter: NodeId, approve: bool, signature: [u8; 64]) -> Self {
        Self {
            voter,
            approve,
            signature,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        }
    }
}

/// Result of adding a vote
#[derive(Debug, Clone)]
pub enum VoteResult {
    /// Vote recorded as approval
    ApprovalRecorded,
    /// Vote recorded as rejection
    RejectionRecorded,
    /// Consensus decided
    Decided(ConsensusResult),
    /// Session already decided
    AlreadyDecided,
    /// Voter not eligible
    NotEligible,
    /// Duplicate vote from same voter (same decision)
    DuplicateVote,
    /// Invalid signature
    InvalidSignature,
    /// Equivocation detected (voter signed conflicting votes)
    Equivocation(Box<VoteEquivocationProof>),
}

/// Compute the message that should be signed for a vote
///
/// Format: SHA256(round_id || proposal_hash || voter_id || decision_byte)
///
/// Including round_id prevents replay attacks across rounds.
/// Including voter_id prevents signature theft/reuse.
pub fn compute_vote_signing_message(
    round_id: RoundId,
    proposal_hash: &[u8; 32],
    voter_id: &NodeId,
    approve: bool,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"GhostVote/v1");
    hasher.update(round_id.to_le_bytes());
    hasher.update(proposal_hash);
    hasher.update(voter_id);
    hasher.update([if approve { 1u8 } else { 0u8 }]);
    hasher.finalize().into()
}

/// Verify vote signature with round_id included
///
/// This is the secure verification that prevents replay attacks.
fn verify_vote_signature_with_round(
    vote: &Vote,
    round_id: RoundId,
    proposal_hash: &[u8; 32],
    voter_id: &NodeId,
) -> bool {
    let message = compute_vote_signing_message(round_id, proposal_hash, voter_id, vote.approve);
    // SEC-VOTE-1: Log signature verification errors instead of silently failing
    match verify_signature(&vote.voter, &message, &vote.signature) {
        Ok(valid) => valid,
        Err(e) => {
            error!(
                voter = %hex::encode(&vote.voter[..8]),
                round_id = round_id,
                error = %e,
                "Signature verification failed with error (not just invalid)"
            );
            false
        }
    }
}

/// Verify vote signature (legacy - only for backward compatibility)
///
/// DEPRECATED: Use verify_vote_signature_with_round instead
#[deprecated(note = "Use verify_vote_signature_with_round for replay attack prevention")]
pub fn verify_vote_signature(vote: &Vote, proposal_hash: &[u8; 32]) -> bool {
    // SEC-VOTE-2: Log signature verification errors instead of silently failing
    match verify_signature(&vote.voter, proposal_hash, &vote.signature) {
        Ok(valid) => valid,
        Err(e) => {
            warn!(
                voter = %hex::encode(&vote.voter[..8]),
                error = %e,
                "Legacy signature verification failed with error"
            );
            false
        }
    }
}

/// Voting manager for multiple sessions
#[derive(Debug)]
pub struct VotingManager {
    /// Active sessions by (round_id, proposal_hash)
    sessions: RwLock<HashMap<(RoundId, [u8; 32]), VotingSession>>,
    /// Completed sessions (for reference)
    completed: RwLock<Vec<VotingSession>>,
    /// Max completed sessions to keep
    max_completed: usize,
}

impl VotingManager {
    /// Create a new voting manager
    pub fn new(max_completed: usize) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            completed: RwLock::new(Vec::new()),
            max_completed,
        }
    }

    /// Start a new voting session
    pub fn start_session(&self, session: VotingSession) -> bool {
        let key = (session.round_id, session.proposal_hash);

        let mut sessions = self.sessions.write();
        if sessions.contains_key(&key) {
            return false;
        }

        info!(
            round_id = session.round_id,
            voters = session.eligible_voters.len(),
            "Starting voting session"
        );

        sessions.insert(key, session);
        true
    }

    /// Add a vote to a session
    pub fn vote(
        &self,
        round_id: RoundId,
        proposal_hash: [u8; 32],
        vote: Vote,
    ) -> Option<VoteResult> {
        let key = (round_id, proposal_hash);

        let mut sessions = self.sessions.write();
        let session = sessions.get_mut(&key)?;

        let result = session.add_vote(vote);

        // If decided, move to completed
        if let VoteResult::Decided(_) = &result {
            if let Some(session) = sessions.remove(&key) {
                self.add_completed(session);
            }
        }

        Some(result)
    }

    /// Get session status
    pub fn get_session(&self, round_id: RoundId, proposal_hash: [u8; 32]) -> Option<SessionStatus> {
        let key = (round_id, proposal_hash);
        let sessions = self.sessions.read();

        sessions.get(&key).map(|s| SessionStatus {
            round_id: s.round_id,
            proposal_hash: s.proposal_hash,
            vote_type: s.vote_type,
            approvals: s.votes.values().filter(|v| v.approve).count() as u32,
            rejections: s.votes.values().filter(|v| !v.approve).count() as u32,
            total_eligible: s.eligible_voters.len() as u32,
            threshold: s.threshold(),
            is_decided: s.result.is_some(),
            result: s.result.clone(),
        })
    }

    /// Check for timed out sessions
    pub fn check_timeouts(&self) -> Vec<ConsensusResult> {
        let mut results = Vec::new();
        let mut to_complete = Vec::new();

        {
            let mut sessions = self.sessions.write();
            for (key, session) in sessions.iter_mut() {
                if session.is_timed_out() && session.result.is_none() {
                    let result = session.timeout();
                    results.push(result);
                    to_complete.push(*key);
                }
            }

            for key in to_complete {
                if let Some(session) = sessions.remove(&key) {
                    self.add_completed(session);
                }
            }
        }

        results
    }

    /// Cancel all sessions for a round (called on reorg)
    ///
    /// Returns the number of sessions cancelled.
    pub fn cancel_sessions_for_round(&self, round_id: RoundId) -> usize {
        let mut sessions = self.sessions.write();
        let keys_to_remove: Vec<_> = sessions
            .keys()
            .filter(|(rid, _)| *rid == round_id)
            .cloned()
            .collect();

        let count = keys_to_remove.len();
        for key in keys_to_remove {
            if let Some(mut session) = sessions.remove(&key) {
                // Mark as cancelled/rejected due to reorg
                session.result = Some(ConsensusResult::Rejected {
                    proposal_hash: session.proposal_hash,
                    rejection_count: 0, // Not rejected by votes, cancelled by reorg
                    total_nodes: session.eligible_voters.len() as u32,
                    reason: Some("Block orphaned due to reorg".to_string()),
                });
                self.add_completed(session);
            }
        }

        if count > 0 {
            info!(
                round_id,
                sessions_cancelled = count,
                "Cancelled voting sessions due to reorg"
            );
        }

        count
    }

    /// Add completed session
    fn add_completed(&self, session: VotingSession) {
        let mut completed = self.completed.write();
        completed.push(session);

        // Trim if too many
        while completed.len() > self.max_completed {
            completed.remove(0);
        }
    }

    /// Get active session count
    pub fn active_count(&self) -> usize {
        self.sessions.read().len()
    }
}

/// Session status summary
#[derive(Debug, Clone)]
pub struct SessionStatus {
    pub round_id: RoundId,
    pub proposal_hash: [u8; 32],
    pub vote_type: VoteType,
    pub approvals: u32,
    pub rejections: u32,
    pub total_eligible: u32,
    pub threshold: u32,
    pub is_decided: bool,
    pub result: Option<ConsensusResult>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::identity::NodeIdentity;

    fn create_test_session() -> VotingSession {
        let mut eligible = HashSet::new();
        for i in 0..10 {
            eligible.insert([i as u8; 32]);
        }

        VotingSession::new(1, [0u8; 32], VoteType::PayoutApproval, eligible, 5000)
    }

    #[test]
    fn test_voting_threshold() {
        let session = create_test_session();
        // 67% of 10 = 6.7, ceiling = 7
        assert_eq!(session.threshold(), 7);
    }

    #[test]
    fn test_vote_counts() {
        let mut session = create_test_session();

        // Add some votes (without real signatures for testing)
        for i in 0..5 {
            let vote = Vote::new([i as u8; 32], true, [0u8; 64]);
            // In real code this would verify signature, but we're testing counts
            session.votes.insert(vote.voter, vote);
        }

        let (approvals, rejections, total) = session.vote_counts();
        assert_eq!(approvals, 5);
        assert_eq!(rejections, 0);
        assert_eq!(total, 10);
    }

    #[test]
    fn test_vote_signing_message_includes_round_id() {
        let proposal_hash = [1u8; 32];
        let voter_id = [2u8; 32];

        // Different round_ids should produce different signing messages
        let msg1 = compute_vote_signing_message(100, &proposal_hash, &voter_id, true);
        let msg2 = compute_vote_signing_message(200, &proposal_hash, &voter_id, true);

        assert_ne!(
            msg1, msg2,
            "Different round_ids must produce different messages"
        );
    }

    #[test]
    fn test_vote_signing_message_includes_decision() {
        let proposal_hash = [1u8; 32];
        let voter_id = [2u8; 32];
        let round_id = 100;

        // Different decisions should produce different signing messages
        let msg_approve = compute_vote_signing_message(round_id, &proposal_hash, &voter_id, true);
        let msg_reject = compute_vote_signing_message(round_id, &proposal_hash, &voter_id, false);

        assert_ne!(
            msg_approve, msg_reject,
            "Different decisions must produce different messages"
        );
    }

    #[test]
    fn test_vote_signing_message_deterministic() {
        let proposal_hash = [1u8; 32];
        let voter_id = [2u8; 32];
        let round_id = 100;

        let msg1 = compute_vote_signing_message(round_id, &proposal_hash, &voter_id, true);
        let msg2 = compute_vote_signing_message(round_id, &proposal_hash, &voter_id, true);

        assert_eq!(msg1, msg2, "Same inputs must produce same message");
    }

    #[test]
    fn test_vote_replay_rejected_different_round() {
        // Create two sessions with different round_ids
        // Use multiple eligible voters so threshold isn't immediately met
        let proposal_hash = [0u8; 32];
        let identity = NodeIdentity::generate();
        let voter_id = identity.node_id();

        let mut eligible = HashSet::new();
        eligible.insert(voter_id);
        // Add some dummy voters so threshold isn't 1
        for i in 0..5 {
            eligible.insert([i as u8 + 100; 32]);
        }

        let mut session1 = VotingSession::new(
            100,
            proposal_hash,
            VoteType::PayoutApproval,
            eligible.clone(),
            5000,
        );
        let mut session2 =
            VotingSession::new(200, proposal_hash, VoteType::PayoutApproval, eligible, 5000);

        // Sign vote for round 100
        let msg = compute_vote_signing_message(100, &proposal_hash, &voter_id, true);
        let sig = identity.sign(&msg);
        let vote = Vote::new(voter_id, true, sig);

        // Vote should be valid in session1 (round 100)
        let result1 = session1.add_vote(vote.clone());
        assert!(
            matches!(result1, VoteResult::ApprovalRecorded),
            "Expected ApprovalRecorded, got {:?}",
            result1
        );

        // Same vote should be INVALID in session2 (round 200) - replay attack prevented
        let result2 = session2.add_vote(vote);
        assert!(
            matches!(result2, VoteResult::InvalidSignature),
            "Vote from round 100 should be rejected in round 200, got {:?}",
            result2
        );
    }

    #[test]
    fn test_vote_equivocation_detected() {
        let proposal_hash = [0u8; 32];
        let round_id = 100;
        let identity = NodeIdentity::generate();
        let voter_id = identity.node_id();

        // Use multiple eligible voters so threshold isn't immediately met
        let mut eligible = HashSet::new();
        eligible.insert(voter_id);
        for i in 0..5 {
            eligible.insert([i as u8 + 100; 32]);
        }

        let mut session = VotingSession::new(
            round_id,
            proposal_hash,
            VoteType::PayoutApproval,
            eligible,
            5000,
        );

        // First vote: approve
        let msg1 = compute_vote_signing_message(round_id, &proposal_hash, &voter_id, true);
        let sig1 = identity.sign(&msg1);
        let vote1 = Vote::new(voter_id, true, sig1);

        let result1 = session.add_vote(vote1);
        assert!(
            matches!(result1, VoteResult::ApprovalRecorded),
            "Expected ApprovalRecorded, got {:?}",
            result1
        );

        // Second vote: reject (equivocation!)
        let msg2 = compute_vote_signing_message(round_id, &proposal_hash, &voter_id, false);
        let sig2 = identity.sign(&msg2);
        let vote2 = Vote::new(voter_id, false, sig2);

        let result2 = session.add_vote(vote2);
        assert!(
            matches!(result2, VoteResult::Equivocation(_)),
            "Should detect equivocation when voter changes decision, got {:?}",
            result2
        );

        // Verify equivocation was recorded
        assert_eq!(session.equivocations.len(), 1);
        let proof = &session.equivocations[0];
        assert_eq!(proof.voter, voter_id);
        assert!(proof.verify(), "Equivocation proof should be valid");
    }

    #[test]
    fn test_duplicate_same_decision_is_not_equivocation() {
        let proposal_hash = [0u8; 32];
        let round_id = 100;
        let identity = NodeIdentity::generate();
        let voter_id = identity.node_id();

        // Use multiple eligible voters so threshold isn't immediately met
        let mut eligible = HashSet::new();
        eligible.insert(voter_id);
        for i in 0..5 {
            eligible.insert([i as u8 + 100; 32]);
        }

        let mut session = VotingSession::new(
            round_id,
            proposal_hash,
            VoteType::PayoutApproval,
            eligible,
            5000,
        );

        // First vote: approve
        let msg = compute_vote_signing_message(round_id, &proposal_hash, &voter_id, true);
        let sig = identity.sign(&msg);
        let vote1 = Vote::new(voter_id, true, sig);

        let result1 = session.add_vote(vote1);
        assert!(
            matches!(result1, VoteResult::ApprovalRecorded),
            "Expected ApprovalRecorded, got {:?}",
            result1
        );

        // Second vote: also approve (duplicate, not equivocation)
        let vote2 = Vote::new(voter_id, true, identity.sign(&msg));

        let result2 = session.add_vote(vote2);
        assert!(
            matches!(result2, VoteResult::DuplicateVote),
            "Same decision should be duplicate, not equivocation, got {:?}",
            result2
        );

        // No equivocations recorded
        assert!(session.equivocations.is_empty());
    }

    #[test]
    fn test_equivocation_proof_verification() {
        let proposal_hash = [0u8; 32];
        let round_id = 100;
        let identity = NodeIdentity::generate();
        let voter_id = identity.node_id();

        // Create two conflicting votes
        let msg1 = compute_vote_signing_message(round_id, &proposal_hash, &voter_id, true);
        let vote1 = Vote::new(voter_id, true, identity.sign(&msg1));

        let msg2 = compute_vote_signing_message(round_id, &proposal_hash, &voter_id, false);
        let vote2 = Vote::new(voter_id, false, identity.sign(&msg2));

        let proof = VoteEquivocationProof::from_votes(round_id, proposal_hash, &vote1, &vote2);

        // Valid proof should verify
        assert!(proof.verify());

        // Tampered proof (wrong signature) should not verify
        let mut bad_proof = proof.clone();
        bad_proof.vote1.signature = [0u8; 64];
        assert!(!bad_proof.verify());
    }
}
