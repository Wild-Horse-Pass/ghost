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

use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use tracing::{debug, info};

use ghost_common::constants::BFT_THRESHOLD_PERCENT;
use ghost_common::identity::verify_signature;
use ghost_common::types::{ConsensusResult, NodeId, RoundId, VoteType};

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
    /// Votes received
    pub votes: HashMap<NodeId, Vote>,
    /// Result (if decided)
    pub result: Option<ConsensusResult>,
}

impl VotingSession {
    /// Create a new voting session
    pub fn new(
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
        }
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

        // Check for duplicate vote
        if self.votes.contains_key(&vote.voter) {
            return VoteResult::DuplicateVote;
        }

        // Verify signature
        if !verify_vote_signature(&vote, &self.proposal_hash) {
            return VoteResult::InvalidSignature;
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
        let total = self.eligible_voters.len() as u32;
        // Use ceiling division: (total * 67 + 99) / 100 to round up
        // For 4 nodes: (4 * 67 + 99) / 100 = 367 / 100 = 3
        let threshold = ((total as u64 * BFT_THRESHOLD_PERCENT + 99) / 100) as u32;

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
        ((total * BFT_THRESHOLD_PERCENT + 99) / 100) as u32
    }
}

/// A single vote
#[derive(Debug, Clone)]
pub struct Vote {
    /// Voter node ID
    pub voter: NodeId,
    /// Approve or reject
    pub approve: bool,
    /// Signature of proposal hash
    pub signature: [u8; 64],
    /// Timestamp
    pub timestamp: u64,
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
    /// Duplicate vote from same voter
    DuplicateVote,
    /// Invalid signature
    InvalidSignature,
}

/// Verify vote signature
fn verify_vote_signature(vote: &Vote, proposal_hash: &[u8; 32]) -> bool {
    match verify_signature(&vote.voter, proposal_hash, &vote.signature) {
        Ok(valid) => valid,
        Err(_) => false,
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
}
