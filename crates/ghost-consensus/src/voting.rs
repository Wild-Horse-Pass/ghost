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
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, warn};

use ghost_common::constants::BFT_THRESHOLD_PERCENT;
use ghost_common::error::GhostError;
use ghost_common::identity::verify_signature;
use ghost_common::types::{ConsensusResult, NodeId, RoundId, VoteType};

use crate::ban_manager::{BanManager, BanReason};
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
    /// M-4: Timestamp when equivocation was detected (Unix milliseconds)
    pub detected_at: u64,
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
    ///
    /// M-4: Sets detected_at timestamp to current time
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
            detected_at: chrono::Utc::now().timestamp_millis() as u64,
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

/// H-P2P-1: Minimum timeout for voting sessions (1 second)
/// Prevents DoS via zero timeout causing immediate timeout of all votes.
pub const MIN_TIMEOUT_MS: u64 = 1000;

/// Voting session for a specific proposal
///
/// Note: Debug is manually implemented to skip the ban_manager field.
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
    /// H-P2P-1: Optional ban manager for automatic equivocation banning
    ban_manager: Option<Arc<BanManager>>,
}

impl std::fmt::Debug for VotingSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VotingSession")
            .field("round_id", &self.round_id)
            .field("proposal_hash", &hex::encode(&self.proposal_hash[..8]))
            .field("vote_type", &self.vote_type)
            .field("started", &self.started)
            .field("timeout_ms", &self.timeout_ms)
            .field("eligible_voters", &self.eligible_voters.len())
            .field("votes", &self.votes.len())
            .field("result", &self.result)
            .field("equivocations", &self.equivocations.len())
            .field("has_ban_manager", &self.ban_manager.is_some())
            .finish()
    }
}

impl VotingSession {
    /// Create a new voting session
    ///
    /// CRIT-CONS-2 SECURITY: This constructor MUST enforce MIN_VOTERS_FOR_BFT to prevent
    /// Byzantine control. It is intentionally private to force use of from_elder_list()
    /// which provides additional validation.
    ///
    /// This is the ONLY way to create VotingSession instances. All other constructors
    /// (from_elder_list, from_elder_list_with_validation, new_for_testing) delegate here.
    ///
    /// H-5 SECURITY: Enforces MIN_VOTERS_FOR_BFT (7) to ensure proper BFT guarantees.
    /// BFT requires n >= 3f+1, so for f=2 Byzantine nodes, we need n >= 7.
    /// Creating a voting session with fewer voters would allow Byzantine nodes to
    /// control the outcome (e.g., with 4 voters and 2 Byzantine, they have 50% control).
    ///
    /// MED-CONS-1 SECURITY: Timeout must be >= MIN_TIMEOUT_MS (1 second), otherwise error.
    /// Values below this are REJECTED (not clamped) to prevent DoS via zero timeout.
    ///
    /// # Errors
    ///
    /// - Returns `GhostError::InsufficientVoters` if fewer than MIN_VOTERS_FOR_BFT (7)
    /// - Returns `GhostError::Config` if timeout_ms < MIN_TIMEOUT_MS
    fn new(
        round_id: RoundId,
        proposal_hash: [u8; 32],
        vote_type: VoteType,
        eligible_voters: HashSet<NodeId>,
        timeout_ms: u64,
    ) -> Result<Self, GhostError> {
        // CRIT-CONS-2 SECURITY: This validation is the security gate for all voting sessions.
        // Every VotingSession MUST go through this check - no bypasses allowed.
        if eligible_voters.len() < Self::MIN_VOTERS_FOR_BFT {
            error!(
                round_id,
                voters = eligible_voters.len(),
                required = Self::MIN_VOTERS_FOR_BFT,
                "CRIT-CONS-2: Cannot create voting session: BFT requires at least {} eligible voters",
                Self::MIN_VOTERS_FOR_BFT
            );
            return Err(GhostError::InsufficientVoters {
                required: Self::MIN_VOTERS_FOR_BFT,
                available: eligible_voters.len(),
            });
        }

        // MED-CONS-1 SECURITY: Enforce minimum timeout strictly (error, not clamp)
        // Clamping silently allowed DoS - now we reject invalid timeouts
        if timeout_ms < MIN_TIMEOUT_MS {
            error!(
                round_id,
                requested_timeout = timeout_ms,
                minimum = MIN_TIMEOUT_MS,
                "MED-CONS-1: Timeout is below minimum, rejecting voting session creation"
            );
            return Err(GhostError::Config(format!(
                "MED-CONS-1: Voting session timeout must be >= {} ms, got {} ms",
                MIN_TIMEOUT_MS, timeout_ms
            )));
        }

        Ok(Self {
            round_id,
            proposal_hash,
            vote_type,
            started: Instant::now(),
            timeout_ms, // MED-CONS-1: Use the validated timeout directly (no clamping)
            eligible_voters,
            votes: HashMap::new(),
            result: None,
            equivocations: Vec::new(),
            ban_manager: None,
        })
    }

    /// H-P2P-1: Set the ban manager for automatic equivocation banning
    ///
    /// When set, nodes that equivocate are immediately banned via this manager.
    pub fn with_ban_manager(mut self, ban_manager: Arc<BanManager>) -> Self {
        self.ban_manager = Some(ban_manager);
        self
    }

    /// L-11 SECURITY: Minimum voters for proper BFT guarantees
    ///
    /// For f=2 Byzantine faults, we need n >= 3f+1 = 7 voters.
    /// The previous minimum of 4 (f=1) was close to the Byzantine threshold
    /// and provided minimal margin for error. With 7 voters:
    /// - We can tolerate 2 Byzantine nodes (f=2)
    /// - 67% threshold requires 5 of 7 votes (properly above 2/3)
    /// - More robust consensus even if some nodes are slow/offline
    pub const MIN_VOTERS_FOR_BFT: usize = 7;

    /// Create a new voting session using a canonical elder list
    ///
    /// P2P-C1/C2/C3: This constructor uses the canonical elder list to determine
    /// eligible voters, ensuring all nodes agree on who can vote.
    ///
    /// SEC-VOTE-4: This is the ONLY public constructor for production use.
    ///
    /// H-P2P-2: Timeout must be at least MIN_TIMEOUT_MS (1 second). Values below
    /// this are clamped up to prevent DoS via zero timeout.
    ///
    /// # Errors
    ///
    /// L-11 SECURITY: Returns `GhostError::InsufficientVoters` if fewer than 7
    /// eligible voters are available. BFT requires n >= 3f+1, so for f=2 Byzantine
    /// nodes, we need n >= 7. The previous minimum of 4 was too close to the
    /// Byzantine threshold.
    pub fn from_elder_list(
        round_id: RoundId,
        proposal_hash: [u8; 32],
        vote_type: VoteType,
        elder_list: &CanonicalElderList,
        timeout_ms: u64,
    ) -> Result<Self, GhostError> {
        let eligible_voters = elder_list.get_eligible_voters();

        // L-11: BFT requires n >= 3f+1, so for f=2 Byzantine nodes, need n >= 7
        // The previous f=1 (4 voters) was too close to the threshold
        // With f=2, we have proper safety margin for real-world conditions
        if eligible_voters.len() < Self::MIN_VOTERS_FOR_BFT {
            error!(
                epoch = elder_list.epoch,
                voters = eligible_voters.len(),
                required = Self::MIN_VOTERS_FOR_BFT,
                "Cannot create voting session: BFT requires at least 7 eligible voters (n >= 3f+1 for f=2)"
            );
            return Err(GhostError::InsufficientVoters {
                required: Self::MIN_VOTERS_FOR_BFT,
                available: eligible_voters.len(),
            });
        }

        // H-P2P-2: Timeout validation is handled in new()
        // H-5: Minimum voter validation is also handled in new()
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

    /// CRIT-4: Create a voting session with full elder list validation
    ///
    /// This is the security-hardened constructor that verifies the elder list
    /// is properly approved by the previous epoch's elders before using it.
    ///
    /// # Security Properties
    ///
    /// - **Merkle Integrity**: Verifies the merkle root of the elder list
    /// - **BFT Approval**: Verifies >67% of previous elders approved this list
    /// - **Minimum Voters**: Requires at least 4 voters for BFT security
    ///
    /// # Arguments
    ///
    /// * `round_id` - The voting round ID
    /// * `proposal_hash` - The hash of the proposal being voted on
    /// * `vote_type` - The type of vote
    /// * `elder_list` - The elder list to use for determining eligible voters
    /// * `previous_elders` - The set of node IDs from the previous epoch
    /// * `timeout_ms` - Timeout for the voting session in milliseconds
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The elder list fails `verify_canonical` validation
    /// - Fewer than 4 eligible voters are available
    pub fn from_elder_list_with_validation(
        round_id: RoundId,
        proposal_hash: [u8; 32],
        vote_type: VoteType,
        elder_list: &CanonicalElderList,
        previous_elders: &HashSet<NodeId>,
        timeout_ms: u64,
    ) -> Result<Self, GhostError> {
        // CRIT-4: Verify the elder list is properly approved before using it
        elder_list.verify_canonical(previous_elders)?;

        // Delegate to the standard constructor for remaining validation
        Self::from_elder_list(round_id, proposal_hash, vote_type, elder_list, timeout_ms)
    }

    /// Test-only constructor for creating voting sessions with arbitrary voters
    ///
    /// SEC-VOTE-6: This is intentionally only available in test builds.
    /// Production code MUST use from_elder_list() to ensure BFT security.
    ///
    /// H-P2P-2: Timeout is clamped to MIN_TIMEOUT_MS if below.
    /// H-5: Returns Result - tests must provide at least MIN_VOTERS_FOR_BFT (7) voters.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_for_testing(
        round_id: RoundId,
        proposal_hash: [u8; 32],
        vote_type: VoteType,
        eligible_voters: HashSet<NodeId>,
        timeout_ms: u64,
    ) -> Result<Self, GhostError> {
        Self::new(
            round_id,
            proposal_hash,
            vote_type,
            eligible_voters,
            timeout_ms,
        )
    }

    /// H-P2P-1: Set the ban manager after construction
    ///
    /// This is useful when the ban manager isn't available at construction time.
    pub fn set_ban_manager(&mut self, ban_manager: Arc<BanManager>) {
        self.ban_manager = Some(ban_manager);
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

            // H-P2P-1: Immediately ban the equivocating node if ban manager is available
            if let Some(ref ban_manager) = self.ban_manager {
                ban_manager.ban(vote.voter, BanReason::Equivocation);
                info!(
                    voter = %hex::encode(&vote.voter[..8]),
                    round_id = self.round_id,
                    "H-P2P-1: Equivocating node automatically banned"
                );
            }

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

    /// 3.2/HIGH-8 SECURITY: Invalidate a voter and remove their vote
    ///
    /// Called when a node is banned (e.g., for equivocation). This removes
    /// the node from eligible_voters and removes any vote they cast.
    /// This prevents banned nodes' votes from influencing consensus.
    ///
    /// HIGH-8: After removing a vote, we recalculate whether the existing
    /// decision is still valid. If the removed vote was decisive (meaning
    /// the decision was reached only because of that vote), we clear
    /// the result so the session can continue collecting votes or timeout.
    ///
    /// # Threshold Behavior (L-4)
    ///
    /// When a voter is invalidated, the threshold is recalculated based on
    /// the new (smaller) set of eligible voters. This is correct behavior:
    /// - If we had 10 voters and threshold was 7, removing 1 voter gives us
    ///   9 voters with threshold 7 (ceil(9 * 67 / 100) = 7)
    /// - The decision might still stand if we had 7+ votes from remaining voters
    /// - But if we only had exactly threshold votes and one was removed, the
    ///   decision is invalidated
    ///
    /// Returns true if the voter had a vote that was removed.
    pub fn invalidate_voter(&mut self, node_id: &NodeId) -> bool {
        // Remove from eligible voters
        self.eligible_voters.remove(node_id);

        // Remove their vote if present
        let had_vote = self.votes.remove(node_id).is_some();

        if had_vote {
            tracing::info!(
                voter = hex::encode(&node_id[..8]),
                round_id = self.round_id,
                "3.2 SECURITY: Invalidated vote from banned voter"
            );

            // HIGH-8: Recalculate decision after vote removal
            // If there was a previous decision, check if it's still valid
            if self.result.is_some() {
                // Get current counts and new threshold
                let (approvals, rejections, total) = self.vote_counts();
                let new_threshold = self.threshold();

                // Check if the decision is still valid with the new threshold
                let decision_still_valid = match &self.result {
                    Some(ConsensusResult::Approved { .. }) => approvals >= new_threshold,
                    Some(ConsensusResult::Rejected { .. }) => rejections >= new_threshold,
                    Some(ConsensusResult::Timeout { .. }) => {
                        // Timeout decisions remain valid - they indicate the session
                        // timed out, which is still true
                        true
                    }
                    Some(ConsensusResult::Error(_)) => {
                        // Error decisions remain valid - they indicate an error occurred
                        // which is still true regardless of voter changes
                        true
                    }
                    None => true, // No decision to validate
                };

                if !decision_still_valid {
                    tracing::warn!(
                        round_id = self.round_id,
                        voter = hex::encode(&node_id[..8]),
                        approvals = approvals,
                        rejections = rejections,
                        total = total,
                        new_threshold = new_threshold,
                        "HIGH-8: Decision invalidated after removing decisive vote"
                    );
                    self.result = None;
                }
            }
        }

        had_vote
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

    /// 3.2 SECURITY: Invalidate a voter in all active sessions
    ///
    /// Called when a node is banned. This removes the node from all
    /// active voting sessions and removes any votes they have cast.
    /// This prevents banned nodes' votes from influencing any ongoing consensus.
    ///
    /// Returns the number of sessions where the voter's vote was invalidated.
    pub fn invalidate_voter_in_all_sessions(&self, node_id: &NodeId) -> usize {
        let mut sessions = self.sessions.write();
        let mut invalidated_count = 0;

        for session in sessions.values_mut() {
            if session.invalidate_voter(node_id) {
                invalidated_count += 1;
            }
        }

        if invalidated_count > 0 {
            tracing::warn!(
                voter = hex::encode(&node_id[..8]),
                sessions_affected = invalidated_count,
                "3.2 SECURITY: Invalidated votes from banned voter in all active sessions"
            );
        }

        invalidated_count
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
            .expect("Test session should have enough voters")
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
        // H-5: Use at least MIN_VOTERS_FOR_BFT (7) eligible voters
        let proposal_hash = [0u8; 32];
        let identity = NodeIdentity::generate();
        let voter_id = identity.node_id();

        let mut eligible = HashSet::new();
        eligible.insert(voter_id);
        // Add enough dummy voters to meet MIN_VOTERS_FOR_BFT requirement (7 total)
        for i in 0..8 {
            eligible.insert([i as u8 + 100; 32]);
        }

        let mut session1 = VotingSession::new(
            100,
            proposal_hash,
            VoteType::PayoutApproval,
            eligible.clone(),
            5000,
        )
        .expect("Session should have enough voters");
        let mut session2 =
            VotingSession::new(200, proposal_hash, VoteType::PayoutApproval, eligible, 5000)
                .expect("Session should have enough voters");

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

        // H-5: Use at least MIN_VOTERS_FOR_BFT (7) eligible voters
        let mut eligible = HashSet::new();
        eligible.insert(voter_id);
        for i in 0..8 {
            eligible.insert([i as u8 + 100; 32]);
        }

        let mut session = VotingSession::new(
            round_id,
            proposal_hash,
            VoteType::PayoutApproval,
            eligible,
            5000,
        )
        .expect("Session should have enough voters");

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

        // H-5: Use at least MIN_VOTERS_FOR_BFT (7) eligible voters
        let mut eligible = HashSet::new();
        eligible.insert(voter_id);
        for i in 0..8 {
            eligible.insert([i as u8 + 100; 32]);
        }

        let mut session = VotingSession::new(
            round_id,
            proposal_hash,
            VoteType::PayoutApproval,
            eligible,
            5000,
        )
        .expect("Session should have enough voters");

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

    /// SEC-VOTE-TEST-1: Verify that invalid signatures return InvalidSignature,
    /// not a panic or silent acceptance
    #[test]
    fn test_signature_error_returns_invalid_not_panic() {
        let proposal_hash = [0u8; 32];
        let round_id = 100;

        // H-5: Use at least MIN_VOTERS_FOR_BFT (7) eligible voters
        let mut eligible = HashSet::new();
        let voter_id = [1u8; 32];
        eligible.insert(voter_id);
        for i in 0..8 {
            eligible.insert([i as u8 + 100; 32]);
        }

        let mut session = VotingSession::new(
            round_id,
            proposal_hash,
            VoteType::PayoutApproval,
            eligible,
            5000,
        )
        .expect("Session should have enough voters");

        // Create a vote with garbage signature (not a valid ed25519 signature)
        let bad_vote = Vote::new(voter_id, true, [0xDE; 64]);

        // Should return InvalidSignature, not panic
        let result = session.add_vote(bad_vote);
        assert!(
            matches!(result, VoteResult::InvalidSignature),
            "Garbage signature should return InvalidSignature, got {:?}",
            result
        );
    }

    /// SEC-VOTE-TEST-2: Verify that BFT threshold calculation handles
    /// extreme voter counts without overflow
    #[test]
    fn test_threshold_overflow_protection() {
        // Test with a very large number of voters
        let mut eligible = HashSet::new();
        for i in 0u32..10_000 {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&i.to_le_bytes());
            eligible.insert(id);
        }

        let session = VotingSession::new(1, [0u8; 32], VoteType::PayoutApproval, eligible, 5000)
            .expect("Session should have enough voters");

        // 67% of 10,000 = 6,700
        let threshold = session.threshold();
        assert_eq!(
            threshold, 6700,
            "Threshold for 10,000 voters should be 6,700"
        );
    }

    /// H-5-TEST: Verify that VotingSession::new rejects fewer than MIN_VOTERS_FOR_BFT voters
    #[test]
    fn test_new_rejects_insufficient_voters() {
        // Try to create a session with only 3 voters (below MIN_VOTERS_FOR_BFT = 7)
        let mut small_eligible = HashSet::new();
        for i in 0..3 {
            small_eligible.insert([i as u8; 32]);
        }
        let result =
            VotingSession::new(1, [0u8; 32], VoteType::PayoutApproval, small_eligible, 5000);

        // H-5: Should reject with InsufficientVoters error
        assert!(
            matches!(result, Err(GhostError::InsufficientVoters { required: 7, available: 3 })),
            "Should reject session with fewer than 7 voters, got {:?}",
            result
        );
    }

    /// L-11-TEST: Verify that from_elder_list requires minimum 7 voters for BFT security
    #[test]
    fn test_from_elder_list_requires_minimum_7_voters() {
        use crate::elder_list::{CanonicalElderList, ElderEntry};
        use ghost_common::identity::NodeIdProof;

        // Create a helper to make elder entries
        fn make_elder(i: u8) -> ElderEntry {
            ElderEntry::new(
                [i; 32],
                1, // epoch
                &NodeIdProof {
                    nonce: 0,
                    difficulty: 20,
                },
                chrono::Utc::now().timestamp() as u64,
                99.0,
            )
        }

        // L-11: Create an elder list with only 6 voters (should fail)
        let small_elders: Vec<ElderEntry> = (0u8..6).map(make_elder).collect();
        let small_elder_list = CanonicalElderList::new(1, small_elders);

        let result = VotingSession::from_elder_list(
            1,
            [0u8; 32],
            VoteType::PayoutApproval,
            &small_elder_list,
            5000,
        );

        // Should fail with InsufficientVoters
        assert!(
            result.is_err(),
            "L-11: Should reject elder list with fewer than 7 voters"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                ghost_common::error::GhostError::InsufficientVoters {
                    required: 7,
                    available: 6
                }
            ),
            "L-11: Expected InsufficientVoters error with required=7, available=6, got {:?}",
            err
        );

        // L-11: Create an elder list with exactly 7 voters (should succeed)
        let valid_elders: Vec<ElderEntry> = (0u8..7).map(make_elder).collect();
        let valid_elder_list = CanonicalElderList::new(1, valid_elders);

        let result = VotingSession::from_elder_list(
            1,
            [0u8; 32],
            VoteType::PayoutApproval,
            &valid_elder_list,
            5000,
        );

        // Should succeed with exactly 7 voters
        assert!(
            result.is_ok(),
            "L-11: Should accept elder list with exactly 7 voters"
        );
        let session = result.unwrap();
        assert_eq!(session.eligible_voters.len(), 7);
    }

    /// L-11-TEST: Verify edge case with 0 voters
    #[test]
    fn test_from_elder_list_rejects_empty() {
        use crate::elder_list::CanonicalElderList;

        let empty_elder_list = CanonicalElderList::new(1, vec![]);

        let result = VotingSession::from_elder_list(
            1,
            [0u8; 32],
            VoteType::PayoutApproval,
            &empty_elder_list,
            5000,
        );

        assert!(result.is_err(), "Should reject empty elder list");
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                ghost_common::error::GhostError::InsufficientVoters {
                    required: 7,
                    available: 0
                }
            ),
            "L-11: Expected InsufficientVoters error with required=7, available=0, got {:?}",
            err
        );
    }

    // =========================================================================
    // CRIT-4 TESTS: Elder list validation in voting session creation
    // =========================================================================

    /// CRIT-4-TEST: Verify that from_elder_list_with_validation rejects invalid merkle root
    #[test]
    fn test_crit4_rejects_invalid_merkle_root() {
        use crate::elder_list::{CanonicalElderList, ElderEntry};
        use ghost_common::identity::NodeIdProof;

        // Create a helper to make elder entries
        fn make_elder(i: u8) -> ElderEntry {
            ElderEntry {
                node_id: [i; 32],
                registered_epoch: 1,
                pow_nonce: 12345 + i as u64,
                pow_difficulty: 16,
                first_seen: 1000000,
                uptime_at_registration: 99.5,
            }
        }

        // L-11: Create an elder list with 7 voters (minimum required)
        let elders: Vec<ElderEntry> = (0u8..7).map(make_elder).collect();
        let mut elder_list = CanonicalElderList::new(1, elders);

        // Tamper with the merkle root
        elder_list.merkle_root = [0xDE; 32]; // Invalid merkle root

        // Previous elders (required for validation of epoch > 0)
        let previous_elders: HashSet<NodeId> = (10u8..15).map(|i| [i; 32]).collect();

        let result = VotingSession::from_elder_list_with_validation(
            1,
            [0u8; 32],
            VoteType::PayoutApproval,
            &elder_list,
            &previous_elders,
            5000,
        );

        assert!(
            result.is_err(),
            "Should reject elder list with invalid merkle root"
        );
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("CRIT-4") && err.to_string().contains("merkle"),
            "Error should mention CRIT-4 and merkle root: {:?}",
            err
        );
    }

    /// CRIT-4-TEST: Verify that from_elder_list_with_validation accepts genesis list without approvals
    #[test]
    fn test_crit4_accepts_genesis_without_approvals() {
        use crate::elder_list::{CanonicalElderList, ElderEntry};

        // Create a helper to make elder entries
        fn make_elder(i: u8) -> ElderEntry {
            ElderEntry {
                node_id: [i; 32],
                registered_epoch: 0, // Genesis epoch
                pow_nonce: 12345 + i as u64,
                pow_difficulty: 16,
                first_seen: 1000000,
                uptime_at_registration: 99.5,
            }
        }

        // L-11: Create a genesis elder list (epoch 0) with 7 voters (minimum required)
        let elders: Vec<ElderEntry> = (0u8..7).map(make_elder).collect();
        let genesis_list = CanonicalElderList::genesis(elders);

        // Empty previous elders (appropriate for genesis)
        let previous_elders: HashSet<NodeId> = HashSet::new();

        let result = VotingSession::from_elder_list_with_validation(
            1,
            [0u8; 32],
            VoteType::PayoutApproval,
            &genesis_list,
            &previous_elders,
            5000,
        );

        assert!(result.is_ok(), "Genesis list should not require approvals");
        let session = result.unwrap();
        assert_eq!(session.eligible_voters.len(), 7);
    }

    /// CRIT-4-TEST: Verify that from_elder_list_with_validation rejects non-genesis without previous elders
    #[test]
    fn test_crit4_rejects_non_genesis_without_previous_elders() {
        use crate::elder_list::{CanonicalElderList, ElderEntry};

        // Create a helper to make elder entries
        fn make_elder(i: u8) -> ElderEntry {
            ElderEntry {
                node_id: [i; 32],
                registered_epoch: 1, // Non-genesis
                pow_nonce: 12345 + i as u64,
                pow_difficulty: 16,
                first_seen: 1000000,
                uptime_at_registration: 99.5,
            }
        }

        // Create a non-genesis elder list (epoch 1) with 5 voters
        let elders: Vec<ElderEntry> = (0u8..7).map(make_elder).collect();
        let elder_list = CanonicalElderList::new(1, elders);

        // Empty previous elders - this should cause validation to fail for epoch > 0
        let previous_elders: HashSet<NodeId> = HashSet::new();

        let result = VotingSession::from_elder_list_with_validation(
            1,
            [0u8; 32],
            VoteType::PayoutApproval,
            &elder_list,
            &previous_elders,
            5000,
        );

        assert!(
            result.is_err(),
            "Non-genesis epoch should require previous elders"
        );
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("CRIT-4"),
            "Error should mention CRIT-4: {:?}",
            err
        );
    }

    /// CRIT-4-TEST: Verify that from_elder_list_with_validation rejects insufficient approvals
    #[test]
    fn test_crit4_rejects_insufficient_approvals() {
        use crate::elder_list::{CanonicalElderList, ElderEntry};

        // Create a helper to make elder entries
        fn make_elder(i: u8) -> ElderEntry {
            ElderEntry {
                node_id: [i; 32],
                registered_epoch: 1,
                pow_nonce: 12345 + i as u64,
                pow_difficulty: 16,
                first_seen: 1000000,
                uptime_at_registration: 99.5,
            }
        }

        // Create an elder list with 5 voters
        let elders: Vec<ElderEntry> = (0u8..7).map(make_elder).collect();
        let elder_list = CanonicalElderList::new(1, elders);
        // No approval signatures added - this should fail validation

        // Previous elders (10 elders, so threshold is ceil(10 * 67 / 100) = 7)
        let previous_elders: HashSet<NodeId> = (10u8..20).map(|i| [i; 32]).collect();

        let result = VotingSession::from_elder_list_with_validation(
            1,
            [0u8; 32],
            VoteType::PayoutApproval,
            &elder_list,
            &previous_elders,
            5000,
        );

        assert!(
            result.is_err(),
            "Should reject elder list without sufficient approvals"
        );
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("CRIT-4") && err.to_string().contains("approvals"),
            "Error should mention CRIT-4 and approvals: {:?}",
            err
        );
    }

    // =========================================================================
    // H-P2P-1 TESTS: Automatic ban on equivocation
    // =========================================================================

    /// H-P2P-1-TEST: Verify that equivocation triggers automatic ban when ban_manager is set
    #[test]
    fn test_equivocation_auto_ban() {
        use crate::ban_manager::BanManager;

        let proposal_hash = [0u8; 32];
        let round_id = 100;
        let identity = NodeIdentity::generate();
        let voter_id = identity.node_id();

        // H-5: Use at least MIN_VOTERS_FOR_BFT (7) eligible voters
        let mut eligible = HashSet::new();
        eligible.insert(voter_id);
        for i in 0..8 {
            eligible.insert([i as u8 + 100; 32]);
        }

        let ban_manager = Arc::new(BanManager::new());
        let mut session = VotingSession::new(
            round_id,
            proposal_hash,
            VoteType::PayoutApproval,
            eligible,
            5000,
        )
        .expect("Session should have enough voters");
        session.set_ban_manager(ban_manager.clone());

        // Initially not banned
        assert!(!ban_manager.is_banned(&voter_id));

        // First vote: approve
        let msg1 = compute_vote_signing_message(round_id, &proposal_hash, &voter_id, true);
        let sig1 = identity.sign(&msg1);
        let vote1 = Vote::new(voter_id, true, sig1);

        let result1 = session.add_vote(vote1);
        assert!(matches!(result1, VoteResult::ApprovalRecorded));

        // Still not banned
        assert!(!ban_manager.is_banned(&voter_id));

        // Second vote: reject (equivocation!)
        let msg2 = compute_vote_signing_message(round_id, &proposal_hash, &voter_id, false);
        let sig2 = identity.sign(&msg2);
        let vote2 = Vote::new(voter_id, false, sig2);

        let result2 = session.add_vote(vote2);
        assert!(matches!(result2, VoteResult::Equivocation(_)));

        // NOW the voter should be banned automatically
        assert!(
            ban_manager.is_banned(&voter_id),
            "H-P2P-1: Equivocating voter should be automatically banned"
        );
    }

    /// H-P2P-1-TEST: Verify that without ban_manager, equivocation is still detected but no auto-ban
    #[test]
    fn test_equivocation_without_ban_manager() {
        let proposal_hash = [0u8; 32];
        let round_id = 100;
        let identity = NodeIdentity::generate();
        let voter_id = identity.node_id();

        // H-5: Use at least MIN_VOTERS_FOR_BFT (7) eligible voters
        let mut eligible = HashSet::new();
        eligible.insert(voter_id);
        for i in 0..8 {
            eligible.insert([i as u8 + 100; 32]);
        }

        // No ban manager set
        let mut session = VotingSession::new(
            round_id,
            proposal_hash,
            VoteType::PayoutApproval,
            eligible,
            5000,
        )
        .expect("Session should have enough voters");

        // First vote
        let msg1 = compute_vote_signing_message(round_id, &proposal_hash, &voter_id, true);
        let vote1 = Vote::new(voter_id, true, identity.sign(&msg1));
        session.add_vote(vote1);

        // Second conflicting vote
        let msg2 = compute_vote_signing_message(round_id, &proposal_hash, &voter_id, false);
        let vote2 = Vote::new(voter_id, false, identity.sign(&msg2));

        let result = session.add_vote(vote2);
        assert!(
            matches!(result, VoteResult::Equivocation(_)),
            "Should still detect equivocation even without ban manager"
        );
    }

    // =========================================================================
    // H-P2P-2 TESTS: Timeout validation
    // =========================================================================

    /// H-P2P-2-TEST: Verify that timeout_ms=0 is rejected (MED-CONS-1: strict validation)
    #[test]
    fn test_zero_timeout_rejected() {
        // H-5: Use at least MIN_VOTERS_FOR_BFT (7) eligible voters
        let mut eligible = HashSet::new();
        for i in 0..10 {
            eligible.insert([i as u8; 32]);
        }

        let result = VotingSession::new(1, [0u8; 32], VoteType::PayoutApproval, eligible, 0);

        // MED-CONS-1: Invalid timeouts are now rejected, not clamped
        assert!(result.is_err(), "Zero timeout should be rejected");
        if let Err(e) = result {
            assert!(e.to_string().contains("timeout must be"), "Error should mention timeout");
        }
    }

    /// H-P2P-2-TEST: Verify that timeout below minimum is rejected (MED-CONS-1: strict validation)
    #[test]
    fn test_low_timeout_rejected() {
        // H-5: Use at least MIN_VOTERS_FOR_BFT (7) eligible voters
        let mut eligible = HashSet::new();
        for i in 0..10 {
            eligible.insert([i as u8; 32]);
        }

        let result = VotingSession::new(1, [0u8; 32], VoteType::PayoutApproval, eligible, 500);

        // MED-CONS-1: Invalid timeouts are now rejected, not clamped
        assert!(result.is_err(), "Timeout below MIN_TIMEOUT_MS should be rejected");
        if let Err(e) = result {
            assert!(e.to_string().contains("timeout must be"), "Error should mention timeout");
        }
    }

    /// H-P2P-2-TEST: Verify that valid timeout is preserved
    #[test]
    fn test_valid_timeout_preserved() {
        // H-5: Use at least MIN_VOTERS_FOR_BFT (7) eligible voters
        let mut eligible = HashSet::new();
        for i in 0..10 {
            eligible.insert([i as u8; 32]);
        }

        let session = VotingSession::new(1, [0u8; 32], VoteType::PayoutApproval, eligible, 5000)
            .expect("Session should have enough voters");

        assert_eq!(
            session.timeout_ms, 5000,
            "H-P2P-2: Valid timeout should be preserved"
        );
    }
}
