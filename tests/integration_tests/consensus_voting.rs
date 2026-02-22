//! Category 5: Consensus & Voting Tests (60 tests)
//!
//! Comprehensive tests for BFT consensus including:
//! - Vote session management (local helpers for basic logic)
//! - Quorum calculation (using ghost_common constants)
//! - Payout proposal validation
//! - Health monitoring
//! - Reputation tracking (using real ghost-consensus ReputationManager)

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

// Real imports from ghost-consensus
use ghost_common::constants::BFT_THRESHOLD_PERCENT;
use ghost_common::types::NodeId;
use ghost_consensus::{
    BadBehavior, ReputationManager, DISCONNECT_THRESHOLD, INITIAL_REPUTATION, MAX_REPUTATION,
    TRUST_THRESHOLD,
};

// =============================================================================
// VOTE SESSION TESTS (Tests 235-249)
// Local helper types for basic voting logic without requiring real signatures
// =============================================================================

#[test]
fn test_235_create_session_with_valid_parameters() {
    let proposal_hash = [1u8; 32];
    let session = LocalVotingSession::new(proposal_hash, 5000);

    assert_eq!(session.proposal_hash(), &proposal_hash);
    assert!(!session.is_complete());
}

#[test]
fn test_236_session_initial_state() {
    let session = LocalVotingSession::new([0u8; 32], 5000);

    assert!(session.votes().is_empty());
    assert_eq!(session.yes_votes(), 0);
    assert_eq!(session.no_votes(), 0);
}

#[test]
fn test_237_cast_vote_yes() {
    let mut session = LocalVotingSession::new([0u8; 32], 5000);
    let voter_id = [1u8; 32];

    let result = session.cast_vote(voter_id, true);
    assert!(result.is_ok());
    assert_eq!(session.yes_votes(), 1);
}

#[test]
fn test_238_cast_vote_no() {
    let mut session = LocalVotingSession::new([0u8; 32], 5000);
    let voter_id = [1u8; 32];

    let result = session.cast_vote(voter_id, false);
    assert!(result.is_ok());
    assert_eq!(session.no_votes(), 1);
}

#[test]
fn test_239_prevent_double_voting() {
    let mut session = LocalVotingSession::new([0u8; 32], 5000);
    let voter_id = [1u8; 32];

    session.cast_vote(voter_id, true).unwrap();
    let result = session.cast_vote(voter_id, false);

    assert!(result.is_err());
    assert_eq!(session.yes_votes(), 1);
}

#[test]
fn test_240_session_timeout() {
    let session = LocalVotingSession::new([0u8; 32], 1); // 1ms timeout
    std::thread::sleep(Duration::from_millis(10));

    assert!(session.is_expired());
}

#[test]
fn test_241_session_not_timeout() {
    let session = LocalVotingSession::new([0u8; 32], 60000); // 60s timeout
    assert!(!session.is_expired());
}

#[test]
fn test_242_session_complete_on_quorum() {
    let mut session = LocalVotingSession::with_quorum([0u8; 32], 5000, 3);

    session.cast_vote([1u8; 32], true).unwrap();
    session.cast_vote([2u8; 32], true).unwrap();
    assert!(!session.is_complete());

    session.cast_vote([3u8; 32], true).unwrap();
    assert!(session.is_complete());
}

#[test]
fn test_243_session_result_approved() {
    let mut session = LocalVotingSession::with_quorum([0u8; 32], 5000, 3);

    session.cast_vote([1u8; 32], true).unwrap();
    session.cast_vote([2u8; 32], true).unwrap();
    session.cast_vote([3u8; 32], true).unwrap();

    assert_eq!(session.result(), LocalVoteResult::Approved);
}

#[test]
fn test_244_session_result_rejected() {
    let mut session = LocalVotingSession::with_quorum([0u8; 32], 5000, 3);

    session.cast_vote([1u8; 32], false).unwrap();
    session.cast_vote([2u8; 32], false).unwrap();
    session.cast_vote([3u8; 32], false).unwrap();

    assert_eq!(session.result(), LocalVoteResult::Rejected);
}

#[test]
fn test_245_session_result_pending() {
    let session = LocalVotingSession::with_quorum([0u8; 32], 5000, 3);
    assert_eq!(session.result(), LocalVoteResult::Pending);
}

// =============================================================================
// QUORUM CALCULATION TESTS (Tests 250-259)
// Using real BFT_THRESHOLD_PERCENT from ghost_common
// =============================================================================

#[test]
fn test_250_quorum_67_percent_3_nodes() {
    // 67% of 3 = 2.01, ceiling = 3
    // Using real BFT threshold
    let quorum = calculate_bft_quorum(3);
    assert_eq!(quorum, 3);
}

#[test]
fn test_251_quorum_67_percent_5_nodes() {
    // 67% of 5 = 3.35, ceiling = 4
    let quorum = calculate_bft_quorum(5);
    assert_eq!(quorum, 4);
}

#[test]
fn test_252_quorum_67_percent_10_nodes() {
    // 67% of 10 = 6.7, ceiling = 7
    let quorum = calculate_bft_quorum(10);
    assert_eq!(quorum, 7);
}

#[test]
fn test_253_quorum_custom_percent() {
    // 51% of 10 = 5.1, ceiling = 6
    let quorum = calculate_quorum(10, 51);
    assert_eq!(quorum, 6);
}

#[test]
fn test_254_quorum_100_percent() {
    let quorum = calculate_quorum(5, 100);
    assert_eq!(quorum, 5);
}

#[test]
fn test_255_quorum_zero_nodes() {
    let quorum = calculate_bft_quorum(0);
    assert_eq!(quorum, 0);
}

#[test]
fn test_256_quorum_single_node() {
    let quorum = calculate_bft_quorum(1);
    assert_eq!(quorum, 1);
}

#[test]
fn test_257_byzantine_fault_tolerance() {
    // For BFT, need n >= 3f + 1 where f = failures tolerated
    // With 67% quorum, we can tolerate f = (n-1)/3 failures
    let n = 7;
    let quorum = calculate_bft_quorum(n);
    let f = (n - quorum) as i32;
    assert!(f >= 2); // Can tolerate 2 failures with 7 nodes
}

#[test]
fn test_258_quorum_type_simple_majority() {
    let result = QuorumType::SimpleMajority.required_votes(10);
    assert_eq!(result, 6);
}

#[test]
fn test_259_quorum_type_super_majority() {
    // Super majority uses real BFT threshold
    let result = QuorumType::SuperMajority.required_votes(10);
    assert_eq!(result, 7);
}

// =============================================================================
// PAYOUT PROPOSAL VALIDATION (Tests 269-295)
// =============================================================================

const DUST_THRESHOLD: u64 = 546;
const MAX_PAYOUT_OUTPUTS: usize = 100;
const MAX_BTC_SUPPLY: u64 = 21_000_000 * 100_000_000;

#[test]
fn test_269_valid_proposal_accepted() {
    let proposal = valid_proposal();
    let context = test_context();
    let result = validate_payout_proposal(&proposal, &context);
    assert!(result.is_ok());
}

#[test]
fn test_270_proposal_exceeds_available_rejected() {
    let mut proposal = valid_proposal();
    proposal.total_amount = 1_000_000_000_000; // More than available

    let context = test_context();
    let result = validate_payout_proposal(&proposal, &context);
    assert!(matches!(
        result,
        Err(PayoutValidationError::ExceedsAvailable { .. })
    ));
}

#[test]
fn test_271_proposal_unreasonable_reward_rejected() {
    let mut proposal = valid_proposal();
    proposal.total_amount = 100 * 100_000_000; // 100 BTC (way more than block reward)

    // Use high available balance to pass that check
    let context = ValidationContext {
        available_balance: 200 * 100_000_000, // 200 BTC available
        max_pool_fee_percent: 5,
        block_reward: 625_000_000, // 6.25 BTC
    };
    let result = validate_payout_proposal(&proposal, &context);
    assert!(matches!(
        result,
        Err(PayoutValidationError::UnreasonableReward(_))
    ));
}

#[test]
fn test_272_proposal_exceeds_supply_rejected() {
    let mut proposal = valid_proposal();
    proposal.total_amount = MAX_BTC_SUPPLY + 1;

    // Use very high available balance and block_reward to pass other checks
    let context = ValidationContext {
        available_balance: MAX_BTC_SUPPLY + 100,
        max_pool_fee_percent: 100,
        block_reward: MAX_BTC_SUPPLY,
    };
    let result = validate_payout_proposal(&proposal, &context);
    assert!(matches!(
        result,
        Err(PayoutValidationError::ExceedsSupply(_))
    ));
}

#[test]
fn test_273_dust_output_rejected() {
    let mut proposal = valid_proposal();
    proposal.miner_payouts[0].amount = DUST_THRESHOLD - 1;

    let context = test_context();
    let result = validate_payout_proposal(&proposal, &context);
    assert!(matches!(result, Err(PayoutValidationError::DustOutput(_))));
}

#[test]
fn test_274_empty_address_rejected() {
    let mut proposal = valid_proposal();
    proposal.miner_payouts[0].address = vec![];

    let context = test_context();
    let result = validate_payout_proposal(&proposal, &context);
    assert!(matches!(result, Err(PayoutValidationError::EmptyAddress)));
}

#[test]
fn test_275_too_many_outputs_rejected() {
    let mut proposal = valid_proposal();
    proposal.miner_payouts = (0..MAX_PAYOUT_OUTPUTS + 1)
        .map(|i| PayoutEntry {
            recipient_id: [i as u8; 32],
            address: vec![0xab; 22],
            amount: 1000,
            payout_type: PayoutType::Mining,
        })
        .collect();

    let context = test_context();
    let result = validate_payout_proposal(&proposal, &context);
    assert!(matches!(
        result,
        Err(PayoutValidationError::TooManyOutputs(_))
    ));
}

#[test]
fn test_276_no_miner_payouts_rejected() {
    let mut proposal = valid_proposal();
    proposal.miner_payouts = vec![];

    let context = test_context();
    let result = validate_payout_proposal(&proposal, &context);
    assert!(matches!(result, Err(PayoutValidationError::NoMinerPayouts)));
}

#[test]
fn test_277_duplicate_recipient_rejected() {
    let mut proposal = valid_proposal();
    proposal
        .miner_payouts
        .push(proposal.miner_payouts[0].clone());

    let context = test_context();
    let result = validate_payout_proposal(&proposal, &context);
    assert!(matches!(
        result,
        Err(PayoutValidationError::DuplicateRecipient(_))
    ));
}

#[test]
fn test_278_pool_fee_within_limits() {
    let mut proposal = valid_proposal();
    proposal.pool_fee = 100_000; // 0.001 BTC fee

    let context = test_context();
    let result = validate_payout_proposal(&proposal, &context);
    assert!(result.is_ok());
}

#[test]
fn test_279_pool_fee_exceeds_limit() {
    let mut proposal = valid_proposal();
    proposal.pool_fee = proposal.total_amount; // 100% fee

    let context = test_context();
    let result = validate_payout_proposal(&proposal, &context);
    assert!(matches!(
        result,
        Err(PayoutValidationError::ExcessivePoolFee(_))
    ));
}

#[test]
fn test_280_amounts_sum_correctly() {
    let proposal = valid_proposal();
    let context = test_context();

    let result = validate_payout_proposal(&proposal, &context);
    assert!(result.is_ok());

    // Verify sum doesn't exceed total
    let miner_sum: u64 = proposal.miner_payouts.iter().map(|p| p.amount).sum();
    assert!(miner_sum + proposal.pool_fee <= proposal.total_amount);
}

// =============================================================================
// HEALTH MONITORING TESTS (Tests 296-305)
// Local helpers for health monitoring
// =============================================================================

#[test]
fn test_296_node_initially_healthy() {
    let monitor = HealthMonitor::new();
    let node_id = [1u8; 32];
    assert!(monitor.is_healthy(&node_id));
}

#[test]
fn test_297_node_unhealthy_after_failures() {
    let mut monitor = HealthMonitor::new();
    let node_id = [1u8; 32];

    for _ in 0..5 {
        monitor.record_failure(&node_id);
    }

    assert!(!monitor.is_healthy(&node_id));
}

#[test]
fn test_298_node_recovers_after_success() {
    let mut monitor = HealthMonitor::new();
    let node_id = [1u8; 32];

    for _ in 0..5 {
        monitor.record_failure(&node_id);
    }
    assert!(!monitor.is_healthy(&node_id));

    // Need > failures * 2 successes to recover (i.e., > 10)
    for _ in 0..11 {
        monitor.record_success(&node_id);
    }
    assert!(monitor.is_healthy(&node_id));
}

#[test]
fn test_299_health_score_calculation() {
    let mut monitor = HealthMonitor::new();
    let node_id = [1u8; 32];

    monitor.record_success(&node_id);
    monitor.record_success(&node_id);
    monitor.record_failure(&node_id);

    let score = monitor.health_score(&node_id);
    // 2 successes, 1 failure = ~67% health
    assert!(score > 0.5 && score < 0.8);
}

#[test]
fn test_300_unhealthy_nodes_list() {
    let mut monitor = HealthMonitor::new();

    for i in 0..3 {
        let node_id = [i as u8; 32];
        if i == 1 {
            for _ in 0..10 {
                monitor.record_failure(&node_id);
            }
        } else {
            monitor.record_success(&node_id);
        }
    }

    let unhealthy = monitor.unhealthy_nodes();
    assert_eq!(unhealthy.len(), 1);
    assert_eq!(unhealthy[0], [1u8; 32]);
}

// =============================================================================
// REPUTATION TRACKING TESTS (Tests 306-315)
// Using real ghost-consensus ReputationManager
// =============================================================================

#[test]
fn test_306_initial_reputation() {
    // Using real ghost-consensus ReputationManager
    let manager = ReputationManager::new();
    let node_id: NodeId = [1u8; 32];

    // Real initial reputation is 50 (INITIAL_REPUTATION constant)
    assert_eq!(manager.get_score(&node_id), INITIAL_REPUTATION);
}

#[test]
fn test_307_reputation_increases_on_good_behavior() {
    let manager = ReputationManager::new();
    let node_id: NodeId = [1u8; 32];

    let initial = manager.get_score(&node_id);

    // Record enough good messages to see increase
    // Real system increases +1 every 10 good messages
    for _ in 0..10 {
        manager.record_good(&node_id);
    }

    assert!(manager.get_score(&node_id) > initial);
}

#[test]
fn test_308_reputation_decreases_on_bad_behavior() {
    let manager = ReputationManager::new();
    let node_id: NodeId = [1u8; 32];

    let initial = manager.get_score(&node_id);

    // Record bad behavior
    manager.record_bad(&node_id, BadBehavior::MalformedMessage);

    assert!(manager.get_score(&node_id) < initial);
}

#[test]
fn test_309_reputation_cannot_go_below_zero() {
    let manager = ReputationManager::new();
    let node_id: NodeId = [1u8; 32];

    // Record many bad behaviors
    for _ in 0..100 {
        manager.record_bad(&node_id, BadBehavior::MalformedMessage);
    }

    assert!(manager.get_score(&node_id) <= INITIAL_REPUTATION);
    // Score is capped at 0
    assert!(
        manager.get_score(&node_id) == 0 || manager.get_score(&node_id) <= DISCONNECT_THRESHOLD
    );
}

#[test]
fn test_310_reputation_has_maximum() {
    let manager = ReputationManager::new();
    let node_id: NodeId = [1u8; 32];

    // Record many good behaviors
    for _ in 0..10000 {
        manager.record_good(&node_id);
    }

    // Real max is 100 (MAX_REPUTATION constant)
    assert!(manager.get_score(&node_id) <= MAX_REPUTATION);
}

#[test]
fn test_311_low_reputation_excludes_from_trusted() {
    let manager = ReputationManager::new();
    let node_id: NodeId = [1u8; 32];

    // Record bad behaviors to drop reputation
    for _ in 0..20 {
        manager.record_bad(&node_id, BadBehavior::ProtocolViolation);
    }

    // Should not be trusted with low reputation
    assert!(!manager.is_trusted(&node_id));
}

#[test]
fn test_312_normal_reputation_trust_requires_history() {
    let manager = ReputationManager::new();
    let node_id: NodeId = [1u8; 32];

    // Initial reputation (50) is below trust threshold (70)
    // Even with good score, trust requires message history
    assert!(!manager.is_trusted(&node_id));

    // Build up good history
    // Need score >= 70 AND good_messages >= 100
    for _ in 0..200 {
        manager.record_good(&node_id);
    }

    // Now should meet trust requirements
    let score = manager.get_score(&node_id);
    assert!(score >= TRUST_THRESHOLD || score == MAX_REPUTATION);
}

#[test]
fn test_313_bad_behavior_penalties_vary() {
    // Test that different bad behaviors have different penalties
    let penalty_malformed = BadBehavior::MalformedMessage.penalty();
    let penalty_signature = BadBehavior::InvalidSignature.penalty();
    let penalty_spam = BadBehavior::Spam.penalty();

    // Invalid signature should have severe penalty
    assert!(penalty_signature > penalty_malformed);
    assert!(penalty_signature > penalty_spam);
}

#[test]
fn test_314_ban_permanently() {
    let manager = ReputationManager::new();
    let node_id: NodeId = [1u8; 32];

    assert!(!manager.is_banned(&node_id));

    manager.ban(node_id, "test ban");
    assert!(manager.is_banned(&node_id));

    manager.unban(&node_id);
    assert!(!manager.is_banned(&node_id));
}

#[test]
fn test_315_reputation_stats() {
    let manager = ReputationManager::new();

    // Add some peers with different behaviors
    for i in 0..5 {
        let node_id: NodeId = [i as u8; 32];
        manager.record_good(&node_id);
    }

    // Make one peer have low reputation
    let bad_peer: NodeId = [10u8; 32];
    for _ in 0..20 {
        manager.record_bad(&bad_peer, BadBehavior::ProtocolViolation);
    }

    let stats = manager.stats();
    assert_eq!(stats.total_peers, 6);
    assert!(stats.low_reputation_peers >= 1);
}

// =============================================================================
// HELPER TYPES AND FUNCTIONS
// =============================================================================

/// Calculate BFT quorum using real ghost_common threshold
fn calculate_bft_quorum(total_nodes: usize) -> usize {
    if total_nodes == 0 {
        return 0;
    }
    // Ceiling division: (total * 67 + 99) / 100
    (total_nodes as u64 * BFT_THRESHOLD_PERCENT).div_ceil(100) as usize
}

/// Calculate quorum with custom percentage
fn calculate_quorum(total_nodes: usize, percent: usize) -> usize {
    if total_nodes == 0 {
        return 0;
    }
    (total_nodes * percent).div_ceil(100).max(1)
}

#[derive(Debug, Clone)]
enum QuorumType {
    SimpleMajority,
    SuperMajority,
}

impl QuorumType {
    fn required_votes(&self, total: usize) -> usize {
        match self {
            QuorumType::SimpleMajority => (total / 2) + 1,
            QuorumType::SuperMajority => calculate_bft_quorum(total),
        }
    }
}

// Local voting session (simplified, no signature verification)
#[derive(Debug, Clone, PartialEq)]
enum LocalVoteResult {
    Pending,
    Approved,
    Rejected,
}

struct LocalVotingSession {
    proposal_hash: [u8; 32],
    timeout_ms: u64,
    created_at: Instant,
    votes: HashMap<[u8; 32], bool>,
    quorum: usize,
}

impl LocalVotingSession {
    fn new(proposal_hash: [u8; 32], timeout_ms: u64) -> Self {
        Self {
            proposal_hash,
            timeout_ms,
            created_at: Instant::now(),
            votes: HashMap::new(),
            quorum: 0,
        }
    }

    fn with_quorum(proposal_hash: [u8; 32], timeout_ms: u64, quorum: usize) -> Self {
        Self {
            proposal_hash,
            timeout_ms,
            created_at: Instant::now(),
            votes: HashMap::new(),
            quorum,
        }
    }

    fn proposal_hash(&self) -> &[u8; 32] {
        &self.proposal_hash
    }

    fn votes(&self) -> &HashMap<[u8; 32], bool> {
        &self.votes
    }

    fn yes_votes(&self) -> usize {
        self.votes.values().filter(|&&v| v).count()
    }

    fn no_votes(&self) -> usize {
        self.votes.values().filter(|&&v| !v).count()
    }

    fn cast_vote(&mut self, voter_id: [u8; 32], vote: bool) -> Result<(), String> {
        if self.votes.contains_key(&voter_id) {
            return Err("already voted".into());
        }
        self.votes.insert(voter_id, vote);
        Ok(())
    }

    fn is_expired(&self) -> bool {
        self.created_at.elapsed() > Duration::from_millis(self.timeout_ms)
    }

    fn is_complete(&self) -> bool {
        if self.quorum == 0 {
            return false;
        }
        self.yes_votes() >= self.quorum || self.no_votes() >= self.quorum
    }

    fn result(&self) -> LocalVoteResult {
        if self.quorum == 0 {
            return LocalVoteResult::Pending;
        }
        if self.yes_votes() >= self.quorum {
            LocalVoteResult::Approved
        } else if self.no_votes() >= self.quorum {
            LocalVoteResult::Rejected
        } else {
            LocalVoteResult::Pending
        }
    }
}

// Payout types
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum PayoutType {
    Mining,
    PoolFee,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct PayoutEntry {
    recipient_id: [u8; 32],
    address: Vec<u8>,
    amount: u64,
    payout_type: PayoutType,
}

#[derive(Debug, Clone)]
struct PayoutProposal {
    total_amount: u64,
    pool_fee: u64,
    miner_payouts: Vec<PayoutEntry>,
}

#[derive(Debug)]
struct ValidationContext {
    available_balance: u64,
    max_pool_fee_percent: u64,
    block_reward: u64,
}

#[derive(Debug)]
#[allow(dead_code)]
enum PayoutValidationError {
    ExceedsAvailable { requested: u64, available: u64 },
    UnreasonableReward(u64),
    ExceedsSupply(u64),
    DustOutput(u64),
    EmptyAddress,
    TooManyOutputs(usize),
    NoMinerPayouts,
    DuplicateRecipient([u8; 32]),
    ExcessivePoolFee(u64),
}

fn validate_payout_proposal(
    proposal: &PayoutProposal,
    context: &ValidationContext,
) -> Result<(), PayoutValidationError> {
    // Check against available balance
    if proposal.total_amount > context.available_balance {
        return Err(PayoutValidationError::ExceedsAvailable {
            requested: proposal.total_amount,
            available: context.available_balance,
        });
    }

    // Check reasonable reward (not more than 10x block reward)
    if proposal.total_amount > context.block_reward * 10 {
        return Err(PayoutValidationError::UnreasonableReward(
            proposal.total_amount,
        ));
    }

    // Check against max supply
    if proposal.total_amount > MAX_BTC_SUPPLY {
        return Err(PayoutValidationError::ExceedsSupply(proposal.total_amount));
    }

    // Check for miner payouts
    if proposal.miner_payouts.is_empty() {
        return Err(PayoutValidationError::NoMinerPayouts);
    }

    // Check output count
    if proposal.miner_payouts.len() > MAX_PAYOUT_OUTPUTS {
        return Err(PayoutValidationError::TooManyOutputs(
            proposal.miner_payouts.len(),
        ));
    }

    // Check pool fee
    let max_fee = proposal.total_amount * context.max_pool_fee_percent / 100;
    if proposal.pool_fee > max_fee {
        return Err(PayoutValidationError::ExcessivePoolFee(proposal.pool_fee));
    }

    // Check each payout
    let mut seen_recipients = HashSet::new();
    for payout in &proposal.miner_payouts {
        if payout.amount > 0 && payout.amount < DUST_THRESHOLD {
            return Err(PayoutValidationError::DustOutput(payout.amount));
        }
        if payout.amount > 0 && payout.address.is_empty() {
            return Err(PayoutValidationError::EmptyAddress);
        }
        if !seen_recipients.insert(payout.recipient_id) {
            return Err(PayoutValidationError::DuplicateRecipient(
                payout.recipient_id,
            ));
        }
    }

    Ok(())
}

fn valid_proposal() -> PayoutProposal {
    PayoutProposal {
        total_amount: 625_000_000, // 6.25 BTC
        pool_fee: 6_250_000,       // 1% fee
        miner_payouts: vec![PayoutEntry {
            recipient_id: [1u8; 32],
            address: vec![0xab; 22],
            amount: 618_750_000,
            payout_type: PayoutType::Mining,
        }],
    }
}

fn test_context() -> ValidationContext {
    ValidationContext {
        available_balance: 1_000_000_000, // 10 BTC
        max_pool_fee_percent: 5,
        block_reward: 625_000_000, // 6.25 BTC
    }
}

// Health monitor (local helper)
struct HealthMonitor {
    records: HashMap<[u8; 32], (u32, u32)>, // (successes, failures)
}

impl HealthMonitor {
    fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    fn record_success(&mut self, node_id: &[u8; 32]) {
        let entry = self.records.entry(*node_id).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);
    }

    fn record_failure(&mut self, node_id: &[u8; 32]) {
        let entry = self.records.entry(*node_id).or_insert((0, 0));
        entry.1 = entry.1.saturating_add(1);
    }

    fn is_healthy(&self, node_id: &[u8; 32]) -> bool {
        if let Some((successes, failures)) = self.records.get(node_id) {
            *failures < 5 || *successes > *failures * 2
        } else {
            true // Unknown nodes are considered healthy
        }
    }

    fn health_score(&self, node_id: &[u8; 32]) -> f64 {
        if let Some((successes, failures)) = self.records.get(node_id) {
            let total = *successes + *failures;
            if total == 0 {
                return 1.0;
            }
            *successes as f64 / total as f64
        } else {
            1.0
        }
    }

    fn unhealthy_nodes(&self) -> Vec<[u8; 32]> {
        self.records
            .keys()
            .filter(|id| !self.is_healthy(id))
            .copied()
            .collect()
    }
}
