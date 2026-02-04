//! End-to-End Stratum → Payout → Consensus Integration Tests
//!
//! Tests the complete flow from miner share submission through payout proposal
//! creation and BFT consensus voting. Uses real implementations where possible.
//!
//! Flow tested:
//! 1. Miners submit shares (recorded in database)
//! 2. Block is found (round ends)
//! 3. Payout proposal is created from round data
//! 4. Nodes vote on the proposal
//! 5. Consensus is reached (67% threshold)
//! 6. Payout is approved/rejected

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ghost_common::identity::NodeIdentity;
use ghost_common::types::{ConsensusResult, NodeId, RoundId, VoteType};
use ghost_consensus::voting::{compute_vote_signing_message, Vote, VoteResult, VotingSession};
use ghost_storage::models::{PayoutStatus, RoundRecord, ShareRecord};
use ghost_storage::Database;
use sha2::{Digest, Sha256};

/// Get current timestamp in milliseconds
fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

// ============================================================
// Test Helpers
// ============================================================

/// Generate a unique node identity for testing
/// Note: Uses PoW so generates a new identity each time
fn test_identity(_seed: u8) -> NodeIdentity {
    NodeIdentity::generate()
}

/// Create a test payout proposal hash
fn test_proposal_hash(round_id: u64, block_height: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(round_id.to_le_bytes());
    hasher.update(block_height.to_le_bytes());
    hasher.update(b"test_proposal");
    hasher.finalize().into()
}

/// Create a signed vote with proper signing message (includes round_id for replay protection)
fn create_signed_vote_for_round(
    identity: &NodeIdentity,
    round_id: RoundId,
    proposal_hash: &[u8; 32],
    approve: bool,
) -> Vote {
    let message =
        compute_vote_signing_message(round_id, proposal_hash, &identity.node_id(), approve);
    let signature = identity.sign_hash(&message);
    Vote::new(identity.node_id(), approve, signature)
}

/// Create a signed vote (legacy helper - kept for backward compatibility)
/// Note: This signs only the proposal_hash, not the full signing message.
/// Use create_signed_vote_for_round for tests using VotingSession.
fn create_signed_vote(identity: &NodeIdentity, proposal_hash: &[u8; 32], approve: bool) -> Vote {
    let signature = identity.sign_hash(proposal_hash);
    Vote::new(identity.node_id(), approve, signature)
}

/// Create a test share record
fn test_share(round_id: u64, miner_id: &str, difficulty: f64) -> ShareRecord {
    ShareRecord {
        id: None,
        round_id,
        miner_id: miner_id.to_string(),
        difficulty,
        work: difficulty, // Work equals difficulty for simplicity
        share_hash: format!("{:064x}", rand::random::<u64>()),
        timestamp: now_millis(),
        received_by: "test_node".to_string(),
        valid: true,
    }
}

/// Create a test round record
fn test_round(round_id: u64, block_height: u64) -> RoundRecord {
    RoundRecord {
        round_id,
        block_height,
        block_hash: None,
        start_time: now_millis(),
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: Some(312_500_000),
        tx_fees_sats: Some(50_000_000),
    }
}

// ============================================================
// Database Integration Tests
// ============================================================

#[test]
fn test_share_recording_flow() {
    let db = Database::in_memory().unwrap();

    // Record a round
    let round_id = 1;
    let block_height = 850_000u64;

    db.create_round(&test_round(round_id, block_height))
        .unwrap();

    // Submit shares from multiple miners
    let miners = vec![("miner_1", 100.0), ("miner_2", 150.0), ("miner_3", 75.0)];

    for (miner_id, difficulty) in &miners {
        db.insert_share(&test_share(round_id, miner_id, *difficulty))
            .unwrap();
    }

    // Verify shares were recorded
    let shares = db.get_shares_by_round(round_id).unwrap();
    assert_eq!(shares.len(), 3);

    // Calculate total work
    let total_work: f64 = shares.iter().map(|s| s.work).sum();
    assert!((total_work - 325.0).abs() < 0.001);

    // Verify individual miner work
    let miner_1_work: f64 = shares
        .iter()
        .filter(|s| s.miner_id == "miner_1")
        .map(|s| s.work)
        .sum();
    assert!((miner_1_work - 100.0).abs() < 0.001);
}

#[test]
fn test_round_lifecycle_with_block_found() {
    let db = Database::in_memory().unwrap();

    // Start round
    let round_id = 1;
    db.create_round(&test_round(round_id, 850_000)).unwrap();

    // Submit shares
    for i in 0..10 {
        db.insert_share(&test_share(round_id, &format!("miner_{}", i % 3), 10.0))
            .unwrap();
    }

    // End round with block found
    let block_hash = "00000000000000000001234567890abcdef";
    db.update_round_block_found(
        round_id,
        block_hash,
        "miner_1",
        "node_123",
        312_500_000, // subsidy
        50_000_000,  // fees
    )
    .unwrap();
    db.end_round(round_id, now_millis()).unwrap();

    // Verify round state
    let round = db.get_round(round_id).unwrap().unwrap();
    assert!(round.end_time.is_some());
    assert_eq!(round.block_hash, Some(block_hash.to_string()));
    assert_eq!(round.winning_miner, Some("miner_1".to_string()));
}

#[test]
fn test_payout_status_transitions() {
    let db = Database::in_memory().unwrap();

    let round_id = 1;
    db.create_round(&test_round(round_id, 850_000)).unwrap();

    // Active → Pending (proposal created)
    db.update_round_status(round_id, PayoutStatus::Pending)
        .unwrap();
    let round = db.get_round(round_id).unwrap().unwrap();
    assert_eq!(round.payout_status, PayoutStatus::Pending);

    // Pending → Approved (consensus reached)
    db.update_round_status(round_id, PayoutStatus::Approved)
        .unwrap();
    let round = db.get_round(round_id).unwrap().unwrap();
    assert_eq!(round.payout_status, PayoutStatus::Approved);

    // Approved → Broadcast (tx sent)
    db.update_round_status(round_id, PayoutStatus::Broadcast)
        .unwrap();
    let round = db.get_round(round_id).unwrap().unwrap();
    assert_eq!(round.payout_status, PayoutStatus::Broadcast);

    // Broadcast → Confirmed (tx confirmed)
    db.update_round_status(round_id, PayoutStatus::Confirmed)
        .unwrap();
    let round = db.get_round(round_id).unwrap().unwrap();
    assert_eq!(round.payout_status, PayoutStatus::Confirmed);
}

// ============================================================
// Consensus Voting Integration Tests
// ============================================================

#[test]
fn test_voting_session_with_real_signatures() {
    // Create 5 voters with real identities
    let voters: Vec<NodeIdentity> = (0..5).map(test_identity).collect();
    let voter_ids: HashSet<NodeId> = voters.iter().map(|e| e.node_id()).collect();

    // Create a voting session
    let round_id = 1;
    let proposal_hash = test_proposal_hash(round_id, 850_000);

    let mut session = VotingSession::new_for_testing(
        round_id,
        proposal_hash,
        VoteType::PayoutApproval,
        voter_ids.clone(),
        60_000, // 60 second timeout
    );

    // First 3 voters vote yes (should not reach quorum yet with 5 voters)
    for (i, voter) in voters[0..3].iter().enumerate() {
        let vote = create_signed_vote_for_round(voter, round_id, &proposal_hash, true);
        let result = session.add_vote(vote);

        // With 5 voters, 67% = ceiling(5 * 0.67) = 4 votes needed
        // Votes 1-3 should all return ApprovalRecorded (not yet at threshold)
        assert!(
            matches!(result, VoteResult::ApprovalRecorded),
            "Vote {} should be ApprovalRecorded, got {:?}",
            i,
            result
        );
    }

    // 4th voter votes yes - should reach quorum
    let vote = create_signed_vote_for_round(&voters[3], round_id, &proposal_hash, true);
    let result = session.add_vote(vote);

    // Should be decided now (4/5 = 80% > 67%)
    assert!(matches!(
        result,
        VoteResult::Decided(ConsensusResult::Approved { .. })
    ));
}

#[test]
fn test_voting_rejection_threshold() {
    // Create 5 voters
    let voters: Vec<NodeIdentity> = (0..5).map(test_identity).collect();
    let voter_ids: HashSet<NodeId> = voters.iter().map(|e| e.node_id()).collect();

    let round_id = 1;
    let proposal_hash = test_proposal_hash(round_id, 850_000);

    let mut session = VotingSession::new_for_testing(
        round_id,
        proposal_hash,
        VoteType::PayoutApproval,
        voter_ids,
        60_000,
    );

    // All 5 voters vote no
    for voter in &voters {
        let vote = create_signed_vote_for_round(voter, round_id, &proposal_hash, false);
        session.add_vote(vote);
    }

    // Should be rejected
    assert!(session.result.is_some());
    assert!(matches!(
        session.result,
        Some(ConsensusResult::Rejected { .. })
    ));
}

#[test]
fn test_duplicate_vote_prevention() {
    let voters: Vec<NodeIdentity> = (0..3).map(test_identity).collect();
    let voter_ids: HashSet<NodeId> = voters.iter().map(|e| e.node_id()).collect();

    let round_id = 1;
    let proposal_hash = test_proposal_hash(round_id, 850_000);

    let mut session = VotingSession::new_for_testing(
        round_id,
        proposal_hash,
        VoteType::PayoutApproval,
        voter_ids,
        60_000,
    );

    // First vote succeeds
    let vote1 = create_signed_vote_for_round(&voters[0], round_id, &proposal_hash, true);
    let result1 = session.add_vote(vote1);
    assert!(matches!(result1, VoteResult::ApprovalRecorded));

    // Duplicate vote fails (same approve value = duplicate)
    let vote2 = create_signed_vote_for_round(&voters[0], round_id, &proposal_hash, true);
    let result2 = session.add_vote(vote2);
    assert!(matches!(result2, VoteResult::DuplicateVote));
}

#[test]
fn test_ineligible_voter_rejected() {
    let voters: Vec<NodeIdentity> = (0..3).map(test_identity).collect();
    let voter_ids: HashSet<NodeId> = voters.iter().map(|e| e.node_id()).collect();

    // Create an outsider not in the eligible voter set
    let outsider = test_identity(99);

    let round_id = 1;
    let proposal_hash = test_proposal_hash(round_id, 850_000);

    let mut session = VotingSession::new_for_testing(
        round_id,
        proposal_hash,
        VoteType::PayoutApproval,
        voter_ids,
        60_000,
    );

    // Vote from non-eligible node should be rejected (checked before signature)
    let vote = create_signed_vote_for_round(&outsider, round_id, &proposal_hash, true);
    let result = session.add_vote(vote);
    assert!(matches!(result, VoteResult::NotEligible));
}

#[test]
fn test_invalid_signature_rejected() {
    let voters: Vec<NodeIdentity> = (0..3).map(test_identity).collect();
    let voter_ids: HashSet<NodeId> = voters.iter().map(|e| e.node_id()).collect();

    let proposal_hash = test_proposal_hash(1, 850_000);

    let mut session = VotingSession::new_for_testing(
        1,
        proposal_hash,
        VoteType::PayoutApproval,
        voter_ids,
        60_000,
    );

    // Create a vote with wrong signature (sign different hash)
    let wrong_hash = test_proposal_hash(2, 850_001);
    let bad_signature = voters[0].sign_hash(&wrong_hash);

    let bad_vote = Vote::new(
        voters[0].node_id(),
        true,
        bad_signature, // Wrong signature - signed different hash
    );

    let result = session.add_vote(bad_vote);
    assert!(matches!(result, VoteResult::InvalidSignature));
}

// ============================================================
// Full Flow Integration Tests
// ============================================================

#[test]
fn test_complete_share_to_consensus_flow() {
    // === Phase 1: Setup ===
    let db = Database::in_memory().unwrap();

    // Create 5 voters
    let voters: Vec<NodeIdentity> = (0..5).map(test_identity).collect();
    let voter_ids: HashSet<NodeId> = voters.iter().map(|e| e.node_id()).collect();

    // === Phase 2: Share Submission ===
    let round_id = 1;
    let block_height = 850_000u64;

    db.create_round(&test_round(round_id, block_height))
        .unwrap();

    // Multiple miners submit shares
    let miner_difficulties = vec![
        ("miner_alice", 100.0),
        ("miner_bob", 200.0),
        ("miner_charlie", 150.0),
    ];

    for (miner_id, difficulty) in &miner_difficulties {
        db.insert_share(&test_share(round_id, miner_id, *difficulty))
            .unwrap();
    }

    // === Phase 3: Block Found ===
    // miner_bob finds the block
    let block_hash = "00000000000000000002abcd1234567890abcdef";

    // Add another share from bob that found the block
    db.insert_share(&test_share(round_id, "miner_bob", 200.0))
        .unwrap();

    db.update_round_block_found(
        round_id,
        block_hash,
        "miner_bob",
        "node_123",
        312_500_000,
        50_000_000,
    )
    .unwrap();
    db.end_round(round_id, now_millis()).unwrap();

    // === Phase 4: Calculate Payouts ===
    let shares = db.get_shares_by_round(round_id).unwrap();
    let total_work: f64 = shares.iter().map(|s| s.work).sum();

    // 100 + 200 + 150 + 200 (block share) = 650
    assert!((total_work - 650.0).abs() < 0.001);

    // Calculate miner proportions
    let alice_work: f64 = shares
        .iter()
        .filter(|s| s.miner_id == "miner_alice")
        .map(|s| s.work)
        .sum();
    let bob_work: f64 = shares
        .iter()
        .filter(|s| s.miner_id == "miner_bob")
        .map(|s| s.work)
        .sum();
    let charlie_work: f64 = shares
        .iter()
        .filter(|s| s.miner_id == "miner_charlie")
        .map(|s| s.work)
        .sum();

    // Alice: 100/650 ≈ 15.38%
    // Bob: 400/650 ≈ 61.54%
    // Charlie: 150/650 ≈ 23.08%
    let alice_pct = alice_work / total_work;
    let bob_pct = bob_work / total_work;
    let charlie_pct = charlie_work / total_work;

    assert!((alice_pct - 0.1538).abs() < 0.01);
    assert!((bob_pct - 0.6154).abs() < 0.01);
    assert!((charlie_pct - 0.2308).abs() < 0.01);

    // === Phase 5: Create Payout Proposal ===
    // Update status to pending (proposal created)
    db.update_round_status(round_id, PayoutStatus::Pending)
        .unwrap();

    let proposal_hash = test_proposal_hash(round_id, block_height);

    // === Phase 6: Consensus Voting ===
    let mut session = VotingSession::new_for_testing(
        round_id,
        proposal_hash,
        VoteType::PayoutApproval,
        voter_ids.clone(),
        60_000,
    );

    // 4 out of 5 voters approve (80% > 67%)
    for i in 0..4 {
        let vote = create_signed_vote_for_round(&voters[i], round_id, &proposal_hash, true);
        let result = session.add_vote(vote);

        if i == 3 {
            // 4th vote should trigger approval
            assert!(matches!(
                result,
                VoteResult::Decided(ConsensusResult::Approved { .. })
            ));
        }
    }

    // === Phase 7: Finalize Payout ===
    // Update status to approved
    db.update_round_status(round_id, PayoutStatus::Approved)
        .unwrap();

    let round = db.get_round(round_id).unwrap().unwrap();
    assert_eq!(round.payout_status, PayoutStatus::Approved);
    assert_eq!(round.winning_miner, Some("miner_bob".to_string()));
}

#[test]
fn test_consensus_with_minimum_voters() {
    // Test with exactly 3 voters (minimum for BFT)
    let voters: Vec<NodeIdentity> = (0..3).map(test_identity).collect();
    let voter_ids: HashSet<NodeId> = voters.iter().map(|e| e.node_id()).collect();

    let round_id = 1;
    let proposal_hash = test_proposal_hash(round_id, 850_000);

    let mut session = VotingSession::new_for_testing(
        round_id,
        proposal_hash,
        VoteType::PayoutApproval,
        voter_ids,
        60_000,
    );

    // With 3 voters, 67% = 3 votes needed (ceiling of 2.01)
    // Vote 1 - pending
    let vote1 = create_signed_vote_for_round(&voters[0], round_id, &proposal_hash, true);
    let result1 = session.add_vote(vote1);
    assert!(matches!(result1, VoteResult::ApprovalRecorded));

    // Vote 2 - still pending
    let vote2 = create_signed_vote_for_round(&voters[1], round_id, &proposal_hash, true);
    let result2 = session.add_vote(vote2);
    assert!(matches!(result2, VoteResult::ApprovalRecorded));

    // Vote 3 - approved (3/3 = 100%)
    let vote3 = create_signed_vote_for_round(&voters[2], round_id, &proposal_hash, true);
    let result3 = session.add_vote(vote3);
    assert!(matches!(
        result3,
        VoteResult::Decided(ConsensusResult::Approved { .. })
    ));
}

#[test]
fn test_consensus_with_split_votes() {
    // 7 voters, 2 yes, 5 no = rejection
    let voters: Vec<NodeIdentity> = (0..7).map(test_identity).collect();
    let voter_ids: HashSet<NodeId> = voters.iter().map(|e| e.node_id()).collect();

    let round_id = 1;
    let proposal_hash = test_proposal_hash(round_id, 850_000);

    let mut session = VotingSession::new_for_testing(
        round_id,
        proposal_hash,
        VoteType::PayoutApproval,
        voter_ids,
        60_000,
    );

    // 2 yes votes
    for i in 0..2 {
        let vote = create_signed_vote_for_round(&voters[i], round_id, &proposal_hash, true);
        session.add_vote(vote);
    }

    // 5 no votes
    for i in 2..7 {
        let vote = create_signed_vote_for_round(&voters[i], round_id, &proposal_hash, false);
        session.add_vote(vote);
    }

    // Verify final state is rejected
    assert!(session.result.is_some());
}

// ============================================================
// Stress/Edge Case Tests
// ============================================================

#[test]
fn test_many_shares_same_round() {
    let db = Database::in_memory().unwrap();

    let round_id = 1;
    db.create_round(&test_round(round_id, 850_000)).unwrap();

    // Insert 1000 shares from 50 miners
    for i in 0..1000 {
        let miner_id = format!("miner_{}", i % 50);
        let difficulty = (i % 10 + 1) as f64;
        db.insert_share(&test_share(round_id, &miner_id, difficulty))
            .unwrap();
    }

    let shares = db.get_shares_by_round(round_id).unwrap();
    assert_eq!(shares.len(), 1000);

    // Verify work distribution
    let miner_0_shares: Vec<_> = shares.iter().filter(|s| s.miner_id == "miner_0").collect();
    assert_eq!(miner_0_shares.len(), 20); // 1000/50 = 20 shares per miner
}

#[test]
fn test_large_voter_set() {
    // Test with 21 voters (realistic maximum)
    let voters: Vec<NodeIdentity> = (0..21).map(test_identity).collect();
    let voter_ids: HashSet<NodeId> = voters.iter().map(|e| e.node_id()).collect();

    let round_id = 1;
    let proposal_hash = test_proposal_hash(round_id, 850_000);

    let mut session = VotingSession::new_for_testing(
        round_id,
        proposal_hash,
        VoteType::PayoutApproval,
        voter_ids,
        60_000,
    );

    // 67% of 21 = 14.07, ceil = 15 votes needed
    // Cast 15 yes votes
    for i in 0..15 {
        let vote = create_signed_vote_for_round(&voters[i], round_id, &proposal_hash, true);
        let result = session.add_vote(vote);

        if i == 14 {
            // 15th vote should trigger approval
            assert!(matches!(
                result,
                VoteResult::Decided(ConsensusResult::Approved { .. })
            ));
        }
    }
}

#[test]
fn test_round_orphaned_by_reorg() {
    let db = Database::in_memory().unwrap();

    let round_id = 1;
    let block_hash = "00000000000000000001abcdef";

    // Create round with block
    let mut round = test_round(round_id, 850_000);
    round.block_hash = Some(block_hash.to_string());
    round.payout_status = PayoutStatus::Pending;
    db.create_round(&round).unwrap();

    // Simulate reorg - mark as orphaned
    db.update_round_status(round_id, PayoutStatus::Orphaned)
        .unwrap();

    let round = db.get_round(round_id).unwrap().unwrap();
    assert_eq!(round.payout_status, PayoutStatus::Orphaned);
}

#[test]
fn test_miner_work_aggregation() {
    let db = Database::in_memory().unwrap();

    let round_id = 1;
    db.create_round(&test_round(round_id, 850_000)).unwrap();

    // Same miner submits multiple shares
    for _ in 0..10 {
        db.insert_share(&test_share(round_id, "miner_a", 5.0))
            .unwrap();
    }

    // Get miner work
    let work = db.get_miner_work(round_id, "miner_a").unwrap();
    assert!((work - 50.0).abs() < 0.001); // 10 shares * 5.0 work = 50.0
}

#[test]
fn test_round_miners_distribution() {
    let db = Database::in_memory().unwrap();

    let round_id = 1;
    db.create_round(&test_round(round_id, 850_000)).unwrap();

    // Different miners with different work amounts
    db.insert_share(&test_share(round_id, "miner_a", 100.0))
        .unwrap();
    db.insert_share(&test_share(round_id, "miner_b", 200.0))
        .unwrap();
    db.insert_share(&test_share(round_id, "miner_c", 50.0))
        .unwrap();
    db.insert_share(&test_share(round_id, "miner_a", 50.0))
        .unwrap(); // Another from miner_a

    // Get round miners
    let miners = db.get_round_miners(round_id).unwrap();
    assert_eq!(miners.len(), 3);

    // Find miner_a total
    let miner_a_work: f64 = miners
        .iter()
        .filter(|(id, _)| id == "miner_a")
        .map(|(_, work)| *work)
        .sum();
    assert!((miner_a_work - 150.0).abs() < 0.001); // 100 + 50
}

// ============================================================
// Async Integration Tests
// ============================================================

#[cfg(test)]
mod async_tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_concurrent_share_submission() {
        let db = Arc::new(Database::in_memory().unwrap());

        let round_id = 1;
        db.create_round(&test_round(round_id, 850_000)).unwrap();

        // Spawn 10 concurrent tasks, each submitting 10 shares
        let mut handles = vec![];

        for task_id in 0..10 {
            let db_clone = Arc::clone(&db);
            let handle = tokio::spawn(async move {
                for _ in 0..10 {
                    let share = ShareRecord {
                        id: None,
                        round_id: 1,
                        miner_id: format!("miner_task_{}", task_id),
                        difficulty: 10.0,
                        work: 10.0,
                        share_hash: format!("{:064x}", rand::random::<u64>()),
                        timestamp: now_millis(),
                        received_by: "test_node".to_string(),
                        valid: true,
                    };
                    db_clone.insert_share(&share).unwrap();

                    // Small delay to interleave operations
                    tokio::time::sleep(Duration::from_micros(100)).await;
                }
            });
            handles.push(handle);
        }

        // Wait for all tasks
        for handle in handles {
            handle.await.unwrap();
        }

        // Verify all shares were recorded
        let shares = db.get_shares_by_round(round_id).unwrap();
        assert_eq!(shares.len(), 100); // 10 tasks * 10 shares
    }

    #[tokio::test]
    async fn test_vote_collection_channel() {
        // Simulate vote collection via channel
        let (tx, mut rx) = mpsc::channel::<Vote>(100);

        let voters: Vec<NodeIdentity> = (0..5).map(test_identity).collect();
        let proposal_hash = test_proposal_hash(1, 850_000);

        // Spawn tasks to send votes
        for voter in voters.iter().take(4) {
            let vote = create_signed_vote(voter, &proposal_hash, true);
            tx.send(vote).await.unwrap();
        }
        drop(tx); // Close channel

        // Collect votes
        let mut votes = vec![];
        while let Some(vote) = rx.recv().await {
            votes.push(vote);
        }

        assert_eq!(votes.len(), 4);
        assert!(votes.iter().all(|v| v.approve));
    }
}
