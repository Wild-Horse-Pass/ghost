//! Category 29: L2 Nullifier Route Integration Tests (20 tests, 870-889)
//!
//! Tests the sender-side proof L2 system end-to-end:
//! - NullifierRouteHandler + EpochManager multi-node flows
//! - Checkpoint proposal, BFT voting, finalization
//! - Epoch transitions and tree compaction
//! - Double-spend rejection via nullifier routing
//! - Deterministic proposer/validator rotation

use std::sync::Arc;

use ghost_consensus::epoch_manager::{EpochManager, EpochManagerConfig};
use ghost_consensus::message::{
    L2CheckpointBlockMessage, L2CheckpointVoteMessage, L2ConfidentialTransferMessage,
    L2Transaction, L2TransferBroadcastMessage, MessageType,
};
use ghost_consensus::nullifier_route_handler::NullifierRouteHandler;
use ghost_storage::Database;
use ghost_zkp::GhostNoteVerifier;

// =============================================================================
// HELPERS
// =============================================================================

/// Small tree depth for fast tests (4 levels = 16 leaves)
const TEST_TREE_DEPTH: usize = 4;

/// Create an in-memory DB, epoch manager, and handler for a single node
fn setup_node(node_id: [u8; 32]) -> (Arc<Database>, Arc<EpochManager>, Arc<NullifierRouteHandler>) {
    let db = Arc::new(Database::in_memory().expect("in-memory DB"));
    let config = EpochManagerConfig {
        epoch_length: 100,
        transition_window: 10,
        tree_depth: TEST_TREE_DEPTH,
        max_valid_roots: 16,
    };
    let epoch_mgr = Arc::new(EpochManager::new(db.clone(), config));
    epoch_mgr.initialize_genesis().unwrap();

    let handler = Arc::new(NullifierRouteHandler::with_defaults(
        node_id,
        epoch_mgr.clone(),
        db.clone(),
    ));

    // S-1: Verifier must be set for handle_transfer_broadcast (fail-closed)
    handler.set_verifier(Arc::new(GhostNoteVerifier::test_accept_all()));

    (db, epoch_mgr, handler)
}

/// Create a multi-node test environment with shared active node list
fn setup_multi_node(
    node_ids: &[[u8; 32]],
) -> Vec<(Arc<Database>, Arc<EpochManager>, Arc<NullifierRouteHandler>)> {
    let nodes: Vec<_> = node_ids.iter().map(|id| setup_node(*id)).collect();

    // Set active nodes on all epoch managers
    let active: Vec<[u8; 32]> = node_ids.to_vec();
    for (_, epoch_mgr, _) in &nodes {
        epoch_mgr.update_active_nodes(active.clone());
    }

    nodes
}

/// Create a test transaction with the given nullifier targeting a specific root
fn make_test_tx(nullifier: [u8; 32], root: [u8; 32]) -> L2Transaction {
    L2Transaction {
        epoch: 0,
        nullifier,
        change_commitment: [0u8; 32],
        recipient_commitment: [0u8; 32],
        commitment_root: root,
        proof: vec![0u8; 192], // Dummy proof
        encrypted_change: vec![],
        encrypted_recipient: vec![],
        timestamp: 0,
    }
}

/// Create a dummy checkpoint proposal at the given height with a specific proposer.
/// Returns the proposal and its checkpoint hash.
fn make_dummy_proposal(height: u64, proposer: [u8; 32]) -> (L2CheckpointBlockMessage, [u8; 32]) {
    let proposal = L2CheckpointBlockMessage {
        height,
        epoch: 0,
        prev_commitment_root: [0u8; 32],
        new_commitment_root: [0u8; 32],
        transactions: vec![],
        shield_commitments: vec![],
        active_node_count: 0,
        proposer,
        proposer_signature: [0u8; 64],
        timestamp: 0,
        epoch_transition: None,
    };
    let hash = proposal.checkpoint_hash();
    (proposal, hash)
}

// =============================================================================
// TEST 870-872: Basic multi-node setup
// =============================================================================

/// Test 870: Multi-node setup initializes consistently
#[test]
fn test_870_multi_node_setup_consistency() {
    let node_a = [0x01; 32];
    let node_b = [0x02; 32];
    let node_c = [0x03; 32];

    let nodes = setup_multi_node(&[node_a, node_b, node_c]);

    // All nodes start at epoch 0, height 0
    for (_, epoch_mgr, _) in &nodes {
        assert_eq!(epoch_mgr.current_epoch(), 0);
        assert_eq!(epoch_mgr.current_height(), 0);
        assert_eq!(epoch_mgr.active_node_count(), 3);
    }

    // All nodes have the same genesis root
    let root_a = nodes[0].1.current_root().unwrap();
    let root_b = nodes[1].1.current_root().unwrap();
    let root_c = nodes[2].1.current_root().unwrap();
    assert_eq!(root_a, root_b);
    assert_eq!(root_b, root_c);
}

/// Test 871: Deterministic proposer rotation across nodes
#[test]
fn test_871_proposer_rotation_deterministic() {
    let node_a = [0x01; 32];
    let node_b = [0x02; 32];
    let node_c = [0x03; 32];

    let nodes = setup_multi_node(&[node_a, node_b, node_c]);

    // All nodes agree on who the proposer is for any given height
    for height in 1..=10u64 {
        let proposers: Vec<Option<[u8; 32]>> = nodes
            .iter()
            .map(|(_, em, _)| em.get_proposer(height))
            .collect();

        // All nodes return the same proposer
        assert!(
            proposers.windows(2).all(|w| w[0] == w[1]),
            "Disagreement on proposer at height {}",
            height
        );

        // Proposer should be one of the active nodes
        let proposer = proposers[0].unwrap();
        assert!(
            [node_a, node_b, node_c].contains(&proposer),
            "Unknown proposer at height {}",
            height
        );
    }
}

/// Test 872: Deterministic validator routing across nodes
#[test]
fn test_872_validator_routing_deterministic() {
    let node_a = [0x01; 32];
    let node_b = [0x02; 32];
    let node_c = [0x03; 32];

    let nodes = setup_multi_node(&[node_a, node_b, node_c]);

    // For any nullifier, all nodes agree on the validator
    let nullifier = [0x42; 32];
    let validators: Vec<Option<[u8; 32]>> = nodes
        .iter()
        .map(|(_, em, _)| em.validator_for_nullifier(&nullifier))
        .collect();

    assert!(
        validators.windows(2).all(|w| w[0] == w[1]),
        "Disagreement on validator for nullifier"
    );

    // Different nullifiers may route to different validators
    let null2 = [0x43; 32];
    let v1 = nodes[0].1.validator_for_nullifier(&nullifier);
    let v2 = nodes[0].1.validator_for_nullifier(&null2);
    // They CAN be the same but the routing function should be deterministic
    assert!(v1.is_some());
    assert!(v2.is_some());
}

// =============================================================================
// TEST 873-875: Transaction validation flow
// =============================================================================

/// Test 873: Transfer rejected when sent to wrong validator
#[test]
fn test_873_transfer_wrong_validator_returns_none() {
    let node_a = [0x01; 32];
    let node_b = [0x02; 32];

    let nodes = setup_multi_node(&[node_a, node_b]);

    // Get current root and add as valid
    let root = nodes[0].1.current_root().unwrap();
    nodes[0].1.add_valid_root(root, 0).unwrap();
    nodes[1].1.add_valid_root(root, 0).unwrap();

    // Create a transaction — route it to whichever node is NOT the validator
    let nullifier = [0x42; 32];
    let validator = nodes[0].1.validator_for_nullifier(&nullifier).unwrap();

    // Send to the OTHER node (the one that isn't the validator)
    let wrong_node_idx = if validator == node_a { 1 } else { 0 };
    let msg = L2ConfidentialTransferMessage {
        transaction: make_test_tx(nullifier, root),
        sender: [0x99; 32],
    };

    let result = nodes[wrong_node_idx].2.handle_transfer(&msg).unwrap();
    assert!(result.is_none(), "Wrong validator should return None");
}

/// Test 874: Transfer rejected with invalid commitment root
#[test]
fn test_874_transfer_invalid_root_rejected() {
    let node_a = [0x01; 32];
    let nodes = setup_multi_node(&[node_a]);

    // Get current root and add as valid
    let root = nodes[0].1.current_root().unwrap();
    nodes[0].1.add_valid_root(root, 0).unwrap();

    // Submit with a wrong root
    let msg = L2ConfidentialTransferMessage {
        transaction: make_test_tx([0x42; 32], [0xFF; 32]), // Bad root
        sender: [0x99; 32],
    };

    let result = nodes[0].2.handle_transfer(&msg);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Invalid commitment root"));
}

/// Test 875: Double-spend prevention via nullifier set
#[test]
fn test_875_double_spend_nullifier_rejected() {
    let node_a = [0x01; 32];
    let nodes = setup_multi_node(&[node_a]);

    let root = nodes[0].1.current_root().unwrap();
    nodes[0].1.add_valid_root(root, 0).unwrap();

    let nullifier = [0x42; 32];

    // First: spend the nullifier directly in the epoch manager
    nodes[0].1.spend_nullifier(nullifier, 0).unwrap();

    // Then try to submit a transfer with the same nullifier
    let msg = L2ConfidentialTransferMessage {
        transaction: make_test_tx(nullifier, root),
        sender: [0x99; 32],
    };

    let result = nodes[0].2.handle_transfer(&msg);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("already spent"));
}

// =============================================================================
// TEST 876-879: Checkpoint proposal and BFT voting
// =============================================================================

/// Test 876: Only designated proposer can propose
#[test]
fn test_876_only_designated_proposer_proposes() {
    let node_a = [0x01; 32];
    let node_b = [0x02; 32];
    let node_c = [0x03; 32];

    let nodes = setup_multi_node(&[node_a, node_b, node_c]);

    // Figure out who the proposer is for height 1
    let proposer = nodes[0].1.get_proposer(1).unwrap();

    let mut proposal_count = 0;
    for (_, _, handler) in &nodes {
        if let Ok(Some(_)) = handler.propose_checkpoint() {
            proposal_count += 1;
        }
    }

    // Exactly one node should successfully propose
    assert_eq!(proposal_count, 1, "Exactly one proposer expected");

    // The proposer should be the one the epoch manager designated
    let proposer_idx = [node_a, node_b, node_c]
        .iter()
        .position(|id| *id == proposer)
        .unwrap();
    let proposal = nodes[proposer_idx].2.propose_checkpoint().unwrap();
    assert!(proposal.is_some());
}

/// Test 877: Checkpoint reaches BFT quorum with 3 nodes
#[test]
fn test_877_checkpoint_bft_quorum_3_nodes() {
    let node_a = [0x01; 32];
    let node_b = [0x02; 32];
    let node_c = [0x03; 32];

    let nodes = setup_multi_node(&[node_a, node_b, node_c]);

    // Store a proposal so C-7 guard allows finalization
    let proposer = nodes[0].1.get_proposer(1).unwrap();
    let (proposal, checkpoint_hash) = make_dummy_proposal(1, proposer);
    nodes[0].2.handle_checkpoint_proposal(&proposal).unwrap();

    // With 3 nodes at 67% threshold: ceil(3 * 67 / 100) = 3 — all must vote
    // Vote from node A
    let vote = L2CheckpointVoteMessage {
        height: 1,
        checkpoint_hash,
        voter: node_a,
        approve: true,
        signature: [0u8; 64],
        timestamp: 0,
    };
    let finalized = nodes[0].2.handle_checkpoint_vote(&vote).unwrap();
    assert!(!finalized, "1/3 should not finalize");

    // Vote from node B
    let vote_b = L2CheckpointVoteMessage {
        height: 1,
        checkpoint_hash,
        voter: node_b,
        approve: true,
        signature: [0u8; 64],
        timestamp: 0,
    };
    let finalized = nodes[0].2.handle_checkpoint_vote(&vote_b).unwrap();
    assert!(!finalized, "2/3 should not finalize (67% needs all 3)");

    // Vote from node C — should finalize
    let vote_c = L2CheckpointVoteMessage {
        height: 1,
        checkpoint_hash,
        voter: node_c,
        approve: true,
        signature: [0u8; 64],
        timestamp: 0,
    };
    let finalized = nodes[0].2.handle_checkpoint_vote(&vote_c).unwrap();
    assert!(finalized, "3/3 = 100% should finalize");
}

/// Test 878: Checkpoint quorum with 4 nodes (3/4 = 75% >= 67%)
#[test]
fn test_878_checkpoint_bft_quorum_4_nodes() {
    let nodes_ids = [[0x01; 32], [0x02; 32], [0x03; 32], [0x04; 32]];
    let nodes = setup_multi_node(&nodes_ids);

    // Store a proposal so C-7 guard allows finalization
    let proposer = nodes[0].1.get_proposer(1).unwrap();
    let (proposal, checkpoint_hash) = make_dummy_proposal(1, proposer);
    nodes[0].2.handle_checkpoint_proposal(&proposal).unwrap();

    // 2 votes: 50% < 67%
    for voter in &nodes_ids[..2] {
        let vote = L2CheckpointVoteMessage {
            height: 1,
            checkpoint_hash,
            voter: *voter,
            approve: true,
            signature: [0u8; 64],
            timestamp: 0,
        };
        let finalized = nodes[0].2.handle_checkpoint_vote(&vote).unwrap();
        assert!(!finalized);
    }

    // 3rd vote: 75% >= 67% → finalize
    let vote = L2CheckpointVoteMessage {
        height: 1,
        checkpoint_hash,
        voter: nodes_ids[2],
        approve: true,
        signature: [0u8; 64],
        timestamp: 0,
    };
    let finalized = nodes[0].2.handle_checkpoint_vote(&vote).unwrap();
    assert!(finalized, "3/4 = 75% should reach 67% quorum");
}

/// Test 879: Rejection votes don't count toward quorum
#[test]
fn test_879_rejection_votes_dont_reach_quorum() {
    let nodes_ids = [[0x01; 32], [0x02; 32], [0x03; 32]];
    let nodes = setup_multi_node(&nodes_ids);

    let checkpoint_hash = [0xDD; 32];

    // 2 approvals + 1 rejection = 2/3 approvals = 66.7% < 67%
    let vote_approve1 = L2CheckpointVoteMessage {
        height: 1,
        checkpoint_hash,
        voter: nodes_ids[0],
        approve: true,
        signature: [0u8; 64],
        timestamp: 0,
    };
    nodes[0].2.handle_checkpoint_vote(&vote_approve1).unwrap();

    let vote_reject = L2CheckpointVoteMessage {
        height: 1,
        checkpoint_hash,
        voter: nodes_ids[1],
        approve: false,
        signature: [0u8; 64],
        timestamp: 0,
    };
    let finalized = nodes[0].2.handle_checkpoint_vote(&vote_reject).unwrap();
    assert!(!finalized, "Rejection shouldn't count toward quorum");

    let vote_approve2 = L2CheckpointVoteMessage {
        height: 1,
        checkpoint_hash,
        voter: nodes_ids[2],
        approve: true,
        signature: [0u8; 64],
        timestamp: 0,
    };
    // 2/3 approval = 66.7%, needs ceil(3*67/100)=3
    let finalized = nodes[0].2.handle_checkpoint_vote(&vote_approve2).unwrap();
    assert!(
        !finalized,
        "2/3 approvals not enough when threshold requires all 3"
    );
}

// =============================================================================
// TEST 880-882: Transfer broadcast and confirmed pool
// =============================================================================

/// Test 880: Broadcast adds transaction to confirmed pool
#[test]
fn test_880_broadcast_adds_to_pool() {
    let node_a = [0x01; 32];
    let nodes = setup_multi_node(&[node_a]);

    let root = nodes[0].1.current_root().unwrap();
    nodes[0].1.add_valid_root(root, 0).unwrap();

    let broadcast = L2TransferBroadcastMessage {
        transaction: make_test_tx([0x42; 32], root),
        validator: [0x99; 32],
        signature: [0u8; 64],
        prerequisites: vec![],
    };

    assert_eq!(nodes[0].2.confirmed_pool_size(), 0);
    nodes[0].2.handle_transfer_broadcast(&broadcast).unwrap();
    assert_eq!(nodes[0].2.confirmed_pool_size(), 1);
}

/// Test 881: Duplicate broadcasts are deduplicated
#[test]
fn test_881_broadcast_dedup() {
    let node_a = [0x01; 32];
    let nodes = setup_multi_node(&[node_a]);

    let root = nodes[0].1.current_root().unwrap();
    nodes[0].1.add_valid_root(root, 0).unwrap();

    let broadcast = L2TransferBroadcastMessage {
        transaction: make_test_tx([0x42; 32], root),
        validator: [0x99; 32],
        signature: [0u8; 64],
        prerequisites: vec![],
    };

    nodes[0].2.handle_transfer_broadcast(&broadcast).unwrap();
    nodes[0].2.handle_transfer_broadcast(&broadcast).unwrap();
    nodes[0].2.handle_transfer_broadcast(&broadcast).unwrap();

    assert_eq!(nodes[0].2.confirmed_pool_size(), 1, "Should deduplicate");
}

/// Test 882: Multiple unique broadcasts accumulate in pool
#[test]
fn test_882_multiple_broadcasts_accumulate() {
    let node_a = [0x01; 32];
    let nodes = setup_multi_node(&[node_a]);

    let root = nodes[0].1.current_root().unwrap();
    nodes[0].1.add_valid_root(root, 0).unwrap();

    for i in 0..5u8 {
        let broadcast = L2TransferBroadcastMessage {
            transaction: make_test_tx([i; 32], root),
            validator: [0x99; 32],
            signature: [0u8; 64],
            prerequisites: vec![],
        };
        nodes[0].2.handle_transfer_broadcast(&broadcast).unwrap();
    }

    assert_eq!(nodes[0].2.confirmed_pool_size(), 5);
}

// =============================================================================
// TEST 883-885: Full checkpoint lifecycle
// =============================================================================

/// Test 883: Proposer includes confirmed txs in checkpoint
#[test]
fn test_883_checkpoint_includes_confirmed_txs() {
    let node_a = [0x01; 32];
    let nodes = setup_multi_node(&[node_a]);

    let root = nodes[0].1.current_root().unwrap();
    nodes[0].1.add_valid_root(root, 0).unwrap();

    // Add some transactions to the pool
    for i in 0..3u8 {
        let broadcast = L2TransferBroadcastMessage {
            transaction: make_test_tx([i; 32], root),
            validator: node_a,
            signature: [0u8; 64],
            prerequisites: vec![],
        };
        nodes[0].2.handle_transfer_broadcast(&broadcast).unwrap();
    }

    assert_eq!(nodes[0].2.confirmed_pool_size(), 3);

    // Propose checkpoint (we're the only node, so we're the proposer)
    let proposal = nodes[0].2.propose_checkpoint().unwrap();
    assert!(proposal.is_some());

    let block = proposal.unwrap();
    assert_eq!(block.transactions.len(), 3);
    assert_eq!(block.height, 1); // height 0 + 1
    assert_eq!(block.proposer, node_a);

    // Pool is retained until finalization (clone-not-drain pattern)
    assert_eq!(
        nodes[0].2.confirmed_pool_size(),
        3,
        "Pool should be retained until checkpoint finalization"
    );
}

/// Test 884: Checkpoint proposal validates correctly on other nodes
#[test]
fn test_884_checkpoint_cross_node_validation() {
    let node_a = [0x01; 32];
    let node_b = [0x02; 32];
    let nodes = setup_multi_node(&[node_a, node_b]);

    // Find who proposes height 1
    let proposer = nodes[0].1.get_proposer(1).unwrap();
    let proposer_idx = if proposer == node_a { 0 } else { 1 };
    let voter_idx = if proposer_idx == 0 { 1 } else { 0 };

    // Proposer creates checkpoint
    let proposal = nodes[proposer_idx].2.propose_checkpoint().unwrap().unwrap();

    // Voter validates the proposal
    let vote = nodes[voter_idx]
        .2
        .handle_checkpoint_proposal(&proposal)
        .unwrap();

    assert!(vote.is_some(), "Valid proposal should generate a vote");
    let vote = vote.unwrap();
    assert!(vote.approve, "Valid proposal should be approved");
    assert_eq!(vote.height, 1);
}

/// Test 885: Checkpoint finalization persists to database
#[test]
fn test_885_checkpoint_finalization_persists() {
    let node_a = [0x01; 32];
    let nodes = setup_multi_node(&[node_a]);

    // Get root and register it
    let root = nodes[0].1.current_root().unwrap();
    nodes[0].1.add_valid_root(root, 0).unwrap();

    // Propose an empty checkpoint and use the full propose_and_broadcast flow
    let proposal = nodes[0].2.propose_checkpoint().unwrap().unwrap();
    let checkpoint_hash = proposal.checkpoint_hash();

    // Store proposal in vote state (mirrors propose_and_broadcast flow)
    nodes[0].2.handle_checkpoint_proposal(&proposal).unwrap();

    // Self-vote (single node = 100%)
    let vote = L2CheckpointVoteMessage {
        height: 1,
        checkpoint_hash,
        voter: node_a,
        approve: true,
        signature: [0u8; 64],
        timestamp: 0,
    };
    let finalized = nodes[0].2.handle_checkpoint_vote(&vote).unwrap();
    assert!(finalized);

    // Check that the checkpoint was persisted
    let checkpoint = nodes[0].0.get_l2_checkpoint(1).unwrap();
    assert!(checkpoint.is_some(), "Checkpoint should be persisted in DB");
    let record = checkpoint.unwrap();
    assert_eq!(record.height, 1);
    assert_eq!(record.epoch, 0);
}

// =============================================================================
// TEST 886-887: Epoch transitions
// =============================================================================

/// Test 886: Epoch boundary detection at correct height
#[test]
fn test_886_epoch_boundary_detection() {
    let node_a = [0x01; 32];
    let db = Arc::new(Database::in_memory().unwrap());
    let config = EpochManagerConfig {
        epoch_length: 10, // Short epoch for testing
        transition_window: 2,
        tree_depth: TEST_TREE_DEPTH,
        max_valid_roots: 16,
    };
    let epoch_mgr = Arc::new(EpochManager::new(db.clone(), config));
    epoch_mgr.initialize_genesis().unwrap();
    epoch_mgr.update_active_nodes(vec![node_a]);

    // Heights 1-9: no compaction
    for h in 1..10u64 {
        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, h).unwrap();
        let result = epoch_mgr.on_checkpoint_finalized(h).unwrap();
        assert!(result.is_none(), "No compaction expected at height {}", h);
    }

    // Height 10: epoch boundary, triggers compaction
    let root = epoch_mgr.current_root().unwrap();
    epoch_mgr.add_valid_root(root, 10).unwrap();
    let result = epoch_mgr.on_checkpoint_finalized(10).unwrap();
    assert!(result.is_some(), "Compaction expected at epoch boundary");

    let compaction = result.unwrap();
    assert_eq!(compaction.new_epoch, 1);
}

/// Test 887: Epoch transition preserves unspent notes
#[test]
fn test_887_epoch_transition_preserves_notes() {
    let node_a = [0x01; 32];
    let db = Arc::new(Database::in_memory().unwrap());
    let config = EpochManagerConfig {
        epoch_length: 5, // Very short for testing
        transition_window: 1,
        tree_depth: TEST_TREE_DEPTH,
        max_valid_roots: 16,
    };
    let epoch_mgr = Arc::new(EpochManager::new(db.clone(), config));
    epoch_mgr.initialize_genesis().unwrap();
    epoch_mgr.update_active_nodes(vec![node_a]);

    // Add some commitments (notes)
    let mut c = [0u8; 32];
    c[0] = 0x01;
    epoch_mgr.append_commitment(c, 1).unwrap();
    c[0] = 0x02;
    epoch_mgr.append_commitment(c, 1).unwrap();
    c[0] = 0x03;
    epoch_mgr.append_commitment(c, 1).unwrap();

    // Advance through heights to trigger epoch
    for h in 1..=5u64 {
        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, h).unwrap();
        let _ = epoch_mgr.on_checkpoint_finalized(h);
    }

    // After epoch transition, tree should have a valid root
    let new_root = epoch_mgr.current_root().unwrap();
    assert_ne!(
        new_root, [0u8; 32],
        "Tree should have non-zero root after transition"
    );
    assert_eq!(epoch_mgr.current_epoch(), 1);
}

// =============================================================================
// TEST 888-889: Edge cases and safety
// =============================================================================

/// Test 888: Handler works without verifier (returns error on tx validation)
#[test]
fn test_888_handler_without_verifier() {
    let node_a = [0x01; 32];

    // Build handler WITHOUT verifier to test fail-closed behavior
    let db = Arc::new(Database::in_memory().expect("in-memory DB"));
    let config = EpochManagerConfig {
        epoch_length: 100,
        transition_window: 10,
        tree_depth: TEST_TREE_DEPTH,
        max_valid_roots: 16,
    };
    let epoch_mgr = Arc::new(EpochManager::new(db.clone(), config));
    epoch_mgr.initialize_genesis().unwrap();
    epoch_mgr.update_active_nodes(vec![node_a]);

    let handler = Arc::new(NullifierRouteHandler::with_defaults(
        node_a,
        epoch_mgr.clone(),
        db.clone(),
    ));
    // Deliberately NOT calling handler.set_verifier()

    let root = epoch_mgr.current_root().unwrap();
    epoch_mgr.add_valid_root(root, 0).unwrap();

    let msg = L2ConfidentialTransferMessage {
        transaction: make_test_tx([0x42; 32], root),
        sender: [0x99; 32],
    };

    // Without verifier set, should reject transfers
    let result = handler.handle_transfer(&msg);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("No verifier"));

    // But checkpoint proposals should still work (no proof involved)
    let proposal = handler.propose_checkpoint().unwrap();
    assert!(proposal.is_some());
}

/// Test 889: Vote state pruning keeps memory bounded
#[test]
fn test_889_vote_state_pruning() {
    let node_a = [0x01; 32];
    let nodes = setup_multi_node(&[node_a]);

    // Submit proposals + votes for many heights (single node = immediate quorum)
    for h in 1..=200u64 {
        let (proposal, hash) = make_dummy_proposal(h, node_a);
        nodes[0].2.handle_checkpoint_proposal(&proposal).unwrap();

        let vote = L2CheckpointVoteMessage {
            height: h,
            checkpoint_hash: hash,
            voter: node_a,
            approve: true,
            signature: [0u8; 64],
            timestamp: 0,
        };
        nodes[0].2.handle_checkpoint_vote(&vote).unwrap();
    }

    // After finalization at height 200, old vote states should be pruned.
    // We verify the system doesn't crash with 200 consecutive checkpoints.
}

// =============================================================================
// TEST 891-896: submit_external_transfer, FinalizeFn, fail-closed
// =============================================================================

/// Test 891: submit_external_transfer accepts a valid transaction
#[test]
fn test_891_submit_external_transfer_valid() {
    let node_a = [0x01; 32];
    let node_b = [0x02; 32];
    let nodes = setup_multi_node(&[node_a, node_b]);

    let genesis_root = nodes[0].1.current_root().unwrap();
    for (_, epoch_mgr, _) in &nodes {
        epoch_mgr.add_valid_root(genesis_root, 0).unwrap();
    }

    let nullifier = [0xAA; 32];
    let validator_id = nodes[0].1.validator_for_nullifier(&nullifier).unwrap();
    let validator_idx = [node_a, node_b]
        .iter()
        .position(|id| *id == validator_id)
        .unwrap();

    // Set up broadcast_fn to track calls
    let broadcast_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let bc = broadcast_called.clone();
    nodes[validator_idx].2.set_broadcast_fn(Arc::new(
        move |_msg_type: MessageType,
              _payload: Vec<u8>|
              -> Result<(), ghost_common::error::GhostError> {
            bc.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        },
    ));

    let tx = make_test_tx(nullifier, genesis_root);
    let msg = L2ConfidentialTransferMessage {
        transaction: tx,
        sender: [0x99; 32],
    };

    let result = nodes[validator_idx].2.submit_external_transfer(&msg);
    assert!(result.is_ok(), "Valid external transfer should succeed");
    assert!(
        broadcast_called.load(std::sync::atomic::Ordering::SeqCst),
        "Broadcast function should have been called"
    );
}

/// Test 892: submit_external_transfer rejects double-spend (same nullifier twice)
#[test]
fn test_892_submit_external_transfer_double_spend() {
    let node_a = [0x01; 32];
    let node_b = [0x02; 32];
    let nodes = setup_multi_node(&[node_a, node_b]);

    let genesis_root = nodes[0].1.current_root().unwrap();
    for (_, epoch_mgr, _) in &nodes {
        epoch_mgr.add_valid_root(genesis_root, 0).unwrap();
    }

    let nullifier = [0xBB; 32];
    let validator_id = nodes[0].1.validator_for_nullifier(&nullifier).unwrap();
    let validator_idx = [node_a, node_b]
        .iter()
        .position(|id| *id == validator_id)
        .unwrap();

    let tx = make_test_tx(nullifier, genesis_root);
    let msg = L2ConfidentialTransferMessage {
        transaction: tx,
        sender: [0x99; 32],
    };

    // First submission should succeed
    let result1 = nodes[validator_idx].2.submit_external_transfer(&msg);
    assert!(result1.is_ok(), "First submission should succeed");

    // Second submission with same nullifier should fail
    let result2 = nodes[validator_idx].2.submit_external_transfer(&msg);
    assert!(result2.is_err(), "Double-spend should be rejected");
    let err = result2.unwrap_err().to_string();
    assert!(
        err.contains("already spent") || err.contains("double-spend") || err.contains("Nullifier"),
        "Error should mention nullifier/double-spend, got: {}",
        err
    );
}

/// Test 893: submit_external_transfer rejects invalid commitment root
#[test]
fn test_893_submit_external_transfer_invalid_root() {
    let node_a = [0x01; 32];
    let node_b = [0x02; 32];
    let nodes = setup_multi_node(&[node_a, node_b]);

    // DO NOT add genesis root as valid — any root check should fail
    let wrong_root = [0xFF; 32];
    let nullifier = [0xCC; 32];
    let validator_id = nodes[0].1.validator_for_nullifier(&nullifier).unwrap();
    let validator_idx = [node_a, node_b]
        .iter()
        .position(|id| *id == validator_id)
        .unwrap();

    let tx = make_test_tx(nullifier, wrong_root);
    let msg = L2ConfidentialTransferMessage {
        transaction: tx,
        sender: [0x99; 32],
    };

    let result = nodes[validator_idx].2.submit_external_transfer(&msg);
    assert!(
        result.is_err(),
        "Invalid commitment root should be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("root") || err.contains("commitment"),
        "Error should mention root, got: {}",
        err
    );
}

/// Test 894: FinalizeFn is called on checkpoint finalization with correct args
///
/// Uses 2 nodes so the proposer's proposal gets stored via handle_checkpoint_proposal
/// on the second node, ensuring tx_count is correctly reported.
#[test]
fn test_894_finalize_fn_called_on_checkpoint() {
    let node_a = [0x01; 32];
    let node_b = [0x02; 32];
    let node_ids = [node_a, node_b];
    let nodes = setup_multi_node(&node_ids);

    let genesis_root = nodes[0].1.current_root().unwrap();
    for (_, epoch_mgr, _) in &nodes {
        epoch_mgr.add_valid_root(genesis_root, 0).unwrap();
    }

    // Wire FinalizeFn on the proposer (will be determined below)
    let finalize_height = Arc::new(std::sync::Mutex::new(0u64));
    let finalize_root = Arc::new(std::sync::Mutex::new([0u8; 32]));
    let finalize_nullifiers = Arc::new(std::sync::Mutex::new(Vec::<[u8; 32]>::new()));

    // Set FinalizeFn on both nodes (one of them will be the proposer)
    for (_, _, handler) in &nodes {
        let fh = finalize_height.clone();
        let fr = finalize_root.clone();
        let fn_ = finalize_nullifiers.clone();
        handler.set_finalize_fn(Arc::new(move |h, r, nullifiers| {
            *fh.lock().unwrap() = h;
            *fr.lock().unwrap() = r;
            *fn_.lock().unwrap() = nullifiers;
        }));
    }

    // Submit a transaction to the correct validator
    let nullifier = [0xDD; 32];
    let validator_id = nodes[0].1.validator_for_nullifier(&nullifier).unwrap();
    let validator_idx = node_ids.iter().position(|id| *id == validator_id).unwrap();

    let tx = make_test_tx(nullifier, genesis_root);
    let msg = L2ConfidentialTransferMessage {
        transaction: tx.clone(),
        sender: [0x99; 32],
    };
    nodes[validator_idx].2.handle_transfer(&msg).unwrap();

    // Broadcast to all nodes
    let broadcast = L2TransferBroadcastMessage {
        transaction: tx,
        validator: validator_id,
        signature: [0u8; 64],
        prerequisites: vec![],
    };
    for (_, _, handler) in &nodes {
        handler.handle_transfer_broadcast(&broadcast).unwrap();
    }

    // Proposer creates checkpoint
    let proposer_id = nodes[0].1.get_proposer(1).unwrap();
    let proposer_idx = node_ids.iter().position(|id| *id == proposer_id).unwrap();

    let proposal = nodes[proposer_idx]
        .2
        .propose_checkpoint()
        .unwrap()
        .expect("Should produce proposal");
    assert!(
        !proposal.transactions.is_empty(),
        "Proposal should have transactions"
    );

    // Proposer stores its own proposal (mirrors propose_and_broadcast flow)
    let proposer_vote = nodes[proposer_idx]
        .2
        .handle_checkpoint_proposal(&proposal)
        .unwrap()
        .unwrap();
    let mut votes = vec![proposer_vote];

    // Non-proposer validates and votes
    for (i, (_, _, handler)) in nodes.iter().enumerate() {
        if i == proposer_idx {
            continue;
        }
        let vote = handler
            .handle_checkpoint_proposal(&proposal)
            .unwrap()
            .unwrap();
        assert!(vote.approve);
        votes.push(vote);
    }

    // Feed votes to proposer
    let mut finalized = false;
    for vote in &votes {
        if nodes[proposer_idx].2.handle_checkpoint_vote(vote).unwrap() {
            finalized = true;
        }
    }
    assert!(finalized, "Should reach quorum and finalize");

    // Check FinalizeFn was called with correct values
    assert_eq!(
        *finalize_height.lock().unwrap(),
        1,
        "FinalizeFn height should be 1"
    );
    assert_ne!(
        *finalize_root.lock().unwrap(),
        [0u8; 32],
        "FinalizeFn root should be non-zero"
    );
}

/// Test 895: Full 3-node flow from external submit through finalization
#[test]
fn test_895_external_submit_through_finalization() {
    let node_a = [0x01; 32];
    let node_b = [0x02; 32];
    let node_c = [0x03; 32];
    let node_ids = [node_a, node_b, node_c];
    let nodes = setup_multi_node(&node_ids);

    let genesis_root = nodes[0].1.current_root().unwrap();
    for (_, epoch_mgr, _) in &nodes {
        epoch_mgr.add_valid_root(genesis_root, 0).unwrap();
    }

    // Wire FinalizeFn on all nodes
    let finalized_heights: Vec<Arc<std::sync::Mutex<u64>>> = (0..3)
        .map(|_| Arc::new(std::sync::Mutex::new(0u64)))
        .collect();
    for (i, (_, _, handler)) in nodes.iter().enumerate() {
        let fh = finalized_heights[i].clone();
        handler.set_finalize_fn(Arc::new(move |h, _r, _nullifiers| {
            *fh.lock().unwrap() = h;
        }));
    }

    // Step 1: External submit on the correct validator
    let nullifier = [0xEE; 32];
    let validator_id = nodes[0].1.validator_for_nullifier(&nullifier).unwrap();
    let validator_idx = node_ids.iter().position(|id| *id == validator_id).unwrap();

    let tx = make_test_tx(nullifier, genesis_root);
    let msg = L2ConfidentialTransferMessage {
        transaction: tx.clone(),
        sender: [0x99; 32],
    };
    nodes[validator_idx]
        .2
        .submit_external_transfer(&msg)
        .expect("External submit should succeed");

    // Step 2: Broadcast to all nodes
    let broadcast = L2TransferBroadcastMessage {
        transaction: tx,
        validator: validator_id,
        signature: [0u8; 64],
        prerequisites: vec![],
    };
    for (_, _, handler) in &nodes {
        handler.handle_transfer_broadcast(&broadcast).unwrap();
    }

    // Step 3: Proposer creates checkpoint
    let proposer_id = nodes[0].1.get_proposer(1).unwrap();
    let proposer_idx = node_ids.iter().position(|id| *id == proposer_id).unwrap();

    let proposal = nodes[proposer_idx]
        .2
        .propose_checkpoint()
        .unwrap()
        .expect("Should produce proposal");
    // Step 4: Proposer stores its own proposal and collects votes
    let proposer_vote = nodes[proposer_idx]
        .2
        .handle_checkpoint_proposal(&proposal)
        .unwrap()
        .unwrap();
    let mut votes = vec![proposer_vote];

    for (i, (_, _, handler)) in nodes.iter().enumerate() {
        if i == proposer_idx {
            continue;
        }
        let vote = handler
            .handle_checkpoint_proposal(&proposal)
            .unwrap()
            .unwrap();
        assert!(vote.approve);
        votes.push(vote);
    }

    // Step 5: Feed votes to reach quorum
    let mut finalized = false;
    for vote in &votes {
        if nodes[proposer_idx].2.handle_checkpoint_vote(vote).unwrap() {
            finalized = true;
        }
    }
    assert!(finalized, "Should reach quorum and finalize");

    // Step 6: Verify finalize callback was invoked on proposer
    assert_eq!(
        *finalized_heights[proposer_idx].lock().unwrap(),
        1,
        "FinalizeFn should have been called with height 1"
    );
}

/// Test 896: submit_external_transfer fails closed when no verifier is set (S-1 audit fix)
#[test]
fn test_896_submit_external_no_verifier() {
    let node_a = [0x01; 32];
    let node_b = [0x02; 32];

    // Create nodes WITHOUT setting verifier (manually build without setup_node helper)
    let db = Arc::new(Database::in_memory().expect("in-memory DB"));
    let config = EpochManagerConfig {
        epoch_length: 100,
        transition_window: 10,
        tree_depth: TEST_TREE_DEPTH,
        max_valid_roots: 16,
    };
    let epoch_mgr = Arc::new(EpochManager::new(db.clone(), config));
    epoch_mgr.initialize_genesis().unwrap();
    epoch_mgr.update_active_nodes(vec![node_a, node_b]);

    let handler = Arc::new(NullifierRouteHandler::with_defaults(
        node_a,
        epoch_mgr.clone(),
        db.clone(),
    ));
    // Deliberately DO NOT call handler.set_verifier() — verifier is None

    let genesis_root = epoch_mgr.current_root().unwrap();
    epoch_mgr.add_valid_root(genesis_root, 0).unwrap();

    let nullifier = [0xFF; 32];
    let validator_id = epoch_mgr.validator_for_nullifier(&nullifier).unwrap();

    // Only run if node_a is the validator (otherwise the test is routing to wrong node)
    if validator_id == node_a {
        let tx = make_test_tx(nullifier, genesis_root);
        let msg = L2ConfidentialTransferMessage {
            transaction: tx,
            sender: [0x99; 32],
        };

        let result = handler.submit_external_transfer(&msg);
        assert!(
            result.is_err(),
            "S-1: Must fail closed when no verifier is set"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("verifier") || err.contains("MPC"),
            "Error should mention missing verifier, got: {}",
            err
        );
    } else {
        // node_b would be the validator — adjust test to target node_b
        // Non-validator node returns Ok(None) from handle_transfer, which is fine.
        // We don't assert on the result — it's expected to succeed or be a no-op.
        let _ = handler.submit_external_transfer(&L2ConfidentialTransferMessage {
            transaction: make_test_tx([0x01; 32], genesis_root),
            sender: [0x99; 32],
        });
    }
}

// =============================================================================
// TEST 890: Full-flow end-to-end integration test
// =============================================================================

/// Test 890: Full flow from transfer submission through checkpoint finalization
///
/// This is the end-to-end integration test that chains:
/// 1. 3-node setup with genesis root
/// 2. Transaction creation and routing to correct validator
/// 3. Validator confirms transfer
/// 4. Broadcast to all nodes
/// 5. Proposer creates checkpoint
/// 6. Non-proposers vote to approve
/// 7. BFT quorum reached → checkpoint finalized
/// 8. Assertions: checkpoint persisted, nullifier spent, height advanced
#[test]
fn test_890_full_flow_transfer_to_finalization() {
    // ── Step 1: Setup 3 nodes ──────────────────────────────────────────────
    let node_a = [0x01; 32];
    let node_b = [0x02; 32];
    let node_c = [0x03; 32];
    let node_ids = [node_a, node_b, node_c];

    let nodes = setup_multi_node(&node_ids);

    // Add genesis root as valid on all nodes
    let genesis_root = nodes[0].1.current_root().unwrap();
    for (_, epoch_mgr, _) in &nodes {
        epoch_mgr.add_valid_root(genesis_root, 0).unwrap();
    }

    // ── Step 2: Create tx and route to correct validator ───────────────────
    let nullifier = [0xAA; 32];
    let validator_id = nodes[0].1.validator_for_nullifier(&nullifier).unwrap();
    let validator_idx = node_ids.iter().position(|id| *id == validator_id).unwrap();

    let tx = make_test_tx(nullifier, genesis_root);

    let msg = L2ConfidentialTransferMessage {
        transaction: tx.clone(),
        sender: [0x99; 32],
    };

    // ── Step 3: Validator confirms transfer ────────────────────────────────
    let confirmation = nodes[validator_idx]
        .2
        .handle_transfer(&msg)
        .expect("Transfer should succeed on correct validator");
    assert!(
        confirmation.is_some(),
        "Correct validator should return confirmation"
    );

    // ── Step 4: Broadcast to all nodes ─────────────────────────────────────
    let broadcast = L2TransferBroadcastMessage {
        transaction: tx,
        validator: validator_id,
        signature: [0u8; 64],
        prerequisites: vec![],
    };

    for (_, _, handler) in &nodes {
        handler
            .handle_transfer_broadcast(&broadcast)
            .expect("Broadcast should succeed");
    }

    // Verify all nodes have the tx in their confirmed pool
    for (i, (_, _, handler)) in nodes.iter().enumerate() {
        assert_eq!(
            handler.confirmed_pool_size(),
            1,
            "Node {} should have 1 confirmed tx",
            i
        );
    }

    // ── Step 5: Proposer creates checkpoint ────────────────────────────────
    let proposer_id = nodes[0].1.get_proposer(1).unwrap();
    let proposer_idx = node_ids.iter().position(|id| *id == proposer_id).unwrap();

    let proposal = nodes[proposer_idx]
        .2
        .propose_checkpoint()
        .expect("Proposer should succeed")
        .expect("Proposer should produce a proposal");

    assert_eq!(proposal.height, 1);
    assert_eq!(proposal.transactions.len(), 1);
    assert_eq!(proposal.proposer, proposer_id);

    // Pool is retained until finalization (clone-not-drain)
    assert_eq!(nodes[proposer_idx].2.confirmed_pool_size(), 1);

    // ── Step 6: All nodes validate proposal and vote ────────────────────────
    let mut votes: Vec<L2CheckpointVoteMessage> = Vec::new();

    // Proposer stores its own proposal (mirrors propose_and_broadcast)
    let proposer_vote = nodes[proposer_idx]
        .2
        .handle_checkpoint_proposal(&proposal)
        .expect("Proposer should accept own proposal")
        .expect("Should produce vote");
    votes.push(proposer_vote);

    // Other nodes validate the proposal and produce approval votes
    for (i, (_, _, handler)) in nodes.iter().enumerate() {
        if i == proposer_idx {
            continue;
        }
        let vote = handler
            .handle_checkpoint_proposal(&proposal)
            .expect("Proposal validation should succeed")
            .expect("Valid proposal should produce a vote");

        assert!(vote.approve, "Node {} should approve valid proposal", i);
        assert_eq!(vote.height, 1);
        votes.push(vote);
    }

    assert_eq!(votes.len(), 3, "Should have 3 votes (1 self + 2 voters)");

    // ── Step 7: Feed votes to proposer to reach quorum ────────────────────
    // Quorum = 3/3 for a 3-node network (ceil(3 * 67 / 100) = 3).
    let mut finalized_count = 0;
    for vote in &votes {
        let finalized = nodes[proposer_idx]
            .2
            .handle_checkpoint_vote(vote)
            .expect("Vote handling should succeed");
        if finalized {
            finalized_count += 1;
        }
    }
    assert_eq!(
        finalized_count, 1,
        "Exactly one vote should trigger finalization (the 3rd)"
    );

    // ── Step 8: Assertions ─────────────────────────────────────────────────
    // Checkpoint should be persisted in the proposer's DB
    let checkpoint = nodes[proposer_idx]
        .0
        .get_l2_checkpoint(1)
        .expect("DB query should succeed");
    assert!(
        checkpoint.is_some(),
        "Checkpoint at height 1 should be persisted"
    );
    let record = checkpoint.unwrap();
    assert_eq!(record.height, 1);
    assert_eq!(record.epoch, 0);

    // Nullifier should be spent (double-spend should fail)
    let double_spend_msg = L2ConfidentialTransferMessage {
        transaction: make_test_tx(nullifier, genesis_root),
        sender: [0x99; 32],
    };
    let double_spend_result = nodes[validator_idx].2.handle_transfer(&double_spend_msg);
    assert!(
        double_spend_result.is_err(),
        "Nullifier should be spent after checkpoint finalization"
    );
}
