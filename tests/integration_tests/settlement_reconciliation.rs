//! Category 14: Settlement Reconciliation Tests (40 tests)
//!
//! Tests for L1 settlement and reconciliation:
//! - Settlement creation and validation
//! - Settlement state machine transitions
//! - Ownership proof construction and epoch verification
//! - Batch management lifecycle
//! - Merkle tree computation and proof verification
//! - Global input reservation tracking

use std::collections::HashSet;

use bitcoin::OutPoint;
use ghost_reconciliation::{
    batch::{compute_merkle_proof, compute_merkle_root, verify_merkle_proof, Batch, BatchState},
    executor::GlobalInputReservations,
    settlement::{OwnershipProof, Settlement, SettlementState},
    MAX_BATCH_SIZE, MIN_BATCH_SIZE, MIN_SETTLEMENT_SATS,
};

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

fn test_lock_id() -> [u8; 32] {
    [1u8; 32]
}

fn make_settlement(amount: u64) -> Settlement {
    Settlement::new(
        "ghost1_test_node".to_string(),
        test_lock_id(),
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        amount,
    )
    .expect("valid settlement")
}

fn make_settlement_unique(index: u32) -> Settlement {
    Settlement::new(
        format!("ghost1_test_{}", index),
        [index as u8; 32],
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        50_000 + (index as u64 * 1_000),
    )
    .expect("valid settlement")
}

fn dummy_txid() -> bitcoin::Txid {
    use std::str::FromStr;
    bitcoin::Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001")
        .unwrap()
}

// =============================================================================
// SETTLEMENT CREATION (Tests 780-786)
// =============================================================================

#[test]
fn test_780_settlement_new_valid_params_pending_state() {
    let settlement = Settlement::new(
        "ghost1_test_1".to_string(),
        [1u8; 32],
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        100_000,
    )
    .unwrap();

    assert_eq!(settlement.state(), SettlementState::Pending);
    assert_eq!(settlement.amount_sats(), 100_000);
    assert_eq!(settlement.source_ghost_id(), "ghost1_test_1");
    assert_eq!(
        settlement.destination_address(),
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
    );
    assert!(settlement.batch_id().is_none());
    assert!(settlement.merkle_proof().is_none());
    assert!(settlement.l1_txid().is_none());
}

#[test]
fn test_781_settlement_below_minimum_rejected() {
    // MIN_SETTLEMENT_SATS is 10_000 -- amounts below that must fail
    let result = Settlement::new(
        "ghost1_test_1".to_string(),
        [1u8; 32],
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        9_999,
    );
    assert!(result.is_err());

    // Exactly at the boundary should succeed
    let result = Settlement::new(
        "ghost1_test_1".to_string(),
        [1u8; 32],
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        MIN_SETTLEMENT_SATS,
    );
    assert!(result.is_ok());
}

#[test]
fn test_782_all_settlement_types_fee_free() {
    // Protocol fee removed — all settlement types have fee_sats == 0
    // and net_amount_sats == amount_sats
    let s1 = make_settlement(100_000);
    assert_eq!(s1.fee_sats(), 0);
    assert_eq!(s1.net_amount_sats(), s1.amount_sats());

    let s2 = make_settlement(10_000);
    assert_eq!(s2.fee_sats(), 0);
    assert_eq!(s2.net_amount_sats(), s2.amount_sats());

    let s3 = make_settlement(10_001);
    assert_eq!(s3.fee_sats(), 0);
    assert_eq!(s3.net_amount_sats(), s3.amount_sats());

    // Jump and WraithJump should also be fee-free
    let jump = Settlement::new_jump(
        "ghost1_test_jump".to_string(),
        [10u8; 32],
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        50_000,
    )
    .unwrap();
    assert_eq!(jump.fee_sats(), 0);
    assert_eq!(jump.net_amount_sats(), jump.amount_sats());

    let wraith = Settlement::new_wraith_jump(
        "ghost1_test_wraith".to_string(),
        [11u8; 32],
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        50_000,
    )
    .unwrap();
    assert_eq!(wraith.fee_sats(), 0);
    assert_eq!(wraith.net_amount_sats(), wraith.amount_sats());
}

#[test]
fn test_783_net_amount_equals_amount_no_fee() {
    let settlement = make_settlement(100_000);

    assert_eq!(settlement.fee_sats(), 0);
    assert_eq!(settlement.net_amount_sats(), settlement.amount_sats());
    assert_eq!(settlement.net_amount_sats(), 100_000);
}

#[test]
fn test_784_unique_ids_for_identical_params() {
    let mut ids = HashSet::new();
    for _ in 0..100 {
        let settlement = Settlement::new(
            "ghost1_test_1".to_string(),
            [1u8; 32],
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            100_000,
        )
        .unwrap();
        let id = *settlement.id();
        assert!(
            ids.insert(id),
            "Settlement ID collision detected -- settlements with identical params must have unique IDs"
        );
    }
    assert_eq!(ids.len(), 100);
}

#[test]
fn test_785_destination_address_matches_input() {
    let addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    let settlement = Settlement::new(
        "ghost1_test_1".to_string(),
        [1u8; 32],
        addr.to_string(),
        50_000,
    )
    .unwrap();

    assert_eq!(settlement.destination_address(), addr);
}

#[test]
fn test_786_source_lock_id_matches_input() {
    let lock_id = [42u8; 32];
    let settlement = Settlement::new(
        "ghost1_test_1".to_string(),
        lock_id,
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        50_000,
    )
    .unwrap();

    assert_eq!(settlement.source_lock_id(), &lock_id);
}

// =============================================================================
// SETTLEMENT STATE MACHINE (Tests 787-793)
// =============================================================================

#[test]
fn test_787_mark_batched_from_pending_succeeds() {
    let mut settlement = make_settlement(50_000);
    assert_eq!(settlement.state(), SettlementState::Pending);

    let batch_id = [0xAAu8; 32];
    let merkle_proof = vec![[0xBBu8; 32], [0xCCu8; 32]];
    settlement
        .mark_batched(batch_id, merkle_proof.clone())
        .unwrap();

    assert_eq!(settlement.state(), SettlementState::Batched);
    assert_eq!(settlement.batch_id(), Some(&batch_id));
    assert_eq!(settlement.merkle_proof().unwrap(), &merkle_proof);
}

#[test]
fn test_788_mark_confirming_from_batched_succeeds() {
    let mut settlement = make_settlement(50_000);
    settlement.mark_batched([0u8; 32], vec![]).unwrap();
    assert_eq!(settlement.state(), SettlementState::Batched);

    settlement
        .mark_confirming("abc123txid".to_string())
        .unwrap();
    assert_eq!(settlement.state(), SettlementState::Confirming);
    assert_eq!(settlement.l1_txid(), Some("abc123txid"));
}

#[test]
fn test_789_mark_finalized_from_confirming_succeeds() {
    let mut settlement = make_settlement(50_000);
    settlement.mark_batched([0u8; 32], vec![]).unwrap();
    settlement
        .mark_confirming("txid_final".to_string())
        .unwrap();
    assert_eq!(settlement.state(), SettlementState::Confirming);

    settlement.mark_finalized().unwrap();
    assert_eq!(settlement.state(), SettlementState::Finalized);
}

#[test]
fn test_790_mark_confirming_from_pending_fails() {
    let mut settlement = make_settlement(50_000);
    assert_eq!(settlement.state(), SettlementState::Pending);

    let result = settlement.mark_confirming("txid".to_string());
    assert!(result.is_err(), "mark_confirming from Pending must fail");
}

#[test]
fn test_791_cancel_from_pending_succeeds() {
    let mut settlement = make_settlement(50_000);
    assert_eq!(settlement.state(), SettlementState::Pending);

    settlement.cancel().unwrap();
    assert_eq!(settlement.state(), SettlementState::Cancelled);
}

#[test]
fn test_792_cancel_from_batched_fails() {
    let mut settlement = make_settlement(50_000);
    settlement.mark_batched([0u8; 32], vec![]).unwrap();
    assert_eq!(settlement.state(), SettlementState::Batched);

    // can_cancel() is only true for Pending
    assert!(!settlement.state().can_cancel());
    let result = settlement.cancel();
    assert!(result.is_err(), "cancel from Batched must fail");
}

#[test]
fn test_793_terminal_states_reject_all_transitions() {
    // Test Finalized state
    let mut finalized = make_settlement(50_000);
    finalized.mark_batched([0u8; 32], vec![]).unwrap();
    finalized.mark_confirming("txid".to_string()).unwrap();
    finalized.mark_finalized().unwrap();
    assert!(finalized.state().is_terminal());

    assert!(finalized.mark_batched([1u8; 32], vec![]).is_err());
    assert!(finalized.mark_confirming("txid2".to_string()).is_err());
    assert!(finalized.mark_finalized().is_err());
    assert!(finalized.cancel().is_err());

    // Test Cancelled state
    let mut cancelled = make_settlement(50_000);
    cancelled.cancel().unwrap();
    assert!(cancelled.state().is_terminal());

    assert!(cancelled.mark_batched([1u8; 32], vec![]).is_err());
    assert!(cancelled.mark_confirming("txid".to_string()).is_err());
    assert!(cancelled.mark_finalized().is_err());
    assert!(cancelled.cancel().is_err());
}

// =============================================================================
// OWNERSHIP PROOF (Tests 794-801)
// =============================================================================

#[test]
fn test_794_ownership_proof_new_stores_fields() {
    let sig = [0xAAu8; 64];
    let pubkey = [0xBBu8; 32];
    let epoch = 100u64;
    let batch_id = [0xCCu8; 32];

    let proof = OwnershipProof::new(sig, pubkey, epoch, batch_id);

    assert_eq!(proof.signature().unwrap(), sig);
    assert_eq!(proof.source_pubkey(), &pubkey);
    assert_eq!(proof.epoch(), epoch);
    assert_eq!(proof.batch_id().unwrap(), batch_id);
}

#[test]
fn test_795_new_pending_sets_batch_id_to_zeros() {
    let sig = [0xAAu8; 64];
    let pubkey = [0xBBu8; 32];
    let epoch = 42u64;

    let proof = OwnershipProof::new_pending(sig, pubkey, epoch);

    assert_eq!(proof.batch_id().unwrap(), [0u8; 32]);
    assert_eq!(proof.epoch(), epoch);
    assert_eq!(proof.source_pubkey(), &pubkey);
}

#[test]
fn test_796_build_message_is_deterministic() {
    let epoch = 10u64;
    let batch_id = [5u8; 32];
    let settlement_id = [1u8; 32];
    let destination = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    let amount = 50_000u64;

    let msg1 = OwnershipProof::build_message(epoch, &batch_id, &settlement_id, destination, amount);
    let msg2 = OwnershipProof::build_message(epoch, &batch_id, &settlement_id, destination, amount);

    assert_eq!(msg1, msg2, "Same inputs must produce the same hash");
    // The hash should be 32 bytes (non-zero with overwhelming probability)
    assert_ne!(msg1, [0u8; 32], "Hash should not be all zeros");
}

#[test]
fn test_797_build_message_varies_with_settlement_id() {
    let epoch = 10u64;
    let batch_id = [5u8; 32];
    let destination = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    let amount = 50_000u64;

    let msg_a = OwnershipProof::build_message(epoch, &batch_id, &[1u8; 32], destination, amount);
    let msg_b = OwnershipProof::build_message(epoch, &batch_id, &[2u8; 32], destination, amount);

    assert_ne!(
        msg_a, msg_b,
        "Different settlement_id must produce different hashes"
    );
}

#[test]
fn test_798_build_message_varies_with_epoch() {
    // C-7: Epoch variation prevents cross-epoch replay attacks
    let batch_id = [5u8; 32];
    let settlement_id = [1u8; 32];
    let destination = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    let amount = 50_000u64;

    let msg_epoch_10 =
        OwnershipProof::build_message(10, &batch_id, &settlement_id, destination, amount);
    let msg_epoch_11 =
        OwnershipProof::build_message(11, &batch_id, &settlement_id, destination, amount);

    assert_ne!(
        msg_epoch_10, msg_epoch_11,
        "C-7: Different epochs must produce different hashes for replay prevention"
    );
}

#[test]
fn test_799_build_message_varies_with_batch_id() {
    // C-7: Batch ID variation prevents cross-batch replay attacks
    let epoch = 10u64;
    let settlement_id = [1u8; 32];
    let destination = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    let amount = 50_000u64;

    let msg_batch_a =
        OwnershipProof::build_message(epoch, &[0xAAu8; 32], &settlement_id, destination, amount);
    let msg_batch_b =
        OwnershipProof::build_message(epoch, &[0xBBu8; 32], &settlement_id, destination, amount);

    assert_ne!(
        msg_batch_a, msg_batch_b,
        "C-7: Different batch_ids must produce different hashes for replay prevention"
    );
}

#[test]
fn test_800_epoch_returns_stored_value() {
    let proof = OwnershipProof::new([0u8; 64], [0u8; 32], 999, [0u8; 32]);
    assert_eq!(proof.epoch(), 999);

    let proof2 = OwnershipProof::new_pending([0u8; 64], [0u8; 32], 0);
    assert_eq!(proof2.epoch(), 0);

    let proof3 = OwnershipProof::new([0u8; 64], [0u8; 32], u64::MAX, [0u8; 32]);
    assert_eq!(proof3.epoch(), u64::MAX);
}

#[test]
fn test_801_verify_epoch_pass_and_fail() {
    let proof = OwnershipProof::new([0u8; 64], [0u8; 32], 42, [0u8; 32]);

    // Matching epoch passes
    assert!(proof.verify_epoch(42).is_ok());

    // Mismatched epoch fails
    assert!(proof.verify_epoch(41).is_err());
    assert!(proof.verify_epoch(43).is_err());
    assert!(proof.verify_epoch(0).is_err());
}

// =============================================================================
// BATCH MANAGEMENT (Tests 802-811)
// =============================================================================

#[test]
fn test_802_batch_new_starts_in_collecting() {
    let batch = Batch::new().expect("Batch::new should succeed");

    assert_eq!(batch.state(), BatchState::Collecting);
    assert_eq!(batch.settlement_count(), 0);
    assert!(batch.merkle_root().is_none());
    assert_eq!(batch.total_amount_sats(), 0);
    assert_eq!(batch.total_fee_sats(), 0);
    assert!(batch.can_accept());
    assert!(!batch.has_minimum());
    assert!(!batch.is_full());
}

#[test]
fn test_803_add_settlement_increases_count_and_totals() {
    let mut batch = Batch::new().unwrap();
    let settlement = make_settlement(100_000);

    let amount = settlement.amount_sats();

    batch.add_settlement(&settlement).unwrap();

    assert_eq!(batch.settlement_count(), 1);
    assert_eq!(batch.total_amount_sats(), amount);
    assert_eq!(batch.total_fee_sats(), 0);

    // Add a second settlement
    let settlement2 = make_settlement(200_000);
    let amount2 = settlement2.amount_sats();

    batch.add_settlement(&settlement2).unwrap();

    assert_eq!(batch.settlement_count(), 2);
    assert_eq!(batch.total_amount_sats(), amount + amount2);
    assert_eq!(batch.total_fee_sats(), 0);
}

#[test]
fn test_804_seal_succeeds_with_min_batch_size() {
    let mut batch = Batch::new().unwrap();

    // Add exactly MIN_BATCH_SIZE (10) settlements
    for i in 0..MIN_BATCH_SIZE {
        let settlement = make_settlement_unique(i as u32);
        batch.add_settlement(&settlement).unwrap();
    }

    assert!(batch.has_minimum());
    assert_eq!(batch.settlement_count(), MIN_BATCH_SIZE);

    batch.seal().unwrap();
    assert_eq!(batch.state(), BatchState::Ready);
    assert!(batch.merkle_root().is_some());
}

#[test]
fn test_805_seal_fails_below_min_batch_size() {
    let mut batch = Batch::new().unwrap();

    // Add fewer than MIN_BATCH_SIZE settlements
    for i in 0..(MIN_BATCH_SIZE - 1) {
        let settlement = make_settlement_unique(i as u32);
        batch.add_settlement(&settlement).unwrap();
    }

    assert!(!batch.has_minimum());
    let result = batch.seal();
    assert!(
        result.is_err(),
        "seal() must fail with fewer than MIN_BATCH_SIZE settlements"
    );
}

#[test]
fn test_806_full_batch_lifecycle() {
    let mut batch = Batch::new().unwrap();

    // Collecting: add settlements
    for i in 0..MIN_BATCH_SIZE {
        batch
            .add_settlement(&make_settlement_unique(i as u32))
            .unwrap();
    }
    assert_eq!(batch.state(), BatchState::Collecting);

    // Collecting -> Ready
    batch.seal().unwrap();
    assert_eq!(batch.state(), BatchState::Ready);

    // Ready -> Submitted
    batch.mark_submitted("txid_abc123".to_string()).unwrap();
    assert_eq!(batch.state(), BatchState::Submitted);
    assert_eq!(batch.l1_txid(), Some("txid_abc123"));

    // Submitted -> Confirming
    batch.mark_confirmed(800_000).unwrap();
    assert_eq!(batch.state(), BatchState::Confirming);
    assert_eq!(batch.l1_height(), Some(800_000));

    // Confirming -> Finalized
    batch.mark_finalized().unwrap();
    assert_eq!(batch.state(), BatchState::Finalized);
    assert!(batch.state().is_terminal());
}

#[test]
fn test_807_add_beyond_max_batch_size_returns_error() {
    // Verify the constant first
    assert_eq!(MAX_BATCH_SIZE, 1000);

    let mut batch = Batch::new().unwrap();

    // Fill to capacity
    for i in 0..MAX_BATCH_SIZE {
        let settlement = make_settlement_unique(i as u32);
        batch.add_settlement(&settlement).unwrap();
    }

    assert!(batch.is_full());
    assert!(!batch.can_accept());

    // Adding one more should fail
    let extra = make_settlement_unique(MAX_BATCH_SIZE as u32);
    let result = batch.add_settlement(&extra);
    assert!(result.is_err(), "Adding beyond MAX_BATCH_SIZE must fail");
}

#[test]
fn test_808_multiple_batches_have_unique_ids() {
    let mut ids = HashSet::new();
    for _ in 0..50 {
        let batch = Batch::new().unwrap();
        let id = *batch.id();
        assert!(
            ids.insert(id),
            "Batch ID collision detected -- all batch IDs must be unique"
        );
    }
    assert_eq!(ids.len(), 50);
}

#[test]
fn test_809_merkle_root_is_some_after_seal() {
    let mut batch = Batch::new().unwrap();
    assert!(
        batch.merkle_root().is_none(),
        "merkle_root should be None before seal"
    );

    for i in 0..MIN_BATCH_SIZE {
        batch
            .add_settlement(&make_settlement_unique(i as u32))
            .unwrap();
    }

    batch.seal().unwrap();
    assert!(
        batch.merkle_root().is_some(),
        "merkle_root must be Some after seal"
    );
    assert_ne!(
        *batch.merkle_root().unwrap(),
        [0u8; 32],
        "merkle_root should not be all zeros"
    );
}

#[test]
fn test_810_terminal_state_rejects_further_transitions() {
    let mut batch = Batch::new().unwrap();
    for i in 0..MIN_BATCH_SIZE {
        batch
            .add_settlement(&make_settlement_unique(i as u32))
            .unwrap();
    }
    batch.seal().unwrap();
    batch.mark_submitted("txid".to_string()).unwrap();
    batch.mark_confirmed(800_000).unwrap();
    batch.mark_finalized().unwrap();

    assert!(batch.state().is_terminal());

    // All transitions from Finalized should fail
    assert!(batch.mark_submitted("txid2".to_string()).is_err());
    assert!(batch.mark_confirmed(900_000).is_err());
    assert!(batch.mark_finalized().is_err());
}

#[test]
fn test_811_total_amount_and_fee_accumulate_correctly() {
    let mut batch = Batch::new().unwrap();

    let amounts = [10_000u64, 20_000, 50_000, 100_000, 200_000];
    let mut expected_total_amount = 0u64;

    for (i, &amount) in amounts.iter().enumerate() {
        let settlement = Settlement::new(
            format!("ghost1_user_{}", i),
            [i as u8; 32],
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            amount,
        )
        .unwrap();

        expected_total_amount += settlement.amount_sats();
        assert_eq!(settlement.fee_sats(), 0);

        batch.add_settlement(&settlement).unwrap();
    }

    assert_eq!(batch.total_amount_sats(), expected_total_amount);
    assert_eq!(batch.total_fee_sats(), 0);
    assert_eq!(batch.settlement_count(), amounts.len());
}

// =============================================================================
// MERKLE TREE (Tests 812-817)
// =============================================================================

#[test]
fn test_812_compute_merkle_root_is_deterministic() {
    let leaves: Vec<[u8; 32]> = (0..8).map(|i| [i; 32]).collect();

    let root1 = compute_merkle_root(&leaves);
    let root2 = compute_merkle_root(&leaves);

    assert_eq!(
        root1, root2,
        "Same leaves must produce the same merkle root"
    );
    assert_ne!(root1, [0u8; 32], "Root should not be all zeros");
}

#[test]
fn test_813_merkle_proof_roundtrip_all_positions() {
    let leaves: Vec<[u8; 32]> = (0..16).map(|i| [i; 32]).collect();
    let root = compute_merkle_root(&leaves);

    for (i, leaf) in leaves.iter().enumerate() {
        let proof = compute_merkle_proof(&leaves, i);
        assert!(
            verify_merkle_proof(leaf, &proof, &root, i, leaves.len()),
            "Merkle proof must verify for leaf at position {}",
            i
        );
    }

    // Also test odd-sized tree
    let odd_leaves: Vec<[u8; 32]> = (0..11).map(|i| [i; 32]).collect();
    let odd_root = compute_merkle_root(&odd_leaves);

    for (i, leaf) in odd_leaves.iter().enumerate() {
        let proof = compute_merkle_proof(&odd_leaves, i);
        assert!(
            verify_merkle_proof(leaf, &proof, &odd_root, i, odd_leaves.len()),
            "Merkle proof must verify for odd-tree leaf at position {}",
            i
        );
    }
}

#[test]
fn test_814_different_leaf_sets_produce_different_roots() {
    let leaves_a: Vec<[u8; 32]> = (0..4).map(|i| [i; 32]).collect();
    let leaves_b: Vec<[u8; 32]> = (10..14).map(|i| [i; 32]).collect();

    let root_a = compute_merkle_root(&leaves_a);
    let root_b = compute_merkle_root(&leaves_b);

    assert_ne!(
        root_a, root_b,
        "Different leaf sets must produce different roots"
    );

    // Also different lengths with overlapping prefixes must differ
    let leaves_c: Vec<[u8; 32]> = (0..3).map(|i| [i; 32]).collect();
    let root_c = compute_merkle_root(&leaves_c);
    assert_ne!(
        root_a, root_c,
        "Different-length leaf sets must produce different roots"
    );
}

#[test]
fn test_815_single_leaf_produces_valid_proof() {
    let leaf = [0xFFu8; 32];
    let leaves = vec![leaf];
    let root = compute_merkle_root(&leaves);

    // Root should not be the raw leaf -- it includes domain separation
    assert_ne!(
        root, leaf,
        "Single-leaf root must be hashed with domain separator"
    );

    let proof = compute_merkle_proof(&leaves, 0);
    assert!(
        verify_merkle_proof(&leaf, &proof, &root, 0, 1),
        "Single-leaf proof must verify"
    );
}

#[test]
fn test_816_empty_leaves_produce_deterministic_root() {
    let root1 = compute_merkle_root(&[]);
    let root2 = compute_merkle_root(&[]);

    assert_eq!(root1, root2, "Empty merkle root must be deterministic");
    assert_ne!(
        root1, [0u8; 32],
        "Empty root uses domain separation, not raw zeros"
    );

    // Empty root must differ from single-leaf root
    let single_root = compute_merkle_root(&[[0u8; 32]]);
    assert_ne!(
        root1, single_root,
        "Empty root and single-leaf root must differ"
    );
}

#[test]
fn test_817_two_leaves_both_proofs_verify() {
    let leaf_a = [0xAAu8; 32];
    let leaf_b = [0xBBu8; 32];
    let leaves = vec![leaf_a, leaf_b];
    let root = compute_merkle_root(&leaves);

    // Proof for leaf at index 0
    let proof_0 = compute_merkle_proof(&leaves, 0);
    assert!(
        verify_merkle_proof(&leaf_a, &proof_0, &root, 0, 2),
        "Proof for first of two leaves must verify"
    );

    // Proof for leaf at index 1
    let proof_1 = compute_merkle_proof(&leaves, 1);
    assert!(
        verify_merkle_proof(&leaf_b, &proof_1, &root, 1, 2),
        "Proof for second of two leaves must verify"
    );

    // Cross-verification must fail
    assert!(
        !verify_merkle_proof(&leaf_a, &proof_1, &root, 1, 2),
        "Wrong leaf with correct proof must not verify"
    );
    assert!(
        !verify_merkle_proof(&leaf_b, &proof_0, &root, 0, 2),
        "Wrong leaf with correct proof must not verify"
    );
}

// =============================================================================
// GLOBAL INPUT RESERVATIONS (Tests 818-819)
// =============================================================================

#[test]
fn test_818_reserve_batch_then_is_reserved_returns_true() {
    let reservations = GlobalInputReservations::new();
    let current_time = 1_700_000_000u64;

    let outpoint1 = OutPoint {
        txid: dummy_txid(),
        vout: 0,
    };
    let outpoint2 = OutPoint {
        txid: dummy_txid(),
        vout: 1,
    };

    // Initially nothing is reserved
    assert!(!reservations.is_reserved(&outpoint1));
    assert!(!reservations.is_reserved(&outpoint2));
    assert_eq!(reservations.count(), 0);

    // Reserve a batch with two outpoints
    reservations
        .reserve_batch("batch_abc", &[outpoint1, outpoint2], current_time)
        .unwrap();

    assert!(reservations.is_reserved(&outpoint1));
    assert!(reservations.is_reserved(&outpoint2));
    assert_eq!(reservations.count(), 2);

    // A different outpoint should not be reserved
    let outpoint3 = OutPoint {
        txid: dummy_txid(),
        vout: 99,
    };
    assert!(!reservations.is_reserved(&outpoint3));
}

#[test]
fn test_819_release_batch_then_is_reserved_returns_false() {
    let reservations = GlobalInputReservations::new();
    let current_time = 1_700_000_000u64;

    let outpoint1 = OutPoint {
        txid: dummy_txid(),
        vout: 0,
    };
    let outpoint2 = OutPoint {
        txid: dummy_txid(),
        vout: 1,
    };

    // Reserve and verify
    reservations
        .reserve_batch("batch_xyz", &[outpoint1, outpoint2], current_time)
        .unwrap();
    assert_eq!(reservations.count(), 2);
    assert!(reservations.is_reserved(&outpoint1));
    assert!(reservations.is_reserved(&outpoint2));

    // Release the batch
    let released = reservations.release_batch("batch_xyz");
    assert_eq!(released, 2);

    // Outpoints should no longer be reserved
    assert!(!reservations.is_reserved(&outpoint1));
    assert!(!reservations.is_reserved(&outpoint2));
    assert_eq!(reservations.count(), 0);

    // Releasing an already-released batch is a no-op
    let released_again = reservations.release_batch("batch_xyz");
    assert_eq!(released_again, 0);
}
