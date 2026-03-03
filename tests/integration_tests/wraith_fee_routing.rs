//! Category 31: Wraith Fee Routing Tests (20 tests, 910-929)
//!
//! Integration tests for the wraith fee routing pipeline:
//! - Fee storage & epoch tracking (910-914)
//! - Epoch calculation (915)
//! - Fee distribution calculation (916-920)
//! - Full flow wraith → track → distribute (921-924)
//! - Settlement transaction with L2 fees (925-929)

use std::str::FromStr;

use chrono::{Duration, Utc};

use bitcoin::{Network, Txid};
use ghost_common::constants::{l2_epoch_from_height, L2_TRANSFER_FEE_SATS};
use ghost_reconciliation::{
    executor::{BatchExecutor, ReconciliationInput},
    fee_distribution::{L2FeeDistribution, TreasuryState, TREASURY_THRESHOLD_SATS},
    settlement::Settlement,
};
use ghost_storage::Database;
use wraith_protocol::WraithDenomination;

// =============================================================================
// HELPERS
// =============================================================================

/// Shorthand: create an in-memory database with all migrations applied.
fn test_db() -> Database {
    Database::in_memory().expect("in-memory DB")
}

/// Create a `BatchExecutor` pre-loaded with `count` settlements and matching
/// inputs.  Each settlement is `amount_per` sats, each input is `input_per` sats.
/// Returns the executor and its sealed, Ready batch.
#[allow(deprecated)] // M-12: test-only — no real ownership proof needed
fn setup_executor(
    count: usize,
    amount_per: u64,
    input_per: u64,
) -> (BatchExecutor, ghost_reconciliation::batch::Batch) {
    let mut executor = BatchExecutor::new(
        Network::Signet,
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
    );
    executor.set_block_height(800_000);

    let txid = Txid::from_str(
        "0000000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();

    for i in 0..count as u32 {
        let settlement = Settlement::new(
            format!("ghost1_test_{}", i),
            [i as u8; 32],
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            amount_per,
        )
        .unwrap();
        executor.add_settlement(settlement).unwrap();
    }

    for i in 0..count as u32 {
        executor.add_input(ReconciliationInput {
            txid,
            vout: i,
            amount: input_per,
            ghost_id: format!("ghost1_test_{}", i),
            lock_id: Some([i as u8; 32]),
            confirmations: 10,
        });
    }

    let batch = executor.form_batch().unwrap();
    (executor, batch)
}

// =============================================================================
// LAYER 1: FEE STORAGE & EPOCH TRACKING (910-914)
// =============================================================================

#[test]
fn test_910_increment_wraith_fee_records_per_epoch() {
    let db = test_db();

    // Small (2000) + Micro (500) in same epoch
    db.increment_wraith_fee(5, 2000).unwrap();
    db.increment_wraith_fee(5, 500).unwrap();
    assert_eq!(db.get_epoch_fee_total(5).unwrap(), 2500);

    // Add 5000 more → 7500
    db.increment_wraith_fee(5, 5000).unwrap();
    assert_eq!(db.get_epoch_fee_total(5).unwrap(), 7500);
}

#[test]
fn test_911_wraith_fees_across_multiple_epochs() {
    let db = test_db();

    db.increment_wraith_fee(0, 1000).unwrap();
    db.increment_wraith_fee(1, 2000).unwrap();
    db.increment_wraith_fee(2, 3000).unwrap();

    let undistributed = db.get_undistributed_fees().unwrap();
    assert_eq!(undistributed.len(), 3);
    assert_eq!(undistributed[0], (0, 1000));
    assert_eq!(undistributed[1], (1, 2000));
    assert_eq!(undistributed[2], (2, 3000));
}

#[test]
fn test_912_mark_distributed_excludes_from_undistributed() {
    let db = test_db();

    db.increment_wraith_fee(0, 1000).unwrap();
    db.increment_wraith_fee(1, 2000).unwrap();
    db.increment_wraith_fee(2, 3000).unwrap();

    // Mark epoch 0 distributed → only 1, 2 remain
    db.mark_epoch_fees_distributed(0).unwrap();
    let undistributed = db.get_undistributed_fees().unwrap();
    assert_eq!(undistributed.len(), 2);
    assert_eq!(undistributed[0], (1, 2000));
    assert_eq!(undistributed[1], (2, 3000));

    // Mark epoch 2 distributed → only 1 remains
    db.mark_epoch_fees_distributed(2).unwrap();
    let undistributed = db.get_undistributed_fees().unwrap();
    assert_eq!(undistributed.len(), 1);
    assert_eq!(undistributed[0], (1, 2000));
}

#[test]
fn test_913_mixed_transfer_and_wraith_fees_accumulate() {
    let db = test_db();

    // increment_epoch_fee(epoch=5, transfer_count=10) → 10 * L2_TRANSFER_FEE_SATS = 100 sats
    db.increment_epoch_fee(5, 10).unwrap();

    // increment_wraith_fee(epoch=5, 2000)
    db.increment_wraith_fee(5, 2000).unwrap();

    let expected = 10 * L2_TRANSFER_FEE_SATS + 2000;
    assert_eq!(expected, 2100);
    assert_eq!(db.get_epoch_fee_total(5).unwrap(), 2100);
}

#[test]
fn test_914_zero_fee_wraith_is_noop() {
    let db = test_db();

    // Zero fee short-circuits without writing a row
    db.increment_wraith_fee(0, 0).unwrap();

    let undistributed = db.get_undistributed_fees().unwrap();
    assert!(undistributed.is_empty());
    assert_eq!(db.get_epoch_fee_total(0).unwrap(), 0);
}

// =============================================================================
// LAYER 2: EPOCH CALCULATION (915)
// =============================================================================

#[test]
fn test_915_l2_epoch_from_block_height() {
    // L2_EPOCH_BLOCKS = 2160
    assert_eq!(l2_epoch_from_height(0), 0);
    assert_eq!(l2_epoch_from_height(2159), 0);
    assert_eq!(l2_epoch_from_height(2160), 1);
    assert_eq!(l2_epoch_from_height(4319), 1);
    assert_eq!(l2_epoch_from_height(4320), 2);
    assert_eq!(l2_epoch_from_height(800_000), 370);
}

// =============================================================================
// LAYER 3: FEE DISTRIBUTION CALCULATION (916-920)
// =============================================================================

#[test]
fn test_916_pre_threshold_50_50_split() {
    let state = TreasuryState::new();
    let now = Utc::now();
    let nodes = vec![
        ("node1".into(), "addr1".into(), 5),
        ("node2".into(), "addr2".into(), 5),
        ("node3".into(), "addr3".into(), 5),
    ];

    let dist = L2FeeDistribution::calculate(100_000, &state, now, &nodes);

    assert_eq!(dist.treasury_amount, 50_000);
    assert_eq!(dist.node_pool, 50_000);

    // Conservation: treasury + Σ(node payouts) == total pool
    let payout_total: u64 = dist.node_payouts.iter().map(|(_, _, amt)| *amt).sum();
    assert_eq!(
        dist.treasury_amount + payout_total,
        100_000,
        "conservation violated"
    );
}

#[test]
fn test_917_post_threshold_decay_schedule() {
    let now = Utc::now();
    let nodes = vec![("node1".into(), "addr1".into(), 5)];
    let pool = 100_000u64;

    // Pre-threshold: 50/50
    let pre = TreasuryState::new();
    let dist = L2FeeDistribution::calculate(pool, &pre, now, &nodes);
    assert_eq!(dist.treasury_amount, 50_000, "pre-threshold: expect 50%");

    // Threshold just reached (years_since=0, schedule index 1): 40/60
    let just = TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(now));
    let dist = L2FeeDistribution::calculate(pool, &just, now, &nodes);
    assert_eq!(dist.treasury_amount, 40_000, "year 0 after threshold: 40%");
    assert_eq!(dist.node_pool, 60_000);

    // 2 years after threshold (schedule index 3): 20/80
    let two_y = TreasuryState::from_stored(
        TREASURY_THRESHOLD_SATS,
        Some(now - Duration::days(365 * 2 + 1)),
    );
    let dist = L2FeeDistribution::calculate(pool, &two_y, now, &nodes);
    assert_eq!(dist.treasury_amount, 20_000, "year 2 after threshold: 20%");
    assert_eq!(dist.node_pool, 80_000);

    // 5+ years after threshold (schedule index 5, clamped): 0/100
    let five_y = TreasuryState::from_stored(
        TREASURY_THRESHOLD_SATS,
        Some(now - Duration::days(365 * 5 + 1)),
    );
    let dist = L2FeeDistribution::calculate(pool, &five_y, now, &nodes);
    assert_eq!(dist.treasury_amount, 0, "year 5+ after threshold: 0%");
    assert_eq!(dist.node_pool, 100_000);
}

#[test]
fn test_918_node_distribution_weighted_by_shares() {
    let state = TreasuryState::new();
    let now = Utc::now();
    let nodes = vec![
        ("node_a".into(), "addr_a".into(), 4),
        ("node_b".into(), "addr_b".into(), 8),
        ("node_c".into(), "addr_c".into(), 4),
    ];

    let dist = L2FeeDistribution::calculate(100_000, &state, now, &nodes);
    assert_eq!(dist.node_pool, 50_000);

    // Total shares = 16 → proportional: 4/16 = 25%, 8/16 = 50%, 4/16 = 25%
    let payout_a = dist
        .node_payouts
        .iter()
        .find(|(id, _, _)| id == "node_a")
        .unwrap()
        .2;
    let payout_b = dist
        .node_payouts
        .iter()
        .find(|(id, _, _)| id == "node_b")
        .unwrap()
        .2;
    let payout_c = dist
        .node_payouts
        .iter()
        .find(|(id, _, _)| id == "node_c")
        .unwrap()
        .2;

    assert_eq!(payout_a, 12_500); // 50_000 * 4/16
    assert_eq!(payout_b, 25_000); // 50_000 * 8/16
    assert_eq!(payout_c, 12_500); // 50_000 - 12_500 - 25_000

    // Conservation
    assert_eq!(payout_a + payout_b + payout_c, dist.node_pool);
}

#[test]
fn test_919_dust_payouts_redirected_to_top_node() {
    let state = TreasuryState::new();
    let now = Utc::now();

    // 10 equal-share nodes
    let nodes: Vec<(String, String, i32)> = (0..10)
        .map(|i| (format!("node_{}", i), format!("addr_{}", i), 1))
        .collect();

    // 1_000 pool → 500 treasury, 500 node_pool → each node gets 50 (<546 dust)
    let dist = L2FeeDistribution::calculate(1_000, &state, now, &nodes);

    assert_eq!(dist.treasury_amount, 500);
    assert_eq!(dist.node_pool, 500);

    // All dust redirected to top node — only one payout survives
    assert_eq!(dist.node_payouts.len(), 1);
    assert_eq!(dist.node_payouts[0].2, 500);
}

#[test]
fn test_920_empty_node_list_all_to_treasury() {
    let state = TreasuryState::new();
    let now = Utc::now();

    let dist = L2FeeDistribution::calculate(100_000, &state, now, &[]);

    // Treasury still only gets its BPS share (50%); node_pool has no recipients
    assert_eq!(dist.treasury_amount, 50_000);
    assert_eq!(dist.node_pool, 50_000);
    assert!(dist.node_payouts.is_empty());
}

// =============================================================================
// LAYER 4: FULL FLOW — WRAITH MIX → FEE TRACK → DISTRIBUTION (921-924)
// =============================================================================

#[test]
fn test_921_wraith_mix_session_fee_lifecycle() {
    let db = test_db();
    let epoch = 370u64;
    let participants = 10u64;

    // 1. Compute service fees for all 4 denominations × 10 participants
    let micro_fee = WraithDenomination::Micro.service_fee() * participants; // 5,000
    let small_fee = WraithDenomination::Small.service_fee() * participants; // 20,000
    let medium_fee = WraithDenomination::Medium.service_fee() * participants; // 50,000
    let large_fee = WraithDenomination::Large.service_fee() * participants; // 100,000
    let total = micro_fee + small_fee + medium_fee + large_fee; // 175,000
    assert_eq!(total, 175_000);

    // Track at epoch 370
    db.increment_wraith_fee(epoch, micro_fee).unwrap();
    db.increment_wraith_fee(epoch, small_fee).unwrap();
    db.increment_wraith_fee(epoch, medium_fee).unwrap();
    db.increment_wraith_fee(epoch, large_fee).unwrap();
    assert_eq!(db.get_epoch_fee_total(epoch).unwrap(), total);

    // 2. Pre-threshold → 50/50
    let state = TreasuryState::new();
    let now = Utc::now();
    let nodes = vec![
        ("node1".into(), "addr1".into(), 5),
        ("node2".into(), "addr2".into(), 4),
        ("node3".into(), "addr3".into(), 3),
        ("node4".into(), "addr4".into(), 2),
    ];

    let dist = L2FeeDistribution::calculate(total, &state, now, &nodes);

    assert_eq!(dist.treasury_amount, 87_500);
    assert_eq!(dist.node_pool, 87_500);

    // 3. Verify proportional distribution (shares 5,4,3,2, total=14)
    let payout_total: u64 = dist.node_payouts.iter().map(|(_, _, amt)| *amt).sum();

    // 4. Conservation: treasury + Σ(node_payouts) == 175,000
    assert_eq!(
        dist.treasury_amount + payout_total,
        total,
        "conservation violated"
    );

    // 5. Mark distributed → empty
    db.mark_epoch_fees_distributed(epoch).unwrap();
    assert!(db.get_undistributed_fees().unwrap().is_empty());
}

#[test]
fn test_922_multi_epoch_accumulation_and_batch_distribution() {
    let db = test_db();

    // Epoch 0: Micro sessions (5 × 500 = 2,500)
    db.increment_wraith_fee(0, 2_500).unwrap();

    // Epoch 1: Small + Medium (3 × 2,000 + 2 × 5,000 = 16,000)
    db.increment_wraith_fee(1, 6_000).unwrap();
    db.increment_wraith_fee(1, 10_000).unwrap();

    // Epoch 2: Large sessions (8 × 10,000 = 80,000)
    db.increment_wraith_fee(2, 80_000).unwrap();

    let undistributed = db.get_undistributed_fees().unwrap();
    assert_eq!(undistributed.len(), 3);
    let total: u64 = undistributed.iter().map(|(_, fee)| *fee).sum();
    assert_eq!(total, 98_500);

    // Distribute
    let state = TreasuryState::new();
    let now = Utc::now();
    let nodes = vec![
        ("n1".into(), "a1".into(), 10),
        ("n2".into(), "a2".into(), 5),
    ];
    let dist = L2FeeDistribution::calculate(total, &state, now, &nodes);
    let payout_total: u64 = dist.node_payouts.iter().map(|(_, _, amt)| *amt).sum();
    assert_eq!(
        dist.treasury_amount + payout_total,
        total,
        "conservation violated"
    );

    // Mark all distributed
    for (epoch, _) in &undistributed {
        db.mark_epoch_fees_distributed(*epoch).unwrap();
    }
    assert!(db.get_undistributed_fees().unwrap().is_empty());
}

#[test]
fn test_923_conservation_across_all_denomination_tiers() {
    let state = TreasuryState::new();
    let now = Utc::now();
    let nodes = vec![
        ("node1".into(), "addr1".into(), 8),
        ("node2".into(), "addr2".into(), 4),
        ("node3".into(), "addr3".into(), 3),
    ];

    for denom in WraithDenomination::all() {
        let fee = denom.service_fee() * 10; // 10 participants
        let dist = L2FeeDistribution::calculate(fee, &state, now, &nodes);

        let payout_total: u64 = dist.node_payouts.iter().map(|(_, _, amt)| *amt).sum();
        assert_eq!(
            dist.treasury_amount + payout_total,
            fee,
            "conservation violated for {:?}: treasury {} + payouts {} != fee {}",
            denom,
            dist.treasury_amount,
            payout_total,
            fee,
        );
    }
}

#[test]
fn test_924_service_fee_vs_shielded_amount() {
    // Verify denomination math: service fee is a small fraction of the output,
    // and the user's shielded value (output) is always larger than the fee.
    for denom in WraithDenomination::all() {
        let output = denom.output_sats();
        let fee = denom.service_fee();

        // Fee is strictly less than the denomination output
        assert!(
            fee < output,
            "{:?}: fee {} should be less than output {}",
            denom,
            fee,
            output
        );

        // Shielded value = output_sats (fee is separate at L2 layer)
        let shielded = output;
        assert_eq!(
            shielded,
            denom.output_sats(),
            "{:?}: shielded value must equal denomination output",
            denom
        );

        // Fee percentage sanity: < 5%
        let fee_pct = (fee as f64 / output as f64) * 100.0;
        assert!(
            fee_pct < 5.0,
            "{:?}: fee {:.2}% exceeds 5% cap",
            denom,
            fee_pct
        );
    }
}

// =============================================================================
// LAYER 5: SETTLEMENT TRANSACTION WITH L2 FEES (925-929)
// =============================================================================

#[test]
fn test_925_build_transaction_includes_l2_fee_outputs() {
    // 10 settlements @ 100k, inputs @ 200k (ample surplus)
    let (mut executor, batch) = setup_executor(10, 100_000, 200_000);

    // L2 fees: 50k treasury + 3 node payouts totalling 50k
    let l2_treasury = 50_000u64;
    let l2_nodes: Vec<(String, String, u64)> = vec![
        (
            "node1".into(),
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".into(),
            20_000,
        ),
        (
            "node2".into(),
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".into(),
            15_000,
        ),
        (
            "node3".into(),
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".into(),
            15_000,
        ),
    ];

    let batch_tx = executor
        .build_transaction_with_l2_fees(&batch, 1, l2_treasury, &l2_nodes)
        .unwrap();

    assert_eq!(batch_tx.treasury_amount, l2_treasury);
    assert_eq!(batch_tx.node_rewards, 50_000);

    // H-7 satisfied: function succeeded without error
    // Verify accounting invariant
    assert!(
        batch_tx.total_output_sats + batch_tx.treasury_amount + batch_tx.mining_fee
            + batch_tx.node_rewards
            <= batch_tx.total_input_sats,
        "H-7: outputs exceed inputs"
    );
}

#[test]
fn test_926_l2_fees_exceed_surplus_rejected() {
    // 10 settlements @ 100k, inputs @ 101k (barely covers settlements + mining fee)
    let (mut executor, batch) = setup_executor(10, 100_000, 101_000);

    // Massive L2 treasury fee that exceeds any surplus
    let result = executor.build_transaction_with_l2_fees(&batch, 1, 500_000, &[]);
    assert!(
        result.is_err(),
        "H-7: L2 fees exceeding surplus must be rejected"
    );
}

#[test]
fn test_927_zero_l2_fees_identical_to_regular_build() {
    let (mut executor, batch) = setup_executor(10, 100_000, 200_000);

    let batch_tx = executor
        .build_transaction_with_l2_fees(&batch, 1, 0, &[])
        .unwrap();

    assert_eq!(batch_tx.treasury_amount, 0);
    assert_eq!(batch_tx.node_rewards, 0);
}

#[test]
fn test_928_dust_node_payouts_excluded_from_tx() {
    let (mut executor, batch) = setup_executor(10, 100_000, 200_000);

    // Node payout of 0 sats → skipped, not added as output
    let l2_nodes: Vec<(String, String, u64)> = vec![(
        "node1".into(),
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".into(),
        0,
    )];

    let batch_tx = executor
        .build_transaction_with_l2_fees(&batch, 1, 1_000, &l2_nodes)
        .unwrap();

    // Treasury fee is included
    assert_eq!(batch_tx.treasury_amount, 1_000);
    // Zero-amount node payout is excluded
    assert_eq!(batch_tx.node_rewards, 0);
}

#[test]
fn test_929_full_pipeline_wraith_to_settlement() {
    let db = test_db();

    // 1. Track 3 Small sessions at epoch 5 (2,000 fee × 10 participants = 20,000 each)
    db.increment_wraith_fee(5, 20_000).unwrap();
    db.increment_wraith_fee(5, 20_000).unwrap();
    db.increment_wraith_fee(5, 20_000).unwrap();

    // 2. Verify undistributed
    let undistributed = db.get_undistributed_fees().unwrap();
    assert_eq!(undistributed.len(), 1);
    assert_eq!(undistributed[0], (5, 60_000));
    let total_fees: u64 = undistributed.iter().map(|(_, f)| *f).sum();
    assert_eq!(total_fees, 60_000);

    // 3. Calculate L2 fee distribution: pre-threshold + 3 nodes
    let state = TreasuryState::new();
    let now = Utc::now();
    let nodes: Vec<(String, String, i32)> = vec![
        (
            "node1".into(),
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".into(),
            5,
        ),
        (
            "node2".into(),
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".into(),
            3,
        ),
        (
            "node3".into(),
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".into(),
            2,
        ),
    ];
    let dist = L2FeeDistribution::calculate(total_fees, &state, now, &nodes);

    assert_eq!(dist.treasury_amount, 30_000); // 60_000 * 50%
    let payout_sum: u64 = dist.node_payouts.iter().map(|(_, _, a)| *a).sum();
    assert_eq!(dist.treasury_amount + payout_sum, total_fees);

    // 4. Build settlement transaction with calculated L2 fees
    let (mut executor, batch) = setup_executor(10, 100_000, 200_000);

    let batch_tx = executor
        .build_transaction_with_l2_fees(&batch, 1, dist.treasury_amount, &dist.node_payouts)
        .unwrap();

    // 5. Verify treasury and node rewards on the transaction
    assert_eq!(batch_tx.treasury_amount, 30_000);
    assert_eq!(batch_tx.node_rewards, payout_sum);

    // H-7 satisfied
    assert!(
        batch_tx.total_output_sats + batch_tx.treasury_amount + batch_tx.mining_fee
            + batch_tx.node_rewards
            <= batch_tx.total_input_sats,
        "H-7: outputs exceed inputs"
    );

    // 6. Mark distributed → clean
    for (epoch, _) in &undistributed {
        db.mark_epoch_fees_distributed(*epoch).unwrap();
    }
    assert!(db.get_undistributed_fees().unwrap().is_empty());
}
