//! Category 24: Cross-Layer L2 Verification Tests (20 tests, 850-869)
//!
//! Tests verifying correct integration across the three L2 subsystems:
//! - wraith-protocol (mixing denominations, phases)
//! - ghost-locks (lock denominations, state machine, timelocks)
//! - ghost-reconciliation (settlements, batches, merkle proofs)
//!
//! These tests ensure denomination alignment, state machine transitions
//! across layer boundaries, and end-to-end settlement correctness.

use bitcoin::secp256k1::{Secp256k1, SecretKey};
use rand::RngCore;

// wraith-protocol imports
use wraith_protocol::{Phase, WraithDenomination};

// ghost-locks imports (aliased to avoid collision with WraithDenomination)
use ghost_locks::{
    optimal_denominations, Denomination, GhostLock, LockState, StateTransition, TimelockTier,
    MIN_LOCK_SATS,
};

// ghost-reconciliation imports
use ghost_reconciliation::{
    verify_merkle_proof, Batch, Settlement, DISPUTE_WINDOW_BLOCKS, MIN_BATCH_SIZE,
    MIN_SETTLEMENT_SATS,
};

/// Generate a random secp256k1 secret key using OsRng.
fn generate_secret_key() -> SecretKey {
    let mut secret_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
    SecretKey::from_slice(&secret_bytes).expect("32 bytes, within curve order")
}

/// Create a GhostLock with the given denomination at height 800_000.
fn create_lock(denomination: Denomination) -> GhostLock {
    let secp = Secp256k1::new();
    GhostLock::new(
        &secp,
        &generate_secret_key(),
        &generate_secret_key(),
        denomination,
        TimelockTier::Standard,
        800_000,
    )
    .expect("lock creation should succeed")
}

/// Create a Settlement from a lock's ID and denomination sats.
fn create_settlement_from_lock(lock: &GhostLock) -> Settlement {
    Settlement::new(
        "ghost1abc".to_string(),
        *lock.lock_id(),
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        lock.sats(),
    )
    .expect("settlement creation should succeed")
}

// =============================================================================
// WRAITH -> GHOST LOCK TESTS (850-854)
// =============================================================================

#[test]
fn test_850_wraith_small_matches_ghost_locks_small() {
    // WraithDenomination::Small and Denomination::Small must agree on 1_000_000 sats
    assert_eq!(WraithDenomination::Small.output_sats(), 1_000_000);
    assert_eq!(Denomination::Small.sats(), 1_000_000);
    assert_eq!(
        WraithDenomination::Small.output_sats(),
        Denomination::Small.sats(),
        "Cross-layer denomination mismatch: wraith Small != ghost-locks Small"
    );
}

#[test]
fn test_851_phase_split_outputs_for_participants() {
    // Phase::Split produces 10 * N outputs (one input splits into 10 intermediates)
    assert_eq!(Phase::Split.outputs_for_participants(5), 50);
    assert_eq!(Phase::Split.outputs_for_participants(1), 10);
    assert_eq!(Phase::Split.outputs_for_participants(100), 1000);
}

#[test]
fn test_852_lock_enters_and_exits_mix_lifecycle() {
    // Simulate a lock going through Wraith mix: Active -> InMix -> Active
    let mut lock = create_lock(Denomination::Small);
    assert_eq!(lock.state(), LockState::Active);

    // Enter mix (Phase 1 starts)
    lock.transition(StateTransition::EnterMix)
        .expect("Active -> InMix should succeed");
    assert_eq!(lock.state(), LockState::InMix);

    // Exit mix (Phase 2 completes)
    lock.transition(StateTransition::ExitMix)
        .expect("InMix -> Active should succeed");
    assert_eq!(lock.state(), LockState::Active);
}

#[test]
fn test_853_all_wraith_intermediates_above_dust() {
    // Every wraith denomination's intermediate_sats() must exceed MIN_LOCK_SATS (546)
    // Use largest OPP (10) which produces the smallest intermediates — worst case for dust
    for denom in WraithDenomination::all() {
        let intermediate = denom.intermediate_sats(10);
        assert!(
            intermediate > MIN_LOCK_SATS,
            "WraithDenomination::{} intermediate_sats ({}) must exceed dust threshold ({})",
            denom.name(),
            intermediate,
            MIN_LOCK_SATS
        );
    }
}

#[test]
fn test_854_denomination_mapping_wraith_to_ghost_locks() {
    // Each WraithDenomination has a corresponding ghost-locks Denomination with equal sats
    let mapping: Vec<(WraithDenomination, Denomination)> = vec![
        (WraithDenomination::Micro, Denomination::Tiny),
        (WraithDenomination::Small, Denomination::Small),
        (WraithDenomination::Medium, Denomination::Medium),
        (WraithDenomination::Large, Denomination::Large),
    ];

    for (wraith_denom, lock_denom) in &mapping {
        assert_eq!(
            wraith_denom.output_sats(),
            lock_denom.sats(),
            "Mismatch: Wraith {} ({}) != GhostLock {} ({})",
            wraith_denom.name(),
            wraith_denom.output_sats(),
            lock_denom.name(),
            lock_denom.sats()
        );
    }
}

// =============================================================================
// GHOST LOCK -> SETTLEMENT TESTS (855-859)
// =============================================================================

#[test]
fn test_855_all_lock_denominations_above_min_settlement() {
    // Every ghost-locks Denomination's sats() must be >= MIN_SETTLEMENT_SATS (10_000)
    for denom in Denomination::all() {
        assert!(
            denom.sats() >= MIN_SETTLEMENT_SATS,
            "Denomination::{} ({} sats) is below MIN_SETTLEMENT_SATS ({})",
            denom.name(),
            denom.sats(),
            MIN_SETTLEMENT_SATS
        );
    }
}

#[test]
fn test_856_settlement_from_lock_id() {
    // Create a GhostLock and use its lock_id as the settlement source_lock_id
    let lock = create_lock(Denomination::Small);
    let settlement = Settlement::new(
        "ghost1test".to_string(),
        *lock.lock_id(),
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        lock.sats(),
    )
    .expect("settlement creation should succeed");

    assert_eq!(settlement.source_lock_id(), lock.lock_id());
    assert_eq!(settlement.amount_sats(), lock.sats());
}

#[test]
fn test_857_settlement_net_amount_equals_amount() {
    // Protocol fee removed — net_amount == amount for all denominations
    let denominations = [
        Denomination::Micro,
        Denomination::Small,
        Denomination::Medium,
        Denomination::Large,
    ];

    for denom in &denominations {
        let lock = create_lock(*denom);
        let settlement = create_settlement_from_lock(&lock);

        assert_eq!(
            settlement.fee_sats(),
            0,
            "Fee should be 0 for Denomination::{}",
            denom.name()
        );
        assert_eq!(
            settlement.net_amount_sats(),
            settlement.amount_sats(),
            "Net amount should equal amount for Denomination::{}",
            denom.name()
        );
    }
}

#[test]
fn test_858_lock_transitions_to_spent_after_settlement() {
    // After initiating a settlement, the lock should transition to Spent
    let mut lock = create_lock(Denomination::Small);
    let _settlement = create_settlement_from_lock(&lock);

    // Lock starts Active, settlement initiated means we spend it
    assert_eq!(lock.state(), LockState::Active);
    lock.transition(StateTransition::SettlementSpend {
        batch_id: [0u8; 32],
    })
    .expect("Active -> Spent should succeed");
    assert_eq!(lock.state(), LockState::Spent);
}

#[test]
fn test_859_multiple_settlements_batch_correctly() {
    // Create MIN_BATCH_SIZE (10) settlements from different locks and batch them
    let mut batch = Batch::new().expect("batch creation should succeed");
    let mut settlements = Vec::new();

    for i in 0..MIN_BATCH_SIZE {
        // Alternate between denominations
        let denom = match i % 4 {
            0 => Denomination::Micro,
            1 => Denomination::Small,
            2 => Denomination::Medium,
            _ => Denomination::Large,
        };
        let lock = create_lock(denom);
        let settlement = create_settlement_from_lock(&lock);
        batch
            .add_settlement(&settlement)
            .expect("adding settlement should succeed");
        settlements.push(settlement);
    }

    assert_eq!(batch.settlement_count(), MIN_BATCH_SIZE);
    assert!(batch.has_minimum());

    // Seal the batch
    batch.seal().expect("sealing should succeed");
    assert!(batch.merkle_root().is_some());
}

// =============================================================================
// FULL LIFECYCLE TESTS (860-864)
// =============================================================================

#[test]
fn test_860_full_state_progression_active_inmix_active_spent() {
    // Full lifecycle: Active -> InMix -> Active -> Spent (via settlement)
    let mut lock = create_lock(Denomination::Medium);

    // Start Active
    assert_eq!(lock.state(), LockState::Active);
    assert!(lock.state().can_spend());

    // Enter Wraith mix
    lock.transition(StateTransition::EnterMix).unwrap();
    assert_eq!(lock.state(), LockState::InMix);
    assert!(!lock.state().can_spend());

    // Exit Wraith mix
    lock.transition(StateTransition::ExitMix).unwrap();
    assert_eq!(lock.state(), LockState::Active);
    assert!(lock.state().can_spend());

    // Spend via settlement
    lock.transition(StateTransition::SettlementSpend {
        batch_id: [0u8; 32],
    })
    .unwrap();
    assert_eq!(lock.state(), LockState::Spent);
    assert!(!lock.state().can_spend());
    assert!(lock.state().is_terminal());
}

#[test]
fn test_861_phase_split_merge_output_consistency() {
    // For N participants: Split produces 10N outputs, Merge consumes 10N inputs and produces N
    for n in [1, 5, 10, 50, 100] {
        let split_outputs = Phase::Split.outputs_for_participants(n);
        let merge_inputs = Phase::Merge.inputs_for_participants(n);
        let merge_outputs = Phase::Merge.outputs_for_participants(n);

        // Split outputs feed into Merge inputs
        assert_eq!(
            split_outputs, merge_inputs,
            "For {} participants: Split outputs ({}) must equal Merge inputs ({})",
            n, split_outputs, merge_inputs
        );

        // Merge produces N final outputs
        assert_eq!(
            merge_outputs, n,
            "Merge should produce exactly {} outputs for {} participants",
            n, n
        );
    }
}

#[test]
fn test_862_batch_merkle_proof_verification() {
    // Create a batch, seal it, and verify merkle proof for each settlement
    let mut batch = Batch::new().expect("batch creation should succeed");
    let mut settlements = Vec::new();

    // Create 12 settlements (above MIN_BATCH_SIZE)
    for _ in 0..12 {
        let lock = create_lock(Denomination::Small);
        let settlement = create_settlement_from_lock(&lock);
        batch.add_settlement(&settlement).unwrap();
        settlements.push(settlement);
    }

    batch.seal().expect("seal should succeed");
    let root = batch.merkle_root().expect("merkle root should exist");

    // Verify proof for each settlement
    for settlement in &settlements {
        let hash = settlement.hash();
        let (proof, index, leaf_count) = batch
            .get_merkle_proof(&hash)
            .expect("proof should exist for each settlement");

        assert!(
            verify_merkle_proof(&hash, &proof, root, index, leaf_count),
            "Merkle proof verification failed for settlement {}",
            settlement.id_hex()
        );
    }
}

#[test]
fn test_863_batch_mixed_denomination_settlements() {
    // Batch settlements from Micro, Small, Medium, Large locks together
    let denominations = [
        Denomination::Micro,
        Denomination::Small,
        Denomination::Medium,
        Denomination::Large,
    ];

    let mut batch = Batch::new().expect("batch creation should succeed");
    let mut total_amount = 0u64;

    // Create at least MIN_BATCH_SIZE settlements, cycling through denominations
    for i in 0..12 {
        let denom = denominations[i % denominations.len()];
        let lock = create_lock(denom);
        let settlement = create_settlement_from_lock(&lock);
        total_amount += settlement.amount_sats();
        batch.add_settlement(&settlement).unwrap();
    }

    assert_eq!(batch.settlement_count(), 12);
    assert_eq!(batch.total_amount_sats(), total_amount);
    assert_eq!(batch.total_fee_sats(), 0);

    batch.seal().expect("seal should succeed");
    assert!(batch.merkle_root().is_some());
}

#[test]
fn test_864_optimal_denominations_create_valid_locks() {
    // optimal_denominations() output should create valid GhostLocks
    let amount = 111_100_000u64; // 1.111 BTC
    let breakdown = optimal_denominations(amount);

    // Should have at least one entry
    assert!(!breakdown.is_empty());

    // Verify total sats match (within remainder)
    let total: u64 = breakdown.iter().map(|(d, count)| d.sats() * count).sum();
    assert!(
        total <= amount,
        "Breakdown total {} exceeds input amount {}",
        total,
        amount
    );

    // Create a valid lock for each denomination in the breakdown
    let secp = Secp256k1::new();
    for (denom, count) in &breakdown {
        assert!(*count > 0);
        let lock = GhostLock::new(
            &secp,
            &generate_secret_key(),
            &generate_secret_key(),
            *denom,
            TimelockTier::Standard,
            800_000,
        )
        .expect("lock creation should succeed for optimal denomination");
        assert_eq!(lock.denomination(), *denom);
        assert_eq!(lock.sats(), denom.sats());
        assert_eq!(lock.state(), LockState::Active);
    }
}

// =============================================================================
// EDGE CASE TESTS (865-869)
// =============================================================================

#[test]
fn test_865_micro_intermediate_above_dust() {
    // WraithDenomination::Micro has the smallest intermediate at worst-case OPP=10
    // 100,000 / 10 = 10,000 sats — well above dust threshold (546 sats)
    let intermediate = WraithDenomination::Micro.intermediate_sats(10);
    assert_eq!(intermediate, 10_000);
    assert!(
        intermediate > MIN_LOCK_SATS,
        "Micro intermediate ({}) must exceed dust threshold ({})",
        intermediate,
        MIN_LOCK_SATS
    );
}

#[test]
fn test_866_all_denominations_fee_free() {
    // Protocol fee removed — all denominations should have fee_sats == 0
    let denominations = [
        Denomination::Micro,
        Denomination::Tiny,
        Denomination::Small,
        Denomination::Medium,
        Denomination::Large,
        Denomination::XL,
    ];

    for denom in &denominations {
        let lock = create_lock(*denom);
        let settlement = create_settlement_from_lock(&lock);

        assert_eq!(
            settlement.fee_sats(),
            0,
            "Fee should be 0 for Denomination::{} (protocol fee removed)",
            denom.name()
        );
        assert_eq!(
            settlement.net_amount_sats(),
            settlement.amount_sats(),
            "Net amount should equal amount for Denomination::{}",
            denom.name()
        );
    }
}

#[test]
fn test_867_frozen_lock_cannot_settle() {
    // A Frozen lock cannot be spent (and therefore cannot settle)
    let mut lock = create_lock(Denomination::Small);

    // Freeze the lock
    lock.transition(StateTransition::Freeze)
        .expect("Active -> Frozen should succeed");
    assert_eq!(lock.state(), LockState::Frozen);
    assert!(
        !lock.state().can_spend(),
        "Frozen lock must not be spendable"
    );

    // Attempting to spend a frozen lock should fail
    let result = lock.transition(StateTransition::SettlementSpend {
        batch_id: [0u8; 32],
    });
    assert!(
        result.is_err(),
        "Spending a frozen lock should fail with InvalidStateTransition"
    );
}

#[test]
fn test_868_inmix_lock_cannot_settle() {
    // A lock in InMix state cannot be spent (settlement blocked during mix)
    let mut lock = create_lock(Denomination::Medium);

    lock.transition(StateTransition::EnterMix)
        .expect("Active -> InMix should succeed");
    assert_eq!(lock.state(), LockState::InMix);
    assert!(
        !lock.state().can_spend(),
        "InMix lock must not be spendable"
    );

    // Attempting to spend an InMix lock should fail
    let result = lock.transition(StateTransition::SettlementSpend {
        batch_id: [0u8; 32],
    });
    assert!(
        result.is_err(),
        "Spending an InMix lock should fail with InvalidStateTransition"
    );
}

#[test]
fn test_869_recovery_height_exceeds_dispute_window() {
    // For all timelock tiers, recovery_height - creation_height >> DISPUTE_WINDOW_BLOCKS (144)
    // This ensures locks are held long enough that settlement disputes resolve before recovery
    let creation_height = 800_000u32;

    for tier in TimelockTier::all() {
        let lock_secret = generate_secret_key();
        let recovery_secret = generate_secret_key();
        let secp = Secp256k1::new();
        let lock = GhostLock::new(
            &secp,
            &lock_secret,
            &recovery_secret,
            Denomination::Small,
            *tier,
            creation_height,
        )
        .expect("lock creation should succeed");

        let recovery_blocks = lock.recovery_height() - creation_height;
        assert!(
            recovery_blocks > DISPUTE_WINDOW_BLOCKS,
            "Tier {:?} recovery ({} blocks) must exceed DISPUTE_WINDOW_BLOCKS ({})",
            tier,
            recovery_blocks,
            DISPUTE_WINDOW_BLOCKS
        );

        // Safety margin: recovery should be at least 10x the dispute window
        assert!(
            recovery_blocks >= DISPUTE_WINDOW_BLOCKS * 10,
            "Tier {:?} recovery ({} blocks) should be at least 10x DISPUTE_WINDOW_BLOCKS ({}) for safety",
            tier,
            recovery_blocks,
            DISPUTE_WINDOW_BLOCKS * 10
        );
    }
}
