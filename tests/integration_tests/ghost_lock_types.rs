//! Category 23: Ghost Lock Types Integration Tests (30 tests, 750-779)
//!
//! Tests for P2WSH Ghost Lock creation, state machine, recovery,
//! jump scheduling, and denomination breakdown logic.
//!
//! Uses real ghost-locks crate types with deterministic secret keys.

use ghost_locks::{
    ghost_lock_id, optimal_denominations, Denomination, GhostLock, GhostLockData, GhostLockError,
    JumpRiskTier, LockState, StateTransition, TimelockTier, MAX_CREATION_HEIGHT,
};

use bitcoin::secp256k1::{Secp256k1, SecretKey};

// =============================================================================
// Helper: deterministic secret keys from byte patterns
// =============================================================================

fn lock_secret() -> SecretKey {
    SecretKey::from_slice(&[1u8; 32]).unwrap()
}

fn recovery_secret() -> SecretKey {
    SecretKey::from_slice(&[2u8; 32]).unwrap()
}

fn alt_lock_secret() -> SecretKey {
    SecretKey::from_slice(&[3u8; 32]).unwrap()
}

fn alt_recovery_secret() -> SecretKey {
    SecretKey::from_slice(&[4u8; 32]).unwrap()
}

const HEIGHT: u32 = 800_000;

// =============================================================================
// LOCK CREATION (Tests 750-755)
// =============================================================================

#[test]
fn test_750_ghost_lock_new_small_standard() {
    let secp = Secp256k1::new();
    let lock = GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Small,
        TimelockTier::Standard,
        HEIGHT,
    )
    .expect("creating a Small/Standard lock must succeed");

    assert_eq!(lock.denomination(), Denomination::Small);
    assert_eq!(lock.sats(), 1_000_000);
    assert_eq!(lock.timelock_tier(), TimelockTier::Standard);
    assert_eq!(lock.creation_height(), HEIGHT);
    assert_eq!(lock.state(), LockState::Active);
}

#[test]
fn test_751_create_lock_all_denominations() {
    let secp = Secp256k1::new();
    let expected: &[(Denomination, u64)] = &[
        (Denomination::Micro, 10_000),
        (Denomination::Tiny, 100_000),
        (Denomination::Small, 1_000_000),
        (Denomination::Medium, 10_000_000),
        (Denomination::Large, 100_000_000),
        (Denomination::XL, 1_000_000_000),
    ];

    for &(denom, expected_sats) in expected {
        let lock = GhostLock::new(
            &secp,
            &lock_secret(),
            &recovery_secret(),
            denom,
            TimelockTier::Standard,
            HEIGHT,
        )
        .unwrap_or_else(|e| panic!("Failed to create {:?} lock: {}", denom, e));

        assert_eq!(
            lock.denomination(),
            denom,
            "denomination mismatch for {:?}",
            denom
        );
        assert_eq!(lock.sats(), expected_sats, "sats mismatch for {:?}", denom);
    }
}

#[test]
fn test_752_script_pubkey_is_p2wsh() {
    let secp = Secp256k1::new();
    let lock = GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Small,
        TimelockTier::Standard,
        HEIGHT,
    )
    .unwrap();

    let spk = lock.script_pubkey();
    let bytes = spk.as_bytes();

    // P2WSH: OP_0 (0x00) + PUSH32 (0x20) + 32-byte hash = 34 bytes
    assert_eq!(
        bytes.len(),
        34,
        "P2WSH scriptPubKey must be exactly 34 bytes"
    );
    assert_eq!(bytes[0], 0x00, "first byte must be OP_0");
    assert_eq!(bytes[1], 0x20, "second byte must be PUSH32");
}

#[test]
fn test_753_witness_script_differs_from_script_pubkey() {
    let secp = Secp256k1::new();
    let lock = GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Small,
        TimelockTier::Standard,
        HEIGHT,
    )
    .unwrap();

    let ws = lock.witness_script();
    let spk = lock.script_pubkey();

    assert!(!ws.is_empty(), "witness_script must be non-empty");
    assert_ne!(
        ws.as_bytes(),
        spk.as_bytes(),
        "witness_script and script_pubkey must differ"
    );
}

#[test]
fn test_754_same_keys_same_params_deterministic_lock_id() {
    let secp = Secp256k1::new();

    let lock_a = GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Medium,
        TimelockTier::Short,
        HEIGHT,
    )
    .unwrap();

    let lock_b = GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Medium,
        TimelockTier::Short,
        HEIGHT,
    )
    .unwrap();

    assert_eq!(
        lock_a.lock_id(),
        lock_b.lock_id(),
        "identical parameters must produce identical lock_id"
    );
}

#[test]
fn test_755_different_keys_different_lock_id() {
    let secp = Secp256k1::new();

    let lock_a = GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Small,
        TimelockTier::Standard,
        HEIGHT,
    )
    .unwrap();

    let lock_b = GhostLock::new(
        &secp,
        &alt_lock_secret(),
        &alt_recovery_secret(),
        Denomination::Small,
        TimelockTier::Standard,
        HEIGHT,
    )
    .unwrap();

    assert_ne!(
        lock_a.lock_id(),
        lock_b.lock_id(),
        "different keys must produce different lock_id"
    );
}

// =============================================================================
// LOCK VALIDATION (Tests 756-759)
// =============================================================================

#[test]
fn test_756_same_secret_for_both_keys_rejected() {
    let secp = Secp256k1::new();
    let secret = lock_secret();

    let result = GhostLock::new(
        &secp,
        &secret,
        &secret, // same secret for lock and recovery
        Denomination::Small,
        TimelockTier::Standard,
        HEIGHT,
    );

    assert!(result.is_err(), "using same secret for both keys must fail");
    assert!(
        matches!(result.unwrap_err(), GhostLockError::InvalidKey(_)),
        "error must be InvalidKey"
    );
}

#[test]
fn test_757_creation_height_exceeds_max_rejected() {
    let secp = Secp256k1::new();

    let result = GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Small,
        TimelockTier::Standard,
        MAX_CREATION_HEIGHT + 1,
    );

    assert!(
        result.is_err(),
        "creation height above MAX_CREATION_HEIGHT must fail"
    );
    assert!(
        matches!(
            result.unwrap_err(),
            GhostLockError::InvalidCreationHeight(_)
        ),
        "error must be InvalidCreationHeight"
    );
}

#[test]
fn test_758_ghost_lock_data_preserves_fields() {
    let secp = Secp256k1::new();
    let lock = GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Large,
        TimelockTier::Long,
        HEIGHT,
    )
    .unwrap();

    let data = GhostLockData::from(&lock);

    assert_eq!(data.denomination, Denomination::Large);
    assert_eq!(data.timelock_tier, TimelockTier::Long);
    assert_eq!(data.creation_height, HEIGHT);
    assert_eq!(data.state, LockState::Active);
    assert_eq!(
        data.lock_pubkey,
        hex::encode(lock.lock_pubkey().serialize())
    );
    assert_eq!(
        data.recovery_pubkey,
        hex::encode(lock.recovery_pubkey().serialize())
    );
    assert_eq!(data.lock_id, hex::encode(lock.lock_id()));
    assert!(!data.witness_script.is_empty());
    assert!(!data.script_hash.is_empty());
}

#[test]
fn test_759_denomination_sats_match_tier_values() {
    let secp = Secp256k1::new();

    let denominations = [
        (Denomination::Micro, 10_000u64),
        (Denomination::Tiny, 100_000),
        (Denomination::Small, 1_000_000),
        (Denomination::Medium, 10_000_000),
        (Denomination::Large, 100_000_000),
        (Denomination::XL, 1_000_000_000),
    ];

    for &(denom, expected_sats) in &denominations {
        let lock = GhostLock::new(
            &secp,
            &lock_secret(),
            &recovery_secret(),
            denom,
            TimelockTier::Standard,
            HEIGHT,
        )
        .unwrap();

        assert_eq!(
            lock.denomination().sats(),
            expected_sats,
            "denomination().sats() mismatch for {:?}",
            denom
        );
    }
}

// =============================================================================
// STATE MACHINE (Tests 760-769)
// =============================================================================

fn make_lock() -> GhostLock {
    let secp = Secp256k1::new();
    GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Small,
        TimelockTier::Standard,
        HEIGHT,
    )
    .unwrap()
}

#[test]
fn test_760_new_lock_starts_active() {
    let lock = make_lock();
    assert_eq!(lock.state(), LockState::Active);
    assert!(lock.state().can_spend());
    assert!(lock.state().can_mix());
    assert!(lock.state().can_jump());
    assert!(!lock.state().is_terminal());
    assert!(!lock.state().is_transitional());
}

#[test]
fn test_761_enter_mix_active_to_in_mix() {
    let mut lock = make_lock();
    assert!(lock.transition(StateTransition::EnterMix).is_ok());
    assert_eq!(lock.state(), LockState::InMix);
    assert!(lock.state().is_transitional());
}

#[test]
fn test_762_exit_mix_in_mix_to_active() {
    let mut lock = make_lock();
    lock.transition(StateTransition::EnterMix).unwrap();
    assert!(lock.transition(StateTransition::ExitMix).is_ok());
    assert_eq!(lock.state(), LockState::Active);
}

#[test]
fn test_763_spend_active_to_spent() {
    let mut lock = make_lock();
    assert!(lock
        .transition(StateTransition::SettlementSpend {
            batch_id: [0u8; 32]
        })
        .is_ok());
    assert_eq!(lock.state(), LockState::Spent);
    assert!(lock.state().is_terminal());
}

#[test]
fn test_764_freeze_active_to_frozen() {
    let mut lock = make_lock();
    assert!(lock.transition(StateTransition::Freeze).is_ok());
    assert_eq!(lock.state(), LockState::Frozen);
    assert!(!lock.state().can_spend());
}

#[test]
fn test_765_unfreeze_frozen_to_active() {
    let mut lock = make_lock();
    lock.transition(StateTransition::Freeze).unwrap();
    assert!(lock.transition(StateTransition::Unfreeze).is_ok());
    assert_eq!(lock.state(), LockState::Active);
}

#[test]
fn test_766_start_jump_active_to_jumping() {
    let mut lock = make_lock();
    assert!(lock.transition(StateTransition::StartJump).is_ok());
    assert_eq!(lock.state(), LockState::Jumping);
    assert!(lock.state().is_transitional());
}

#[test]
fn test_767_complete_jump_jumping_to_spent() {
    let mut lock = make_lock();
    lock.transition(StateTransition::StartJump).unwrap();
    assert!(lock.transition(StateTransition::CompleteJump).is_ok());
    assert_eq!(lock.state(), LockState::Spent);
    assert!(lock.state().is_terminal());
}

#[test]
fn test_768_enter_mix_from_in_mix_rejected() {
    let mut lock = make_lock();
    lock.transition(StateTransition::EnterMix).unwrap();
    assert_eq!(lock.state(), LockState::InMix);

    let result = lock.transition(StateTransition::EnterMix);
    assert!(result.is_err(), "EnterMix from InMix must be rejected");
    assert!(matches!(
        result.unwrap_err(),
        GhostLockError::InvalidStateTransition(_)
    ));
    // State must remain unchanged after failed transition
    assert_eq!(lock.state(), LockState::InMix);
}

#[test]
fn test_769_spent_and_recovered_reject_all_transitions() {
    let transitions = [
        StateTransition::EnterMix,
        StateTransition::ExitMix,
        StateTransition::StartJump,
        StateTransition::CompleteJump,
        StateTransition::SettlementSpend {
            batch_id: [0u8; 32],
        },
        StateTransition::Recover,
        StateTransition::Freeze,
        StateTransition::Unfreeze,
    ];

    // Test from Spent
    for transition in &transitions {
        let mut lock = make_lock();
        lock.transition(StateTransition::SettlementSpend {
            batch_id: [0u8; 32],
        })
        .unwrap();
        assert!(
            lock.transition(*transition).is_err(),
            "Spent state must reject {:?}",
            transition
        );
    }

    // Test from Recovered
    for transition in &transitions {
        let mut lock = make_lock();
        lock.transition(StateTransition::Recover).unwrap();
        assert!(
            lock.transition(*transition).is_err(),
            "Recovered state must reject {:?}",
            transition
        );
    }
}

// =============================================================================
// RECOVERY & TIMELOCK (Tests 770-774)
// =============================================================================

#[test]
fn test_770_recovery_not_available_before_recovery_height() {
    let lock = make_lock();
    let recovery_height = lock.recovery_height();

    assert!(
        !lock.is_recovery_available(HEIGHT),
        "recovery must not be available at creation height"
    );
    assert!(
        !lock.is_recovery_available(recovery_height - 1),
        "recovery must not be available one block before recovery_height"
    );
}

#[test]
fn test_771_recovery_available_at_recovery_height() {
    let lock = make_lock();
    let recovery_height = lock.recovery_height();

    assert!(
        lock.is_recovery_available(recovery_height),
        "recovery must be available at exactly recovery_height"
    );
    assert!(
        lock.is_recovery_available(recovery_height + 1000),
        "recovery must be available well after recovery_height"
    );
}

#[test]
fn test_772_short_lt_standard_lt_long_recovery_blocks() {
    let short_blocks = TimelockTier::Short.recovery_blocks();
    let standard_blocks = TimelockTier::Standard.recovery_blocks();
    let long_blocks = TimelockTier::Long.recovery_blocks();

    assert!(
        short_blocks < standard_blocks,
        "Short ({}) must be less than Standard ({})",
        short_blocks,
        standard_blocks
    );
    assert!(
        standard_blocks < long_blocks,
        "Standard ({}) must be less than Long ({})",
        standard_blocks,
        long_blocks
    );
}

#[test]
fn test_773_blocks_until_recovery_decreases_with_height() {
    let lock = make_lock();

    let remaining_at_creation = lock.blocks_until_recovery(HEIGHT);
    let remaining_at_halfway = lock.blocks_until_recovery(HEIGHT + remaining_at_creation / 2);
    let remaining_at_recovery = lock.blocks_until_recovery(lock.recovery_height());

    assert!(
        remaining_at_creation > remaining_at_halfway,
        "blocks_until_recovery must decrease as current_height increases"
    );
    assert!(
        remaining_at_halfway > remaining_at_recovery,
        "blocks_until_recovery must keep decreasing"
    );
    assert_eq!(
        remaining_at_recovery, 0,
        "blocks_until_recovery at recovery_height must be 0"
    );
}

#[test]
fn test_774_recover_transition_active_to_recovered() {
    let mut lock = make_lock();
    assert!(lock.transition(StateTransition::Recover).is_ok());
    assert_eq!(lock.state(), LockState::Recovered);
    assert!(lock.state().is_terminal());
}

// =============================================================================
// JUMP SCHEDULE & DENOMINATIONS (Tests 775-779)
// =============================================================================

#[test]
fn test_775_needs_jump_false_before_true_after_deadline() {
    let secp = Secp256k1::new();

    // Large denomination = High risk tier = 7-14 day randomized rotation
    let lock = GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Large,
        TimelockTier::Standard,
        HEIGHT,
    )
    .unwrap();

    assert_eq!(lock.jump_risk_tier(), JumpRiskTier::High);

    // Deadline is randomized — use the lock's actual stored deadline
    let deadline = lock.jump_schedule().deadline_height;

    // Verify deadline is within the expected range
    let min = HEIGHT + JumpRiskTier::High.min_rotation_blocks();
    let max = HEIGHT + JumpRiskTier::High.max_rotation_blocks();
    assert!(
        deadline >= min && deadline <= max,
        "deadline {} must be in [{}, {}]",
        deadline,
        min,
        max
    );

    assert!(
        !lock.needs_jump(HEIGHT),
        "needs_jump must be false at creation height"
    );
    assert!(
        !lock.needs_jump(deadline - 1),
        "needs_jump must be false one block before deadline"
    );
    assert!(
        lock.needs_jump(deadline),
        "needs_jump must be true at exactly the deadline"
    );
    assert!(
        lock.needs_jump(deadline + 100),
        "needs_jump must be true past the deadline"
    );
}

#[test]
fn test_776_jump_urgency_progresses_toward_one() {
    let secp = Secp256k1::new();

    let lock = GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Large,
        TimelockTier::Standard,
        HEIGHT,
    )
    .unwrap();

    // Deadline is randomized — use the lock's actual stored deadline
    let deadline = lock.jump_schedule().deadline_height;
    let total_blocks = deadline - HEIGHT;
    let midpoint = HEIGHT + total_blocks / 2;

    let urgency_start = lock.jump_urgency(HEIGHT);
    let urgency_mid = lock.jump_urgency(midpoint);
    let urgency_deadline = lock.jump_urgency(deadline);
    let urgency_past = lock.jump_urgency(deadline + total_blocks);

    assert!(
        (urgency_start - 0.0).abs() < 0.01,
        "urgency at creation must be ~0.0, got {}",
        urgency_start
    );
    assert!(
        (urgency_mid - 0.5).abs() < 0.02,
        "urgency at midpoint must be ~0.5, got {}",
        urgency_mid
    );
    assert!(
        (urgency_deadline - 1.0).abs() < 0.01,
        "urgency at deadline must be ~1.0, got {}",
        urgency_deadline
    );
    assert!(
        (urgency_past - 1.0).abs() < 0.01,
        "urgency past deadline must be capped at 1.0, got {}",
        urgency_past
    );
}

#[test]
fn test_777_optimal_denominations_breakdown() {
    // 111_000_000 sats = 1 Large (100M) + 1 Medium (10M) + 1 Small (1M)
    let result = optimal_denominations(111_000_000);

    assert!(
        result
            .iter()
            .any(|&(d, c)| d == Denomination::Large && c == 1),
        "must include 1 Large, got: {:?}",
        result
    );
    assert!(
        result
            .iter()
            .any(|&(d, c)| d == Denomination::Medium && c == 1),
        "must include 1 Medium, got: {:?}",
        result
    );
    assert!(
        result
            .iter()
            .any(|&(d, c)| d == Denomination::Small && c == 1),
        "must include 1 Small, got: {:?}",
        result
    );

    // Total must equal input
    let total: u64 = result.iter().map(|(d, c)| d.sats() * c).sum();
    assert_eq!(total, 111_000_000, "denomination total must match input");
}

#[test]
fn test_778_optimal_denominations_zero_returns_empty() {
    let result = optimal_denominations(0);
    assert!(
        result.is_empty(),
        "optimal_denominations(0) must return empty vec"
    );
}

#[test]
fn test_779_ghost_lock_id_matches_lock_lock_id() {
    let secp = Secp256k1::new();
    let lock = GhostLock::new(
        &secp,
        &lock_secret(),
        &recovery_secret(),
        Denomination::Small,
        TimelockTier::Standard,
        HEIGHT,
    )
    .unwrap();

    let computed_id = ghost_lock_id(
        lock.lock_pubkey(),
        lock.recovery_pubkey(),
        lock.creation_height(),
        lock.denomination().sats(),
    );

    assert_eq!(
        &computed_id,
        lock.lock_id(),
        "ghost_lock_id() must match lock.lock_id() for same params"
    );
}
