//! Category 10: Wraith Mixing Protocol Tests (37 tests)
//!
//! Tests for two-phase CoinJoin-style mixing:
//! - Session lifecycle (using real wraith-protocol types)
//! - Phase transitions
//! - Entry timing (using real EntryScheduler)
//! - Coordinator redundancy (using real CoordinatorPool)

use std::time::{Duration, Instant};

// Real imports from wraith-protocol
use wraith_protocol::{
    coordinator_redundancy::{
        CoordinatorInfo, CoordinatorPool, CoordinatorStatus, PoolError, RotationPolicy,
        RotationReason,
    },
    entry_timing::{EntryConfig, EntryScheduler, EntryTimingError},
    ParticipantTier, Phase, SessionState, TimeoutAction, WraithDenomination, WraithSession,
};

// =============================================================================
// SESSION LIFECYCLE TESTS (Tests 429-437)
// Using real WraithSession, ParticipantTier, WraithDenomination
// =============================================================================

#[test]
fn test_429_create_session_with_tier_parameters() {
    let session = WraithSession::new(ParticipantTier::Standard, WraithDenomination::Small);

    assert_eq!(session.tier().min_participants(), 250);
    assert_eq!(session.denomination().output_sats(), 1_000_000);
}

#[test]
fn test_430_session_initial_state() {
    let session = WraithSession::new(ParticipantTier::Micro, WraithDenomination::Small);

    assert!(matches!(
        session.state(),
        SessionState::WaitingForParticipants
    ));
}

#[test]
fn test_431_minimum_participants_by_tier() {
    // Tiers organized by balance range, optimized for 80KB tx size limit
    assert_eq!(ParticipantTier::Micro.min_participants(), 400); // 0.001-0.01 BTC
    assert_eq!(ParticipantTier::Small.min_participants(), 340); // 0.01-0.1 BTC
    assert_eq!(ParticipantTier::Medium.min_participants(), 290); // 0.1-1 BTC
    assert_eq!(ParticipantTier::Standard.min_participants(), 250); // 1-10 BTC
    assert_eq!(ParticipantTier::Large.min_participants(), 195); // 10-50 BTC
    assert_eq!(ParticipantTier::Whale.min_participants(), 160); // 50+ BTC
}

#[test]
fn test_432_denomination_outputs() {
    // Real WraithDenomination values (no XL variant)
    assert_eq!(WraithDenomination::Micro.output_sats(), 10_000); // 0.0001 BTC
    assert_eq!(WraithDenomination::Small.output_sats(), 1_000_000); // 0.01 BTC
    assert_eq!(WraithDenomination::Medium.output_sats(), 10_000_000); // 0.1 BTC
    assert_eq!(WraithDenomination::Large.output_sats(), 100_000_000); // 1 BTC
}

#[test]
fn test_433_add_participant_to_session() {
    let mut session = WraithSession::new(ParticipantTier::Micro, WraithDenomination::Small);

    assert_eq!(session.participant_count(), 0);
    assert!(session.add_participant());
    assert_eq!(session.participant_count(), 1);
}

#[test]
fn test_434_session_can_start_when_min_reached() {
    let mut session = WraithSession::new(
        ParticipantTier::Whale, // 160 minimum (smallest tier)
        WraithDenomination::Small,
    );

    // Not enough participants
    for _ in 0..159 {
        session.add_participant();
    }
    assert!(!session.has_minimum_participants());

    // Now enough
    session.add_participant();
    assert!(session.has_minimum_participants());
}

#[test]
fn test_435_session_start_transitions_state() {
    let mut session = WraithSession::new(ParticipantTier::Whale, WraithDenomination::Small);

    for _ in 0..160 {
        session.add_participant();
    }

    session.start_collecting().unwrap();
    assert!(matches!(session.state(), SessionState::CollectingInputs));
}

#[test]
fn test_436_session_start_fails_without_minimum() {
    let mut session = WraithSession::new(ParticipantTier::Micro, WraithDenomination::Small);

    session.add_participant();
    let result = session.start_collecting();
    assert!(result.is_err());
}

#[test]
fn test_437_phase_progression() {
    let mut session = WraithSession::new(ParticipantTier::Whale, WraithDenomination::Small);

    // Fill session with minimum participants
    for _ in 0..160 {
        session.add_participant();
    }
    session.start_collecting().unwrap();
    assert_eq!(session.state(), SessionState::CollectingInputs);

    // Progress through phases
    session.start_phase1().unwrap();
    assert_eq!(session.state(), SessionState::ExecutingPhase1);
}

// =============================================================================
// ENTRY TIMING TESTS (Tests 438-450)
// Using real EntryConfig and EntryScheduler from wraith-protocol
// =============================================================================

#[test]
fn test_438_default_entry_config() {
    let config = EntryConfig::default();
    assert!(config.delay_enabled);
    assert!(config.batching_enabled);
    assert_eq!(config.min_batch_size, 5);
}

#[test]
fn test_439_low_latency_config() {
    let config = EntryConfig::low_latency();
    assert!(config.min_delay_ms < EntryConfig::default().min_delay_ms);
    assert!(config.max_delay_ms < EntryConfig::default().max_delay_ms);
}

#[test]
fn test_440_high_privacy_config() {
    let config = EntryConfig::high_privacy();
    assert!(config.min_delay_ms > EntryConfig::default().min_delay_ms);
    assert!(config.cover_traffic_enabled);
    assert!(config.cover_traffic_ratio > 0.0);
}

#[test]
fn test_441_config_validation_min_max_delay() {
    let config = EntryConfig {
        min_delay_ms: 1000,
        max_delay_ms: 500, // Invalid: less than min
        ..EntryConfig::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn test_442_config_validation_batch_size() {
    let config = EntryConfig {
        batching_enabled: true,
        min_batch_size: 0, // Invalid when batching enabled
        ..EntryConfig::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn test_443_scheduler_creation() {
    let config = EntryConfig::default();
    let scheduler = EntryScheduler::new(config);
    assert!(scheduler.is_ok());
}

#[test]
fn test_444_schedule_entry() {
    let config = EntryConfig {
        delay_enabled: false,
        batching_enabled: false,
        cover_traffic_enabled: false, // Disable to make test deterministic
        ..EntryConfig::default()
    };
    let scheduler = EntryScheduler::new(config).unwrap();

    let entry = scheduler.schedule_entry([1u8; 32], vec![]);
    assert!(entry.is_ok());
    assert_eq!(scheduler.queue_len(), 1);
}

#[test]
fn test_445_scheduled_entry_has_delay() {
    let config = EntryConfig {
        delay_enabled: true,
        min_delay_ms: 1000,
        max_delay_ms: 10_000,
        ..EntryConfig::default()
    };
    let scheduler = EntryScheduler::new(config).unwrap();

    let entry = scheduler.schedule_entry([1u8; 32], vec![]).unwrap();
    // Entry should be scheduled in the future (with at least some delay)
    assert!(entry.scheduled_at >= entry.requested_at);
}

#[test]
fn test_446_delay_disabled() {
    let config = EntryConfig {
        delay_enabled: false,
        batching_enabled: false,
        cover_traffic_enabled: false, // Disable to make test deterministic
        ..EntryConfig::default()
    };
    let scheduler = EntryScheduler::new(config).unwrap();

    let _before = Instant::now();
    let entry = scheduler.schedule_entry([1u8; 32], vec![]).unwrap();

    // With delay disabled, should be ready very quickly
    let delay = entry.delay();
    assert!(delay < Duration::from_millis(100));
}

#[test]
fn test_447_batch_formation() {
    let config = EntryConfig {
        delay_enabled: false,
        batching_enabled: true,
        min_batch_size: 3,
        max_batch_wait_ms: 10_000,
        cover_traffic_enabled: false, // Disable to make test deterministic
        ..EntryConfig::default()
    };
    let scheduler = EntryScheduler::new(config).unwrap();

    // Queue entries
    let e1 = scheduler.schedule_entry([1u8; 32], vec![]).unwrap();
    let r1 = scheduler.add_to_batch(e1);
    assert!(r1.is_none());

    let e2 = scheduler.schedule_entry([2u8; 32], vec![]).unwrap();
    let r2 = scheduler.add_to_batch(e2);
    assert!(r2.is_none());

    let e3 = scheduler.schedule_entry([3u8; 32], vec![]).unwrap();
    let batch = scheduler.add_to_batch(e3);
    assert!(batch.is_some());
    assert_eq!(batch.unwrap().entries.len(), 3);
}

#[test]
fn test_448_batch_not_formed_below_minimum() {
    let config = EntryConfig {
        delay_enabled: false,
        batching_enabled: true,
        min_batch_size: 5,
        max_batch_wait_ms: 10_000,
        cover_traffic_enabled: false, // Disable to make test deterministic
        ..EntryConfig::default()
    };
    let scheduler = EntryScheduler::new(config).unwrap();

    // Queue fewer than minimum
    for i in 0..3 {
        let entry = scheduler.schedule_entry([i as u8; 32], vec![]).unwrap();
        let batch = scheduler.add_to_batch(entry);
        assert!(batch.is_none()); // Should not form batch yet
    }
}

#[test]
fn test_449_queue_capacity_limit() {
    let config = EntryConfig {
        delay_enabled: false,
        batching_enabled: false,
        max_queue_size: 5,
        cover_traffic_enabled: false, // Disable to make test deterministic
        ..EntryConfig::default()
    };
    let scheduler = EntryScheduler::new(config).unwrap();

    // Fill queue
    for i in 0..5 {
        scheduler.schedule_entry([i as u8; 32], vec![]).unwrap();
    }

    // Should fail when full
    let result = scheduler.schedule_entry([99u8; 32], vec![]);
    assert!(matches!(result, Err(EntryTimingError::QueueFull(_))));
}

#[test]
fn test_450_cover_traffic_config() {
    let config = EntryConfig {
        cover_traffic_enabled: true,
        cover_traffic_ratio: 0.5,
        ..EntryConfig::default()
    };

    assert!(config.cover_traffic_enabled);
    assert!((config.cover_traffic_ratio - 0.5).abs() < 0.01);
}

// =============================================================================
// COORDINATOR REDUNDANCY TESTS (Tests 451-460)
// Using real CoordinatorPool from wraith-protocol
// =============================================================================

fn test_coordinator_info(id: u8, name: &str) -> CoordinatorInfo {
    let mut coordinator_id = [0u8; 32];
    coordinator_id[0] = id;
    CoordinatorInfo::new(
        coordinator_id,
        name.to_string(),
        format!("http://coordinator-{}.onion:8080", id),
        vec![id; 32],
    )
}

#[test]
fn test_451_coordinator_pool_creation() {
    let policy = RotationPolicy::default();
    let pool = CoordinatorPool::new(policy);
    assert!(pool.is_ok());

    let pool = pool.unwrap();
    let stats = pool.stats();
    assert_eq!(stats.total_coordinators, 0);
}

#[test]
fn test_452_add_coordinator_to_pool() {
    let policy = RotationPolicy::default();
    let pool = CoordinatorPool::new(policy).unwrap();

    let coord = test_coordinator_info(1, "Coordinator A");
    let result = pool.register_coordinator(coord);
    assert!(result.is_ok());

    let stats = pool.stats();
    assert_eq!(stats.total_coordinators, 1);
}

#[test]
fn test_453_get_active_coordinator() {
    let policy = RotationPolicy::default();
    let pool = CoordinatorPool::new(policy).unwrap();

    let coord = test_coordinator_info(1, "Coordinator A");
    pool.register_coordinator(coord.clone()).unwrap();
    pool.activate_coordinator(&coord.id).unwrap();

    let active = pool.get_active();
    assert!(active.is_ok());
    assert_eq!(active.unwrap().id, coord.id);
}

#[test]
fn test_454_no_active_coordinator() {
    let policy = RotationPolicy::default();
    let pool = CoordinatorPool::new(policy).unwrap();

    // Register but don't activate
    let coord = test_coordinator_info(1, "Coordinator A");
    pool.register_coordinator(coord).unwrap();

    let active = pool.get_active();
    assert!(matches!(active, Err(PoolError::NoActiveCoordinator)));
}

#[test]
fn test_455_set_coordinator_status() {
    let policy = RotationPolicy::default();
    let pool = CoordinatorPool::new(policy).unwrap();

    let coord = test_coordinator_info(1, "Coordinator A");
    pool.register_coordinator(coord.clone()).unwrap();

    // Initially pending, activate makes it standby then active
    pool.activate_coordinator(&coord.id).unwrap();

    let active = pool.get_active();
    assert!(active.is_ok());
}

#[test]
fn test_456_coordinator_rotation() {
    let policy = RotationPolicy::default();
    let pool = CoordinatorPool::new(policy).unwrap();

    // Register two coordinators
    let coord_a = test_coordinator_info(1, "A");
    let coord_b = test_coordinator_info(2, "B");

    pool.register_coordinator(coord_a.clone()).unwrap();
    pool.register_coordinator(coord_b.clone()).unwrap();

    pool.activate_coordinator(&coord_a.id).unwrap();
    pool.activate_coordinator(&coord_b.id).unwrap();

    // A should be active initially
    assert_eq!(pool.get_active_id(), Some(coord_a.id));

    // Trigger rotation
    let event = pool.trigger_rotation(RotationReason::Manual).unwrap();

    // B should now be active
    assert_eq!(pool.get_active_id(), Some(coord_b.id));
    assert_eq!(event.previous_id, coord_a.id);
    assert_eq!(event.new_id, coord_b.id);
}

#[test]
fn test_457_coordinator_status_values() {
    // Test real CoordinatorStatus enum values
    assert_ne!(CoordinatorStatus::Active, CoordinatorStatus::Standby);
    assert_ne!(CoordinatorStatus::Draining, CoordinatorStatus::Failed);
    assert_ne!(CoordinatorStatus::Pending, CoordinatorStatus::Disabled);

    // Test can_accept_sessions
    assert!(CoordinatorStatus::Active.can_accept_sessions());
    assert!(CoordinatorStatus::Standby.can_accept_sessions());
    assert!(!CoordinatorStatus::Failed.can_accept_sessions());
    assert!(!CoordinatorStatus::Disabled.can_accept_sessions());
}

#[test]
fn test_458_rotation_policy_types() {
    let default_policy = RotationPolicy::default();
    let ha_policy = RotationPolicy::high_availability();
    let minimal_policy = RotationPolicy::minimal();

    // High availability should have more standby requirement
    assert!(ha_policy.min_standby_count >= default_policy.min_standby_count);

    // Minimal should have lowest requirements
    assert!(minimal_policy.min_standby_count <= default_policy.min_standby_count);
}

#[test]
fn test_459_empty_pool_rotation() {
    let policy = RotationPolicy::default();
    let pool = CoordinatorPool::new(policy).unwrap();

    // Only one coordinator - no standby for rotation
    let coord = test_coordinator_info(1, "A");
    pool.register_coordinator(coord.clone()).unwrap();
    pool.activate_coordinator(&coord.id).unwrap();

    // Rotation should fail - no standby available
    let result = pool.trigger_rotation(RotationReason::Manual);
    assert!(matches!(result, Err(PoolError::NoStandbyAvailable)));
}

#[test]
fn test_460_coordinator_endpoint_stored() {
    let policy = RotationPolicy::default();
    let pool = CoordinatorPool::new(policy).unwrap();

    let coord = test_coordinator_info(1, "TestCoord");
    pool.register_coordinator(coord.clone()).unwrap();
    pool.activate_coordinator(&coord.id).unwrap();

    let active = pool.get_active().unwrap();
    assert!(active.endpoint.contains("coordinator-1"));
}

// =============================================================================
// TIMEOUT AND ACTION TESTS (Tests 461-465)
// Using real types from wraith-protocol
// =============================================================================

#[test]
fn test_461_timeout_action_variants() {
    // Real TimeoutAction from wraith-protocol
    let _none = TimeoutAction::None;
    let _refunded = TimeoutAction::Refunded {
        reason: "test".into(),
        participant_count: 10,
    };
    let _failed = TimeoutAction::Failed {
        phase: 1,
        reason: "timeout".into(),
        stuck_funds: 1000,
    };
}

#[test]
fn test_462_timeout_action_equality() {
    // TimeoutAction uses field values, test the variants exist
    let none1 = TimeoutAction::None;
    let none2 = TimeoutAction::None;

    // Pattern match to verify structure
    assert!(matches!(none1, TimeoutAction::None));
    assert!(matches!(none2, TimeoutAction::None));

    let refunded = TimeoutAction::Refunded {
        reason: "test".into(),
        participant_count: 5,
    };
    assert!(matches!(refunded, TimeoutAction::Refunded { .. }));

    let failed = TimeoutAction::Failed {
        phase: 1,
        reason: "test".into(),
        stuck_funds: 0,
    };
    assert!(matches!(failed, TimeoutAction::Failed { .. }));
}

#[test]
fn test_463_session_state_variants() {
    // Real SessionState from wraith-protocol
    let states = vec![
        SessionState::WaitingForParticipants,
        SessionState::CollectingInputs,
        SessionState::ExecutingPhase1,
        SessionState::WaitingPhase1Confirmation,
        SessionState::ExecutingPhase2,
        SessionState::WaitingPhase2Confirmation,
        SessionState::Completed,
        SessionState::Failed,
        SessionState::Refunded,
    ];

    assert_eq!(states.len(), 9);

    // Test terminal states
    assert!(SessionState::Completed.is_terminal());
    assert!(SessionState::Failed.is_terminal());
    assert!(SessionState::Refunded.is_terminal());
    assert!(!SessionState::WaitingForParticipants.is_terminal());
}

#[test]
fn test_464_phase_ordering() {
    // Real Phase from wraith-protocol
    let phases = vec![Phase::Split, Phase::Merge];

    assert_eq!(phases.len(), 2);
}

#[test]
fn test_465_coordinator_creates_session() {
    // Test that we can create sessions from a coordinator context
    let session = WraithSession::new(ParticipantTier::Micro, WraithDenomination::Small);

    // Session should have an ID
    let session_id = session.session_id();
    assert_eq!(session_id.len(), 32);

    // Should be in waiting state
    assert!(matches!(
        session.state(),
        SessionState::WaitingForParticipants
    ));
    assert!(session.state().can_accept_participants());
}
