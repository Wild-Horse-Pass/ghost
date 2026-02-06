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
//| FILE: session.rs                                                                                                     |
//|======================================================================================================================|

//! Wraith mixing session management

use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Instant;

use crate::denomination::WraithDenomination;
use crate::phase::{Phase, PhaseExecution};
use crate::tier::ParticipantTier;
use crate::{
    COLLECTING_INPUTS_TIMEOUT_SECS, DEFAULT_TIMEOUT_SECS, EARLY_EXECUTION_THRESHOLD,
    MIN_EXECUTION_THRESHOLD, PHASE_CONFIRMATION_TIMEOUT_SECS, PHASE_EXECUTION_TIMEOUT_SECS,
    WAITING_PARTICIPANTS_TIMEOUT_SECS,
};

/// Session registry for tracking seen session IDs (WR-L1)
///
/// Prevents session ID collisions and replay attacks.
#[derive(Debug, Default)]
pub struct SessionRegistry {
    /// Set of session IDs that have been seen
    seen_sessions: HashSet<[u8; 32]>,
}

impl SessionRegistry {
    /// Create a new session registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a session ID has been seen before
    pub fn is_seen(&self, session_id: &[u8; 32]) -> bool {
        self.seen_sessions.contains(session_id)
    }

    /// Register a session ID
    ///
    /// Returns true if the session ID was new, false if it was already seen.
    pub fn register(&mut self, session_id: [u8; 32]) -> bool {
        self.seen_sessions.insert(session_id)
    }

    /// Check and register a session ID in one operation
    ///
    /// Returns Ok(()) if the session ID was new, Err if it was already seen.
    pub fn check_and_register(&mut self, session_id: [u8; 32]) -> Result<(), crate::WraithError> {
        if !self.register(session_id) {
            return Err(crate::WraithError::InvalidInput(format!(
                "Session ID {} already exists (collision or replay)",
                hex::encode(session_id)
            )));
        }
        Ok(())
    }

    /// Get the number of registered sessions
    pub fn session_count(&self) -> usize {
        self.seen_sessions.len()
    }

    /// Clear old sessions (call periodically to prevent unbounded growth)
    pub fn clear(&mut self) {
        self.seen_sessions.clear();
    }
}

/// State of a Wraith session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SessionState {
    /// Waiting for participants to join
    WaitingForParticipants,
    /// Collecting inputs and blinded outputs
    CollectingInputs,
    /// Executing Phase 1 (split)
    ExecutingPhase1,
    /// Waiting for Phase 1 confirmation
    WaitingPhase1Confirmation,
    /// Executing Phase 2 (merge)
    ExecutingPhase2,
    /// Waiting for Phase 2 confirmation
    WaitingPhase2Confirmation,
    /// Session completed successfully
    Completed,
    /// Session failed
    Failed,
    /// Session refunded
    Refunded,
}

impl SessionState {
    /// Check if session is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            SessionState::Completed | SessionState::Failed | SessionState::Refunded
        )
    }

    /// Check if session can accept new participants
    pub fn can_accept_participants(&self) -> bool {
        matches!(self, SessionState::WaitingForParticipants)
    }

    /// Get state name
    pub fn name(&self) -> &'static str {
        match self {
            SessionState::WaitingForParticipants => "Waiting for Participants",
            SessionState::CollectingInputs => "Collecting Inputs",
            SessionState::ExecutingPhase1 => "Executing Phase 1",
            SessionState::WaitingPhase1Confirmation => "Waiting Phase 1 Confirmation",
            SessionState::ExecutingPhase2 => "Executing Phase 2",
            SessionState::WaitingPhase2Confirmation => "Waiting Phase 2 Confirmation",
            SessionState::Completed => "Completed",
            SessionState::Failed => "Failed",
            SessionState::Refunded => "Refunded",
        }
    }
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Session configuration for customizable timeouts (WR4-L1)
#[derive(Debug, Clone, Default)]
pub struct SessionConfig {
    /// Custom timeout in seconds (defaults to DEFAULT_TIMEOUT_SECS)
    pub timeout_secs: Option<u64>,
}

impl SessionConfig {
    /// Create a new session config with custom timeout
    pub fn with_timeout(timeout_secs: u64) -> Self {
        Self {
            timeout_secs: Some(timeout_secs),
        }
    }
}

/// A Wraith mixing session
#[derive(Debug, Clone)]
pub struct WraithSession {
    /// Unique session ID
    session_id: [u8; 32],
    /// Participant tier
    tier: ParticipantTier,
    /// Denomination for this session
    denomination: WraithDenomination,
    /// Current state
    state: SessionState,
    /// Number of registered participants
    participant_count: usize,
    /// Phase 1 execution (if started)
    phase1: Option<PhaseExecution>,
    /// Phase 2 execution (if started)
    phase2: Option<PhaseExecution>,
    /// Session created timestamp (Unix time - for external reporting)
    #[allow(dead_code)]
    created_at: u64,
    /// Session timeout instant (monotonic - for timeout calculations) (WR-L3)
    timeout_instant: Instant,
    /// Session timeout duration from creation
    timeout_duration_secs: u64,
}

impl WraithSession {
    /// Create a new Wraith session with default configuration
    pub fn new(tier: ParticipantTier, denomination: WraithDenomination) -> Self {
        Self::with_config(tier, denomination, SessionConfig::default())
    }

    /// Create a new Wraith session with custom configuration (WR4-L1)
    ///
    /// Allows configurable timeout for different use cases:
    /// - Short timeouts for testing
    /// - Long timeouts for high-participant sessions
    pub fn with_config(
        tier: ParticipantTier,
        denomination: WraithDenomination,
        config: SessionConfig,
    ) -> Self {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Generate cryptographically secure random session ID
        // SECURITY: Using full 32 bytes of randomness prevents session ID prediction/collision
        let mut session_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut session_id);

        // Use monotonic clock for timeout (WR-L3)
        // This prevents NTP manipulation attacks on session timeouts
        // WR4-L1: Allow configurable timeout
        let timeout_duration = config.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
        let timeout_instant = Instant::now() + std::time::Duration::from_secs(timeout_duration);

        Self {
            session_id,
            tier,
            denomination,
            state: SessionState::WaitingForParticipants,
            participant_count: 0,
            phase1: None,
            phase2: None,
            created_at: now_unix,
            timeout_instant,
            timeout_duration_secs: timeout_duration,
        }
    }

    /// Get session ID
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Get session ID as hex
    pub fn session_id_hex(&self) -> String {
        hex::encode(self.session_id)
    }

    /// Get tier
    pub fn tier(&self) -> &ParticipantTier {
        &self.tier
    }

    /// Get denomination
    pub fn denomination(&self) -> &WraithDenomination {
        &self.denomination
    }

    /// Get current state
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Get participant count
    pub fn participant_count(&self) -> usize {
        self.participant_count
    }

    /// Check if session has minimum participants
    pub fn has_minimum_participants(&self) -> bool {
        self.tier.meets_minimum(self.participant_count)
    }

    /// Get fill percentage
    pub fn fill_percentage(&self) -> f64 {
        self.tier.fill_percentage(self.participant_count)
    }

    /// Check if session can force execute (50% threshold)
    pub fn can_force_execute(&self) -> bool {
        self.fill_percentage() >= MIN_EXECUTION_THRESHOLD * 100.0
    }

    /// Check if session can early execute (75% threshold)
    pub fn can_early_execute(&self) -> bool {
        self.fill_percentage() >= EARLY_EXECUTION_THRESHOLD * 100.0
    }

    /// Check if session has timed out
    ///
    /// Uses monotonic clock (Instant) to prevent NTP manipulation attacks (WR-L3).
    pub fn is_timed_out(&self) -> bool {
        Instant::now() >= self.timeout_instant
    }

    /// Get remaining time in seconds
    ///
    /// Uses monotonic clock (Instant) to prevent NTP manipulation attacks (WR-L3).
    pub fn remaining_secs(&self) -> u64 {
        let now = Instant::now();
        if now >= self.timeout_instant {
            0
        } else {
            (self.timeout_instant - now).as_secs()
        }
    }

    /// Get appropriate timeout for the current state
    fn timeout_for_state(state: SessionState) -> u64 {
        match state {
            SessionState::WaitingForParticipants => WAITING_PARTICIPANTS_TIMEOUT_SECS,
            SessionState::CollectingInputs => COLLECTING_INPUTS_TIMEOUT_SECS,
            SessionState::ExecutingPhase1 | SessionState::ExecutingPhase2 => {
                PHASE_EXECUTION_TIMEOUT_SECS
            }
            SessionState::WaitingPhase1Confirmation | SessionState::WaitingPhase2Confirmation => {
                PHASE_CONFIRMATION_TIMEOUT_SECS
            }
            _ => DEFAULT_TIMEOUT_SECS,
        }
    }

    /// Reset timeout for a new state transition
    ///
    /// Uses monotonic clock (Instant) to prevent NTP manipulation attacks (WR-L3).
    fn reset_timeout(&mut self) {
        let new_duration = Self::timeout_for_state(self.state);
        self.timeout_instant = Instant::now() + std::time::Duration::from_secs(new_duration);
        self.timeout_duration_secs = new_duration;
    }

    /// Extend timeout by a specific duration (e.g., for slow confirmations)
    ///
    /// Uses monotonic clock (Instant) to prevent NTP manipulation attacks (WR-L3).
    pub fn extend_timeout(&mut self, additional_secs: u64) {
        self.timeout_instant += std::time::Duration::from_secs(additional_secs);
        self.timeout_duration_secs = self.timeout_duration_secs.saturating_add(additional_secs);
    }

    /// Get timeout deadline as approximate Unix timestamp
    ///
    /// Note: This is computed from the monotonic timeout for external reporting.
    /// Internal timeout calculations use the monotonic Instant directly (WR-L3).
    pub fn timeout_at(&self) -> u64 {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now_unix + self.remaining_secs()
    }

    /// Add a participant
    pub fn add_participant(&mut self) -> bool {
        if !self.state.can_accept_participants() {
            return false;
        }
        if self.participant_count >= self.tier.max_participants() {
            return false;
        }
        self.participant_count += 1;
        true
    }

    /// Transition to collecting inputs
    pub fn start_collecting(&mut self) -> Result<(), crate::WraithError> {
        if self.state != SessionState::WaitingForParticipants {
            return Err(crate::WraithError::InvalidState {
                expected: "WaitingForParticipants".to_string(),
                actual: format!("{:?}", self.state),
            });
        }
        if !self.has_minimum_participants() {
            return Err(crate::WraithError::NotEnoughParticipants(
                self.participant_count,
                self.tier.min_participants(),
            ));
        }
        self.state = SessionState::CollectingInputs;
        self.reset_timeout();
        Ok(())
    }

    /// Start phase 1
    pub fn start_phase1(&mut self) -> Result<(), crate::WraithError> {
        if self.state != SessionState::CollectingInputs {
            return Err(crate::WraithError::InvalidState {
                expected: "CollectingInputs".to_string(),
                actual: format!("{:?}", self.state),
            });
        }
        self.state = SessionState::ExecutingPhase1;
        self.phase1 = Some(PhaseExecution::new(Phase::Split, self.participant_count));
        self.reset_timeout();
        Ok(())
    }

    /// Start phase 2
    pub fn start_phase2(&mut self) -> Result<(), crate::WraithError> {
        if self.state != SessionState::WaitingPhase1Confirmation {
            return Err(crate::WraithError::InvalidState {
                expected: "WaitingPhase1Confirmation".to_string(),
                actual: format!("{:?}", self.state),
            });
        }
        self.state = SessionState::ExecutingPhase2;
        self.phase2 = Some(PhaseExecution::new(Phase::Merge, self.participant_count));
        self.reset_timeout();
        Ok(())
    }

    /// Mark phase 1 as confirmed
    pub fn confirm_phase1(&mut self, height: u32) -> Result<(), crate::WraithError> {
        if let Some(ref mut phase1) = self.phase1 {
            phase1.confirm(height);
        }
        if self.state == SessionState::ExecutingPhase1 {
            self.state = SessionState::WaitingPhase1Confirmation;
            self.reset_timeout();
        }
        Ok(())
    }

    /// Mark phase 2 as confirmed (session complete)
    pub fn confirm_phase2(&mut self, height: u32) -> Result<(), crate::WraithError> {
        if let Some(ref mut phase2) = self.phase2 {
            phase2.confirm(height);
        }
        if self.state == SessionState::ExecutingPhase2 {
            self.state = SessionState::Completed;
            // No timeout reset needed for terminal state
        }
        Ok(())
    }

    /// WR4-M3: Mark session as failed (returns Result to prevent invalid transitions)
    ///
    /// Returns an error if the session is already in a terminal state.
    /// This prevents confusing state tracking where a completed session
    /// could be marked as failed.
    pub fn fail(&mut self) -> Result<(), crate::WraithError> {
        if self.state.is_terminal() {
            return Err(crate::WraithError::InvalidState {
                expected: "non-terminal state".to_string(),
                actual: format!("{:?}", self.state),
            });
        }
        self.state = SessionState::Failed;
        Ok(())
    }

    /// WR4-M3: Mark session as refunded (returns Result to prevent invalid transitions)
    ///
    /// Returns an error if the session is already in a terminal state.
    /// This prevents confusing state tracking where a completed session
    /// could be marked as refunded.
    pub fn refund(&mut self) -> Result<(), crate::WraithError> {
        if self.state.is_terminal() {
            return Err(crate::WraithError::InvalidState {
                expected: "non-terminal state".to_string(),
                actual: format!("{:?}", self.state),
            });
        }
        self.state = SessionState::Refunded;
        Ok(())
    }

    /// Get phase 1 execution
    pub fn phase1(&self) -> Option<&PhaseExecution> {
        self.phase1.as_ref()
    }

    /// Get phase 1 execution (mutable)
    pub fn phase1_mut(&mut self) -> Option<&mut PhaseExecution> {
        self.phase1.as_mut()
    }

    /// Get phase 2 execution
    pub fn phase2(&self) -> Option<&PhaseExecution> {
        self.phase2.as_ref()
    }

    /// Get phase 2 execution (mutable)
    pub fn phase2_mut(&mut self) -> Option<&mut PhaseExecution> {
        self.phase2.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = WraithSession::new(ParticipantTier::Standard, WraithDenomination::Small);

        assert_eq!(session.state(), SessionState::WaitingForParticipants);
        assert_eq!(session.participant_count(), 0);
        assert!(!session.has_minimum_participants());
    }

    #[test]
    fn test_add_participants() {
        // Use Whale tier (160 minimum) for practical test values
        let mut session = WraithSession::new(ParticipantTier::Whale, WraithDenomination::Small);

        for _ in 0..160 {
            assert!(session.add_participant());
        }

        assert_eq!(session.participant_count(), 160);
        assert!(session.has_minimum_participants());
    }

    #[test]
    fn test_fill_percentage() {
        // Use Whale tier (160 minimum) for practical test values
        let mut session = WraithSession::new(ParticipantTier::Whale, WraithDenomination::Small);

        for _ in 0..80 {
            session.add_participant();
        }

        // 80/160 = 50%
        assert!((session.fill_percentage() - 50.0).abs() < 1.0);
    }

    #[test]
    fn test_session_lifecycle() {
        // Use Whale tier (160 minimum) for practical test values
        let mut session = WraithSession::new(ParticipantTier::Whale, WraithDenomination::Small);

        // Add minimum participants
        for _ in 0..160 {
            session.add_participant();
        }

        session.start_collecting().unwrap();
        assert_eq!(session.state(), SessionState::CollectingInputs);

        session.start_phase1().unwrap();
        assert_eq!(session.state(), SessionState::ExecutingPhase1);
    }

    /// WR-L1 Test: Session registry prevents duplicate session IDs
    #[test]
    fn test_session_registry() {
        let mut registry = SessionRegistry::new();

        let session_id1 = [0x01u8; 32];
        let session_id2 = [0x02u8; 32];

        // First registration should succeed
        assert!(registry.register(session_id1));
        assert_eq!(registry.session_count(), 1);

        // Same ID should fail (returns false)
        assert!(!registry.register(session_id1));
        assert_eq!(registry.session_count(), 1);

        // Different ID should succeed
        assert!(registry.register(session_id2));
        assert_eq!(registry.session_count(), 2);

        // Check is_seen
        assert!(registry.is_seen(&session_id1));
        assert!(registry.is_seen(&session_id2));
        assert!(!registry.is_seen(&[0x03u8; 32]));
    }

    /// WR-L1 Test: check_and_register returns proper errors
    #[test]
    fn test_session_registry_check_and_register() {
        let mut registry = SessionRegistry::new();

        let session_id = [0x42u8; 32];

        // First check_and_register should succeed
        assert!(registry.check_and_register(session_id).is_ok());

        // Second should fail with error
        let result = registry.check_and_register(session_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    /// WR-L3 Test: Monotonic clock for timeouts
    #[test]
    fn test_monotonic_timeout() {
        let session = WraithSession::new(ParticipantTier::Micro, WraithDenomination::Small);

        // Session should not be timed out immediately
        assert!(!session.is_timed_out());

        // Remaining time should be positive
        assert!(session.remaining_secs() > 0);

        // timeout_at should return a reasonable Unix timestamp
        let timeout_at = session.timeout_at();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // timeout_at should be in the future
        assert!(timeout_at > now);
    }

    /// WR-L3 Test: Timeout extension uses monotonic clock
    #[test]
    fn test_timeout_extension() {
        let mut session = WraithSession::new(ParticipantTier::Micro, WraithDenomination::Small);

        let initial_remaining = session.remaining_secs();

        // Extend by 1 hour
        session.extend_timeout(3600);

        let new_remaining = session.remaining_secs();

        // New remaining should be approximately initial + 3600
        // Allow some tolerance for execution time
        assert!(new_remaining > initial_remaining);
        assert!(new_remaining >= initial_remaining + 3590);
    }
}
