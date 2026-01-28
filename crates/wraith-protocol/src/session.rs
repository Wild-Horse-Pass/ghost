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

use crate::denomination::WraithDenomination;
use crate::phase::{Phase, PhaseExecution};
use crate::tier::ParticipantTier;
use crate::{
    COLLECTING_INPUTS_TIMEOUT_SECS, DEFAULT_TIMEOUT_SECS, EARLY_EXECUTION_THRESHOLD,
    MIN_EXECUTION_THRESHOLD, PHASE_CONFIRMATION_TIMEOUT_SECS, PHASE_EXECUTION_TIMEOUT_SECS,
    WAITING_PARTICIPANTS_TIMEOUT_SECS,
};

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

/// A Wraith mixing session
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Session created timestamp
    created_at: u64,
    /// Session timeout timestamp
    timeout_at: u64,
}

impl WraithSession {
    /// Create a new Wraith session
    pub fn new(tier: ParticipantTier, denomination: WraithDenomination) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Generate cryptographically secure random session ID
        // SECURITY: Using full 32 bytes of randomness prevents session ID prediction/collision
        let mut session_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut session_id);

        Self {
            session_id,
            tier,
            denomination,
            state: SessionState::WaitingForParticipants,
            participant_count: 0,
            phase1: None,
            phase2: None,
            created_at: now,
            timeout_at: now + DEFAULT_TIMEOUT_SECS,
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
    pub fn is_timed_out(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now >= self.timeout_at
    }

    /// Get remaining time in seconds
    pub fn remaining_secs(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.timeout_at.saturating_sub(now)
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
    fn reset_timeout(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.timeout_at = now + Self::timeout_for_state(self.state);
    }

    /// Extend timeout by a specific duration (e.g., for slow confirmations)
    pub fn extend_timeout(&mut self, additional_secs: u64) {
        self.timeout_at = self.timeout_at.saturating_add(additional_secs);
    }

    /// Get timeout deadline timestamp
    pub fn timeout_at(&self) -> u64 {
        self.timeout_at
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

    /// Mark session as failed
    pub fn fail(&mut self) {
        self.state = SessionState::Failed;
    }

    /// Mark session as refunded
    pub fn refund(&mut self) {
        self.state = SessionState::Refunded;
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
        let mut session = WraithSession::new(ParticipantTier::Express, WraithDenomination::Small);

        for _ in 0..25 {
            assert!(session.add_participant());
        }

        assert_eq!(session.participant_count(), 25);
        assert!(session.has_minimum_participants());
    }

    #[test]
    fn test_fill_percentage() {
        let mut session = WraithSession::new(ParticipantTier::Express, WraithDenomination::Small);

        for _ in 0..12 {
            session.add_participant();
        }

        assert!((session.fill_percentage() - 48.0).abs() < 1.0);
    }

    #[test]
    fn test_session_lifecycle() {
        let mut session = WraithSession::new(ParticipantTier::Express, WraithDenomination::Small);

        // Add minimum participants
        for _ in 0..25 {
            session.add_participant();
        }

        session.start_collecting().unwrap();
        assert_eq!(session.state(), SessionState::CollectingInputs);

        session.start_phase1().unwrap();
        assert_eq!(session.state(), SessionState::ExecutingPhase1);
    }
}
