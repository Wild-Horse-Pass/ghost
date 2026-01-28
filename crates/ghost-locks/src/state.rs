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
//| FILE: state.rs                                                                                                       |
//|======================================================================================================================|

//! Lock state management

use serde::{Deserialize, Serialize};

/// State of a Ghost Lock
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum LockState {
    /// Lock is active and spendable
    #[default]
    Active,
    /// Lock is being used in a Wraith mix
    InMix,
    /// Lock is being jumped (key rotation in progress)
    Jumping,
    /// Lock has been spent
    Spent,
    /// Lock was recovered via timelock
    Recovered,
    /// Lock is frozen (investigation, dispute, etc.)
    Frozen,
}

impl LockState {
    /// Check if the lock can be spent normally
    pub fn can_spend(&self) -> bool {
        matches!(self, LockState::Active)
    }

    /// Check if the lock can enter a Wraith mix
    pub fn can_mix(&self) -> bool {
        matches!(self, LockState::Active)
    }

    /// Check if the lock can be jumped
    pub fn can_jump(&self) -> bool {
        matches!(self, LockState::Active)
    }

    /// Check if the lock is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(self, LockState::Spent | LockState::Recovered)
    }

    /// Check if the lock is in a transitional state
    pub fn is_transitional(&self) -> bool {
        matches!(self, LockState::InMix | LockState::Jumping)
    }

    /// Get state name
    pub fn name(&self) -> &'static str {
        match self {
            LockState::Active => "Active",
            LockState::InMix => "In Mix",
            LockState::Jumping => "Jumping",
            LockState::Spent => "Spent",
            LockState::Recovered => "Recovered",
            LockState::Frozen => "Frozen",
        }
    }

    /// Get state description
    pub fn description(&self) -> &'static str {
        match self {
            LockState::Active => "Lock is active and available for spending",
            LockState::InMix => "Lock is participating in a Wraith mix",
            LockState::Jumping => "Lock is being rotated to fresh keys",
            LockState::Spent => "Lock has been spent",
            LockState::Recovered => "Lock was recovered via timelock script",
            LockState::Frozen => "Lock is frozen and cannot be spent",
        }
    }
}

impl std::fmt::Display for LockState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Lock state transition
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateTransition {
    /// Start a Wraith mix
    EnterMix,
    /// Complete a Wraith mix (back to active)
    ExitMix,
    /// Start a jump (key rotation)
    StartJump,
    /// Complete a jump (new lock created)
    CompleteJump,
    /// Spend the lock
    Spend,
    /// Recover via timelock
    Recover,
    /// Freeze the lock
    Freeze,
    /// Unfreeze the lock
    Unfreeze,
}

impl StateTransition {
    /// Check if this transition is valid from the given state
    pub fn is_valid_from(&self, state: LockState) -> bool {
        match (state, self) {
            (LockState::Active, StateTransition::EnterMix) => true,
            (LockState::Active, StateTransition::StartJump) => true,
            (LockState::Active, StateTransition::Spend) => true,
            (LockState::Active, StateTransition::Recover) => true,
            (LockState::Active, StateTransition::Freeze) => true,
            (LockState::InMix, StateTransition::ExitMix) => true,
            (LockState::Jumping, StateTransition::CompleteJump) => true,
            (LockState::Frozen, StateTransition::Unfreeze) => true,
            _ => false,
        }
    }

    /// Get the resulting state after this transition
    pub fn result_state(&self) -> LockState {
        match self {
            StateTransition::EnterMix => LockState::InMix,
            StateTransition::ExitMix => LockState::Active,
            StateTransition::StartJump => LockState::Jumping,
            StateTransition::CompleteJump => LockState::Spent, // Old lock is spent
            StateTransition::Spend => LockState::Spent,
            StateTransition::Recover => LockState::Recovered,
            StateTransition::Freeze => LockState::Frozen,
            StateTransition::Unfreeze => LockState::Active,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_capabilities() {
        assert!(LockState::Active.can_spend());
        assert!(LockState::Active.can_mix());
        assert!(LockState::Active.can_jump());

        assert!(!LockState::InMix.can_spend());
        assert!(!LockState::Jumping.can_mix());
        assert!(!LockState::Spent.can_jump());
    }

    #[test]
    fn test_terminal_states() {
        assert!(!LockState::Active.is_terminal());
        assert!(!LockState::InMix.is_terminal());
        assert!(LockState::Spent.is_terminal());
        assert!(LockState::Recovered.is_terminal());
    }

    #[test]
    fn test_valid_transitions() {
        assert!(StateTransition::EnterMix.is_valid_from(LockState::Active));
        assert!(StateTransition::StartJump.is_valid_from(LockState::Active));
        assert!(StateTransition::Spend.is_valid_from(LockState::Active));

        assert!(!StateTransition::EnterMix.is_valid_from(LockState::InMix));
        assert!(!StateTransition::StartJump.is_valid_from(LockState::Spent));
    }

    #[test]
    fn test_transition_results() {
        assert_eq!(StateTransition::EnterMix.result_state(), LockState::InMix);
        assert_eq!(StateTransition::ExitMix.result_state(), LockState::Active);
        assert_eq!(StateTransition::Spend.result_state(), LockState::Spent);
    }
}
