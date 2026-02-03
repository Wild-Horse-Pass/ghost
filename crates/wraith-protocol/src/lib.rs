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
//| FILE: lib.rs                                                                                                         |
//|======================================================================================================================|

//! Wraith Protocol - Two-phase mixing for Ghost Pay
//!
//! Wraith Protocol provides private entry from public Bitcoin into Ghost Pay.
//! Two-phase split-merge mixing breaks the trail between public Bitcoin and
//! Ghost Locks.
//!
//! # Two-Phase Design
//!
//! **Phase 1: Split**
//! - N inputs (one per participant) → 10N intermediate Ghost Locks
//! - Trail break: observer cannot link input to outputs
//!
//! **Phase 2: Merge (next epoch)**
//! - 10N intermediate Ghost Locks → N final Ghost Locks
//! - Trail break: observer cannot link inputs to outputs
//!
//! Result: User starts with 1 public UTXO, ends with 1 clean Ghost Lock.
//!
//! # Example
//!
//! ```
//! use wraith_protocol::{WraithSession, ParticipantTier, WraithDenomination};
//!
//! // Create a new Wraith session
//! let session = WraithSession::new(
//!     ParticipantTier::Standard,  // 500 participants
//!     WraithDenomination::Small,  // 0.01 BTC output
//! );
//!
//! assert_eq!(session.tier().min_participants(), 500);
//! ```

mod blind;
mod coordinator;
pub mod coordinator_redundancy;
mod denomination;
pub mod entry_timing;
mod error;
mod executor;
mod phase;
pub mod rpc;
mod session;
mod tier;

pub use blind::{
    BlindSignature, BlindedAddress, BlindingContext, CoordinatorSigner, TokenVerifier,
    UnblindedToken,
};
pub use coordinator::{Participant, SessionAuditRecord, TimeoutAction, WraithCoordinator};
pub use denomination::WraithDenomination;
pub use error::WraithError;
pub use executor::{
    MergeTransaction, SplitTransaction, WraithInput, WraithOutput, WraithTransactionBuilder,
};
pub use phase::{Phase, PhaseExecution, PhaseState};
pub use session::{SessionState, WraithSession};
pub use tier::ParticipantTier;

/// Protocol version
pub const WRAITH_VERSION: u32 = 1;

/// Default timeout in seconds (7 days)
pub const DEFAULT_TIMEOUT_SECS: u64 = 7 * 24 * 60 * 60;

/// Timeout for waiting for participants phase (24 hours)
pub const WAITING_PARTICIPANTS_TIMEOUT_SECS: u64 = 24 * 60 * 60;

/// Timeout for input collection phase (2 hours)
pub const COLLECTING_INPUTS_TIMEOUT_SECS: u64 = 2 * 60 * 60;

/// Timeout for phase execution (1 hour)
pub const PHASE_EXECUTION_TIMEOUT_SECS: u64 = 60 * 60;

/// Timeout for phase confirmation (6 hours - waiting for blockchain confirmations)
pub const PHASE_CONFIRMATION_TIMEOUT_SECS: u64 = 6 * 60 * 60;

/// Fee percentage (1%)
pub const FEE_PERCENTAGE: f64 = 0.01;

/// Split ratio (1 input -> 10 intermediates)
pub const SPLIT_RATIO: usize = 10;

/// Minimum threshold for forced execution (50%)
pub const MIN_EXECUTION_THRESHOLD: f64 = 0.50;

/// Threshold for optional early execution (75%)
pub const EARLY_EXECUTION_THRESHOLD: f64 = 0.75;

/// Supermajority for refund vote (67%)
pub const REFUND_VOTE_THRESHOLD: f64 = 0.67;

/// OP_RETURN marker for Phase 1 (split)
pub const WRAITH_PHASE1_MARKER: &[u8] = b"WR1";

/// OP_RETURN marker for Phase 2 (merge)
pub const WRAITH_PHASE2_MARKER: &[u8] = b"WR2";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = WraithSession::new(ParticipantTier::Standard, WraithDenomination::Small);

        assert_eq!(session.tier().min_participants(), 500);
        assert_eq!(session.denomination().output_sats(), 1_000_000);
        assert!(matches!(
            session.state(),
            SessionState::WaitingForParticipants
        ));
    }

    #[test]
    fn test_denomination_fees() {
        let denom = WraithDenomination::Small;
        assert_eq!(denom.input_sats(), 1_010_000); // 0.01 + 1% fee
        assert_eq!(denom.fee_sats(), 10_000);
        assert_eq!(denom.output_sats(), 1_000_000);
        assert_eq!(denom.intermediate_sats(), 100_000); // 10x split
    }

    #[test]
    fn test_tier_participants() {
        assert_eq!(ParticipantTier::Express.min_participants(), 25);
        assert_eq!(ParticipantTier::Quick.min_participants(), 50);
        assert_eq!(ParticipantTier::Small.min_participants(), 100);
        assert_eq!(ParticipantTier::Medium.min_participants(), 250);
        assert_eq!(ParticipantTier::Standard.min_participants(), 500);
        assert_eq!(ParticipantTier::Large.min_participants(), 750);
        assert_eq!(ParticipantTier::Whale.min_participants(), 1000);
    }
}
