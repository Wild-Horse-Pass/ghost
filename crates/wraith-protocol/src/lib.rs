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
//!     ParticipantTier::Standard,  // 250 participants (optimized for 80KB limit)
//!     WraithDenomination::Small,  // 0.01 BTC output
//! );
//!
//! assert_eq!(session.tier().min_participants(), 250);
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
    BlindSignature, BlindedAddress, BlindingContext, CoordinatorSigner, CoordinatorSignerConfig,
    TokenVerifier, UnblindedToken,
};
pub use coordinator::{
    AuditEvent, AuditLog, InMemoryAuditLog, Participant, ReputationTracker, SessionAuditRecord,
    TimeoutAction, WraithCoordinator,
};
pub use denomination::WraithDenomination;
pub use error::WraithError;
pub use executor::{
    MergeTransaction, SplitTransaction, WraithInput, WraithOutput, WraithTransactionBuilder,
};
pub use phase::{Phase, PhaseExecution, PhaseState};
pub use session::{SessionConfig, SessionRegistry, SessionState, WraithSession};
pub use tier::{ParticipantTier, WraithMode};

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

/// Fee divisor (100 = 1%). Integer-only arithmetic; no float constant.
pub const FEE_DIVISOR: u64 = 100;

/// Split ratio (1 input -> 10 intermediates)
pub const SPLIT_RATIO: usize = 10;

/// Minimum threshold for forced execution (50%)
pub const MIN_EXECUTION_THRESHOLD: f64 = 0.50;

/// Threshold for optional early execution (75%)
pub const EARLY_EXECUTION_THRESHOLD: f64 = 0.75;

/// Supermajority for refund vote (67%)
pub const REFUND_VOTE_THRESHOLD: f64 = 0.67;

/// Generate encrypted OP_RETURN marker v3 — absorbs participant count
///
/// The participant count is included in the SHA256 input, so the OP_RETURN is
/// exactly 32 bytes of opaque data. An observer cannot determine the number of
/// participants without knowing the session ID and trying all plausible counts.
///
/// # Arguments
/// * `phase` - 1 for split, 2 for merge
/// * `session_id` - The 32-byte session ID used as encryption key
/// * `participant_count` - Number of participants in this session
///
/// # Returns
/// A 32-byte encrypted marker embedding phase + participant count
pub fn generate_encrypted_marker_v3(
    phase: u8,
    session_id: &[u8; 32],
    participant_count: u16,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"wraith/op-return-marker/v3");
    hasher.update([phase]);
    hasher.update(session_id);
    hasher.update(participant_count.to_le_bytes());
    hasher.finalize().into()
}

/// Verify an encrypted v3 OP_RETURN marker by brute-forcing participant count
///
/// Iterates over both phases and all participant counts from 1..=max_count,
/// performing ~2*max_count SHA256 operations (sub-ms for max_count=400).
///
/// # Arguments
/// * `marker` - The 32-byte marker from the OP_RETURN output
/// * `session_id` - The 32-byte session ID used as encryption key
/// * `max_count` - Maximum participant count to try (e.g., 400 for Micro tier)
///
/// # Returns
/// * `Some((phase, count))` if a match is found
/// * `None` if no match for any phase/count combination
pub fn verify_encrypted_marker_v3(
    marker: &[u8; 32],
    session_id: &[u8; 32],
    max_count: u16,
) -> Option<(u8, u16)> {
    for phase in 1..=2u8 {
        for count in 1..=max_count {
            let expected = generate_encrypted_marker_v3(phase, session_id, count);
            if marker == &expected {
                return Some((phase, count));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = WraithSession::new(ParticipantTier::Standard, WraithDenomination::Small);

        // Standard tier: 1-10 BTC balance range, 250 participants, 6 outputs each
        assert_eq!(session.tier().min_participants(), 250);
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
        // Tiers organized by balance range, with participant counts optimized
        // for Bitcoin L1 transaction size limits (80KB budget)
        assert_eq!(ParticipantTier::Micro.min_participants(), 400); // 0.001-0.01 BTC, 3 outputs
        assert_eq!(ParticipantTier::Small.min_participants(), 340); // 0.01-0.1 BTC, 4 outputs
        assert_eq!(ParticipantTier::Medium.min_participants(), 290); // 0.1-1 BTC, 5 outputs
        assert_eq!(ParticipantTier::Standard.min_participants(), 250); // 1-10 BTC, 6 outputs
        assert_eq!(ParticipantTier::Large.min_participants(), 195); // 10-50 BTC, 8 outputs
        assert_eq!(ParticipantTier::Whale.min_participants(), 160); // 50+ BTC, 10 outputs
    }
}
