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

//! Wraith Protocol — single-round atomic CoinJoin for Ghost Pay.
//!
//! Wraith provides private entry from public Bitcoin into Ghost Pay. Each
//! round mixes N participants atomically: a single transaction takes their
//! inputs and produces N equal-denomination outputs (plus a service-fee
//! output and any change), so an observer cannot link any input to any
//! output. See `DESIGN_LITE.md` for the protocol spec.
//!
//! # Example
//!
//! ```
//! use wraith_protocol::LiteTier;
//!
//! let tier = LiteTier::Denom100kSats;
//! assert_eq!(tier.denomination_sats(), 100_000);
//! ```

mod blind;
pub mod coordinator_redundancy;
mod error;
mod tier;

pub use blind::{
    BlindSignature, BlindSignatureResponse, BlindedAddress, BlindedChallenge, BlindingContext,
    CoordinatorSigner, CoordinatorSignerConfig, PublicNonce, TokenVerifier, UnblindedToken,
};
pub use error::WraithError;
pub use tier::{
    LiteTier, LITE_BOND_BPS, LITE_FILL_WINDOW_SECS, LITE_SERVICE_FEE_BPS, VBYTES_PER_INPUT,
    VBYTES_PER_OUTPUT,
};

pub mod single_round;
pub use single_round::{
    LiteOutputKind, LiteOutputProvenance, LiteParticipantInput, LiteRound, LiteRoundBuilder,
    CHANGE_DUST_THRESHOLD_SATS, DEFAULT_FEE_RATE_SATS_PER_VB,
};

pub mod bond;
pub use bond::{
    BondError, BondId, BondLedger, BondRecord, BondResolution, BondStatus, MockBondLedger,
    RefundReason, SlashReason,
};

pub mod lite_session;
pub use lite_session::{
    find_or_create_session, Clock, DeterministicSessionIdGenerator, GossipSink, LiteSession,
    LiteSessionError, LiteSessionParticipant, LiteSessionRegistry, LiteSessionState, MockClock,
    NullGossipSink, RandomSessionIdGenerator, RecordingGossipSink, SessionDescriptor,
    SessionGossipEvent, SessionIdGenerator, SystemClock,
};

pub mod remix;
pub use remix::{
    RemixEnrolment, RemixError, RemixId, RemixQueue, RemixStatus, DEFAULT_QUEUE_TIMEOUT_SECS,
    DEFAULT_REMIX_COUNT, MAX_REMIX_COUNT,
};

/// Session type determines fee structure
///
/// Mix sessions charge a service fee + mining cost.
/// Jump sessions (key rotation via Wraith) charge mining cost only.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum SessionType {
    /// Normal CoinJoin mixing (service fee + mining cost)
    #[default]
    Mix,
    /// Key rotation via Wraith mixing (mining cost only, no service fee)
    Jump,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_type_default() {
        assert_eq!(SessionType::default(), SessionType::Mix);
    }

    #[test]
    fn test_lite_tier_denomination() {
        assert_eq!(LiteTier::Denom100kSats.denomination_sats(), 100_000);
    }
}
