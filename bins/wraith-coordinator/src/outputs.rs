//! Per-session anonymous output store.
//!
//! Wallets submit their unblinded mix-output addresses here over a
//! fresh anonymous connection (Tor circuit, separate IP, etc.). The
//! Schnorr signature accompanying each submission proves the address
//! was authorised by *someone* in this round — without revealing
//! which participant. That's the unlinkability that makes Wraith Lite
//! a CoinJoin and not just a coin shuffle.
//!
//! The data lives in `CoordinatorState::outputs_store` (a
//! `Mutex<HashMap<session_id, Vec<AcceptedOutput>>>`); this module
//! defines the record shape. Once the registry holds N outputs for an
//! N-participant session, B/5b's tx-assembly path picks them up.

use serde::{Deserialize, Serialize};

/// One unblinded mix-output address that was successfully verified
/// against the per-round signing key.
///
/// Crucially: NO ghost_id is stored here. The coordinator deliberately
/// does not know which participant submitted which output — that's the
/// privacy property the protocol exists to provide. The submission
/// metadata kept around (just `accepted_at`) is for diagnostic /
/// audit logging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedOutput {
    /// The unblinded destination address that will receive a denom-
    /// sized output in the round transaction. Must parse against the
    /// coordinator's `Network` (signet / mainnet); enforced at
    /// validation time, not here.
    pub address: String,
    /// Unix-seconds the submission was accepted.
    pub accepted_at: u64,
}
