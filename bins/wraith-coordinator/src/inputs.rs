//! Per-session validated input store.
//!
//! Once a session is `Locked`, each enrolled participant submits a single
//! input UTXO + change address via `POST /api/v1/session/:id/inputs`.
//! The handler validates the submission and stashes an `AcceptedInputs`
//! record here. Once every enrolled participant has submitted, the
//! session transitions Locked → Signing.
//!
//! The data lives in `CoordinatorState::inputs_store` (a
//! `Mutex<HashMap<session_id, Vec<AcceptedInputs>>>`); this module
//! defines the record shape and the helpers that mutate it. Keeping the
//! store outside `wraith-protocol` for now — until B/4b adds the
//! blinded-token half, the protocol crate doesn't need to know about
//! input acceptance.

use serde::{Deserialize, Serialize};

use wraith_protocol::BondId;

/// One participant's accepted commit-phase submission. Records exactly
/// the fields the coordinator needs to build the round transaction in
/// `/sign` — txid + vout + value + spending script for the input, plus
/// the change address (None when the input is exact change).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedInputs {
    /// Wallet's per-round identity (matches `LiteSessionParticipant.ghost_id`).
    pub ghost_id: String,
    /// L2 bond record this input set is anchored to. Verified against
    /// the BondLedger before acceptance.
    pub bond_id: BondId,
    /// The participant's single input UTXO.
    pub input: TxInputRef,
    /// Where surplus over (denom + fee shares) goes. `None` is only
    /// legal when surplus < dust threshold; the handler enforces this.
    pub change_address: Option<String>,
    /// Unix-seconds the submission was accepted by the coordinator.
    /// Used for diagnostic / audit logging; the round-tx itself has no
    /// per-input timestamp.
    pub accepted_at: u64,
}

/// Wire-format input reference — what the wallet sends and what the
/// coordinator stores. Bitcoin types live one layer in (parsed by the
/// handler before storage).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInputRef {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    /// Hex-encoded scriptPubKey of the spending output. Coordinator
    /// will validate this against the on-chain UTXO at /sign time;
    /// for B/4a we just store what the wallet supplied.
    pub scriptpubkey_hex: String,
}
