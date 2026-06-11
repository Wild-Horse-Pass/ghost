//! Per-session witness store.
//!
//! After tx assembly (B/5b), each enrolled participant fetches the
//! unsigned tx from `/round-tx`, signs their own input, and posts the
//! resulting `bitcoin::Witness` to `/witness`. Once all N witnesses
//! land, the coordinator merges them into the assembled tx and calls
//! the `Broadcaster`.
//!
//! Validation of the signature itself (signed-message correctness, key
//! ownership of the input's scriptpubkey) is deferred to broadcast time
//! — bitcoind / mempool acceptance will reject any malformed witness
//! anyway, and pre-validating it on the coordinator would require
//! shipping the per-input prevout amount around for taproot/segwit
//! sighash, which complicates the wire format. v1 trusts wallets to
//! produce a valid witness and surfaces failure as a Rejected
//! broadcast.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedWitness {
    /// Wallet identity, used to dedupe and to map back to the right
    /// `input_index` in the assembled tx.
    pub ghost_id: String,
    /// Index into `LiteRound::tx.input` this witness is for. Wallets
    /// compute this themselves by scanning the round-tx for their
    /// own (txid, vout).
    pub input_index: u32,
    /// Hex-encoded `bitcoin::Witness` (consensus encoding —
    /// length-prefixed witness stack).
    pub witness_hex: String,
    /// Unix-seconds the witness was accepted.
    pub accepted_at: u64,
}
