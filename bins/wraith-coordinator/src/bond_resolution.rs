//! Bond resolution at round terminal transitions.
//!
//! When a round reaches `Complete` (successful broadcast) or `Failed`
//! (assembly / broadcast rejection), every participant's L2 bond must
//! be settled with the `BondLedger`. This module handles that walk.
//!
//! Bond IDs come from `inputs_store`: at /inputs time the coordinator
//! calls `BondLedger::verify_bond(ghost_id, session_id, expected_sats)`
//! and stores the returned `BondId` on the participant's
//! `AcceptedInputs` record. By round terminal time we already have a
//! confirmed-correct mapping from ghost_id to BondId for everyone who
//! made it past /inputs.
//!
//! What this module does NOT cover (intentionally):
//!
//!   - Filling → Failed (no-quorum) bond cleanup. Those participants
//!     never hit /inputs so the coordinator has no verified BondIds
//!     for them. The wallet's bond ledger client (phase C) will need
//!     to scan for orphaned escrows by (ghost_id, session_id) and
//!     refund directly. Out of scope until phase C.
//!
//!   - No-sign deadline + slashing. Today every enrolled participant
//!     must submit a /witness for the round to advance. The deadline
//!     path (B/5e) will mark non-signers' bonds as
//!     `Slash(NoSignDuringSigning)` and signers' bonds as
//!     `Refund(RoundVoided)` if the round fails to broadcast as a
//!     result of those non-signs. Adding a background timer touches
//!     enough of the runtime to deserve its own commit.
//!
//! Errors during resolution are logged but do not fail the round —
//! the on-chain transaction is already broadcast (or the round is
//! already failed) by the time we get here, so a flaky ledger
//! shouldn't undo that. Operators reconcile from logs + ghost-pay
//! audit records.

use std::sync::Arc;

use tracing::{info, warn};

use wraith_protocol::{BondLedger, BondResolution};

use crate::inputs::AcceptedInputs;

/// Outcome of a bond-resolution pass. Surfaced in logs and (in
/// future) in the round-status endpoint so operators can confirm
/// every participant got their bond returned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolutionSummary {
    /// Number of bonds successfully resolved.
    pub resolved: u32,
    /// Number of bonds that failed to resolve. Each failure is logged
    /// at warn-level with the offending ghost_id and the underlying
    /// error from the ledger.
    pub failed: u32,
    /// Number of inputs that had no bond_id stored (the
    /// "should-not-happen but defensive" case — every entry written
    /// by /inputs has a verified BondId, so this should always be 0).
    pub skipped: u32,
}

/// Walk the per-session input set and resolve each participant's
/// bond with the supplied resolution.
///
/// Idempotent at the ledger layer: re-calling against an already-
/// resolved bond returns `BondError::AlreadyResolved`, which we log
/// and count as `failed`. The function never panics, never returns
/// an error type — it always returns a summary so the caller can
/// proceed with the terminal transition unconditionally.
pub fn resolve_round_bonds(
    ledger: &Arc<dyn BondLedger>,
    session_id: &str,
    inputs: &[AcceptedInputs],
    resolution: BondResolution,
) -> ResolutionSummary {
    let mut summary = ResolutionSummary::default();
    for input in inputs {
        match ledger.resolve_bond(&input.bond_id, resolution.clone()) {
            Ok(_record) => {
                info!(
                    %session_id,
                    ghost_id = %input.ghost_id,
                    bond_id = %input.bond_id,
                    ?resolution,
                    "bond resolved",
                );
                summary.resolved += 1;
            }
            Err(e) => {
                warn!(
                    %session_id,
                    ghost_id = %input.ghost_id,
                    bond_id = %input.bond_id,
                    ?resolution,
                    error = %e,
                    "bond resolution failed",
                );
                summary.failed += 1;
            }
        }
    }
    summary
}
