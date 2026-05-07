//! `GET /api/v1/session/:session_id/round-tx` — fetch the assembled
//! unsigned round transaction.
//!
//! Available once `/outputs` has collected its Nth submission and
//! tx assembly succeeded. Wallets poll this between `/outputs` and
//! the upcoming `/witness` (B/5c) so they can sign their own input
//! against the canonical round transaction.
//!
//! The response carries the unsigned tx as hex plus per-output
//! provenance (which output index belongs to whom, what kind it is,
//! and what value). This is what lets a participant verify their
//! mixed output is present and at the right denomination before they
//! sign — no need to trust the coordinator's word.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use wraith_protocol::{LiteOutputKind, LiteSessionState};

use crate::state::CoordinatorState;

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
    detail: String,
}

#[derive(Debug, Serialize)]
pub struct OutputProvenanceWire {
    pub tx_output_index: usize,
    /// `mixed` / `change` / `service_fee` — stable lowercase strings.
    pub kind: &'static str,
    /// Internal participant index for Mixed/Change; `None` for
    /// ServiceFee. Diagnostic only — the privacy-relevant property
    /// (which mix output belongs to which input) is preserved by the
    /// shuffle, not by hiding this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub participant_id: Option<u32>,
    pub amount_sats: u64,
}

#[derive(Debug, Serialize)]
pub struct ResponseBody {
    pub session_id: String,
    /// Hex-encoded unsigned bitcoin transaction (consensus serialised).
    pub unsigned_tx_hex: String,
    /// Hex-encoded txid the eventual signed tx will commit to.
    pub txid: String,
    pub mining_fee_sats: u64,
    pub output_provenance: Vec<OutputProvenanceWire>,
    /// Unix-seconds the round was assembled (per the coordinator's
    /// clock).
    pub assembled_at: u64,
}

pub async fn get(
    State(state): State<Arc<CoordinatorState>>,
    Path(session_id): Path<String>,
) -> Response {
    let session = match state.sessions.get(&session_id) {
        Some(s) => s,
        None => {
            return error(
                StatusCode::NOT_FOUND,
                "session_not_found",
                format!("no session with id '{session_id}'"),
            );
        }
    };

    // Assembled tx is only meaningful in Signing or Broadcasting state.
    // In Failed it tells us nothing useful (the tx was never built or
    // was built and then thrown out); in Filling/Locked it doesn't
    // exist yet.
    match &session.state {
        LiteSessionState::Signing | LiteSessionState::Broadcasting | LiteSessionState::Complete => {}
        other => {
            return error(
                StatusCode::CONFLICT,
                "wrong_session_state",
                format!(
                    "round-tx is only available in signing/broadcasting/complete; \
                     session is currently '{}'",
                    other.as_str()
                ),
            );
        }
    }

    let assembled = match state
        .assembled_rounds
        .lock()
        .expect("assembled_rounds poisoned")
        .get(&session_id)
        .cloned()
    {
        Some(a) => a,
        None => {
            return error(
                StatusCode::NOT_FOUND,
                "round_not_assembled",
                "round transaction has not been assembled yet — \
                 wait for /outputs to collect all submissions"
                    .into(),
            );
        }
    };

    let provenance = assembled
        .round
        .output_provenance
        .iter()
        .map(|p| OutputProvenanceWire {
            tx_output_index: p.tx_output_index,
            kind: kind_str(p.kind),
            participant_id: p.participant_id,
            amount_sats: p.amount_sats,
        })
        .collect();

    let body = ResponseBody {
        session_id,
        unsigned_tx_hex: assembled.unsigned_tx_hex.clone(),
        txid: assembled.round.txid().to_string(),
        mining_fee_sats: assembled.round.mining_fee_sats,
        output_provenance: provenance,
        assembled_at: assembled.assembled_at,
    };
    (StatusCode::OK, Json(body)).into_response()
}

fn kind_str(k: LiteOutputKind) -> &'static str {
    match k {
        LiteOutputKind::Mixed => "mixed",
        LiteOutputKind::Change => "change",
        LiteOutputKind::ServiceFee => "service_fee",
    }
}

fn error(status: StatusCode, code: &'static str, detail: String) -> Response {
    (
        status,
        Json(ErrorBody {
            error: code,
            detail,
        }),
    )
        .into_response()
}
