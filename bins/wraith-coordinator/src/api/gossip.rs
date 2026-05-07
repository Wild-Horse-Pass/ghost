//! `POST /api/v1/internal/gossip` — Standby coordinators receive
//! `SessionGossipEvent`s here from the Active and apply them to their
//! local `LiteSessionRegistry`.
//!
//! See `crate::gossip_http` for the publishing side.

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use tracing::{debug, warn};
use wraith_protocol::{LiteSessionError, SessionGossipEvent};

use crate::CoordinatorState;

/// `POST /api/v1/internal/gossip`
///
/// Body: a JSON-encoded `SessionGossipEvent`.
///
/// Returns:
///   * `200 OK` on successful apply (or no-op idempotent reapply)
///   * `404 Not Found` if the event references a session this Standby
///     never saw (`ParticipantAdded` / `StateChanged` without a prior
///     `SessionCreated`); caller logs but doesn't retry — the
///     reconciliation snapshot will pick it up
///   * `400 Bad Request` if the JSON is malformed (handled by axum
///     before this handler runs)
pub async fn post(
    State(state): State<Arc<CoordinatorState>>,
    Json(event): Json<SessionGossipEvent>,
) -> impl IntoResponse {
    match state.sessions.apply_event(event) {
        Ok(()) => {
            debug!("gossip: event applied");
            StatusCode::OK
        }
        Err(LiteSessionError::NotFound(sid)) => {
            warn!(session_id = %sid, "gossip: event references unknown session");
            StatusCode::NOT_FOUND
        }
        Err(e) => {
            warn!(error = %e, "gossip: apply_event failed");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}
