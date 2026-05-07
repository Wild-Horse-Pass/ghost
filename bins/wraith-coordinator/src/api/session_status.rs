//! `GET /api/v1/session/{session_id}` — wallet polling endpoint.
//!
//! Wallets poll this between calls to `/find_or_create` and `/inputs` to
//! watch for `Filling → Locked` (other participants showed up, round
//! is full) or `Filling → Failed` (fill window expired without
//! quorum). Read-only from the wallet's perspective; the coordinator
//! itself ticks the registry on every call so time-driven transitions
//! show up without needing a separate background loop.
//!
//! Idempotent: repeated calls at the same `now` produce the same
//! response. The registry's `tick(now)` is a no-op past the first
//! call for any given timestamp.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use wraith_protocol::SessionDescriptor;

use crate::state::CoordinatorState;

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    detail: String,
}

#[derive(Serialize)]
pub struct ResponseBody {
    pub session: SessionDescriptor,
}

pub async fn get(
    State(state): State<Arc<CoordinatorState>>,
    Path(session_id): Path<String>,
) -> Response {
    let now = state.now();
    // Advance any time-driven transitions before snapshotting. Cheap +
    // idempotent — re-running tick(now) at the same `now` is a no-op.
    let _changed = state.sessions.tick(now);

    match state.sessions.get(&session_id) {
        Some(session) => {
            let descriptor = SessionDescriptor::from_session(&session);
            (StatusCode::OK, Json(ResponseBody { session: descriptor })).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: "session_not_found",
                detail: format!("no session with id '{session_id}'"),
            }),
        )
            .into_response(),
    }
}
