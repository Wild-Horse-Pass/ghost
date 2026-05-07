//! `POST /api/v1/internal/gossip` — Standby coordinators receive
//! `SessionGossipEvent`s here from the Active and apply them to their
//! local `LiteSessionRegistry`.
//!
//! Authenticated when `state.gossip_peer_secret` is set: requires
//! `X-Ghost-Signature` (hex HMAC-SHA256 of `timestamp || body`) and
//! `X-Ghost-Timestamp` (Unix seconds, ±300s window). When the secret
//! is unset, requests are accepted without auth — operators must
//! firewall the `/api/v1/internal/` prefix.
//!
//! See `crate::gossip_http` for the publishing side and
//! `crate::gossip_auth` for the HMAC scheme.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use tracing::{debug, warn};
use wraith_protocol::{LiteSessionError, SessionGossipEvent};

use crate::gossip_auth;
use crate::CoordinatorState;

/// `POST /api/v1/internal/gossip`
///
/// Body: a JSON-encoded `SessionGossipEvent`.
///
/// Returns:
///   * `200 OK` on successful apply (or no-op idempotent reapply)
///   * `400 Bad Request` if the JSON is malformed
///   * `401 Unauthorized` if the secret is configured and the
///     `X-Ghost-Signature` / `X-Ghost-Timestamp` headers are missing,
///     malformed, expired, or don't verify
///   * `404 Not Found` if the event references a session this Standby
///     never saw (`ParticipantAdded` / `StateChanged` without a prior
///     `SessionCreated`); caller logs but doesn't retry — the
///     reconciliation snapshot will pick it up
///   * `500 Internal Server Error` on registry errors
pub async fn post(
    State(state): State<Arc<CoordinatorState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if let Some(secret) = state.gossip_peer_secret.as_deref() {
        // Wall-clock time, not state.now(). The signing side
        // (gossip_http) uses chrono::Utc::now() to stamp the
        // request — both sides must agree on a real clock or the
        // 5-minute replay window is meaningless. Tests that inject
        // MockClock for session-tick timing don't affect this path.
        let now = chrono::Utc::now().timestamp() as u64;
        if !verify_request(secret, &headers, &body, now) {
            warn!("gossip: signature verification failed");
            return StatusCode::UNAUTHORIZED;
        }
    }

    let event: SessionGossipEvent = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(e) => {
            warn!(error = %e, "gossip: malformed JSON body");
            return StatusCode::BAD_REQUEST;
        }
    };

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

/// Pull the signature + timestamp headers and verify against the
/// shared secret. Returns false on any failure path (missing header,
/// malformed value, stale timestamp, mismatched MAC) so the caller
/// can collapse to a single `401`.
fn verify_request(secret: &str, headers: &HeaderMap, body: &[u8], now_secs: u64) -> bool {
    let signature = match headers
        .get(gossip_auth::SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        Some(s) => s,
        None => return false,
    };
    let timestamp: i64 = match headers
        .get(gossip_auth::TIMESTAMP_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
    {
        Some(ts) => ts,
        None => return false,
    };
    gossip_auth::verify(secret, signature, timestamp, body, now_secs as i64)
}
