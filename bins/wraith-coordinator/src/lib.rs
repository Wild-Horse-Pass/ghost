//! Wraith Lite v1 — coordinator library surface.
//!
//! Most of the coordinator runs as a binary (`bins/wraith-coordinator/
//! src/main.rs`). This lib target exists so integration tests under
//! `tests/` can reach `build_router` + `CoordinatorState` without
//! shelling out to a real process. Production code uses the binary;
//! tests use this lib.

use std::sync::Arc;

use axum::Router;

pub mod api;
pub mod state;

pub use state::CoordinatorState;

/// Construct the Axum router for a given coordinator state. Pure
/// function so tests can build it deterministically.
pub fn build_router(state: Arc<CoordinatorState>) -> Router {
    Router::new()
        .route("/health", axum::routing::get(api::health::get))
        .route(
            "/api/v1/pool/discover",
            axum::routing::get(api::discover::get),
        )
        .route(
            "/api/v1/session/find_or_create",
            axum::routing::post(api::find_or_create::post),
        )
        .route(
            "/api/v1/session/:session_id",
            axum::routing::get(api::session_status::get),
        )
        .with_state(state)
}
