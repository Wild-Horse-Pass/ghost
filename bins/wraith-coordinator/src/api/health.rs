//! `GET /health` — liveness + version + uptime.
//!
//! Used by load balancers, deployment scripts, and `wraith doctor` to
//! confirm a coordinator is reachable and answering. Always returns
//! 200; never holds locks; never blocks. If you can't get a response
//! to this, the process is wedged.

use std::sync::Arc;
use std::time::SystemTime;

use axum::{extract::State, Json};
use serde::Serialize;

use crate::state::CoordinatorState;

#[derive(Serialize)]
pub struct HealthResponse {
    /// `wraith-coordinator` — useful for log/diagnostic correlation
    /// when multiple services share a host.
    pub service: &'static str,
    /// Coordinator binary version (cargo package version).
    pub version: &'static str,
    /// Network name, lowercase: `mainnet` / `signet` / `testnet` / `regtest`.
    pub network: &'static str,
    /// Seconds since the coordinator process started.
    pub uptime_secs: u64,
}

pub async fn get(State(state): State<Arc<CoordinatorState>>) -> Json<HealthResponse> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(state.started_at);
    Json(HealthResponse {
        service: "wraith-coordinator",
        version: env!("CARGO_PKG_VERSION"),
        network: state.network_name(),
        uptime_secs: now.saturating_sub(state.started_at),
    })
}
