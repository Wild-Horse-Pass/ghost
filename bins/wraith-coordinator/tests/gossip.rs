//! Active → Standby gossip end-to-end test.
//!
//! Spins up two coordinators on real ephemeral ports, points Active's
//! `HttpGossipSink` at Standby, drives a `find_or_create` session
//! against Active, and asserts the Standby's `LiteSessionRegistry`
//! mirrors the new session.
//!
//! Real HTTP — `reqwest` inside the sink talks to `axum::serve` on
//! the Standby. This is the only path that exercises both halves of
//! the wire format end-to-end; the unit tests in `wraith-protocol`
//! cover `apply_event` semantics, and this test pins the JSON shape
//! and the receive endpoint.

use std::sync::Arc;
use std::time::Duration;

use bitcoin::Network;
use wraith_coordinator::gossip_http::HttpGossipSink;
use wraith_coordinator::{build_router, CoordinatorState};
use wraith_protocol::{DeterministicSessionIdGenerator, MockBondLedger, MockClock};

const TEST_FEE_ADDRESS: &str = "tb1q0xcqpzrky6eff2g52qdye53xkk9jxkvraulyla";

/// Build an Active coordinator that publishes via HTTP to `peer_url`.
async fn spawn_active_with_peer(peer_url: String) -> (String, Arc<CoordinatorState>) {
    let mut state = CoordinatorState::with_components(
        Network::Signet,
        Arc::new(MockClock::new(1_700_000_000)),
        Arc::new(DeterministicSessionIdGenerator::new()),
        Some(Arc::new(MockBondLedger::new())),
        Some(TEST_FEE_ADDRESS.to_string()),
        None,
    );
    let sink = HttpGossipSink::spawn(vec![peer_url], &tokio::runtime::Handle::current());
    state.sessions.set_gossip_sink(Box::new(sink));
    let state = Arc::new(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = build_router(state.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{}", addr), state)
}

/// Build a Standby coordinator (no outbound sink — pure receiver).
async fn spawn_standby() -> (String, Arc<CoordinatorState>) {
    let state = Arc::new(CoordinatorState::with_components(
        Network::Signet,
        Arc::new(MockClock::new(1_700_000_000)),
        Arc::new(DeterministicSessionIdGenerator::new()),
        Some(Arc::new(MockBondLedger::new())),
        Some(TEST_FEE_ADDRESS.to_string()),
        None,
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = build_router(state.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{}", addr), state)
}

/// Wait until `pred` returns true, polling every 25ms up to ~2s.
/// Async tasks need a moment to drain the gossip queue and complete
/// their reqwest call to the standby.
async fn poll_until<F: FnMut() -> bool>(mut pred: F) -> bool {
    for _ in 0..80 {
        if pred() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    pred()
}

#[tokio::test]
async fn active_session_creation_replicates_to_standby() {
    let (standby_url, standby_state) = spawn_standby().await;
    let (active_url, _active_state) = spawn_active_with_peer(standby_url).await;

    // Sanity: Standby starts empty.
    assert_eq!(standby_state.sessions.len(), 0);

    // Drive a session creation on the Active via its real HTTP API.
    // `find_or_create` publishes a `SessionCreated` gossip event; the
    // sink POSTs it to Standby's `/api/v1/internal/gossip` route.
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/session/find_or_create", active_url))
        .json(&serde_json::json!({
            "tier_id": "100k_sats",
            "session_type": "mix",
            "ghost_id": "test_wallet_a",
            "bond_id": "bond_a",
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(status.is_success(), "find_or_create failed: {} body={}", status, body);

    // Standby should have mirrored the new session within a moment.
    let mirrored = poll_until(|| standby_state.sessions.len() == 1).await;
    assert!(mirrored, "standby never observed the session");
}

#[tokio::test]
async fn solo_coordinator_with_no_peers_runs_fine() {
    // Regression guard: gossip is optional. With an empty peer list
    // the binary still boots and serves traffic.
    let state = Arc::new(CoordinatorState::with_components(
        Network::Signet,
        Arc::new(MockClock::new(1_700_000_000)),
        Arc::new(DeterministicSessionIdGenerator::new()),
        Some(Arc::new(MockBondLedger::new())),
        Some(TEST_FEE_ADDRESS.to_string()),
        None,
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = build_router(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // /health should still respond.
    let resp = reqwest::get(format!("http://{}/health", addr)).await.unwrap();
    assert!(resp.status().is_success());
}
