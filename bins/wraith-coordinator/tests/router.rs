//! End-to-end router tests. Builds the same Axum router `main()` builds
//! and exercises it via tower's `oneshot` plumbing — no port binding,
//! no flaky timing, just the request → handler → response path.

use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use bitcoin::Network;
use tower::ServiceExt;
use wraith_coordinator::{build_router, CoordinatorState};
use wraith_protocol::{DeterministicSessionIdGenerator, MockClock};

fn router() -> axum::Router {
    build_router(Arc::new(CoordinatorState::new(Network::Signet)))
}

/// Router backed by deterministic clock + session-id generator. Returns
/// the `Arc<CoordinatorState>` too so tests can inspect/manipulate the
/// shared state directly (advance the clock, peek at the registry, …).
fn deterministic_router(initial_unix: u64) -> (axum::Router, Arc<CoordinatorState>) {
    let state = Arc::new(CoordinatorState::with_components(
        Network::Signet,
        Arc::new(MockClock::new(initial_unix)),
        Arc::new(DeterministicSessionIdGenerator::new()),
    ));
    (build_router(state.clone()), state)
}

/// Build a JSON POST request — small ergonomics helper for the
/// find_or_create tests below.
fn post_json(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn health_endpoint_returns_200_with_expected_shape() {
    let response = router()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["service"], "wraith-coordinator");
    assert_eq!(json["network"], "signet");
    // version + uptime_secs present
    assert!(json["version"].is_string());
    assert!(json["uptime_secs"].is_number());
}

#[tokio::test]
async fn discover_endpoint_returns_full_tier_table() {
    let response = router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/pool/discover")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["network"], "signet");
    assert_eq!(json["pool_id"], "wraith-pool-signet");
    assert_eq!(json["service_fee_bps"], 50);
    assert_eq!(json["bond_bps"], 50);
    assert_eq!(json["fill_window_secs"], 300);

    let tiers = json["tiers"].as_array().expect("tiers must be an array");
    assert_eq!(tiers.len(), 4, "all four Lite tiers advertised");

    // Verify the smallest tier specifically — lock the wire shape so any
    // change to LiteTier's exposed values surfaces here.
    let smallest = tiers
        .iter()
        .find(|t| t["id"] == "100k_sats")
        .expect("100k_sats tier present");
    assert_eq!(smallest["denomination_sats"], 100_000);
    assert_eq!(smallest["min_participants"], 5);
    assert_eq!(smallest["max_participants"], 20);
    assert_eq!(smallest["bond_sats"], 500);
    assert_eq!(smallest["service_fee_sats"], 500);
}

#[tokio::test]
async fn discover_response_carries_network_in_pool_id() {
    let mainnet = build_router(Arc::new(CoordinatorState::new(Network::Bitcoin)));
    let response = mainnet
        .oneshot(
            Request::builder()
                .uri("/api/v1/pool/discover")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["network"], "mainnet");
    assert_eq!(json["pool_id"], "wraith-pool-mainnet");
}

#[tokio::test]
async fn unknown_path_returns_404() {
    let response = router()
        .oneshot(
            Request::builder()
                .uri("/this/does/not/exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// POST /api/v1/session/find_or_create
// ---------------------------------------------------------------------------

#[tokio::test]
async fn find_or_create_creates_a_new_session_when_registry_is_empty() {
    let (router, state) = deterministic_router(1_000_000);
    let response = router
        .oneshot(post_json(
            "/api/v1/session/find_or_create",
            serde_json::json!({
                "tier_id": "100k_sats",
                "ghost_id": "wallet-alice",
                "bond_id": "bond-aaaa",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["session"]["session_id"], "test-session-0000");
    assert_eq!(json["session"]["tier_id"], "100k_sats");
    assert_eq!(json["session"]["state"], "filling");
    assert_eq!(json["session"]["slots_filled"], 1);
    assert_eq!(json["session"]["slots_total"], 20);
    assert_eq!(json["session"]["fill_window_expires_at"], 1_000_000 + 300);
    assert_eq!(json["joined"], false, "creating, not joining");
    assert_eq!(json["bond_id"], "bond-aaaa");

    // Registry should now hold exactly one session.
    assert_eq!(state.sessions.len(), 1);
}

#[tokio::test]
async fn find_or_create_joins_an_existing_open_session() {
    let (router, _state) = deterministic_router(1_000_000);

    let body_for = |ghost: &str, bond: &str| {
        serde_json::json!({
            "tier_id": "100k_sats",
            "ghost_id": ghost,
            "bond_id": bond,
        })
    };

    let alice = router
        .clone()
        .oneshot(post_json(
            "/api/v1/session/find_or_create",
            body_for("wallet-alice", "bond-a"),
        ))
        .await
        .unwrap();
    assert_eq!(alice.status(), StatusCode::OK);
    let alice_body = to_bytes(alice.into_body(), 4096).await.unwrap();
    let alice_json: serde_json::Value = serde_json::from_slice(&alice_body).unwrap();
    let alice_session = alice_json["session"]["session_id"].as_str().unwrap().to_owned();

    let bob = router
        .oneshot(post_json(
            "/api/v1/session/find_or_create",
            body_for("wallet-bob", "bond-b"),
        ))
        .await
        .unwrap();
    assert_eq!(bob.status(), StatusCode::OK);
    let bob_body = to_bytes(bob.into_body(), 4096).await.unwrap();
    let bob_json: serde_json::Value = serde_json::from_slice(&bob_body).unwrap();

    // Both wallets land in the same session — slots are now 2.
    assert_eq!(bob_json["session"]["session_id"], alice_session);
    assert_eq!(bob_json["session"]["slots_filled"], 2);
    assert_eq!(bob_json["joined"], true, "second wallet joined, didn't create");
}

#[tokio::test]
async fn find_or_create_separates_distinct_tiers_into_distinct_sessions() {
    let (router, _state) = deterministic_router(1_000_000);

    let small = router
        .clone()
        .oneshot(post_json(
            "/api/v1/session/find_or_create",
            serde_json::json!({
                "tier_id": "100k_sats",
                "ghost_id": "wallet-small",
                "bond_id": "bond-small",
            }),
        ))
        .await
        .unwrap();
    let small_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(small.into_body(), 4096).await.unwrap()).unwrap();

    let big = router
        .oneshot(post_json(
            "/api/v1/session/find_or_create",
            serde_json::json!({
                "tier_id": "1m_sats",
                "ghost_id": "wallet-big",
                "bond_id": "bond-big",
            }),
        ))
        .await
        .unwrap();
    let big_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(big.into_body(), 4096).await.unwrap()).unwrap();

    assert_ne!(
        small_json["session"]["session_id"], big_json["session"]["session_id"],
        "distinct tiers must yield distinct sessions",
    );
    assert_eq!(small_json["session"]["tier_id"], "100k_sats");
    assert_eq!(big_json["session"]["tier_id"], "1m_sats");
}

#[tokio::test]
async fn find_or_create_rejects_unknown_tier_id_with_400() {
    let (router, _state) = deterministic_router(1_000_000);
    let response = router
        .oneshot(post_json(
            "/api/v1/session/find_or_create",
            serde_json::json!({
                "tier_id": "not_a_tier",
                "ghost_id": "wallet-alice",
                "bond_id": "bond-x",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "unknown_tier");
}

#[tokio::test]
async fn find_or_create_rejects_unknown_session_type_with_400() {
    let (router, _state) = deterministic_router(1_000_000);
    let response = router
        .oneshot(post_json(
            "/api/v1/session/find_or_create",
            serde_json::json!({
                "tier_id": "100k_sats",
                "session_type": "blender",
                "ghost_id": "wallet-alice",
                "bond_id": "bond-x",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "unknown_session_type");
}

#[tokio::test]
async fn find_or_create_rejects_duplicate_ghost_id_with_409() {
    let (router, _state) = deterministic_router(1_000_000);

    let body = serde_json::json!({
        "tier_id": "100k_sats",
        "ghost_id": "wallet-alice",
        "bond_id": "bond-a",
    });
    let first = router
        .clone()
        .oneshot(post_json("/api/v1/session/find_or_create", body.clone()))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    // Same ghost_id, second call — coordinator joins the same session
    // and rejects the duplicate registration.
    let dup = router
        .oneshot(post_json("/api/v1/session/find_or_create", body))
        .await
        .unwrap();
    assert_eq!(dup.status(), StatusCode::CONFLICT);
    let dup_body = to_bytes(dup.into_body(), 4096).await.unwrap();
    let dup_json: serde_json::Value = serde_json::from_slice(&dup_body).unwrap();
    assert_eq!(dup_json["error"], "already_registered");
}

#[tokio::test]
async fn find_or_create_rejects_blank_ghost_id_with_400() {
    let (router, _state) = deterministic_router(1_000_000);
    let response = router
        .oneshot(post_json(
            "/api/v1/session/find_or_create",
            serde_json::json!({
                "tier_id": "100k_sats",
                "ghost_id": "   ",
                "bond_id": "bond-a",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "missing_ghost_id");
}
