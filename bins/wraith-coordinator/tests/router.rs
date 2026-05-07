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
use wraith_protocol::{DeterministicSessionIdGenerator, MockBondLedger, MockClock};

/// Signet P2WPKH address used as the placeholder coordinator fee
/// destination in tests. Address validation is a build-time concern;
/// for /inputs validation alone the string just needs to be present.
const TEST_FEE_ADDRESS: &str = "tb1qsdvdgnp5ckj5d8z9wnz4tmkx7fdrfgnktdv60d";

fn router() -> axum::Router {
    build_router(Arc::new(CoordinatorState::new(Network::Signet)))
}

/// Router backed by deterministic clock + session-id generator,
/// MockBondLedger, and a placeholder fee address. Returns:
///   - the router
///   - the shared `Arc<CoordinatorState>` for direct inspection
///   - the `Arc<MockBondLedger>` so tests can pre-escrow bonds before
///     hitting `/inputs`. The same Arc lives inside `state.bond_ledger`,
///     so escrows on it are visible to the handler.
fn deterministic_router(
    initial_unix: u64,
) -> (axum::Router, Arc<CoordinatorState>, Arc<MockBondLedger>) {
    deterministic_router_full(initial_unix, true, true)
}

/// Variant that lets tests opt out of the bond ledger (503 path) or
/// the fee address (Mix-needs-fee-address path). Returns the ledger as
/// `Option` so tests can detect when it's absent.
fn deterministic_router_full(
    initial_unix: u64,
    install_ledger: bool,
    install_fee_address: bool,
) -> (axum::Router, Arc<CoordinatorState>, Arc<MockBondLedger>) {
    // Always construct a ledger Arc so the test helper can return it;
    // when `install_ledger == false` the state simply doesn't hold a
    // reference to it.
    let ledger = Arc::new(MockBondLedger::new());
    let bond_ledger = if install_ledger {
        Some(ledger.clone() as Arc<dyn wraith_protocol::BondLedger>)
    } else {
        None
    };
    let state = Arc::new(CoordinatorState::with_components(
        Network::Signet,
        Arc::new(MockClock::new(initial_unix)),
        Arc::new(DeterministicSessionIdGenerator::new()),
        bond_ledger,
        install_fee_address.then(|| TEST_FEE_ADDRESS.to_string()),
    ));
    (build_router(state.clone()), state, ledger)
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
    let (router, state, _ledger) = deterministic_router(1_000_000);
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
    let (router, _state, _ledger) = deterministic_router(1_000_000);

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
    let (router, _state, _ledger) = deterministic_router(1_000_000);

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
    let (router, _state, _ledger) = deterministic_router(1_000_000);
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
    let (router, _state, _ledger) = deterministic_router(1_000_000);
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
    let (router, _state, _ledger) = deterministic_router(1_000_000);

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
    let (router, _state, _ledger) = deterministic_router(1_000_000);
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


// ---------------------------------------------------------------------------
// GET /api/v1/session/{id} — status polling
// ---------------------------------------------------------------------------

/// Helper — runs find_or_create on the given router and returns the
/// session_id from the response.
async fn create_session_via_router(router: axum::Router, ghost: &str, bond: &str) -> String {
    let response = router
        .oneshot(post_json(
            "/api/v1/session/find_or_create",
            serde_json::json!({
                "tier_id": "100k_sats",
                "ghost_id": ghost,
                "bond_id": bond,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    json["session"]["session_id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn session_status_returns_200_with_descriptor_for_known_session() {
    let (router, _state, _ledger) = deterministic_router(1_000_000);
    let session_id = create_session_via_router(router.clone(), "wallet-a", "bond-a").await;

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/session/{session_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["session"]["session_id"], session_id);
    assert_eq!(json["session"]["tier_id"], "100k_sats");
    assert_eq!(json["session"]["state"], "filling");
    assert_eq!(json["session"]["slots_filled"], 1);
    assert_eq!(json["session"]["fill_window_expires_at"], 1_000_000 + 300);
}

#[tokio::test]
async fn session_status_returns_404_for_unknown_session() {
    let (router, _state, _ledger) = deterministic_router(1_000_000);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/session/no-such-session")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "session_not_found");
}

#[tokio::test]
async fn session_status_reflects_fill_window_expiry_after_clock_advance() {
    // 100k_sats tier needs 5 to lock; we'll add 1 then advance past
    // the fill window so the registry's tick rolls Filling → Failed
    // (FillWindowExpired). Status should report "failed".
    let mock_clock = Arc::new(MockClock::new(1_000_000));
    let state = Arc::new(CoordinatorState::with_components(
        Network::Signet,
        mock_clock.clone(),
        Arc::new(DeterministicSessionIdGenerator::new()),
        Some(Arc::new(MockBondLedger::new())),
        Some(TEST_FEE_ADDRESS.to_string()),
    ));
    let router = build_router(state.clone());

    let session_id = create_session_via_router(router.clone(), "lonely-wallet", "bond-x").await;
    // Clock advances past the fill window (300s) without enough joiners.
    mock_clock.advance(301);

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/session/{session_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["session"]["state"], "failed",
        "fill window expired without quorum should surface as failed",
    );
    assert!(
        json["session"]["fill_window_expires_at"].is_null(),
        "fill_window_expires_at should be cleared once not in Filling",
    );
}


// ---------------------------------------------------------------------------
// POST /api/v1/session/:id/inputs — commit phase (B/4a, validation only)
// ---------------------------------------------------------------------------

/// Min-N for 100k_sats — 5. Anything below this won't reach Locked.
const MIN_5: usize = 5;

/// Per-participant minimum input for 100k_sats Mix at the default fee rate.
/// Computed from: denom 100_000 + service_fee 500 + ceil((5*58 + 12*43)*10/5)
/// = 100_000 + 500 + 1612 = 102_112. Same number the handler computes.
const MIN_INPUT_100K_MIX: u64 = 102_112;

/// Drive 5 wallets through /find_or_create, escrow a bond per wallet,
/// then advance the clock past the fill window so the registry's tick
/// transitions Filling → Locked. Returns the session_id.
async fn make_locked_session(
    router: axum::Router,
    state: &Arc<CoordinatorState>,
    ledger: &Arc<MockBondLedger>,
) -> String {
    // Enrol 5 distinct wallets.
    let mut session_id: Option<String> = None;
    for i in 0..MIN_5 {
        let resp = router
            .clone()
            .oneshot(post_json(
                "/api/v1/session/find_or_create",
                serde_json::json!({
                    "tier_id": "100k_sats",
                    "ghost_id": format!("wallet-{i}"),
                    "bond_id": format!("placeholder-{i}"),
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "find_or_create #{i}");
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let sid = json["session"]["session_id"].as_str().unwrap().to_owned();
        if session_id.is_none() {
            session_id = Some(sid.clone());
        } else {
            assert_eq!(session_id.as_deref(), Some(sid.as_str()));
        }
    }
    let session_id = session_id.expect("at least one find_or_create succeeded");

    // Escrow a real bond per wallet against this session.
    for i in 0..MIN_5 {
        ledger.escrow(format!("wallet-{i}"), &session_id, 500);
    }

    // 100k_sats has min=5 but max=20, so 5 joiners doesn't auto-lock —
    // the registry would normally wait for the fill window to expire
    // and then run tick(). We can't reach through `Arc<dyn Clock>` to
    // advance the underlying MockClock, so we drive the same end state
    // via the gossip path that production tick + standby failover both
    // use.
    state
        .sessions
        .apply_event(wraith_protocol::SessionGossipEvent::StateChanged {
            session_id: session_id.clone(),
            new_state: wraith_protocol::LiteSessionState::Locked,
        })
        .expect("apply Locked");

    session_id
}

#[tokio::test]
async fn inputs_returns_503_when_bond_ledger_not_configured() {
    // No ledger configured; even submitting against an existing locked
    // session fails fast with a clear error.
    let (router, state, _unused_ledger) = deterministic_router_full(1_000_000, false, true);
    // Manually create a locked session via gossip — same shortcut
    // make_locked_session uses, but inline because no real bond
    // ledger is available to escrow against.
    state
        .sessions
        .apply_event(wraith_protocol::SessionGossipEvent::SessionCreated {
            session: wraith_protocol::LiteSession {
                session_id: "manual-session".into(),
                tier: wraith_protocol::LiteTier::Denom100kSats,
                session_type: wraith_protocol::SessionType::Mix,
                created_at: 1_000_000,
                state: wraith_protocol::LiteSessionState::Locked,
                participants: vec![wraith_protocol::LiteSessionParticipant {
                    ghost_id: "wallet-x".into(),
                    bond_id: wraith_protocol::BondId::new("placeholder"),
                    registered_at: 1_000_000,
                }],
            },
        })
        .unwrap();

    let response = router
        .oneshot(post_json(
            "/api/v1/session/manual-session/inputs",
            serde_json::json!({
                "ghost_id": "wallet-x",
                "input": {
                    "txid": "00".repeat(32),
                    "vout": 0,
                    "value_sats": MIN_INPUT_100K_MIX,
                    "scriptpubkey_hex": "deadbeef",
                },
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "ledger_not_configured");
}

#[tokio::test]
async fn inputs_returns_404_for_unknown_session() {
    let (router, _state, _ledger) = deterministic_router(1_000_000);
    let response = router
        .oneshot(post_json(
            "/api/v1/session/no-such-session/inputs",
            serde_json::json!({
                "ghost_id": "wallet-x",
                "input": {
                    "txid": "00".repeat(32),
                    "vout": 0,
                    "value_sats": MIN_INPUT_100K_MIX,
                    "scriptpubkey_hex": "deadbeef",
                },
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "session_not_found");
}

#[tokio::test]
async fn inputs_returns_409_when_session_still_filling() {
    let (router, _state, _ledger) = deterministic_router(1_000_000);
    let session_id = create_session_via_router(router.clone(), "wallet-a", "bond-a").await;
    // Session is in Filling. /inputs should reject.
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            serde_json::json!({
                "ghost_id": "wallet-a",
                "input": {
                    "txid": "00".repeat(32),
                    "vout": 0,
                    "value_sats": MIN_INPUT_100K_MIX,
                    "scriptpubkey_hex": "deadbeef",
                },
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "wrong_session_state");
}

#[tokio::test]
async fn inputs_returns_403_for_unenrolled_ghost_id() {
    let (router, state, ledger) = deterministic_router(1_000_000);
    let session_id = make_locked_session(router.clone(), &state, &ledger).await;
    // wallet-99 is not on the participant list.
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            serde_json::json!({
                "ghost_id": "wallet-99",
                "input": {
                    "txid": "00".repeat(32),
                    "vout": 0,
                    "value_sats": MIN_INPUT_100K_MIX,
                    "scriptpubkey_hex": "deadbeef",
                },
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "not_enrolled");
}

#[tokio::test]
async fn inputs_returns_402_when_bond_missing_in_ledger() {
    // A locked session with all 5 enrolled but NO ledger escrows.
    // /inputs should fail with bond_not_found.
    let (router, state, ledger) = deterministic_router(1_000_000);
    // Manually construct a locked session whose enrolled wallet has
    // no bond escrowed in the (initially-empty) ledger.
    state
        .sessions
        .apply_event(wraith_protocol::SessionGossipEvent::SessionCreated {
            session: wraith_protocol::LiteSession {
                session_id: "no-bond-session".into(),
                tier: wraith_protocol::LiteTier::Denom100kSats,
                session_type: wraith_protocol::SessionType::Mix,
                created_at: 1_000_000,
                state: wraith_protocol::LiteSessionState::Locked,
                participants: vec![wraith_protocol::LiteSessionParticipant {
                    ghost_id: "wallet-no-bond".into(),
                    bond_id: wraith_protocol::BondId::new("placeholder"),
                    registered_at: 1_000_000,
                }],
            },
        })
        .unwrap();
    assert!(ledger.is_empty(), "test sanity: ledger really has no bonds");

    let response = router
        .oneshot(post_json(
            "/api/v1/session/no-bond-session/inputs",
            serde_json::json!({
                "ghost_id": "wallet-no-bond",
                "input": {
                    "txid": "00".repeat(32),
                    "vout": 0,
                    "value_sats": MIN_INPUT_100K_MIX,
                    "scriptpubkey_hex": "deadbeef",
                },
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "bond_not_found");
}

#[tokio::test]
async fn inputs_rejects_input_below_minimum_with_400() {
    let (router, state, ledger) = deterministic_router(1_000_000);
    let session_id = make_locked_session(router.clone(), &state, &ledger).await;
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "input": {
                    "txid": "00".repeat(32),
                    "vout": 0,
                    // 1000 sats well below the minimum 102_112.
                    "value_sats": 1_000,
                    "scriptpubkey_hex": "deadbeef",
                },
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "insufficient_input");
}

#[tokio::test]
async fn inputs_rejects_surplus_above_dust_without_change_address() {
    let (router, state, ledger) = deterministic_router(1_000_000);
    let session_id = make_locked_session(router.clone(), &state, &ledger).await;
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "input": {
                    "txid": "00".repeat(32),
                    "vout": 0,
                    // Big surplus (~98k sats over min) but no change address.
                    "value_sats": 200_000,
                    "scriptpubkey_hex": "deadbeef",
                },
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "missing_change_address");
}

#[tokio::test]
async fn inputs_accepts_exact_minimum_without_change_address() {
    // Exact-minimum input (no surplus) is fine without a change address.
    let (router, state, ledger) = deterministic_router(1_000_000);
    let session_id = make_locked_session(router.clone(), &state, &ledger).await;
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "input": {
                    "txid": "00".repeat(32),
                    "vout": 0,
                    "value_sats": MIN_INPUT_100K_MIX,
                    "scriptpubkey_hex": "deadbeef",
                },
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["session_id"], session_id);
    assert_eq!(json["state"], "locked", "1/5 submitted; not yet Signing");
    assert_eq!(json["submitted_count"], 1);
    assert_eq!(json["enrolled_count"], 5);
    assert!(json["blind_signature"].is_null(), "B/4a does not sign");
}

#[tokio::test]
async fn inputs_advances_session_to_signing_when_all_submit() {
    let (router, state, ledger) = deterministic_router(1_000_000);
    let session_id = make_locked_session(router.clone(), &state, &ledger).await;
    for i in 0..MIN_5 {
        let response = router
            .clone()
            .oneshot(post_json(
                &format!("/api/v1/session/{session_id}/inputs"),
                serde_json::json!({
                    "ghost_id": format!("wallet-{i}"),
                    "input": {
                        "txid": "11".repeat(32),
                        "vout": i as u32,
                        "value_sats": 200_000,
                        "scriptpubkey_hex": "deadbeef",
                    },
                    "change_address": TEST_FEE_ADDRESS,
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "submission #{i}");
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let expected_state = if i + 1 == MIN_5 { "signing" } else { "locked" };
        assert_eq!(json["state"], expected_state, "after submission {i}");
        assert_eq!(json["submitted_count"], (i as u32) + 1);
    }
    // Final session state in the registry confirms the transition.
    let final_session = state.sessions.get(&session_id).expect("session present");
    assert!(matches!(
        final_session.state,
        wraith_protocol::LiteSessionState::Signing
    ));
}

#[tokio::test]
async fn inputs_idempotent_on_resubmission() {
    // Wallet retries with a different input; the latest submission
    // wins and the count doesn't double-up.
    let (router, state, ledger) = deterministic_router(1_000_000);
    let session_id = make_locked_session(router.clone(), &state, &ledger).await;
    let body = |sats: u64| {
        serde_json::json!({
            "ghost_id": "wallet-0",
            "input": {
                "txid": "00".repeat(32),
                "vout": 0,
                "value_sats": sats,
                "scriptpubkey_hex": "deadbeef",
            },
            "change_address": TEST_FEE_ADDRESS,
        })
    };
    let first = router
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            body(200_000),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(first.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(first_json["submitted_count"], 1);

    let second = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            body(300_000),
        ))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    let second_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(second.into_body(), 4096).await.unwrap()).unwrap();
    // Still one submission, not two — the duplicate replaced the first.
    assert_eq!(second_json["submitted_count"], 1);
}
