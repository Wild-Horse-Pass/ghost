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
/// destination + change destination in tests. Real bech32 with a
/// valid checksum so /outputs's address parser accepts it.
const TEST_FEE_ADDRESS: &str = "tb1q0xcqpzrky6eff2g52qdye53xkk9jxkvraulyla";

/// Five distinct valid signet P2WPKH addresses for the
/// outputs-over-submission test. Generated from `[i; 32]` secret keys
/// 1..=5 — deterministic so the strings are stable.
const FIVE_SIGNET_ADDRS: [&str; 5] = [
    "tb1q0xcqpzrky6eff2g52qdye53xkk9jxkvraulyla",
    "tb1qa0qwuze2h85zw7nqpsj3ga0z9geyrgwptrz29s",
    "tb1qg975h6gdx5mryeac72h6lj2nzygugxhyk6dnhr",
    "tb1q3zxmh4ue370cp48c9d8eeek43qhnzzhvz4t84j",
    "tb1qn454ga9rqwkx6ax309knw5hs0z2erz7jg4x4y7",
];

/// A sixth distinct valid signet P2WPKH address for the
/// outputs-full over-submission test (key = [6; 32]).
const SIXTH_SIGNET_ADDR: &str = "tb1q6jlzchtg6pl8sstn4m42uaz7xmnkhv3606kk9z";

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


// ---------------------------------------------------------------------------
// POST /api/v1/session/:id/nonce + /blind-sign — Schnorr blind signature (B/4b)
// ---------------------------------------------------------------------------

/// /nonce on a properly-locked session with an enrolled wallet returns
/// 200 with hex-encoded crypto material that's the right length.
#[tokio::test]
async fn nonce_returns_200_with_valid_shape() {
    let (router, state, ledger) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state, &ledger).await;
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/nonce"),
            serde_json::json!({ "ghost_id": "wallet-0" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let pubkey_hex = json["signing_pubkey"].as_str().unwrap();
    let key_id_hex = json["signing_key_id"].as_str().unwrap();
    let nonce_hex = json["nonce_point"].as_str().unwrap();
    let blind_sid_hex = json["blind_session_id"].as_str().unwrap();
    assert_eq!(pubkey_hex.len(), 66, "33-byte SEC1 compressed");
    assert_eq!(key_id_hex.len(), 64, "32-byte sha256");
    assert_eq!(nonce_hex.len(), 66, "33-byte SEC1 compressed");
    assert_eq!(blind_sid_hex.len(), 64, "32-byte session id");
}

#[tokio::test]
async fn nonce_returns_403_for_unenrolled_ghost_id() {
    let (router, state, ledger) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state, &ledger).await;
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/nonce"),
            serde_json::json!({ "ghost_id": "wallet-99" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "not_enrolled");
}

#[tokio::test]
async fn nonce_returns_409_for_filling_session() {
    let (router, _state, _ledger) = deterministic_router(1_000_000);
    let session_id = create_session_via_router(router.clone(), "wallet-a", "bond-a").await;
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/nonce"),
            serde_json::json!({ "ghost_id": "wallet-a" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "wrong_session_state");
}

#[tokio::test]
async fn nonce_returns_404_for_unknown_session() {
    let (router, _state, _ledger) = deterministic_router(1_000_000);
    let response = router
        .oneshot(post_json(
            "/api/v1/session/no-such-session/nonce",
            serde_json::json!({ "ghost_id": "x" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "session_not_found");
}

#[tokio::test]
async fn blind_sign_returns_400_when_no_signer_for_round() {
    // /blind-sign before any /nonce on this round → 400 no_active_signer.
    let (router, state, ledger) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state, &ledger).await;
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/blind-sign"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "blinded_challenge": "00".repeat(32),
                "blind_session_id": "00".repeat(32),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "no_active_signer");
}

#[tokio::test]
async fn blind_sign_returns_400_for_bad_hex() {
    let (router, state, ledger) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state, &ledger).await;
    // Prime a signer so we get past the no_active_signer gate.
    let _ = router
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/nonce"),
            serde_json::json!({ "ghost_id": "wallet-0" }),
        ))
        .await
        .unwrap();
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/blind-sign"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "blinded_challenge": "not-hex",
                "blind_session_id": "00".repeat(32),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "bad_blinded_challenge");
}

#[tokio::test]
async fn blind_sign_rejects_cross_participant_nonce_hijack() {
    let (router, state, ledger) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state, &ledger).await;

    // wallet-0 requests a nonce.
    let nonce_resp = router
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/nonce"),
            serde_json::json!({ "ghost_id": "wallet-0" }),
        ))
        .await
        .unwrap();
    assert_eq!(nonce_resp.status(), StatusCode::OK);
    let nonce_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(nonce_resp.into_body(), 4096).await.unwrap()).unwrap();
    let blind_sid = nonce_json["blind_session_id"].as_str().unwrap().to_string();

    // wallet-1 attempts to use wallet-0's nonce. Coordinator rejects.
    let bad_resp = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/blind-sign"),
            serde_json::json!({
                "ghost_id": "wallet-1",
                "blinded_challenge": "11".repeat(32),
                "blind_session_id": blind_sid,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(bad_resp.status(), StatusCode::FORBIDDEN);
    let bad_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(bad_resp.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(bad_json["error"], "blind_sign_rejected");
}

/// End-to-end happy path: wallet runs the full blind-sig protocol
/// against the coordinator and verifies the resulting unblinded
/// signature with `TokenVerifier`. Demonstrates that the two endpoints
/// implement the protocol correctly — the coordinator's signature is
/// a valid Schnorr sig on the wallet's chosen message and the
/// coordinator never saw the message.
#[tokio::test]
async fn blind_sign_full_round_trip_produces_valid_signature() {
    use secp256k1::PublicKey;
    use wraith_protocol::{
        BlindSignatureResponse, BlindingContext, PublicNonce, TokenVerifier,
    };

    let (router, state, ledger) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state, &ledger).await;

    // Step 1 — wallet asks coordinator for a fresh nonce.
    let nonce_resp = router
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/nonce"),
            serde_json::json!({ "ghost_id": "wallet-0" }),
        ))
        .await
        .unwrap();
    assert_eq!(nonce_resp.status(), StatusCode::OK);
    let nonce_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(nonce_resp.into_body(), 4096).await.unwrap()).unwrap();

    let signing_pubkey_bytes = hex::decode(nonce_json["signing_pubkey"].as_str().unwrap()).unwrap();
    let signer_session_id_bytes =
        hex::decode(nonce_json["signer_session_id"].as_str().unwrap()).unwrap();
    let signing_key_id_bytes =
        hex::decode(nonce_json["signing_key_id"].as_str().unwrap()).unwrap();
    let nonce_point_bytes = hex::decode(nonce_json["nonce_point"].as_str().unwrap()).unwrap();
    let blind_sid_bytes = hex::decode(nonce_json["blind_session_id"].as_str().unwrap()).unwrap();

    let coordinator_pubkey = PublicKey::from_slice(&signing_pubkey_bytes).expect("valid pubkey");
    let mut nonce_point_arr = [0u8; 33];
    nonce_point_arr.copy_from_slice(&nonce_point_bytes);
    let mut blind_sid_arr = [0u8; 32];
    blind_sid_arr.copy_from_slice(&blind_sid_bytes);
    let mut signing_key_id_arr = [0u8; 32];
    signing_key_id_arr.copy_from_slice(&signing_key_id_bytes);
    let mut signer_session_id_arr = [0u8; 32];
    signer_session_id_arr.copy_from_slice(&signer_session_id_bytes);

    let public_nonce = PublicNonce {
        nonce_point: nonce_point_arr,
        session_id: blind_sid_arr,
    };

    // Step 2 — wallet builds a blinding context over its own message
    // (the unblinded mix-output address it wants signed) and computes
    // the blinded challenge.
    let message = b"wallet-0 chose this output address".to_vec();
    let blinding = BlindingContext::new(message.clone(), &coordinator_pubkey, &public_nonce)
        .expect("blinding context");
    let blinded_challenge = blinding.create_blinded_challenge().expect("blinded challenge");

    // Step 3 — wallet posts the blinded challenge to /blind-sign.
    let sign_resp = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/blind-sign"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "blinded_challenge": hex::encode(blinded_challenge.challenge),
                "blind_session_id": hex::encode(blinded_challenge.session_id),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(sign_resp.status(), StatusCode::OK);
    let sign_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(sign_resp.into_body(), 4096).await.unwrap()).unwrap();
    let s_bytes_vec = hex::decode(sign_json["signature_scalar"].as_str().unwrap()).unwrap();
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&s_bytes_vec);

    let response = BlindSignatureResponse {
        signature_scalar: s_bytes,
        session_id: blind_sid_arr,
    };

    // Step 4 — wallet unblinds locally, then verifies. The verifier
    // sees only the unblinded signature on the wallet's chosen message,
    // and the verification ought to pass — proving the coordinator
    // signed something it never saw.
    let token = blinding.unblind(&response, signing_key_id_arr).expect("unblind");
    assert_eq!(token.message, message, "message preserved through unblind");

    // The verifier takes the SIGNER's session_id (not the key_id) and
    // re-derives the key_id internally to match `token.session_key_id`.
    let verifier = TokenVerifier::new(coordinator_pubkey, &signer_session_id_arr);
    let valid = verifier.verify(&token).expect("verify");
    assert!(
        valid,
        "unblinded signature must be a valid Schnorr sig on the wallet's message"
    );

    // Crucially: the coordinator never saw `message`. The blinded
    // challenge is c' = c + β where c = H(X || R' || message). The
    // coordinator returns s = k + c'*x without learning c (β was
    // generated locally and never transmitted). Unlinkability holds.
}


// ---------------------------------------------------------------------------
// POST /api/v1/session/:id/outputs — anonymous output submission (B/5a)
// ---------------------------------------------------------------------------

/// Drive a session all the way through to Signing state with all 5
/// participants having submitted /inputs. Returns the session_id; the
/// session is ready for /nonce + /blind-sign + /outputs.
async fn make_signing_session(
    router: axum::Router,
    state: &Arc<CoordinatorState>,
    ledger: &Arc<MockBondLedger>,
) -> String {
    let session_id = make_locked_session(router.clone(), state, ledger).await;
    // 5 participants submit /inputs → session advances to Signing.
    for i in 0..MIN_5 {
        let resp = router
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
        assert_eq!(resp.status(), StatusCode::OK, "inputs #{i}");
    }
    // Confirm we're now in Signing.
    let snapshot = state.sessions.get(&session_id).expect("present");
    assert!(matches!(
        snapshot.state,
        wraith_protocol::LiteSessionState::Signing
    ));
    session_id
}

/// One pass of the wallet-side blind-sig protocol: call /nonce, build
/// a `BlindingContext` over `message`, post the blinded challenge to
/// /blind-sign, return everything needed for an /outputs submission.
async fn run_blind_sig_for(
    router: axum::Router,
    session_id: &str,
    ghost_id: &str,
    message: Vec<u8>,
) -> (String, String) {
    use secp256k1::PublicKey;
    use wraith_protocol::{BlindSignatureResponse, BlindingContext, PublicNonce};

    let nonce_resp = router
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/nonce"),
            serde_json::json!({ "ghost_id": ghost_id }),
        ))
        .await
        .unwrap();
    assert_eq!(nonce_resp.status(), StatusCode::OK);
    let nj: serde_json::Value =
        serde_json::from_slice(&to_bytes(nonce_resp.into_body(), 4096).await.unwrap()).unwrap();

    let pubkey =
        PublicKey::from_slice(&hex::decode(nj["signing_pubkey"].as_str().unwrap()).unwrap())
            .unwrap();
    let mut nonce_point = [0u8; 33];
    nonce_point.copy_from_slice(&hex::decode(nj["nonce_point"].as_str().unwrap()).unwrap());
    let mut blind_sid = [0u8; 32];
    blind_sid.copy_from_slice(&hex::decode(nj["blind_session_id"].as_str().unwrap()).unwrap());
    let mut key_id = [0u8; 32];
    key_id.copy_from_slice(&hex::decode(nj["signing_key_id"].as_str().unwrap()).unwrap());

    let public_nonce = PublicNonce {
        nonce_point,
        session_id: blind_sid,
    };
    let ctx = BlindingContext::new(message, &pubkey, &public_nonce).unwrap();
    let blinded = ctx.create_blinded_challenge().unwrap();
    let blinded_nonce = ctx.blinded_nonce().serialize();

    let sign_resp = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/blind-sign"),
            serde_json::json!({
                "ghost_id": ghost_id,
                "blinded_challenge": hex::encode(blinded.challenge),
                "blind_session_id": hex::encode(blinded.session_id),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(sign_resp.status(), StatusCode::OK);
    let sj: serde_json::Value =
        serde_json::from_slice(&to_bytes(sign_resp.into_body(), 4096).await.unwrap()).unwrap();
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&hex::decode(sj["signature_scalar"].as_str().unwrap()).unwrap());

    let response = BlindSignatureResponse {
        signature_scalar: s_bytes,
        session_id: blind_sid,
    };
    let token = ctx.unblind(&response, key_id).unwrap();

    (
        hex::encode(blinded_nonce),
        hex::encode(token.signature_scalar),
    )
}

#[tokio::test]
async fn outputs_returns_404_for_unknown_session() {
    let (router, _state, _ledger) = deterministic_router(1_000_000);
    let response = router
        .oneshot(post_json(
            "/api/v1/session/no-such-session/outputs",
            serde_json::json!({
                "address": TEST_FEE_ADDRESS,
                "blinded_nonce_point": "00".repeat(33),
                "unblinded_signature_scalar": "00".repeat(32),
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
async fn outputs_returns_409_when_session_still_locked() {
    // /outputs only accepts in Signing state. A session in Locked
    // (post-/nonce, pre-all-/inputs) is not yet accepting outputs.
    let (router, state, ledger) = deterministic_router(1_000_000);
    let session_id = make_locked_session(router.clone(), &state, &ledger).await;
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/outputs"),
            serde_json::json!({
                "address": TEST_FEE_ADDRESS,
                "blinded_nonce_point": "00".repeat(33),
                "unblinded_signature_scalar": "00".repeat(32),
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
async fn outputs_rejects_address_for_wrong_network() {
    let (router, state, ledger) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state, &ledger).await;
    // Need a signer to exist before signature checks would matter,
    // but address parsing happens first — exercise that path with
    // a mainnet-format address against this signet coordinator.
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/outputs"),
            serde_json::json!({
                // Mainnet bech32 prefix (`bc1`) not valid for signet.
                "address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                "blinded_nonce_point": "00".repeat(33),
                "unblinded_signature_scalar": "00".repeat(32),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "wrong_network");
}

#[tokio::test]
async fn outputs_rejects_when_no_signer_initialised() {
    // Session in Signing but nobody ever called /nonce, so no signer
    // exists. /outputs has nothing to verify against.
    let (router, state, ledger) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state, &ledger).await;
    // Sanity: signers map is empty.
    assert!(state
        .signers
        .lock()
        .unwrap()
        .get(&session_id)
        .is_none());

    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/outputs"),
            serde_json::json!({
                "address": TEST_FEE_ADDRESS,
                "blinded_nonce_point": "00".repeat(33),
                "unblinded_signature_scalar": "00".repeat(32),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "no_active_signer");
}

#[tokio::test]
async fn outputs_rejects_invalid_signature_with_403() {
    let (router, state, ledger) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state, &ledger).await;
    // Prime the signer so the no_active_signer gate doesn't fire.
    let _ = router
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/nonce"),
            serde_json::json!({ "ghost_id": "wallet-0" }),
        ))
        .await
        .unwrap();
    // Submit a syntactically-valid but cryptographically-junk sig.
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/outputs"),
            serde_json::json!({
                "address": TEST_FEE_ADDRESS,
                // 33-byte point that's actually a valid SEC1 generator-G
                // serialisation (not zero, which from_slice rejects).
                "blinded_nonce_point": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "unblinded_signature_scalar": "01".repeat(32),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "verification_failed");
}

#[tokio::test]
async fn outputs_full_round_trip_accepts_valid_signature() {
    let (router, state, ledger) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state, &ledger).await;

    let address = TEST_FEE_ADDRESS.to_string();
    let (blinded_nonce_hex, unblinded_sig_hex) = run_blind_sig_for(
        router.clone(),
        &session_id,
        "wallet-0",
        address.as_bytes().to_vec(),
    )
    .await;

    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/outputs"),
            serde_json::json!({
                "address": address,
                "blinded_nonce_point": blinded_nonce_hex,
                "unblinded_signature_scalar": unblinded_sig_hex,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["session_id"], session_id);
    assert_eq!(json["state"], "signing");
    assert_eq!(json["outputs_collected"], 1);
    assert_eq!(json["enrolled_count"], 5);
}

#[tokio::test]
async fn outputs_rejects_duplicate_address_with_409() {
    let (router, state, ledger) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state, &ledger).await;

    let address = TEST_FEE_ADDRESS.to_string();
    let (n1, s1) = run_blind_sig_for(
        router.clone(),
        &session_id,
        "wallet-0",
        address.as_bytes().to_vec(),
    )
    .await;

    let body = |bn: &str, us: &str| {
        serde_json::json!({
            "address": &address,
            "blinded_nonce_point": bn,
            "unblinded_signature_scalar": us,
        })
    };

    let first = router
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/outputs"),
            body(&n1, &s1),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    // Second wallet runs a fresh blind-sig over the SAME address.
    // Both signatures verify, but the coordinator refuses to record
    // the duplicate.
    let (n2, s2) = run_blind_sig_for(
        router.clone(),
        &session_id,
        "wallet-1",
        address.as_bytes().to_vec(),
    )
    .await;
    let second = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/outputs"),
            body(&n2, &s2),
        ))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);
    let json: serde_json::Value =
        serde_json::from_slice(&to_bytes(second.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(json["error"], "duplicate_output");
}

#[tokio::test]
async fn outputs_rejects_over_submission_with_409() {
    // 5 distinct outputs accepted, then a sixth with a fresh address
    // fails because the round set is full.
    let (router, state, ledger) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state, &ledger).await;

    // Five distinct signet P2WPKH addresses to accept.
    let addrs = FIVE_SIGNET_ADDRS;
    for (i, a) in addrs.iter().enumerate() {
        let (bn, sg) = run_blind_sig_for(
            router.clone(),
            &session_id,
            &format!("wallet-{i}"),
            a.as_bytes().to_vec(),
        )
        .await;
        let resp = router
            .clone()
            .oneshot(post_json(
                &format!("/api/v1/session/{session_id}/outputs"),
                serde_json::json!({
                    "address": a,
                    "blinded_nonce_point": bn,
                    "unblinded_signature_scalar": sg,
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "address {i}");
    }

    // Sixth submission (fresh address, fresh blind sig from wallet-0
    // again — they could theoretically request multiple nonces, the
    // rate limit allows it). Should be rejected because outputs is full.
    let extra_addr = SIXTH_SIGNET_ADDR;
    let (bn, sg) = run_blind_sig_for(
        router.clone(),
        &session_id,
        "wallet-0",
        extra_addr.as_bytes().to_vec(),
    )
    .await;
    let resp = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/outputs"),
            serde_json::json!({
                "address": extra_addr,
                "blinded_nonce_point": bn,
                "unblinded_signature_scalar": sg,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let json: serde_json::Value =
        serde_json::from_slice(&to_bytes(resp.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(json["error"], "outputs_full");
}
