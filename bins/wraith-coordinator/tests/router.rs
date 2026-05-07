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

fn router() -> axum::Router {
    build_router(Arc::new(CoordinatorState::new(Network::Signet)))
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
