//! Integration test for `GhostPayClient::scan_utxos`. Spins up an
//! axum stub that mimics ghost-pay's `POST /api/v1/utxos/scan`,
//! drives the real wallet client against it, and asserts:
//!
//! 1. the request body shape (addresses + min_confirmations)
//! 2. the `X-Internal-Auth` header is set when the client was
//!    built with `with_internal_secret(...)`, and absent otherwise
//! 3. the response parses into the wallet-side
//!    `ScanUtxosResponse` shape with all fields preserved.
//!
//! This is the contract test for the wallet-half of the L1 UTXO
//! scanner. The ghost-pay server-half has its own `parse_addr_from_desc`
//! tests; the bitcoind-side wire is covered by
//! `scripts/regtest-l1-scan-demo.sh`. Together they form the test
//! pyramid for the new endpoint.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use serde_json::{json, Value};
use wraith_wallet_core::chain::GhostPayClient;

#[derive(Clone)]
struct StubState {
    expect_auth: Arc<AtomicBool>,
    /// True iff the most recent request carried X-Internal-Auth.
    last_had_auth: Arc<AtomicBool>,
    /// True iff the most recent request body shape matched.
    last_body_ok: Arc<AtomicBool>,
}

async fn handle_scan(
    State(state): State<StubState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let had_auth = headers.get("x-internal-auth").is_some();
    state.last_had_auth.store(had_auth, Ordering::SeqCst);
    if state.expect_auth.load(Ordering::SeqCst) && !had_auth {
        return Err((StatusCode::UNAUTHORIZED, "missing X-Internal-Auth".into()));
    }
    let body_ok = body
        .get("addresses")
        .and_then(Value::as_array)
        .map(|a| !a.is_empty())
        .unwrap_or(false)
        && body
            .get("min_confirmations")
            .and_then(Value::as_u64)
            .is_some();
    state.last_body_ok.store(body_ok, Ordering::SeqCst);

    Ok(Json(json!({
        "utxos": [
            {
                "txid": "11".repeat(32),
                "vout": 0,
                "amount_sats": 500_000,
                "scriptpubkey_hex": "5120abcd",
                "address": "bcrt1qfundedaddr",
                "confirmations": 6,
                "height": 105,
            }
        ],
        "total_sats": 500_000,
        "chain_height": 110,
    })))
}

async fn spawn_stub(expect_auth: bool) -> (std::net::SocketAddr, StubState) {
    let state = StubState {
        expect_auth: Arc::new(AtomicBool::new(expect_auth)),
        last_had_auth: Arc::new(AtomicBool::new(false)),
        last_body_ok: Arc::new(AtomicBool::new(false)),
    };
    let app = Router::new()
        .route("/api/v1/utxos/scan", post(handle_scan))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    (addr, state)
}

#[tokio::test]
async fn scan_utxos_round_trips_with_auth() {
    let (addr, stub) = spawn_stub(true).await;
    let base = format!("http://{addr}");
    let client = GhostPayClient::new(base).with_internal_secret("shh-it-is-a-secret");

    let result = client
        .scan_utxos(&["bcrt1qfundedaddr".to_string()], 1)
        .await
        .expect("scan_utxos must succeed");

    assert_eq!(result.utxos.len(), 1);
    let u = &result.utxos[0];
    assert_eq!(u.amount_sats, 500_000);
    assert_eq!(u.scriptpubkey_hex, "5120abcd");
    assert_eq!(u.address.as_deref(), Some("bcrt1qfundedaddr"));
    assert_eq!(u.confirmations, 6);
    assert_eq!(u.height, 105);
    assert_eq!(result.total_sats, 500_000);
    assert_eq!(result.chain_height, 110);

    assert!(
        stub.last_had_auth.load(Ordering::SeqCst),
        "expected X-Internal-Auth on the request"
    );
    assert!(
        stub.last_body_ok.load(Ordering::SeqCst),
        "request body shape mismatch"
    );
}

#[tokio::test]
async fn scan_utxos_omits_auth_header_when_unset() {
    let (addr, stub) = spawn_stub(false).await;
    let base = format!("http://{addr}");
    // No with_internal_secret — the header must not appear.
    let client = GhostPayClient::new(base);

    let _ = client
        .scan_utxos(&["bcrt1qaddr".to_string()], 0)
        .await
        .expect("scan_utxos must succeed (stub doesn't enforce auth)");

    assert!(
        !stub.last_had_auth.load(Ordering::SeqCst),
        "X-Internal-Auth must not be sent when no secret is configured"
    );
}

#[tokio::test]
async fn scan_utxos_surfaces_4xx_as_backend_error() {
    let (addr, _stub) = spawn_stub(true).await;
    let base = format!("http://{addr}");
    // Build the client WITHOUT a secret — the stub is configured to
    // require auth, so we expect a 401 surfaced as ChainError::Backend.
    let client = GhostPayClient::new(base);

    let err = client
        .scan_utxos(&["bcrt1qaddr".to_string()], 0)
        .await
        .expect_err("must error when stub returns 401");

    let msg = format!("{err}");
    assert!(
        msg.contains("401"),
        "expected 401 to bubble through, got: {msg}"
    );
}
