//! Tests that `WraithSessionClient::with_peers` rotates to a fallback
//! coordinator when the primary URL is unreachable.
//!
//! This is the wire-level half of task #77 (signer handover): if the
//! Active coordinator goes dark, the wallet must transparently route
//! to a Standby without operator intervention. The test proves the
//! rotation path triggers on connection-level errors but does NOT
//! trigger on HTTP error responses (which mean a coordinator answered).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use axum::{routing::post, Json, Router};
use bitcoin::Network;
use serde_json::{json, Value};
use wraith_wallet_core::wraith::{MixRequest, ParticipantUtxo, WraithClientError, WraithSessionClient};

/// Stub `/api/v1/session/find_or_create` that increments a counter on
/// each hit and returns a Filling-state session reply. We don't care
/// what happens after find_or_create — the test asserts on whether
/// THIS endpoint was reached, not whether the full mix succeeds.
async fn spawn_stub() -> (std::net::SocketAddr, Arc<AtomicU32>) {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();
    let app = Router::new().route(
        "/api/v1/session/find_or_create",
        post(move |Json(_body): Json<Value>| {
            let counter = counter_clone.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Json(json!({
                    "session": {
                        "session_id": "stub-session",
                        "tier_id": "100k_sats",
                        "denom_sats": 100_000,
                        "bond_amount_sats": 500,
                        "min_participants": 5,
                        "max_participants": 20,
                        "fill_window_secs": 300,
                        "current_state": "Filling",
                        "participant_count": 1,
                        "fees": {
                            "coord_fee_sats": 0,
                            "miner_fee_sats": 0,
                        },
                    }
                }))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    (addr, counter)
}

fn signet_addr_for(i: u8) -> String {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{Address, CompressedPublicKey};
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[i; 32]).unwrap();
    let cpk = CompressedPublicKey(sk.public_key(&secp));
    Address::p2wpkh(&cpk, Network::Signet).to_string()
}

fn fixture_request() -> MixRequest {
    MixRequest {
        tier_id: "100k_sats".into(),
        ghost_id: "rotation-test".into(),
        bond_id_placeholder: "placeholder".into(),
        utxo: ParticipantUtxo {
            txid: "11".repeat(32),
            vout: 0,
            value_sats: 200_000,
            scriptpubkey_hex: "deadbeef".into(),
        },
        change_address: Some(signet_addr_for(50)),
        mix_output_address: signet_addr_for(1),
    }
}

/// `bond_setup` shouldn't run — `prepare_mix` returns a coordinator
/// error before reaching it because our stub only handles
/// `/find_or_create`. Returns Ok regardless to avoid masking the
/// rotation behaviour we actually care about.
fn bond_setup_noop(
    _: &str,
    _: u64,
) -> impl std::future::Future<Output = Result<(), WraithClientError>> {
    async { Ok(()) }
}

#[tokio::test]
async fn rotates_to_peer_when_primary_unreachable() {
    let (addr, counter) = spawn_stub().await;
    let live_url = format!("http://{addr}");
    // Port 1 is well-known to refuse — connect-error path.
    let dead_url = "http://127.0.0.1:1".to_string();

    let client = WraithSessionClient::with_peers(
        dead_url,
        vec![live_url],
        Network::Signet,
    );

    // We expect this to FAIL — the stub only answers find_or_create —
    // but it must reach find_or_create on the peer at least once.
    let _ = client.prepare_mix(fixture_request(), bond_setup_noop).await;

    assert!(
        counter.load(Ordering::SeqCst) >= 1,
        "rotation must reach the live peer at least once"
    );
}

#[tokio::test]
async fn does_not_rotate_on_http_error() {
    // A coordinator that answers but rejects with 500 must NOT cause
    // failover — that means a coordinator IS reachable, and silently
    // moving to a different one would mask real bugs.
    let app = Router::new().route(
        "/api/v1/session/find_or_create",
        post(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom") }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let primary = format!("http://{addr}");

    let (peer_addr, peer_counter) = spawn_stub().await;
    let peer_url = format!("http://{peer_addr}");

    let client = WraithSessionClient::with_peers(
        primary,
        vec![peer_url],
        Network::Signet,
    );

    let result = client.prepare_mix(fixture_request(), bond_setup_noop).await;

    assert!(
        matches!(result, Err(WraithClientError::Coordinator { status: 500, .. })),
        "expected 500 from primary, got {result:?}"
    );
    assert_eq!(
        peer_counter.load(Ordering::SeqCst),
        0,
        "peer must NOT be hit when primary returns an HTTP error"
    );
}
