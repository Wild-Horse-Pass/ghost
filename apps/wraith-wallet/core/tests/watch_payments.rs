//! End-to-end wiring test for the persistent session's payment broadcast.
//!
//! Spins up an in-process axum mock that speaks just enough of the GSP
//! WebSocket protocol to (a) authenticate a client, (b) reply to GetBalance,
//! and (c) push a single synthetic BIP-352 CandidateTransaction crafted to
//! match a freshly generated GhostKeys.
//!
//! Then it spawns the real `session::run` task against that mock, subscribes
//! via `SessionHandle::subscribe_payments()`, and asserts the detection lands
//! on the broadcast channel within a small timeout.
//!
//! This is the contract test for `subscribe_payments` — if it goes red, the
//! daemon's `WatchPayments` push will silently stop reaching clients.

use std::time::Duration;

use axum::{
    extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
    routing::get,
    Router,
};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use ghost_gsp_proto::{CandidateOutput, ClientMessage, ServerMessage};
use ghost_keys::{derive_payment_address_v2, derive_shared_secret, GhostKeys};
use rand::RngCore;
use wraith_wallet_core::gsp::spawn_session;

async fn handle_ws(mut socket: WebSocket, candidate: ServerMessage) {
    while let Some(Ok(frame)) = socket.recv().await {
        let text = match frame {
            WsMessage::Text(t) => t,
            WsMessage::Close(_) => return,
            _ => continue,
        };
        let msg: ClientMessage = match serde_json::from_str(&text) {
            Ok(m) => m,
            Err(_) => continue,
        };
        match msg {
            ClientMessage::Authenticate { .. } => {
                let auth = ServerMessage::AuthResult {
                    success: true,
                    wallet_id: Some("mock-wallet".into()),
                    error: None,
                };
                let _ = socket
                    .send(WsMessage::Text(serde_json::to_string(&auth).unwrap()))
                    .await;
            }
            ClientMessage::GetBalance { .. } => {
                let bal = ServerMessage::BalanceUpdate {
                    confirmed: 0,
                    unconfirmed: 0,
                    locked: 0,
                };
                let _ = socket
                    .send(WsMessage::Text(serde_json::to_string(&bal).unwrap()))
                    .await;
                // After the initial GetBalance round-trip the session enters
                // its main loop. Push the synthetic candidate exactly once.
                let _ = socket
                    .send(WsMessage::Text(serde_json::to_string(&candidate).unwrap()))
                    .await;
            }
            // Anything else (Pings, SubscribeSilentPayments, etc.) we just
            // accept silently — the test only cares about the candidate path.
            _ => {}
        }
    }
}

fn build_synthetic_candidate(keys: &GhostKeys) -> ServerMessage {
    let secp = Secp256k1::new();
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let eph_secret = SecretKey::from_slice(&bytes).expect("nonzero scalar");
    let ephemeral_pub = PublicKey::from_secret_key(&secp, &eph_secret);

    let shared = derive_shared_secret(&eph_secret, keys.scan_pubkey());
    let (output_pub, _tweak) =
        derive_payment_address_v2(keys.spend_pubkey(), &shared, 0).expect("derive output pubkey");
    let serialized = output_pub.serialize();
    let xonly = &serialized[1..];

    ServerMessage::CandidateTransaction {
        ephemeral_pubkey: hex::encode(ephemeral_pub.serialize()),
        outputs: vec![CandidateOutput {
            output_pubkey: hex::encode(xonly),
            amount_sats: Some(50_000),
            vout: 7,
        }],
        txid: "0".repeat(64),
        block_height: Some(123_456),
    }
}

async fn spawn_mock(candidate: ServerMessage) -> std::net::SocketAddr {
    let app = Router::new().route(
        "/ws/v1",
        get(move |ws: WebSocketUpgrade| {
            let cand = candidate.clone();
            async move {
                ws.on_upgrade(move |socket| handle_ws(socket, cand))
                    .into_response()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    addr
}

#[tokio::test]
async fn watch_payments_delivers_synthetic_match() {
    let receiver = GhostKeys::generate();
    let candidate = build_synthetic_candidate(&receiver);

    let addr = spawn_mock(candidate).await;
    let ws_url = format!("ws://{addr}/ws/v1");

    let session = spawn_session(
        vec![ws_url],
        "mock-jwt-token".to_string(),
        Some(receiver),
        None,
    );
    let mut rx = session.subscribe_payments();

    let detected = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("watch did not deliver in time")
        .expect("broadcast channel closed before delivery");

    assert_eq!(detected.k, 0);
    assert_eq!(detected.amount_sats, Some(50_000));
    assert_eq!(detected.vout, 7);
    assert_eq!(detected.block_height, Some(123_456));
    assert_eq!(detected.txid, "0".repeat(64));
}

#[tokio::test]
async fn watch_payments_no_match_keeps_channel_quiet() {
    // A receiver who didn't generate the payment must NOT see the event,
    // even though they subscribed before the mock pushed it.
    let real_receiver = GhostKeys::generate();
    let unrelated_receiver = GhostKeys::generate();
    let candidate = build_synthetic_candidate(&real_receiver);

    let addr = spawn_mock(candidate).await;
    let ws_url = format!("ws://{addr}/ws/v1");

    let session = spawn_session(
        vec![ws_url],
        "mock-jwt-token".to_string(),
        Some(unrelated_receiver),
        None,
    );
    let mut rx = session.subscribe_payments();

    // 500ms is plenty for the candidate to arrive AND be scanned-and-dropped.
    let outcome = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await;
    assert!(
        outcome.is_err(),
        "broadcast must stay silent for non-matching candidates, got {outcome:?}"
    );
}
