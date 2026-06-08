//! End-to-end wiring test for `wraith locks prepare`.
//!
//! Mirrors `l2_transfer_e2e.rs`: spins up an in-process axum
//! WebSocket server that speaks just enough of the GSP proto to
//! handle `Authenticate` + `PrepareGhostLock`, drives the wallet's
//! real `SessionHandle::prepare_ghost_lock`, and asserts the
//! `LockPreparedResult` shape — every field that wraithd later
//! stores in `prepared_locks.json` and that the recovery path needs
//! to rebuild the lock script.
//!
//! This is the contract test for the lock-prepare wire. If it goes
//! red, `wraith locks prepare` will silently break end-to-end
//! against a real ghost-gsp + ghost-pay stack. The coverage is
//! otherwise only via `scripts/regtest-recovery-demo.sh`, which
//! needs a real `ghostd`/`bitcoind` to run.

use std::time::Duration;

use axum::{
    extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
    routing::get,
    Router,
};
use ghost_gsp_proto::{ClientMessage, ServerMessage};
use wraith_wallet_core::gsp::spawn_session;

const FAKE_OWNER_PUBKEY: &str =
    "02a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd";
const FAKE_RECOVERY_PUBKEY: &str =
    "03f5b761c5d570a323c368af1ed38981a3ab668f3843f47bc9c467ec83fcdb07b0";

async fn handle_ws(mut socket: WebSocket) {
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
                    wallet_id: Some("test-wallet".into()),
                    error: None,
                };
                let _ = socket
                    .send(WsMessage::Text(serde_json::to_string(&auth).unwrap()))
                    .await;
            }
            ClientMessage::PrepareGhostLock {
                owner_pubkey,
                capacity_sats,
                recovery_pubkey,
                recovery_index,
            } => {
                // Mirror what ghost-gsp does: synthesise a lock_id +
                // funding address based on the inputs, echo every
                // wallet-supplied field back so the wallet can verify
                // the operator didn't substitute the recovery key.
                let lock_id = format!("lock_{}", &owner_pubkey[..16.min(owner_pubkey.len())]);
                let reply = ServerMessage::LockPrepared {
                    success: true,
                    lock_id: Some(lock_id),
                    funding_address: Some(
                        "bcrt1qmagdfmhljgml3arzv3sgu2kkn89dhnjwqzn8wr5aqnv4np08x8us03gh3a"
                            .to_string(),
                    ),
                    required_sats: Some(capacity_sats),
                    lock_pubkey: Some(owner_pubkey),
                    recovery_pubkey: Some(recovery_pubkey),
                    recovery_index: Some(recovery_index),
                    recovery_blocks: Some(10),
                    creation_height: Some(101),
                    error: None,
                };
                let _ = socket
                    .send(WsMessage::Text(serde_json::to_string(&reply).unwrap()))
                    .await;
            }
            _ => {}
        }
    }
}

async fn spawn_mock() -> std::net::SocketAddr {
    let app = Router::new().route(
        "/ws/v1",
        get(|ws: WebSocketUpgrade| async move { ws.on_upgrade(handle_ws).into_response() }),
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
async fn prepare_ghost_lock_round_trips_lock_prepared() {
    let addr = spawn_mock().await;
    let ws_url = format!("ws://{addr}/ws/v1");

    let session = spawn_session(vec![ws_url], "mock-jwt-token".to_string(), None, None);

    let result = tokio::time::timeout(
        Duration::from_secs(3),
        session.prepare_ghost_lock(
            FAKE_OWNER_PUBKEY.to_string(),
            100_000,
            FAKE_RECOVERY_PUBKEY.to_string(),
            7,
        ),
    )
    .await
    .expect("prepare_ghost_lock timeout")
    .expect("prepare_ghost_lock failed");

    assert_eq!(result.required_sats, 100_000);
    assert_eq!(
        result.funding_address,
        "bcrt1qmagdfmhljgml3arzv3sgu2kkn89dhnjwqzn8wr5aqnv4np08x8us03gh3a"
    );
    assert!(
        result.lock_id.starts_with("lock_"),
        "expected lock_ prefix, got {}",
        result.lock_id
    );
    // Verify the operator echoed back exactly what the wallet sent —
    // this is the substitution-attack guard the recovery path relies
    // on. If these drift, the wallet's recovery would build a script
    // that doesn't match the on-chain lock.
    assert_eq!(result.lock_pubkey, FAKE_OWNER_PUBKEY);
    assert_eq!(result.recovery_pubkey, FAKE_RECOVERY_PUBKEY);
    assert_eq!(result.recovery_index, 7);
    assert_eq!(result.recovery_blocks, 10);
    assert_eq!(result.creation_height, 101);
}

#[tokio::test]
async fn prepare_ghost_lock_propagates_server_error() {
    async fn handle_ws_failure(mut socket: WebSocket) {
        while let Some(Ok(frame)) = socket.recv().await {
            let text = match frame {
                WsMessage::Text(t) => t,
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
                        wallet_id: Some("alice".into()),
                        error: None,
                    };
                    let _ = socket
                        .send(WsMessage::Text(serde_json::to_string(&auth).unwrap()))
                        .await;
                }
                ClientMessage::PrepareGhostLock { .. } => {
                    let reply = ServerMessage::LockPrepared {
                        success: false,
                        lock_id: None,
                        funding_address: None,
                        required_sats: None,
                        lock_pubkey: None,
                        recovery_pubkey: None,
                        recovery_index: None,
                        recovery_blocks: None,
                        creation_height: None,
                        error: Some("Capacity below dust limit".to_string()),
                    };
                    let _ = socket
                        .send(WsMessage::Text(serde_json::to_string(&reply).unwrap()))
                        .await;
                }
                _ => {}
            }
        }
    }

    let app = Router::new().route(
        "/ws/v1",
        get(|ws: WebSocketUpgrade| async move { ws.on_upgrade(handle_ws_failure).into_response() }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let ws_url = format!("ws://{addr}/ws/v1");

    let session = spawn_session(vec![ws_url], "mock-jwt-token".to_string(), None, None);

    let outcome = tokio::time::timeout(
        Duration::from_secs(3),
        session.prepare_ghost_lock(
            FAKE_OWNER_PUBKEY.to_string(),
            42, // below dust on purpose
            FAKE_RECOVERY_PUBKEY.to_string(),
            0,
        ),
    )
    .await
    .expect("timeout waiting for failure response");

    assert!(outcome.is_err(), "expected Err, got {outcome:?}");
    let err = outcome.unwrap_err();
    assert!(
        err.contains("Capacity below dust limit"),
        "expected error to surface server message, got: {err}"
    );
}
