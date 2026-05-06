//! Round-trip integration test for the GSP REST client against an in-process axum mock.
//!
//! Does not require a real GSP. Asserts that the JSON shapes the wallet emits match what
//! the server's request handlers consume, by hosting a fake server that uses the SAME
//! `RegisterRequest` / `SessionRequest` types from `ghost-gsp-proto`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    extract::{Json, State},
    routing::post,
    Router,
};
use ghost_gsp_proto::{
    RegisterRequest, RegisterResponse, SessionRequest, SessionResponse, SessionToken, WalletId,
};
use wraith_wallet_core::auth;
use wraith_wallet_core::gsp::GspClient;
use wraith_wallet_core::keystore::Keystore;

const VECTOR_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[derive(Default, Clone)]
struct MockState {
    last_register: Arc<Mutex<Option<RegisterRequest>>>,
    last_session: Arc<Mutex<Option<SessionRequest>>>,
}

async fn mock_register(
    State(state): State<MockState>,
    Json(req): Json<RegisterRequest>,
) -> Json<RegisterResponse> {
    // Sanity-checks the wallet would fail anyway; recording lets the test inspect.
    let wallet_id = req.proof.wallet_id().expect("proof yields wallet_id");
    *state.last_register.lock().unwrap() = Some(req);
    Json(RegisterResponse {
        success: true,
        wallet_id: Some(wallet_id),
        error: None,
    })
}

async fn mock_session(
    State(state): State<MockState>,
    Json(req): Json<SessionRequest>,
) -> Json<SessionResponse> {
    let wallet_id = req.derive_wallet_id().expect("derive session wallet_id");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let token = SessionToken {
        token: "mock.jwt.token".to_string(),
        wallet_id,
        created_at: now,
        expires_at: now + 3600,
    };
    *state.last_session.lock().unwrap() = Some(req);
    Json(SessionResponse {
        success: true,
        token: Some(token.clone()),
        expires_at: Some(token.expires_at),
        error: None,
    })
}

async fn spawn_mock(state: MockState) -> std::net::SocketAddr {
    let app = Router::new()
        .route("/api/v1/register", post(mock_register))
        .route("/api/v1/session", post(mock_session))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    // Tiny pause so listener is reachable before the client tries.
    tokio::time::sleep(Duration::from_millis(20)).await;
    addr
}

#[tokio::test]
async fn register_round_trip() {
    let state = MockState::default();
    let addr = spawn_mock(state.clone()).await;
    let client = GspClient::new(format!("ws://{addr}/ws/v1"));

    let ks = Keystore::from_mnemonic(VECTOR_MNEMONIC).unwrap();
    let kp = auth::auth_keypair(&ks).unwrap();
    let proof = auth::make_proof(&kp, "register").unwrap();

    let returned_id = client
        .register(proof, Some("test-wallet".into()))
        .await
        .expect("register succeeds against mock");

    let expected_id = {
        let pk = auth::xonly_pubkey_bytes(&kp);
        WalletId::from_pubkey(&pk)
    };
    assert_eq!(returned_id, expected_id);

    let recorded = state.last_register.lock().unwrap().clone().unwrap();
    assert_eq!(recorded.proof.action(), Some("register"));
    assert_eq!(recorded.display_name.as_deref(), Some("test-wallet"));
}

#[tokio::test]
async fn create_session_round_trip() {
    let state = MockState::default();
    let addr = spawn_mock(state.clone()).await;
    let client = GspClient::new(format!("ws://{addr}/ws/v1"));

    let ks = Keystore::from_mnemonic(VECTOR_MNEMONIC).unwrap();
    let kp = auth::auth_keypair(&ks).unwrap();
    let proof = auth::make_proof(&kp, "session").unwrap();

    let session_nonce = hex::encode([0xCDu8; 32]);
    let token = client
        .create_session(proof, Some(session_nonce.clone()))
        .await
        .expect("session succeeds against mock");

    assert_eq!(token.token, "mock.jwt.token");
    assert!(!token.is_expired());

    let recorded = state.last_session.lock().unwrap().clone().unwrap();
    assert_eq!(recorded.proof.action(), Some("session"));
    assert_eq!(
        recorded.session_nonce.as_deref(),
        Some(session_nonce.as_str())
    );
}

#[tokio::test]
async fn server_error_propagates() {
    // 4xx-equivalent — mock returns success: false, error: Some(...)
    async fn handler(Json(_req): Json<RegisterRequest>) -> Json<RegisterResponse> {
        Json(RegisterResponse {
            success: false,
            wallet_id: None,
            error: Some("WalletAlreadyRegistered".to_string()),
        })
    }
    let app = Router::new().route("/api/v1/register", post(handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let client = GspClient::new(format!("ws://{addr}/ws/v1"));
    let ks = Keystore::from_mnemonic(VECTOR_MNEMONIC).unwrap();
    let kp = auth::auth_keypair(&ks).unwrap();
    let proof = auth::make_proof(&kp, "register").unwrap();
    let err = client.register(proof, None).await.unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("WalletAlreadyRegistered"), "got: {msg}");
}
