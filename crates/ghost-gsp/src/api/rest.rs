//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: api/rest.rs                                                                                                    |
//|======================================================================================================================|

//! REST API handlers

use std::sync::Arc;

use axum::{extract::State, Json};
use tracing::info;

use ghost_gsp_proto::{
    RegisterRequest, RegisterResponse, SessionRequest, SessionResponse, PROTOCOL_VERSION,
};

use crate::error::{GspError, GspResult};
use crate::server::GspState;
use crate::GSP_VERSION;

/// Health check response
#[derive(serde::Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
}

/// Health check handler
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: GSP_VERSION,
    })
}

/// GSP info response
#[derive(serde::Serialize)]
pub struct InfoResponse {
    pub version: &'static str,
    pub protocol_version: &'static str,
    pub network: String,
    pub sync_status: String,
    pub connections: usize,
}

/// GSP info handler
pub async fn info(State(state): State<Arc<GspState>>) -> Json<InfoResponse> {
    let connections = *state.connection_count.read();

    // Check pay node connectivity
    let sync_status = match state.pay_node.health_check().await {
        Ok(true) => "synced".to_string(),
        Ok(false) => "syncing".to_string(),
        Err(_) => "disconnected".to_string(),
    };

    Json(InfoResponse {
        version: GSP_VERSION,
        protocol_version: PROTOCOL_VERSION,
        network: format!("{:?}", state.config.network),
        sync_status,
        connections,
    })
}

/// Register a new wallet
pub async fn register(
    State(state): State<Arc<GspState>>,
    Json(req): Json<RegisterRequest>,
) -> GspResult<Json<RegisterResponse>> {
    // Validate proof structure
    req.proof
        .validate_structure()
        .map_err(|e| GspError::BadRequest(format!("Invalid proof: {}", e)))?;

    // Check timestamp
    if !req.proof.is_timestamp_valid() {
        return Err(GspError::BadRequest(
            "Proof timestamp out of range".to_string(),
        ));
    }

    // Verify action
    if req.proof.action() != Some("register") {
        return Err(GspError::BadRequest("Invalid proof action".to_string()));
    }

    // Get wallet ID
    let wallet_id = req
        .proof
        .wallet_id()
        .map_err(|e| GspError::BadRequest(format!("Invalid wallet ID: {}", e)))?;

    // Check if already registered
    if state.registry.is_registered(&wallet_id)? {
        return Err(GspError::WalletAlreadyRegistered);
    }

    // Get public key bytes
    let pubkey = req
        .proof
        .public_key_bytes()
        .map_err(|e| GspError::BadRequest(format!("Invalid public key: {}", e)))?;

    // Verify signature
    state.registry.verify_proof(&req.proof)?;

    // Register wallet
    state
        .registry
        .register(&wallet_id, &pubkey, req.display_name.as_deref())?;

    info!(wallet_id = %wallet_id, "Wallet registered");

    Ok(Json(RegisterResponse {
        success: true,
        wallet_id: Some(wallet_id),
        error: None,
    }))
}

/// Create a new session
pub async fn create_session(
    State(state): State<Arc<GspState>>,
    Json(req): Json<SessionRequest>,
) -> GspResult<Json<SessionResponse>> {
    // Validate proof structure
    req.proof
        .validate_structure()
        .map_err(|e| GspError::BadRequest(format!("Invalid proof: {}", e)))?;

    // Check timestamp
    if !req.proof.is_timestamp_valid() {
        return Err(GspError::BadRequest(
            "Proof timestamp out of range".to_string(),
        ));
    }

    // Verify action
    if req.proof.action() != Some("session") {
        return Err(GspError::BadRequest("Invalid proof action".to_string()));
    }

    // Get wallet ID
    let wallet_id = req
        .proof
        .wallet_id()
        .map_err(|e| GspError::BadRequest(format!("Invalid wallet ID: {}", e)))?;

    // Check if registered
    if !state.registry.is_registered(&wallet_id)? {
        return Err(GspError::WalletNotRegistered);
    }

    // Verify signature
    state.registry.verify_proof(&req.proof)?;

    // Create session token
    let token = state.jwt.create_token(&wallet_id)?;

    info!(wallet_id = %wallet_id, "Session created");

    Ok(Json(SessionResponse {
        success: true,
        token: Some(token.clone()),
        expires_at: Some(token.expires_at),
        error: None,
    }))
}
