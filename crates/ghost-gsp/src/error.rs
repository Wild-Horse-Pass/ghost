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
//| FILE: error.rs                                                                                                       |
//|======================================================================================================================|

//! Error types for GSP server

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use thiserror::Error;

/// GSP server errors
#[derive(Debug, Error)]
pub enum GspError {
    // =========================================================================
    // Configuration Errors
    // =========================================================================
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid bind address: {0}")]
    InvalidBindAddress(String),

    #[error("Insecure JWT secret: {0}")]
    InsecureJwtSecret(String),

    // =========================================================================
    // Authentication Errors
    // =========================================================================
    #[error("Authentication required")]
    Unauthorized,

    #[error("Invalid credentials: {0}")]
    InvalidCredentials(String),

    #[error("Session expired")]
    SessionExpired,

    #[error("Invalid token: {0}")]
    InvalidToken(String),

    #[error("Wallet not registered")]
    WalletNotRegistered,

    #[error("Wallet already registered")]
    WalletAlreadyRegistered,

    #[error("Signature verification failed: {0}")]
    SignatureVerification(String),

    #[error("Wallet ID mismatch: public key does not derive to claimed wallet ID")]
    WalletIdMismatch,

    #[error("Nonce replay detected")]
    NonceReplay,

    // =========================================================================
    // Request Errors
    // =========================================================================
    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    // =========================================================================
    // Proxy Errors
    // =========================================================================
    #[error("Pay node unavailable: {0}")]
    PayNodeUnavailable(String),

    #[error("Pay node error: {0}")]
    PayNodeError(String),

    // =========================================================================
    // Database Errors
    // =========================================================================
    #[error("Database error: {0}")]
    Database(String),

    // =========================================================================
    // Internal Errors
    // =========================================================================
    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Protocol error: {0}")]
    Protocol(ghost_gsp_proto::GspProtoError),

    // =========================================================================
    // H-9: Payment Ownership Errors
    // =========================================================================
    /// H-9: Payment does not belong to the authenticated wallet
    #[error("Payment does not belong to this wallet")]
    PaymentOwnershipMismatch,

    // =========================================================================
    // H-11: Instant Payment Verification Errors
    // =========================================================================
    /// H-11: Lock UTXO not found on L1
    #[error("Lock not found on L1: {0}")]
    LockNotFound(String),

    /// H-11: Lock UTXO is still pending in mempool
    #[error("Lock is pending (unconfirmed in mempool)")]
    LockPending,

    /// H-11: Lock UTXO has insufficient confirmations
    #[error("Insufficient confirmations: {have} < {need}")]
    InsufficientConfirmations { have: u32, need: u32 },
}

impl From<ghost_gsp_proto::GspProtoError> for GspError {
    fn from(e: ghost_gsp_proto::GspProtoError) -> Self {
        GspError::Protocol(e)
    }
}

impl From<rusqlite::Error> for GspError {
    fn from(e: rusqlite::Error) -> Self {
        GspError::Database(e.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for GspError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        GspError::InvalidToken(e.to_string())
    }
}

impl From<std::io::Error> for GspError {
    fn from(e: std::io::Error) -> Self {
        GspError::Internal(e.to_string())
    }
}

impl IntoResponse for GspError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match &self {
            GspError::Config(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "CONFIG_ERROR",
                msg.clone(),
            ),
            GspError::InvalidBindAddress(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INVALID_BIND_ADDRESS",
                msg.clone(),
            ),
            GspError::InsecureJwtSecret(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INSECURE_JWT_SECRET",
                msg.clone(),
            ),
            GspError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Authentication required".to_string(),
            ),
            GspError::InvalidCredentials(msg) => {
                (StatusCode::UNAUTHORIZED, "INVALID_CREDENTIALS", msg.clone())
            }
            GspError::SessionExpired => (
                StatusCode::UNAUTHORIZED,
                "SESSION_EXPIRED",
                "Session has expired".to_string(),
            ),
            GspError::InvalidToken(msg) => (StatusCode::UNAUTHORIZED, "INVALID_TOKEN", msg.clone()),
            GspError::WalletNotRegistered => (
                StatusCode::NOT_FOUND,
                "WALLET_NOT_REGISTERED",
                "Wallet not registered".to_string(),
            ),
            GspError::WalletAlreadyRegistered => (
                StatusCode::CONFLICT,
                "WALLET_ALREADY_REGISTERED",
                "Wallet already registered".to_string(),
            ),
            GspError::SignatureVerification(msg) => (
                StatusCode::UNAUTHORIZED,
                "SIGNATURE_VERIFICATION_FAILED",
                msg.clone(),
            ),
            GspError::WalletIdMismatch => (
                StatusCode::UNAUTHORIZED,
                "WALLET_ID_MISMATCH",
                "Public key does not derive to claimed wallet ID".to_string(),
            ),
            GspError::NonceReplay => (
                StatusCode::UNAUTHORIZED,
                "NONCE_REPLAY",
                "Nonce has already been used".to_string(),
            ),
            GspError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "BAD_REQUEST", msg.clone()),
            GspError::NotFound(msg) => (StatusCode::NOT_FOUND, "NOT_FOUND", msg.clone()),
            GspError::RateLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                "RATE_LIMIT_EXCEEDED",
                "Rate limit exceeded".to_string(),
            ),
            GspError::PayNodeUnavailable(msg) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "PAY_NODE_UNAVAILABLE",
                msg.clone(),
            ),
            GspError::PayNodeError(msg) => (StatusCode::BAD_GATEWAY, "PAY_NODE_ERROR", msg.clone()),
            GspError::Database(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                msg.clone(),
            ),
            GspError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                msg.clone(),
            ),
            GspError::Protocol(e) => (StatusCode::BAD_REQUEST, "PROTOCOL_ERROR", e.to_string()),
            // H-9: Payment ownership mismatch
            GspError::PaymentOwnershipMismatch => (
                StatusCode::FORBIDDEN,
                "PAYMENT_OWNERSHIP_MISMATCH",
                "Payment does not belong to this wallet".to_string(),
            ),
            // H-11: Instant payment verification errors
            GspError::LockNotFound(lock_id) => (
                StatusCode::NOT_FOUND,
                "LOCK_NOT_FOUND",
                format!("Lock not found on L1: {}", lock_id),
            ),
            GspError::LockPending => (
                StatusCode::CONFLICT,
                "LOCK_PENDING",
                "Lock is pending (unconfirmed in mempool)".to_string(),
            ),
            GspError::InsufficientConfirmations { have, need } => (
                StatusCode::CONFLICT,
                "INSUFFICIENT_CONFIRMATIONS",
                format!("Insufficient confirmations: {} < {}", have, need),
            ),
        };

        let body = serde_json::json!({
            "success": false,
            "error": {
                "code": error_code,
                "message": message
            }
        });

        (status, Json(body)).into_response()
    }
}

/// Result type for GSP operations
pub type GspResult<T> = Result<T, GspError>;
