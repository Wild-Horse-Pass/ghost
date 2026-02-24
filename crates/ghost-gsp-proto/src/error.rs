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

//! Error types for GSP Protocol

use thiserror::Error;

/// Errors that can occur in GSP Protocol operations
#[derive(Debug, Error)]
pub enum GspProtoError {
    // =========================================================================
    // Authentication Errors
    // =========================================================================
    /// Invalid wallet proof
    #[error("Invalid wallet proof: {0}")]
    InvalidProof(String),

    /// Proof timestamp expired or too far in future
    #[error("Proof timestamp out of range: {0}")]
    ProofTimestampInvalid(String),

    /// Proof nonce already used (replay attempt)
    #[error("Proof nonce already used")]
    NonceReused,

    /// Signature verification failed
    #[error("Signature verification failed: {0}")]
    SignatureInvalid(String),

    /// Invalid public key format
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Session nonce is required but was not provided
    #[error(
        "Session nonce required: clients must generate a fresh 32-byte CSPRNG nonce per session"
    )]
    SessionNonceRequired,

    /// Session expired
    #[error("Session expired")]
    SessionExpired,

    /// Session not found
    #[error("Session not found")]
    SessionNotFound,

    /// Invalid session token
    #[error("Invalid session token: {0}")]
    InvalidSessionToken(String),

    // =========================================================================
    // Message Errors
    // =========================================================================
    /// Message too large
    #[error("Message exceeds maximum size of {max} bytes")]
    MessageTooLarge { max: usize },

    /// Invalid message format
    #[error("Invalid message format: {0}")]
    InvalidMessageFormat(String),

    /// Unknown message type
    #[error("Unknown message type: {0}")]
    UnknownMessageType(String),

    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Invalid field value
    #[error("Invalid field value for {field}: {reason}")]
    InvalidField { field: String, reason: String },

    // =========================================================================
    // Payment Errors
    // =========================================================================
    /// Invalid payment amount
    #[error("Invalid payment amount: {0}")]
    InvalidAmount(String),

    /// Invalid recipient address
    #[error("Invalid recipient address: {0}")]
    InvalidRecipient(String),

    /// Payment not found
    #[error("Payment not found: {0}")]
    PaymentNotFound(String),

    /// Payment already submitted
    #[error("Payment already submitted: {0}")]
    PaymentAlreadySubmitted(String),

    /// Insufficient balance
    #[error("Insufficient balance: required {required} sats, available {available} sats")]
    InsufficientBalance { required: u64, available: u64 },

    // =========================================================================
    // Lock Errors
    // =========================================================================
    /// Lock not found
    #[error("Lock not found: {0}")]
    LockNotFound(String),

    /// Lock not in valid state for operation
    #[error("Lock {lock_id} in invalid state {state} for operation")]
    InvalidLockState { lock_id: String, state: String },

    /// Lock capacity exceeded
    #[error("Lock capacity exceeded: {0}")]
    LockCapacityExceeded(String),

    // =========================================================================
    // Serialization Errors
    // =========================================================================
    /// JSON serialization error
    #[error("JSON error: {0}")]
    Json(String),

    /// Hex encoding/decoding error
    #[error("Hex error: {0}")]
    Hex(String),

    // =========================================================================
    // Internal Errors
    // =========================================================================
    /// Internal protocol error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<serde_json::Error> for GspProtoError {
    fn from(e: serde_json::Error) -> Self {
        GspProtoError::Json(e.to_string())
    }
}

impl From<hex::FromHexError> for GspProtoError {
    fn from(e: hex::FromHexError) -> Self {
        GspProtoError::Hex(e.to_string())
    }
}
