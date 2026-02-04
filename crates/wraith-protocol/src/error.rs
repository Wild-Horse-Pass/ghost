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

//! Error types for Wraith Protocol

use thiserror::Error;

/// Errors that can occur in Wraith Protocol operations
#[derive(Debug, Error)]
pub enum WraithError {
    /// Session not found
    #[error("Session not found: {0}")]
    SessionNotFound(String),

    /// Invalid session state
    #[error("Invalid session state: expected {expected}, got {actual}")]
    InvalidState { expected: String, actual: String },

    /// Session is full
    #[error("Session is full: {current}/{max} participants")]
    SessionFull { current: usize, max: usize },

    /// Insufficient participants
    #[error("Insufficient participants: have {have}, need {need}")]
    InsufficientParticipants { have: usize, need: usize },

    /// Invalid denomination
    #[error("Invalid denomination: {0}")]
    InvalidDenomination(String),

    /// Timeout exceeded
    #[error("Session timeout exceeded")]
    Timeout,

    /// Signature verification failed
    #[error("Signature verification failed: {0}")]
    SignatureError(String),

    /// Blinding error
    #[error("Blinding error: {0}")]
    BlindingError(String),

    /// Phase execution error
    #[error("Phase execution error: {0}")]
    PhaseError(String),

    /// Transaction error
    #[error("Transaction error: {0}")]
    TransactionError(String),

    /// Missing data error
    #[error("Missing data: {0}")]
    MissingData(String),

    /// Invalid signature
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Not enough participants
    #[error("Not enough participants: have {0}, need {1}")]
    NotEnoughParticipants(usize, usize),

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Insufficient fee
    #[error("Insufficient fee: need {0} sats, have {1} sats")]
    InsufficientFee(u64, u64),

    /// RPC error when communicating with ghost-core
    #[error("RPC error: {0}")]
    RpcError(String),

    /// Broadcast error
    #[error("Broadcast error: {0}")]
    BroadcastError(String),

    /// SEC-WRAITH-4: Security violation - operation disabled for security reasons
    #[error("Security error: {0}")]
    SecurityError(String),
}
