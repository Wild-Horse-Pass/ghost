//! Error types for the MPC ceremony

use thiserror::Error;

/// Result type for MPC operations
pub type MpcResult<T> = Result<T, MpcError>;

/// Errors that can occur during MPC ceremony operations
#[derive(Debug, Clone, Error)]
pub enum MpcError {
    /// Ceremony has already ossified - no more contributions allowed
    #[error("MPC ceremony has ossified at elder {0} - no more contributions accepted")]
    CeremonyOssified(u32),

    /// Invalid contribution position
    #[error("Invalid contribution position {0}: expected {1}")]
    InvalidPosition(u32, u32),

    /// Contribution doesn't chain correctly to previous parameters
    #[error(
        "Contribution does not chain to previous parameters: expected {expected}, got {actual}"
    )]
    InvalidChain { expected: String, actual: String },

    /// Contribution proof verification failed
    #[error("Contribution proof verification failed: {0}")]
    InvalidProof(String),

    /// Parameters file not found
    #[error("Parameters file not found: {0}")]
    ParamsNotFound(String),

    /// Parameters file corrupted or invalid
    #[error("Invalid parameters: {0}")]
    InvalidParams(String),

    /// Hash mismatch on parameters
    #[error("Parameters hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    /// Contribution from wrong node
    #[error("Contribution from unauthorized node {0}: expected {1}")]
    UnauthorizedContributor(String, String),

    /// Duplicate contribution for position
    #[error("Duplicate contribution for position {0}")]
    DuplicateContribution(u32),

    /// Not enough approvals for contribution
    #[error("Insufficient approvals for contribution: {0}/{1} required")]
    InsufficientApprovals(u32, u32),

    /// Database error
    #[error("Database error: {0}")]
    Database(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Cryptographic operation failed
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Random number generation failure
    #[error("Random number generation failed: {0}")]
    RandomFailure(String),
}

impl From<bincode::Error> for MpcError {
    fn from(err: bincode::Error) -> Self {
        MpcError::Serialization(err.to_string())
    }
}

impl From<std::io::Error> for MpcError {
    fn from(err: std::io::Error) -> Self {
        MpcError::Io(err.to_string())
    }
}

impl From<rusqlite::Error> for MpcError {
    fn from(err: rusqlite::Error) -> Self {
        MpcError::Database(err.to_string())
    }
}
