//! ZK proof error types

use thiserror::Error;

/// Errors that can occur during ZK operations
#[derive(Debug, Error)]
pub enum ZkError {
    /// Proof generation failed
    #[error("Proof generation failed: {0}")]
    ProvingError(String),

    /// Proof verification failed
    #[error("Proof verification failed: {0}")]
    VerificationError(String),

    /// Invalid witness data
    #[error("Invalid witness: {0}")]
    InvalidWitness(String),

    /// Circuit synthesis failed
    #[error("Circuit synthesis failed: {0}")]
    SynthesisError(String),

    /// Parameter generation/loading failed
    #[error("Parameter error: {0}")]
    ParameterError(String),

    /// Serialization/deserialization failed
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// State root mismatch
    #[error("State root mismatch: expected {expected}, got {actual}")]
    StateRootMismatch { expected: String, actual: String },

    /// Merkle proof invalid
    #[error("Invalid merkle proof: {0}")]
    InvalidMerkleProof(String),

    /// Signature verification failed
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Insufficient balance in witness
    #[error("Insufficient balance: has {has}, needs {needs}")]
    InsufficientBalance { has: u64, needs: u64 },

    /// Block proof height mismatch
    #[error("Block height mismatch: expected {expected}, got {actual}")]
    HeightMismatch { expected: u64, actual: u64 },

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Result type for ZK operations
pub type ZkResult<T> = Result<T, ZkError>;

impl From<bincode::Error> for ZkError {
    fn from(e: bincode::Error) -> Self {
        ZkError::SerializationError(e.to_string())
    }
}
