//! ZK proof error types

use thiserror::Error;

/// Errors that can occur during ZK operations
#[derive(Debug, Error)]
pub enum ZkError {
    /// Field element conversion failed - bytes represent value outside field
    #[error("Field conversion error: {0}")]
    FieldConversionError(String),

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

    /// Balance overflow during payment
    #[error("Balance overflow: adding {amount} to {balance} exceeds u64::MAX")]
    BalanceOverflow { balance: u64, amount: u64 },

    /// Block proof height mismatch
    #[error("Block height mismatch: expected {expected}, got {actual}")]
    HeightMismatch { expected: u64, actual: u64 },

    /// Invalid proof format or data
    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    /// Invalid parameters provided to ZK operation
    #[error("Invalid parameters: {0}")]
    InvalidParams(String),

    /// Setup/trusted setup failed
    #[error("Setup error: {0}")]
    SetupError(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// M-2: Simulated proof rejected in production mode
    #[error("Simulated proof rejected: simulated proofs are not allowed in production")]
    SimulatedProofRejected,

    /// HIGH-5: Missing Groth16 verification key
    /// Production deployments MUST provide a verification key from an MPC ceremony
    #[error("Missing verification key: {0}")]
    MissingVerificationKey(String),
}

/// Result type for ZK operations
pub type ZkResult<T> = Result<T, ZkError>;
