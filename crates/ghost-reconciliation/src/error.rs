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

//! Error types for reconciliation

use thiserror::Error;

/// Reconciliation errors
#[derive(Error, Debug)]
pub enum ReconciliationError {
    #[error("Settlement below minimum: {amount} < {minimum}")]
    BelowMinimum { amount: u64, minimum: u64 },

    #[error("Batch too small: {size} < {minimum}")]
    BatchTooSmall { size: usize, minimum: usize },

    #[error("Batch too large: {size} > {maximum}")]
    BatchTooLarge { size: usize, maximum: usize },

    #[error("Settlement not found: {id}")]
    SettlementNotFound { id: String },

    #[error("Batch not found: {id}")]
    BatchNotFound { id: String },

    #[error("Invalid proof: {reason}")]
    InvalidProof { reason: String },

    #[error("Dispute active: {batch_id}")]
    DisputeActive { batch_id: String },

    #[error("Already finalized: {id}")]
    AlreadyFinalized { id: String },

    #[error("Invalid state transition: {from} -> {to}")]
    InvalidStateTransition { from: String, to: String },

    #[error("Merkle tree error: {0}")]
    MerkleError(String),

    #[error("L1 transaction error: {0}")]
    L1TransactionError(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid batch: {0}")]
    InvalidBatch(String),

    #[error("Insufficient settlements: have {have}, need {need}")]
    InsufficientSettlements { have: usize, need: usize },

    #[error("Insufficient funds for {ghost_id}: required {required}, available {available}")]
    InsufficientFunds { ghost_id: String, required: u64, available: u64 },

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Dispute window active: ends at block {ends_at}, current {current}")]
    DisputeWindowActive { ends_at: u64, current: u64 },

    #[error("Invalid settlement: {0}")]
    InvalidSettlement(String),
}

// Simplified BatchNotFound that takes a String directly
impl ReconciliationError {
    pub fn batch_not_found(id: impl Into<String>) -> Self {
        ReconciliationError::BatchNotFound { id: id.into() }
    }
}

pub type ReconciliationResult<T> = Result<T, ReconciliationError>;
