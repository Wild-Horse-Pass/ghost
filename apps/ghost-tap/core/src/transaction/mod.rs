//! Transaction building and signing

mod builder;
mod signer;

pub use builder::*;
pub use signer::*;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum TransactionError {
    #[error("Insufficient funds: need {needed}, have {available}")]
    InsufficientFunds { needed: u64, available: u64 },

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Fee estimation failed")]
    FeeEstimationFailed,
}
