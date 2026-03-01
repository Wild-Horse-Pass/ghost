//! GhostTap Core Library
//!
//! Cross-platform Rust core for the GhostTap mobile wallet & payment terminal.
//! This library handles all wallet logic, cryptography, and network communication.

pub mod crypto;
pub mod ffi;
pub mod merchant;
pub mod network;
pub mod payment;
pub mod storage;
pub mod transaction;
pub mod wallet;

use thiserror::Error;

// Generate UniFFI scaffolding at crate root
uniffi::setup_scaffolding!("ghost_tap");

/// Core error types for GhostTap operations
#[derive(Error, Debug)]
pub enum GhostTapError {
    #[error("Wallet error: {0}")]
    Wallet(#[from] wallet::WalletError),

    #[error("Transaction error: {0}")]
    Transaction(#[from] transaction::TransactionError),

    #[error("Network error: {0}")]
    Network(#[from] network::NetworkError),

    #[error("Storage error: {0}")]
    Storage(#[from] storage::StorageError),

    #[error("Cryptographic error: {0}")]
    Crypto(#[from] crypto::CryptoError),
}

pub type Result<T> = std::result::Result<T, GhostTapError>;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the GhostTap core library
///
/// Must be called before any other operations.
/// Sets up logging, validates platform capabilities, etc.
pub fn init() -> Result<()> {
    tracing::info!("Initializing GhostTap Core v{}", VERSION);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        assert!(init().is_ok());
    }
}
