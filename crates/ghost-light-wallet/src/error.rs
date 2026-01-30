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

//! Error types for Light Wallet

use thiserror::Error;

/// Light wallet errors
#[derive(Debug, Error)]
pub enum LightWalletError {
    // =========================================================================
    // Key Management Errors
    // =========================================================================
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("Wallet not initialized")]
    NotInitialized,

    #[error("Wallet already exists")]
    WalletExists,

    // =========================================================================
    // Storage Errors
    // =========================================================================
    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption failed - wrong password?")]
    DecryptionFailed,

    // =========================================================================
    // GSP Connection Errors
    // =========================================================================
    #[error("Not connected to GSP")]
    NotConnected,

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Session expired")]
    SessionExpired,

    #[error("GSP error: {0}")]
    GspError(String),

    #[error("All GSPs unavailable")]
    AllGspsUnavailable,

    // =========================================================================
    // Payment Errors
    // =========================================================================
    #[error("Insufficient balance: need {required} sats, have {available} sats")]
    InsufficientBalance { required: u64, available: u64 },

    #[error("Invalid recipient: {0}")]
    InvalidRecipient(String),

    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    #[error("Payment failed: {0}")]
    PaymentFailed(String),

    #[error("Payment not found: {0}")]
    PaymentNotFound(String),

    #[error("Invalid payment: {0}")]
    InvalidPayment(String),

    // =========================================================================
    // Lock Errors
    // =========================================================================
    #[error("Lock not found: {0}")]
    LockNotFound(String),

    #[error("Lock operation failed: {0}")]
    LockFailed(String),

    // =========================================================================
    // Signing Errors
    // =========================================================================
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    // =========================================================================
    // Protocol Errors
    // =========================================================================
    #[error("Protocol error: {0}")]
    Protocol(ghost_gsp_proto::GspProtoError),

    // =========================================================================
    // Internal Errors
    // =========================================================================
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<ghost_gsp_proto::GspProtoError> for LightWalletError {
    fn from(e: ghost_gsp_proto::GspProtoError) -> Self {
        LightWalletError::Protocol(e)
    }
}

impl From<rusqlite::Error> for LightWalletError {
    fn from(e: rusqlite::Error) -> Self {
        LightWalletError::Storage(e.to_string())
    }
}

impl From<std::io::Error> for LightWalletError {
    fn from(e: std::io::Error) -> Self {
        LightWalletError::Storage(e.to_string())
    }
}

impl From<bip39::Error> for LightWalletError {
    fn from(e: bip39::Error) -> Self {
        LightWalletError::InvalidMnemonic(e.to_string())
    }
}

/// Result type for light wallet operations
pub type WalletResult<T> = Result<T, LightWalletError>;
