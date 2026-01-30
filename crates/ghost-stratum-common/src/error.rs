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

//! Error types for ghost-stratum-common.

use thiserror::Error;

/// Errors that can occur in stratum protocol handling.
#[derive(Debug, Error)]
pub enum StratumError {
    /// Connection error.
    #[error("Connection error: {0}")]
    Connection(String),

    /// Noise handshake failed.
    #[error("Noise handshake failed: {0}")]
    NoiseHandshake(String),

    /// Frame encoding/decoding error.
    #[error("Frame error: {0}")]
    Frame(String),

    /// Invalid message format.
    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    /// Protocol version mismatch.
    #[error("Protocol version mismatch: expected {expected}, got {got}")]
    VersionMismatch { expected: u16, got: u16 },

    /// Channel not found.
    #[error("Channel not found: {0}")]
    ChannelNotFound(u32),

    /// Job not found.
    #[error("Job not found: {0}")]
    JobNotFound(u32),

    /// Translation error (SV1↔SV2).
    #[error("Translation error: {0}")]
    Translation(String),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Timeout.
    #[error("Operation timed out")]
    Timeout,

    /// Channel closed.
    #[error("Channel closed")]
    ChannelClosed,

    /// Invalid configuration.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Shutdown requested.
    #[error("Shutdown requested")]
    Shutdown,
}

/// Result type for stratum operations.
pub type Result<T> = std::result::Result<T, StratumError>;

impl From<async_channel::RecvError> for StratumError {
    fn from(_: async_channel::RecvError) -> Self {
        StratumError::ChannelClosed
    }
}

impl<T> From<async_channel::SendError<T>> for StratumError {
    fn from(_: async_channel::SendError<T>) -> Self {
        StratumError::ChannelClosed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = StratumError::Connection("refused".into());
        assert_eq!(err.to_string(), "Connection error: refused");

        let err = StratumError::VersionMismatch {
            expected: 2,
            got: 1,
        };
        assert_eq!(
            err.to_string(),
            "Protocol version mismatch: expected 2, got 1"
        );
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
        let stratum_err: StratumError = io_err.into();
        assert!(matches!(stratum_err, StratumError::Io(_)));
    }
}
