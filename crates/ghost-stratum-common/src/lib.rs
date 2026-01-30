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
//| FILE: lib.rs                                                                                                         |
//|======================================================================================================================|

//! Ghost Stratum Common
//!
//! This crate provides Stratum V2 protocol support for Bitcoin Ghost by wrapping
//! the stratum-sri (Stratum Reference Implementation) crates.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    ghost-stratum-common                         │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  Re-exports:                                                    │
//! │  - mining_sv2: Mining protocol messages                         │
//! │  - common_messages_sv2: Setup, reconnect messages               │
//! │  - sv1_api: Stratum V1 JSON-RPC types                          │
//! │  - noise_sv2: Noise protocol encryption                         │
//! │  - codec_sv2: Frame encoding/decoding                          │
//! │                                                                 │
//! │  Ghost helpers:                                                 │
//! │  - connection: SV1 and SV2 connection management               │
//! │  - translation: SV1↔SV2 message conversion                     │
//! │  - error: Unified error types                                  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Features
//!
//! - **Native SV2**: Binary protocol with Noise encryption for modern miners
//! - **SV1 Translation**: Convert legacy JSON-RPC to SV2 and back
//! - **Fast Block Propagation**: `SetNewPrevHash` for <100ms updates
//! - **Seamless Failover**: `Reconnect` message support
//!
//! # Example
//!
//! ```ignore
//! use ghost_stratum_common::{
//!     mining_sv2::{OpenExtendedMiningChannel, SubmitSharesExtended},
//!     common_messages_sv2::{SetupConnection, SetupConnectionSuccess},
//!     translation,
//! };
//!
//! // Convert SV1 mining.submit to SV2 SubmitSharesExtended
//! let sv2_submit = translation::sv1_to_sv2::build_sv2_submit_shares_extended_from_sv1_submit(
//!     &sv1_submit,
//!     channel_id,
//!     sequence_number,
//!     job_version,
//!     version_rolling_mask,
//! )?;
//! ```

pub mod connection;
pub mod error;

// ============================================================================
// Re-exports from stratum-sri
// ============================================================================

/// Stratum V2 mining protocol messages.
///
/// Key types:
/// - `OpenExtendedMiningChannel` / `OpenExtendedMiningChannelSuccess`
/// - `NewExtendedMiningJob`
/// - `SetNewPrevHash` - Fast block propagation
/// - `SubmitSharesExtended` / `SubmitSharesSuccess` / `SubmitSharesError`
/// - `SetTarget` - Difficulty adjustment
/// - `Reconnect` - Seamless failover
pub use mining_sv2;

/// Common SV2 messages shared across subprotocols.
///
/// Key types:
/// - `SetupConnection` / `SetupConnectionSuccess` / `SetupConnectionError`
/// - `Protocol` - Protocol identifier
pub use common_messages_sv2;

/// Stratum V1 JSON-RPC API types.
///
/// Key modules:
/// - `json_rpc` - JSON-RPC message types
/// - `client_to_server` - mining.subscribe, mining.authorize, mining.submit
/// - `server_to_client` - mining.notify, mining.set_difficulty
pub use sv1_api;

/// Noise protocol encryption for SV2.
///
/// Key types:
/// - `Initiator` - Client-side handshake
/// - `Responder` - Server-side handshake
pub use noise_sv2;

/// SV2 frame codec.
///
/// Key types:
/// - `HandshakeRole` - Initiator or Responder
/// - `StandardEitherFrame` - Framed message container
pub use codec_sv2;

/// Binary serialization for SV2.
pub use binary_sv2;

/// SV2 framing layer.
pub use framing_sv2;

/// SV2 channel management utilities.
pub use channels_sv2;

/// SV1↔SV2 translation functions.
///
/// Provides pure conversion functions without networking:
/// - `sv1_to_sv2::build_sv2_submit_shares_extended_from_sv1_submit`
/// - `sv1_to_sv2::build_sv2_open_extended_mining_channel`
/// - `sv2_to_sv1::build_sv1_notify_from_sv2`
/// - `sv2_to_sv1::build_sv1_set_difficulty_from_sv2_set_target`
pub mod translation {
    pub use stratum_core::stratum_translation::*;
}

/// Core stratum types (unified re-export).
pub use stratum_core;

// ============================================================================
// Ghost-specific types
// ============================================================================

/// Stratum protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StratumProtocol {
    /// Legacy Stratum V1 (JSON-RPC over TCP).
    V1,
    /// Modern Stratum V2 (binary with Noise encryption).
    V2,
}

impl Default for StratumProtocol {
    fn default() -> Self {
        Self::V2
    }
}

/// Configuration for SV2 connections.
#[derive(Debug, Clone)]
pub struct Sv2Config {
    /// Noise protocol private key (32 bytes).
    pub noise_private_key: [u8; 32],
    /// Maximum message size in bytes.
    pub max_message_size: usize,
    /// Connection timeout in seconds.
    pub timeout_secs: u64,
}

impl Default for Sv2Config {
    fn default() -> Self {
        Self {
            noise_private_key: [0u8; 32], // Must be set!
            max_message_size: 1 << 16,    // 64KB
            timeout_secs: 30,
        }
    }
}

/// Configuration for SV1 connections.
#[derive(Debug, Clone)]
pub struct Sv1Config {
    /// Maximum line length for JSON-RPC messages.
    pub max_line_length: usize,
    /// Connection timeout in seconds.
    pub timeout_secs: u64,
}

impl Default for Sv1Config {
    fn default() -> Self {
        Self {
            max_line_length: 1 << 16, // 64KB
            timeout_secs: 30,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_default() {
        assert_eq!(StratumProtocol::default(), StratumProtocol::V2);
    }

    #[test]
    fn test_sv2_config_default() {
        let config = Sv2Config::default();
        assert_eq!(config.max_message_size, 65536);
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn test_sv1_config_default() {
        let config = Sv1Config::default();
        assert_eq!(config.max_line_length, 65536);
        assert_eq!(config.timeout_secs, 30);
    }

    // Verify re-exports work
    #[test]
    fn test_mining_sv2_reexport() {
        // Just verify the type exists
        let _: mining_sv2::OpenExtendedMiningChannel;
    }

    #[test]
    fn test_sv1_api_reexport() {
        // Verify json_rpc module is accessible
        let _msg = sv1_api::json_rpc::Message::OkResponse(sv1_api::json_rpc::Response {
            id: 1,
            result: serde_json::Value::Null,
            error: None,
        });
    }
}
