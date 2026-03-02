//! Network communication module
//!
//! Handles communication with Ghost network nodes, including:
//! - Standard blockchain queries
//! - Wraith Protocol (private transactions)
//! - Ghost Locks (staking)
//! - Jump Locks (HTLC/cross-chain)

mod client;
pub mod connection;
pub mod ghost_pay;
pub mod gsp;
pub mod gsp_auth;
pub mod gsp_failover;
mod peer;
mod sync;
mod types;

pub use client::*;
pub use ghost_pay::*;
pub use peer::*;
pub use sync::*;
pub use types::*;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Request failed: {0}")]
    RequestFailed(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Timeout")]
    Timeout,

    #[error("No available nodes")]
    NoAvailableNodes,

    #[error("Sync failed: {0}")]
    SyncFailed(String),

    #[error("Wraith protocol error: {0}")]
    WraithError(String),

    #[error("Lock operation failed: {0}")]
    LockError(String),

    #[error("WebSocket error: {0}")]
    WebSocket(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
}
