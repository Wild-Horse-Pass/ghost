//! Chain client — talks to the wallet's configured ghost-pay backend.
//!
//! Phase 1: a single REST client over HTTPS. Transport layer (clearnet vs. Tor) and
//! GSP WebSocket subscriptions land in subsequent commits.

mod ghost_pay;

use async_trait::async_trait;

pub use ghost_pay::GhostPayClient;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainStatus {
    pub backend_version: String,
    pub network: String,
    pub has_keys: bool,
    pub lock_count: u64,
    pub active_sessions: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("backend returned error: {0}")]
    Backend(String),
    #[error("malformed response: {0}")]
    Malformed(String),
}

#[async_trait]
pub trait ChainClient: Send + Sync {
    async fn status(&self) -> Result<ChainStatus, ChainError>;
}
