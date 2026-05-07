//! Shared coordinator state. Held in an `Arc<CoordinatorState>` and
//! threaded into every endpoint handler via Axum's `State` extractor.
//!
//! All mutable state lives behind sync primitives (`Mutex`, `RwLock` from
//! the protocol crate's pieces). Axum handlers are async; the inner
//! locks are short-lived so we don't need async mutexes.

use std::time::SystemTime;

use bitcoin::Network;

use wraith_protocol::{LiteSessionRegistry, LiteTier, RemixQueue};

/// Process-global state shared across HTTP handlers.
pub struct CoordinatorState {
    /// Bitcoin network this coordinator serves.
    pub network: Network,
    /// In-flight session registry. Active coordinators populate it via
    /// `find_or_create` + lifecycle transitions; standbys mirror it via
    /// gossip events.
    pub sessions: LiteSessionRegistry,
    /// Remix queue per tier. Wallets enrol after a successful round to
    /// auto-rotate into the next session.
    pub remix: RemixQueue,
    /// Unix-seconds the binary started. `/health` reports uptime.
    pub started_at: u64,
}

impl CoordinatorState {
    pub fn new(network: Network) -> Self {
        Self {
            network,
            sessions: LiteSessionRegistry::new(),
            remix: RemixQueue::new(),
            started_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        }
    }

    /// Stable lowercase name of the network — matches the wallet's
    /// `wraith env` output and the protocol crate's `as_str()` helpers.
    pub fn network_name(&self) -> &'static str {
        match self.network {
            Network::Bitcoin => "mainnet",
            Network::Testnet => "testnet",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
            _ => "unknown",
        }
    }

    /// All tiers this coordinator advertises support for. v1 supports
    /// every tier in the protocol; future iterations may filter (e.g.
    /// "this coordinator pool only handles ≥1m_sats").
    pub fn supported_tiers(&self) -> Vec<LiteTier> {
        LiteTier::all().to_vec()
    }
}
