//! Shared coordinator state. Held in an `Arc<CoordinatorState>` and
//! threaded into every endpoint handler via Axum's `State` extractor.
//!
//! All mutable state lives behind sync primitives (`Mutex`, `RwLock` from
//! the protocol crate's pieces). Axum handlers are async; the inner
//! locks are short-lived so we don't need async mutexes.

use std::sync::Arc;
use std::time::SystemTime;

use bitcoin::Network;

use wraith_protocol::{
    Clock, LiteSessionRegistry, LiteTier, RandomSessionIdGenerator, RemixQueue, SessionIdGenerator,
    SystemClock,
};

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
    /// Source of "now". `SystemClock` in production; tests inject
    /// `MockClock` so fill-window expiry can be exercised deterministically.
    pub clock: Arc<dyn Clock>,
    /// Source of fresh session IDs. `RandomSessionIdGenerator` in
    /// production; tests inject `DeterministicSessionIdGenerator` so they
    /// can pin exact session_id strings.
    pub id_gen: Arc<dyn SessionIdGenerator>,
    /// Unix-seconds the binary started. `/health` reports uptime.
    pub started_at: u64,
}

impl CoordinatorState {
    /// Production constructor — system clock, CSPRNG-based session ids.
    pub fn new(network: Network) -> Self {
        Self::with_components(
            network,
            Arc::new(SystemClock),
            Arc::new(RandomSessionIdGenerator),
        )
    }

    /// Test constructor — caller supplies the clock + id generator.
    /// Used by integration tests under `tests/` to pin deterministic
    /// session IDs and exercise time-driven transitions.
    pub fn with_components(
        network: Network,
        clock: Arc<dyn Clock>,
        id_gen: Arc<dyn SessionIdGenerator>,
    ) -> Self {
        let started_at = clock.unix_secs();
        Self {
            network,
            sessions: LiteSessionRegistry::new(),
            remix: RemixQueue::new(),
            clock,
            id_gen,
            started_at,
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

    /// Convenience — `now` from the configured clock.
    pub fn now(&self) -> u64 {
        self.clock.unix_secs()
    }

    /// Convenience — `now` minus `started_at`, saturating at 0. Used by
    /// `/health`. Started_at is captured against the same clock, so this
    /// is correct under MockClock too.
    pub fn uptime_secs(&self) -> u64 {
        self.now().saturating_sub(self.started_at)
    }
}

/// Stable wall-clock at module load — kept around for the rare case where
/// a test wants the real wall-clock baseline. Production code uses the
/// per-state `started_at` field instead.
pub fn process_start_unix() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
