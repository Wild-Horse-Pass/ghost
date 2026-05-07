//! Shared coordinator state. Held in an `Arc<CoordinatorState>` and
//! threaded into every endpoint handler via Axum's `State` extractor.
//!
//! All mutable state lives behind sync primitives (`Mutex`, `RwLock` from
//! the protocol crate's pieces). Axum handlers are async; the inner
//! locks are short-lived so we don't need async mutexes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use bitcoin::Network;

use wraith_protocol::{
    BondLedger, Clock, CoordinatorSigner, LiteSessionRegistry, LiteTier, RandomSessionIdGenerator,
    RemixQueue, SessionIdGenerator, SystemClock,
};

use crate::inputs::AcceptedInputs;

/// One Schnorr blind-signature signer per active round, lazily created
/// the first time a participant hits `/nonce`. Kept inside an
/// `Arc<Mutex<…>>` so handlers can lock briefly during crypto operations
/// without holding the outer registry mutex.
pub type SharedSigner = Arc<Mutex<CoordinatorSigner>>;

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
    /// L2 escrow ledger. `None` until phase C wires the real ghost-pay
    /// client; tests inject `MockBondLedger`. `/inputs` returns
    /// `503 ledger_not_configured` while this is None — the binary boots
    /// fine without it but won't accept commit-phase submissions.
    pub bond_ledger: Option<Arc<dyn BondLedger>>,
    /// Coordinator's fee-collection address. Used as the destination for
    /// the per-Mix-round service-fee output. `None` until the operator
    /// supplies one (CLI flag / config). `/inputs` returns
    /// `503 fee_address_not_configured` for Mix rounds while this is None;
    /// Jump rounds don't need it.
    pub coordinator_fee_address: Option<String>,
    /// Per-session validated participant inputs, accumulated as
    /// participants hit `/inputs`. Once every enrolled participant has
    /// submitted, the session transitions Locked → Signing.
    pub inputs_store: Mutex<HashMap<String, Vec<AcceptedInputs>>>,
    /// Per-round Schnorr blind-signature signer. Lazily created on the
    /// first `/nonce` call for a session; reused for every subsequent
    /// `/nonce` and `/blind-sign` on the same session. Each signer
    /// holds its own ephemeral signing keypair so the coordinator
    /// can't link blinded requests to unblinded outputs.
    ///
    /// Failover note: signers are in-memory only — a coordinator
    /// restart drops them, and B/6 (Active/Standby gossip) will need
    /// the re-blinding-on-failover path described in DESIGN_LITE §7
    /// before standbys can serve a round started by a now-dead Active.
    pub signers: Mutex<HashMap<String, SharedSigner>>,
    /// Unix-seconds the binary started. `/health` reports uptime.
    pub started_at: u64,
}

impl CoordinatorState {
    /// Production constructor — system clock, CSPRNG-based session ids,
    /// no bond ledger (phase C wires it), no fee address (operator
    /// configures it).
    pub fn new(network: Network) -> Self {
        Self::with_components(
            network,
            Arc::new(SystemClock),
            Arc::new(RandomSessionIdGenerator),
            None,
            None,
        )
    }

    /// Test / advanced-config constructor — caller supplies clock, id
    /// generator, bond ledger, and fee address. Used by integration
    /// tests under `tests/` to pin deterministic session IDs and
    /// inject `MockBondLedger`.
    pub fn with_components(
        network: Network,
        clock: Arc<dyn Clock>,
        id_gen: Arc<dyn SessionIdGenerator>,
        bond_ledger: Option<Arc<dyn BondLedger>>,
        coordinator_fee_address: Option<String>,
    ) -> Self {
        let started_at = clock.unix_secs();
        Self {
            network,
            sessions: LiteSessionRegistry::new(),
            remix: RemixQueue::new(),
            clock,
            id_gen,
            bond_ledger,
            coordinator_fee_address,
            inputs_store: Mutex::new(HashMap::new()),
            signers: Mutex::new(HashMap::new()),
            started_at,
        }
    }

    /// Get-or-create the per-round signer. Idempotent under concurrent
    /// access — only one signer is ever created per session_id, even
    /// if multiple `/nonce` requests race.
    pub fn signer_for(&self, session_id: &str) -> Result<SharedSigner, wraith_protocol::WraithError> {
        let mut signers = self.signers.lock().expect("signers poisoned");
        if let Some(existing) = signers.get(session_id) {
            return Ok(existing.clone());
        }
        // Derive a 32-byte signer-internal session id from the textual
        // round id. The signer's `session_id` is opaque internally — it
        // just needs to be a stable per-round value.
        let mut digest = [0u8; 32];
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"wraith-coordinator/signer-session-id/v1");
        h.update(session_id.as_bytes());
        digest.copy_from_slice(&h.finalize());
        let signer = CoordinatorSigner::new(&digest)?;
        let arc = Arc::new(Mutex::new(signer));
        signers.insert(session_id.to_string(), arc.clone());
        Ok(arc)
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
