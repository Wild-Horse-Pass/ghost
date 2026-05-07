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
//| FILE: lite_session.rs                                                                                                |
//|======================================================================================================================|

//! Wraith Lite v1 — session lifecycle + demand-driven session creation.
//!
//! See `DESIGN_LITE.md` §4 (architecture) and §5 (wallet API). This module
//! is the coordinator-side state machine for the wallet's
//! `session.find_or_create(tier)` flow: a wallet shows up wanting to mix
//! at tier X, the Active coordinator either returns an open session at
//! that tier or spins up a new one. Standbys learn about new sessions
//! via the gossip protocol added in task #38.
//!
//! Coexists with the legacy `session.rs`'s two-phase `WraithSession`
//! during the v1 refactor; the legacy module gets deleted in the
//! subtractive commit at task #40.
//!
//! ## Session lifecycle
//!
//! ```text
//!                               (max participants reached)
//!         create_session()             OR
//! ()  ─────────────────────►  Filling  (fill_window expired with min met)
//!                                │
//!                                ▼
//!                              Locked  ──── coordinator builds tx ────►  Signing
//!                                                                         │
//!                                                                         ▼
//!                                                                    Broadcasting
//!                                                                         │
//!                                                                         ▼
//!                                                                      Complete
//!
//! Failed is reachable from any non-terminal state on
//!  abort (e.g. round-wide no-sign timeout).
//! ```
//!
//! ## What this module owns vs. defers
//!
//! Owns:
//!   - The `LiteSession` struct (in-memory state of one round).
//!   - The `LiteSessionRegistry` (collection of all in-flight sessions on
//!     the Active coordinator).
//!   - The `find_or_create_session()` orchestration function.
//!   - The state-transition helpers + their validity checks.
//!
//! Defers (other modules):
//!   - Bond verification: handled by `BondLedger` from `bond.rs`. We just
//!     hold the `BondId` per participant.
//!   - Round transaction construction: handled by `LiteRoundBuilder` from
//!     `single_round.rs`, called once a session transitions to `Signing`.
//!   - Standby gossip: task #38 (`coordinator_redundancy.rs` extension).
//!   - Remix queue: task #39 (separate module `remix.rs`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::bond::BondId;
use crate::tier::{LiteTier, LITE_FILL_WINDOW_SECS};
use crate::SessionType;

/// Errors surfaced by the registry. All map cleanly to wallet-facing
/// `Response::Error` envelopes — no panics on the coordinator hot path.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LiteSessionError {
    #[error("session '{0}' not found in registry")]
    NotFound(String),
    #[error("session '{0}' is full ({1}/{1} participants)")]
    Full(String, u32),
    #[error("session '{0}' is not accepting new participants (state: {1})")]
    NotAcceptingParticipants(String, &'static str),
    /// Caller asked for a state transition the session can't make
    /// (e.g. `Filling` → `Complete` skipping `Locked` / `Signing` /
    /// `Broadcasting`). Carries the from/to labels for diagnostic logs.
    #[error("invalid transition from {from} to {to}")]
    InvalidTransition {
        from: &'static str,
        to: &'static str,
    },
    #[error("participant '{0}' is already registered for session '{1}'")]
    AlreadyRegistered(String, String),
}

/// Where a session is in its lifecycle. Participants may register only
/// during `Filling`; signatures may be collected only during `Signing`;
/// etc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiteSessionState {
    /// Open for new participants. Carries the unix-seconds timestamp at
    /// which the fill window expires; once `now ≥ this`, the session
    /// transitions to `Locked` (provided it has reached
    /// `tier.min_participants()`) or `Failed::FillWindowExpired` (if not).
    Filling { fill_window_expires_at: u64 },
    /// At or past `tier.min_participants()` and either at max or past the
    /// fill window. No more participants accepted. Coordinator is about
    /// to build the round transaction.
    Locked,
    /// Round transaction is built; participants are submitting signature
    /// shares.
    Signing,
    /// Transaction has been broadcast; coordinator is waiting for the
    /// configured number of confirmations.
    Broadcasting,
    /// Round complete — final transaction is on chain.
    Complete,
    /// Round aborted. Carries a short reason code so the coordinator's
    /// gossip and the wallet's user-facing surface can distinguish e.g.
    /// "fill window expired without quorum" from "coordinator aborted
    /// for protocol error" from "round-wide no-sign". The granular
    /// taxonomy of bond-resolution reasons lives in `bond.rs`'s
    /// `RefundReason`/`SlashReason`. `String` (not `&'static str`) so
    /// the variant survives serde round-trip.
    Failed { reason: String },
}

impl LiteSessionState {
    /// Stable wire-format string. Used in `SessionDescriptor` so wallets
    /// don't have to know the Rust enum layout.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Filling { .. } => "filling",
            Self::Locked => "locked",
            Self::Signing => "signing",
            Self::Broadcasting => "broadcasting",
            Self::Complete => "complete",
            Self::Failed { .. } => "failed",
        }
    }
}

/// One participant's slot in a session. The bond_id is the link between
/// the on-chain participant and the L2 escrow record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiteSessionParticipant {
    pub ghost_id: String,
    pub bond_id: BondId,
    /// Unix seconds of registration. Used for diagnostics and to detect
    /// extremely-late arrivals (e.g. a participant who somehow registered
    /// after the fill window — defensive logging).
    pub registered_at: u64,
}

/// The full state of one Wraith Lite session. Held in the registry while
/// the round is in flight; archived to a completed-rounds log after
/// `Complete` for audit purposes (audit log is task #38).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiteSession {
    pub session_id: String,
    pub tier: LiteTier,
    pub session_type: SessionType,
    pub created_at: u64,
    pub state: LiteSessionState,
    pub participants: Vec<LiteSessionParticipant>,
}

impl LiteSession {
    /// True if the session would currently accept a new participant. Pure
    /// function of state + clock; doesn't mutate. Used by
    /// `find_or_create_session` to decide whether to return this session
    /// or spin up a new one.
    pub fn is_open_for_new_participants(&self, now: u64) -> bool {
        match &self.state {
            LiteSessionState::Filling {
                fill_window_expires_at,
            } => {
                self.participants.len() < self.tier.max_participants()
                    && now < *fill_window_expires_at
            }
            _ => false,
        }
    }
}

/// Wire-format DTO returned by `find_or_create_session()` and friends.
/// What the wallet sees over IPC. Detached from `LiteSession` so the
/// coordinator can evolve internal state without breaking the wire
/// contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionDescriptor {
    pub session_id: String,
    pub tier_id: String,
    pub state: String,
    pub slots_filled: u32,
    pub slots_total: u32,
    pub bond_amount_sats: u64,
    pub fill_window_expires_at: Option<u64>,
}

impl SessionDescriptor {
    pub fn from_session(s: &LiteSession) -> Self {
        let fill_window_expires_at = match &s.state {
            LiteSessionState::Filling {
                fill_window_expires_at,
            } => Some(*fill_window_expires_at),
            _ => None,
        };
        Self {
            session_id: s.session_id.clone(),
            tier_id: s.tier.id().to_string(),
            state: s.state.as_str().to_string(),
            slots_filled: s.participants.len() as u32,
            slots_total: s.tier.max_participants() as u32,
            bond_amount_sats: s.tier.bond_sats(),
            fill_window_expires_at,
        }
    }
}

// ---------------------------------------------------------------------------
// Clock + SessionIdGenerator traits — testable substitutes for system time
// and randomness so the coordinator's state machine can be exercised
// deterministically.
// ---------------------------------------------------------------------------

/// Source of "current time" in unix-seconds. The registry's lifecycle
/// transitions are time-based (fill window expiration); making time
/// pluggable means tests don't have to sleep.
pub trait Clock: Send + Sync {
    fn unix_secs(&self) -> u64;
}

/// Real-world clock backed by `std::time::SystemTime`.
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Test clock — explicit "now" with manual advancement. Atomic so the
/// registry can be wrapped in `Arc` and shared across tasks without
/// the clock needing its own mutex.
pub struct MockClock {
    now: AtomicU64,
}

impl MockClock {
    pub fn new(initial_secs: u64) -> Self {
        Self {
            now: AtomicU64::new(initial_secs),
        }
    }

    pub fn advance(&self, secs: u64) {
        self.now.fetch_add(secs, Ordering::SeqCst);
    }

    pub fn set(&self, secs: u64) {
        self.now.store(secs, Ordering::SeqCst);
    }
}

impl Clock for MockClock {
    fn unix_secs(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

/// Strategy for producing fresh session IDs. Production uses 32-byte
/// CSPRNG-derived hex strings (`RandomSessionIdGenerator`); tests use
/// `DeterministicSessionIdGenerator` so assertions can pin exact IDs.
pub trait SessionIdGenerator: Send + Sync {
    fn next_id(&self) -> String;
}

/// 32-byte hex IDs from the OS CSPRNG. ~10^77 keyspace — collision in
/// the lifetime of the network is negligible.
pub struct RandomSessionIdGenerator;

impl SessionIdGenerator for RandomSessionIdGenerator {
    fn next_id(&self) -> String {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf).expect("os csprng");
        hex::encode(buf)
    }
}

/// Counter-based IDs for tests. Stable across runs so test assertions
/// can pin exact strings.
pub struct DeterministicSessionIdGenerator {
    counter: AtomicU64,
}

impl DeterministicSessionIdGenerator {
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }
}

impl Default for DeterministicSessionIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionIdGenerator for DeterministicSessionIdGenerator {
    fn next_id(&self) -> String {
        let n = self.counter.fetch_add(1, Ordering::SeqCst);
        format!("test-session-{:04}", n)
    }
}

// ---------------------------------------------------------------------------
// Registry — collection of all in-flight sessions on the Active coordinator
// ---------------------------------------------------------------------------

/// Coordinator-side registry of in-flight Wraith Lite sessions. One
/// instance per Active coordinator; standbys hold a replicated copy
/// updated via gossip (task #38).
///
/// Internally a `Mutex<HashMap>`. Reads are common (every wallet RPC
/// pokes the registry) but contention should be low — operations are
/// short and the hashmap is small (sessions in flight, not lifetime
/// total).
pub struct LiteSessionRegistry {
    sessions: Mutex<HashMap<String, LiteSession>>,
}

impl LiteSessionRegistry {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Number of sessions currently tracked, regardless of state. Used by
    /// tests + diagnostics; production code should prefer counted
    /// queries below.
    pub fn len(&self) -> usize {
        self.sessions.lock().expect("registry mutex").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Snapshot a single session by ID. Returns a clone — caller doesn't
    /// hold the registry's lock while inspecting.
    pub fn get(&self, session_id: &str) -> Option<LiteSession> {
        self.sessions
            .lock()
            .expect("registry mutex")
            .get(session_id)
            .cloned()
    }

    /// All sessions matching `(tier, session_type)` that
    /// `is_open_for_new_participants(now) == true`. Used internally by
    /// `find_or_create_session` and by the wallet's
    /// `session.list_open(tier)` discovery path.
    pub fn open_sessions_at(
        &self,
        tier: LiteTier,
        session_type: SessionType,
        now: u64,
    ) -> Vec<LiteSession> {
        self.sessions
            .lock()
            .expect("registry mutex")
            .values()
            .filter(|s| {
                s.tier == tier
                    && s.session_type == session_type
                    && s.is_open_for_new_participants(now)
            })
            .cloned()
            .collect()
    }

    /// Insert a freshly-created session. Returns its descriptor.
    /// Refuses to overwrite an existing session_id (would indicate an
    /// id-generator collision; production CSPRNG makes this
    /// vanishingly unlikely but the assert catches dev/test mistakes).
    fn insert_new(&self, session: LiteSession) -> SessionDescriptor {
        let descriptor = SessionDescriptor::from_session(&session);
        let mut guard = self.sessions.lock().expect("registry mutex");
        assert!(
            !guard.contains_key(&session.session_id),
            "session_id collision (csprng broken or dev test using duplicate id): {}",
            session.session_id
        );
        guard.insert(session.session_id.clone(), session);
        descriptor
    }

    /// Add a participant to an existing session. Validates state +
    /// uniqueness, transitions to `Locked` if the round is now full.
    /// Returns the updated descriptor.
    pub fn add_participant(
        &self,
        session_id: &str,
        ghost_id: &str,
        bond_id: BondId,
        now: u64,
    ) -> Result<SessionDescriptor, LiteSessionError> {
        let mut guard = self.sessions.lock().expect("registry mutex");
        let session = guard
            .get_mut(session_id)
            .ok_or_else(|| LiteSessionError::NotFound(session_id.to_string()))?;
        // Must be Filling, and not yet expired/full.
        match &session.state {
            LiteSessionState::Filling {
                fill_window_expires_at,
            } => {
                if now >= *fill_window_expires_at {
                    return Err(LiteSessionError::NotAcceptingParticipants(
                        session_id.to_string(),
                        "filling-expired",
                    ));
                }
            }
            other => {
                return Err(LiteSessionError::NotAcceptingParticipants(
                    session_id.to_string(),
                    other.as_str(),
                ));
            }
        }
        if session.participants.len() >= session.tier.max_participants() {
            return Err(LiteSessionError::Full(
                session_id.to_string(),
                session.tier.max_participants() as u32,
            ));
        }
        if session.participants.iter().any(|p| p.ghost_id == ghost_id) {
            return Err(LiteSessionError::AlreadyRegistered(
                ghost_id.to_string(),
                session_id.to_string(),
            ));
        }
        session.participants.push(LiteSessionParticipant {
            ghost_id: ghost_id.to_string(),
            bond_id,
            registered_at: now,
        });
        // Lock immediately if we hit max — otherwise wait for the fill
        // window to expire.
        if session.participants.len() >= session.tier.max_participants() {
            session.state = LiteSessionState::Locked;
        }
        Ok(SessionDescriptor::from_session(session))
    }

    /// Process time-based transitions: any session whose fill window has
    /// expired transitions to either `Locked` (if min reached) or
    /// `Failed::FillWindowExpired` (if quorum never formed).
    ///
    /// Called by the coordinator's tick loop. Idempotent — running it
    /// repeatedly with the same `now` does nothing past the first call.
    /// Returns the list of session IDs whose state changed (for gossip
    /// in task #38).
    pub fn tick(&self, now: u64) -> Vec<String> {
        let mut changed = Vec::new();
        let mut guard = self.sessions.lock().expect("registry mutex");
        for (id, session) in guard.iter_mut() {
            let should_advance = match &session.state {
                LiteSessionState::Filling {
                    fill_window_expires_at,
                } => now >= *fill_window_expires_at,
                _ => false,
            };
            if !should_advance {
                continue;
            }
            if session.participants.len() >= session.tier.min_participants() {
                session.state = LiteSessionState::Locked;
            } else {
                session.state = LiteSessionState::Failed {
                    reason: "fill-window-expired-without-quorum".to_string(),
                };
            }
            changed.push(id.clone());
        }
        changed
    }

    /// Force a session to `Failed`. Used by the coordinator when a
    /// downstream invariant is violated (e.g. ledger disagreement,
    /// transaction-build error). Returns the new descriptor. `reason`
    /// takes `impl Into<String>` so callers can pass a `&'static str`
    /// literal or a runtime-formatted explanation.
    pub fn fail_session(
        &self,
        session_id: &str,
        reason: impl Into<String>,
    ) -> Result<SessionDescriptor, LiteSessionError> {
        let mut guard = self.sessions.lock().expect("registry mutex");
        let session = guard
            .get_mut(session_id)
            .ok_or_else(|| LiteSessionError::NotFound(session_id.to_string()))?;
        match &session.state {
            LiteSessionState::Complete | LiteSessionState::Failed { .. } => {
                return Err(LiteSessionError::InvalidTransition {
                    from: session.state.as_str(),
                    to: "failed",
                });
            }
            _ => {}
        }
        session.state = LiteSessionState::Failed {
            reason: reason.into(),
        };
        Ok(SessionDescriptor::from_session(session))
    }

    /// Advance a `Locked` session to `Signing`. Called after the round
    /// transaction has been built by `LiteRoundBuilder`.
    pub fn transition_to_signing(
        &self,
        session_id: &str,
    ) -> Result<SessionDescriptor, LiteSessionError> {
        self.transition_strict(session_id, "locked", LiteSessionState::Signing)
    }

    /// Advance a `Signing` session to `Broadcasting`. Called once
    /// signatures have been collected and the tx has been posted to the
    /// network.
    pub fn transition_to_broadcasting(
        &self,
        session_id: &str,
    ) -> Result<SessionDescriptor, LiteSessionError> {
        self.transition_strict(session_id, "signing", LiteSessionState::Broadcasting)
    }

    /// Advance a `Broadcasting` session to `Complete`. Called once the
    /// configured number of confirmations has landed.
    pub fn transition_to_complete(
        &self,
        session_id: &str,
    ) -> Result<SessionDescriptor, LiteSessionError> {
        self.transition_strict(session_id, "broadcasting", LiteSessionState::Complete)
    }

    fn transition_strict(
        &self,
        session_id: &str,
        from_label: &'static str,
        new_state: LiteSessionState,
    ) -> Result<SessionDescriptor, LiteSessionError> {
        let mut guard = self.sessions.lock().expect("registry mutex");
        let session = guard
            .get_mut(session_id)
            .ok_or_else(|| LiteSessionError::NotFound(session_id.to_string()))?;
        if session.state.as_str() != from_label {
            return Err(LiteSessionError::InvalidTransition {
                from: session.state.as_str(),
                to: new_state.as_str(),
            });
        }
        session.state = new_state;
        Ok(SessionDescriptor::from_session(session))
    }
}

impl Default for LiteSessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// find_or_create_session — the wallet's entry point
// ---------------------------------------------------------------------------

/// The demand-driven session creation path. Wallet calls this when it
/// wants to mix at `tier`; we either return an existing session at that
/// tier with open slots, or spin up a new one.
///
/// Pure orchestration over the registry, clock, and id generator —
/// makes the function fully deterministic in tests and trivial to
/// reason about.
pub fn find_or_create_session(
    tier: LiteTier,
    session_type: SessionType,
    registry: &LiteSessionRegistry,
    clock: &dyn Clock,
    id_gen: &dyn SessionIdGenerator,
) -> SessionDescriptor {
    let now = clock.unix_secs();
    // Prefer existing open sessions — that's how the wallet gets fast
    // fill (joining a session already half-filled by other users).
    let open = registry.open_sessions_at(tier, session_type, now);
    if let Some(s) = open.into_iter().next() {
        return SessionDescriptor::from_session(&s);
    }
    // None open — create a new session.
    let session = LiteSession {
        session_id: id_gen.next_id(),
        tier,
        session_type,
        created_at: now,
        state: LiteSessionState::Filling {
            fill_window_expires_at: now + LITE_FILL_WINDOW_SECS,
        },
        participants: Vec::new(),
    };
    registry.insert_new(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures() -> (LiteSessionRegistry, MockClock, DeterministicSessionIdGenerator) {
        (
            LiteSessionRegistry::new(),
            MockClock::new(1_000_000),
            DeterministicSessionIdGenerator::new(),
        )
    }

    #[test]
    fn find_or_create_creates_when_registry_empty() {
        let (reg, clock, gen) = fixtures();
        let d = find_or_create_session(
            LiteTier::Denom100kSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        assert_eq!(d.session_id, "test-session-0000");
        assert_eq!(d.tier_id, "100k_sats");
        assert_eq!(d.state, "filling");
        assert_eq!(d.slots_filled, 0);
        assert_eq!(d.slots_total, 20);
        assert_eq!(d.bond_amount_sats, 500);
        assert_eq!(d.fill_window_expires_at, Some(1_000_000 + 300));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn find_or_create_returns_existing_open_session() {
        let (reg, clock, gen) = fixtures();
        let d1 = find_or_create_session(
            LiteTier::Denom100kSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        let d2 = find_or_create_session(
            LiteTier::Denom100kSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        assert_eq!(d1.session_id, d2.session_id);
        // Only one session in the registry — the second call didn't
        // accidentally create a duplicate.
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn find_or_create_skips_sessions_at_other_tiers() {
        let (reg, clock, gen) = fixtures();
        let d_small = find_or_create_session(
            LiteTier::Denom100kSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        let d_big = find_or_create_session(
            LiteTier::Denom1mSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        assert_ne!(d_small.session_id, d_big.session_id);
        assert_eq!(d_small.tier_id, "100k_sats");
        assert_eq!(d_big.tier_id, "1m_sats");
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn find_or_create_skips_mix_when_asking_for_jump() {
        // Mix and Jump rounds at the same tier MUST NOT cross-contaminate
        // — they have different fee structures and the on-chain
        // transactions look different.
        let (reg, clock, gen) = fixtures();
        let mix = find_or_create_session(
            LiteTier::Denom100kSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        let jump = find_or_create_session(
            LiteTier::Denom100kSats,
            SessionType::Jump,
            &reg,
            &clock,
            &gen,
        );
        assert_ne!(mix.session_id, jump.session_id);
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn find_or_create_skips_full_sessions() {
        let (reg, clock, gen) = fixtures();
        let d = find_or_create_session(
            LiteTier::Denom100kSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        // Fill it to the max (20 for 100k tier).
        for i in 0..20 {
            let bond = BondId::new(format!("bond-{i}"));
            reg.add_participant(&d.session_id, &format!("ghost-{i}"), bond, 1_000_000)
                .expect("add up to max");
        }
        // Should be Locked now.
        let snap = reg.get(&d.session_id).unwrap();
        assert!(matches!(snap.state, LiteSessionState::Locked));
        // Now ask for another session — should create a fresh one.
        let d2 = find_or_create_session(
            LiteTier::Denom100kSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        assert_ne!(d.session_id, d2.session_id);
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn find_or_create_skips_sessions_past_fill_window() {
        let (reg, clock, gen) = fixtures();
        let d1 = find_or_create_session(
            LiteTier::Denom100kSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        // Advance past the fill window (300s).
        clock.advance(LITE_FILL_WINDOW_SECS + 1);
        let d2 = find_or_create_session(
            LiteTier::Denom100kSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        assert_ne!(d1.session_id, d2.session_id);
        // Old session is still in registry but no longer "open."
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn add_participant_increments_slot_count() {
        let (reg, clock, gen) = fixtures();
        let d = find_or_create_session(
            LiteTier::Denom100kSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        assert_eq!(d.slots_filled, 0);
        let d2 = reg
            .add_participant(
                &d.session_id,
                "alice",
                BondId::new("bond-alice"),
                1_000_000,
            )
            .unwrap();
        assert_eq!(d2.slots_filled, 1);
    }

    #[test]
    fn add_participant_rejects_duplicate_ghost_id() {
        let (reg, clock, gen) = fixtures();
        let d = find_or_create_session(
            LiteTier::Denom100kSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        reg.add_participant(
            &d.session_id,
            "alice",
            BondId::new("bond-alice-1"),
            1_000_000,
        )
        .unwrap();
        let err = reg
            .add_participant(
                &d.session_id,
                "alice",
                BondId::new("bond-alice-2"),
                1_000_000,
            )
            .expect_err("duplicate registration should fail");
        assert!(matches!(err, LiteSessionError::AlreadyRegistered(_, _)));
    }

    #[test]
    fn add_participant_rejects_when_locked() {
        // Filling to max → Locked. Subsequent registers fail with
        // NotAcceptingParticipants("locked") — the session is no longer
        // in `Filling`, so the state check fires before the size check.
        let (reg, clock, gen) = fixtures();
        let d = find_or_create_session(
            LiteTier::Denom100kSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        for i in 0..20 {
            reg.add_participant(
                &d.session_id,
                &format!("g-{i}"),
                BondId::new(format!("b-{i}")),
                1_000_000,
            )
            .unwrap();
        }
        let err = reg
            .add_participant(
                &d.session_id,
                "late",
                BondId::new("bond-late"),
                1_000_000,
            )
            .expect_err("locked round should reject new participants");
        match err {
            LiteSessionError::NotAcceptingParticipants(_, why) => {
                assert_eq!(why, "locked");
            }
            other => panic!("expected NotAcceptingParticipants(locked), got {other:?}"),
        }
    }

    #[test]
    fn add_participant_rejects_after_fill_window() {
        let (reg, clock, gen) = fixtures();
        let d = find_or_create_session(
            LiteTier::Denom100kSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        clock.advance(LITE_FILL_WINDOW_SECS + 1);
        let err = reg
            .add_participant(
                &d.session_id,
                "tardy",
                BondId::new("bond-tardy"),
                clock.unix_secs(),
            )
            .expect_err("expired fill window should reject");
        match err {
            LiteSessionError::NotAcceptingParticipants(_, why) => {
                assert_eq!(why, "filling-expired");
            }
            other => panic!("expected NotAcceptingParticipants, got {other:?}"),
        }
    }

    #[test]
    fn tick_locks_session_at_fill_window_when_quorum_reached() {
        let (reg, clock, gen) = fixtures();
        let d = find_or_create_session(
            LiteTier::Denom100kSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        // 5 participants is exactly min — enough for quorum.
        for i in 0..5 {
            reg.add_participant(
                &d.session_id,
                &format!("g-{i}"),
                BondId::new(format!("b-{i}")),
                clock.unix_secs(),
            )
            .unwrap();
        }
        clock.advance(LITE_FILL_WINDOW_SECS + 1);
        let changed = reg.tick(clock.unix_secs());
        assert_eq!(changed, vec![d.session_id.clone()]);
        let snap = reg.get(&d.session_id).unwrap();
        assert!(matches!(snap.state, LiteSessionState::Locked));
    }

    #[test]
    fn tick_fails_session_at_fill_window_without_quorum() {
        let (reg, clock, gen) = fixtures();
        let d = find_or_create_session(
            LiteTier::Denom100kSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        // 4 < min participants of 5.
        for i in 0..4 {
            reg.add_participant(
                &d.session_id,
                &format!("g-{i}"),
                BondId::new(format!("b-{i}")),
                clock.unix_secs(),
            )
            .unwrap();
        }
        clock.advance(LITE_FILL_WINDOW_SECS + 1);
        reg.tick(clock.unix_secs());
        let snap = reg.get(&d.session_id).unwrap();
        match snap.state {
            LiteSessionState::Failed { ref reason } => {
                assert_eq!(reason, "fill-window-expired-without-quorum");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn tick_is_idempotent() {
        let (reg, clock, gen) = fixtures();
        let _ = find_or_create_session(
            LiteTier::Denom100kSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        clock.advance(LITE_FILL_WINDOW_SECS + 1);
        let first = reg.tick(clock.unix_secs());
        let second = reg.tick(clock.unix_secs());
        assert!(!first.is_empty());
        assert!(
            second.is_empty(),
            "second tick at same time should be a no-op"
        );
    }

    #[test]
    fn lifecycle_locked_to_complete_via_strict_transitions() {
        let (reg, clock, gen) = fixtures();
        let d = find_or_create_session(
            LiteTier::Denom100kSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        // Fill to max → Locked.
        for i in 0..20 {
            reg.add_participant(
                &d.session_id,
                &format!("g-{i}"),
                BondId::new(format!("b-{i}")),
                clock.unix_secs(),
            )
            .unwrap();
        }
        // Locked → Signing → Broadcasting → Complete.
        let r = reg.transition_to_signing(&d.session_id).unwrap();
        assert_eq!(r.state, "signing");
        let r = reg.transition_to_broadcasting(&d.session_id).unwrap();
        assert_eq!(r.state, "broadcasting");
        let r = reg.transition_to_complete(&d.session_id).unwrap();
        assert_eq!(r.state, "complete");
    }

    #[test]
    fn invalid_transitions_are_rejected() {
        let (reg, clock, gen) = fixtures();
        let d = find_or_create_session(
            LiteTier::Denom100kSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        // Cannot go Filling → Broadcasting.
        let err = reg
            .transition_to_broadcasting(&d.session_id)
            .expect_err("filling -> broadcasting is invalid");
        assert!(matches!(err, LiteSessionError::InvalidTransition { .. }));
        // Cannot go Filling → Complete.
        let err = reg
            .transition_to_complete(&d.session_id)
            .expect_err("filling -> complete is invalid");
        assert!(matches!(err, LiteSessionError::InvalidTransition { .. }));
    }

    #[test]
    fn fail_session_works_from_any_non_terminal_state() {
        let (reg, clock, gen) = fixtures();
        let d = find_or_create_session(
            LiteTier::Denom100kSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        let r = reg.fail_session(&d.session_id, "test-abort").unwrap();
        assert_eq!(r.state, "failed");
        // Re-failing a Failed session is rejected.
        let err = reg
            .fail_session(&d.session_id, "test-abort-again")
            .expect_err("can't fail an already-failed session");
        assert!(matches!(err, LiteSessionError::InvalidTransition { .. }));
    }

    #[test]
    fn descriptor_round_trips_through_serde() {
        let (reg, clock, gen) = fixtures();
        let d = find_or_create_session(
            LiteTier::Denom100kSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        let s = serde_json::to_string(&d).unwrap();
        let back: SessionDescriptor = serde_json::from_str(&s).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn random_session_id_generator_yields_unique_ids() {
        let g = RandomSessionIdGenerator;
        let id1 = g.next_id();
        let id2 = g.next_id();
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 64); // 32 bytes hex
        assert!(id1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn deterministic_id_generator_is_actually_deterministic() {
        let g = DeterministicSessionIdGenerator::new();
        assert_eq!(g.next_id(), "test-session-0000");
        assert_eq!(g.next_id(), "test-session-0001");
        assert_eq!(g.next_id(), "test-session-0002");
    }

    #[test]
    fn open_sessions_at_returns_only_open_filling_sessions() {
        let (reg, clock, gen) = fixtures();
        let _open = find_or_create_session(
            LiteTier::Denom100kSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        let other_tier = find_or_create_session(
            LiteTier::Denom1mSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        // Fill the second one to max so it locks.
        for i in 0..LiteTier::Denom1mSats.max_participants() {
            reg.add_participant(
                &other_tier.session_id,
                &format!("g-{i}"),
                BondId::new(format!("b-{i}")),
                clock.unix_secs(),
            )
            .unwrap();
        }
        // Asking for 1m_sats should NOT find the locked one — should
        // create a new session.
        let new_1m = find_or_create_session(
            LiteTier::Denom1mSats,
            SessionType::Mix,
            &reg,
            &clock,
            &gen,
        );
        assert_ne!(new_1m.session_id, other_tier.session_id);
        // Registry now has 3 sessions.
        assert_eq!(reg.len(), 3);
    }
}
