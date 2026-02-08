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
//| FILE: session.rs                                                                                                     |
//|======================================================================================================================|

//! Wraith mixing session management

use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{Duration, Instant, SystemTime};

use crate::denomination::WraithDenomination;
use crate::phase::{Phase, PhaseExecution};
use crate::tier::ParticipantTier;
use crate::{
    COLLECTING_INPUTS_TIMEOUT_SECS, DEFAULT_TIMEOUT_SECS, EARLY_EXECUTION_THRESHOLD,
    MIN_EXECUTION_THRESHOLD, PHASE_CONFIRMATION_TIMEOUT_SECS, PHASE_EXECUTION_TIMEOUT_SECS,
    WAITING_PARTICIPANTS_TIMEOUT_SECS,
};

/// Session registry for tracking seen session IDs (WR-L1)
///
/// Prevents session ID collisions and replay attacks.
///
/// CRIT-2 SECURITY: This registry is in-memory only. On process restart,
/// all session tracking is lost, which could allow replay attacks if sessions
/// from before the restart are still valid. Callers MUST:
/// 1. Call `requires_persistence_warning()` on startup and handle accordingly
/// 2. Either use persistent storage or ensure all pre-restart sessions are expired
#[derive(Debug)]
pub struct SessionRegistry {
    /// Set of session IDs that have been seen
    seen_sessions: HashSet<[u8; 32]>,
    /// Whether the caller has acknowledged the in-memory limitation
    persistence_acknowledged: bool,
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionRegistry {
    /// Create a new session registry
    ///
    /// CRIT-2: The registry starts in unacknowledged mode. Callers must call
    /// `acknowledge_in_memory_mode()` before using the registry.
    pub fn new() -> Self {
        Self {
            seen_sessions: HashSet::new(),
            persistence_acknowledged: false,
        }
    }

    /// LOW-WRAITH-3 FIX: Enforce persistence acknowledgment
    ///
    /// Returns true if the registry is in-memory only and the caller has not
    /// yet acknowledged this limitation. Callers MUST either:
    /// 1. Implement persistent storage and not use this registry
    /// 2. Call `acknowledge_in_memory_mode()` after ensuring all pre-restart
    ///    sessions have expired (via timeout or explicit invalidation)
    ///
    /// Unlike previous implementation, all registry methods now ERROR if
    /// this is not acknowledged, preventing accidental unprotected use.
    pub fn requires_persistence_warning(&self) -> bool {
        !self.persistence_acknowledged
    }

    /// LOW-WRAITH-3 FIX: Acknowledge that in-memory mode is acceptable
    ///
    /// Call this ONLY after verifying that:
    /// - All sessions from before restart have expired, OR
    /// - The system has been down long enough that session timeouts have passed, OR
    /// - This is a fresh deployment with no prior sessions
    ///
    /// # Safety
    ///
    /// Calling this without ensuring the above conditions could allow replay attacks
    /// from sessions that existed before the restart. This is enforced by requiring
    /// explicit acknowledgment - all registry methods will error until this is called.
    pub fn acknowledge_in_memory_mode(&mut self) {
        tracing::warn!(
            "SessionRegistry: Acknowledging in-memory mode. \
             Ensure all pre-restart sessions have expired to prevent replay attacks."
        );
        self.persistence_acknowledged = true;
    }

    /// CRIT-2 FIX: Clear registry and reset to fresh state
    ///
    /// Use this on restart after waiting for all previous sessions to expire.
    /// This method also requires re-acknowledgment of in-memory mode.
    pub fn reset_for_restart(&mut self) {
        self.seen_sessions.clear();
        self.persistence_acknowledged = false;
    }

    /// Check if a session ID has been seen before
    ///
    /// CRIT-2: Returns error if persistence has not been acknowledged
    pub fn is_seen(&self, session_id: &[u8; 32]) -> Result<bool, crate::WraithError> {
        if !self.persistence_acknowledged {
            return Err(crate::WraithError::InvalidState {
                expected: "persistence acknowledged".to_string(),
                actual: "registry not initialized - call acknowledge_in_memory_mode()".to_string(),
            });
        }
        Ok(self.seen_sessions.contains(session_id))
    }

    /// Register a session ID
    ///
    /// Returns Ok(true) if the session ID was new, Ok(false) if it was already seen.
    /// Returns Err if persistence has not been acknowledged.
    pub fn register(&mut self, session_id: [u8; 32]) -> Result<bool, crate::WraithError> {
        if !self.persistence_acknowledged {
            return Err(crate::WraithError::InvalidState {
                expected: "persistence acknowledged".to_string(),
                actual: "registry not initialized - call acknowledge_in_memory_mode()".to_string(),
            });
        }
        Ok(self.seen_sessions.insert(session_id))
    }

    /// Check and register a session ID in one operation
    ///
    /// Returns Ok(()) if the session ID was new, Err if it was already seen.
    /// Also returns Err if persistence has not been acknowledged.
    pub fn check_and_register(&mut self, session_id: [u8; 32]) -> Result<(), crate::WraithError> {
        if !self.persistence_acknowledged {
            return Err(crate::WraithError::InvalidState {
                expected: "persistence acknowledged".to_string(),
                actual: "registry not initialized - call acknowledge_in_memory_mode()".to_string(),
            });
        }
        if !self.seen_sessions.insert(session_id) {
            return Err(crate::WraithError::InvalidInput(format!(
                "Session ID {} already exists (collision or replay)",
                hex::encode(session_id)
            )));
        }
        Ok(())
    }

    /// Get the number of registered sessions
    pub fn session_count(&self) -> usize {
        self.seen_sessions.len()
    }

    /// Clear old sessions (call periodically to prevent unbounded growth)
    ///
    /// Note: This does not reset the persistence acknowledgment.
    pub fn clear(&mut self) {
        self.seen_sessions.clear();
    }
}

// ============================================================================
// H-6: Persistent Session Registry
// ============================================================================

/// H-6: Trait for persisting session IDs to durable storage
///
/// Implement this trait to provide crash-safe session tracking.
/// Without persistence, session replay attacks are possible after restarts.
#[allow(dead_code)] // Prepared for persistence integration
pub trait SessionPersistence: Send + Sync {
    /// Store a session ID in persistent storage
    fn store_session(&self, session_id: &[u8; 32]) -> Result<(), crate::WraithError>;

    /// Check if a session ID exists in persistent storage
    fn session_exists(&self, session_id: &[u8; 32]) -> Result<bool, crate::WraithError>;

    /// Load all session IDs from persistent storage
    /// Used on startup to restore in-memory state
    fn load_all_sessions(&self) -> Result<Vec<[u8; 32]>, crate::WraithError>;

    /// Remove expired sessions older than the given timestamp
    fn cleanup_expired(&self, before_timestamp: u64) -> Result<usize, crate::WraithError>;
}

/// H-6: Session registry with optional persistent storage
///
/// This registry provides crash-safe session tracking when a persistence
/// backend is provided. It combines in-memory caching with durable storage.
///
/// On startup:
/// 1. Load all session IDs from persistent storage
/// 2. Populate in-memory cache
/// 3. Acknowledge in-memory mode (automatic when persistence is available)
#[allow(dead_code)] // Prepared for persistence integration
pub struct PersistentSessionRegistry {
    /// In-memory cache for fast lookup
    in_memory: SessionRegistry,
    /// Optional persistence backend
    persistence: Option<std::sync::Arc<dyn SessionPersistence>>,
    /// Session expiry duration in seconds (default: 7 days)
    expiry_secs: u64,
}

impl std::fmt::Debug for PersistentSessionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistentSessionRegistry")
            .field("in_memory", &self.in_memory)
            .field("persistence", &self.persistence.is_some())
            .field("expiry_secs", &self.expiry_secs)
            .finish()
    }
}

impl Default for PersistentSessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)] // Prepared for persistence integration
impl PersistentSessionRegistry {
    /// Default session expiry: 7 days (matches maximum session duration)
    const DEFAULT_EXPIRY_SECS: u64 = 7 * 24 * 60 * 60;

    /// Create a new persistent session registry without a backend
    ///
    /// Without a persistence backend, this behaves like the basic SessionRegistry
    /// and requires explicit acknowledgment of in-memory mode.
    pub fn new() -> Self {
        Self {
            in_memory: SessionRegistry::new(),
            persistence: None,
            expiry_secs: Self::DEFAULT_EXPIRY_SECS,
        }
    }

    /// Create with a persistence backend
    ///
    /// This automatically:
    /// 1. Loads existing sessions from storage
    /// 2. Acknowledges in-memory mode (persistence provides crash safety)
    ///
    /// # Errors
    /// Returns error if loading from persistence fails
    pub fn with_persistence(
        persistence: std::sync::Arc<dyn SessionPersistence>,
    ) -> Result<Self, crate::WraithError> {
        let mut registry = Self {
            in_memory: SessionRegistry::new(),
            persistence: Some(persistence.clone()),
            expiry_secs: Self::DEFAULT_EXPIRY_SECS,
        };

        // Load existing sessions from persistent storage
        let sessions = persistence.load_all_sessions()?;
        registry.in_memory.acknowledge_in_memory_mode();

        for session_id in sessions {
            // Use register directly since we've already acknowledged
            let _ = registry.in_memory.register(session_id);
        }

        tracing::info!(
            session_count = registry.in_memory.session_count(),
            "H-6: Loaded session registry from persistent storage"
        );

        Ok(registry)
    }

    /// Set custom expiry duration
    pub fn with_expiry(mut self, expiry_secs: u64) -> Self {
        self.expiry_secs = expiry_secs;
        self
    }

    /// Check if persistence is available
    pub fn has_persistence(&self) -> bool {
        self.persistence.is_some()
    }

    /// Check if the registry requires persistence warning
    ///
    /// Returns true if no persistence backend is configured and the caller
    /// has not acknowledged in-memory mode.
    pub fn requires_persistence_warning(&self) -> bool {
        self.persistence.is_none() && self.in_memory.requires_persistence_warning()
    }

    /// Acknowledge in-memory mode (only needed without persistence)
    pub fn acknowledge_in_memory_mode(&mut self) {
        self.in_memory.acknowledge_in_memory_mode();
    }

    /// Check and register a session ID
    ///
    /// Returns Ok(()) if the session ID is new, Err if already seen.
    /// If persistence is available, also stores to durable storage.
    pub fn check_and_register(&mut self, session_id: [u8; 32]) -> Result<(), crate::WraithError> {
        // Check in-memory first (fast path)
        self.in_memory.check_and_register(session_id)?;

        // If persistence is available, also store durably
        if let Some(ref persistence) = self.persistence {
            if let Err(e) = persistence.store_session(&session_id) {
                // Rollback in-memory registration on persistence failure
                // Note: We can't easily remove from HashSet, but the session will be
                // rejected on next attempt anyway since it's marked as seen
                tracing::error!(
                    session_id = %hex::encode(session_id),
                    error = %e,
                    "H-6: Failed to persist session ID"
                );
                return Err(e);
            }
        }

        Ok(())
    }

    /// Check if a session ID has been seen
    pub fn is_seen(&self, session_id: &[u8; 32]) -> Result<bool, crate::WraithError> {
        // Check in-memory cache first
        if self.in_memory.is_seen(session_id)? {
            return Ok(true);
        }

        // If not in cache but persistence is available, check storage
        // (This handles the case where cache was cleared but storage wasn't)
        if let Some(ref persistence) = self.persistence {
            return persistence.session_exists(session_id);
        }

        Ok(false)
    }

    /// Get the number of sessions in the in-memory cache
    pub fn session_count(&self) -> usize {
        self.in_memory.session_count()
    }

    /// Cleanup expired sessions
    ///
    /// Removes sessions older than expiry_secs from both in-memory cache
    /// and persistent storage.
    pub fn cleanup_expired(&mut self) -> Result<usize, crate::WraithError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = now.saturating_sub(self.expiry_secs);

        // Clear in-memory (we don't track timestamps in HashSet, so clear all)
        // The persistent storage tracks timestamps
        self.in_memory.clear();

        // Cleanup persistent storage if available
        if let Some(ref persistence) = self.persistence {
            let removed = persistence.cleanup_expired(cutoff)?;

            // Reload from persistent storage to repopulate in-memory cache
            let sessions = persistence.load_all_sessions()?;
            for session_id in sessions {
                let _ = self.in_memory.register(session_id);
            }

            return Ok(removed);
        }

        Ok(0)
    }

    /// Reset for restart (clears both in-memory and requires re-initialization)
    pub fn reset_for_restart(&mut self) {
        self.in_memory.reset_for_restart();
    }
}

/// State of a Wraith session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SessionState {
    /// Waiting for participants to join
    WaitingForParticipants,
    /// Collecting inputs and blinded outputs
    CollectingInputs,
    /// Executing Phase 1 (split)
    ExecutingPhase1,
    /// Waiting for Phase 1 confirmation
    WaitingPhase1Confirmation,
    /// Executing Phase 2 (merge)
    ExecutingPhase2,
    /// Waiting for Phase 2 confirmation
    WaitingPhase2Confirmation,
    /// Session completed successfully
    Completed,
    /// Session failed
    Failed,
    /// Session refunded
    Refunded,
}

impl SessionState {
    /// Check if session is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            SessionState::Completed | SessionState::Failed | SessionState::Refunded
        )
    }

    /// Check if session can accept new participants
    pub fn can_accept_participants(&self) -> bool {
        matches!(self, SessionState::WaitingForParticipants)
    }

    /// Get state name
    pub fn name(&self) -> &'static str {
        match self {
            SessionState::WaitingForParticipants => "Waiting for Participants",
            SessionState::CollectingInputs => "Collecting Inputs",
            SessionState::ExecutingPhase1 => "Executing Phase 1",
            SessionState::WaitingPhase1Confirmation => "Waiting Phase 1 Confirmation",
            SessionState::ExecutingPhase2 => "Executing Phase 2",
            SessionState::WaitingPhase2Confirmation => "Waiting Phase 2 Confirmation",
            SessionState::Completed => "Completed",
            SessionState::Failed => "Failed",
            SessionState::Refunded => "Refunded",
        }
    }
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Session configuration for customizable timeouts (WR4-L1)
#[derive(Debug, Clone, Default)]
pub struct SessionConfig {
    /// Custom timeout in seconds (defaults to DEFAULT_TIMEOUT_SECS)
    pub timeout_secs: Option<u64>,
}

impl SessionConfig {
    /// Create a new session config with custom timeout
    pub fn with_timeout(timeout_secs: u64) -> Self {
        Self {
            timeout_secs: Some(timeout_secs),
        }
    }
}

/// A Wraith mixing session
///
/// MED-CRYPTO-1 FIX: Uses both Instant (monotonic) and SystemTime for timeout
/// calculations to handle system suspend/resume correctly.
#[derive(Debug, Clone)]
pub struct WraithSession {
    /// Unique session ID
    session_id: [u8; 32],
    /// Participant tier
    tier: ParticipantTier,
    /// Denomination for this session
    denomination: WraithDenomination,
    /// Current state
    state: SessionState,
    /// Number of registered participants
    participant_count: usize,
    /// Phase 1 execution (if started)
    phase1: Option<PhaseExecution>,
    /// Phase 2 execution (if started)
    phase2: Option<PhaseExecution>,
    /// Session created timestamp (Unix time - for external reporting)
    #[allow(dead_code)]
    created_at: u64,
    /// Session timeout instant (monotonic - for timeout calculations) (WR-L3)
    timeout_instant: Instant,
    /// MED-CRYPTO-1: Session creation time for suspend-aware timeout
    /// This is used alongside timeout_instant to detect suspend/resume
    creation_system_time: SystemTime,
    /// Session timeout duration from creation
    timeout_duration_secs: u64,
    /// M-6: Total extension time used (to enforce MAX_EXTENSION_SECS limit)
    total_extensions_secs: u64,
}

impl WraithSession {
    /// Create a new Wraith session with default configuration
    pub fn new(tier: ParticipantTier, denomination: WraithDenomination) -> Self {
        Self::with_config(tier, denomination, SessionConfig::default())
    }

    /// Create a new Wraith session with custom configuration (WR4-L1)
    ///
    /// Allows configurable timeout for different use cases:
    /// - Short timeouts for testing
    /// - Long timeouts for high-participant sessions
    pub fn with_config(
        tier: ParticipantTier,
        denomination: WraithDenomination,
        config: SessionConfig,
    ) -> Self {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Generate cryptographically secure random session ID
        // SECURITY: Using full 32 bytes of randomness prevents session ID prediction/collision
        // M-1 FIX: Use OsRng for cryptographic security instead of thread_rng()
        let mut session_id = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut session_id);

        // Use monotonic clock for timeout (WR-L3)
        // This prevents NTP manipulation attacks on session timeouts
        // WR4-L1: Allow configurable timeout
        let timeout_duration = config.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
        let timeout_instant = Instant::now() + Duration::from_secs(timeout_duration);

        Self {
            session_id,
            tier,
            denomination,
            state: SessionState::WaitingForParticipants,
            participant_count: 0,
            phase1: None,
            phase2: None,
            created_at: now_unix,
            timeout_instant,
            // MED-CRYPTO-1: Initialize SystemTime for suspend-aware timeout
            creation_system_time: std::time::SystemTime::now(),
            timeout_duration_secs: timeout_duration,
            total_extensions_secs: 0,
        }
    }

    /// Get session ID
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Get session ID as hex
    pub fn session_id_hex(&self) -> String {
        hex::encode(self.session_id)
    }

    /// Get tier
    pub fn tier(&self) -> &ParticipantTier {
        &self.tier
    }

    /// Get denomination
    pub fn denomination(&self) -> &WraithDenomination {
        &self.denomination
    }

    /// Get current state
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Get participant count
    pub fn participant_count(&self) -> usize {
        self.participant_count
    }

    /// Check if session has minimum participants
    pub fn has_minimum_participants(&self) -> bool {
        self.tier.meets_minimum(self.participant_count)
    }

    /// Get fill percentage
    pub fn fill_percentage(&self) -> f64 {
        self.tier.fill_percentage(self.participant_count)
    }

    /// Check if session can force execute (50% threshold)
    pub fn can_force_execute(&self) -> bool {
        self.fill_percentage() >= MIN_EXECUTION_THRESHOLD * 100.0
    }

    /// Check if session can early execute (75% threshold)
    pub fn can_early_execute(&self) -> bool {
        self.fill_percentage() >= EARLY_EXECUTION_THRESHOLD * 100.0
    }

    /// Check if session has timed out
    ///
    /// MED-CRYPTO-1 FIX: Uses both monotonic clock (Instant) AND wall-clock (SystemTime)
    /// to handle system suspend/resume correctly. When a system suspends:
    /// - Instant::now() freezes during suspend (doesn't account for sleep time)
    /// - SystemTime::now() advances during suspend
    ///
    /// We timeout if EITHER clock indicates timeout has elapsed, providing
    /// protection against both NTP manipulation (via Instant) and suspend evasion
    /// (via SystemTime).
    pub fn is_timed_out(&self) -> bool {
        // Check monotonic clock (protects against NTP manipulation)
        let monotonic_expired = Instant::now() >= self.timeout_instant;

        // Check wall clock (protects against suspend evasion)
        let wall_clock_expired = match self.creation_system_time.elapsed() {
            Ok(elapsed) => elapsed.as_secs() >= self.timeout_duration_secs + self.total_extensions_secs,
            Err(_) => {
                // System clock went backwards - be conservative and don't timeout
                // This can happen on NTP adjustments, handled safely
                false
            }
        };

        // Session is timed out if EITHER clock says so
        monotonic_expired || wall_clock_expired
    }

    /// Get remaining time in seconds
    ///
    /// MED-CRYPTO-1 FIX: Returns the minimum of monotonic and wall-clock remaining time.
    /// This ensures we report the most conservative (lowest) remaining time,
    /// which protects against both NTP manipulation and suspend evasion.
    pub fn remaining_secs(&self) -> u64 {
        // Calculate remaining from monotonic clock
        let now = Instant::now();
        let monotonic_remaining = if now >= self.timeout_instant {
            0
        } else {
            (self.timeout_instant - now).as_secs()
        };

        // Calculate remaining from wall clock
        let total_timeout = self.timeout_duration_secs + self.total_extensions_secs;
        let wall_remaining = match self.creation_system_time.elapsed() {
            Ok(elapsed) => total_timeout.saturating_sub(elapsed.as_secs()),
            Err(_) => {
                // System clock went backwards - return monotonic value only
                return monotonic_remaining;
            }
        };

        // Return the minimum (most conservative) of the two
        monotonic_remaining.min(wall_remaining)
    }

    /// Get appropriate timeout for the current state
    fn timeout_for_state(state: SessionState) -> u64 {
        match state {
            SessionState::WaitingForParticipants => WAITING_PARTICIPANTS_TIMEOUT_SECS,
            SessionState::CollectingInputs => COLLECTING_INPUTS_TIMEOUT_SECS,
            SessionState::ExecutingPhase1 | SessionState::ExecutingPhase2 => {
                PHASE_EXECUTION_TIMEOUT_SECS
            }
            SessionState::WaitingPhase1Confirmation | SessionState::WaitingPhase2Confirmation => {
                PHASE_CONFIRMATION_TIMEOUT_SECS
            }
            _ => DEFAULT_TIMEOUT_SECS,
        }
    }

    /// Reset timeout for a new state transition
    ///
    /// Uses monotonic clock (Instant) to prevent NTP manipulation attacks (WR-L3).
    fn reset_timeout(&mut self) {
        let new_duration = Self::timeout_for_state(self.state);
        self.timeout_instant = Instant::now() + Duration::from_secs(new_duration);
        self.timeout_duration_secs = new_duration;
    }

    /// Maximum total extension allowed in seconds (24 hours)
    /// M-6 FIX: Prevents unbounded timeout extension attacks
    /// This limits how much ADDITIONAL time can be added beyond the initial timeout
    pub const MAX_EXTENSION_SECS: u64 = 24 * 60 * 60;

    /// Extend timeout by a specific duration (e.g., for slow confirmations)
    ///
    /// Uses monotonic clock (Instant) to prevent NTP manipulation attacks (WR-L3).
    ///
    /// M-6 FIX: Total cumulative extensions cannot exceed MAX_EXTENSION_SECS.
    /// This prevents attackers from keeping sessions alive indefinitely through
    /// repeated extensions. Once the extension budget is exhausted, no further
    /// extensions are allowed.
    pub fn extend_timeout(&mut self, additional_secs: u64) {
        // M-6: Calculate remaining extension budget
        let remaining_budget = Self::MAX_EXTENSION_SECS.saturating_sub(self.total_extensions_secs);

        // Clamp to remaining budget
        let actual_extension = additional_secs.min(remaining_budget);

        if actual_extension > 0 {
            self.timeout_instant += Duration::from_secs(actual_extension);
            self.timeout_duration_secs =
                self.timeout_duration_secs.saturating_add(actual_extension);
            self.total_extensions_secs =
                self.total_extensions_secs.saturating_add(actual_extension);
        }
    }

    /// Get timeout deadline as approximate Unix timestamp
    ///
    /// Note: This is computed from the monotonic timeout for external reporting.
    /// Internal timeout calculations use the monotonic Instant directly (WR-L3).
    pub fn timeout_at(&self) -> u64 {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now_unix + self.remaining_secs()
    }

    /// Add a participant
    pub fn add_participant(&mut self) -> bool {
        if !self.state.can_accept_participants() {
            return false;
        }
        if self.participant_count >= self.tier.max_participants() {
            return false;
        }
        self.participant_count += 1;
        true
    }

    /// Transition to collecting inputs
    pub fn start_collecting(&mut self) -> Result<(), crate::WraithError> {
        if self.state != SessionState::WaitingForParticipants {
            return Err(crate::WraithError::InvalidState {
                expected: "WaitingForParticipants".to_string(),
                actual: format!("{:?}", self.state),
            });
        }
        if !self.has_minimum_participants() {
            return Err(crate::WraithError::NotEnoughParticipants(
                self.participant_count,
                self.tier.min_participants(),
            ));
        }
        self.state = SessionState::CollectingInputs;
        self.reset_timeout();
        Ok(())
    }

    /// Start phase 1
    pub fn start_phase1(&mut self) -> Result<(), crate::WraithError> {
        if self.state != SessionState::CollectingInputs {
            return Err(crate::WraithError::InvalidState {
                expected: "CollectingInputs".to_string(),
                actual: format!("{:?}", self.state),
            });
        }
        self.state = SessionState::ExecutingPhase1;
        self.phase1 = Some(PhaseExecution::new(Phase::Split, self.participant_count));
        self.reset_timeout();
        Ok(())
    }

    /// Start phase 2
    pub fn start_phase2(&mut self) -> Result<(), crate::WraithError> {
        if self.state != SessionState::WaitingPhase1Confirmation {
            return Err(crate::WraithError::InvalidState {
                expected: "WaitingPhase1Confirmation".to_string(),
                actual: format!("{:?}", self.state),
            });
        }
        self.state = SessionState::ExecutingPhase2;
        self.phase2 = Some(PhaseExecution::new(Phase::Merge, self.participant_count));
        self.reset_timeout();
        Ok(())
    }

    /// Mark phase 1 as confirmed
    pub fn confirm_phase1(&mut self, height: u32) -> Result<(), crate::WraithError> {
        if let Some(ref mut phase1) = self.phase1 {
            phase1.confirm(height);
        }
        if self.state == SessionState::ExecutingPhase1 {
            self.state = SessionState::WaitingPhase1Confirmation;
            self.reset_timeout();
        }
        Ok(())
    }

    /// Mark phase 2 as confirmed (session complete)
    pub fn confirm_phase2(&mut self, height: u32) -> Result<(), crate::WraithError> {
        if let Some(ref mut phase2) = self.phase2 {
            phase2.confirm(height);
        }
        if self.state == SessionState::ExecutingPhase2 {
            self.state = SessionState::Completed;
            // No timeout reset needed for terminal state
        }
        Ok(())
    }

    /// WR4-M3: Mark session as failed (returns Result to prevent invalid transitions)
    ///
    /// Returns an error if the session is already in a terminal state.
    /// This prevents confusing state tracking where a completed session
    /// could be marked as failed.
    pub fn fail(&mut self) -> Result<(), crate::WraithError> {
        if self.state.is_terminal() {
            return Err(crate::WraithError::InvalidState {
                expected: "non-terminal state".to_string(),
                actual: format!("{:?}", self.state),
            });
        }
        self.state = SessionState::Failed;
        Ok(())
    }

    /// WR4-M3: Mark session as refunded (returns Result to prevent invalid transitions)
    ///
    /// Returns an error if the session is already in a terminal state.
    /// This prevents confusing state tracking where a completed session
    /// could be marked as refunded.
    pub fn refund(&mut self) -> Result<(), crate::WraithError> {
        if self.state.is_terminal() {
            return Err(crate::WraithError::InvalidState {
                expected: "non-terminal state".to_string(),
                actual: format!("{:?}", self.state),
            });
        }
        self.state = SessionState::Refunded;
        Ok(())
    }

    /// Get phase 1 execution
    pub fn phase1(&self) -> Option<&PhaseExecution> {
        self.phase1.as_ref()
    }

    /// Get phase 1 execution (mutable)
    pub fn phase1_mut(&mut self) -> Option<&mut PhaseExecution> {
        self.phase1.as_mut()
    }

    /// Get phase 2 execution
    pub fn phase2(&self) -> Option<&PhaseExecution> {
        self.phase2.as_ref()
    }

    /// Get phase 2 execution (mutable)
    pub fn phase2_mut(&mut self) -> Option<&mut PhaseExecution> {
        self.phase2.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = WraithSession::new(ParticipantTier::Standard, WraithDenomination::Small);

        assert_eq!(session.state(), SessionState::WaitingForParticipants);
        assert_eq!(session.participant_count(), 0);
        assert!(!session.has_minimum_participants());
    }

    #[test]
    fn test_add_participants() {
        // Use Whale tier (160 minimum) for practical test values
        let mut session = WraithSession::new(ParticipantTier::Whale, WraithDenomination::Small);

        for _ in 0..160 {
            assert!(session.add_participant());
        }

        assert_eq!(session.participant_count(), 160);
        assert!(session.has_minimum_participants());
    }

    #[test]
    fn test_fill_percentage() {
        // Use Whale tier (160 minimum) for practical test values
        let mut session = WraithSession::new(ParticipantTier::Whale, WraithDenomination::Small);

        for _ in 0..80 {
            session.add_participant();
        }

        // 80/160 = 50%
        assert!((session.fill_percentage() - 50.0).abs() < 1.0);
    }

    #[test]
    fn test_session_lifecycle() {
        // Use Whale tier (160 minimum) for practical test values
        let mut session = WraithSession::new(ParticipantTier::Whale, WraithDenomination::Small);

        // Add minimum participants
        for _ in 0..160 {
            session.add_participant();
        }

        session.start_collecting().unwrap();
        assert_eq!(session.state(), SessionState::CollectingInputs);

        session.start_phase1().unwrap();
        assert_eq!(session.state(), SessionState::ExecutingPhase1);
    }

    /// WR-L1 Test: Session registry prevents duplicate session IDs
    #[test]
    fn test_session_registry() {
        let mut registry = SessionRegistry::new();

        // CRIT-2: Must acknowledge in-memory mode before using registry
        assert!(registry.requires_persistence_warning());
        registry.acknowledge_in_memory_mode();
        assert!(!registry.requires_persistence_warning());

        let session_id1 = [0x01u8; 32];
        let session_id2 = [0x02u8; 32];

        // First registration should succeed
        assert!(registry.register(session_id1).unwrap());
        assert_eq!(registry.session_count(), 1);

        // Same ID should fail (returns false)
        assert!(!registry.register(session_id1).unwrap());
        assert_eq!(registry.session_count(), 1);

        // Different ID should succeed
        assert!(registry.register(session_id2).unwrap());
        assert_eq!(registry.session_count(), 2);

        // Check is_seen
        assert!(registry.is_seen(&session_id1).unwrap());
        assert!(registry.is_seen(&session_id2).unwrap());
        assert!(!registry.is_seen(&[0x03u8; 32]).unwrap());
    }

    /// WR-L1 Test: check_and_register returns proper errors
    #[test]
    fn test_session_registry_check_and_register() {
        let mut registry = SessionRegistry::new();
        registry.acknowledge_in_memory_mode();

        let session_id = [0x42u8; 32];

        // First check_and_register should succeed
        assert!(registry.check_and_register(session_id).is_ok());

        // Second should fail with error
        let result = registry.check_and_register(session_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    /// CRIT-2 Test: Registry requires acknowledgment before use
    #[test]
    fn test_session_registry_requires_acknowledgment() {
        let mut registry = SessionRegistry::new();

        let session_id = [0x01u8; 32];

        // Should fail before acknowledgment
        let result = registry.is_seen(&session_id);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("registry not initialized"));

        let result = registry.register(session_id);
        assert!(result.is_err());

        let result = registry.check_and_register(session_id);
        assert!(result.is_err());

        // After acknowledgment, should work
        registry.acknowledge_in_memory_mode();
        assert!(registry.is_seen(&session_id).is_ok());
        assert!(registry.register(session_id).is_ok());
    }

    /// CRIT-2 Test: reset_for_restart clears state and requires re-acknowledgment
    #[test]
    fn test_session_registry_reset_for_restart() {
        let mut registry = SessionRegistry::new();
        registry.acknowledge_in_memory_mode();

        let session_id = [0x01u8; 32];
        registry.register(session_id).unwrap();
        assert_eq!(registry.session_count(), 1);

        // Reset for restart
        registry.reset_for_restart();

        // Should require re-acknowledgment
        assert!(registry.requires_persistence_warning());
        assert!(registry.is_seen(&session_id).is_err());

        // After re-acknowledgment, should be empty
        registry.acknowledge_in_memory_mode();
        assert_eq!(registry.session_count(), 0);
        assert!(!registry.is_seen(&session_id).unwrap());
    }

    /// WR-L3 Test: Monotonic clock for timeouts
    #[test]
    fn test_monotonic_timeout() {
        let session = WraithSession::new(ParticipantTier::Micro, WraithDenomination::Small);

        // Session should not be timed out immediately
        assert!(!session.is_timed_out());

        // Remaining time should be positive
        assert!(session.remaining_secs() > 0);

        // timeout_at should return a reasonable Unix timestamp
        let timeout_at = session.timeout_at();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // timeout_at should be in the future
        assert!(timeout_at > now);
    }

    /// WR-L3 Test: Timeout extension uses monotonic clock
    /// M-6: Test that cumulative extensions are bounded to MAX_EXTENSION_SECS
    #[test]
    fn test_timeout_extension() {
        // Use a short custom timeout so we can test extensions properly
        let config = SessionConfig::with_timeout(3600); // 1 hour initial
        let mut session =
            WraithSession::with_config(ParticipantTier::Micro, WraithDenomination::Small, config);

        let initial_remaining = session.remaining_secs();

        // Extend by 1 hour - should work (within 24-hour budget)
        session.extend_timeout(3600);

        let new_remaining = session.remaining_secs();

        // New remaining should be approximately initial + 3600
        // Allow some tolerance for execution time
        assert!(new_remaining > initial_remaining);
        assert!(new_remaining >= initial_remaining + 3590);

        // Check that we've used 1 hour of extension budget
        assert_eq!(session.total_extensions_secs, 3600);

        // M-6 FIX Test: Cumulative extensions should be bounded
        // Try to extend by more than remaining budget
        let before_mega_extend = session.remaining_secs();
        session.extend_timeout(100 * 24 * 60 * 60); // Try 100 days

        let after_mega_extend = session.remaining_secs();

        // Should only have extended by remaining budget (24 hours - 1 hour already used)
        let expected_extension = WraithSession::MAX_EXTENSION_SECS - 3600;
        assert!(
            after_mega_extend <= before_mega_extend + expected_extension + 10,
            "Extension should be bounded to remaining budget"
        );

        // Total extensions should be capped at MAX_EXTENSION_SECS
        assert_eq!(
            session.total_extensions_secs,
            WraithSession::MAX_EXTENSION_SECS
        );

        // Further extensions should have no effect
        let before_exhausted = session.remaining_secs();
        session.extend_timeout(3600); // Try another hour
        let after_exhausted = session.remaining_secs();

        // Should not have extended (budget exhausted)
        // Allow small tolerance for timing
        assert!(
            after_exhausted <= before_exhausted + 1,
            "No extension should occur after budget exhausted"
        );
        assert_eq!(
            session.total_extensions_secs,
            WraithSession::MAX_EXTENSION_SECS
        );
    }
}
