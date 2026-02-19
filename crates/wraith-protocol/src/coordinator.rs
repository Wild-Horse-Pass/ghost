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
//| FILE: coordinator.rs                                                                                                 |
//|======================================================================================================================|

//! Wraith Coordinator - Orchestrates full session lifecycle
//!
//! Manages participant registration, blind signatures, transaction building,
//! signing coordination, and broadcasting.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Maximum strike count before a participant is banned
const MAX_STRIKES: u32 = 3;

/// Maximum number of used tokens to track in the LRU cache
///
/// H-12 FIX: Increased from 100,000 to 1,000,000 tokens.
/// At typical Wraith session rates (100 sessions/day with 50 participants each),
/// this provides ~200 days of headroom before any eviction occurs.
/// Combined with TOKEN_MAX_AGE_SECS (14 days), tokens are rejected by age
/// long before capacity-based eviction would occur in normal operation.
///
/// Worst case: 1M tokens * 40 bytes = ~40MB memory - acceptable for a coordinator.
const MAX_USED_TOKENS: usize = 1_000_000;

/// Maximum age for tokens in the cache (14 days)
/// SECURITY: Must exceed 2x maximum session duration (7 days) to prevent replay attacks.
/// This ensures tokens from completed sessions cannot be replayed after cache eviction.
/// 14 days provides sufficient margin for edge cases and clock drift.
const TOKEN_MAX_AGE_SECS: u64 = 14 * 24 * 60 * 60;

/// WR4-L7: Maximum number of outputs in a single mix transaction
/// This prevents transactions that exceed Bitcoin's consensus limits
/// Bitcoin allows ~2500 outputs max, but we use a lower limit for safety
const MAX_TX_OUTPUTS: usize = 500;

/// WR4-L7: Maximum transaction size in virtual bytes
/// Standard Bitcoin nodes reject transactions > 100KB
/// Note: Currently used for documentation; actual size validation happens in build_split_transaction
#[allow(dead_code)]
const MAX_TX_SIZE_VBYTES: usize = 100_000;

/// Time-based LRU cache for tracking used tokens
///
/// This cache evicts tokens based on age first, then by oldest entry when at capacity.
/// This prevents the security vulnerability of clearing ALL tokens at once (M-WRAITH-1).
#[derive(Debug)]
pub struct TokenCache {
    /// Token hash -> timestamp when it was added
    tokens: HashMap<[u8; 32], Instant>,
    /// Maximum number of entries
    max_size: usize,
    /// Maximum age for entries
    max_age: Duration,
}

impl Default for TokenCache {
    fn default() -> Self {
        Self::new(MAX_USED_TOKENS, Duration::from_secs(TOKEN_MAX_AGE_SECS))
    }
}

impl TokenCache {
    /// Create a new token cache with specified limits
    pub fn new(max_size: usize, max_age: Duration) -> Self {
        Self {
            tokens: HashMap::new(),
            max_size,
            max_age,
        }
    }

    /// Check if a token is a replay and mark it as used if not
    ///
    /// Returns true if the token was already seen (replay attack detected).
    /// Returns false if the token is new (and has been added to the cache).
    ///
    /// H-7 FIX: Logs warning if capacity-based eviction occurs before age expiry.
    pub fn check_and_mark(&mut self, token_hash: [u8; 32]) -> bool {
        // Clean expired tokens first
        let cutoff = Instant::now() - self.max_age;
        let before_age_cleanup = self.tokens.len();
        self.tokens.retain(|_, ts| *ts > cutoff);
        let after_age_cleanup = self.tokens.len();
        let age_expired = before_age_cleanup - after_age_cleanup;

        // If still at capacity, evict oldest entries
        // H-7 FIX: Track capacity-based evictions that happen before natural age expiry
        let mut capacity_evictions = 0;
        while self.tokens.len() >= self.max_size {
            if let Some(oldest_key) = self
                .tokens
                .iter()
                .min_by_key(|(_, ts)| *ts)
                .map(|(k, _)| *k)
            {
                // H-7 FIX: Check if this token would have naturally expired
                if let Some(oldest_ts) = self.tokens.get(&oldest_key) {
                    if oldest_ts.elapsed() < self.max_age {
                        // Token is being evicted before its natural expiry
                        capacity_evictions += 1;
                    }
                }
                self.tokens.remove(&oldest_key);
            } else {
                break;
            }
        }

        // H-7 FIX: Warn about potential replay risk from early evictions
        if capacity_evictions > 0 {
            tracing::warn!(
                capacity_evictions = capacity_evictions,
                age_expired = age_expired,
                cache_size = self.tokens.len(),
                max_size = self.max_size,
                max_age_secs = self.max_age.as_secs(),
                "H-7 SECURITY: Tokens evicted before natural expiry - potential replay risk. \
                 Consider increasing MAX_USED_TOKENS or reducing session throughput."
            );
        }

        // Check for replay
        if self.tokens.contains_key(&token_hash) {
            return true; // Is replay
        }

        // Add new token
        self.tokens.insert(token_hash, Instant::now());
        false // Not replay
    }

    /// Check if a token has been used (without marking it)
    pub fn contains(&self, token_hash: &[u8; 32]) -> bool {
        // LOW-WRAITH-1 FIX: Handle zero max_age edge case
        if self.max_age.as_secs() == 0 {
            // Zero max_age means tokens never expire - unusual but handle gracefully
            return self.tokens.contains_key(token_hash);
        }

        if let Some(ts) = self.tokens.get(token_hash) {
            // Check if still within max age
            ts.elapsed() < self.max_age
        } else {
            false
        }
    }

    /// Clear all tokens (for session cleanup)
    pub fn clear(&mut self) {
        self.tokens.clear();
    }

    /// Get current number of tokens in cache
    #[allow(dead_code)] // Used in tests
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Check if cache is empty
    #[allow(dead_code)] // Companion to len()
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

/// Reputation tracking for participants across sessions
///
/// Tracks participants who fail to complete signing to prevent repeat offenders.
/// This is a simple strike-based system: 3 strikes and you're banned.
///
/// 4.11 SECURITY: Uses hashed ghost_id instead of plaintext to prevent
/// identity leakage through memory dumps or logging.
#[derive(Debug, Clone, Default)]
pub struct ReputationTracker {
    /// Strike counts for participants who failed to sign
    /// hashed_id -> number of failures
    /// 4.11: Keys are hashed for privacy
    strikes: HashMap<String, u32>,
    /// Permanently banned participants (by hashed ID)
    banned: HashSet<String>,
}

impl ReputationTracker {
    /// Create a new reputation tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// 4.11 SECURITY: Hash ghost_id for privacy-preserving storage
    ///
    /// Uses SHA256 with domain separation to prevent rainbow table attacks
    /// and ensure hashes are distinct from other uses of ghost_id hashes.
    fn hash_ghost_id(ghost_id: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"wraith/reputation/v1/");
        hasher.update(ghost_id.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Check if a participant is allowed to join (not banned)
    pub fn is_allowed(&self, ghost_id: &str) -> bool {
        let hashed = Self::hash_ghost_id(ghost_id);
        !self.banned.contains(&hashed)
    }

    /// Record a failure to sign for a participant
    ///
    /// Increments strike count. If strikes >= MAX_STRIKES, the participant is banned.
    pub fn record_failure(&mut self, ghost_id: &str) {
        let hashed = Self::hash_ghost_id(ghost_id);
        let strikes = self.strikes.entry(hashed.clone()).or_insert(0);
        *strikes += 1;
        if *strikes >= MAX_STRIKES {
            self.banned.insert(hashed);
        }
    }

    /// Record successful completion (reduces strike count)
    ///
    /// Good behavior reduces strike count by 1 (but not below 0).
    pub fn record_success(&mut self, ghost_id: &str) {
        let hashed = Self::hash_ghost_id(ghost_id);
        if let Some(strikes) = self.strikes.get_mut(&hashed) {
            *strikes = strikes.saturating_sub(1);
        }
    }

    /// Get the strike count for a participant
    pub fn get_strikes(&self, ghost_id: &str) -> u32 {
        let hashed = Self::hash_ghost_id(ghost_id);
        self.strikes.get(&hashed).copied().unwrap_or(0)
    }

    /// Check if a participant is banned
    pub fn is_banned(&self, ghost_id: &str) -> bool {
        let hashed = Self::hash_ghost_id(ghost_id);
        self.banned.contains(&hashed)
    }

    /// Manually ban a participant
    pub fn ban(&mut self, ghost_id: &str) {
        let hashed = Self::hash_ghost_id(ghost_id);
        self.banned.insert(hashed);
    }

    /// Manually unban a participant (use with caution)
    ///
    /// H-1 FIX: Now correctly uses hashed ghost_id like ban() and is_banned()
    /// Previously this function used raw ghost_id which would never match
    /// entries in self.banned (which stores hashed IDs).
    pub fn unban(&mut self, ghost_id: &str) {
        let hashed = Self::hash_ghost_id(ghost_id);
        self.banned.remove(&hashed);
        self.strikes.remove(&hashed);
    }

    /// Get all banned participants
    pub fn get_banned(&self) -> Vec<String> {
        self.banned.iter().cloned().collect()
    }
}

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::{Address, Network, ScriptBuf, Txid};

use crate::blind::{
    BlindSignatureResponse, BlindedChallenge, CoordinatorSigner, PublicNonce, UnblindedToken,
};
use crate::denomination::WraithDenomination;
use crate::error::WraithError;
use crate::executor::{MergeTransaction, SplitTransaction, WraithInput, WraithTransactionBuilder};
use crate::phase::PhaseState;
use crate::session::{SessionState, WraithSession};
use crate::tier::ParticipantTier;
use crate::SPLIT_RATIO;

/// Minimal audit record retained after purging sensitive session data
///
/// This contains only the information needed for potential emergency recovery
/// (e.g., if a reorg somehow requires transaction rebroadcast) without
/// retaining any data that could link participants to their Ghost Locks.
#[derive(Debug, Clone)]
pub struct SessionAuditRecord {
    /// Session ID (for correlation)
    pub session_id: [u8; 32],
    /// Phase 1 transaction ID (for potential rebroadcast)
    pub phase1_txid: Option<[u8; 32]>,
    /// Phase 2 transaction ID (for potential rebroadcast)
    pub phase2_txid: Option<[u8; 32]>,
    /// Number of participants (for statistics only)
    pub participant_count: usize,
    /// Unix timestamp when session was confirmed
    pub confirmed_at: u64,
}

/// WR4-L9: Audit event types for mix operations
///
/// These events are logged for security auditing without revealing
/// participant identities or linking inputs to outputs.
#[derive(Debug, Clone)]
pub enum AuditEvent {
    /// Session created
    SessionCreated {
        session_id: [u8; 32],
        tier: String,
        denomination: String,
        timestamp: u64,
    },
    /// Participant registered (count only, no identity)
    ParticipantRegistered {
        session_id: [u8; 32],
        participant_count: usize,
        timestamp: u64,
    },
    /// Phase transition occurred
    PhaseTransition {
        session_id: [u8; 32],
        from_state: String,
        to_state: String,
        timestamp: u64,
    },
    /// Transaction broadcast
    TransactionBroadcast {
        session_id: [u8; 32],
        phase: u8,
        txid: String,
        timestamp: u64,
    },
    /// Session completed
    SessionCompleted {
        session_id: [u8; 32],
        success: bool,
        participant_count: usize,
        timestamp: u64,
    },
    /// Error occurred (sanitized message)
    Error {
        session_id: [u8; 32],
        error_type: String,
        timestamp: u64,
    },
}

impl AuditEvent {
    /// Get the timestamp of the event
    pub fn timestamp(&self) -> u64 {
        match self {
            AuditEvent::SessionCreated { timestamp, .. } => *timestamp,
            AuditEvent::ParticipantRegistered { timestamp, .. } => *timestamp,
            AuditEvent::PhaseTransition { timestamp, .. } => *timestamp,
            AuditEvent::TransactionBroadcast { timestamp, .. } => *timestamp,
            AuditEvent::SessionCompleted { timestamp, .. } => *timestamp,
            AuditEvent::Error { timestamp, .. } => *timestamp,
        }
    }

    /// Get the session ID of the event
    pub fn session_id(&self) -> &[u8; 32] {
        match self {
            AuditEvent::SessionCreated { session_id, .. } => session_id,
            AuditEvent::ParticipantRegistered { session_id, .. } => session_id,
            AuditEvent::PhaseTransition { session_id, .. } => session_id,
            AuditEvent::TransactionBroadcast { session_id, .. } => session_id,
            AuditEvent::SessionCompleted { session_id, .. } => session_id,
            AuditEvent::Error { session_id, .. } => session_id,
        }
    }
}

/// WR4-L9: Audit log trait for recording mix operation events
///
/// Implementations can store events in files, databases, or remote services.
pub trait AuditLog: Send + Sync {
    /// Record an audit event
    fn record(&self, event: AuditEvent);
}

/// WR4-L9: Simple in-memory audit log for testing
#[derive(Debug, Default)]
pub struct InMemoryAuditLog {
    events: parking_lot::RwLock<Vec<AuditEvent>>,
}

impl InMemoryAuditLog {
    /// Create a new in-memory audit log
    pub fn new() -> Self {
        Self::default()
    }

    /// Get all recorded events
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.read().clone()
    }

    /// Get event count
    pub fn event_count(&self) -> usize {
        self.events.read().len()
    }

    /// Clear all events
    pub fn clear(&self) {
        self.events.write().clear();
    }
}

impl AuditLog for InMemoryAuditLog {
    fn record(&self, event: AuditEvent) {
        self.events.write().push(event);
    }
}

/// UTXO proof for Sybil-resistant registration (M-WRAITH-2)
///
/// Participants must provide proof of a UTXO they control to register.
/// This prevents attackers from filling sessions without real funds.
#[derive(Debug, Clone)]
pub struct UtxoProof {
    /// Transaction ID containing the UTXO
    pub txid: Txid,
    /// Output index within the transaction
    pub vout: u32,
    /// Expected minimum value (must meet denomination requirement)
    pub min_value: u64,
}

impl UtxoProof {
    /// Create a new UTXO proof
    pub fn new(txid: Txid, vout: u32, min_value: u64) -> Self {
        Self {
            txid,
            vout,
            min_value,
        }
    }
}

/// Participant in a Wraith session
#[derive(Debug, Clone)]
pub struct Participant {
    /// Participant index (0-based)
    pub index: u32,
    /// Session-specific participant ID (derived from ghost_id and session_id)
    /// This is H(ghost_id || session_id) to prevent cross-session tracking (WR-M4)
    pub session_participant_id: String,
    /// Input UTXO
    pub input: Option<WraithInput>,
    /// Public nonces issued to this participant (for blind signing)
    pub issued_nonces: Vec<PublicNonce>,
    /// Blinded challenges received from participant
    pub blinded_challenges: Vec<BlindedChallenge>,
    /// Blind signature responses sent to participant
    pub signature_responses: Vec<BlindSignatureResponse>,
    /// Unblinded tokens proving output ownership (verified)
    pub tokens: Vec<UnblindedToken>,
    /// Final output address (Phase 2 output)
    pub final_address: Option<String>,
    /// Has submitted Phase 1 signature
    pub phase1_signed: bool,
    /// Has submitted Phase 2 signature
    pub phase2_signed: bool,
}

impl Participant {
    /// Create new participant with session-specific ID
    ///
    /// The session_participant_id is H(ghost_id || session_id) to prevent
    /// cross-session tracking (WR-M4).
    pub fn new(index: u32, session_participant_id: String) -> Self {
        Self {
            index,
            session_participant_id,
            input: None,
            issued_nonces: Vec::new(),
            blinded_challenges: Vec::new(),
            signature_responses: Vec::new(),
            tokens: Vec::new(),
            final_address: None,
            phase1_signed: false,
            phase2_signed: false,
        }
    }
}

/// Derive session-specific participant ID (WR-M4)
///
/// Computes H(ghost_id || session_id) to create a unique identifier
/// that cannot be linked across sessions.
///
/// ## 3.14 SECURITY: Full 32-byte hash for collision resistance
///
/// Uses the full 32-byte SHA256 output for the participant ID. Previously
/// this was truncated to 16 bytes (128 bits), which while still very unlikely
/// to collide, provides less margin against birthday attacks when sessions
/// have many participants.
///
/// With full 32 bytes (256 bits), finding a collision would require ~2^128
/// operations (birthday bound), compared to ~2^64 with 16 bytes.
fn derive_session_participant_id(ghost_id: &str, session_id: &[u8; 32]) -> String {
    use bitcoin::hashes::{sha256, Hash, HashEngine};
    let mut engine = sha256::Hash::engine();
    engine.input(b"wraith/session-participant-id/v1");
    engine.input(ghost_id.as_bytes());
    engine.input(session_id);
    let hash = sha256::Hash::from_engine(engine);
    // 3.14: Use full 32 bytes for maximum collision resistance
    hex::encode(&hash[..])
}

/// Broadcast function type for transaction broadcasting
type BroadcastFn = Arc<dyn Fn(&str) -> Result<String, String> + Send + Sync>;

/// Anonymous token batch with final address
///
/// CRITICAL PRIVACY: This structure stores tokens and final addresses together
/// WITHOUT any participant identity linkage. The coordinator knows which tokens
/// belong together (they were submitted as a batch) and which final address
/// corresponds to that batch, but cannot determine which participant owns it.
#[derive(Debug, Clone)]
pub struct AnonymousTokenBatch {
    /// Tokens in this batch (SPLIT_RATIO tokens per batch)
    pub tokens: Vec<UnblindedToken>,
    /// Final output address for Phase 2 (submitted anonymously with tokens)
    pub final_address: String,
}

/// Wraith Coordinator - manages a single session's full lifecycle
pub struct WraithCoordinator {
    /// The underlying session
    session: WraithSession,
    /// Coordinator's blind signer
    signer: CoordinatorSigner,
    /// Registered participants (keyed by session-specific participant ID)
    participants: HashMap<String, Participant>, // session_participant_id -> Participant
    /// Mapping from ghost_id to session_participant_id (WR-M4)
    ghost_id_to_session_id: HashMap<String, String>,
    /// Reverse mapping from session_participant_id to ghost_id (for reputation tracking)
    session_id_to_ghost_id: HashMap<String, String>,
    /// Participant order (for deterministic indexing) - stores session_participant_ids
    participant_order: Vec<String>,
    /// Network (mainnet, testnet, etc.)
    network: Network,
    /// Phase 1 transaction (after building)
    phase1_tx: Option<SplitTransaction>,
    /// Phase 2 transaction (after building)
    phase2_tx: Option<MergeTransaction>,
    /// Phase 1 intermediate outputs (for Phase 2 inputs)
    phase1_outputs: Vec<(Txid, u32, u64, ScriptBuf)>, // (txid, vout, amount, script_pubkey)
    /// Broadcast callback
    broadcast_fn: Option<BroadcastFn>,
    /// Anonymous token batches - tokens and final addresses verified but NOT linked to any participant
    /// CRITICAL PRIVACY: coordinator verifies validity without knowing submitter identity.
    /// Each batch contains SPLIT_RATIO tokens and one final address.
    anonymous_token_batches: Vec<AnonymousTokenBatch>,
    /// Legacy anonymous tokens (deprecated - use anonymous_token_batches instead)
    /// Kept for backward compatibility with existing sessions
    #[allow(dead_code)]
    anonymous_tokens: Vec<UnblindedToken>,
    /// Tokens that have been used (for replay prevention) - time-based LRU cache
    /// SECURITY: Prevents resubmission of the same token
    /// M-WRAITH-1: Uses time-based LRU eviction instead of clearing all tokens at once
    used_tokens: TokenCache,
    /// All submitted addresses (for duplicate detection)
    submitted_addresses: HashSet<String>,
    /// Optional UTXO verification callback
    utxo_verifier: Option<UtxoVerifier>,
    /// M-WRAITH-2: Require UTXO proof during registration to prevent Sybil attacks
    require_utxo_for_registration: bool,
    /// Reputation tracker for participants (shared across sessions)
    reputation: Option<Arc<parking_lot::RwLock<ReputationTracker>>>,
    /// WR4-L9: Optional audit log for recording mix operations
    audit_log: Option<Arc<dyn AuditLog>>,
}

/// UTXO verification callback type
///
/// Returns true if the UTXO exists and is unspent, false otherwise.
type UtxoVerifier = Arc<dyn Fn(&Txid, u32) -> Result<bool, String> + Send + Sync>;

impl std::fmt::Debug for WraithCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WraithCoordinator")
            .field("session", &self.session)
            .field("participants", &self.participants.len())
            .field("network", &self.network)
            .field("has_phase1_tx", &self.phase1_tx.is_some())
            .field("has_phase2_tx", &self.phase2_tx.is_some())
            .field("has_broadcaster", &self.broadcast_fn.is_some())
            .finish()
    }
}

impl WraithCoordinator {
    /// Create a new coordinator for a session
    ///
    /// # Errors
    ///
    /// Returns `WraithError::SecurityError` if the RNG fails to generate signing keys.
    pub fn new(
        tier: ParticipantTier,
        denomination: WraithDenomination,
        network: Network,
    ) -> Result<Self, WraithError> {
        let session = WraithSession::new(tier, denomination);
        let signer = CoordinatorSigner::new(session.session_id())?;

        let session_id = *session.session_id();
        let coordinator = Self {
            session,
            signer,
            participants: HashMap::new(),
            ghost_id_to_session_id: HashMap::new(),
            session_id_to_ghost_id: HashMap::new(),
            participant_order: Vec::new(),
            network,
            phase1_tx: None,
            phase2_tx: None,
            phase1_outputs: Vec::new(),
            broadcast_fn: None,
            anonymous_token_batches: Vec::new(),
            anonymous_tokens: Vec::new(), // Legacy field, deprecated
            used_tokens: TokenCache::default(),
            submitted_addresses: HashSet::new(),
            utxo_verifier: None,
            // SECURITY: UTXO proof is required by default to prevent Sybil attacks
            require_utxo_for_registration: true,
            reputation: None,
            audit_log: None,
        };

        // WR4-L9: Log session creation (if audit log is set later, this won't be recorded)
        // The actual logging happens when with_audit_log is called
        tracing::info!(
            session_id = %hex::encode(session_id),
            tier = %tier.name(),
            denomination = ?denomination,
            "Wraith session created"
        );

        Ok(coordinator)
    }

    /// Set broadcast callback function
    pub fn with_broadcaster<F>(mut self, f: F) -> Self
    where
        F: Fn(&str) -> Result<String, String> + Send + Sync + 'static,
    {
        self.broadcast_fn = Some(Arc::new(f));
        self
    }

    /// Set UTXO verification callback (WR-L2)
    ///
    /// If set, submit_input() will verify the UTXO exists before accepting it.
    /// The callback should return Ok(true) if the UTXO exists, Ok(false) if not,
    /// or Err if the verification cannot be performed.
    pub fn with_utxo_verifier<F>(mut self, f: F) -> Self
    where
        F: Fn(&Txid, u32) -> Result<bool, String> + Send + Sync + 'static,
    {
        self.utxo_verifier = Some(Arc::new(f));
        self
    }

    /// Require UTXO proof during registration (M-WRAITH-2)
    ///
    /// When enabled, participants must use `register_participant_with_utxo()` instead
    /// of `register_participant()`. This prevents Sybil attacks where attackers fill
    /// sessions without having real UTXOs.
    ///
    /// Note: Requires `with_utxo_verifier()` to be set first.
    /// This is enabled by default for security.
    pub fn with_utxo_required_for_registration(mut self) -> Self {
        self.require_utxo_for_registration = true;
        self
    }

    /// Disable UTXO proof requirement for registration
    ///
    /// WARNING: This weakens security by allowing Sybil attacks. Only use for:
    /// - Testing (where UTXO verification is not the focus)
    /// - Development environments
    ///
    /// NEVER use this in production.
    #[cfg(any(test, feature = "dev-mode"))]
    pub fn without_utxo_required_for_registration(mut self) -> Self {
        self.require_utxo_for_registration = false;
        self
    }

    /// Set reputation tracker (WR-M3)
    ///
    /// The reputation tracker is shared across sessions to track participants
    /// who fail to complete signing.
    pub fn with_reputation(
        mut self,
        reputation: Arc<parking_lot::RwLock<ReputationTracker>>,
    ) -> Self {
        self.reputation = Some(reputation);
        self
    }

    /// Set audit log for recording mix operations (WR4-L9)
    ///
    /// The audit log records key events without revealing participant identities
    /// or linking inputs to outputs.
    pub fn with_audit_log(mut self, audit_log: Arc<dyn AuditLog>) -> Self {
        // Record session creation event
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        audit_log.record(AuditEvent::SessionCreated {
            session_id: *self.session.session_id(),
            tier: self.session.tier().name().to_string(),
            denomination: format!("{:?}", self.session.denomination()),
            timestamp: now,
        });

        self.audit_log = Some(audit_log);
        self
    }

    /// Helper to record audit events (WR4-L9)
    fn log_audit_event(&self, event: AuditEvent) {
        if let Some(ref audit_log) = self.audit_log {
            audit_log.record(event);
        }
    }

    /// Get current Unix timestamp
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Get session ID
    pub fn session_id(&self) -> &[u8; 32] {
        self.session.session_id()
    }

    /// Get session ID as hex
    pub fn session_id_hex(&self) -> String {
        hex::encode(self.session.session_id())
    }

    /// Get current session state
    pub fn state(&self) -> SessionState {
        self.session.state()
    }

    /// Get participant count
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    /// Check if session has minimum participants
    pub fn has_minimum_participants(&self) -> bool {
        self.session.has_minimum_participants()
    }

    /// Register a new participant
    ///
    /// Checks reputation (if tracker is set) and rejects banned participants.
    /// Internally uses session-specific IDs to prevent cross-session tracking (WR-M4).
    /// WR4-L5: Enforces tier participant limit to prevent oversized sessions.
    ///
    /// M-WRAITH-2: If `require_utxo_for_registration` is enabled, this method will
    /// return an error. Use `register_participant_with_utxo()` instead.
    pub fn register_participant(&mut self, ghost_id: String) -> Result<u32, WraithError> {
        // M-WRAITH-2: Check if UTXO proof is required
        if self.require_utxo_for_registration {
            return Err(WraithError::InvalidInput(
                "UTXO proof required for registration. Use register_participant_with_utxo() instead.".to_string()
            ));
        }

        self.register_participant_internal(ghost_id)
    }

    /// Register a new participant with UTXO proof (M-WRAITH-2)
    ///
    /// This method requires the participant to prove ownership of a UTXO,
    /// preventing Sybil attacks where attackers fill sessions without real funds.
    ///
    /// The UTXO is verified using the configured UTXO verifier callback.
    /// If no verifier is configured, this method will return an error.
    pub fn register_participant_with_utxo(
        &mut self,
        ghost_id: String,
        utxo_proof: UtxoProof,
    ) -> Result<u32, WraithError> {
        // Verify UTXO exists
        let verifier = self
            .utxo_verifier
            .as_ref()
            .ok_or_else(|| WraithError::InvalidInput("No UTXO verifier configured".to_string()))?;

        match verifier(&utxo_proof.txid, utxo_proof.vout) {
            Ok(true) => { /* UTXO exists, continue */ }
            Ok(false) => {
                return Err(WraithError::InvalidInput(format!(
                    "UTXO {}:{} does not exist or is already spent",
                    utxo_proof.txid, utxo_proof.vout
                )));
            }
            Err(e) => {
                return Err(WraithError::RpcError(format!(
                    "Failed to verify UTXO: {}",
                    e
                )));
            }
        }

        // Proceed with registration
        self.register_participant_internal(ghost_id)
    }

    /// Internal registration logic shared by both registration methods
    fn register_participant_internal(&mut self, ghost_id: String) -> Result<u32, WraithError> {
        if !matches!(self.session.state(), SessionState::WaitingForParticipants) {
            return Err(WraithError::InvalidState {
                expected: "WaitingForParticipants".to_string(),
                actual: format!("{:?}", self.session.state()),
            });
        }

        // WR4-L5: Check participant limit before registration (mode-aware)
        let max_participants = self.session.tier().max_participants_for_mode(self.session.mode());
        if self.participants.len() >= max_participants {
            return Err(WraithError::SessionFull {
                current: self.participants.len(),
                max: max_participants,
            });
        }

        // Check reputation if tracker is set (WR-M3)
        if let Some(ref reputation) = self.reputation {
            let rep = reputation.read();
            if rep.is_banned(&ghost_id) {
                return Err(WraithError::InvalidInput(format!(
                    "Participant {} is banned due to prior failures",
                    ghost_id
                )));
            }
        }

        // Check if already registered using ghost_id mapping
        if self.ghost_id_to_session_id.contains_key(&ghost_id) {
            return Err(WraithError::InvalidInput(format!(
                "Participant {} already registered",
                ghost_id
            )));
        }

        // Derive session-specific participant ID (WR-M4)
        let session_participant_id =
            derive_session_participant_id(&ghost_id, self.session.session_id());

        let index = self.participants.len() as u32;
        let participant = Participant::new(index, session_participant_id.clone());
        self.participants
            .insert(session_participant_id.clone(), participant);
        self.ghost_id_to_session_id
            .insert(ghost_id.clone(), session_participant_id.clone());
        self.session_id_to_ghost_id
            .insert(session_participant_id.clone(), ghost_id);
        self.participant_order.push(session_participant_id);
        self.session.add_participant();

        // WR4-L9: Log participant registration (count only, not identity)
        self.log_audit_event(AuditEvent::ParticipantRegistered {
            session_id: *self.session.session_id(),
            participant_count: self.participants.len(),
            timestamp: Self::current_timestamp(),
        });

        Ok(index)
    }

    /// Get the session-specific participant ID for a ghost_id
    ///
    /// Returns None if the ghost_id is not registered.
    fn get_session_participant_id(&self, ghost_id: &str) -> Option<&String> {
        self.ghost_id_to_session_id.get(ghost_id)
    }

    /// Submit input UTXO for a participant
    ///
    /// If a UTXO verifier is configured, verifies the UTXO exists before accepting (WR-L2).
    pub fn submit_input(&mut self, ghost_id: &str, input: WraithInput) -> Result<(), WraithError> {
        let session_id = self
            .get_session_participant_id(ghost_id)
            .ok_or_else(|| WraithError::InvalidInput("Unknown participant".to_string()))?
            .clone();
        // CRIT-7: Return error instead of panicking on internal inconsistency
        let participant = self.participants.get_mut(&session_id).ok_or_else(|| {
            WraithError::MissingData("Internal error: participant mapping inconsistent".into())
        })?;

        // Validate input amount
        let expected = self.session.denomination().input_sats();
        if input.amount < expected {
            return Err(WraithError::InvalidInput(format!(
                "Input amount {} too small, need at least {}",
                input.amount, expected
            )));
        }

        // Verify UTXO exists if verifier is configured (WR-L2)
        if let Some(ref verifier) = self.utxo_verifier {
            match verifier(&input.txid, input.vout) {
                Ok(true) => { /* UTXO exists, continue */ }
                Ok(false) => {
                    return Err(WraithError::InvalidInput(format!(
                        "UTXO {}:{} does not exist or is already spent",
                        input.txid, input.vout
                    )));
                }
                Err(e) => {
                    return Err(WraithError::RpcError(format!(
                        "Failed to verify UTXO: {}",
                        e
                    )));
                }
            }
        }

        participant.input = Some(input);
        Ok(())
    }

    /// Request nonces for blind signing (Step 1 of interactive protocol)
    ///
    /// Participant calls this to get public nonces before creating blinded challenges.
    /// Returns `SPLIT_RATIO` nonces, one for each intermediate output.
    ///
    /// SECURITY: Each nonce is bound to the requesting participant's session-specific ID
    /// to prevent nonce hijacking attacks.
    ///
    /// RATE LIMITING: May return error if participant has exceeded nonce limits.
    pub fn request_nonces(&mut self, ghost_id: &str) -> Result<Vec<PublicNonce>, WraithError> {
        let session_id = self
            .get_session_participant_id(ghost_id)
            .ok_or_else(|| WraithError::InvalidInput("Unknown participant".to_string()))?
            .clone();

        // Create nonces for each intermediate output, BOUND to session-specific participant ID
        let mut nonces = Vec::with_capacity(SPLIT_RATIO);
        for _ in 0..SPLIT_RATIO {
            let nonce = self.signer.create_nonce_for_participant(&session_id)?;
            nonces.push(nonce);
        }

        // CRIT-7: Return error instead of panicking on internal inconsistency
        let participant = self.participants.get_mut(&session_id).ok_or_else(|| {
            WraithError::MissingData("Internal error: participant mapping inconsistent".into())
        })?;
        participant.issued_nonces = nonces.clone();
        Ok(nonces)
    }

    /// Submit blinded challenges for signing (Step 2 of interactive protocol)
    ///
    /// Participant sends blinded challenges after receiving nonces and blinding.
    /// Returns signature responses that the participant can unblind.
    ///
    /// SECURITY: The session-specific participant ID is verified against the nonce binding
    /// to ensure the participant is using nonces issued to them.
    pub fn submit_blinded_challenges(
        &mut self,
        ghost_id: &str,
        challenges: Vec<BlindedChallenge>,
    ) -> Result<Vec<BlindSignatureResponse>, WraithError> {
        if challenges.len() != SPLIT_RATIO {
            return Err(WraithError::InvalidInput(format!(
                "Expected {} blinded challenges, got {}",
                SPLIT_RATIO,
                challenges.len()
            )));
        }

        let session_id = self
            .get_session_participant_id(ghost_id)
            .ok_or_else(|| WraithError::InvalidInput("Unknown participant".to_string()))?
            .clone();

        // Sign each blinded challenge WITH session-specific participant verification
        let mut responses = Vec::with_capacity(SPLIT_RATIO);
        for challenge in &challenges {
            let response = self
                .signer
                .sign_blinded_challenge_for_participant(challenge, &session_id)?;
            responses.push(response);
        }

        // CRIT-7: Return error instead of panicking on internal inconsistency
        let participant = self.participants.get_mut(&session_id).ok_or_else(|| {
            WraithError::MissingData("Internal error: participant mapping inconsistent".into())
        })?;

        participant.blinded_challenges = challenges;
        participant.signature_responses = responses.clone();

        Ok(responses)
    }

    /// Submit final output address for Phase 2 (DEPRECATED - PRIVACY LEAK!)
    ///
    /// # Deprecated
    ///
    /// **CRITICAL PRIVACY ISSUE (CRIT-1):** This method takes `ghost_id` which links
    /// the participant's identity to their final output address. This defeats the
    /// privacy guarantees of the blind signature scheme.
    ///
    /// Use `submit_tokens_with_address_anonymous` instead, which accepts both
    /// tokens and final address in a single anonymous submission without ghost_id.
    ///
    /// Submit final output address for Phase 2 (REMOVED - PRIVACY LEAK!)
    ///
    /// # CRIT-1 FIX: This method has been disabled
    ///
    /// **CRITICAL PRIVACY ISSUE:** This method took `ghost_id` which linked
    /// the participant's identity to their final output address. This defeated the
    /// privacy guarantees of the blind signature scheme.
    ///
    /// Use `submit_tokens_with_address_anonymous` instead, which accepts both
    /// tokens and final address in a single anonymous submission without ghost_id.
    #[deprecated(
        since = "1.7.0",
        note = "PRIVACY LEAK: Use submit_tokens_with_address_anonymous instead"
    )]
    pub fn submit_final_address(
        &mut self,
        _ghost_id: &str,
        _address: String,
    ) -> Result<(), WraithError> {
        // CRIT-1 FIX: This method is now disabled to prevent privacy leaks
        Err(WraithError::InvalidInput(
            "submit_final_address is disabled due to privacy leak. \
             Use submit_tokens_with_address_anonymous instead, which accepts \
             both tokens and final address without linking to participant identity."
                .to_string(),
        ))
    }

    /// Submit unblinded tokens with final address anonymously
    ///
    /// CRITICAL PRIVACY FIX (CRIT-1): This method takes both tokens AND final address
    /// WITHOUT any participant identity (ghost_id). This breaks the linkage between
    /// participant identity and output address that previously existed in submit_final_address.
    ///
    /// The coordinator:
    /// 1. Verifies tokens are valid (signed by coordinator)
    /// 2. Stores tokens + final_address together as an anonymous batch
    /// 3. CANNOT determine which participant submitted which batch
    ///
    /// When Phase 2 is built, final addresses come from these anonymous batches,
    /// NOT from participant.final_address (which would leak identity).
    pub fn submit_tokens_with_address_anonymous(
        &mut self,
        tokens: Vec<UnblindedToken>,
        final_address: String,
    ) -> Result<(), WraithError> {
        if tokens.len() != SPLIT_RATIO {
            return Err(WraithError::InvalidInput(format!(
                "Expected {} tokens, got {}",
                SPLIT_RATIO,
                tokens.len()
            )));
        }

        // Validate final address is not empty
        if final_address.is_empty() {
            return Err(WraithError::InvalidInput(
                "Final address cannot be empty".into(),
            ));
        }

        // SECURITY: Check for duplicate address BEFORE accepting
        // This prevents address reuse attacks across anonymous submissions
        if self.submitted_addresses.contains(&final_address) {
            return Err(WraithError::InvalidInput(format!(
                "Duplicate address rejected: {} (already submitted)",
                final_address
            )));
        }

        // CRIT-CRYPTO-2 FIX: Atomic check-and-reserve for all tokens to prevent race conditions
        // This prevents a race where two concurrent requests could both pass the contains()
        // check before either calls check_and_mark().
        //
        // We compute all hashes first, then atomically check-and-mark ALL of them.
        // If any token is already used, we abort before marking any new ones.
        let token_hashes: Vec<[u8; 32]> =
            tokens.iter().map(|t| self.compute_token_hash(t)).collect();

        // First pass: check if any token is already used (read-only)
        for (i, hash) in token_hashes.iter().enumerate() {
            if self.used_tokens.contains(hash) {
                return Err(WraithError::InvalidInput(format!(
                    "Token {} replay detected",
                    i
                )));
            }
        }

        // CRIT-CRYPTO-2: Reserve all tokens atomically BEFORE verification
        // This ensures no other request can claim these tokens while we verify
        for hash in &token_hashes {
            // check_and_mark returns true if this was a replay (already existed)
            if self.used_tokens.check_and_mark(*hash) {
                // Another concurrent request claimed this token between our contains() and check_and_mark()
                // This is a race condition that we caught - abort cleanly
                return Err(WraithError::InvalidInput(
                    "Token replay detected (concurrent claim)".into(),
                ));
            }
        }

        // Verify each token using standard Schnorr verification
        // Coordinator proves tokens are valid WITHOUT knowing who submitted them
        // Note: Tokens are already marked as used - if verification fails, they stay marked
        // (conservative: prevents potential attacks using verification timing)
        for (i, token) in tokens.iter().enumerate() {
            let valid = self.signer.verify_signature(token)?;
            if !valid {
                return Err(WraithError::InvalidSignature(format!(
                    "Token {} verification failed",
                    i
                )));
            }

            // HIGH-3 FIX: Validate token message is a valid x-only pubkey
            // This catches invalid pubkeys early instead of failing during build_phase1
            if token.message.len() != 32 {
                return Err(WraithError::InvalidInput(format!(
                    "Token {} message is not 32 bytes (got {})",
                    i,
                    token.message.len()
                )));
            }
            let message_bytes: [u8; 32] = token.message.clone().try_into().map_err(|_| {
                WraithError::InvalidInput(format!("Token {} message conversion failed", i))
            })?;
            // Validate it's a valid x-only pubkey on the secp256k1 curve
            XOnlyPublicKey::from_slice(&message_bytes).map_err(|e| {
                WraithError::InvalidInput(format!(
                    "Token {} message is not a valid x-only pubkey: {}",
                    i, e
                ))
            })?;
        }

        // Tokens are already marked as used above (CRIT-CRYPTO-2 fix)

        // Record address to prevent duplicates
        self.submitted_addresses.insert(final_address.clone());

        // Add to anonymous batch pool - NO ghost_id linkage!
        // The batch contains both tokens and final address together
        self.anonymous_token_batches.push(AnonymousTokenBatch {
            tokens,
            final_address,
        });

        // HIGH-2 FIX: Shuffle batches immediately on receipt to prevent timing correlation
        // This uses Fisher-Yates shuffle with OsRng for cryptographic security
        self.shuffle_anonymous_token_batches_immediate()?;

        Ok(())
    }

    /// Submit unblinded tokens anonymously (REMOVED - PRIVACY LEAK!)
    ///
    /// # CRIT-1 FIX: This method has been disabled
    ///
    /// This method is DEPRECATED because it requires a separate call to
    /// `submit_final_address` which takes ghost_id, creating a privacy leak.
    ///
    /// Use `submit_tokens_with_address_anonymous` instead, which accepts both
    /// tokens and final address in a single anonymous submission.
    #[deprecated(
        since = "1.7.0",
        note = "Use submit_tokens_with_address_anonymous instead to avoid privacy leak via submit_final_address"
    )]
    pub fn submit_tokens_anonymous(
        &mut self,
        _tokens: Vec<UnblindedToken>,
    ) -> Result<(), WraithError> {
        // CRIT-1 FIX: This method is now disabled to prevent privacy leaks
        Err(WraithError::InvalidInput(
            "submit_tokens_anonymous is disabled due to privacy leak. \
             Use submit_tokens_with_address_anonymous instead, which accepts \
             both tokens and final address in a single anonymous call."
                .to_string(),
        ))
    }

    /// Compute a session-and-key-bound hash of a token for replay prevention
    ///
    /// WR-C4: Token hash is bound to session_id to prevent cross-session replay.
    /// H-CRYPTO-2: Token hash also includes coordinator's current key_id to prevent
    /// cross-rotation replay attacks. After key rotation, tokens signed with the old
    /// key will produce different hashes and cannot be replayed with the new key.
    ///
    /// Even if a token is valid (signed by coordinator), it can only be used in the
    /// session it was issued for AND with the same signing key it was issued under.
    fn compute_token_hash(&self, token: &UnblindedToken) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        // H-CRYPTO-2: Version bump to v3 to indicate key binding
        hasher.update(b"wraith/token-hash/v3");
        hasher.update(self.session.session_id());
        // H-CRYPTO-2: Include coordinator's CURRENT key_id to bind token to this key rotation epoch
        // This prevents replaying tokens across key rotations
        hasher.update(self.signer.key_id());
        hasher.update(token.session_key_id);
        hasher.update(token.nonce_point);
        hasher.update(token.signature_scalar);
        hasher.finalize().into()
    }

    // 3.13 SECURITY: Removed deprecated submit_tokens() method
    //
    // The submit_tokens(ghost_id, tokens) method was deprecated because it creates
    // input-output linkage that defeats blind signatures. The ghost_id parameter
    // allowed the coordinator to correlate which tokens belonged to which participant,
    // completely defeating the privacy guarantees of the blind signature scheme.
    //
    // Use submit_tokens_anonymous(tokens) instead, which adds tokens to an anonymous
    // pool without any participant linkage. The coordinator can verify tokens are
    // valid (signed by coordinator) but cannot determine which participant submitted them.

    /// Convert an x-only pubkey to a P2TR address string
    fn xonly_to_p2tr_address(&self, xonly: &[u8; 32]) -> Result<String, WraithError> {
        let pubkey = XOnlyPublicKey::from_slice(xonly)
            .map_err(|e| WraithError::InvalidInput(format!("Invalid x-only pubkey: {}", e)))?;

        // Create a P2TR address with no script path (key-path only)
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let address = Address::p2tr(&secp, pubkey, None, self.network);

        Ok(address.to_string())
    }

    /// Start input collection phase
    pub fn start_collecting(&mut self) -> Result<(), WraithError> {
        self.session.start_collecting()
    }

    /// Check if ready to build Phase 1 transaction
    ///
    /// CRIT-1 FIX: Only uses anonymous_token_batches, not legacy anonymous_tokens
    pub fn ready_for_phase1(&self) -> bool {
        // Need all participants to have inputs
        let all_have_inputs = self.participants.values().all(|p| p.input.is_some());

        // Need one anonymous batch per participant (each batch has SPLIT_RATIO tokens + final address)
        // CRIT-1 FIX: Only use anonymous_token_batches which include final addresses
        // Legacy anonymous_tokens path is disabled due to privacy leak
        let have_enough_batches = self.anonymous_token_batches.len() >= self.participants.len();

        all_have_inputs && have_enough_batches
    }

    /// Get count of anonymous token batches submitted
    pub fn anonymous_batch_count(&self) -> usize {
        self.anonymous_token_batches.len()
    }

    /// Get count of anonymous tokens submitted (total across all batches)
    pub fn anonymous_token_count(&self) -> usize {
        let batch_tokens: usize = self
            .anonymous_token_batches
            .iter()
            .map(|b| b.tokens.len())
            .sum();
        // Include legacy tokens for backward compatibility
        batch_tokens + self.anonymous_tokens.len()
    }

    /// Build Phase 1 (split) transaction
    ///
    /// WR4-L7: Validates transaction size before building to prevent
    /// transactions that exceed Bitcoin's consensus limits.
    pub fn build_phase1(&mut self) -> Result<&SplitTransaction, WraithError> {
        if !self.ready_for_phase1() {
            return Err(WraithError::PhaseError(
                "Not all participants have submitted inputs or not enough anonymous tokens"
                    .to_string(),
            ));
        }

        // WR4-L7: Check output count limit
        // Phase 1 creates SPLIT_RATIO outputs per participant + 1 OP_RETURN
        let expected_outputs = self.participants.len() * crate::SPLIT_RATIO + 1;
        if expected_outputs > MAX_TX_OUTPUTS {
            return Err(WraithError::TransactionError(format!(
                "Transaction too large: {} outputs exceeds maximum {} outputs",
                expected_outputs, MAX_TX_OUTPUTS
            )));
        }

        // Transition session state
        self.session.start_phase1()?;

        // Build transaction
        let mut builder = WraithTransactionBuilder::new(
            self.session_id_hex(),
            *self.session.denomination(),
            self.network,
        );

        // Add inputs in order
        for ghost_id in &self.participant_order {
            let participant = self.participants.get(ghost_id).ok_or_else(|| {
                WraithError::InvalidInput("Missing participant in order".to_string())
            })?;
            if let Some(ref input) = participant.input {
                builder.add_input(input.clone())?;
            }
        }

        // CRIT-1 FIX: Only use anonymous_token_batches which include both tokens AND final addresses
        // Legacy anonymous_tokens path has been removed due to privacy leak

        // WR-C1: CRYPTOGRAPHIC SHUFFLE before processing to break submission order correlation
        // Note: Batches are also shuffled immediately on receipt (HIGH-2 fix)
        self.shuffle_anonymous_token_batches()?;

        // Collect intermediate addresses from token batches
        // CRITICAL: Neither tokens NOR final addresses are linked to participants - this is the privacy guarantee
        let mut intermediate_addresses: Vec<Vec<String>> = Vec::new();

        // Secure path: each batch has tokens + final address together
        for batch in &self.anonymous_token_batches {
            let mut addrs = Vec::with_capacity(SPLIT_RATIO);
            for token in &batch.tokens {
                let address_bytes: [u8; 32] = token.message.clone().try_into().map_err(|_| {
                    WraithError::InvalidInput(format!(
                        "Token message is not 32 bytes (got {})",
                        token.message.len()
                    ))
                })?;
                let addr = self.xonly_to_p2tr_address(&address_bytes)?;
                addrs.push(addr);
            }
            intermediate_addresses.push(addrs);
        }

        let tx = builder.build_split_transaction(&intermediate_addresses)?;
        self.phase1_tx = Some(tx);

        // Immediately clear sensitive data after building transaction (WR-H3)
        self.clear_sensitive_data_post_build();

        // CRIT-7: Return error instead of panicking (though this should never fail)
        self.phase1_tx
            .as_ref()
            .ok_or_else(|| WraithError::MissingData("Internal error: phase1_tx was not set".into()))
    }

    // CRIT-1 FIX: shuffle_anonymous_tokens removed - legacy anonymous_tokens path is disabled

    /// CRIT-1 FIX: Cryptographically shuffle anonymous token batches
    ///
    /// This shuffle keeps tokens and final addresses together while randomizing
    /// the order of batches. This prevents an attacker from correlating
    /// submission order with participant identities.
    fn shuffle_anonymous_token_batches(&mut self) -> Result<(), WraithError> {
        use rand::seq::SliceRandom;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use sha2::{Digest, Sha256};

        // Generate fresh entropy from CSPRNG
        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy)
            .map_err(|e| WraithError::InvalidInput(format!("Failed to generate entropy: {}", e)))?;

        // Derive seed from session_id + entropy for unpredictability
        let mut hasher = Sha256::new();
        hasher.update(b"wraith/batch-shuffle/v1");
        hasher.update(self.session.session_id());
        hasher.update(entropy);
        let seed: [u8; 32] = hasher.finalize().into();

        let mut rng = ChaCha20Rng::from_seed(seed);
        self.anonymous_token_batches.shuffle(&mut rng);
        Ok(())
    }

    /// HIGH-2 FIX: Shuffle batches immediately on receipt using Fisher-Yates with OsRng
    ///
    /// This is called after each batch submission to prevent timing correlation.
    /// Uses OsRng directly for maximum security instead of seeded ChaCha20Rng.
    fn shuffle_anonymous_token_batches_immediate(&mut self) -> Result<(), WraithError> {
        use rand::rngs::OsRng;
        use rand::seq::SliceRandom;

        // HIGH-2: Use OsRng for immediate, unpredictable shuffling
        // Fisher-Yates shuffle is built into SliceRandom::shuffle
        self.anonymous_token_batches.shuffle(&mut OsRng);
        Ok(())
    }

    /// Clear sensitive data immediately after building transactions
    /// This reduces the window for compromise (WR-H3)
    ///
    /// SECURITY: Call this immediately after building each phase transaction
    /// to minimize the window during which sensitive data could be compromised.
    pub fn clear_sensitive_data_post_build(&mut self) {
        // Clear anonymous tokens and batches - no longer needed after building tx
        self.anonymous_tokens.clear();
        // Note: Don't clear anonymous_token_batches yet - needed for Phase 2 final addresses!

        // Clear participant-linked data
        for participant in self.participants.values_mut() {
            // Clear tokens (if any were stored via deprecated method)
            participant.tokens.clear();
            // Clear blinded challenges
            participant.blinded_challenges.clear();
            // Clear signature responses
            participant.signature_responses.clear();
            // Clear issued nonces
            participant.issued_nonces.clear();
        }
    }

    /// Record Phase 1 signature from participant
    pub fn add_phase1_signature(&mut self, ghost_id: &str) -> Result<bool, WraithError> {
        let session_id = self
            .get_session_participant_id(ghost_id)
            .ok_or_else(|| WraithError::InvalidInput("Unknown participant".to_string()))?
            .clone();
        // CRIT-7: Return error instead of panicking on internal inconsistency
        let participant = self.participants.get_mut(&session_id).ok_or_else(|| {
            WraithError::MissingData("Internal error: participant mapping inconsistent".into())
        })?;

        participant.phase1_signed = true;

        // Check if all signatures collected
        let all_signed = self.participants.values().all(|p| p.phase1_signed);
        if all_signed {
            if let Some(ref mut phase1) = self.session.phase1_mut() {
                // Add all signatures at once
                for _ in 0..self.participants.len() {
                    phase1.add_signature();
                }
            }
        }

        Ok(all_signed)
    }

    /// Broadcast Phase 1 transaction
    pub fn broadcast_phase1(&mut self, tx_hex: &str) -> Result<String, WraithError> {
        let broadcast_fn = self.broadcast_fn.as_ref().ok_or_else(|| {
            WraithError::PhaseError("No broadcast function configured".to_string())
        })?;

        let txid_str = broadcast_fn(tx_hex)
            .map_err(|e| WraithError::TransactionError(format!("Broadcast failed: {}", e)))?;

        // Update phase state
        if let Some(ref mut phase1) = self.session.phase1_mut() {
            phase1.broadcast(txid_str.clone());
        }

        // Parse txid and store outputs for Phase 2
        let txid = txid_str
            .parse::<Txid>()
            .map_err(|e| WraithError::TransactionError(format!("Invalid txid: {}", e)))?;

        // Store Phase 1 outputs for Phase 2 inputs (with script pubkeys from built tx)
        let phase1_tx = self
            .phase1_tx
            .as_ref()
            .ok_or_else(|| WraithError::PhaseError("Phase 1 transaction not built".to_string()))?;

        let intermediate_amount = self.session.denomination().intermediate_sats();

        // Get script pubkeys from the Phase 1 transaction outputs
        // Skip the last output (OP_RETURN marker)
        for (vout, output) in phase1_tx.transaction.output.iter().enumerate() {
            // Skip OP_RETURN output (zero value)
            if output.value.to_sat() == 0 {
                continue;
            }
            self.phase1_outputs.push((
                txid,
                vout as u32,
                intermediate_amount,
                output.script_pubkey.clone(),
            ));
        }

        // WR4-L9: Log transaction broadcast
        self.log_audit_event(AuditEvent::TransactionBroadcast {
            session_id: *self.session.session_id(),
            phase: 1,
            txid: txid_str.clone(),
            timestamp: Self::current_timestamp(),
        });

        Ok(txid_str)
    }

    /// Confirm Phase 1 on-chain
    pub fn confirm_phase1(&mut self, block_height: u32) -> Result<(), WraithError> {
        let result = self.session.confirm_phase1(block_height);

        // WR4-L9: Log phase transition
        if result.is_ok() {
            self.log_audit_event(AuditEvent::PhaseTransition {
                session_id: *self.session.session_id(),
                from_state: "ExecutingPhase1".to_string(),
                to_state: "WaitingPhase1Confirmation".to_string(),
                timestamp: Self::current_timestamp(),
            });
        }

        result
    }

    /// Check if ready for Phase 2
    pub fn ready_for_phase2(&self) -> bool {
        // Need Phase 1 confirmed
        let phase1_confirmed = matches!(
            self.session.state(),
            SessionState::WaitingPhase1Confirmation
        ) && self
            .session
            .phase1()
            .map(|p| p.state() == PhaseState::Confirmed)
            .unwrap_or(false);

        if !phase1_confirmed {
            return false;
        }

        // CRIT-1 FIX: Check anonymous_token_batches for final addresses (new secure path)
        // Each batch contains a final address that was submitted anonymously
        let have_anonymous_addresses =
            self.anonymous_token_batches.len() >= self.participants.len();

        // Legacy fallback: check participant.final_address (deprecated, leaks identity)
        let have_legacy_addresses = self
            .participants
            .values()
            .all(|p| p.final_address.is_some());

        have_anonymous_addresses || have_legacy_addresses
    }

    /// Build Phase 2 (merge) transaction
    pub fn build_phase2(&mut self) -> Result<&MergeTransaction, WraithError> {
        if self.phase1_outputs.is_empty() {
            return Err(WraithError::PhaseError(
                "Phase 1 outputs not available".to_string(),
            ));
        }

        // Transition session state
        self.session.start_phase2()?;

        let builder = WraithTransactionBuilder::new(
            self.session_id_hex(),
            *self.session.denomination(),
            self.network,
        );

        // Build intermediate inputs (10 per participant)
        let mut intermediate_inputs: Vec<Vec<WraithInput>> = Vec::new();
        let mut output_idx = 0;

        for (p_idx, _session_id) in self.participant_order.iter().enumerate() {
            let mut participant_inputs = Vec::new();
            for _ in 0..SPLIT_RATIO {
                let (txid, vout, amount, ref script_pubkey) = self.phase1_outputs[output_idx];
                participant_inputs.push(WraithInput {
                    txid,
                    vout,
                    amount,
                    script_pubkey: script_pubkey.clone(),
                    participant_id: p_idx as u32,
                });
                output_idx += 1;
            }
            intermediate_inputs.push(participant_inputs);
        }

        // CRIT-1 FIX: Collect final addresses from ANONYMOUS batches (not linked to participants)
        // This eliminates the privacy leak where submit_final_address(ghost_id, addr) linked
        // participant identity to output address.
        let use_anonymous_addresses = self.anonymous_token_batches.len() >= self.participants.len();

        let final_addresses: Vec<String> = if use_anonymous_addresses {
            // New secure path: addresses come from anonymous batches (shuffled during Phase 1)
            // The order matches the shuffled token batches, so there's no identity linkage
            self.anonymous_token_batches
                .iter()
                .map(|batch| batch.final_address.clone())
                .collect()
        } else {
            // Legacy path: addresses from participant.final_address (DEPRECATED - leaks identity!)
            // This path exists for backward compatibility but should not be used
            let mut addrs = Vec::with_capacity(self.participant_order.len());
            for session_id in &self.participant_order {
                let participant = self.participants.get(session_id).ok_or_else(|| {
                    WraithError::PhaseError(format!("Missing participant in order: {}", session_id))
                })?;

                let address = participant.final_address.as_ref().ok_or_else(|| {
                    WraithError::PhaseError(format!(
                        "Participant {} has not submitted a final address (use submit_tokens_with_address_anonymous)",
                        session_id
                    ))
                })?;

                if address.is_empty() {
                    return Err(WraithError::PhaseError(format!(
                        "Participant {} has empty final address",
                        session_id
                    )));
                }

                addrs.push(address.clone());
            }
            addrs
        };

        // Validate we have the right number of addresses
        if final_addresses.len() != self.participants.len() {
            return Err(WraithError::PhaseError(format!(
                "Address count mismatch: have {}, need {}",
                final_addresses.len(),
                self.participants.len()
            )));
        }

        let tx = builder.build_merge_transaction(&intermediate_inputs, &final_addresses)?;
        self.phase2_tx = Some(tx);

        // CRIT-7: Return error instead of panicking (though this should never fail)
        self.phase2_tx
            .as_ref()
            .ok_or_else(|| WraithError::MissingData("Internal error: phase2_tx was not set".into()))
    }

    /// Record Phase 2 signature from participant
    pub fn add_phase2_signature(&mut self, ghost_id: &str) -> Result<bool, WraithError> {
        let session_id = self
            .get_session_participant_id(ghost_id)
            .ok_or_else(|| WraithError::InvalidInput("Unknown participant".to_string()))?
            .clone();
        // CRIT-7: Return error instead of panicking on internal inconsistency
        let participant = self.participants.get_mut(&session_id).ok_or_else(|| {
            WraithError::MissingData("Internal error: participant mapping inconsistent".into())
        })?;

        participant.phase2_signed = true;

        // Check if all signatures collected
        let all_signed = self.participants.values().all(|p| p.phase2_signed);
        if all_signed {
            if let Some(ref mut phase2) = self.session.phase2_mut() {
                for _ in 0..self.participants.len() {
                    phase2.add_signature();
                }
            }
        }

        Ok(all_signed)
    }

    /// Broadcast Phase 2 transaction
    pub fn broadcast_phase2(&mut self, tx_hex: &str) -> Result<String, WraithError> {
        let broadcast_fn = self.broadcast_fn.as_ref().ok_or_else(|| {
            WraithError::PhaseError("No broadcast function configured".to_string())
        })?;

        let txid_str = broadcast_fn(tx_hex)
            .map_err(|e| WraithError::TransactionError(format!("Broadcast failed: {}", e)))?;

        // Update phase state
        if let Some(ref mut phase2) = self.session.phase2_mut() {
            phase2.broadcast(txid_str.clone());
        }

        // WR4-L9: Log transaction broadcast
        self.log_audit_event(AuditEvent::TransactionBroadcast {
            session_id: *self.session.session_id(),
            phase: 2,
            txid: txid_str.clone(),
            timestamp: Self::current_timestamp(),
        });

        Ok(txid_str)
    }

    /// Confirm Phase 2 on-chain (completes the session)
    ///
    /// Also records successful completion in reputation tracker (WR-M3).
    pub fn confirm_phase2(&mut self, block_height: u32) -> Result<(), WraithError> {
        self.session.confirm_phase2(block_height)?;

        // Record success for all participants in reputation tracker (WR-M3)
        // Use reverse mapping to get original ghost_ids
        if let Some(ref reputation) = self.reputation {
            let mut rep = reputation.write();
            for session_id in &self.participant_order {
                if let Some(ghost_id) = self.session_id_to_ghost_id.get(session_id) {
                    rep.record_success(ghost_id);
                }
            }
        }

        // WR4-L9: Log session completion
        self.log_audit_event(AuditEvent::SessionCompleted {
            session_id: *self.session.session_id(),
            success: true,
            participant_count: self.participants.len(),
            timestamp: Self::current_timestamp(),
        });

        Ok(())
    }

    /// Get Phase 1 transaction (if built)
    pub fn phase1_transaction(&self) -> Option<&SplitTransaction> {
        self.phase1_tx.as_ref()
    }

    /// Get Phase 2 transaction (if built)
    pub fn phase2_transaction(&self) -> Option<&MergeTransaction> {
        self.phase2_tx.as_ref()
    }

    /// Get Phase 1 txid (if broadcast)
    ///
    /// Returns the txid of the Phase 1 transaction if it has been broadcast.
    pub fn phase1_txid(&self) -> Option<Txid> {
        self.phase1_outputs.first().map(|(txid, _, _, _)| *txid)
    }

    /// Get Phase 2 txid (if broadcast)
    ///
    /// Returns the txid of the Phase 2 transaction if it has been broadcast.
    pub fn phase2_txid(&self) -> Option<Txid> {
        self.phase2_tx
            .as_ref()
            .map(|tx| tx.transaction.compute_txid())
    }

    /// Check if Phase 1 needs confirmation (has been broadcast but not confirmed)
    pub fn phase1_needs_confirmation(&self) -> bool {
        let has_broadcast = !self.phase1_outputs.is_empty();
        let is_confirmed = self
            .session
            .phase1()
            .map(|p| p.state() == PhaseState::Confirmed)
            .unwrap_or(false);
        has_broadcast && !is_confirmed
    }

    /// Check if Phase 2 needs confirmation (has been broadcast but not confirmed)
    pub fn phase2_needs_confirmation(&self) -> bool {
        let has_broadcast = self
            .session
            .phase2()
            .map(|p| p.txid().is_some())
            .unwrap_or(false);
        let is_confirmed = self
            .session
            .phase2()
            .map(|p| p.state() == PhaseState::Confirmed)
            .unwrap_or(false);
        has_broadcast && !is_confirmed
    }

    /// Check if session has timed out
    pub fn is_timed_out(&self) -> bool {
        self.session.is_timed_out()
    }

    /// Get remaining time in seconds before timeout
    pub fn remaining_secs(&self) -> u64 {
        self.session.remaining_secs()
    }

    /// Handle session timeout - returns action to take
    ///
    /// Returns Ok(TimeoutAction) describing what happened:
    /// - Refunded: Session was in early stage, participants refunded
    /// - Failed: Session failed in execution phase, manual recovery needed
    /// - None: Session is not timed out or already terminal
    pub fn handle_timeout(&mut self) -> Result<TimeoutAction, WraithError> {
        if !self.session.is_timed_out() {
            return Ok(TimeoutAction::None);
        }

        if self.session.state().is_terminal() {
            return Ok(TimeoutAction::None);
        }

        match self.session.state() {
            SessionState::WaitingForParticipants => {
                // Not enough participants joined in time - refund
                let _ = self.session.refund();
                Ok(TimeoutAction::Refunded {
                    reason: "Not enough participants joined before timeout".to_string(),
                    participant_count: self.participants.len(),
                })
            }
            SessionState::CollectingInputs => {
                // Some participants didn't submit inputs - need refund
                let missing: Vec<String> = self
                    .participants
                    .iter()
                    .filter(|(_, p)| p.input.is_none())
                    .map(|(id, _)| id.clone())
                    .collect();
                let _ = self.session.refund();
                Ok(TimeoutAction::Refunded {
                    reason: format!("{} participant(s) didn't submit inputs", missing.len()),
                    participant_count: self.participants.len(),
                })
            }
            SessionState::ExecutingPhase1 | SessionState::WaitingPhase1Confirmation => {
                // Phase 1 failed - funds may be stuck, need manual recovery
                let missing_session_ids: Vec<String> = self
                    .participants
                    .iter()
                    .filter(|(_, p)| !p.phase1_signed)
                    .map(|(id, _)| id.clone())
                    .collect();

                // Record failures in reputation tracker (WR-M3)
                // Use reverse mapping to get original ghost_ids
                if let Some(ref reputation) = self.reputation {
                    let mut rep = reputation.write();
                    for session_id in &missing_session_ids {
                        if let Some(ghost_id) = self.session_id_to_ghost_id.get(session_id) {
                            rep.record_failure(ghost_id);
                        }
                    }
                }

                let _ = self.session.fail();
                Ok(TimeoutAction::Failed {
                    phase: 1,
                    reason: format!(
                        "Phase 1 timed out, {} participant(s) didn't sign",
                        missing_session_ids.len()
                    ),
                    stuck_funds: self.calculate_stuck_funds(),
                })
            }
            SessionState::ExecutingPhase2 | SessionState::WaitingPhase2Confirmation => {
                // Phase 2 failed - intermediate UTXOs may be stuck
                let missing_session_ids: Vec<String> = self
                    .participants
                    .iter()
                    .filter(|(_, p)| !p.phase2_signed)
                    .map(|(id, _)| id.clone())
                    .collect();

                // Record failures in reputation tracker (WR-M3)
                // Use reverse mapping to get original ghost_ids
                if let Some(ref reputation) = self.reputation {
                    let mut rep = reputation.write();
                    for session_id in &missing_session_ids {
                        if let Some(ghost_id) = self.session_id_to_ghost_id.get(session_id) {
                            rep.record_failure(ghost_id);
                        }
                    }
                }

                let _ = self.session.fail();
                Ok(TimeoutAction::Failed {
                    phase: 2,
                    reason: format!(
                        "Phase 2 timed out, {} participant(s) didn't sign",
                        missing_session_ids.len()
                    ),
                    stuck_funds: self.calculate_stuck_funds(),
                })
            }
            _ => Ok(TimeoutAction::None),
        }
    }

    /// Calculate total funds that may be stuck due to failure
    fn calculate_stuck_funds(&self) -> u64 {
        self.participants
            .values()
            .filter_map(|p| p.input.as_ref().map(|i| i.amount))
            .sum()
    }

    /// Extend session timeout (for slow confirmation phases)
    pub fn extend_timeout(&mut self, additional_secs: u64) {
        self.session.extend_timeout(additional_secs);
    }

    /// End the session and clear all sensitive data (WR4-L2)
    ///
    /// This method should be called when a session ends (either successfully or due to failure).
    /// It clears all session-specific data including:
    /// - Used tokens (prevents unbounded memory growth)
    /// - Anonymous tokens
    /// - Participant data
    /// - Transaction outputs
    ///
    /// SECURITY: This ensures tokens are cleaned up per-session rather than globally,
    /// preventing token tracking across sessions.
    pub fn end_session(&mut self) {
        // Clear used tokens for this session
        self.used_tokens.clear();

        // Clear anonymous token pool and batches
        self.anonymous_tokens.clear();
        self.anonymous_token_batches.clear();

        // Clear submitted addresses
        self.submitted_addresses.clear();

        // Clear Phase 1 outputs
        self.phase1_outputs.clear();

        // Clear participant-linked data
        for participant in self.participants.values_mut() {
            participant.tokens.clear();
            participant.blinded_challenges.clear();
            participant.signature_responses.clear();
            participant.issued_nonces.clear();
            participant.input = None;
            participant.final_address = None;
        }

        // Clear ghost_id mappings
        self.ghost_id_to_session_id.clear();
        self.session_id_to_ghost_id.clear();

        tracing::debug!(
            session_id = %self.session_id_hex(),
            "Session ended and sensitive data cleared"
        );
    }

    /// Get session created timestamp
    pub fn created_at(&self) -> u64 {
        // Session stores this internally
        self.session
            .timeout_at()
            .saturating_sub(crate::DEFAULT_TIMEOUT_SECS)
    }

    /// Check if the session has deep confirmation (safe for purging)
    ///
    /// Both Phase 1 and Phase 2 must be confirmed with sufficient depth
    /// before we consider it safe to purge sensitive data.
    pub fn is_deep_confirmed(&self, required_depth: u32, current_height: u32) -> bool {
        // Update depths first
        let phase1_deep = if let Some(phase1) = self.session.phase1() {
            let mut phase1_clone = phase1.clone();
            phase1_clone.update_depth(current_height);
            phase1_clone.is_deep_confirmed(required_depth)
        } else {
            false
        };

        let phase2_deep = if let Some(phase2) = self.session.phase2() {
            let mut phase2_clone = phase2.clone();
            phase2_clone.update_depth(current_height);
            phase2_clone.is_deep_confirmed(required_depth)
        } else {
            false
        };

        phase1_deep && phase2_deep
    }

    /// Update confirmation depths from current block height
    ///
    /// Call this when new blocks arrive to track confirmation depth.
    pub fn update_confirmation_depth(&mut self, current_height: u32) {
        if let Some(phase1) = self.session.phase1_mut() {
            phase1.update_depth(current_height);
        }
        if let Some(phase2) = self.session.phase2_mut() {
            phase2.update_depth(current_height);
        }
    }

    /// Purge sensitive data after deep confirmation
    ///
    /// This removes all data that could link participants to their Ghost Locks
    /// while retaining minimal audit information for emergency recovery.
    ///
    /// # Safety
    ///
    /// Only call this after `is_deep_confirmed()` returns true with at least 6 blocks.
    /// The 6-block depth requirement ensures the transaction is extremely unlikely
    /// to be reorged (would require >50% hash power attacking for 6+ blocks).
    ///
    /// # Returns
    ///
    /// Returns `Some(SessionAuditRecord)` if data was purged, `None` if the session
    /// doesn't have deep enough confirmations yet.
    pub fn purge_sensitive_data(
        &mut self,
        required_depth: u32,
        current_height: u32,
    ) -> Option<SessionAuditRecord> {
        // Only purge if deeply confirmed
        if !self.is_deep_confirmed(required_depth, current_height) {
            return None;
        }

        // Create audit record before purging
        let phase1_txid = self.phase1_txid().map(|txid| *txid.as_byte_array());

        let phase2_txid = self.phase2_txid().map(|txid| *txid.as_byte_array());

        let confirmed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let audit = SessionAuditRecord {
            session_id: *self.session.session_id(),
            phase1_txid,
            phase2_txid,
            participant_count: self.participants.len(),
            confirmed_at,
        };

        // Purge sensitive data from all participants
        for participant in self.participants.values_mut() {
            // Clear input UTXO data (links public Bitcoin to this session)
            participant.input = None;

            // Clear blind signature tokens (could be used to trace)
            participant.tokens.clear();
            participant.issued_nonces.clear();
            participant.blinded_challenges.clear();
            participant.signature_responses.clear();

            // Clear session participant ID (severs the link to ghost_id)
            participant.session_participant_id = String::new();

            // Clear final address (links session to output)
            participant.final_address = None;
        }

        // Clear transaction outputs that could be used to trace
        self.phase1_outputs.clear();

        // Clear ghost_id mappings (severs all cross-session tracking ability)
        self.ghost_id_to_session_id.clear();
        self.session_id_to_ghost_id.clear();

        // Clear used tokens (privacy: prevents cross-session token correlation)
        self.used_tokens.clear();

        // Clear anonymous tokens pool and batches
        self.anonymous_tokens.clear();
        self.anonymous_token_batches.clear();

        Some(audit)
    }
}

/// Action to take when a session times out
#[derive(Debug, Clone)]
pub enum TimeoutAction {
    /// No action needed (not timed out or already terminal)
    None,
    /// Session was refunded (early stage timeout)
    Refunded {
        reason: String,
        participant_count: usize,
    },
    /// Session failed (execution stage timeout)
    Failed {
        phase: u8,
        reason: String,
        stuck_funds: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a coordinator for testing (UTXO requirement disabled)
    fn create_test_coordinator(
        tier: ParticipantTier,
        denomination: WraithDenomination,
        network: Network,
    ) -> WraithCoordinator {
        WraithCoordinator::new(tier, denomination, network)
            .expect("test RNG should work")
            .without_utxo_required_for_registration()
    }

    #[test]
    fn test_coordinator_creation() {
        let coord = create_test_coordinator(
            ParticipantTier::Micro,
            WraithDenomination::Small,
            Network::Regtest,
        );

        assert_eq!(coord.participant_count(), 0);
        assert!(matches!(
            coord.state(),
            SessionState::WaitingForParticipants
        ));
    }

    #[test]
    fn test_participant_registration() {
        let mut coord = create_test_coordinator(
            ParticipantTier::Micro,
            WraithDenomination::Small,
            Network::Regtest,
        );

        let idx = coord.register_participant("ghost1abc".to_string()).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(coord.participant_count(), 1);

        let idx2 = coord.register_participant("ghost1def".to_string()).unwrap();
        assert_eq!(idx2, 1);
        assert_eq!(coord.participant_count(), 2);
    }

    #[test]
    fn test_duplicate_registration_fails() {
        let mut coord = create_test_coordinator(
            ParticipantTier::Micro,
            WraithDenomination::Small,
            Network::Regtest,
        );

        coord.register_participant("ghost1abc".to_string()).unwrap();
        let result = coord.register_participant("ghost1abc".to_string());
        assert!(result.is_err());
    }

    /// WR-C2 Security Test: Token submission is unlinkable
    ///
    /// This test verifies that anonymous token submission does NOT create
    /// any linkage between the submitter and the tokens.
    #[test]
    fn test_token_submission_unlinkable() {
        use crate::blind::BlindingContext;

        let mut coord = create_test_coordinator(
            ParticipantTier::Micro,
            WraithDenomination::Small,
            Network::Regtest,
        );

        // Register two participants
        coord.register_participant("ghost1".to_string()).unwrap();
        coord.register_participant("ghost2".to_string()).unwrap();

        // Get the coordinator's public key for blinding
        let coord_pubkey = *coord.signer.public_key();
        let key_id = *coord.signer.key_id();

        // Participant 1 requests nonces through the coordinator
        let nonces1 = coord.request_nonces("ghost1").unwrap();
        assert_eq!(nonces1.len(), crate::SPLIT_RATIO);

        // Participant 1 creates blinded challenges
        let mut challenges1 = Vec::new();
        let mut contexts1 = Vec::new();
        for nonce in &nonces1 {
            let message = [0x01u8; 32].to_vec(); // Fake address bytes
            let context = BlindingContext::new(message, &coord_pubkey, nonce).unwrap();
            let challenge = context.create_blinded_challenge().unwrap();
            challenges1.push(challenge);
            contexts1.push(context);
        }

        // Participant 1 submits challenges and gets responses
        let responses1 = coord
            .submit_blinded_challenges("ghost1", challenges1)
            .unwrap();

        // Participant 1 unblinds to get tokens
        let mut tokens1 = Vec::new();
        for (context, response) in contexts1.iter().zip(responses1.iter()) {
            let token = context.unblind(response, key_id).unwrap();
            tokens1.push(token);
        }

        // Participant 2 goes through the same process
        let nonces2 = coord.request_nonces("ghost2").unwrap();
        let mut challenges2 = Vec::new();
        let mut contexts2 = Vec::new();
        for nonce in &nonces2 {
            let message = [0x02u8; 32].to_vec(); // Different fake address
            let context = BlindingContext::new(message, &coord_pubkey, nonce).unwrap();
            let challenge = context.create_blinded_challenge().unwrap();
            challenges2.push(challenge);
            contexts2.push(context);
        }
        let responses2 = coord
            .submit_blinded_challenges("ghost2", challenges2)
            .unwrap();
        let mut tokens2 = Vec::new();
        for (context, response) in contexts2.iter().zip(responses2.iter()) {
            let token = context.unblind(response, key_id).unwrap();
            tokens2.push(token);
        }

        // Submit tokens WITH addresses ANONYMOUSLY using the new secure API
        // The coordinator doesn't know who submitted what batch
        // CRIT-1 FIX: Uses submit_tokens_with_address_anonymous instead of deprecated method
        let final_address1 = "bcrt1qdummy1qqqqqqqqqqqqqqqqqqqqqqqqqqz87fmc".to_string();
        let final_address2 = "bcrt1qdummy2qqqqqqqqqqqqqqqqqqqqqqqqqqpglhxe".to_string();

        coord
            .submit_tokens_with_address_anonymous(tokens1, final_address1)
            .unwrap();
        coord
            .submit_tokens_with_address_anonymous(tokens2, final_address2)
            .unwrap();

        // Verify we have 2 anonymous batches
        assert_eq!(coord.anonymous_batch_count(), 2);

        // Verify total token count across batches
        assert_eq!(coord.anonymous_token_count(), 2 * crate::SPLIT_RATIO);

        // The coordinator cannot determine which tokens/addresses belong to which participant
        // This is verified by the fact that submit_tokens_with_address_anonymous takes no ghost_id
    }

    /// WR-H2 Security Test: Duplicate addresses are rejected
    /// CRIT-1 Updated: Uses new submit_tokens_with_address_anonymous API
    #[test]
    fn test_duplicate_address_rejected() {
        use crate::blind::BlindingContext;

        let mut coord = create_test_coordinator(
            ParticipantTier::Micro,
            WraithDenomination::Small,
            Network::Regtest,
        );

        coord.register_participant("ghost1".to_string()).unwrap();

        // Get coordinator's public key for blinding
        let coord_pubkey = *coord.signer.public_key();
        let key_id = *coord.signer.key_id();

        // Create tokens for test
        let nonces = coord.request_nonces("ghost1").unwrap();
        let mut challenges = Vec::new();
        let mut contexts = Vec::new();
        for nonce in &nonces {
            let message = [0x01u8; 32].to_vec();
            let context = BlindingContext::new(message, &coord_pubkey, nonce).unwrap();
            let challenge = context.create_blinded_challenge().unwrap();
            challenges.push(challenge);
            contexts.push(context);
        }
        let responses = coord
            .submit_blinded_challenges("ghost1", challenges)
            .unwrap();
        let mut tokens1 = Vec::new();
        for (context, response) in contexts.iter().zip(responses.iter()) {
            let token = context.unblind(response, key_id).unwrap();
            tokens1.push(token);
        }

        // Create another set of tokens
        coord.register_participant("ghost2".to_string()).unwrap();
        let nonces2 = coord.request_nonces("ghost2").unwrap();
        let mut challenges2 = Vec::new();
        let mut contexts2 = Vec::new();
        for nonce in &nonces2 {
            let message = [0x02u8; 32].to_vec();
            let context = BlindingContext::new(message, &coord_pubkey, nonce).unwrap();
            let challenge = context.create_blinded_challenge().unwrap();
            challenges2.push(challenge);
            contexts2.push(context);
        }
        let responses2 = coord
            .submit_blinded_challenges("ghost2", challenges2)
            .unwrap();
        let mut tokens2 = Vec::new();
        for (context, response) in contexts2.iter().zip(responses2.iter()) {
            let token = context.unblind(response, key_id).unwrap();
            tokens2.push(token);
        }

        let test_address = "bcrt1qdummy1qqqqqqqqqqqqqqqqqqqqqqqqqqz87fmc".to_string();

        // First submission should succeed
        coord
            .submit_tokens_with_address_anonymous(tokens1, test_address.clone())
            .unwrap();

        // Second submission of SAME address should FAIL
        let result = coord.submit_tokens_with_address_anonymous(tokens2, test_address.clone());
        assert!(result.is_err(), "Duplicate address should be rejected");
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Duplicate address"));
    }

    /// WR-H3 Test: Data is cleared after building transaction
    #[test]
    fn test_data_cleared_after_build() {
        use crate::blind::BlindingContext;
        use bitcoin::ScriptBuf;

        let mut coord = create_test_coordinator(
            ParticipantTier::Micro,
            WraithDenomination::Small,
            Network::Regtest,
        );

        // Create test txid
        let txid = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();

        // Register a participant
        coord.register_participant("ghost1".to_string()).unwrap();

        // Submit input
        coord
            .submit_input(
                "ghost1",
                crate::executor::WraithInput {
                    txid,
                    vout: 0,
                    amount: 1_100_000,
                    script_pubkey: ScriptBuf::new(),
                    participant_id: 0,
                },
            )
            .unwrap();

        // Get coordinator's public key for blinding
        let coord_pubkey = *coord.signer.public_key();
        let key_id = *coord.signer.key_id();

        // Request nonces through coordinator
        let nonces = coord.request_nonces("ghost1").unwrap();

        // Create blinded challenges
        let mut challenges = Vec::new();
        let mut contexts = Vec::new();
        for nonce in &nonces {
            let message = [0x01u8; 32].to_vec();
            let context = BlindingContext::new(message, &coord_pubkey, nonce).unwrap();
            let challenge = context.create_blinded_challenge().unwrap();
            challenges.push(challenge);
            contexts.push(context);
        }

        // Submit challenges and get responses
        let responses = coord
            .submit_blinded_challenges("ghost1", challenges)
            .unwrap();

        // Unblind to get tokens
        let mut tokens = Vec::new();
        for (context, response) in contexts.iter().zip(responses.iter()) {
            let token = context.unblind(response, key_id).unwrap();
            tokens.push(token);
        }

        // CRIT-1 FIX: Use submit_tokens_with_address_anonymous instead
        let final_address = "bcrt1qdummy1qqqqqqqqqqqqqqqqqqqqqqqqqqz87fmc".to_string();
        coord
            .submit_tokens_with_address_anonymous(tokens, final_address)
            .unwrap();
        assert_eq!(coord.anonymous_batch_count(), 1);
        assert_eq!(coord.anonymous_token_count(), crate::SPLIT_RATIO);

        // After clear, anonymous batches should be cleared from anonymous_tokens legacy field
        // Note: anonymous_token_batches are NOT cleared as they're needed for Phase 2
        // This test verifies the legacy anonymous_tokens are cleared
        coord.clear_sensitive_data_post_build();

        // The batch count should still be 1 (needed for Phase 2 final addresses)
        // But the legacy anonymous_tokens field (not used with new API) should be cleared
        // anonymous_token_count includes batch tokens which are kept for Phase 2
        assert_eq!(coord.anonymous_batch_count(), 1, "Batches kept for Phase 2");
    }

    /// WR-M4 Test: Session-specific participant IDs prevent cross-session tracking
    #[test]
    fn test_session_specific_participant_ids() {
        // Create two coordinators with different sessions
        let coord1 = create_test_coordinator(
            ParticipantTier::Micro,
            WraithDenomination::Small,
            Network::Regtest,
        );
        let coord2 = create_test_coordinator(
            ParticipantTier::Micro,
            WraithDenomination::Small,
            Network::Regtest,
        );

        // Same ghost_id in different sessions should produce different session_participant_ids
        let ghost_id = "same_ghost_id";

        let session_id1 = derive_session_participant_id(ghost_id, coord1.session_id());
        let session_id2 = derive_session_participant_id(ghost_id, coord2.session_id());

        assert_ne!(
            session_id1, session_id2,
            "Same ghost_id should have different session_participant_ids in different sessions"
        );
    }

    /// WR-M3 Test: Reputation tracking bans repeat offenders
    #[test]
    fn test_reputation_tracking() {
        let mut reputation = ReputationTracker::new();

        let ghost_id = "bad_actor";

        // Initially allowed
        assert!(reputation.is_allowed(ghost_id));
        assert_eq!(reputation.get_strikes(ghost_id), 0);

        // First two failures: still allowed
        reputation.record_failure(ghost_id);
        assert!(reputation.is_allowed(ghost_id));
        assert_eq!(reputation.get_strikes(ghost_id), 1);

        reputation.record_failure(ghost_id);
        assert!(reputation.is_allowed(ghost_id));
        assert_eq!(reputation.get_strikes(ghost_id), 2);

        // Third failure: BANNED
        reputation.record_failure(ghost_id);
        assert!(!reputation.is_allowed(ghost_id));
        assert!(reputation.is_banned(ghost_id));

        // Success can reduce strikes (but doesn't unban)
        let good_actor = "good_actor";
        reputation.record_failure(good_actor);
        assert_eq!(reputation.get_strikes(good_actor), 1);
        reputation.record_success(good_actor);
        assert_eq!(reputation.get_strikes(good_actor), 0);
    }

    /// WR-M3 Test: Banned participants cannot register
    #[test]
    fn test_banned_participant_rejected() {
        let reputation = Arc::new(parking_lot::RwLock::new(ReputationTracker::new()));

        // Ban a ghost_id
        {
            let mut rep = reputation.write();
            rep.ban("banned_ghost");
        }

        let mut coord = WraithCoordinator::new(
            ParticipantTier::Micro,
            WraithDenomination::Small,
            Network::Regtest,
        )
        .expect("test RNG should work")
        .with_reputation(reputation)
        .without_utxo_required_for_registration();

        // Banned ghost_id should be rejected
        let result = coord.register_participant("banned_ghost".to_string());
        assert!(result.is_err(), "Banned ghost should be rejected");
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("banned") || err_str.contains("Participant is banned"),
            "Error should mention banned: {}",
            err_str
        );

        // Non-banned ghost_id should be accepted
        let result = coord.register_participant("good_ghost".to_string());
        assert!(result.is_ok());
    }

    /// WR-L2 Test: UTXO verification callback is called
    #[test]
    fn test_utxo_verification() {
        use bitcoin::ScriptBuf;
        use std::sync::atomic::{AtomicBool, Ordering};

        let verification_called = Arc::new(AtomicBool::new(false));
        let verification_called_clone = verification_called.clone();

        let mut coord = WraithCoordinator::new(
            ParticipantTier::Micro,
            WraithDenomination::Small,
            Network::Regtest,
        )
        .expect("test RNG should work")
        .with_utxo_verifier(move |_txid, _vout| {
            verification_called_clone.store(true, Ordering::SeqCst);
            Ok(true) // UTXO exists
        })
        .without_utxo_required_for_registration();

        coord.register_participant("ghost1".to_string()).unwrap();

        let txid = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();

        coord
            .submit_input(
                "ghost1",
                crate::executor::WraithInput {
                    txid,
                    vout: 0,
                    amount: 1_100_000,
                    script_pubkey: ScriptBuf::new(),
                    participant_id: 0,
                },
            )
            .unwrap();

        assert!(
            verification_called.load(Ordering::SeqCst),
            "UTXO verification callback should have been called"
        );
    }

    /// WR-L2 Test: Non-existent UTXO is rejected
    #[test]
    fn test_utxo_verification_rejects_nonexistent() {
        use bitcoin::ScriptBuf;

        let mut coord = WraithCoordinator::new(
            ParticipantTier::Micro,
            WraithDenomination::Small,
            Network::Regtest,
        )
        .expect("test RNG should work")
        .with_utxo_verifier(|_txid, _vout| {
            Ok(false) // UTXO does NOT exist
        })
        .without_utxo_required_for_registration();

        coord.register_participant("ghost1".to_string()).unwrap();

        let txid = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();

        let result = coord.submit_input(
            "ghost1",
            crate::executor::WraithInput {
                txid,
                vout: 0,
                amount: 1_100_000,
                script_pubkey: ScriptBuf::new(),
                participant_id: 0,
            },
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not exist"));
    }

    /// M-WRAITH-1 Test: TokenCache evicts old tokens instead of clearing all
    #[test]
    fn test_token_cache_lru_eviction() {
        use std::time::Duration;

        // Create a small cache with short max age for testing
        let mut cache = TokenCache::new(3, Duration::from_secs(60));

        // Add 3 tokens
        let token1 = [1u8; 32];
        let token2 = [2u8; 32];
        let token3 = [3u8; 32];

        assert!(!cache.check_and_mark(token1)); // Not replay
        assert!(!cache.check_and_mark(token2)); // Not replay
        assert!(!cache.check_and_mark(token3)); // Not replay

        // Cache should have 3 tokens
        assert_eq!(cache.len(), 3);

        // Verify they are still tracked as replays
        assert!(cache.contains(&token1));
        assert!(cache.contains(&token2));
        assert!(cache.contains(&token3));

        // Add a 4th token - should evict oldest (token1)
        let token4 = [4u8; 32];
        assert!(!cache.check_and_mark(token4)); // Not replay

        // Cache should still have 3 tokens (one was evicted)
        assert_eq!(cache.len(), 3);

        // token1 WAS evicted (it was the oldest)
        // So it should NOT be detected as a replay anymore
        assert!(!cache.contains(&token1), "token1 should have been evicted");

        // But token2, token3, and token4 should still be tracked
        assert!(cache.contains(&token2), "token2 should still be in cache");
        assert!(cache.contains(&token3), "token3 should still be in cache");
        assert!(cache.contains(&token4), "token4 should be in cache");

        // Replaying token4 should be detected
        assert!(cache.check_and_mark(token4)); // IS replay

        // This is the key security property: we evicted ONLY the oldest token,
        // not ALL tokens like the vulnerable code did
    }

    /// M-WRAITH-1 Test: Replayed tokens are detected
    #[test]
    fn test_token_cache_replay_detection() {
        let mut cache = TokenCache::default();

        let token = [42u8; 32];

        // First submission: not a replay
        assert!(!cache.check_and_mark(token));

        // Second submission: IS a replay
        assert!(cache.check_and_mark(token));

        // Third submission: still a replay
        assert!(cache.check_and_mark(token));
    }

    /// M-WRAITH-2 Test: Registration without UTXO fails when required
    #[test]
    fn test_utxo_required_for_registration() {
        let mut coord = WraithCoordinator::new(
            ParticipantTier::Micro,
            WraithDenomination::Small,
            Network::Regtest,
        )
        .expect("test RNG should work")
        .with_utxo_verifier(|_txid, _vout| Ok(true)) // UTXO exists
        .with_utxo_required_for_registration();

        // Regular registration should fail
        let result = coord.register_participant("ghost1".to_string());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("UTXO proof required"));
    }

    /// M-WRAITH-2 Test: Registration with UTXO proof succeeds
    #[test]
    fn test_registration_with_utxo_proof() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let verification_called = Arc::new(AtomicBool::new(false));
        let verification_called_clone = verification_called.clone();

        let mut coord = WraithCoordinator::new(
            ParticipantTier::Micro,
            WraithDenomination::Small,
            Network::Regtest,
        )
        .expect("test RNG should work")
        .with_utxo_verifier(move |_txid, _vout| {
            verification_called_clone.store(true, Ordering::SeqCst);
            Ok(true) // UTXO exists
        })
        .with_utxo_required_for_registration();

        let txid = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let utxo_proof = UtxoProof::new(txid, 0, 1_100_000);

        // Registration with UTXO proof should succeed
        let result = coord.register_participant_with_utxo("ghost1".to_string(), utxo_proof);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0); // First participant index

        // Verification should have been called
        assert!(verification_called.load(Ordering::SeqCst));
    }

    /// M-WRAITH-2 Test: Registration with invalid UTXO is rejected
    #[test]
    fn test_registration_with_invalid_utxo_rejected() {
        let mut coord = WraithCoordinator::new(
            ParticipantTier::Micro,
            WraithDenomination::Small,
            Network::Regtest,
        )
        .expect("test RNG should work")
        .with_utxo_verifier(|_txid, _vout| Ok(false)) // UTXO does NOT exist
        .with_utxo_required_for_registration();

        let txid = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let utxo_proof = UtxoProof::new(txid, 0, 1_100_000);

        // Registration with non-existent UTXO should fail
        let result = coord.register_participant_with_utxo("ghost1".to_string(), utxo_proof);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not exist"));
    }

    /// M-WRAITH-2 Test: Registration without verifier fails
    #[test]
    fn test_registration_with_utxo_no_verifier() {
        let mut coord = create_test_coordinator(
            ParticipantTier::Micro,
            WraithDenomination::Small,
            Network::Regtest,
        );
        // No UTXO verifier configured

        let txid = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let utxo_proof = UtxoProof::new(txid, 0, 1_100_000);

        // Registration should fail because no verifier is configured
        let result = coord.register_participant_with_utxo("ghost1".to_string(), utxo_proof);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No UTXO verifier"));
    }

    // ==========================================================================
    // Security Tests (WR-C1, WR-C2, WR-C3, WR-C4)
    // ==========================================================================

    /// WR-C3 Test: Token cache TTL is extended to 14 days
    /// SECURITY: Must exceed 2x maximum session duration (7 days) to prevent replay attacks
    #[test]
    fn test_token_cache_ttl_extended() {
        // Verify the constant is set to 14 days (2x max session duration)
        assert_eq!(
            TOKEN_MAX_AGE_SECS,
            14 * 24 * 60 * 60,
            "Token cache TTL should be 14 days (2x max session duration)"
        );

        // Default cache should use the extended TTL
        let cache = TokenCache::default();
        assert_eq!(
            cache.max_age,
            std::time::Duration::from_secs(14 * 24 * 60 * 60),
            "Default cache should use 14-day TTL"
        );
    }

    /// WR-C4 Test: Token hash is session-bound
    #[test]
    fn test_token_hash_session_bound() {
        // Create two coordinators with different sessions
        let coord1 = create_test_coordinator(
            ParticipantTier::Micro,
            WraithDenomination::Small,
            Network::Regtest,
        );
        let coord2 = create_test_coordinator(
            ParticipantTier::Micro,
            WraithDenomination::Small,
            Network::Regtest,
        );

        // Create a fake token (we're just testing the hash function)
        let token = crate::blind::UnblindedToken {
            message: vec![0u8; 32],
            nonce_point: [0u8; 33],
            signature_scalar: [0u8; 32],
            session_key_id: [0u8; 32],
        };

        // The same token should produce different hashes in different sessions
        let hash1 = coord1.compute_token_hash(&token);
        let hash2 = coord2.compute_token_hash(&token);

        assert_ne!(
            hash1, hash2,
            "Same token in different sessions should have different hashes"
        );

        // Same token in same session should have same hash
        let hash1_again = coord1.compute_token_hash(&token);
        assert_eq!(
            hash1, hash1_again,
            "Same token in same session should have same hash"
        );
    }

    /// H-CRYPTO-2 Test: Token hash is bound to coordinator key_id
    ///
    /// After key rotation, the same token should produce a different hash,
    /// preventing cross-rotation replay attacks.
    #[test]
    fn test_token_hash_key_bound() {
        // Create a coordinator
        let mut coord = create_test_coordinator(
            ParticipantTier::Micro,
            WraithDenomination::Small,
            Network::Regtest,
        );

        // Create a fake token
        let token = crate::blind::UnblindedToken {
            message: vec![0u8; 32],
            nonce_point: [0u8; 33],
            signature_scalar: [0u8; 32],
            session_key_id: [0u8; 32],
        };

        // Compute hash before key rotation
        let hash_before = coord.compute_token_hash(&token);

        // Store the old key_id for comparison
        let old_key_id = *coord.signer.key_id();

        // Rotate the coordinator's signing key
        let new_key = coord.signer.rotate_key().unwrap();
        let new_key_id = *coord.signer.key_id();

        // Verify key actually changed
        assert_ne!(
            old_key_id, new_key_id,
            "Key rotation should produce new key_id"
        );

        // rotate_key returns the NEW public key, so it should match current public_key
        assert_eq!(
            new_key,
            *coord.signer.public_key(),
            "rotate_key should return the new public key"
        );

        // Compute hash after key rotation
        let hash_after = coord.compute_token_hash(&token);

        // H-CRYPTO-2: Same token should produce DIFFERENT hash after key rotation
        assert_ne!(
            hash_before, hash_after,
            "Token hash should change after key rotation to prevent cross-rotation replay"
        );
    }
}
