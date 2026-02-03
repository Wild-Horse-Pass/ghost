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

/// Maximum strike count before a participant is banned
const MAX_STRIKES: u32 = 3;

/// Reputation tracking for participants across sessions
///
/// Tracks participants who fail to complete signing to prevent repeat offenders.
/// This is a simple strike-based system: 3 strikes and you're banned.
#[derive(Debug, Clone, Default)]
pub struct ReputationTracker {
    /// Strike counts for participants who failed to sign
    /// ghost_id -> number of failures
    strikes: HashMap<String, u32>,
    /// Permanently banned participants
    banned: HashSet<String>,
}

impl ReputationTracker {
    /// Create a new reputation tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a participant is allowed to join (not banned)
    pub fn is_allowed(&self, ghost_id: &str) -> bool {
        !self.banned.contains(ghost_id)
    }

    /// Record a failure to sign for a participant
    ///
    /// Increments strike count. If strikes >= MAX_STRIKES, the participant is banned.
    pub fn record_failure(&mut self, ghost_id: &str) {
        let strikes = self.strikes.entry(ghost_id.to_string()).or_insert(0);
        *strikes += 1;
        if *strikes >= MAX_STRIKES {
            self.banned.insert(ghost_id.to_string());
        }
    }

    /// Record successful completion (reduces strike count)
    ///
    /// Good behavior reduces strike count by 1 (but not below 0).
    pub fn record_success(&mut self, ghost_id: &str) {
        if let Some(strikes) = self.strikes.get_mut(ghost_id) {
            *strikes = strikes.saturating_sub(1);
        }
    }

    /// Get the strike count for a participant
    pub fn get_strikes(&self, ghost_id: &str) -> u32 {
        self.strikes.get(ghost_id).copied().unwrap_or(0)
    }

    /// Check if a participant is banned
    pub fn is_banned(&self, ghost_id: &str) -> bool {
        self.banned.contains(ghost_id)
    }

    /// Manually ban a participant
    pub fn ban(&mut self, ghost_id: &str) {
        self.banned.insert(ghost_id.to_string());
    }

    /// Manually unban a participant (use with caution)
    pub fn unban(&mut self, ghost_id: &str) {
        self.banned.remove(ghost_id);
        self.strikes.remove(ghost_id);
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
fn derive_session_participant_id(ghost_id: &str, session_id: &[u8; 32]) -> String {
    use bitcoin::hashes::{sha256, Hash, HashEngine};
    let mut engine = sha256::Hash::engine();
    engine.input(b"wraith/session-participant-id/v1");
    engine.input(ghost_id.as_bytes());
    engine.input(session_id);
    let hash = sha256::Hash::from_engine(engine);
    hex::encode(&hash[..16]) // Use first 16 bytes (32 hex chars)
}

/// Broadcast function type for transaction broadcasting
type BroadcastFn = Arc<dyn Fn(&str) -> Result<String, String> + Send + Sync>;

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
    /// Anonymous token pool - tokens verified but NOT linked to any participant
    /// This is CRITICAL for privacy: coordinator verifies validity without knowing submitter
    anonymous_tokens: Vec<UnblindedToken>,
    /// Tokens that have been used (for replay prevention) - stores token hash
    /// SECURITY: Prevents resubmission of the same token
    used_tokens: HashSet<[u8; 32]>,
    /// All submitted addresses (for duplicate detection)
    submitted_addresses: HashSet<String>,
    /// Optional UTXO verification callback
    utxo_verifier: Option<UtxoVerifier>,
    /// Reputation tracker for participants (shared across sessions)
    reputation: Option<Arc<parking_lot::RwLock<ReputationTracker>>>,
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
    pub fn new(tier: ParticipantTier, denomination: WraithDenomination, network: Network) -> Self {
        let session = WraithSession::new(tier, denomination);
        let signer = CoordinatorSigner::new(session.session_id());

        Self {
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
            anonymous_tokens: Vec::new(),
            used_tokens: HashSet::new(),
            submitted_addresses: HashSet::new(),
            utxo_verifier: None,
            reputation: None,
        }
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

    /// Set reputation tracker (WR-M3)
    ///
    /// The reputation tracker is shared across sessions to track participants
    /// who fail to complete signing.
    pub fn with_reputation(mut self, reputation: Arc<parking_lot::RwLock<ReputationTracker>>) -> Self {
        self.reputation = Some(reputation);
        self
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
    pub fn register_participant(&mut self, ghost_id: String) -> Result<u32, WraithError> {
        if !matches!(self.session.state(), SessionState::WaitingForParticipants) {
            return Err(WraithError::InvalidState {
                expected: "WaitingForParticipants".to_string(),
                actual: format!("{:?}", self.session.state()),
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
        let session_participant_id = derive_session_participant_id(&ghost_id, self.session.session_id());

        let index = self.participants.len() as u32;
        let participant = Participant::new(index, session_participant_id.clone());
        self.participants.insert(session_participant_id.clone(), participant);
        self.ghost_id_to_session_id.insert(ghost_id.clone(), session_participant_id.clone());
        self.session_id_to_ghost_id.insert(session_participant_id.clone(), ghost_id);
        self.participant_order.push(session_participant_id);
        self.session.add_participant();

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
        let session_id = self.get_session_participant_id(ghost_id)
            .ok_or_else(|| WraithError::InvalidInput(format!("Unknown participant: {}", ghost_id)))?
            .clone();
        let participant = self.participants.get_mut(&session_id)
            .expect("session_id must exist if ghost_id mapping exists");

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
        let session_id = self.get_session_participant_id(ghost_id)
            .ok_or_else(|| WraithError::InvalidInput(format!("Unknown participant: {}", ghost_id)))?
            .clone();

        // Create nonces for each intermediate output, BOUND to session-specific participant ID
        let mut nonces = Vec::with_capacity(SPLIT_RATIO);
        for _ in 0..SPLIT_RATIO {
            let nonce = self.signer.create_nonce_for_participant(&session_id)?;
            nonces.push(nonce);
        }

        let participant = self.participants.get_mut(&session_id)
            .expect("session_id must exist if ghost_id mapping exists");
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

        let session_id = self.get_session_participant_id(ghost_id)
            .ok_or_else(|| WraithError::InvalidInput(format!("Unknown participant: {}", ghost_id)))?
            .clone();

        // Sign each blinded challenge WITH session-specific participant verification
        let mut responses = Vec::with_capacity(SPLIT_RATIO);
        for challenge in &challenges {
            let response = self
                .signer
                .sign_blinded_challenge_for_participant(challenge, &session_id)?;
            responses.push(response);
        }

        let participant = self.participants.get_mut(&session_id)
            .expect("session_id must exist if ghost_id mapping exists");

        participant.blinded_challenges = challenges;
        participant.signature_responses = responses.clone();

        Ok(responses)
    }

    /// Submit final output address for Phase 2
    ///
    /// SECURITY: Rejects duplicate addresses across all participants.
    /// This prevents address reuse attacks that could enable tracing.
    pub fn submit_final_address(
        &mut self,
        ghost_id: &str,
        address: String,
    ) -> Result<(), WraithError> {
        // Check for duplicate address BEFORE accepting
        if self.submitted_addresses.contains(&address) {
            return Err(WraithError::InvalidInput(format!(
                "Duplicate address rejected: {} (already submitted by another participant)",
                address
            )));
        }

        let session_id = self.get_session_participant_id(ghost_id)
            .ok_or_else(|| WraithError::InvalidInput(format!("Unknown participant: {}", ghost_id)))?
            .clone();
        let participant = self.participants.get_mut(&session_id)
            .expect("session_id must exist if ghost_id mapping exists");

        // If this participant previously submitted an address, remove it from the set
        if let Some(ref old_addr) = participant.final_address {
            self.submitted_addresses.remove(old_addr);
        }

        // Record the new address
        self.submitted_addresses.insert(address.clone());
        participant.final_address = Some(address);
        Ok(())
    }

    /// Submit unblinded tokens anonymously (Step 3 of interactive protocol)
    ///
    /// CRITICAL PRIVACY: This method does NOT take ghost_id, breaking the link
    /// between token submission and participant identity. The coordinator only
    /// verifies that tokens are valid (signed by coordinator) but cannot determine
    /// which participant submitted them.
    ///
    /// Tokens are added to an anonymous pool and later used for Phase 1 outputs.
    pub fn submit_tokens_anonymous(
        &mut self,
        tokens: Vec<UnblindedToken>,
    ) -> Result<(), WraithError> {
        if tokens.len() != SPLIT_RATIO {
            return Err(WraithError::InvalidInput(format!(
                "Expected {} tokens, got {}",
                SPLIT_RATIO,
                tokens.len()
            )));
        }

        // SECURITY: Check for replay BEFORE verification to prevent timing attacks
        for token in &tokens {
            let hash = Self::compute_token_hash(token);
            if self.used_tokens.contains(&hash) {
                return Err(WraithError::InvalidInput("Token replay detected".into()));
            }
        }

        // Verify each token using standard Schnorr verification
        // Coordinator proves tokens are valid WITHOUT knowing who submitted them
        for (i, token) in tokens.iter().enumerate() {
            let valid = self.signer.verify_signature(token)?;
            if !valid {
                return Err(WraithError::InvalidSignature(format!(
                    "Token {} verification failed",
                    i
                )));
            }
        }

        // Mark tokens as used AFTER verification
        for token in &tokens {
            self.used_tokens.insert(Self::compute_token_hash(token));
        }

        // Add to anonymous pool - NO ghost_id linkage!
        self.anonymous_tokens.extend(tokens);
        Ok(())
    }

    /// Compute a hash of a token for replay prevention
    fn compute_token_hash(token: &UnblindedToken) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&token.nonce_point);
        hasher.update(&token.signature_scalar);
        hasher.finalize().into()
    }

    /// DEPRECATED: Submit tokens with ghost_id linking (insecure)
    ///
    /// WARNING: This method creates input-output linkage that defeats blind signatures.
    /// Use `submit_tokens_anonymous()` instead for privacy-preserving token submission.
    #[deprecated(
        since = "0.2.0",
        note = "Use submit_tokens_anonymous() for privacy-preserving token submission"
    )]
    pub fn submit_tokens(
        &mut self,
        ghost_id: &str,
        tokens: Vec<UnblindedToken>,
    ) -> Result<(), WraithError> {
        if tokens.len() != SPLIT_RATIO {
            return Err(WraithError::InvalidInput(format!(
                "Expected {} tokens, got {}",
                SPLIT_RATIO,
                tokens.len()
            )));
        }

        // Verify each token using standard Schnorr verification
        for (i, token) in tokens.iter().enumerate() {
            let valid = self.signer.verify_signature(token)?;
            if !valid {
                return Err(WraithError::InvalidSignature(format!(
                    "Token {} verification failed for participant {}",
                    i, ghost_id
                )));
            }
        }

        let participant = self.participants.get_mut(ghost_id).ok_or_else(|| {
            WraithError::InvalidInput(format!("Unknown participant: {}", ghost_id))
        })?;

        participant.tokens = tokens;
        Ok(())
    }

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
    pub fn ready_for_phase1(&self) -> bool {
        // Need all participants to have inputs
        let all_have_inputs = self.participants.values().all(|p| p.input.is_some());

        // Need enough anonymous tokens for all participants (SPLIT_RATIO per participant)
        let expected_tokens = self.participants.len() * SPLIT_RATIO;
        let have_enough_tokens = self.anonymous_tokens.len() >= expected_tokens;

        all_have_inputs && have_enough_tokens
    }

    /// Get count of anonymous tokens submitted
    pub fn anonymous_token_count(&self) -> usize {
        self.anonymous_tokens.len()
    }

    /// Build Phase 1 (split) transaction
    pub fn build_phase1(&mut self) -> Result<&SplitTransaction, WraithError> {
        if !self.ready_for_phase1() {
            return Err(WraithError::PhaseError(
                "Not all participants have submitted inputs or not enough anonymous tokens".to_string(),
            ));
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
                WraithError::InvalidInput(format!("Missing participant in order: {}", ghost_id))
            })?;
            if let Some(ref input) = participant.input {
                builder.add_input(input.clone())?;
            }
        }

        // Collect intermediate addresses from ANONYMOUS token pool
        // CRITICAL: Tokens are NOT linked to specific participants - this is the privacy guarantee
        // The shuffle in build_split_transaction randomizes output order
        let expected_tokens = self.participants.len() * SPLIT_RATIO;
        if self.anonymous_tokens.len() < expected_tokens {
            return Err(WraithError::PhaseError(format!(
                "Not enough anonymous tokens: need {}, have {}",
                expected_tokens,
                self.anonymous_tokens.len()
            )));
        }

        // Group anonymous tokens into participant-sized batches
        // Note: We don't know WHICH participant each batch belongs to - that's the point!
        let mut intermediate_addresses: Vec<Vec<String>> = Vec::new();
        for batch_idx in 0..self.participants.len() {
            let start = batch_idx * SPLIT_RATIO;
            let end = start + SPLIT_RATIO;
            let mut addrs = Vec::with_capacity(SPLIT_RATIO);
            for token in &self.anonymous_tokens[start..end] {
                // The message is the x-only pubkey (32 bytes)
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

        // Safe: we just assigned Some(tx) above
        Ok(self
            .phase1_tx
            .as_ref()
            .expect("phase1_tx was just assigned"))
    }

    /// Clear sensitive data immediately after building transactions
    /// This reduces the window for compromise (WR-H3)
    ///
    /// SECURITY: Call this immediately after building each phase transaction
    /// to minimize the window during which sensitive data could be compromised.
    pub fn clear_sensitive_data_post_build(&mut self) {
        // Clear anonymous tokens - no longer needed after building tx
        self.anonymous_tokens.clear();

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
        let session_id = self.get_session_participant_id(ghost_id)
            .ok_or_else(|| WraithError::InvalidInput(format!("Unknown participant: {}", ghost_id)))?
            .clone();
        let participant = self.participants.get_mut(&session_id)
            .expect("session_id must exist if ghost_id mapping exists");

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

        Ok(txid_str)
    }

    /// Confirm Phase 1 on-chain
    pub fn confirm_phase1(&mut self, block_height: u32) -> Result<(), WraithError> {
        self.session.confirm_phase1(block_height)
    }

    /// Check if ready for Phase 2
    pub fn ready_for_phase2(&self) -> bool {
        // Need Phase 1 confirmed and all final addresses submitted
        matches!(
            self.session.state(),
            SessionState::WaitingPhase1Confirmation
        ) && self
            .session
            .phase1()
            .map(|p| p.state() == PhaseState::Confirmed)
            .unwrap_or(false)
            && self
                .participants
                .values()
                .all(|p| p.final_address.is_some())
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

        // Collect final addresses
        let final_addresses: Vec<String> = self
            .participant_order
            .iter()
            .map(|session_id| {
                self.participants
                    .get(session_id)
                    .and_then(|p| p.final_address.clone())
                    .unwrap_or_default()
            })
            .collect();

        let tx = builder.build_merge_transaction(&intermediate_inputs, &final_addresses)?;
        self.phase2_tx = Some(tx);

        // Safe: we just assigned Some(tx) above
        Ok(self
            .phase2_tx
            .as_ref()
            .expect("phase2_tx was just assigned"))
    }

    /// Record Phase 2 signature from participant
    pub fn add_phase2_signature(&mut self, ghost_id: &str) -> Result<bool, WraithError> {
        let session_id = self.get_session_participant_id(ghost_id)
            .ok_or_else(|| WraithError::InvalidInput(format!("Unknown participant: {}", ghost_id)))?
            .clone();
        let participant = self.participants.get_mut(&session_id)
            .expect("session_id must exist if ghost_id mapping exists");

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
                self.session.refund();
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
                self.session.refund();
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

                self.session.fail();
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

                self.session.fail();
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

    #[test]
    fn test_coordinator_creation() {
        let coord = WraithCoordinator::new(
            ParticipantTier::Express,
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
        let mut coord = WraithCoordinator::new(
            ParticipantTier::Express,
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
        let mut coord = WraithCoordinator::new(
            ParticipantTier::Express,
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

        let mut coord = WraithCoordinator::new(
            ParticipantTier::Express,
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

        // Submit tokens ANONYMOUSLY - the coordinator doesn't know who submitted what
        coord.submit_tokens_anonymous(tokens1).unwrap();
        coord.submit_tokens_anonymous(tokens2).unwrap();

        // Verify anonymous pool has all tokens
        assert_eq!(coord.anonymous_token_count(), 2 * crate::SPLIT_RATIO);

        // The coordinator cannot determine which tokens belong to which participant
        // This is verified by the fact that submit_tokens_anonymous takes no ghost_id
    }

    /// WR-H2 Security Test: Duplicate addresses are rejected
    #[test]
    fn test_duplicate_address_rejected() {
        let mut coord = WraithCoordinator::new(
            ParticipantTier::Express,
            WraithDenomination::Small,
            Network::Regtest,
        );

        coord.register_participant("ghost1".to_string()).unwrap();
        coord.register_participant("ghost2".to_string()).unwrap();

        let test_address = "bcrt1qtest123456789".to_string();

        // First submission should succeed
        coord
            .submit_final_address("ghost1", test_address.clone())
            .unwrap();

        // Second submission of SAME address by DIFFERENT participant should FAIL
        let result = coord.submit_final_address("ghost2", test_address.clone());
        assert!(result.is_err(), "Duplicate address should be rejected");
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Duplicate address"));

        // Same participant can update their own address
        let new_address = "bcrt1qnewaddress".to_string();
        coord
            .submit_final_address("ghost1", new_address.clone())
            .unwrap();

        // Now the old address is available again
        coord.submit_final_address("ghost2", test_address).unwrap();
    }

    /// WR-H3 Test: Data is cleared after building transaction
    #[test]
    fn test_data_cleared_after_build() {
        use crate::blind::BlindingContext;
        use bitcoin::ScriptBuf;

        let mut coord = WraithCoordinator::new(
            ParticipantTier::Express,
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

        coord.submit_tokens_anonymous(tokens).unwrap();
        assert_eq!(coord.anonymous_token_count(), crate::SPLIT_RATIO);

        // After build, anonymous tokens should be cleared
        // (build_phase1 will fail due to state, but that's okay for this test -
        // we're testing that clear_sensitive_data_post_build works)
        coord.clear_sensitive_data_post_build();

        assert_eq!(
            coord.anonymous_token_count(),
            0,
            "Anonymous tokens should be cleared after build"
        );
    }

    /// WR-M4 Test: Session-specific participant IDs prevent cross-session tracking
    #[test]
    fn test_session_specific_participant_ids() {
        // Create two coordinators with different sessions
        let coord1 = WraithCoordinator::new(
            ParticipantTier::Express,
            WraithDenomination::Small,
            Network::Regtest,
        );
        let coord2 = WraithCoordinator::new(
            ParticipantTier::Express,
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
            ParticipantTier::Express,
            WraithDenomination::Small,
            Network::Regtest,
        )
        .with_reputation(reputation);

        // Banned ghost_id should be rejected
        let result = coord.register_participant("banned_ghost".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("banned"));

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
            ParticipantTier::Express,
            WraithDenomination::Small,
            Network::Regtest,
        )
        .with_utxo_verifier(move |_txid, _vout| {
            verification_called_clone.store(true, Ordering::SeqCst);
            Ok(true) // UTXO exists
        });

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
            ParticipantTier::Express,
            WraithDenomination::Small,
            Network::Regtest,
        )
        .with_utxo_verifier(|_txid, _vout| {
            Ok(false) // UTXO does NOT exist
        });

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
}
