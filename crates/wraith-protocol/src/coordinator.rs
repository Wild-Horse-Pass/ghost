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

use std::collections::HashMap;
use std::sync::Arc;

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
    /// Ghost ID of participant
    pub ghost_id: String,
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
    /// Create new participant
    pub fn new(index: u32, ghost_id: String) -> Self {
        Self {
            index,
            ghost_id,
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

/// Broadcast function type for transaction broadcasting
type BroadcastFn = Arc<dyn Fn(&str) -> Result<String, String> + Send + Sync>;

/// Wraith Coordinator - manages a single session's full lifecycle
pub struct WraithCoordinator {
    /// The underlying session
    session: WraithSession,
    /// Coordinator's blind signer
    signer: CoordinatorSigner,
    /// Registered participants
    participants: HashMap<String, Participant>, // ghost_id -> Participant
    /// Participant order (for deterministic indexing)
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
}

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
            participant_order: Vec::new(),
            network,
            phase1_tx: None,
            phase2_tx: None,
            phase1_outputs: Vec::new(),
            broadcast_fn: None,
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
    pub fn register_participant(&mut self, ghost_id: String) -> Result<u32, WraithError> {
        if !matches!(self.session.state(), SessionState::WaitingForParticipants) {
            return Err(WraithError::InvalidState {
                expected: "WaitingForParticipants".to_string(),
                actual: format!("{:?}", self.session.state()),
            });
        }

        if self.participants.contains_key(&ghost_id) {
            return Err(WraithError::InvalidInput(format!(
                "Participant {} already registered",
                ghost_id
            )));
        }

        let index = self.participants.len() as u32;
        let participant = Participant::new(index, ghost_id.clone());
        self.participants.insert(ghost_id.clone(), participant);
        self.participant_order.push(ghost_id);
        self.session.add_participant();

        Ok(index)
    }

    /// Submit input UTXO for a participant
    pub fn submit_input(&mut self, ghost_id: &str, input: WraithInput) -> Result<(), WraithError> {
        let participant = self.participants.get_mut(ghost_id).ok_or_else(|| {
            WraithError::InvalidInput(format!("Unknown participant: {}", ghost_id))
        })?;

        // Validate input amount
        let expected = self.session.denomination().input_sats();
        if input.amount < expected {
            return Err(WraithError::InvalidInput(format!(
                "Input amount {} too small, need at least {}",
                input.amount, expected
            )));
        }

        participant.input = Some(input);
        Ok(())
    }

    /// Request nonces for blind signing (Step 1 of interactive protocol)
    ///
    /// Participant calls this to get public nonces before creating blinded challenges.
    /// Returns `SPLIT_RATIO` nonces, one for each intermediate output.
    pub fn request_nonces(&mut self, ghost_id: &str) -> Result<Vec<PublicNonce>, WraithError> {
        let participant = self.participants.get_mut(ghost_id).ok_or_else(|| {
            WraithError::InvalidInput(format!("Unknown participant: {}", ghost_id))
        })?;

        // Create nonces for each intermediate output
        let mut nonces = Vec::with_capacity(SPLIT_RATIO);
        for _ in 0..SPLIT_RATIO {
            let nonce = self.signer.create_nonce();
            nonces.push(nonce);
        }

        participant.issued_nonces = nonces.clone();
        Ok(nonces)
    }

    /// Submit blinded challenges for signing (Step 2 of interactive protocol)
    ///
    /// Participant sends blinded challenges after receiving nonces and blinding.
    /// Returns signature responses that the participant can unblind.
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

        // Sign each blinded challenge
        let mut responses = Vec::with_capacity(SPLIT_RATIO);
        for challenge in &challenges {
            let response = self.signer.sign_blinded_challenge(challenge)?;
            responses.push(response);
        }

        let participant = self.participants.get_mut(ghost_id).ok_or_else(|| {
            WraithError::InvalidInput(format!("Unknown participant: {}", ghost_id))
        })?;

        participant.blinded_challenges = challenges;
        participant.signature_responses = responses.clone();

        Ok(responses)
    }

    /// Submit final output address for Phase 2
    pub fn submit_final_address(
        &mut self,
        ghost_id: &str,
        address: String,
    ) -> Result<(), WraithError> {
        let participant = self.participants.get_mut(ghost_id).ok_or_else(|| {
            WraithError::InvalidInput(format!("Unknown participant: {}", ghost_id))
        })?;

        participant.final_address = Some(address);
        Ok(())
    }

    /// Submit unblinded tokens for intermediate addresses (Step 3 of interactive protocol)
    ///
    /// Participants call this after receiving signature responses and unblinding them.
    /// The coordinator verifies each token using standard Schnorr verification.
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
        // Need all participants to have inputs and verified tokens
        self.participants
            .values()
            .all(|p| p.input.is_some() && p.tokens.len() == SPLIT_RATIO)
    }

    /// Build Phase 1 (split) transaction
    pub fn build_phase1(&mut self) -> Result<&SplitTransaction, WraithError> {
        if !self.ready_for_phase1() {
            return Err(WraithError::PhaseError(
                "Not all participants have submitted inputs and verified tokens".to_string(),
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

        // Collect intermediate addresses from verified unblinded tokens
        let mut intermediate_addresses: Vec<Vec<String>> = Vec::new();
        for ghost_id in &self.participant_order {
            let participant = self.participants.get(ghost_id).ok_or_else(|| {
                WraithError::InvalidInput(format!("Missing participant in order: {}", ghost_id))
            })?;
            // Convert each token's message (x-only pubkey bytes) to a P2TR address
            let mut addrs = Vec::with_capacity(SPLIT_RATIO);
            for token in &participant.tokens {
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

        // Safe: we just assigned Some(tx) above
        Ok(self
            .phase1_tx
            .as_ref()
            .expect("phase1_tx was just assigned"))
    }

    /// Record Phase 1 signature from participant
    pub fn add_phase1_signature(&mut self, ghost_id: &str) -> Result<bool, WraithError> {
        let participant = self.participants.get_mut(ghost_id).ok_or_else(|| {
            WraithError::InvalidInput(format!("Unknown participant: {}", ghost_id))
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

        for (p_idx, _ghost_id) in self.participant_order.iter().enumerate() {
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
            .map(|ghost_id| {
                self.participants
                    .get(ghost_id)
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
        let participant = self.participants.get_mut(ghost_id).ok_or_else(|| {
            WraithError::InvalidInput(format!("Unknown participant: {}", ghost_id))
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

        Ok(txid_str)
    }

    /// Confirm Phase 2 on-chain (completes the session)
    pub fn confirm_phase2(&mut self, block_height: u32) -> Result<(), WraithError> {
        self.session.confirm_phase2(block_height)
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
                let missing_sigs: Vec<String> = self
                    .participants
                    .iter()
                    .filter(|(_, p)| !p.phase1_signed)
                    .map(|(id, _)| id.clone())
                    .collect();
                self.session.fail();
                Ok(TimeoutAction::Failed {
                    phase: 1,
                    reason: format!(
                        "Phase 1 timed out, {} participant(s) didn't sign",
                        missing_sigs.len()
                    ),
                    stuck_funds: self.calculate_stuck_funds(),
                })
            }
            SessionState::ExecutingPhase2 | SessionState::WaitingPhase2Confirmation => {
                // Phase 2 failed - intermediate UTXOs may be stuck
                let missing_sigs: Vec<String> = self
                    .participants
                    .iter()
                    .filter(|(_, p)| !p.phase2_signed)
                    .map(|(id, _)| id.clone())
                    .collect();
                self.session.fail();
                Ok(TimeoutAction::Failed {
                    phase: 2,
                    reason: format!(
                        "Phase 2 timed out, {} participant(s) didn't sign",
                        missing_sigs.len()
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

            // Sever Ghost ID linkage (the key privacy protection)
            participant.ghost_id = String::new();

            // Clear final address (links session to output)
            participant.final_address = None;
        }

        // Clear transaction outputs that could be used to trace
        self.phase1_outputs.clear();

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
}
