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
//| FILE: blind.rs                                                                                                       |
//|======================================================================================================================|

//! Blind Signature System for Wraith Protocol
//!
//! Implements proper Schnorr blind signatures to ensure the coordinator
//! cannot link participants to their output addresses.
//!
//! # Protocol Flow (Interactive)
//!
//! 1. Coordinator generates nonce R = k*G and sends to participant
//! 2. Participant blinds: R' = R + α*G + β*X, computes c = H(X, R', m), c' = c + β
//! 3. Participant sends blinded challenge c' to coordinator
//! 4. Coordinator signs: s = k + c'*x
//! 5. Participant unblinds: s' = s + α
//! 6. Result: (R', s') is valid Schnorr signature on m, coordinator cannot link
//!
//! # Security Properties
//!
//! - **Blindness**: Coordinator cannot determine which message it signed
//! - **Unforgeability**: Only coordinator can produce valid signatures (DLOG + ROM)
//! - **Unlinkability**: No way to link blind signature request to unblinded signature
//!
//! # References
//!
//! - Schnorr blind signatures: https://eprint.iacr.org/2019/877
//! - Interactive demo: https://blindsigs.utxo.club/

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::WraithError;

/// Generate random 32 bytes for key material
fn random_bytes_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Generate a random secret key
fn random_secret_key() -> SecretKey {
    loop {
        let bytes = random_bytes_32();
        if let Ok(sk) = SecretKey::from_slice(&bytes) {
            return sk;
        }
    }
}

// Custom serde for [u8; 33] using hex encoding
mod bytes33_hex {
    use super::*;

    pub fn serialize<S>(data: &[u8; 33], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(data))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 33], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 33 bytes"))
    }
}

// Custom serde for [u8; 64] using hex encoding
#[allow(dead_code)]
mod bytes64_hex {
    use super::*;

    pub fn serialize<S>(data: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(data))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

/// Compute BIP-340 style tagged hash
fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag);
    let mut engine = sha256::Hash::engine();
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);
    engine.input(data);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// Compute the Schnorr challenge: c = H(X || R' || m)
fn compute_challenge(pubkey: &PublicKey, nonce_point: &PublicKey, message: &[u8]) -> [u8; 32] {
    let x_only = pubkey.x_only_public_key().0;
    let r_only = nonce_point.x_only_public_key().0;

    let mut data = Vec::with_capacity(32 + 32 + message.len());
    data.extend_from_slice(&r_only.serialize());
    data.extend_from_slice(&x_only.serialize());
    data.extend_from_slice(message);

    tagged_hash(b"BIP0340/challenge", &data)
}

// ============================================================================
// Coordinator (Signer) Side
// ============================================================================

/// A signing session nonce created by the coordinator
///
/// The coordinator must keep track of (k, R) for each signing session.
/// This is sent to participants who want to obtain a blind signature.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SigningNonce {
    /// The secret nonce scalar (must be kept secret!)
    secret_nonce: SecretKey,
    /// The public nonce point R = k*G
    pub public_nonce: PublicKey,
    /// Session identifier (includes ghost_id for binding)
    pub session_id: [u8; 32],
    /// Ghost ID of the participant this nonce was issued to (for verification)
    pub bound_ghost_id: Option<String>,
}

/// Public nonce sent to participants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicNonce {
    /// R = k*G (compressed point)
    #[serde(with = "bytes33_hex")]
    pub nonce_point: [u8; 33],
    /// Session identifier
    pub session_id: [u8; 32],
}

/// Blinded challenge sent from participant to coordinator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedChallenge {
    /// The blinded challenge c' = c + β (mod n)
    pub challenge: [u8; 32],
    /// Session identifier (to match with nonce)
    pub session_id: [u8; 32],
}

/// Blind signature response from coordinator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindSignatureResponse {
    /// s = k + c'*x (mod n)
    pub signature_scalar: [u8; 32],
    /// Session identifier
    pub session_id: [u8; 32],
}

/// Coordinator's signing key for a Wraith session
///
/// Each session has a unique signing key. The coordinator uses this to
/// sign blinded challenges without learning the actual messages.
pub struct CoordinatorSigner {
    /// Session-specific signing key (x)
    signing_key: SecretKey,
    /// Public key (X = x*G) for verification
    public_key: PublicKey,
    /// Session key identifier
    key_id: [u8; 32],
    /// Active signing nonces (indexed by session_id)
    active_nonces: std::collections::HashMap<[u8; 32], SigningNonce>,
}

impl std::fmt::Debug for CoordinatorSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoordinatorSigner")
            .field("key_id", &hex::encode(self.key_id))
            .field("active_nonces", &self.active_nonces.len())
            .finish_non_exhaustive()
    }
}

impl CoordinatorSigner {
    /// Create a new coordinator signer for a session
    pub fn new(session_id: &[u8; 32]) -> Self {
        let secp = Secp256k1::new();

        // Generate session-specific signing key
        let signing_key = random_secret_key();
        let public_key = PublicKey::from_secret_key(&secp, &signing_key);

        // Key ID is hash of session_id and public key
        let mut engine = sha256::Hash::engine();
        engine.input(b"wraith/key-id/v1");
        engine.input(session_id);
        engine.input(&public_key.serialize());
        let key_id = sha256::Hash::from_engine(engine).to_byte_array();

        Self {
            signing_key,
            public_key,
            key_id,
            active_nonces: std::collections::HashMap::new(),
        }
    }

    /// Create from existing key bytes (for restoration)
    pub fn from_bytes(key_bytes: &[u8; 32], session_id: &[u8; 32]) -> Result<Self, WraithError> {
        let secp = Secp256k1::new();

        let signing_key = SecretKey::from_slice(key_bytes)
            .map_err(|e| WraithError::MissingData(format!("Invalid key: {}", e)))?;
        let public_key = PublicKey::from_secret_key(&secp, &signing_key);

        let mut engine = sha256::Hash::engine();
        engine.input(b"wraith/key-id/v1");
        engine.input(session_id);
        engine.input(&public_key.serialize());
        let key_id = sha256::Hash::from_engine(engine).to_byte_array();

        Ok(Self {
            signing_key,
            public_key,
            key_id,
            active_nonces: std::collections::HashMap::new(),
        })
    }

    /// Get the key ID for this session signer
    pub fn key_id(&self) -> &[u8; 32] {
        &self.key_id
    }

    /// Get the public key for verification
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Step 1: Create a new signing nonce bound to a specific participant
    ///
    /// Returns a public nonce that should be sent to the participant.
    /// The coordinator must keep track of this nonce until signing completes.
    ///
    /// SECURITY: The ghost_id is included in session_id generation to bind
    /// the nonce to the requesting participant. This prevents nonce hijacking
    /// where a malicious participant uses another's nonce.
    pub fn create_nonce_for_participant(&mut self, ghost_id: &str) -> PublicNonce {
        let secp = Secp256k1::new();

        // Generate random nonce k
        let secret_nonce = random_secret_key();
        let public_nonce = PublicKey::from_secret_key(&secp, &secret_nonce);

        // Create unique session ID for this nonce INCLUDING ghost_id binding
        let mut engine = sha256::Hash::engine();
        engine.input(b"wraith/nonce-session/v2"); // v2 includes ghost_id
        engine.input(&public_nonce.serialize());
        engine.input(ghost_id.as_bytes()); // Bind to participant
        engine.input(&random_bytes_32());
        let session_id = sha256::Hash::from_engine(engine).to_byte_array();

        let nonce = SigningNonce {
            secret_nonce,
            public_nonce,
            session_id,
            bound_ghost_id: Some(ghost_id.to_string()),
        };

        let public = PublicNonce {
            nonce_point: public_nonce.serialize(),
            session_id,
        };

        self.active_nonces.insert(session_id, nonce);

        public
    }

    /// Create a new signing nonce (unbound - DEPRECATED)
    ///
    /// WARNING: This creates an unbound nonce that can be used by any participant.
    /// Use `create_nonce_for_participant()` for proper security.
    #[deprecated(
        since = "0.2.0",
        note = "Use create_nonce_for_participant() to bind nonces to participants"
    )]
    pub fn create_nonce(&mut self) -> PublicNonce {
        let secp = Secp256k1::new();

        // Generate random nonce k
        let secret_nonce = random_secret_key();
        let public_nonce = PublicKey::from_secret_key(&secp, &secret_nonce);

        // Create unique session ID for this nonce (unbound - insecure)
        let mut engine = sha256::Hash::engine();
        engine.input(b"wraith/nonce-session/v1");
        engine.input(&public_nonce.serialize());
        engine.input(&random_bytes_32());
        let session_id = sha256::Hash::from_engine(engine).to_byte_array();

        let nonce = SigningNonce {
            secret_nonce,
            public_nonce,
            session_id,
            bound_ghost_id: None, // Unbound - INSECURE
        };

        let public = PublicNonce {
            nonce_point: public_nonce.serialize(),
            session_id,
        };

        self.active_nonces.insert(session_id, nonce);

        public
    }

    /// Step 2: Sign a blinded challenge with participant verification
    ///
    /// Computes s = k + c'*x where k is the secret nonce and x is the signing key.
    /// The nonce is consumed (removed) after signing to prevent reuse.
    ///
    /// SECURITY: Verifies that the requestor matches the ghost_id bound to the nonce.
    /// This prevents nonce hijacking attacks.
    pub fn sign_blinded_challenge_for_participant(
        &mut self,
        challenge: &BlindedChallenge,
        requesting_ghost_id: &str,
    ) -> Result<BlindSignatureResponse, WraithError> {
        // Look up the nonce first to verify binding BEFORE removing
        let nonce = self
            .active_nonces
            .get(&challenge.session_id)
            .ok_or_else(|| WraithError::MissingData("Unknown or expired nonce session".into()))?;

        // Verify requestor matches the bound ghost_id
        if let Some(ref bound_id) = nonce.bound_ghost_id {
            if bound_id != requesting_ghost_id {
                return Err(WraithError::InvalidSignature(format!(
                    "Nonce bound to '{}' but requested by '{}'",
                    bound_id, requesting_ghost_id
                )));
            }
        }
        // Note: If nonce is unbound (from deprecated create_nonce), we allow it for backwards compat

        // Now remove the nonce (single use!)
        let nonce = self
            .active_nonces
            .remove(&challenge.session_id)
            .expect("nonce exists - we just checked");

        // Parse challenge as scalar
        let c_prime = SecretKey::from_slice(&challenge.challenge)
            .map_err(|e| WraithError::InvalidSignature(format!("Invalid challenge: {}", e)))?;

        // Compute s = k + c'*x
        let c_prime_scalar = Scalar::from(c_prime);
        let cx = self
            .signing_key
            .mul_tweak(&c_prime_scalar)
            .map_err(|e| WraithError::PhaseError(format!("Scalar multiply failed: {}", e)))?;

        let s = nonce
            .secret_nonce
            .add_tweak(&Scalar::from(cx))
            .map_err(|e| WraithError::PhaseError(format!("Scalar add failed: {}", e)))?;

        Ok(BlindSignatureResponse {
            signature_scalar: s.secret_bytes(),
            session_id: challenge.session_id,
        })
    }

    /// Sign a blinded challenge (unverified - DEPRECATED)
    ///
    /// WARNING: This does not verify the requestor matches the nonce binding.
    /// Use `sign_blinded_challenge_for_participant()` for proper security.
    #[deprecated(
        since = "0.2.0",
        note = "Use sign_blinded_challenge_for_participant() to verify requestor"
    )]
    pub fn sign_blinded_challenge(
        &mut self,
        challenge: &BlindedChallenge,
    ) -> Result<BlindSignatureResponse, WraithError> {
        // Look up and remove the nonce (single use!)
        let nonce = self
            .active_nonces
            .remove(&challenge.session_id)
            .ok_or_else(|| WraithError::MissingData("Unknown or expired nonce session".into()))?;

        // Parse challenge as scalar
        let c_prime = SecretKey::from_slice(&challenge.challenge)
            .map_err(|e| WraithError::InvalidSignature(format!("Invalid challenge: {}", e)))?;

        // Compute s = k + c'*x
        let c_prime_scalar = Scalar::from(c_prime);
        let cx = self
            .signing_key
            .mul_tweak(&c_prime_scalar)
            .map_err(|e| WraithError::PhaseError(format!("Scalar multiply failed: {}", e)))?;

        let s = nonce
            .secret_nonce
            .add_tweak(&Scalar::from(cx))
            .map_err(|e| WraithError::PhaseError(format!("Scalar add failed: {}", e)))?;

        Ok(BlindSignatureResponse {
            signature_scalar: s.secret_bytes(),
            session_id: challenge.session_id,
        })
    }

    /// Verify a final unblinded signature
    ///
    /// This is standard Schnorr verification: s'*G = R' + c*X
    pub fn verify_signature(&self, token: &UnblindedToken) -> Result<bool, WraithError> {
        let secp = Secp256k1::new();

        // Check key ID
        if token.session_key_id != self.key_id {
            return Ok(false);
        }

        // Parse signature components
        let r_prime = PublicKey::from_slice(&token.nonce_point)
            .map_err(|e| WraithError::InvalidSignature(format!("Invalid nonce point: {}", e)))?;

        let s_prime = SecretKey::from_slice(&token.signature_scalar).map_err(|e| {
            WraithError::InvalidSignature(format!("Invalid signature scalar: {}", e))
        })?;

        // Compute challenge c = H(X || R' || m)
        let challenge = compute_challenge(&self.public_key, &r_prime, &token.message);

        // Verify: s'*G == R' + c*X
        // Equivalent to: s'*G - c*X == R'
        let s_g = PublicKey::from_secret_key(&secp, &s_prime);

        let c_scalar = SecretKey::from_slice(&challenge)
            .map_err(|e| WraithError::InvalidSignature(format!("Invalid challenge: {}", e)))?;

        // Compute c*X
        let c_x = self
            .public_key
            .mul_tweak(&secp, &Scalar::from(c_scalar))
            .map_err(|e| WraithError::PhaseError(format!("Point multiply failed: {}", e)))?;

        // Compute R' + c*X
        let expected = r_prime
            .combine(&c_x)
            .map_err(|e| WraithError::PhaseError(format!("Point add failed: {}", e)))?;

        Ok(s_g == expected)
    }

    /// Get count of active nonces (for monitoring)
    pub fn active_nonce_count(&self) -> usize {
        self.active_nonces.len()
    }

    /// Clear expired nonces (call periodically)
    pub fn clear_nonces(&mut self) {
        self.active_nonces.clear();
    }
}

// ============================================================================
// Participant (User) Side
// ============================================================================

/// Context for blinding a message and obtaining a blind signature
///
/// Stores the blinding factors needed to unblind the signature.
/// Must be kept secret by the participant until unblinding is complete.
#[derive(Clone)]
#[allow(dead_code)]
pub struct BlindingContext {
    /// Random blinding scalar α (alpha)
    alpha: SecretKey,
    /// Random blinding scalar β (beta)
    beta: SecretKey,
    /// The original message being signed
    message: Vec<u8>,
    /// The coordinator's public key X
    coordinator_pubkey: PublicKey,
    /// The original nonce R from coordinator
    original_nonce: PublicKey,
    /// The blinded nonce R' = R + α*G + β*X
    blinded_nonce: PublicKey,
    /// Session ID for this signing
    session_id: [u8; 32],
}

impl BlindingContext {
    /// Create a blinding context from a coordinator's nonce
    ///
    /// # Arguments
    /// * `message` - The message to be signed (e.g., address bytes)
    /// * `coordinator_pubkey` - The coordinator's public key X
    /// * `nonce` - The public nonce from coordinator
    pub fn new(
        message: Vec<u8>,
        coordinator_pubkey: &PublicKey,
        nonce: &PublicNonce,
    ) -> Result<Self, WraithError> {
        let secp = Secp256k1::new();

        // Parse the nonce point
        let original_nonce = PublicKey::from_slice(&nonce.nonce_point)
            .map_err(|e| WraithError::InvalidSignature(format!("Invalid nonce: {}", e)))?;

        // Generate random blinding factors
        let alpha = random_secret_key();
        let beta = random_secret_key();

        // Compute R' = R + α*G + β*X
        let alpha_g = PublicKey::from_secret_key(&secp, &alpha);
        let beta_x = coordinator_pubkey
            .mul_tweak(&secp, &Scalar::from(beta))
            .map_err(|e| WraithError::PhaseError(format!("Point multiply failed: {}", e)))?;

        let r_plus_alpha = original_nonce
            .combine(&alpha_g)
            .map_err(|e| WraithError::PhaseError(format!("Point add failed: {}", e)))?;

        let blinded_nonce = r_plus_alpha
            .combine(&beta_x)
            .map_err(|e| WraithError::PhaseError(format!("Point add failed: {}", e)))?;

        Ok(Self {
            alpha,
            beta,
            message,
            coordinator_pubkey: *coordinator_pubkey,
            original_nonce,
            blinded_nonce,
            session_id: nonce.session_id,
        })
    }

    /// Create the blinded challenge to send to the coordinator
    ///
    /// Computes c = H(X || R' || m), then c' = c + β
    pub fn create_blinded_challenge(&self) -> Result<BlindedChallenge, WraithError> {
        // Compute unblinded challenge c = H(X || R' || m)
        let c = compute_challenge(&self.coordinator_pubkey, &self.blinded_nonce, &self.message);

        // Parse as scalar
        let c_scalar = SecretKey::from_slice(&c)
            .map_err(|e| WraithError::InvalidSignature(format!("Invalid challenge hash: {}", e)))?;

        // Compute c' = c + β
        let c_prime = c_scalar
            .add_tweak(&Scalar::from(self.beta))
            .map_err(|e| WraithError::PhaseError(format!("Scalar add failed: {}", e)))?;

        Ok(BlindedChallenge {
            challenge: c_prime.secret_bytes(),
            session_id: self.session_id,
        })
    }

    /// Unblind the signature response to get a valid Schnorr signature
    ///
    /// Computes s' = s + α, producing signature (R', s') on the original message.
    pub fn unblind(
        &self,
        response: &BlindSignatureResponse,
        session_key_id: [u8; 32],
    ) -> Result<UnblindedToken, WraithError> {
        // Verify session matches
        if response.session_id != self.session_id {
            return Err(WraithError::MissingData("Session ID mismatch".into()));
        }

        // Parse s
        let s = SecretKey::from_slice(&response.signature_scalar)
            .map_err(|e| WraithError::InvalidSignature(format!("Invalid signature: {}", e)))?;

        // Compute s' = s + α
        let s_prime = s
            .add_tweak(&Scalar::from(self.alpha))
            .map_err(|e| WraithError::PhaseError(format!("Scalar add failed: {}", e)))?;

        Ok(UnblindedToken {
            message: self.message.clone(),
            nonce_point: self.blinded_nonce.serialize(),
            signature_scalar: s_prime.secret_bytes(),
            session_key_id,
        })
    }

    /// Get the blinded nonce R' (for debugging)
    pub fn blinded_nonce(&self) -> &PublicKey {
        &self.blinded_nonce
    }
}

/// Unblinded token proving message was signed by coordinator
///
/// This is a standard Schnorr signature (R', s') on the message m.
/// The coordinator cannot link this to the blind signing request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnblindedToken {
    /// The signed message
    pub message: Vec<u8>,
    /// R' = R + α*G + β*X (the blinded nonce point)
    #[serde(with = "bytes33_hex")]
    pub nonce_point: [u8; 33],
    /// s' = s + α (the unblinded signature scalar)
    pub signature_scalar: [u8; 32],
    /// Session key ID for verification
    pub session_key_id: [u8; 32],
}

impl UnblindedToken {
    /// Convert to standard 64-byte Schnorr signature format
    ///
    /// Format: R' (32 bytes x-only) || s' (32 bytes)
    pub fn to_schnorr_bytes(&self) -> Result<[u8; 64], WraithError> {
        let r_point = PublicKey::from_slice(&self.nonce_point)
            .map_err(|e| WraithError::InvalidSignature(format!("Invalid nonce: {}", e)))?;

        let r_x_only = r_point.x_only_public_key().0;

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_x_only.serialize());
        sig[32..].copy_from_slice(&self.signature_scalar);

        Ok(sig)
    }
}

/// Verifier for unblinded tokens (used by non-coordinators)
pub struct TokenVerifier {
    /// Coordinator's public key
    coordinator_pubkey: PublicKey,
    /// Expected key ID
    key_id: [u8; 32],
}

impl TokenVerifier {
    /// Create a verifier from coordinator's public key
    pub fn new(coordinator_pubkey: PublicKey, session_id: &[u8; 32]) -> Self {
        let mut engine = sha256::Hash::engine();
        engine.input(b"wraith/key-id/v1");
        engine.input(session_id);
        engine.input(&coordinator_pubkey.serialize());
        let key_id = sha256::Hash::from_engine(engine).to_byte_array();

        Self {
            coordinator_pubkey,
            key_id,
        }
    }

    /// Verify an unblinded token
    ///
    /// Performs standard Schnorr verification: s'*G == R' + c*X
    pub fn verify(&self, token: &UnblindedToken) -> Result<bool, WraithError> {
        let secp = Secp256k1::new();

        // Check key ID
        if token.session_key_id != self.key_id {
            return Ok(false);
        }

        // Parse signature components
        let r_prime = PublicKey::from_slice(&token.nonce_point)
            .map_err(|e| WraithError::InvalidSignature(format!("Invalid nonce point: {}", e)))?;

        let s_prime = SecretKey::from_slice(&token.signature_scalar).map_err(|e| {
            WraithError::InvalidSignature(format!("Invalid signature scalar: {}", e))
        })?;

        // Compute challenge c = H(X || R' || m)
        let challenge = compute_challenge(&self.coordinator_pubkey, &r_prime, &token.message);

        // Verify: s'*G == R' + c*X
        let s_g = PublicKey::from_secret_key(&secp, &s_prime);

        let c_scalar = SecretKey::from_slice(&challenge)
            .map_err(|e| WraithError::InvalidSignature(format!("Invalid challenge: {}", e)))?;

        // Compute c*X
        let c_x = self
            .coordinator_pubkey
            .mul_tweak(&secp, &Scalar::from(c_scalar))
            .map_err(|e| WraithError::PhaseError(format!("Point multiply failed: {}", e)))?;

        // Compute R' + c*X
        let expected = r_prime
            .combine(&c_x)
            .map_err(|e| WraithError::PhaseError(format!("Point add failed: {}", e)))?;

        Ok(s_g == expected)
    }
}

// ============================================================================
// Legacy API Compatibility Layer
// ============================================================================

/// A blinded address ready to be signed by coordinator (legacy compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedAddress {
    /// Blinded challenge c'
    pub blinded_challenge: [u8; 32],
    /// Session ID
    pub session_id: [u8; 32],
}

/// Coordinator's signature on a blinded address (legacy compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindSignature {
    /// The signature scalar s
    pub signature_scalar: [u8; 32],
    /// Session-specific signing key identifier
    pub session_key_id: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::XOnlyPublicKey;

    fn generate_test_address() -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = random_secret_key();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        pk.x_only_public_key().0
    }

    #[test]
    fn test_blind_signature_full_protocol() {
        let session_id = [1u8; 32];
        let address = generate_test_address();
        let message = address.serialize().to_vec();

        // Step 1: Coordinator creates signer and nonce
        let mut signer = CoordinatorSigner::new(&session_id);
        let nonce = signer.create_nonce();

        // Step 2: Participant creates blinding context
        let context = BlindingContext::new(message.clone(), signer.public_key(), &nonce).unwrap();

        // Step 3: Participant creates blinded challenge
        let blinded_challenge = context.create_blinded_challenge().unwrap();

        // Step 4: Coordinator signs blinded challenge
        let response = signer.sign_blinded_challenge(&blinded_challenge).unwrap();

        // Step 5: Participant unblinds to get final signature
        let token = context.unblind(&response, *signer.key_id()).unwrap();

        // Verify the signature is valid
        assert!(signer.verify_signature(&token).unwrap());

        // Verify with external verifier
        let verifier = TokenVerifier::new(*signer.public_key(), &session_id);
        assert!(verifier.verify(&token).unwrap());

        // Verify the message is correct
        assert_eq!(token.message, message);
    }

    #[test]
    fn test_unlinkability() {
        let session_id = [2u8; 32];
        let address = generate_test_address();
        let message = address.serialize().to_vec();

        let mut signer = CoordinatorSigner::new(&session_id);

        // Get two blind signatures on the same message
        let nonce1 = signer.create_nonce();
        let nonce2 = signer.create_nonce();

        let context1 = BlindingContext::new(message.clone(), signer.public_key(), &nonce1).unwrap();
        let context2 = BlindingContext::new(message.clone(), signer.public_key(), &nonce2).unwrap();

        let challenge1 = context1.create_blinded_challenge().unwrap();
        let challenge2 = context2.create_blinded_challenge().unwrap();

        // Challenges should be different (due to random blinding)
        assert_ne!(challenge1.challenge, challenge2.challenge);

        let response1 = signer.sign_blinded_challenge(&challenge1).unwrap();
        let response2 = signer.sign_blinded_challenge(&challenge2).unwrap();

        let token1 = context1.unblind(&response1, *signer.key_id()).unwrap();
        let token2 = context2.unblind(&response2, *signer.key_id()).unwrap();

        // Both should verify
        assert!(signer.verify_signature(&token1).unwrap());
        assert!(signer.verify_signature(&token2).unwrap());

        // The final signatures should be different (unlinkable)
        assert_ne!(token1.nonce_point, token2.nonce_point);
        assert_ne!(token1.signature_scalar, token2.signature_scalar);

        // But both are valid signatures on the same message
        assert_eq!(token1.message, token2.message);
    }

    #[test]
    fn test_nonce_single_use() {
        let session_id = [3u8; 32];
        let address = generate_test_address();
        let message = address.serialize().to_vec();

        let mut signer = CoordinatorSigner::new(&session_id);
        let nonce = signer.create_nonce();

        let context = BlindingContext::new(message, signer.public_key(), &nonce).unwrap();
        let challenge = context.create_blinded_challenge().unwrap();

        // First signing should succeed
        let _ = signer.sign_blinded_challenge(&challenge).unwrap();

        // Second attempt with same session should fail (nonce consumed)
        let result = signer.sign_blinded_challenge(&challenge);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_sessions_different_keys() {
        let session1 = [1u8; 32];
        let session2 = [2u8; 32];

        let signer1 = CoordinatorSigner::new(&session1);
        let signer2 = CoordinatorSigner::new(&session2);

        assert_ne!(signer1.key_id(), signer2.key_id());
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let session_id = [4u8; 32];
        let address = generate_test_address();
        let message = address.serialize().to_vec();

        let mut signer = CoordinatorSigner::new(&session_id);
        let nonce = signer.create_nonce();

        let context = BlindingContext::new(message, signer.public_key(), &nonce).unwrap();
        let challenge = context.create_blinded_challenge().unwrap();
        let response = signer.sign_blinded_challenge(&challenge).unwrap();
        let mut token = context.unblind(&response, *signer.key_id()).unwrap();

        // Tamper with session key ID
        token.session_key_id = [0u8; 32];

        // Should fail verification
        assert!(!signer.verify_signature(&token).unwrap());
    }

    #[test]
    fn test_tampered_message_fails() {
        let session_id = [5u8; 32];
        let address = generate_test_address();
        let message = address.serialize().to_vec();

        let mut signer = CoordinatorSigner::new(&session_id);
        let nonce = signer.create_nonce();

        let context = BlindingContext::new(message, signer.public_key(), &nonce).unwrap();
        let challenge = context.create_blinded_challenge().unwrap();
        let response = signer.sign_blinded_challenge(&challenge).unwrap();
        let mut token = context.unblind(&response, *signer.key_id()).unwrap();

        // Tamper with message
        token.message[0] ^= 0xff;

        // Should fail verification
        assert!(!signer.verify_signature(&token).unwrap());
    }

    #[test]
    fn test_schnorr_bytes_conversion() {
        let session_id = [6u8; 32];
        let address = generate_test_address();
        let message = address.serialize().to_vec();

        let mut signer = CoordinatorSigner::new(&session_id);
        let nonce = signer.create_nonce();

        let context = BlindingContext::new(message, signer.public_key(), &nonce).unwrap();
        let challenge = context.create_blinded_challenge().unwrap();
        let response = signer.sign_blinded_challenge(&challenge).unwrap();
        let token = context.unblind(&response, *signer.key_id()).unwrap();

        // Should be able to convert to standard 64-byte format
        let schnorr_bytes = token.to_schnorr_bytes().unwrap();
        assert_eq!(schnorr_bytes.len(), 64);
    }

    /// WR-H1 Security Test: Nonces are bound to participants
    ///
    /// This test verifies that:
    /// 1. Nonces created for participant A cannot be used by participant B
    /// 2. The binding is enforced during signing
    #[test]
    fn test_nonce_bound_to_participant() {
        let session_id = [7u8; 32];
        let address = generate_test_address();
        let message = address.serialize().to_vec();

        let mut signer = CoordinatorSigner::new(&session_id);

        // Create a nonce bound to "ghost1"
        let nonce = signer.create_nonce_for_participant("ghost1");

        // Participant creates blinding context
        let context = BlindingContext::new(message, signer.public_key(), &nonce).unwrap();
        let challenge = context.create_blinded_challenge().unwrap();

        // Attempt to sign as "ghost2" (wrong participant) should FAIL
        let result = signer.sign_blinded_challenge_for_participant(&challenge, "ghost2");
        assert!(
            result.is_err(),
            "Signing with wrong participant should fail"
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Nonce bound to"));

        // Create a new nonce for the test since the first was not consumed
        // (we got an error before removal)
        let nonce2 = signer.create_nonce_for_participant("ghost1");
        let context2 = BlindingContext::new(
            address.serialize().to_vec(),
            signer.public_key(),
            &nonce2,
        )
        .unwrap();
        let challenge2 = context2.create_blinded_challenge().unwrap();

        // Signing as "ghost1" (correct participant) should SUCCEED
        let result = signer.sign_blinded_challenge_for_participant(&challenge2, "ghost1");
        assert!(result.is_ok(), "Signing with correct participant should succeed");
    }

    /// Test that nonce binding includes ghost_id in session_id generation
    #[test]
    fn test_nonce_session_id_includes_participant() {
        let session_id = [8u8; 32];

        let mut signer1 = CoordinatorSigner::new(&session_id);
        let mut signer2 = CoordinatorSigner::new(&session_id);

        // Create nonces for different participants on different signers
        let nonce1 = signer1.create_nonce_for_participant("ghost1");
        let nonce2 = signer2.create_nonce_for_participant("ghost2");

        // Even with same coordinator key, different participants get different session IDs
        // (due to random entropy AND ghost_id in hash)
        assert_ne!(
            nonce1.session_id, nonce2.session_id,
            "Different participants should get different session IDs"
        );
    }

    /// Test backwards compatibility with unbound nonces (deprecated)
    #[test]
    #[allow(deprecated)]
    fn test_unbound_nonce_backwards_compat() {
        let session_id = [9u8; 32];
        let address = generate_test_address();
        let message = address.serialize().to_vec();

        let mut signer = CoordinatorSigner::new(&session_id);

        // Create an unbound nonce (deprecated but should still work)
        let nonce = signer.create_nonce();

        let context = BlindingContext::new(message, signer.public_key(), &nonce).unwrap();
        let challenge = context.create_blinded_challenge().unwrap();

        // Signing with any participant should work for unbound nonces (backwards compat)
        let result = signer.sign_blinded_challenge_for_participant(&challenge, "any_ghost_id");
        assert!(
            result.is_ok(),
            "Unbound nonces should work with any participant for backwards compat"
        );
    }
}
