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
//| FILE: auth.rs                                                                                                        |
//|======================================================================================================================|

//! Authentication types for GSP Protocol
//!
//! Implements the WalletProof Schnorr challenge-response authentication scheme.
//!
//! # Authentication Flow
//!
//! 1. Wallet generates auth keypair at derivation path `m/352'/0'/0'/0/0`
//! 2. `wallet_id` = SHA256(auth_pubkey)[0:16]
//! 3. Registration: POST /register with signed proof
//! 4. Session: POST /session returns JWT (24h expiry)
//! 5. WebSocket: Send JWT in `authenticate` message
//! 6. Sensitive ops: Include fresh WalletProof with each request

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::GspProtoError;
use crate::PROOF_TIMESTAMP_TOLERANCE_SECS;

/// Wallet identifier derived from public key
///
/// Computed as SHA256(auth_pubkey)[0:16] (first 16 bytes as hex = 32 chars)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WalletId(pub String);

impl WalletId {
    /// Create a WalletId from a public key
    pub fn from_pubkey(pubkey: &[u8; 32]) -> Self {
        let hash = Sha256::digest(pubkey);
        let id_bytes = &hash[0..16];
        WalletId(hex::encode(id_bytes))
    }

    /// Get the wallet ID as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate wallet ID format
    pub fn is_valid(&self) -> bool {
        self.0.len() == 32 && self.0.chars().all(|c| c.is_ascii_hexdigit())
    }
}

impl std::fmt::Display for WalletId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for WalletId {
    fn from(s: String) -> Self {
        WalletId(s)
    }
}

/// Wallet proof for Schnorr challenge-response authentication
///
/// Used for both registration and sensitive operations.
/// The message format is: "ghost-{action}:{timestamp}:{nonce_hex}"
///
/// # Security: Redacted Debug
///
/// The Debug implementation redacts sensitive fields (signature, public_key, nonce)
/// to prevent accidental exposure in logs or error messages.
#[derive(Clone, Serialize, Deserialize)]
pub struct WalletProof {
    /// Unix timestamp in seconds
    pub timestamp: i64,

    /// Random nonce for replay protection (16 bytes as hex)
    pub nonce: String,

    /// Message being signed: "ghost-{action}:{timestamp}:{nonce}"
    pub message: String,

    /// Schnorr signature (64 bytes as hex)
    pub signature: String,

    /// X-only public key (32 bytes as hex)
    pub public_key: String,
}

impl std::fmt::Debug for WalletProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletProof")
            .field("timestamp", &self.timestamp)
            .field("nonce", &"[REDACTED]")
            .field("message", &self.message)
            .field("signature", &"[REDACTED]")
            .field("public_key", &"[REDACTED]")
            .finish()
    }
}

impl WalletProof {
    /// Create a new wallet proof (unsigned)
    ///
    /// The caller must sign the message and set the signature field.
    ///
    /// LOW FIX: Returns Result to propagate entropy source errors instead of panicking.
    pub fn new(action: &str, public_key: &[u8; 32]) -> Result<Self, GspProtoError> {
        let timestamp = chrono::Utc::now().timestamp();
        let nonce_bytes: [u8; 16] = rand_nonce()?;
        let nonce = hex::encode(nonce_bytes);
        let message = format!("ghost-{}:{}:{}", action, timestamp, nonce);

        Ok(WalletProof {
            timestamp,
            nonce,
            message,
            signature: String::new(),
            public_key: hex::encode(public_key),
        })
    }

    /// Get the message bytes for signing
    pub fn message_bytes(&self) -> Vec<u8> {
        self.message.as_bytes().to_vec()
    }

    /// Validate proof structure (not signature)
    pub fn validate_structure(&self) -> Result<(), GspProtoError> {
        // Check nonce length (16 bytes = 32 hex chars)
        if self.nonce.len() != 32 {
            return Err(GspProtoError::InvalidProof(
                "Nonce must be 32 hex characters".to_string(),
            ));
        }

        // Check signature length (64 bytes = 128 hex chars)
        if self.signature.len() != 128 {
            return Err(GspProtoError::InvalidProof(
                "Signature must be 128 hex characters".to_string(),
            ));
        }

        // Check public key length (32 bytes = 64 hex chars)
        if self.public_key.len() != 64 {
            return Err(GspProtoError::InvalidProof(
                "Public key must be 64 hex characters".to_string(),
            ));
        }

        // Validate hex encoding
        hex::decode(&self.nonce)
            .map_err(|_| GspProtoError::InvalidProof("Invalid nonce hex encoding".to_string()))?;
        hex::decode(&self.signature).map_err(|_| {
            GspProtoError::InvalidProof("Invalid signature hex encoding".to_string())
        })?;
        hex::decode(&self.public_key).map_err(|_| {
            GspProtoError::InvalidProof("Invalid public key hex encoding".to_string())
        })?;

        // Validate message format
        let parts: Vec<&str> = self.message.split(':').collect();
        if parts.len() != 3 || !parts[0].starts_with("ghost-") {
            return Err(GspProtoError::InvalidProof(
                "Invalid message format".to_string(),
            ));
        }

        // Validate timestamp matches message
        let msg_timestamp: i64 = parts[1]
            .parse()
            .map_err(|_| GspProtoError::InvalidProof("Invalid timestamp in message".to_string()))?;
        if msg_timestamp != self.timestamp {
            return Err(GspProtoError::InvalidProof(
                "Timestamp mismatch".to_string(),
            ));
        }

        // Validate nonce matches message
        if parts[2] != self.nonce {
            return Err(GspProtoError::InvalidProof("Nonce mismatch".to_string()));
        }

        Ok(())
    }

    /// Check if timestamp is within acceptable range
    pub fn is_timestamp_valid(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        let diff = (now - self.timestamp).abs();
        diff <= PROOF_TIMESTAMP_TOLERANCE_SECS
    }

    /// Extract the action from the message
    pub fn action(&self) -> Option<&str> {
        self.message
            .split(':')
            .next()
            .and_then(|s| s.strip_prefix("ghost-"))
    }

    /// Get the wallet ID derived from this proof's public key
    pub fn wallet_id(&self) -> Result<WalletId, GspProtoError> {
        let pubkey_bytes = hex::decode(&self.public_key)?;
        if pubkey_bytes.len() != 32 {
            return Err(GspProtoError::InvalidPublicKey(
                "Public key must be 32 bytes".to_string(),
            ));
        }
        let mut pubkey_array = [0u8; 32];
        pubkey_array.copy_from_slice(&pubkey_bytes);
        Ok(WalletId::from_pubkey(&pubkey_array))
    }

    /// Get signature bytes
    pub fn signature_bytes(&self) -> Result<[u8; 64], GspProtoError> {
        let bytes = hex::decode(&self.signature)?;
        if bytes.len() != 64 {
            return Err(GspProtoError::SignatureInvalid(
                "Signature must be 64 bytes".to_string(),
            ));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&bytes);
        Ok(sig)
    }

    /// Get public key bytes
    pub fn public_key_bytes(&self) -> Result<[u8; 32], GspProtoError> {
        let bytes = hex::decode(&self.public_key)?;
        if bytes.len() != 32 {
            return Err(GspProtoError::InvalidPublicKey(
                "Public key must be 32 bytes".to_string(),
            ));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&bytes);
        Ok(pk)
    }
}

/// Generate a cryptographically secure random 16-byte nonce
///
/// CRIT-1 FIX: Uses getrandom for CSPRNG-quality randomness instead of
/// the insecure time-based approach. This is essential for replay protection
/// in wallet proofs - predictable nonces could allow replay attacks.
///
/// LOW FIX: Returns Result instead of panicking to allow graceful error handling.
fn rand_nonce() -> Result<[u8; 16], GspProtoError> {
    let mut nonce = [0u8; 16];
    // getrandom uses the OS CSPRNG (/dev/urandom on Linux, CryptGenRandom on Windows)
    getrandom::getrandom(&mut nonce).map_err(|e| {
        GspProtoError::Internal(format!("Failed to generate secure nonce: OS entropy source unavailable ({})", e))
    })?;
    Ok(nonce)
}

/// Registration request sent to GSP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// Wallet proof with "register" action
    pub proof: WalletProof,

    /// Optional display name for the wallet
    pub display_name: Option<String>,
}

/// Registration response from GSP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    /// Whether registration was successful
    pub success: bool,

    /// Assigned wallet ID
    pub wallet_id: Option<WalletId>,

    /// Error message if failed
    pub error: Option<String>,
}

/// Session creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRequest {
    /// Wallet proof with "session" action
    pub proof: WalletProof,
}

/// Session creation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResponse {
    /// Whether session creation was successful
    pub success: bool,

    /// JWT session token
    pub token: Option<SessionToken>,

    /// Token expiry timestamp (Unix seconds)
    pub expires_at: Option<i64>,

    /// Error message if failed
    pub error: Option<String>,
}

/// Session token (JWT)
///
/// # Security: Redacted Debug
///
/// The Debug implementation redacts the token field to prevent exposure in logs.
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionToken {
    /// The JWT string
    pub token: String,

    /// Wallet ID this session belongs to
    pub wallet_id: WalletId,

    /// Session creation timestamp
    pub created_at: i64,

    /// Session expiry timestamp
    pub expires_at: i64,
}

impl std::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionToken")
            .field("token", &"[REDACTED]")
            .field("wallet_id", &self.wallet_id)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl SessionToken {
    /// Check if the session has expired
    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        now >= self.expires_at
    }

    /// Get remaining validity in seconds
    pub fn remaining_secs(&self) -> i64 {
        let now = chrono::Utc::now().timestamp();
        (self.expires_at - now).max(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_id_from_pubkey() {
        let pubkey = [0u8; 32];
        let id = WalletId::from_pubkey(&pubkey);
        assert!(id.is_valid());
        assert_eq!(id.0.len(), 32);
    }

    #[test]
    fn test_wallet_proof_structure() {
        let pubkey = [1u8; 32];
        let mut proof = WalletProof::new("register", &pubkey).expect("nonce generation failed");

        // Without signature, validation should fail
        assert!(proof.validate_structure().is_err());

        // Add valid signature
        proof.signature = hex::encode([2u8; 64]);
        assert!(proof.validate_structure().is_ok());
    }

    #[test]
    fn test_wallet_proof_timestamp_valid() {
        let pubkey = [1u8; 32];
        let proof = WalletProof::new("register", &pubkey).expect("nonce generation failed");
        assert!(proof.is_timestamp_valid());
    }

    #[test]
    fn test_wallet_proof_action() {
        let pubkey = [1u8; 32];
        let proof = WalletProof::new("register", &pubkey).expect("nonce generation failed");
        assert_eq!(proof.action(), Some("register"));

        let proof2 = WalletProof::new("session", &pubkey).expect("nonce generation failed");
        assert_eq!(proof2.action(), Some("session"));
    }

    #[test]
    fn test_session_token_expiry() {
        let token = SessionToken {
            token: "test".to_string(),
            wallet_id: WalletId("abc123".to_string()),
            created_at: chrono::Utc::now().timestamp(),
            expires_at: chrono::Utc::now().timestamp() + 3600, // 1 hour from now
        };
        assert!(!token.is_expired());
        assert!(token.remaining_secs() > 0);

        let expired_token = SessionToken {
            token: "test".to_string(),
            wallet_id: WalletId("abc123".to_string()),
            created_at: chrono::Utc::now().timestamp() - 7200,
            expires_at: chrono::Utc::now().timestamp() - 3600, // 1 hour ago
        };
        assert!(expired_token.is_expired());
        assert_eq!(expired_token.remaining_secs(), 0);
    }

    #[test]
    fn test_wallet_proof_debug_redacts_sensitive_fields() {
        // M-INFO-1 TEST: Verify Debug implementation redacts sensitive data
        let pubkey = [1u8; 32];
        let mut proof = WalletProof::new("register", &pubkey).expect("nonce generation failed");
        proof.signature = hex::encode([2u8; 64]);

        let debug_output = format!("{:?}", proof);

        // Ensure sensitive fields are redacted
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains(&hex::encode([1u8; 32]))); // public_key
        assert!(!debug_output.contains(&hex::encode([2u8; 64]))); // signature
                                                                  // Message should still be visible (not sensitive)
        assert!(debug_output.contains("ghost-register"));
    }

    #[test]
    fn test_session_token_debug_redacts_token() {
        // M-INFO-1 TEST: Verify Debug implementation redacts session token
        let token = SessionToken {
            token: "super_secret_jwt_token".to_string(),
            wallet_id: WalletId("abc123".to_string()),
            created_at: chrono::Utc::now().timestamp(),
            expires_at: chrono::Utc::now().timestamp() + 3600,
        };

        let debug_output = format!("{:?}", token);

        // Ensure token is redacted
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("super_secret_jwt_token"));
        // wallet_id is not sensitive (it's derived from public key hash)
        assert!(debug_output.contains("abc123"));
    }

    #[test]
    fn test_crit1_nonce_is_cryptographically_random() {
        // CRIT-1 TEST: Verify nonces are generated using CSPRNG and are unique
        use std::collections::HashSet;

        // Generate multiple nonces and verify they're all unique
        let mut seen_nonces = HashSet::new();
        for _ in 0..100 {
            let nonce = super::rand_nonce().expect("nonce generation failed");
            // Each nonce should be unique
            assert!(
                seen_nonces.insert(nonce),
                "CRIT-1 FAILURE: Duplicate nonce detected - this indicates weak randomness"
            );
        }

        // Verify all 16 bytes are being used (not just a few bytes)
        let nonce = super::rand_nonce().expect("nonce generation failed");
        let zeros: usize = nonce.iter().filter(|&&b| b == 0).count();
        // Statistically, having more than 12 zero bytes in 16 random bytes is extremely unlikely
        // P(12+ zeros) = sum(C(16,k) * (1/256)^k * (255/256)^(16-k) for k in 12..17) < 1e-20
        assert!(
            zeros < 12,
            "CRIT-1 FAILURE: Too many zero bytes ({}/16) - suggests weak entropy",
            zeros
        );
    }

    #[test]
    fn test_crit1_wallet_proof_has_random_nonce() {
        // CRIT-1 TEST: Verify WalletProof uses CSPRNG nonces
        let pubkey = [1u8; 32];
        let proof1 = WalletProof::new("register", &pubkey).expect("nonce generation failed");
        let proof2 = WalletProof::new("register", &pubkey).expect("nonce generation failed");

        // Nonces must be different even for same action and pubkey
        assert_ne!(
            proof1.nonce, proof2.nonce,
            "CRIT-1 FAILURE: Two proofs generated same nonce - replay attacks possible"
        );

        // Verify nonce is properly formatted (32 hex chars = 16 bytes)
        assert_eq!(proof1.nonce.len(), 32);
        assert!(proof1.nonce.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
