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
//| FILE: challenge.rs                                                                                                   |
//|======================================================================================================================|

//! Verification challenge types

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Challenge type for verification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeType {
    /// Archive mode: Request historical block
    ArchiveBlock,
    /// Archive mode: Request historical transaction
    ArchiveTx,
    /// Policy: Submit test transaction for classification
    PolicyCheck,
    /// Stratum: Check port accessibility
    StratumPing,
    /// Ghost Pay: L2 balance query
    GhostPayBalance,
    /// Ghost Pay: L2 transfer capability
    GhostPayTransfer,
}

/// Archive challenge request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveChallenge {
    /// Challenge type
    pub challenge_type: ChallengeType,
    /// Block hash to retrieve (hex)
    pub block_hash: Option<String>,
    /// Transaction ID to retrieve (hex)
    pub txid: Option<String>,
    /// Minimum block height to prove
    pub min_height: Option<u64>,
}

/// Archive challenge response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveResponse {
    /// Success
    pub success: bool,
    /// Block data (if requested)
    pub block_data: Option<BlockData>,
    /// Transaction data (if requested)
    pub tx_data: Option<TxData>,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Block data for archive verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockData {
    /// Block hash
    pub hash: String,
    /// Block height
    pub height: u64,
    /// Block timestamp
    pub timestamp: u64,
    /// Number of transactions
    pub tx_count: usize,
    /// Merkle root
    pub merkle_root: String,
}

/// Transaction data for archive verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxData {
    /// Transaction ID
    pub txid: String,
    /// Block hash containing the transaction
    pub block_hash: String,
    /// Transaction index in block
    pub tx_index: usize,
    /// Transaction size (bytes)
    pub size: usize,
    /// Number of inputs
    pub input_count: usize,
    /// Number of outputs
    pub output_count: usize,
}

/// Policy challenge request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyChallenge {
    /// Raw transaction hex
    pub tx_hex: String,
    /// Expected tier (for verification)
    pub expected_tier: Option<String>,
}

/// Policy challenge response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResponse {
    /// Success
    pub success: bool,
    /// Active policy profile
    pub profile: String,
    /// Transaction classification
    pub classification: Option<PolicyClassification>,
    /// Would transaction be accepted
    pub accepted: bool,
    /// Rejection reason (if not accepted)
    pub rejection_reason: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Policy classification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyClassification {
    /// BUDS tier (T0-T3)
    pub tier: String,
    /// Classification reason
    pub reason: String,
    /// Detected features
    pub features: Vec<String>,
}

/// Stratum challenge request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StratumChallenge {
    /// Port to check (default: 34255 for SV2, 3333 for SV1)
    pub port: Option<u16>,
    /// Protocol version
    pub protocol: StratumProtocol,
}

/// Stratum protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StratumProtocol {
    Sv1,
    Sv2,
}

/// Stratum challenge response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StratumResponse {
    /// Success
    pub success: bool,
    /// Port checked
    pub port: u16,
    /// Protocol
    pub protocol: StratumProtocol,
    /// Connection established
    pub connected: bool,
    /// Latency (milliseconds)
    pub latency_ms: Option<u32>,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Ghost Pay challenge request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostPayChallenge {
    /// Challenge type
    pub challenge_type: ChallengeType,
    /// Address to query (for balance)
    pub address: Option<String>,
}

/// Ghost Pay challenge response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostPayResponse {
    /// Success
    pub success: bool,
    /// L2 enabled
    pub l2_enabled: bool,
    /// Current virtual block
    pub virtual_block: Option<u64>,
    /// Current epoch
    pub epoch: Option<u64>,
    /// Balance (if queried)
    pub balance_sats: Option<u64>,
    /// Wraith enabled
    pub wraith_enabled: bool,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Node is healthy
    pub healthy: bool,
    /// Node ID (hex)
    pub node_id: String,
    /// Software version
    pub version: String,
    /// Current block height
    pub block_height: u64,
    /// Current round ID
    pub round_id: u64,
    /// Connected miners
    pub miner_count: u32,
    /// Connected peers
    pub peer_count: u32,
    /// Capabilities
    pub capabilities: CapabilityStatus,
    /// Uptime (seconds)
    pub uptime_secs: u64,
}

/// Capability status
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilityStatus {
    /// Archive mode enabled
    pub archive_mode: bool,
    /// Ghost Pay enabled
    pub ghost_pay: bool,
    /// Public mining enabled
    pub public_mining: bool,
    /// Bitcoin Pure policy enabled
    pub bitcoin_pure: bool,
    /// Elder status
    pub elder_status: bool,
    /// GSP (Ghost Service Protocol) light wallet server enabled
    pub gsp_enabled: bool,
    /// Total shares
    pub total_shares: i32,
}

impl From<ghost_common::types::NodeCapabilities> for CapabilityStatus {
    fn from(caps: ghost_common::types::NodeCapabilities) -> Self {
        Self {
            archive_mode: caps.archive_mode,
            ghost_pay: caps.ghost_pay,
            public_mining: caps.public_mining,
            bitcoin_pure: caps.bitcoin_pure,
            elder_status: caps.elder_status,
            gsp_enabled: false, // Set via VerificationState.gsp_enabled()
            total_shares: caps.total_shares(),
        }
    }
}

/// Maximum age of a signed response before it's considered stale (5 minutes)
pub const MAX_RESPONSE_AGE_SECS: u64 = 300;

/// Maximum time in the future a response timestamp can be (2 minutes)
pub const MAX_FUTURE_TIME_SECS: u64 = 120;

/// Signed verification response wrapper
///
/// Wraps any verification response with a cryptographic signature to:
/// - Prove the response came from the claimed node
/// - Prevent proxying attacks (where an attacker relays another node's responses)
/// - Ensure freshness via timestamp and nonce
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedResponse<T: Serialize> {
    /// The actual response payload
    pub payload: T,
    /// Node ID that signed this response (hex-encoded Ed25519 public key)
    pub signer: String,
    /// Unix timestamp when the response was generated
    pub timestamp: u64,
    /// Random nonce for uniqueness (hex-encoded 16 bytes)
    pub nonce: String,
    /// Challenge nonce from request (if provided) - ensures response matches request
    pub challenge_nonce: Option<String>,
    /// Ed25519 signature over (payload_hash || signer || timestamp || nonce || challenge_nonce)
    /// Hex-encoded 64-byte signature
    pub signature: String,
}

impl<T: Serialize> SignedResponse<T> {
    /// Create a new signed response
    ///
    /// # Arguments
    /// * `payload` - The response data to sign
    /// * `signer` - Node ID (hex-encoded public key)
    /// * `sign_fn` - Closure that takes a message hash and returns a signature
    /// * `challenge_nonce` - Optional nonce from the request
    pub fn new<F>(payload: T, signer: String, sign_fn: F, challenge_nonce: Option<String>) -> Self
    where
        F: FnOnce(&[u8]) -> [u8; 64],
    {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Generate random nonce
        let nonce_bytes: [u8; 16] = rand::random();
        let nonce = hex::encode(nonce_bytes);

        // Compute message hash for signing
        let message_hash = Self::compute_message_hash(
            &payload,
            &signer,
            timestamp,
            &nonce,
            challenge_nonce.as_deref(),
        );

        // Sign the message hash
        let signature_bytes = sign_fn(&message_hash);
        let signature = hex::encode(signature_bytes);

        Self {
            payload,
            signer,
            timestamp,
            nonce,
            challenge_nonce,
            signature,
        }
    }

    /// Compute the message hash for signing/verification
    fn compute_message_hash(
        payload: &T,
        signer: &str,
        timestamp: u64,
        nonce: &str,
        challenge_nonce: Option<&str>,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();

        // Hash the payload JSON
        if let Ok(payload_json) = serde_json::to_vec(payload) {
            hasher.update(&payload_json);
        }

        // Hash metadata
        hasher.update(signer.as_bytes());
        hasher.update(timestamp.to_le_bytes());
        hasher.update(nonce.as_bytes());

        // Include challenge nonce if present
        if let Some(cn) = challenge_nonce {
            hasher.update(cn.as_bytes());
        }

        hasher.finalize().into()
    }

    /// Verify the signature is valid
    ///
    /// # Arguments
    /// * `verify_fn` - Closure that takes (public_key_hex, message_hash, signature_bytes)
    ///   and returns true if the signature is valid
    ///
    /// # Returns
    /// * `Ok(())` if signature is valid
    /// * `Err(reason)` if verification fails
    pub fn verify<F>(&self, verify_fn: F) -> Result<(), String>
    where
        F: FnOnce(&str, &[u8], &[u8]) -> bool,
    {
        // Check timestamp bounds
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Not too far in the future
        if self.timestamp > now + MAX_FUTURE_TIME_SECS {
            return Err(format!(
                "Response timestamp {} is too far in the future (current: {})",
                self.timestamp, now
            ));
        }

        // Not too old
        if self.timestamp + MAX_RESPONSE_AGE_SECS < now {
            return Err(format!(
                "Response timestamp {} is too old (max age: {}s, current: {})",
                self.timestamp, MAX_RESPONSE_AGE_SECS, now
            ));
        }

        // Decode signature
        let signature_bytes =
            hex::decode(&self.signature).map_err(|e| format!("Invalid signature hex: {}", e))?;

        if signature_bytes.len() != 64 {
            return Err(format!(
                "Invalid signature length: {} (expected 64)",
                signature_bytes.len()
            ));
        }

        // Recompute message hash
        let message_hash = Self::compute_message_hash(
            &self.payload,
            &self.signer,
            self.timestamp,
            &self.nonce,
            self.challenge_nonce.as_deref(),
        );

        // Verify signature
        if verify_fn(&self.signer, &message_hash, &signature_bytes) {
            Ok(())
        } else {
            Err("Signature verification failed".to_string())
        }
    }
}

/// Verification request with nonce
///
/// Clients should include a nonce in requests so that the response
/// can be bound to that specific request (prevents replay of old responses).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRequest<T> {
    /// The actual request payload
    pub request: T,
    /// Random nonce for this request (hex-encoded 16 bytes)
    pub nonce: String,
}

impl<T> VerificationRequest<T> {
    /// Create a new verification request with random nonce
    pub fn new(request: T) -> Self {
        let nonce_bytes: [u8; 16] = rand::random();

        Self {
            request,
            nonce: hex::encode(nonce_bytes),
        }
    }

    /// Create a verification request with a specific nonce
    pub fn with_nonce(request: T, nonce: String) -> Self {
        Self { request, nonce }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_serialization() {
        let challenge = ArchiveChallenge {
            challenge_type: ChallengeType::ArchiveBlock,
            block_hash: Some("abc123".to_string()),
            txid: None,
            min_height: Some(100),
        };

        let json = serde_json::to_string(&challenge).unwrap();
        let decoded: ArchiveChallenge = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.challenge_type, ChallengeType::ArchiveBlock);
    }

    #[test]
    fn test_signed_response_creation() {
        let health = HealthResponse {
            healthy: true,
            node_id: "test_node".to_string(),
            version: "1.0.0".to_string(),
            block_height: 100,
            round_id: 1,
            miner_count: 10,
            peer_count: 5,
            capabilities: CapabilityStatus::default(),
            uptime_secs: 3600,
        };

        // Mock signing function that returns a fake signature
        let sign_fn = |_message: &[u8]| -> [u8; 64] { [0xABu8; 64] };

        let signed = SignedResponse::new(
            health,
            "0123456789abcdef".to_string(),
            sign_fn,
            Some("challenge_nonce".to_string()),
        );

        assert_eq!(signed.signer, "0123456789abcdef");
        assert!(signed.timestamp > 0);
        assert!(!signed.nonce.is_empty());
        assert_eq!(signed.challenge_nonce, Some("challenge_nonce".to_string()));
        assert_eq!(signed.signature, hex::encode([0xABu8; 64]));
    }

    #[test]
    fn test_signed_response_timestamp_validation() {
        let health = HealthResponse {
            healthy: true,
            node_id: "test".to_string(),
            version: "1.0".to_string(),
            block_height: 0,
            round_id: 0,
            miner_count: 0,
            peer_count: 0,
            capabilities: CapabilityStatus::default(),
            uptime_secs: 0,
        };

        // Create a signed response with timestamp far in the past
        let mut signed = SignedResponse {
            payload: health,
            signer: "test".to_string(),
            timestamp: 1000, // Very old timestamp
            nonce: "abc123".to_string(),
            challenge_nonce: None,
            signature: hex::encode([0u8; 64]),
        };

        // Verification should fail due to old timestamp
        let result = signed.verify(|_, _, _| true);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too old"));

        // Test timestamp too far in future
        signed.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + MAX_FUTURE_TIME_SECS
            + 100;

        let result = signed.verify(|_, _, _| true);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("future"));
    }

    #[test]
    fn test_verification_request_nonce() {
        let request = VerificationRequest::new(ArchiveChallenge {
            challenge_type: ChallengeType::ArchiveBlock,
            block_hash: Some("abc".to_string()),
            txid: None,
            min_height: None,
        });

        // Nonce should be 32 hex chars (16 bytes)
        assert_eq!(request.nonce.len(), 32);

        // Each request should have a different nonce
        let request2 = VerificationRequest::new(ArchiveChallenge {
            challenge_type: ChallengeType::ArchiveBlock,
            block_hash: Some("abc".to_string()),
            txid: None,
            min_height: None,
        });

        assert_ne!(request.nonce, request2.nonce);
    }
}
