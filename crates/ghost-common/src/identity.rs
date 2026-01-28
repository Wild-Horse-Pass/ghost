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
//| FILE: identity.rs                                                                                                    |
//|======================================================================================================================|

//! Node identity management using Ed25519 keys
//!
//! Each node has a unique Ed25519 keypair that identifies it in the network.
//! The public key (32 bytes) serves as the NodeId.
//!
//! ## Sybil Resistance via Proof-of-Work
//!
//! To prevent Sybil attacks on elder selection (which uses node_id ordering),
//! nodes must provide a proof-of-work nonce such that:
//!   SHA256(public_key || nonce) has at least `NODE_ID_POW_DIFFICULTY` leading zero bits
//!
//! This makes generating "favorable" node_ids computationally expensive.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

use crate::error::{GhostError, GhostResult};
use crate::types::NodeId;

/// Required leading zero bits for node_id proof-of-work.
/// 20 bits = ~1 million hashes on average (a few seconds on modern hardware)
/// This is enough to make mass Sybil attacks expensive while not burdening legitimate nodes.
pub const NODE_ID_POW_DIFFICULTY: u32 = 20;

/// Maximum nonce value to try (prevents infinite loops)
const MAX_POW_ATTEMPTS: u64 = 100_000_000;

/// Proof-of-work for node identity
/// Proves computational work was done to create this identity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeIdProof {
    /// The nonce that satisfies the PoW requirement
    pub nonce: u64,
    /// The difficulty level (leading zero bits) achieved
    pub difficulty: u32,
}

impl NodeIdProof {
    /// Compute the proof hash for a given public key and nonce
    pub fn compute_hash(public_key: &[u8; 32], nonce: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        hasher.update(&nonce.to_le_bytes());
        hasher.finalize().into()
    }

    /// Count leading zero bits in a hash
    pub fn leading_zeros(hash: &[u8; 32]) -> u32 {
        let mut zeros = 0u32;
        for byte in hash {
            if *byte == 0 {
                zeros += 8;
            } else {
                zeros += byte.leading_zeros();
                break;
            }
        }
        zeros
    }

    /// Verify that this proof is valid for the given public key
    pub fn verify(&self, public_key: &[u8; 32], required_difficulty: u32) -> bool {
        let hash = Self::compute_hash(public_key, self.nonce);
        let zeros = Self::leading_zeros(&hash);
        zeros >= required_difficulty && self.difficulty >= required_difficulty
    }

    /// Mine a proof-of-work nonce for the given public key
    /// Returns None if max attempts exceeded (should not happen with reasonable difficulty)
    pub fn mine(public_key: &[u8; 32], required_difficulty: u32) -> Option<Self> {
        for nonce in 0..MAX_POW_ATTEMPTS {
            let hash = Self::compute_hash(public_key, nonce);
            let zeros = Self::leading_zeros(&hash);
            if zeros >= required_difficulty {
                return Some(Self {
                    nonce,
                    difficulty: zeros,
                });
            }
        }
        None
    }

    /// Serialize to bytes (for storage)
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut bytes = [0u8; 12];
        bytes[0..8].copy_from_slice(&self.nonce.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.difficulty.to_le_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 12 {
            return None;
        }
        let nonce = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
        let difficulty = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
        Some(Self { nonce, difficulty })
    }

    /// Serialize to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Deserialize from hex string
    pub fn from_hex(hex_str: &str) -> Option<Self> {
        let bytes = hex::decode(hex_str).ok()?;
        Self::from_bytes(&bytes)
    }
}

/// Node identity with Ed25519 keypair and proof-of-work
#[derive(Debug)]
pub struct NodeIdentity {
    /// Ed25519 signing key (private)
    signing_key: SigningKey,
    /// Ed25519 verifying key (public)
    verifying_key: VerifyingKey,
    /// Proof-of-work for Sybil resistance
    pow_proof: Option<NodeIdProof>,
    /// Display name (optional)
    display_name: Option<String>,
}

impl NodeIdentity {
    /// Create a new random identity with proof-of-work
    /// This will mine a nonce that satisfies the PoW difficulty requirement
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let public_key = verifying_key.to_bytes();

        // Mine proof-of-work
        let pow_proof = NodeIdProof::mine(&public_key, NODE_ID_POW_DIFFICULTY);

        if pow_proof.is_none() {
            tracing::warn!("Failed to mine node_id proof-of-work after max attempts");
        } else {
            tracing::debug!(
                difficulty = pow_proof.as_ref().map(|p| p.difficulty).unwrap_or(0),
                nonce = pow_proof.as_ref().map(|p| p.nonce).unwrap_or(0),
                "Node identity proof-of-work mined"
            );
        }

        Self {
            signing_key,
            verifying_key,
            pow_proof,
            display_name: None,
        }
    }

    /// Create identity without proof-of-work (for testing only)
    #[cfg(test)]
    pub fn generate_without_pow() -> Self {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
            pow_proof: None,
            display_name: None,
        }
    }

    /// Load identity from a key file (44 bytes: 32 key + 12 PoW proof)
    /// Legacy 32-byte files are supported but will lack PoW proof
    pub fn load<P: AsRef<Path>>(path: P) -> GhostResult<Self> {
        let path = path.as_ref();

        if !path.exists() {
            return Err(GhostError::KeyFileNotFound(
                path.to_string_lossy().to_string(),
            ));
        }

        let key_bytes = fs::read(path)
            .map_err(|e| GhostError::InvalidKey(format!("Failed to read key file: {}", e)))?;

        // Support both legacy (32 bytes) and new format (44 bytes with PoW)
        if key_bytes.len() != 32 && key_bytes.len() != 44 {
            return Err(GhostError::InvalidKey(format!(
                "Invalid key length: expected 32 or 44, got {}",
                key_bytes.len()
            )));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes[..32]);

        let signing_key = SigningKey::from_bytes(&key_array);
        let verifying_key = signing_key.verifying_key();

        // Extract PoW proof if present
        let pow_proof = if key_bytes.len() == 44 {
            NodeIdProof::from_bytes(&key_bytes[32..])
        } else {
            // Legacy key without PoW - mine one now
            let public_key = verifying_key.to_bytes();
            NodeIdProof::mine(&public_key, NODE_ID_POW_DIFFICULTY)
        };

        Ok(Self {
            signing_key,
            verifying_key,
            pow_proof,
            display_name: None,
        })
    }

    /// Load identity from hex-encoded string (private key only, will mine PoW)
    pub fn from_hex(hex_str: &str) -> GhostResult<Self> {
        let key_bytes = hex::decode(hex_str)
            .map_err(|e| GhostError::InvalidKey(format!("Invalid hex: {}", e)))?;

        if key_bytes.len() != 32 {
            return Err(GhostError::InvalidKey(format!(
                "Invalid key length: expected 32, got {}",
                key_bytes.len()
            )));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);

        let signing_key = SigningKey::from_bytes(&key_array);
        let verifying_key = signing_key.verifying_key();
        let public_key = verifying_key.to_bytes();

        // Mine proof-of-work
        let pow_proof = NodeIdProof::mine(&public_key, NODE_ID_POW_DIFFICULTY);

        Ok(Self {
            signing_key,
            verifying_key,
            pow_proof,
            display_name: None,
        })
    }

    /// Load identity with existing PoW proof (for database restoration)
    pub fn from_hex_with_proof(hex_str: &str, proof_hex: &str) -> GhostResult<Self> {
        let key_bytes = hex::decode(hex_str)
            .map_err(|e| GhostError::InvalidKey(format!("Invalid hex: {}", e)))?;

        if key_bytes.len() != 32 {
            return Err(GhostError::InvalidKey(format!(
                "Invalid key length: expected 32, got {}",
                key_bytes.len()
            )));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);

        let signing_key = SigningKey::from_bytes(&key_array);
        let verifying_key = signing_key.verifying_key();

        let pow_proof = NodeIdProof::from_hex(proof_hex);

        // Verify the proof is valid for this key
        if let Some(ref proof) = pow_proof {
            let public_key = verifying_key.to_bytes();
            if !proof.verify(&public_key, NODE_ID_POW_DIFFICULTY) {
                return Err(GhostError::InvalidKey(
                    "PoW proof does not match public key".into(),
                ));
            }
        }

        Ok(Self {
            signing_key,
            verifying_key,
            pow_proof,
            display_name: None,
        })
    }

    /// Save identity to a key file (44 bytes: 32 key + 12 PoW proof)
    pub fn save<P: AsRef<Path>>(&self, path: P) -> GhostResult<()> {
        let path = path.as_ref();

        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Build 44-byte output: private key + PoW proof
        let mut output = Vec::with_capacity(44);
        output.extend_from_slice(&self.signing_key.to_bytes());

        if let Some(ref proof) = self.pow_proof {
            output.extend_from_slice(&proof.to_bytes());
        } else {
            // No proof - write zeros (legacy compatibility)
            output.extend_from_slice(&[0u8; 12]);
        }

        fs::write(path, &output)?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            fs::set_permissions(path, perms)?;
        }

        Ok(())
    }

    /// Get the node ID (public key bytes)
    pub fn node_id(&self) -> NodeId {
        self.verifying_key.to_bytes()
    }

    /// Get the node ID as hex string
    pub fn node_id_hex(&self) -> String {
        hex::encode(self.node_id())
    }

    /// Get the short node ID (first 8 chars of hex)
    pub fn node_id_short(&self) -> String {
        self.node_id_hex()[..8].to_string()
    }

    /// Get the verifying key for signature verification
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Get the proof-of-work proof
    pub fn pow_proof(&self) -> Option<&NodeIdProof> {
        self.pow_proof.as_ref()
    }

    /// Get the PoW proof as hex string (for database storage)
    pub fn pow_proof_hex(&self) -> Option<String> {
        self.pow_proof.as_ref().map(|p| p.to_hex())
    }

    /// Check if this identity has a valid proof-of-work
    pub fn has_valid_pow(&self) -> bool {
        if let Some(ref proof) = self.pow_proof {
            let public_key = self.verifying_key.to_bytes();
            proof.verify(&public_key, NODE_ID_POW_DIFFICULTY)
        } else {
            false
        }
    }

    /// Get the achieved PoW difficulty (leading zero bits)
    pub fn pow_difficulty(&self) -> u32 {
        self.pow_proof.as_ref().map(|p| p.difficulty).unwrap_or(0)
    }

    /// Set display name
    pub fn set_display_name(&mut self, name: impl Into<String>) {
        self.display_name = Some(name.into());
    }

    /// Get display name
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signature: Signature = self.signing_key.sign(message);
        signature.to_bytes()
    }

    /// Sign a hash (for consensus messages)
    pub fn sign_hash(&self, hash: &[u8; 32]) -> [u8; 64] {
        self.sign(hash)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        let sig = Signature::from_bytes(signature);
        self.verifying_key.verify(message, &sig).is_ok()
    }
}

/// Verify a signature from a remote node
pub fn verify_signature(
    node_id: &NodeId,
    message: &[u8],
    signature: &[u8; 64],
) -> GhostResult<bool> {
    let verifying_key = VerifyingKey::from_bytes(node_id)
        .map_err(|e| GhostError::InvalidKey(format!("Invalid public key: {}", e)))?;

    let sig = Signature::from_bytes(signature);

    Ok(verifying_key.verify(message, &sig).is_ok())
}

/// Verify a remote node_id has valid proof-of-work
/// This should be checked when accepting elder registrations
pub fn verify_node_id_pow(node_id: &NodeId, proof: &NodeIdProof, required_difficulty: u32) -> bool {
    proof.verify(node_id, required_difficulty)
}

/// Verify node_id PoW from hex strings (convenience for database values)
pub fn verify_node_id_pow_hex(
    node_id_hex: &str,
    proof_hex: &str,
    required_difficulty: u32,
) -> bool {
    let node_id_bytes = match hex::decode(node_id_hex) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return false,
    };
    let mut node_id = [0u8; 32];
    node_id.copy_from_slice(&node_id_bytes);

    let proof = match NodeIdProof::from_hex(proof_hex) {
        Some(p) => p,
        None => return false,
    };

    proof.verify(&node_id, required_difficulty)
}

/// Hash a message using SHA-256
pub fn hash_message(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Compute proposal hash for consensus
pub fn compute_proposal_hash(
    round_id: u64,
    block_hash: &[u8; 32],
    miner_payouts: &[(Vec<u8>, u64)],
    node_payouts: &[(Vec<u8>, u64)],
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    hasher.update(round_id.to_le_bytes());
    hasher.update(block_hash);

    for (address, amount) in miner_payouts {
        hasher.update(address);
        hasher.update(amount.to_le_bytes());
    }

    for (address, amount) in node_payouts {
        hasher.update(address);
        hasher.update(amount.to_le_bytes());
    }

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generate_identity() {
        let identity = NodeIdentity::generate();
        let node_id = identity.node_id();
        assert_eq!(node_id.len(), 32);
        // New identities should have valid PoW
        assert!(identity.has_valid_pow());
    }

    #[test]
    fn test_pow_proof_mining() {
        let identity = NodeIdentity::generate_without_pow();
        let public_key = identity.node_id();

        // Mine a proof
        let proof = NodeIdProof::mine(&public_key, 8).unwrap(); // Low difficulty for test speed
        assert!(proof.difficulty >= 8);
        assert!(proof.verify(&public_key, 8));

        // Wrong key should fail verification
        let wrong_key = [0u8; 32];
        assert!(!proof.verify(&wrong_key, 8));
    }

    #[test]
    fn test_pow_leading_zeros() {
        // 0x00 has 8 leading zeros
        assert_eq!(
            NodeIdProof::leading_zeros(&[
                0, 0, 0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0
            ]),
            24
        );
        // 0x0f has 4 leading zeros
        assert_eq!(
            NodeIdProof::leading_zeros(&[
                0x0f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0
            ]),
            4
        );
        // 0x80 has 0 leading zeros
        assert_eq!(
            NodeIdProof::leading_zeros(&[
                0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0
            ]),
            0
        );
    }

    #[test]
    fn test_pow_serialization() {
        let proof = NodeIdProof {
            nonce: 12345678,
            difficulty: 20,
        };

        let hex = proof.to_hex();
        let restored = NodeIdProof::from_hex(&hex).unwrap();

        assert_eq!(restored.nonce, proof.nonce);
        assert_eq!(restored.difficulty, proof.difficulty);
    }

    #[test]
    fn test_sign_verify() {
        let identity = NodeIdentity::generate();
        let message = b"Hello, Ghost!";

        let signature = identity.sign(message);
        assert!(identity.verify(message, &signature));

        // Wrong message should fail
        assert!(!identity.verify(b"Wrong message", &signature));
    }

    #[test]
    fn test_save_load() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test.key");

        let identity = NodeIdentity::generate();
        let original_node_id = identity.node_id();
        let original_pow = identity.pow_proof().cloned();

        identity.save(&key_path).unwrap();
        let loaded = NodeIdentity::load(&key_path).unwrap();

        assert_eq!(loaded.node_id(), original_node_id);
        // PoW should also be preserved
        if let Some(orig) = original_pow {
            let loaded_pow = loaded.pow_proof().unwrap();
            assert_eq!(loaded_pow.nonce, orig.nonce);
            assert_eq!(loaded_pow.difficulty, orig.difficulty);
        }
    }

    #[test]
    fn test_from_hex() {
        let identity = NodeIdentity::generate_without_pow();
        let hex = hex::encode(identity.signing_key.to_bytes());

        let loaded = NodeIdentity::from_hex(&hex).unwrap();
        assert_eq!(loaded.node_id(), identity.node_id());
        // from_hex mines a new PoW
        assert!(loaded.has_valid_pow());
    }

    #[test]
    fn test_verify_remote_signature() {
        let identity = NodeIdentity::generate();
        let message = b"Consensus vote";
        let signature = identity.sign(message);

        let result = verify_signature(&identity.node_id(), message, &signature).unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_node_id_pow() {
        let identity = NodeIdentity::generate();
        let proof = identity.pow_proof().unwrap();

        assert!(verify_node_id_pow(
            &identity.node_id(),
            proof,
            NODE_ID_POW_DIFFICULTY
        ));
    }

    #[test]
    fn test_verify_node_id_pow_hex() {
        let identity = NodeIdentity::generate();
        let node_id_hex = identity.node_id_hex();
        let proof_hex = identity.pow_proof_hex().unwrap();

        assert!(verify_node_id_pow_hex(
            &node_id_hex,
            &proof_hex,
            NODE_ID_POW_DIFFICULTY
        ));
    }

    #[test]
    fn test_hash_message() {
        let message = b"Test message";
        let hash = hash_message(message);
        assert_eq!(hash.len(), 32);

        // Same message should produce same hash
        let hash2 = hash_message(message);
        assert_eq!(hash, hash2);

        // Different message should produce different hash
        let hash3 = hash_message(b"Different message");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_node_id_short() {
        let identity = NodeIdentity::generate();
        let short = identity.node_id_short();
        assert_eq!(short.len(), 8);
        assert!(identity.node_id_hex().starts_with(&short));
    }
}
