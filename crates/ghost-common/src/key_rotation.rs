//! Secure key rotation with elder status transfer
//!
//! This module provides cryptographic proofs for rotating node identity keys
//! while preserving elder status. The design prevents:
//!
//! - **Identity theft**: Requires signatures from BOTH old and new keys
//! - **Replay attacks**: Timestamped proofs expire after 1 hour
//! - **Double rotation**: Old node_id is permanently retired after rotation
//! - **Mass attacks**: Optional PoW requirement on rotation proofs
//!
//! ## Security Model
//!
//! A valid rotation proof requires:
//! 1. The old private key signs the new public key (proves ownership of old identity)
//! 2. The new private key signs the old public key (proves control of destination)
//! 3. Both signatures include a timestamp that must be recent
//! 4. The old node_id must not already be retired
//!
//! This dual-signature scheme ensures that:
//! - Only the legitimate owner can initiate rotation (old key signature)
//! - Nobody can redirect your identity to their key without your new key (new key signature)

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{GhostError, GhostResult};
use crate::identity::NodeIdentity;
use crate::types::NodeId;

/// Maximum age of a rotation proof before it's considered expired (1 hour)
pub const ROTATION_PROOF_MAX_AGE_SECS: u64 = 3600;

/// Minimum age before a rotation can be finalized (grace period for revocation)
/// During this window, the old key can revoke the rotation
pub const ROTATION_GRACE_PERIOD_SECS: u64 = 300; // 5 minutes

/// Optional PoW difficulty for rotation proofs (0 = disabled)
/// 16 bits = ~65k hashes, adds slight cost to mass rotation attempts
pub const ROTATION_POW_DIFFICULTY: u32 = 16;

/// Cryptographic proof linking old and new node identities
///
/// This proof demonstrates that:
/// 1. The holder of the old private key authorized the rotation
/// 2. The holder of the new private key consented to receive the transfer
/// 3. The proof was created recently (not a replay)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRotationProof {
    /// The node_id (public key) being rotated FROM
    #[serde(with = "crate::serde_hex::bytes32")]
    pub old_node_id: NodeId,

    /// The node_id (public key) being rotated TO
    #[serde(with = "crate::serde_hex::bytes32")]
    pub new_node_id: NodeId,

    /// Unix timestamp when this rotation was initiated
    pub timestamp: u64,

    /// Nonce for PoW (if required) and uniqueness
    pub nonce: u64,

    /// Signature by OLD private key of: SHA256(new_node_id || timestamp || nonce || "rotate_from")
    /// This proves the old identity owner authorized this rotation
    #[serde(with = "crate::serde_hex::bytes64")]
    pub old_key_signature: [u8; 64],

    /// Signature by NEW private key of: SHA256(old_node_id || timestamp || nonce || "rotate_to")
    /// This proves the new identity owner consented to receive the transfer
    /// Prevents someone from rotating your identity to their controlled key
    #[serde(with = "crate::serde_hex::bytes64")]
    pub new_key_signature: [u8; 64],
}

impl KeyRotationProof {
    /// Create a new rotation proof
    ///
    /// This requires access to BOTH the old and new private keys.
    /// The proof cryptographically links the two identities.
    ///
    /// # Arguments
    /// * `old_identity` - The current identity being rotated from
    /// * `new_identity` - The new identity being rotated to
    ///
    /// # Returns
    /// A rotation proof that can be verified by anyone with the public keys
    pub fn create(old_identity: &NodeIdentity, new_identity: &NodeIdentity) -> GhostResult<Self> {
        let old_node_id = old_identity.node_id();
        let new_node_id = new_identity.node_id();

        // Prevent rotating to self
        if old_node_id == new_node_id {
            return Err(GhostError::InvalidKey(
                "Cannot rotate to the same identity".to_string(),
            ));
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| GhostError::InvalidKey(format!("System time error: {}", e)))?
            .as_secs();

        // Find a nonce that satisfies PoW (if required)
        let nonce = if ROTATION_POW_DIFFICULTY > 0 {
            Self::mine_nonce(
                &old_node_id,
                &new_node_id,
                timestamp,
                ROTATION_POW_DIFFICULTY,
            )?
        } else {
            0
        };

        // Create the messages to sign
        let old_key_message = Self::create_old_key_message(&new_node_id, timestamp, nonce);
        let new_key_message = Self::create_new_key_message(&old_node_id, timestamp, nonce);

        // Sign with both keys
        let old_key_signature = old_identity.sign(&old_key_message);
        let new_key_signature = new_identity.sign(&new_key_message);

        Ok(Self {
            old_node_id,
            new_node_id,
            timestamp,
            nonce,
            old_key_signature,
            new_key_signature,
        })
    }

    /// Verify the rotation proof is valid
    ///
    /// Checks:
    /// 1. Old key signature is valid
    /// 2. New key signature is valid
    /// 3. Timestamp is recent (not expired)
    /// 4. PoW is valid (if required)
    /// 5. Not rotating to self
    ///
    /// Note: This does NOT check if the old_node_id is already retired.
    /// The database layer must check that separately.
    pub fn verify(&self) -> GhostResult<()> {
        // Check not rotating to self
        if self.old_node_id == self.new_node_id {
            return Err(GhostError::SignatureVerification(
                "Cannot rotate to the same identity".to_string(),
            ));
        }

        // Check timestamp is recent
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| GhostError::InvalidKey(format!("System time error: {}", e)))?
            .as_secs();

        if self.timestamp > now {
            return Err(GhostError::SignatureVerification(
                "Rotation proof timestamp is in the future".to_string(),
            ));
        }

        let age = now.saturating_sub(self.timestamp);
        if age > ROTATION_PROOF_MAX_AGE_SECS {
            return Err(GhostError::SignatureVerification(format!(
                "Rotation proof expired ({} seconds old, max {} seconds)",
                age, ROTATION_PROOF_MAX_AGE_SECS
            )));
        }

        // Verify PoW if required
        if ROTATION_POW_DIFFICULTY > 0 && !self.verify_pow(ROTATION_POW_DIFFICULTY) {
            return Err(GhostError::SignatureVerification(
                "Rotation proof PoW is invalid".to_string(),
            ));
        }

        // Verify old key signature
        let old_key_message =
            Self::create_old_key_message(&self.new_node_id, self.timestamp, self.nonce);
        Self::verify_signature(&self.old_node_id, &old_key_message, &self.old_key_signature)
            .map_err(|e| {
                GhostError::SignatureVerification(format!("Old key signature invalid: {}", e))
            })?;

        // Verify new key signature
        let new_key_message =
            Self::create_new_key_message(&self.old_node_id, self.timestamp, self.nonce);
        Self::verify_signature(&self.new_node_id, &new_key_message, &self.new_key_signature)
            .map_err(|e| {
                GhostError::SignatureVerification(format!("New key signature invalid: {}", e))
            })?;

        Ok(())
    }

    /// Check if the proof is still in the grace period
    ///
    /// During the grace period, the old key can revoke the rotation.
    pub fn in_grace_period(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let age = now.saturating_sub(self.timestamp);
        age < ROTATION_GRACE_PERIOD_SECS
    }

    /// Get the age of the proof in seconds
    pub fn age_secs(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        now.saturating_sub(self.timestamp)
    }

    /// Create the message that the old key signs
    fn create_old_key_message(new_node_id: &NodeId, timestamp: u64, nonce: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(new_node_id);
        hasher.update(timestamp.to_le_bytes());
        hasher.update(nonce.to_le_bytes());
        hasher.update(b"rotate_from");
        hasher.finalize().into()
    }

    /// Create the message that the new key signs
    fn create_new_key_message(old_node_id: &NodeId, timestamp: u64, nonce: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(old_node_id);
        hasher.update(timestamp.to_le_bytes());
        hasher.update(nonce.to_le_bytes());
        hasher.update(b"rotate_to");
        hasher.finalize().into()
    }

    /// Verify a signature against a public key
    fn verify_signature(
        public_key: &NodeId,
        message: &[u8; 32],
        signature: &[u8; 64],
    ) -> GhostResult<()> {
        let verifying_key = VerifyingKey::from_bytes(public_key)
            .map_err(|e| GhostError::InvalidKey(format!("Invalid public key: {}", e)))?;

        let sig = Signature::from_bytes(signature);

        verifying_key.verify(message, &sig).map_err(|e| {
            GhostError::SignatureVerification(format!("Signature verification failed: {}", e))
        })
    }

    /// Compute PoW hash for mining
    fn compute_pow_hash(
        old_node_id: &NodeId,
        new_node_id: &NodeId,
        timestamp: u64,
        nonce: u64,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(old_node_id);
        hasher.update(new_node_id);
        hasher.update(timestamp.to_le_bytes());
        hasher.update(nonce.to_le_bytes());
        hasher.update(b"rotation_pow");
        hasher.finalize().into()
    }

    /// Count leading zero bits
    fn leading_zeros(hash: &[u8; 32]) -> u32 {
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

    /// Mine a nonce that satisfies PoW requirement
    fn mine_nonce(
        old_node_id: &NodeId,
        new_node_id: &NodeId,
        timestamp: u64,
        difficulty: u32,
    ) -> GhostResult<u64> {
        const MAX_ATTEMPTS: u64 = 100_000_000;

        for nonce in 0..MAX_ATTEMPTS {
            let hash = Self::compute_pow_hash(old_node_id, new_node_id, timestamp, nonce);
            if Self::leading_zeros(&hash) >= difficulty {
                return Ok(nonce);
            }
        }

        Err(GhostError::InvalidKey(
            "Failed to find PoW nonce (max attempts exceeded)".to_string(),
        ))
    }

    /// Verify the PoW is valid
    fn verify_pow(&self, difficulty: u32) -> bool {
        let hash = Self::compute_pow_hash(
            &self.old_node_id,
            &self.new_node_id,
            self.timestamp,
            self.nonce,
        );
        Self::leading_zeros(&hash) >= difficulty
    }

    /// Serialize to bytes for storage/transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 32 + 8 + 8 + 64 + 64);
        bytes.extend_from_slice(&self.old_node_id);
        bytes.extend_from_slice(&self.new_node_id);
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes.extend_from_slice(&self.old_key_signature);
        bytes.extend_from_slice(&self.new_key_signature);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> GhostResult<Self> {
        const EXPECTED_LEN: usize = 32 + 32 + 8 + 8 + 64 + 64; // 208 bytes

        if bytes.len() != EXPECTED_LEN {
            return Err(GhostError::InvalidKey(format!(
                "Invalid rotation proof length: expected {}, got {}",
                EXPECTED_LEN,
                bytes.len()
            )));
        }

        let mut old_node_id = [0u8; 32];
        let mut new_node_id = [0u8; 32];
        let mut timestamp_bytes = [0u8; 8];
        let mut nonce_bytes = [0u8; 8];
        let mut old_key_signature = [0u8; 64];
        let mut new_key_signature = [0u8; 64];

        old_node_id.copy_from_slice(&bytes[0..32]);
        new_node_id.copy_from_slice(&bytes[32..64]);
        timestamp_bytes.copy_from_slice(&bytes[64..72]);
        nonce_bytes.copy_from_slice(&bytes[72..80]);
        old_key_signature.copy_from_slice(&bytes[80..144]);
        new_key_signature.copy_from_slice(&bytes[144..208]);

        Ok(Self {
            old_node_id,
            new_node_id,
            timestamp: u64::from_le_bytes(timestamp_bytes),
            nonce: u64::from_le_bytes(nonce_bytes),
            old_key_signature,
            new_key_signature,
        })
    }
}

/// Revocation of a pending rotation (during grace period)
///
/// The old key can revoke a rotation during the grace period if:
/// - The new key was compromised before transfer completed
/// - The rotation was initiated by mistake
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotationRevocation {
    /// The rotation proof being revoked
    #[serde(with = "crate::serde_hex::bytes32")]
    pub rotation_proof_hash: [u8; 32],

    /// The old node_id (must match the rotation proof)
    #[serde(with = "crate::serde_hex::bytes32")]
    pub old_node_id: NodeId,

    /// Timestamp of revocation
    pub timestamp: u64,

    /// Signature by OLD private key of: SHA256(rotation_proof_hash || timestamp || "revoke")
    #[serde(with = "crate::serde_hex::bytes64")]
    pub signature: [u8; 64],
}

impl RotationRevocation {
    /// Create a revocation for a rotation proof
    pub fn create(
        rotation_proof: &KeyRotationProof,
        old_identity: &NodeIdentity,
    ) -> GhostResult<Self> {
        // Verify this identity matches the rotation proof
        if old_identity.node_id() != rotation_proof.old_node_id {
            return Err(GhostError::InvalidKey(
                "Identity does not match rotation proof".to_string(),
            ));
        }

        // Check rotation is still in grace period
        if !rotation_proof.in_grace_period() {
            return Err(GhostError::InvalidKey(
                "Rotation is past grace period, cannot revoke".to_string(),
            ));
        }

        let rotation_proof_hash = Self::hash_rotation_proof(rotation_proof);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| GhostError::InvalidKey(format!("System time error: {}", e)))?
            .as_secs();

        let message = Self::create_message(&rotation_proof_hash, timestamp);
        let signature = old_identity.sign(&message);

        Ok(Self {
            rotation_proof_hash,
            old_node_id: old_identity.node_id(),
            timestamp,
            signature,
        })
    }

    /// Verify the revocation is valid
    pub fn verify(&self, rotation_proof: &KeyRotationProof) -> GhostResult<()> {
        // Verify the hash matches
        let expected_hash = Self::hash_rotation_proof(rotation_proof);
        if self.rotation_proof_hash != expected_hash {
            return Err(GhostError::SignatureVerification(
                "Revocation hash does not match rotation proof".to_string(),
            ));
        }

        // Verify old_node_id matches
        if self.old_node_id != rotation_proof.old_node_id {
            return Err(GhostError::SignatureVerification(
                "Revocation old_node_id does not match rotation proof".to_string(),
            ));
        }

        // Verify signature
        let message = Self::create_message(&self.rotation_proof_hash, self.timestamp);
        KeyRotationProof::verify_signature(&self.old_node_id, &message, &self.signature)?;

        Ok(())
    }

    fn hash_rotation_proof(proof: &KeyRotationProof) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(proof.to_bytes());
        hasher.finalize().into()
    }

    fn create_message(rotation_proof_hash: &[u8; 32], timestamp: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(rotation_proof_hash);
        hasher.update(timestamp.to_le_bytes());
        hasher.update(b"revoke");
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_verify_rotation_proof() {
        let old_identity = NodeIdentity::generate();
        let new_identity = NodeIdentity::generate();

        let proof = KeyRotationProof::create(&old_identity, &new_identity).unwrap();

        // Verify the proof
        assert!(proof.verify().is_ok());

        // Check fields
        assert_eq!(proof.old_node_id, old_identity.node_id());
        assert_eq!(proof.new_node_id, new_identity.node_id());
    }

    #[test]
    fn test_cannot_rotate_to_self() {
        let identity = NodeIdentity::generate();

        let result = KeyRotationProof::create(&identity, &identity);
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_serialization() {
        let old_identity = NodeIdentity::generate();
        let new_identity = NodeIdentity::generate();

        let proof = KeyRotationProof::create(&old_identity, &new_identity).unwrap();
        let bytes = proof.to_bytes();
        let restored = KeyRotationProof::from_bytes(&bytes).unwrap();

        assert_eq!(proof, restored);
        assert!(restored.verify().is_ok());
    }

    #[test]
    fn test_tampered_proof_fails_verification() {
        let old_identity = NodeIdentity::generate();
        let new_identity = NodeIdentity::generate();

        let mut proof = KeyRotationProof::create(&old_identity, &new_identity).unwrap();

        // Tamper with the new_node_id
        proof.new_node_id[0] ^= 0xFF;

        assert!(proof.verify().is_err());
    }

    #[test]
    fn test_wrong_old_key_signature_fails() {
        let old_identity = NodeIdentity::generate();
        let new_identity = NodeIdentity::generate();
        let wrong_identity = NodeIdentity::generate();

        // Create proof with wrong old identity
        let mut proof = KeyRotationProof::create(&old_identity, &new_identity).unwrap();

        // Replace old_key_signature with signature from wrong identity
        let message = KeyRotationProof::create_old_key_message(
            &new_identity.node_id(),
            proof.timestamp,
            proof.nonce,
        );
        proof.old_key_signature = wrong_identity.sign(&message);

        assert!(proof.verify().is_err());
    }

    #[test]
    fn test_wrong_new_key_signature_fails() {
        let old_identity = NodeIdentity::generate();
        let new_identity = NodeIdentity::generate();
        let wrong_identity = NodeIdentity::generate();

        let mut proof = KeyRotationProof::create(&old_identity, &new_identity).unwrap();

        // Replace new_key_signature with signature from wrong identity
        let message = KeyRotationProof::create_new_key_message(
            &old_identity.node_id(),
            proof.timestamp,
            proof.nonce,
        );
        proof.new_key_signature = wrong_identity.sign(&message);

        assert!(proof.verify().is_err());
    }

    #[test]
    fn test_grace_period() {
        let old_identity = NodeIdentity::generate();
        let new_identity = NodeIdentity::generate();

        let proof = KeyRotationProof::create(&old_identity, &new_identity).unwrap();

        // Should be in grace period immediately after creation
        assert!(proof.in_grace_period());
    }

    #[test]
    fn test_revocation() {
        let old_identity = NodeIdentity::generate();
        let new_identity = NodeIdentity::generate();

        let proof = KeyRotationProof::create(&old_identity, &new_identity).unwrap();
        let revocation = RotationRevocation::create(&proof, &old_identity).unwrap();

        assert!(revocation.verify(&proof).is_ok());
    }

    #[test]
    fn test_revocation_wrong_identity_fails() {
        let old_identity = NodeIdentity::generate();
        let new_identity = NodeIdentity::generate();
        let wrong_identity = NodeIdentity::generate();

        let proof = KeyRotationProof::create(&old_identity, &new_identity).unwrap();

        // Try to revoke with wrong identity
        let result = RotationRevocation::create(&proof, &wrong_identity);
        assert!(result.is_err());
    }
}
