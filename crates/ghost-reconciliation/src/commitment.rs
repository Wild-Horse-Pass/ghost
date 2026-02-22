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
//| FILE: commitment.rs                                                                                                  |
//|======================================================================================================================|

//! L1 commitment structures
//!
//! Commitments are published to Bitcoin to anchor L2 settlement batches.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// L1 Commitment - Published to Bitcoin
#[derive(Debug, Clone)]
pub struct L1Commitment {
    /// Batch ID being committed
    pub batch_id: [u8; 32],
    /// Merkle root of settlements
    pub merkle_root: [u8; 32],
    /// Total settlement count
    pub settlement_count: u32,
    /// Total amount in satoshis
    pub total_amount_sats: u64,
    /// Commitment timestamp
    pub timestamp: u64,
    /// Coordinator signature
    pub coordinator_signature: [u8; 64],
    /// Pedersen commitment tree root (confidential transfers)
    pub commitment_tree_root: Option<[u8; 32]>,
    /// Number of nullifiers in this batch window
    pub nullifier_count: Option<u32>,
    /// Merkle root over nullifiers consumed in this batch
    pub nullifier_merkle_root: Option<[u8; 32]>,
}

/// Serializable commitment (for JSON/storage)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L1CommitmentSerializable {
    pub batch_id: String,
    pub merkle_root: String,
    pub settlement_count: u32,
    pub total_amount_sats: u64,
    pub timestamp: u64,
    pub coordinator_signature: String,
    /// Pedersen commitment tree root (hex, confidential transfers)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment_tree_root: Option<String>,
    /// Number of nullifiers in this batch window
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nullifier_count: Option<u32>,
    /// Merkle root over nullifiers consumed in this batch (hex)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nullifier_merkle_root: Option<String>,
}

impl From<&L1Commitment> for L1CommitmentSerializable {
    fn from(c: &L1Commitment) -> Self {
        Self {
            batch_id: hex::encode(c.batch_id),
            merkle_root: hex::encode(c.merkle_root),
            settlement_count: c.settlement_count,
            total_amount_sats: c.total_amount_sats,
            timestamp: c.timestamp,
            coordinator_signature: hex::encode(c.coordinator_signature),
            commitment_tree_root: c.commitment_tree_root.map(hex::encode),
            nullifier_count: c.nullifier_count,
            nullifier_merkle_root: c.nullifier_merkle_root.map(hex::encode),
        }
    }
}

impl From<&L1CommitmentSerializable> for L1Commitment {
    fn from(s: &L1CommitmentSerializable) -> Self {
        let mut batch_id = [0u8; 32];
        if let Ok(bytes) = hex::decode(&s.batch_id) {
            if bytes.len() == 32 {
                batch_id.copy_from_slice(&bytes);
            }
        }

        let mut merkle_root = [0u8; 32];
        if let Ok(bytes) = hex::decode(&s.merkle_root) {
            if bytes.len() == 32 {
                merkle_root.copy_from_slice(&bytes);
            }
        }

        let mut coordinator_signature = [0u8; 64];
        if let Ok(bytes) = hex::decode(&s.coordinator_signature) {
            if bytes.len() == 64 {
                coordinator_signature.copy_from_slice(&bytes);
            }
        }

        let commitment_tree_root = s.commitment_tree_root.as_ref().and_then(|h| {
            let bytes = hex::decode(h).ok()?;
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(arr)
            } else {
                None
            }
        });

        let nullifier_merkle_root = s.nullifier_merkle_root.as_ref().and_then(|h| {
            let bytes = hex::decode(h).ok()?;
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(arr)
            } else {
                None
            }
        });

        Self {
            batch_id,
            merkle_root,
            settlement_count: s.settlement_count,
            total_amount_sats: s.total_amount_sats,
            timestamp: s.timestamp,
            coordinator_signature,
            commitment_tree_root,
            nullifier_count: s.nullifier_count,
            nullifier_merkle_root,
        }
    }
}

impl L1Commitment {
    /// Create a new commitment
    pub fn new(
        batch_id: [u8; 32],
        merkle_root: [u8; 32],
        settlement_count: u32,
        total_amount_sats: u64,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            batch_id,
            merkle_root,
            settlement_count,
            total_amount_sats,
            timestamp,
            coordinator_signature: [0u8; 64],
            commitment_tree_root: None,
            nullifier_count: None,
            nullifier_merkle_root: None,
        }
    }

    /// Compute the commitment hash
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"ghost_commitment_v1");
        hasher.update(self.batch_id);
        hasher.update(self.merkle_root);
        hasher.update(self.settlement_count.to_le_bytes());
        hasher.update(self.total_amount_sats.to_le_bytes());
        hasher.update(self.timestamp.to_le_bytes());
        hasher.finalize().into()
    }

    /// Encode as OP_RETURN data
    ///
    /// Format: "GHOST" || version || batch_id[0..8] || merkle_root || count || amount
    pub fn encode_op_return(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(80);

        // Magic prefix
        data.extend_from_slice(b"GHOST");

        // Version byte
        data.push(0x01);

        // Truncated batch ID (first 8 bytes)
        data.extend_from_slice(&self.batch_id[..8]);

        // Full merkle root
        data.extend_from_slice(&self.merkle_root);

        // Settlement count (4 bytes)
        data.extend_from_slice(&self.settlement_count.to_le_bytes());

        // Total amount (8 bytes)
        data.extend_from_slice(&self.total_amount_sats.to_le_bytes());

        data
    }

    /// Encode as OP_RETURN v2 data (with confidential state)
    ///
    /// V2 format (74 bytes, fits 80-byte limit):
    /// "GHOST" (5) || version=0x02 (1) || batch_id[0..8] (8) || settlement_root (32)
    /// || commitment_tree_root[0..16] (16) || count (4) || amount (8)
    ///
    /// Falls back to v1 format if no commitment_tree_root is present.
    pub fn encode_op_return_v2(&self) -> Vec<u8> {
        let commitment_tree_root = match self.commitment_tree_root {
            Some(root) => root,
            None => return self.encode_op_return(),
        };

        let mut data = Vec::with_capacity(74);

        // Magic prefix
        data.extend_from_slice(b"GHOST");

        // Version byte (v2)
        data.push(0x02);

        // Truncated batch ID (first 8 bytes)
        data.extend_from_slice(&self.batch_id[..8]);

        // Full merkle root (settlement root)
        data.extend_from_slice(&self.merkle_root);

        // Truncated commitment tree root (first 16 bytes)
        data.extend_from_slice(&commitment_tree_root[..16]);

        // Settlement count (4 bytes)
        data.extend_from_slice(&self.settlement_count.to_le_bytes());

        // Total amount (8 bytes)
        data.extend_from_slice(&self.total_amount_sats.to_le_bytes());

        data
    }

    /// Decode from OP_RETURN data (supports v1 and v2)
    pub fn decode_op_return(data: &[u8]) -> Option<PartialCommitment> {
        // Minimum size check: v1 is 58 bytes (5+1+8+32+4+8)
        if data.len() < 58 {
            return None;
        }

        // Check magic
        if &data[0..5] != b"GHOST" {
            return None;
        }

        let version = data[5];

        match version {
            0x01 => Self::decode_op_return_v1(data),
            0x02 => Self::decode_op_return_v2(data),
            _ => None,
        }
    }

    /// Decode v1 OP_RETURN data
    fn decode_op_return_v1(data: &[u8]) -> Option<PartialCommitment> {
        if data.len() < 58 {
            return None;
        }

        let mut batch_id_prefix = [0u8; 8];
        batch_id_prefix.copy_from_slice(&data[6..14]);

        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&data[14..46]);

        let settlement_count = u32::from_le_bytes([data[46], data[47], data[48], data[49]]);
        let total_amount_sats = u64::from_le_bytes([
            data[50], data[51], data[52], data[53], data[54], data[55], data[56], data[57],
        ]);

        Some(PartialCommitment {
            batch_id_prefix,
            merkle_root,
            settlement_count,
            total_amount_sats,
            commitment_tree_root_prefix: None,
        })
    }

    /// Decode v2 OP_RETURN data (with confidential state)
    fn decode_op_return_v2(data: &[u8]) -> Option<PartialCommitment> {
        // v2 is 74 bytes: 5+1+8+32+16+4+8
        if data.len() < 74 {
            return None;
        }

        let mut batch_id_prefix = [0u8; 8];
        batch_id_prefix.copy_from_slice(&data[6..14]);

        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&data[14..46]);

        let mut commitment_tree_root_prefix = [0u8; 16];
        commitment_tree_root_prefix.copy_from_slice(&data[46..62]);

        let settlement_count = u32::from_le_bytes([data[62], data[63], data[64], data[65]]);
        let total_amount_sats = u64::from_le_bytes([
            data[66], data[67], data[68], data[69], data[70], data[71], data[72], data[73],
        ]);

        Some(PartialCommitment {
            batch_id_prefix,
            merkle_root,
            settlement_count,
            total_amount_sats,
            commitment_tree_root_prefix: Some(commitment_tree_root_prefix),
        })
    }
}

/// Partial commitment (decoded from OP_RETURN)
#[derive(Debug, Clone)]
pub struct PartialCommitment {
    /// First 8 bytes of batch ID
    pub batch_id_prefix: [u8; 8],
    /// Full merkle root
    pub merkle_root: [u8; 32],
    /// Settlement count
    pub settlement_count: u32,
    /// Total amount
    pub total_amount_sats: u64,
    /// First 16 bytes of commitment tree root (v2 only)
    pub commitment_tree_root_prefix: Option<[u8; 16]>,
}

impl PartialCommitment {
    /// Check if this matches a full commitment
    pub fn matches(&self, commitment: &L1Commitment) -> bool {
        let base_match = self.batch_id_prefix == commitment.batch_id[..8]
            && self.merkle_root == commitment.merkle_root
            && self.settlement_count == commitment.settlement_count
            && self.total_amount_sats == commitment.total_amount_sats;

        if !base_match {
            return false;
        }

        // If v2 partial has a commitment tree root prefix, verify it matches
        if let Some(prefix) = &self.commitment_tree_root_prefix {
            match &commitment.commitment_tree_root {
                Some(full_root) => {
                    if *prefix != full_root[..16] {
                        return false;
                    }
                }
                // v2 partial but commitment has no tree root -- mismatch
                None => return false,
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_creation() {
        let commitment = L1Commitment::new([1u8; 32], [2u8; 32], 100, 10_000_000_000);

        assert_eq!(commitment.settlement_count, 100);
        assert_eq!(commitment.total_amount_sats, 10_000_000_000);
        assert!(commitment.commitment_tree_root.is_none());
        assert!(commitment.nullifier_count.is_none());
        assert!(commitment.nullifier_merkle_root.is_none());
    }

    #[test]
    fn test_op_return_encoding() {
        let commitment = L1Commitment::new([1u8; 32], [2u8; 32], 100, 10_000_000_000);

        let encoded = commitment.encode_op_return();
        assert!(encoded.len() <= 80); // OP_RETURN limit
        assert_eq!(encoded.len(), 58); // v1 is exactly 58 bytes

        let decoded = L1Commitment::decode_op_return(&encoded).unwrap();
        assert!(decoded.matches(&commitment));
        assert!(decoded.commitment_tree_root_prefix.is_none());
    }

    #[test]
    fn test_commitment_hash() {
        let commitment = L1Commitment::new([1u8; 32], [2u8; 32], 100, 10_000_000_000);

        let hash = commitment.hash();
        assert_ne!(hash, [0u8; 32]);

        // Hash should be deterministic
        let hash2 = commitment.hash();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_op_return_v2_roundtrip() {
        let mut commitment = L1Commitment::new([1u8; 32], [2u8; 32], 100, 10_000_000_000);
        commitment.commitment_tree_root = Some([0xABu8; 32]);

        let encoded = commitment.encode_op_return_v2();
        assert_eq!(encoded.len(), 74); // v2 is exactly 74 bytes
        assert!(encoded.len() <= 80); // Fits OP_RETURN limit
        assert_eq!(encoded[5], 0x02); // Version byte is 0x02

        let decoded = L1Commitment::decode_op_return(&encoded).unwrap();
        assert!(decoded.matches(&commitment));

        // Verify the commitment tree root prefix was decoded
        let prefix = decoded
            .commitment_tree_root_prefix
            .expect("v2 should have commitment_tree_root_prefix");
        assert_eq!(prefix, [0xABu8; 16]);
    }

    #[test]
    fn test_op_return_v2_fallback_to_v1() {
        // When commitment_tree_root is None, encode_op_return_v2 falls back to v1
        let commitment = L1Commitment::new([1u8; 32], [2u8; 32], 50, 5_000_000);

        let v1_encoded = commitment.encode_op_return();
        let v2_encoded = commitment.encode_op_return_v2();

        assert_eq!(v1_encoded, v2_encoded);
        assert_eq!(v2_encoded[5], 0x01); // Falls back to v1 version byte
    }

    #[test]
    fn test_partial_commitment_v1_no_prefix() {
        let commitment = L1Commitment::new([3u8; 32], [4u8; 32], 200, 50_000_000);

        let encoded = commitment.encode_op_return();
        let decoded = L1Commitment::decode_op_return(&encoded).unwrap();

        assert!(decoded.commitment_tree_root_prefix.is_none());
        assert!(decoded.matches(&commitment));
    }

    #[test]
    fn test_partial_commitment_v2_with_prefix() {
        let mut commitment = L1Commitment::new([5u8; 32], [6u8; 32], 300, 99_000_000);
        commitment.commitment_tree_root = Some([0xCDu8; 32]);

        let encoded = commitment.encode_op_return_v2();
        let decoded = L1Commitment::decode_op_return(&encoded).unwrap();

        assert!(decoded.commitment_tree_root_prefix.is_some());
        assert!(decoded.matches(&commitment));

        // Verify the prefix matches the first 16 bytes of commitment_tree_root
        let prefix = decoded.commitment_tree_root_prefix.unwrap();
        assert_eq!(prefix, commitment.commitment_tree_root.unwrap()[..16]);
    }

    #[test]
    fn test_partial_commitment_v2_mismatch_without_tree_root() {
        // A v2 partial should NOT match a commitment without commitment_tree_root
        let commitment = L1Commitment::new([7u8; 32], [8u8; 32], 10, 100_000);

        // Manually construct a v2 partial that has a prefix
        let partial = PartialCommitment {
            batch_id_prefix: {
                let mut p = [0u8; 8];
                p.copy_from_slice(&commitment.batch_id[..8]);
                p
            },
            merkle_root: commitment.merkle_root,
            settlement_count: commitment.settlement_count,
            total_amount_sats: commitment.total_amount_sats,
            commitment_tree_root_prefix: Some([0xFFu8; 16]),
        };

        // Should fail because commitment has no commitment_tree_root
        assert!(!partial.matches(&commitment));
    }

    #[test]
    fn test_serializable_roundtrip_with_confidential_fields() {
        let mut commitment = L1Commitment::new([9u8; 32], [10u8; 32], 42, 1_000_000);
        commitment.commitment_tree_root = Some([0xBBu8; 32]);
        commitment.nullifier_count = Some(7);
        commitment.nullifier_merkle_root = Some([0xCCu8; 32]);

        let serializable = L1CommitmentSerializable::from(&commitment);
        assert_eq!(
            serializable.commitment_tree_root,
            Some(hex::encode([0xBBu8; 32]))
        );
        assert_eq!(serializable.nullifier_count, Some(7));
        assert_eq!(
            serializable.nullifier_merkle_root,
            Some(hex::encode([0xCCu8; 32]))
        );

        let restored = L1Commitment::from(&serializable);
        assert_eq!(
            restored.commitment_tree_root,
            commitment.commitment_tree_root
        );
        assert_eq!(restored.nullifier_count, commitment.nullifier_count);
        assert_eq!(
            restored.nullifier_merkle_root,
            commitment.nullifier_merkle_root
        );
    }

    #[test]
    fn test_serializable_roundtrip_without_confidential_fields() {
        let commitment = L1Commitment::new([11u8; 32], [12u8; 32], 55, 2_000_000);

        let serializable = L1CommitmentSerializable::from(&commitment);
        assert!(serializable.commitment_tree_root.is_none());
        assert!(serializable.nullifier_count.is_none());
        assert!(serializable.nullifier_merkle_root.is_none());

        let restored = L1Commitment::from(&serializable);
        assert!(restored.commitment_tree_root.is_none());
        assert!(restored.nullifier_count.is_none());
        assert!(restored.nullifier_merkle_root.is_none());
    }
}
