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
        }
    }

    /// Compute the commitment hash
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"ghost_commitment_v1");
        hasher.update(&self.batch_id);
        hasher.update(&self.merkle_root);
        hasher.update(&self.settlement_count.to_le_bytes());
        hasher.update(&self.total_amount_sats.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
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

    /// Decode from OP_RETURN data
    pub fn decode_op_return(data: &[u8]) -> Option<PartialCommitment> {
        if data.len() < 55 {
            return None;
        }

        // Check magic
        if &data[0..5] != b"GHOST" {
            return None;
        }

        // Check version
        if data[5] != 0x01 {
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
}

impl PartialCommitment {
    /// Check if this matches a full commitment
    pub fn matches(&self, commitment: &L1Commitment) -> bool {
        self.batch_id_prefix == commitment.batch_id[..8]
            && self.merkle_root == commitment.merkle_root
            && self.settlement_count == commitment.settlement_count
            && self.total_amount_sats == commitment.total_amount_sats
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
    }

    #[test]
    fn test_op_return_encoding() {
        let commitment = L1Commitment::new([1u8; 32], [2u8; 32], 100, 10_000_000_000);

        let encoded = commitment.encode_op_return();
        assert!(encoded.len() <= 80); // OP_RETURN limit

        let decoded = L1Commitment::decode_op_return(&encoded).unwrap();
        assert!(decoded.matches(&commitment));
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
}
