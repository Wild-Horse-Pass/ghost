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
//| FILE: proof.rs                                                                                                       |
//|======================================================================================================================|

//! Settlement proofs for users

use serde::{Deserialize, Serialize};

use crate::batch::verify_merkle_proof;
use crate::error::{ReconciliationError, ReconciliationResult};

/// Proof of settlement for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementProof {
    /// Settlement hash (leaf)
    pub settlement_hash: [u8; 32],
    /// Merkle proof path
    pub merkle_proof: Vec<[u8; 32]>,
    /// Index in batch
    pub index: usize,
    /// Total leaf count in batch (required for collision-resistant verification)
    pub leaf_count: usize,
    /// Batch merkle root
    pub merkle_root: [u8; 32],
    /// Batch ID
    pub batch_id: [u8; 32],
    /// L1 transaction ID
    pub l1_txid: String,
    /// L1 block height
    pub l1_height: u32,
    /// L1 block hash
    pub l1_block_hash: String,
}

impl SettlementProof {
    /// Verify the merkle proof
    pub fn verify(&self) -> ReconciliationResult<()> {
        if self.index >= self.leaf_count {
            return Err(ReconciliationError::InvalidProof {
                reason: format!("Index {} >= leaf count {}", self.index, self.leaf_count),
            });
        }

        if !verify_merkle_proof(
            &self.settlement_hash,
            &self.merkle_proof,
            &self.merkle_root,
            self.index,
            self.leaf_count,
        ) {
            return Err(ReconciliationError::InvalidProof {
                reason: "Merkle proof verification failed".to_string(),
            });
        }

        Ok(())
    }

    /// Encode as compact bytes for sharing
    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Version (0x02 for new format with leaf_count)
        data.push(0x02);

        // Settlement hash
        data.extend_from_slice(&self.settlement_hash);

        // Merkle root
        data.extend_from_slice(&self.merkle_root);

        // Batch ID (first 8 bytes)
        data.extend_from_slice(&self.batch_id[..8]);

        // Index
        data.extend_from_slice(&(self.index as u32).to_le_bytes());

        // Leaf count (required for collision-resistant verification)
        data.extend_from_slice(&(self.leaf_count as u32).to_le_bytes());

        // Proof length
        data.push(self.merkle_proof.len() as u8);

        // Proof elements
        for elem in &self.merkle_proof {
            data.extend_from_slice(elem);
        }

        // L1 height
        data.extend_from_slice(&self.l1_height.to_le_bytes());

        data
    }

    /// Get proof as hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.encode())
    }
}

/// Verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the proof is valid
    pub valid: bool,
    /// Settlement amount (if valid)
    pub amount_sats: Option<u64>,
    /// L1 confirmation height (if valid)
    pub l1_height: Option<u32>,
    /// Blocks confirmed (if valid)
    pub confirmations: Option<u32>,
    /// Error message (if invalid)
    pub error: Option<String>,
}

impl VerificationResult {
    /// Create a successful verification
    pub fn success(amount_sats: u64, l1_height: u32, current_height: u32) -> Self {
        Self {
            valid: true,
            amount_sats: Some(amount_sats),
            l1_height: Some(l1_height),
            confirmations: Some(current_height.saturating_sub(l1_height)),
            error: None,
        }
    }

    /// Create a failed verification
    pub fn failure(error: String) -> Self {
        Self {
            valid: false,
            amount_sats: None,
            l1_height: None,
            confirmations: None,
            error: Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::compute_merkle_proof;
    use crate::batch::compute_merkle_root;

    #[test]
    fn test_proof_verification() {
        // Create some leaves
        let leaves: Vec<[u8; 32]> = (0..8).map(|i| [i; 32]).collect();
        let merkle_root = compute_merkle_root(&leaves);

        // Create proof for leaf at index 3
        let proof = SettlementProof {
            settlement_hash: leaves[3],
            merkle_proof: compute_merkle_proof(&leaves, 3),
            index: 3,
            leaf_count: leaves.len(),
            merkle_root,
            batch_id: [0u8; 32],
            l1_txid: "abc123".to_string(),
            l1_height: 800_000,
            l1_block_hash: "def456".to_string(),
        };

        assert!(proof.verify().is_ok());
    }

    #[test]
    fn test_proof_wrong_leaf_count_fails() {
        // Verify that proofs with wrong leaf_count are rejected
        let leaves: Vec<[u8; 32]> = (0..8).map(|i| [i; 32]).collect();
        let merkle_root = compute_merkle_root(&leaves);

        // Create proof with WRONG leaf_count
        let proof = SettlementProof {
            settlement_hash: leaves[3],
            merkle_proof: compute_merkle_proof(&leaves, 3),
            index: 3,
            leaf_count: 10, // Wrong! Should be 8
            merkle_root,
            batch_id: [0u8; 32],
            l1_txid: "abc123".to_string(),
            l1_height: 800_000,
            l1_block_hash: "def456".to_string(),
        };

        // Should fail because leaf_count is wrong
        assert!(proof.verify().is_err());
    }

    #[test]
    fn test_proof_encoding() {
        let proof = SettlementProof {
            settlement_hash: [1u8; 32],
            merkle_proof: vec![[2u8; 32], [3u8; 32]],
            index: 5,
            leaf_count: 8,
            merkle_root: [4u8; 32],
            batch_id: [5u8; 32],
            l1_txid: "abc123".to_string(),
            l1_height: 800_000,
            l1_block_hash: "def456".to_string(),
        };

        let encoded = proof.encode();
        assert!(!encoded.is_empty());

        let hex = proof.to_hex();
        assert!(!hex.is_empty());
    }
}
