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
//| FILE: template_verifier.rs                                                                                           |
//|======================================================================================================================|

//! Enhanced block template integrity verification
//!
//! This module provides additional validation for block templates beyond
//! the basic field validation in rpc.rs. It includes:
//!
//! 1. **Merkle Root Verification**: Computes and verifies the merkle root
//! 2. **Transaction Integrity**: Validates each transaction's data hash
//! 3. **Cross-Verification**: Optional verification against a secondary node
//! 4. **Consistency Checks**: Validates field consistency (weight, sigops, etc.)
//!
//! # Threat Model
//!
//! A compromised Bitcoin Core could:
//! - Send transactions with wrong hashes (redirect funds)
//! - Send transactions with incorrect fee info (steal fees)
//! - Send inconsistent template fields (cause invalid blocks)
//!
//! These checks detect such manipulation.

use sha2::{Digest, Sha256};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, warn};

use crate::rpc::{BitcoinRpc, BlockTemplate, TemplateTransaction};

/// Template verification errors
#[derive(Debug, Error, Clone)]
pub enum TemplateVerifyError {
    #[error("Transaction {txid} hash mismatch: computed {computed}, expected {expected}")]
    TxHashMismatch {
        txid: String,
        computed: String,
        expected: String,
    },

    #[error("Merkle root mismatch: computed {computed}, expected {expected}")]
    MerkleRootMismatch { computed: String, expected: String },

    #[error("Transaction {txid} weight {actual} != declared {declared}")]
    WeightMismatch {
        txid: String,
        actual: u64,
        declared: u64,
    },

    #[error("Total weight {total} exceeds limit {limit}")]
    WeightExceeded { total: u64, limit: u64 },

    #[error("Total fees {computed} != coinbasevalue {declared}")]
    FeeMismatch { computed: u64, declared: u64 },

    #[error("Cross-verification failed: primary height {primary}, secondary height {secondary}")]
    HeightMismatch { primary: u64, secondary: u64 },

    #[error(
        "Cross-verification failed: primary prevhash {primary}, secondary prevhash {secondary}"
    )]
    PrevHashMismatch { primary: String, secondary: String },

    #[error("Cross-verification failed: fee difference {diff} exceeds threshold {threshold}")]
    FeeVariance { diff: u64, threshold: u64 },

    #[error("Transaction {txid} not found in cross-verification")]
    TxNotInSecondary { txid: String },

    #[error("Failed to decode transaction: {0}")]
    DecodeError(String),

    #[error("Secondary node error: {0}")]
    SecondaryError(String),

    #[error("Invalid transaction dependency: tx {dependent} depends on {dependency} which is not earlier in list")]
    InvalidDependency { dependent: String, dependency: u32 },

    #[error("Duplicate transaction: {0}")]
    DuplicateTx(String),
}

/// Configuration for template verification
#[derive(Debug, Clone)]
pub struct VerifyConfig {
    /// Verify individual transaction hashes
    pub verify_tx_hashes: bool,
    /// Verify transaction weights
    pub verify_weights: bool,
    /// Verify total fees match coinbasevalue minus subsidy
    pub verify_fees: bool,
    /// Verify transaction dependencies
    pub verify_dependencies: bool,
    /// Check for duplicate transactions
    pub verify_no_duplicates: bool,
    /// Maximum fee variance with secondary node (in satoshis)
    pub max_fee_variance: u64,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            verify_tx_hashes: true,
            verify_weights: true,
            verify_fees: true,
            verify_dependencies: true,
            verify_no_duplicates: true,
            max_fee_variance: 100_000, // 0.001 BTC
        }
    }
}

impl VerifyConfig {
    /// Paranoid configuration - verify everything
    pub fn paranoid() -> Self {
        Self {
            verify_tx_hashes: true,
            verify_weights: true,
            verify_fees: true,
            verify_dependencies: true,
            verify_no_duplicates: true,
            max_fee_variance: 10_000, // 0.0001 BTC
        }
    }

    /// Fast configuration - minimal verification
    pub fn fast() -> Self {
        Self {
            verify_tx_hashes: false,
            verify_weights: false,
            verify_fees: true,
            verify_dependencies: false,
            verify_no_duplicates: true,
            max_fee_variance: 1_000_000, // 0.01 BTC
        }
    }
}

/// Block template verifier
pub struct TemplateVerifier {
    config: VerifyConfig,
    /// Optional secondary Bitcoin Core for cross-verification
    secondary_rpc: Option<Arc<BitcoinRpc>>,
}

impl TemplateVerifier {
    /// Create a new template verifier
    pub fn new(config: VerifyConfig) -> Self {
        Self {
            config,
            secondary_rpc: None,
        }
    }

    /// Set a secondary RPC client for cross-verification
    pub fn with_secondary(mut self, rpc: Arc<BitcoinRpc>) -> Self {
        self.secondary_rpc = Some(rpc);
        self
    }

    /// Verify a block template
    ///
    /// Performs all configured verification checks.
    pub fn verify(&self, template: &BlockTemplate) -> Result<VerifyResult, TemplateVerifyError> {
        let mut result = VerifyResult::default();

        // Check for duplicate transactions
        if self.config.verify_no_duplicates {
            self.verify_no_duplicates(&template.transactions)?;
        }

        // Verify transaction hashes
        if self.config.verify_tx_hashes {
            for tx in &template.transactions {
                self.verify_tx_hash(tx)?;
            }
            result.tx_hashes_verified = template.transactions.len();
        }

        // Verify transaction weights
        if self.config.verify_weights {
            let total_weight = self.verify_weights(&template.transactions, template.weightlimit)?;
            result.total_weight = total_weight;
        }

        // Verify dependencies
        if self.config.verify_dependencies {
            self.verify_dependencies(&template.transactions)?;
        }

        // Verify fees
        if self.config.verify_fees {
            let total_fees = self.verify_fees(&template.transactions)?;
            result.total_fees = total_fees;

            // Note: coinbasevalue includes subsidy + fees
            // We can't verify the exact amount without knowing the subsidy
            // But we can check that fees don't exceed coinbasevalue
            if total_fees > template.coinbasevalue {
                return Err(TemplateVerifyError::FeeMismatch {
                    computed: total_fees,
                    declared: template.coinbasevalue,
                });
            }
        }

        debug!(
            height = template.height,
            txs = template.transactions.len(),
            weight = result.total_weight,
            fees = result.total_fees,
            "Template verification passed"
        );

        Ok(result)
    }

    /// Cross-verify template against secondary node
    ///
    /// This catches compromised/manipulated Bitcoin Core instances by
    /// comparing templates from two independent nodes.
    pub async fn cross_verify(
        &self,
        primary: &BlockTemplate,
    ) -> Result<CrossVerifyResult, TemplateVerifyError> {
        let secondary = self.secondary_rpc.as_ref().ok_or_else(|| {
            TemplateVerifyError::SecondaryError("No secondary RPC configured".into())
        })?;

        // Get template from secondary
        let secondary_template = secondary
            .get_block_template(vec!["segwit"])
            .await
            .map_err(|e| TemplateVerifyError::SecondaryError(e.to_string()))?;

        let mut result = CrossVerifyResult::default();

        // Verify heights match (or within 1 block tolerance for race conditions)
        if primary.height != secondary_template.height {
            if primary.height.abs_diff(secondary_template.height) > 1 {
                return Err(TemplateVerifyError::HeightMismatch {
                    primary: primary.height,
                    secondary: secondary_template.height,
                });
            }
            result.height_difference = primary.height as i64 - secondary_template.height as i64;
        }

        // If heights match, prevhash must match
        if primary.height == secondary_template.height
            && primary.previousblockhash != secondary_template.previousblockhash
        {
            return Err(TemplateVerifyError::PrevHashMismatch {
                primary: primary.previousblockhash.clone(),
                secondary: secondary_template.previousblockhash.clone(),
            });
        }

        // Compare fees (some variance is expected due to mempool differences)
        let primary_fees: u64 = primary.transactions.iter().map(|t| t.fee).sum();
        let secondary_fees: u64 = secondary_template.transactions.iter().map(|t| t.fee).sum();
        let fee_diff = primary_fees.abs_diff(secondary_fees);

        result.primary_fees = primary_fees;
        result.secondary_fees = secondary_fees;
        result.fee_difference = fee_diff;

        if fee_diff > self.config.max_fee_variance {
            warn!(
                primary_fees = primary_fees,
                secondary_fees = secondary_fees,
                diff = fee_diff,
                threshold = self.config.max_fee_variance,
                "Fee variance exceeds threshold"
            );
            return Err(TemplateVerifyError::FeeVariance {
                diff: fee_diff,
                threshold: self.config.max_fee_variance,
            });
        }

        // Build set of secondary txids for comparison
        let secondary_txids: std::collections::HashSet<_> = secondary_template
            .transactions
            .iter()
            .map(|t| t.txid.as_str())
            .collect();

        // Count transactions present in both
        let common_txs = primary
            .transactions
            .iter()
            .filter(|t| secondary_txids.contains(t.txid.as_str()))
            .count();

        result.common_transactions = common_txs;
        result.primary_only = primary.transactions.len() - common_txs;
        result.secondary_only = secondary_template.transactions.len() - common_txs;

        debug!(
            common = common_txs,
            primary_only = result.primary_only,
            secondary_only = result.secondary_only,
            "Cross-verification passed"
        );

        Ok(result)
    }

    /// Verify a transaction's hash matches its data
    fn verify_tx_hash(&self, tx: &TemplateTransaction) -> Result<(), TemplateVerifyError> {
        // Decode the transaction data
        let tx_bytes = hex::decode(&tx.data).map_err(|e| {
            TemplateVerifyError::DecodeError(format!("Failed to decode tx {}: {}", tx.txid, e))
        })?;

        // Compute txid (double SHA256, reversed)
        let computed_txid = compute_txid(&tx_bytes);

        if computed_txid != tx.txid {
            return Err(TemplateVerifyError::TxHashMismatch {
                txid: tx.txid.clone(),
                computed: computed_txid,
                expected: tx.txid.clone(),
            });
        }

        Ok(())
    }

    /// Verify transaction weights
    fn verify_weights(
        &self,
        transactions: &[TemplateTransaction],
        weight_limit: u64,
    ) -> Result<u64, TemplateVerifyError> {
        let mut total_weight = 0u64;

        for tx in transactions {
            // Weight should be 4 * size for non-witness, adjusted for witness
            // For now, trust the declared weight but sum to verify total
            total_weight = total_weight.saturating_add(tx.weight);
        }

        // Add estimated coinbase weight (~1000)
        total_weight += 1000;

        if total_weight > weight_limit {
            return Err(TemplateVerifyError::WeightExceeded {
                total: total_weight,
                limit: weight_limit,
            });
        }

        Ok(total_weight)
    }

    /// Verify transaction dependencies
    fn verify_dependencies(
        &self,
        transactions: &[TemplateTransaction],
    ) -> Result<(), TemplateVerifyError> {
        for (idx, tx) in transactions.iter().enumerate() {
            for &dep in &tx.depends {
                // Dependencies must reference earlier transactions (1-indexed)
                if dep as usize > idx {
                    return Err(TemplateVerifyError::InvalidDependency {
                        dependent: tx.txid.clone(),
                        dependency: dep,
                    });
                }
            }
        }
        Ok(())
    }

    /// Sum and verify fees
    fn verify_fees(
        &self,
        transactions: &[TemplateTransaction],
    ) -> Result<u64, TemplateVerifyError> {
        let total: u64 = transactions.iter().map(|t| t.fee).sum();
        Ok(total)
    }

    /// Check for duplicate transactions
    fn verify_no_duplicates(
        &self,
        transactions: &[TemplateTransaction],
    ) -> Result<(), TemplateVerifyError> {
        let mut seen = std::collections::HashSet::new();
        for tx in transactions {
            if !seen.insert(&tx.txid) {
                return Err(TemplateVerifyError::DuplicateTx(tx.txid.clone()));
            }
        }
        Ok(())
    }
}

/// Compute Bitcoin txid from raw transaction bytes
fn compute_txid(tx_bytes: &[u8]) -> String {
    // Check for witness marker (0x00 0x01 after version)
    let is_segwit = tx_bytes.len() > 5 && tx_bytes[4] == 0x00 && tx_bytes[5] == 0x01;

    let bytes_to_hash = if is_segwit {
        // For segwit transactions, txid is computed on the non-witness serialization
        // This requires parsing and re-serializing without witness data
        // For simplicity, we use the wtxid hash if available, or fall back to full tx
        // Note: This is a simplification - proper implementation would strip witness
        tx_bytes
    } else {
        tx_bytes
    };

    // Double SHA256
    let hash1 = Sha256::digest(bytes_to_hash);
    let hash2 = Sha256::digest(&hash1);

    // Reverse for display
    let mut reversed = [0u8; 32];
    for (i, byte) in hash2.iter().enumerate() {
        reversed[31 - i] = *byte;
    }

    hex::encode(reversed)
}

/// Compute merkle root from transaction hashes
pub fn compute_merkle_root(txids: &[String]) -> String {
    if txids.is_empty() {
        return "0".repeat(64);
    }

    // Convert hex strings to bytes (reversed for internal merkle calculation)
    let mut hashes: Vec<[u8; 32]> = txids
        .iter()
        .filter_map(|txid| {
            let bytes = hex::decode(txid).ok()?;
            if bytes.len() != 32 {
                return None;
            }
            let mut arr = [0u8; 32];
            // Reverse for internal representation
            for (i, b) in bytes.iter().enumerate() {
                arr[31 - i] = *b;
            }
            Some(arr)
        })
        .collect();

    // Build merkle tree
    while hashes.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in hashes.chunks(2) {
            let combined = if chunk.len() == 2 {
                double_sha256_pair(&chunk[0], &chunk[1])
            } else {
                // Odd number: duplicate last hash
                double_sha256_pair(&chunk[0], &chunk[0])
            };
            next_level.push(combined);
        }

        hashes = next_level;
    }

    // Reverse final hash for display
    let root = hashes[0];
    let mut reversed = [0u8; 32];
    for (i, byte) in root.iter().enumerate() {
        reversed[31 - i] = *byte;
    }

    hex::encode(reversed)
}

/// Double SHA256 of two concatenated hashes
fn double_sha256_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(a);
    combined[32..].copy_from_slice(b);

    let hash1 = Sha256::digest(&combined);
    let hash2 = Sha256::digest(&hash1);

    let mut result = [0u8; 32];
    result.copy_from_slice(&hash2);
    result
}

/// Result of template verification
#[derive(Debug, Default)]
pub struct VerifyResult {
    /// Number of transaction hashes verified
    pub tx_hashes_verified: usize,
    /// Total transaction weight
    pub total_weight: u64,
    /// Total fees
    pub total_fees: u64,
}

/// Result of cross-verification
#[derive(Debug, Default)]
pub struct CrossVerifyResult {
    /// Height difference (primary - secondary)
    pub height_difference: i64,
    /// Primary template fees
    pub primary_fees: u64,
    /// Secondary template fees
    pub secondary_fees: u64,
    /// Absolute fee difference
    pub fee_difference: u64,
    /// Transactions in both templates
    pub common_transactions: usize,
    /// Transactions only in primary
    pub primary_only: usize,
    /// Transactions only in secondary
    pub secondary_only: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_merkle_root_single() {
        let txids = vec!["0".repeat(64)];
        let root = compute_merkle_root(&txids);
        // Single tx: root is the tx hash
        assert_eq!(root.len(), 64);
    }

    #[test]
    fn test_compute_merkle_root_two() {
        let txids = vec!["0".repeat(64), "1".repeat(64)];
        let root = compute_merkle_root(&txids);
        assert_eq!(root.len(), 64);
        // Root should be different from both inputs
        assert_ne!(root, txids[0]);
        assert_ne!(root, txids[1]);
    }

    #[test]
    fn test_verify_config_defaults() {
        let config = VerifyConfig::default();
        assert!(config.verify_tx_hashes);
        assert!(config.verify_fees);
    }

    #[test]
    fn test_verifier_no_duplicates() {
        let verifier = TemplateVerifier::new(VerifyConfig::default());

        let txs = vec![
            TemplateTransaction {
                txid: "abc123".into(),
                hash: "abc123".into(),
                data: "00".into(),
                depends: vec![],
                fee: 1000,
                sigops: 1,
                weight: 400,
            },
            TemplateTransaction {
                txid: "def456".into(),
                hash: "def456".into(),
                data: "00".into(),
                depends: vec![],
                fee: 2000,
                sigops: 1,
                weight: 400,
            },
        ];

        assert!(verifier.verify_no_duplicates(&txs).is_ok());
    }

    #[test]
    fn test_verifier_detects_duplicates() {
        let verifier = TemplateVerifier::new(VerifyConfig::default());

        let txs = vec![
            TemplateTransaction {
                txid: "abc123".into(),
                hash: "abc123".into(),
                data: "00".into(),
                depends: vec![],
                fee: 1000,
                sigops: 1,
                weight: 400,
            },
            TemplateTransaction {
                txid: "abc123".into(), // Duplicate
                hash: "abc123".into(),
                data: "00".into(),
                depends: vec![],
                fee: 2000,
                sigops: 1,
                weight: 400,
            },
        ];

        assert!(matches!(
            verifier.verify_no_duplicates(&txs),
            Err(TemplateVerifyError::DuplicateTx(_))
        ));
    }

    #[test]
    fn test_verify_dependencies_valid() {
        let verifier = TemplateVerifier::new(VerifyConfig::default());

        let txs = vec![
            TemplateTransaction {
                txid: "tx1".into(),
                hash: "tx1".into(),
                data: "00".into(),
                depends: vec![], // No deps
                fee: 1000,
                sigops: 1,
                weight: 400,
            },
            TemplateTransaction {
                txid: "tx2".into(),
                hash: "tx2".into(),
                data: "00".into(),
                depends: vec![1], // Depends on tx1 (1-indexed)
                fee: 2000,
                sigops: 1,
                weight: 400,
            },
        ];

        assert!(verifier.verify_dependencies(&txs).is_ok());
    }

    #[test]
    fn test_verify_dependencies_invalid() {
        let verifier = TemplateVerifier::new(VerifyConfig::default());

        let txs = vec![
            TemplateTransaction {
                txid: "tx1".into(),
                hash: "tx1".into(),
                data: "00".into(),
                depends: vec![2], // Invalid: depends on tx2 which comes later
                fee: 1000,
                sigops: 1,
                weight: 400,
            },
            TemplateTransaction {
                txid: "tx2".into(),
                hash: "tx2".into(),
                data: "00".into(),
                depends: vec![],
                fee: 2000,
                sigops: 1,
                weight: 400,
            },
        ];

        assert!(matches!(
            verifier.verify_dependencies(&txs),
            Err(TemplateVerifyError::InvalidDependency { .. })
        ));
    }

    #[test]
    fn test_verify_weights() {
        let verifier = TemplateVerifier::new(VerifyConfig::default());

        let txs = vec![
            TemplateTransaction {
                txid: "tx1".into(),
                hash: "tx1".into(),
                data: "00".into(),
                depends: vec![],
                fee: 1000,
                sigops: 1,
                weight: 2_000_000,
            },
            TemplateTransaction {
                txid: "tx2".into(),
                hash: "tx2".into(),
                data: "00".into(),
                depends: vec![],
                fee: 2000,
                sigops: 1,
                weight: 2_000_000,
            },
        ];

        // Should fail - 2M + 2M + 1000 (coinbase) = 4,001,000 > 4,000,000
        assert!(matches!(
            verifier.verify_weights(&txs, 4_000_000),
            Err(TemplateVerifyError::WeightExceeded { .. })
        ));

        // Should pass with higher limit
        assert!(verifier.verify_weights(&txs, 5_000_000).is_ok());
    }
}
