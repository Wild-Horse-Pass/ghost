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
//| FILE: coinbase_verifier.rs                                                                                           |
//|======================================================================================================================|

//! Coinbase integrity verification
//!
//! Ensures the coinbase transaction in submitted blocks matches the
//! consensus-approved payout proposal. This prevents:
//! - Address substitution attacks by modified nodes
//! - Coinbase output manipulation
//! - Fund redirection attacks
//!
//! # Security Model
//!
//! When a payout proposal is approved by BFT consensus, we compute a
//! cryptographic commitment (hash) of the expected coinbase outputs.
//! Before submitting any block, we verify the actual coinbase matches
//! this commitment exactly.

use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{debug, error};

use ghost_common::types::PayoutProposal;

/// Coinbase verification errors
#[derive(Debug, Error)]
pub enum CoinbaseVerificationError {
    #[error("No approved payout commitment found")]
    NoCommitment,

    #[error("Coinbase commitment mismatch: expected {expected}, got {actual}")]
    CommitmentMismatch { expected: String, actual: String },

    #[error("Output count mismatch: expected {expected}, got {actual}")]
    OutputCountMismatch { expected: usize, actual: usize },

    #[error("Output {index} amount mismatch: expected {expected}, got {actual}")]
    AmountMismatch {
        index: usize,
        expected: u64,
        actual: u64,
    },

    #[error("Output {index} script mismatch")]
    ScriptMismatch { index: usize },

    #[error("Total value mismatch: expected {expected}, got {actual}")]
    TotalValueMismatch { expected: u64, actual: u64 },

    #[error("L-5: Total script size too large: {actual} > {max}")]
    TotalScriptSizeTooLarge { actual: usize, max: usize },

    #[error("Failed to parse coinbase transaction: {0}")]
    ParseError(String),
}

/// Cryptographic commitment to a coinbase transaction
///
/// This is computed from the approved payout proposal and stored.
/// Before block submission, the actual coinbase is verified against this.
#[derive(Debug, Clone)]
pub struct CoinbaseCommitment {
    /// Hash of the expected coinbase outputs
    pub output_hash: [u8; 32],
    /// Expected total output value
    pub total_value: u64,
    /// Expected output count
    pub output_count: usize,
    /// Round ID this commitment is for
    pub round_id: u64,
    /// Block height this commitment is for
    pub block_height: u64,
    /// The proposal hash this was derived from
    pub proposal_hash: [u8; 32],
}

/// H-8: Domain separator for coinbase output hash consistency
/// CRITICAL: Both from_proposal() and compute_outputs_hash() MUST use this same domain.
const COINBASE_OUTPUTS_DOMAIN: &[u8] = b"CoinbaseOutputs/v1";

impl CoinbaseCommitment {
    /// Create a commitment from an approved payout proposal
    ///
    /// H-8 FIX: Uses the same hash format as compute_outputs_hash() to ensure
    /// that verification will succeed when the actual coinbase matches the proposal.
    ///
    /// The commitment hash is computed from:
    /// - All miner payout addresses (as script pubkeys) and amounts
    /// - All node payout addresses (as script pubkeys) and amounts
    /// - Treasury address (as script pubkey) and amount
    ///
    /// The hash format matches compute_outputs_hash() exactly:
    /// - Domain separator: "CoinbaseOutputs/v1"
    /// - Total output count (including all expected outputs)
    /// - For each output: amount (8 bytes LE) + script length (4 bytes LE) + script bytes
    pub fn from_proposal(proposal: &PayoutProposal, treasury_address: &[u8]) -> Self {
        let mut total_value = 0u64;
        let mut output_count = 0usize;

        // Count all outputs first
        output_count += proposal.miner_payouts.len();
        output_count += proposal.node_payouts.len();
        if proposal.treasury_amount > 0 {
            output_count += 1;
        }

        // H-8: Use the SAME domain separator and format as compute_outputs_hash()
        let mut hasher = Sha256::new();
        hasher.update(COINBASE_OUTPUTS_DOMAIN);
        // Note: We add 1 to include the witness commitment output that will have value 0
        // The compute_outputs_hash skips 0-value outputs, so we need the same count
        // Actually, the total count should only be value outputs, matching what verify() checks
        hasher.update((output_count as u32).to_le_bytes());

        // Hash miner payouts (order-sensitive) - same format as compute_outputs_hash
        for payout in &proposal.miner_payouts {
            hasher.update(payout.amount.to_le_bytes());
            hasher.update((payout.address.len() as u32).to_le_bytes());
            hasher.update(&payout.address);
            total_value = total_value.saturating_add(payout.amount);
        }

        // Hash node payouts (order-sensitive) - same format as compute_outputs_hash
        for payout in &proposal.node_payouts {
            hasher.update(payout.amount.to_le_bytes());
            hasher.update((payout.address.len() as u32).to_le_bytes());
            hasher.update(&payout.address);
            total_value = total_value.saturating_add(payout.amount);
        }

        // Hash treasury output - same format as compute_outputs_hash
        if proposal.treasury_amount > 0 {
            hasher.update(proposal.treasury_amount.to_le_bytes());
            hasher.update((treasury_address.len() as u32).to_le_bytes());
            hasher.update(treasury_address);
            total_value = total_value.saturating_add(proposal.treasury_amount);
        }

        let output_hash: [u8; 32] = hasher.finalize().into();

        debug!(
            round_id = proposal.round_id,
            block_height = proposal.block_height,
            output_count = output_count,
            total_value = total_value,
            hash = %hex::encode(&output_hash[..8]),
            "Created coinbase commitment (H-8 consistent format)"
        );

        Self {
            output_hash,
            total_value,
            output_count,
            round_id: proposal.round_id,
            block_height: proposal.block_height,
            proposal_hash: proposal.proposal_hash,
        }
    }

    /// L-5: Maximum total script size across all outputs (100KB)
    /// This prevents excessively large coinbase transactions that could
    /// cause memory issues or slow down block validation.
    pub const MAX_TOTAL_SCRIPT_SIZE: usize = 100_000;

    /// Verify a coinbase transaction matches this commitment
    ///
    /// This performs a deep verification:
    /// 1. L-5: Total script size is within bounds
    /// 2. Output count matches
    /// 3. Total value matches
    /// 4. Cryptographic hash of outputs matches
    pub fn verify(
        &self,
        coinbase_outputs: &[CoinbaseOutput],
    ) -> Result<(), CoinbaseVerificationError> {
        // L-5: Check total script size before processing
        let total_script_size: usize = coinbase_outputs.iter().map(|o| o.script_pubkey.len()).sum();
        if total_script_size > Self::MAX_TOTAL_SCRIPT_SIZE {
            error!(
                total_size = total_script_size,
                max = Self::MAX_TOTAL_SCRIPT_SIZE,
                "L-5: Total script size exceeds maximum"
            );
            return Err(CoinbaseVerificationError::TotalScriptSizeTooLarge {
                actual: total_script_size,
                max: Self::MAX_TOTAL_SCRIPT_SIZE,
            });
        }

        // Check output count (excluding witness commitment which has 0 value)
        let value_outputs: Vec<_> = coinbase_outputs.iter().filter(|o| o.value > 0).collect();

        if value_outputs.len() != self.output_count {
            return Err(CoinbaseVerificationError::OutputCountMismatch {
                expected: self.output_count,
                actual: value_outputs.len(),
            });
        }

        // Check total value
        let actual_total: u64 = value_outputs.iter().map(|o| o.value).sum();
        if actual_total != self.total_value {
            return Err(CoinbaseVerificationError::TotalValueMismatch {
                expected: self.total_value,
                actual: actual_total,
            });
        }

        // Compute hash of actual outputs and compare
        let actual_hash = Self::compute_outputs_hash(coinbase_outputs);
        if actual_hash != self.output_hash {
            error!(
                expected = %hex::encode(&self.output_hash[..8]),
                actual = %hex::encode(&actual_hash[..8]),
                "COINBASE COMMITMENT MISMATCH - possible address substitution attack!"
            );
            return Err(CoinbaseVerificationError::CommitmentMismatch {
                expected: hex::encode(self.output_hash),
                actual: hex::encode(actual_hash),
            });
        }

        debug!(
            hash = %hex::encode(&self.output_hash[..8]),
            outputs = self.output_count,
            value = self.total_value,
            "Coinbase commitment verified"
        );

        Ok(())
    }

    /// Compute hash of coinbase outputs for comparison
    ///
    /// H-8 FIX: Uses the same domain separator and format as from_proposal()
    /// to ensure hash consistency between expected and actual coinbases.
    ///
    /// Format:
    /// - Domain separator: "CoinbaseOutputs/v1" (COINBASE_OUTPUTS_DOMAIN)
    /// - Value output count (excludes 0-value witness commitment)
    /// - For each value output: amount (8 bytes LE) + script length (4 bytes LE) + script bytes
    fn compute_outputs_hash(outputs: &[CoinbaseOutput]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        // H-8: Use the SAME domain separator as from_proposal()
        hasher.update(COINBASE_OUTPUTS_DOMAIN);

        // Count only value outputs (exclude witness commitment)
        let value_output_count = outputs.iter().filter(|o| o.value > 0).count();
        hasher.update((value_output_count as u32).to_le_bytes());

        for output in outputs {
            if output.value > 0 {
                // Only hash value outputs (skip witness commitment)
                hasher.update(output.value.to_le_bytes());
                hasher.update((output.script_pubkey.len() as u32).to_le_bytes());
                hasher.update(&output.script_pubkey);
            }
        }

        hasher.finalize().into()
    }
}

/// Simplified coinbase output for verification
#[derive(Debug, Clone)]
pub struct CoinbaseOutput {
    /// Output value in satoshis
    pub value: u64,
    /// Script pubkey bytes
    pub script_pubkey: Vec<u8>,
}

impl CoinbaseOutput {
    /// Parse outputs from raw coinbase transaction bytes
    pub fn parse_from_coinbase(
        coinbase_bytes: &[u8],
    ) -> Result<Vec<Self>, CoinbaseVerificationError> {
        // Minimum size check
        if coinbase_bytes.len() < 60 {
            return Err(CoinbaseVerificationError::ParseError(
                "Coinbase too short".into(),
            ));
        }

        // Parse as bitcoin transaction to extract outputs
        // Note: Using bitcoin crate's deserialize would be cleaner but we avoid
        // the dependency here. Manual parsing is straightforward for outputs.

        let mut cursor = 0;

        // Skip version (4 bytes)
        cursor += 4;

        // Check for witness marker/flag
        let has_witness = coinbase_bytes.get(cursor) == Some(&0x00)
            && coinbase_bytes.get(cursor + 1) == Some(&0x01);
        if has_witness {
            cursor += 2;
        }

        // Read input count (varint)
        let (input_count, consumed) = read_varint(&coinbase_bytes[cursor..])
            .ok_or_else(|| CoinbaseVerificationError::ParseError("Invalid input count".into()))?;
        cursor += consumed;

        // Skip inputs (for coinbase, there's always exactly 1)
        if input_count != 1 {
            return Err(CoinbaseVerificationError::ParseError(format!(
                "Expected 1 coinbase input, got {}",
                input_count
            )));
        }

        // Skip prevout hash (32) + index (4) = 36 bytes
        cursor += 36;

        // Read script length and skip script
        let (script_len, consumed) = read_varint(&coinbase_bytes[cursor..])
            .ok_or_else(|| CoinbaseVerificationError::ParseError("Invalid script length".into()))?;
        cursor += consumed;
        cursor += script_len;

        // Skip sequence (4 bytes)
        cursor += 4;

        // Now read outputs
        let (output_count, consumed) = read_varint(&coinbase_bytes[cursor..])
            .ok_or_else(|| CoinbaseVerificationError::ParseError("Invalid output count".into()))?;
        cursor += consumed;

        let mut outputs = Vec::with_capacity(output_count);

        for i in 0..output_count {
            // Read value (8 bytes LE)
            if cursor + 8 > coinbase_bytes.len() {
                return Err(CoinbaseVerificationError::ParseError(format!(
                    "Truncated output {} value",
                    i
                )));
            }
            let value = u64::from_le_bytes(coinbase_bytes[cursor..cursor + 8].try_into().map_err(
                |_| CoinbaseVerificationError::ParseError("Invalid value bytes".into()),
            )?);
            cursor += 8;

            // Read script pubkey
            let (script_len, consumed) =
                read_varint(&coinbase_bytes[cursor..]).ok_or_else(|| {
                    CoinbaseVerificationError::ParseError("Invalid output script length".into())
                })?;
            cursor += consumed;

            // L-12: Add script length upper bound to prevent excessive memory allocation
            // Maximum standard script is ~10KB; consensus limit is much higher but not needed here
            if script_len > 10_000 {
                return Err(CoinbaseVerificationError::ParseError(format!(
                    "L-12: Script length {} exceeds maximum (10000) for output {}",
                    script_len, i
                )));
            }

            if cursor + script_len > coinbase_bytes.len() {
                return Err(CoinbaseVerificationError::ParseError(format!(
                    "Truncated output {} script",
                    i
                )));
            }

            let script_pubkey = coinbase_bytes[cursor..cursor + script_len].to_vec();
            cursor += script_len;

            outputs.push(CoinbaseOutput {
                value,
                script_pubkey,
            });
        }

        Ok(outputs)
    }
}

/// Read a Bitcoin varint from a byte slice
///
/// HIGH-9: Uses bounds-checked .get() for all array accesses
fn read_varint(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;

    if first < 0xfd {
        Some((first as usize, 1))
    } else if first == 0xfd {
        // Need bytes at indices 1, 2
        let b1 = *data.get(1)?;
        let b2 = *data.get(2)?;
        let val = u16::from_le_bytes([b1, b2]) as usize;
        Some((val, 3))
    } else if first == 0xfe {
        // Need bytes at indices 1, 2, 3, 4
        let bytes: [u8; 4] = data.get(1..5)?.try_into().ok()?;
        let val = u32::from_le_bytes(bytes) as usize;
        Some((val, 5))
    } else {
        // first == 0xff: Need bytes at indices 1-8
        let bytes: [u8; 8] = data.get(1..9)?.try_into().ok()?;
        let val = u64::from_le_bytes(bytes) as usize;
        Some((val, 9))
    }
}

/// Coinbase verifier that tracks commitments and performs verification
#[derive(Debug, Default)]
pub struct CoinbaseVerifier {
    /// Current commitment (for the block being mined)
    commitment: parking_lot::RwLock<Option<CoinbaseCommitment>>,
}

impl CoinbaseVerifier {
    pub fn new() -> Self {
        Self {
            commitment: parking_lot::RwLock::new(None),
        }
    }

    /// Set the commitment for an approved payout
    pub fn set_commitment(&self, commitment: CoinbaseCommitment) {
        *self.commitment.write() = Some(commitment);
    }

    /// Clear the commitment (after block submission or reorg)
    pub fn clear_commitment(&self) {
        *self.commitment.write() = None;
    }

    /// Get the current commitment if any
    pub fn get_commitment(&self) -> Option<CoinbaseCommitment> {
        self.commitment.read().clone()
    }

    /// Verify a coinbase transaction against the stored commitment
    ///
    /// Returns Ok(()) if verification passes, Err otherwise.
    /// If no commitment is stored, returns an error.
    pub fn verify_coinbase(&self, coinbase_bytes: &[u8]) -> Result<(), CoinbaseVerificationError> {
        let commitment = self
            .commitment
            .read()
            .clone()
            .ok_or(CoinbaseVerificationError::NoCommitment)?;

        // Parse coinbase outputs
        let outputs = CoinbaseOutput::parse_from_coinbase(coinbase_bytes)?;

        // Verify against commitment
        commitment.verify(&outputs)
    }

    /// Verify and log the result (for use in block submission flow)
    pub fn verify_before_submission(&self, coinbase_bytes: &[u8]) -> bool {
        match self.verify_coinbase(coinbase_bytes) {
            Ok(()) => {
                debug!("Coinbase verification passed");
                true
            }
            Err(e) => {
                error!(
                    error = %e,
                    "COINBASE VERIFICATION FAILED - block submission blocked"
                );
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::types::{PayoutEntry, PayoutType};

    fn create_test_proposal() -> PayoutProposal {
        PayoutProposal {
            proposal_hash: [1u8; 32],
            round_id: 100,
            block_hash: [2u8; 32],
            block_height: 800_000,
            proposer: [3u8; 32],
            miner_payouts: vec![
                PayoutEntry {
                    address: b"bc1qminer1".to_vec(),
                    amount: 100_000_000,
                    recipient_id: [10u8; 32],
                    payout_type: PayoutType::Mining,
                },
                PayoutEntry {
                    address: b"bc1qminer2".to_vec(),
                    amount: 50_000_000,
                    recipient_id: [11u8; 32],
                    payout_type: PayoutType::Mining,
                },
            ],
            node_payouts: vec![PayoutEntry {
                address: b"bc1qnode1".to_vec(),
                amount: 25_000_000,
                recipient_id: [20u8; 32],
                payout_type: PayoutType::NodeReward,
            }],
            treasury_amount: 12_500_000,
            treasury_address: b"bc1qtreasury".to_vec(), // H-MINE-3: snapshot address
            tx_fees: 1_000_000,
            subsidy: 312_500_000,
            timestamp: 1700000000,
            tx_fees_unallocated: 0,
        }
    }

    #[test]
    fn test_commitment_creation() {
        let proposal = create_test_proposal();
        let treasury_addr = b"bc1qtreasury";

        let commitment = CoinbaseCommitment::from_proposal(&proposal, treasury_addr);

        assert_eq!(commitment.output_count, 4); // 2 miners + 1 node + 1 treasury
        assert_eq!(
            commitment.total_value,
            100_000_000 + 50_000_000 + 25_000_000 + 12_500_000
        );
        assert_eq!(commitment.round_id, 100);
        assert_eq!(commitment.block_height, 800_000);
    }

    #[test]
    fn test_commitment_deterministic() {
        let proposal = create_test_proposal();
        let treasury_addr = b"bc1qtreasury";

        let commitment1 = CoinbaseCommitment::from_proposal(&proposal, treasury_addr);
        let commitment2 = CoinbaseCommitment::from_proposal(&proposal, treasury_addr);

        assert_eq!(commitment1.output_hash, commitment2.output_hash);
    }

    #[test]
    fn test_commitment_different_for_different_proposals() {
        let proposal1 = create_test_proposal();
        let mut proposal2 = create_test_proposal();
        proposal2.miner_payouts[0].amount = 99_999_999; // Change one satoshi

        let treasury_addr = b"bc1qtreasury";

        let commitment1 = CoinbaseCommitment::from_proposal(&proposal1, treasury_addr);
        let commitment2 = CoinbaseCommitment::from_proposal(&proposal2, treasury_addr);

        assert_ne!(commitment1.output_hash, commitment2.output_hash);
    }

    #[test]
    fn test_read_varint() {
        // Single byte
        assert_eq!(read_varint(&[0x50]), Some((0x50, 1)));

        // Two bytes (0xfd prefix)
        assert_eq!(read_varint(&[0xfd, 0x00, 0x01]), Some((256, 3)));

        // Four bytes (0xfe prefix)
        assert_eq!(
            read_varint(&[0xfe, 0x01, 0x00, 0x01, 0x00]),
            Some((65537, 5))
        );
    }

    #[test]
    fn test_verifier_workflow() {
        let proposal = create_test_proposal();
        let treasury_addr = b"bc1qtreasury";

        let commitment = CoinbaseCommitment::from_proposal(&proposal, treasury_addr);
        let verifier = CoinbaseVerifier::new();

        // Initially no commitment
        assert!(verifier.get_commitment().is_none());

        // Set commitment
        verifier.set_commitment(commitment.clone());
        assert!(verifier.get_commitment().is_some());

        // Clear commitment
        verifier.clear_commitment();
        assert!(verifier.get_commitment().is_none());
    }
}
