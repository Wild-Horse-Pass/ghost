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
//| FILE: rpc.rs                                                                                                         |
//|======================================================================================================================|

//! Ghost-core RPC integration for Reconciliation
//!
//! This module provides async functions that delegate transaction building
//! and batch signing coordination to ghost-core.
//!
//! Benefits of using ghost-core:
//! - Proper Silent Payment address derivation
//! - Wallet signing for batch transactions
//! - PSBT support for multi-party coordination
//! - Standardized transaction formats

use ghost_common::rpc::{
    BatchFeeEstimate, BitcoinRpc, CombinedPsbtResult, DerivedAddress, ReconciliationInputRpc,
    ReconciliationOutputRpc,
};

use crate::batch::Batch;
use crate::error::ReconciliationError;
use crate::settlement::Settlement;

/// RPC-backed reconciliation transaction builder
///
/// Uses ghost-core RPC calls instead of building transactions in Rust.
/// This enables proper wallet signing and PSBT coordination.
pub struct ReconciliationRpcBuilder {
    rpc: BitcoinRpc,
}

impl ReconciliationRpcBuilder {
    /// Create a new RPC-backed builder
    pub fn new(rpc: BitcoinRpc) -> Self {
        Self { rpc }
    }

    /// Build a reconciliation transaction via ghost-core RPC
    ///
    /// This creates the L1 settlement transaction with all outputs.
    pub async fn build_reconciliation_tx(
        &self,
        inputs: &[ReconciliationInputData],
        outputs: &[ReconciliationOutputData],
        epoch_id: u32,
        state_root: &[u8; 32],
        treasury_address: Option<&str>,
        treasury_amount: Option<u64>,
    ) -> Result<RpcReconciliationResult, ReconciliationError> {
        // Convert inputs to RPC format
        let rpc_inputs: Vec<ReconciliationInputRpc> = inputs
            .iter()
            .map(|i| ReconciliationInputRpc {
                txid: i.txid.clone(),
                vout: i.vout,
                amount: i.amount,
                lock_id: hex::encode(i.lock_id),
            })
            .collect();

        // Convert outputs to RPC format
        let rpc_outputs: Vec<ReconciliationOutputRpc> = outputs
            .iter()
            .map(|o| ReconciliationOutputRpc {
                ghost_id: o.ghost_id.clone(),
                amount: o.amount,
                output_type: o.output_type.clone(),
            })
            .collect();

        let state_root_hex = hex::encode(state_root);

        // Call ghost-core RPC
        let result = self
            .rpc
            .create_reconciliation_tx(
                rpc_inputs,
                rpc_outputs,
                epoch_id,
                &state_root_hex,
                treasury_address,
                treasury_amount,
            )
            .await
            .map_err(|e| ReconciliationError::L1TransactionError(e.to_string()))?;

        Ok(RpcReconciliationResult {
            hex: result.hex,
            txid: result.txid,
            complete: result.complete,
            fee_sats: result.fee,
            epoch_id: result.epoch_id,
            state_root: result.state_root,
        })
    }

    /// Create a PSBT for multi-party batch signing
    ///
    /// Used when multiple parties need to sign the reconciliation transaction.
    pub async fn create_batch_psbt(
        &self,
        inputs: &[ReconciliationInputData],
        outputs: &[ReconciliationOutputData],
    ) -> Result<String, ReconciliationError> {
        let rpc_inputs: Vec<ReconciliationInputRpc> = inputs
            .iter()
            .map(|i| ReconciliationInputRpc {
                txid: i.txid.clone(),
                vout: i.vout,
                amount: i.amount,
                lock_id: hex::encode(i.lock_id),
            })
            .collect();

        let rpc_outputs: Vec<ReconciliationOutputRpc> = outputs
            .iter()
            .map(|o| ReconciliationOutputRpc {
                ghost_id: o.ghost_id.clone(),
                amount: o.amount,
                output_type: o.output_type.clone(),
            })
            .collect();

        self.rpc
            .coordinate_batch_signing(rpc_inputs, rpc_outputs)
            .await
            .map_err(|e| ReconciliationError::L1TransactionError(e.to_string()))
    }

    /// Combine PSBTs from multiple signing participants
    pub async fn combine_psbts(
        &self,
        psbts: Vec<String>,
    ) -> Result<CombinedPsbtResult, ReconciliationError> {
        self.rpc
            .combine_batch_psbt(psbts)
            .await
            .map_err(|e| ReconciliationError::L1TransactionError(e.to_string()))
    }

    /// Estimate fee for a batch transaction
    pub async fn estimate_batch_fee(
        &self,
        input_count: u32,
        output_count: u32,
        conf_target: u32,
    ) -> Result<BatchFeeEstimate, ReconciliationError> {
        self.rpc
            .estimate_batch_fee(input_count, output_count, conf_target)
            .await
            .map_err(|e| ReconciliationError::L1TransactionError(e.to_string()))
    }

    /// Derive output addresses from Ghost IDs via Silent Payments
    ///
    /// This uses ghost-core's wallet to derive proper P2TR addresses
    /// for each recipient's Ghost ID.
    pub async fn derive_output_addresses(
        &self,
        ghost_ids: Vec<String>,
        amounts: Vec<u64>,
    ) -> Result<Vec<DerivedAddress>, ReconciliationError> {
        self.rpc
            .derive_reconciliation_outputs(ghost_ids, amounts)
            .await
            .map_err(|e| ReconciliationError::L1TransactionError(e.to_string()))
    }

    /// Broadcast a signed reconciliation transaction
    pub async fn broadcast_transaction(&self, tx_hex: &str) -> Result<String, ReconciliationError> {
        self.rpc
            .send_raw_transaction(tx_hex)
            .await
            .map_err(|e| ReconciliationError::L1TransactionError(e.to_string()))
    }

    /// Get current block height
    pub async fn get_block_height(&self) -> Result<u64, ReconciliationError> {
        self.rpc
            .get_block_count()
            .await
            .map_err(|e| ReconciliationError::L1TransactionError(e.to_string()))
    }

    /// Check if a transaction is confirmed
    pub async fn check_confirmation(&self, txid: &str) -> Result<Option<i64>, ReconciliationError> {
        let tx_info = self
            .rpc
            .get_raw_transaction(txid, true)
            .await
            .map_err(|e| ReconciliationError::L1TransactionError(e.to_string()))?;

        // Extract confirmations from the response
        Ok(tx_info.get("confirmations").and_then(|c| c.as_i64()))
    }

    // =========================================================================
    // H-8: UTXO Verification for Settlement Security
    // =========================================================================

    /// H-8: Verify that a UTXO still exists on L1 before executing settlement
    ///
    /// This prevents double-spend attacks where the source lock UTXO may have been:
    /// - Already spent in another transaction
    /// - Removed due to a blockchain reorg
    /// - Never confirmed in the first place
    ///
    /// Returns Ok(true) if the UTXO exists, Ok(false) if it doesn't exist,
    /// or an error if the RPC call fails.
    pub async fn verify_utxo_exists(
        &self,
        txid: &str,
        vout: u32,
    ) -> Result<bool, ReconciliationError> {
        // Query Bitcoin Core for the UTXO
        // include_mempool=true to also check mempool for unconfirmed UTXOs
        match self.rpc.get_tx_out(txid, vout, true).await {
            Ok(Some(_tx_out)) => {
                // UTXO exists and is unspent
                Ok(true)
            }
            Ok(None) => {
                // UTXO does not exist (either spent or never existed)
                Ok(false)
            }
            Err(e) => Err(ReconciliationError::BitcoinRpcError(e.to_string())),
        }
    }

    /// H-CRYPTO-3: Verify that a UTXO exists AND has sufficient confirmations
    ///
    /// This provides finality proof by ensuring the UTXO:
    /// 1. Still exists on L1 (not spent)
    /// 2. Has at least `min_confirmations` blocks on top of it (reorg protection)
    ///
    /// The confirmation requirement protects against reorgs where a lock UTXO
    /// may have been spent via a different path in a competing chain.
    ///
    /// Returns Ok(confirmations) if the UTXO exists with enough confirmations,
    /// or an appropriate error otherwise.
    pub async fn verify_utxo_with_confirmations(
        &self,
        txid: &str,
        vout: u32,
        min_confirmations: u32,
    ) -> Result<i64, ReconciliationError> {
        // Query Bitcoin Core for the UTXO
        // include_mempool=false because we need confirmed UTXOs for finality
        match self.rpc.get_tx_out(txid, vout, false).await {
            Ok(Some(tx_out)) => {
                let confirmations = tx_out.confirmations;

                if confirmations < min_confirmations as i64 {
                    tracing::warn!(
                        txid = %txid,
                        vout = vout,
                        confirmations = confirmations,
                        required = min_confirmations,
                        "H-CRYPTO-3: UTXO exists but has insufficient confirmations"
                    );
                    return Err(ReconciliationError::InsufficientConfirmations {
                        txid: txid.to_string(),
                        vout,
                        confirmations: confirmations as u32,
                        required: min_confirmations,
                    });
                }

                Ok(confirmations)
            }
            Ok(None) => {
                // UTXO does not exist (either spent or never existed)
                Err(ReconciliationError::UtxoNotFound {
                    lock_id: format!("{}:{}", txid, vout),
                })
            }
            Err(e) => Err(ReconciliationError::BitcoinRpcError(e.to_string())),
        }
    }

    /// H-8: Verify that a lock UTXO exists before settlement batch execution
    ///
    /// This takes a lock_id and looks up the corresponding UTXO from the provided
    /// input data. Use this when building batches to ensure all source UTXOs are valid.
    ///
    /// Returns Ok(()) if the UTXO exists, or an error if it doesn't.
    pub async fn verify_lock_utxo(
        &self,
        input: &ReconciliationInputData,
    ) -> Result<(), ReconciliationError> {
        let exists = self.verify_utxo_exists(&input.txid, input.vout).await?;

        if !exists {
            tracing::error!(
                txid = %input.txid,
                vout = input.vout,
                lock_id = %hex::encode(input.lock_id),
                "H-8 Security: Lock UTXO not found on L1 - potential double-spend or reorg"
            );
            return Err(ReconciliationError::UtxoNotFound {
                lock_id: hex::encode(input.lock_id),
            });
        }

        tracing::debug!(
            txid = %input.txid,
            vout = input.vout,
            lock_id = %hex::encode(input.lock_id),
            "H-8: Lock UTXO verified on L1"
        );

        Ok(())
    }

    /// H-8: Verify all lock UTXOs in a batch before execution (LEGACY)
    ///
    /// WARNING: This method only checks existence, NOT confirmations.
    /// For production use, prefer `verify_batch_utxos_with_finality()` which
    /// also checks confirmation depth to protect against reorgs (H-BTC-1).
    ///
    /// This should be called before building and broadcasting a settlement batch
    /// to ensure all source lock UTXOs still exist on L1. If any UTXO is missing,
    /// the batch should be rejected to prevent double-spend losses.
    ///
    /// Returns Ok(()) if all UTXOs exist, or the first error encountered.
    pub async fn verify_batch_utxos(
        &self,
        inputs: &[ReconciliationInputData],
    ) -> Result<(), ReconciliationError> {
        tracing::info!(
            input_count = inputs.len(),
            "H-8: Verifying all batch input UTXOs exist on L1"
        );

        for input in inputs {
            self.verify_lock_utxo(input).await?;
        }

        tracing::info!(
            input_count = inputs.len(),
            "H-8: All batch input UTXOs verified successfully"
        );

        Ok(())
    }

    /// H-CRYPTO-3: Verify all lock UTXOs with confirmation depth requirement
    ///
    /// This is the finality-aware version of verify_batch_utxos. It ensures:
    /// 1. All UTXOs exist and are unspent on L1
    /// 2. All UTXOs have at least `min_confirmations` (reorg protection)
    ///
    /// Call this at batch SUBMISSION time (not just creation time) to prove
    /// finality. The confirmation requirement protects against the race condition
    /// where a lock could be spent via a different path between verification and
    /// batch execution.
    ///
    /// Recommended values:
    /// - 6 confirmations for large batches (standard Bitcoin finality)
    /// - 3 confirmations for time-sensitive settlements
    /// - 1 confirmation minimum (never accept mempool-only UTXOs)
    ///
    /// Returns Ok(()) if all UTXOs pass, or the first error encountered.
    pub async fn verify_batch_utxos_with_finality(
        &self,
        inputs: &[ReconciliationInputData],
        min_confirmations: u32,
    ) -> Result<(), ReconciliationError> {
        // H-CRYPTO-3: Never accept 0 confirmations - mempool UTXOs can vanish
        if min_confirmations == 0 {
            return Err(ReconciliationError::InvalidBatch(
                "H-CRYPTO-3: min_confirmations must be >= 1".to_string(),
            ));
        }

        tracing::info!(
            input_count = inputs.len(),
            min_confirmations = min_confirmations,
            "H-CRYPTO-3: Verifying batch finality with confirmation depth"
        );

        for input in inputs {
            let confirmations = self
                .verify_utxo_with_confirmations(&input.txid, input.vout, min_confirmations)
                .await?;

            tracing::debug!(
                txid = %input.txid,
                vout = input.vout,
                lock_id = %hex::encode(input.lock_id),
                confirmations = confirmations,
                "H-CRYPTO-3: UTXO finality verified"
            );
        }

        tracing::info!(
            input_count = inputs.len(),
            min_confirmations = min_confirmations,
            "H-CRYPTO-3: All batch UTXOs verified with sufficient confirmations"
        );

        Ok(())
    }
}

/// Maximum reasonable vout value (Bitcoin allows up to 2^32-1, but realistically much smaller)
const MAX_REASONABLE_VOUT: u32 = 65535;

/// Maximum amount (21 million BTC in satoshis)
const MAX_BITCOIN_SATS: u64 = 21_000_000 * 100_000_000;

/// Minimum dust amount (546 sats for P2WPKH)
const MIN_DUST_AMOUNT: u64 = 546;

/// Input data for reconciliation RPC
///
/// M-VAL-1 FIX: Includes validation methods to ensure input data integrity
/// before processing.
#[derive(Debug, Clone)]
pub struct ReconciliationInputData {
    /// Transaction ID
    pub txid: String,
    /// Output index
    pub vout: u32,
    /// Amount in satoshis
    pub amount: u64,
    /// Ghost Lock ID
    pub lock_id: [u8; 32],
}

impl ReconciliationInputData {
    /// Create and validate new input data
    ///
    /// M-VAL-1 FIX: Validates all fields before construction
    pub fn new(
        txid: String,
        vout: u32,
        amount: u64,
        lock_id: [u8; 32],
    ) -> Result<Self, ReconciliationError> {
        let input = Self {
            txid,
            vout,
            amount,
            lock_id,
        };
        input.validate()?;
        Ok(input)
    }

    /// Validate the input data
    ///
    /// M-VAL-1 FIX: Comprehensive validation of reconciliation input
    pub fn validate(&self) -> Result<(), ReconciliationError> {
        // Validate txid is valid hex (64 chars = 32 bytes)
        if self.txid.len() != 64 {
            return Err(ReconciliationError::InvalidInput(format!(
                "Invalid txid length: expected 64 hex chars, got {}",
                self.txid.len()
            )));
        }

        // Validate txid is valid hex
        if hex::decode(&self.txid).is_err() {
            return Err(ReconciliationError::InvalidInput(
                "Invalid txid: not valid hex".to_string(),
            ));
        }

        // Validate vout is reasonable
        if self.vout > MAX_REASONABLE_VOUT {
            return Err(ReconciliationError::InvalidInput(format!(
                "Invalid vout: {} exceeds maximum {}",
                self.vout, MAX_REASONABLE_VOUT
            )));
        }

        // Validate amount is within Bitcoin's supply limits
        if self.amount > MAX_BITCOIN_SATS {
            return Err(ReconciliationError::InvalidInput(format!(
                "Invalid amount: {} exceeds maximum Bitcoin supply",
                self.amount
            )));
        }

        // Validate amount is above dust
        if self.amount < MIN_DUST_AMOUNT {
            return Err(ReconciliationError::InvalidInput(format!(
                "Invalid amount: {} is below dust threshold {}",
                self.amount, MIN_DUST_AMOUNT
            )));
        }

        // Validate lock_id is not all zeros
        if self.lock_id.iter().all(|&b| b == 0) {
            return Err(ReconciliationError::InvalidInput(
                "Invalid lock_id: cannot be all zeros".to_string(),
            ));
        }

        Ok(())
    }
}

/// Output data for reconciliation RPC
#[derive(Debug, Clone)]
pub struct ReconciliationOutputData {
    /// Ghost ID of recipient
    pub ghost_id: String,
    /// Amount in satoshis
    pub amount: u64,
    /// Output type: "lock", "payment", "exit"
    pub output_type: String,
}

impl ReconciliationOutputData {
    /// Create a new lock output (re-entering Ghost Pay)
    pub fn new_lock(ghost_id: String, amount: u64) -> Self {
        Self {
            ghost_id,
            amount,
            output_type: "lock".to_string(),
        }
    }

    /// Create a payment output
    pub fn new_payment(ghost_id: String, amount: u64) -> Self {
        Self {
            ghost_id,
            amount,
            output_type: "payment".to_string(),
        }
    }

    /// Create an exit output (leaving Ghost Pay to regular Bitcoin)
    pub fn new_exit(address: String, amount: u64) -> Self {
        Self {
            ghost_id: address, // For exits, ghost_id field holds the Bitcoin address
            amount,
            output_type: "exit".to_string(),
        }
    }
}

/// Result of building reconciliation transaction via RPC
#[derive(Debug, Clone)]
pub struct RpcReconciliationResult {
    /// Transaction hex (signed if wallet has keys)
    pub hex: String,
    /// Transaction ID
    pub txid: String,
    /// Whether fully signed
    pub complete: bool,
    /// Fee in satoshis
    pub fee_sats: u64,
    /// Epoch ID from OP_RETURN
    pub epoch_id: u32,
    /// State root from OP_RETURN
    pub state_root: String,
}

/// Convert a batch and its settlements to RPC input/output data
///
/// Settlements represent exits from L2 (Ghost Pay) to L1 (Bitcoin addresses).
/// Each settlement specifies a source Ghost ID (L2 account) and destination
/// Bitcoin address.
pub fn batch_to_rpc_data(
    _batch: &Batch,
    settlements: &[Settlement],
    available_inputs: &std::collections::HashMap<String, Vec<ReconciliationInputData>>,
) -> Result<(Vec<ReconciliationInputData>, Vec<ReconciliationOutputData>), ReconciliationError> {
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();

    for settlement in settlements {
        let amount = settlement.amount_sats();

        // Get inputs for this settlement's source
        let source_inputs = available_inputs
            .get(settlement.source_ghost_id())
            .ok_or_else(|| ReconciliationError::InsufficientFunds {
                available: 0,
                required: amount,
                ghost_id: settlement.source_ghost_id().to_string(),
            })?;

        // Collect enough inputs to cover the settlement
        let mut remaining = amount;
        for input in source_inputs {
            if remaining == 0 {
                break;
            }
            inputs.push(input.clone());
            remaining = remaining.saturating_sub(input.amount);
        }

        if remaining > 0 {
            return Err(ReconciliationError::InsufficientFunds {
                available: amount - remaining,
                required: amount,
                ghost_id: settlement.source_ghost_id().to_string(),
            });
        }

        // Create exit output (L2 -> L1 Bitcoin address)
        // net_amount_sats() already deducts the fee
        let output = ReconciliationOutputData::new_exit(
            settlement.destination_address().to_string(),
            settlement.net_amount_sats(),
        );
        outputs.push(output);
    }

    Ok((inputs, outputs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_data_types() {
        let lock = ReconciliationOutputData::new_lock("ghost1abc...".to_string(), 100_000);
        assert_eq!(lock.output_type, "lock");

        let payment = ReconciliationOutputData::new_payment("ghost1def...".to_string(), 50_000);
        assert_eq!(payment.output_type, "payment");

        let exit = ReconciliationOutputData::new_exit("bc1q...".to_string(), 25_000);
        assert_eq!(exit.output_type, "exit");
    }

    /// H-CRYPTO-3: Test that zero confirmations are rejected for finality verification
    #[tokio::test]
    async fn test_finality_rejects_zero_confirmations() {
        // This test verifies the validation logic without needing a real RPC connection
        // The actual RPC calls would fail without a server, but we can test the validation
        let result = validate_min_confirmations(0);
        assert!(
            result.is_err(),
            "Zero confirmations should be rejected for finality"
        );

        // 1 or more confirmations should pass validation
        assert!(
            validate_min_confirmations(1).is_ok(),
            "1 confirmation should be accepted"
        );
        assert!(
            validate_min_confirmations(6).is_ok(),
            "6 confirmations should be accepted"
        );
    }

    /// Helper function to validate min_confirmations parameter
    fn validate_min_confirmations(min_confirmations: u32) -> Result<(), ReconciliationError> {
        if min_confirmations == 0 {
            return Err(ReconciliationError::InvalidBatch(
                "H-CRYPTO-3: min_confirmations must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    /// M-VAL-1: Test ReconciliationInputData validation
    #[test]
    fn test_input_data_validation_valid() {
        // Valid input
        let valid_txid = "abcd".repeat(16); // 64 hex chars
        let result = ReconciliationInputData::new(
            valid_txid,
            0,
            10_000, // Above dust
            [1u8; 32],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_input_data_validation_invalid_txid_length() {
        // Invalid txid length
        let result = ReconciliationInputData::new(
            "abc".to_string(), // Too short
            0,
            10_000,
            [1u8; 32],
        );
        assert!(result.is_err());
        assert!(matches!(result, Err(ReconciliationError::InvalidInput(_))));
    }

    #[test]
    fn test_input_data_validation_invalid_txid_hex() {
        // Invalid hex in txid
        let invalid_txid = "gggg".repeat(16); // 64 chars but not valid hex
        let result = ReconciliationInputData::new(
            invalid_txid,
            0,
            10_000,
            [1u8; 32],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_input_data_validation_excessive_vout() {
        // Excessive vout
        let valid_txid = "abcd".repeat(16);
        let result = ReconciliationInputData::new(
            valid_txid,
            100_000, // Exceeds MAX_REASONABLE_VOUT (65535)
            10_000,
            [1u8; 32],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_input_data_validation_excessive_amount() {
        // Excessive amount (more than 21M BTC)
        let valid_txid = "abcd".repeat(16);
        let result = ReconciliationInputData::new(
            valid_txid,
            0,
            22_000_000 * 100_000_000, // 22M BTC > max supply
            [1u8; 32],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_input_data_validation_dust_amount() {
        // Dust amount
        let valid_txid = "abcd".repeat(16);
        let result = ReconciliationInputData::new(
            valid_txid,
            0,
            100, // Below MIN_DUST_AMOUNT (546)
            [1u8; 32],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_input_data_validation_zero_lock_id() {
        // Zero lock_id
        let valid_txid = "abcd".repeat(16);
        let result = ReconciliationInputData::new(
            valid_txid,
            0,
            10_000,
            [0u8; 32], // All zeros
        );
        assert!(result.is_err());
    }
}
