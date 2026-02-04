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

    /// H-8: Verify all lock UTXOs in a batch before execution
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
}

/// Input data for reconciliation RPC
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
}
