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

//! Ghost-core RPC integration for Wraith Protocol
//!
//! This module provides async functions that delegate transaction building
//! to ghost-core instead of building transactions in pure Rust.
//!
//! Benefits of using ghost-core:
//! - Transactions can be signed (wallet integration)
//! - Standardized transaction format
//! - PSBT support for multi-party signing

use ghost_common::rpc::{BitcoinRpc, WraithInputRpc};

use crate::denomination::WraithDenomination;
use crate::error::WraithError;
use crate::executor::WraithInput;

/// RPC-backed Wraith transaction builder
///
/// Uses ghost-core RPC calls instead of building transactions in Rust.
/// This allows for wallet signing and standardized transaction formats.
pub struct WraithRpcBuilder {
    rpc: BitcoinRpc,
    session_id: String,
    denomination: WraithDenomination,
}

impl WraithRpcBuilder {
    /// Create a new RPC-backed builder
    pub fn new(rpc: BitcoinRpc, session_id: String, denomination: WraithDenomination) -> Self {
        Self {
            rpc,
            session_id,
            denomination,
        }
    }

    /// Build Phase 1 (Split) transaction via ghost-core RPC
    ///
    /// Takes N inputs and creates 10N intermediate outputs.
    /// The transaction is built and optionally signed by ghost-core.
    pub async fn build_split_transaction(
        &self,
        inputs: &[WraithInput],
        intermediate_addresses: &[Vec<String>],
    ) -> Result<RpcSplitResult, WraithError> {
        // Convert inputs to RPC format
        let rpc_inputs: Vec<WraithInputRpc> = inputs
            .iter()
            .map(|i| WraithInputRpc {
                txid: i.txid.to_string(),
                vout: i.vout,
                amount: i.amount,
                script_pubkey: Some(i.script_pubkey.to_hex_string()),
            })
            .collect();

        // Call ghost-core RPC
        let result = self
            .rpc
            .create_wraith_tx(
                rpc_inputs,
                intermediate_addresses.to_vec(),
                &self.session_id,
                &self.denomination.to_string(),
            )
            .await
            .map_err(|e| WraithError::RpcError(e.to_string()))?;

        Ok(RpcSplitResult {
            hex: result.hex,
            txid: result.txid,
            complete: result.complete,
            fee_sats: result.fee,
            input_count: result.input_count,
            output_count: result.output_count,
            session_id: self.session_id.clone(),
            participant_count: inputs.len(),
        })
    }

    /// Build Phase 2 (Merge) transaction via ghost-core RPC
    ///
    /// Takes 10N intermediate inputs and creates N final outputs.
    pub async fn build_merge_transaction(
        &self,
        intermediate_inputs: &[WraithInput],
        final_addresses: &[String],
    ) -> Result<RpcMergeResult, WraithError> {
        // Convert inputs to RPC format
        let rpc_inputs: Vec<WraithInputRpc> = intermediate_inputs
            .iter()
            .map(|i| WraithInputRpc {
                txid: i.txid.to_string(),
                vout: i.vout,
                amount: i.amount,
                script_pubkey: Some(i.script_pubkey.to_hex_string()),
            })
            .collect();

        // Call ghost-core RPC
        let result = self
            .rpc
            .create_wraith_final_tx(rpc_inputs, final_addresses.to_vec(), &self.session_id)
            .await
            .map_err(|e| WraithError::RpcError(e.to_string()))?;

        Ok(RpcMergeResult {
            hex: result.hex,
            txid: result.txid,
            complete: result.complete,
            fee_sats: result.fee,
            session_id: self.session_id.clone(),
            participant_count: final_addresses.len(),
        })
    }

    /// Broadcast a transaction via ghost-core
    pub async fn broadcast_transaction(&self, tx_hex: &str) -> Result<String, WraithError> {
        self.rpc
            .send_raw_transaction(tx_hex)
            .await
            .map_err(|e| WraithError::RpcError(e.to_string()))
    }

    /// Shuffle outputs via ghost-core for deterministic ordering
    pub async fn shuffle_outputs(&self, tx_hex: &str) -> Result<String, WraithError> {
        self.rpc
            .shuffle_outputs(tx_hex, &self.session_id)
            .await
            .map_err(|e| WraithError::RpcError(e.to_string()))
    }

    /// Parse Wraith transaction metadata
    pub async fn parse_wraith_tx(&self, txid: &str) -> Result<WraithTxMetadata, WraithError> {
        let info = self
            .rpc
            .parse_wraith_tx(txid)
            .await
            .map_err(|e| WraithError::RpcError(e.to_string()))?;

        Ok(WraithTxMetadata {
            session_id: info.session_id,
            phase: info.phase,
            participant_count: info.participant_count,
            valid: info.valid,
        })
    }
}

/// Result of building a split transaction via RPC
#[derive(Debug, Clone)]
pub struct RpcSplitResult {
    /// Transaction hex (signed if wallet has keys)
    pub hex: String,
    /// Transaction ID
    pub txid: String,
    /// Whether fully signed
    pub complete: bool,
    /// Fee in satoshis
    pub fee_sats: u64,
    /// Number of inputs
    pub input_count: u32,
    /// Number of outputs
    pub output_count: u32,
    /// Session ID
    pub session_id: String,
    /// Number of participants
    pub participant_count: usize,
}

/// Result of building a merge transaction via RPC
#[derive(Debug, Clone)]
pub struct RpcMergeResult {
    /// Transaction hex (signed if wallet has keys)
    pub hex: String,
    /// Transaction ID
    pub txid: String,
    /// Whether fully signed
    pub complete: bool,
    /// Fee in satoshis
    pub fee_sats: u64,
    /// Session ID
    pub session_id: String,
    /// Number of participants
    pub participant_count: usize,
}

/// Parsed Wraith transaction metadata
#[derive(Debug, Clone)]
pub struct WraithTxMetadata {
    /// Session ID from OP_RETURN
    pub session_id: String,
    /// Phase (1 = split, 2 = merge)
    pub phase: u8,
    /// Participant count
    pub participant_count: u16,
    /// Whether valid Wraith transaction
    pub valid: bool,
}

#[cfg(test)]
mod tests {
    // RPC tests require a running ghost-core instance
    // These are integration tests, not unit tests
}
