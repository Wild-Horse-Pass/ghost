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
//| FILE: transaction.rs                                                                                                 |
//|======================================================================================================================|

//! Reconciliation transaction building
//!
//! Key rotation happens automatically via Silent Payments:
//! - Each participant has a GhostId (scan_pubkey + spend_pubkey)
//! - New lock addresses are derived using derive_payment_address()
//! - Ephemeral pubkeys are included in OP_RETURN for scanning

use bitcoin::absolute::LockTime;
use bitcoin::address::Address;
use bitcoin::blockdata::script::{Builder, PushBytesBuf, ScriptBuf};
use bitcoin::secp256k1::PublicKey;
use bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use bitcoin::{Amount, Network, Sequence, Witness};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::str::FromStr;

use crate::error::ReconciliationError;

/// OP_RETURN marker for reconciliation transactions
pub const RECONCILIATION_MARKER: &[u8; 4] = b"GPAY";

/// A GhostPay-enabled node eligible for fee distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostPayNode {
    /// Node identifier
    pub node_id: String,
    /// Node's payout address for receiving fee share
    pub payout_address: String,
}

impl GhostPayNode {
    pub fn new(node_id: impl Into<String>, payout_address: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            payout_address: payout_address.into(),
        }
    }
}

/// Custom serde for PublicKey
mod pubkey_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(pubkey: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(pubkey.serialize()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = serde::Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        PublicKey::from_slice(&bytes).map_err(serde::de::Error::custom)
    }
}

/// Output type in reconciliation transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TxOutput {
    /// New Ghost Lock with automatic key rotation (Silent Payments style)
    GhostLock {
        /// P2TR address derived from GhostId
        address: String,
        /// Amount in sats
        amount: u64,
        /// Original lock ID
        from_lock: [u8; 32],
        /// Ephemeral pubkey for scanning (33 bytes compressed)
        #[serde(with = "pubkey_serde")]
        ephemeral_pubkey: PublicKey,
        /// Output index in this batch
        output_index: u32,
    },

    /// Payment to recipient's Ghost Lock
    Payment {
        /// Recipient address
        address: String,
        /// Amount in sats
        amount: u64,
        /// From lock ID
        from_lock: [u8; 32],
    },

    /// Exit to regular Bitcoin address (leaving Ghost Pay)
    Exit {
        /// Bitcoin address
        address: String,
        /// Amount in sats
        amount: u64,
        /// From lock ID
        from_lock: [u8; 32],
    },

    /// OP_RETURN with batch metadata
    OpReturn {
        /// Batch ID
        batch_id: u32,
        /// State root
        state_root: [u8; 32],
    },

    /// Fee output to treasury
    TreasuryFee {
        /// Address
        address: String,
        /// Amount
        amount: u64,
    },

    /// Fee output to individual GhostPay node
    NodeFee {
        /// Node's payout address
        address: String,
        /// Amount (equal share of 50% protocol fees)
        amount: u64,
        /// Node identifier (for tracking)
        node_id: String,
    },
}

impl TxOutput {
    /// Get output amount (0 for OP_RETURN)
    pub fn amount(&self) -> u64 {
        match self {
            TxOutput::GhostLock { amount, .. } => *amount,
            TxOutput::Payment { amount, .. } => *amount,
            TxOutput::Exit { amount, .. } => *amount,
            TxOutput::OpReturn { .. } => 0,
            TxOutput::TreasuryFee { amount, .. } => *amount,
            TxOutput::NodeFee { amount, .. } => *amount,
        }
    }

    /// Get output address (None for OP_RETURN)
    pub fn address(&self) -> Option<&str> {
        match self {
            TxOutput::GhostLock { address, .. } => Some(address),
            TxOutput::Payment { address, .. } => Some(address),
            TxOutput::Exit { address, .. } => Some(address),
            TxOutput::OpReturn { .. } => None,
            TxOutput::TreasuryFee { address, .. } => Some(address),
            TxOutput::NodeFee { address, .. } => Some(address),
        }
    }

    /// Get ephemeral pubkey (only for GhostLock outputs)
    pub fn ephemeral_pubkey(&self) -> Option<&PublicKey> {
        match self {
            TxOutput::GhostLock {
                ephemeral_pubkey, ..
            } => Some(ephemeral_pubkey),
            _ => None,
        }
    }
}

/// Reconciliation transaction structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationTx {
    /// Transaction ID (computed)
    txid: Option<[u8; 32]>,

    /// Batch ID
    batch_id: u32,

    /// Input lock IDs
    inputs: Vec<[u8; 32]>,

    /// Outputs
    outputs: Vec<TxOutput>,

    /// State root
    state_root: [u8; 32],

    /// Total input amount
    total_input: u64,

    /// Total output amount
    total_output: u64,

    /// Mining fee
    mining_fee: u64,
}

impl ReconciliationTx {
    /// Create a new reconciliation transaction
    pub fn new(batch_id: u32, state_root: [u8; 32], mining_fee: u64) -> Self {
        Self {
            txid: None,
            batch_id,
            inputs: Vec::new(),
            outputs: Vec::new(),
            state_root,
            total_input: 0,
            total_output: 0,
            mining_fee,
        }
    }

    /// Add an input
    pub fn add_input(&mut self, lock_id: [u8; 32], amount: u64) {
        self.inputs.push(lock_id);
        self.total_input += amount;
    }

    /// Add an output
    pub fn add_output(&mut self, output: TxOutput) {
        self.total_output += output.amount();
        self.outputs.push(output);
    }

    /// Add OP_RETURN output
    pub fn add_op_return(&mut self) {
        self.outputs.push(TxOutput::OpReturn {
            batch_id: self.batch_id,
            state_root: self.state_root,
        });
    }

    /// Get inputs
    pub fn inputs(&self) -> &[[u8; 32]] {
        &self.inputs
    }

    /// Get outputs
    pub fn outputs(&self) -> &[TxOutput] {
        &self.outputs
    }

    /// Get batch ID
    pub fn batch_id(&self) -> u32 {
        self.batch_id
    }

    /// Get state root
    pub fn state_root(&self) -> [u8; 32] {
        self.state_root
    }

    /// Get total input
    pub fn total_input(&self) -> u64 {
        self.total_input
    }

    /// Get total output
    pub fn total_output(&self) -> u64 {
        self.total_output
    }

    /// Get mining fee
    pub fn mining_fee(&self) -> u64 {
        self.mining_fee
    }

    /// Get all ephemeral pubkeys from GhostLock outputs
    pub fn ephemeral_pubkeys(&self) -> Vec<&PublicKey> {
        self.outputs
            .iter()
            .filter_map(|o| o.ephemeral_pubkey())
            .collect()
    }

    /// Compute OP_RETURN data
    pub fn op_return_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(40);
        data.extend_from_slice(RECONCILIATION_MARKER);
        data.extend_from_slice(&self.batch_id.to_le_bytes());
        data.extend_from_slice(&self.state_root);
        data
    }

    /// Compute L2 transaction ID (internal tracking)
    pub fn compute_l2_txid(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"ReconciliationTx/v1");
        hasher.update(self.batch_id.to_le_bytes());
        for input in &self.inputs {
            hasher.update(input);
        }
        hasher.update(self.state_root);
        hasher.finalize().into()
    }

    /// Build an actual Bitcoin transaction
    ///
    /// Requires UTXO outpoints for all inputs.
    pub fn to_bitcoin_transaction(
        &self,
        input_outpoints: &[bitcoin::OutPoint],
        network: Network,
    ) -> Result<Transaction, ReconciliationError> {
        if input_outpoints.len() != self.inputs.len() {
            return Err(ReconciliationError::InvalidBatch(format!(
                "Input count mismatch: {} outpoints vs {} inputs",
                input_outpoints.len(),
                self.inputs.len()
            )));
        }

        // Build inputs
        let tx_inputs: Vec<TxIn> = input_outpoints
            .iter()
            .map(|outpoint| TxIn {
                previous_output: *outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect();

        // Build outputs
        let mut tx_outputs = Vec::with_capacity(self.outputs.len());
        for output in &self.outputs {
            match output {
                TxOutput::OpReturn {
                    batch_id,
                    state_root,
                } => {
                    let mut data = Vec::with_capacity(40);
                    data.extend_from_slice(RECONCILIATION_MARKER);
                    data.extend_from_slice(&batch_id.to_le_bytes());
                    data.extend_from_slice(state_root);

                    let push_bytes = PushBytesBuf::try_from(data)
                        .map_err(|_| ReconciliationError::InvalidBatch(
                            "OP_RETURN data exceeds push limit".to_string()
                        ))?;

                    let script = Builder::new()
                        .push_opcode(bitcoin::blockdata::opcodes::all::OP_RETURN)
                        .push_slice(push_bytes)
                        .into_script();

                    tx_outputs.push(TxOut {
                        value: Amount::ZERO,
                        script_pubkey: script,
                    });
                }

                TxOutput::GhostLock {
                    address, amount, ..
                }
                | TxOutput::Payment {
                    address, amount, ..
                }
                | TxOutput::Exit {
                    address, amount, ..
                }
                | TxOutput::TreasuryFee { address, amount }
                | TxOutput::NodeFee { address, amount, .. } => {
                    let addr = Address::from_str(address)
                        .map_err(|e| {
                            ReconciliationError::InvalidBatch(format!("Invalid address: {}", e))
                        })?
                        .require_network(network)
                        .map_err(|e| {
                            ReconciliationError::InvalidBatch(format!("Network mismatch: {}", e))
                        })?;

                    tx_outputs.push(TxOut {
                        value: Amount::from_sat(*amount),
                        script_pubkey: addr.script_pubkey(),
                    });
                }
            }
        }

        Ok(Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: tx_inputs,
            output: tx_outputs,
        })
    }

    /// Compute the real Bitcoin txid
    pub fn compute_real_txid(
        &self,
        input_outpoints: &[bitcoin::OutPoint],
        network: Network,
    ) -> Result<[u8; 32], ReconciliationError> {
        let tx = self.to_bitcoin_transaction(input_outpoints, network)?;
        // Use Hash trait to get bytes
        use bitcoin::hashes::Hash;
        Ok(tx.compute_txid().to_byte_array())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_creation() {
        let state_root = [1u8; 32];
        let mut tx = ReconciliationTx::new(100, state_root, 1000);

        tx.add_input([1u8; 32], 1_000_000);
        tx.add_input([2u8; 32], 2_000_000);

        assert_eq!(tx.inputs().len(), 2);
        assert_eq!(tx.total_input(), 3_000_000);
    }

    #[test]
    fn test_op_return_data() {
        let state_root = [42u8; 32];
        let tx = ReconciliationTx::new(100, state_root, 1000);

        let data = tx.op_return_data();
        assert_eq!(&data[..4], RECONCILIATION_MARKER);
    }

    #[test]
    fn test_l2_txid_deterministic() {
        let state_root = [1u8; 32];
        let tx = ReconciliationTx::new(100, state_root, 1000);

        let txid1 = tx.compute_l2_txid();
        let txid2 = tx.compute_l2_txid();
        assert_eq!(txid1, txid2);
    }
}
