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
//| FILE: coinbase.rs                                                                                                    |
//|======================================================================================================================|

//! Coinbase transaction construction

use bitcoin::{
    absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Witness,
};
use tracing::info;

use ghost_common::constants::MAX_COINBASE_OUTPUTS;
use ghost_common::error::{GhostError, GhostResult};
use ghost_common::types::PayoutEntry;

use crate::payout::PayoutResult;

/// Coinbase transaction builder
#[derive(Debug, Clone)]
pub struct CoinbaseBuilder {
    /// Block height
    block_height: u64,
    /// Block hash (for BIP34)
    block_hash: Option<[u8; 32]>,
    /// Extra nonce space
    extra_nonce_size: usize,
    /// Pool identifier in coinbase
    pool_tag: Vec<u8>,
}

impl CoinbaseBuilder {
    /// Create a new coinbase builder
    pub fn new(block_height: u64) -> Self {
        Self {
            block_height,
            block_hash: None,
            extra_nonce_size: 8,
            pool_tag: b"Ghost".to_vec(),
        }
    }

    /// Set block hash
    pub fn with_block_hash(mut self, hash: [u8; 32]) -> Self {
        self.block_hash = Some(hash);
        self
    }

    /// Set extra nonce size
    pub fn with_extra_nonce_size(mut self, size: usize) -> Self {
        self.extra_nonce_size = size;
        self
    }

    /// Set pool tag
    pub fn with_pool_tag(mut self, tag: impl Into<Vec<u8>>) -> Self {
        self.pool_tag = tag.into();
        self
    }

    /// Build coinbase script sig (BIP34 compliant)
    fn build_script_sig(&self) -> ScriptBuf {
        // BIP34: Block height in script sig
        let height_bytes = self.block_height.to_le_bytes();
        let height_len = height_bytes
            .iter()
            .rposition(|&b| b != 0)
            .map(|i| i + 1)
            .unwrap_or(1);

        let mut script_data = Vec::new();

        // Push height (variable length)
        script_data.push(height_len as u8);
        script_data.extend_from_slice(&height_bytes[..height_len]);

        // Extra nonce placeholder
        script_data.extend(vec![0u8; self.extra_nonce_size]);

        // Pool tag
        if !self.pool_tag.is_empty() {
            script_data.extend_from_slice(&self.pool_tag);
        }

        ScriptBuf::from(script_data)
    }

    /// Build coinbase transaction from payout result
    pub fn build(&self, payouts: &PayoutResult) -> GhostResult<Transaction> {
        // Validate output count
        if payouts.output_count() > MAX_COINBASE_OUTPUTS {
            return Err(GhostError::TooManyOutputs {
                count: payouts.output_count(),
                limit: MAX_COINBASE_OUTPUTS,
            });
        }

        // Build outputs
        let mut outputs = Vec::new();

        // Add all payout entries
        for entry in payouts.all_entries() {
            let script = self.script_from_address(&entry.address)?;
            outputs.push(TxOut {
                value: Amount::from_sat(entry.amount),
                script_pubkey: script,
            });
        }

        // Build the coinbase transaction
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(), // Coinbase has null input
                script_sig: self.build_script_sig(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: outputs,
        };

        info!(
            height = self.block_height,
            outputs = tx.output.len(),
            "Built coinbase transaction"
        );

        Ok(tx)
    }

    /// Build coinbase from raw entries
    pub fn build_from_entries(&self, entries: &[PayoutEntry]) -> GhostResult<Transaction> {
        if entries.len() > MAX_COINBASE_OUTPUTS {
            return Err(GhostError::TooManyOutputs {
                count: entries.len(),
                limit: MAX_COINBASE_OUTPUTS,
            });
        }

        let mut outputs = Vec::new();

        for entry in entries {
            let script = self.script_from_address(&entry.address)?;
            outputs.push(TxOut {
                value: Amount::from_sat(entry.amount),
                script_pubkey: script,
            });
        }

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: self.build_script_sig(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: outputs,
        };

        Ok(tx)
    }

    /// Convert address bytes to script pubkey
    ///
    /// Address can be:
    /// - Raw script pubkey bytes (for internal use)
    /// - Bech32/Bech32m encoded address string (P2WPKH, P2WSH only - P2TR rejected)
    ///
    /// # Quantum Safety
    ///
    /// P2TR addresses (bc1p...) are rejected for quantum safety.
    /// P2TR exposes public keys on-chain, making them vulnerable to
    /// quantum computer attacks while funds are locked.
    fn script_from_address(&self, address: &[u8]) -> GhostResult<ScriptBuf> {
        // First, try to parse as UTF-8 address string
        if let Ok(addr_str) = std::str::from_utf8(address) {
            // QUANTUM SAFETY: Reject P2TR addresses
            if addr_str.starts_with("bc1p")
                || addr_str.starts_with("tb1p")
                || addr_str.starts_with("bcrt1p")
            {
                return Err(GhostError::QuantumUnsafe(
                    "P2TR addresses (bc1p...) are quantum-vulnerable. Use P2WPKH (bc1q...) instead.".into()
                ));
            }

            // Try to parse as Bitcoin address
            if let Ok(addr) =
                addr_str.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            {
                // Return the script pubkey without network validation
                // (validation happens at transaction broadcast time)
                return Ok(addr.assume_checked().script_pubkey());
            }
        }

        // If raw script pubkey bytes, check for P2TR format
        // P2TR: 34 bytes, starts with OP_1 (0x51) + PUSH32 (0x20)
        if address.len() == 34 && address[0] == 0x51 && address[1] == 0x20 {
            return Err(GhostError::QuantumUnsafe(
                "P2TR script pubkeys are quantum-vulnerable. Use P2WSH instead.".into(),
            ));
        }

        // Defense-in-depth: reject oversized raw scripts
        // P2WSH (34 bytes) is the largest standard non-OP_RETURN scriptPubKey
        if address.len() > 34 {
            return Err(GhostError::InvalidInput(format!(
                "Raw script pubkey too large: {} bytes (max 34)",
                address.len()
            )));
        }

        Ok(ScriptBuf::from(address.to_vec()))
    }

    /// Calculate coinbase commitment for merkle root
    pub fn calculate_commitment(tx: &Transaction) -> [u8; 32] {
        use bitcoin::hashes::{sha256d, Hash};

        let serialized = bitcoin::consensus::serialize(tx);
        let hash = sha256d::Hash::hash(&serialized);
        hash.to_byte_array()
    }
}

/// Coinbase output allocation
#[derive(Debug, Clone)]
pub struct CoinbaseAllocation {
    /// Treasury output
    pub treasury: Option<(Vec<u8>, u64)>,
    /// TX fees output (to block builder)
    pub tx_fees: Option<(Vec<u8>, u64)>,
    /// Node reward outputs
    pub node_rewards: Vec<(Vec<u8>, u64)>,
    /// Miner outputs
    pub miners: Vec<(Vec<u8>, u64)>,
}

impl CoinbaseAllocation {
    /// Create from payout result
    pub fn from_payout_result(payouts: &PayoutResult) -> Self {
        Self {
            treasury: payouts
                .treasury_entry
                .as_ref()
                .map(|e| (e.address.clone(), e.amount)),
            tx_fees: payouts
                .tx_fee_entry
                .as_ref()
                .map(|e| (e.address.clone(), e.amount)),
            node_rewards: payouts
                .node_payouts
                .iter()
                .map(|e| (e.address.clone(), e.amount))
                .collect(),
            miners: payouts
                .miner_payouts
                .iter()
                .map(|e| (e.address.clone(), e.amount))
                .collect(),
        }
    }

    /// Total output count
    pub fn output_count(&self) -> usize {
        let mut count = 0;
        if self.treasury.is_some() {
            count += 1;
        }
        if self.tx_fees.is_some() {
            count += 1;
        }
        count += self.node_rewards.len();
        count += self.miners.len();
        count
    }

    /// Total amount
    pub fn total_amount(&self) -> u64 {
        let mut total = 0u64;
        if let Some((_, amt)) = &self.treasury {
            total += amt;
        }
        if let Some((_, amt)) = &self.tx_fees {
            total += amt;
        }
        total += self.node_rewards.iter().map(|(_, amt)| amt).sum::<u64>();
        total += self.miners.iter().map(|(_, amt)| amt).sum::<u64>();
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coinbase_builder() {
        let builder = CoinbaseBuilder::new(100)
            .with_pool_tag(b"TestPool")
            .with_extra_nonce_size(8);

        let entries = vec![
            PayoutEntry {
                address: vec![0x00; 25], // P2PKH-like
                amount: 100_000,
                recipient_id: [0u8; 32],
                payout_type: ghost_common::types::PayoutType::Treasury,
            },
            PayoutEntry {
                address: vec![0x00; 25],
                amount: 200_000,
                recipient_id: [1u8; 32],
                payout_type: ghost_common::types::PayoutType::Mining,
            },
        ];

        let tx = builder.build_from_entries(&entries).unwrap();

        assert_eq!(tx.input.len(), 1);
        assert!(tx.input[0].previous_output.is_null());
        assert_eq!(tx.output.len(), 2);
    }

    #[test]
    fn test_output_limit() {
        let builder = CoinbaseBuilder::new(100);

        let entries: Vec<PayoutEntry> = (0..350)
            .map(|i| PayoutEntry {
                address: vec![i as u8; 25],
                amount: 1000,
                recipient_id: [i as u8; 32],
                payout_type: ghost_common::types::PayoutType::Mining,
            })
            .collect();

        let result = builder.build_from_entries(&entries);
        assert!(result.is_err());
    }
}
