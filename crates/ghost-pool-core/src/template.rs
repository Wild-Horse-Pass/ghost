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
//| FILE: template.rs                                                                              |
//|======================================================================================================================|

//! Block template handling for mining job creation.
//!
//! This module converts Bitcoin Core's getblocktemplate response into
//! mining jobs that can be distributed to miners.

use ghost_primitives::{BlockHash, Txid};
use thiserror::Error;

use crate::job::{JobBuilder, JobId, MiningJob, TransactionData};

/// Errors that can occur during template processing.
#[derive(Debug, Error)]
pub enum TemplateError {
    #[error("Failed to decode hex: {0}")]
    HexDecode(String),
    #[error("Invalid block hash: {0}")]
    InvalidBlockHash(String),
    #[error("Invalid transaction ID: {0}")]
    InvalidTxid(String),
    #[error("Invalid nbits: {0}")]
    InvalidNbits(String),
}

/// Block template from Bitcoin Core's getblocktemplate RPC.
///
/// This is a simplified version that contains just what we need
/// for job creation.
#[derive(Debug, Clone)]
pub struct BlockTemplate {
    /// Block version.
    pub version: u32,
    /// Previous block hash (hex, reversed display order).
    pub prev_block_hash: String,
    /// Block height.
    pub height: u64,
    /// Difficulty bits (hex).
    pub bits: String,
    /// Coinbase value (subsidy + fees).
    pub coinbase_value: u64,
    /// Transactions to include.
    pub transactions: Vec<TemplateTransaction>,
    /// Current time.
    pub curtime: u64,
}

/// Transaction from the block template.
#[derive(Debug, Clone)]
pub struct TemplateTransaction {
    /// Transaction ID (hex, reversed display order).
    pub txid: String,
    /// Witness transaction ID (hex, reversed display order).
    /// For non-segwit transactions, this equals txid.
    pub wtxid: String,
    /// Raw transaction data (hex).
    pub data: String,
    /// Fee in satoshis.
    pub fee: u64,
    /// Transaction weight.
    pub weight: u32,
}

impl BlockTemplate {
    /// Convert this template into a JobBuilder.
    ///
    /// The caller should add coinbase outputs before building the job.
    pub fn to_job_builder(&self) -> Result<JobBuilder, TemplateError> {
        // Parse previous block hash
        let prev_hash = parse_block_hash(&self.prev_block_hash)?;

        // Parse nbits
        let nbits = parse_nbits(&self.bits)?;

        // Start building the job
        let mut builder = JobBuilder::new()
            .prev_block_hash(prev_hash)
            .version(self.version)
            .nbits(nbits)
            .block_height(self.height as u32)
            .block_reward(self.coinbase_value);

        // Add transactions
        for tx in &self.transactions {
            let tx_data = parse_transaction(tx)?;
            builder = builder.add_transaction(tx_data);
        }

        Ok(builder)
    }

    /// Create a mining job from this template.
    ///
    /// This is a convenience method that builds a job with the given
    /// coinbase outputs.
    pub fn to_mining_job(
        &self,
        job_id: JobId,
        coinbase_outputs: Vec<(Vec<u8>, u64)>,
    ) -> Result<MiningJob, TemplateError> {
        let mut builder = self.to_job_builder()?;

        for (script, value) in coinbase_outputs {
            builder = builder.add_coinbase_output(script, value);
        }

        Ok(builder.build(job_id))
    }

    /// Calculate total fees from all transactions.
    pub fn total_fees(&self) -> u64 {
        self.transactions.iter().map(|tx| tx.fee).sum()
    }

    /// Get the block subsidy (coinbase_value - fees).
    pub fn subsidy(&self) -> u64 {
        self.coinbase_value.saturating_sub(self.total_fees())
    }
}

/// Parse a hex block hash (reversed display order) into BlockHash.
fn parse_block_hash(hex: &str) -> Result<BlockHash, TemplateError> {
    BlockHash::from_hex(hex)
        .map_err(|_| TemplateError::InvalidBlockHash(hex.to_string()))
}

/// Parse hex nbits into u32.
fn parse_nbits(hex: &str) -> Result<u32, TemplateError> {
    u32::from_str_radix(hex, 16)
        .map_err(|_| TemplateError::InvalidNbits(hex.to_string()))
}

/// Parse a template transaction into TransactionData.
fn parse_transaction(tx: &TemplateTransaction) -> Result<TransactionData, TemplateError> {
    // Parse txid
    let txid = parse_txid(&tx.txid)?;

    // Parse wtxid
    let wtxid = parse_wtxid(&tx.wtxid)?;

    // Decode transaction data
    let data = hex::decode(&tx.data)
        .map_err(|e| TemplateError::HexDecode(e.to_string()))?;

    Ok(TransactionData {
        txid,
        wtxid,
        data,
        fee: tx.fee,
        weight: tx.weight,
    })
}

/// Parse a hex txid (reversed display order) into Txid.
fn parse_txid(hex: &str) -> Result<Txid, TemplateError> {
    Txid::from_hex(hex)
        .map_err(|_| TemplateError::InvalidTxid(hex.to_string()))
}

/// Parse a hex wtxid (reversed display order) into bytes.
fn parse_wtxid(hex: &str) -> Result<[u8; 32], TemplateError> {
    let bytes = hex::decode(hex)
        .map_err(|e| TemplateError::HexDecode(e.to_string()))?;

    if bytes.len() != 32 {
        return Err(TemplateError::InvalidTxid(hex.to_string()));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    // Reverse for internal representation (Bitcoin displays reversed)
    arr.reverse();
    Ok(arr)
}

/// Create a BlockTemplate from ghost-core-client's BlockTemplate fields.
///
/// This is a helper for converting the RPC response format.
impl BlockTemplate {
    /// Create from ghost-core-client BlockTemplate fields.
    ///
    /// Use this when you have data from getblocktemplate RPC.
    pub fn from_rpc(
        version: u32,
        previousblockhash: String,
        height: u64,
        bits: String,
        coinbasevalue: u64,
        curtime: u64,
        transactions: Vec<(String, String, String, i64, u32)>, // (txid, hash, data, fee, weight)
    ) -> Self {
        Self {
            version,
            prev_block_hash: previousblockhash,
            height,
            bits,
            coinbase_value: coinbasevalue,
            curtime,
            transactions: transactions.into_iter().map(|(txid, hash, data, fee, weight)| {
                TemplateTransaction {
                    txid,
                    wtxid: hash, // In getblocktemplate, 'hash' is the wtxid
                    data,
                    fee: fee.max(0) as u64, // Convert from i64, ensure non-negative
                    weight,
                }
            }).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_template() -> BlockTemplate {
        BlockTemplate {
            version: 0x20000000,
            prev_block_hash: "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            height: 800000,
            bits: "1d00ffff".to_string(),
            coinbase_value: 312_500_000 + 50_000, // subsidy + fees
            curtime: 1700000000,
            transactions: vec![
                TemplateTransaction {
                    txid: "0000000000000000000000000000000000000000000000000000000000000002".to_string(),
                    wtxid: "0000000000000000000000000000000000000000000000000000000000000003".to_string(),
                    data: "0100000000010100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff".to_string(),
                    fee: 50_000,
                    weight: 400,
                },
            ],
        }
    }

    #[test]
    fn test_template_to_job_builder() {
        let template = sample_template();
        let builder = template.to_job_builder().unwrap();

        // Builder should have the transaction
        // We can't inspect internal state, but we can build and check the result
        let job = builder
            .add_coinbase_output(vec![0x51], 312_550_000)
            .build(JobId::new(1));

        assert_eq!(job.version, 0x20000000);
        assert_eq!(job.nbits, 0x1d00ffff);
    }

    #[test]
    fn test_template_to_mining_job() {
        let template = sample_template();
        let job = template.to_mining_job(
            JobId::new(1),
            vec![(vec![0x51], 312_550_000)],
        ).unwrap();

        assert_eq!(job.id, JobId::new(1));

        // Should have witness commitment because we have transactions
        let marker = [0xaa, 0x21, 0xa9, 0xed];
        let has_commitment = job.coinbase2.windows(4).any(|w| w == marker);
        assert!(has_commitment, "Should have witness commitment");
    }

    #[test]
    fn test_total_fees() {
        let template = sample_template();
        assert_eq!(template.total_fees(), 50_000);
    }

    #[test]
    fn test_subsidy() {
        let template = sample_template();
        assert_eq!(template.subsidy(), 312_500_000);
    }

    #[test]
    fn test_parse_nbits() {
        assert_eq!(parse_nbits("1d00ffff").unwrap(), 0x1d00ffff);
        assert_eq!(parse_nbits("170c7f12").unwrap(), 0x170c7f12);
    }

    #[test]
    fn test_parse_block_hash() {
        let hash = parse_block_hash(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ).unwrap();
        // After reversal, the internal bytes should be different
        assert_ne!(hash.as_bytes()[0], 0);
    }
}
