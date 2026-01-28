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
//| FILE: template.rs                                                                                                    |
//|======================================================================================================================|

//! Block template structures

use bitcoin::Transaction;
use serde::{Deserialize, Serialize};

/// Block template from Bitcoin Core
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTemplate {
    /// Block version
    pub version: i32,
    /// Previous block hash
    pub previousblockhash: String,
    /// Transactions to include
    pub transactions: Vec<TemplateTransaction>,
    /// Coinbase transaction (to be constructed)
    pub coinbaseaux: CoinbaseAux,
    /// Coinbase value (subsidy + fees)
    pub coinbasevalue: u64,
    /// Block target (compact form)
    pub bits: String,
    /// Block height
    pub height: u64,
    /// Current time
    pub curtime: u64,
    /// Minimum time
    pub mintime: u64,
    /// Mutable fields
    pub mutable: Vec<String>,
    /// Nonce range
    pub noncerange: String,
    /// Signature operations limit
    pub sigoplimit: u64,
    /// Size limit
    pub sizelimit: u64,
    /// Weight limit
    pub weightlimit: u64,
    /// Long poll ID
    pub longpollid: Option<String>,
    /// Target hash
    pub target: String,
}

/// Transaction in block template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateTransaction {
    /// Transaction data (hex)
    pub data: String,
    /// Transaction ID
    pub txid: String,
    /// Transaction hash (for witness txs)
    pub hash: String,
    /// Dependencies (indices of transactions this depends on)
    pub depends: Vec<usize>,
    /// Transaction fee (satoshis)
    pub fee: u64,
    /// Signature operations
    pub sigops: u64,
    /// Transaction weight
    pub weight: u64,
}

impl TemplateTransaction {
    /// Decode the transaction
    pub fn decode(&self) -> Result<Transaction, bitcoin::consensus::encode::Error> {
        let bytes = hex::decode(&self.data).map_err(|_| {
            bitcoin::consensus::encode::Error::ParseFailed("Invalid hex")
        })?;
        bitcoin::consensus::deserialize(&bytes)
    }

    /// Fee rate in sat/vB
    pub fn fee_rate(&self) -> f64 {
        if self.weight == 0 {
            return 0.0;
        }
        self.fee as f64 / (self.weight as f64 / 4.0)
    }
}

/// Coinbase auxiliary data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoinbaseAux {
    /// Flags to include in coinbase
    pub flags: Option<String>,
}

/// Filtered block template
#[derive(Debug, Clone)]
pub struct FilteredTemplate {
    /// Original template
    pub original: BlockTemplate,
    /// Filtered transactions (indices into original)
    pub included_indices: Vec<usize>,
    /// Rejected transactions (indices into original)
    pub rejected_indices: Vec<usize>,
    /// New merkle root
    pub merkle_root: [u8; 32],
    /// Total fee from included transactions
    pub total_fee: u64,
    /// Total weight of included transactions
    pub total_weight: u64,
}

impl FilteredTemplate {
    /// Get included transactions
    pub fn included_transactions(&self) -> Vec<&TemplateTransaction> {
        self.included_indices
            .iter()
            .map(|&i| &self.original.transactions[i])
            .collect()
    }

    /// Get rejected transactions
    pub fn rejected_transactions(&self) -> Vec<&TemplateTransaction> {
        self.rejected_indices
            .iter()
            .map(|&i| &self.original.transactions[i])
            .collect()
    }

    /// Rejection rate
    pub fn rejection_rate(&self) -> f64 {
        let total = self.original.transactions.len();
        if total == 0 {
            return 0.0;
        }
        self.rejected_indices.len() as f64 / total as f64
    }

    /// Fee impact (fees lost to filtering)
    pub fn fee_impact(&self) -> u64 {
        let original_fees: u64 = self.original.transactions.iter().map(|t| t.fee).sum();
        original_fees - self.total_fee
    }
}

/// Template statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TemplateStats {
    /// Original transaction count
    pub original_tx_count: usize,
    /// Filtered transaction count
    pub filtered_tx_count: usize,
    /// Original total fee
    pub original_total_fee: u64,
    /// Filtered total fee
    pub filtered_total_fee: u64,
    /// Original total weight
    pub original_total_weight: u64,
    /// Filtered total weight
    pub filtered_total_weight: u64,
    /// Transactions rejected per tier
    pub rejected_by_tier: TierRejections,
    /// Average fee rate (original)
    pub original_avg_fee_rate: f64,
    /// Average fee rate (filtered)
    pub filtered_avg_fee_rate: f64,
}

/// Rejections by BUDS tier
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TierRejections {
    pub t0: usize,
    pub t1: usize,
    pub t2: usize,
    pub t3: usize,
}

impl TemplateStats {
    /// Calculate stats from filtered template
    pub fn from_filtered(template: &FilteredTemplate) -> Self {
        let original_total_fee: u64 = template.original.transactions.iter().map(|t| t.fee).sum();
        let original_total_weight: u64 = template.original.transactions.iter().map(|t| t.weight).sum();

        let original_avg_fee_rate = if original_total_weight > 0 {
            original_total_fee as f64 / (original_total_weight as f64 / 4.0)
        } else {
            0.0
        };

        let filtered_avg_fee_rate = if template.total_weight > 0 {
            template.total_fee as f64 / (template.total_weight as f64 / 4.0)
        } else {
            0.0
        };

        Self {
            original_tx_count: template.original.transactions.len(),
            filtered_tx_count: template.included_indices.len(),
            original_total_fee,
            filtered_total_fee: template.total_fee,
            original_total_weight,
            filtered_total_weight: template.total_weight,
            rejected_by_tier: TierRejections::default(),
            original_avg_fee_rate,
            filtered_avg_fee_rate,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_rate() {
        let tx = TemplateTransaction {
            data: String::new(),
            txid: String::new(),
            hash: String::new(),
            depends: vec![],
            fee: 1000,
            sigops: 1,
            weight: 400, // 100 vB
        };

        assert_eq!(tx.fee_rate(), 10.0); // 1000 sat / 100 vB = 10 sat/vB
    }
}
