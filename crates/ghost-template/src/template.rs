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
        let bytes = hex::decode(&self.data)
            .map_err(|_| bitcoin::consensus::encode::Error::ParseFailed("Invalid hex"))?;
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
        let original_total_weight: u64 = template
            .original
            .transactions
            .iter()
            .map(|t| t.weight)
            .sum();

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

    // ---- Helper builders for tests ----

    fn make_tx(fee: u64, weight: u64) -> TemplateTransaction {
        TemplateTransaction {
            data: String::new(),
            txid: String::new(),
            hash: String::new(),
            depends: vec![],
            fee,
            sigops: 1,
            weight,
        }
    }

    fn make_block_template(txs: Vec<TemplateTransaction>) -> BlockTemplate {
        BlockTemplate {
            version: 0x20000000,
            previousblockhash: "00".repeat(32),
            transactions: txs,
            coinbaseaux: CoinbaseAux::default(),
            coinbasevalue: 5_000_000_000,
            bits: "1d00ffff".to_string(),
            height: 1,
            curtime: 1700000000,
            mintime: 1700000000,
            mutable: vec![],
            noncerange: "00000000ffffffff".to_string(),
            sigoplimit: 80000,
            sizelimit: 4000000,
            weightlimit: 4000000,
            longpollid: None,
            target: "00".repeat(32),
        }
    }

    // ---- New tests ----

    #[test]
    fn test_fee_rate_zero_weight() {
        let tx = make_tx(5000, 0);
        assert_eq!(tx.fee_rate(), 0.0, "zero weight must return 0.0 without div-by-zero");
    }

    #[test]
    fn test_fee_rate_zero_fee() {
        let tx = make_tx(0, 800);
        assert_eq!(tx.fee_rate(), 0.0, "zero fee must return 0.0");
    }

    #[test]
    fn test_rejection_rate_empty() {
        let template = FilteredTemplate {
            original: make_block_template(vec![]),
            included_indices: vec![],
            rejected_indices: vec![],
            merkle_root: [0u8; 32],
            total_fee: 0,
            total_weight: 0,
        };
        assert_eq!(
            template.rejection_rate(),
            0.0,
            "empty transaction list must yield 0.0 rejection rate"
        );
    }

    #[test]
    fn test_rejection_rate_all_rejected() {
        let txs = vec![make_tx(100, 400), make_tx(200, 800), make_tx(300, 600)];
        let template = FilteredTemplate {
            original: make_block_template(txs),
            included_indices: vec![],
            rejected_indices: vec![0, 1, 2],
            merkle_root: [0u8; 32],
            total_fee: 0,
            total_weight: 0,
        };
        assert_eq!(
            template.rejection_rate(),
            1.0,
            "all transactions rejected must yield 1.0"
        );
    }

    #[test]
    fn test_fee_impact_no_filtering() {
        let txs = vec![make_tx(1000, 400), make_tx(2000, 800)];
        let total_fee = 1000 + 2000;
        let total_weight = 400 + 800;
        let template = FilteredTemplate {
            original: make_block_template(txs),
            included_indices: vec![0, 1],
            rejected_indices: vec![],
            merkle_root: [0u8; 32],
            total_fee,
            total_weight,
        };
        assert_eq!(
            template.fee_impact(),
            0,
            "no rejected transactions means zero fee impact"
        );
    }

    #[test]
    fn test_template_stats_from_filtered() {
        // 5 transactions: indices 0-4. Include 0,1,2; reject 3,4.
        let txs = vec![
            make_tx(1000, 400),  // included
            make_tx(2000, 800),  // included
            make_tx(3000, 1200), // included
            make_tx(500, 200),   // rejected
            make_tx(700, 300),   // rejected
        ];
        let included_fee: u64 = 1000 + 2000 + 3000;
        let included_weight: u64 = 400 + 800 + 1200;
        let original_fee: u64 = 1000 + 2000 + 3000 + 500 + 700;
        let original_weight: u64 = 400 + 800 + 1200 + 200 + 300;

        let filtered = FilteredTemplate {
            original: make_block_template(txs),
            included_indices: vec![0, 1, 2],
            rejected_indices: vec![3, 4],
            merkle_root: [0u8; 32],
            total_fee: included_fee,
            total_weight: included_weight,
        };

        let stats = TemplateStats::from_filtered(&filtered);

        assert_eq!(stats.original_tx_count, 5);
        assert_eq!(stats.filtered_tx_count, 3);
        assert_eq!(stats.original_total_fee, original_fee);
        assert_eq!(stats.filtered_total_fee, included_fee);
        assert_eq!(stats.original_total_weight, original_weight);
        assert_eq!(stats.filtered_total_weight, included_weight);

        // Verify average fee rates: fee / (weight / 4.0)
        let expected_original_avg = original_fee as f64 / (original_weight as f64 / 4.0);
        let expected_filtered_avg = included_fee as f64 / (included_weight as f64 / 4.0);
        assert!(
            (stats.original_avg_fee_rate - expected_original_avg).abs() < 1e-9,
            "original avg fee rate mismatch: got {}, expected {}",
            stats.original_avg_fee_rate,
            expected_original_avg
        );
        assert!(
            (stats.filtered_avg_fee_rate - expected_filtered_avg).abs() < 1e-9,
            "filtered avg fee rate mismatch: got {}, expected {}",
            stats.filtered_avg_fee_rate,
            expected_filtered_avg
        );
    }
}
