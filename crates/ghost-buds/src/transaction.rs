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

//! Transaction wrapper for BUDS analysis

use bitcoin::{Transaction, TxOut};
use serde::{Deserialize, Serialize};

use crate::tier::{BudsTier, ClassificationResult, DetectedFeature};

/// Transaction with BUDS classification metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifiedTransaction {
    /// Transaction ID (hex)
    pub txid: String,
    /// Assigned BUDS tier
    pub tier: BudsTier,
    /// Classification result with details
    pub classification: ClassificationResult,
    /// Transaction weight (vbytes)
    pub weight: usize,
    /// Transaction fee (satoshis)
    pub fee: Option<u64>,
    /// Fee rate (sat/vB)
    pub fee_rate: Option<f64>,
    /// Total output value
    pub output_value: u64,
    /// Number of inputs
    pub input_count: usize,
    /// Number of outputs
    pub output_count: usize,
    /// Is this a coinbase transaction
    pub is_coinbase: bool,
}

impl ClassifiedTransaction {
    /// Create from a Bitcoin transaction and classification
    pub fn new(tx: &Transaction, classification: ClassificationResult, fee: Option<u64>) -> Self {
        let txid = tx.compute_txid().to_string();
        let weight = tx.weight().to_wu() as usize;
        let output_value: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        let fee_rate = fee.map(|f| f as f64 / (weight as f64 / 4.0));

        Self {
            txid,
            tier: classification.tier,
            classification,
            weight,
            fee,
            fee_rate,
            output_value,
            input_count: tx.input.len(),
            output_count: tx.output.len(),
            is_coinbase: tx.is_coinbase(),
        }
    }

    /// Check if transaction should be included given allowed tiers
    pub fn is_allowed(&self, allowed_tiers: &[BudsTier]) -> bool {
        self.tier.is_allowed_by(allowed_tiers)
    }
}

/// Statistics about a set of classified transactions
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClassificationStats {
    /// Total transactions analyzed
    pub total_count: usize,
    /// Count per tier
    pub tier_counts: TierCounts,
    /// Total weight per tier
    pub tier_weights: TierWeights,
    /// Total fees per tier
    pub tier_fees: TierFees,
    /// Detected feature counts
    pub feature_counts: FeatureCounts,
}

/// Counts by tier
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TierCounts {
    pub t0: usize,
    pub t1: usize,
    pub t2: usize,
    pub t3: usize,
}

impl TierCounts {
    pub fn increment(&mut self, tier: BudsTier) {
        match tier {
            BudsTier::T0 => self.t0 += 1,
            BudsTier::T1 => self.t1 += 1,
            BudsTier::T2 => self.t2 += 1,
            BudsTier::T3 => self.t3 += 1,
        }
    }

    pub fn get(&self, tier: BudsTier) -> usize {
        match tier {
            BudsTier::T0 => self.t0,
            BudsTier::T1 => self.t1,
            BudsTier::T2 => self.t2,
            BudsTier::T3 => self.t3,
        }
    }
}

/// Weight by tier
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TierWeights {
    pub t0: usize,
    pub t1: usize,
    pub t2: usize,
    pub t3: usize,
}

impl TierWeights {
    pub fn add(&mut self, tier: BudsTier, weight: usize) {
        match tier {
            BudsTier::T0 => self.t0 += weight,
            BudsTier::T1 => self.t1 += weight,
            BudsTier::T2 => self.t2 += weight,
            BudsTier::T3 => self.t3 += weight,
        }
    }
}

/// Fees by tier
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TierFees {
    pub t0: u64,
    pub t1: u64,
    pub t2: u64,
    pub t3: u64,
}

impl TierFees {
    pub fn add(&mut self, tier: BudsTier, fee: u64) {
        match tier {
            BudsTier::T0 => self.t0 += fee,
            BudsTier::T1 => self.t1 += fee,
            BudsTier::T2 => self.t2 += fee,
            BudsTier::T3 => self.t3 += fee,
        }
    }
}

/// Counts of detected features
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeatureCounts {
    pub p2pkh: usize,
    pub p2wpkh: usize,
    pub p2sh: usize,
    pub p2wsh: usize,
    pub p2tr: usize,
    pub op_return: usize,
    pub multisig: usize,
    pub timelock: usize,
    pub htlc: usize,
    pub inscription: usize,
    pub runes: usize,
    pub brc20: usize,
}

impl FeatureCounts {
    pub fn increment(&mut self, feature: &DetectedFeature) {
        match feature {
            DetectedFeature::P2pkh => self.p2pkh += 1,
            DetectedFeature::P2wpkh => self.p2wpkh += 1,
            DetectedFeature::P2sh => self.p2sh += 1,
            DetectedFeature::P2wsh => self.p2wsh += 1,
            DetectedFeature::P2tr => self.p2tr += 1,
            DetectedFeature::OpReturn { .. } => self.op_return += 1,
            DetectedFeature::Multisig { .. } => self.multisig += 1,
            DetectedFeature::Cltv | DetectedFeature::Csv => self.timelock += 1,
            DetectedFeature::Htlc => self.htlc += 1,
            DetectedFeature::InscriptionEnvelope => self.inscription += 1,
            DetectedFeature::RunesRunestone => self.runes += 1,
            DetectedFeature::Brc20Pattern => self.brc20 += 1,
            DetectedFeature::LargeWitness { .. } => {} // Not counted separately
        }
    }
}

impl ClassificationStats {
    /// Create new empty stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a classified transaction to the stats
    pub fn add(&mut self, tx: &ClassifiedTransaction) {
        self.total_count += 1;
        self.tier_counts.increment(tx.tier);
        self.tier_weights.add(tx.tier, tx.weight);

        if let Some(fee) = tx.fee {
            self.tier_fees.add(tx.tier, fee);
        }

        for feature in &tx.classification.features {
            self.feature_counts.increment(feature);
        }
    }

    /// Get percentage of transactions in each tier
    pub fn tier_percentages(&self) -> (f64, f64, f64, f64) {
        if self.total_count == 0 {
            return (0.0, 0.0, 0.0, 0.0);
        }

        let total = self.total_count as f64;
        (
            self.tier_counts.t0 as f64 / total * 100.0,
            self.tier_counts.t1 as f64 / total * 100.0,
            self.tier_counts.t2 as f64 / total * 100.0,
            self.tier_counts.t3 as f64 / total * 100.0,
        )
    }
}

/// Analyze transaction outputs for value distribution
pub fn analyze_outputs(outputs: &[TxOut]) -> OutputAnalysis {
    let mut analysis = OutputAnalysis::default();

    for output in outputs {
        let script = &output.script_pubkey;
        let value = output.value.to_sat();

        analysis.total_value += value;
        analysis.output_count += 1;

        if script.is_op_return() {
            analysis.op_return_count += 1;
            analysis.op_return_size += script.len();
        } else if script.is_p2pkh() || script.is_p2wpkh() {
            analysis.payment_count += 1;
            analysis.payment_value += value;
        } else if script.is_p2sh() || script.is_p2wsh() {
            analysis.script_count += 1;
            analysis.script_value += value;
        } else if script.is_p2tr() {
            analysis.taproot_count += 1;
            analysis.taproot_value += value;
        }
    }

    analysis
}

/// Analysis of transaction outputs
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OutputAnalysis {
    pub output_count: usize,
    pub total_value: u64,
    pub payment_count: usize,
    pub payment_value: u64,
    pub script_count: usize,
    pub script_value: u64,
    pub taproot_count: usize,
    pub taproot_value: u64,
    pub op_return_count: usize,
    pub op_return_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::script::Builder as ScriptBuilder;
    use bitcoin::{Amount, ScriptBuf, WPubkeyHash};

    #[test]
    fn test_tier_counts() {
        let mut counts = TierCounts::default();
        counts.increment(BudsTier::T0);
        counts.increment(BudsTier::T0);
        counts.increment(BudsTier::T1);

        assert_eq!(counts.t0, 2);
        assert_eq!(counts.t1, 1);
        assert_eq!(counts.get(BudsTier::T0), 2);
    }

    #[test]
    fn test_stats_percentages() {
        let mut stats = ClassificationStats::new();

        // Simulate adding transactions
        stats.total_count = 100;
        stats.tier_counts.t0 = 60;
        stats.tier_counts.t1 = 25;
        stats.tier_counts.t2 = 10;
        stats.tier_counts.t3 = 5;

        let (t0, t1, t2, t3) = stats.tier_percentages();
        assert_eq!(t0, 60.0);
        assert_eq!(t1, 25.0);
        assert_eq!(t2, 10.0);
        assert_eq!(t3, 5.0);
    }

    #[test]
    fn test_analyze_outputs_empty() {
        let analysis = analyze_outputs(&[]);
        assert_eq!(analysis.output_count, 0);
        assert_eq!(analysis.total_value, 0);
        assert_eq!(analysis.payment_count, 0);
        assert_eq!(analysis.payment_value, 0);
        assert_eq!(analysis.script_count, 0);
        assert_eq!(analysis.script_value, 0);
        assert_eq!(analysis.taproot_count, 0);
        assert_eq!(analysis.taproot_value, 0);
        assert_eq!(analysis.op_return_count, 0);
        assert_eq!(analysis.op_return_size, 0);
    }

    #[test]
    fn test_analyze_outputs_op_return() {
        let op_return_script = ScriptBuilder::new()
            .push_opcode(bitcoin::opcodes::all::OP_RETURN)
            .push_slice(b"hello")
            .into_script();
        let outputs = vec![TxOut {
            value: Amount::from_sat(0),
            script_pubkey: op_return_script,
        }];
        let analysis = analyze_outputs(&outputs);
        assert_eq!(analysis.op_return_count, 1);
        assert_eq!(analysis.output_count, 1);
        assert_eq!(analysis.payment_count, 0);
    }

    #[test]
    fn test_analyze_outputs_p2wpkh() {
        // Build a valid P2WPKH scriptPubKey: OP_0 <20-byte-hash>
        let hash = WPubkeyHash::from_slice(&[0xab; 20]).expect("valid 20 byte hash");
        let p2wpkh_script = ScriptBuf::new_p2wpkh(&hash);
        let outputs = vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2wpkh_script,
        }];
        let analysis = analyze_outputs(&outputs);
        assert_eq!(analysis.payment_count, 1);
        assert_eq!(analysis.payment_value, 50_000);
        assert_eq!(analysis.op_return_count, 0);
        assert_eq!(analysis.output_count, 1);
    }

    #[test]
    fn test_tier_percentages_zero_count() {
        let stats = ClassificationStats::new();
        let (t0, t1, t2, t3) = stats.tier_percentages();
        assert_eq!(t0, 0.0);
        assert_eq!(t1, 0.0);
        assert_eq!(t2, 0.0);
        assert_eq!(t3, 0.0);
    }

    #[test]
    fn test_tier_weights_add() {
        let mut weights = TierWeights::default();
        weights.add(BudsTier::T0, 100);
        weights.add(BudsTier::T0, 50);
        weights.add(BudsTier::T1, 200);
        weights.add(BudsTier::T2, 300);
        weights.add(BudsTier::T3, 400);

        assert_eq!(weights.t0, 150);
        assert_eq!(weights.t1, 200);
        assert_eq!(weights.t2, 300);
        assert_eq!(weights.t3, 400);
    }

    #[test]
    fn test_feature_counts_increment_all() {
        let mut counts = FeatureCounts::default();

        counts.increment(&DetectedFeature::P2pkh);
        counts.increment(&DetectedFeature::P2wpkh);
        counts.increment(&DetectedFeature::P2sh);
        counts.increment(&DetectedFeature::P2wsh);
        counts.increment(&DetectedFeature::P2tr);
        counts.increment(&DetectedFeature::OpReturn { size: 40 });
        counts.increment(&DetectedFeature::Multisig { m: 2, n: 3 });
        counts.increment(&DetectedFeature::Cltv);
        counts.increment(&DetectedFeature::Csv);
        counts.increment(&DetectedFeature::Htlc);
        counts.increment(&DetectedFeature::InscriptionEnvelope);
        counts.increment(&DetectedFeature::RunesRunestone);
        counts.increment(&DetectedFeature::Brc20Pattern);
        counts.increment(&DetectedFeature::LargeWitness { bytes: 5000 });

        assert_eq!(counts.p2pkh, 1);
        assert_eq!(counts.p2wpkh, 1);
        assert_eq!(counts.p2sh, 1);
        assert_eq!(counts.p2wsh, 1);
        assert_eq!(counts.p2tr, 1);
        assert_eq!(counts.op_return, 1);
        assert_eq!(counts.multisig, 1);
        assert_eq!(counts.timelock, 2); // Cltv + Csv both map to timelock
        assert_eq!(counts.htlc, 1);
        assert_eq!(counts.inscription, 1);
        assert_eq!(counts.runes, 1);
        assert_eq!(counts.brc20, 1);
    }
}
