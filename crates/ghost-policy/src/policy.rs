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
//| FILE: policy.rs                                                                                                      |
//|======================================================================================================================|

//! Policy engine for transaction filtering
//!
//! The policy engine evaluates transactions against the active policy profile.

use bitcoin::Transaction;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use ghost_buds::{BudsClassifier, BudsTier, ClassificationResult};

use crate::profile::PolicyProfile;

/// Policy engine for evaluating transactions
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    /// Active policy profile
    profile: PolicyProfile,
    /// BUDS classifier
    classifier: BudsClassifier,
    /// Statistics
    stats: PolicyStats,
}

impl PolicyEngine {
    /// Create a new policy engine with the given profile
    pub fn new(profile: PolicyProfile) -> Self {
        debug!(profile = %profile.name, "Creating policy engine");
        Self {
            profile,
            classifier: BudsClassifier::new(),
            stats: PolicyStats::default(),
        }
    }

    /// Create with default (permissive) profile
    pub fn permissive() -> Self {
        Self::new(PolicyProfile::permissive())
    }

    /// Create with bitcoin_pure profile
    pub fn bitcoin_pure() -> Self {
        Self::new(PolicyProfile::bitcoin_pure())
    }

    /// Create with full_open profile
    pub fn full_open() -> Self {
        Self::new(PolicyProfile::full_open())
    }

    /// Get the active profile
    pub fn profile(&self) -> &PolicyProfile {
        &self.profile
    }

    /// Update the active profile
    pub fn set_profile(&mut self, profile: PolicyProfile) {
        debug!(
            old_profile = %self.profile.name,
            new_profile = %profile.name,
            "Updating policy profile"
        );
        self.profile = profile;
    }

    /// Evaluate a transaction against the policy
    pub fn evaluate(&mut self, tx: &Transaction) -> PolicyDecision {
        let txid = tx.compute_txid().to_string();
        trace!(txid = %txid, "Evaluating transaction");

        // Classify the transaction
        let classification = self.classifier.classify(tx);

        // Check tier
        if !self.profile.allows_tier(classification.tier) {
            self.stats.rejected_tier += 1;
            return PolicyDecision::Reject {
                reason: RejectionReason::TierNotAllowed {
                    tier: classification.tier,
                    allowed: self.profile.allowed_tiers.clone(),
                },
                classification,
            };
        }

        // Check transaction size
        let tx_size = tx.weight().to_wu() as usize / 4; // vbytes
        if tx_size > self.profile.max_tx_size {
            self.stats.rejected_size += 1;
            return PolicyDecision::Reject {
                reason: RejectionReason::TransactionTooLarge {
                    size: tx_size,
                    limit: self.profile.max_tx_size,
                },
                classification,
            };
        }

        // Check output count
        if tx.output.len() > self.profile.max_tx_outputs {
            self.stats.rejected_outputs += 1;
            return PolicyDecision::Reject {
                reason: RejectionReason::TooManyOutputs {
                    count: tx.output.len(),
                    limit: self.profile.max_tx_outputs,
                },
                classification,
            };
        }

        // Check OP_RETURN size
        for output in &tx.output {
            if output.script_pubkey.is_op_return() {
                let op_return_size = output.script_pubkey.len().saturating_sub(2);
                if op_return_size > self.profile.max_op_return_size {
                    self.stats.rejected_op_return += 1;
                    return PolicyDecision::Reject {
                        reason: RejectionReason::OpReturnTooLarge {
                            size: op_return_size,
                            limit: self.profile.max_op_return_size,
                        },
                        classification,
                    };
                }
            }
        }

        // Check witness sizes
        for (i, input) in tx.input.iter().enumerate() {
            let witness_size: usize = input.witness.iter().map(|w| w.len()).sum();
            if witness_size > self.profile.max_witness_per_input {
                self.stats.rejected_witness += 1;
                return PolicyDecision::Reject {
                    reason: RejectionReason::WitnessTooLarge {
                        input_index: i,
                        size: witness_size,
                        limit: self.profile.max_witness_per_input,
                    },
                    classification,
                };
            }
        }

        // Check specific feature restrictions
        if !self.profile.allow_inscriptions {
            if classification.features.iter().any(|f| {
                matches!(f, ghost_buds::DetectedFeature::InscriptionEnvelope)
            }) {
                self.stats.rejected_inscription += 1;
                return PolicyDecision::Reject {
                    reason: RejectionReason::InscriptionsNotAllowed,
                    classification,
                };
            }
        }

        if !self.profile.allow_runes {
            if classification.features.iter().any(|f| {
                matches!(f, ghost_buds::DetectedFeature::RunesRunestone)
            }) {
                self.stats.rejected_runes += 1;
                return PolicyDecision::Reject {
                    reason: RejectionReason::RunesNotAllowed,
                    classification,
                };
            }
        }

        if !self.profile.allow_brc20 {
            if classification.features.iter().any(|f| {
                matches!(f, ghost_buds::DetectedFeature::Brc20Pattern)
            }) {
                self.stats.rejected_brc20 += 1;
                return PolicyDecision::Reject {
                    reason: RejectionReason::Brc20NotAllowed,
                    classification,
                };
            }
        }

        // Calculate priority
        let priority = self.calculate_priority(&classification);

        self.stats.accepted += 1;
        PolicyDecision::Accept {
            classification,
            priority,
        }
    }

    /// Evaluate a transaction and return simple accept/reject
    pub fn allows(&mut self, tx: &Transaction) -> bool {
        matches!(self.evaluate(tx), PolicyDecision::Accept { .. })
    }

    /// Filter a list of transactions
    pub fn filter<'a>(&mut self, transactions: &'a [Transaction]) -> Vec<&'a Transaction> {
        transactions
            .iter()
            .filter(|tx| self.allows(tx))
            .collect()
    }

    /// Filter and sort by priority
    pub fn filter_and_sort<'a>(
        &mut self,
        transactions: &'a [Transaction],
    ) -> Vec<(&'a Transaction, f64)> {
        let mut accepted: Vec<_> = transactions
            .iter()
            .filter_map(|tx| {
                if let PolicyDecision::Accept { priority, .. } = self.evaluate(tx) {
                    Some((tx, priority))
                } else {
                    None
                }
            })
            .collect();

        // Sort by priority (descending)
        accepted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        accepted
    }

    /// Calculate priority for a transaction
    fn calculate_priority(&self, classification: &ClassificationResult) -> f64 {
        let mut priority = 1.0;

        // T0 transactions get a boost if configured
        if classification.tier == BudsTier::T0 {
            priority *= self.profile.t0_priority_boost;
        }

        priority
    }

    /// Get policy statistics
    pub fn stats(&self) -> &PolicyStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = PolicyStats::default();
    }
}

/// Policy decision for a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyDecision {
    /// Transaction accepted
    Accept {
        classification: ClassificationResult,
        priority: f64,
    },
    /// Transaction rejected
    Reject {
        reason: RejectionReason,
        classification: ClassificationResult,
    },
}

impl PolicyDecision {
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accept { .. })
    }

    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Reject { .. })
    }

    pub fn tier(&self) -> BudsTier {
        match self {
            Self::Accept { classification, .. } => classification.tier,
            Self::Reject { classification, .. } => classification.tier,
        }
    }
}

/// Reason for policy rejection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RejectionReason {
    /// Transaction tier not allowed by policy
    TierNotAllowed {
        tier: BudsTier,
        allowed: Vec<BudsTier>,
    },
    /// Transaction too large
    TransactionTooLarge { size: usize, limit: usize },
    /// Too many outputs
    TooManyOutputs { count: usize, limit: usize },
    /// OP_RETURN too large
    OpReturnTooLarge { size: usize, limit: usize },
    /// Witness too large
    WitnessTooLarge {
        input_index: usize,
        size: usize,
        limit: usize,
    },
    /// Fee rate too low
    FeeRateTooLow { rate: f64, minimum: f64 },
    /// Inscriptions not allowed
    InscriptionsNotAllowed,
    /// Runes not allowed
    RunesNotAllowed,
    /// BRC-20 not allowed
    Brc20NotAllowed,
}

impl std::fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TierNotAllowed { tier, allowed } => {
                write!(f, "Tier {} not allowed (allowed: {:?})", tier, allowed)
            }
            Self::TransactionTooLarge { size, limit } => {
                write!(f, "Transaction too large: {} > {} bytes", size, limit)
            }
            Self::TooManyOutputs { count, limit } => {
                write!(f, "Too many outputs: {} > {}", count, limit)
            }
            Self::OpReturnTooLarge { size, limit } => {
                write!(f, "OP_RETURN too large: {} > {} bytes", size, limit)
            }
            Self::WitnessTooLarge {
                input_index,
                size,
                limit,
            } => {
                write!(
                    f,
                    "Witness too large on input {}: {} > {} bytes",
                    input_index, size, limit
                )
            }
            Self::FeeRateTooLow { rate, minimum } => {
                write!(f, "Fee rate too low: {} < {} sat/vB", rate, minimum)
            }
            Self::InscriptionsNotAllowed => write!(f, "Inscriptions not allowed by policy"),
            Self::RunesNotAllowed => write!(f, "Runes not allowed by policy"),
            Self::Brc20NotAllowed => write!(f, "BRC-20 not allowed by policy"),
        }
    }
}

/// Policy enforcement statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyStats {
    /// Transactions accepted
    pub accepted: u64,
    /// Rejected due to tier
    pub rejected_tier: u64,
    /// Rejected due to size
    pub rejected_size: u64,
    /// Rejected due to output count
    pub rejected_outputs: u64,
    /// Rejected due to OP_RETURN size
    pub rejected_op_return: u64,
    /// Rejected due to witness size
    pub rejected_witness: u64,
    /// Rejected due to inscription
    pub rejected_inscription: u64,
    /// Rejected due to Runes
    pub rejected_runes: u64,
    /// Rejected due to BRC-20
    pub rejected_brc20: u64,
}

impl PolicyStats {
    /// Total rejections
    pub fn total_rejected(&self) -> u64 {
        self.rejected_tier
            + self.rejected_size
            + self.rejected_outputs
            + self.rejected_op_return
            + self.rejected_witness
            + self.rejected_inscription
            + self.rejected_runes
            + self.rejected_brc20
    }

    /// Total evaluated
    pub fn total_evaluated(&self) -> u64 {
        self.accepted + self.total_rejected()
    }

    /// Acceptance rate (0.0 - 1.0)
    pub fn acceptance_rate(&self) -> f64 {
        let total = self.total_evaluated();
        if total == 0 {
            1.0
        } else {
            self.accepted as f64 / total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        absolute::LockTime, transaction::Version, Amount, ScriptBuf, Sequence,
        TxIn, TxOut, Witness,
        blockdata::script::Builder,
    };

    /// Create a P2WPKH script (OP_0 <20-byte-hash>)
    fn create_p2wpkh_script() -> ScriptBuf {
        Builder::new()
            .push_int(0)
            .push_slice([0u8; 20])
            .into_script()
    }

    /// Create an OP_RETURN script with given data size
    fn create_op_return_script(data_size: usize) -> ScriptBuf {
        // Create OP_RETURN script using raw bytes for compatibility
        // Format: OP_RETURN (0x6a) + OP_PUSHBYTES_N (0x01-0x4b) + data
        let mut bytes = vec![0x6a]; // OP_RETURN

        if data_size <= 40 {
            // Small OP_RETURN: OP_RETURN + PUSHBYTES_40 + 40 bytes
            bytes.push(40); // OP_PUSHBYTES_40
            bytes.extend(std::iter::repeat(0u8).take(40));
        } else {
            // Large OP_RETURN (>80 bytes): Use multiple pushes
            // OP_RETURN + PUSHBYTES_50 + 50 bytes + PUSHBYTES_50 + 50 bytes
            bytes.push(50); // OP_PUSHBYTES_50
            bytes.extend(std::iter::repeat(0u8).take(50));
            bytes.push(50); // OP_PUSHBYTES_50
            bytes.extend(std::iter::repeat(0u8).take(50));
        }

        ScriptBuf::from(bytes)
    }

    /// Create a non-coinbase outpoint
    fn non_coinbase_outpoint() -> bitcoin::OutPoint {
        use bitcoin::hashes::Hash;
        let txid = bitcoin::Txid::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::hash(&[1u8])
        );
        bitcoin::OutPoint { txid, vout: 0 }
    }

    fn create_simple_tx() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: non_coinbase_outpoint(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: create_p2wpkh_script(),
            }],
        }
    }

    fn create_op_return_tx(data_size: usize) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: non_coinbase_outpoint(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(50000),
                    script_pubkey: create_p2wpkh_script(),
                },
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: create_op_return_script(data_size),
                },
            ],
        }
    }

    #[test]
    fn test_permissive_accepts_simple() {
        let mut engine = PolicyEngine::permissive();
        let tx = create_simple_tx();

        let decision = engine.evaluate(&tx);
        assert!(decision.is_accepted());
    }

    #[test]
    fn test_bitcoin_pure_rejects_op_return() {
        let mut engine = PolicyEngine::bitcoin_pure();
        let tx = create_op_return_tx(40);

        let decision = engine.evaluate(&tx);
        assert!(decision.is_rejected());
    }

    #[test]
    fn test_permissive_accepts_small_op_return() {
        let mut engine = PolicyEngine::permissive();
        let tx = create_op_return_tx(40);

        let decision = engine.evaluate(&tx);
        assert!(decision.is_accepted());
    }

    #[test]
    fn test_permissive_rejects_large_op_return() {
        let mut engine = PolicyEngine::permissive();
        let tx = create_op_return_tx(100); // > 80 bytes

        let decision = engine.evaluate(&tx);
        assert!(decision.is_rejected());
    }

    #[test]
    fn test_full_open_accepts_large_op_return() {
        let mut engine = PolicyEngine::full_open();
        let tx = create_op_return_tx(100);

        let decision = engine.evaluate(&tx);
        assert!(decision.is_accepted());
    }

    #[test]
    fn test_stats() {
        let mut engine = PolicyEngine::bitcoin_pure();

        engine.evaluate(&create_simple_tx());
        engine.evaluate(&create_op_return_tx(40));

        let stats = engine.stats();
        assert_eq!(stats.accepted, 1);
        assert!(stats.total_rejected() > 0);
    }
}
