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
//| FILE: validator.rs                                                                                                   |
//|======================================================================================================================|

//! Transaction validator for policy compliance
//!
//! Provides validation utilities for checking transactions against policies.

use bitcoin::Transaction;
use serde::{Deserialize, Serialize};

use ghost_buds::BudsTier;

use crate::policy::{PolicyDecision, PolicyEngine, RejectionReason};
use crate::profile::PolicyProfile;

/// Validation result for a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Transaction ID (hex)
    pub txid: String,
    /// Whether transaction is valid for the policy
    pub valid: bool,
    /// Assigned BUDS tier
    pub tier: BudsTier,
    /// Rejection reason (if invalid)
    pub rejection_reason: Option<String>,
    /// Warnings (non-fatal issues)
    pub warnings: Vec<String>,
    /// Transaction weight (vbytes)
    pub weight_vbytes: usize,
}

impl ValidationResult {
    /// Create from a policy decision
    pub fn from_decision(tx: &Transaction, decision: PolicyDecision) -> Self {
        let txid = tx.compute_txid().to_string();
        let weight_vbytes = tx.weight().to_wu() as usize / 4;

        match decision {
            PolicyDecision::Accept { classification, .. } => Self {
                txid,
                valid: true,
                tier: classification.tier,
                rejection_reason: None,
                warnings: vec![],
                weight_vbytes,
            },
            PolicyDecision::Reject {
                reason,
                classification,
            } => Self {
                txid,
                valid: false,
                tier: classification.tier,
                rejection_reason: Some(reason.to_string()),
                warnings: vec![],
                weight_vbytes,
            },
        }
    }
}

/// Batch validation results
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BatchValidationResult {
    /// Total transactions validated
    pub total: usize,
    /// Valid transactions
    pub valid_count: usize,
    /// Invalid transactions
    pub invalid_count: usize,
    /// Breakdown by tier
    pub tier_breakdown: TierBreakdown,
    /// Breakdown by rejection reason
    pub rejection_breakdown: RejectionBreakdown,
    /// Individual results (optional, may be truncated)
    pub results: Vec<ValidationResult>,
}

/// Breakdown of transactions by tier
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TierBreakdown {
    pub t0: usize,
    pub t1: usize,
    pub t2: usize,
    pub t3: usize,
}

impl TierBreakdown {
    pub fn increment(&mut self, tier: BudsTier) {
        match tier {
            BudsTier::T0 => self.t0 += 1,
            BudsTier::T1 => self.t1 += 1,
            BudsTier::T2 => self.t2 += 1,
            BudsTier::T3 => self.t3 += 1,
        }
    }
}

/// Breakdown of rejections by reason
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RejectionBreakdown {
    pub tier_not_allowed: usize,
    pub too_large: usize,
    pub too_many_outputs: usize,
    pub op_return_too_large: usize,
    pub witness_too_large: usize,
    pub inscription_blocked: usize,
    pub runes_blocked: usize,
    pub brc20_blocked: usize,
}

impl RejectionBreakdown {
    pub fn increment(&mut self, reason: &RejectionReason) {
        match reason {
            RejectionReason::TierNotAllowed { .. } => self.tier_not_allowed += 1,
            RejectionReason::TransactionTooLarge { .. } => self.too_large += 1,
            RejectionReason::TooManyOutputs { .. } => self.too_many_outputs += 1,
            RejectionReason::OpReturnTooLarge { .. } => self.op_return_too_large += 1,
            RejectionReason::WitnessTooLarge { .. } => self.witness_too_large += 1,
            RejectionReason::FeeRateTooLow { .. } => {} // Not tracked separately
            RejectionReason::InscriptionsNotAllowed => self.inscription_blocked += 1,
            RejectionReason::RunesNotAllowed => self.runes_blocked += 1,
            RejectionReason::Brc20NotAllowed => self.brc20_blocked += 1,
        }
    }
}

/// Transaction validator
pub struct TransactionValidator {
    engine: PolicyEngine,
    /// Whether to include individual results
    include_individual_results: bool,
    /// Maximum individual results to include
    max_individual_results: usize,
}

impl TransactionValidator {
    /// Create a new validator with the given profile
    pub fn new(profile: PolicyProfile) -> Self {
        Self {
            engine: PolicyEngine::new(profile),
            include_individual_results: true,
            max_individual_results: 1000,
        }
    }

    /// Create with default permissive profile
    pub fn permissive() -> Self {
        Self::new(PolicyProfile::permissive())
    }

    /// Set whether to include individual results
    pub fn with_individual_results(mut self, include: bool) -> Self {
        self.include_individual_results = include;
        self
    }

    /// Set maximum individual results to include
    pub fn with_max_results(mut self, max: usize) -> Self {
        self.max_individual_results = max;
        self
    }

    /// Validate a single transaction
    pub fn validate(&mut self, tx: &Transaction) -> ValidationResult {
        let decision = self.engine.evaluate(tx);
        ValidationResult::from_decision(tx, decision)
    }

    /// Validate a batch of transactions
    pub fn validate_batch(&mut self, transactions: &[Transaction]) -> BatchValidationResult {
        let mut result = BatchValidationResult {
            total: transactions.len(),
            ..Default::default()
        };

        for tx in transactions {
            let decision = self.engine.evaluate(tx);
            let validation = ValidationResult::from_decision(tx, decision.clone());

            // Update tier breakdown
            result.tier_breakdown.increment(validation.tier);

            // Update valid/invalid counts
            if validation.valid {
                result.valid_count += 1;
            } else {
                result.invalid_count += 1;

                // Update rejection breakdown
                if let PolicyDecision::Reject { reason, .. } = &decision {
                    result.rejection_breakdown.increment(reason);
                }
            }

            // Optionally include individual results
            if self.include_individual_results && result.results.len() < self.max_individual_results
            {
                result.results.push(validation);
            }
        }

        result
    }

    /// Check if a transaction would be valid
    pub fn is_valid(&mut self, tx: &Transaction) -> bool {
        self.engine.allows(tx)
    }

    /// Get the active profile
    pub fn profile(&self) -> &PolicyProfile {
        self.engine.profile()
    }

    /// Update the profile
    pub fn set_profile(&mut self, profile: PolicyProfile) {
        self.engine.set_profile(profile);
    }
}

/// Compare two profiles
pub fn compare_profiles(
    transactions: &[Transaction],
    profile_a: &PolicyProfile,
    profile_b: &PolicyProfile,
) -> ProfileComparison {
    let mut engine_a = PolicyEngine::new(profile_a.clone());
    let mut engine_b = PolicyEngine::new(profile_b.clone());

    let mut comparison = ProfileComparison {
        profile_a_name: profile_a.name.clone(),
        profile_b_name: profile_b.name.clone(),
        ..Default::default()
    };

    for tx in transactions {
        let accepted_a = engine_a.allows(tx);
        let accepted_b = engine_b.allows(tx);

        match (accepted_a, accepted_b) {
            (true, true) => comparison.both_accept += 1,
            (false, false) => comparison.both_reject += 1,
            (true, false) => comparison.only_a_accepts += 1,
            (false, true) => comparison.only_b_accepts += 1,
        }
    }

    comparison.total = transactions.len();
    comparison
}

/// Comparison of two policy profiles
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileComparison {
    pub profile_a_name: String,
    pub profile_b_name: String,
    pub total: usize,
    pub both_accept: usize,
    pub both_reject: usize,
    pub only_a_accepts: usize,
    pub only_b_accepts: usize,
}

impl ProfileComparison {
    /// Agreement rate between profiles
    pub fn agreement_rate(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            (self.both_accept + self.both_reject) as f64 / self.total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        absolute::LockTime, blockdata::script::Builder, transaction::Version, Amount, ScriptBuf,
        Sequence, TxIn, TxOut, Witness,
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
            bytes.extend(std::iter::repeat_n(0u8, 40));
        } else {
            // Large OP_RETURN (>80 bytes): Use multiple pushes
            // OP_RETURN + PUSHBYTES_50 + 50 bytes + PUSHBYTES_50 + 50 bytes
            bytes.push(50); // OP_PUSHBYTES_50
            bytes.extend(std::iter::repeat_n(0u8, 50));
            bytes.push(50); // OP_PUSHBYTES_50
            bytes.extend(std::iter::repeat_n(0u8, 50));
        }

        ScriptBuf::from(bytes)
    }

    /// Create a non-coinbase outpoint
    fn non_coinbase_outpoint() -> bitcoin::OutPoint {
        use bitcoin::hashes::Hash;
        let txid = bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::hash(&[1u8]));
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
    fn test_validate_single() {
        let mut validator = TransactionValidator::permissive();
        let result = validator.validate(&create_simple_tx());

        assert!(result.valid);
        assert_eq!(result.tier, BudsTier::T0);
    }

    #[test]
    fn test_validate_batch() {
        let mut validator = TransactionValidator::permissive();
        let transactions = vec![
            create_simple_tx(),
            create_op_return_tx(40),
            create_op_return_tx(100), // > 80 bytes, rejected
        ];

        let result = validator.validate_batch(&transactions);

        assert_eq!(result.total, 3);
        assert_eq!(result.valid_count, 2);
        assert_eq!(result.invalid_count, 1);
    }

    #[test]
    fn test_compare_profiles() {
        let transactions = vec![
            create_simple_tx(),
            create_op_return_tx(40),
            create_op_return_tx(100),
        ];

        let comparison = compare_profiles(
            &transactions,
            &PolicyProfile::bitcoin_pure(),
            &PolicyProfile::permissive(),
        );

        // T0 accepted by both, T2 only by permissive, T3 rejected by both
        assert_eq!(comparison.total, 3);
        assert!(comparison.only_b_accepts > 0); // permissive accepts T2
    }
}
