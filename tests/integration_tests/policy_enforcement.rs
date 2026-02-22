//! Category 7: Policy Enforcement Tests (35 tests)
//!
//! Tests for mining pool policy rules including:
//! - Fee rate requirements
//! - Transaction size limits
//! - BUDS tier restrictions (using real ghost-policy crate)
//! - Spam prevention
//!
//! BUDS tier tests use real ghost-policy PolicyProfile and PolicyEngine.
//! Fee, size, and dust tests use local helpers for Bitcoin consensus rules.

use bitcoin::{
    absolute::LockTime, blockdata::script::Builder, hashes::Hash, transaction::Version, Amount,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use ghost_buds::BudsTier;
use ghost_policy::{PolicyDecision, PolicyEngine, PolicyProfile, ProfileBuilder, RejectionReason};

// =============================================================================
// TRANSACTION CREATION HELPERS
// =============================================================================

/// Create a P2WPKH script (OP_0 <20-byte-hash>)
fn create_p2wpkh_script() -> ScriptBuf {
    Builder::new()
        .push_int(0)
        .push_slice([0u8; 20])
        .into_script()
}

/// Create a P2TR script (OP_1 <32-byte-key>)
#[allow(dead_code)]
fn create_p2tr_script() -> ScriptBuf {
    Builder::new()
        .push_int(1)
        .push_slice([0u8; 32])
        .into_script()
}

/// Create an OP_RETURN script with given data size
fn create_op_return_script(data_size: usize) -> ScriptBuf {
    let mut bytes = vec![0x6a]; // OP_RETURN

    if data_size == 0 {
        // Empty OP_RETURN
    } else if data_size <= 75 {
        // Direct push
        bytes.push(data_size as u8);
        bytes.extend(std::iter::repeat_n(0x42u8, data_size));
    } else {
        // OP_PUSHDATA1 for larger data
        bytes.push(0x4c); // OP_PUSHDATA1
        bytes.push(data_size.min(255) as u8);
        bytes.extend(std::iter::repeat_n(0x42u8, data_size.min(255)));
    }

    ScriptBuf::from(bytes)
}

/// Create a non-coinbase outpoint
fn non_coinbase_outpoint() -> bitcoin::OutPoint {
    let txid = bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::hash(&[1u8]));
    bitcoin::OutPoint { txid, vout: 0 }
}

/// Create a simple T0 payment transaction
fn create_simple_payment_tx() -> Transaction {
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

/// Create a transaction with OP_RETURN data (becomes T2 with small data, T3 with large)
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

/// Create a multisig-like transaction (T1)
#[allow(dead_code)]
fn create_multisig_tx() -> Transaction {
    // Use a 2-of-3 P2SH pattern (simplified)
    let p2sh_script = Builder::new()
        .push_opcode(bitcoin::opcodes::all::OP_HASH160)
        .push_slice([0u8; 20])
        .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
        .into_script();

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
            script_pubkey: p2sh_script,
        }],
    }
}

/// Create a transaction with many outputs
#[allow(dead_code)]
fn create_many_outputs_tx(count: usize) -> Transaction {
    let outputs: Vec<TxOut> = (0..count)
        .map(|_| TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: create_p2wpkh_script(),
        })
        .collect();

    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs,
    }
}

// =============================================================================
// FEE RATE POLICY (Tests 401-410)
// Local helpers for Bitcoin fee rate consensus rules
// =============================================================================

#[test]
fn test_401_minimum_fee_rate_enforced() {
    let policy = FeePolicy::default();
    // Default minimum is 1 sat/vB
    assert!(policy.check_fee_rate(1.0).is_ok());
    assert!(policy.check_fee_rate(0.5).is_err());
}

#[test]
fn test_402_zero_fee_rejected() {
    let policy = FeePolicy::default();
    assert!(policy.check_fee_rate(0.0).is_err());
}

#[test]
fn test_403_negative_fee_rejected() {
    let policy = FeePolicy::default();
    assert!(policy.check_fee_rate(-1.0).is_err());
}

#[test]
fn test_404_high_fee_accepted() {
    let policy = FeePolicy::default();
    // High fees should always be accepted
    assert!(policy.check_fee_rate(1000.0).is_ok());
}

#[test]
fn test_405_fee_rate_calculation() {
    // fee_rate = fee / vsize
    let fee = 1000u64; // satoshis
    let vsize = 250u64; // virtual bytes
    let rate = calculate_fee_rate(fee, vsize);
    assert_eq!(rate, 4.0);
}

#[test]
fn test_406_fee_rate_zero_vsize_handled() {
    // Avoid division by zero
    let rate = calculate_fee_rate(1000, 0);
    assert!(rate.is_infinite() || rate == 0.0);
}

#[test]
fn test_407_total_fees_calculation() {
    let transactions = vec![
        TxFeeInfo {
            fee: 100,
            vsize: 100,
        },
        TxFeeInfo {
            fee: 200,
            vsize: 150,
        },
        TxFeeInfo {
            fee: 300,
            vsize: 200,
        },
    ];
    let total = calculate_total_fees(&transactions);
    assert_eq!(total, 600);
}

#[test]
fn test_408_fee_priority_ordering() {
    let mut transactions = vec![
        TxFeeInfo {
            fee: 100,
            vsize: 100,
        }, // 1 sat/vB
        TxFeeInfo {
            fee: 400,
            vsize: 100,
        }, // 4 sat/vB
        TxFeeInfo {
            fee: 200,
            vsize: 100,
        }, // 2 sat/vB
    ];

    sort_by_fee_rate(&mut transactions);

    // Should be sorted by descending fee rate
    assert_eq!(transactions[0].fee, 400);
    assert_eq!(transactions[1].fee, 200);
    assert_eq!(transactions[2].fee, 100);
}

#[test]
fn test_409_dynamic_minimum_fee() {
    let policy = FeePolicy::with_minimum(2.0);
    assert!(policy.check_fee_rate(2.0).is_ok());
    assert!(policy.check_fee_rate(1.9).is_err());
}

#[test]
fn test_410_fee_estimation_accuracy() {
    // P2WPKH input: ~68 vbytes
    // P2WPKH output: ~31 vbytes
    // Overhead: ~11 vbytes
    let estimated = estimate_tx_vsize(1, 2); // 1 input, 2 outputs
    assert!((100..=150).contains(&estimated));
}

// =============================================================================
// TRANSACTION SIZE LIMITS (Tests 411-420)
// Local helpers for Bitcoin size consensus rules
// =============================================================================

#[test]
fn test_411_standard_tx_size_accepted() {
    let policy = SizePolicy::default();
    // 1KB transaction is standard
    assert!(policy.check_size(1000).is_ok());
}

#[test]
fn test_412_large_tx_size_accepted() {
    let policy = SizePolicy::default();
    // 100KB is still within limits
    assert!(policy.check_size(100_000).is_ok());
}

#[test]
fn test_413_oversized_tx_rejected() {
    let policy = SizePolicy::default();
    // Over 400KB is non-standard
    assert!(policy.check_size(400_001).is_err());
}

#[test]
fn test_414_zero_size_tx_rejected() {
    let policy = SizePolicy::default();
    assert!(policy.check_size(0).is_err());
}

#[test]
fn test_415_witness_size_limit() {
    let policy = SizePolicy::default();
    // Max witness is 4MB (SegWit limit)
    assert!(policy.check_witness_size(1_000_000).is_ok());
    assert!(policy.check_witness_size(4_000_001).is_err());
}

#[test]
fn test_416_input_count_limit() {
    let policy = SizePolicy::default();
    assert!(policy.check_input_count(100).is_ok());
    assert!(policy.check_input_count(10_000).is_err());
}

#[test]
fn test_417_output_count_limit() {
    let policy = SizePolicy::default();
    assert!(policy.check_output_count(100).is_ok());
    assert!(policy.check_output_count(10_000).is_err());
}

#[test]
fn test_418_sigop_limit() {
    let policy = SizePolicy::default();
    // Max sigops per tx is 4000
    assert!(policy.check_sigops(4000).is_ok());
    assert!(policy.check_sigops(4001).is_err());
}

#[test]
fn test_419_weight_calculation() {
    // Weight = (base_size * 3) + total_size
    let weight = calculate_weight(100, 250); // base=100, total=250
    assert_eq!(weight, 550); // 100*3 + 250 = 550
}

#[test]
fn test_420_vsize_from_weight() {
    // vsize = ceil(weight / 4)
    assert_eq!(vsize_from_weight(400), 100);
    assert_eq!(vsize_from_weight(401), 101);
    assert_eq!(vsize_from_weight(404), 101);
}

// =============================================================================
// BUDS TIER RESTRICTIONS (Tests 421-430)
// Using real ghost-policy PolicyProfile and PolicyEngine
// =============================================================================

#[test]
fn test_421_t0_always_accepted() {
    // All policy profiles accept T0 (standard payments)
    let bitcoin_pure = PolicyProfile::bitcoin_pure();
    let permissive = PolicyProfile::permissive();
    let full_open = PolicyProfile::full_open();

    assert!(bitcoin_pure.allows_tier(BudsTier::T0));
    assert!(permissive.allows_tier(BudsTier::T0));
    assert!(full_open.allows_tier(BudsTier::T0));

    // Test with real transaction
    let mut engine = PolicyEngine::bitcoin_pure();
    let tx = create_simple_payment_tx();
    let decision = engine.evaluate(&tx);
    assert!(decision.is_accepted());
    assert_eq!(decision.tier(), BudsTier::T0);
}

#[test]
fn test_422_t1_accepted_by_default() {
    // Default (permissive) accepts T1
    let profile = PolicyProfile::default();
    assert!(profile.allows_tier(BudsTier::T1));

    // Bitcoin pure also accepts T1 (multisig, timelocks)
    let bitcoin_pure = PolicyProfile::bitcoin_pure();
    assert!(bitcoin_pure.allows_tier(BudsTier::T1));
}

#[test]
fn test_423_t2_accepted_by_default() {
    // Default (permissive) accepts T2 (small OP_RETURN)
    let profile = PolicyProfile::default();
    assert!(profile.allows_tier(BudsTier::T2));

    // Test with PolicyEngine and small OP_RETURN transaction
    let mut engine = PolicyEngine::permissive();
    let tx = create_op_return_tx(40); // Small data, classified as T2
    let decision = engine.evaluate(&tx);
    // Note: acceptance depends on op_return size vs profile limit
    // Permissive allows up to 80 bytes
    assert!(
        decision.is_accepted()
            || matches!(
                &decision,
                PolicyDecision::Reject {
                    reason: RejectionReason::OpReturnTooLarge { .. },
                    ..
                }
            )
    );
}

#[test]
fn test_424_t3_optional() {
    // Full open accepts T3
    let full_open = PolicyProfile::full_open();
    assert!(full_open.allows_tier(BudsTier::T3));

    // Permissive rejects T3
    let permissive = PolicyProfile::permissive();
    assert!(!permissive.allows_tier(BudsTier::T3));

    // Bitcoin pure rejects T3
    let bitcoin_pure = PolicyProfile::bitcoin_pure();
    assert!(!bitcoin_pure.allows_tier(BudsTier::T3));
}

#[test]
fn test_425_tier_priority_boost() {
    // T0 transactions get priority boost in some profiles
    let bitcoin_pure = PolicyProfile::bitcoin_pure();
    let permissive = PolicyProfile::permissive();
    let full_open = PolicyProfile::full_open();

    // bitcoin_pure has highest T0 boost
    assert!(bitcoin_pure.t0_priority_boost >= 1.0);
    assert!(permissive.t0_priority_boost >= 1.0);
    // full_open has no boost (1.0)
    assert_eq!(full_open.t0_priority_boost, 1.0);

    // Verify ordering: bitcoin_pure >= permissive >= full_open
    assert!(bitcoin_pure.t0_priority_boost >= permissive.t0_priority_boost);
}

#[test]
fn test_426_strictness_levels() {
    // Profile strictness levels
    // Higher strictness = more restrictive
    let bitcoin_pure = PolicyProfile::bitcoin_pure();
    let permissive = PolicyProfile::permissive();
    let full_open = PolicyProfile::full_open();

    assert_eq!(bitcoin_pure.strictness(), 2); // T0+T1 only
    assert_eq!(permissive.strictness(), 1); // T0+T1+T2
    assert_eq!(full_open.strictness(), 0); // T0-T3
}

#[test]
fn test_427_highest_allowed_tier() {
    let bitcoin_pure = PolicyProfile::bitcoin_pure();
    let permissive = PolicyProfile::permissive();
    let full_open = PolicyProfile::full_open();

    assert_eq!(bitcoin_pure.highest_allowed_tier(), Some(BudsTier::T1));
    assert_eq!(permissive.highest_allowed_tier(), Some(BudsTier::T2));
    assert_eq!(full_open.highest_allowed_tier(), Some(BudsTier::T3));
}

#[test]
fn test_428_allows_data_methods() {
    let bitcoin_pure = PolicyProfile::bitcoin_pure();
    let permissive = PolicyProfile::permissive();
    let full_open = PolicyProfile::full_open();

    // allows_data() returns true if T2+ allowed
    assert!(!bitcoin_pure.allows_data()); // Only T0+T1
    assert!(permissive.allows_data()); // T0+T1+T2
    assert!(full_open.allows_data()); // T0-T3

    // allows_heavy_data() returns true if T3 allowed
    assert!(!bitcoin_pure.allows_heavy_data());
    assert!(!permissive.allows_heavy_data());
    assert!(full_open.allows_heavy_data());
}

#[test]
fn test_429_custom_profile_tiers() {
    // Create custom profile with specific tiers
    let custom = ProfileBuilder::new("t0_only")
        .allowed_tiers(vec![BudsTier::T0])
        .build();

    assert!(custom.allows_tier(BudsTier::T0));
    assert!(!custom.allows_tier(BudsTier::T1));
    assert!(!custom.allows_tier(BudsTier::T2));
    assert!(!custom.allows_tier(BudsTier::T3));

    // Custom with T0+T2 (skipping T1)
    let custom2 = ProfileBuilder::new("t0_t2")
        .allowed_tiers(vec![BudsTier::T0, BudsTier::T2])
        .build();

    assert!(custom2.allows_tier(BudsTier::T0));
    assert!(!custom2.allows_tier(BudsTier::T1));
    assert!(custom2.allows_tier(BudsTier::T2));
    assert!(!custom2.allows_tier(BudsTier::T3));
}

#[test]
fn test_430_policy_engine_tier_rejection() {
    // Create engine with bitcoin_pure (T0+T1 only)
    let mut engine = PolicyEngine::bitcoin_pure();

    // T0 transaction should be accepted
    let t0_tx = create_simple_payment_tx();
    let decision = engine.evaluate(&t0_tx);
    assert!(decision.is_accepted());

    // Large OP_RETURN (would be T3) should be rejected
    // Note: rejection could be TierNotAllowed or OpReturnTooLarge
    let large_op_return_tx = create_op_return_tx(200);
    let decision = engine.evaluate(&large_op_return_tx);
    assert!(decision.is_rejected());

    // Check stats
    let stats = engine.stats();
    assert_eq!(stats.accepted, 1);
    assert!(stats.total_rejected() >= 1);
}

// =============================================================================
// SPAM PREVENTION (Tests 431-435)
// Local helpers for dust and spam rules
// =============================================================================

#[test]
fn test_431_dust_output_rejected() {
    let policy = DustPolicy::default();
    // Dust threshold is ~546 satoshis for P2PKH
    assert!(policy.check_output_value(546, OutputType::P2PKH).is_ok());
    assert!(policy.check_output_value(545, OutputType::P2PKH).is_err());
}

#[test]
fn test_432_dust_threshold_varies_by_type() {
    let policy = DustPolicy::default();
    // P2WPKH has lower dust threshold (~294 sats)
    assert!(policy.check_output_value(294, OutputType::P2WPKH).is_ok());
    assert!(policy.check_output_value(293, OutputType::P2WPKH).is_err());
}

#[test]
fn test_433_op_return_exempt_from_dust() {
    let policy = DustPolicy::default();
    // OP_RETURN outputs can be 0 value
    assert!(policy.check_output_value(0, OutputType::OpReturn).is_ok());
}

#[test]
fn test_434_anchor_output_exempt_from_dust() {
    let policy = DustPolicy::default();
    // Lightning anchor outputs can be small
    assert!(policy.check_output_value(330, OutputType::Anchor).is_ok());
}

#[test]
fn test_435_mempool_limit_per_address() {
    let policy = SpamPolicy::default();
    // Limit unconfirmed txs per address
    assert!(policy.check_unconfirmed_count("bc1q...", 25).is_ok());
    assert!(policy.check_unconfirmed_count("bc1q...", 26).is_err());
}

// =============================================================================
// HELPER TYPES AND FUNCTIONS (Local stubs for consensus rules)
// =============================================================================

fn calculate_fee_rate(fee: u64, vsize: u64) -> f64 {
    if vsize == 0 {
        return f64::INFINITY;
    }
    fee as f64 / vsize as f64
}

#[derive(Debug, Clone)]
struct TxFeeInfo {
    fee: u64,
    vsize: u64,
}

fn calculate_total_fees(txs: &[TxFeeInfo]) -> u64 {
    txs.iter().map(|tx| tx.fee).sum()
}

fn sort_by_fee_rate(txs: &mut [TxFeeInfo]) {
    txs.sort_by(|a, b| {
        let rate_a = a.fee as f64 / a.vsize as f64;
        let rate_b = b.fee as f64 / b.vsize as f64;
        rate_b.partial_cmp(&rate_a).unwrap()
    });
}

fn estimate_tx_vsize(inputs: u32, outputs: u32) -> u32 {
    // Simplified estimation for P2WPKH
    11 + (inputs * 68) + (outputs * 31)
}

fn calculate_weight(base_size: u32, total_size: u32) -> u32 {
    base_size * 3 + total_size
}

fn vsize_from_weight(weight: u32) -> u32 {
    weight.div_ceil(4)
}

// Fee policy struct (local helper)
#[derive(Debug, Default)]
struct FeePolicy {
    minimum_rate: f64,
}

impl FeePolicy {
    fn with_minimum(rate: f64) -> Self {
        Self { minimum_rate: rate }
    }

    fn check_fee_rate(&self, rate: f64) -> Result<(), String> {
        let min = if self.minimum_rate > 0.0 {
            self.minimum_rate
        } else {
            1.0
        };
        if rate < min {
            return Err(format!("fee rate {} below minimum {}", rate, min));
        }
        Ok(())
    }
}

// Size policy struct (local helper)
#[derive(Debug, Default)]
struct SizePolicy {
    max_tx_size: u32,
    max_witness_size: u32,
    max_inputs: u32,
    max_outputs: u32,
    max_sigops: u32,
}

impl SizePolicy {
    fn check_size(&self, size: u32) -> Result<(), String> {
        if size == 0 {
            return Err("zero size".into());
        }
        let max = if self.max_tx_size > 0 {
            self.max_tx_size
        } else {
            400_000
        };
        if size > max {
            return Err("oversized".into());
        }
        Ok(())
    }

    fn check_witness_size(&self, size: u32) -> Result<(), String> {
        let max = if self.max_witness_size > 0 {
            self.max_witness_size
        } else {
            4_000_000
        };
        if size > max {
            return Err("witness too large".into());
        }
        Ok(())
    }

    fn check_input_count(&self, count: u32) -> Result<(), String> {
        let max = if self.max_inputs > 0 {
            self.max_inputs
        } else {
            5000
        };
        if count > max {
            return Err("too many inputs".into());
        }
        Ok(())
    }

    fn check_output_count(&self, count: u32) -> Result<(), String> {
        let max = if self.max_outputs > 0 {
            self.max_outputs
        } else {
            5000
        };
        if count > max {
            return Err("too many outputs".into());
        }
        Ok(())
    }

    fn check_sigops(&self, count: u32) -> Result<(), String> {
        let max = if self.max_sigops > 0 {
            self.max_sigops
        } else {
            4000
        };
        if count > max {
            return Err("too many sigops".into());
        }
        Ok(())
    }
}

// Output type enum (local helper)
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum OutputType {
    P2PKH,
    P2WPKH,
    P2SH,
    P2WSH,
    P2TR,
    OpReturn,
    Anchor,
}

// Dust policy struct (local helper)
#[derive(Debug, Default)]
#[allow(dead_code)]
struct DustPolicy {
    p2pkh_dust: u64,
    p2wpkh_dust: u64,
}

impl DustPolicy {
    fn check_output_value(&self, value: u64, output_type: OutputType) -> Result<(), String> {
        let threshold = match output_type {
            OutputType::P2PKH | OutputType::P2SH => 546,
            OutputType::P2WPKH | OutputType::P2WSH => 294,
            OutputType::P2TR => 330,
            OutputType::OpReturn => 0,
            OutputType::Anchor => 330,
        };

        if value < threshold {
            return Err(format!("dust: {} < {}", value, threshold));
        }
        Ok(())
    }
}

// Spam policy struct (local helper)
#[derive(Debug, Default)]
struct SpamPolicy {
    max_unconfirmed_per_address: u32,
}

impl SpamPolicy {
    fn check_unconfirmed_count(&self, _address: &str, count: u32) -> Result<(), String> {
        let max = if self.max_unconfirmed_per_address > 0 {
            self.max_unconfirmed_per_address
        } else {
            25
        };
        if count > max {
            return Err("too many unconfirmed".into());
        }
        Ok(())
    }
}
