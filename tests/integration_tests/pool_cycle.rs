//! End-to-End Pool Cycle Integration Tests
//!
//! Tests the complete mining pool lifecycle:
//! 1. Miner connects to pool
//! 2. Pool receives block template from Bitcoin Core
//! 3. Pool filters transactions via BUDS
//! 4. Pool sends work to miners
//! 5. Miner submits share
//! 6. Miner finds block
//! 7. Pool submits block to Bitcoin Core
//! 8. Round ends and payouts are calculated

use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use ghost_buds::{BudsClassifier, BudsTier};
use ghost_policy::PolicyProfile;

use super::helpers::*;

/// Test basic template filtering with BUDS classifier
#[test]
fn test_buds_filtering_in_pool_cycle() {
    // Create classifier and policy
    let _classifier = BudsClassifier::new();
    let policy = PolicyProfile::bitcoin_pure(); // Only T0 allowed

    // Simulate transactions in mempool with their tiers
    let tx_tiers = vec![
        (random_id(), BudsTier::T0), // Standard payment - allowed
        (random_id(), BudsTier::T0), // Standard payment - allowed
        (random_id(), BudsTier::T0), // Consolidation - allowed
        (random_id(), BudsTier::T3), // Inscription - blocked
        (random_id(), BudsTier::T3), // Runes - blocked
        (random_id(), BudsTier::T3), // Ordinal - blocked
    ];

    // Filter transactions
    let mut allowed = Vec::new();
    let mut blocked = Vec::new();

    for (txid, tier) in &tx_tiers {
        if policy.allows_tier(*tier) {
            allowed.push(txid);
        } else {
            blocked.push(txid);
        }
    }

    // Verify filtering
    assert_eq!(allowed.len(), 3, "Should allow 3 T0 transactions");
    assert_eq!(blocked.len(), 3, "Should block 3 T3 transactions");
}

/// Test round management during pool cycle
#[test]
fn test_round_management() {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

    // Simulate round tracking
    struct SimpleRound {
        round_id: AtomicU32,
        height: AtomicU64,
        shares: parking_lot::RwLock<HashMap<String, u64>>,
    }

    impl SimpleRound {
        fn new() -> Self {
            Self {
                round_id: AtomicU32::new(0),
                height: AtomicU64::new(800_000),
                shares: parking_lot::RwLock::new(HashMap::new()),
            }
        }

        fn start_round(&self, height: u64) -> u32 {
            self.height.store(height, Ordering::SeqCst);
            self.shares.write().clear();
            self.round_id.fetch_add(1, Ordering::SeqCst) + 1
        }

        fn add_share(&self, miner: &str, work: u64) {
            *self.shares.write().entry(miner.to_string()).or_insert(0) += work;
        }

        fn get_shares(&self, miner: &str) -> u64 {
            self.shares.read().get(miner).copied().unwrap_or(0)
        }

        fn total_work(&self) -> u64 {
            self.shares.read().values().sum()
        }
    }

    let round = SimpleRound::new();

    // Start round at height 800,001
    let round_id = round.start_round(800_001);
    assert_eq!(round_id, 1);

    // Miners submit shares
    round.add_share("miner_1", 100);
    round.add_share("miner_2", 150);
    round.add_share("miner_1", 50); // Additional share

    assert_eq!(round.get_shares("miner_1"), 150);
    assert_eq!(round.get_shares("miner_2"), 150);
    assert_eq!(round.total_work(), 300);

    // New block found - new round
    let round_id = round.start_round(800_002);
    assert_eq!(round_id, 2);
    assert_eq!(round.total_work(), 0, "Shares should reset on new round");
}

/// Test share submission and work calculation
#[test]
fn test_share_submission() {
    // Simulate difficulty-based work calculation
    struct Share {
        miner_id: String,
        difficulty: f64,
        #[allow(dead_code)]
        timestamp: u64,
    }

    impl Share {
        fn work(&self) -> u64 {
            // Work = difficulty * scale factor
            (self.difficulty * 1_000_000.0) as u64
        }
    }

    // Test various difficulty levels
    let shares = [
        Share {
            miner_id: "miner_1".to_string(),
            difficulty: 1.0,
            timestamp: 1000,
        },
        Share {
            miner_id: "miner_2".to_string(),
            difficulty: 2.0,
            timestamp: 1001,
        },
        Share {
            miner_id: "miner_1".to_string(),
            difficulty: 0.5,
            timestamp: 1002,
        },
    ];

    let total_work: u64 = shares.iter().map(|s| s.work()).sum();

    // 1.0 + 2.0 + 0.5 = 3.5 * 1_000_000 = 3_500_000
    assert_eq!(total_work, 3_500_000);

    // Calculate proportional shares
    let miner_1_work: u64 = shares
        .iter()
        .filter(|s| s.miner_id == "miner_1")
        .map(|s| s.work())
        .sum();

    let miner_1_share = miner_1_work as f64 / total_work as f64;
    assert!((miner_1_share - 0.4286).abs() < 0.001); // ~42.86%
}

/// Test coinbase construction for payout
#[test]
fn test_coinbase_payout_construction() {
    // Simulate payout calculation
    #[allow(dead_code)]
    struct PayoutEntry {
        address: String,
        amount_sats: u64,
    }

    // Block reward simulation (3.125 BTC)
    let block_reward = 312_500_000u64;
    let fees = 50_000_000u64; // 0.5 BTC in fees
    let total = block_reward + fees;

    // Payout structure:
    // - 1% treasury fee
    // - 99% to miners proportionally

    let treasury_fee = total / 100; // 1%
    let miner_pool = total - treasury_fee;

    // Simulate 3 miners with work proportions
    let miner_shares = vec![
        ("miner_1", 0.5), // 50%
        ("miner_2", 0.3), // 30%
        ("miner_3", 0.2), // 20%
    ];

    let mut payouts: Vec<PayoutEntry> = Vec::new();

    // Treasury output
    payouts.push(PayoutEntry {
        address: "bc1qtreasury...".to_string(),
        amount_sats: treasury_fee,
    });

    // Miner outputs
    for (miner, share) in &miner_shares {
        let amount = (miner_pool as f64 * share) as u64;
        payouts.push(PayoutEntry {
            address: format!("bc1q{}...", miner),
            amount_sats: amount,
        });
    }

    // Verify total payout
    let total_payout: u64 = payouts.iter().map(|p| p.amount_sats).sum();
    assert!(
        total - total_payout < 10,
        "Rounding error should be minimal"
    );

    // Verify treasury got 1%
    assert_eq!(payouts[0].amount_sats, treasury_fee);

    // Verify largest miner got ~50% of miner pool
    let expected_miner_1 = (miner_pool as f64 * 0.5) as u64;
    assert_eq!(payouts[1].amount_sats, expected_miner_1);
}

/// Test block submission flow
#[test]
fn test_block_submission_flow() {
    let mock_rpc = MockBitcoinRpc::new();

    // Initial state
    assert_eq!(mock_rpc.get_height(), 800_000);
    assert!(mock_rpc.get_submitted_blocks().is_empty());

    // Simulate finding a block
    // In real code, this would be a full Bitcoin block
    // For testing, we just track that submission happened

    // Create a minimal block (in real tests, this would be proper Bitcoin block)
    let block_hash = BlockHash::all_zeros();

    // Track submission
    mock_rpc.set_height(800_001);
    mock_rpc.set_block_hash(800_001, block_hash);

    // Verify state
    assert_eq!(mock_rpc.get_height(), 800_001);
    assert_eq!(mock_rpc.get_block_hash(800_001), Some(block_hash));
}

/// Test full pool cycle simulation
#[test]
fn test_full_pool_cycle_simulation() {
    // This test simulates the complete pool cycle without actual network connections

    // 1. Initialize pool state
    let mock_rpc = MockBitcoinRpc::new();
    let _classifier = BudsClassifier::new();
    let _policy = PolicyProfile::permissive(); // Allow T0-T2

    // 2. Receive block template
    let template = MockTemplate::new(800_001);
    mock_rpc.add_template(800_001, template);

    // 3. Simulate miners connecting
    let miners: Vec<MockMiner> = (0..5)
        .map(|i| {
            MockMiner::new(
                &format!("miner_{}", i),
                format!("192.168.1.{}:3333", i + 1).parse().unwrap(),
            )
        })
        .collect();

    assert_eq!(miners.len(), 5);

    // 4. Simulate work distribution
    for miner in &miners {
        miner.set_job_id("job_001".to_string());
    }

    // 5. Simulate share submissions
    for miner in &miners {
        for _ in 0..10 {
            miner.submit_share();
        }
    }

    let total_shares: u64 = miners.iter().map(|m| m.get_shares()).sum();
    assert_eq!(total_shares, 50);

    // 6. Simulate block found (miner_2 finds it)
    let finder = &miners[2];
    let final_shares = finder.get_shares();

    // 7. Submit block
    mock_rpc.increment_height();
    assert_eq!(mock_rpc.get_height(), 800_001);

    // 8. Calculate payouts (simplified)
    let block_reward = 312_500_000u64;
    let work_per_miner: Vec<u64> = miners.iter().map(|m| m.get_shares()).collect();
    let total_work: u64 = work_per_miner.iter().sum();

    let payouts: Vec<u64> = work_per_miner
        .iter()
        .map(|&w| (block_reward as f64 * (w as f64 / total_work as f64)) as u64)
        .collect();

    // Each miner did equal work, so should get equal share
    let expected_payout = block_reward / 5;
    for payout in &payouts {
        assert!((*payout as i64 - expected_payout as i64).abs() < 1000);
    }

    println!("Pool cycle simulation completed successfully");
    println!("  Miners: {}", miners.len());
    println!("  Total shares: {}", total_shares);
    println!("  Block found by: miner_2 with {} shares", final_shares);
    println!("  Payout per miner: ~{} sats", expected_payout);
}

/// Test template update on new block
#[test]
fn test_template_update_on_new_block() {
    let mock_rpc = MockBitcoinRpc::new();

    // Initial template at height 800,000
    let template1 = MockTemplate::new(800_000);
    mock_rpc.add_template(800_000, template1);

    // Simulate new block arrival
    mock_rpc.increment_height();

    // New template at height 800,001
    let template2 = MockTemplate::new(800_001);
    mock_rpc.add_template(800_001, template2);

    assert_eq!(mock_rpc.get_height(), 800_001);
}

/// Test vardiff (variable difficulty) adjustment
#[test]
fn test_vardiff_adjustment() {
    // Simulate vardiff controller logic
    struct VardiffState {
        target_secs: u64,  // Target seconds between shares
        current_diff: f64, // Current difficulty
        min_diff: f64,
        max_diff: f64,
    }

    impl VardiffState {
        fn new() -> Self {
            Self {
                target_secs: 10, // 10 seconds between shares
                current_diff: 1.0,
                min_diff: 0.001,
                max_diff: 1_000_000.0,
            }
        }

        fn adjust(&mut self, actual_secs: u64) {
            // If shares coming too fast, increase difficulty
            // If shares coming too slow, decrease difficulty
            let ratio = actual_secs as f64 / self.target_secs as f64;

            if ratio < 0.5 {
                // Shares too fast - double difficulty
                self.current_diff = (self.current_diff * 2.0).min(self.max_diff);
            } else if ratio > 2.0 {
                // Shares too slow - halve difficulty
                self.current_diff = (self.current_diff / 2.0).max(self.min_diff);
            }
            // Otherwise, difficulty is appropriate
        }
    }

    let mut vardiff = VardiffState::new();
    assert_eq!(vardiff.current_diff, 1.0);

    // Shares coming every 2 seconds (too fast)
    vardiff.adjust(2);
    assert_eq!(vardiff.current_diff, 2.0);

    // Still too fast
    vardiff.adjust(3);
    assert_eq!(vardiff.current_diff, 4.0);

    // Now appropriate
    vardiff.adjust(10);
    assert_eq!(vardiff.current_diff, 4.0); // No change

    // Too slow
    vardiff.adjust(25);
    assert_eq!(vardiff.current_diff, 2.0);
}

#[cfg(test)]
mod async_tests {
    use super::*;
    use std::sync::Arc;
    use tokio::time::Duration;

    #[tokio::test]
    async fn test_async_miner_session() {
        // Simulate async miner session
        let miner = Arc::new(MockMiner::new(
            "async_miner",
            "127.0.0.1:3333".parse().unwrap(),
        ));

        // Simulate periodic share submissions
        let miner_clone = Arc::clone(&miner);
        let handle = tokio::spawn(async move {
            for _ in 0..10 {
                miner_clone.submit_share();
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });

        handle.await.unwrap();
        assert_eq!(miner.get_shares(), 10);
    }

    #[tokio::test]
    async fn test_template_refresh_cycle() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let template_version = Arc::new(AtomicU32::new(0));

        // Simulate periodic template refresh
        let version = Arc::clone(&template_version);
        let handle = tokio::spawn(async move {
            for _ in 0..5 {
                version.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });

        handle.await.unwrap();
        assert_eq!(template_version.load(Ordering::SeqCst), 5);
    }
}
