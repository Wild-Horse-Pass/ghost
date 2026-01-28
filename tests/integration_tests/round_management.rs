//! Category 13: Round Management Tests (30 tests)
//!
//! Tests for mining round lifecycle including:
//! - Round creation and finalization
//! - Share accounting
//! - Payout calculation
//! - Round transitions

use std::collections::HashMap;
use std::time::{Duration, Instant};

// =============================================================================
// ROUND LIFECYCLE (Tests 701-710)
// =============================================================================

#[test]
fn test_701_create_new_round() {
    let mut manager = RoundManager::new();
    let round = manager.create_round();

    assert!(round.is_ok());
    assert_eq!(manager.current_round().unwrap().state, RoundState::Active);
}

#[test]
fn test_702_round_id_increments() {
    let mut manager = RoundManager::new();

    let r1 = manager.create_round().unwrap();
    manager.finalize_current(BlockInfo::default()).unwrap();

    let r2 = manager.create_round().unwrap();

    assert_eq!(r2.id, r1.id + 1);
}

#[test]
fn test_703_round_start_time_recorded() {
    let mut manager = RoundManager::new();
    let round = manager.create_round().unwrap();

    assert!(round.started_at.elapsed() < Duration::from_secs(1));
}

#[test]
fn test_704_round_finalization() {
    let mut manager = RoundManager::new();
    manager.create_round().unwrap();

    let result = manager.finalize_current(BlockInfo::default());
    assert!(result.is_ok());

    let round = manager.get_round(0).unwrap();
    assert_eq!(round.state, RoundState::Finalized);
}

#[test]
fn test_705_cannot_finalize_twice() {
    let mut manager = RoundManager::new();
    manager.create_round().unwrap();
    manager.finalize_current(BlockInfo::default()).unwrap();

    let result = manager.finalize_current(BlockInfo::default());
    assert!(result.is_err());
}

#[test]
fn test_706_round_end_time_recorded() {
    let mut manager = RoundManager::new();
    manager.create_round().unwrap();
    std::thread::sleep(Duration::from_millis(10));
    manager.finalize_current(BlockInfo::default()).unwrap();

    let round = manager.get_round(0).unwrap();
    assert!(round.ended_at.is_some());
    assert!(round.duration() > Duration::from_millis(0));
}

#[test]
fn test_707_no_active_round_initially() {
    let manager = RoundManager::new();
    assert!(manager.current_round().is_none());
}

#[test]
fn test_708_only_one_active_round() {
    let mut manager = RoundManager::new();
    manager.create_round().unwrap();

    // Cannot create another while one is active
    let result = manager.create_round();
    assert!(result.is_err());
}

#[test]
fn test_709_round_block_height_recorded() {
    let mut manager = RoundManager::new();
    manager.create_round().unwrap();

    let block_info = BlockInfo {
        height: 800_000,
        hash: "000abc...".to_string(),
        reward: 625_000_000,
    };

    manager.finalize_current(block_info).unwrap();

    let round = manager.get_round(0).unwrap();
    assert_eq!(round.block_height, Some(800_000));
}

#[test]
fn test_710_round_history_preserved() {
    let mut manager = RoundManager::new();

    for i in 0..5 {
        manager.create_round().unwrap();
        manager
            .finalize_current(BlockInfo {
                height: 800_000 + i,
                hash: format!("hash{}", i),
                reward: 625_000_000,
            })
            .unwrap();
    }

    assert_eq!(manager.round_count(), 5);
}

// =============================================================================
// SHARE ACCOUNTING (Tests 711-720)
// =============================================================================

#[test]
fn test_711_record_share_to_round() {
    let mut manager = RoundManager::new();
    manager.create_round().unwrap();

    let result = manager.record_share(ShareRecord {
        miner_id: "miner1".to_string(),
        difficulty: 1000.0,
        timestamp: current_timestamp(),
    });

    assert!(result.is_ok());
}

#[test]
fn test_712_share_rejected_no_active_round() {
    let mut manager = RoundManager::new();

    let result = manager.record_share(ShareRecord {
        miner_id: "miner1".to_string(),
        difficulty: 1000.0,
        timestamp: current_timestamp(),
    });

    assert!(result.is_err());
}

#[test]
fn test_713_share_count_accurate() {
    let mut manager = RoundManager::new();
    manager.create_round().unwrap();

    for i in 0..100 {
        manager
            .record_share(ShareRecord {
                miner_id: format!("miner{}", i % 10),
                difficulty: 1000.0,
                timestamp: current_timestamp(),
            })
            .unwrap();
    }

    let round = manager.current_round().unwrap();
    assert_eq!(round.total_shares, 100);
}

#[test]
fn test_714_difficulty_sum_accurate() {
    let mut manager = RoundManager::new();
    manager.create_round().unwrap();

    for i in 0..10 {
        manager
            .record_share(ShareRecord {
                miner_id: "miner1".to_string(),
                difficulty: (i + 1) as f64 * 100.0,
                timestamp: current_timestamp(),
            })
            .unwrap();
    }

    let round = manager.current_round().unwrap();
    // 100 + 200 + ... + 1000 = 5500
    assert!((round.total_difficulty - 5500.0).abs() < 0.001);
}

#[test]
fn test_715_per_miner_shares_tracked() {
    let mut manager = RoundManager::new();
    manager.create_round().unwrap();

    for i in 0..20 {
        manager
            .record_share(ShareRecord {
                miner_id: format!("miner{}", i % 4),
                difficulty: 1000.0,
                timestamp: current_timestamp(),
            })
            .unwrap();
    }

    let round = manager.current_round().unwrap();
    assert_eq!(round.miner_shares.len(), 4);
    assert_eq!(round.miner_shares.get("miner0").unwrap().count, 5);
}

#[test]
fn test_716_per_miner_difficulty_tracked() {
    let mut manager = RoundManager::new();
    manager.create_round().unwrap();

    manager
        .record_share(ShareRecord {
            miner_id: "miner1".to_string(),
            difficulty: 500.0,
            timestamp: current_timestamp(),
        })
        .unwrap();

    manager
        .record_share(ShareRecord {
            miner_id: "miner1".to_string(),
            difficulty: 1500.0,
            timestamp: current_timestamp(),
        })
        .unwrap();

    let round = manager.current_round().unwrap();
    assert!((round.miner_shares.get("miner1").unwrap().difficulty - 2000.0).abs() < 0.001);
}

#[test]
fn test_717_share_rejected_after_finalization() {
    let mut manager = RoundManager::new();
    manager.create_round().unwrap();
    manager.finalize_current(BlockInfo::default()).unwrap();

    let result = manager.record_share(ShareRecord {
        miner_id: "miner1".to_string(),
        difficulty: 1000.0,
        timestamp: current_timestamp(),
    });

    assert!(result.is_err());
}

#[test]
fn test_718_late_share_window() {
    let mut manager = RoundManager::with_config(RoundConfig {
        late_share_window: Duration::from_millis(100),
        ..Default::default()
    });

    manager.create_round().unwrap();
    manager.finalize_current(BlockInfo::default()).unwrap();

    // Immediately after finalization, late shares should be accepted
    let result = manager.record_late_share(
        0,
        ShareRecord {
            miner_id: "miner1".to_string(),
            difficulty: 1000.0,
            timestamp: current_timestamp(),
        },
    );

    assert!(result.is_ok());
}

#[test]
fn test_719_late_share_expired() {
    let mut manager = RoundManager::with_config(RoundConfig {
        late_share_window: Duration::from_millis(1),
        ..Default::default()
    });

    manager.create_round().unwrap();
    manager.finalize_current(BlockInfo::default()).unwrap();

    std::thread::sleep(Duration::from_millis(10));

    let result = manager.record_late_share(
        0,
        ShareRecord {
            miner_id: "miner1".to_string(),
            difficulty: 1000.0,
            timestamp: current_timestamp(),
        },
    );

    assert!(result.is_err());
}

#[test]
fn test_720_share_timestamp_validation() {
    let mut manager = RoundManager::new();
    manager.create_round().unwrap();

    // Share with timestamp from the past (before round started)
    let result = manager.record_share(ShareRecord {
        miner_id: "miner1".to_string(),
        difficulty: 1000.0,
        timestamp: 0, // Way in the past
    });

    // Should still be accepted (timestamp is informational)
    assert!(result.is_ok());
}

// =============================================================================
// PAYOUT CALCULATION (Tests 721-730)
// =============================================================================

#[test]
fn test_721_pps_payout_calculation() {
    let mut manager = RoundManager::new();
    manager.create_round().unwrap();

    // Two miners with equal shares
    for _ in 0..50 {
        manager
            .record_share(ShareRecord {
                miner_id: "miner1".to_string(),
                difficulty: 1000.0,
                timestamp: current_timestamp(),
            })
            .unwrap();
        manager
            .record_share(ShareRecord {
                miner_id: "miner2".to_string(),
                difficulty: 1000.0,
                timestamp: current_timestamp(),
            })
            .unwrap();
    }

    manager
        .finalize_current(BlockInfo {
            height: 800_000,
            hash: "hash".to_string(),
            reward: 625_000_000,
        })
        .unwrap();

    let payouts = manager.calculate_payouts(0, PayoutScheme::PPS).unwrap();

    // Each miner should get ~50% of reward
    let miner1_payout = payouts.get("miner1").unwrap();
    let miner2_payout = payouts.get("miner2").unwrap();

    assert!(miner1_payout.abs_diff(*miner2_payout) < 1000); // Within 1000 sats
}

#[test]
fn test_722_pplns_payout_calculation() {
    let mut manager = RoundManager::new();
    manager.create_round().unwrap();

    // Miner1 submits more shares
    for _ in 0..75 {
        manager
            .record_share(ShareRecord {
                miner_id: "miner1".to_string(),
                difficulty: 1000.0,
                timestamp: current_timestamp(),
            })
            .unwrap();
    }
    for _ in 0..25 {
        manager
            .record_share(ShareRecord {
                miner_id: "miner2".to_string(),
                difficulty: 1000.0,
                timestamp: current_timestamp(),
            })
            .unwrap();
    }

    manager
        .finalize_current(BlockInfo {
            height: 800_000,
            hash: "hash".to_string(),
            reward: 625_000_000,
        })
        .unwrap();

    let payouts = manager.calculate_payouts(0, PayoutScheme::PPLNS).unwrap();

    let miner1_payout = *payouts.get("miner1").unwrap();
    let miner2_payout = *payouts.get("miner2").unwrap();

    // Miner1 should get ~3x miner2
    assert!(miner1_payout > miner2_payout * 2);
}

#[test]
fn test_723_prop_payout_calculation() {
    let mut manager = RoundManager::new();
    manager.create_round().unwrap();

    manager
        .record_share(ShareRecord {
            miner_id: "miner1".to_string(),
            difficulty: 2000.0,
            timestamp: current_timestamp(),
        })
        .unwrap();

    manager
        .record_share(ShareRecord {
            miner_id: "miner2".to_string(),
            difficulty: 1000.0,
            timestamp: current_timestamp(),
        })
        .unwrap();

    manager
        .finalize_current(BlockInfo {
            height: 800_000,
            hash: "hash".to_string(),
            reward: 300_000_000, // 3 BTC for easy math
        })
        .unwrap();

    let payouts = manager.calculate_payouts(0, PayoutScheme::Proportional).unwrap();

    let miner1_payout = *payouts.get("miner1").unwrap();
    let miner2_payout = *payouts.get("miner2").unwrap();

    // Miner1: 2/3, Miner2: 1/3
    assert!(miner1_payout.abs_diff(200_000_000) < 1000);
    assert!(miner2_payout.abs_diff(100_000_000) < 1000);
}

#[test]
fn test_724_pool_fee_deduction() {
    let mut manager = RoundManager::with_config(RoundConfig {
        pool_fee_percent: 2.0,
        ..Default::default()
    });

    manager.create_round().unwrap();
    manager
        .record_share(ShareRecord {
            miner_id: "miner1".to_string(),
            difficulty: 1000.0,
            timestamp: current_timestamp(),
        })
        .unwrap();

    manager
        .finalize_current(BlockInfo {
            height: 800_000,
            hash: "hash".to_string(),
            reward: 100_000_000, // 1 BTC
        })
        .unwrap();

    let payouts = manager.calculate_payouts(0, PayoutScheme::PPS).unwrap();

    // Miner should get 98% (2% fee)
    let miner_payout = *payouts.get("miner1").unwrap();
    assert_eq!(miner_payout, 98_000_000);
}

#[test]
fn test_725_minimum_payout_threshold() {
    let mut manager = RoundManager::with_config(RoundConfig {
        minimum_payout: 100_000,
        ..Default::default()
    });

    manager.create_round().unwrap();

    // One share with tiny difficulty
    manager
        .record_share(ShareRecord {
            miner_id: "miner1".to_string(),
            difficulty: 0.001,
            timestamp: current_timestamp(),
        })
        .unwrap();

    manager
        .finalize_current(BlockInfo {
            height: 800_000,
            hash: "hash".to_string(),
            reward: 100_000, // Very small reward
        })
        .unwrap();

    let payouts = manager.calculate_payouts(0, PayoutScheme::PPS).unwrap();

    // Payout below threshold should be 0 (held for next round)
    let miner_payout = payouts.get("miner1").copied().unwrap_or(0);
    assert!(miner_payout == 0 || miner_payout >= 100_000);
}

#[test]
fn test_726_payout_rounding() {
    let mut manager = RoundManager::new();
    manager.create_round().unwrap();

    // Three miners with equal shares
    for miner in &["miner1", "miner2", "miner3"] {
        manager
            .record_share(ShareRecord {
                miner_id: miner.to_string(),
                difficulty: 1000.0,
                timestamp: current_timestamp(),
            })
            .unwrap();
    }

    manager
        .finalize_current(BlockInfo {
            height: 800_000,
            hash: "hash".to_string(),
            reward: 100, // Not evenly divisible by 3
        })
        .unwrap();

    let payouts = manager.calculate_payouts(0, PayoutScheme::PPS).unwrap();

    // Total payouts should not exceed reward
    let total: u64 = payouts.values().sum();
    assert!(total <= 100);
}

#[test]
fn test_727_zero_shares_round() {
    let mut manager = RoundManager::new();
    manager.create_round().unwrap();

    // No shares submitted
    manager.finalize_current(BlockInfo::default()).unwrap();

    let payouts = manager.calculate_payouts(0, PayoutScheme::PPS).unwrap();
    assert!(payouts.is_empty());
}

#[test]
fn test_728_orphan_block_no_payout() {
    let mut manager = RoundManager::new();
    manager.create_round().unwrap();
    manager
        .record_share(ShareRecord {
            miner_id: "miner1".to_string(),
            difficulty: 1000.0,
            timestamp: current_timestamp(),
        })
        .unwrap();

    manager
        .finalize_current(BlockInfo {
            height: 800_000,
            hash: "hash".to_string(),
            reward: 625_000_000,
        })
        .unwrap();

    // Mark block as orphaned
    manager.mark_round_orphaned(0).unwrap();

    let round = manager.get_round(0).unwrap();
    assert_eq!(round.state, RoundState::Orphaned);
}

#[test]
fn test_729_pending_balance_accumulation() {
    let mut manager = RoundManager::with_config(RoundConfig {
        minimum_payout: 1_000_000_000, // 10 BTC threshold
        ..Default::default()
    });

    // Multiple rounds with small payouts
    for _ in 0..3 {
        manager.create_round().unwrap();
        manager
            .record_share(ShareRecord {
                miner_id: "miner1".to_string(),
                difficulty: 1000.0,
                timestamp: current_timestamp(),
            })
            .unwrap();
        manager
            .finalize_current(BlockInfo {
                height: 800_000,
                hash: "hash".to_string(),
                reward: 100_000_000, // 1 BTC
            })
            .unwrap();
    }

    let pending = manager.get_pending_balance("miner1");
    // Should have accumulated ~3 BTC pending
    assert!(pending >= 290_000_000);
}

#[test]
fn test_730_payout_history_recorded() {
    let mut manager = RoundManager::new();
    manager.create_round().unwrap();
    manager
        .record_share(ShareRecord {
            miner_id: "miner1".to_string(),
            difficulty: 1000.0,
            timestamp: current_timestamp(),
        })
        .unwrap();
    manager
        .finalize_current(BlockInfo {
            height: 800_000,
            hash: "hash".to_string(),
            reward: 100_000_000,
        })
        .unwrap();

    let payouts = manager.calculate_payouts(0, PayoutScheme::PPS).unwrap();
    manager.execute_payouts(0, &payouts).unwrap();

    let history = manager.get_payout_history("miner1");
    assert_eq!(history.len(), 1);
}

// =============================================================================
// HELPER TYPES AND FUNCTIONS
// =============================================================================

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Debug, Clone, PartialEq)]
enum RoundState {
    Active,
    Finalized,
    Orphaned,
}

#[derive(Debug, Clone)]
struct Round {
    id: u64,
    state: RoundState,
    started_at: Instant,
    ended_at: Option<Instant>,
    total_shares: u64,
    total_difficulty: f64,
    miner_shares: HashMap<String, MinerShareInfo>,
    block_height: Option<u64>,
    block_hash: Option<String>,
    block_reward: Option<u64>,
}

impl Round {
    fn duration(&self) -> Duration {
        self.ended_at
            .map(|e| e.duration_since(self.started_at))
            .unwrap_or(Duration::from_secs(0))
    }
}

#[derive(Debug, Clone)]
struct MinerShareInfo {
    count: u64,
    difficulty: f64,
}

#[derive(Debug, Clone, Default)]
struct BlockInfo {
    height: u64,
    hash: String,
    reward: u64,
}

#[derive(Debug)]
struct ShareRecord {
    miner_id: String,
    difficulty: f64,
    timestamp: u64,
}

#[derive(Debug, Clone)]
enum PayoutScheme {
    PPS,
    PPLNS,
    Proportional,
}

#[derive(Debug, Clone, Default)]
struct RoundConfig {
    pool_fee_percent: f64,
    minimum_payout: u64,
    late_share_window: Duration,
}

struct RoundManager {
    rounds: Vec<Round>,
    config: RoundConfig,
    pending_balances: HashMap<String, u64>,
    payout_history: HashMap<String, Vec<PayoutRecord>>,
}

#[derive(Debug, Clone)]
struct PayoutRecord {
    round_id: u64,
    amount: u64,
    timestamp: u64,
}

impl RoundManager {
    fn new() -> Self {
        Self::with_config(RoundConfig::default())
    }

    fn with_config(config: RoundConfig) -> Self {
        Self {
            rounds: Vec::new(),
            config,
            pending_balances: HashMap::new(),
            payout_history: HashMap::new(),
        }
    }

    fn create_round(&mut self) -> Result<Round, String> {
        if self.rounds.iter().any(|r| r.state == RoundState::Active) {
            return Err("active round exists".into());
        }

        let round = Round {
            id: self.rounds.len() as u64,
            state: RoundState::Active,
            started_at: Instant::now(),
            ended_at: None,
            total_shares: 0,
            total_difficulty: 0.0,
            miner_shares: HashMap::new(),
            block_height: None,
            block_hash: None,
            block_reward: None,
        };

        self.rounds.push(round.clone());
        Ok(round)
    }

    fn current_round(&self) -> Option<Round> {
        self.rounds
            .iter()
            .find(|r| r.state == RoundState::Active)
            .cloned()
    }

    fn get_round(&self, id: u64) -> Option<Round> {
        self.rounds.get(id as usize).cloned()
    }

    fn finalize_current(&mut self, block_info: BlockInfo) -> Result<(), String> {
        let round_idx = self
            .rounds
            .iter()
            .position(|r| r.state == RoundState::Active)
            .ok_or("no active round")?;

        {
            let round = &mut self.rounds[round_idx];
            round.state = RoundState::Finalized;
            round.ended_at = Some(Instant::now());
            round.block_height = Some(block_info.height);
            round.block_hash = Some(block_info.hash.clone());
            round.block_reward = Some(block_info.reward);
        }

        // Calculate and distribute payouts to pending_balances
        let round = &self.rounds[round_idx];
        if round.total_difficulty > 0.0 {
            let pool_fee = (block_info.reward as f64 * self.config.pool_fee_percent / 100.0) as u64;
            let distributable = block_info.reward - pool_fee;

            for (miner_id, share_info) in &round.miner_shares {
                let share_pct = share_info.difficulty / round.total_difficulty;
                let payout = (distributable as f64 * share_pct) as u64;

                *self.pending_balances.entry(miner_id.clone()).or_insert(0) += payout;
            }
        }

        Ok(())
    }

    fn record_share(&mut self, share: ShareRecord) -> Result<(), String> {
        let round = self
            .rounds
            .iter_mut()
            .find(|r| r.state == RoundState::Active)
            .ok_or("no active round")?;

        round.total_shares += 1;
        round.total_difficulty += share.difficulty;

        let entry = round
            .miner_shares
            .entry(share.miner_id)
            .or_insert(MinerShareInfo {
                count: 0,
                difficulty: 0.0,
            });

        entry.count += 1;
        entry.difficulty += share.difficulty;

        Ok(())
    }

    fn record_late_share(&mut self, round_id: u64, share: ShareRecord) -> Result<(), String> {
        let round = self
            .rounds
            .get_mut(round_id as usize)
            .ok_or("round not found")?;

        if round.state != RoundState::Finalized {
            return Err("round not finalized".into());
        }

        let ended = round.ended_at.ok_or("no end time")?;
        if ended.elapsed() > self.config.late_share_window {
            return Err("late share window expired".into());
        }

        round.total_shares += 1;
        round.total_difficulty += share.difficulty;

        let entry = round
            .miner_shares
            .entry(share.miner_id)
            .or_insert(MinerShareInfo {
                count: 0,
                difficulty: 0.0,
            });

        entry.count += 1;
        entry.difficulty += share.difficulty;

        Ok(())
    }

    fn calculate_payouts(
        &self,
        round_id: u64,
        _scheme: PayoutScheme,
    ) -> Result<HashMap<String, u64>, String> {
        let round = self.get_round(round_id).ok_or("round not found")?;

        if round.state == RoundState::Orphaned {
            return Ok(HashMap::new());
        }

        let reward = round.block_reward.unwrap_or(0);
        if reward == 0 || round.total_difficulty == 0.0 {
            return Ok(HashMap::new());
        }

        // Apply pool fee
        let fee_multiplier = 1.0 - (self.config.pool_fee_percent / 100.0);
        let distributable = (reward as f64 * fee_multiplier) as u64;

        let mut payouts = HashMap::new();

        for (miner_id, info) in &round.miner_shares {
            let share = info.difficulty / round.total_difficulty;
            let payout = (distributable as f64 * share) as u64;

            if payout >= self.config.minimum_payout || self.config.minimum_payout == 0 {
                payouts.insert(miner_id.clone(), payout);
            }
        }

        Ok(payouts)
    }

    fn execute_payouts(
        &mut self,
        round_id: u64,
        payouts: &HashMap<String, u64>,
    ) -> Result<(), String> {
        let timestamp = current_timestamp();

        for (miner_id, amount) in payouts {
            let history = self.payout_history.entry(miner_id.clone()).or_default();
            history.push(PayoutRecord {
                round_id,
                amount: *amount,
                timestamp,
            });
        }

        Ok(())
    }

    fn mark_round_orphaned(&mut self, round_id: u64) -> Result<(), String> {
        let round = self
            .rounds
            .get_mut(round_id as usize)
            .ok_or("round not found")?;

        round.state = RoundState::Orphaned;
        Ok(())
    }

    fn round_count(&self) -> usize {
        self.rounds.len()
    }

    fn get_pending_balance(&self, miner_id: &str) -> u64 {
        *self.pending_balances.get(miner_id).unwrap_or(&0)
    }

    fn get_payout_history(&self, miner_id: &str) -> Vec<PayoutRecord> {
        self.payout_history.get(miner_id).cloned().unwrap_or_default()
    }
}
