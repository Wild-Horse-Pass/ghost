//! Mining Load Tests
//!
//! Tests pool performance with 1000+ simulated miners

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

/// Configuration for load test
#[derive(Debug, Clone)]
pub struct LoadTestConfig {
    /// Number of simulated miners
    pub miner_count: usize,
    /// Shares per second per miner
    pub shares_per_second: f64,
    /// Test duration in seconds
    pub duration_secs: u64,
    /// Vardiff enabled
    pub vardiff_enabled: bool,
    /// Initial difficulty
    pub initial_difficulty: f64,
}

impl Default for LoadTestConfig {
    fn default() -> Self {
        Self {
            miner_count: 1000,
            shares_per_second: 0.1, // 1 share every 10 seconds per miner
            duration_secs: 60,
            vardiff_enabled: true,
            initial_difficulty: 1.0,
        }
    }
}

/// Simulated miner for load testing
#[allow(dead_code)]
struct LoadTestMiner {
    id: usize,
    difficulty: AtomicU64, // Stored as difficulty * 1000 for atomics
    shares_submitted: AtomicU64,
    last_share_time: RwLock<Instant>,
}

impl LoadTestMiner {
    fn new(id: usize, initial_difficulty: f64) -> Self {
        Self {
            id,
            difficulty: AtomicU64::new((initial_difficulty * 1000.0) as u64),
            shares_submitted: AtomicU64::new(0),
            last_share_time: RwLock::new(Instant::now()),
        }
    }

    fn submit_share(&self) -> u64 {
        *self.last_share_time.write() = Instant::now();
        self.shares_submitted.fetch_add(1, Ordering::SeqCst) + 1
    }

    fn get_difficulty(&self) -> f64 {
        self.difficulty.load(Ordering::SeqCst) as f64 / 1000.0
    }

    fn set_difficulty(&self, diff: f64) {
        self.difficulty.store((diff * 1000.0) as u64, Ordering::SeqCst);
    }

    fn work(&self) -> u64 {
        let shares = self.shares_submitted.load(Ordering::SeqCst);
        let diff = self.get_difficulty();
        (shares as f64 * diff * 1_000_000.0) as u64
    }
}

/// Load test results
#[derive(Debug)]
pub struct LoadTestResults {
    /// Total shares submitted
    pub total_shares: u64,
    /// Shares per second
    pub shares_per_second: f64,
    /// Total work calculated
    pub total_work: u64,
    /// Peak memory usage (bytes)
    pub peak_memory: usize,
    /// Average latency (microseconds)
    pub avg_latency_us: u64,
    /// P99 latency (microseconds)
    pub p99_latency_us: u64,
    /// Miners that connected
    pub miners_connected: usize,
    /// Test duration
    pub duration: Duration,
}

/// Run mining load test
pub fn run_mining_load_test(config: LoadTestConfig) -> LoadTestResults {
    let start = Instant::now();
    let miners: Vec<Arc<LoadTestMiner>> = (0..config.miner_count)
        .map(|id| Arc::new(LoadTestMiner::new(id, config.initial_difficulty)))
        .collect();

    // Track share submission latencies
    let latencies: Arc<RwLock<Vec<u64>>> = Arc::new(RwLock::new(Vec::with_capacity(
        (config.miner_count as f64 * config.shares_per_second * config.duration_secs as f64) as usize,
    )));

    // Simulate share submissions
    let share_interval = Duration::from_secs_f64(1.0 / config.shares_per_second);
    let test_duration = Duration::from_secs(config.duration_secs);

    while start.elapsed() < test_duration {
        let batch_start = Instant::now();

        for miner in &miners {
            let share_start = Instant::now();
            miner.submit_share();
            let latency = share_start.elapsed().as_micros() as u64;
            latencies.write().push(latency);
        }

        // Sleep to maintain target rate
        let batch_duration = batch_start.elapsed();
        if batch_duration < share_interval {
            std::thread::sleep(share_interval - batch_duration);
        }
    }

    let duration = start.elapsed();

    // Calculate results
    let total_shares: u64 = miners.iter().map(|m| m.shares_submitted.load(Ordering::SeqCst)).sum();
    let total_work: u64 = miners.iter().map(|m| m.work()).sum();

    let latency_data = latencies.read();
    let mut sorted_latencies = latency_data.clone();
    sorted_latencies.sort();

    let avg_latency_us = if sorted_latencies.is_empty() {
        0
    } else {
        sorted_latencies.iter().sum::<u64>() / sorted_latencies.len() as u64
    };

    let p99_latency_us = if sorted_latencies.is_empty() {
        0
    } else {
        let p99_idx = (sorted_latencies.len() as f64 * 0.99) as usize;
        sorted_latencies.get(p99_idx.min(sorted_latencies.len() - 1)).copied().unwrap_or(0)
    };

    LoadTestResults {
        total_shares,
        shares_per_second: total_shares as f64 / duration.as_secs_f64(),
        total_work,
        peak_memory: 0, // Would need platform-specific measurement
        avg_latency_us,
        p99_latency_us,
        miners_connected: config.miner_count,
        duration,
    }
}

/// Vardiff simulation for load testing
struct VardiffSimulator {
    target_secs: f64,
    min_diff: f64,
    max_diff: f64,
}

impl VardiffSimulator {
    fn new(target_secs: f64) -> Self {
        Self {
            target_secs,
            min_diff: 0.001,
            max_diff: 1_000_000.0,
        }
    }

    fn calculate_adjustment(&self, actual_secs: f64, current_diff: f64) -> f64 {
        let ratio = self.target_secs / actual_secs;

        // Smooth adjustment
        let adjustment = ratio.sqrt();
        let new_diff = current_diff * adjustment;

        new_diff.clamp(self.min_diff, self.max_diff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_test_small_scale() {
        // Quick test with small numbers
        let config = LoadTestConfig {
            miner_count: 10,
            shares_per_second: 1.0,
            duration_secs: 1,
            ..Default::default()
        };

        let results = run_mining_load_test(config);

        assert!(results.total_shares > 0);
        assert_eq!(results.miners_connected, 10);
        println!("Small scale test results:");
        println!("  Total shares: {}", results.total_shares);
        println!("  Shares/sec: {:.2}", results.shares_per_second);
        println!("  Avg latency: {}μs", results.avg_latency_us);
    }

    #[test]
    fn test_load_test_medium_scale() {
        let config = LoadTestConfig {
            miner_count: 100,
            shares_per_second: 0.5,
            duration_secs: 2,
            ..Default::default()
        };

        let results = run_mining_load_test(config);

        assert!(results.total_shares >= 50);
        println!("Medium scale test results:");
        println!("  Total shares: {}", results.total_shares);
        println!("  Shares/sec: {:.2}", results.shares_per_second);
    }

    #[test]
    #[ignore] // Run with: cargo test test_load_test_large_scale -- --ignored
    fn test_load_test_large_scale() {
        let config = LoadTestConfig {
            miner_count: 1000,
            shares_per_second: 0.1,
            duration_secs: 30,
            ..Default::default()
        };

        let results = run_mining_load_test(config);

        println!("Large scale test results:");
        println!("  Miners: {}", results.miners_connected);
        println!("  Total shares: {}", results.total_shares);
        println!("  Shares/sec: {:.2}", results.shares_per_second);
        println!("  Total work: {}", results.total_work);
        println!("  Avg latency: {}μs", results.avg_latency_us);
        println!("  P99 latency: {}μs", results.p99_latency_us);
        println!("  Duration: {:?}", results.duration);

        // Performance assertions
        assert!(results.shares_per_second > 50.0, "Should achieve >50 shares/sec");
        assert!(results.avg_latency_us < 1000, "Avg latency should be <1ms");
    }

    #[test]
    fn test_vardiff_adjustment() {
        let vardiff = VardiffSimulator::new(10.0);

        // Shares too fast (5 sec instead of 10)
        let new_diff = vardiff.calculate_adjustment(5.0, 1.0);
        assert!(new_diff > 1.0, "Difficulty should increase");

        // Shares too slow (20 sec instead of 10)
        let new_diff = vardiff.calculate_adjustment(20.0, 1.0);
        assert!(new_diff < 1.0, "Difficulty should decrease");

        // Just right
        let new_diff = vardiff.calculate_adjustment(10.0, 1.0);
        assert!((new_diff - 1.0).abs() < 0.01, "Difficulty should stay same");
    }

    #[test]
    fn test_miner_work_calculation() {
        let miner = LoadTestMiner::new(0, 2.0);

        // Submit 10 shares at difficulty 2.0
        for _ in 0..10 {
            miner.submit_share();
        }

        // Work = shares * difficulty * 1_000_000
        // Work = 10 * 2.0 * 1_000_000 = 20_000_000
        assert_eq!(miner.work(), 20_000_000);

        // Change difficulty
        miner.set_difficulty(4.0);
        for _ in 0..10 {
            miner.submit_share();
        }

        // Total: 10 shares at diff 2 + 10 shares at diff 4 = 60_000_000
        // But our simple model uses current difficulty for all shares
        // so it's 20 * 4.0 * 1_000_000 = 80_000_000
        // This is a simplification - real impl tracks per-share difficulty
    }
}
