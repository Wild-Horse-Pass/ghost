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
//| FILE: entry_timing.rs                                                                                                |
//|======================================================================================================================|

//! Entry timing for Wraith sessions
//!
//! Provides random delays and batching to prevent timing correlation attacks
//! when participants enter Wraith mixing sessions.
//!
//! # Attack Model
//!
//! Without timing protection, an observer watching network traffic can:
//! 1. Correlate participants who join a session at similar times
//! 2. Link users to sessions based on entry timing patterns
//! 3. Narrow down possible outputs by grouping contemporaneous entrants
//!
//! # Defenses
//!
//! 1. **Random Delay**: Add exponential random delay before entry
//! 2. **Batching**: Accumulate entries and submit in batches
//! 3. **Jitter**: Add noise to all timing operations
//! 4. **Cover Traffic**: Optional dummy join attempts
//!
//! # Usage
//!
//! ```ignore
//! use wraith_protocol::entry_timing::{EntryScheduler, EntryConfig};
//!
//! let config = EntryConfig::default();
//! let scheduler = EntryScheduler::new(config);
//!
//! // Schedule entry with random delay
//! let entry = scheduler.schedule_entry(session_id, participant);
//!
//! // Wait for scheduled time
//! tokio::time::sleep_until(entry.scheduled_at).await;
//!
//! // Execute entry
//! coordinator.register_participant(entry.participant).await?;
//! ```

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info};

/// Entry timing errors
#[derive(Debug, Error)]
pub enum EntryTimingError {
    #[error("Queue full: {0} pending entries")]
    QueueFull(usize),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Session not accepting entries")]
    SessionClosed,
}

/// Configuration for entry timing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryConfig {
    /// Enable random delay before entry
    pub delay_enabled: bool,

    /// Minimum delay in milliseconds
    pub min_delay_ms: u64,

    /// Maximum delay in milliseconds (exponential distribution mean)
    pub max_delay_ms: u64,

    /// Enable batching of entries
    pub batching_enabled: bool,

    /// Minimum batch size before release
    pub min_batch_size: usize,

    /// Maximum batch wait time in milliseconds
    pub max_batch_wait_ms: u64,

    /// Add random jitter to all timings (milliseconds)
    pub jitter_ms: u64,

    /// Enable cover traffic (dummy join attempts)
    pub cover_traffic_enabled: bool,

    /// Cover traffic rate (dummy joins per real join)
    pub cover_traffic_ratio: f64,

    /// Maximum pending entries in queue
    pub max_queue_size: usize,
}

impl Default for EntryConfig {
    fn default() -> Self {
        Self {
            delay_enabled: true,
            min_delay_ms: 1000,   // 1 second minimum
            max_delay_ms: 60_000, // 1 minute mean delay
            batching_enabled: true,
            min_batch_size: 5,         // Wait for at least 5 entries
            max_batch_wait_ms: 30_000, // Or 30 seconds max
            jitter_ms: 500,            // ±500ms jitter
            // SECURITY: Cover traffic enabled by default to prevent timing analysis
            cover_traffic_enabled: true,
            cover_traffic_ratio: 0.1, // 10% cover traffic
            max_queue_size: 1000,
        }
    }
}

impl EntryConfig {
    /// Create a low-latency config (less privacy, faster entry)
    pub fn low_latency() -> Self {
        Self {
            delay_enabled: true,
            min_delay_ms: 100,
            max_delay_ms: 5_000,
            batching_enabled: true,
            min_batch_size: 3,
            max_batch_wait_ms: 5_000,
            jitter_ms: 100,
            cover_traffic_enabled: false,
            cover_traffic_ratio: 0.0,
            max_queue_size: 1000,
        }
    }

    /// Create a high-privacy config (more delays, better mixing)
    pub fn high_privacy() -> Self {
        Self {
            delay_enabled: true,
            min_delay_ms: 5_000,
            max_delay_ms: 300_000, // 5 minute mean delay
            batching_enabled: true,
            min_batch_size: 10,
            max_batch_wait_ms: 120_000, // 2 minute batch wait
            jitter_ms: 2_000,
            cover_traffic_enabled: true,
            cover_traffic_ratio: 0.2, // 20% cover traffic
            max_queue_size: 1000,
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), EntryTimingError> {
        if self.max_delay_ms < self.min_delay_ms {
            return Err(EntryTimingError::InvalidConfig(
                "max_delay_ms must be >= min_delay_ms".into(),
            ));
        }
        if self.batching_enabled && self.min_batch_size == 0 {
            return Err(EntryTimingError::InvalidConfig(
                "min_batch_size must be > 0 when batching enabled".into(),
            ));
        }
        Ok(())
    }
}

/// A scheduled entry
#[derive(Debug, Clone)]
pub struct ScheduledEntry {
    /// Session ID to enter
    pub session_id: [u8; 32],
    /// Participant data (opaque to timing layer)
    pub participant_data: Vec<u8>,
    /// When this entry was requested
    pub requested_at: Instant,
    /// When this entry should be executed
    pub scheduled_at: Instant,
    /// Whether this is cover traffic (dummy)
    pub is_cover: bool,
    /// Entry ID for tracking
    pub entry_id: u64,
}

impl ScheduledEntry {
    /// Get delay until scheduled time
    pub fn delay(&self) -> Duration {
        self.scheduled_at.saturating_duration_since(Instant::now())
    }

    /// Check if entry is ready
    pub fn is_ready(&self) -> bool {
        Instant::now() >= self.scheduled_at
    }
}

/// Entry batch for grouped submission
#[derive(Debug, Clone)]
pub struct EntryBatch {
    /// Entries in this batch
    pub entries: Vec<ScheduledEntry>,
    /// When batch was created
    pub created_at: Instant,
    /// When batch should be released
    pub release_at: Instant,
    /// Batch ID
    pub batch_id: u64,
}

impl EntryBatch {
    /// Check if batch is ready for release
    pub fn is_ready(&self, min_size: usize) -> bool {
        self.entries.len() >= min_size || Instant::now() >= self.release_at
    }
}

/// Entry scheduler managing timing and batching
pub struct EntryScheduler {
    /// Configuration
    config: EntryConfig,
    /// Pending entries queue
    queue: Mutex<VecDeque<ScheduledEntry>>,
    /// Current batch
    current_batch: Mutex<Option<EntryBatch>>,
    /// Entry counter
    entry_counter: AtomicU64,
    /// Batch counter
    batch_counter: AtomicU64,
    /// Statistics
    stats: SchedulerStats,
}

/// Scheduler statistics
#[derive(Default)]
struct SchedulerStats {
    entries_scheduled: AtomicU64,
    entries_executed: AtomicU64,
    batches_released: AtomicU64,
    cover_traffic_sent: AtomicU64,
    total_delay_ms: AtomicU64,
}

impl EntryScheduler {
    /// Create a new entry scheduler
    pub fn new(config: EntryConfig) -> Result<Self, EntryTimingError> {
        config.validate()?;

        Ok(Self {
            config,
            queue: Mutex::new(VecDeque::new()),
            current_batch: Mutex::new(None),
            entry_counter: AtomicU64::new(0),
            batch_counter: AtomicU64::new(0),
            stats: SchedulerStats::default(),
        })
    }

    /// Schedule an entry with random delay
    pub fn schedule_entry(
        &self,
        session_id: [u8; 32],
        participant_data: Vec<u8>,
    ) -> Result<ScheduledEntry, EntryTimingError> {
        // Check queue capacity
        let queue_len = self.queue.lock().len();
        if queue_len >= self.config.max_queue_size {
            return Err(EntryTimingError::QueueFull(queue_len));
        }

        let now = Instant::now();
        let entry_id = self.entry_counter.fetch_add(1, Ordering::Relaxed);

        // Calculate delay
        let delay = self.calculate_delay();
        let scheduled_at = now + delay;

        let entry = ScheduledEntry {
            session_id,
            participant_data,
            requested_at: now,
            scheduled_at,
            is_cover: false,
            entry_id,
        };

        // Add to queue
        self.queue.lock().push_back(entry.clone());

        self.stats.entries_scheduled.fetch_add(1, Ordering::Relaxed);
        self.stats
            .total_delay_ms
            .fetch_add(delay.as_millis() as u64, Ordering::Relaxed);

        debug!(
            entry_id = entry_id,
            delay_ms = delay.as_millis(),
            "Scheduled entry"
        );

        // Optionally generate cover traffic
        if self.config.cover_traffic_enabled && self.should_generate_cover() {
            self.schedule_cover_traffic(session_id)?;
        }

        Ok(entry)
    }

    /// Calculate random delay using exponential distribution
    fn calculate_delay(&self) -> Duration {
        if !self.config.delay_enabled {
            return Duration::ZERO;
        }

        // Exponential distribution: delay = -mean * ln(random)
        let random = random_f64();
        let mean = (self.config.max_delay_ms - self.config.min_delay_ms) as f64;
        let exp_delay = -mean * random.ln();
        let delay_ms = self.config.min_delay_ms + (exp_delay as u64).min(self.config.max_delay_ms);

        // Add jitter
        let jitter = self.calculate_jitter();

        Duration::from_millis(delay_ms) + jitter
    }

    /// Calculate random jitter
    fn calculate_jitter(&self) -> Duration {
        if self.config.jitter_ms == 0 {
            return Duration::ZERO;
        }

        let random = random_f64();
        let jitter_ms = (random * (self.config.jitter_ms * 2) as f64) as u64;
        let centered_jitter = jitter_ms.saturating_sub(self.config.jitter_ms);

        Duration::from_millis(centered_jitter)
    }

    /// Check if cover traffic should be generated
    fn should_generate_cover(&self) -> bool {
        random_f64() < self.config.cover_traffic_ratio
    }

    /// Schedule cover traffic (dummy entry)
    fn schedule_cover_traffic(&self, session_id: [u8; 32]) -> Result<(), EntryTimingError> {
        let now = Instant::now();
        let entry_id = self.entry_counter.fetch_add(1, Ordering::Relaxed);

        // Cover traffic gets similar delay distribution
        let delay = self.calculate_delay();

        let cover = ScheduledEntry {
            session_id,
            participant_data: vec![], // Empty - will be filtered on execution
            requested_at: now,
            scheduled_at: now + delay,
            is_cover: true,
            entry_id,
        };

        self.queue.lock().push_back(cover);
        self.stats
            .cover_traffic_sent
            .fetch_add(1, Ordering::Relaxed);

        debug!(entry_id = entry_id, "Scheduled cover traffic");

        Ok(())
    }

    /// Add entry to current batch
    pub fn add_to_batch(&self, entry: ScheduledEntry) -> Option<EntryBatch> {
        if !self.config.batching_enabled {
            // Return single-entry batch immediately
            return Some(EntryBatch {
                entries: vec![entry],
                created_at: Instant::now(),
                release_at: Instant::now(),
                batch_id: self.batch_counter.fetch_add(1, Ordering::Relaxed),
            });
        }

        let mut batch = self.current_batch.lock();

        match batch.as_mut() {
            Some(b) => {
                b.entries.push(entry);

                // Check if batch should be released
                if b.is_ready(self.config.min_batch_size) {
                    let ready_batch = batch.take().unwrap();
                    self.stats.batches_released.fetch_add(1, Ordering::Relaxed);

                    info!(
                        batch_id = ready_batch.batch_id,
                        entries = ready_batch.entries.len(),
                        "Releasing entry batch"
                    );

                    return Some(ready_batch);
                }
            }
            None => {
                // Create new batch
                let now = Instant::now();
                *batch = Some(EntryBatch {
                    entries: vec![entry],
                    created_at: now,
                    release_at: now + Duration::from_millis(self.config.max_batch_wait_ms),
                    batch_id: self.batch_counter.fetch_add(1, Ordering::Relaxed),
                });
            }
        }

        None
    }

    /// Force release current batch (e.g., on timeout)
    pub fn force_release_batch(&self) -> Option<EntryBatch> {
        let mut batch = self.current_batch.lock();

        if let Some(b) = batch.take() {
            if !b.entries.is_empty() {
                self.stats.batches_released.fetch_add(1, Ordering::Relaxed);

                info!(
                    batch_id = b.batch_id,
                    entries = b.entries.len(),
                    "Force-releasing entry batch"
                );

                return Some(b);
            }
        }

        None
    }

    /// Get ready entries from queue
    pub fn get_ready_entries(&self) -> Vec<ScheduledEntry> {
        let mut queue = self.queue.lock();
        let mut ready = Vec::new();
        let now = Instant::now();

        // Drain ready entries
        while let Some(entry) = queue.front() {
            if entry.scheduled_at <= now {
                ready.push(queue.pop_front().unwrap());
            } else {
                break;
            }
        }

        if !ready.is_empty() {
            self.stats
                .entries_executed
                .fetch_add(ready.len() as u64, Ordering::Relaxed);
        }

        ready
    }

    /// Get time until next entry is ready
    pub fn time_until_next(&self) -> Option<Duration> {
        self.queue
            .lock()
            .front()
            .map(|e| e.scheduled_at.saturating_duration_since(Instant::now()))
    }

    /// Get queue length
    pub fn queue_len(&self) -> usize {
        self.queue.lock().len()
    }

    /// Get statistics
    pub fn get_stats(&self) -> EntryStats {
        EntryStats {
            entries_scheduled: self.stats.entries_scheduled.load(Ordering::Relaxed),
            entries_executed: self.stats.entries_executed.load(Ordering::Relaxed),
            batches_released: self.stats.batches_released.load(Ordering::Relaxed),
            cover_traffic_sent: self.stats.cover_traffic_sent.load(Ordering::Relaxed),
            average_delay_ms: self.average_delay_ms(),
            queue_length: self.queue_len(),
        }
    }

    fn average_delay_ms(&self) -> u64 {
        let total = self.stats.total_delay_ms.load(Ordering::Relaxed);
        let count = self.stats.entries_scheduled.load(Ordering::Relaxed);
        if count > 0 {
            total / count
        } else {
            0
        }
    }
}

/// Entry statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryStats {
    pub entries_scheduled: u64,
    pub entries_executed: u64,
    pub batches_released: u64,
    pub cover_traffic_sent: u64,
    pub average_delay_ms: u64,
    pub queue_length: usize,
}

/// Generate random f64 in [0, 1)
fn random_f64() -> f64 {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes).expect("Random generation failed");
    let raw = u64::from_le_bytes(bytes);
    // Convert to [0, 1) range
    (raw >> 11) as f64 / (1u64 << 53) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let mut config = EntryConfig::default();
        assert!(config.validate().is_ok());

        config.max_delay_ms = 0;
        config.min_delay_ms = 1000;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_low_latency_config() {
        let config = EntryConfig::low_latency();
        assert!(config.max_delay_ms <= 10_000);
        assert!(config.min_batch_size <= 5);
    }

    #[test]
    fn test_high_privacy_config() {
        let config = EntryConfig::high_privacy();
        assert!(config.max_delay_ms >= 60_000);
        assert!(config.cover_traffic_enabled);
    }

    #[test]
    fn test_scheduler_creation() {
        let config = EntryConfig::default();
        let scheduler = EntryScheduler::new(config).unwrap();
        assert_eq!(scheduler.queue_len(), 0);
    }

    #[test]
    fn test_schedule_entry() {
        let config = EntryConfig {
            delay_enabled: true,
            min_delay_ms: 100,
            max_delay_ms: 1000,
            batching_enabled: false,
            ..Default::default()
        };

        let scheduler = EntryScheduler::new(config).unwrap();
        let session_id = [1u8; 32];
        let participant_data = vec![0x01, 0x02, 0x03];

        let entry = scheduler
            .schedule_entry(session_id, participant_data.clone())
            .unwrap();

        assert_eq!(entry.session_id, session_id);
        assert_eq!(entry.participant_data, participant_data);
        assert!(!entry.is_cover);
        assert!(entry.scheduled_at >= entry.requested_at);
    }

    #[test]
    fn test_no_delay() {
        let config = EntryConfig {
            delay_enabled: false,
            batching_enabled: false,
            ..Default::default()
        };

        let scheduler = EntryScheduler::new(config).unwrap();
        let entry = scheduler.schedule_entry([0u8; 32], vec![]).unwrap();

        // With no delay, should be ready immediately (or very close)
        let delay = entry.delay();
        assert!(delay < Duration::from_millis(100));
    }

    #[test]
    fn test_batching() {
        let config = EntryConfig {
            delay_enabled: false,
            batching_enabled: true,
            min_batch_size: 3,
            max_batch_wait_ms: 10_000,
            ..Default::default()
        };

        let scheduler = EntryScheduler::new(config).unwrap();

        // First two entries should not release batch
        let entry1 = scheduler.schedule_entry([1u8; 32], vec![]).unwrap();
        let result1 = scheduler.add_to_batch(entry1);
        assert!(result1.is_none());

        let entry2 = scheduler.schedule_entry([2u8; 32], vec![]).unwrap();
        let result2 = scheduler.add_to_batch(entry2);
        assert!(result2.is_none());

        // Third entry should release batch
        let entry3 = scheduler.schedule_entry([3u8; 32], vec![]).unwrap();
        let result3 = scheduler.add_to_batch(entry3);
        assert!(result3.is_some());

        let batch = result3.unwrap();
        assert_eq!(batch.entries.len(), 3);
    }

    #[test]
    fn test_force_release_batch() {
        let config = EntryConfig {
            delay_enabled: false,
            batching_enabled: true,
            min_batch_size: 10,
            ..Default::default()
        };

        let scheduler = EntryScheduler::new(config).unwrap();

        // Add one entry
        let entry = scheduler.schedule_entry([1u8; 32], vec![]).unwrap();
        scheduler.add_to_batch(entry);

        // Force release should return partial batch
        let batch = scheduler.force_release_batch();
        assert!(batch.is_some());
        assert_eq!(batch.unwrap().entries.len(), 1);
    }

    #[test]
    fn test_queue_full() {
        let config = EntryConfig {
            max_queue_size: 2,
            delay_enabled: false,
            batching_enabled: false,
            ..Default::default()
        };

        let scheduler = EntryScheduler::new(config).unwrap();

        // Fill queue
        scheduler.schedule_entry([1u8; 32], vec![]).unwrap();
        scheduler.schedule_entry([2u8; 32], vec![]).unwrap();

        // Third should fail
        let result = scheduler.schedule_entry([3u8; 32], vec![]);
        assert!(matches!(result, Err(EntryTimingError::QueueFull(_))));
    }

    #[test]
    fn test_get_ready_entries() {
        let config = EntryConfig {
            delay_enabled: false,
            batching_enabled: false,
            ..Default::default()
        };

        let scheduler = EntryScheduler::new(config).unwrap();

        scheduler.schedule_entry([1u8; 32], vec![]).unwrap();
        scheduler.schedule_entry([2u8; 32], vec![]).unwrap();

        // Entries should be immediately ready
        std::thread::sleep(Duration::from_millis(10));
        let ready = scheduler.get_ready_entries();
        assert_eq!(ready.len(), 2);

        // Queue should be empty
        assert_eq!(scheduler.queue_len(), 0);
    }

    #[test]
    fn test_statistics() {
        let config = EntryConfig {
            delay_enabled: false,
            batching_enabled: false,
            ..Default::default()
        };

        let scheduler = EntryScheduler::new(config).unwrap();

        scheduler.schedule_entry([1u8; 32], vec![]).unwrap();
        scheduler.schedule_entry([2u8; 32], vec![]).unwrap();

        let stats = scheduler.get_stats();
        assert_eq!(stats.entries_scheduled, 2);
    }

    #[test]
    fn test_random_f64() {
        // Test that random values are in valid range
        for _ in 0..100 {
            let r = random_f64();
            assert!((0.0..1.0).contains(&r));
        }
    }

    #[test]
    fn test_scheduled_entry_ready() {
        let entry = ScheduledEntry {
            session_id: [0u8; 32],
            participant_data: vec![],
            requested_at: Instant::now(),
            scheduled_at: Instant::now() - Duration::from_secs(1), // Already past
            is_cover: false,
            entry_id: 0,
        };

        assert!(entry.is_ready());
        assert_eq!(entry.delay(), Duration::ZERO);
    }
}
