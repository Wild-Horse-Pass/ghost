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
//| FILE: clock.rs                                                                                                       |
//|======================================================================================================================|

//! Clock utilities for time-sensitive operations
//!
//! This module provides utilities for handling clock-related concerns in a
//! distributed system:
//!
//! - Clock skew detection via peer timestamps
//! - Monotonic time for internal timers (not affected by clock adjustments)
//! - Median peer time for consensus-safe timestamps
//!
//! # Operational Requirements (M-10)
//!
//! ## NTP Synchronization
//!
//! **All Ghost Pool nodes MUST have accurate system time.** The recommended
//! configuration is:
//!
//! 1. Install and enable NTP or chrony
//! 2. Configure at least 3 reliable NTP servers
//! 3. Ensure firewall allows NTP traffic (UDP port 123)
//! 4. Monitor for clock skew warnings in logs
//!
//! Example NTP configuration (`/etc/ntp.conf`):
//! ```text
//! server 0.pool.ntp.org iburst
//! server 1.pool.ntp.org iburst
//! server 2.pool.ntp.org iburst
//! server 3.pool.ntp.org iburst
//! ```
//!
//! ## Clock Tolerance
//!
//! The system tolerates up to [`MAX_ACCEPTABLE_SKEW_SECS`] (2 minutes) of clock
//! drift before warning. However, for optimal operation:
//!
//! - Clock accuracy within 10 seconds is recommended
//! - Clock accuracy within 30 seconds is acceptable
//! - Clock drift >2 minutes will generate warnings
//! - Clock drift >1 hour will cause peer timestamp rejection
//!
//! ## Why Accurate Time Matters
//!
//! - **Voting sessions**: BFT consensus uses timestamps to detect stale votes
//! - **Settlement proofs**: Epoch-bound signatures require consistent time
//! - **Health monitoring**: Peer liveness detection relies on timestamp freshness
//! - **Share attribution**: Mining shares are timestamped for round accounting
//!
//! # Security Model
//!
//! The system assumes nodes may have slightly inaccurate clocks (up to a few
//! minutes of drift). For security-critical time decisions:
//!
//! 1. Use monotonic time for timeouts and durations
//! 2. Use median peer time for cross-node timestamp validation
//! 3. Warn if local clock differs significantly from peers

use std::collections::VecDeque;
use std::time::Instant;

use parking_lot::RwLock;
use tracing::warn;

/// Maximum acceptable clock skew before warning (2 minutes)
pub const MAX_ACCEPTABLE_SKEW_SECS: i64 = 120;

/// Maximum offset from local time to accept a peer timestamp (1 hour)
/// Timestamps outside this range are rejected to prevent manipulation
const MAX_PEER_OFFSET_SECS: i64 = 3600;

/// Number of peer timestamps to keep for median calculation
const PEER_SAMPLE_SIZE: usize = 20;

/// Clock monitor for detecting and handling clock skew
pub struct ClockMonitor {
    /// Peer timestamps (most recent at back)
    peer_samples: RwLock<VecDeque<(i64, Instant)>>,
    /// Estimated clock offset (our_time - peer_median_time)
    estimated_offset: RwLock<i64>,
    /// Whether we've warned about clock skew
    skew_warned: RwLock<bool>,
}

impl ClockMonitor {
    pub fn new() -> Self {
        Self {
            peer_samples: RwLock::new(VecDeque::with_capacity(PEER_SAMPLE_SIZE)),
            estimated_offset: RwLock::new(0),
            skew_warned: RwLock::new(false),
        }
    }

    /// Record a timestamp from a peer message
    ///
    /// Call this whenever you receive a timestamped message from a peer.
    /// The monitor will track peer timestamps and detect clock skew.
    ///
    /// Returns false if the timestamp was rejected as an outlier.
    pub fn record_peer_timestamp(&self, peer_timestamp_secs: i64) -> bool {
        let now_wall = chrono::Utc::now().timestamp();
        let now_mono = Instant::now();

        // SECURITY: Reject timestamps that are too far from local time
        // This prevents a malicious peer from manipulating our clock estimate
        let offset = (peer_timestamp_secs - now_wall).abs();
        if offset > MAX_PEER_OFFSET_SECS {
            warn!(
                peer_timestamp = peer_timestamp_secs,
                local_timestamp = now_wall,
                offset_secs = offset,
                max_allowed = MAX_PEER_OFFSET_SECS,
                "Rejecting peer timestamp as outlier"
            );
            return false;
        }

        let mut samples = self.peer_samples.write();
        samples.push_back((peer_timestamp_secs, now_mono));

        // Keep only recent samples
        while samples.len() > PEER_SAMPLE_SIZE {
            samples.pop_front();
        }

        // Calculate median offset if we have enough samples
        if samples.len() >= 3 {
            let mut offsets: Vec<i64> = samples
                .iter()
                .map(|(peer_ts, received_at)| {
                    // Calculate what our wall time was when we received this
                    let elapsed = now_mono.duration_since(*received_at).as_secs() as i64;
                    let our_time_then = now_wall - elapsed;
                    our_time_then - peer_ts
                })
                .collect();

            offsets.sort();
            let median_offset = offsets[offsets.len() / 2];

            *self.estimated_offset.write() = median_offset;

            // Warn if significant skew detected
            if median_offset.abs() > MAX_ACCEPTABLE_SKEW_SECS {
                let mut warned = self.skew_warned.write();
                if !*warned {
                    warn!(
                        offset_secs = median_offset,
                        "Clock skew detected: local clock is {}s {} than network median. \
                         Consider synchronizing with NTP.",
                        median_offset.abs(),
                        if median_offset > 0 { "ahead" } else { "behind" }
                    );
                    *warned = true;
                }
            } else {
                *self.skew_warned.write() = false;
            }
        }

        true
    }

    /// Get the estimated clock offset (our_time - network_median_time)
    ///
    /// Positive means our clock is ahead of the network.
    /// Negative means our clock is behind the network.
    pub fn estimated_offset_secs(&self) -> i64 {
        *self.estimated_offset.read()
    }

    /// Get a network-adjusted timestamp
    ///
    /// Returns our current time adjusted by the estimated clock offset.
    /// This is safer for cross-node timestamp comparisons.
    pub fn adjusted_timestamp(&self) -> i64 {
        let now = chrono::Utc::now().timestamp();
        let offset = *self.estimated_offset.read();
        now - offset
    }

    /// Check if a timestamp is within acceptable bounds
    ///
    /// Uses the adjusted time window to account for clock skew.
    /// `max_age_secs` is how old the timestamp can be.
    /// `max_future_secs` is how far in the future it can be.
    pub fn is_timestamp_valid(
        &self,
        timestamp: i64,
        max_age_secs: i64,
        max_future_secs: i64,
    ) -> bool {
        let adjusted_now = self.adjusted_timestamp();
        let min_valid = adjusted_now - max_age_secs;
        let max_valid = adjusted_now + max_future_secs;
        timestamp >= min_valid && timestamp <= max_valid
    }

    /// Check if we have significant clock skew
    pub fn has_significant_skew(&self) -> bool {
        self.estimated_offset_secs().abs() > MAX_ACCEPTABLE_SKEW_SECS
    }

    /// Get number of peer samples collected
    pub fn sample_count(&self) -> usize {
        self.peer_samples.read().len()
    }
}

impl Default for ClockMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Monotonic timer for durations and timeouts
///
/// Unlike system time, monotonic time is not affected by clock adjustments
/// (NTP updates, manual changes, etc.). Use this for:
/// - Voting session timeouts
/// - Rate limiter token refill
/// - Any internal timing that shouldn't be affected by clock changes
pub struct MonotonicTimer {
    started: Instant,
}

impl MonotonicTimer {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
        }
    }

    /// Get elapsed milliseconds since timer was created
    pub fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// Get elapsed seconds since timer was created
    pub fn elapsed_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    /// Check if the specified duration has passed
    pub fn has_elapsed_ms(&self, duration_ms: u64) -> bool {
        self.elapsed_ms() >= duration_ms
    }

    /// Check if the specified duration has passed
    pub fn has_elapsed_secs(&self, duration_secs: u64) -> bool {
        self.elapsed_secs() >= duration_secs
    }

    /// Reset the timer
    pub fn reset(&mut self) {
        self.started = Instant::now();
    }
}

impl Default for MonotonicTimer {
    fn default() -> Self {
        Self::new()
    }
}

/// Get current timestamp in seconds (UTC)
#[inline]
pub fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Get current timestamp in milliseconds (UTC)
#[inline]
pub fn now_millis() -> u64 {
    chrono::Utc::now().timestamp_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monotonic_timer() {
        let timer = MonotonicTimer::new();
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(timer.elapsed_ms() >= 10);
    }

    #[test]
    fn test_clock_monitor_basic() {
        let monitor = ClockMonitor::new();

        // Record some peer timestamps
        let now = chrono::Utc::now().timestamp();
        monitor.record_peer_timestamp(now);
        monitor.record_peer_timestamp(now - 1);
        monitor.record_peer_timestamp(now + 1);

        // Should have 3 samples
        assert_eq!(monitor.sample_count(), 3);

        // Offset should be small since we used our own time
        assert!(monitor.estimated_offset_secs().abs() < 5);
    }

    #[test]
    fn test_timestamp_validation() {
        let monitor = ClockMonitor::new();
        let now = chrono::Utc::now().timestamp();

        // Without any peer samples, uses raw local time
        assert!(monitor.is_timestamp_valid(now, 60, 60));
        assert!(monitor.is_timestamp_valid(now - 30, 60, 60));
        assert!(monitor.is_timestamp_valid(now + 30, 60, 60));
        assert!(!monitor.is_timestamp_valid(now - 120, 60, 60));
        assert!(!monitor.is_timestamp_valid(now + 120, 60, 60));
    }
}
