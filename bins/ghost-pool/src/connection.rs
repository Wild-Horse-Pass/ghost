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
//| FILE: connection.rs                                                                                                  |
//|======================================================================================================================|

//! Connection tracking, rate limiting, and IP banning
//!
//! Provides defense against DoS attacks, brute force auth attempts,
//! and resource exhaustion from misbehaving miners.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Connection limits configuration
#[derive(Debug, Clone)]
pub struct ConnectionLimits {
    /// Maximum connections per IP address
    pub max_per_ip: usize,
    /// Maximum total connections
    pub max_total: usize,
    /// Maximum message size (bytes)
    pub max_message_size: usize,
    /// Maximum messages per second per connection
    pub max_messages_per_sec: u32,
    /// Maximum authentication failures before ban
    pub max_auth_failures: u32,
    /// Ban duration after exceeded failures
    pub ban_duration: Duration,
    /// Maximum invalid shares before ban
    pub max_invalid_shares: u32,
    /// Window for counting invalid shares
    pub invalid_share_window: Duration,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            max_per_ip: 100, // Reasonable for NAT/mining farms
            max_total: 10_000,
            max_message_size: 4096, // Stratum messages are small
            max_messages_per_sec: 50,
            max_auth_failures: 3,
            ban_duration: Duration::from_secs(3600), // 1 hour ban
            max_invalid_shares: 100,
            invalid_share_window: Duration::from_secs(60),
        }
    }
}

impl ConnectionLimits {
    /// Strict limits for production
    pub fn strict() -> Self {
        Self {
            max_per_ip: 50,
            max_total: 5_000,
            max_message_size: 2048,
            max_messages_per_sec: 30,
            max_auth_failures: 2,
            ban_duration: Duration::from_secs(7200), // 2 hour ban
            max_invalid_shares: 50,
            invalid_share_window: Duration::from_secs(60),
        }
    }

    /// Relaxed limits for testing
    pub fn relaxed() -> Self {
        Self {
            max_per_ip: 500,
            max_total: 50_000,
            max_message_size: 8192,
            max_messages_per_sec: 100,
            max_auth_failures: 10,
            ban_duration: Duration::from_secs(300), // 5 minute ban
            max_invalid_shares: 500,
            invalid_share_window: Duration::from_secs(120),
        }
    }
}

/// Reason for connection rejection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// IP is currently banned
    Banned { until: Instant },
    /// Too many connections from this IP
    TooManyFromIp { current: usize, max: usize },
    /// Server at capacity
    ServerFull { current: usize, max: usize },
    /// Rate limit exceeded
    RateLimited,
    /// Too many invalid shares
    TooManyInvalidShares,
}

impl std::fmt::Display for RejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RejectReason::Banned { .. } => write!(f, "IP is banned"),
            RejectReason::TooManyFromIp { current, max } => {
                write!(f, "Too many connections from IP ({}/{})", current, max)
            }
            RejectReason::ServerFull { current, max } => {
                write!(f, "Server at capacity ({}/{})", current, max)
            }
            RejectReason::RateLimited => write!(f, "Rate limit exceeded"),
            RejectReason::TooManyInvalidShares => write!(f, "Too many invalid shares"),
        }
    }
}

/// Per-IP tracking data
#[derive(Debug)]
struct IpTracker {
    /// Current connection count
    connections: usize,
    /// Authentication failures (count, first_failure_time)
    auth_failures: (u32, Instant),
    /// Invalid shares (count, window_start)
    invalid_shares: (u32, Instant),
    /// Last activity time
    last_activity: Instant,
}

impl Default for IpTracker {
    fn default() -> Self {
        Self {
            connections: 0,
            auth_failures: (0, Instant::now()),
            invalid_shares: (0, Instant::now()),
            last_activity: Instant::now(),
        }
    }
}

/// Connection tracker with rate limiting and banning
pub struct ConnectionTracker {
    /// Per-IP tracking
    ip_trackers: RwLock<HashMap<IpAddr, IpTracker>>,
    /// Banned IPs with expiration time
    banned_ips: RwLock<HashMap<IpAddr, Instant>>,
    /// Total connection count
    total_connections: RwLock<usize>,
    /// Configuration
    limits: ConnectionLimits,
}

impl ConnectionTracker {
    /// Create a new connection tracker
    pub fn new(limits: ConnectionLimits) -> Self {
        Self {
            ip_trackers: RwLock::new(HashMap::new()),
            banned_ips: RwLock::new(HashMap::new()),
            total_connections: RwLock::new(0),
            limits,
        }
    }

    /// M-13: Atomically check if a new connection is allowed and register it
    ///
    /// This replaces the separate `allow_connection()` + `connection_opened()` calls
    /// which had a TOCTOU race: between the check and the registration, another
    /// connection could sneak in and exceed the limit.
    ///
    /// Now, all checks and registration happen under a single write lock acquisition,
    /// ensuring the limits cannot be bypassed by concurrent connections.
    ///
    /// Returns Ok(()) if the connection was accepted and registered.
    /// Returns Err(RejectReason) if the connection was rejected (not registered).
    pub fn try_open_connection(&self, ip: IpAddr) -> Result<(), RejectReason> {
        // Check ban list first (separate lock is fine - bans are advisory)
        {
            let banned = self.banned_ips.read();
            if let Some(&ban_until) = banned.get(&ip) {
                if Instant::now() < ban_until {
                    return Err(RejectReason::Banned { until: ban_until });
                }
                // Ban expired, will be cleaned up later
            }
        }

        // M-13: Acquire BOTH write locks before checking limits, then register atomically
        let mut total = self.total_connections.write();
        let mut trackers = self.ip_trackers.write();

        // Check total connections
        if *total >= self.limits.max_total {
            return Err(RejectReason::ServerFull {
                current: *total,
                max: self.limits.max_total,
            });
        }

        // Check per-IP connections
        if let Some(tracker) = trackers.get(&ip) {
            if tracker.connections >= self.limits.max_per_ip {
                return Err(RejectReason::TooManyFromIp {
                    current: tracker.connections,
                    max: self.limits.max_per_ip,
                });
            }
        }

        // All checks passed - register atomically under the same locks
        *total += 1;
        let tracker = trackers.entry(ip).or_default();
        tracker.connections += 1;
        tracker.last_activity = Instant::now();

        debug!(ip = %ip, connections = tracker.connections, "Connection opened");

        Ok(())
    }

    /// Check if a new connection is allowed (without registering)
    ///
    /// M-13: For most use cases, prefer `try_open_connection()` which atomically
    /// checks and registers. This method is kept for cases where you need to
    /// check without committing (e.g., diagnostics).
    pub fn allow_connection(&self, ip: IpAddr) -> Result<(), RejectReason> {
        // Check ban list first
        {
            let banned = self.banned_ips.read();
            if let Some(&ban_until) = banned.get(&ip) {
                if Instant::now() < ban_until {
                    return Err(RejectReason::Banned { until: ban_until });
                }
            }
        }

        // Check total connections
        {
            let total = *self.total_connections.read();
            if total >= self.limits.max_total {
                return Err(RejectReason::ServerFull {
                    current: total,
                    max: self.limits.max_total,
                });
            }
        }

        // Check per-IP connections
        {
            let trackers = self.ip_trackers.read();
            if let Some(tracker) = trackers.get(&ip) {
                if tracker.connections >= self.limits.max_per_ip {
                    return Err(RejectReason::TooManyFromIp {
                        current: tracker.connections,
                        max: self.limits.max_per_ip,
                    });
                }
            }
        }

        Ok(())
    }

    /// Register a new connection (without checking limits)
    ///
    /// M-13: For most use cases, prefer `try_open_connection()` which atomically
    /// checks and registers. This method is kept for backward compatibility.
    pub fn connection_opened(&self, ip: IpAddr) {
        // Increment total
        *self.total_connections.write() += 1;

        // Increment per-IP
        let mut trackers = self.ip_trackers.write();
        let tracker = trackers.entry(ip).or_default();
        tracker.connections += 1;
        tracker.last_activity = Instant::now();

        debug!(ip = %ip, connections = tracker.connections, "Connection opened");
    }

    /// Unregister a closed connection
    pub fn connection_closed(&self, ip: IpAddr) {
        // Decrement total
        {
            let mut total = self.total_connections.write();
            *total = total.saturating_sub(1);
        }

        // Decrement per-IP
        let mut trackers = self.ip_trackers.write();
        if let Some(tracker) = trackers.get_mut(&ip) {
            tracker.connections = tracker.connections.saturating_sub(1);
            debug!(ip = %ip, connections = tracker.connections, "Connection closed");

            // Clean up if no connections and no recent failures
            if tracker.connections == 0 && tracker.auth_failures.0 == 0 {
                trackers.remove(&ip);
            }
        }
    }

    /// Record an authentication failure
    pub fn record_auth_failure(&self, ip: IpAddr) {
        let should_ban = {
            let mut trackers = self.ip_trackers.write();
            let tracker = trackers.entry(ip).or_default();

            // Reset counter if window expired
            if tracker.auth_failures.1.elapsed() > self.limits.ban_duration {
                tracker.auth_failures = (0, Instant::now());
            }

            tracker.auth_failures.0 += 1;
            tracker.last_activity = Instant::now();

            warn!(
                ip = %ip,
                failures = tracker.auth_failures.0,
                max = self.limits.max_auth_failures,
                "Authentication failure"
            );

            tracker.auth_failures.0 >= self.limits.max_auth_failures
        };

        if should_ban {
            self.ban_ip(ip, "excessive authentication failures");
        }
    }

    /// Record an invalid share submission
    pub fn record_invalid_share(&self, ip: IpAddr) -> Result<(), RejectReason> {
        let should_ban = {
            let mut trackers = self.ip_trackers.write();
            let tracker = trackers.entry(ip).or_default();

            // Reset counter if window expired
            if tracker.invalid_shares.1.elapsed() > self.limits.invalid_share_window {
                tracker.invalid_shares = (0, Instant::now());
            }

            tracker.invalid_shares.0 += 1;
            tracker.last_activity = Instant::now();

            tracker.invalid_shares.0 >= self.limits.max_invalid_shares
        };

        if should_ban {
            self.ban_ip(ip, "excessive invalid shares");
            return Err(RejectReason::TooManyInvalidShares);
        }

        Ok(())
    }

    /// Record a valid share (resets invalid share counter)
    pub fn record_valid_share(&self, ip: IpAddr) {
        let mut trackers = self.ip_trackers.write();
        if let Some(tracker) = trackers.get_mut(&ip) {
            // Decay invalid share count on valid shares
            tracker.invalid_shares.0 = tracker.invalid_shares.0.saturating_sub(1);
            tracker.last_activity = Instant::now();
        }
    }

    /// Ban an IP address
    pub fn ban_ip(&self, ip: IpAddr, reason: &str) {
        let ban_until = Instant::now() + self.limits.ban_duration;
        self.banned_ips.write().insert(ip, ban_until);

        warn!(
            ip = %ip,
            duration_secs = self.limits.ban_duration.as_secs(),
            reason = reason,
            "IP banned"
        );
    }

    /// Manually unban an IP address
    pub fn unban_ip(&self, ip: IpAddr) {
        if self.banned_ips.write().remove(&ip).is_some() {
            info!(ip = %ip, "IP unbanned");
        }
    }

    /// Check if an IP is banned
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        let banned = self.banned_ips.read();
        if let Some(&ban_until) = banned.get(&ip) {
            Instant::now() < ban_until
        } else {
            false
        }
    }

    /// Get current connection count for an IP
    pub fn connection_count(&self, ip: IpAddr) -> usize {
        self.ip_trackers
            .read()
            .get(&ip)
            .map(|t| t.connections)
            .unwrap_or(0)
    }

    /// Get total connection count
    pub fn total_connections(&self) -> usize {
        *self.total_connections.read()
    }

    /// Clean up expired bans and stale trackers
    pub fn cleanup(&self) {
        let now = Instant::now();

        // Clean expired bans
        {
            let mut banned = self.banned_ips.write();
            banned.retain(|ip, &mut ban_until| {
                let expired = now >= ban_until;
                if expired {
                    debug!(ip = %ip, "Ban expired");
                }
                !expired
            });
        }

        // Clean stale trackers (no connections, no recent activity)
        {
            let mut trackers = self.ip_trackers.write();
            trackers.retain(|_ip, tracker| {
                tracker.connections > 0
                    || tracker.last_activity.elapsed() < Duration::from_secs(3600)
            });
        }
    }

    /// Get statistics
    pub fn stats(&self) -> ConnectionStats {
        ConnectionStats {
            total_connections: *self.total_connections.read(),
            unique_ips: self.ip_trackers.read().len(),
            banned_ips: self.banned_ips.read().len(),
        }
    }
}

/// Connection statistics
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    pub total_connections: usize,
    pub unique_ips: usize,
    pub banned_ips: usize,
}

/// Per-connection rate limiter
pub struct RateLimiter {
    /// Tokens available (allows bursting)
    tokens: f64,
    /// Last update time
    last_update: Instant,
    /// Maximum tokens (burst size)
    max_tokens: f64,
    /// Tokens added per second
    refill_rate: f64,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(max_per_sec: u32, burst: u32) -> Self {
        Self {
            tokens: burst as f64,
            last_update: Instant::now(),
            max_tokens: burst as f64,
            refill_rate: max_per_sec as f64,
        }
    }

    /// Check if an action is allowed (and consume a token if so)
    pub fn allow(&mut self) -> bool {
        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;

        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
    }

    /// Get current token count
    pub fn tokens(&self) -> f64 {
        self.tokens
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))
    }

    #[test]
    fn test_connection_tracking() {
        let tracker = ConnectionTracker::new(ConnectionLimits::default());
        let ip = test_ip();

        // Should allow first connection
        assert!(tracker.allow_connection(ip).is_ok());
        tracker.connection_opened(ip);
        assert_eq!(tracker.connection_count(ip), 1);

        // Close connection
        tracker.connection_closed(ip);
        assert_eq!(tracker.connection_count(ip), 0);
    }

    #[test]
    fn test_per_ip_limit() {
        let limits = ConnectionLimits {
            max_per_ip: 2,
            ..Default::default()
        };
        let tracker = ConnectionTracker::new(limits);
        let ip = test_ip();

        // Allow first two
        assert!(tracker.allow_connection(ip).is_ok());
        tracker.connection_opened(ip);
        assert!(tracker.allow_connection(ip).is_ok());
        tracker.connection_opened(ip);

        // Third should be rejected
        let result = tracker.allow_connection(ip);
        assert!(matches!(result, Err(RejectReason::TooManyFromIp { .. })));
    }

    #[test]
    fn test_auth_failure_ban() {
        let limits = ConnectionLimits {
            max_auth_failures: 2,
            ban_duration: Duration::from_secs(10),
            ..Default::default()
        };
        let tracker = ConnectionTracker::new(limits);
        let ip = test_ip();

        // First failure - not banned
        tracker.record_auth_failure(ip);
        assert!(!tracker.is_banned(ip));

        // Second failure - banned
        tracker.record_auth_failure(ip);
        assert!(tracker.is_banned(ip));

        // Connection should be rejected
        let result = tracker.allow_connection(ip);
        assert!(matches!(result, Err(RejectReason::Banned { .. })));
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(10, 5); // 10/sec, burst of 5

        // Should allow burst
        for _ in 0..5 {
            assert!(limiter.allow());
        }

        // 6th should be denied (no time to refill)
        assert!(!limiter.allow());
    }

    #[test]
    fn test_rate_limiter_refill() {
        let mut limiter = RateLimiter::new(1000, 1); // High rate for testing

        // Use the token
        assert!(limiter.allow());
        assert!(!limiter.allow());

        // Wait a bit and try again
        std::thread::sleep(Duration::from_millis(10));
        assert!(limiter.allow()); // Should have refilled
    }

    // =========================================================================
    // M-13: Atomic try_open_connection tests
    // =========================================================================

    #[test]
    fn test_m13_try_open_connection_basic() {
        let tracker = ConnectionTracker::new(ConnectionLimits::default());
        let ip = test_ip();

        // Should atomically check and register
        assert!(tracker.try_open_connection(ip).is_ok());
        assert_eq!(tracker.connection_count(ip), 1);
        assert_eq!(tracker.total_connections(), 1);

        // Close and verify
        tracker.connection_closed(ip);
        assert_eq!(tracker.connection_count(ip), 0);
        assert_eq!(tracker.total_connections(), 0);
    }

    #[test]
    fn test_m13_try_open_connection_per_ip_limit() {
        let limits = ConnectionLimits {
            max_per_ip: 2,
            ..Default::default()
        };
        let tracker = ConnectionTracker::new(limits);
        let ip = test_ip();

        // First two should succeed atomically
        assert!(tracker.try_open_connection(ip).is_ok());
        assert!(tracker.try_open_connection(ip).is_ok());
        assert_eq!(tracker.connection_count(ip), 2);

        // Third should be rejected and NOT registered
        let result = tracker.try_open_connection(ip);
        assert!(matches!(result, Err(RejectReason::TooManyFromIp { .. })));
        assert_eq!(tracker.connection_count(ip), 2); // Still 2, not 3
    }

    #[test]
    fn test_m13_try_open_connection_total_limit() {
        let limits = ConnectionLimits {
            max_total: 2,
            ..Default::default()
        };
        let tracker = ConnectionTracker::new(limits);
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let ip3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

        assert!(tracker.try_open_connection(ip1).is_ok());
        assert!(tracker.try_open_connection(ip2).is_ok());

        // Third from different IP should be rejected (total limit)
        let result = tracker.try_open_connection(ip3);
        assert!(matches!(result, Err(RejectReason::ServerFull { .. })));
        assert_eq!(tracker.total_connections(), 2);
    }

    #[test]
    fn test_m13_try_open_connection_banned_ip() {
        let limits = ConnectionLimits {
            ban_duration: Duration::from_secs(60),
            ..Default::default()
        };
        let tracker = ConnectionTracker::new(limits);
        let ip = test_ip();

        // Ban the IP
        tracker.ban_ip(ip, "test");

        // Should be rejected before any counting
        let result = tracker.try_open_connection(ip);
        assert!(matches!(result, Err(RejectReason::Banned { .. })));
        assert_eq!(tracker.connection_count(ip), 0);
        assert_eq!(tracker.total_connections(), 0);
    }
}
