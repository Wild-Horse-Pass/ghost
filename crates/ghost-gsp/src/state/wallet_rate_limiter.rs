//|======================================================================================================================|
//|                                                                                                                      |
//|  M-12 FIX: Per-Wallet-ID Rate Limiting                                                                               |
//|                                                                                                                      |
//| This module provides rate limiting on a per-wallet basis, complementing the per-connection                           |
//| rate limiting in websocket.rs. A single wallet may have multiple connections, so per-wallet                          |
//| rate limiting prevents abuse across connections from the same authenticated wallet.                                   |
//|                                                                                                                      |
//|======================================================================================================================|

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use ghost_gsp_proto::WalletId;

/// M-12 FIX: Per-wallet rate limit configuration
/// Maximum operations per second per wallet (across all connections)
const WALLET_RATE_LIMIT_PER_SEC: u64 = 50;

/// M-12 FIX: Per-wallet burst allowance
/// Allows brief bursts of activity (2x sustained rate)
const WALLET_BURST_SIZE: u64 = 100;

/// M-12 FIX: Token bucket cleanup interval (seconds)
/// Wallet rate limiters that haven't been used in this time are evicted
const BUCKET_CLEANUP_INTERVAL_SECS: u64 = 300; // 5 minutes

/// M-12 FIX: Maximum number of wallet rate limiters to track
/// Prevents memory exhaustion from tracking too many wallets
const MAX_TRACKED_WALLETS: usize = 10000;

/// Token bucket for a single wallet
struct WalletTokenBucket {
    /// Current number of tokens available
    tokens: u64,
    /// Maximum tokens (bucket capacity)
    capacity: u64,
    /// Tokens to add per second
    refill_rate: u64,
    /// Last time tokens were refilled
    last_refill: Instant,
    /// Last time this bucket was accessed
    last_access: Instant,
}

impl WalletTokenBucket {
    /// Create a new token bucket for a wallet
    fn new() -> Self {
        let now = Instant::now();
        Self {
            tokens: WALLET_BURST_SIZE,
            capacity: WALLET_BURST_SIZE,
            refill_rate: WALLET_RATE_LIMIT_PER_SEC,
            last_refill: now,
            last_access: now,
        }
    }

    /// Try to consume one token. Returns true if allowed, false if rate limited.
    fn try_consume(&mut self) -> bool {
        self.refill();
        self.last_access = Instant::now();

        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let elapsed_secs = elapsed.as_secs_f64();

        if elapsed_secs > 0.0 {
            // Calculate tokens to add based on elapsed time
            let tokens_to_add = (elapsed_secs * self.refill_rate as f64) as u64;
            if tokens_to_add > 0 {
                self.tokens = (self.tokens + tokens_to_add).min(self.capacity);
                self.last_refill = now;
            }
        }
    }

    /// Check if this bucket should be evicted (hasn't been used recently)
    fn is_stale(&self) -> bool {
        self.last_access.elapsed() > Duration::from_secs(BUCKET_CLEANUP_INTERVAL_SECS)
    }
}

/// M-12 FIX: Per-wallet rate limiter
///
/// Tracks rate limits on a per-wallet basis across all connections.
/// This prevents a malicious user from evading rate limits by opening
/// multiple WebSocket connections to the same wallet.
pub struct WalletRateLimiter {
    /// Wallet ID -> Token bucket
    buckets: RwLock<HashMap<String, WalletTokenBucket>>,
    /// Last time we ran cleanup
    last_cleanup: RwLock<Instant>,
}

impl WalletRateLimiter {
    /// Create a new per-wallet rate limiter
    pub fn new() -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
            last_cleanup: RwLock::new(Instant::now()),
        }
    }

    /// M-12: Try to consume a rate limit token for the given wallet.
    ///
    /// Returns true if the operation is allowed, false if rate limited.
    /// This should be called for each authenticated operation.
    pub fn try_consume(&self, wallet_id: &WalletId) -> bool {
        // Periodically cleanup stale buckets
        self.maybe_cleanup();

        let wallet_key = wallet_id.to_string();

        // Need write lock to create bucket or consume token
        let mut buckets = self.buckets.write();

        // Check if we're at the max tracked wallets
        if buckets.len() >= MAX_TRACKED_WALLETS && !buckets.contains_key(&wallet_key) {
            // At capacity and this is a new wallet - run emergency cleanup
            self.cleanup_stale_buckets(&mut buckets);

            // If still at capacity, reject (fail closed for security)
            if buckets.len() >= MAX_TRACKED_WALLETS {
                tracing::warn!(
                    wallet_id = %wallet_id,
                    tracked_wallets = buckets.len(),
                    max_wallets = MAX_TRACKED_WALLETS,
                    "M-12: Per-wallet rate limiter at capacity, rejecting new wallet"
                );
                return false;
            }
        }

        // Get or create bucket for this wallet
        let bucket = buckets
            .entry(wallet_key)
            .or_insert_with(WalletTokenBucket::new);

        bucket.try_consume()
    }

    /// Periodically cleanup stale buckets
    fn maybe_cleanup(&self) {
        let should_cleanup = {
            let last_cleanup = self.last_cleanup.read();
            last_cleanup.elapsed() > Duration::from_secs(60) // Check every minute
        };

        if should_cleanup {
            let mut buckets = self.buckets.write();
            let mut last_cleanup = self.last_cleanup.write();

            // Double-check after acquiring write lock
            if last_cleanup.elapsed() > Duration::from_secs(60) {
                self.cleanup_stale_buckets(&mut buckets);
                *last_cleanup = Instant::now();
            }
        }
    }

    /// Remove stale buckets that haven't been used recently
    fn cleanup_stale_buckets(&self, buckets: &mut HashMap<String, WalletTokenBucket>) {
        let before = buckets.len();
        buckets.retain(|_, bucket| !bucket.is_stale());
        let removed = before - buckets.len();

        if removed > 0 {
            tracing::debug!(
                removed = removed,
                remaining = buckets.len(),
                "M-12: Cleaned up stale per-wallet rate limit buckets"
            );
        }
    }

    /// Get the number of tracked wallets (for monitoring)
    pub fn tracked_wallet_count(&self) -> usize {
        self.buckets.read().len()
    }
}

impl Default for WalletRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_m12_wallet_rate_limiter_basic() {
        let limiter = WalletRateLimiter::new();
        let wallet = WalletId::from("test_wallet_12345678901234".to_string());

        // Should allow initial requests (up to burst size)
        for _ in 0..WALLET_BURST_SIZE {
            assert!(limiter.try_consume(&wallet), "M-12: Should allow requests within burst");
        }

        // Should deny after burst exhausted
        assert!(!limiter.try_consume(&wallet), "M-12: Should deny after burst exhausted");
    }

    #[test]
    fn test_m12_wallet_rate_limiter_different_wallets() {
        let limiter = WalletRateLimiter::new();
        let wallet1 = WalletId::from("wallet1_1234567890123456".to_string());
        let wallet2 = WalletId::from("wallet2_1234567890123456".to_string());

        // Exhaust wallet1's burst
        for _ in 0..WALLET_BURST_SIZE {
            limiter.try_consume(&wallet1);
        }

        // wallet1 should be rate limited
        assert!(!limiter.try_consume(&wallet1), "M-12: wallet1 should be rate limited");

        // wallet2 should still be allowed (separate bucket)
        assert!(limiter.try_consume(&wallet2), "M-12: wallet2 should have its own bucket");
    }

    #[test]
    fn test_m12_tracked_wallet_count() {
        let limiter = WalletRateLimiter::new();

        assert_eq!(limiter.tracked_wallet_count(), 0);

        let wallet = WalletId::from("test_wallet_12345678901234".to_string());
        limiter.try_consume(&wallet);

        assert_eq!(limiter.tracked_wallet_count(), 1);
    }
}
