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

/// H-3 FIX: Milli-tokens per full token (integer arithmetic for precision)
const MILLIS_PER_TOKEN: u64 = 1000;

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

/// M-6 FIX: Maximum consecutive rejections before backoff tracking
const MAX_REJECTION_COUNT: u32 = 10;

/// M-6 FIX: Maximum backoff time in seconds (1 hour)
const MAX_BACKOFF_SECS: u64 = 3600;

/// Token bucket for a single wallet
/// H-3 FIX: Uses milli-tokens (integer) instead of f64 to avoid float precision issues
struct WalletTokenBucket {
    /// H-3 FIX: Current number of milli-tokens available (1000 milli-tokens = 1 token)
    milli_tokens: u64,
    /// H-3 FIX: Maximum milli-tokens (bucket capacity)
    max_milli_tokens: u64,
    /// H-3 FIX: Milli-tokens to add per second
    refill_rate_millis_per_sec: u64,
    /// Last time tokens were refilled
    last_refill: Instant,
    /// Last time this bucket was accessed
    last_access: Instant,
    /// M-6 FIX: Consecutive rejection count for backoff
    rejection_count: u32,
    /// M-6 FIX: Time until backoff expires (if in backoff state)
    backoff_until: Option<Instant>,
}

impl WalletTokenBucket {
    /// Create a new token bucket for a wallet
    fn new() -> Self {
        let now = Instant::now();
        Self {
            // H-3 FIX: Store as milli-tokens
            milli_tokens: WALLET_BURST_SIZE * MILLIS_PER_TOKEN,
            max_milli_tokens: WALLET_BURST_SIZE * MILLIS_PER_TOKEN,
            refill_rate_millis_per_sec: WALLET_RATE_LIMIT_PER_SEC * MILLIS_PER_TOKEN,
            last_refill: now,
            last_access: now,
            rejection_count: 0,
            backoff_until: None,
        }
    }

    /// Try to consume one token. Returns true if allowed, false if rate limited.
    fn try_consume(&mut self) -> bool {
        self.last_access = Instant::now();

        // M-6 FIX: Check if in backoff state
        if let Some(backoff_until) = self.backoff_until {
            if Instant::now() < backoff_until {
                // Still in backoff, reject
                return false;
            } else {
                // Backoff expired, clear it
                self.backoff_until = None;
                self.rejection_count = 0;
            }
        }

        self.refill();

        // H-3 FIX: Check if we have at least one full token (1000 milli-tokens)
        if self.milli_tokens >= MILLIS_PER_TOKEN {
            self.milli_tokens -= MILLIS_PER_TOKEN;
            // Reset rejection count on successful consume
            self.rejection_count = 0;
            true
        } else {
            // M-6 FIX: Track rejection and apply backoff
            self.rejection_count = self.rejection_count.saturating_add(1);

            if self.rejection_count >= MAX_REJECTION_COUNT {
                // Apply exponential backoff
                let backoff_secs = (1u64 << self.rejection_count.min(10)).min(MAX_BACKOFF_SECS);
                self.backoff_until = Some(Instant::now() + Duration::from_secs(backoff_secs));
                tracing::warn!(
                    rejection_count = self.rejection_count,
                    backoff_secs = backoff_secs,
                    "M-6: Wallet entering backoff state due to repeated rate limit violations"
                );
            }

            false
        }
    }

    /// H-3 FIX: Refill tokens using integer arithmetic
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed_millis = self.last_refill.elapsed().as_millis() as u64;

        // H-3 FIX: Integer arithmetic: millis_to_add = elapsed_ms * (refill_rate_millis / 1000)
        // Simplified: elapsed_millis * refill_rate_millis_per_sec / 1000
        let millis_to_add = elapsed_millis.saturating_mul(self.refill_rate_millis_per_sec) / 1000;

        if millis_to_add > 0 {
            self.milli_tokens = self
                .milli_tokens
                .saturating_add(millis_to_add)
                .min(self.max_milli_tokens);
            self.last_refill = now;
        }
    }

    /// Check if this bucket should be evicted (hasn't been used recently)
    fn is_stale(&self) -> bool {
        self.last_access.elapsed() > Duration::from_secs(BUCKET_CLEANUP_INTERVAL_SECS)
    }

    /// Get current token count (for testing/monitoring)
    #[cfg(test)]
    fn tokens(&self) -> u64 {
        self.milli_tokens / MILLIS_PER_TOKEN
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
            // M-5 FIX: Collect stale keys first to avoid holding write lock during full scan
            let stale_keys: Vec<String> = buckets
                .iter()
                .filter(|(_, bucket)| bucket.is_stale())
                .map(|(key, _)| key.clone())
                .collect();

            // Now remove the stale entries
            for key in &stale_keys {
                buckets.remove(key);
            }

            if !stale_keys.is_empty() {
                tracing::debug!(
                    removed = stale_keys.len(),
                    remaining = buckets.len(),
                    "M-5: Emergency cleanup of stale per-wallet rate limit buckets"
                );
            }

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
    /// M-5 FIX: Uses collect-then-remove pattern to minimize lock hold time
    fn maybe_cleanup(&self) {
        let should_cleanup = {
            let last_cleanup = self.last_cleanup.read();
            last_cleanup.elapsed() > Duration::from_secs(60) // Check every minute
        };

        if should_cleanup {
            // M-5 FIX: First collect stale keys with read lock
            let stale_keys: Vec<String> = {
                let buckets = self.buckets.read();
                buckets
                    .iter()
                    .filter(|(_, bucket)| bucket.is_stale())
                    .map(|(key, _)| key.clone())
                    .collect()
            };

            // Only acquire write lock if we have something to remove
            if !stale_keys.is_empty() {
                let mut buckets = self.buckets.write();
                let mut last_cleanup = self.last_cleanup.write();

                // Double-check after acquiring write lock
                if last_cleanup.elapsed() > Duration::from_secs(60) {
                    let before = buckets.len();
                    for key in &stale_keys {
                        // Re-check staleness in case it was accessed since read lock
                        if let Some(bucket) = buckets.get(key) {
                            if bucket.is_stale() {
                                buckets.remove(key);
                            }
                        }
                    }
                    let removed = before - buckets.len();

                    if removed > 0 {
                        tracing::debug!(
                            removed = removed,
                            remaining = buckets.len(),
                            "M-12: Cleaned up stale per-wallet rate limit buckets"
                        );
                    }
                    *last_cleanup = Instant::now();
                }
            } else {
                // Just update the timestamp if no stale entries
                let mut last_cleanup = self.last_cleanup.write();
                if last_cleanup.elapsed() > Duration::from_secs(60) {
                    *last_cleanup = Instant::now();
                }
            }
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
            assert!(
                limiter.try_consume(&wallet),
                "M-12: Should allow requests within burst"
            );
        }

        // Should deny after burst exhausted
        assert!(
            !limiter.try_consume(&wallet),
            "M-12: Should deny after burst exhausted"
        );
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
        assert!(
            !limiter.try_consume(&wallet1),
            "M-12: wallet1 should be rate limited"
        );

        // wallet2 should still be allowed (separate bucket)
        assert!(
            limiter.try_consume(&wallet2),
            "M-12: wallet2 should have its own bucket"
        );
    }

    #[test]
    fn test_m12_tracked_wallet_count() {
        let limiter = WalletRateLimiter::new();

        assert_eq!(limiter.tracked_wallet_count(), 0);

        let wallet = WalletId::from("test_wallet_12345678901234".to_string());
        limiter.try_consume(&wallet);

        assert_eq!(limiter.tracked_wallet_count(), 1);
    }

    #[test]
    fn test_h3_integer_token_arithmetic() {
        // H-3 FIX: Verify milli-token arithmetic works correctly
        let mut bucket = WalletTokenBucket::new();

        // Initial tokens should be burst size
        assert_eq!(bucket.tokens(), WALLET_BURST_SIZE);

        // Consume one token
        assert!(bucket.try_consume());
        assert_eq!(bucket.tokens(), WALLET_BURST_SIZE - 1);

        // Consume all remaining tokens
        for _ in 0..(WALLET_BURST_SIZE - 1) {
            assert!(bucket.try_consume());
        }

        // Should be empty now
        assert_eq!(bucket.tokens(), 0);
        assert!(!bucket.try_consume());
    }

    #[test]
    fn test_m6_backoff_tracking() {
        // M-6 FIX: Verify backoff is applied after repeated rejections
        let mut bucket = WalletTokenBucket::new();

        // Exhaust all tokens
        for _ in 0..WALLET_BURST_SIZE {
            bucket.try_consume();
        }

        // Should now be empty - first rejection increments count to 1
        assert!(!bucket.try_consume());
        assert_eq!(bucket.rejection_count, 1);

        // Keep rejecting until we hit MAX_REJECTION_COUNT
        // At MAX_REJECTION_COUNT, backoff should be triggered
        for i in 2..MAX_REJECTION_COUNT {
            assert!(!bucket.try_consume());
            assert_eq!(bucket.rejection_count, i);
            assert!(
                bucket.backoff_until.is_none(),
                "Backoff should not be applied yet at count {i}"
            );
        }

        // This rejection should trigger backoff (rejection_count becomes MAX_REJECTION_COUNT)
        assert!(!bucket.try_consume());
        assert_eq!(bucket.rejection_count, MAX_REJECTION_COUNT);
        assert!(bucket.backoff_until.is_some(), "Backoff should be applied");
    }

    #[test]
    fn test_h3_refill_precision() {
        // H-3 FIX: Test that refill uses integer arithmetic correctly
        let mut bucket = WalletTokenBucket::new();

        // Exhaust all tokens
        for _ in 0..WALLET_BURST_SIZE {
            bucket.try_consume();
        }

        // Simulate time passing (we can't easily test this without mocking time,
        // but we can verify the calculation logic)
        assert_eq!(bucket.tokens(), 0);

        // Verify the milli-token fields are set correctly
        assert_eq!(
            bucket.refill_rate_millis_per_sec,
            WALLET_RATE_LIMIT_PER_SEC * MILLIS_PER_TOKEN
        );
        assert_eq!(
            bucket.max_milli_tokens,
            WALLET_BURST_SIZE * MILLIS_PER_TOKEN
        );
    }
}
