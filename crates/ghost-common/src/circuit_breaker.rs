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
//| FILE: circuit_breaker.rs                                                                                             |
//|======================================================================================================================|

//! Circuit breaker pattern for fault tolerance
//!
//! Implements the circuit breaker pattern to prevent cascading failures:
//!
//! - **Closed**: Normal operation, requests pass through
//! - **Open**: Service has failed too many times, requests are rejected immediately
//! - **Half-Open**: After cooldown, allows a single probe request to test recovery
//!
//! # Usage
//!
//! ```ignore
//! let breaker = CircuitBreaker::new("bitcoin_rpc", CircuitBreakerConfig::default());
//!
//! match breaker.call(|| async { bitcoin_client.get_template().await }) {
//!     Ok(template) => { /* use template */ }
//!     Err(CircuitBreakerError::Open) => { /* service unavailable */ }
//!     Err(CircuitBreakerError::ServiceError(e)) => { /* handle error */ }
//! }
//! ```

use parking_lot::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening the circuit
    pub failure_threshold: u32,
    /// Time to wait before attempting recovery (half-open)
    pub recovery_timeout: Duration,
    /// Number of successes needed in half-open to close circuit
    pub success_threshold: u32,
    /// Time window for counting failures
    pub failure_window: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            recovery_timeout: Duration::from_secs(30),
            success_threshold: 2,
            failure_window: Duration::from_secs(60),
        }
    }
}

impl CircuitBreakerConfig {
    /// Config for critical services (strict thresholds)
    pub fn strict() -> Self {
        Self {
            failure_threshold: 3,
            recovery_timeout: Duration::from_secs(60),
            success_threshold: 3,
            failure_window: Duration::from_secs(60),
        }
    }

    /// Config for non-critical services (relaxed thresholds)
    pub fn relaxed() -> Self {
        Self {
            failure_threshold: 10,
            recovery_timeout: Duration::from_secs(15),
            success_threshold: 1,
            failure_window: Duration::from_secs(120),
        }
    }
}

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation
    Closed,
    /// Service has failed, rejecting requests
    Open,
    /// Testing if service has recovered
    HalfOpen,
}

/// Circuit breaker errors
#[derive(Debug, thiserror::Error)]
pub enum CircuitBreakerError<E> {
    /// Circuit is open, request rejected
    #[error("Circuit breaker is open")]
    Open,
    /// Service returned an error
    #[error("Service error: {0}")]
    ServiceError(E),
}

/// Circuit breaker for fault tolerance
pub struct CircuitBreaker {
    name: String,
    config: CircuitBreakerConfig,
    state: Mutex<CircuitState>,
    failure_count: AtomicU32,
    success_count: AtomicU32,
    last_failure_time: Mutex<Option<Instant>>,
    opened_at: Mutex<Option<Instant>>,
    total_trips: AtomicU64,
}

impl CircuitBreaker {
    /// Create a new circuit breaker
    pub fn new(name: impl Into<String>, config: CircuitBreakerConfig) -> Self {
        Self {
            name: name.into(),
            config,
            state: Mutex::new(CircuitState::Closed),
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            last_failure_time: Mutex::new(None),
            opened_at: Mutex::new(None),
            total_trips: AtomicU64::new(0),
        }
    }

    /// Get current circuit state
    pub fn state(&self) -> CircuitState {
        self.check_and_update_state();
        *self.state.lock()
    }

    /// Check if the circuit allows requests
    pub fn is_allowed(&self) -> bool {
        match self.state() {
            CircuitState::Closed => true,
            CircuitState::HalfOpen => true,
            CircuitState::Open => false,
        }
    }

    /// Record a successful operation
    pub fn record_success(&self) {
        let mut state = self.state.lock();

        match *state {
            CircuitState::HalfOpen => {
                let count = self.success_count.fetch_add(1, Ordering::SeqCst) + 1;
                if count >= self.config.success_threshold {
                    info!(name = %self.name, "Circuit breaker closing after recovery");
                    *state = CircuitState::Closed;
                    self.failure_count.store(0, Ordering::SeqCst);
                    self.success_count.store(0, Ordering::SeqCst);
                    *self.opened_at.lock() = None;
                }
            }
            CircuitState::Closed => {
                // Reset failure count on success
                self.failure_count.store(0, Ordering::SeqCst);
            }
            CircuitState::Open => {
                // Shouldn't happen, but handle gracefully
            }
        }
    }

    /// Record a failed operation
    pub fn record_failure(&self) {
        let now = Instant::now();

        // Check if we should reset the failure window
        {
            let mut last_failure = self.last_failure_time.lock();
            if let Some(last) = *last_failure {
                if now.duration_since(last) > self.config.failure_window {
                    self.failure_count.store(0, Ordering::SeqCst);
                }
            }
            *last_failure = Some(now);
        }

        let failures = self.failure_count.fetch_add(1, Ordering::SeqCst) + 1;
        let mut state = self.state.lock();

        match *state {
            CircuitState::Closed => {
                if failures >= self.config.failure_threshold {
                    warn!(
                        name = %self.name,
                        failures,
                        threshold = self.config.failure_threshold,
                        "Circuit breaker tripped"
                    );
                    *state = CircuitState::Open;
                    *self.opened_at.lock() = Some(now);
                    self.total_trips.fetch_add(1, Ordering::SeqCst);
                }
            }
            CircuitState::HalfOpen => {
                // Failed during probe, go back to open
                warn!(name = %self.name, "Circuit breaker probe failed, re-opening");
                *state = CircuitState::Open;
                *self.opened_at.lock() = Some(now);
                self.success_count.store(0, Ordering::SeqCst);
            }
            CircuitState::Open => {
                // Already open
            }
        }
    }

    /// Check if circuit should transition from open to half-open
    fn check_and_update_state(&self) {
        let mut state = self.state.lock();

        if *state == CircuitState::Open {
            let opened_at = self.opened_at.lock();
            if let Some(opened) = *opened_at {
                if opened.elapsed() >= self.config.recovery_timeout {
                    debug!(name = %self.name, "Circuit breaker entering half-open state");
                    *state = CircuitState::HalfOpen;
                    self.success_count.store(0, Ordering::SeqCst);
                }
            }
        }
    }

    /// Execute a function with circuit breaker protection
    pub fn call<F, T, E>(&self, f: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: FnOnce() -> Result<T, E>,
    {
        if !self.is_allowed() {
            return Err(CircuitBreakerError::Open);
        }

        match f() {
            Ok(result) => {
                self.record_success();
                Ok(result)
            }
            Err(e) => {
                self.record_failure();
                Err(CircuitBreakerError::ServiceError(e))
            }
        }
    }

    /// Execute an async function with circuit breaker protection
    pub async fn call_async<F, Fut, T, E>(&self, f: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
    {
        if !self.is_allowed() {
            return Err(CircuitBreakerError::Open);
        }

        match f().await {
            Ok(result) => {
                self.record_success();
                Ok(result)
            }
            Err(e) => {
                self.record_failure();
                Err(CircuitBreakerError::ServiceError(e))
            }
        }
    }

    /// Get circuit breaker statistics
    pub fn stats(&self) -> CircuitBreakerStats {
        CircuitBreakerStats {
            name: self.name.clone(),
            state: self.state(),
            failure_count: self.failure_count.load(Ordering::SeqCst),
            success_count: self.success_count.load(Ordering::SeqCst),
            total_trips: self.total_trips.load(Ordering::SeqCst),
        }
    }

    /// Reset the circuit breaker to closed state
    pub fn reset(&self) {
        let mut state = self.state.lock();
        *state = CircuitState::Closed;
        self.failure_count.store(0, Ordering::SeqCst);
        self.success_count.store(0, Ordering::SeqCst);
        *self.opened_at.lock() = None;
        info!(name = %self.name, "Circuit breaker manually reset");
    }
}

/// Circuit breaker statistics
#[derive(Debug, Clone)]
pub struct CircuitBreakerStats {
    pub name: String,
    pub state: CircuitState,
    pub failure_count: u32,
    pub success_count: u32,
    pub total_trips: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_closed() {
        let breaker = CircuitBreaker::new("test", CircuitBreakerConfig::default());
        assert_eq!(breaker.state(), CircuitState::Closed);
        assert!(breaker.is_allowed());
    }

    #[test]
    fn test_circuit_breaker_trips() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let breaker = CircuitBreaker::new("test", config);

        // Record failures until tripped
        for _ in 0..3 {
            breaker.record_failure();
        }

        assert_eq!(breaker.state(), CircuitState::Open);
        assert!(!breaker.is_allowed());
    }

    #[test]
    fn test_circuit_breaker_success_resets() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let breaker = CircuitBreaker::new("test", config);

        // Record some failures
        breaker.record_failure();
        breaker.record_failure();

        // Success should reset
        breaker.record_success();
        assert_eq!(breaker.failure_count.load(Ordering::SeqCst), 0);
        assert_eq!(breaker.state(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_call() {
        let breaker = CircuitBreaker::new("test", CircuitBreakerConfig::default());

        // Successful call
        let result: Result<i32, CircuitBreakerError<&str>> = breaker.call(|| Ok(42));
        assert_eq!(result.unwrap(), 42);

        // Failed call
        let result: Result<i32, CircuitBreakerError<&str>> = breaker.call(|| Err("error"));
        assert!(matches!(
            result,
            Err(CircuitBreakerError::ServiceError("error"))
        ));
    }
}
