//! GSP failover and reconnection logic
//!
//! Wraps `MobileGspClient` with a list of GSP endpoints and
//! provides automatic failover on connection loss.

use super::gsp::MobileGspClient;
use super::NetworkError;
use parking_lot::Mutex;
use std::sync::Arc;
use tracing;

/// Configuration for failover behaviour.
#[derive(Debug, Clone)]
pub struct FailoverConfig {
    /// Maximum number of connection attempts per endpoint before
    /// moving to the next one.
    pub max_retries_per_endpoint: u32,
    /// Delay between retry attempts in milliseconds.
    pub retry_delay_ms: u64,
    /// Whether to cycle back to the first endpoint after exhausting
    /// all endpoints.
    pub cycle: bool,
}

impl Default for FailoverConfig {
    fn default() -> Self {
        Self {
            max_retries_per_endpoint: 3,
            retry_delay_ms: 2000,
            cycle: true,
        }
    }
}

/// GSP client with multi-endpoint failover.
///
/// Maintains an ordered list of GSP endpoints and automatically
/// connects to the next one when the current connection fails.
pub struct GspFailover {
    /// Ordered list of GSP WebSocket endpoint URLs.
    endpoints: Vec<String>,
    /// Index of the currently active (or last attempted) endpoint.
    current_index: Arc<Mutex<usize>>,
    /// The underlying GSP client.
    client: MobileGspClient,
    /// Failover configuration.
    config: FailoverConfig,
}

impl GspFailover {
    /// Create a new failover wrapper.
    ///
    /// # Arguments
    /// * `endpoints` - At least one GSP WebSocket URL.
    /// * `config` - Failover behaviour settings.
    ///
    /// # Panics
    /// Panics if `endpoints` is empty.
    pub fn new(endpoints: Vec<String>, config: FailoverConfig) -> Self {
        assert!(!endpoints.is_empty(), "at least one endpoint is required");
        Self {
            endpoints,
            current_index: Arc::new(Mutex::new(0)),
            client: MobileGspClient::new(),
            config,
        }
    }

    /// Create a failover wrapper with default configuration.
    pub fn with_defaults(endpoints: Vec<String>) -> Self {
        Self::new(endpoints, FailoverConfig::default())
    }

    /// Get a reference to the underlying GSP client.
    ///
    /// Use this after a successful connection to send requests and
    /// subscribe to events.
    pub fn client(&self) -> &MobileGspClient {
        &self.client
    }

    /// Get the currently active endpoint URL.
    pub fn current_endpoint(&self) -> String {
        let idx = *self.current_index.lock();
        self.endpoints[idx].clone()
    }

    /// Get the number of available endpoints.
    pub fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }

    /// Try to connect, cycling through endpoints on failure.
    ///
    /// Tries each endpoint up to `max_retries_per_endpoint` times
    /// before moving to the next. Returns an error only if all
    /// endpoints have been exhausted (or the maximum cycle count is
    /// reached when cycling is disabled).
    pub async fn connect_with_failover(&self) -> Result<(), NetworkError> {
        let total = self.endpoints.len();
        let max_attempts = if self.config.cycle {
            total * 2 // cycle through twice at most
        } else {
            total
        };

        for attempt in 0..max_attempts {
            let idx = {
                let mut idx = self.current_index.lock();
                let current = *idx;
                if attempt > 0 {
                    *idx = (current + 1) % total;
                }
                *idx
            };

            let endpoint = &self.endpoints[idx];

            for retry in 0..self.config.max_retries_per_endpoint {
                tracing::info!(
                    endpoint = %endpoint,
                    attempt = attempt + 1,
                    retry = retry + 1,
                    "GSP failover: connecting"
                );

                match self.client.connect(endpoint).await {
                    Ok(()) => {
                        tracing::info!(endpoint = %endpoint, "GSP failover: connected");
                        return Ok(());
                    }
                    Err(e) => {
                        tracing::warn!(
                            endpoint = %endpoint,
                            error = %e,
                            "GSP failover: connection failed"
                        );

                        if retry + 1 < self.config.max_retries_per_endpoint {
                            tokio::time::sleep(std::time::Duration::from_millis(
                                self.config.retry_delay_ms,
                            ))
                            .await;
                        }
                    }
                }
            }
        }

        Err(NetworkError::NoAvailableNodes)
    }

    /// Reconnect after a disconnection.
    ///
    /// Advances to the next endpoint and tries to connect, cycling
    /// through the list on failure.
    pub async fn reconnect(&self) -> Result<(), NetworkError> {
        // Disconnect first (idempotent).
        self.client.disconnect().await;

        // Advance to the next endpoint.
        {
            let mut idx = self.current_index.lock();
            *idx = (*idx + 1) % self.endpoints.len();
        }

        self.connect_with_failover().await
    }

    /// Disconnect from the current endpoint.
    pub async fn disconnect(&self) {
        self.client.disconnect().await;
    }

    /// Check whether the client is currently connected.
    pub fn is_connected(&self) -> bool {
        self.client.is_connected()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failover_creation() {
        let failover = GspFailover::with_defaults(vec![
            "wss://gsp1.ghost.network/ws".into(),
            "wss://gsp2.ghost.network/ws".into(),
            "wss://gsp3.ghost.network/ws".into(),
        ]);

        assert_eq!(failover.endpoint_count(), 3);
        assert_eq!(
            failover.current_endpoint(),
            "wss://gsp1.ghost.network/ws"
        );
        assert!(!failover.is_connected());
    }

    #[test]
    fn test_failover_config() {
        let config = FailoverConfig {
            max_retries_per_endpoint: 5,
            retry_delay_ms: 1000,
            cycle: false,
        };

        let failover = GspFailover::new(
            vec!["wss://node.example.com/ws".into()],
            config.clone(),
        );

        assert_eq!(failover.config.max_retries_per_endpoint, 5);
        assert!(!failover.config.cycle);
    }

    #[test]
    #[should_panic(expected = "at least one endpoint is required")]
    fn test_failover_empty_endpoints_panics() {
        let _failover = GspFailover::with_defaults(vec![]);
    }
}
