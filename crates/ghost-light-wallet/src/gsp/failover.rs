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
//| FILE: gsp/failover.rs                                                                                                |
//|======================================================================================================================|

//! Multi-GSP failover handling

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tracing::{info, warn};

use ghost_gsp_proto::WalletId;

use super::GspClient;
use crate::error::{LightWalletError, WalletResult};

/// GSP endpoint with health tracking
#[derive(Debug, Clone)]
pub struct GspEndpoint {
    /// WebSocket URL
    pub url: String,

    /// Is endpoint currently healthy
    pub healthy: bool,

    /// Last successful connection time
    pub last_success: Option<Instant>,

    /// Last failure time
    pub last_failure: Option<Instant>,

    /// Consecutive failure count
    pub failure_count: u32,

    /// Priority (lower = preferred)
    pub priority: u32,
}

impl GspEndpoint {
    /// Create a new endpoint
    pub fn new(url: &str, priority: u32) -> Self {
        Self {
            url: url.to_string(),
            healthy: true,
            last_success: None,
            last_failure: None,
            failure_count: 0,
            priority,
        }
    }

    /// Mark endpoint as healthy
    pub fn mark_healthy(&mut self) {
        self.healthy = true;
        self.last_success = Some(Instant::now());
        self.failure_count = 0;
    }

    /// Mark endpoint as failed
    pub fn mark_failed(&mut self) {
        self.healthy = false;
        self.last_failure = Some(Instant::now());
        self.failure_count += 1;
    }

    /// Check if endpoint should be retried
    pub fn should_retry(&self, backoff: Duration) -> bool {
        if self.healthy {
            return true;
        }

        match self.last_failure {
            Some(t) => t.elapsed() >= backoff * self.failure_count,
            None => true,
        }
    }
}

/// Multi-GSP failover manager
#[allow(dead_code)]
pub struct GspFailover {
    /// Available endpoints
    endpoints: Arc<RwLock<Vec<GspEndpoint>>>,

    /// Current active client
    client: Arc<RwLock<Option<GspClient>>>,

    /// Wallet ID
    wallet_id: WalletId,

    /// Retry backoff duration
    backoff: Duration,

    /// Maximum retry attempts
    max_retries: u32,
}

impl GspFailover {
    /// Create a new failover manager
    pub fn new(urls: Vec<String>, wallet_id: WalletId) -> Self {
        let endpoints: Vec<GspEndpoint> = urls
            .into_iter()
            .enumerate()
            .map(|(i, url)| GspEndpoint::new(&url, i as u32))
            .collect();

        Self {
            endpoints: Arc::new(RwLock::new(endpoints)),
            client: Arc::new(RwLock::new(None)),
            wallet_id,
            backoff: Duration::from_secs(5),
            max_retries: 3,
        }
    }

    /// Connect to the best available GSP
    pub async fn connect(&self) -> WalletResult<()> {
        let endpoints = self.endpoints.read().clone();

        // Sort by priority and health
        let mut candidates: Vec<_> = endpoints
            .iter()
            .filter(|e| e.should_retry(self.backoff))
            .collect();

        candidates.sort_by_key(|e| (if e.healthy { 0 } else { 1 }, e.priority));

        for endpoint in candidates {
            info!(url = endpoint.url, "Attempting GSP connection");

            match GspClient::connect(&endpoint.url, &self.wallet_id).await {
                Ok(client) => {
                    // Mark endpoint as healthy
                    self.mark_endpoint_healthy(&endpoint.url);

                    // Store client
                    *self.client.write() = Some(client);

                    info!(url = endpoint.url, "Connected to GSP");
                    return Ok(());
                }
                Err(e) => {
                    warn!(url = endpoint.url, error = %e, "GSP connection failed");
                    self.mark_endpoint_failed(&endpoint.url);
                }
            }
        }

        Err(LightWalletError::AllGspsUnavailable)
    }

    /// Get current client
    pub fn client(&self) -> Option<Arc<RwLock<Option<GspClient>>>> {
        Some(self.client.clone())
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.client
            .read()
            .as_ref()
            .map(|c| c.is_connected())
            .unwrap_or(false)
    }

    /// Disconnect current client
    pub async fn disconnect(&self) {
        if let Some(client) = self.client.write().take() {
            client.close().await;
        }
    }

    /// Reconnect (try next available GSP)
    pub async fn reconnect(&self) -> WalletResult<()> {
        // Mark current as failed
        if let Some(client) = self.client.read().as_ref() {
            self.mark_endpoint_failed(client.url());
        }

        // Disconnect
        self.disconnect().await;

        // Connect to next available
        self.connect().await
    }

    /// Add an endpoint
    pub fn add_endpoint(&self, url: &str, priority: u32) {
        let mut endpoints = self.endpoints.write();
        if !endpoints.iter().any(|e| e.url == url) {
            endpoints.push(GspEndpoint::new(url, priority));
        }
    }

    /// Remove an endpoint
    pub fn remove_endpoint(&self, url: &str) {
        let mut endpoints = self.endpoints.write();
        endpoints.retain(|e| e.url != url);
    }

    /// Mark endpoint as healthy
    fn mark_endpoint_healthy(&self, url: &str) {
        let mut endpoints = self.endpoints.write();
        if let Some(e) = endpoints.iter_mut().find(|e| e.url == url) {
            e.mark_healthy();
        }
    }

    /// Mark endpoint as failed
    fn mark_endpoint_failed(&self, url: &str) {
        let mut endpoints = self.endpoints.write();
        if let Some(e) = endpoints.iter_mut().find(|e| e.url == url) {
            e.mark_failed();
        }
    }

    /// Get endpoint statuses
    pub fn endpoint_statuses(&self) -> Vec<GspEndpoint> {
        self.endpoints.read().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_health() {
        let mut endpoint = GspEndpoint::new("wss://test.example.com/ws", 0);
        assert!(endpoint.healthy);

        endpoint.mark_failed();
        assert!(!endpoint.healthy);
        assert_eq!(endpoint.failure_count, 1);

        endpoint.mark_healthy();
        assert!(endpoint.healthy);
        assert_eq!(endpoint.failure_count, 0);
    }

    #[test]
    fn test_failover_creation() {
        let wallet_id = WalletId::from_pubkey(&[0u8; 32]);
        let failover = GspFailover::new(
            vec![
                "wss://gsp1.example.com/ws".to_string(),
                "wss://gsp2.example.com/ws".to_string(),
            ],
            wallet_id,
        );

        let statuses = failover.endpoint_statuses();
        assert_eq!(statuses.len(), 2);
        assert!(statuses[0].healthy);
        assert!(statuses[1].healthy);
    }
}
