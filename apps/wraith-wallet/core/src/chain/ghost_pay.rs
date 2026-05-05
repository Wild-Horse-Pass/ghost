//! Ghost-pay REST client.

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

use super::{ChainClient, ChainError, ChainStatus};

/// REST client for ghost-pay. Holds one or more base URLs and tries them in
/// order on each request — a failure on the first URL automatically falls
/// over to the next.
pub struct GhostPayClient {
    base_urls: Vec<String>,
    http: Client,
}

impl GhostPayClient {
    /// Construct from a single base URL.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_urls(vec![base_url.into()])
    }

    /// Construct from a list of base URLs. They will be tried in order on
    /// each request until one succeeds.
    pub fn with_urls(base_urls: Vec<String>) -> Self {
        let urls = if base_urls.is_empty() {
            vec!["http://127.0.0.1:8800".to_string()]
        } else {
            base_urls
        };
        Self {
            base_urls: urls,
            http: Client::new(),
        }
    }

    /// Parse a comma-separated URL list, trimming whitespace and dropping
    /// empty entries.
    pub fn parse_urls(s: &str) -> Vec<String> {
        s.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    }

    fn endpoint(&self, base_url: &str, path: &str) -> String {
        format!("{}{}", base_url.trim_end_matches('/'), path)
    }
}

#[async_trait]
impl ChainClient for GhostPayClient {
    async fn status(&self) -> Result<ChainStatus, ChainError> {
        let mut last_err: Option<ChainError> = None;
        for base in &self.base_urls {
            match self.try_status(base).await {
                Ok(s) => return Ok(s),
                Err(e) => {
                    tracing::debug!(url = %base, error = %e, "ghost-pay endpoint failed, trying next");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| ChainError::Transport("no endpoints configured".into())))
    }
}

impl GhostPayClient {
    async fn try_status(&self, base_url: &str) -> Result<ChainStatus, ChainError> {
        let url = self.endpoint(base_url, "/api/v1/status");
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| ChainError::Transport(e.to_string()))?
            .error_for_status()
            .map_err(|e| ChainError::Backend(e.to_string()))?;
        let body: StatusBody = resp
            .json()
            .await
            .map_err(|e| ChainError::Malformed(e.to_string()))?;
        Ok(ChainStatus {
            backend_version: body.version,
            network: body.network,
            has_keys: body.has_keys,
            lock_count: body.lock_count,
            active_sessions: body.active_sessions,
        })
    }
}

#[derive(Deserialize)]
struct StatusBody {
    version: String,
    has_keys: bool,
    lock_count: u64,
    active_sessions: u64,
    network: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_urls_strips_and_drops_empties() {
        assert_eq!(
            GhostPayClient::parse_urls("http://a, http://b ,, http://c"),
            vec!["http://a", "http://b", "http://c"]
        );
        assert!(GhostPayClient::parse_urls("").is_empty());
        assert!(GhostPayClient::parse_urls(" , , ").is_empty());
    }

    #[test]
    fn parses_ghost_pay_status_body() {
        let json = r#"{
            "version": "1.8.0",
            "has_keys": true,
            "lock_count": 3,
            "active_sessions": 0,
            "network": "signet"
        }"#;
        let body: StatusBody = serde_json::from_str(json).unwrap();
        assert_eq!(body.version, "1.8.0");
        assert_eq!(body.network, "signet");
        assert!(body.has_keys);
        assert_eq!(body.lock_count, 3);
        assert_eq!(body.active_sessions, 0);
    }
}
