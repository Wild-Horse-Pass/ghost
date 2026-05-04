//! Ghost-pay REST client.

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

use super::{ChainClient, ChainError, ChainStatus};

pub struct GhostPayClient {
    base_url: String,
    http: Client,
}

impl GhostPayClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            http: Client::new(),
        }
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.base_url.trim_end_matches('/'), path)
    }
}

#[async_trait]
impl ChainClient for GhostPayClient {
    async fn status(&self) -> Result<ChainStatus, ChainError> {
        let url = self.endpoint("/api/v1/status");
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
