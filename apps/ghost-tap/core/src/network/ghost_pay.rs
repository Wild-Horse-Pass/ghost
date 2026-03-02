//! Ghost Pay API client
//!
//! HTTP client for interacting with the Ghost Pay L2 REST API.
//! Supports glyph operations (claim, lookup, availability check).

use serde::{Deserialize, Serialize};
use tracing::warn;

use super::NetworkError;

/// Configuration for Ghost Pay API connection
#[derive(Debug, Clone)]
pub struct PayConfig {
    /// Ghost Pay API base URL (e.g. "http://127.0.0.1:8800")
    pub base_url: String,
    /// Request timeout in milliseconds
    pub timeout_ms: u64,
}

impl Default for PayConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:8800".to_string(),
            timeout_ms: 10_000,
        }
    }
}

/// Ghost Pay REST API client
pub struct GhostPayClient {
    config: PayConfig,
    client: reqwest::Client,
}

/// Response from POST /api/v1/glyph/claim
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlyphClaimResponse {
    pub commitment: String,
    pub bitmap_hash: String,
    pub status: String,
}

/// Response from GET /api/v1/glyph/:ghost_id
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlyphInfo {
    pub ghost_id: String,
    pub pixels: Vec<u8>,
    pub bitmap_hash: String,
    pub commitment: String,
    pub funding_txid: Option<String>,
    pub registered_at: Option<u64>,
    pub status: String,
}

/// Response from GET /api/v1/glyph/check/:bitmap_hash_hex
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlyphAvailability {
    pub available: bool,
}

impl GhostPayClient {
    /// Create a new Ghost Pay API client
    pub fn new(config: PayConfig) -> Result<Self, NetworkError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?;

        Ok(Self { config, client })
    }

    /// Submit a glyph claim (design chosen, pending lock funding)
    pub async fn claim_glyph(
        &self,
        ghost_id: &str,
        pixels: &[u8],
    ) -> Result<GlyphClaimResponse, NetworkError> {
        let url = format!("{}/api/v1/glyph/claim", self.config.base_url);
        let body = serde_json::json!({
            "ghost_id": ghost_id,
            "pixels": pixels,
        });

        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| NetworkError::RequestFailed(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(status = %status, body = %body, "Glyph claim failed");
            return Err(NetworkError::RequestFailed(format!(
                "HTTP {}: {}",
                status, body
            )));
        }

        resp.json::<GlyphClaimResponse>()
            .await
            .map_err(|e| NetworkError::InvalidResponse(e.to_string()))
    }

    /// Get glyph info by ghost ID
    pub async fn get_glyph(&self, ghost_id: &str) -> Result<Option<GlyphInfo>, NetworkError> {
        let url = format!("{}/api/v1/glyph/{}", self.config.base_url, ghost_id);

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| NetworkError::RequestFailed(e.to_string()))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(NetworkError::RequestFailed(format!(
                "HTTP {}: {}",
                status, body
            )));
        }

        resp.json::<GlyphInfo>()
            .await
            .map(Some)
            .map_err(|e| NetworkError::InvalidResponse(e.to_string()))
    }

    /// Check if a bitmap hash is available for registration
    pub async fn check_glyph_availability(
        &self,
        bitmap_hash_hex: &str,
    ) -> Result<bool, NetworkError> {
        let url = format!(
            "{}/api/v1/glyph/check/{}",
            self.config.base_url, bitmap_hash_hex
        );

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| NetworkError::RequestFailed(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(NetworkError::RequestFailed(format!(
                "HTTP {}: {}",
                status, body
            )));
        }

        let result: GlyphAvailability = resp
            .json()
            .await
            .map_err(|e| NetworkError::InvalidResponse(e.to_string()))?;

        Ok(result.available)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pay_config_default() {
        let config = PayConfig::default();
        assert_eq!(config.base_url, "http://127.0.0.1:8800");
        assert_eq!(config.timeout_ms, 10_000);
    }

    #[test]
    fn test_ghost_pay_client_creation() {
        let config = PayConfig::default();
        let client = GhostPayClient::new(config);
        assert!(client.is_ok());
    }
}
