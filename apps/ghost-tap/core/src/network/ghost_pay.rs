//! Ghost Pay API client
//!
//! HTTP client for interacting with the Ghost Pay L2 REST API.
//! Supports glyph operations (claim, lookup, availability check).
//! Includes retry with exponential backoff for transient failures.

use serde::{Deserialize, Serialize};
use tracing::warn;

use super::NetworkError;

/// Maximum number of retry attempts for transient failures.
const MAX_RETRIES: u32 = 3;

/// Initial backoff delay in milliseconds (doubles each retry: 200, 400, 800).
const INITIAL_BACKOFF_MS: u64 = 200;

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

/// Whether an HTTP status code is retryable (server error or rate limited).
fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS
}

/// Whether a reqwest error is retryable (timeout, connection reset, etc.).
fn is_retryable_error(err: &reqwest::Error) -> bool {
    err.is_timeout() || err.is_connect() || err.is_request()
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

    /// Create a Ghost Pay API client using a shared reqwest::Client.
    ///
    /// This avoids creating a new connection pool per request — use when
    /// making repeated calls from a long-lived application (e.g. desktop).
    pub fn with_client(config: PayConfig, client: reqwest::Client) -> Self {
        Self { config, client }
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

        let mut last_err = None;
        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                let delay_ms = INITIAL_BACKOFF_MS * (1 << (attempt - 1));
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }

            let result = self.client.post(&url).json(&body).send().await;

            match result {
                Ok(resp) => {
                    if resp.status().is_success() {
                        return resp
                            .json::<GlyphClaimResponse>()
                            .await
                            .map_err(|e| NetworkError::InvalidResponse(e.to_string()));
                    }

                    let status = resp.status();
                    let resp_body = resp.text().await.unwrap_or_default();

                    if is_retryable_status(status) && attempt < MAX_RETRIES {
                        warn!(status = %status, attempt, "Glyph claim got retryable status, retrying");
                        last_err = Some(NetworkError::RequestFailed(format!(
                            "HTTP {}: {}", status, resp_body
                        )));
                        continue;
                    }

                    warn!(status = %status, body = %resp_body, "Glyph claim failed");
                    return Err(NetworkError::RequestFailed(format!(
                        "HTTP {}: {}", status, resp_body
                    )));
                }
                Err(e) => {
                    if is_retryable_error(&e) && attempt < MAX_RETRIES {
                        warn!(error = %e, attempt, "Glyph claim request failed, retrying");
                        last_err = Some(NetworkError::RequestFailed(e.to_string()));
                        continue;
                    }
                    return Err(NetworkError::RequestFailed(e.to_string()));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| NetworkError::RequestFailed("Max retries exceeded".into())))
    }

    /// Get glyph info by ghost ID
    pub async fn get_glyph(&self, ghost_id: &str) -> Result<Option<GlyphInfo>, NetworkError> {
        let url = format!("{}/api/v1/glyph/{}", self.config.base_url, ghost_id);

        let mut last_err = None;
        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                let delay_ms = INITIAL_BACKOFF_MS * (1 << (attempt - 1));
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }

            let result = self.client.get(&url).send().await;

            match result {
                Ok(resp) => {
                    if resp.status() == reqwest::StatusCode::NOT_FOUND {
                        return Ok(None);
                    }

                    if resp.status().is_success() {
                        return resp
                            .json::<GlyphInfo>()
                            .await
                            .map(Some)
                            .map_err(|e| NetworkError::InvalidResponse(e.to_string()));
                    }

                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();

                    if is_retryable_status(status) && attempt < MAX_RETRIES {
                        warn!(status = %status, attempt, "Get glyph got retryable status, retrying");
                        last_err = Some(NetworkError::RequestFailed(format!(
                            "HTTP {}: {}", status, body
                        )));
                        continue;
                    }

                    return Err(NetworkError::RequestFailed(format!(
                        "HTTP {}: {}", status, body
                    )));
                }
                Err(e) => {
                    if is_retryable_error(&e) && attempt < MAX_RETRIES {
                        warn!(error = %e, attempt, "Get glyph request failed, retrying");
                        last_err = Some(NetworkError::RequestFailed(e.to_string()));
                        continue;
                    }
                    return Err(NetworkError::RequestFailed(e.to_string()));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| NetworkError::RequestFailed("Max retries exceeded".into())))
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

        let mut last_err = None;
        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                let delay_ms = INITIAL_BACKOFF_MS * (1 << (attempt - 1));
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }

            let result = self.client.get(&url).send().await;

            match result {
                Ok(resp) => {
                    if resp.status().is_success() {
                        let avail: GlyphAvailability = resp
                            .json()
                            .await
                            .map_err(|e| NetworkError::InvalidResponse(e.to_string()))?;
                        return Ok(avail.available);
                    }

                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();

                    if is_retryable_status(status) && attempt < MAX_RETRIES {
                        warn!(status = %status, attempt, "Glyph availability check got retryable status, retrying");
                        last_err = Some(NetworkError::RequestFailed(format!(
                            "HTTP {}: {}", status, body
                        )));
                        continue;
                    }

                    return Err(NetworkError::RequestFailed(format!(
                        "HTTP {}: {}", status, body
                    )));
                }
                Err(e) => {
                    if is_retryable_error(&e) && attempt < MAX_RETRIES {
                        warn!(error = %e, attempt, "Glyph availability check failed, retrying");
                        last_err = Some(NetworkError::RequestFailed(e.to_string()));
                        continue;
                    }
                    return Err(NetworkError::RequestFailed(e.to_string()));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| NetworkError::RequestFailed("Max retries exceeded".into())))
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

    #[test]
    fn test_retryable_status_codes() {
        assert!(is_retryable_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR));
        assert!(is_retryable_status(reqwest::StatusCode::BAD_GATEWAY));
        assert!(is_retryable_status(reqwest::StatusCode::SERVICE_UNAVAILABLE));
        assert!(is_retryable_status(reqwest::StatusCode::TOO_MANY_REQUESTS));
        assert!(!is_retryable_status(reqwest::StatusCode::BAD_REQUEST));
        assert!(!is_retryable_status(reqwest::StatusCode::NOT_FOUND));
        assert!(!is_retryable_status(reqwest::StatusCode::OK));
    }
}
