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
//| FILE: client.rs                                                                                                      |
//|======================================================================================================================|

//! Verification client for challenging other nodes

use std::time::Duration;
use tracing::{debug, warn};

use ghost_common::constants::VERIFICATION_TIMEOUT_SECS;
use ghost_common::error::{GhostError, GhostResult};

use crate::challenge::*;

/// Configuration for the verification client
///
/// AUTH4-2: Configurable HTTPS support to prevent MITM attacks on verification requests.
#[derive(Debug, Clone)]
pub struct VerificationClientConfig {
    /// Use HTTPS for verification requests (default: true)
    ///
    /// SECURITY: Should always be true in production. Set to false only for
    /// local testing where TLS certificates are not available.
    pub use_https: bool,
    /// Request timeout
    pub timeout: Duration,
    /// Accept invalid TLS certificates (DANGEROUS - testing only)
    pub danger_accept_invalid_certs: bool,
}

impl Default for VerificationClientConfig {
    fn default() -> Self {
        Self {
            use_https: true,
            timeout: Duration::from_secs(VERIFICATION_TIMEOUT_SECS),
            danger_accept_invalid_certs: false,
        }
    }
}

impl VerificationClientConfig {
    /// Create a config for production (HTTPS required)
    pub fn production() -> Self {
        Self::default()
    }

    /// Create a config for testing (HTTP allowed)
    ///
    /// WARNING: Do not use in production - allows MITM attacks.
    pub fn insecure_for_testing() -> Self {
        Self {
            use_https: false,
            timeout: Duration::from_secs(VERIFICATION_TIMEOUT_SECS),
            danger_accept_invalid_certs: false,
        }
    }
}

/// Verification client
#[derive(Debug, Clone)]
pub struct VerificationClient {
    /// HTTP client
    client: reqwest::Client,
    /// Configuration
    config: VerificationClientConfig,
}

impl VerificationClient {
    /// Create a new verification client with default configuration (HTTPS required)
    ///
    /// AUTH4-2: Uses HTTPS by default to prevent MITM attacks.
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be created
    pub fn new() -> GhostResult<Self> {
        Self::with_config(VerificationClientConfig::default())
    }

    /// Create with custom configuration
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be created
    pub fn with_config(config: VerificationClientConfig) -> GhostResult<Self> {
        let mut builder = reqwest::Client::builder().timeout(config.timeout);

        if config.danger_accept_invalid_certs {
            warn!("DANGER: Verification client configured to accept invalid TLS certificates");
            builder = builder.danger_accept_invalid_certs(true);
        }

        let client = builder.build().map_err(|e| {
            debug!("HTTP client creation error: {}", e);
            GhostError::Internal("Failed to create HTTP client".to_string())
        })?;

        Ok(Self { client, config })
    }

    /// Create with custom timeout (uses HTTPS)
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be created
    pub fn with_timeout(timeout: Duration) -> GhostResult<Self> {
        Self::with_config(VerificationClientConfig {
            timeout,
            ..Default::default()
        })
    }

    /// Create an insecure client for testing only
    ///
    /// WARNING: This client uses HTTP without TLS, allowing MITM attacks.
    /// Do not use in production.
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be created
    pub fn new_insecure() -> GhostResult<Self> {
        warn!("Creating INSECURE verification client - for testing only!");
        Self::with_config(VerificationClientConfig::insecure_for_testing())
    }

    /// Get the URL scheme based on configuration
    fn scheme(&self) -> &'static str {
        if self.config.use_https {
            "https"
        } else {
            "http"
        }
    }

    /// Build a URL with the configured scheme
    fn build_url(&self, host: &str, path: &str) -> String {
        format!("{}://{}{}", self.scheme(), host, path)
    }

    /// Get health status of a node
    pub async fn health(&self, node_address: &str) -> GhostResult<HealthResponse> {
        let url = self.build_url(node_address, "/health?unsigned=true");
        debug!(url = %url, "Checking node health");

        let response = self.client.get(&url).send().await.map_err(|e| {
            debug!("Health check request failed: {}", e);
            GhostError::VerificationTimeout("Health check request failed".to_string())
        })?;

        // Health endpoint returns {"signed": bool, "response": HealthResponse}
        // We request unsigned=true for simplicity, but still need to unwrap
        let wrapper: serde_json::Value = response.json().await.map_err(|e| {
            debug!("Health check response parse error: {}", e);
            GhostError::InvalidVerificationResponse("Invalid health response format".to_string())
        })?;

        // Extract the inner response object
        let inner = wrapper.get("response").ok_or_else(|| {
            GhostError::InvalidVerificationResponse("Missing 'response' field".to_string())
        })?;

        let health: HealthResponse = serde_json::from_value(inner.clone()).map_err(|e| {
            debug!("Health response deserialization error: {}", e);
            GhostError::InvalidVerificationResponse("Invalid health response data".to_string())
        })?;

        Ok(health)
    }

    /// Verify archive capability
    pub async fn verify_archive(
        &self,
        node_address: &str,
        block_hash: Option<&str>,
        txid: Option<&str>,
    ) -> GhostResult<ArchiveResponse> {
        let mut params = vec!["unsigned=true".to_string()];
        if let Some(hash) = block_hash {
            params.push(format!("block={}", hash));
        }
        if let Some(tx) = txid {
            params.push(format!("tx={}", tx));
        }

        let url = self.build_url(
            node_address,
            &format!("/verify/archive?{}", params.join("&")),
        );

        debug!(url = %url, "Verifying archive capability");

        let response = self.client.get(&url).send().await.map_err(|e| {
            debug!("Archive verification request failed: {}", e);
            GhostError::VerificationTimeout("Archive verification request failed".to_string())
        })?;

        // Archive endpoint returns {"signed": bool, "response": ArchiveResponse}
        let wrapper: serde_json::Value = response.json().await.map_err(|e| {
            debug!("Archive verification response parse error: {}", e);
            GhostError::InvalidVerificationResponse("Invalid archive response format".to_string())
        })?;

        let inner = wrapper.get("response").ok_or_else(|| {
            GhostError::InvalidVerificationResponse("Missing 'response' field".to_string())
        })?;

        let result: ArchiveResponse = serde_json::from_value(inner.clone()).map_err(|e| {
            debug!("Archive response deserialization error: {}", e);
            GhostError::InvalidVerificationResponse("Invalid archive response data".to_string())
        })?;

        Ok(result)
    }

    /// Verify policy capability
    pub async fn verify_policy(
        &self,
        node_address: &str,
        tx_hex: &str,
    ) -> GhostResult<PolicyResponse> {
        let url = self.build_url(
            node_address,
            &format!(
                "/verify/policy?tx={}&unsigned=true",
                urlencoding::encode(tx_hex)
            ),
        );

        debug!(url = %url, "Verifying policy capability");

        let response = self.client.get(&url).send().await.map_err(|e| {
            debug!("Policy verification request failed: {}", e);
            GhostError::VerificationTimeout("Policy verification request failed".to_string())
        })?;

        // Policy endpoint returns {"signed": bool, "response": PolicyResponse}
        let wrapper: serde_json::Value = response.json().await.map_err(|e| {
            debug!("Policy verification response parse error: {}", e);
            GhostError::InvalidVerificationResponse("Invalid policy response format".to_string())
        })?;

        // Extract the inner response object
        let inner = wrapper.get("response").ok_or_else(|| {
            GhostError::InvalidVerificationResponse("Missing 'response' field".to_string())
        })?;

        let result: PolicyResponse = serde_json::from_value(inner.clone()).map_err(|e| {
            debug!("Policy response deserialization error: {}", e);
            GhostError::InvalidVerificationResponse("Invalid policy response data".to_string())
        })?;

        Ok(result)
    }

    /// Verify stratum capability
    pub async fn verify_stratum(
        &self,
        node_address: &str,
        protocol: StratumProtocol,
    ) -> GhostResult<StratumResponse> {
        let protocol_str = match protocol {
            StratumProtocol::Sv1 => "sv1",
            StratumProtocol::Sv2 => "sv2",
        };

        let url = self.build_url(
            node_address,
            &format!("/verify/stratum?protocol={}&unsigned=true", protocol_str),
        );

        debug!(url = %url, "Verifying stratum capability");

        let response = self.client.get(&url).send().await.map_err(|e| {
            debug!("Stratum verification request failed: {}", e);
            GhostError::VerificationTimeout("Stratum verification request failed".to_string())
        })?;

        // Stratum endpoint returns {"signed": bool, "response": StratumResponse}
        let wrapper: serde_json::Value = response.json().await.map_err(|e| {
            debug!("Stratum verification response parse error: {}", e);
            GhostError::InvalidVerificationResponse("Invalid stratum response format".to_string())
        })?;

        let inner = wrapper.get("response").ok_or_else(|| {
            GhostError::InvalidVerificationResponse("Missing 'response' field".to_string())
        })?;

        let result: StratumResponse = serde_json::from_value(inner.clone()).map_err(|e| {
            debug!("Stratum response deserialization error: {}", e);
            GhostError::InvalidVerificationResponse("Invalid stratum response data".to_string())
        })?;

        Ok(result)
    }

    /// Verify GhostPay capability
    pub async fn verify_ghostpay(
        &self,
        node_address: &str,
        address: Option<&str>,
    ) -> GhostResult<GhostPayResponse> {
        let path = if let Some(addr) = address {
            format!(
                "/verify/ghostpay?unsigned=true&address={}",
                urlencoding::encode(addr)
            )
        } else {
            "/verify/ghostpay?unsigned=true".to_string()
        };
        let url = self.build_url(node_address, &path);

        debug!(url = %url, "Verifying GhostPay capability");

        let response = self.client.get(&url).send().await.map_err(|e| {
            debug!("GhostPay verification request failed: {}", e);
            GhostError::VerificationTimeout("GhostPay verification request failed".to_string())
        })?;

        // GhostPay endpoint returns {"signed": bool, "response": GhostPayResponse}
        let wrapper: serde_json::Value = response.json().await.map_err(|e| {
            debug!("GhostPay verification response parse error: {}", e);
            GhostError::InvalidVerificationResponse("Invalid GhostPay response format".to_string())
        })?;

        let inner = wrapper.get("response").ok_or_else(|| {
            GhostError::InvalidVerificationResponse("Missing 'response' field".to_string())
        })?;

        let result: GhostPayResponse = serde_json::from_value(inner.clone()).map_err(|e| {
            debug!("GhostPay response deserialization error: {}", e);
            GhostError::InvalidVerificationResponse("Invalid GhostPay response data".to_string())
        })?;

        Ok(result)
    }

    /// Run full verification suite
    pub async fn verify_all_capabilities(
        &self,
        node_address: &str,
        test_block_hash: Option<&str>,
        test_tx_hex: Option<&str>,
    ) -> VerificationSuiteResult {
        let mut result = VerificationSuiteResult::default();

        // Health check
        match self.health(node_address).await {
            Ok(health) => {
                result.health = Some(health.clone());
                result.claimed_capabilities = health.capabilities;
            }
            Err(e) => {
                warn!(error = %e, "Health check failed");
                result.errors.push(format!("Health: {}", e));
                return result;
            }
        }

        // Archive verification
        if result.claimed_capabilities.archive_mode {
            if let Some(hash) = test_block_hash {
                match self.verify_archive(node_address, Some(hash), None).await {
                    Ok(resp) => result.archive_verified = resp.success,
                    Err(e) => result.errors.push(format!("Archive: {}", e)),
                }
            }
        }

        // Policy verification
        if result.claimed_capabilities.bitcoin_pure {
            if let Some(tx) = test_tx_hex {
                match self.verify_policy(node_address, tx).await {
                    Ok(resp) => result.policy_verified = resp.success,
                    Err(e) => result.errors.push(format!("Policy: {}", e)),
                }
            }
        }

        // Stratum verification
        if result.claimed_capabilities.public_mining {
            match self
                .verify_stratum(node_address, StratumProtocol::Sv2)
                .await
            {
                Ok(resp) => result.stratum_verified = resp.success && resp.connected,
                Err(e) => result.errors.push(format!("Stratum: {}", e)),
            }
        }

        // GhostPay verification
        if result.claimed_capabilities.ghost_pay {
            match self.verify_ghostpay(node_address, None).await {
                Ok(resp) => result.ghostpay_verified = resp.success && resp.l2_enabled,
                Err(e) => result.errors.push(format!("GhostPay: {}", e)),
            }
        }

        result
    }
}

/// Result of full verification suite
#[derive(Debug, Clone, Default)]
pub struct VerificationSuiteResult {
    /// Health response
    pub health: Option<HealthResponse>,
    /// Claimed capabilities
    pub claimed_capabilities: CapabilityStatus,
    /// Archive verified
    pub archive_verified: bool,
    /// Policy verified
    pub policy_verified: bool,
    /// Stratum verified
    pub stratum_verified: bool,
    /// GhostPay verified
    pub ghostpay_verified: bool,
    /// Errors encountered
    pub errors: Vec<String>,
}

impl VerificationSuiteResult {
    /// Calculate pass rate
    pub fn pass_rate(&self) -> f64 {
        let mut checks = 0;
        let mut passes = 0;

        if self.claimed_capabilities.archive_mode {
            checks += 1;
            if self.archive_verified {
                passes += 1;
            }
        }

        if self.claimed_capabilities.bitcoin_pure {
            checks += 1;
            if self.policy_verified {
                passes += 1;
            }
        }

        if self.claimed_capabilities.public_mining {
            checks += 1;
            if self.stratum_verified {
                passes += 1;
            }
        }

        if self.claimed_capabilities.ghost_pay {
            checks += 1;
            if self.ghostpay_verified {
                passes += 1;
            }
        }

        if checks == 0 {
            return 1.0;
        }

        passes as f64 / checks as f64
    }
}

// URL encoding helper
mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut result = String::new();
        for c in s.chars() {
            match c {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => result.push(c),
                _ => {
                    for byte in c.to_string().as_bytes() {
                        result.push_str(&format!("%{:02X}", byte));
                    }
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_encoding() {
        assert_eq!(urlencoding::encode("hello world"), "hello%20world");
        assert_eq!(urlencoding::encode("test=value"), "test%3Dvalue");
    }

    #[test]
    fn test_pass_rate() {
        let mut result = VerificationSuiteResult::default();
        result.claimed_capabilities.archive_mode = true;
        result.claimed_capabilities.public_mining = true;
        result.archive_verified = true;
        result.stratum_verified = false;

        assert_eq!(result.pass_rate(), 0.5);
    }
}
