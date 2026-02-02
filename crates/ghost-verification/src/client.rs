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

/// Verification client
#[derive(Debug, Clone)]
pub struct VerificationClient {
    /// HTTP client
    client: reqwest::Client,
    /// Request timeout (configured, used implicitly by reqwest)
    #[allow(dead_code)]
    timeout: Duration,
}

impl VerificationClient {
    /// Create a new verification client
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be created
    pub fn new() -> GhostResult<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(VERIFICATION_TIMEOUT_SECS))
            .build()
            .map_err(|e| GhostError::Internal(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            client,
            timeout: Duration::from_secs(VERIFICATION_TIMEOUT_SECS),
        })
    }

    /// Create with custom timeout
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be created
    pub fn with_timeout(timeout: Duration) -> GhostResult<Self> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| GhostError::Internal(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self { client, timeout })
    }

    /// Get health status of a node
    pub async fn health(&self, node_address: &str) -> GhostResult<HealthResponse> {
        let url = format!("http://{}/health?unsigned=true", node_address);
        debug!(url = %url, "Checking node health");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| GhostError::VerificationTimeout(e.to_string()))?;

        // Health endpoint returns {"signed": bool, "response": HealthResponse}
        // We request unsigned=true for simplicity, but still need to unwrap
        let wrapper: serde_json::Value = response
            .json()
            .await
            .map_err(|e| GhostError::InvalidVerificationResponse(e.to_string()))?;

        // Extract the inner response object
        let inner = wrapper
            .get("response")
            .ok_or_else(|| GhostError::InvalidVerificationResponse("Missing 'response' field".to_string()))?;

        let health: HealthResponse = serde_json::from_value(inner.clone())
            .map_err(|e| GhostError::InvalidVerificationResponse(e.to_string()))?;

        Ok(health)
    }

    /// Verify archive capability
    pub async fn verify_archive(
        &self,
        node_address: &str,
        block_hash: Option<&str>,
        txid: Option<&str>,
    ) -> GhostResult<ArchiveResponse> {
        let mut url = format!("http://{}/verify/archive", node_address);

        let mut params = vec!["unsigned=true".to_string()];
        if let Some(hash) = block_hash {
            params.push(format!("block={}", hash));
        }
        if let Some(tx) = txid {
            params.push(format!("tx={}", tx));
        }

        url = format!("{}?{}", url, params.join("&"));

        debug!(url = %url, "Verifying archive capability");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| GhostError::VerificationTimeout(e.to_string()))?;

        // Archive endpoint returns {"signed": bool, "response": ArchiveResponse}
        let wrapper: serde_json::Value = response
            .json()
            .await
            .map_err(|e| GhostError::InvalidVerificationResponse(e.to_string()))?;

        let inner = wrapper
            .get("response")
            .ok_or_else(|| GhostError::InvalidVerificationResponse("Missing 'response' field".to_string()))?;

        let result: ArchiveResponse = serde_json::from_value(inner.clone())
            .map_err(|e| GhostError::InvalidVerificationResponse(e.to_string()))?;

        Ok(result)
    }

    /// Verify policy capability
    pub async fn verify_policy(
        &self,
        node_address: &str,
        tx_hex: &str,
    ) -> GhostResult<PolicyResponse> {
        let url = format!(
            "http://{}/verify/policy?tx={}&unsigned=true",
            node_address,
            urlencoding::encode(tx_hex)
        );

        debug!(url = %url, "Verifying policy capability");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| GhostError::VerificationTimeout(e.to_string()))?;

        // Policy endpoint returns {"signed": bool, "response": PolicyResponse}
        let wrapper: serde_json::Value = response
            .json()
            .await
            .map_err(|e| GhostError::InvalidVerificationResponse(e.to_string()))?;

        // Extract the inner response object
        let inner = wrapper
            .get("response")
            .ok_or_else(|| GhostError::InvalidVerificationResponse("Missing 'response' field".to_string()))?;

        let result: PolicyResponse = serde_json::from_value(inner.clone())
            .map_err(|e| GhostError::InvalidVerificationResponse(e.to_string()))?;

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

        let url = format!(
            "http://{}/verify/stratum?protocol={}&unsigned=true",
            node_address, protocol_str
        );

        debug!(url = %url, "Verifying stratum capability");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| GhostError::VerificationTimeout(e.to_string()))?;

        // Stratum endpoint returns {"signed": bool, "response": StratumResponse}
        let wrapper: serde_json::Value = response
            .json()
            .await
            .map_err(|e| GhostError::InvalidVerificationResponse(e.to_string()))?;

        let inner = wrapper
            .get("response")
            .ok_or_else(|| GhostError::InvalidVerificationResponse("Missing 'response' field".to_string()))?;

        let result: StratumResponse = serde_json::from_value(inner.clone())
            .map_err(|e| GhostError::InvalidVerificationResponse(e.to_string()))?;

        Ok(result)
    }

    /// Verify GhostPay capability
    pub async fn verify_ghostpay(
        &self,
        node_address: &str,
        address: Option<&str>,
    ) -> GhostResult<GhostPayResponse> {
        let mut url = format!("http://{}/verify/ghostpay?unsigned=true", node_address);

        if let Some(addr) = address {
            url = format!("{}&address={}", url, urlencoding::encode(addr));
        }

        debug!(url = %url, "Verifying GhostPay capability");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| GhostError::VerificationTimeout(e.to_string()))?;

        // GhostPay endpoint returns {"signed": bool, "response": GhostPayResponse}
        let wrapper: serde_json::Value = response
            .json()
            .await
            .map_err(|e| GhostError::InvalidVerificationResponse(e.to_string()))?;

        let inner = wrapper
            .get("response")
            .ok_or_else(|| GhostError::InvalidVerificationResponse("Missing 'response' field".to_string()))?;

        let result: GhostPayResponse = serde_json::from_value(inner.clone())
            .map_err(|e| GhostError::InvalidVerificationResponse(e.to_string()))?;

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
