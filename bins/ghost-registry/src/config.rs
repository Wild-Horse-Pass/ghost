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
//| FILE: config.rs                                                                                                      |
//|======================================================================================================================|

//! Configuration for ghost-registry service

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main registry service configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryServiceConfig {
    /// Server configuration
    pub server: ServerConfig,
    /// Cloudflare DNS configuration
    pub cloudflare: CloudflareConfig,
    /// DNS update settings
    pub dns: DnsConfig,
    /// Health monitoring settings
    pub health: HealthConfig,
    /// Database configuration
    pub database: DatabaseConfig,
}

/// HTTP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Listen address (e.g., "0.0.0.0:8333")
    pub listen: String,
    /// Request timeout in seconds
    pub request_timeout_secs: u64,
    /// Maximum request body size in bytes
    pub max_body_size: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8333".to_string(),
            request_timeout_secs: 30,
            max_body_size: 1024 * 1024, // 1MB
        }
    }
}

/// Cloudflare API configuration
///
/// M-18 FIX: Custom Debug implementation to redact api_token
#[derive(Clone, Serialize, Deserialize)]
pub struct CloudflareConfig {
    /// Cloudflare Zone ID for the domain
    pub zone_id: String,
    /// API token (scoped to DNS edit)
    /// Can use ${CLOUDFLARE_API_TOKEN} for environment variable
    pub api_token: String,
    /// Base domain (e.g., "bitcoinghost.org")
    pub base_domain: String,
    /// Enable Cloudflare integration (can be disabled for testing)
    pub enabled: bool,
}

// M-18 FIX: Custom Debug that redacts api_token to prevent accidental exposure in logs
impl std::fmt::Debug for CloudflareConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareConfig")
            .field("zone_id", &self.zone_id)
            .field("api_token", &"[REDACTED]")
            .field("base_domain", &self.base_domain)
            .field("enabled", &self.enabled)
            .finish()
    }
}

impl Default for CloudflareConfig {
    fn default() -> Self {
        Self {
            zone_id: String::new(),
            api_token: String::new(),
            base_domain: "bitcoinghost.org".to_string(),
            enabled: true,
        }
    }
}

impl CloudflareConfig {
    /// Resolve environment variables in configuration
    pub fn resolve_env(&mut self) {
        // Resolve ${VAR} or $VAR patterns in api_token
        if self.api_token.starts_with("${") && self.api_token.ends_with('}') {
            let var_name = &self.api_token[2..self.api_token.len() - 1];
            if let Ok(value) = std::env::var(var_name) {
                self.api_token = value;
            }
        } else if self.api_token.starts_with('$') {
            let var_name = &self.api_token[1..];
            if let Ok(value) = std::env::var(var_name) {
                self.api_token = value;
            }
        }
    }
}

/// DNS update configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// TTL for DNS A records (seconds)
    pub ttl_seconds: u32,
    /// Maximum nodes per region to include in DNS
    pub max_nodes_per_region: usize,
    /// DNS update interval (seconds)
    pub update_interval_secs: u64,
    /// Regional subdomain prefix (e.g., "pool" for "eu.pool.bitcoinghost.org")
    pub subdomain_prefix: String,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            ttl_seconds: 60,
            max_nodes_per_region: 3,
            update_interval_secs: 60,
            subdomain_prefix: "pool".to_string(),
        }
    }
}

/// Health monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    /// Heartbeat timeout in seconds (node considered offline after this)
    pub heartbeat_timeout_secs: u64,
    /// Number of missed heartbeats before removal
    pub missed_heartbeats_threshold: u32,
    /// Health check interval (seconds)
    pub check_interval_secs: u64,
    /// Maximum load percentage before removing node from DNS
    pub max_load_percent: u8,
    /// Load percentage threshold to resume DNS inclusion (hysteresis)
    pub resume_load_percent: u8,
    /// Rate limit: minimum seconds between registrations from same node
    pub registration_rate_limit_secs: u64,
    /// Maximum timestamp drift allowed (seconds)
    pub max_timestamp_drift_secs: u64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            heartbeat_timeout_secs: 90,
            missed_heartbeats_threshold: 3,
            check_interval_secs: 30,
            max_load_percent: 80,
            resume_load_percent: 70,
            registration_rate_limit_secs: 300, // 5 minutes
            max_timestamp_drift_secs: 60,
        }
    }
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database file path
    pub path: PathBuf,
    /// Enable WAL mode for SQLite
    pub wal_mode: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/var/lib/ghost-registry/registry.db"),
            wal_mode: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RegistryServiceConfig::default();
        assert_eq!(config.server.listen, "0.0.0.0:8333");
        assert_eq!(config.dns.ttl_seconds, 60);
        assert_eq!(config.health.heartbeat_timeout_secs, 90);
    }

    #[test]
    fn test_cloudflare_env_resolution() {
        std::env::set_var("TEST_CF_TOKEN", "test_token_value");

        let mut config = CloudflareConfig {
            api_token: "${TEST_CF_TOKEN}".to_string(),
            ..Default::default()
        };

        config.resolve_env();
        assert_eq!(config.api_token, "test_token_value");

        std::env::remove_var("TEST_CF_TOKEN");
    }
}
