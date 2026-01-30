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
//| FILE: registry.rs                                                                                                    |
//|======================================================================================================================|

//! Registry client for load balancer registration
//!
//! This module handles registration of pool nodes with the ghost-web-backend
//! load balancer, enabling miners to connect via pool.bitcoinghost.org.
//!
//! Uses secp256k1 signing (same as Bitcoin) for authentication.

use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use ghost_common::config::{Region, RegistryConfig};
use ghost_common::types::CapacityState;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

/// Node registration message sent to the load balancer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRegistration {
    /// Unique node identifier (public key hex)
    pub node_id: String,
    /// Public host/IP for miners
    pub host: String,
    /// Stratum V1 port
    pub sv1_port: u16,
    /// Stratum V2 port
    pub sv2_port: u16,
    /// Geographic region
    pub region: Region,
    /// Latitude (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    /// Longitude (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    /// Maximum miners this node can handle
    pub max_miners: u32,
    /// Signature proving node_id ownership (hex)
    pub signature: String,
    /// Timestamp (unix seconds)
    pub timestamp: u64,
}

/// Node heartbeat message sent periodically
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHeartbeat {
    /// Node identifier (public key hex)
    pub node_id: String,
    /// Current miner count
    pub miner_count: u32,
    /// Maximum miners
    pub max_miners: u32,
    /// Current load percentage (0-100)
    pub load_percent: u8,
    /// CPU usage percentage
    pub cpu_percent: u8,
    /// Memory usage percentage
    pub memory_percent: u8,
    /// Average share processing latency (ms)
    pub share_latency_ms: u16,
    /// Bandwidth usage percentage
    pub bandwidth_percent: u8,
    /// Current capacity state
    pub capacity_state: CapacityState,
    /// Whether accepting new miners
    pub accepting_miners: bool,
    /// Signature (hex)
    pub signature: String,
    /// Timestamp
    pub timestamp: u64,
}

/// Response from registration endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResponse {
    /// Status ("ok" on success)
    #[serde(default)]
    pub status: String,
    /// Error message (if any)
    #[serde(default)]
    pub error: Option<String>,
}

impl RegistrationResponse {
    pub fn is_success(&self) -> bool {
        self.status == "ok" && self.error.is_none()
    }
}

/// Registry client for load balancer communication
pub struct RegistryClient {
    /// HTTP client
    client: Client,
    /// Registry URL
    registry_url: String,
    /// secp256k1 context
    secp: Secp256k1<bitcoin::secp256k1::All>,
    /// Secret key for signing
    secret_key: SecretKey,
    /// Public key hex (node_id)
    public_key_hex: String,
    /// Configuration
    config: RegistryConfig,
    /// Host address to register
    host: String,
    /// SV1 port
    sv1_port: u16,
    /// SV2 port
    sv2_port: u16,
    /// Max miners
    max_miners: u32,
}

impl RegistryClient {
    /// Create a new registry client with secp256k1 signing key
    pub fn new(
        signing_key_hex: &str,
        config: RegistryConfig,
        host: String,
        sv1_port: u16,
        sv2_port: u16,
        max_miners: u32,
    ) -> Result<Self, String> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        let secp = Secp256k1::new();

        let secret_bytes =
            hex::decode(signing_key_hex).map_err(|e| format!("Invalid signing key hex: {}", e))?;

        let secret_key = SecretKey::from_slice(&secret_bytes)
            .map_err(|e| format!("Invalid signing key: {}", e))?;

        let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let public_key_hex = hex::encode(public_key.serialize());

        Ok(Self {
            client,
            registry_url: config.url.clone(),
            secp,
            secret_key,
            public_key_hex,
            config,
            host,
            sv1_port,
            sv2_port,
            max_miners,
        })
    }

    /// Get current timestamp
    fn now_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Hash a message using SHA256
    fn hash_message(message: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        hasher.finalize().into()
    }

    /// Sign a message and return hex-encoded signature
    fn sign(&self, message: &str) -> String {
        let hash = Self::hash_message(message);
        let msg = Message::from_digest(hash);
        let sig = self.secp.sign_ecdsa(&msg, &self.secret_key);
        hex::encode(sig.serialize_compact())
    }

    /// Create signable message for registration
    fn registration_message(
        node_id: &str,
        host: &str,
        sv1_port: u16,
        sv2_port: u16,
        timestamp: u64,
    ) -> String {
        format!(
            "ghost:register:{}:{}:{}:{}:{}",
            node_id, host, sv1_port, sv2_port, timestamp
        )
    }

    /// Create signable message for heartbeat
    fn heartbeat_message(
        node_id: &str,
        miner_count: u32,
        load_percent: u8,
        timestamp: u64,
    ) -> String {
        format!(
            "ghost:heartbeat:{}:{}:{}:{}",
            node_id, miner_count, load_percent, timestamp
        )
    }

    /// Register with the load balancer
    pub async fn register(&self) -> Result<RegistrationResponse, String> {
        let timestamp = Self::now_timestamp();
        let node_id = &self.public_key_hex;

        // Create message to sign
        let msg = Self::registration_message(
            node_id,
            &self.host,
            self.sv1_port,
            self.sv2_port,
            timestamp,
        );

        // Sign the message
        let signature_hex = self.sign(&msg);

        let registration = NodeRegistration {
            node_id: node_id.clone(),
            host: self.host.clone(),
            sv1_port: self.sv1_port,
            sv2_port: self.sv2_port,
            region: self.config.region,
            latitude: None,
            longitude: None,
            max_miners: self.max_miners,
            signature: signature_hex,
            timestamp,
        };

        let url = format!("{}/api/v1/nodes/register", self.registry_url);

        debug!(url = %url, "Sending registration to load balancer");

        let response = self
            .client
            .post(&url)
            .json(&registration)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!(
                "Registration failed with status {}: {}",
                status, body
            ));
        }

        response
            .json::<RegistrationResponse>()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    }

    /// Send heartbeat to the load balancer
    pub async fn heartbeat(
        &self,
        miner_count: u32,
        load_percent: u8,
        cpu_percent: u8,
        memory_percent: u8,
    ) -> Result<(), String> {
        let timestamp = Self::now_timestamp();
        let node_id = &self.public_key_hex;

        // Create message to sign
        let msg = Self::heartbeat_message(node_id, miner_count, load_percent, timestamp);

        // Sign the message
        let signature_hex = self.sign(&msg);

        let capacity_state = CapacityState::from_load(miner_count, self.max_miners);
        let accepting_miners = load_percent < 90 && miner_count < self.max_miners;

        let heartbeat = NodeHeartbeat {
            node_id: node_id.clone(),
            miner_count,
            max_miners: self.max_miners,
            load_percent,
            cpu_percent,
            memory_percent,
            share_latency_ms: 0,
            bandwidth_percent: 0,
            capacity_state,
            accepting_miners,
            signature: signature_hex,
            timestamp,
        };

        let url = format!("{}/api/v1/nodes/heartbeat", self.registry_url);

        let response = self
            .client
            .post(&url)
            .json(&heartbeat)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("Heartbeat failed with status {}: {}", status, body));
        }

        Ok(())
    }

    /// Start the registry client (register and heartbeat loop)
    pub async fn start(
        self,
        miner_count_fn: impl Fn() -> u32 + Send + Sync + 'static,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        info!(
            registry = %self.registry_url,
            host = %self.host,
            node_id = %self.public_key_hex,
            "Starting registry client"
        );

        // Initial registration
        match self.register().await {
            Ok(resp) => {
                if resp.is_success() {
                    info!("Registered with load balancer successfully");
                } else if let Some(err) = resp.error {
                    warn!("Registration rejected: {}", err);
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to register with load balancer");
            }
        }

        // Heartbeat loop
        let interval = Duration::from_secs(self.config.heartbeat_interval_secs);
        let mut heartbeat_interval = tokio::time::interval(interval);

        loop {
            tokio::select! {
                _ = heartbeat_interval.tick() => {
                    let miner_count = miner_count_fn();
                    let (cpu, mem) = get_system_stats();
                    let load = calculate_load(miner_count, self.max_miners, cpu);

                    match self.heartbeat(miner_count, load, cpu, mem).await {
                        Ok(()) => {
                            debug!(
                                miners = miner_count,
                                load = load,
                                cpu = cpu,
                                mem = mem,
                                "Heartbeat sent"
                            );
                        }
                        Err(e) => {
                            warn!(error = %e, "Heartbeat failed");
                            // Try to re-register on heartbeat failure
                            if let Err(re) = self.register().await {
                                error!(error = %re, "Re-registration failed");
                            }
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Registry client shutting down");
                    break;
                }
            }
        }
    }
}

/// Get CPU and memory usage percentages
fn get_system_stats() -> (u8, u8) {
    // Read CPU load from /proc/loadavg
    let cpu_percent = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|content| {
            let load1: f64 = content.split_whitespace().next()?.parse().ok()?;
            let num_cpus = std::fs::read_to_string("/proc/cpuinfo")
                .ok()
                .map(|c| c.matches("processor").count())
                .unwrap_or(1)
                .max(1) as f64;
            Some((load1 / num_cpus * 100.0).min(100.0) as u8)
        })
        .unwrap_or(0);

    // Read memory from /proc/meminfo
    let mem_percent = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|content| {
            let mut total: u64 = 0;
            let mut available: u64 = 0;
            for line in content.lines() {
                if line.starts_with("MemTotal:") {
                    total = line.split_whitespace().nth(1)?.parse().ok()?;
                } else if line.starts_with("MemAvailable:") {
                    available = line.split_whitespace().nth(1)?.parse().ok()?;
                }
            }
            if total > 0 {
                let used_percent = ((total - available) as f64 / total as f64 * 100.0) as u8;
                Some(used_percent)
            } else {
                None
            }
        })
        .unwrap_or(0);

    (cpu_percent, mem_percent)
}

/// Calculate overall load percentage
fn calculate_load(miner_count: u32, max_miners: u32, cpu_percent: u8) -> u8 {
    let miner_load = if max_miners > 0 {
        (miner_count as f64 / max_miners as f64 * 100.0) as u8
    } else {
        0
    };

    ((miner_load as u16 * 60 + cpu_percent as u16 * 40) / 100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration_message() {
        let msg =
            RegistryClient::registration_message("abc123", "1.2.3.4", 3333, 34255, 1234567890);
        assert_eq!(msg, "ghost:register:abc123:1.2.3.4:3333:34255:1234567890");
    }

    #[test]
    fn test_heartbeat_message() {
        let msg = RegistryClient::heartbeat_message("abc123", 500, 50, 1234567890);
        assert_eq!(msg, "ghost:heartbeat:abc123:500:50:1234567890");
    }

    #[test]
    fn test_calculate_load() {
        assert_eq!(calculate_load(500, 1000, 50), 50);
        assert_eq!(calculate_load(1000, 1000, 0), 60);
        assert_eq!(calculate_load(0, 1000, 100), 40);
    }
}
