//! HTTP API client for Ghost Node

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use reqwest::Client;
use sha2::Sha256;
use std::time::Duration;

use super::types::*;

type HmacSha256 = Hmac<Sha256>;

/// API client for a single Ghost Node
#[derive(Clone)]
pub struct NodeApiClient {
    client: Client,
    base_url: String,
    auth_token: Option<String>,
    hmac_secret: Option<String>,
}

impl NodeApiClient {
    /// Create a new API client
    pub fn new(base_url: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            auth_token: None,
            hmac_secret: None,
        }
    }

    /// Create with authentication token
    pub fn with_auth(base_url: &str, token: &str) -> Self {
        let mut client = Self::new(base_url);
        client.auth_token = Some(token.to_string());
        client
    }

    /// Set authentication token
    #[allow(dead_code)]
    pub fn set_auth_token(&mut self, token: Option<String>) {
        self.auth_token = token;
    }

    /// Set HMAC secret for authenticated POST requests
    pub fn set_hmac_secret(&mut self, secret: Option<String>) {
        self.hmac_secret = secret;
    }

    /// Get the base URL
    #[allow(dead_code)]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    // === Health Check ===

    /// Check if node is reachable
    #[allow(dead_code)]
    pub async fn health_check(&self) -> Result<bool> {
        let url = format!("{}/health", self.base_url);
        let resp = self.client.get(&url).send().await?;
        Ok(resp.status().is_success())
    }

    // === Node Status ===

    /// Get node status
    pub async fn get_node_status(&self) -> Result<NodeStatus> {
        self.get("/api/v1/node/status").await
    }

    /// Get node nickname
    #[allow(dead_code)]
    pub async fn get_node_nickname(&self) -> Result<String> {
        #[derive(serde::Deserialize)]
        struct NicknameResponse {
            nickname: String,
        }
        let resp: NicknameResponse = self.get("/api/v1/node/nickname").await?;
        Ok(resp.nickname)
    }

    // === Resources ===

    /// Get resource status (CPU, memory, disk)
    pub async fn get_resources(&self) -> Result<ResourceStatus> {
        self.get("/api/v1/resources/status").await
    }

    // === Rewards ===

    /// Get current rewards
    pub async fn get_rewards(&self) -> Result<RewardsData> {
        self.get("/api/v1/rewards/current").await
    }

    // === Network ===

    /// Get peer list
    pub async fn get_peers(&self) -> Result<Vec<PeerInfo>> {
        #[derive(serde::Deserialize)]
        struct PeersResponse {
            #[serde(default)]
            peers: Vec<PeerInfo>,
        }
        let resp: PeersResponse = self.get("/api/v1/network/peers").await?;
        Ok(resp.peers)
    }

    // === Mining ===

    /// Get mining status
    pub async fn get_mining_status(&self) -> Result<MiningStatus> {
        self.get("/api/v1/mining/status").await
    }

    /// Get miner list
    /// Note: Public endpoint returns redacted aggregate data (no individual miners).
    /// Returns empty vec if miners are redacted.
    pub async fn get_miners(&self) -> Result<Vec<MinerInfo>> {
        #[derive(serde::Deserialize)]
        struct MinersResponse {
            #[serde(default)]
            miners: Vec<MinerInfo>,
            #[serde(default)]
            miners_redacted: bool,
        }
        match self.get::<MinersResponse>("/api/v1/mining/miners").await {
            Ok(resp) => {
                if resp.miners_redacted || resp.miners.is_empty() {
                    Ok(vec![])
                } else {
                    Ok(resp.miners)
                }
            }
            Err(_) => Ok(vec![]),
        }
    }

    // === Ghost Pay ===

    /// Get Ghost Pay L2 status
    pub async fn get_ghostpay_status(&self) -> Result<GhostPayStatus> {
        self.get("/api/v1/ghostpay/status").await
    }

    /// Get Wraith mixing sessions
    pub async fn get_wraith_sessions(&self) -> Result<Vec<WraithSession>> {
        #[derive(serde::Deserialize)]
        struct WraithResponse {
            #[serde(default)]
            sessions: Vec<WraithSession>,
        }
        let resp: WraithResponse = self.get("/api/v1/wraith/sessions").await?;
        Ok(resp.sessions)
    }

    /// Get locks summary
    pub async fn get_locks(&self) -> Result<LocksSummary> {
        self.get("/api/v1/locks").await
    }

    // === Watchdog ===

    /// Get watchdog status
    pub async fn get_watchdog_status(&self) -> Result<WatchdogStatus> {
        self.get("/api/v1/watchdog/status").await
    }

    // === Backup ===

    /// Get backup history
    pub async fn get_backup_history(&self) -> Result<Vec<BackupEntry>> {
        #[derive(serde::Deserialize)]
        struct BackupResponse {
            #[serde(default)]
            backups: Vec<BackupEntry>,
        }
        let resp: BackupResponse = self.get("/api/v1/backup/history").await?;
        Ok(resp.backups)
    }

    // === Logs ===

    /// Get logs with optional filter
    /// Note: This endpoint may be removed for security reasons.
    /// Returns empty vec on 404 or error.
    pub async fn get_logs(&self, level: LogLevel, limit: usize) -> Result<Vec<LogEntry>> {
        #[derive(serde::Deserialize)]
        struct LogsResponse {
            #[serde(default)]
            entries: Vec<LogEntry>,
        }
        let url = format!(
            "{}/api/v1/logs?level={}&limit={}",
            self.base_url,
            level.as_str(),
            limit
        );

        let mut req = self.client.get(&url);
        if let Some(token) = &self.auth_token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        let resp = match req.send().await {
            Ok(r) => r,
            Err(_) => return Ok(vec![]),
        };

        // Handle 404 (endpoint removed for security) or other errors gracefully
        if !resp.status().is_success() {
            return Ok(vec![]);
        }

        match resp.json::<LogsResponse>().await {
            Ok(logs_resp) => Ok(logs_resp.entries),
            Err(_) => Ok(vec![]),
        }
    }

    // === Swarm ===

    /// Get swarm nodes
    #[allow(dead_code)]
    pub async fn get_swarm_nodes(&self) -> Result<Vec<SwarmNodeInfo>> {
        #[derive(serde::Deserialize)]
        struct SwarmResponse {
            #[serde(default)]
            nodes: Vec<SwarmNodeInfo>,
        }
        let resp: SwarmResponse = self.get("/api/v1/swarm/nodes").await?;
        Ok(resp.nodes)
    }

    // === Authenticated Actions (HMAC-signed POST) ===

    /// Restart a service via watchdog
    pub async fn restart_service(&self, name: &str) -> Result<String> {
        self.post_authenticated(&format!("/api/v1/watchdog/restart/{}", name), b"")
            .await
    }

    /// Stop a service via watchdog
    pub async fn stop_service(&self, name: &str) -> Result<String> {
        self.post_authenticated(&format!("/api/v1/watchdog/stop/{}", name), b"")
            .await
    }

    /// Start a service via watchdog
    #[allow(dead_code)]
    pub async fn start_service(&self, name: &str) -> Result<String> {
        self.post_authenticated(&format!("/api/v1/watchdog/start/{}", name), b"")
            .await
    }

    /// Set node nickname
    pub async fn set_nickname(&self, name: &str) -> Result<String> {
        let body = serde_json::json!({ "nickname": name }).to_string();
        self.post_authenticated("/api/v1/node/nickname", body.as_bytes())
            .await
    }

    /// Set payout address
    pub async fn set_payout_address(&self, addr: &str) -> Result<String> {
        let body = serde_json::json!({ "address": addr }).to_string();
        self.post_authenticated("/api/v1/mining/payout_address", body.as_bytes())
            .await
    }

    /// Trigger a backup export
    pub async fn trigger_backup(&self) -> Result<String> {
        self.post_authenticated("/api/v1/backup/export", b"")
            .await
    }

    /// Delete a backup by filename
    pub async fn delete_backup(&self, filename: &str) -> Result<String> {
        let url = format!("{}/api/v1/backup/delete/{}", self.base_url, filename);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut req = self.client.delete(&url);
        if let Some(token) = &self.auth_token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        if let Some(secret) = &self.hmac_secret {
            let signature = Self::sign_request(secret, timestamp, b"");
            req = req
                .header("X-Ghost-Signature", signature)
                .header("X-Ghost-Timestamp", timestamp.to_string());
        }

        let resp = req.send().await.context("Failed to send request")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("API error {}: {}", status, body);
        }
        resp.text().await.context("Failed to read response")
    }

    // === Generic Helpers ===

    /// Generic GET request
    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);

        let mut req = self.client.get(&url);
        if let Some(token) = &self.auth_token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        let resp = req.send().await.context("Failed to send request")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("API error {}: {}", status, body);
        }

        resp.json().await.context("Failed to parse response")
    }

    /// Authenticated POST with HMAC-SHA256 signature
    /// Uses same pattern as ghost-verification auth: HMAC-SHA256(secret, timestamp_le || body)
    async fn post_authenticated(&self, path: &str, body: &[u8]) -> Result<String> {
        let url = format!("{}{}", self.base_url, path);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut req = self.client.post(&url);
        if let Some(token) = &self.auth_token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        if let Some(secret) = &self.hmac_secret {
            let signature = Self::sign_request(secret, timestamp, body);
            req = req
                .header("X-Ghost-Signature", signature)
                .header("X-Ghost-Timestamp", timestamp.to_string());
        }
        if !body.is_empty() {
            req = req
                .header("Content-Type", "application/json")
                .body(body.to_vec());
        }

        let resp = req.send().await.context("Failed to send request")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("API error {}: {}", status, body);
        }
        resp.text().await.context("Failed to read response")
    }

    /// Generate HMAC-SHA256 signature: HMAC(secret, timestamp_le_bytes || body)
    fn sign_request(secret: &str, timestamp: u64, body: &[u8]) -> String {
        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can accept any key size");
        mac.update(&timestamp.to_le_bytes());
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }
}
