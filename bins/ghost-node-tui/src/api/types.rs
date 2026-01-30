//! API response types for Ghost Node TUI

use serde::{Deserialize, Serialize};

/// Node status from /api/v1/node/status
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NodeStatus {
    pub online: bool,
    pub node_id: String,
    pub version: String,
    #[serde(default = "default_network")]
    pub network: String,
    pub sync_height: u64,
    pub block_height: u64,
    pub round_id: u64,
    pub uptime_seconds: u64,
    pub peer_count: u32,
    pub miner_count: u32,
    pub is_synced: bool,
    #[serde(default)]
    pub mempool_profile: Option<String>,
    #[serde(default)]
    pub capabilities: Option<CapabilityStatus>,
}

fn default_network() -> String {
    "mainnet".to_string()
}

/// Node capabilities
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct CapabilityStatus {
    pub archive_mode: bool,
    pub ghost_pay: bool,
    pub public_mining: bool,
    pub bitcoin_pure: bool,
    pub elder_status: bool,
    #[serde(default)]
    pub elder_number: Option<u32>,
    #[serde(default)]
    pub gsp_enabled: bool,
    pub total_shares: i32,
}

/// Resource status from /api/v1/resources/status
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResourceStatus {
    pub cpu_percent: f64,
    pub memory_percent: f64,
    #[serde(default)]
    pub memory_mb: Option<u64>,
    pub disk_percent: f64,
    #[serde(default)]
    pub disk_usage_percent: Option<f64>,
    pub uptime_seconds: u64,
    pub status: String,
}

/// Rewards data from /api/v1/rewards/current
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RewardsData {
    pub round_id: u64,
    pub block_height: u64,
    pub pending_rewards_sats: u64,
    pub total_earned_sats: u64,
    pub last_credited_round: u64,
    #[serde(default)]
    pub estimated_share: Option<f64>,
    pub node_shares: i32,
    pub total_network_shares: i32,
    #[serde(default)]
    pub message: Option<String>,
}

/// Peer info from /api/v1/network/peers
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub address: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub node_id: Option<String>,
    pub last_seen: i64,
    #[serde(default)]
    pub latency_ms: Option<f64>,
    #[serde(default)]
    pub is_connected: Option<bool>,
}

/// Mining status from /api/v1/mining/status
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MiningStatus {
    pub active: bool,
    pub sync_height: u64,
    pub block_height: u64,
    pub round_id: u64,
    pub miner_count: u32,
    #[serde(default)]
    pub total_hashrate: Option<f64>,
    pub shares_this_round: u64,
    pub difficulty: f64,
    #[serde(default)]
    pub best_hash: Option<String>,
    pub public_mining: bool,
    pub is_synced: bool,
}

/// Miner info from /api/v1/mining/miners
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MinerInfo {
    pub miner_id: String,
    pub work: f64,
    pub shares_this_round: u64,
    pub active: bool,
    #[serde(default)]
    pub last_seen: Option<i64>,
    #[serde(default)]
    pub avg_hashrate_ths: Option<f64>,
}

/// Ghost Pay status from /api/v1/ghostpay/status
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GhostPayStatus {
    pub enabled: bool,
    #[serde(default)]
    pub virtual_block: Option<u64>,
    #[serde(default)]
    pub l2_height: Option<u64>,
    pub block_height: u64,
    #[serde(default)]
    pub epoch: Option<u64>,
    pub peer_count: u32,
    #[serde(default)]
    pub wraith_enabled: Option<bool>,
    #[serde(default)]
    pub total_balances: Option<u64>,
}

/// Wraith session from /api/v1/wraith/sessions
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WraithSession {
    pub round_id: String,
    pub denomination: String,
    pub amount_sats: u64,
    pub participant_count: u32,
    pub phase: String,
    pub registration_deadline: i64,
}

/// Locks summary from /api/v1/locks
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LocksSummary {
    pub enabled: bool,
    pub active_locks: u32,
    pub total_locked_sats: u64,
    #[serde(default)]
    pub locks: Vec<LockInfo>,
}

/// Individual lock info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LockInfo {
    pub lock_id: String,
    pub denomination: String,
    pub amount_sats: u64,
    pub state: String,
    #[serde(default)]
    pub next_jump_height: Option<u32>,
}

/// Watchdog status from /api/v1/watchdog/status
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WatchdogStatus {
    pub healthy: bool,
    pub uptime_secs: u64,
    #[serde(default)]
    pub services: Option<ServicesStatus>,
    // UI-friendly fields
    #[serde(default = "healthy_status")]
    pub bitcoin_core: String,
    #[serde(default = "healthy_status")]
    pub ghost_pay: String,
    #[serde(default = "healthy_status")]
    pub mining_pool: String,
    #[serde(default = "healthy_status")]
    pub api_server: String,
    #[serde(default)]
    pub last_check: i64,
    #[serde(default)]
    pub recent_events: Vec<WatchdogEvent>,
}

fn healthy_status() -> String {
    "healthy".to_string()
}

/// Watchdog event
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WatchdogEvent {
    pub timestamp: i64,
    pub service: String,
    pub event_type: String,
    pub message: String,
}

/// Status of individual services
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServicesStatus {
    #[serde(default)]
    pub ghost_pool: Option<ServiceInfo>,
    #[serde(default)]
    pub ghost_core: Option<CoreServiceInfo>,
    #[serde(default)]
    pub gsp: Option<GspServiceInfo>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServiceInfo {
    pub status: String,
    #[serde(default)]
    pub uptime_secs: Option<u64>,
    #[serde(default)]
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CoreServiceInfo {
    pub status: String,
    #[serde(default)]
    pub chain: Option<String>,
    #[serde(default)]
    pub blocks: Option<u64>,
    #[serde(default)]
    pub headers: Option<u64>,
    #[serde(default)]
    pub synced: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GspServiceInfo {
    pub status: String,
    #[serde(default)]
    pub connections: Option<u32>,
    #[serde(default)]
    pub registered_wallets: Option<u32>,
}

/// Backup entry from /api/v1/backup/history
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackupEntry {
    #[serde(alias = "filename")]
    pub backup_id: String,
    #[serde(default)]
    pub backup_type: String,
    #[serde(alias = "created_at")]
    pub timestamp: i64,
    #[serde(default)]
    pub size_bytes: Option<u64>,
    #[serde(default = "default_status")]
    pub status: String,
    #[serde(default)]
    pub path: Option<String>,
}

fn default_status() -> String {
    "completed".to_string()
}

/// Log entry from /api/v1/logs
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogEntry {
    #[serde(default)]
    pub timestamp: String,
    pub level: String,
    pub message: String,
    #[serde(default = "unknown_component")]
    pub component: String,
}

fn unknown_component() -> String {
    "system".to_string()
}

/// Log level filter
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }

    pub fn all() -> &'static [LogLevel] {
        &[
            LogLevel::Error,
            LogLevel::Warn,
            LogLevel::Info,
            LogLevel::Debug,
            LogLevel::Trace,
        ]
    }
}

/// Swarm node info from /api/v1/swarm/nodes
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SwarmNodeInfo {
    pub node_id: String,
    pub address: String,
    pub last_seen: i64,
    #[serde(default)]
    pub is_self: bool,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub capabilities: Option<CapabilityStatus>,
}

/// API response wrapper
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiResponse<T> {
    #[serde(default)]
    pub success: Option<bool>,
    #[serde(flatten)]
    pub data: T,
}

/// Error response from API
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiError {
    pub error: ErrorDetail,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}
