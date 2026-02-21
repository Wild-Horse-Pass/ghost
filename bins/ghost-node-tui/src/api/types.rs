//! API response types for Ghost Node TUI

use serde::{Deserialize, Serialize};

/// Node status from /api/v1/node/status
/// Backend returns flat capability flags (not nested)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NodeStatus {
    #[serde(default)]
    pub online: bool,
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub version: String,
    #[serde(default = "default_network")]
    pub network: String,
    #[serde(default)]
    pub sync_height: u64,
    #[serde(default)]
    pub block_height: u64,
    #[serde(default)]
    pub round_id: u64,
    #[serde(default, alias = "uptime_secs")]
    pub uptime_seconds: u64,
    #[serde(default)]
    pub peer_count: u32,
    #[serde(default)]
    pub miner_count: u32,
    #[serde(default)]
    pub is_synced: bool,
    #[serde(default)]
    pub mempool_profile: Option<String>,
    #[serde(default)]
    pub template_profile: Option<String>,

    // Flat capability flags from backend
    #[serde(default)]
    pub archive_mode: bool,
    #[serde(default)]
    pub ghost_pay: bool,
    #[serde(default)]
    pub public_mining: bool,
    #[serde(default)]
    pub private_mining: bool,
    #[serde(default)]
    pub reaper: bool,
    #[serde(default)]
    pub ghost_mode: bool,

    // Legacy nested capabilities (may not be present from current backend)
    #[serde(default)]
    pub capabilities: Option<CapabilityStatus>,
}

fn default_network() -> String {
    "signet".to_string()
}

impl NodeStatus {
    /// Get capabilities from nested struct (if present) or from flat fields
    pub fn get_capabilities(&self) -> CapabilityStatus {
        if let Some(caps) = &self.capabilities {
            caps.clone()
        } else {
            CapabilityStatus {
                archive_mode: self.archive_mode,
                ghost_pay: self.ghost_pay,
                public_mining: self.public_mining,
                reaper: self.reaper,
                elder_status: false,
                elder_number: None,
                gsp_enabled: false,
                total_shares: 0,
            }
        }
    }
}

/// Node capabilities
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct CapabilityStatus {
    #[serde(default)]
    pub archive_mode: bool,
    #[serde(default)]
    pub ghost_pay: bool,
    #[serde(default)]
    pub public_mining: bool,
    #[serde(default)]
    pub reaper: bool,
    #[serde(default)]
    pub elder_status: bool,
    #[serde(default)]
    pub elder_number: Option<u32>,
    #[serde(default)]
    pub gsp_enabled: bool,
    #[serde(default)]
    pub total_shares: i32,
}

/// Resource status from /api/v1/resources/status
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResourceStatus {
    #[serde(default)]
    pub cpu_percent: f64,
    #[serde(default)]
    pub memory_percent: f64,
    #[serde(default)]
    pub memory_mb: Option<u64>,
    #[serde(default)]
    pub memory_used_mb: Option<u64>,
    #[serde(default)]
    pub memory_total_mb: Option<u64>,
    #[serde(default)]
    pub disk_percent: f64,
    #[serde(default)]
    pub disk_usage_percent: Option<f64>,
    #[serde(default)]
    pub disk_used_gb: Option<f64>,
    #[serde(default)]
    pub disk_total_gb: Option<f64>,
    #[serde(default, alias = "uptime_secs")]
    pub uptime_seconds: u64,
    #[serde(default)]
    pub status: String,
}

/// Rewards data from /api/v1/rewards/current
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RewardsData {
    #[serde(default)]
    pub round_id: u64,
    #[serde(default)]
    pub block_height: u64,
    #[serde(default)]
    pub pending_rewards_sats: u64,
    #[serde(default)]
    pub total_earned_sats: u64,
    #[serde(default)]
    pub last_credited_round: u64,
    #[serde(default)]
    pub estimated_share: Option<f64>,
    #[serde(default)]
    pub node_shares: i32,
    #[serde(default)]
    pub total_network_shares: i32,
    #[serde(default)]
    pub message: Option<String>,
}

/// Peer info from /api/v1/network/peers
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PeerInfo {
    #[serde(default)]
    pub peer_id: String,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub last_seen: i64,
    #[serde(default)]
    pub latency_ms: Option<f64>,
    #[serde(default)]
    pub is_connected: Option<bool>,
    #[serde(default)]
    pub synced: Option<bool>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub connected_at: Option<i64>,
    #[serde(default)]
    pub is_self: Option<bool>,
}

/// Mining status from /api/v1/mining/status
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MiningStatus {
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub sync_height: u64,
    #[serde(default)]
    pub block_height: u64,
    #[serde(default)]
    pub round_id: u64,
    #[serde(default, alias = "connected_miners")]
    pub miner_count: u32,
    #[serde(default, alias = "hashrate_th")]
    pub total_hashrate: Option<f64>,
    #[serde(default)]
    pub shares_this_round: u64,
    #[serde(default)]
    pub difficulty: f64,
    #[serde(default)]
    pub best_hash: Option<String>,
    #[serde(default)]
    pub public_mining: bool,
    #[serde(default)]
    pub private_mining: bool,
    #[serde(default)]
    pub is_synced: bool,
    #[serde(default)]
    pub shares_submitted: Option<u64>,
    #[serde(default)]
    pub shares_accepted: Option<u64>,
    #[serde(default)]
    pub shares_rejected: Option<u64>,
    #[serde(default)]
    pub stratum_v1_port: Option<u16>,
    #[serde(default)]
    pub stratum_v1_endpoint: Option<String>,
    #[serde(default)]
    pub blocks_found: Option<u64>,
    #[serde(default)]
    pub payout_address: Option<String>,
    #[serde(default)]
    pub stratum_v2_port: Option<u16>,
    #[serde(default)]
    pub stratum_v2_endpoint: Option<String>,
}

/// Miner info from /api/v1/mining/miners
/// Note: Public endpoint returns redacted/aggregate data only
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MinerInfo {
    #[serde(default)]
    pub miner_id: String,
    #[serde(default)]
    pub work: f64,
    #[serde(default)]
    pub shares_this_round: u64,
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub last_seen: Option<i64>,
    #[serde(default)]
    pub avg_hashrate_ths: Option<f64>,
}

/// Ghost Pay status from /api/v1/ghostpay/status
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GhostPayStatus {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub virtual_block: Option<u64>,
    #[serde(default)]
    pub l2_height: Option<u64>,
    #[serde(default)]
    pub block_height: u64,
    #[serde(default)]
    pub epoch: Option<u64>,
    #[serde(default)]
    pub peer_count: u32,
    #[serde(default)]
    pub wraith_enabled: Option<bool>,
    #[serde(default)]
    pub total_balances: Option<u64>,
    #[serde(default)]
    pub protocol_version: Option<u32>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub l2_era: Option<u64>,
    #[serde(default)]
    pub sync_state: Option<String>,
    #[serde(default)]
    pub uptime_secs: Option<u64>,
}

/// Wraith session from /api/v1/wraith/sessions
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WraithSession {
    #[serde(default, alias = "session_id")]
    pub round_id: String,
    #[serde(default)]
    pub denomination: String,
    #[serde(default)]
    pub amount_sats: u64,
    #[serde(default)]
    pub participant_count: u32,
    #[serde(default)]
    pub phase: String,
    #[serde(default, alias = "status")]
    pub _status: Option<String>,
    #[serde(default)]
    pub registration_deadline: i64,
    #[serde(default)]
    pub fill_percentage: Option<f64>,
}

/// Locks summary from /api/v1/locks
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LocksSummary {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub active_locks: u32,
    #[serde(default)]
    pub total_locked_sats: u64,
    #[serde(default)]
    pub locks: Vec<LockInfo>,
}

/// Individual lock info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LockInfo {
    #[serde(default)]
    pub lock_id: String,
    #[serde(default)]
    pub denomination: String,
    #[serde(default, alias = "balance")]
    pub amount_sats: u64,
    #[serde(default, alias = "status")]
    pub state: String,
    #[serde(default)]
    pub timelock_tier: Option<String>,
    #[serde(default)]
    pub next_jump_height: Option<u32>,
    #[serde(default)]
    pub creation_height: Option<u64>,
    #[serde(default)]
    pub recovery_height: Option<u64>,
    #[serde(default)]
    pub created_at: Option<i64>,
}

/// Watchdog status from /api/v1/watchdog/status
/// Backend returns dynamic services/components arrays
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WatchdogStatus {
    #[serde(default)]
    pub healthy: bool,
    #[serde(default)]
    pub uptime_secs: u64,
    #[serde(default)]
    pub overall_health: Option<String>,
    #[serde(default)]
    pub last_check: i64,
    // Dynamic service list from backend
    #[serde(default)]
    pub services: Vec<WatchdogService>,
    #[serde(default)]
    pub components: Vec<WatchdogComponent>,
    #[serde(default)]
    pub recent_events: Vec<WatchdogEvent>,
}

impl WatchdogStatus {
    /// Get status for a service by name, searching both services and components
    pub fn service_status(&self, name: &str) -> &str {
        // Check services array first
        for svc in &self.services {
            if svc.name.eq_ignore_ascii_case(name) {
                return &svc.status;
            }
        }
        // Check components array
        for comp in &self.components {
            if comp.name.eq_ignore_ascii_case(name) {
                return &comp.status;
            }
        }
        "unknown"
    }
}

/// Service entry from watchdog
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WatchdogService {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub details: Option<serde_json::Value>,
}

/// Component entry from watchdog
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WatchdogComponent {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub last_check: Option<i64>,
}

/// Watchdog event
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WatchdogEvent {
    #[serde(default)]
    pub timestamp: i64,
    #[serde(default)]
    pub service: String,
    #[serde(default)]
    pub event_type: String,
    #[serde(default)]
    pub message: String,
}

/// Backup entry from /api/v1/backup/history
/// Backend sends minimal: {filename, size_bytes, created_at}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackupEntry {
    #[serde(alias = "filename", default)]
    pub backup_id: String,
    #[serde(default = "default_backup_type")]
    pub backup_type: String,
    #[serde(alias = "created_at", default)]
    pub timestamp: i64,
    #[serde(default)]
    pub size_bytes: Option<u64>,
    #[serde(default = "default_status")]
    pub status: String,
    #[serde(default)]
    pub path: Option<String>,
}

fn default_backup_type() -> String {
    "full".to_string()
}

fn default_status() -> String {
    "completed".to_string()
}

/// Log entry from /api/v1/logs
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogEntry {
    #[serde(default)]
    pub timestamp: String,
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub message: String,
    #[serde(alias = "target", default = "unknown_component")]
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

    #[allow(dead_code)]
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
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SwarmNodeInfo {
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub last_seen: i64,
    #[serde(default)]
    pub is_self: bool,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub capabilities: Option<CapabilityStatus>,
}

/// API response wrapper
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiResponse<T> {
    #[serde(default)]
    pub success: Option<bool>,
    #[serde(flatten)]
    pub data: T,
}

/// Error response from API
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiError {
    pub error: ErrorDetail,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}
