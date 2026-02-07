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
//| FILE: server.rs                                                                                                      |
//|======================================================================================================================|

//! Verification server

use axum::extract::DefaultBodyLimit;
use axum::http::Method;
use ghost_common::constants::{SV1_STRATUM_PORT, SV2_STRATUM_PORT};
use ghost_common::error::{GhostError, GhostResult};
use ghost_common::identity::NodeIdentity;
use ghost_common::rpc::BitcoinRpc;
use ghost_common::types::NodeCapabilities;
use ghost_policy::{PolicyEngine, PolicyProfile};
use ghost_storage::Database;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::NodeConfig;
/// Full node configuration from ghost_common (pool.toml)
/// Used by the config update API to modify settings like mining_mode, policy_profile, etc.
pub use ghost_common::config::NodeConfig as FullNodeConfig;
use tokio::net::TcpListener;
use tower_governor::{
    errors::GovernorError, governor::GovernorConfigBuilder, key_extractor::KeyExtractor,
    GovernorLayer,
};
use tower_http::cors::CorsLayer;
use tracing::info;

/// L-21 FIX: Validate that an IP address is acceptable as a trusted proxy.
///
/// Returns true if the IP is valid for use as a trusted proxy:
/// - Localhost addresses (127.0.0.1, ::1) are always allowed
/// - Private network addresses (10.x, 172.16-31.x, 192.168.x) are allowed
/// - Link-local addresses are rejected (169.254.x.x, fe80::)
/// - Multicast addresses are rejected
/// - Unspecified addresses (0.0.0.0, ::) are rejected
/// - Public IP addresses are allowed (for cloud proxy scenarios)
///
/// This prevents attackers from specifying reserved/special addresses.
fn is_valid_trusted_proxy(ip: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;

    match ip {
        IpAddr::V4(ipv4) => {
            // Reject unspecified address (0.0.0.0)
            if ipv4.is_unspecified() {
                tracing::warn!(ip = %ip, "L-21: Rejecting unspecified IPv4 address as trusted proxy");
                return false;
            }
            // Reject link-local (169.254.x.x)
            if ipv4.is_link_local() {
                tracing::warn!(ip = %ip, "L-21: Rejecting link-local IPv4 address as trusted proxy");
                return false;
            }
            // Reject multicast (224.0.0.0 - 239.255.255.255)
            if ipv4.is_multicast() {
                tracing::warn!(ip = %ip, "L-21: Rejecting multicast IPv4 address as trusted proxy");
                return false;
            }
            // Reject broadcast (255.255.255.255)
            if ipv4.is_broadcast() {
                tracing::warn!(ip = %ip, "L-21: Rejecting broadcast IPv4 address as trusted proxy");
                return false;
            }
            // Reject documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
            let octets = ipv4.octets();
            if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
            {
                tracing::warn!(ip = %ip, "L-21: Rejecting documentation IPv4 address as trusted proxy");
                return false;
            }
            true
        }
        IpAddr::V6(ipv6) => {
            // Reject unspecified address (::)
            if ipv6.is_unspecified() {
                tracing::warn!(ip = %ip, "L-21: Rejecting unspecified IPv6 address as trusted proxy");
                return false;
            }
            // Reject multicast (ff00::/8)
            if ipv6.is_multicast() {
                tracing::warn!(ip = %ip, "L-21: Rejecting multicast IPv6 address as trusted proxy");
                return false;
            }
            // Note: is_unicast_link_local requires nightly or manual check
            // Link-local: fe80::/10
            let segments = ipv6.segments();
            if (segments[0] & 0xffc0) == 0xfe80 {
                tracing::warn!(ip = %ip, "L-21: Rejecting link-local IPv6 address as trusted proxy");
                return false;
            }
            true
        }
    }
}

/// C-2: Trusted proxy configuration for secure IP extraction.
///
/// Only requests from trusted proxy IPs will have X-Forwarded-For/X-Real-IP headers
/// honored. This prevents IP spoofing attacks where attackers set fake headers.
///
/// Load from GHOST_TRUSTED_PROXIES env var (comma-separated IPs) or use defaults.
///
/// L-21 FIX: Validates that configured proxy IPs are not reserved/special addresses.
fn get_trusted_proxies() -> Vec<std::net::IpAddr> {
    use std::net::IpAddr;

    if let Ok(proxies_str) = std::env::var("GHOST_TRUSTED_PROXIES") {
        let proxies: Vec<IpAddr> = proxies_str
            .split(',')
            .filter_map(|s| {
                let trimmed = s.trim();
                match trimmed.parse::<IpAddr>() {
                    Ok(ip) => {
                        // L-21 FIX: Validate the IP is acceptable
                        if is_valid_trusted_proxy(&ip) {
                            Some(ip)
                        } else {
                            None // Already logged in is_valid_trusted_proxy
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            ip = %trimmed,
                            error = %e,
                            "L-21: Failed to parse trusted proxy IP, skipping"
                        );
                        None
                    }
                }
            })
            .collect();

        if proxies.is_empty() {
            tracing::warn!(
                "L-21: No valid trusted proxies configured, falling back to localhost only"
            );
            vec![
                "127.0.0.1"
                    .parse()
                    .expect("L-1: Valid hardcoded IPv4 localhost"),
                "::1".parse().expect("L-1: Valid hardcoded IPv6 localhost"),
            ]
        } else {
            proxies
        }
    } else {
        // Default: only trust localhost as proxy
        vec![
            "127.0.0.1"
                .parse()
                .expect("L-1: Valid hardcoded IPv4 localhost"),
            "::1".parse().expect("L-1: Valid hardcoded IPv6 localhost"),
        ]
    }
}

/// C-2: Check if an IP address is a trusted proxy.
fn is_trusted_proxy(ip: &std::net::IpAddr, trusted: &[std::net::IpAddr]) -> bool {
    trusted.contains(ip)
}

/// AUTH4-M1: Custom key extractor that uses NodeId from X-Ghost-NodeId header
/// with fallback to IP address.
///
/// This provides better rate limiting by identifying nodes by their cryptographic
/// identity rather than just IP, preventing attackers from bypassing limits by
/// changing IPs while still providing a fallback for anonymous requests.
///
/// C-2: X-Forwarded-For and X-Real-IP headers are ONLY trusted when the direct
/// peer IP is in the trusted proxy list. This prevents IP spoofing attacks.
#[derive(Debug, Clone)]
pub struct NodeIdKeyExtractor {
    trusted_proxies: Vec<std::net::IpAddr>,
}

impl Default for NodeIdKeyExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeIdKeyExtractor {
    /// Create a new NodeIdKeyExtractor with trusted proxies from environment.
    pub fn new() -> Self {
        Self {
            trusted_proxies: get_trusted_proxies(),
        }
    }

    /// Create with explicit trusted proxy list (for testing).
    #[cfg(test)]
    pub fn with_trusted_proxies(trusted_proxies: Vec<std::net::IpAddr>) -> Self {
        Self { trusted_proxies }
    }
}

/// Key type for NodeId-based rate limiting
/// Either a 32-byte NodeId or an IP address (encoded as string for simplicity)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeIdOrIpKey(String);

impl KeyExtractor for NodeIdKeyExtractor {
    type Key = NodeIdOrIpKey;

    fn extract<T>(&self, req: &axum::http::Request<T>) -> Result<Self::Key, GovernorError> {
        // Try X-Ghost-NodeId header first (64-char hex-encoded NodeId)
        if let Some(node_id) = req.headers().get("X-Ghost-NodeId") {
            if let Ok(node_id_str) = node_id.to_str() {
                let s: &str = node_id_str;
                // Validate it looks like a valid node ID (64 hex chars = 32 bytes)
                if s.len() == 64 && s.chars().all(|c: char| c.is_ascii_hexdigit()) {
                    return Ok(NodeIdOrIpKey(format!("node:{}", s)));
                }
            }
        }

        // C-2: Get actual peer IP from connection info FIRST
        let peer_ip = req
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip());

        // C-2: Only trust proxy headers if peer is a trusted proxy
        let trust_proxy_headers = peer_ip
            .as_ref()
            .map(|ip| is_trusted_proxy(ip, &self.trusted_proxies))
            .unwrap_or(false);

        if trust_proxy_headers {
            // Try X-Forwarded-For (standard for proxied requests)
            // L-15: Use the LAST IP in the chain, not the first.
            // X-Forwarded-For format: "client, proxy1, proxy2, ..."
            // The first IP (client) can be spoofed by the client.
            // Each proxy appends its peer's IP, so the last IP was added by our
            // trusted proxy and represents the actual connecting peer.
            if let Some(xff) = req.headers().get("X-Forwarded-For") {
                if let Ok(xff_str) = xff.to_str() {
                    let s: &str = xff_str;
                    // L-15: Take the LAST IP (added by our trusted proxy), not the first (spoofable)
                    if let Some(ip_str) = s.split(',').next_back() {
                        let ip_trimmed: &str = ip_str.trim();
                        if !ip_trimmed.is_empty() {
                            return Ok(NodeIdOrIpKey(format!("ip:{}", ip_trimmed)));
                        }
                    }
                }
            }

            // Try X-Real-IP (nginx convention) - this is typically set by the proxy
            // to the actual client IP, so it's already trustworthy when from a trusted proxy
            if let Some(xri) = req.headers().get("X-Real-IP") {
                if let Ok(ip_str) = xri.to_str() {
                    let s: &str = ip_str;
                    return Ok(NodeIdOrIpKey(format!("ip:{}", s)));
                }
            }
        }

        // Fall back to actual peer IP
        if let Some(ip) = peer_ip {
            return Ok(NodeIdOrIpKey(format!("ip:{}", ip)));
        }

        // Last resort: unknown source
        Err(GovernorError::UnableToExtractKey)
    }
}

use crate::challenge::*;
use crate::routes::create_router;
use crate::websocket::WsState;

/// M-12: Validate that a CORS origin is a properly formatted HTTPS URL.
///
/// Returns true only if:
/// - The origin starts with "https://" (enforced for security)
/// - The origin has a valid host after the scheme
/// - The origin doesn't contain path components (origins are scheme + host + optional port)
///
/// This prevents malformed origins from bypassing CORS protection.
fn is_valid_cors_origin(origin: &str) -> bool {
    // Must start with https:// for security
    if !origin.starts_with("https://") {
        tracing::warn!(
            origin = %origin,
            "M-12: Rejecting CORS origin without https:// scheme"
        );
        return false;
    }

    // Extract the host part (after scheme, before any path)
    let host_part = &origin[8..]; // Skip "https://"

    // Must have a non-empty host
    if host_part.is_empty() {
        tracing::warn!(origin = %origin, "M-12: Rejecting CORS origin with empty host");
        return false;
    }

    // Split host from optional port
    let host = if let Some(colon_pos) = host_part.rfind(':') {
        // Check if this is actually a port (not part of IPv6)
        let potential_port = &host_part[colon_pos + 1..];
        if potential_port.chars().all(|c| c.is_ascii_digit()) {
            &host_part[..colon_pos]
        } else {
            host_part
        }
    } else {
        host_part
    };

    // Should not have path components
    if host.contains('/') {
        tracing::warn!(
            origin = %origin,
            "M-12: Rejecting CORS origin with path component"
        );
        return false;
    }

    // Host must be valid (letters, digits, dots, hyphens)
    let is_valid_host = host.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '[' || c == ']' || c == ':'
    });

    if !is_valid_host {
        tracing::warn!(
            origin = %origin,
            "M-12: Rejecting CORS origin with invalid host characters"
        );
        return false;
    }

    true
}

/// Parse a share hash hex string to [u8; 32]
/// Returns zeros if the string is invalid or too short
fn parse_share_hash(hash_str: &str) -> [u8; 32] {
    let mut result = [0u8; 32];
    if let Ok(bytes) = hex::decode(hash_str) {
        let len = bytes.len().min(32);
        result[..len].copy_from_slice(&bytes[..len]);
    }
    result
}

/// Callback for triggering test consensus proposal
pub type TestProposalFn = Arc<dyn Fn() -> GhostResult<[u8; 32]> + Send + Sync>;

/// Share notification data from SRI Pool
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShareNotification {
    pub miner_id: String,
    pub work: f64,
    pub share_hash: String,
    pub job_id: u32,
    pub timestamp: u64,
    /// Whether this share found a block (triggers payout proposal)
    pub is_block: bool,
    /// Payout address extracted from user_identity (format: <address>.<worker>)
    pub payout_address: Option<String>,
}

/// Data for a single share in a batch (from SRI Pool native webhook)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShareData {
    /// Timestamp in milliseconds since epoch
    pub timestamp_ms: u64,
    /// Share hash as hex string
    pub share_hash: String,
    /// Share work/difficulty value
    pub share_work: f64,
    /// Channel ID the share was submitted on
    pub channel_id: u32,
    /// Sequence number from the share submission
    pub sequence_number: u32,
    /// Job ID the share was submitted for
    pub job_id: u32,
    /// Downstream client ID
    pub downstream_id: usize,
    /// Whether this share found a block
    pub is_block: bool,
    /// User identity string (format: <payout_address>.<worker_name>)
    /// Used to identify the miner's payout address
    #[serde(default)]
    pub user_identity: String,
}

/// Batch of shares from SRI Pool native webhook
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShareBatch {
    /// Pool/server ID
    pub pool_id: u16,
    /// Sequence number for this batch
    pub batch_seq: u64,
    /// Array of shares in this batch
    pub shares: Vec<ShareData>,
}

/// Callback for recording shares (from SRI Pool notifications)
pub type RecordShareFn = Arc<dyn Fn(ShareNotification) -> GhostResult<()> + Send + Sync>;

/// Block found notification from SRI Pool (when is_block == true)
#[derive(Debug, Clone)]
pub struct BlockFoundNotification {
    /// Block hash (parsed from share_hash)
    pub block_hash: [u8; 32],
    /// Miner ID that found the block
    pub miner_id: String,
    /// Share work value
    pub share_work: f64,
    /// Timestamp (seconds since epoch)
    pub timestamp: u64,
    /// Payout address extracted from user_identity (format: <address>.<worker>)
    pub payout_address: Option<String>,
}

/// Parse user_identity string to extract payout address and worker name.
/// Format: <payout_address>.<worker_name>
/// Returns (payout_address, worker_name) or (user_identity, "default") if no dot found.
fn parse_user_identity(user_identity: &str) -> (String, String) {
    if let Some(last_dot) = user_identity.rfind('.') {
        let address = &user_identity[..last_dot];
        let worker = &user_identity[last_dot + 1..];
        (address.to_string(), worker.to_string())
    } else {
        // No dot found - treat entire string as address with default worker
        (user_identity.to_string(), "default".to_string())
    }
}

/// Callback for block found events (triggers payout proposal creation)
pub type BlockFoundFn = Arc<dyn Fn(BlockFoundNotification) -> GhostResult<()> + Send + Sync>;

/// Dashboard configuration state (mutable settings)
#[derive(Debug, Clone)]
pub struct DashboardConfig {
    pub ghost_mode: bool,
    pub archive_mode: bool,
    pub ghost_pay: bool,
    pub public_mining: bool,
    pub bitcoin_pure: bool,
    pub elder: bool,
    pub elder_slot: Option<u32>,
    pub mempool_profile: String,
    pub template_profile: String,
    pub prune_profile: String,
    /// Maximum miners this node will accept
    pub max_miners: u32,
    /// Node display name for node finder
    pub node_name: Option<String>,
    /// Geographic region (eu, us, asia)
    pub region: Option<String>,
    /// Public stratum hostname
    pub stratum_host: Option<String>,
    /// Public stratum port
    pub stratum_port: Option<u16>,
    /// Public HTTP API port
    pub http_port: Option<u16>,
    /// M-STOR-2: Enable debug endpoints (logs, system info)
    /// Should be false in production
    pub enable_debug_endpoints: bool,
    /// M-STOR-3: Allowed paths for /proc filesystem access
    pub proc_paths_allowed: Vec<String>,
    /// M-STOR-3: Backup directory path
    pub backup_dir: String,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            ghost_mode: true,
            archive_mode: true,  // enabled by default
            ghost_pay: true,     // enabled by default
            public_mining: true, // enabled by default
            bitcoin_pure: true,  // enabled by default
            elder: false,        // set per-node
            elder_slot: None,
            mempool_profile: "permissive".to_string(),
            template_profile: "default".to_string(),
            prune_profile: "none".to_string(),
            max_miners: 1000,
            node_name: None,
            region: None,
            stratum_host: None,
            stratum_port: None,
            http_port: None,
            // M-STOR-2: Debug endpoints disabled by default for security
            enable_debug_endpoints: false,
            // M-STOR-3: Allowed /proc paths for system monitoring
            proc_paths_allowed: vec![
                "/proc/meminfo".to_string(),
                "/proc/loadavg".to_string(),
                "/proc/cpuinfo".to_string(),
            ],
            // M-STOR-3: Default backup directory
            backup_dir: "/home/ghost/.ghost/backups".to_string(),
        }
    }
}

/// Verification server state
pub struct VerificationState {
    /// Node ID (hex)
    pub node_id: String,
    /// Software version
    pub version: String,
    /// Node identity for signing responses
    identity: Option<Arc<NodeIdentity>>,
    /// Policy engine
    policy_engine: parking_lot::Mutex<PolicyEngine>,
    /// Capabilities
    pub capabilities: NodeCapabilities,
    /// Server start time
    start_time: Instant,
    /// Block height getter (callback)
    get_block_height: Box<dyn Fn() -> u64 + Send + Sync>,
    /// Round ID getter (callback)
    get_round_id: Box<dyn Fn() -> u64 + Send + Sync>,
    /// Miner count getter (callback)
    get_miner_count: Box<dyn Fn() -> u32 + Send + Sync>,
    /// Peer count getter (callback)
    get_peer_count: Box<dyn Fn() -> u32 + Send + Sync>,
    /// Archive mode handler
    archive_handler: Option<Box<dyn ArchiveHandler + Send + Sync>>,
    /// GhostPay handler
    ghostpay_handler: Option<Box<dyn GhostPayHandler + Send + Sync>>,
    /// GSP (Ghost Service Protocol) handler for light wallets
    gsp_handler: Option<Box<dyn GspHandler + Send + Sync>>,
    /// Stratum port (SV2)
    stratum_sv2_port: u16,
    /// Stratum port (SV1)
    stratum_sv1_port: u16,
    /// Database for queries (optional)
    pub database: Option<Database>,
    /// Ghost Core RPC client (optional)
    pub rpc: Option<Arc<BitcoinRpc>>,
    /// Dashboard config (mutable settings)
    pub dashboard_config: parking_lot::RwLock<DashboardConfig>,
    /// Node config with disk persistence (ghost_mode, etc.) - minimal JSON config
    pub node_config: parking_lot::RwLock<NodeConfig>,
    /// Path to node config file (JSON, for ghost_mode)
    pub node_config_path: Option<PathBuf>,
    /// Full node configuration (pool.toml) for config update API
    /// Contains all settings like mining_mode, policy_profile, ghost_pay, etc.
    pub full_node_config: Option<parking_lot::RwLock<FullNodeConfig>>,
    /// Path to full node config file (pool.toml)
    pub full_node_config_path: Option<PathBuf>,
    /// WebSocket state for real-time updates
    pub ws_state: Arc<WsState>,
    /// Test proposal callback (for admin testing)
    test_proposal_fn: Option<TestProposalFn>,
    /// Share recording callback (from SRI Pool notifications)
    record_share_fn: Option<RecordShareFn>,
    /// Block found callback (triggers payout proposal when is_block == true)
    block_found_fn: Option<BlockFoundFn>,
    /// Internal API authentication (H10/H11 security fix)
    /// When Some, internal endpoints require HMAC-SHA256 authentication
    pub internal_auth: Option<Arc<crate::auth::InternalAuth>>,
    /// VF-C2: Whether to require internal API authentication at startup
    /// When true (default), server will fail to start if internal_auth is not configured
    /// When false, allows insecure mode for development/testing ONLY
    pub require_internal_auth: bool,
    /// Signal to trigger graceful restart (set by config update API)
    /// When true, main.rs will initiate shutdown and exit with code 100
    pub restart_signal: Arc<AtomicBool>,
    /// L-28: Debug endpoints enabled flag - IMMUTABLE after startup
    /// This is set once from DashboardConfig during construction and cannot be changed
    /// at runtime via any API. This prevents attackers from enabling debug endpoints
    /// to gain access to sensitive system information.
    debug_endpoints_frozen: AtomicBool,
}

/// Archive handler trait
pub trait ArchiveHandler {
    fn get_block(&self, hash: &str) -> GhostResult<Option<BlockData>>;
    fn get_transaction(&self, txid: &str) -> GhostResult<Option<TxData>>;
    fn has_block_at_height(&self, height: u64) -> bool;
}

/// H-5: Epoch proof for cryptographic GhostPay verification
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EpochProof {
    /// Epoch number this proof is for
    pub epoch: u64,
    /// Hash of L2 state at this epoch (SHA256 of serialized state)
    pub state_hash: String,
    /// Number of transactions in this epoch
    pub tx_count: u64,
}

/// GhostPay handler trait
pub trait GhostPayHandler {
    fn is_enabled(&self) -> bool;
    fn get_virtual_block(&self) -> u64;
    fn get_epoch(&self) -> u64;
    fn get_balance(&self, address: &str) -> GhostResult<u64>;
    fn is_wraith_enabled(&self) -> bool;

    /// H-5: Get proof of L2 state at a specific epoch
    ///
    /// This method is used for cryptographic verification that a node
    /// actually has L2 state data, not just self-reporting capability.
    /// Returns None if the node doesn't have state for the requested epoch.
    fn get_epoch_proof(&self, epoch: u64) -> Option<EpochProof> {
        // Default implementation returns None (node doesn't support proofs)
        let _ = epoch;
        None
    }
}

/// GSP (Ghost Service Protocol) handler trait for light wallet support
pub trait GspHandler: Send + Sync {
    /// Check if GSP is enabled
    fn is_enabled(&self) -> bool;
    /// Get GSP protocol version
    fn get_protocol_version(&self) -> String;
    /// Get network name (mainnet, signet, regtest, etc.)
    fn get_network(&self) -> String;
    /// Get current connection count
    fn get_connection_count(&self) -> u32;
    /// Get number of registered wallets
    fn get_registered_wallets(&self) -> u32;
    /// Get sync status
    fn get_sync_status(&self) -> String;
    /// Perform health check
    fn health_check(&self) -> GhostResult<bool>;
}

/// GSP status info for watchdog
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GspInfo {
    pub protocol_version: String,
    pub network: String,
    pub connections: u32,
    pub sync_status: String,
    pub registered_wallets: u32,
}

impl VerificationState {
    /// Create new verification state
    pub fn new(
        node_id: String,
        version: String,
        policy_profile: PolicyProfile,
        capabilities: NodeCapabilities,
    ) -> Self {
        // Initialize dashboard config with defaults (all features enabled)
        let dashboard_config = DashboardConfig::default();
        // L-28: Capture debug endpoint setting at startup - immutable thereafter
        let debug_enabled = dashboard_config.enable_debug_endpoints;
        Self {
            node_id,
            version,
            identity: None,
            policy_engine: parking_lot::Mutex::new(PolicyEngine::new(policy_profile)),
            capabilities,
            start_time: Instant::now(),
            get_block_height: Box::new(|| 0),
            get_round_id: Box::new(|| 0),
            get_miner_count: Box::new(|| 0),
            get_peer_count: Box::new(|| 0),
            archive_handler: None,
            ghostpay_handler: None,
            gsp_handler: None,
            stratum_sv2_port: SV2_STRATUM_PORT,
            stratum_sv1_port: SV1_STRATUM_PORT,
            database: None,
            rpc: None,
            dashboard_config: parking_lot::RwLock::new(dashboard_config),
            node_config: parking_lot::RwLock::new(NodeConfig::default()),
            node_config_path: None,
            full_node_config: None,
            full_node_config_path: None,
            ws_state: Arc::new(WsState::new()),
            test_proposal_fn: None,
            record_share_fn: None,
            block_found_fn: None,
            internal_auth: None,
            // VF-C2: Default to requiring internal auth for security
            require_internal_auth: true,
            restart_signal: Arc::new(AtomicBool::new(false)),
            // L-28: Debug endpoints flag frozen at startup
            debug_endpoints_frozen: AtomicBool::new(debug_enabled),
        }
    }

    /// Signal that a restart is needed (config update API)
    pub fn request_restart(&self) {
        self.restart_signal.store(true, Ordering::SeqCst);
    }

    /// Check if a restart has been requested
    pub fn restart_requested(&self) -> bool {
        self.restart_signal.load(Ordering::SeqCst)
    }

    /// Get the restart signal for external monitoring (main.rs)
    pub fn restart_signal(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.restart_signal)
    }

    /// L-28: Check if debug endpoints are enabled.
    ///
    /// This value is frozen at startup and cannot be changed at runtime.
    /// Even if DashboardConfig.enable_debug_endpoints is modified, this
    /// method will return the original startup value.
    ///
    /// # Security
    /// This prevents runtime attacks that attempt to enable debug endpoints
    /// to gain access to sensitive system information.
    pub fn debug_endpoints_enabled(&self) -> bool {
        self.debug_endpoints_frozen.load(Ordering::Relaxed)
    }

    /// L-28: Set debug endpoints enabled (builder pattern).
    ///
    /// **WARNING**: This can only be called during construction (before start_server).
    /// Once the server is started, this setting is immutable.
    ///
    /// Default is false (disabled) for security.
    pub fn with_debug_endpoints(self, enabled: bool) -> Self {
        self.debug_endpoints_frozen.store(enabled, Ordering::Relaxed);
        // Also update dashboard_config for consistency in responses
        {
            let mut config = self.dashboard_config.write();
            config.enable_debug_endpoints = enabled;
        }
        self
    }

    /// Set internal API authentication (H10/H11 security fix)
    ///
    /// When configured, internal endpoints (`/api/internal/*`, `/admin/*`) require
    /// HMAC-SHA256 authentication via X-Ghost-Signature and X-Ghost-Timestamp headers.
    pub fn with_internal_auth(mut self, auth: crate::auth::InternalAuth) -> Self {
        self.internal_auth = Some(Arc::new(auth));
        self
    }

    /// VF-C2: Allow insecure internal API mode (for development/testing ONLY)
    ///
    /// **SECURITY WARNING**: This bypasses mandatory authentication for internal endpoints.
    /// Only use this in development/test environments, NEVER in production.
    ///
    /// When `allow_insecure` is true:
    /// - Server will start even without `internal_auth` configured
    /// - Internal endpoints will be unprotected
    /// - A warning will be logged at startup
    ///
    /// When `allow_insecure` is false (default):
    /// - Server will fail to start if `internal_auth` is not configured
    /// - This ensures production deployments are always protected
    pub fn allow_insecure_internal_api(mut self, allow_insecure: bool) -> Self {
        self.require_internal_auth = !allow_insecure;
        self
    }

    /// Set share recording callback (for SRI Pool share notifications)
    pub fn with_share_recorder<F>(mut self, recorder: F) -> Self
    where
        F: Fn(ShareNotification) -> GhostResult<()> + Send + Sync + 'static,
    {
        self.record_share_fn = Some(Arc::new(recorder));
        self
    }

    /// Set block found callback (triggers payout proposal when is_block == true)
    pub fn with_block_found_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(BlockFoundNotification) -> GhostResult<()> + Send + Sync + 'static,
    {
        self.block_found_fn = Some(Arc::new(handler));
        self
    }

    /// Record a share (called from HTTP endpoint)
    pub fn record_share(&self, share: ShareNotification) -> GhostResult<()> {
        if let Some(ref recorder) = self.record_share_fn {
            recorder(share)
        } else {
            Err(GhostError::Internal(
                "Share recorder not configured".to_string(),
            ))
        }
    }

    /// Record a batch of shares (called from HTTP endpoint for native SRI webhook)
    ///
    /// Converts ShareData to ShareNotification format and records each share.
    /// Extracts payout address from user_identity (format: <address>.<worker>).
    /// When is_block == true, triggers block found callback for payout proposal.
    pub fn record_share_batch(&self, batch: ShareBatch) -> GhostResult<usize> {
        if self.record_share_fn.is_none() {
            return Err(GhostError::Internal(
                "Share recorder not configured".to_string(),
            ));
        }

        let mut recorded = 0;
        let mut blocks_found = 0;

        for share in batch.shares {
            // Parse user_identity to extract payout address and worker name
            // Format: <payout_address>.<worker_name>
            let (payout_address, worker_name) = if !share.user_identity.is_empty() {
                parse_user_identity(&share.user_identity)
            } else {
                // Fallback to downstream_id if no user_identity
                (share.downstream_id.to_string(), "default".to_string())
            };

            // Use user_identity as miner_id if available, otherwise downstream_id
            let miner_id = if !share.user_identity.is_empty() {
                share.user_identity.clone()
            } else {
                share.downstream_id.to_string()
            };

            // Convert ShareData to ShareNotification
            let notification = ShareNotification {
                miner_id: miner_id.clone(),
                work: share.share_work,
                share_hash: share.share_hash.clone(),
                job_id: share.job_id,
                timestamp: share.timestamp_ms / 1000, // Convert ms to seconds
                is_block: share.is_block,
                payout_address: if !payout_address.is_empty() {
                    Some(payout_address.clone())
                } else {
                    None
                },
            };

            if let Err(e) = self.record_share(notification) {
                tracing::warn!(error = %e, "Failed to record share from batch");
            } else {
                recorded += 1;
            }

            // Handle block found event (triggers payout proposal creation)
            if share.is_block {
                blocks_found += 1;
                tracing::info!(
                    share_hash = %share.share_hash,
                    miner_id = %miner_id,
                    payout_address = %payout_address,
                    worker_name = %worker_name,
                    work = share.share_work,
                    "Block found via SRI webhook - triggering payout proposal"
                );

                if let Some(ref block_found_fn) = self.block_found_fn {
                    // Parse share hash from hex string to bytes
                    let block_hash = parse_share_hash(&share.share_hash);

                    let block_notification = BlockFoundNotification {
                        block_hash,
                        miner_id,
                        share_work: share.share_work,
                        timestamp: share.timestamp_ms / 1000,
                        payout_address: if !payout_address.is_empty() {
                            Some(payout_address)
                        } else {
                            None
                        },
                    };

                    if let Err(e) = block_found_fn(block_notification) {
                        tracing::error!(error = %e, "Failed to handle block found event");
                    }
                } else {
                    tracing::warn!("Block found but no block_found_handler configured");
                }
            }
        }

        if blocks_found > 0 {
            tracing::info!(
                recorded,
                blocks_found,
                "Share batch processed with block(s) found"
            );
        }

        Ok(recorded)
    }

    /// Parse a share hash hex string to [u8; 32]
    #[allow(dead_code)]
    fn parse_share_hash_internal(hash_str: &str) -> [u8; 32] {
        parse_share_hash(hash_str)
    }

    /// Set the node config path and load config from disk
    pub fn with_node_config_path(mut self, path: PathBuf) -> Self {
        let config = NodeConfig::load_or_default(&path);
        // Sync dashboard_config ghost_mode with loaded node_config
        {
            let mut dashboard = self.dashboard_config.write();
            dashboard.ghost_mode = config.ghost_mode;
        }
        self.node_config = parking_lot::RwLock::new(config);
        self.node_config_path = Some(path);
        self
    }

    /// Set the full node configuration (pool.toml) for config update API
    ///
    /// This allows the config update API to modify settings like mining_mode,
    /// policy_profile, ghost_pay_enabled, etc. and persist them to disk.
    ///
    /// # Arguments
    /// * `config` - The full NodeConfig loaded from pool.toml
    /// * `path` - Path to the pool.toml file for atomic save
    pub fn with_full_node_config(mut self, config: FullNodeConfig, path: PathBuf) -> Self {
        self.full_node_config = Some(parking_lot::RwLock::new(config));
        self.full_node_config_path = Some(path);
        self
    }

    /// Set node identity for signing responses
    pub fn with_identity(mut self, identity: Arc<NodeIdentity>) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Sign a response payload using node identity
    ///
    /// Returns a SignedResponse wrapper if identity is configured, otherwise returns None.
    /// Callers should fall back to unsigned responses when None is returned.
    pub fn sign_response<T: serde::Serialize + Clone>(
        &self,
        payload: T,
        challenge_nonce: Option<String>,
    ) -> Option<SignedResponse<T>> {
        let identity = self.identity.as_ref()?;

        let sign_fn = |message: &[u8]| -> [u8; 64] { identity.sign(message) };

        Some(SignedResponse::new(
            payload,
            self.node_id.clone(),
            sign_fn,
            challenge_nonce,
        ))
    }

    /// Check if response signing is available
    pub fn can_sign(&self) -> bool {
        self.identity.is_some()
    }

    /// Set test proposal callback (for admin testing of BFT consensus)
    pub fn with_test_proposal_fn(mut self, f: TestProposalFn) -> Self {
        self.test_proposal_fn = Some(f);
        self
    }

    /// Trigger test proposal if callback is set
    pub fn trigger_test_proposal(&self) -> GhostResult<Option<[u8; 32]>> {
        match &self.test_proposal_fn {
            Some(f) => Ok(Some(f()?)),
            None => Ok(None),
        }
    }

    /// Set database for queries
    pub fn with_database(mut self, db: Database) -> Self {
        self.database = Some(db);
        self
    }

    /// Set Ghost Core RPC client
    pub fn with_rpc(mut self, rpc: Arc<BitcoinRpc>) -> Self {
        self.rpc = Some(rpc);
        self
    }

    /// Sync ghost mode with ghost-core on startup
    ///
    /// If RPC is available, queries ghost-core for the current ghost mode
    /// and syncs the local config. If the local config differs, updates
    /// ghost-core to match the persisted config (local wins on startup).
    pub async fn sync_ghost_mode_with_core(&self) -> GhostResult<()> {
        use tracing::{debug, info, warn};

        let rpc = match &self.rpc {
            Some(rpc) => rpc,
            None => {
                debug!("No RPC client available, skipping ghost mode sync");
                return Ok(());
            }
        };

        // Get local config state
        let local_ghost_mode = self.node_config.read().ghost_mode;

        // Query ghost-core for current state
        match rpc.get_ghost_mode().await {
            Ok(response) => {
                if response.ghost_mode != local_ghost_mode {
                    info!(
                        "Ghost mode mismatch: local={}, core={}. Syncing core to local.",
                        local_ghost_mode, response.ghost_mode
                    );
                    // Local persisted config wins - sync ghost-core to match
                    match rpc.set_ghost_mode(local_ghost_mode).await {
                        Ok(_) => {
                            info!(
                                "Successfully synced ghost-core to ghost_mode={}",
                                local_ghost_mode
                            );
                        }
                        Err(e) => {
                            warn!("Failed to sync ghost mode to ghost-core: {}", e);
                        }
                    }
                } else {
                    debug!("Ghost mode already in sync: {}", local_ghost_mode);
                }

                // Sync dashboard config
                {
                    let mut dashboard = self.dashboard_config.write();
                    dashboard.ghost_mode = local_ghost_mode;
                }
            }
            Err(e) => {
                warn!("Failed to query ghost mode from ghost-core: {}", e);
            }
        }

        Ok(())
    }

    /// Set callbacks
    pub fn with_callbacks(
        mut self,
        block_height: impl Fn() -> u64 + Send + Sync + 'static,
        round_id: impl Fn() -> u64 + Send + Sync + 'static,
        miner_count: impl Fn() -> u32 + Send + Sync + 'static,
        peer_count: impl Fn() -> u32 + Send + Sync + 'static,
    ) -> Self {
        self.get_block_height = Box::new(block_height);
        self.get_round_id = Box::new(round_id);
        self.get_miner_count = Box::new(miner_count);
        self.get_peer_count = Box::new(peer_count);
        self
    }

    /// Set archive handler
    pub fn with_archive_handler(
        mut self,
        handler: impl ArchiveHandler + Send + Sync + 'static,
    ) -> Self {
        self.archive_handler = Some(Box::new(handler));
        self
    }

    /// Set GhostPay handler
    pub fn with_ghostpay_handler(
        mut self,
        handler: impl GhostPayHandler + Send + Sync + 'static,
    ) -> Self {
        self.ghostpay_handler = Some(Box::new(handler));
        self
    }

    /// Set GSP handler for light wallet support
    pub fn with_gsp_handler(mut self, handler: impl GspHandler + 'static) -> Self {
        self.gsp_handler = Some(Box::new(handler));
        self
    }

    /// Check if GSP is enabled
    pub fn gsp_enabled(&self) -> bool {
        self.gsp_handler
            .as_ref()
            .map(|h| h.is_enabled())
            .unwrap_or(false)
    }

    /// Get GSP info for watchdog
    pub fn get_gsp_info(&self) -> Option<GspInfo> {
        let handler = self.gsp_handler.as_ref()?;
        Some(GspInfo {
            protocol_version: handler.get_protocol_version(),
            network: handler.get_network(),
            connections: handler.get_connection_count(),
            sync_status: handler.get_sync_status(),
            registered_wallets: handler.get_registered_wallets(),
        })
    }

    /// Set stratum ports
    pub fn with_stratum_ports(mut self, sv2_port: u16, sv1_port: u16) -> Self {
        self.stratum_sv2_port = sv2_port;
        self.stratum_sv1_port = sv1_port;
        self
    }

    /// Get WebSocket state for broadcasting events
    pub fn ws(&self) -> &Arc<WsState> {
        &self.ws_state
    }

    /// Get health response
    pub async fn get_health(&self) -> HealthResponse {
        HealthResponse {
            healthy: true,
            node_id: self.node_id.clone(),
            version: self.version.clone(),
            block_height: (self.get_block_height)(),
            round_id: (self.get_round_id)(),
            miner_count: (self.get_miner_count)(),
            peer_count: (self.get_peer_count)(),
            capabilities: self.capabilities.into(),
            uptime_secs: self.start_time.elapsed().as_secs(),
        }
    }

    /// Verify archive challenge
    pub async fn verify_archive(
        &self,
        challenge: ArchiveChallenge,
    ) -> GhostResult<ArchiveResponse> {
        if !self.capabilities.archive_mode {
            return Ok(ArchiveResponse {
                success: false,
                block_data: None,
                tx_data: None,
                error: Some("Archive mode not enabled".to_string()),
            });
        }

        let handler =
            self.archive_handler
                .as_ref()
                .ok_or_else(|| GhostError::VerificationFailed {
                    capability: "archive".to_string(),
                    reason: "Archive handler not configured".to_string(),
                })?;

        match challenge.challenge_type {
            ChallengeType::ArchiveBlock => {
                let hash = challenge
                    .block_hash
                    .ok_or_else(|| GhostError::VerificationFailed {
                        capability: "archive".to_string(),
                        reason: "Block hash required".to_string(),
                    })?;

                let block_data = handler.get_block(&hash)?;

                Ok(ArchiveResponse {
                    success: block_data.is_some(),
                    block_data,
                    tx_data: None,
                    error: None,
                })
            }
            ChallengeType::ArchiveTx => {
                let txid = challenge
                    .txid
                    .ok_or_else(|| GhostError::VerificationFailed {
                        capability: "archive".to_string(),
                        reason: "Transaction ID required".to_string(),
                    })?;

                let tx_data = handler.get_transaction(&txid)?;

                Ok(ArchiveResponse {
                    success: tx_data.is_some(),
                    block_data: None,
                    tx_data,
                    error: None,
                })
            }
            _ => Ok(ArchiveResponse {
                success: false,
                block_data: None,
                tx_data: None,
                error: Some("Invalid challenge type for archive".to_string()),
            }),
        }
    }

    /// Verify policy challenge
    pub async fn verify_policy(&self, challenge: PolicyChallenge) -> GhostResult<PolicyResponse> {
        // Decode transaction hex
        let tx_bytes =
            hex::decode(&challenge.tx_hex).map_err(|e| GhostError::VerificationFailed {
                capability: "policy".to_string(),
                reason: format!("Invalid transaction hex: {}", e),
            })?;

        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_bytes).map_err(|e| {
            GhostError::VerificationFailed {
                capability: "policy".to_string(),
                reason: format!("Invalid transaction: {}", e),
            }
        })?;

        // Evaluate against policy
        let mut engine = self.policy_engine.lock();
        let decision = engine.evaluate(&tx);

        let classification = match &decision {
            ghost_policy::PolicyDecision::Accept { classification, .. }
            | ghost_policy::PolicyDecision::Reject { classification, .. } => {
                Some(PolicyClassification {
                    tier: classification.tier.to_string(),
                    reason: classification.reason.to_string(),
                    features: classification
                        .features
                        .iter()
                        .map(|f| f.to_string())
                        .collect(),
                })
            }
        };

        let (accepted, rejection_reason) = match &decision {
            ghost_policy::PolicyDecision::Accept { .. } => (true, None),
            ghost_policy::PolicyDecision::Reject { reason, .. } => {
                (false, Some(reason.to_string()))
            }
        };

        Ok(PolicyResponse {
            success: true,
            profile: engine.profile().name.clone(),
            classification,
            accepted,
            rejection_reason,
            error: None,
        })
    }

    /// Verify stratum challenge
    ///
    /// H-4: Performs actual Stratum protocol verification, not just TCP connection.
    /// Uses StratumVerifier to perform proper mining.subscribe (SV1) or Noise handshake (SV2).
    pub async fn verify_stratum(
        &self,
        challenge: StratumChallenge,
    ) -> GhostResult<StratumResponse> {
        use crate::handlers::StratumVerifier;

        if !self.capabilities.public_mining {
            return Ok(StratumResponse {
                success: false,
                port: challenge.port.unwrap_or(self.stratum_sv2_port),
                protocol: challenge.protocol,
                connected: false,
                latency_ms: None,
                error: Some("Public mining not enabled".to_string()),
            });
        }

        let port = match challenge.protocol {
            StratumProtocol::Sv2 => challenge.port.unwrap_or(self.stratum_sv2_port),
            StratumProtocol::Sv1 => challenge.port.unwrap_or(self.stratum_sv1_port),
        };

        // H-4: Use StratumVerifier to perform actual protocol handshake
        // This prevents nodes from passing verification with just a TCP listener
        let verifier = StratumVerifier::new().with_timeout(Duration::from_secs(5));

        let result = match challenge.protocol {
            StratumProtocol::Sv1 => verifier.verify_sv1("127.0.0.1", port).await,
            StratumProtocol::Sv2 => verifier.verify_sv2("127.0.0.1", port).await,
        };

        match result {
            Ok(verify_result) => {
                // H-4: Require valid_protocol, not just connection
                let success = verify_result.connected && verify_result.valid_protocol;
                Ok(StratumResponse {
                    success,
                    port,
                    protocol: challenge.protocol,
                    connected: verify_result.connected,
                    latency_ms: Some(verify_result.total_latency.as_millis() as u32),
                    error: if success {
                        None
                    } else {
                        Some(
                            verify_result
                                .error
                                .unwrap_or_else(|| "Protocol handshake failed".to_string()),
                        )
                    },
                })
            }
            Err(e) => Ok(StratumResponse {
                success: false,
                port,
                protocol: challenge.protocol,
                connected: false,
                latency_ms: None,
                error: Some(format!("Verification failed: {}", e)),
            }),
        }
    }

    /// Verify GhostPay challenge
    ///
    /// H-5: When a challenge_epoch is provided, the node must prove it has
    /// L2 state data for that epoch. This prevents nodes from claiming
    /// GhostPay capability without actually maintaining L2 state.
    pub async fn verify_ghostpay(
        &self,
        challenge: GhostPayChallenge,
    ) -> GhostResult<GhostPayResponse> {
        if !self.capabilities.ghost_pay {
            return Ok(GhostPayResponse {
                success: false,
                l2_enabled: false,
                virtual_block: None,
                epoch: None,
                balance_sats: None,
                wraith_enabled: false,
                epoch_state_hash: None,
                epoch_tx_count: None,
                error: Some("Ghost Pay not enabled".to_string()),
            });
        }

        let handler = match &self.ghostpay_handler {
            Some(h) => h,
            None => {
                return Ok(GhostPayResponse {
                    success: false,
                    l2_enabled: true,
                    virtual_block: None,
                    epoch: None,
                    balance_sats: None,
                    wraith_enabled: false,
                    epoch_state_hash: None,
                    epoch_tx_count: None,
                    error: Some("Ghost Pay handler not configured".to_string()),
                });
            }
        };

        let balance = if let Some(address) = &challenge.address {
            Some(handler.get_balance(address)?)
        } else {
            None
        };

        // H-5: If a challenge epoch is specified, require epoch proof
        let (epoch_state_hash, epoch_tx_count, epoch_proof_success) =
            if let Some(challenge_epoch) = challenge.challenge_epoch {
                match handler.get_epoch_proof(challenge_epoch) {
                    Some(proof) => (Some(proof.state_hash), Some(proof.tx_count), true),
                    None => {
                        // Node claims GhostPay but can't prove epoch state
                        return Ok(GhostPayResponse {
                            success: false,
                            l2_enabled: handler.is_enabled(),
                            virtual_block: Some(handler.get_virtual_block()),
                            epoch: Some(handler.get_epoch()),
                            balance_sats: balance,
                            wraith_enabled: handler.is_wraith_enabled(),
                            epoch_state_hash: None,
                            epoch_tx_count: None,
                            error: Some(format!(
                                "Cannot prove L2 state for epoch {}",
                                challenge_epoch
                            )),
                        });
                    }
                }
            } else {
                // No challenge epoch - basic verification only
                (None, None, true)
            };

        Ok(GhostPayResponse {
            success: epoch_proof_success,
            l2_enabled: handler.is_enabled(),
            virtual_block: Some(handler.get_virtual_block()),
            epoch: Some(handler.get_epoch()),
            balance_sats: balance,
            wraith_enabled: handler.is_wraith_enabled(),
            epoch_state_hash,
            epoch_tx_count,
            error: None,
        })
    }
}

/// Start verification server
///
/// # VF-C2: Mandatory Internal API Authentication
///
/// By default, the server requires internal API authentication to be configured.
/// If `internal_auth` is None and `require_internal_auth` is true, startup fails.
/// Use `allow_insecure_internal_api(true)` to bypass this check in dev environments.
pub async fn start_server(state: Arc<VerificationState>, port: u16) -> GhostResult<()> {
    // VF-C2: Validate internal API auth requirement
    if state.require_internal_auth && state.internal_auth.is_none() {
        return Err(GhostError::Config(
            "VF-C2 SECURITY: Internal API authentication is required but not configured. \
             Configure 'internal_api_secret' in pool.toml or use \
             'allow_insecure_internal_api: true' in config (development ONLY)."
                .to_string(),
        ));
    }

    // VF-C2: Log security status
    if state.internal_auth.is_some() {
        info!("VF-C2: Internal API authentication ENABLED");
    } else {
        tracing::warn!(
            "VF-C2 SECURITY WARNING: Internal API authentication DISABLED! \
             /api/internal/* and /admin/* endpoints are UNPROTECTED. \
             This is acceptable ONLY for development/testing environments. \
             For production, configure 'internal_api_secret' in pool.toml."
        );
    }

    // C-1: CORS configuration - restricted to trusted origins
    // Environment variable allows deployment-specific configuration
    // Default: bitcoinghost.org domains only
    // M-12: Origins are validated to ensure proper https:// URL format
    let allowed_origins = std::env::var("GHOST_VERIFICATION_ALLOWED_ORIGINS")
        .unwrap_or_else(|_| "https://bitcoinghost.org,https://wallet.bitcoinghost.org".to_string());

    // M-12: Validate each origin before parsing
    let origins: Vec<axum::http::HeaderValue> = allowed_origins
        .split(',')
        .filter_map(|s| {
            let trimmed = s.trim();
            // M-12: Validate URL format before accepting
            if is_valid_cors_origin(trimmed) {
                trimmed.parse().ok()
            } else {
                // Warning already logged in is_valid_cors_origin
                None
            }
        })
        .collect();

    // If no valid origins parsed, use secure defaults
    let cors = if origins.is_empty() {
        tracing::warn!(
            "C-1 SECURITY: No valid CORS origins configured, using secure defaults"
        );
        CorsLayer::new()
            .allow_origin(tower_http::cors::AllowOrigin::list([
                "https://bitcoinghost.org"
                    .parse()
                    .expect("L-1: Valid hardcoded origin URL"),
                "https://wallet.bitcoinghost.org"
                    .parse()
                    .expect("L-1: Valid hardcoded origin URL"),
            ]))
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([
                axum::http::header::CONTENT_TYPE,
                axum::http::header::AUTHORIZATION,
                axum::http::header::ACCEPT,
            ])
            .max_age(Duration::from_secs(3600))
    } else {
        info!(
            origins = ?origins.iter().map(|h| h.to_str().unwrap_or("?")).collect::<Vec<_>>(),
            "C-1: CORS configured with validated origins (M-12: https:// enforced)"
        );
        CorsLayer::new()
            .allow_origin(tower_http::cors::AllowOrigin::list(origins))
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([
                axum::http::header::CONTENT_TYPE,
                axum::http::header::AUTHORIZATION,
                axum::http::header::ACCEPT,
            ])
            .max_age(Duration::from_secs(3600))
    };

    // Rate limiting configuration - AUTH4-M1: NodeId-based rate limiting
    // - 50 requests per second burst capacity
    // - Refills at 10 requests per second
    // - Per NodeId (from X-Ghost-NodeId header) with IP fallback
    // L-28: Use proper error handling instead of expect()
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(10)
            .burst_size(50)
            .key_extractor(NodeIdKeyExtractor::new())
            .finish()
            .ok_or_else(|| {
                GhostError::Config(
                    "L-28: Failed to initialize rate limiter: invalid configuration. \
                     This is an internal configuration error.".to_string()
                )
            })?,
    );

    let governor_limiter = governor_conf.limiter().clone();

    // Spawn background task to clean up rate limiter state
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            governor_limiter.retain_recent();
        }
    });

    // Build service with security layers
    // - Rate limiting: 50 req/s burst, 10 req/s sustained per NodeId/IP
    // - CORS: restrict to allowed origins
    // - Request body limit: 1MB max to prevent DoS
    let app = create_router(state)
        .layer(GovernorLayer {
            config: governor_conf,
        })
        .layer(cors)
        .layer(DefaultBodyLimit::max(1024 * 1024)); // 1MB limit

    let addr = format!("0.0.0.0:{}", port);
    info!(address = %addr, rate_limit = "50 burst / 10 per sec (NodeId/IP keyed)", "Starting verification server");

    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| GhostError::Internal(format!("Failed to bind: {}", e)))?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .map_err(|e| GhostError::Internal(format!("Server error: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::types::NodeCapabilities;
    use ghost_policy::PolicyProfile;

    fn test_secret() -> [u8; 32] {
        let mut secret = [0u8; 32];
        for (i, b) in secret.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0x42);
        }
        secret
    }

    #[test]
    fn test_verification_state_default_requires_auth() {
        let state = VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        );

        // Default should require internal auth
        assert!(state.require_internal_auth);
        assert!(state.internal_auth.is_none());
    }

    #[test]
    fn test_verification_state_with_internal_auth() {
        let secret = test_secret();
        let auth = crate::auth::InternalAuth::new(&secret).unwrap();

        let state = VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        )
        .with_internal_auth(auth);

        assert!(state.internal_auth.is_some());
    }

    #[test]
    fn test_verification_state_allow_insecure_api() {
        let state = VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        )
        .allow_insecure_internal_api(true);

        // Should allow insecure mode
        assert!(!state.require_internal_auth);
        assert!(state.internal_auth.is_none());
    }

    #[tokio::test]
    async fn test_start_server_fails_without_auth() {
        let state = Arc::new(VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        ));

        // Should fail because require_internal_auth is true but internal_auth is None
        let result = start_server(state, 0).await;
        assert!(result.is_err());

        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("VF-C2"));
        assert!(err_msg.contains("Internal API authentication is required"));
    }

    #[test]
    fn test_auth_validation_insecure_mode() {
        // When allow_insecure_internal_api(true) is set, the validation
        // should pass even without auth configured
        let state = VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        )
        .allow_insecure_internal_api(true);

        // The validation logic: require_internal_auth && internal_auth.is_none()
        // With allow_insecure = true: require_internal_auth = false
        // So: false && true = false -> no error
        let should_fail = state.require_internal_auth && state.internal_auth.is_none();
        assert!(!should_fail, "Insecure mode should bypass auth requirement");
    }

    #[test]
    fn test_auth_validation_with_auth_configured() {
        let secret = test_secret();
        let auth = crate::auth::InternalAuth::new(&secret).unwrap();

        let state = VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        )
        .with_internal_auth(auth);

        // The validation logic: require_internal_auth && internal_auth.is_none()
        // With auth configured: internal_auth.is_none() = false
        // So: true && false = false -> no error
        let should_fail = state.require_internal_auth && state.internal_auth.is_none();
        assert!(!should_fail, "Auth configured should pass validation");
    }

    #[test]
    fn test_auth_validation_requires_auth_when_missing() {
        let state = VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        );

        // The validation logic: require_internal_auth && internal_auth.is_none()
        // Default state: require_internal_auth = true, internal_auth = None
        // So: true && true = true -> error
        let should_fail = state.require_internal_auth && state.internal_auth.is_none();
        assert!(should_fail, "Should require auth by default");
    }

    // M-12: CORS origin validation tests
    #[test]
    fn test_cors_origin_valid_https() {
        assert!(is_valid_cors_origin("https://bitcoinghost.org"));
        assert!(is_valid_cors_origin("https://wallet.bitcoinghost.org"));
        assert!(is_valid_cors_origin("https://localhost:8080"));
        assert!(is_valid_cors_origin("https://192.168.1.1:443"));
    }

    #[test]
    fn test_cors_origin_rejects_http() {
        // Must use https:// for security
        assert!(!is_valid_cors_origin("http://bitcoinghost.org"));
        assert!(!is_valid_cors_origin("http://localhost"));
    }

    #[test]
    fn test_cors_origin_rejects_no_scheme() {
        assert!(!is_valid_cors_origin("bitcoinghost.org"));
        assert!(!is_valid_cors_origin("localhost:8080"));
    }

    #[test]
    fn test_cors_origin_rejects_path() {
        // Origins should not have path components
        assert!(!is_valid_cors_origin("https://bitcoinghost.org/api"));
        assert!(!is_valid_cors_origin("https://example.com/path/to/page"));
    }

    #[test]
    fn test_cors_origin_rejects_empty_host() {
        assert!(!is_valid_cors_origin("https://"));
    }

    #[test]
    fn test_cors_origin_rejects_invalid_chars() {
        // Origins with spaces or special chars should be rejected
        assert!(!is_valid_cors_origin("https://example .com"));
        assert!(!is_valid_cors_origin("https://example<script>.com"));
    }

    // L-28: Debug endpoints immutability tests
    #[test]
    fn test_debug_endpoints_frozen_at_startup_disabled() {
        let state = VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        );

        // Default should be disabled
        assert!(!state.debug_endpoints_enabled());
    }

    #[test]
    fn test_debug_endpoints_frozen_at_startup_enabled() {
        let state = VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        )
        .with_debug_endpoints(true);

        // Should be enabled after with_debug_endpoints(true)
        assert!(state.debug_endpoints_enabled());
    }

    #[test]
    fn test_debug_endpoints_immutable_after_set() {
        let state = VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        )
        .with_debug_endpoints(true);

        // Even if someone modifies DashboardConfig, the frozen value should persist
        {
            let mut config = state.dashboard_config.write();
            config.enable_debug_endpoints = false;
        }

        // The frozen value should still be true (from startup)
        assert!(
            state.debug_endpoints_enabled(),
            "L-28: Frozen debug flag should not change after startup"
        );
    }
}
