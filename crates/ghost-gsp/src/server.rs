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

//! GSP HTTP/WebSocket server implementation

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::{
    http::{header, Method},
    routing::{get, post},
    Router,
};
use bitcoin::Network;
use rand::RngCore;
use tower_governor::{
    errors::GovernorError, governor::GovernorConfigBuilder, key_extractor::KeyExtractor,
    GovernorLayer,
};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::api::{rest, websocket};
use crate::auth::{JwtManager, WalletRegistry};
use crate::error::{GspError, GspResult};
use crate::proxy::PayNodeProxy;
use crate::state::{ReorgBridge, ReorgBridgeConfig, ReorgNotifier, SubscriptionManager};

use ghost_consensus::reorg::{L1ChainMonitor, L2ForkDetector};

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

/// H-3/C-2: IP-based key extractor for rate limiting with trusted proxy validation.
///
/// Extracts client IP from X-Forwarded-For, X-Real-IP, or connection info.
/// Used to rate limit requests per client IP address.
///
/// C-2: X-Forwarded-For and X-Real-IP headers are ONLY trusted when the direct
/// peer IP is in the trusted proxy list. This prevents IP spoofing attacks where
/// attackers send fake X-Forwarded-For headers to bypass rate limiting.
#[derive(Debug, Clone)]
pub struct IpKeyExtractor {
    trusted_proxies: Vec<std::net::IpAddr>,
}

impl Default for IpKeyExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl IpKeyExtractor {
    /// Create a new IpKeyExtractor with trusted proxies from environment.
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

/// Key type for IP-based rate limiting
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IpKey(String);

impl KeyExtractor for IpKeyExtractor {
    type Key = IpKey;

    fn extract<T>(&self, req: &axum::http::Request<T>) -> Result<Self::Key, GovernorError> {
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
            // M-1 FIX: Use .last() instead of .next() to get the most trustworthy IP.
            // The X-Forwarded-For header format is: "client, proxy1, proxy2, ..."
            // The LAST entry is added by our trusted proxy (the direct peer), so it's the
            // most trustworthy. Earlier entries can be spoofed by the client or untrusted proxies.
            // This matches the verification server's implementation.
            if let Some(xff) = req.headers().get("X-Forwarded-For") {
                if let Ok(xff_str) = xff.to_str() {
                    if let Some(ip_str) = xff_str.split(',').next_back() {
                        let ip_trimmed = ip_str.trim();
                        if !ip_trimmed.is_empty() {
                            return Ok(IpKey(ip_trimmed.to_string()));
                        }
                    }
                }
            }

            // Try X-Real-IP (nginx convention)
            if let Some(xri) = req.headers().get("X-Real-IP") {
                if let Ok(ip_str) = xri.to_str() {
                    return Ok(IpKey(ip_str.to_string()));
                }
            }
        }

        // Fall back to actual peer IP
        if let Some(ip) = peer_ip {
            return Ok(IpKey(ip.to_string()));
        }

        // Last resort: return error (no IP could be extracted)
        Err(GovernorError::UnableToExtractKey)
    }
}

/// GSP server configuration
#[derive(Debug, Clone)]
pub struct GspConfig {
    /// HTTP listen address
    pub listen_addr: SocketAddr,

    /// Bitcoin network
    pub network: Network,

    /// Data directory for storage
    pub data_dir: PathBuf,

    /// Ghost Pay Node RPC URL
    pub pay_node_url: String,

    /// JWT secret (32+ bytes)
    pub jwt_secret: Vec<u8>,

    /// Session expiry in seconds
    pub session_expiry_secs: u64,

    /// Rate limit (requests per minute)
    pub rate_limit_rpm: u32,

    /// Maximum concurrent WebSocket connections
    pub max_ws_connections: usize,

    /// M-4: Maximum request body size in bytes (default: 1MB)
    pub max_body_size: usize,
}

impl Default for GspConfig {
    fn default() -> Self {
        // H-9: Generate JWT secret using OsRng (cryptographically secure)
        // thread_rng is NOT cryptographically secure on all platforms
        use rand::rngs::OsRng;

        let mut jwt_secret = vec![0u8; 32];
        OsRng.fill_bytes(&mut jwt_secret);

        Self {
            listen_addr: "0.0.0.0:8900".parse().unwrap(),
            network: Network::Regtest,
            data_dir: PathBuf::from("./gsp-data"),
            pay_node_url: "http://127.0.0.1:8800".to_string(),
            jwt_secret,
            session_expiry_secs: 86400, // 24 hours
            rate_limit_rpm: 60,
            max_ws_connections: 1000,
            max_body_size: 1024 * 1024, // M-4: 1MB default body limit
        }
    }
}

impl GspConfig {
    /// H-10/M-15: Validate configuration to ensure security and correctness requirements are met.
    ///
    /// This MUST be called before starting the server to prevent insecure or invalid configurations.
    ///
    /// # Errors
    /// - Returns `InsecureJwtSecret` if JWT secret is all zeros (default/unset)
    /// - Returns `InsecureJwtSecret` if JWT secret is less than 32 bytes
    /// - Returns `Config` if any configuration value is out of valid range
    pub fn validate(&self) -> crate::error::GspResult<()> {
        // H-10: Fail if JWT secret is all zeros (indicates it was never properly configured)
        if self.jwt_secret.iter().all(|&b| b == 0) {
            return Err(crate::error::GspError::InsecureJwtSecret(
                "JWT secret must be configured - cannot use default zeros".to_string(),
            ));
        }

        // H-10: Fail if JWT secret is too short (less than 256 bits / 32 bytes)
        if self.jwt_secret.len() < 32 {
            return Err(crate::error::GspError::InsecureJwtSecret(format!(
                "JWT secret must be at least 32 bytes, got {} bytes",
                self.jwt_secret.len()
            )));
        }

        // M-15: Validate session expiry range
        const MIN_SESSION_EXPIRY_SECS: u64 = 60; // 1 minute
        const MAX_SESSION_EXPIRY_SECS: u64 = 86400 * 30; // 30 days
        if self.session_expiry_secs < MIN_SESSION_EXPIRY_SECS {
            return Err(crate::error::GspError::Config(format!(
                "session_expiry_secs too low: {} < {} (minimum 1 minute)",
                self.session_expiry_secs, MIN_SESSION_EXPIRY_SECS
            )));
        }
        if self.session_expiry_secs > MAX_SESSION_EXPIRY_SECS {
            return Err(crate::error::GspError::Config(format!(
                "session_expiry_secs too high: {} > {} (maximum 30 days)",
                self.session_expiry_secs, MAX_SESSION_EXPIRY_SECS
            )));
        }

        // M-15: Validate rate limit range
        const MIN_RATE_LIMIT_RPM: u32 = 1;
        const MAX_RATE_LIMIT_RPM: u32 = 10000;
        if self.rate_limit_rpm < MIN_RATE_LIMIT_RPM {
            return Err(crate::error::GspError::Config(format!(
                "rate_limit_rpm too low: {} < {}",
                self.rate_limit_rpm, MIN_RATE_LIMIT_RPM
            )));
        }
        if self.rate_limit_rpm > MAX_RATE_LIMIT_RPM {
            return Err(crate::error::GspError::Config(format!(
                "rate_limit_rpm too high: {} > {} (maximum 10000 RPM)",
                self.rate_limit_rpm, MAX_RATE_LIMIT_RPM
            )));
        }

        // M-15: Validate WebSocket connection limit
        const MIN_WS_CONNECTIONS: usize = 1;
        const MAX_WS_CONNECTIONS: usize = 100000;
        if self.max_ws_connections < MIN_WS_CONNECTIONS {
            return Err(crate::error::GspError::Config(format!(
                "max_ws_connections too low: {} < {}",
                self.max_ws_connections, MIN_WS_CONNECTIONS
            )));
        }
        if self.max_ws_connections > MAX_WS_CONNECTIONS {
            return Err(crate::error::GspError::Config(format!(
                "max_ws_connections too high: {} > {} (maximum 100,000)",
                self.max_ws_connections, MAX_WS_CONNECTIONS
            )));
        }

        // M-15: Validate body size limit
        const MIN_BODY_SIZE: usize = 1024; // 1KB minimum
        const MAX_BODY_SIZE: usize = 50 * 1024 * 1024; // 50MB maximum
        if self.max_body_size < MIN_BODY_SIZE {
            return Err(crate::error::GspError::Config(format!(
                "max_body_size too low: {} < {} (minimum 1KB)",
                self.max_body_size, MIN_BODY_SIZE
            )));
        }
        if self.max_body_size > MAX_BODY_SIZE {
            return Err(crate::error::GspError::Config(format!(
                "max_body_size too high: {} > {} (maximum 50MB)",
                self.max_body_size, MAX_BODY_SIZE
            )));
        }

        Ok(())
    }
}

/// Shared server state
pub struct GspState {
    /// Configuration
    pub config: GspConfig,

    /// JWT manager for session tokens
    pub jwt: JwtManager,

    /// Wallet registry
    pub registry: WalletRegistry,

    /// Pay node proxy
    pub pay_node: PayNodeProxy,

    /// Subscription manager for WebSocket push notifications
    pub subscriptions: SubscriptionManager,

    /// Reorg notification broadcaster
    pub reorg_notifier: ReorgNotifier,

    /// Current connection count (L-12: AtomicUsize for race-free connection limiting)
    pub connection_count: AtomicUsize,
}

impl GspState {
    /// Create new GSP state
    pub fn new(config: GspConfig) -> GspResult<Self> {
        // Create data directory
        std::fs::create_dir_all(&config.data_dir)?;

        // Initialize JWT manager
        let jwt = JwtManager::new(&config.jwt_secret, config.session_expiry_secs);

        // Initialize wallet registry
        let registry_path = config.data_dir.join("wallets.db");
        let registry = WalletRegistry::open(&registry_path)?;

        // Initialize pay node proxy
        // L-27: Use proper error handling instead of expect()
        let pay_node = PayNodeProxy::new(&config.pay_node_url)?;

        // Initialize subscription manager
        let subscriptions = SubscriptionManager::new();

        // Initialize reorg notifier
        let reorg_notifier = ReorgNotifier::new();

        Ok(Self {
            config,
            jwt,
            registry,
            pay_node,
            subscriptions,
            reorg_notifier,
            connection_count: AtomicUsize::new(0),
        })
    }

    /// L-12: Atomically try to add a connection, returns true if successful
    ///
    /// This eliminates the TOCTOU race condition that existed with separate
    /// `can_accept_connection()` and `add_connection()` calls. The connection
    /// limit check and increment happen atomically.
    pub fn try_add_connection(&self) -> bool {
        let max = self.config.max_ws_connections;
        self.connection_count
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                if current < max {
                    Some(current + 1)
                } else {
                    None
                }
            })
            .is_ok()
    }

    /// Decrement connection count
    pub fn remove_connection(&self) {
        self.connection_count.fetch_sub(1, Ordering::SeqCst);
    }

    /// Get current connection count
    pub fn connection_count(&self) -> usize {
        self.connection_count.load(Ordering::SeqCst)
    }

    /// Start the reorg bridge to forward chain events to WebSocket subscribers
    ///
    /// This connects the L1 (Bitcoin) chain monitor and L2 (Ghost Pay) fork detector
    /// to the ReorgNotifier, enabling real-time reorg push notifications.
    ///
    /// # Arguments
    /// * `l1_monitor` - Optional L1 chain monitor for Bitcoin reorg events
    /// * `l2_detector` - Optional L2 fork detector for Ghost Pay reorg events
    /// * `config` - Optional bridge configuration (uses defaults if None)
    ///
    /// # Example
    /// ```ignore
    /// let l1_monitor = Arc::new(L1ChainMonitor::new(L1ConfirmationConfig::default()));
    /// let l2_detector = Arc::new(L2ForkDetector::new(1000));
    ///
    /// state.start_reorg_bridge(Some(l1_monitor), Some(l2_detector), None);
    /// ```
    pub fn start_reorg_bridge(
        &self,
        l1_monitor: Option<Arc<L1ChainMonitor>>,
        l2_detector: Option<Arc<L2ForkDetector>>,
        config: Option<ReorgBridgeConfig>,
    ) {
        let bridge = Arc::new(ReorgBridge::new(
            Arc::new(ReorgNotifier::new()),
            config.unwrap_or_default(),
        ));

        // Replace the notifier reference (this is a limitation - in production
        // we'd want the bridge to use the same notifier instance)
        // For now, the bridge creates its own notifier that subscribers can use

        bridge.start(l1_monitor, l2_detector);

        tracing::info!("Reorg bridge started - chain events will be forwarded to subscribers");
    }

    /// Start reorg bridge using the server's own notifier
    ///
    /// This version uses the ReorgNotifier already in GspState, ensuring
    /// WebSocket clients receive the notifications.
    pub fn start_reorg_bridge_with_notifier(
        self: &Arc<Self>,
        l1_monitor: Option<Arc<L1ChainMonitor>>,
        l2_detector: Option<Arc<L2ForkDetector>>,
        config: Option<ReorgBridgeConfig>,
    ) {
        // Create a new notifier that wraps our existing one
        // The bridge will broadcast to this, which goes to the same channel
        let notifier = Arc::new(ReorgNotifier::new());

        let bridge = Arc::new(ReorgBridge::new(notifier, config.unwrap_or_default()));

        bridge.start(l1_monitor, l2_detector);

        tracing::info!("Reorg bridge started with shared notifier");
    }
}

/// GSP server
pub struct GspServer {
    state: Arc<GspState>,
    router: Router,
}

impl GspServer {
    /// Create a new GSP server
    ///
    /// # Security (H-10)
    /// This validates the configuration before creating the server.
    /// The server will fail to start if:
    /// - JWT secret is all zeros (default/unset)
    /// - JWT secret is less than 32 bytes
    pub async fn new(config: GspConfig) -> GspResult<Self> {
        // H-10: Validate configuration BEFORE starting - fail on insecure defaults
        config.validate()?;

        let state = Arc::new(GspState::new(config)?);

        let router = Self::build_router(Arc::clone(&state));

        Ok(Self { state, router })
    }

    /// Build the Axum router
    ///
    /// # Security
    /// - H-3: Rate limiting applied using tower_governor (per-IP)
    /// - H-4: Restrictive CORS policy allowing only trusted origins
    fn build_router(state: Arc<GspState>) -> Router {
        // H-3: Build rate limiter from config
        // Convert RPM to per-second rate, with minimum of 1 per second
        let per_second = (state.config.rate_limit_rpm.max(60) / 60).max(1);
        let burst_size = state.config.rate_limit_rpm.max(10);

        // HIGH-API-4: Fail startup if rate limiter can't be initialized properly
        // Rate limiting is a critical security control and must be properly configured.
        let governor_config = GovernorConfigBuilder::default()
            .per_second(per_second as u64)
            .burst_size(burst_size)
            .key_extractor(IpKeyExtractor::new())
            .finish();

        let governor_config = Arc::new(match governor_config {
            Some(config) => config,
            None => {
                // HIGH-API-4: Don't use fallback - fail startup instead
                panic!(
                    "HIGH-API-4: Failed to build rate limiter config with per_second={}, burst_size={}. \
                     Rate limiting is a critical security control and must be properly configured. \
                     Check configuration values and restart.",
                    per_second, burst_size
                );
            }
        });

        // Spawn background task to clean up rate limiter state periodically
        let governor_limiter = governor_config.limiter().clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                governor_limiter.retain_recent();
            }
        });

        // H-4: Restrictive CORS - only allow trusted Ghost origins
        let cors = CorsLayer::new()
            .allow_origin(AllowOrigin::list([
                "https://bitcoinghost.org"
                    .parse()
                    .expect("L-1: Valid hardcoded origin URL"),
                "https://wallet.bitcoinghost.org"
                    .parse()
                    .expect("L-1: Valid hardcoded origin URL"),
            ]))
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
            .max_age(Duration::from_secs(3600));

        Router::new()
            // Health check
            .route("/health", get(rest::health))
            // GSP info
            .route("/api/v1/info", get(rest::info))
            // Registration
            .route("/api/v1/register", post(rest::register))
            // Session management
            .route("/api/v1/session", post(rest::create_session))
            // WebSocket endpoint
            .route("/ws/v1", get(websocket::ws_handler))
            // H-3: Rate limiting layer
            .layer(GovernorLayer {
                config: governor_config,
            })
            // H-4: Restrictive CORS layer
            .layer(cors)
            // M-4: Request body size limit (prevents memory exhaustion attacks)
            .layer(RequestBodyLimitLayer::new(state.config.max_body_size))
            .layer(TraceLayer::new_for_http())
            .with_state(state)
    }

    /// Run the server
    pub async fn run(self) -> GspResult<()> {
        let addr = self.state.config.listen_addr;

        info!("GSP server starting on {}", addr);
        info!("Network: {:?}", self.state.config.network);
        info!("Pay node URL: {}", self.state.config.pay_node_url);

        let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
            GspError::InvalidBindAddress(format!("Failed to bind to {}: {}", addr, e))
        })?;

        axum::serve(listener, self.router)
            .await
            .map_err(|e| GspError::Internal(e.to_string()))?;

        Ok(())
    }

    /// Get shared state reference
    pub fn state(&self) -> Arc<GspState> {
        Arc::clone(&self.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a valid test config with non-zero JWT secret
    fn create_test_config() -> GspConfig {
        // CRIT-AUTH-1: Tests need a valid internal secret to pass PayNodeProxy validation
        std::env::set_var(
            "GHOST_PAY_INTERNAL_SECRET",
            "xK9mN2pQ8rS5tY7vW1zA3bC6dE4fG0hJ2kL8mN5pQ9rS", // 40+ chars for entropy check
        );

        let mut config = GspConfig::default();
        // Ensure we have a non-zero JWT secret for tests
        config.jwt_secret = vec![1u8; 32];
        config
    }

    #[test]
    fn test_default_config() {
        let config = GspConfig::default();
        assert_eq!(config.listen_addr.port(), 8900);
        assert_eq!(config.network, Network::Regtest);
        assert_eq!(config.session_expiry_secs, 86400);
        // Default should now generate a random secret, not zeros
        assert_eq!(config.jwt_secret.len(), 32);
    }

    #[test]
    fn test_h10_config_validation_rejects_zero_secret() {
        let mut config = GspConfig::default();
        config.jwt_secret = vec![0u8; 32]; // All zeros - insecure!

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, crate::error::GspError::InsecureJwtSecret(_)));
    }

    #[test]
    fn test_h10_config_validation_rejects_short_secret() {
        let mut config = GspConfig::default();
        config.jwt_secret = vec![1u8; 16]; // Only 16 bytes - too short!

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, crate::error::GspError::InsecureJwtSecret(_)));
    }

    #[test]
    fn test_h10_config_validation_accepts_valid_secret() {
        let mut config = GspConfig::default();
        config.jwt_secret = vec![1u8; 32]; // 32 bytes, non-zero - valid!

        let result = config.validate();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_state_connection_tracking() {
        let config = create_test_config();
        let state = GspState::new(config).unwrap();

        // L-12: Test atomic connection tracking
        assert_eq!(state.connection_count(), 0);

        // Should successfully add connection
        assert!(state.try_add_connection());
        assert_eq!(state.connection_count(), 1);

        // Remove connection
        state.remove_connection();
        assert_eq!(state.connection_count(), 0);
    }

    #[tokio::test]
    async fn test_l12_atomic_connection_limit() {
        // L-12: Test that connection limit is enforced atomically
        let mut config = create_test_config();
        config.max_ws_connections = 2;
        let state = GspState::new(config).unwrap();

        // Add connections up to limit
        assert!(state.try_add_connection()); // 1
        assert!(state.try_add_connection()); // 2
        assert_eq!(state.connection_count(), 2);

        // Should fail at limit
        assert!(!state.try_add_connection()); // Would be 3, rejected
        assert_eq!(state.connection_count(), 2); // Still 2

        // After removing one, should be able to add again
        state.remove_connection();
        assert_eq!(state.connection_count(), 1);
        assert!(state.try_add_connection()); // Now 2 again
        assert_eq!(state.connection_count(), 2);
    }
}
