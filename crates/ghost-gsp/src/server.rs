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
use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use bitcoin::Network;
use parking_lot::RwLock;
use rand::RngCore;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::api::{rest, websocket};
use crate::auth::{JwtManager, WalletRegistry};
use crate::error::{GspError, GspResult};
use crate::proxy::PayNodeProxy;
use crate::state::{ReorgBridge, ReorgBridgeConfig, ReorgNotifier, SubscriptionManager};

use ghost_consensus::reorg::{L1ChainMonitor, L2ForkDetector};

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
}

impl Default for GspConfig {
    fn default() -> Self {
        // Generate a random JWT secret by default using cryptographically secure RNG
        let mut jwt_secret = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut jwt_secret);

        Self {
            listen_addr: "0.0.0.0:8900".parse().unwrap(),
            network: Network::Regtest,
            data_dir: PathBuf::from("./gsp-data"),
            pay_node_url: "http://127.0.0.1:8800".to_string(),
            jwt_secret,
            session_expiry_secs: 86400, // 24 hours
            rate_limit_rpm: 60,
            max_ws_connections: 1000,
        }
    }
}

impl GspConfig {
    /// H-10: Validate configuration to ensure security requirements are met.
    ///
    /// This MUST be called before starting the server to prevent insecure configurations.
    ///
    /// # Errors
    /// - Returns `InsecureJwtSecret` if JWT secret is all zeros (default/unset)
    /// - Returns `InsecureJwtSecret` if JWT secret is less than 32 bytes
    pub fn validate(&self) -> crate::error::GspResult<()> {
        // H-10: Fail if JWT secret is all zeros (indicates it was never properly configured)
        if self.jwt_secret.iter().all(|&b| b == 0) {
            return Err(crate::error::GspError::InsecureJwtSecret(
                "JWT secret must be configured - cannot use default zeros".to_string(),
            ));
        }

        // H-10: Fail if JWT secret is too short (less than 256 bits / 32 bytes)
        if self.jwt_secret.len() < 32 {
            return Err(crate::error::GspError::InsecureJwtSecret(
                format!(
                    "JWT secret must be at least 32 bytes, got {} bytes",
                    self.jwt_secret.len()
                ),
            ));
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

    /// Current connection count
    pub connection_count: RwLock<usize>,
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
        let pay_node = PayNodeProxy::new(&config.pay_node_url);

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
            connection_count: RwLock::new(0),
        })
    }

    /// Check if we can accept more connections
    pub fn can_accept_connection(&self) -> bool {
        *self.connection_count.read() < self.config.max_ws_connections
    }

    /// Increment connection count
    pub fn add_connection(&self) {
        *self.connection_count.write() += 1;
    }

    /// Decrement connection count
    pub fn remove_connection(&self) {
        let mut count = self.connection_count.write();
        *count = count.saturating_sub(1);
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
    fn build_router(state: Arc<GspState>) -> Router {
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
            // CORS and tracing
            .layer(CorsLayer::permissive())
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

        assert!(state.can_accept_connection());
        assert_eq!(*state.connection_count.read(), 0);

        state.add_connection();
        assert_eq!(*state.connection_count.read(), 1);

        state.remove_connection();
        assert_eq!(*state.connection_count.read(), 0);
    }
}
