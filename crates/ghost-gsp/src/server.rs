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
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::api::{rest, websocket};
use crate::auth::{JwtManager, WalletRegistry};
use crate::error::{GspError, GspResult};
use crate::proxy::PayNodeProxy;
use crate::state::{ReorgNotifier, SubscriptionManager};

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
        Self {
            listen_addr: "0.0.0.0:8900".parse().unwrap(),
            network: Network::Regtest,
            data_dir: PathBuf::from("./gsp-data"),
            pay_node_url: "http://127.0.0.1:8800".to_string(),
            jwt_secret: vec![0u8; 32], // Should be randomized in production
            session_expiry_secs: 86400, // 24 hours
            rate_limit_rpm: 60,
            max_ws_connections: 1000,
        }
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
}

/// GSP server
pub struct GspServer {
    state: Arc<GspState>,
    router: Router,
}

impl GspServer {
    /// Create a new GSP server
    pub async fn new(config: GspConfig) -> GspResult<Self> {
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

    #[test]
    fn test_default_config() {
        let config = GspConfig::default();
        assert_eq!(config.listen_addr.port(), 8900);
        assert_eq!(config.network, Network::Regtest);
        assert_eq!(config.session_expiry_secs, 86400);
    }

    #[tokio::test]
    async fn test_state_connection_tracking() {
        let config = GspConfig::default();
        let state = GspState::new(config).unwrap();

        assert!(state.can_accept_connection());
        assert_eq!(*state.connection_count.read(), 0);

        state.add_connection();
        assert_eq!(*state.connection_count.read(), 1);

        state.remove_connection();
        assert_eq!(*state.connection_count.read(), 0);
    }
}
