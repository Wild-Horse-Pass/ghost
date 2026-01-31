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
use ghost_common::error::{GhostError, GhostResult};
use ghost_common::identity::NodeIdentity;
use ghost_common::rpc::BitcoinRpc;
use ghost_common::types::NodeCapabilities;
use ghost_policy::{PolicyEngine, PolicyProfile};
use ghost_storage::Database;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::NodeConfig;
use tokio::net::TcpListener;
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor, GovernorLayer,
};
use tower_http::cors::CorsLayer;
use tracing::info;

use crate::challenge::*;
use crate::routes::create_router;
use crate::websocket::WsState;

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
}

/// Callback for recording shares (from SRI Pool notifications)
pub type RecordShareFn = Arc<dyn Fn(ShareNotification) -> GhostResult<()> + Send + Sync>;

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
    /// Node config with disk persistence (ghost_mode, etc.)
    pub node_config: parking_lot::RwLock<NodeConfig>,
    /// Path to node config file
    pub node_config_path: Option<PathBuf>,
    /// WebSocket state for real-time updates
    pub ws_state: Arc<WsState>,
    /// Test proposal callback (for admin testing)
    test_proposal_fn: Option<TestProposalFn>,
    /// Share recording callback (from SRI Pool notifications)
    record_share_fn: Option<RecordShareFn>,
}

/// Archive handler trait
pub trait ArchiveHandler {
    fn get_block(&self, hash: &str) -> GhostResult<Option<BlockData>>;
    fn get_transaction(&self, txid: &str) -> GhostResult<Option<TxData>>;
    fn has_block_at_height(&self, height: u64) -> bool;
}

/// GhostPay handler trait
pub trait GhostPayHandler {
    fn is_enabled(&self) -> bool;
    fn get_virtual_block(&self) -> u64;
    fn get_epoch(&self) -> u64;
    fn get_balance(&self, address: &str) -> GhostResult<u64>;
    fn is_wraith_enabled(&self) -> bool;
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
            stratum_sv2_port: 34255,
            stratum_sv1_port: 3333,
            database: None,
            rpc: None,
            dashboard_config: parking_lot::RwLock::new(dashboard_config),
            node_config: parking_lot::RwLock::new(NodeConfig::default()),
            node_config_path: None,
            ws_state: Arc::new(WsState::new()),
            test_proposal_fn: None,
            record_share_fn: None,
        }
    }

    /// Set share recording callback (for SRI Pool share notifications)
    pub fn with_share_recorder<F>(mut self, recorder: F) -> Self
    where
        F: Fn(ShareNotification) -> GhostResult<()> + Send + Sync + 'static,
    {
        self.record_share_fn = Some(Arc::new(recorder));
        self
    }

    /// Record a share (called from HTTP endpoint)
    pub fn record_share(&self, share: ShareNotification) -> GhostResult<()> {
        if let Some(ref recorder) = self.record_share_fn {
            recorder(share)
        } else {
            Err(GhostError::Internal("Share recorder not configured".to_string()))
        }
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
    pub async fn verify_stratum(
        &self,
        challenge: StratumChallenge,
    ) -> GhostResult<StratumResponse> {
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

        // Try to connect to the port
        let start = Instant::now();
        let addr = format!("127.0.0.1:{}", port);

        match tokio::net::TcpStream::connect(&addr).await {
            Ok(_) => {
                let latency = start.elapsed().as_millis() as u32;
                Ok(StratumResponse {
                    success: true,
                    port,
                    protocol: challenge.protocol,
                    connected: true,
                    latency_ms: Some(latency),
                    error: None,
                })
            }
            Err(e) => Ok(StratumResponse {
                success: false,
                port,
                protocol: challenge.protocol,
                connected: false,
                latency_ms: None,
                error: Some(format!("Connection failed: {}", e)),
            }),
        }
    }

    /// Verify GhostPay challenge
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
                    error: Some("Ghost Pay handler not configured".to_string()),
                });
            }
        };

        let balance = if let Some(address) = &challenge.address {
            Some(handler.get_balance(address)?)
        } else {
            None
        };

        Ok(GhostPayResponse {
            success: true,
            l2_enabled: handler.is_enabled(),
            virtual_block: Some(handler.get_virtual_block()),
            epoch: Some(handler.get_epoch()),
            balance_sats: balance,
            wraith_enabled: handler.is_wraith_enabled(),
            error: None,
        })
    }
}

/// Start verification server
pub async fn start_server(state: Arc<VerificationState>, port: u16) -> GhostResult<()> {
    // CORS configuration - permissive for node dashboard access
    // The dashboard runs on port 3000 on the same machine and needs to access the API on 8080.
    // Since nodes may have various IP addresses, we allow any origin for API access.
    // The API itself is protected by rate limiting and authentication where needed.
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::header::ACCEPT,
        ])
        .max_age(Duration::from_secs(3600));

    // Rate limiting configuration
    // - 50 requests per second burst capacity
    // - Refills at 10 requests per second
    // - Per IP address rate limiting
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(10)
            .burst_size(50)
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("valid governor config"),
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
    // - Rate limiting: 50 req/s burst, 10 req/s sustained per IP
    // - CORS: restrict to allowed origins
    // - Request body limit: 1MB max to prevent DoS
    let app = create_router(state)
        .layer(GovernorLayer {
            config: governor_conf,
        })
        .layer(cors)
        .layer(DefaultBodyLimit::max(1024 * 1024)); // 1MB limit

    let addr = format!("0.0.0.0:{}", port);
    info!(address = %addr, rate_limit = "50 burst / 10 per sec", "Starting verification server");

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
