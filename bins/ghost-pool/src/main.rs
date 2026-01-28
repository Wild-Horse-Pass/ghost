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
//| FILE: main.rs                                                                                                        |
//|======================================================================================================================|

//! Ghost Pool - Bitcoin Ghost Mining Pool Node
//!
//! Main entry point for the Ghost Pool node. This is a complete mining pool
//! implementation featuring:
//!
//! - Stratum V2 server for miner connections
//! - BUDS-based transaction filtering
//! - Pre-consensus coinbase construction
//! - P2P mesh network for share propagation
//! - 67% BFT consensus for payouts
//!
//! Run with: ghost-pool --config ghost.toml

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use ghost_common::config::NodeConfig;
use ghost_common::identity::NodeIdentity;
use ghost_common::rpc::BitcoinRpc;
use ghost_common::types::{ConsensusResult, NodeCapabilities};
use ghost_common::zmq::{ZmqConfig, ZmqSubscriber};
use ghost_consensus::mesh::{MeshConfig, MeshNetwork};
use ghost_consensus::message::MessageType;
use ghost_consensus::health_handler::HealthPingHandler;
use ghost_consensus::vote_handler::{BroadcastFn, ExecuteFn, VoteHandler};
use ghost_consensus::voting::VotingManager;
use ghost_policy::PolicyProfile;
use ghost_storage::Database;
use ghost_verification::{start_server, RpcArchiveHandler, VerificationState};

use ghost_pool::payout::{BlockFoundData, PayoutConfig, PayoutHandler};
use ghost_pool::reorg::{ReorgConfig, ReorgHandler};
use ghost_pool::round::{RoundConfig, RoundEvent, RoundManager};
use ghost_pool::stratum::{JobNotification, StratumConfig, StratumEvent, StratumServer, VardiffController};
use ghost_pool::template::{TemplateConfig, TemplateEvent, TemplateProcessor};

/// Ghost Pool - Decentralized Bitcoin Mining Pool
#[derive(Parser, Debug)]
#[command(name = "ghost-pool")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "ghost.toml")]
    config: PathBuf,

    /// Data directory
    #[arg(short, long, default_value = "~/.ghost")]
    data_dir: PathBuf,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Generate new node identity
    #[arg(long)]
    generate_identity: bool,

    /// Show node identity and exit
    #[arg(long)]
    show_identity: bool,

    /// Bitcoin RPC host override
    #[arg(long)]
    rpc_host: Option<String>,

    /// Bitcoin RPC port override
    #[arg(long)]
    rpc_port: Option<u16>,

    /// Stratum listen port override
    #[arg(long)]
    stratum_port: Option<u16>,
}

/// Pool state shared across components
pub struct PoolState {
    /// Node identity
    pub identity: Arc<NodeIdentity>,
    /// Node capabilities
    pub capabilities: NodeCapabilities,
    /// Policy profile
    pub policy: PolicyProfile,
    /// Bitcoin RPC client
    pub rpc: Arc<BitcoinRpc>,
    /// Database
    pub db: Arc<Database>,
    /// Round manager
    pub round_manager: Arc<RoundManager>,
    /// Template processor
    pub template_processor: Arc<TemplateProcessor>,
    /// Stratum server
    pub stratum_server: Arc<StratumServer>,
    /// P2P mesh network
    pub mesh: Arc<MeshNetwork>,
    /// Vote handler for consensus
    pub vote_handler: Arc<VoteHandler>,
    /// Shutdown signal
    pub shutdown_tx: broadcast::Sender<()>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Setup logging
    let level = match args.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");

    // Expand data directory
    let data_dir = expand_path(&args.data_dir)?;
    std::fs::create_dir_all(&data_dir)?;

    // Handle identity commands
    let key_path = data_dir.join("node.key");

    if args.generate_identity {
        info!("Generating new node identity...");
        let identity = NodeIdentity::generate();
        identity.save(&key_path)?;
        info!("Node ID: {}", identity.node_id_hex());
        info!("Key saved to: {}", key_path.display());
        return Ok(());
    }

    // Load or create identity
    let identity = if key_path.exists() {
        NodeIdentity::load(&key_path)?
    } else {
        info!("No identity found, generating new one...");
        let identity = NodeIdentity::generate();
        identity.save(&key_path)?;
        identity
    };

    if args.show_identity {
        println!("Node ID: {}", identity.node_id_hex());
        println!("Short ID: {}", identity.node_id_short());
        return Ok(());
    }

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║              Ghost Pool v{}                           ║", env!("CARGO_PKG_VERSION"));
    info!("║          Decentralized Bitcoin Mining Pool                   ║");
    info!("╚══════════════════════════════════════════════════════════════╝");
    info!("Node ID: {}", identity.node_id_short());

    // Load configuration
    let config = load_config(&args.config)?;

    // Validate configuration
    let validation = config.validate();

    // Log warnings
    for warning in &validation.warnings {
        warn!("{}", warning);
    }

    // Check for errors
    if !validation.is_valid() {
        error!("Configuration validation failed:");
        for err in &validation.errors {
            error!("  {}", err);
        }
        return Err(anyhow::anyhow!(
            "Configuration validation failed with {} error(s)",
            validation.errors.len()
        ));
    }

    info!("Configuration validated ({} warning(s))", validation.warnings.len());

    // Override config with CLI args
    let rpc_host = args.rpc_host.as_ref().unwrap_or(&config.bitcoin.rpc_host);
    let rpc_port = args.rpc_port.unwrap_or(config.bitcoin.rpc_port);

    // Initialize Bitcoin RPC
    info!("Connecting to Bitcoin Core at {}:{}", rpc_host, rpc_port);
    let rpc = Arc::new(BitcoinRpc::new(
        rpc_host,
        rpc_port,
        &config.bitcoin.rpc_user,
        &config.bitcoin.rpc_password,
    )?);

    // Test RPC connection
    match rpc.get_blockchain_info().await {
        Ok(info) => {
            info!(
                chain = %info.chain,
                height = info.blocks,
                difficulty = info.difficulty,
                "Connected to Bitcoin Core"
            );
        }
        Err(e) => {
            error!(error = %e, "Failed to connect to Bitcoin Core");
            return Err(anyhow::anyhow!("Bitcoin RPC connection failed: {}", e));
        }
    }

    // Initialize database
    let db_path = data_dir.join("ghost.db");
    let db = Arc::new(Database::open(&db_path)?);
    info!("Database opened: {}", db_path.display());

    // Setup policy profile
    let policy = match config.policy.profile {
        ghost_common::config::PolicyProfile::BitcoinPure => PolicyProfile::bitcoin_pure(),
        ghost_common::config::PolicyProfile::Permissive => PolicyProfile::permissive(),
        ghost_common::config::PolicyProfile::FullOpen => PolicyProfile::full_open(),
        ghost_common::config::PolicyProfile::Custom => PolicyProfile::permissive(),
    };
    info!("Policy profile: {} (allows up to T{})", policy.name, policy.highest_allowed_tier().map(|t| t as u8).unwrap_or(0));

    // Setup capabilities - initially with elder_status = false
    // We'll update after registering with the database
    let mut capabilities = NodeCapabilities {
        archive_mode: config.storage.archive_mode,
        ghost_pay: config.ghost_pay.is_some(),
        public_mining: config.network.public_mining,
        bitcoin_pure: matches!(config.policy.profile, ghost_common::config::PolicyProfile::BitcoinPure),
        elder_status: false,
    };

    // Register node with database and check if we should be an elder
    // First 101 nodes to register become elders automatically
    let node_id_hex = identity.node_id_hex();
    let public_address = config.network.public_address.as_deref();
    let display_name = config.identity.display_name.as_deref();
    let capabilities_str = format!(
        "archive:{},ghost_pay:{},public_mining:{},bitcoin_pure:{}",
        capabilities.archive_mode, capabilities.ghost_pay,
        capabilities.public_mining, capabilities.bitcoin_pure
    );

    match db.register_node_with_elder_check(&node_id_hex, public_address, display_name, &capabilities_str) {
        Ok((is_elder, elder_order)) => {
            capabilities.elder_status = is_elder;
            if is_elder {
                info!("Node registered as Elder #{}", elder_order.unwrap_or(0));
            } else {
                info!("Node registered (non-elder, {} elders already exist)",
                    db.get_elder_count().unwrap_or(0));
            }
        }
        Err(e) => {
            warn!("Failed to register node for elder check: {} - defaulting to non-elder", e);
        }
    }

    info!("Capability shares: {}/15", capabilities.total_shares());

    // Create identity Arc
    let identity = Arc::new(identity);

    // Initialize round manager
    let round_config = RoundConfig::default();
    let round_manager = Arc::new(RoundManager::new(
        identity.node_id(),
        round_config,
    ));

    // Initialize template processor with treasury and pool payout addresses from config
    // Pool payout address defaults to treasury address if not explicitly configured separately
    let template_config = TemplateConfig {
        treasury_address: config.pool.treasury_address.clone(),
        pool_payout_address: config.pool.treasury_address.clone(), // Use same as treasury for now
        network: config.bitcoin.network.clone(),
        ..Default::default()
    };
    let template_processor = Arc::new(TemplateProcessor::new(
        template_config,
        Arc::clone(&rpc),
        policy.clone(),
    ));

    // Initialize Stratum server
    let stratum_port = args.stratum_port.unwrap_or(config.network.sv2_port);
    let stratum_config = StratumConfig {
        listen_addr: format!("0.0.0.0:{}", stratum_port).parse()?,
        ..Default::default()
    };
    let vardiff_target_secs = stratum_config.vardiff_target_secs; // Save before move
    let stratum_server = Arc::new(StratumServer::new(
        stratum_config,
        Arc::clone(&round_manager),
    ));

    // Initialize P2P mesh
    let mesh_config = MeshConfig {
        public_address: config.network.public_address.clone().unwrap_or_else(|| "127.0.0.1".to_string()),
        ports: config.network.p2p.clone(),
        ..Default::default()
    };
    let mesh = Arc::new(MeshNetwork::new(
        Arc::clone(&identity),
        mesh_config,
    ));

    // Initialize consensus voting
    let voting_manager = Arc::new(VotingManager::new(100)); // 100 max sessions

    // Create broadcast callback for vote propagation
    let mesh_for_broadcast = Arc::clone(&mesh);
    let broadcast_fn: BroadcastFn = Arc::new(move |msg_type: MessageType, payload: Vec<u8>| {
        // Clone mesh for async context
        let mesh = Arc::clone(&mesh_for_broadcast);
        // Broadcast synchronously (mesh handles async internally)
        mesh.broadcast_sync(msg_type, payload)
    });

    // Create execute callback for consensus decisions
    let tp_for_execute = Arc::clone(&template_processor);
    let execute_fn: ExecuteFn = Arc::new(move |result: ConsensusResult| {
        match result {
            ConsensusResult::Approved { proposal_hash, approval_count, total_nodes } => {
                info!(
                    hash = %hex::encode(&proposal_hash[..8]),
                    approvals = approval_count,
                    total = total_nodes,
                    "Payout consensus approved - executing"
                );
                // Store approved payout for coinbase construction
                // The template processor will use this when building the next block
                tp_for_execute.set_approved_payout(proposal_hash);
            }
            ConsensusResult::Rejected { proposal_hash, rejection_count, reason, .. } => {
                warn!(
                    hash = %hex::encode(&proposal_hash[..8]),
                    rejections = rejection_count,
                    reason = ?reason,
                    "Payout consensus rejected"
                );
            }
            ConsensusResult::Timeout { proposal_hash, approvals, rejections, .. } => {
                warn!(
                    hash = %hex::encode(&proposal_hash[..8]),
                    approvals = approvals,
                    rejections = rejections,
                    "Payout consensus timed out"
                );
            }
            ConsensusResult::Error(msg) => {
                error!(error = %msg, "Consensus error");
            }
        }
        Ok(())
    });

    // Create vote handler with callbacks
    let vote_handler = Arc::new(
        VoteHandler::new(Arc::clone(&identity), Arc::clone(&voting_manager))
            .with_broadcaster(broadcast_fn)
            .with_executor(execute_fn)
    );

    // Populate elders from database for BFT voting
    match db.get_elders() {
        Ok(elders) => {
            for elder in &elders {
                // Parse node_id hex to bytes
                if let Ok(node_id_bytes) = hex::decode(&elder.node_id) {
                    if node_id_bytes.len() == 32 {
                        let mut node_id = [0u8; 32];
                        node_id.copy_from_slice(&node_id_bytes);
                        vote_handler.add_elder(node_id);
                    }
                }
            }
            info!("Registered {} elders from database for BFT voting", elders.len());
        }
        Err(e) => {
            warn!("Failed to load elders for voting: {}", e);
        }
    }

    // Register ourselves as a voter - ALL active nodes participate in BFT consensus
    // (elder_status is just a capability flag indicating uptime/reliability, not a voting requirement)
    vote_handler.add_elder(identity.node_id());
    info!("Registered self as BFT voter");
    info!("Initial voters for BFT: {} (peer discovery will add more from HealthPing)", vote_handler.elder_count());

    // Register vote handler with mesh for incoming vote messages
    mesh.register_handler(Arc::clone(&vote_handler) as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>);

    // Create and register health ping handler for peer tracking and voter discovery
    // ALL active nodes participate in BFT consensus - the callback registers discovered nodes as voters
    let vh_for_callback = Arc::clone(&vote_handler);
    let voter_callback: ghost_consensus::health_handler::ElderCallback = Arc::new(move |node_id| {
        vh_for_callback.add_elder(node_id);
    });
    let health_handler = Arc::new(
        HealthPingHandler::new(Arc::clone(mesh.peers()), Some(Arc::clone(&db)))
            .with_elder_callback(voter_callback)
    );
    mesh.register_handler(Arc::clone(&health_handler) as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>);

    // Create and register discovery handler for peer gossip
    // This enables nodes to discover peers beyond just seed nodes
    let public_address = config.network.public_address.clone().unwrap_or_else(|| "".to_string());
    let mesh_for_connect = Arc::clone(&mesh);
    let connect_callback: ghost_consensus::discovery_handler::ConnectCallback = Arc::new(move |addr| {
        let mesh_clone = Arc::clone(&mesh_for_connect);
        tokio::spawn(async move {
            if let Err(e) = mesh_clone.connect_peer(&addr).await {
                tracing::debug!(addr = %addr, error = %e, "Failed to connect to discovered peer");
            }
        });
    });
    let discovery_handler = Arc::new(
        ghost_consensus::DiscoveryHandler::new(
            identity.node_id(),
            public_address.clone(),
            Arc::clone(mesh.peers()),
        ).with_connect_callback(connect_callback)
    );
    mesh.register_handler(Arc::clone(&discovery_handler) as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>);

    // Create shutdown channel
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // Create pool state (will be used for API handlers)
    let _pool_state = Arc::new(PoolState {
        identity: Arc::clone(&identity),
        capabilities,
        policy: policy.clone(),
        rpc: Arc::clone(&rpc),
        db: Arc::clone(&db),
        round_manager: Arc::clone(&round_manager),
        template_processor: Arc::clone(&template_processor),
        stratum_server: Arc::clone(&stratum_server),
        mesh: Arc::clone(&mesh),
        vote_handler: Arc::clone(&vote_handler),
        shutdown_tx: shutdown_tx.clone(),
    });

    // Start verification HTTP server
    let rpc_for_verification = Arc::clone(&rpc);
    let rm_for_height = Arc::clone(&round_manager);
    let rm_for_round = Arc::clone(&round_manager);
    let ss_for_verification = Arc::clone(&stratum_server);
    let mesh_for_verification = Arc::clone(&mesh);

    let mut verification_state = VerificationState::new(
        identity.node_id_hex(),
        env!("CARGO_PKG_VERSION").to_string(),
        policy.clone(),
        capabilities,
    );

    // Configure callbacks for health/status endpoints
    verification_state = verification_state.with_callbacks(
        move || rm_for_height.current_height(),
        move || rm_for_round.current_round_id() as u64,
        move || ss_for_verification.miner_count() as u32,
        move || mesh_for_verification.peers().peer_count() as u32,
    );

    // Configure archive handler if archive mode enabled
    if capabilities.archive_mode {
        let archive_handler = RpcArchiveHandler::new(Arc::clone(&rpc_for_verification));
        verification_state = verification_state.with_archive_handler(archive_handler);
    }

    // Pass database and RPC to verification state for API endpoints
    verification_state = verification_state.with_database((*db).clone());
    verification_state = verification_state.with_rpc(Arc::clone(&rpc));

    // Configure test proposal callback for BFT consensus testing
    let vh_for_test = Arc::clone(&vote_handler);
    let identity_for_test = Arc::clone(&identity);
    let rm_for_test = Arc::clone(&round_manager);
    let test_proposal_fn: ghost_verification::TestProposalFn = Arc::new(move || {
        use ghost_common::types::{PayoutEntry, PayoutProposal, PayoutType};

        // Create a test payout proposal
        let round_id = rm_for_test.current_round_id() as u64;
        let height = rm_for_test.current_height();
        let timestamp = chrono::Utc::now().timestamp() as u64;

        // Create minimal valid test proposal
        let proposal = PayoutProposal {
            proposal_hash: [0u8; 32], // Will be computed by handler
            round_id,
            block_hash: [0u8; 32],
            block_height: height.max(800_000), // Ensure valid height
            proposer: identity_for_test.node_id(),
            miner_payouts: vec![
                PayoutEntry {
                    address: b"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_vec(), // Signet address
                    amount: 100_000_000, // 1 BTC test
                    recipient_id: [1u8; 32],
                    payout_type: PayoutType::Mining,
                },
            ],
            node_payouts: vec![],
            treasury_amount: 1_000_000, // 0.01 BTC
            tx_fees: 500_000,
            subsidy: 312_500_000, // 3.125 BTC (signet subsidy)
            timestamp,
        };

        // Submit to vote handler (broadcasts to peers)
        vh_for_test.handle_proposal(proposal)
    });
    verification_state = verification_state.with_test_proposal_fn(test_proposal_fn);

    let verification_state = Arc::new(verification_state);

    // Start WebSocket health broadcast task
    let ws_state = Arc::clone(&verification_state.ws_state);
    let rm_for_ws = Arc::clone(&round_manager);
    let ss_for_ws = Arc::clone(&stratum_server);
    let mesh_for_ws = Arc::clone(&mesh);
    let start_time = std::time::Instant::now();
    let mut ws_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let event = ghost_verification::WsEvent::HealthUpdate {
                        block_height: rm_for_ws.current_height(),
                        round_id: rm_for_ws.current_round_id() as u64,
                        miner_count: ss_for_ws.miner_count() as u32,
                        peer_count: mesh_for_ws.peers().peer_count() as u32,
                        uptime_secs: start_time.elapsed().as_secs(),
                    };
                    ws_state.broadcast(event);
                }
                _ = ws_shutdown.recv() => break,
            }
        }
    });

    // Clone ws_state for event handlers before moving verification_state
    let verification_state_for_ws = Arc::clone(&verification_state);
    let ws_for_stratum = Arc::clone(&verification_state.ws_state);

    let http_port = config.network.http_port;
    tokio::spawn(async move {
        if let Err(e) = start_server(verification_state, http_port).await {
            error!(error = %e, "Verification server error");
        }
    });
    info!("HTTP API listening on port {}", http_port);

    // Start template processor
    let tp = Arc::clone(&template_processor);
    let mut template_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        tokio::select! {
            result = tp.start() => {
                if let Err(e) = result {
                    error!(error = %e, "Template processor error");
                }
            }
            _ = template_shutdown.recv() => {}
        }
    });
    info!("Template processor started");

    // Start Stratum server
    let ss = Arc::clone(&stratum_server);
    let mut stratum_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        tokio::select! {
            result = ss.start() => {
                if let Err(e) = result {
                    error!(error = %e, "Stratum server error");
                }
            }
            _ = stratum_shutdown.recv() => {}
        }
    });
    info!("Stratum server listening on port {}", stratum_port);

    // Start vardiff controller
    let vardiff_config = StratumConfig {
        listen_addr: format!("0.0.0.0:{}", stratum_port)
            .parse()
            .expect("valid socket address from configured port"),
        ..Default::default()
    };
    let vardiff_controller = Arc::new(VardiffController::new(vardiff_config));

    // Link vardiff controller to stratum server for share tracking
    stratum_server.set_vardiff_controller(Arc::clone(&vardiff_controller));

    let ss_vardiff = Arc::clone(&stratum_server);
    let vc = Arc::clone(&vardiff_controller);
    tokio::spawn(async move {
        ss_vardiff.run_vardiff_loop(vc).await;
    });
    info!("Vardiff controller started (target {}s between shares)", vardiff_target_secs);

    // Start P2P mesh
    let m = Arc::clone(&mesh);
    tokio::spawn(async move {
        if let Err(e) = m.start().await {
            error!(error = %e, "Mesh network error");
        }
    });
    info!("P2P mesh network started");

    // Bootstrap peer connections from seed nodes
    if !config.network.seed_nodes.is_empty() {
        let mesh_bootstrap = Arc::clone(&mesh);
        let seed_nodes = config.network.seed_nodes.clone();
        let discovery_for_bootstrap = Arc::clone(&discovery_handler);
        tokio::spawn(async move {
            // Wait a moment for mesh to fully start
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            for seed in &seed_nodes {
                info!(seed = %seed, "Connecting to seed node");
                // Add seed to discovery handler's known peers
                discovery_for_bootstrap.add_known_peer([0u8; 32], seed.clone());
                if let Err(e) = mesh_bootstrap.connect_peer(seed).await {
                    warn!(seed = %seed, error = %e, "Failed to connect to seed node");
                }
            }
        });
    }

    // Start periodic discovery broadcast task
    // This gossips our known peers to other nodes every 30 seconds
    let mesh_for_discovery = Arc::clone(&mesh);
    let discovery_for_broadcast = Arc::clone(&discovery_handler);
    tokio::spawn(async move {
        // Wait for mesh to establish connections
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        loop {
            // Get the discovery message with our known peers
            let discovery_msg = discovery_for_broadcast.get_discovery_message();

            // Broadcast it
            match mesh_for_discovery.broadcast_message(
                ghost_consensus::MessageType::Discovery,
                &discovery_msg,
            ).await {
                Ok(sent) => {
                    if sent > 0 {
                        tracing::debug!(
                            sent = sent,
                            known_peers = discovery_msg.known_peers.len(),
                            "Broadcast discovery message"
                        );
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "Failed to broadcast discovery");
                }
            }

            // Broadcast every 30 seconds
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    });

    // Start ZMQ block watcher with reorg detection (if configured)
    if let Some(ref zmq_endpoint) = config.bitcoin.zmq_hashblock {
        let rm = Arc::clone(&round_manager);
        let tp = Arc::clone(&template_processor);

        // Use ZmqSubscriber for both block notifications and reorg detection
        // Derive sequence endpoint from hashblock (28332 -> 28334 typically)
        let sequence_endpoint = config.bitcoin.zmq_sequence.clone().or_else(|| {
            // Auto-derive sequence endpoint: tcp://127.0.0.1:28332 -> tcp://127.0.0.1:28334
            zmq_endpoint.replace(":28332", ":28334").into()
        });

        let zmq_config = ZmqConfig {
            hashblock_endpoint: Some(zmq_endpoint.clone()),
            hashtx_endpoint: None,
            rawblock_endpoint: None,
            rawtx_endpoint: None,
            sequence_endpoint: sequence_endpoint.clone(),
        };

        let zmq_subscriber = ZmqSubscriber::new(zmq_config);
        let mut block_rx = zmq_subscriber.subscribe_blocks();

        // Start block event handler for new blocks
        tokio::spawn(async move {
            while let Ok(block_hash) = block_rx.recv().await {
                info!(hash = %block_hash, "New block detected via ZMQ");

                // End current round
                if let Some(summary) = rm.end_round() {
                    info!(
                        round = summary.round_id,
                        miners = summary.miner_count,
                        work = summary.total_miner_work,
                        "Round ended"
                    );
                }

                // Refresh template (starts new round)
                if let Err(e) = tp.refresh_template().await {
                    error!(error = %e, "Failed to refresh template on new block");
                }
            }
        });

        // Start reorg handler (subscribes to block disconnect events)
        let block_events = zmq_subscriber.subscribe_block_events();
        let reorg_handler = ReorgHandler::new(Arc::clone(&db), ReorgConfig::default())
            .with_vote_handler(Arc::clone(&vote_handler));
        reorg_handler.start(block_events);

        info!("ZMQ block watcher connected to {}", zmq_endpoint);
        if let Some(seq_ep) = sequence_endpoint {
            info!("ZMQ reorg detection connected to {}", seq_ep);
        }
    }

    // Subscribe to template events for job notifications
    let ss_notify = Arc::clone(&stratum_server);
    let tp_notify = Arc::clone(&template_processor);
    let rm_notify = Arc::clone(&round_manager);
    let mut template_events = template_processor.subscribe();
    tokio::spawn(async move {
        while let Ok(event) = template_events.recv().await {
            match event {
                TemplateEvent::NewWork { job_id: _, height } => {
                    // Start new round
                    rm_notify.start_round(height);

                    // Get work state and notify miners
                    if let Some(work) = tp_notify.current_work() {
                        let job = JobNotification {
                            job_id: work.job_id,
                            prev_hash: work.prev_hash,
                            coinbase1: hex::encode(&work.coinbase1),
                            coinbase2: hex::encode(&work.coinbase2),
                            merkle_branches: work.merkle_branches.iter().map(hex::encode).collect(),
                            version: format!("{:08x}", work.version),
                            nbits: work.nbits,
                            ntime: format!("{:08x}", work.ntime),
                            clean_jobs: true,
                        };
                        ss_notify.notify_new_job(job).await;
                    }
                }
                TemplateEvent::TransactionsFiltered { original_count, filtered_count, removed_fees } => {
                    info!(
                        original = original_count,
                        filtered = filtered_count,
                        removed_fees = removed_fees,
                        "BUDS filtering applied"
                    );
                }
                TemplateEvent::FetchFailed { error } => {
                    warn!(error = %error, "Template fetch failed");
                }
            }
        }
    });

    // Create payout handler for block found events
    // This wires BlockFound -> PayoutProposal -> VoteHandler (BFT consensus)
    //
    // Convert treasury address from bech32 string to script pubkey bytes
    let treasury_script = if !config.pool.treasury_address.is_empty() {
        use bitcoin::address::NetworkUnchecked;
        use bitcoin::Address;
        use std::str::FromStr;

        match Address::<NetworkUnchecked>::from_str(&config.pool.treasury_address) {
            Ok(addr) => addr.assume_checked().script_pubkey().into_bytes(),
            Err(e) => {
                warn!(
                    address = %config.pool.treasury_address,
                    error = %e,
                    "Invalid treasury address, using empty (payouts will fail)"
                );
                Vec::new()
            }
        }
    } else {
        warn!("No treasury address configured, pool fee payouts will fail");
        Vec::new()
    };

    let payout_config = PayoutConfig {
        pool_fee_percent: config.pool.treasury_fee_percent / 100.0, // Config is 0-100, convert to 0-1
        dust_threshold_sats: config.pool.min_payout_sats.max(546), // Use config value but ensure at least dust limit
        max_miner_outputs: 200,
        max_node_outputs: 100,
        treasury_address: treasury_script,
    };
    let payout_handler = Arc::new(PayoutHandler::new(
        Arc::clone(&identity),
        payout_config,
        Arc::clone(&db),
        Arc::clone(&vote_handler),
    ));

    // Clone refs for the async round event handler
    let rm_for_events = Arc::clone(&round_manager);
    let tp_for_events = Arc::clone(&template_processor);
    let payout_for_events = Arc::clone(&payout_handler);

    // Subscribe to round events and handle block found
    let mut round_events = round_manager.subscribe();
    tokio::spawn(async move {
        while let Ok(event) = round_events.recv().await {
            match event {
                RoundEvent::BlockFound { round_id, block_hash, miner_id } => {
                    info!(
                        round = round_id,
                        hash = %hex::encode(&block_hash[..8]),
                        miner = %miner_id,
                        "🎉 BLOCK FOUND! Creating payout proposal..."
                    );

                    // Gather data for payout proposal
                    // Get miner work distribution from round manager
                    let miner_work = rm_for_events.get_miner_work(round_id);
                    let node_shares = rm_for_events.get_node_shares(round_id);

                    // Get block subsidy and fees from template processor
                    let (subsidy, fees, height) = tp_for_events.get_current_block_info();

                    // Create block found data for payout handler
                    let block_data = BlockFoundData {
                        round_id,
                        block_hash,
                        block_height: height,
                        winning_miner_id: miner_id.clone(),
                        subsidy_sats: subsidy,
                        tx_fees_sats: fees,
                        miner_work,
                        node_shares,
                    };

                    // Submit payout proposal for BFT consensus
                    match payout_for_events.handle_block_found(block_data) {
                        Ok(proposal_hash) => {
                            if proposal_hash != [0u8; 32] {
                                info!(
                                    round = round_id,
                                    hash = %hex::encode(&proposal_hash[..8]),
                                    "Payout proposal submitted for consensus"
                                );
                            }
                        }
                        Err(e) => {
                            error!(error = %e, round = round_id, "Failed to create payout proposal");
                        }
                    }
                }
                RoundEvent::ShareSubmitted { round_id: _, miner_id: _, work: _ } => {
                    // Log periodically, not every share
                }
                _ => {}
            }
        }
    });

    // Subscribe to stratum events for logging and WebSocket broadcast
    let mut stratum_events = stratum_server.subscribe_events();
    tokio::spawn(async move {
        while let Ok(event) = stratum_events.recv().await {
            match event {
                StratumEvent::MinerConnected { miner_id, addr } => {
                    info!(miner = %miner_id, addr = %addr, "Miner connected");
                    ws_for_stratum.broadcast(ghost_verification::WsEvent::MinerConnected {
                        miner_id: miner_id.clone(),
                        address: addr.to_string(),
                    });
                }
                StratumEvent::MinerDisconnected { miner_id } => {
                    info!(miner = %miner_id, "Miner disconnected");
                    ws_for_stratum.broadcast(ghost_verification::WsEvent::MinerDisconnected {
                        miner_id: miner_id.clone(),
                    });
                }
                StratumEvent::BlockFound { miner_id, block_hash } => {
                    info!(miner = %miner_id, hash = %block_hash, "Block found by miner!");
                    ws_for_stratum.broadcast(ghost_verification::WsEvent::BlockFound {
                        height: 0, // Would need to get from round manager
                        hash: block_hash.clone(),
                        miner_id: miner_id.clone(),
                    });
                }
                StratumEvent::ShareSubmitted { miner_id, difficulty, accepted, .. } => {
                    ws_for_stratum.broadcast(ghost_verification::WsEvent::ShareSubmitted {
                        miner_id: miner_id.clone(),
                        difficulty,
                        valid: accepted,
                    });
                }
                _ => {}
            }
        }
    });

    // Print startup summary
    info!("════════════════════════════════════════════════════════════════");
    info!("Ghost Pool is ready!");
    info!("  Stratum:    0.0.0.0:{}", stratum_port);
    info!("  HTTP API:   0.0.0.0:{}", http_port);
    info!("  Policy:     {}", policy.name);
    info!("  Shares:     {}/15", capabilities.total_shares());
    info!("════════════════════════════════════════════════════════════════");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;

    info!("Shutting down Ghost Pool...");
    let _ = shutdown_tx.send(());

    // Cleanup
    template_processor.stop();
    stratum_server.stop();
    mesh.stop().await?;

    info!("Ghost Pool shutdown complete");
    Ok(())
}

/// Expand ~ in path
fn expand_path(path: &PathBuf) -> Result<PathBuf> {
    let path_str = path.to_string_lossy();
    if path_str.starts_with("~/") {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map_err(|_| anyhow::anyhow!("Could not determine home directory"))?;
        Ok(PathBuf::from(home).join(&path_str[2..]))
    } else {
        Ok(path.clone())
    }
}

/// Load configuration from file
fn load_config(path: &PathBuf) -> Result<NodeConfig> {
    let config = if path.exists() {
        let content = std::fs::read_to_string(path)?;
        let config: NodeConfig = toml::from_str(&content)?;
        config
    } else {
        info!("No config file found at {}, using defaults", path.display());
        NodeConfig::default()
    };

    // Validate pool configuration
    if let Err(e) = config.pool.validate() {
        warn!("Pool configuration warning: {}", e);
    }

    Ok(config)
}
