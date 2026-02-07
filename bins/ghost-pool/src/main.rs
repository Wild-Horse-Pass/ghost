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

use ghost_common::config::{MiningMode, NodeConfig};
use ghost_common::identity::NodeIdentity;
use ghost_common::rpc::BitcoinRpc;
use ghost_common::signer::SignerConfig;
use ghost_common::types::{ConsensusResult, NodeCapabilities};
use ghost_common::zmq::{ZmqConfig, ZmqSubscriber};
use ghost_consensus::ban_manager::BanManager;
use ghost_consensus::health_handler::HealthPingHandler;
use ghost_consensus::mesh::{MeshConfig, MeshNetwork};
use ghost_consensus::message::MessageType;
use ghost_consensus::verification_handler::VerificationResultHandler;
use ghost_consensus::vote_handler::{BroadcastFn, ExecuteFn, VoteHandler};
use ghost_consensus::voting::VotingManager;
use ghost_policy::PolicyProfile;
use ghost_storage::Database;
use ghost_verification::{
    start_server, BlockFoundNotification, GhostPayL2Handler, PeerProvider,
    QualifiedCapabilityProvider, RpcArchiveHandler, VerifiablePeer, VerificationState,
    VerificationTask,
};

use ghost_pool::payout::{BlockFoundData, PayoutConfig, PayoutHandler, SoloBlockFoundData};
use ghost_pool::registry::RegistryClient;
use ghost_pool::reorg::{ReorgConfig, ReorgHandler};
use ghost_pool::round::{RoundConfig, RoundEvent, RoundManager};
use ghost_pool::template::{TemplateConfig, TemplateEvent, TemplateProcessor};
use ghost_pool::template_provider::{TdpConfig, TemplateDistributionServer};
use ghost_pool::treasury::TreasuryState;

/// Exit code that signals systemd to restart the service
/// Used when config is updated via API and requires restart to apply
const EXIT_CODE_RESTART: i32 = 100;

/// Adapter to provide peers for verification from PeerManager
struct PeerProviderAdapter {
    peers: Arc<ghost_consensus::peer::PeerManager>,
    http_port: u16,
}

impl PeerProviderAdapter {
    fn new(peers: Arc<ghost_consensus::peer::PeerManager>, http_port: u16) -> Self {
        Self { peers, http_port }
    }
}

impl PeerProvider for PeerProviderAdapter {
    fn get_random_peers(
        &self,
        exclude: &ghost_common::types::NodeId,
        count: usize,
    ) -> Vec<VerifiablePeer> {
        use rand::seq::SliceRandom;

        // Get connected peers (seen in last 60 seconds)
        let connected = self.peers.get_connected_peers(60);

        // Filter out the excluded node (ourselves) and peers without valid addresses
        let mut candidates: Vec<_> = connected
            .into_iter()
            .filter(|p| &p.node_id != exclude && !p.public_address.is_empty())
            .map(|p| {
                // Derive HTTP address from public_address + http_port
                // public_address is typically just an IP or host
                let host = if p.public_address.contains(':') {
                    // Has port, extract just the host
                    p.public_address
                        .split(':')
                        .next()
                        .unwrap_or(&p.public_address)
                } else {
                    &p.public_address
                };
                VerifiablePeer {
                    node_id: p.node_id,
                    http_address: format!("{}:{}", host, self.http_port),
                }
            })
            .collect();

        // Shuffle and take up to count
        let mut rng = rand::thread_rng();
        candidates.shuffle(&mut rng);
        candidates.truncate(count);
        candidates
    }
}

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

    /// Show node status in load balancer and exit
    #[arg(long)]
    status: bool,

    /// Watch node status continuously (refresh every N seconds)
    #[arg(long, value_name = "SECS")]
    watch: Option<u64>,

    /// Bitcoin RPC host override
    #[arg(long)]
    rpc_host: Option<String>,

    /// Bitcoin RPC port override
    #[arg(long)]
    rpc_port: Option<u16>,

    /// Stratum listen port override
    #[arg(long)]
    stratum_port: Option<u16>,

    /// Enable Template Distribution Protocol server (for SRI pool)
    #[arg(long)]
    tdp_enabled: bool,

    /// TDP server port (default: 8442)
    #[arg(long, default_value = "8442")]
    tdp_port: u16,

    /// Disable native stratum server (use when running with SRI pool via TDP)
    #[arg(long)]
    no_stratum: bool,
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
    /// P2P mesh network
    pub mesh: Arc<MeshNetwork>,
    /// Vote handler for consensus
    pub vote_handler: Arc<VoteHandler>,
    /// Shutdown signal
    pub shutdown_tx: broadcast::Sender<()>,
}

/// Handle --status command: query and display node status from registry
async fn handle_status_command(
    config: &NodeConfig,
    identity: &NodeIdentity,
    watch_interval: Option<u64>,
) -> Result<()> {
    use ghost_pool::registry::NodeStatusResponse;

    let Some(ref registry_config) = config.registry else {
        println!("Registry not configured in config file.");
        println!("Add [registry] section with url and region to enable load balancing.");
        return Ok(());
    };

    // Create a simple HTTP client to query status
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let node_id = identity.node_id_hex();
    let url = format!("{}/api/v1/nodes/{}/status", registry_config.url, node_id);

    loop {
        // Clear screen in watch mode
        if watch_interval.is_some() {
            print!("\x1B[2J\x1B[1;1H");
        }

        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║                    Ghost Pool Status                          ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!();

        println!("Registry:    {}", registry_config.url);
        println!("Node ID:     {} ({})", identity.node_id_short(), node_id);
        println!();

        match client.get(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    let api_resp: serde_json::Value = response.json().await?;

                    if let Some(data) = api_resp.get("data") {
                        let status: NodeStatusResponse = serde_json::from_value(data.clone())?;
                        print_status(&status);
                    } else if let Some(error) = api_resp.get("error") {
                        println!("Error: {}", error);
                    }
                } else if response.status().as_u16() == 404 {
                    println!("Status:      NOT REGISTERED");
                    println!();
                    println!("This node is not registered with the registry.");
                    println!("Start the pool service to register automatically.");
                } else {
                    println!("Error: Registry returned status {}", response.status());
                }
            }
            Err(e) => {
                println!("Error:       Could not connect to registry");
                println!("             {}", e);
                println!();
                println!("Check that the registry is running and accessible.");
            }
        }

        // Exit if not in watch mode
        let Some(interval) = watch_interval else {
            break;
        };

        println!();
        println!("─────────────────────────────────────────────────────────────────");
        println!("Refreshing every {}s. Press Ctrl+C to exit.", interval);

        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
    }

    Ok(())
}

/// Print formatted status output
fn print_status(status: &ghost_pool::registry::NodeStatusResponse) {
    // Status indicator
    let status_icon = if status.in_dns { "●" } else { "○" };
    let status_text = if status.in_dns {
        "IN DNS (receiving miners)"
    } else {
        "NOT IN DNS"
    };

    println!("Status:      {} {}", status_icon, status_text);
    println!();

    // Details
    println!("┌─ Load Balancer Status ─────────────────────────────────────┐");
    println!(
        "│ Registered:        {:<39} │",
        if status.registered { "Yes" } else { "No" }
    );
    println!(
        "│ In DNS:            {:<39} │",
        if status.in_dns { "Yes" } else { "No" }
    );
    println!(
        "│ Healthy:           {:<39} │",
        if status.healthy { "Yes" } else { "No" }
    );
    println!(
        "│ Accepting Miners:  {:<39} │",
        if status.accepting_miners { "Yes" } else { "No" }
    );
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();

    println!("┌─ Load & Ranking ────────────────────────────────────────────┐");
    println!(
        "│ Current Load:      {:<39} │",
        format!("{}%", status.load_percent)
    );
    println!("│ Region:            {:<39} │", status.region);
    println!(
        "│ Rank in Region:    {:<39} │",
        format!(
            "{} of {} (by load)",
            status.rank_in_region, status.healthy_in_region
        )
    );
    println!(
        "│ Total in Region:   {:<39} │",
        format!(
            "{} nodes ({} healthy)",
            status.total_in_region, status.healthy_in_region
        )
    );
    println!(
        "│ Last Heartbeat:    {:<39} │",
        format!("{}s ago", status.last_heartbeat_ago_secs)
    );
    println!("└─────────────────────────────────────────────────────────────┘");

    // Exclusion reason if any
    if let Some(ref reason) = status.exclusion_reason {
        println!();
        println!("┌─ Exclusion Reason ─────────────────────────────────────────┐");
        println!("│ {:<59} │", reason);
        println!("└─────────────────────────────────────────────────────────────┘");
    }

    // Tips
    if !status.in_dns {
        println!();
        println!("Tip: Node is not receiving miners because it's excluded from DNS.");
        if status.excluded_for_load {
            println!("     Load is ≥80%. Will resume when load drops below 70%.");
        } else if !status.healthy {
            println!("     Node marked unhealthy. Check heartbeat connectivity.");
        } else if !status.accepting_miners {
            println!("     Node is not accepting miners. Check configuration.");
        }
    }
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

    // HIGH-8: Use fallible initialization - if subscriber is already set, that's fine
    if tracing::subscriber::set_global_default(subscriber).is_err() {
        // A subscriber is already registered (e.g., from test harness). Continue with existing one.
        eprintln!("Note: Tracing subscriber already initialized, using existing configuration");
    }

    // Expand data directory
    let data_dir = expand_path(&args.data_dir)?;
    std::fs::create_dir_all(&data_dir)?;

    // Default key path in data directory (used for --generate-identity and fallback)
    let default_key_path = data_dir.join("node.key");

    // Handle --generate-identity command (doesn't need config)
    if args.generate_identity {
        info!("Generating new node identity...");
        let identity = NodeIdentity::generate();
        identity.save(&default_key_path)?;
        info!("Node ID: {}", identity.node_id_hex());
        info!("Key saved to: {}", default_key_path.display());
        return Ok(());
    }

    // Load configuration first (needed for signer config)
    let config = load_config(&args.config)?;

    // Determine the effective signer configuration
    // Priority: config.identity.signer > config.identity.key_path > data_dir/node.key
    let signer_config = match &config.identity.signer {
        Some(cfg) => {
            // Explicit signer configuration in config file
            cfg.clone()
        }
        None => {
            // Use config key_path if it exists, otherwise fall back to data_dir
            let cfg_key_path = expand_path(&config.identity.key_path)?;
            if cfg_key_path.exists() {
                SignerConfig::Local {
                    key_path: cfg_key_path,
                }
            } else if default_key_path.exists() {
                SignerConfig::Local {
                    key_path: default_key_path.clone(),
                }
            } else {
                // No key file exists, we'll generate one below
                SignerConfig::Local {
                    key_path: default_key_path.clone(),
                }
            }
        }
    };

    // Load or create identity using signer config
    let identity = match &signer_config {
        SignerConfig::Local { key_path } => {
            if key_path.exists() {
                NodeIdentity::load(key_path)?
            } else {
                info!(
                    "No identity found at {}, generating new one...",
                    key_path.display()
                );
                let identity = NodeIdentity::generate();
                identity.save(key_path)?;
                info!("Generated new identity, saved to: {}", key_path.display());
                identity
            }
        }
        SignerConfig::Hsm { .. } | SignerConfig::Kms { .. } => {
            // HSM/KMS signers require the key to already exist
            NodeIdentity::from_config(&signer_config).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to initialize {} signer: {}",
                    match &signer_config {
                        SignerConfig::Hsm { .. } => "HSM",
                        SignerConfig::Kms { .. } => "KMS",
                        _ => "unknown",
                    },
                    e
                )
            })?
        }
    };

    // Handle --show-identity command
    if args.show_identity {
        println!("Node ID: {}", identity.node_id_hex());
        println!("Short ID: {}", identity.node_id_short());
        println!("Signer: {}", identity.signer_type());
        return Ok(());
    }

    // Handle --status command
    if args.status {
        return handle_status_command(&config, &identity, None).await;
    }

    // Handle --watch command
    if let Some(interval) = args.watch {
        return handle_status_command(&config, &identity, Some(interval.max(1))).await;
    }

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!(
        "║              Ghost Pool v{}                           ║",
        env!("CARGO_PKG_VERSION")
    );
    info!("║          Decentralized Bitcoin Mining Pool                   ║");
    info!("╚══════════════════════════════════════════════════════════════╝");
    info!(
        "Node ID: {} ({})",
        identity.node_id_short(),
        identity.signer_type()
    );

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

    info!(
        "Configuration validated ({} warning(s))",
        validation.warnings.len()
    );

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
    info!(
        "Policy profile: {} (allows up to T{})",
        policy.name,
        policy.highest_allowed_tier().map(|t| t as u8).unwrap_or(0)
    );

    // Determine effective public_mining from mining_mode
    // PublicPool = public mining enabled, other modes = private
    let mining_mode = config.network.mining_mode;
    let is_public_mining = matches!(mining_mode, MiningMode::PublicPool);

    info!(
        "Mining mode: {:?} (public_mining={})",
        mining_mode, is_public_mining
    );

    // Setup capabilities - initially with elder_status = false
    // We'll update after registering with the database
    let mut capabilities = NodeCapabilities {
        archive_mode: config.storage.archive_mode,
        ghost_pay: config.ghost_pay.is_some(),
        public_mining: is_public_mining, // Derived from mining_mode
        bitcoin_pure: matches!(
            config.policy.profile,
            ghost_common::config::PolicyProfile::BitcoinPure
        ),
        elder_status: false,
    };

    // Register node with database and check if we should be an elder
    // First 101 nodes to register become elders automatically
    let node_id_hex = identity.node_id_hex();
    let public_address = config.network.public_address.as_deref();
    let display_name = config.identity.display_name.as_deref();
    let capabilities_str = format!(
        "archive:{},ghost_pay:{},public_mining:{},bitcoin_pure:{}",
        capabilities.archive_mode,
        capabilities.ghost_pay,
        capabilities.public_mining,
        capabilities.bitcoin_pure
    );

    match db.register_node_with_elder_check(
        &node_id_hex,
        public_address,
        display_name,
        &capabilities_str,
    ) {
        Ok((is_elder, elder_order)) => {
            capabilities.elder_status = is_elder;
            if is_elder {
                info!("Node registered as Elder #{}", elder_order.unwrap_or(0));
            } else {
                info!(
                    "Node registered (non-elder, {} elders already exist)",
                    db.get_elder_count().unwrap_or(0)
                );
            }
        }
        Err(e) => {
            warn!(
                "Failed to register node for elder check: {} - defaulting to non-elder",
                e
            );
        }
    }

    info!("Capability shares: {}/15", capabilities.total_shares());

    // Create identity Arc
    let identity = Arc::new(identity);

    // Initialize round manager with mining mode
    let round_config = RoundConfig {
        mining_mode,
        ..Default::default()
    };
    let round_manager = Arc::new(RoundManager::new(identity.node_id(), round_config));

    // Register our own node's capabilities so we're included in node reward calculations
    // This is critical - without this, our shares won't be counted for node rewards
    round_manager.register_node(identity.node_id(), capabilities);

    // Initialize template processor with treasury and pool payout addresses from config
    // Pool payout address defaults to treasury address if not explicitly configured separately
    let template_config = TemplateConfig {
        treasury_address: config.pool.treasury_address.clone(),
        pool_payout_address: config.pool.treasury_address.address().to_string(), // Use same as treasury for now
        network: config.bitcoin.network,
        mining_mode,
        solo_payout_address: config.network.solo_payout_address.clone(),
        ..Default::default()
    };
    let template_processor = Arc::new(TemplateProcessor::new(
        template_config,
        Arc::clone(&rpc),
        policy.clone(),
    ));

    // Note: Native stratum server removed - using SRI (Stratum Reference Implementation) via TDP
    // SRI pool connects to ghost-pool's TDP server for templates
    // SRI translator handles SV1 miners on port 3333

    // Initialize P2P mesh with actual node capabilities for health pings
    // C-1: Enable Noise Protocol encryption for sensitive P2P traffic
    let noise_keypair_path = data_dir.join("noise.key");
    let mesh_config = MeshConfig {
        public_address: config
            .network
            .public_address
            .clone()
            .unwrap_or_else(|| "127.0.0.1".to_string()),
        ports: config.network.p2p.clone(),
        capabilities,
        // C-1: Noise Protocol configuration for encrypted P2P
        // Read from config (mainnet validation ensures this is true on mainnet)
        noise_enabled: config.network.noise_enabled,
        noise_port: ghost_consensus::mesh::DEFAULT_NOISE_PORT,
        noise_keypair_path: Some(noise_keypair_path),
        noise_required: false, // Allow fallback during migration
        ..Default::default()
    };
    // M-2: Use try_new() to properly handle Noise initialization failures
    let mesh = Arc::new(MeshNetwork::try_new(Arc::clone(&identity), mesh_config)?);

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
            ConsensusResult::Approved {
                proposal_hash,
                approval_count,
                total_nodes,
            } => {
                info!(
                    hash = %hex::encode(&proposal_hash[..8]),
                    approvals = approval_count,
                    total = total_nodes,
                    "Payout consensus approved - executing"
                );
                // Store approved payout for coinbase construction
                tp_for_execute.set_approved_payout(proposal_hash);

                // Refresh template to include approved payout in coinbase
                // This is the "1 block behind" fix: when consensus approves the payout
                // from round N, refresh templates so block N+1 has correct outputs
                let tp = Arc::clone(&tp_for_execute);
                tokio::spawn(async move {
                    if let Err(e) = tp.refresh_template().await {
                        tracing::error!(error = %e, "Failed to refresh template after payout approval");
                    } else {
                        tracing::info!("Template refreshed with approved payout outputs");
                    }
                });
            }
            ConsensusResult::Rejected {
                proposal_hash,
                rejection_count,
                reason,
                ..
            } => {
                warn!(
                    hash = %hex::encode(&proposal_hash[..8]),
                    rejections = rejection_count,
                    reason = ?reason,
                    "Payout consensus rejected"
                );
            }
            ConsensusResult::Timeout {
                proposal_hash,
                approvals,
                rejections,
                ..
            } => {
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

    // Create shared ban manager for cross-handler enforcement (C1 security fix)
    let ban_manager = Arc::new(BanManager::new());
    info!("Shared BanManager created for cross-handler ban enforcement");

    // Create vote handler with callbacks and shared ban manager
    // 4.5 SECURITY: Rate limiter persistence is now enabled by default to prevent
    // attackers from bypassing rate limits by triggering node restarts.
    let rate_limiter_path = data_dir.join("rate_limiter.json");
    let vote_handler = Arc::new(
        VoteHandler::new(Arc::clone(&identity), Arc::clone(&voting_manager))
            .with_broadcaster(broadcast_fn)
            .with_executor(execute_fn)
            .with_ban_manager(Arc::clone(&ban_manager))
            .with_rate_limiter_persistence(rate_limiter_path),
    );
    // Start the background persistence task (persists every 60 seconds)
    vote_handler.start_persistence_task();

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
            info!(
                "Registered {} elders from database for BFT voting",
                elders.len()
            );
        }
        Err(e) => {
            warn!("Failed to load elders for voting: {}", e);
        }
    }

    // Register ourselves as a voter - ALL active nodes participate in BFT consensus
    // (elder_status is just a capability flag indicating uptime/reliability, not a voting requirement)
    vote_handler.add_elder(identity.node_id());
    info!("Registered self as BFT voter");
    info!(
        "Initial voters for BFT: {} (peer discovery will add more from HealthPing)",
        vote_handler.elder_count()
    );

    // Register vote handler with mesh for incoming vote messages
    mesh.register_handler(
        Arc::clone(&vote_handler) as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>
    );

    // Create and register health ping handler for peer tracking and voter discovery
    // ALL active nodes participate in BFT consensus - the callback registers discovered nodes as voters
    let vh_for_callback = Arc::clone(&vote_handler);
    let voter_callback: ghost_consensus::health_handler::ElderCallback = Arc::new(move |node_id| {
        vh_for_callback.add_elder(node_id);
    });

    // Callback to register node capabilities for payout calculations
    let rm_for_callback = Arc::clone(&round_manager);
    let node_caps_callback: ghost_consensus::health_handler::NodeCapabilitiesCallback =
        Arc::new(move |node_id, capabilities| {
            rm_for_callback.register_node(node_id, capabilities);
        });

    // P2P4-M2: Create capability verifier to replace claimed capabilities with VERIFIED ones
    // This ensures health pings register nodes with their actual verified capabilities,
    // not just what they claim. The QualifiedCapabilityProvider checks challenge results.
    let qualification_provider_for_health =
        Arc::new(QualifiedCapabilityProvider::new(Arc::clone(&db)));
    let qp_for_verifier = Arc::clone(&qualification_provider_for_health);
    let capability_verifier: ghost_consensus::health_handler::CapabilityVerifierCallback =
        Arc::new(move |node_id| qp_for_verifier.get_qualified(node_id));

    let health_handler = Arc::new(
        HealthPingHandler::new(Arc::clone(mesh.peers()), Some(Arc::clone(&db)))
            .with_elder_callback(voter_callback)
            .with_node_capabilities_callback(node_caps_callback)
            .with_capability_verifier(capability_verifier)
            .with_ban_manager(Arc::clone(&ban_manager)),
    );
    mesh.register_handler(
        Arc::clone(&health_handler) as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>
    );

    // Create and register verification result handler for P2P verification results
    let verification_result_handler = Arc::new(VerificationResultHandler::new(Arc::clone(&db)));
    mesh.register_handler(Arc::clone(&verification_result_handler)
        as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>);

    // Create and register discovery handler for peer gossip
    // This enables nodes to discover peers beyond just seed nodes
    let public_address = config
        .network
        .public_address
        .clone()
        .unwrap_or_else(|| "".to_string());
    let mesh_for_connect = Arc::clone(&mesh);
    let connect_callback: ghost_consensus::discovery_handler::ConnectCallback = Arc::new(
        move |addr| {
            let mesh_clone = Arc::clone(&mesh_for_connect);
            tokio::spawn(async move {
                if let Err(e) = mesh_clone.connect_peer(&addr).await {
                    tracing::debug!(addr = %addr, error = %e, "Failed to connect to discovered peer");
                }
            });
        },
    );
    let discovery_handler = Arc::new(
        ghost_consensus::DiscoveryHandler::new(
            identity.node_id(),
            public_address.clone(),
            Arc::clone(mesh.peers()),
        )
        .with_connect_callback(connect_callback),
    );
    mesh.register_handler(Arc::clone(&discovery_handler)
        as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>);

    // === CANONICAL ELDER LIST INITIALIZATION (P2P-C1/C2/C3) ===
    // Load or create the canonical elder list manager from database
    let elder_list_manager = match ghost_consensus::ElderListManager::load_from_database(&db) {
        Ok(manager) if manager.current_epoch() > 0 => {
            info!(
                epoch = manager.current_epoch(),
                elder_count = manager.current().elder_count(),
                "Loaded canonical elder list from database"
            );
            Arc::new(parking_lot::RwLock::new(manager))
        }
        Ok(_) | Err(_) => {
            // Genesis bootstrap - create epoch 0 with empty list
            // First nodes to register become elders via the normal node registration process
            let genesis = ghost_consensus::CanonicalElderList::genesis(vec![]);
            let manager = ghost_consensus::ElderListManager::with_list(genesis);
            if let Err(e) = manager.save_current_to_database(&db) {
                warn!(error = %e, "Failed to save genesis elder list to database");
            }
            info!("Created genesis elder list (epoch 0, empty)");
            Arc::new(parking_lot::RwLock::new(manager))
        }
    };

    // Create broadcast callback for elder registration handler
    let mesh_for_elder_broadcast = Arc::clone(&mesh);
    let elder_broadcast_fn: ghost_consensus::elder_registration_handler::ElderBroadcastFn =
        Arc::new(
            move |msg_type: ghost_consensus::MessageType, payload: Vec<u8>| {
                mesh_for_elder_broadcast.broadcast_sync(msg_type, payload)
            },
        );

    // M-1 SECURITY FIX: Set up transition callback BEFORE Arc wrapping
    // This callback updates VoteHandler's eligible voters when epoch transitions occur
    let vh_for_elder_transition = Arc::clone(&vote_handler);
    let transition_callback: ghost_consensus::elder_registration_handler::TransitionCallback =
        Arc::new(move |new_list: &ghost_consensus::CanonicalElderList| {
            // Update eligible voters in VoteHandler from the new canonical list
            vh_for_elder_transition.set_canonical_elder_list(new_list.clone());
            info!(
                epoch = new_list.epoch,
                elder_count = new_list.elder_count(),
                "M-1: Updated VoteHandler with new canonical elder list"
            );
        });

    // Create the elder registration handler with transition callback set BEFORE Arc wrapping
    let mut elder_handler = ghost_consensus::ElderRegistrationHandler::new(
        Arc::clone(&identity),
        Arc::clone(&elder_list_manager),
        Arc::clone(&db),
    )
    .with_broadcaster(elder_broadcast_fn)
    .with_ban_manager(Arc::clone(&ban_manager));

    // M-1: Set callback before Arc wrapping (required because set_transition_callback takes &mut self)
    elder_handler.set_transition_callback(transition_callback);

    let elder_registration_handler = Arc::new(elder_handler);

    // Register elder registration handler with mesh
    mesh.register_handler(Arc::clone(&elder_registration_handler)
        as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>);

    info!(
        "Elder registration handler initialized (epoch {}, {} elders)",
        elder_list_manager.read().current_epoch(),
        elder_list_manager.read().current().elder_count()
    );

    // ZK consensus handlers (optional feature)
    #[cfg(feature = "zk-consensus")]
    {
        use ghost_consensus::{ZkPayoutVoteHandler, ZkVoteHandler};
        use ghost_zkp::{BlockProver, BlockVerifier, PayoutProver, PayoutVerifier};

        // Check production mode and load trusted params
        if ghost_zkp::is_production_mode() {
            ghost_zkp::load_trusted_params()?;
            info!("ZK consensus using PRODUCTION parameters from MPC ceremony");
        } else {
            // MAINNET SECURITY: ZK consensus on mainnet REQUIRES trusted setup
            if config.bitcoin.network == ghost_common::config::BitcoinNetwork::Mainnet {
                return Err(anyhow::anyhow!(
                    "MAINNET SECURITY: ZK consensus on mainnet requires trusted setup parameters. \
                     Either:\n  \
                     1. Complete MPC ceremony and build with --features zk-production\n  \
                     2. Disable ZK consensus by building without --features zk-consensus\n\n\
                     Running ZK consensus with test parameters on mainnet would allow proof forgery."
                ));
            }
            warn!("ZK consensus using TEST parameters - NOT SECURE FOR MAINNET");
        }

        // Initialize block prover/verifier with Groth16 setup (for L2 blocks)
        // Using 100 max txs and depth 20 for the state tree
        // L-25: Use proper error handling instead of expect()
        let block_prover = Arc::new(
            BlockProver::new_with_setup_and_state_transitions(100, 20).map_err(|e| {
                anyhow::anyhow!(
                    "L-25: Failed to initialize ZK block prover with Groth16 setup: {}. \
                     This may indicate insufficient memory or corrupted parameters.",
                    e
                )
            })?,
        );
        let block_verifier = Arc::new(if let Some(vk) = block_prover.prepared_verifying_key() {
            BlockVerifier::new_with_groth16_vk(&block_prover.verification_key(), vk).map_err(
                |e| {
                    anyhow::anyhow!(
                        "L-25: Failed to create ZK block verifier with prepared VK: {}",
                        e
                    )
                },
            )?
        } else {
            BlockVerifier::new(&block_prover.verification_key()).map_err(|e| {
                anyhow::anyhow!("L-25: Failed to create ZK block verifier: {}", e)
            })?
        });

        // Initialize payout prover/verifier with Groth16 setup
        // L-25: Use proper error handling instead of expect()
        let payout_prover = Arc::new(
            PayoutProver::default_params_with_setup().map_err(|e| {
                anyhow::anyhow!(
                    "L-25: Failed to initialize ZK payout prover with Groth16 setup: {}. \
                     This may indicate insufficient memory or corrupted parameters.",
                    e
                )
            })?,
        );
        let payout_verifier = Arc::new(PayoutVerifier::for_prover(&payout_prover));

        // Create broadcast callbacks for ZK handlers
        let mesh_for_zk_block = Arc::clone(&mesh);
        let zk_block_broadcast: ghost_consensus::zk_vote_handler::ZkBroadcastFn =
            Arc::new(move |msg_type, payload| mesh_for_zk_block.broadcast_sync(msg_type, payload));

        let mesh_for_zk_payout = Arc::clone(&mesh);
        let zk_payout_broadcast: ghost_consensus::zk_payout_handler::ZkPayoutBroadcastFn =
            Arc::new(move |msg_type, payload| mesh_for_zk_payout.broadcast_sync(msg_type, payload));

        // Create ZK vote handler for L2 block consensus
        let zk_vote_handler = Arc::new(
            ZkVoteHandler::new(Arc::clone(&identity))
                .with_verifier(ghost_consensus::zk_vote_handler::create_block_verifier(
                    Arc::clone(&block_verifier),
                ))
                .with_broadcaster(zk_block_broadcast),
        );

        // Create ZK payout vote handler
        let zk_payout_handler = Arc::new(
            ZkPayoutVoteHandler::new(Arc::clone(&identity))
                .with_verifier(ghost_consensus::zk_payout_handler::create_payout_verifier(
                    Arc::clone(&payout_verifier),
                ))
                .with_broadcaster(zk_payout_broadcast)
                .with_ban_manager(Arc::clone(&ban_manager)),
        );

        // Initialize validators from elder list
        let validators: std::collections::HashSet<_> = elder_list_manager
            .read()
            .current()
            .get_eligible_voters()
            .into_iter()
            .collect();
        zk_vote_handler.set_validators(validators.clone());
        zk_payout_handler.set_validators(validators);

        // Register ZK handlers with mesh
        mesh.register_handler(Arc::clone(&zk_vote_handler)
            as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>);
        mesh.register_handler(Arc::clone(&zk_payout_handler)
            as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>);

        info!(
            "ZK consensus handlers registered (block_verifier={}, payout_verifier={})",
            block_verifier.has_groth16_vk(),
            payout_verifier.has_groth16_vk()
        );
    }

    // MPC ceremony integration (optional feature)
    #[cfg(feature = "mpc-ceremony")]
    {
        use ghost_consensus::MpcHandler;
        use ghost_mpc::CeremonyManager;

        // Load MPC ceremony state from database
        let mpc_state = db.get_mpc_ceremony_state()?;

        // Determine params directory (from config or default)
        let mpc_params_dir =
            std::path::PathBuf::from(std::env::var("MPC_PARAMS_PATH").unwrap_or_else(|_| {
                format!(
                    "{}/.ghost/mpc_params",
                    std::env::var("HOME").unwrap_or_default()
                )
            }));

        // Initialize ceremony manager
        let ceremony_manager = match CeremonyManager::load_or_init(
            mpc_params_dir.clone(),
            mpc_state.map(|s| ghost_mpc::CeremonyState {
                contribution_count: s.contribution_count,
                current_params_hash: s.current_params_hash,
                is_ossified: s.is_ossified,
                ossified_at: s.ossified_at,
                block_vk_hash: s.block_vk_hash,
                payout_vk_hash: s.payout_vk_hash,
                updated_at: s.updated_at,
            }),
        ) {
            Ok(manager) => Arc::new(manager),
            Err(e) => {
                warn!(error = %e, "Failed to initialize MPC ceremony manager, continuing without MPC");
                // Create a minimal ceremony manager that reports as ossified
                Arc::new(CeremonyManager::new(mpc_params_dir))
            }
        };

        // Create broadcast callback for MPC handler
        let mesh_for_mpc = Arc::clone(&mesh);
        let mpc_broadcast: ghost_consensus::mpc_handler::MpcBroadcastFn =
            Arc::new(move |msg_type, payload| mesh_for_mpc.broadcast_sync(msg_type, payload));

        // Create MPC handler
        let mpc_handler = Arc::new(
            MpcHandler::new(
                Arc::clone(&identity),
                Arc::clone(&elder_list_manager),
                Arc::clone(&db),
            )
            .with_broadcaster(mpc_broadcast)
            .with_state(
                ceremony_manager.contribution_count(),
                ceremony_manager.is_ossified(),
            ),
        );

        // Register MPC handler with mesh
        mesh.register_handler(Arc::clone(&mpc_handler)
            as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>);

        info!(
            "MPC ceremony handler initialized (contributions={}, ossified={})",
            ceremony_manager.contribution_count(),
            ceremony_manager.is_ossified()
        );
    }

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
        mesh: Arc::clone(&mesh),
        vote_handler: Arc::clone(&vote_handler),
        shutdown_tx: shutdown_tx.clone(),
    });

    // Create payout handler for block found events
    // This wires BlockFound -> PayoutProposal -> VoteHandler (BFT consensus)
    //
    // Convert treasury address from bech32 string to script pubkey bytes
    let treasury_script = if !config.pool.treasury_address.is_empty() {
        use bitcoin::address::NetworkUnchecked;
        use bitcoin::Address;
        use std::str::FromStr;

        let addr_str = config.pool.treasury_address.address();
        match Address::<NetworkUnchecked>::from_str(addr_str) {
            Ok(addr) => addr.assume_checked().script_pubkey().into_bytes(),
            Err(e) => {
                warn!(
                    address = %addr_str,
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
        dust_threshold_sats: config.pool.min_payout_sats.max(546),
        max_miner_outputs: 200,
        max_node_outputs: 100,
        treasury_address: Some(treasury_script),
    };

    // H-MINE-1: PayoutHandler uses the same QualifiedCapabilityProvider as health_handler
    // This ensures consistent verified capability lookups across the system
    let payout_handler = Arc::new(PayoutHandler::new(
        Arc::clone(&identity),
        payout_config,
        Arc::clone(&db),
        Arc::clone(&vote_handler),
        Arc::clone(&template_processor),
        Arc::clone(&qualification_provider_for_health), // Reuse provider from health_handler
    )?);

    // Start verification HTTP server
    let rpc_for_verification = Arc::clone(&rpc);
    let rm_for_height = Arc::clone(&round_manager);
    let rm_for_round = Arc::clone(&round_manager);
    let rm_for_miners = Arc::clone(&round_manager);
    let mesh_for_verification = Arc::clone(&mesh);

    let mut verification_state = VerificationState::new(
        identity.node_id_hex(),
        env!("CARGO_PKG_VERSION").to_string(),
        policy.clone(),
        capabilities,
    );

    // Configure callbacks for health/status endpoints
    // Miner count now comes from share notifications via SRI forwarder
    verification_state = verification_state.with_callbacks(
        move || rm_for_height.current_height(),
        move || rm_for_round.current_round_id() as u64,
        move || {
            rm_for_miners
                .round_stats(rm_for_miners.current_round_id())
                .map(|s| s.miner_count as u32)
                .unwrap_or(0)
        },
        move || mesh_for_verification.peers().unique_peer_count() as u32,
    );

    // Configure archive handler if archive mode enabled
    if capabilities.archive_mode {
        let archive_handler = RpcArchiveHandler::new(Arc::clone(&rpc_for_verification));
        verification_state = verification_state.with_archive_handler(archive_handler);
    }

    // Configure GhostPay handler if ghost_pay enabled
    if let Some(ref gp_config) = config.ghost_pay {
        if gp_config.enabled {
            // Calculate virtual blocks from time since startup
            let startup_time = std::time::Instant::now();
            let virtual_block_secs = gp_config.virtual_block_secs;
            let epoch_blocks = gp_config.epoch_blocks;
            let wraith_enabled = gp_config.wraith_enabled;

            let ghostpay_handler = GhostPayL2Handler::new(
                true, // enabled
                move || {
                    // Virtual block = elapsed seconds / virtual_block_secs
                    startup_time.elapsed().as_secs() / virtual_block_secs.max(1)
                },
                move || {
                    // Epoch = virtual_block / epoch_blocks
                    let virtual_block =
                        startup_time.elapsed().as_secs() / virtual_block_secs.max(1);
                    virtual_block / epoch_blocks.max(1)
                },
                |_address| {
                    // No real L2 balances tracked - return 0
                    // In a full implementation, this would query the L2 state
                    Ok(0u64)
                },
                wraith_enabled,
            );
            verification_state = verification_state.with_ghostpay_handler(ghostpay_handler);
            info!(
                "GhostPay handler configured (virtual_block_secs={}, epoch_blocks={})",
                virtual_block_secs, epoch_blocks
            );
        }
    }

    // Pass database and RPC to verification state for API endpoints
    verification_state = verification_state.with_database((*db).clone());
    verification_state = verification_state.with_rpc(Arc::clone(&rpc));

    // Wire full node config for config update API
    // This allows the dashboard to modify settings via POST /api/internal/config/update
    verification_state =
        verification_state.with_full_node_config(config.clone(), args.config.clone());

    // Configure internal API authentication (AUTH4-1 security fix)
    if let Some(ref secret_hex) = config.network.internal_api_secret {
        match ghost_verification::InternalAuth::from_hex(secret_hex) {
            Ok(auth) => {
                info!("Internal API authentication configured for /api/internal/* and /admin/*");
                verification_state = verification_state.with_internal_auth(auth);
            }
            Err(e) => {
                error!(
                    "Invalid internal_api_secret: {} - internal endpoints will be UNPROTECTED",
                    e
                );
            }
        }
    } else {
        warn!(
            "AUTH4-1 WARNING: network.internal_api_secret not configured! \
             Internal endpoints (/api/internal/*, /admin/*) are UNPROTECTED. \
             Generate a secret with: openssl rand -hex 32"
        );
    }

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
            miner_payouts: vec![PayoutEntry {
                address: b"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_vec(), // Signet address
                amount: 100_000_000,                                             // 1 BTC test
                recipient_id: [1u8; 32],
                payout_type: PayoutType::Mining,
            }],
            node_payouts: vec![],
            treasury_amount: 1_000_000,                 // 0.01 BTC
            treasury_address: b"tb1qtreasury".to_vec(), // H-MINE-3: snapshot address (test)
            tx_fees: 500_000,
            subsidy: 312_500_000, // 3.125 BTC (signet subsidy)
            timestamp,
            tx_fees_unallocated: 0,
        };

        // Submit to vote handler (broadcasts to peers)
        vh_for_test.handle_proposal(proposal)
    });
    verification_state = verification_state.with_test_proposal_fn(test_proposal_fn);

    // Configure share recorder callback for SRI Pool share notifications
    let rm_for_shares = Arc::clone(&round_manager);
    let identity_for_shares = Arc::clone(&identity);
    let db_for_shares = Arc::clone(&db);
    verification_state = verification_state.with_share_recorder(move |share| {
        // Get current round ID for database record
        let round_id = rm_for_shares.current_round_id();

        // Record the share in the current round (in-memory tracking)
        rm_for_shares
            .record_share(&share.miner_id, share.work, identity_for_shares.node_id())
            .map_err(|e| ghost_common::GhostError::Internal(e.to_string()))?;

        // Persist share to database for historical tracking and auditing
        let share_record = ghost_storage::models::ShareRecord {
            id: None,
            round_id,
            miner_id: share.miner_id.clone(),
            difficulty: share.work, // SRI reports work as difficulty-adjusted value
            work: share.work,
            share_hash: share.share_hash.clone(),
            timestamp: share.timestamp as i64,
            received_by: hex::encode(&identity_for_shares.node_id()[..8]),
            valid: true, // Already validated by SRI Pool
        };

        if let Err(e) = db_for_shares.insert_share(&share_record) {
            // Log but don't fail - in-memory tracking is primary, DB is for auditing
            tracing::warn!(
                miner_id = %share.miner_id,
                share_hash = %share.share_hash,
                error = %e,
                "Failed to persist share to database"
            );
        }

        // Update miner's payout address in database if provided
        // The payout_address is extracted from user_identity (format: <address>.<worker>)
        if let Some(ref payout_address) = share.payout_address {
            if !payout_address.is_empty() {
                if let Err(e) = db_for_shares.update_miner_address(&share.miner_id, payout_address)
                {
                    tracing::warn!(
                        miner_id = %share.miner_id,
                        payout_address = %payout_address,
                        error = %e,
                        "Failed to update miner payout address"
                    );
                } else {
                    tracing::trace!(
                        miner_id = %share.miner_id,
                        payout_address = %payout_address,
                        "Updated miner payout address"
                    );
                }
            }
        }

        tracing::debug!(
            miner_id = %share.miner_id,
            work = share.work,
            round_id = round_id,
            "Share recorded from SRI notification"
        );
        Ok(())
    });

    // Configure block found handler for payout proposal creation from SRI webhook
    let rm_for_block = Arc::clone(&round_manager);
    let tp_for_block = Arc::clone(&template_processor);
    let payout_for_block = Arc::clone(&payout_handler);
    let identity_for_block = Arc::clone(&identity);
    let db_for_block = Arc::clone(&db);
    let solo_payout_address_for_block = config.network.solo_payout_address.clone();
    verification_state = verification_state.with_block_found_handler(move |notification: BlockFoundNotification| {
        let round_id = rm_for_block.current_round_id();
        let is_solo_mode = rm_for_block.is_solo_mode();

        info!(
            round = round_id,
            hash = %hex::encode(&notification.block_hash[..8]),
            miner = %notification.miner_id,
            solo_mode = is_solo_mode,
            "🎉 BLOCK FOUND via webhook! Creating payout proposal..."
        );

        // Gather data for payout proposal
        let node_shares = rm_for_block.get_node_shares(round_id);
        let (subsidy, fees, height) = tp_for_block.get_current_block_info();

        // Load treasury state from database
        // SEC-ERR-4: Log database errors instead of silently ignoring them
        let treasury_state = match db_for_block.get_treasury_balance() {
            Ok(balance) => {
                let threshold_ts = match db_for_block.get_treasury_threshold_reached() {
                    Ok(ts_opt) => ts_opt
                        .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
                        .map(|dt| dt.with_timezone(&chrono::Utc)),
                    Err(e) => {
                        warn!(error = %e, "Failed to load treasury threshold timestamp, using None");
                        None
                    }
                };
                TreasuryState::from_stored(balance, threshold_ts)
            }
            Err(e) => {
                warn!(error = %e, "Failed to load treasury state, using default");
                TreasuryState::new()
            }
        };

        // This node found the block
        let winning_node_id = identity_for_block.node_id();

        // Dispatch to appropriate payout handler based on mining mode
        if is_solo_mode {
            // Solo mode: 99% subsidy + ALL TX fees to solo_payout_address
            let solo_address = match &solo_payout_address_for_block {
                Some(addr) if !addr.is_empty() => addr.clone(),
                _ => {
                    error!("Solo mode block found but solo_payout_address not configured!");
                    return Err(ghost_common::GhostError::Config(
                        "solo_payout_address required for solo mode".to_string(),
                    ));
                }
            };

            // PO4-M2: Capture treasury address snapshot to prevent TOCTOU issues
            let treasury_address_snapshot = payout_for_block.get_treasury_address_snapshot();

            let solo_data = SoloBlockFoundData {
                round_id,
                block_hash: notification.block_hash,
                block_height: height,
                block_timestamp: chrono::Utc::now(),
                solo_payout_address: solo_address,
                subsidy_sats: subsidy,
                treasury_address_snapshot,
                tx_fees_sats: fees,
                node_shares,
                treasury_state,
            };

            match payout_for_block.handle_solo_block_found(solo_data) {
                Ok(proposal_hash) => {
                    if proposal_hash != [0u8; 32] {
                        info!(
                            round = round_id,
                            hash = %hex::encode(&proposal_hash[..8]),
                            "Solo mode payout proposal submitted for consensus"
                        );
                    }
                }
                Err(e) => {
                    error!(error = %e, round = round_id, "Failed to create solo mode payout proposal");
                }
            }
        } else {
            // Pool mode: proportional distribution to all miners
            let miner_work = rm_for_block.get_miner_work(round_id);

            // PO4-M2: Capture treasury address snapshot to prevent TOCTOU issues
            let treasury_address_snapshot = payout_for_block.get_treasury_address_snapshot();

            let block_data = BlockFoundData {
                round_id,
                block_hash: notification.block_hash,
                block_height: height,
                block_timestamp: chrono::Utc::now(),
                winning_miner_id: notification.miner_id.clone(),
                winning_miner_payout_address: notification.payout_address.clone(),
                treasury_address_snapshot,
                winning_node_id,
                subsidy_sats: subsidy,
                tx_fees_sats: fees,
                miner_work,
                node_shares,
                treasury_state,
            };

            match payout_for_block.handle_block_found(block_data) {
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

        Ok(())
    });

    let verification_state = Arc::new(verification_state);

    // Get restart signal for monitoring (config update API)
    let restart_signal = verification_state.restart_signal();

    // Start restart signal monitor task
    // When config is updated via API, this triggers graceful shutdown
    let restart_signal_for_monitor = Arc::clone(&restart_signal);
    let shutdown_tx_for_restart = shutdown_tx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            if restart_signal_for_monitor.load(std::sync::atomic::Ordering::SeqCst) {
                info!("Restart signal received (config update). Initiating graceful shutdown...");
                let _ = shutdown_tx_for_restart.send(());
                break;
            }
        }
    });
    info!("Restart signal monitor started (for config update API)");

    // Start WebSocket health broadcast task
    let ws_state = Arc::clone(&verification_state.ws_state);
    let rm_for_ws = Arc::clone(&round_manager);
    let mesh_for_ws = Arc::clone(&mesh);
    let start_time = std::time::Instant::now();
    let mut ws_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let miner_count = rm_for_ws
                        .round_stats(rm_for_ws.current_round_id())
                        .map(|s| s.miner_count as u32)
                        .unwrap_or(0);
                    let event = ghost_verification::WsEvent::HealthUpdate {
                        block_height: rm_for_ws.current_height(),
                        round_id: rm_for_ws.current_round_id() as u64,
                        miner_count,
                        peer_count: mesh_for_ws.peers().unique_peer_count() as u32,
                        uptime_secs: start_time.elapsed().as_secs(),
                    };
                    ws_state.broadcast(event);
                }
                _ = ws_shutdown.recv() => break,
            }
        }
    });

    // Start self-uptime recording task
    // Records our own uptime so we can be qualified for payouts
    // This is necessary because verification results are stored by OTHER nodes about us,
    // but we need our own uptime record for the gatekeeper calculation (95% over 7 days).
    // Without self-recording, this node would have no uptime data ABOUT itself.
    let db_for_uptime = Arc::clone(&db);
    let node_id_for_uptime = identity.node_id_hex();
    let mut uptime_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        let mut sample_count: u64 = 0;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let now = chrono::Utc::now().timestamp();
                    match db_for_uptime.record_uptime_sample(&node_id_for_uptime, now, true) {
                        Ok(_) => {
                            sample_count += 1;
                            // Log every 360 samples (~1 hour) to confirm it's working
                            if sample_count.is_multiple_of(360) {
                                tracing::debug!(
                                    samples = sample_count,
                                    node_id = %&node_id_for_uptime[..8],
                                    "Self-uptime recording checkpoint"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                node_id = %&node_id_for_uptime[..8],
                                "Failed to record self-uptime sample"
                            );
                        }
                    }
                }
                _ = uptime_shutdown.recv() => {
                    tracing::info!(
                        total_samples = sample_count,
                        "Self-uptime recording task shutting down"
                    );
                    break;
                }
            }
        }
    });
    info!(
        node_id = %&node_id_hex[..8],
        interval_secs = 10,
        "Self-uptime recording task started"
    );

    // Start ban manager cleanup task (C1 security fix)
    // Periodically cleans up expired bans to prevent memory growth
    let ban_manager_for_cleanup = Arc::clone(&ban_manager);
    let mut ban_cleanup_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let removed = ban_manager_for_cleanup.cleanup_expired();
                    if removed > 0 {
                        tracing::debug!(removed, "Cleaned up expired bans");
                    }
                }
                _ = ban_cleanup_shutdown.recv() => {
                    tracing::info!("Ban manager cleanup task shutting down");
                    break;
                }
            }
        }
    });
    info!("Ban manager cleanup task started (60s interval)");

    // M-MINE-2: Start rate limit cleanup task for RoundManager
    // Periodically cleans up old rate limit entries to prevent memory growth
    let rm_for_cleanup = Arc::clone(&round_manager);
    let mut rate_limit_cleanup_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    rm_for_cleanup.cleanup_rate_limits();
                }
                _ = rate_limit_cleanup_shutdown.recv() => {
                    tracing::info!("Rate limit cleanup task shutting down");
                    break;
                }
            }
        }
    });
    info!("Rate limit cleanup task started (60s interval)");

    // Clone ws_state for event handlers before moving verification_state
    let _verification_state_for_ws = Arc::clone(&verification_state);

    let http_port = config.network.http_port;
    tokio::spawn(async move {
        if let Err(e) = start_server(verification_state, http_port).await {
            error!(error = %e, "Verification server error");
        }
    });
    info!("HTTP API listening on port {}", http_port);

    // Subscribe to template events BEFORE starting the processor to avoid race condition
    // (the processor fires NewWork immediately on first refresh)
    let mut template_events_early = template_processor.subscribe();

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

    // Note: Native stratum server removed - SRI handles all miner connections via TDP

    // Start Template Distribution Protocol server (for SRI pool integration)
    if args.tdp_enabled {
        // Load node key bytes for TDP Noise authentication
        // The key file contains 32 bytes of private key (+ optional 12 bytes PoW proof)
        let key_path = data_dir.join("node.key");
        let key_bytes = std::fs::read(&key_path)
            .map_err(|e| anyhow::anyhow!("Failed to read node key for TDP: {}", e))?;

        // HIGH-6: Proper error handling instead of panic on short key file
        if key_bytes.len() < 32 {
            return Err(anyhow::anyhow!(
                "Node key file '{}' is too short: expected at least 32 bytes, got {}. \
                 Generate a new key with: ghost-pool --generate-identity",
                key_path.display(),
                key_bytes.len()
            ));
        }
        let tdp_secret_key: [u8; 32] = key_bytes[..32]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Node key slice conversion failed"))?;

        // L-26: Use proper error handling instead of expect()
        let mut tdp_config = TdpConfig::new(tdp_secret_key).map_err(|e| {
            anyhow::anyhow!(
                "L-26: Invalid TDP secret key from node key file '{}': {}. \
                 The key may be all zeros or outside the valid secp256k1 scalar range. \
                 Regenerate with: ghost-pool --generate-identity",
                key_path.display(),
                e
            )
        })?;
        tdp_config.port = args.tdp_port;
        tdp_config.max_connections = 10;
        tdp_config.timeout_secs = 30;

        info!(
            "TDP authority public key: {} (use this in SRI pool config)",
            tdp_config.authority_pubkey_base58()
        );

        let tdp_server = TemplateDistributionServer::new(
            tdp_config,
            Arc::clone(&template_processor),
            shutdown_tx.subscribe(),
        );

        tokio::spawn(async move {
            if let Err(e) = tdp_server.run().await {
                error!(error = %e, "TDP server error");
            }
        });

        info!(
            "TDP server listening on port {} (Template Distribution Protocol for SRI pool)",
            args.tdp_port
        );
    }

    // Start P2P mesh
    let m = Arc::clone(&mesh);
    tokio::spawn(async move {
        if let Err(e) = m.start().await {
            error!(error = %e, "Mesh network error");
        }
    });
    info!("P2P mesh network started");

    // C-1: Start Noise Protocol listener for encrypted P2P connections
    // This listens for incoming encrypted TCP connections from peers
    if let Some(noise_pool) = mesh.noise_pool() {
        let noise_pool_clone = Arc::clone(noise_pool);
        let mesh_for_noise = Arc::clone(&mesh);
        let noise_port = ghost_consensus::mesh::DEFAULT_NOISE_PORT;

        tokio::spawn(async move {
            use tokio::net::TcpListener;

            let bind_addr = format!("0.0.0.0:{}", noise_port);
            let listener = match TcpListener::bind(&bind_addr).await {
                Ok(l) => {
                    info!(
                        port = noise_port,
                        "Noise Protocol listener started (encrypted P2P)"
                    );
                    l
                }
                Err(e) => {
                    error!(error = %e, port = noise_port, "Failed to start Noise listener");
                    return;
                }
            };

            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let pool = Arc::clone(&noise_pool_clone);
                        let mesh = Arc::clone(&mesh_for_noise);

                        tokio::spawn(async move {
                            match pool.accept_connection(stream).await {
                                Ok(conn) => {
                                    tracing::debug!(
                                        peer = %addr,
                                        peer_key = %hex::encode(&conn.peer_key[..8]),
                                        "Accepted Noise connection"
                                    );

                                    // Handle incoming messages from this connection
                                    // Messages are received, validated, and dispatched to handlers
                                    loop {
                                        match conn.recv().await {
                                            Ok(payload) => {
                                                // Process received encrypted message through the mesh handler
                                                if let Err(e) = mesh.handle_received(&payload).await
                                                {
                                                    tracing::debug!(
                                                        peer = %addr,
                                                        error = %e,
                                                        "Error handling Noise message"
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                tracing::debug!(
                                                    peer = %addr,
                                                    error = %e,
                                                    "Noise connection error"
                                                );
                                                // Remove broken connection
                                                pool.remove_connection(&conn.peer_key);
                                                break;
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        peer = %addr,
                                        error = %e,
                                        "Noise handshake failed"
                                    );
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Noise accept error");
                    }
                }
            }
        });
    } else {
        warn!("Noise Protocol DISABLED - P2P traffic is unencrypted");
    }

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
            match mesh_for_discovery
                .broadcast_message(ghost_consensus::MessageType::Discovery, &discovery_msg)
                .await
            {
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

    // Start periodic verification task (verifies peer capabilities every 5 minutes)
    // This implements the spec: nodes verify each other, results stored in DB for payout calculation
    let peer_provider = Arc::new(PeerProviderAdapter::new(
        Arc::clone(mesh.peers()),
        config.network.http_port,
    ));

    // Create broadcast channel for verification results
    let (verification_tx, mut verification_rx) =
        ghost_verification::task::verification_broadcast_channel(100);

    // C-3: Handle Result from VerificationTask::new() instead of panicking
    match VerificationTask::new(
        Arc::clone(&db),
        identity.node_id(),
        peer_provider as Arc<dyn PeerProvider>,
    ) {
        Ok(verification_task) => {
            let verification_task = verification_task
                .with_rpc(Arc::clone(&rpc))
                .with_broadcast(verification_tx);

            tokio::spawn(async move {
                // Wait for mesh to establish connections before starting verification
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                verification_task.run().await;
            });
            info!("Verification task started (5 minute interval)");
        }
        Err(e) => {
            error!(error = %e, "Failed to create verification task - verification disabled");
        }
    }

    // Start verification result broadcaster (sends results to other nodes via P2P)
    let mesh_for_verification = Arc::clone(&mesh);
    let identity_for_verification = Arc::clone(&identity);
    tokio::spawn(async move {
        use ghost_consensus::message::{CapabilityType, MessageType, VerificationResultMessage};

        while let Some(broadcast) = verification_rx.recv().await {
            let target_short = hex::encode(&broadcast.target_node_id[..4]);
            let challenger_short = hex::encode(&broadcast.challenger_id[..4]);

            info!(
                target = %target_short,
                challenger = %challenger_short,
                capability = %broadcast.capability,
                passed = broadcast.passed,
                "DIAG: Broadcasting verification result to P2P mesh"
            );

            // Convert the capability to the message enum
            let capability = match broadcast.capability.as_str() {
                "archive" => CapabilityType::Archive,
                "policy" => CapabilityType::Policy,
                "stratum" => CapabilityType::Stratum,
                "ghostpay" => CapabilityType::GhostPay,
                other => {
                    warn!(capability = %other, "Unknown capability type, skipping broadcast");
                    continue;
                }
            };

            // Sign the verification result
            let mut signing_data = Vec::new();
            signing_data.extend_from_slice(&broadcast.target_node_id);
            signing_data.extend_from_slice(broadcast.capability.as_bytes());
            signing_data.push(if broadcast.passed { 1 } else { 0 });
            signing_data.extend_from_slice(&broadcast.timestamp.to_le_bytes());
            let signature = identity_for_verification.sign(&signing_data);

            let msg = VerificationResultMessage {
                target_node_id: broadcast.target_node_id,
                challenger_id: broadcast.challenger_id,
                capability,
                passed: broadcast.passed,
                timestamp: broadcast.timestamp,
                challenge_data: broadcast.challenge_data,
                response_data: broadcast.response_data,
                signature,
            };

            // Get peer count before broadcast for logging
            let peer_count = mesh_for_verification.peers().peer_count();
            let connected_count = mesh_for_verification.peers().connected_count();

            match mesh_for_verification
                .broadcast_message(MessageType::VerificationResult, &msg)
                .await
            {
                Ok(sent) => {
                    info!(
                        target = %target_short,
                        capability = %broadcast.capability,
                        passed = broadcast.passed,
                        sent_to = sent,
                        total_peers = peer_count,
                        connected_peers = connected_count,
                        "DIAG: Verification result broadcast complete"
                    );
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        target = %target_short,
                        capability = %broadcast.capability,
                        peer_count = peer_count,
                        connected_count = connected_count,
                        "DIAG: Failed to broadcast verification result"
                    );
                }
            }
        }
    });
    info!("Verification result broadcaster started");

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

        let zmq_subscriber = ZmqSubscriber::new(zmq_config).map_err(|e| {
            anyhow::anyhow!(
                "ZMQ security validation failed: {}. Only localhost endpoints are allowed.",
                e
            )
        })?;
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

        // IMPORTANT: Keep zmq_subscriber alive for the lifetime of the program.
        // If dropped, the shutdown channel closes and ZMQ tasks terminate immediately.
        std::mem::forget(zmq_subscriber);
    }

    // Handle template events for round management
    // (subscription was created earlier before template processor started)
    // Note: Job notifications to miners now handled by SRI via TDP
    let rm_notify = Arc::clone(&round_manager);
    let tp_for_template_events = Arc::clone(&template_processor);

    tokio::spawn(async move {
        while let Ok(event) = template_events_early.recv().await {
            match event {
                TemplateEvent::NewWork { job_id: _, height } => {
                    // Start new round (SRI gets jobs via TDP automatically)
                    rm_notify.start_round(height);

                    // M-MINE-1: Update template ID for share validation
                    // The template ID is the prev_block_hash which uniquely identifies the template
                    if let Some(work_state) = tp_for_template_events.current_work() {
                        // Parse prev_hash hex string to [u8; 32]
                        if let Ok(prev_hash_bytes) = hex::decode(&work_state.prev_hash) {
                            if prev_hash_bytes.len() == 32 {
                                let mut template_id = [0u8; 32];
                                template_id.copy_from_slice(&prev_hash_bytes);
                                rm_notify.set_template_id(template_id);
                            }
                        }
                    }
                }
                TemplateEvent::TransactionsFiltered {
                    original_count,
                    filtered_count,
                    removed_fees,
                } => {
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

    // Clone refs for the async round event handler
    let rm_for_events = Arc::clone(&round_manager);
    let tp_for_events = Arc::clone(&template_processor);
    let payout_for_events = Arc::clone(&payout_handler);
    let identity_for_events = Arc::clone(&identity);
    let db_for_events = Arc::clone(&db);
    let solo_payout_address_for_events = config.network.solo_payout_address.clone();

    // Subscribe to round events and handle block found
    let mut round_events = round_manager.subscribe();
    tokio::spawn(async move {
        while let Ok(event) = round_events.recv().await {
            match event {
                RoundEvent::BlockFound {
                    round_id,
                    block_hash,
                    miner_id,
                } => {
                    let is_solo_mode = rm_for_events.is_solo_mode();
                    info!(
                        round = round_id,
                        hash = %hex::encode(&block_hash[..8]),
                        miner = %miner_id,
                        solo_mode = is_solo_mode,
                        "🎉 BLOCK FOUND! Creating payout proposal..."
                    );

                    // Gather data for payout proposal
                    let node_shares = rm_for_events.get_node_shares(round_id);

                    // Get block subsidy and fees from template processor
                    let (subsidy, fees, height) = tp_for_events.get_current_block_info();

                    // Load treasury state from database for decay calculation
                    // SEC-ERR-4: Log database errors instead of silently ignoring them
                    let treasury_state = match db_for_events.get_treasury_balance() {
                        Ok(balance) => {
                            let threshold_ts = match db_for_events.get_treasury_threshold_reached() {
                                Ok(ts_opt) => ts_opt
                                    .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
                                    .map(|dt| dt.with_timezone(&chrono::Utc)),
                                Err(e) => {
                                    warn!(error = %e, "Failed to load treasury threshold timestamp, using None");
                                    None
                                }
                            };
                            TreasuryState::from_stored(balance, threshold_ts)
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to load treasury state, using default");
                            TreasuryState::new()
                        }
                    };

                    // Dispatch based on mining mode
                    if is_solo_mode {
                        // Solo mode: 99% subsidy + ALL TX fees to solo_payout_address
                        let solo_address = match &solo_payout_address_for_events {
                            Some(addr) if !addr.is_empty() => addr.clone(),
                            _ => {
                                error!(
                                    "Solo mode block found but solo_payout_address not configured!"
                                );
                                continue;
                            }
                        };

                        // PO4-M2: Capture treasury address snapshot
                        let treasury_address_snapshot =
                            payout_for_events.get_treasury_address_snapshot();

                        let solo_data = SoloBlockFoundData {
                            round_id,
                            block_hash,
                            block_height: height,
                            block_timestamp: chrono::Utc::now(),
                            solo_payout_address: solo_address,
                            subsidy_sats: subsidy,
                            treasury_address_snapshot,
                            tx_fees_sats: fees,
                            node_shares,
                            treasury_state,
                        };

                        match payout_for_events.handle_solo_block_found(solo_data) {
                            Ok(proposal_hash) => {
                                if proposal_hash != [0u8; 32] {
                                    info!(
                                        round = round_id,
                                        hash = %hex::encode(&proposal_hash[..8]),
                                        "Solo mode payout proposal submitted for consensus"
                                    );
                                }
                            }
                            Err(e) => {
                                error!(error = %e, round = round_id, "Failed to create solo mode payout proposal");
                            }
                        }
                    } else {
                        // Pool mode: proportional distribution to all miners
                        let miner_work = rm_for_events.get_miner_work(round_id);
                        let winning_node_id = identity_for_events.node_id();

                        // PO4-M2: Capture treasury address snapshot
                        let treasury_address_snapshot =
                            payout_for_events.get_treasury_address_snapshot();

                        let block_data = BlockFoundData {
                            round_id,
                            block_hash,
                            block_height: height,
                            block_timestamp: chrono::Utc::now(),
                            winning_miner_id: miner_id.clone(),
                            winning_miner_payout_address: None, // Address looked up from DB
                            treasury_address_snapshot,
                            winning_node_id,
                            subsidy_sats: subsidy,
                            tx_fees_sats: fees,
                            miner_work,
                            node_shares,
                            treasury_state,
                        };

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
                }
                RoundEvent::ShareSubmitted {
                    round_id: _,
                    miner_id: _,
                    work: _,
                } => {
                    // Log periodically, not every share
                }
                _ => {}
            }
        }
    });

    // Note: Stratum events now come from SRI, not ghost-pool
    // WebSocket broadcast for miner events would need SRI integration

    // Start registry client for load balancer registration (only for PublicPool mode)
    // Private modes (PrivatePool, PrivateSolo) skip DNS registration
    // Store registry client for deregistration on shutdown
    let registry_client_for_shutdown: Option<Arc<RegistryClient>> = if !matches!(
        mining_mode,
        MiningMode::PublicPool
    ) {
        info!(
            "Mining mode {:?}: skipping DNS registration (private mode)",
            mining_mode
        );
        None
    } else if let Some(ref registry_config) = config.registry {
        if !registry_config.url.is_empty() {
            let host = config
                .network
                .public_address
                .clone()
                .unwrap_or_else(|| "".to_string());

            if host.is_empty() {
                warn!("Registry configured but network.public_address is not set - skipping registration");
                None
            } else if let Some(ref signing_key) = config.network.signing_key {
                match RegistryClient::new(
                    signing_key,
                    registry_config.clone(),
                    host,
                    config.network.sv1_port,
                    config.network.sv2_port,
                    config.network.max_miners,
                ) {
                    Ok(registry_client) => {
                        let registry_client = Arc::new(registry_client);
                        let registry_for_task = Arc::clone(&registry_client);
                        let registry_shutdown = shutdown_tx.subscribe();
                        tokio::spawn(async move {
                            registry_for_task
                                .start(
                                    move || 0_u32, // Miner count from SRI (not tracked here)
                                    registry_shutdown,
                                )
                                .await;
                        });

                        info!(
                            "Registry client started (heartbeat every {}s)",
                            registry_config.heartbeat_interval_secs
                        );
                        Some(registry_client)
                    }
                    Err(e) => {
                        error!("Failed to create registry client: {}", e);
                        None
                    }
                }
            } else {
                warn!("Registry configured but network.signing_key is not set - skipping registration");
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    // Print startup summary
    info!("════════════════════════════════════════════════════════════════");
    info!("Ghost Pool is ready!");
    info!("  Stratum:    via SRI (connect to TDP)");
    if args.tdp_enabled {
        info!("  TDP:        0.0.0.0:{}", args.tdp_port);
    }
    info!("  HTTP API:   0.0.0.0:{}", http_port);
    info!("  Policy:     {}", policy.name);
    info!("  Shares:     {}/15", capabilities.total_shares());
    info!("════════════════════════════════════════════════════════════════");

    // Verify template processor has work (for TDP job delivery)
    {
        let tp_check = Arc::clone(&template_processor);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            match tp_check.current_work() {
                Some(work) => {
                    info!(
                        height = work.height,
                        job_id = %work.job_id,
                        "STARTUP CHECK: Template processor has work available"
                    );
                }
                None => {
                    error!("STARTUP CHECK: Template processor has NO work - SRI won't receive templates!");
                }
            }
        });
    }

    // Wait for shutdown signal (ctrl+c or restart signal from config update)
    let mut shutdown_rx = shutdown_tx.subscribe();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl+C, shutting down Ghost Pool...");
        }
        _ = shutdown_rx.recv() => {
            // Shutdown triggered by restart signal monitor
            if restart_signal.load(std::sync::atomic::Ordering::SeqCst) {
                info!("Shutting down for restart (config update)...");
            } else {
                info!("Shutting down Ghost Pool...");
            }
        }
    }

    // Send shutdown signal to all tasks
    let _ = shutdown_tx.send(());

    // Deregister from load balancer (if registered)
    if let Some(registry_client) = registry_client_for_shutdown {
        info!("Deregistering from load balancer...");
        if let Err(e) = registry_client.deregister().await {
            warn!("Failed to deregister from load balancer: {}", e);
        }
    }

    // Cleanup
    template_processor.stop();
    mesh.stop().await?;

    // Check if this was a restart request
    if restart_signal.load(std::sync::atomic::Ordering::SeqCst) {
        info!(
            "Ghost Pool shutdown complete. Exiting with code {} for systemd restart.",
            EXIT_CODE_RESTART
        );
        std::process::exit(EXIT_CODE_RESTART);
    }

    info!("Ghost Pool shutdown complete");
    Ok(())
}

/// Expand ~ in path
fn expand_path(path: &std::path::Path) -> Result<PathBuf> {
    let path_str = path.to_string_lossy();
    if let Some(stripped) = path_str.strip_prefix("~/") {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map_err(|_| anyhow::anyhow!("Could not determine home directory"))?;
        Ok(PathBuf::from(home).join(stripped))
    } else {
        Ok(path.to_path_buf())
    }
}

/// Load configuration from file
fn load_config(path: &std::path::Path) -> Result<NodeConfig> {
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
