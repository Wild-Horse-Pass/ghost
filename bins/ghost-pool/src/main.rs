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
use std::sync::{Arc, OnceLock};
use tokio::sync::{broadcast, Semaphore};
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use ghost_common::config::{MiningMode, NodeConfig};
use ghost_common::identity::NodeIdentity;
use ghost_common::metrics::Metrics;
use ghost_common::rpc::BitcoinRpc;
use ghost_common::signer::SignerConfig;
use ghost_common::types::{ConsensusResult, NodeCapabilities};
use ghost_common::zmq::{ZmqConfig, ZmqSubscriber};
use ghost_consensus::ban_manager::BanManager;
use ghost_consensus::health_handler::HealthPingHandler;
use ghost_consensus::mesh::{MeshConfig, MeshNetwork};
use ghost_consensus::message::MessageType;
use ghost_consensus::verification_handler::VerificationResultHandler;
use ghost_consensus::vote_handler::{
    BroadcastFn, ExecuteFn, ProposalStoreFn, VoteHandler, VoteHandlerConfig,
};
use ghost_consensus::voting::VotingManager;
use ghost_policy::PolicyProfile;
use ghost_reaper::ReaperConfig;
use ghost_storage::Database;
use ghost_verification::{
    start_server, GspHandler, PeerProvider, QualifiedCapabilityProvider, RpcArchiveHandler,
    VerifiablePeer, VerificationState, VerificationTask,
};

use ghost_pool::payout::{BlockFoundData, PayoutConfig, PayoutHandler, SoloBlockFoundData};
use ghost_pool::registry::RegistryClient;
use ghost_pool::reorg::{ReorgConfig, ReorgHandler};
use ghost_pool::round::{RoundConfig, RoundEvent, RoundManager};
use ghost_pool::share_handler::ShareProofHandler;
use ghost_pool::template::{TemplateConfig, TemplateEvent, TemplateProcessor};
use ghost_pool::template_provider::{TdpConfig, TemplateDistributionServer};
use ghost_pool::treasury::TreasuryState;

/// Exit code that signals systemd to restart the service
/// Used when config is updated via API and requires restart to apply
const EXIT_CODE_RESTART: i32 = 100;

/// H-8 SECURITY: Static storage for ZMQ subscriber to prevent memory leak.
/// Previously used std::mem::forget which intentionally leaked memory.
/// Using OnceLock ensures the subscriber lives for the program lifetime
/// without leaking, and can be properly dropped on program exit.
static ZMQ_SUBSCRIBER: OnceLock<ZmqSubscriber> = OnceLock::new();

/// GSP handler that caches status from periodic HTTP polls to the GSP service
struct CachedGspHandler {
    cache: Arc<parking_lot::RwLock<GspCachedState>>,
}

#[derive(Default)]
struct GspCachedState {
    enabled: bool,
    protocol_version: String,
    network: String,
    connections: u32,
    registered_wallets: u32,
    sync_status: String,
}

impl CachedGspHandler {
    fn new(gsp_url: String) -> Self {
        let cache = Arc::new(parking_lot::RwLock::new(GspCachedState::default()));
        let poll_cache = Arc::clone(&cache);

        // C-04: Validate GSP URL is a loopback address to prevent MITM on health checks
        let is_loopback = gsp_url.contains("127.0.0.1")
            || gsp_url.contains("localhost")
            || gsp_url.contains("[::1]");

        if !is_loopback {
            tracing::warn!(
                url = %gsp_url,
                "C-04: GSP URL is not a loopback address — TLS verification enforced. \
                 Use 127.0.0.1 or localhost for local GSP connections."
            );
        }

        // Background task polls GSP info every 30s
        tokio::spawn(async move {
            let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(5));
            // C-04: Only accept invalid certs for loopback addresses (self-signed localhost)
            let client = if is_loopback {
                client.danger_accept_invalid_certs(true)
            } else {
                client
            };
            let client = client.build().unwrap_or_default();
            loop {
                match client.get(format!("{}/api/v1/info", gsp_url)).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(info) = resp.json::<serde_json::Value>().await {
                            let mut state = poll_cache.write();
                            state.enabled = true;
                            state.protocol_version = info
                                .get("protocol_version")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                            state.network = info
                                .get("network")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                            state.connections =
                                info.get("connections")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0) as u32;
                            state.sync_status = info
                                .get("sync_status")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                        }
                    }
                    _ => {
                        poll_cache.write().enabled = false;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
        });

        Self { cache }
    }
}

impl GspHandler for CachedGspHandler {
    fn is_enabled(&self) -> bool {
        self.cache.read().enabled
    }
    fn get_protocol_version(&self) -> String {
        self.cache.read().protocol_version.clone()
    }
    fn get_network(&self) -> String {
        self.cache.read().network.clone()
    }
    fn get_connection_count(&self) -> u32 {
        self.cache.read().connections
    }
    fn get_registered_wallets(&self) -> u32 {
        self.cache.read().registered_wallets
    }
    fn get_sync_status(&self) -> String {
        self.cache.read().sync_status.clone()
    }
    fn health_check(&self) -> ghost_common::GhostResult<bool> {
        Ok(self.cache.read().enabled)
    }
}

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

                // CRIT-VER-1: Extract IP address for Sybil resistance
                let ip_address = Some(host.to_string());

                // CRIT-VER-1: Uptime info for reputation weighting
                // Default to None, will be filled by verification task from DB
                let uptime = None;

                VerifiablePeer {
                    node_id: p.node_id,
                    http_address: format!("{}:{}", host, self.http_port),
                    uptime,
                    ip_address,
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

    /// Initialize MPC genesis (only use on first node in network)
    #[arg(long)]
    genesis: bool,

    /// Password for genesis initialization (must match genesis_password in pool config)
    #[arg(long)]
    genesis_password: Option<String>,

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
    let mut rpc = BitcoinRpc::new(
        rpc_host,
        rpc_port,
        &config.bitcoin.rpc_user,
        &config.bitcoin.rpc_password,
    )?;
    rpc.set_network(config.bitcoin.network);
    let rpc = Arc::new(rpc);

    // Test RPC connection
    let blockchain_info = match rpc.get_blockchain_info().await {
        Ok(info) => {
            info!(
                chain = %info.chain,
                height = info.blocks,
                difficulty = info.difficulty,
                "Connected to Bitcoin Core"
            );
            info
        }
        Err(e) => {
            error!(error = %e, "Failed to connect to Bitcoin Core");
            return Err(anyhow::anyhow!("Bitcoin RPC connection failed: {}", e));
        }
    };

    // Query Tor mode status from Ghost Core
    let tor_status = match rpc.get_tor_mode().await {
        Ok(status) => {
            if status.enabled {
                info!(
                    onion_address = status.onion_address.as_deref().unwrap_or("pending"),
                    embedded = status.embedded_tor,
                    "Tor mode active on Ghost Core"
                );
            }
            Some(status)
        }
        Err(e) => {
            // gettormode may not exist on older Ghost Core versions
            debug!(error = %e, "Could not query Tor mode (older ghostd?)");
            None
        }
    };

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

    // Setup reaper config for dead code detection
    let reaper_config = if !config.reaper.enabled {
        ReaperConfig::disabled()
    } else {
        match config.reaper.mode.as_str() {
            "strict" => ReaperConfig::strict(),
            "moderate" => ReaperConfig::moderate(),
            "monitor" => ReaperConfig::monitor(),
            _ => {
                warn!(
                    mode = %config.reaper.mode,
                    "Unknown reaper mode, defaulting to strict"
                );
                ReaperConfig::strict()
            }
        }
    };
    info!(
        "Reaper: {} (mode: {})",
        if reaper_config.enabled {
            "enabled"
        } else {
            "disabled"
        },
        config.reaper.mode
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
        reaper: config.reaper.enabled && config.reaper.mode == "strict",
        elder_status: false,
    };

    // Register node with database
    let node_id_hex = identity.node_id_hex();
    let public_address = config.network.public_address.as_deref();
    let display_name = config.identity.display_name.as_deref();
    let capabilities_str = format!(
        "archive:{},ghost_pay:{},public_mining:{},reaper:{}",
        capabilities.archive_mode,
        capabilities.ghost_pay,
        capabilities.public_mining,
        capabilities.reaper
    );

    // Register node in database (for tracking/discovery purposes)
    if let Err(e) = db.register_node_with_elder_check(
        &node_id_hex,
        public_address,
        display_name,
        &capabilities_str,
    ) {
        warn!("Failed to register node: {} - continuing anyway", e);
    }

    // Set local node's payout address for node reward distribution
    if let Some(ref addr) = config.pool.node_payout_address {
        if let Err(e) = db.update_node_payout_address(&node_id_hex, addr) {
            warn!(
                "Failed to set node payout address: {} - continuing anyway",
                e
            );
        } else {
            info!(address = %addr, "Node payout address configured");
        }
    }

    // Check MPC-based elder status
    // Elder = MPC contributor (position 1-101 in the ceremony)
    match db.get_mpc_elder_position(&node_id_hex) {
        Ok(Some(position)) => {
            capabilities.elder_status = true;
            info!("Node is MPC Elder #{}", position);
        }
        Ok(None) => {
            info!(
                "Node is not an MPC elder ({} MPC contributors exist)",
                db.get_mpc_elder_count().unwrap_or(0)
            );
        }
        Err(e) => {
            warn!(
                "Failed to check MPC elder status: {} - defaulting to non-elder",
                e
            );
        }
    }

    // Hazed nodes cannot claim archive mode — they strip witness/scriptSig/OP_RETURN data
    if blockchain_info.hazed && capabilities.archive_mode {
        warn!("Ghost Core is running in haze mode — disabling archive_mode capability (+5 shares)");
        capabilities.archive_mode = false;
    }

    info!("Capability shares: {}/15", capabilities.total_shares());

    // Create identity Arc
    let identity = Arc::new(identity);

    // Prometheus metrics
    let metrics = Metrics::default_metrics();

    // Initialize round manager with mining mode
    let is_mainnet_round = config.bitcoin.network == ghost_common::config::BitcoinNetwork::Mainnet;
    let round_config = RoundConfig {
        mining_mode,
        ..Default::default()
    };
    let mut round_manager_inner = RoundManager::new(identity.node_id(), round_config);
    round_manager_inner.set_metrics(Arc::clone(&metrics));
    let round_manager = Arc::new(round_manager_inner);

    // Register our own node's capabilities so we're included in node reward calculations
    // This is critical - without this, our shares won't be counted for node rewards
    round_manager.register_node(identity.node_id(), capabilities);

    // Reload pre-restart share data from database so miners don't lose credit
    round_manager.reload_from_db(&db);

    // Resolve coinbase tag: coinbase_extra > pool_name formatted > mode default
    let coinbase_tag = config
        .pool
        .coinbase_extra
        .clone()
        .or_else(|| {
            config
                .pool
                .pool_name
                .as_ref()
                .map(|name| format!("- G H O S T - {}", name))
        })
        .unwrap_or_else(|| mining_mode.default_coinbase_tag().to_string());

    // Write tag file so SRI pool service can pick it up via ExecStartPre
    let tag_path = data_dir.join("coinbase_tag");
    if let Err(e) = std::fs::write(&tag_path, &coinbase_tag) {
        warn!(error = %e, "Failed to write coinbase tag file");
    }
    info!(tag = %coinbase_tag, "Coinbase tag: {}", coinbase_tag);

    // Initialize template processor with treasury and pool payout addresses from config
    // Pool payout address defaults to treasury address if not explicitly configured separately
    let template_config = TemplateConfig {
        treasury_address: config.pool.treasury_address.clone(),
        pool_payout_address: config.pool.treasury_address.address().to_string(), // Use same as treasury for now
        network: config.bitcoin.network,
        mining_mode,
        solo_payout_address: config.network.solo_payout_address.clone(),
        coinbase_extra: coinbase_tag,
        ..Default::default()
    };
    let template_processor = Arc::new(
        TemplateProcessor::new(
            template_config,
            Arc::clone(&rpc),
            policy.clone(),
            reaper_config,
        )
        .with_database(Arc::clone(&db)),
    );
    // Restore any previously approved payout proposal from database
    template_processor.restore_from_db();

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
        noise_required: true,
        payout_address: config.pool.node_payout_address.clone(),
        ..Default::default()
    };
    // M-2: Use try_new() to properly handle Noise initialization failures
    let mesh = Arc::new(MeshNetwork::try_new(Arc::clone(&identity), mesh_config)?);

    // Initialize consensus voting
    let voting_manager = Arc::new(VotingManager::new(100)); // 100 max sessions

    // Create broadcast callback for vote propagation via Noise relay
    let (vote_tx, mut vote_rx) =
        tokio::sync::mpsc::channel::<(ghost_consensus::message::MessageType, Vec<u8>)>(64);
    let mesh_for_vote_relay = Arc::clone(&mesh);
    tokio::spawn(async move {
        while let Some((msg_type, payload)) = vote_rx.recv().await {
            match mesh_for_vote_relay.create_envelope_raw(msg_type, payload) {
                Ok(envelope) => {
                    if let Err(e) = mesh_for_vote_relay.broadcast(envelope).await {
                        tracing::warn!(error = %e, "Vote Noise broadcast failed");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Vote envelope creation failed");
                }
            }
        }
    });
    let broadcast_fn: BroadcastFn = Arc::new(move |msg_type, payload| {
        vote_tx.try_send((msg_type, payload)).map_err(|e| {
            ghost_common::error::GhostError::Internal(format!(
                "Vote broadcast channel error: {}",
                e
            ))
        })
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
    // BFT voter threshold: mainnet requires 7 (f=2), non-mainnet allows 3 (f=1)
    let rate_limiter_path = data_dir.join("rate_limiter.json");
    let vote_config = VoteHandlerConfig {
        min_voters_for_bft: if is_mainnet_round { 7 } else { 3 },
        ..VoteHandlerConfig::default()
    };
    // Create proposal store callback so remote nodes store proposal data
    // in the template processor when proposals arrive via P2P
    let tp_for_proposal_store = Arc::clone(&template_processor);
    let proposal_store_fn: ProposalStoreFn = Arc::new(move |proposal| {
        tp_for_proposal_store.store_proposal(proposal);
    });

    let vote_handler = Arc::new(
        VoteHandler::with_config(
            Arc::clone(&identity),
            Arc::clone(&voting_manager),
            vote_config,
        )
        .with_broadcaster(broadcast_fn)
        .with_executor(execute_fn)
        .with_proposal_store(proposal_store_fn)
        .with_ban_manager(Arc::clone(&ban_manager))
        .with_database(Arc::clone(&db))
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

    // Periodic timeout checker for payout proposals
    // Without this, voting sessions that don't get enough votes never expire,
    // which can cause stale proposals to accumulate and block new ones.
    {
        let vh_for_timeouts = Arc::clone(&vote_handler);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let timeouts = vh_for_timeouts.check_timeouts();
                for result in &timeouts {
                    if let ghost_common::types::ConsensusResult::Timeout {
                        proposal_hash,
                        approvals,
                        total_nodes,
                        ..
                    } = result
                    {
                        tracing::warn!(
                            hash = %hex::encode(&proposal_hash[..8]),
                            approvals,
                            total_nodes,
                            "Payout proposal timed out"
                        );
                    }
                }
                vh_for_timeouts.cleanup_rate_limiter();
            }
        });
    }

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
    // HIGH-VER-4: Use with_peers to validate challengers are known nodes before recording
    let verification_result_handler = Arc::new(VerificationResultHandler::with_peers(
        Arc::clone(&db),
        Arc::clone(mesh.peers()),
    ));
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

    // Register share proof handler for cross-node share propagation
    let share_proof_handler = Arc::new(ShareProofHandler::new(
        Arc::clone(&round_manager),
        Arc::clone(&db),
        identity.node_id(),
    ));
    mesh.register_handler(Arc::clone(&share_proof_handler)
        as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>);

    // ZK consensus handlers (optional feature)
    // DEFERRED INITIALIZATION: ZK parameter generation is memory-intensive and can take minutes.
    // We spawn it in a background task so the node can start serving immediately.
    #[cfg(feature = "zk-consensus")]
    {
        use ghost_consensus::epoch_manager::{EpochManager, EpochManagerConfig};
        use ghost_consensus::nullifier_route_handler::NullifierRouteHandler;
        use ghost_consensus::ZkPayoutVoteHandler;

        // Check production mode early (this is fast)
        let is_production = ghost_zkp::is_production_mode();
        let is_mainnet = config.bitcoin.network == ghost_common::config::BitcoinNetwork::Mainnet;

        // MAINNET SECURITY: ZK consensus on mainnet REQUIRES trusted setup
        if is_mainnet && !is_production {
            return Err(anyhow::anyhow!(
                "MAINNET SECURITY: ZK consensus on mainnet requires trusted setup parameters. \
                 Either:\n  \
                 1. Complete MPC ceremony and build with --features zk-production\n  \
                 2. Disable ZK consensus by building without --features zk-consensus\n\n\
                 Running ZK consensus with test parameters on mainnet would allow proof forgery."
            ));
        }

        if is_production {
            ghost_zkp::load_trusted_params()?;
            info!("ZK consensus using PRODUCTION parameters from MPC ceremony");
        } else {
            warn!("ZK consensus using TEST parameters - NOT SECURE FOR MAINNET");
        }

        // Initialize epoch manager (commitment tree, nullifier set, proposer rotation)
        let epoch_config = EpochManagerConfig::default();
        let epoch_manager = Arc::new(EpochManager::new(Arc::clone(&db), epoch_config));

        // Recover epoch state from DB or initialize genesis
        epoch_manager.initialize()?;
        if db.get_active_l2_epoch()?.is_none() {
            epoch_manager.initialize_genesis()?;
            info!("L2 epoch genesis initialized (fresh database)");
        }

        info!(
            epoch = epoch_manager.current_epoch(),
            height = epoch_manager.current_height(),
            "Epoch manager initialized"
        );

        // Create broadcast relay for L2 messages (Noise-encrypted)
        let (l2_tx, mut l2_rx) =
            tokio::sync::mpsc::channel::<(ghost_consensus::message::MessageType, Vec<u8>)>(256);
        let mesh_for_l2_relay = Arc::clone(&mesh);
        tokio::spawn(async move {
            while let Some((msg_type, payload)) = l2_rx.recv().await {
                match mesh_for_l2_relay.create_envelope_raw(msg_type, payload) {
                    Ok(envelope) => {
                        if let Err(e) = mesh_for_l2_relay.broadcast(envelope).await {
                            tracing::warn!(error = %e, "L2 Noise broadcast failed");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "L2 envelope creation failed");
                    }
                }
            }
        });
        let l2_broadcast: ghost_consensus::vote_handler::BroadcastFn =
            Arc::new(move |msg_type, payload| {
                l2_tx.try_send((msg_type, payload)).map_err(|e| {
                    ghost_common::error::GhostError::Internal(format!(
                        "L2 broadcast channel error: {}",
                        e
                    ))
                })
            });

        // Create payout broadcast relay (separate channel)
        let (zk_payout_tx, mut zk_payout_rx) =
            tokio::sync::mpsc::channel::<(ghost_consensus::message::MessageType, Vec<u8>)>(64);
        let mesh_for_zk_payout_relay = Arc::clone(&mesh);
        tokio::spawn(async move {
            while let Some((msg_type, payload)) = zk_payout_rx.recv().await {
                match mesh_for_zk_payout_relay.create_envelope_raw(msg_type, payload) {
                    Ok(envelope) => {
                        if let Err(e) = mesh_for_zk_payout_relay.broadcast(envelope).await {
                            tracing::warn!(error = %e, "ZK payout Noise broadcast failed");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "ZK payout envelope creation failed");
                    }
                }
            }
        });
        let zk_payout_broadcast: ghost_consensus::zk_payout_handler::ZkPayoutBroadcastFn =
            Arc::new(move |msg_type, payload| {
                zk_payout_tx.try_send((msg_type, payload)).map_err(|e| {
                    ghost_common::error::GhostError::Internal(format!(
                        "ZK payout broadcast channel error: {}",
                        e
                    ))
                })
            });

        // Create NullifierRouteHandler (replaces ZkVoteHandler for L2)
        let nullifier_handler = Arc::new(NullifierRouteHandler::with_defaults(
            identity.node_id(),
            Arc::clone(&epoch_manager),
            Arc::clone(&db),
        ));
        nullifier_handler.set_broadcast_fn(l2_broadcast);
        let identity_for_sign = Arc::clone(&identity);
        nullifier_handler.set_sign_fn(std::sync::Arc::new(move |msg: &[u8]| {
            identity_for_sign.sign(msg)
        }));

        // Create payout handler (unchanged)
        let zk_payout_handler = Arc::new(
            ZkPayoutVoteHandler::new(Arc::clone(&identity))
                .with_broadcaster(zk_payout_broadcast)
                .with_ban_manager(Arc::clone(&ban_manager)),
        );

        // Initialize validators from MPC elders in DB
        let validators = db.get_mpc_elder_node_ids().unwrap_or_default();
        epoch_manager.update_active_nodes(validators.iter().copied().collect());
        zk_payout_handler.set_validators(validators);

        // Register handlers with mesh
        mesh.register_handler(Arc::clone(&nullifier_handler)
            as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>);
        mesh.register_handler(Arc::clone(&zk_payout_handler)
            as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>);

        info!("L2 nullifier route handler + payout handler registered (verifiers initializing in background...)");

        // Spawn checkpoint proposal loop (every 10s)
        let handler_for_proposals = Arc::clone(&nullifier_handler);
        tokio::spawn(async move {
            // Wait for initial setup
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            info!("L2 checkpoint proposer starting (10s interval)");

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;

                if !handler_for_proposals.has_verifier() {
                    tracing::debug!("NoteVerifier not ready yet, skipping checkpoint proposal");
                    continue;
                }

                match handler_for_proposals.propose_checkpoint() {
                    Ok(Some(proposal)) => {
                        // Broadcast the checkpoint proposal
                        let payload = match serde_json::to_vec(&proposal) {
                            Ok(p) => p,
                            Err(e) => {
                                tracing::warn!(error = %e, "Failed to serialize checkpoint proposal");
                                continue;
                            }
                        };
                        // The handler's broadcast_fn sends it to the mesh
                        if let Err(e) = handler_for_proposals.handle_checkpoint_proposal(&proposal) {
                            tracing::warn!(error = %e, "Failed to handle own checkpoint proposal");
                        }
                        // Also broadcast to network
                        // (broadcast_fn is already set, use it via the mesh relay)
                        let _ = payload; // proposal already handled locally, broadcast via MessageHandler
                    }
                    Ok(None) => {
                        // Not our turn to propose
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Checkpoint proposal failed");
                    }
                }
            }
        });

        // Spawn background task to generate ZK parameters
        let nullifier_handler_for_init = Arc::clone(&nullifier_handler);
        let zk_payout_handler_for_init = Arc::clone(&zk_payout_handler);
        tokio::spawn(async move {
            use ghost_zkp::{NoteProver, NoteVerifier, PayoutProver, PayoutVerifier};

            info!("ZK parameter generation starting in background...");
            let start = std::time::Instant::now();

            // Generate note prover/verifier (for sender-side proofs)
            match NoteProver::new_with_setup(40) {
                Ok(note_prover) => {
                    // Extract prepared VK for the verifier
                    if let Some(pvk) = note_prover.prepared_verifying_key() {
                        let verifier = Arc::new(NoteVerifier::new(
                            pvk,
                            note_prover.prover_id(),
                        ));
                        nullifier_handler_for_init.set_verifier(verifier);
                        info!(
                            elapsed_secs = start.elapsed().as_secs(),
                            "L2 note verifier initialized (depth=40)"
                        );
                    } else {
                        error!("NoteProver has no prepared verifying key");
                    }
                }
                Err(e) => {
                    error!(error = %e, "Failed to generate note prover parameters");
                }
            }

            // Generate payout prover/verifier (unchanged)
            match PayoutProver::default_params_with_setup() {
                Ok(payout_prover) => {
                    let payout_prover = Arc::new(payout_prover);
                    let payout_verifier = Arc::new(PayoutVerifier::for_prover(&payout_prover));
                    zk_payout_handler_for_init.set_verifier(
                        ghost_consensus::zk_payout_handler::create_payout_verifier(payout_verifier),
                    );
                    info!(
                        elapsed_secs = start.elapsed().as_secs(),
                        "ZK payout verifier initialized"
                    );
                }
                Err(e) => {
                    error!(error = %e, "Failed to generate ZK payout prover parameters");
                }
            }

            info!(
                total_secs = start.elapsed().as_secs(),
                "ZK parameter generation complete"
            );
        });
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
                // Fields added in later versions - derive ceremony_id from params hash
                ceremony_id: s.current_params_hash, // Use params hash as ceremony ID for continuity
                pending_commitment_count: 0,
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
        // Uses async Noise relay: sync closure queues messages, background task
        // routes them through mesh.broadcast() which uses Noise encryption
        let (mpc_tx, mut mpc_rx) =
            tokio::sync::mpsc::channel::<(ghost_consensus::message::MessageType, Vec<u8>)>(64);
        let mesh_for_mpc_relay = Arc::clone(&mesh);
        tokio::spawn(async move {
            while let Some((msg_type, payload)) = mpc_rx.recv().await {
                match mesh_for_mpc_relay.create_envelope_raw(msg_type, payload) {
                    Ok(envelope) => {
                        if let Err(e) = mesh_for_mpc_relay.broadcast(envelope).await {
                            tracing::warn!(error = %e, "MPC Noise broadcast failed");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "MPC envelope creation failed");
                    }
                }
            }
        });
        let mpc_broadcast: ghost_consensus::mpc_handler::MpcBroadcastFn =
            Arc::new(move |msg_type, payload| {
                mpc_tx.try_send((msg_type, payload)).map_err(|e| {
                    ghost_common::error::GhostError::Internal(format!(
                        "MPC broadcast channel error: {}",
                        e
                    ))
                })
            });

        // Create MPC handler with params update callback.
        // When the handler applies a BFT-approved contribution from another node,
        // we need to fetch the actual params binary from the contributor so our
        // local params stay current. Without this, /api/v1/mpc/params serves stale
        // genesis params and new contributors can't build valid hash chains.
        let params_dir_for_callback = ceremony_manager.params_dir().clone();
        let ceremony_mgr_for_callback = Arc::clone(&ceremony_manager);
        let seed_nodes_for_callback = config.network.seed_nodes.clone();
        type ParamsUpdateFn = dyn Fn(&[u8; 32], &[u8; 32]) + Send + Sync;
        let params_update_callback: Arc<ParamsUpdateFn> = Arc::new(
            move |expected_hash: &[u8; 32], _contributor: &[u8; 32]| {
                let params_dir = params_dir_for_callback.clone();
                let ceremony_mgr = Arc::clone(&ceremony_mgr_for_callback);
                let seeds = seed_nodes_for_callback.clone();
                let expected = *expected_hash;
                tokio::spawn(async move {
                    // Small delay to let the contributing node finish writing
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    let _ = std::fs::create_dir_all(&params_dir);
                    // Try each seed node, verify the fetched params hash matches
                    for seed in &seeds {
                        let host = seed.split(':').next().unwrap_or(seed);
                        let url = format!("http://{}:8080/api/v1/mpc/params", host);
                        match reqwest::Client::new()
                            .get(&url)
                            .timeout(std::time::Duration::from_secs(60))
                            .send()
                            .await
                        {
                            Ok(resp) if resp.status().is_success() => {
                                match resp.bytes().await {
                                    Ok(data) if data.len() > 1000 => {
                                        // Write to temp file, load, verify hash
                                        let tmp_path = params_dir.join("block_params_tmp.bin");
                                        if let Err(e) = std::fs::write(&tmp_path, &data) {
                                            tracing::warn!(error = %e, peer = %host,
                                                "MPC params_callback: Failed to write temp params");
                                            continue;
                                        }
                                        // Load and verify hash before committing
                                        match ghost_mpc::params::load_parameters(&tmp_path) {
                                            Ok(params) => {
                                                match ghost_mpc::contribution::hash_parameters(
                                                    &params,
                                                ) {
                                                    Ok(hash) if hash == expected => {
                                                        // Hash matches! Move to current
                                                        let current = params_dir
                                                            .join("block_params_current.bin");
                                                        if let Err(e) =
                                                            std::fs::rename(&tmp_path, &current)
                                                        {
                                                            tracing::warn!(error = %e, "MPC params_callback: Failed to rename params");
                                                            continue;
                                                        }
                                                        if let Err(e) =
                                                            ceremony_mgr.load_current_params()
                                                        {
                                                            tracing::warn!(error = %e, "MPC params_callback: Failed to reload");
                                                        } else {
                                                            tracing::info!(
                                                                size = data.len(),
                                                                peer = %host,
                                                                hash = %hex::encode(&hash[..8]),
                                                                "MPC params_callback: Verified and updated params"
                                                            );
                                                        }
                                                        return;
                                                    }
                                                    Ok(hash) => {
                                                        tracing::debug!(
                                                            peer = %host,
                                                            got = %hex::encode(&hash[..8]),
                                                            expected = %hex::encode(&expected[..8]),
                                                            "MPC params_callback: Hash mismatch, trying next peer"
                                                        );
                                                        let _ = std::fs::remove_file(&tmp_path);
                                                    }
                                                    Err(e) => {
                                                        tracing::warn!(error = %e, "MPC params_callback: Hash computation failed");
                                                        let _ = std::fs::remove_file(&tmp_path);
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                tracing::warn!(error = %e, peer = %host,
                                                    "MPC params_callback: Failed to load params for verification");
                                                let _ = std::fs::remove_file(&tmp_path);
                                            }
                                        }
                                    }
                                    _ => continue,
                                }
                            }
                            _ => continue,
                        }
                    }
                    tracing::warn!(
                        expected = %hex::encode(&expected[..8]),
                        "MPC params_callback: No peer had matching params"
                    );
                });
            },
        );

        let mpc_handler = Arc::new(
            MpcHandler::new(Arc::clone(&identity), Arc::clone(&db))
                .with_broadcaster(mpc_broadcast)
                .with_params_callback(params_update_callback)
                .with_state(
                    ceremony_manager.contribution_count(),
                    ceremony_manager.is_ossified(),
                ),
        );

        // Register MPC handler with mesh
        mesh.register_handler(Arc::clone(&mpc_handler)
            as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>);

        // Auto-contribute to MPC ceremony on startup
        // Any node can contribute - first 101 become elders
        // Only the genesis node (--genesis flag) can create initial parameters
        let ceremony_manager_for_startup = Arc::clone(&ceremony_manager);
        let mesh_for_mpc_startup = Arc::clone(&mesh);
        let identity_for_mpc = Arc::clone(&identity);
        let db_for_mpc = Arc::clone(&db);
        let round_manager_for_mpc = Arc::clone(&round_manager);
        let initial_capabilities = capabilities; // Copy for MPC task to update after elder promotion
        let is_genesis_node = args.genesis;
        let args_genesis_password = args.genesis_password.clone();
        let genesis_password = config.pool.genesis_password.clone();
        let seed_nodes_for_mpc = config.network.seed_nodes.clone();

        tokio::spawn(async move {
            // Wait a bit for network to stabilize
            tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;

            let node_id_hex = hex::encode(identity_for_mpc.node_id());

            // Check if ceremony is ossified
            if ceremony_manager_for_startup.is_ossified() {
                info!("MPC ceremony is ossified (101 contributors reached)");
                return;
            }

            // Check if we've already contributed
            if db_for_mpc.is_mpc_elder(&node_id_hex).unwrap_or(false) {
                let position = db_for_mpc
                    .get_mpc_elder_position(&node_id_hex)
                    .unwrap_or(None);
                info!(position = ?position, "Already an MPC contributor (elder)");
                return;
            }

            // Retry loop: attempt contribution up to 5 times with random 10-100s intervals.
            // This handles race conditions where multiple nodes try the same position
            // simultaneously — the loser retries at the next position.
            // Between retries: sync contributors, re-fetch latest params from network
            // (prevents stale prev_params_hash), and randomize delay to avoid races.
            // Cache the signed message so retries broadcast the same hash (votes accumulate).
            let mut cached_msg: Option<(ghost_consensus::message::MpcContributionMessage, u32)> =
                None;
            for attempt in 1..=5u32 {
                // Re-check if we became an elder (e.g., via P2P sync of our own contribution)
                if db_for_mpc.is_mpc_elder(&node_id_hex).unwrap_or(false) {
                    let position = db_for_mpc
                        .get_mpc_elder_position(&node_id_hex)
                        .unwrap_or(None);
                    info!(position = ?position, "Now an MPC contributor (elder)");
                    // Update live capabilities so health pings reflect elder status
                    mesh_for_mpc_startup.update_elder_status(true);
                    let mut updated_caps = initial_capabilities;
                    updated_caps.elder_status = true;
                    round_manager_for_mpc
                        .update_node_capabilities(identity_for_mpc.node_id(), updated_caps);
                    return;
                }

                // Ensure we have parameters loaded
                if !ceremony_manager_for_startup.has_current_params() {
                    // Use DB to determine if this is truly genesis or if we need to fetch
                    let db_count = db_for_mpc.get_mpc_elder_count().unwrap_or(0) as u32;

                    if db_count == 0 && is_genesis_node {
                        // Genesis protection layer 1: Query seed peers for existing contributors
                        // If any peer already has MPC contributors, abort genesis to prevent dual-genesis
                        let mut network_has_contributors = false;
                        for seed in &seed_nodes_for_mpc {
                            let host = seed.split(':').next().unwrap_or(seed);
                            let url = format!("http://{}:8080/api/v1/mpc/contributors", host);
                            if let Ok(resp) = reqwest::Client::new()
                                .get(&url)
                                .timeout(std::time::Duration::from_secs(10))
                                .send()
                                .await
                            {
                                if let Ok(body) = resp.text().await {
                                    // If response is a non-empty JSON array, contributors exist
                                    let trimmed = body.trim();
                                    if trimmed.starts_with('[') && trimmed != "[]" {
                                        error!(
                                            seed = %seed,
                                            "Cannot init genesis: network already has MPC contributors (via {})",
                                            host
                                        );
                                        network_has_contributors = true;
                                        break;
                                    }
                                }
                            }
                        }
                        if network_has_contributors {
                            warn!("MPC: Aborting genesis — existing contributors detected on network. Remove --genesis flag.");
                            return;
                        }

                        // Genesis protection layer 2: Password check
                        if let Some(ref required_pw) = genesis_password {
                            if args_genesis_password.as_deref() != Some(required_pw.as_str()) {
                                error!("MPC: genesis_password is configured but --genesis-password was not provided or does not match");
                                return;
                            }
                        }

                        // Truly the first node — no contributors exist anywhere, create genesis
                        info!("MPC: Genesis node with empty DB - creating initial parameters");
                        if let Err(e) = ceremony_manager_for_startup.ensure_genesis_initialized() {
                            warn!(error = %e, "Failed to initialize MPC genesis parameters");
                            return;
                        }
                    } else {
                        // Either DB already has contributors (synced from peers) or not genesis node
                        // In both cases, fetch params from network
                        if db_count > 0 {
                            info!(db_count, "MPC: DB has contributors but no local params, fetching from network...");
                        } else {
                            info!("MPC: No genesis parameters found, fetching from network...");
                        }

                        // Try to fetch params from seed nodes
                        let params_dir = ceremony_manager_for_startup.params_dir().clone();
                        let mut fetched = false;

                        for fetch_attempt in 1..=20 {
                            // Try each seed node
                            for seed in &seed_nodes_for_mpc {
                                // Extract host from seed (format: "host:port")
                                let host = seed.split(':').next().unwrap_or(seed);
                                let url = format!("http://{}:8080/api/v1/mpc/params", host);

                                debug!(url = %url, "MPC: Trying to fetch params from peer");

                                match reqwest::Client::new()
                                    .get(&url)
                                    .timeout(std::time::Duration::from_secs(60))
                                    .send()
                                    .await
                                {
                                    Ok(response) if response.status().is_success() => {
                                        match response.bytes().await {
                                            Ok(data) if data.len() > 1000 => {
                                                // Save params to disk
                                                let _ = std::fs::create_dir_all(&params_dir);
                                                let params_path =
                                                    params_dir.join("block_params_v0.bin");
                                                let current_path =
                                                    params_dir.join("block_params_current.bin");

                                                if let Err(e) = std::fs::write(&params_path, &data)
                                                {
                                                    warn!(error = %e, "MPC: Failed to save fetched params");
                                                    continue;
                                                }

                                                // Create symlink to current
                                                let _ = std::fs::remove_file(&current_path);
                                                if let Err(e) = std::os::unix::fs::symlink(
                                                    &params_path,
                                                    &current_path,
                                                ) {
                                                    warn!(error = %e, "MPC: Failed to create params symlink");
                                                }

                                                info!(size = data.len(), peer = %host, "MPC: Fetched genesis params from peer!");
                                                fetched = true;
                                                break;
                                            }
                                            Ok(data) => {
                                                debug!(size = data.len(), "MPC: Response too small, peer may not have params");
                                            }
                                            Err(e) => {
                                                debug!(error = %e, peer = %host, "MPC: Failed to read response body");
                                            }
                                        }
                                    }
                                    Ok(response) => {
                                        debug!(status = %response.status(), peer = %host, "MPC: Peer returned non-success status");
                                    }
                                    Err(e) => {
                                        debug!(error = %e, peer = %host, "MPC: Failed to fetch from peer");
                                    }
                                }
                            }

                            if fetched {
                                // Also fetch MPC status to sync contribution count
                                for seed in &seed_nodes_for_mpc {
                                    let host = seed.split(':').next().unwrap_or(seed);
                                    let status_url =
                                        format!("http://{}:8080/api/v1/mpc/status", host);

                                    if let Ok(response) = reqwest::Client::new()
                                        .get(&status_url)
                                        .timeout(std::time::Duration::from_secs(10))
                                        .send()
                                        .await
                                    {
                                        if let Ok(status) =
                                            response.json::<serde_json::Value>().await
                                        {
                                            if let Some(count) = status
                                                .get("contribution_count")
                                                .and_then(|c| c.as_u64())
                                            {
                                                info!(
                                                    contribution_count = count,
                                                    "MPC: Synced contribution count from peer"
                                                );
                                                ceremony_manager_for_startup
                                                    .sync_contribution_count(count as u32);
                                            }
                                            break;
                                        }
                                    }
                                }

                                // Fetch and sync MPC contributors list (needed for vote validation)
                                for seed in &seed_nodes_for_mpc {
                                    let host = seed.split(':').next().unwrap_or(seed);
                                    let contributors_url =
                                        format!("http://{}:8080/api/v1/mpc/contributors", host);

                                    if let Ok(response) = reqwest::Client::new()
                                        .get(&contributors_url)
                                        .timeout(std::time::Duration::from_secs(10))
                                        .send()
                                        .await
                                    {
                                        if let Ok(data) = response.json::<serde_json::Value>().await
                                        {
                                            if let Some(contributors) =
                                                data.get("contributors").and_then(|c| c.as_array())
                                            {
                                                let mut synced_count = 0;
                                                for contrib in contributors {
                                                    let position = contrib
                                                        .get("position")
                                                        .and_then(|p| p.as_u64())
                                                        .unwrap_or(0)
                                                        as u32;
                                                    let node_id = contrib
                                                        .get("node_id")
                                                        .and_then(|n| n.as_str())
                                                        .unwrap_or("");
                                                    let prev_hash_hex = contrib
                                                        .get("prev_params_hash")
                                                        .and_then(|h| h.as_str())
                                                        .unwrap_or("");
                                                    let new_hash_hex = contrib
                                                        .get("new_params_hash")
                                                        .and_then(|h| h.as_str())
                                                        .unwrap_or("");
                                                    let epoch = contrib
                                                        .get("epoch")
                                                        .and_then(|e| e.as_u64())
                                                        .unwrap_or(0);
                                                    let created_at = contrib
                                                        .get("created_at")
                                                        .and_then(|c| c.as_u64())
                                                        .unwrap_or(0);

                                                    if position == 0 || node_id.is_empty() {
                                                        continue;
                                                    }

                                                    let prev_hash: [u8; 32] =
                                                        hex::decode(prev_hash_hex)
                                                            .ok()
                                                            .and_then(|b| b.try_into().ok())
                                                            .unwrap_or([0u8; 32]);
                                                    let new_hash: [u8; 32] =
                                                        hex::decode(new_hash_hex)
                                                            .ok()
                                                            .and_then(|b| b.try_into().ok())
                                                            .unwrap_or([0u8; 32]);

                                                    let record = ghost_storage::queries::MpcContributionRecord {
                                                        elder_position: position,
                                                        contributor_node_id: node_id.to_string(),
                                                        prev_params_hash: prev_hash,
                                                        new_params_hash: new_hash,
                                                        contribution_proof: Vec::new(),
                                                        epoch,
                                                        created_at,
                                                    };

                                                    if db_for_mpc
                                                        .save_mpc_contribution(&record)
                                                        .is_ok()
                                                    {
                                                        synced_count += 1;
                                                    }
                                                }
                                                if synced_count > 0 {
                                                    info!(
                                                        count = synced_count,
                                                        "MPC: Synced contributor records from peer"
                                                    );
                                                }
                                                break;
                                            }
                                        }
                                    }
                                }

                                // Load fetched params into ceremony manager
                                if let Err(e) = ceremony_manager_for_startup.load_current_params() {
                                    warn!(error = %e, "MPC: Failed to load fetched params");
                                    fetched = false;
                                } else {
                                    info!("MPC: Loaded fetched params into ceremony manager");
                                }
                                break;
                            }

                            if fetch_attempt % 4 == 0 {
                                info!(
                                    fetch_attempt,
                                    "MPC: Still trying to fetch params (attempt {}/20)...",
                                    fetch_attempt
                                );
                            }

                            tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
                        }

                        if !fetched || !ceremony_manager_for_startup.has_current_params() {
                            warn!("MPC: Failed to fetch genesis parameters from network. Use --genesis on the first node.");
                            return;
                        }
                    }
                }

                // Determine position from DB (authoritative source, not stale in-memory state)
                let db_count = db_for_mpc.get_mpc_elder_count().unwrap_or(0) as u32;
                let next_position = db_count + 1;

                info!(
                    attempt,
                    db_count, next_position, "MPC: Attempting to contribute to ceremony"
                );

                // Cache the signed message so retries broadcast the same hash.
                // Regenerate only on first attempt or when db_count changes (position shifted).
                let need_generate = match &cached_msg {
                    Some((_, cached_db_count)) => *cached_db_count != db_count,
                    None => true,
                };

                if need_generate {
                    match ceremony_manager_for_startup
                        .generate_contribution_at_position(&node_id_hex, next_position)
                    {
                        Ok((new_params, contribution)) => {
                            let position = contribution.position;
                            info!(
                                position = position,
                                "MPC contribution generated for position {}", position,
                            );

                            // Genesis case: ONLY the genesis node auto-applies position 1.
                            // Non-genesis nodes must wait for BFT approval from existing elders.
                            // Without this guard, all nodes race to auto-apply their own position 1.
                            if db_count == 0 && is_genesis_node {
                                info!("MPC genesis: Auto-applying first contribution (no existing contributors to vote)");
                                if let Err(e) = ceremony_manager_for_startup
                                    .apply_contribution(new_params, &contribution)
                                {
                                    warn!(error = %e, "Failed to apply genesis contribution");
                                } else {
                                    let proof_bytes =
                                        serde_json::to_vec(&contribution.proof).unwrap_or_default();
                                    let record = ghost_storage::queries::MpcContributionRecord {
                                        elder_position: position,
                                        contributor_node_id: node_id_hex.clone(),
                                        prev_params_hash: contribution.prev_params_hash,
                                        new_params_hash: contribution.new_params_hash,
                                        contribution_proof: proof_bytes,
                                        epoch: 0,
                                        created_at: contribution.timestamp,
                                    };
                                    if let Err(e) = db_for_mpc.save_mpc_contribution(&record) {
                                        warn!(error = %e, "Failed to save genesis contribution to database");
                                    } else {
                                        info!("MPC genesis contribution applied - we are now Elder #1");
                                        // Update live capabilities so health pings reflect elder status
                                        mesh_for_mpc_startup.update_elder_status(true);
                                        let mut updated_caps = initial_capabilities;
                                        updated_caps.elder_status = true;
                                        round_manager_for_mpc.update_node_capabilities(
                                            identity_for_mpc.node_id(),
                                            updated_caps,
                                        );
                                    }
                                }
                            } else {
                                // Non-genesis: save params to disk for serving via API.
                                // We can't use apply_contribution here because it modifies
                                // internal state (contribution_count) which breaks retries
                                // if BFT rejects. Instead, write the binary directly.
                                let params_dir = ceremony_manager_for_startup.params_dir().clone();
                                let _ = std::fs::create_dir_all(&params_dir);
                                let current_path = params_dir.join("block_params_current.bin");
                                let mut buf = Vec::new();
                                if new_params.write(&mut buf).is_ok() {
                                    if let Err(e) = std::fs::write(&current_path, &buf) {
                                        warn!(error = %e, "MPC: Failed to save params to disk");
                                    } else {
                                        info!(
                                            position = position,
                                            size = buf.len(),
                                            "MPC: Saved generated params to disk for serving"
                                        );
                                    }
                                }
                            }

                            // Build and sign the broadcast message
                            let proof_bytes =
                                serde_json::to_vec(&contribution.proof).unwrap_or_default();

                            let candidate: [u8; 32] = hex::decode(&contribution.contributor)
                                .ok()
                                .and_then(|b| b.try_into().ok())
                                .unwrap_or_else(|| identity_for_mpc.node_id());

                            let mut msg = ghost_consensus::message::MpcContributionMessage {
                                candidate,
                                elder_position: contribution.position,
                                prev_params_hash: contribution.prev_params_hash,
                                new_params_hash: contribution.new_params_hash,
                                contribution_proof: proof_bytes,
                                signature: [0u8; 64],
                                timestamp: contribution.timestamp,
                            };

                            let signing_message = msg.signing_message();
                            msg.signature = identity_for_mpc.sign(&signing_message);

                            cached_msg = Some((msg, db_count));

                            // If this was genesis (auto-applied), broadcast and we're done.
                            // Only genesis node returns early — non-genesis nodes must
                            // continue the retry loop to get BFT approval.
                            if db_count == 0 && is_genesis_node {
                                if let Some((ref cached, _)) = cached_msg {
                                    match mesh_for_mpc_startup
                                        .broadcast_message(
                                            ghost_consensus::message::MessageType::MpcContribution,
                                            cached,
                                        )
                                        .await
                                    {
                                        Ok(sent) => info!(
                                            sent = sent,
                                            "MPC genesis contribution broadcast via Noise"
                                        ),
                                        Err(e) => {
                                            warn!(error = %e, "Failed to broadcast MPC genesis contribution")
                                        }
                                    }
                                }
                                return;
                            }
                        }
                        Err(e) => {
                            info!(error = %e, attempt, "Could not generate MPC contribution, will retry");
                        }
                    }
                } else {
                    info!(
                        attempt,
                        db_count, "MPC: Rebroadcasting cached contribution (same position)"
                    );
                }

                // Broadcast (or rebroadcast) the cached message
                if let Some((ref cached, _)) = cached_msg {
                    match mesh_for_mpc_startup
                        .broadcast_message(
                            ghost_consensus::message::MessageType::MpcContribution,
                            cached,
                        )
                        .await
                    {
                        Ok(sent) => {
                            info!(sent = sent, attempt, "MPC contribution broadcast via Noise");
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to broadcast MPC contribution");
                        }
                    }
                }

                // Wait random 10-100s before retry to prevent race conditions
                // where multiple nodes fight for the same position simultaneously.
                if attempt < 5 {
                    let delay_secs = {
                        use rand::Rng;
                        rand::thread_rng().gen_range(10..=100)
                    };
                    info!(
                        attempt,
                        delay_secs, "MPC: Waiting before retry (randomized to prevent races)"
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(delay_secs)).await;

                    // Sync contributors from peers to detect if our contribution was approved
                    for seed in &seed_nodes_for_mpc {
                        let host = seed.split(':').next().unwrap_or(seed);
                        let contributors_url =
                            format!("http://{}:8080/api/v1/mpc/contributors", host);

                        if let Ok(response) = reqwest::Client::new()
                            .get(&contributors_url)
                            .timeout(std::time::Duration::from_secs(10))
                            .send()
                            .await
                        {
                            if let Ok(data) = response.json::<serde_json::Value>().await {
                                if let Some(contributors) =
                                    data.get("contributors").and_then(|c| c.as_array())
                                {
                                    for contrib in contributors {
                                        let position = contrib
                                            .get("position")
                                            .and_then(|p| p.as_u64())
                                            .unwrap_or(0)
                                            as u32;
                                        let node_id = contrib
                                            .get("node_id")
                                            .and_then(|n| n.as_str())
                                            .unwrap_or("");
                                        let prev_hash_hex = contrib
                                            .get("prev_params_hash")
                                            .and_then(|h| h.as_str())
                                            .unwrap_or("");
                                        let new_hash_hex = contrib
                                            .get("new_params_hash")
                                            .and_then(|h| h.as_str())
                                            .unwrap_or("");
                                        let epoch = contrib
                                            .get("epoch")
                                            .and_then(|e| e.as_u64())
                                            .unwrap_or(0);
                                        let created_at = contrib
                                            .get("created_at")
                                            .and_then(|c| c.as_u64())
                                            .unwrap_or(0);

                                        if position == 0 || node_id.is_empty() {
                                            continue;
                                        }

                                        let prev_hash: [u8; 32] = hex::decode(prev_hash_hex)
                                            .ok()
                                            .and_then(|b| b.try_into().ok())
                                            .unwrap_or([0u8; 32]);
                                        let new_hash: [u8; 32] = hex::decode(new_hash_hex)
                                            .ok()
                                            .and_then(|b| b.try_into().ok())
                                            .unwrap_or([0u8; 32]);

                                        let record =
                                            ghost_storage::queries::MpcContributionRecord {
                                                elder_position: position,
                                                contributor_node_id: node_id.to_string(),
                                                prev_params_hash: prev_hash,
                                                new_params_hash: new_hash,
                                                contribution_proof: Vec::new(),
                                                epoch,
                                                created_at,
                                            };

                                        let _ = db_for_mpc.save_mpc_contribution(&record);
                                    }
                                    break;
                                }
                            }
                        }
                    }

                    // Re-fetch latest MPC params from network before next attempt.
                    // Without this, the ceremony manager holds stale params and any
                    // new contribution will fail hash-chain validation because
                    // prev_params_hash won't match the latest applied contribution.
                    let params_dir = ceremony_manager_for_startup.params_dir().clone();
                    for seed in &seed_nodes_for_mpc {
                        let host = seed.split(':').next().unwrap_or(seed);
                        let url = format!("http://{}:8080/api/v1/mpc/params", host);

                        match reqwest::Client::new()
                            .get(&url)
                            .timeout(std::time::Duration::from_secs(60))
                            .send()
                            .await
                        {
                            Ok(response) if response.status().is_success() => {
                                match response.bytes().await {
                                    Ok(data) if data.len() > 1000 => {
                                        // Ensure params directory exists (may have been wiped)
                                        let _ = std::fs::create_dir_all(&params_dir);
                                        let params_path =
                                            params_dir.join("block_params_current.bin");
                                        // Resolve symlink target or overwrite directly
                                        let write_path = std::fs::read_link(&params_path)
                                            .unwrap_or(params_path.clone());
                                        if let Err(e) = std::fs::write(&write_path, &data) {
                                            warn!(error = %e, "MPC: Failed to save refreshed params");
                                            continue;
                                        }
                                        // Reload into ceremony manager
                                        if let Err(e) =
                                            ceremony_manager_for_startup.load_current_params()
                                        {
                                            warn!(error = %e, "MPC: Failed to reload refreshed params");
                                        } else {
                                            info!(size = data.len(), peer = %host, "MPC: Refreshed params from network for retry");
                                            // Invalidate cached contribution since params changed
                                            cached_msg = None;
                                        }
                                        break;
                                    }
                                    _ => continue,
                                }
                            }
                            _ => continue,
                        }
                    }
                }
            }

            // Final check after all attempts
            if db_for_mpc.is_mpc_elder(&node_id_hex).unwrap_or(false) {
                let position = db_for_mpc
                    .get_mpc_elder_position(&node_id_hex)
                    .unwrap_or(None);
                info!(position = ?position, "MPC contribution succeeded after retries");
                // Update live capabilities so health pings reflect elder status
                mesh_for_mpc_startup.update_elder_status(true);
                let mut updated_caps = initial_capabilities;
                updated_caps.elder_status = true;
                round_manager_for_mpc
                    .update_node_capabilities(identity_for_mpc.node_id(), updated_caps);
            } else {
                warn!("MPC: Failed to contribute after 5 attempts. Node will not be an elder.");
            }
        });
        info!("MPC auto-contribution task scheduled (15s delay)");

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
        network: config.bitcoin.network, // M-15/LOW: Enable mainnet-specific security checks
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

    // Note: GhostPay verification is now handled directly by ghost-pay on port 8800.
    // The verification client routes GhostPay challenges to ghost-pay instead of ghost-pool,
    // so no stub handler is needed here. Ghost-pay queries its own L2 database for real state.

    // Wire GSP handler if GSP service URL is configured or default (port 8900)
    let gsp_handler = CachedGspHandler::new("https://127.0.0.1:8900".to_string());
    verification_state = verification_state.with_gsp_handler(gsp_handler);

    // Pass database and RPC to verification state for API endpoints
    verification_state = verification_state.with_database((*db).clone());
    verification_state = verification_state.with_rpc(Arc::clone(&rpc));

    // Wire node config path for persisting ghost_mode, shroud_enabled, etc.
    verification_state =
        verification_state.with_node_config_path(data_dir.join("node_config.json"));

    // Wire Tor mode status from Ghost Core RPC
    if let Some(ref ts) = tor_status {
        verification_state =
            verification_state.with_tor_status(ts.enabled, ts.onion_address.clone());
    }

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

    // Share broadcast relay: sync callback → async Noise broadcast
    // Follows the MPC relay pattern (main.rs:1107-1134)
    let (share_broadcast_tx, mut share_broadcast_rx) =
        tokio::sync::mpsc::channel::<ghost_common::types::ShareProof>(256);
    let mesh_for_shares_relay = Arc::clone(&mesh);
    tokio::spawn(async move {
        while let Some(proof) = share_broadcast_rx.recv().await {
            let msg = ghost_consensus::message::ShareProofMessage { proof };
            match serde_json::to_vec(&msg) {
                Ok(payload) => {
                    match mesh_for_shares_relay
                        .create_envelope_raw(MessageType::ShareProof, payload)
                    {
                        Ok(envelope) => {
                            if let Err(e) = mesh_for_shares_relay.smart_broadcast(envelope).await {
                                tracing::warn!(error = %e, "Share proof broadcast failed");
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Share proof envelope creation failed");
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Share proof serialization failed");
                }
            }
        }
    });

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

        match db_for_shares.insert_share(&share_record) {
            Ok(_) => {
                // Share inserted successfully — update miner cumulative stats
                if let Err(e) = db_for_shares.increment_miner_stats(&share.miner_id, 1, share.work)
                {
                    tracing::warn!(
                        miner_id = %share.miner_id,
                        error = %e,
                        "Failed to increment miner stats"
                    );
                }
            }
            Err(e) => {
                // Log but don't fail - in-memory tracking is primary, DB is for auditing
                // UNIQUE constraint failures are expected (dedup) and don't increment stats
                tracing::warn!(
                    miner_id = %share.miner_id,
                    share_hash = %share.share_hash,
                    error = %e,
                    "Failed to persist share to database"
                );
            }
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

        // Broadcast share proof to other nodes via P2P
        // Uses SHA256(miner_id) as the 32-byte miner identifier for the proof
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(share.miner_id.as_bytes());
        let miner_hash: [u8; 32] = hasher.finalize().into();

        let mut share_hash_bytes = [0u8; 32];
        if let Ok(decoded) = hex::decode(&share.share_hash) {
            let len = decoded.len().min(32);
            share_hash_bytes[..len].copy_from_slice(&decoded[..len]);
        }

        let proof = ghost_common::types::ShareProof {
            round_id,
            miner_id: miner_hash,
            difficulty: share.work,
            work: share.work,
            share_hash: share_hash_bytes,
            timestamp: share.timestamp,
            received_by: identity_for_shares.node_id(),
            template_id: rm_for_shares.current_template_id(),
            payout_address: share.payout_address.clone(),
        };

        if let Err(e) = share_broadcast_tx.try_send(proof) {
            tracing::warn!(error = %e, "Share broadcast channel full or closed");
        }

        tracing::debug!(
            miner_id = %share.miner_id,
            work = share.work,
            round_id = round_id,
            "Share recorded from SRI notification"
        );
        Ok(())
    });

    // Configure block_found callback: triggers payout proposal BEFORE block submission.
    // This breaks the bootstrap deadlock where:
    //   1. submitblock requires an approved coinbase commitment
    //   2. Coinbase commitment requires an approved payout proposal
    //   3. Payout proposals were only created from block_submitted_rx (AFTER submitblock)
    // By creating the proposal when a block-difficulty share is found (before submission),
    // the next template will include the committed coinbase and submitblock will succeed.
    {
        let rm_for_bf = Arc::clone(&round_manager);
        let tp_for_bf = Arc::clone(&template_processor);
        let payout_for_bf = Arc::clone(&payout_handler);
        let identity_for_bf = Arc::clone(&identity);
        let db_for_bf = Arc::clone(&db);
        let solo_payout_address_for_bf = config.network.solo_payout_address.clone();
        let metrics_for_bf = Arc::clone(&metrics);

        verification_state = verification_state.with_block_found_callback(move |block_info| {
            let round_id = rm_for_bf.current_round_id();
            let is_solo_mode = rm_for_bf.is_solo_mode();

            info!(
                round = round_id,
                share_hash = %block_info.share_hash,
                miner = %block_info.miner_id,
                solo_mode = is_solo_mode,
                "Block-difficulty share found, creating pre-submission payout proposal..."
            );

            // Use the share hash as block hash — the share met block difficulty,
            // so this IS the candidate block hash. Can't use [0u8;32] because
            // PO4-M1 validation rejects zero block hashes.
            let mut block_hash = [0u8; 32];
            if let Ok(decoded) = hex::decode(&block_info.share_hash) {
                let len = decoded.len().min(32);
                block_hash[..len].copy_from_slice(&decoded[..len]);
            }

            let node_shares = rm_for_bf.get_node_shares(round_id);
            let (subsidy, fees, height) = tp_for_bf.get_current_block_info();

            // Load treasury state from database
            let treasury_state = match db_for_bf.get_treasury_balance() {
                Ok(balance) => {
                    let threshold_ts = match db_for_bf.get_treasury_threshold_reached() {
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

            let winning_node_id = identity_for_bf.node_id();

            if is_solo_mode {
                let solo_address = match &solo_payout_address_for_bf {
                    Some(addr) if !addr.is_empty() => addr.clone(),
                    _ => {
                        error!("Solo mode block found but solo_payout_address not configured!");
                        return;
                    }
                };

                let treasury_address_snapshot =
                    payout_for_bf.get_treasury_address_snapshot();

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

                match payout_for_bf.handle_solo_block_found(solo_data) {
                    Ok(proposal_hash) => {
                        if proposal_hash != [0u8; 32] {
                            info!(
                                round = round_id,
                                hash = %hex::encode(&proposal_hash[..8]),
                                "Solo pre-submission payout proposal submitted for consensus"
                            );
                        }
                    }
                    Err(e) => {
                        error!(error = %e, round = round_id, "Failed to create solo pre-submission payout proposal");
                    }
                }
            } else {
                // Pool mode: proportional distribution to all miners
                let miner_work = {
                    use ghost_accounting::shares::WORK_SCALE;
                    let db_work = db_for_bf.get_round_miners(round_id).unwrap_or_default();
                    let db_work = if db_work.is_empty() && round_id > 0 {
                        db_for_bf
                            .get_round_miners(round_id - 1)
                            .unwrap_or_default()
                    } else {
                        db_work
                    };
                    if db_work.is_empty() {
                        warn!(
                            round = round_id,
                            "No miner work in DB for pre-submission proposal, falling back to in-memory data"
                        );
                        rm_for_bf.get_miner_work_scaled(round_id)
                    } else {
                        db_work
                            .into_iter()
                            .take(200)
                            .map(|(id, w)| (id, (w * WORK_SCALE as f64) as u128))
                            .collect()
                    }
                };

                let treasury_address_snapshot =
                    payout_for_bf.get_treasury_address_snapshot();

                let block_data = BlockFoundData {
                    round_id,
                    block_hash,
                    block_height: height,
                    block_timestamp: chrono::Utc::now(),
                    winning_miner_id: "pool".to_string(),
                    winning_miner_payout_address: Some(block_info.payout_address.clone()),
                    treasury_address_snapshot,
                    winning_node_id,
                    subsidy_sats: subsidy,
                    tx_fees_sats: fees,
                    miner_work,
                    node_shares,
                    treasury_state,
                };

                match payout_for_bf.handle_block_found(block_data) {
                    Ok(proposal_hash) => {
                        if proposal_hash != [0u8; 32] {
                            metrics_for_bf.payouts_total.inc();
                            info!(
                                round = round_id,
                                hash = %hex::encode(&proposal_hash[..8]),
                                "Pre-submission payout proposal submitted for consensus"
                            );
                        }
                    }
                    Err(e) => {
                        metrics_for_bf.payout_errors_total.inc();
                        error!(error = %e, round = round_id, "Failed to create pre-submission payout proposal");
                    }
                }
            }
        });
    }

    // Spawn async payout task: triggers payout proposal creation when a block is
    // submitted to Bitcoin Core via SubmitSolution (channel from TemplateProcessor).
    // This is the SECONDARY path — the primary path is now the block_found callback above.
    // This path handles the case where the block was successfully submitted and we need
    // to create a proposal for the NEXT block's coinbase.
    {
        let rm_for_block = Arc::clone(&round_manager);
        let tp_for_block = Arc::clone(&template_processor);
        let payout_for_block = Arc::clone(&payout_handler);
        let identity_for_block = Arc::clone(&identity);
        let db_for_block = Arc::clone(&db);
        let solo_payout_address_for_block = config.network.solo_payout_address.clone();
        let metrics_for_block = Arc::clone(&metrics);
        let mut block_rx = template_processor
            .take_block_submitted_rx()
            .expect("M-02: block_submitted_rx already taken — startup bug");

        tokio::spawn(async move {
            while let Some(info) = block_rx.recv().await {
                let round_id = rm_for_block.current_round_id();
                let is_solo_mode = rm_for_block.is_solo_mode();

                info!(
                    round = round_id,
                    hash = %hex::encode(&info.block_hash[..8]),
                    height = info.height,
                    solo_mode = is_solo_mode,
                    "Block submitted to Bitcoin Core, creating payout proposal..."
                );

                // Gather data for payout proposal
                let node_shares = rm_for_block.get_node_shares(round_id);
                let (subsidy, fees, height) = tp_for_block.get_current_block_info();

                // Load treasury state from database
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

                let winning_node_id = identity_for_block.node_id();

                if is_solo_mode {
                    let solo_address = match &solo_payout_address_for_block {
                        Some(addr) if !addr.is_empty() => addr.clone(),
                        _ => {
                            error!("Solo mode block found but solo_payout_address not configured!");
                            continue;
                        }
                    };

                    let treasury_address_snapshot =
                        payout_for_block.get_treasury_address_snapshot();

                    let solo_data = SoloBlockFoundData {
                        round_id,
                        block_hash: info.block_hash,
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
                    let miner_work = {
                        use ghost_accounting::shares::WORK_SCALE;
                        let db_work = db_for_block.get_round_miners(round_id).unwrap_or_default();
                        let db_work = if db_work.is_empty() && round_id > 0 {
                            db_for_block
                                .get_round_miners(round_id - 1)
                                .unwrap_or_default()
                        } else {
                            db_work
                        };
                        if db_work.is_empty() {
                            warn!(
                                round = round_id,
                                "No miner work in DB, falling back to in-memory data"
                            );
                            rm_for_block.get_miner_work_scaled(round_id)
                        } else {
                            db_work
                                .into_iter()
                                .take(200)
                                .map(|(id, w)| (id, (w * WORK_SCALE as f64) as u128))
                                .collect()
                        }
                    };

                    let treasury_address_snapshot =
                        payout_for_block.get_treasury_address_snapshot();

                    let block_data = BlockFoundData {
                        round_id,
                        block_hash: info.block_hash,
                        block_height: height,
                        block_timestamp: chrono::Utc::now(),
                        winning_miner_id: "pool".to_string(),
                        winning_miner_payout_address: None,
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
                                metrics_for_block.payouts_total.inc();
                                info!(
                                    round = round_id,
                                    hash = %hex::encode(&proposal_hash[..8]),
                                    "Payout proposal submitted for consensus"
                                );
                            }
                        }
                        Err(e) => {
                            metrics_for_block.payout_errors_total.inc();
                            error!(error = %e, round = round_id, "Failed to create payout proposal");
                        }
                    }
                }
            }
            warn!("Block submission channel closed, payout task exiting");
        });
    }

    // Wire Prometheus metrics to verification state
    verification_state = verification_state.with_metrics(Arc::clone(&metrics));

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

    // Dedup cache cleanup — evict expired seen messages every 60s
    let mesh_for_dedup_cleanup = Arc::clone(&mesh);
    let mut dedup_cleanup_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    mesh_for_dedup_cleanup.cleanup_seen_messages(300);
                }
                _ = dedup_cleanup_shutdown.recv() => {
                    tracing::info!("Dedup cache cleanup task shutting down");
                    break;
                }
            }
        }
    });
    info!("Dedup cache cleanup task started (60s interval, 5min TTL)");

    // Noise connection pool cleanup — evict stale connections every 60s
    if let Some(noise_pool) = mesh.noise_pool() {
        let pool_for_cleanup = Arc::clone(noise_pool);
        let mut noise_cleanup_shutdown = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        pool_for_cleanup.cleanup_stale();
                    }
                    _ = noise_cleanup_shutdown.recv() => {
                        tracing::info!("Noise pool cleanup task shutting down");
                        break;
                    }
                }
            }
        });
        info!("Noise pool cleanup task started (60s interval)");
    }

    // Periodic share pruning — delete shares older than 24 hours, run every hour
    let db_for_pruning = Arc::clone(&db);
    let mut share_prune_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        const PRUNE_INTERVAL_SECS: u64 = 3600;
        const SHARE_RETENTION_SECS: i64 = 24 * 3600;

        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(PRUNE_INTERVAL_SECS));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match db_for_pruning.delete_old_shares(SHARE_RETENTION_SECS) {
                        Ok(0) => {}
                        Ok(count) => {
                            tracing::info!(deleted = count, "Pruned old shares from database");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Failed to prune old shares");
                        }
                    }
                }
                _ = share_prune_shutdown.recv() => {
                    tracing::info!("Share pruning task shutting down");
                    break;
                }
            }
        }
    });
    info!("Share pruning task started (hourly, 24h retention)");

    // Periodic database maintenance — prune health_pings, uptime_samples, challenges,
    // verifications, votes + WAL checkpoint + VACUUM. Runs every hour.
    let db_for_maintenance = Arc::clone(&db);
    let mut maintenance_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        const MAINTENANCE_INTERVAL_SECS: u64 = 3600;

        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(MAINTENANCE_INTERVAL_SECS));
        // Skip the first immediate tick — let the node fully start up first
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let config = ghost_storage::database::MaintenanceConfig::default();
                    match db_for_maintenance.run_maintenance(config) {
                        Ok(result) => {
                            tracing::info!(
                                shares = result.shares_deleted,
                                rounds = result.rounds_deleted,
                                pings = result.pings_deleted,
                                votes = result.votes_deleted,
                                uptime = result.uptime_deleted,
                                challenges = result.challenges_deleted.total(),
                                verifications = result.verifications_deleted,
                                db_size_mb = result.db_size_bytes / (1024 * 1024),
                                "Database maintenance complete"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Database maintenance failed");
                        }
                    }
                }
                _ = maintenance_shutdown.recv() => {
                    tracing::info!("Database maintenance task shutting down");
                    break;
                }
            }
        }
    });
    info!("Database maintenance task started (hourly)");

    // M5: Daily database backup task
    let db_for_backup = Arc::clone(&db);
    let backup_dir = data_dir.clone();
    let mut backup_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        const BACKUP_INTERVAL_SECS: u64 = 86400; // 24 hours

        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(BACKUP_INTERVAL_SECS));
        // Skip first immediate tick — let node start fully first
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let backup_path = backup_dir.join("ghost_backup.db");
                    match db_for_backup.backup(&backup_path) {
                        Ok(()) => {
                            tracing::info!(path = ?backup_path, "Daily database backup complete");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Daily database backup failed");
                        }
                    }
                }
                _ = backup_shutdown.recv() => {
                    tracing::info!("Database backup task shutting down");
                    break;
                }
            }
        }
    });
    info!("Database backup task started (daily)");

    // Clone ws_state for event handlers before moving verification_state
    let _verification_state_for_ws = Arc::clone(&verification_state);

    let http_port = config.network.http_port;
    // Build TLS config for HTTPS on the verification server.
    // Only enable TLS when the operator explicitly provides cert/key paths OR on mainnet.
    // On signet/testnet without explicit certs, use plain HTTP to match the verification
    // client which uses HTTP for peer challenges (self-signed certs aren't trusted).
    let has_explicit_tls = config.network.tls.cert_path.is_some();
    let is_mainnet_tls = config.bitcoin.network == ghost_common::config::BitcoinNetwork::Mainnet;
    let tls_server_config = if has_explicit_tls || is_mainnet_tls {
        match ghost_common::tls::build_server_config_for_network(
            &config.network.tls,
            is_mainnet_tls,
        ) {
            Ok(tls) => {
                info!(
                    "TLS configured for verification server on port {}",
                    http_port
                );
                Some(tls)
            }
            Err(e) => {
                if is_mainnet_tls {
                    return Err(anyhow::anyhow!(
                        "MAINNET SECURITY: TLS configuration failed and cannot fall back to HTTP on mainnet. \
                         Fix TLS cert/key at {:?}/{:?}: {}",
                        config.network.tls.cert_path,
                        config.network.tls.key_path,
                        e
                    ));
                }
                warn!(error = %e, "Failed to build TLS config, verification server will use plain HTTP");
                None
            }
        }
    } else {
        info!("Verification server using plain HTTP (no TLS cert configured)");
        None
    };
    tokio::spawn(async move {
        if let Err(e) = start_server(verification_state, http_port, tls_server_config).await {
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

        // M-17 SECURITY: Limit concurrent Noise connections to prevent resource exhaustion.
        // 100 concurrent connections is sufficient for a healthy P2P mesh while preventing
        // DoS attacks that exhaust file descriptors or memory.
        let noise_connection_limit = Arc::new(Semaphore::new(100));
        let mut noise_shutdown = shutdown_tx.subscribe();

        tokio::spawn(async move {
            use tokio::net::TcpListener;

            let bind_addr = format!("0.0.0.0:{}", noise_port);
            let listener = match TcpListener::bind(&bind_addr).await {
                Ok(l) => {
                    info!(
                        port = noise_port,
                        max_connections = 100,
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
                // M-17: Acquire permit before accepting connection
                let permit = match noise_connection_limit.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => {
                        // Semaphore closed - should not happen
                        error!("Noise connection semaphore closed unexpectedly");
                        return;
                    }
                };

                let accept_result = tokio::select! {
                    result = listener.accept() => result,
                    _ = noise_shutdown.recv() => {
                        tracing::info!("Noise listener shutting down");
                        return;
                    }
                };

                match accept_result {
                    Ok((stream, addr)) => {
                        let pool = Arc::clone(&noise_pool_clone);
                        let mesh = Arc::clone(&mesh_for_noise);

                        tokio::spawn(async move {
                            // M-17: Hold permit for connection lifetime - released when dropped
                            let _permit = permit;

                            // H2: Timeout Noise handshake to prevent resource exhaustion
                            // from peers that connect but never complete the handshake
                            let accept_result = tokio::time::timeout(
                                std::time::Duration::from_secs(30),
                                pool.accept_connection(stream),
                            )
                            .await;

                            let accept_result = match accept_result {
                                Ok(result) => result,
                                Err(_) => {
                                    tracing::warn!(
                                        peer = %addr,
                                        "Noise handshake timed out after 30s"
                                    );
                                    return;
                                }
                            };

                            match accept_result {
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
                        // Drop permit on error so we don't leak it
                        drop(permit);
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
    //
    // L-15 SECURITY NOTE: Discovery broadcasts are intentionally unauthenticated
    //
    // Discovery messages are sent over ZMQ PUB/SUB without encryption because:
    //
    // 1. **Bootstrap Problem**: Nodes need to discover peers before they can
    //    establish authenticated connections. Requiring authentication for
    //    discovery would create a chicken-and-egg problem.
    //
    // 2. **Defense in Depth via Noise Authentication**: After discovering a peer,
    //    all sensitive communication (shares, blocks, votes, payouts) is sent
    //    over Noise Protocol encrypted channels (port 8563). An attacker who
    //    injects false discovery messages cannot:
    //    - Receive shares or blocks (encrypted to real node's Noise key)
    //    - Cast votes (requires cryptographic identity proof)
    //    - Modify payouts (BFT consensus with signed votes)
    //
    // 3. **Address Validation**: Discovery handler validates that advertised
    //    addresses are valid IPs (not domains), non-reserved, and haven't been
    //    claimed by another node (H-P2P-4 address hijacking protection).
    //
    // 4. **Rate Limiting**: Discovery messages are rate-limited per sender to
    //    prevent flooding attacks (M-8).
    //
    // 5. **Signature Verification**: While broadcast is unauthenticated,
    //    discovery messages include the sender's signature. The handler verifies
    //    this signature before processing (M-3 defense-in-depth).
    //
    // The worst case for a discovery attacker is wasting CPU on connection
    // attempts to non-existent or malicious endpoints, which is mitigated by
    // the Noise handshake timeout and connection backoff.
    let mesh_for_discovery = Arc::clone(&mesh);
    let discovery_for_broadcast = Arc::clone(&discovery_handler);
    let mut discovery_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        // Wait for mesh to establish connections
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            tokio::select! {
                _ = interval.tick() => {
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
                }
                _ = discovery_shutdown.recv() => {
                    tracing::info!("Discovery broadcast task shutting down");
                    break;
                }
            }
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
    // Use HTTPS on mainnet, HTTP on signet/testnet (where TLS is typically not configured)
    let is_mainnet = config.bitcoin.network == ghost_common::config::BitcoinNetwork::Mainnet;
    let verification_result = if is_mainnet {
        VerificationTask::new_with_identity(
            Arc::clone(&db),
            &identity,
            peer_provider as Arc<dyn PeerProvider>,
        )
    } else {
        // Signet/testnet: Use HTTP since TLS is typically not configured
        VerificationTask::new_for_signet(
            Arc::clone(&db),
            &identity,
            peer_provider as Arc<dyn PeerProvider>,
        )
    };
    match verification_result {
        Ok(verification_task) => {
            let verification_task = verification_task
                .with_rpc(Arc::clone(&rpc))
                .with_broadcast(verification_tx);

            let mut verification_shutdown = shutdown_tx.subscribe();
            tokio::spawn(async move {
                // Wait for mesh to establish connections before starting verification
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                tokio::select! {
                    _ = verification_task.run() => {}
                    _ = verification_shutdown.recv() => {
                        tracing::info!("Verification task shutting down");
                    }
                }
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
                        peer_entries = peer_count,
                        zmq_connections = connected_count,
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

        // H-8 SECURITY: Store ZMQ subscriber in static OnceLock instead of leaking via mem::forget.
        // This keeps it alive for the program lifetime while allowing proper cleanup on exit.
        if ZMQ_SUBSCRIBER.set(zmq_subscriber).is_err() {
            warn!("ZMQ subscriber already initialized - this should not happen");
        }
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
                            let threshold_ts = match db_for_events.get_treasury_threshold_reached()
                            {
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
                        // Query miner work from database (source of truth, not ephemeral memory)
                        let miner_work = {
                            use ghost_accounting::shares::WORK_SCALE;
                            let db_work =
                                db_for_events.get_round_miners(round_id).unwrap_or_default();
                            let db_work = if db_work.is_empty() && round_id > 0 {
                                db_for_events
                                    .get_round_miners(round_id - 1)
                                    .unwrap_or_default()
                            } else {
                                db_work
                            };
                            if db_work.is_empty() {
                                warn!(
                                    round = round_id,
                                    "No miner work in DB, falling back to in-memory data"
                                );
                                rm_for_events.get_miner_work_scaled(round_id)
                            } else {
                                db_work
                                    .into_iter()
                                    .take(200)
                                    .map(|(id, w)| (id, (w * WORK_SCALE as f64) as u128))
                                    .collect()
                            }
                        };
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
    if let Some(ref ts) = tor_status {
        if ts.enabled {
            info!(
                "  Tor:        active ({})",
                ts.onion_address.as_deref().unwrap_or("pending")
            );
        }
    }
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

    // H-9 SECURITY: Allow graceful shutdown period for spawned tasks.
    // Tasks subscribe to shutdown_tx and exit when signaled. This gives them
    // time to complete in-flight operations (save state, close connections).
    // 5 seconds is sufficient for orderly cleanup without blocking restart.
    info!("Waiting up to 5 seconds for tasks to complete...");
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

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
        // Check config file permissions (warns if world-readable)
        ghost_common::config::validate_config_permissions(path);

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
