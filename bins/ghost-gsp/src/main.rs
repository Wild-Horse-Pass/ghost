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
//| FILE: bins/ghost-gsp/main.rs                                                                                         |
//|======================================================================================================================|

//! Ghost Service Provider (GSP)
//!
//! A server that enables light wallets to use Ghost Pay without running a full node.
//!
//! Features:
//! - REST API for registration and session management
//! - WebSocket API for real-time updates
//! - Proxy to ghost-pay-node for payment operations
//! - Balance and transaction queries
//! - Ghost Lock management
//!
//! Architecture:
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                          GSP                                 │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐  │
//! │  │ REST API │  │WebSocket │  │ Session  │  │  Registry  │  │
//! │  │/register │  │  Handler │  │ Manager  │  │   (SQLite) │  │
//! │  │/session  │  │          │  │  (JWT)   │  │            │  │
//! │  └──────────┘  └──────────┘  └──────────┘  └────────────┘  │
//! │                           │                                  │
//! │  ┌────────────────────────┴────────────────────────────────┐│
//! │  │                    Proxy Layer                           ││
//! │  │  ┌──────────┐  ┌──────────┐                            ││
//! │  │  │ PayNode  │  │  ghostd  │                            ││
//! │  │  │  Proxy   │  │  Proxy   │                            ││
//! │  │  └──────────┘  └──────────┘                            ││
//! │  └─────────────────────────────────────────────────────────┘│
//! └───────────────────────────┬─────────────────────────────────┘
//!                             │ JSON-RPC
//!                             ▼
//!               ┌─────────────────────────────┐
//!               │  ghost-pay-node + ghostd    │
//!               └─────────────────────────────┘
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use bitcoin::Network;
use clap::Parser;
use serde::Deserialize;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use ghost_gsp::{GspConfig, GspServer};

/// Ghost Service Provider
#[derive(Parser, Debug)]
#[command(name = "ghost-gsp")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "gsp.toml")]
    config: PathBuf,

    /// Listen address (HTTP and WebSocket)
    #[arg(long)]
    listen: Option<String>,

    /// Data directory for storage
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// ghost-pay-node RPC URL
    #[arg(long)]
    pay_node_url: Option<String>,

    /// Bitcoin network (mainnet, testnet, signet, regtest)
    #[arg(long)]
    network: Option<String>,

    /// JWT secret (use random if not provided)
    #[arg(long)]
    jwt_secret: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,
}

/// Configuration file format
#[derive(Debug, Deserialize, Default)]
struct ConfigFile {
    /// Server configuration
    #[serde(default)]
    server: ServerConfig,

    /// Storage configuration
    #[serde(default)]
    storage: StorageConfig,

    /// Proxy configuration
    #[serde(default)]
    proxy: ProxyConfig,

    /// Security configuration
    #[serde(default)]
    security: SecurityConfig,
}

#[derive(Debug, Deserialize)]
struct ServerConfig {
    #[serde(default = "default_listen")]
    listen: String,

    #[serde(default = "default_network")]
    network: String,

    #[serde(default = "default_rate_limit")]
    rate_limit_rpm: u32,

    #[serde(default = "default_max_ws_connections")]
    max_ws_connections: usize,

    /// M-4: Maximum request body size in bytes
    #[serde(default = "default_max_body_size")]
    max_body_size: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            network: default_network(),
            rate_limit_rpm: default_rate_limit(),
            max_ws_connections: default_max_ws_connections(),
            max_body_size: default_max_body_size(),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct StorageConfig {
    #[serde(default = "default_data_dir")]
    data_dir: PathBuf,
}

#[derive(Debug, Deserialize, Default)]
struct ProxyConfig {
    #[serde(default = "default_pay_node_url")]
    pay_node_url: String,
}

#[derive(Debug, Deserialize)]
struct SecurityConfig {
    jwt_secret: Option<String>,

    #[serde(default = "default_session_expiry")]
    session_expiry_secs: u64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            jwt_secret: None,
            session_expiry_secs: default_session_expiry(),
        }
    }
}

fn default_listen() -> String {
    "0.0.0.0:8900".to_string()
}

fn default_network() -> String {
    "regtest".to_string()
}

fn default_rate_limit() -> u32 {
    60
}

fn default_max_ws_connections() -> usize {
    100
}

/// M-4: Default max body size (1MB)
fn default_max_body_size() -> usize {
    1024 * 1024
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("./gsp-data")
}

fn default_pay_node_url() -> String {
    "http://127.0.0.1:8800".to_string()
}

fn default_session_expiry() -> u64 {
    86400 // 24 hours
}

fn parse_network(s: &str) -> Network {
    match s.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" | "testnet3" => Network::Testnet,
        "signet" => Network::Signet,
        _ => Network::Regtest,
    }
}

/// L-24: Generate 32-byte cryptographic random secret with proper error handling
fn generate_random_secret() -> Result<[u8; 32]> {
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret).map_err(|e| {
        anyhow::anyhow!(
            "L-24: Failed to generate cryptographic random bytes for JWT secret: {}. \
             This could indicate a system entropy issue or blocked /dev/urandom.",
            e
        )
    })?;
    Ok(secret)
}

/// M-18/L-24: Generate or load JWT secret with proper error handling
fn resolve_jwt_secret(
    configured_secret: Option<String>,
    network: Network,
    data_dir: &std::path::Path,
) -> Result<Vec<u8>> {
    // If explicitly configured, use it
    if let Some(secret) = configured_secret {
        info!("Using configured JWT secret");
        return Ok(secret.into_bytes());
    }

    // On mainnet, secret MUST be explicitly configured
    if network == Network::Bitcoin {
        return Err(anyhow::anyhow!(
            "M-18 SECURITY: jwt_secret MUST be explicitly configured on mainnet. \
             Add 'jwt_secret' to your config file or use --jwt-secret argument. \
             This is required to ensure JWT tokens remain valid across restarts."
        ));
    }

    // Non-mainnet: Generate and persist to data directory
    let secret_path = data_dir.join(".jwt_secret");

    if secret_path.exists() {
        // Load existing persisted secret
        match std::fs::read(&secret_path) {
            Ok(bytes) if bytes.len() == 32 => {
                info!("Loaded persisted JWT secret from {}", secret_path.display());
                return Ok(bytes);
            }
            Ok(bytes) => {
                // Invalid length - regenerate
                tracing::warn!(
                    "Invalid JWT secret length {} in {}, regenerating",
                    bytes.len(),
                    secret_path.display()
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to read JWT secret from {}: {}",
                    secret_path.display(),
                    e
                );
            }
        }
    } else {
        info!(
            "Generating and persisting new JWT secret to {}",
            secret_path.display()
        );
    }

    // Generate new secret
    let secret = generate_random_secret()?;

    // Persist it
    if let Err(e) = std::fs::write(&secret_path, secret) {
        tracing::warn!("Failed to persist JWT secret: {}", e);
    }

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))
        {
            tracing::warn!("Failed to set JWT secret file permissions: {}", e);
        }
    }

    Ok(secret.to_vec())
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
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    info!(
        "Starting Ghost Service Provider v{}",
        env!("CARGO_PKG_VERSION")
    );

    // Load configuration file
    let config_file = if args.config.exists() {
        let content = std::fs::read_to_string(&args.config)?;
        toml::from_str::<ConfigFile>(&content)?
    } else {
        info!("Config file not found, using defaults");
        ConfigFile::default()
    };

    // Build configuration (CLI args override config file)
    let listen_str = args.listen.unwrap_or(config_file.server.listen);
    let listen_addr: SocketAddr = listen_str.parse().map_err(|e| {
        anyhow::anyhow!(
            "L-23: Invalid listen address '{}': {}. Expected format: 'IP:PORT' (e.g., '0.0.0.0:8900' or '[::]:8900')",
            listen_str,
            e
        )
    })?;
    let network_str = args.network.unwrap_or(config_file.server.network);
    let network = parse_network(&network_str);
    let data_dir = args.data_dir.unwrap_or(config_file.storage.data_dir);
    let pay_node_url = args.pay_node_url.unwrap_or(config_file.proxy.pay_node_url);

    // M-18/L-24: JWT secret handling with proper error handling and persistence
    let configured_secret = args.jwt_secret.or(config_file.security.jwt_secret);
    let jwt_secret = resolve_jwt_secret(configured_secret, network, &data_dir)?;

    // Create data directory
    std::fs::create_dir_all(&data_dir)?;

    info!("Listen address: {}", listen_addr);
    info!("Network: {:?}", network);
    info!("Data directory: {}", data_dir.display());
    info!("Pay node URL: {}", pay_node_url);

    // Build GSP configuration
    let gsp_config = GspConfig {
        listen_addr,
        network,
        data_dir: data_dir.clone(),
        pay_node_url: pay_node_url.clone(),
        jwt_secret,
        session_expiry_secs: config_file.security.session_expiry_secs,
        rate_limit_rpm: config_file.server.rate_limit_rpm,
        max_ws_connections: config_file.server.max_ws_connections,
        max_body_size: config_file.server.max_body_size,
    };

    // Create and run GSP server
    let server = GspServer::new(gsp_config).await?;

    info!("GSP server ready");

    // Run the server
    server.run().await?;

    Ok(())
}
