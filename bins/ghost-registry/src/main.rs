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

//! Ghost Registry - Pool Node Registry and DNS Load Balancer
//!
//! This service receives registrations from ghost-pool nodes and manages
//! Cloudflare DNS records for geographic load balancing.
//!
//! Run with: ghost-registry --config registry.toml

mod api;
mod cloudflare;
mod config;
mod db;
mod health_checker;

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use api::{build_router, AppState};
use cloudflare::CloudflareClient;
use config::RegistryServiceConfig;
use db::RegistryDb;
use health_checker::HealthChecker;

/// Ghost Registry - Pool Node Registry and DNS Load Balancer
#[derive(Parser, Debug)]
#[command(name = "ghost-registry")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "/etc/ghost/registry.toml")]
    config: PathBuf,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Override listen address
    #[arg(long)]
    listen: Option<String>,
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

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!(
        "║              Ghost Registry v{}                         ║",
        env!("CARGO_PKG_VERSION")
    );
    info!("║         Pool Node Registry & DNS Load Balancer               ║");
    info!("╚══════════════════════════════════════════════════════════════╝");

    // Load configuration
    let mut config = load_config(&args.config)?;

    // Resolve environment variables in Cloudflare config
    config.cloudflare.resolve_env();

    // Override listen address if specified
    if let Some(listen) = args.listen {
        config.server.listen = listen;
    }

    // Ensure database directory exists
    if let Some(parent) = config.database.path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Initialize database
    let db = Arc::new(RegistryDb::open(&config.database.path)?);
    info!("Database opened: {}", config.database.path.display());

    // Initialize Cloudflare client
    let cloudflare = Arc::new(CloudflareClient::new(
        config.cloudflare.clone(),
        config.dns.clone(),
    )?);

    if config.cloudflare.enabled {
        info!(
            "Cloudflare DNS integration enabled for {}",
            config.cloudflare.base_domain
        );
    } else {
        info!("Cloudflare DNS integration disabled");
    }

    // Create shutdown channel
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // Initialize health checker
    let health_checker = Arc::new(HealthChecker::new(
        Arc::clone(&db),
        Arc::clone(&cloudflare),
        config.health.clone(),
        config.dns.max_nodes_per_region,
    ));

    // Start health checker background task
    let health_checker_task = Arc::clone(&health_checker);
    let health_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        health_checker_task.start(health_shutdown).await;
    });

    // Create app state
    let app_state = Arc::new(AppState {
        db,
        health_checker,
        health_config: config.health.clone(),
    });

    // Build router with middleware
    let app = build_router(app_state)
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );

    // Parse listen address
    let addr: SocketAddr = config.server.listen.parse()?;

    info!("════════════════════════════════════════════════════════════════");
    info!("Ghost Registry is ready!");
    info!("  HTTP API:     {}", addr);
    info!("  Health check: {}/health", addr);
    info!("  Cloudflare:   {}", if config.cloudflare.enabled { "enabled" } else { "disabled" });
    info!("════════════════════════════════════════════════════════════════");

    // Start server
    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install CTRL+C handler");
            info!("Shutdown signal received");
            let _ = shutdown_tx.send(());
        })
        .await?;

    info!("Ghost Registry shutdown complete");
    Ok(())
}

/// Load configuration from file
fn load_config(path: &PathBuf) -> Result<RegistryServiceConfig> {
    if path.exists() {
        let content = std::fs::read_to_string(path)?;
        let config: RegistryServiceConfig = toml::from_str(&content)?;
        info!("Configuration loaded from: {}", path.display());
        Ok(config)
    } else {
        info!(
            "No config file found at {}, using defaults",
            path.display()
        );
        Ok(RegistryServiceConfig::default())
    }
}
