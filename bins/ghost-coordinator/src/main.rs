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

//! Ghost Coordinator - Miner Assignment and Load Balancing
//!
//! The coordinator helps new miners find the best node to connect to.
//! It does NOT participate in consensus - it's purely a discovery service.
//!
//! Features:
//! - Fire Ping: Measure latency to nodes
//! - Gradient Descent: Optimize miner placement
//! - Health Monitoring: Track node availability
//! - Load Balancing: Distribute miners across nodes

use anyhow::Result;
use axum::{
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use clap::Parser;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing::{debug, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use ghost_common::constants::{
    COORDINATOR_HEARTBEAT_SECS, CONVERGENCE_MAX_ITERATIONS, CONVERGENCE_MIGRATION_THRESHOLD,
    CONVERGENCE_TEST_INTERVAL_SECS, FIRE_PING_TIMEOUT_MS,
};
use ghost_common::types::{CapacityState, NodeCapabilities};

/// Ghost Coordinator
#[derive(Parser, Debug)]
#[command(name = "ghost-coordinator")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// HTTP listen address
    #[arg(long, default_value = "0.0.0.0:8333")]
    listen: String,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Fire Ping timeout (milliseconds)
    #[arg(long, default_value_t = FIRE_PING_TIMEOUT_MS)]
    fire_ping_timeout: u64,

    /// Heartbeat interval (seconds)
    #[arg(long, default_value_t = COORDINATOR_HEARTBEAT_SECS)]
    heartbeat_interval: u64,

    /// Enable gradient descent optimization
    #[arg(long)]
    enable_convergence: bool,
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

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");

    info!("Starting Ghost Coordinator v{}", env!("CARGO_PKG_VERSION"));

    // Create coordinator state
    let state = Arc::new(CoordinatorState::new(
        Duration::from_millis(args.fire_ping_timeout),
        args.enable_convergence,
    ));

    // Start background tasks
    let state_clone = Arc::clone(&state);
    let heartbeat_interval = args.heartbeat_interval;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(heartbeat_interval));
        loop {
            interval.tick().await;
            state_clone.update_node_health().await;
        }
    });

    if args.enable_convergence {
        let state_clone = Arc::clone(&state);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(CONVERGENCE_TEST_INTERVAL_SECS));
            loop {
                interval.tick().await;
                state_clone.run_convergence_test().await;
            }
        });
    }

    // Create router
    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/nodes", get(list_nodes_handler))
        .route("/assign", get(assign_node_handler))
        .route("/register", get(register_node_handler))
        .route("/fire-ping", get(fire_ping_handler))
        // API v1 routes for website
        .route("/api/v1/stats", get(api_stats_handler))
        .route("/api/v1/nodes", get(api_nodes_handler))
        .layer(CorsLayer::permissive())
        .with_state(state);

    // Start server
    let addr: SocketAddr = args.listen.parse()?;
    info!("Coordinator listening on {}", addr);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Coordinator state
struct CoordinatorState {
    nodes: RwLock<HashMap<String, NodeInfo>>,
    #[allow(dead_code)]
    fire_ping_timeout: Duration,
    enable_convergence: bool,
    http_client: reqwest::Client,
}

impl CoordinatorState {
    fn new(fire_ping_timeout: Duration, enable_convergence: bool) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(fire_ping_timeout)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            nodes: RwLock::new(HashMap::new()),
            fire_ping_timeout,
            enable_convergence,
            http_client,
        }
    }

    /// Register or update a node
    fn register_node(&self, info: NodeInfo) {
        let mut nodes = self.nodes.write();
        info!("Registering node: {} at {}", info.node_id_short(), info.address);
        nodes.insert(info.node_id.clone(), info);
    }

    /// Get all nodes
    fn get_nodes(&self) -> Vec<NodeInfo> {
        self.nodes.read().values().cloned().collect()
    }

    /// Get healthy nodes
    fn get_healthy_nodes(&self) -> Vec<NodeInfo> {
        self.nodes
            .read()
            .values()
            .filter(|n| n.is_healthy())
            .cloned()
            .collect()
    }

    /// Find best node for a miner
    fn find_best_node(&self, _miner_ip: Option<&str>) -> Option<NodeInfo> {
        let healthy = self.get_healthy_nodes();
        if healthy.is_empty() {
            return None;
        }

        // Score nodes based on:
        // 1. Latency (from Fire Ping)
        // 2. Load (capacity state)
        // 3. Capabilities (more shares = better rewards)
        let mut scored: Vec<_> = healthy
            .into_iter()
            .map(|n| {
                let latency_score = n.latency_ms.map(|l| 1.0 - (l as f64 / 1000.0).min(1.0)).unwrap_or(0.5);
                let load_score = 1.0 - n.capacity_state.load_penalty();
                let capability_score = n.capabilities.total_shares() as f64 / 15.0;

                let score = (latency_score * 0.4) + (load_score * 0.4) + (capability_score * 0.2);
                (n, score)
            })
            .collect();

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.first().map(|(n, _)| n.clone())
    }

    /// Update health status of all nodes
    async fn update_node_health(&self) {
        let nodes: Vec<_> = self.nodes.read().values().cloned().collect();

        for node in nodes {
            let latency = self.fire_ping(&node.address).await;

            let mut nodes = self.nodes.write();
            if let Some(n) = nodes.get_mut(&node.node_id) {
                n.latency_ms = latency;
                n.last_seen = chrono::Utc::now().timestamp() as u64;

                if latency.is_none() {
                    n.consecutive_failures += 1;
                    if n.consecutive_failures > 3 {
                        warn!("Node {} appears unhealthy", n.node_id_short());
                    }
                } else {
                    n.consecutive_failures = 0;
                }
            }
        }
    }

    /// Fire Ping - measure latency to a node with multiple samples
    ///
    /// Performs multiple HTTP pings and returns the median latency.
    /// Uses retry logic for transient failures.
    async fn fire_ping(&self, address: &str) -> Option<u32> {
        let result = self.fire_ping_detailed(address).await;
        result.map(|r| r.median_ms)
    }

    /// Fire Ping with detailed statistics
    ///
    /// Returns detailed ping statistics including min, max, median, and jitter.
    async fn fire_ping_detailed(&self, address: &str) -> Option<FirePingResult> {
        const NUM_SAMPLES: usize = 5;
        const SAMPLE_DELAY_MS: u64 = 50;

        let url = format!("http://{}/health", address);
        let mut latencies: Vec<u32> = Vec::with_capacity(NUM_SAMPLES);
        let mut failures = 0;

        for i in 0..NUM_SAMPLES {
            // Small delay between samples (except first)
            if i > 0 {
                tokio::time::sleep(Duration::from_millis(SAMPLE_DELAY_MS)).await;
            }

            let start = Instant::now();
            match self.http_client.get(&url).send().await {
                Ok(response) if response.status().is_success() => {
                    let latency = start.elapsed().as_millis() as u32;
                    latencies.push(latency);
                }
                Ok(response) => {
                    debug!(
                        address = %address,
                        status = %response.status(),
                        "Fire ping returned non-success status"
                    );
                    failures += 1;
                }
                Err(e) => {
                    debug!(
                        address = %address,
                        error = %e,
                        attempt = i + 1,
                        "Fire ping failed"
                    );
                    failures += 1;
                }
            }
        }

        // Need at least 2 successful samples for meaningful statistics
        if latencies.len() < 2 {
            return None;
        }

        // Calculate statistics
        latencies.sort_unstable();

        let min_ms = *latencies.first().unwrap();
        let max_ms = *latencies.last().unwrap();
        let median_ms = latencies[latencies.len() / 2];

        // Calculate average
        let sum: u32 = latencies.iter().sum();
        let avg_ms = sum / latencies.len() as u32;

        // Calculate jitter (standard deviation)
        let variance: f64 = latencies
            .iter()
            .map(|&l| {
                let diff = l as f64 - avg_ms as f64;
                diff * diff
            })
            .sum::<f64>()
            / latencies.len() as f64;
        let jitter_ms = variance.sqrt() as u32;

        Some(FirePingResult {
            min_ms,
            max_ms,
            avg_ms,
            median_ms,
            jitter_ms,
            samples: latencies.len() as u32,
            failures: failures as u32,
        })
    }

    /// Run gradient descent convergence test
    async fn run_convergence_test(&self) {
        if !self.enable_convergence {
            return;
        }

        debug!("Running convergence test");

        let nodes = self.get_healthy_nodes();
        if nodes.len() < 2 {
            return;
        }

        // Calculate current cost (sum of weighted latencies)
        let current_cost = self.calculate_total_cost(&nodes);

        // Run gradient descent iterations
        let mut best_assignments = self.get_current_assignments();
        let mut best_cost = current_cost;

        for iteration in 0..CONVERGENCE_MAX_ITERATIONS {
            // Try swapping some miner assignments
            let test_assignments = self.propose_swaps(&best_assignments, &nodes);
            let test_cost = self.calculate_assignment_cost(&test_assignments, &nodes);

            if test_cost < best_cost {
                let improvement = (best_cost - test_cost) / best_cost;
                debug!(
                    iteration = iteration,
                    improvement_percent = improvement * 100.0,
                    "Found better assignment"
                );

                if improvement >= CONVERGENCE_MIGRATION_THRESHOLD {
                    best_assignments = test_assignments;
                    best_cost = test_cost;
                }
            }
        }

        // Log results
        let improvement = (current_cost - best_cost) / current_cost;
        if improvement > 0.0 {
            info!(
                improvement_percent = improvement * 100.0,
                suggested_migrations = best_assignments.len(),
                "Convergence test complete - improvements found"
            );
        }
    }

    /// Calculate total latency cost across all nodes
    fn calculate_total_cost(&self, nodes: &[NodeInfo]) -> f64 {
        nodes.iter()
            .map(|n| {
                let latency = n.latency_ms.unwrap_or(500) as f64;
                let load = n.miner_count as f64;
                latency * load
            })
            .sum()
    }

    /// Get current miner assignments
    fn get_current_assignments(&self) -> Vec<MinerAssignment> {
        let nodes = self.nodes.read();
        nodes.values()
            .map(|n| MinerAssignment {
                node_id: n.node_id.clone(),
                miner_count: n.miner_count,
            })
            .collect()
    }

    /// Propose swaps to improve distribution
    fn propose_swaps(&self, current: &[MinerAssignment], nodes: &[NodeInfo]) -> Vec<MinerAssignment> {
        let mut proposed = current.to_vec();

        // Find overloaded and underloaded nodes
        let avg_load = proposed.iter().map(|a| a.miner_count).sum::<u32>() as f64 / proposed.len() as f64;

        for assignment in &mut proposed {
            let node = nodes.iter().find(|n| n.node_id == assignment.node_id);
            if let Some(node) = node {
                // Move miners from slow nodes to fast nodes
                let latency_factor = node.latency_ms.unwrap_or(500) as f64 / 100.0;
                if latency_factor > 3.0 && assignment.miner_count as f64 > avg_load {
                    // This node is slow and overloaded, reduce
                    assignment.miner_count = (assignment.miner_count as f64 * 0.8) as u32;
                }
            }
        }

        proposed
    }

    /// Calculate cost for a proposed assignment
    fn calculate_assignment_cost(&self, assignments: &[MinerAssignment], nodes: &[NodeInfo]) -> f64 {
        assignments.iter()
            .map(|a| {
                let node = nodes.iter().find(|n| n.node_id == a.node_id);
                let latency = node.and_then(|n| n.latency_ms).unwrap_or(500) as f64;
                latency * a.miner_count as f64
            })
            .sum()
    }
}

/// Miner assignment for convergence
#[derive(Debug, Clone)]
struct MinerAssignment {
    node_id: String,
    miner_count: u32,
}

/// Node information
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NodeInfo {
    node_id: String,
    address: String,
    capabilities: NodeCapabilities,
    capacity_state: CapacityState,
    miner_count: u32,
    max_miners: u32,
    latency_ms: Option<u32>,
    last_seen: u64,
    #[serde(skip)]
    consecutive_failures: u32,
}

impl NodeInfo {
    fn node_id_short(&self) -> String {
        if self.node_id.len() >= 8 {
            self.node_id[..8].to_string()
        } else {
            self.node_id.clone()
        }
    }

    fn is_healthy(&self) -> bool {
        let now = chrono::Utc::now().timestamp() as u64;
        let age = now.saturating_sub(self.last_seen);
        age < 60 && self.consecutive_failures < 3
    }
}

// HTTP Handlers

async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "healthy": true,
        "service": "ghost-coordinator",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn list_nodes_handler(
    State(state): State<Arc<CoordinatorState>>,
) -> impl IntoResponse {
    let nodes = state.get_nodes();
    Json(serde_json::json!({
        "nodes": nodes,
        "count": nodes.len(),
    }))
}

#[derive(Debug, Deserialize)]
struct AssignQuery {
    miner_ip: Option<String>,
}

async fn assign_node_handler(
    State(state): State<Arc<CoordinatorState>>,
    Query(query): Query<AssignQuery>,
) -> impl IntoResponse {
    match state.find_best_node(query.miner_ip.as_deref()) {
        Some(node) => Json(serde_json::json!({
            "success": true,
            "node": {
                "address": node.address,
                "node_id": node.node_id,
                "latency_ms": node.latency_ms,
            }
        })),
        None => Json(serde_json::json!({
            "success": false,
            "error": "No healthy nodes available"
        })),
    }
}

#[derive(Debug, Deserialize)]
struct RegisterQuery {
    node_id: String,
    address: String,
    max_miners: Option<u32>,
}

async fn register_node_handler(
    State(state): State<Arc<CoordinatorState>>,
    Query(query): Query<RegisterQuery>,
) -> impl IntoResponse {
    let info = NodeInfo {
        node_id: query.node_id,
        address: query.address,
        capabilities: NodeCapabilities::default(),
        capacity_state: CapacityState::Healthy,
        miner_count: 0,
        max_miners: query.max_miners.unwrap_or(1000),
        latency_ms: None,
        last_seen: chrono::Utc::now().timestamp() as u64,
        consecutive_failures: 0,
    };

    state.register_node(info);

    Json(serde_json::json!({
        "success": true,
        "message": "Node registered"
    }))
}

/// Fire Ping result with detailed statistics
#[derive(Debug, Clone, Serialize)]
struct FirePingResult {
    /// Minimum latency across samples
    min_ms: u32,
    /// Maximum latency across samples
    max_ms: u32,
    /// Average latency
    avg_ms: u32,
    /// Median latency (used as primary metric)
    median_ms: u32,
    /// Jitter (standard deviation)
    jitter_ms: u32,
    /// Number of successful samples
    samples: u32,
    /// Number of failed samples
    failures: u32,
}

#[derive(Debug, Deserialize)]
struct FirePingQuery {
    address: String,
    /// If true, return detailed statistics
    #[serde(default)]
    detailed: bool,
}

async fn fire_ping_handler(
    State(state): State<Arc<CoordinatorState>>,
    Query(query): Query<FirePingQuery>,
) -> impl IntoResponse {
    if query.detailed {
        // Return detailed statistics
        match state.fire_ping_detailed(&query.address).await {
            Some(result) => Json(serde_json::json!({
                "address": query.address,
                "success": true,
                "latency_ms": result.median_ms,
                "stats": {
                    "min_ms": result.min_ms,
                    "max_ms": result.max_ms,
                    "avg_ms": result.avg_ms,
                    "median_ms": result.median_ms,
                    "jitter_ms": result.jitter_ms,
                    "samples": result.samples,
                    "failures": result.failures,
                }
            })),
            None => Json(serde_json::json!({
                "address": query.address,
                "success": false,
                "error": "Failed to reach node",
            })),
        }
    } else {
        // Return simple latency (backwards compatible)
        let latency = state.fire_ping(&query.address).await;
        Json(serde_json::json!({
            "address": query.address,
            "latency_ms": latency,
            "success": latency.is_some(),
        }))
    }
}

// ============================================================================
// API v1 Handlers for Website
// ============================================================================

/// API v1 stats handler - aggregated pool statistics
async fn api_stats_handler(
    State(state): State<Arc<CoordinatorState>>,
) -> impl IntoResponse {
    let nodes = state.get_nodes();
    let healthy_nodes = state.get_healthy_nodes();

    let total_miners: u32 = nodes.iter().map(|n| n.miner_count).sum();
    let total_capacity: u32 = nodes.iter().map(|n| n.max_miners).sum();

    Json(serde_json::json!({
        "online_nodes": healthy_nodes.len(),
        "total_nodes": nodes.len(),
        "active_sessions": total_miners,
        "total_capacity": total_capacity,
        "pool_hashrate_th": 0.0,
        "network": "signet"
    }))
}

/// API v1 nodes handler - node list for website display
async fn api_nodes_handler(
    State(state): State<Arc<CoordinatorState>>,
) -> impl IntoResponse {
    let nodes = state.get_nodes();

    let formatted_nodes: Vec<_> = nodes.iter().map(|n| {
        let load_percent = if n.max_miners > 0 {
            (n.miner_count as f64 / n.max_miners as f64 * 100.0) as u32
        } else {
            0
        };

        serde_json::json!({
            "node_id": n.node_id,
            "host": n.address.split(':').next().unwrap_or(&n.address),
            "port": n.address.split(':').nth(1).unwrap_or("8080"),
            "region": "europe",
            "miner_count": n.miner_count,
            "max_miners": n.max_miners,
            "load_percent": load_percent,
            "latency_ms": n.latency_ms,
            "accepting_miners": n.is_healthy() && n.miner_count < n.max_miners,
            "capabilities": n.capabilities
        })
    }).collect();

    Json(serde_json::json!({
        "nodes": formatted_nodes,
        "count": formatted_nodes.len()
    }))
}
