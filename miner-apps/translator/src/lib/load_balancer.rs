use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Deserialize)]
pub struct LoadBalancerConfig {
    #[serde(default = "default_ghost_pool_url")]
    pub ghost_pool_url: String,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_proxy_threshold")]
    pub proxy_threshold: u32,
    #[serde(default = "default_proxy_timeout_ms")]
    pub proxy_timeout_ms: u64,
}

fn default_ghost_pool_url() -> String {
    "127.0.0.1:8080".to_string()
}
fn default_poll_interval() -> u64 {
    10
}
fn default_proxy_threshold() -> u32 {
    2
}
fn default_proxy_timeout_ms() -> u64 {
    5000
}

#[derive(Debug, Deserialize)]
struct PoolNodesResponse {
    this_node: ThisNode,
    peers: Vec<PeerInfo>,
}

#[derive(Debug, Deserialize)]
struct ThisNode {
    miner_count: u32,
}

#[derive(Debug, Clone, Deserialize)]
struct PeerInfo {
    public_address: String,
    miner_count: u32,
    public_mining: bool,
    last_seen: u64,
}

struct Cache {
    peers: Vec<PeerInfo>,
    updated_at: Instant,
}

pub struct LoadBalancer {
    config: LoadBalancerConfig,
    cache: Arc<RwLock<Option<Cache>>>,
    connections_proxied: AtomicU64,
    proxy_failures: AtomicU64,
}

impl LoadBalancer {
    pub fn new(config: LoadBalancerConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            cache: Arc::new(RwLock::new(None)),
            connections_proxied: AtomicU64::new(0),
            proxy_failures: AtomicU64::new(0),
        })
    }

    pub fn spawn_poller(self: &Arc<Self>) {
        let lb = Arc::clone(self);
        tokio::spawn(async move {
            let interval = Duration::from_secs(lb.config.poll_interval_secs);
            loop {
                match poll_pool_nodes(&lb.config.ghost_pool_url).await {
                    Ok(resp) => {
                        let mut cache = lb.cache.write().await;
                        *cache = Some(Cache {
                            peers: resp.peers,
                            updated_at: Instant::now(),
                        });
                    }
                    Err(e) => {
                        debug!("Load balancer poll failed (non-fatal): {}", e);
                    }
                }
                tokio::time::sleep(interval).await;
            }
        });
    }

    /// Decide whether to proxy an incoming connection to a less-loaded peer.
    /// Returns `Some(target_addr)` if proxying, `None` to handle locally.
    pub async fn should_proxy(&self, local_downstream_count: usize) -> Option<SocketAddr> {
        let cache = self.cache.read().await;
        let cache = cache.as_ref()?;

        // Stale cache (>3x poll interval) → handle locally
        if cache.updated_at.elapsed() > Duration::from_secs(self.config.poll_interval_secs * 3) {
            return None;
        }

        let local_count = local_downstream_count as u32;

        // Find the least-loaded peer with public_mining
        let best_peer = cache
            .peers
            .iter()
            .filter(|p| p.public_mining && !p.public_address.is_empty())
            .min_by_key(|p| p.miner_count)?;

        // Only proxy if local count exceeds best peer by the threshold
        if local_count < best_peer.miner_count + self.config.proxy_threshold {
            return None;
        }

        // Parse peer address — health ping public_address is "IP:P2P_port",
        // we want IP:3333 (SV1 stratum port).
        let ip = best_peer
            .public_address
            .split(':')
            .next()
            .unwrap_or(&best_peer.public_address);
        let target: SocketAddr = format!("{}:3333", ip).parse().ok()?;

        Some(target)
    }

    /// Spawn a background task that pipes bytes between the miner and the target node.
    pub fn spawn_proxy(self: &Arc<Self>, client: TcpStream, target: SocketAddr) {
        let lb = Arc::clone(self);
        let timeout = Duration::from_millis(lb.config.proxy_timeout_ms);
        tokio::spawn(async move {
            match tokio::time::timeout(timeout, TcpStream::connect(target)).await {
                Ok(Ok(mut server)) => {
                    lb.connections_proxied.fetch_add(1, Ordering::Relaxed);
                    info!("Proxying miner to {}", target);
                    let mut client = client;
                    if let Err(e) =
                        tokio::io::copy_bidirectional(&mut client, &mut server).await
                    {
                        debug!("Proxied connection ended: {}", e);
                    }
                }
                Ok(Err(e)) => {
                    lb.proxy_failures.fetch_add(1, Ordering::Relaxed);
                    warn!("Proxy target {} unreachable: {} — miner will reconnect via DNS", target, e);
                    // Drop client — miner firmware auto-reconnects
                }
                Err(_) => {
                    lb.proxy_failures.fetch_add(1, Ordering::Relaxed);
                    warn!("Proxy connect to {} timed out — miner will reconnect via DNS", target);
                }
            }
        });
    }

    pub fn stats(&self) -> (u64, u64) {
        (
            self.connections_proxied.load(Ordering::Relaxed),
            self.proxy_failures.load(Ordering::Relaxed),
        )
    }
}

/// Minimal HTTP/1.1 GET to a local endpoint, returns parsed JSON.
async fn poll_pool_nodes(host_port: &str) -> Result<PoolNodesResponse, String> {
    let mut stream = TcpStream::connect(host_port)
        .await
        .map_err(|e| format!("connect: {}", e))?;

    let request = format!(
        "GET /api/internal/pool-nodes HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        host_port
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write: {}", e))?;

    let mut buf = Vec::with_capacity(4096);
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("read: {}", e))?;

    let response = String::from_utf8_lossy(&buf);
    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .ok_or("no HTTP body")?;

    serde_json::from_str(body).map_err(|e| format!("json: {}", e))
}
