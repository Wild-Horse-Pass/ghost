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
//| FILE: stratum.rs                                                                                                     |
//|======================================================================================================================|

//! Stratum V1 server implementation
//!
//! Handles miner connections and share submissions using Stratum V1 (JSON-RPC) protocol.
//! Implements standard mining.subscribe, mining.authorize, mining.notify, mining.submit methods.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info, warn};

use crate::round::{RoundManager, ShareError};

/// Parse miner username in `address.worker` format (industry standard)
///
/// Returns (payout_address, worker_name).
/// If no `.` is found, the entire username is treated as the address.
///
/// Examples:
/// - `bc1qxyz...abc.rig1` -> (`bc1qxyz...abc`, `rig1`)
/// - `bc1qxyz...abc` -> (`bc1qxyz...abc`, `default`)
/// - `.worker` -> (``, `worker`) - invalid, will be rejected
pub fn parse_miner_username(username: &str) -> (String, String) {
    if let Some(dot_pos) = username.rfind('.') {
        // Split at the last dot (address may contain '.' in some schemes)
        let address = &username[..dot_pos];
        let worker = &username[dot_pos + 1..];

        // Worker name defaults to "default" if empty
        let worker_name = if worker.is_empty() {
            "default".to_string()
        } else {
            worker.to_string()
        };

        (address.to_string(), worker_name)
    } else {
        // No dot found, entire username is the address
        (username.to_string(), "default".to_string())
    }
}

/// Validate a Bitcoin address using proper parsing
///
/// Uses the bitcoin crate for thorough address validation including:
/// - Correct checksum for base58 (P2PKH, P2SH)
/// - Valid bech32/bech32m encoding for segwit (P2WPKH, P2WSH, P2TR)
/// - Correct witness program length
pub fn is_valid_bitcoin_address(address: &str) -> bool {
    use bitcoin::address::NetworkUnchecked;
    use bitcoin::Address;
    use std::str::FromStr;

    // Basic sanity checks
    if address.is_empty() {
        return false;
    }

    // Length check (mainnet: 26-35 chars, bech32: 42-62 chars, taproot: 62 chars)
    if address.len() < 26 || address.len() > 90 {
        return false;
    }

    // Try to parse as a Bitcoin address (network-unchecked)
    // This validates checksum and format but not network
    if let Ok(_addr) = Address::<NetworkUnchecked>::from_str(address) {
        return true;
    }

    false
}

/// Validate a Bitcoin address for a specific network
pub fn is_valid_bitcoin_address_for_network(address: &str, network: bitcoin::Network) -> bool {
    use bitcoin::address::NetworkUnchecked;
    use bitcoin::Address;
    use std::str::FromStr;

    if address.is_empty() || address.len() < 26 || address.len() > 90 {
        return false;
    }

    // Parse and validate network
    match Address::<NetworkUnchecked>::from_str(address) {
        Ok(addr) => addr.is_valid_for_network(network),
        Err(_) => false,
    }
}

/// Stratum server configuration
#[derive(Debug, Clone)]
pub struct StratumConfig {
    /// Listen address
    pub listen_addr: SocketAddr,
    /// Maximum connections
    pub max_connections: usize,
    /// Connection timeout (seconds)
    pub connection_timeout_secs: u64,
    /// Share difficulty (for vardiff)
    pub initial_difficulty: f64,
    /// Minimum difficulty
    pub min_difficulty: f64,
    /// Maximum difficulty
    pub max_difficulty: f64,
    /// Vardiff target time (seconds between shares)
    pub vardiff_target_secs: f64,
    /// Rate limiting: max shares per second per miner
    pub max_shares_per_second: u32,
    /// Rate limiting: burst allowance (shares that can be submitted in a burst)
    pub rate_limit_burst: u32,
    /// Ban duration for misbehaving miners (seconds)
    pub ban_duration_secs: u64,
    /// Invalid share threshold before ban
    pub invalid_share_threshold: u32,
}

impl Default for StratumConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:3333".parse().expect("valid socket address constant"),
            max_connections: 10000,
            connection_timeout_secs: 300,
            initial_difficulty: 1000.0,
            min_difficulty: 100.0,
            max_difficulty: 1_000_000.0,
            vardiff_target_secs: 10.0,
            max_shares_per_second: 10, // Max 10 shares per second
            rate_limit_burst: 20,       // Allow burst of 20 shares
            ban_duration_secs: 300,     // 5 minute ban
            invalid_share_threshold: 10, // Ban after 10 invalid shares
        }
    }
}

/// Stratum server events
#[derive(Debug, Clone)]
pub enum StratumEvent {
    /// Miner connected
    MinerConnected {
        miner_id: String,
        addr: SocketAddr,
    },
    /// Miner disconnected
    MinerDisconnected {
        miner_id: String,
    },
    /// Share submitted
    ShareSubmitted {
        miner_id: String,
        difficulty: f64,
        accepted: bool,
    },
    /// Block found by miner
    BlockFound {
        miner_id: String,
        block_hash: String,
    },
}

/// Connected miner state
#[derive(Debug)]
pub struct MinerConnection {
    /// Miner identifier (username)
    pub miner_id: String,
    /// Remote address
    pub addr: SocketAddr,
    /// Payout Bitcoin address (parsed from username)
    pub payout_address: String,
    /// Worker name (parsed from username)
    pub worker_name: String,
    /// Current difficulty
    pub difficulty: f64,
    /// Shares submitted
    pub shares_submitted: u64,
    /// Shares accepted
    pub shares_accepted: u64,
    /// Last share timestamp
    pub last_share_time: u64,
    /// Connection timestamp
    pub connected_at: u64,
    /// Is authorized
    pub authorized: bool,
    /// Subscribed
    pub subscribed: bool,
    /// Extra nonce 1 (unique per connection, used for coinbase construction)
    #[allow(dead_code)]
    pub extranonce1: String,
    /// Channel for sending notifications to this miner
    pub notify_tx: Option<mpsc::Sender<String>>,
    /// Invalid share count (for ban threshold)
    pub invalid_shares: u32,
}

/// Rate limiter using token bucket algorithm
pub struct RateLimiter {
    /// Configuration
    config: StratumConfig,
    /// Token buckets per miner (miner_id -> (tokens, last_refill_time))
    buckets: RwLock<HashMap<String, (f64, u64)>>,
    /// Banned IPs with expiry time
    banned_ips: RwLock<HashMap<std::net::IpAddr, u64>>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: StratumConfig) -> Self {
        Self {
            config,
            buckets: RwLock::new(HashMap::new()),
            banned_ips: RwLock::new(HashMap::new()),
        }
    }

    /// Check if a share submission is allowed (returns false if rate limited)
    pub fn check_share(&self, miner_id: &str) -> bool {
        let now = chrono::Utc::now().timestamp() as u64;
        let mut buckets = self.buckets.write();

        let (tokens, last_refill) = buckets
            .entry(miner_id.to_string())
            .or_insert((self.config.rate_limit_burst as f64, now));

        // Refill tokens based on elapsed time
        let elapsed_secs = (now - *last_refill) as f64;
        let new_tokens = *tokens + (elapsed_secs * self.config.max_shares_per_second as f64);
        *tokens = new_tokens.min(self.config.rate_limit_burst as f64);
        *last_refill = now;

        // Check if we have tokens available
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Check if an IP is banned
    pub fn is_banned(&self, ip: &std::net::IpAddr) -> bool {
        let now = chrono::Utc::now().timestamp() as u64;
        let banned = self.banned_ips.read();

        if let Some(&expiry) = banned.get(ip) {
            if now < expiry {
                return true;
            }
        }
        false
    }

    /// Ban an IP address
    pub fn ban_ip(&self, ip: std::net::IpAddr, reason: &str) {
        let now = chrono::Utc::now().timestamp() as u64;
        let expiry = now + self.config.ban_duration_secs;

        self.banned_ips.write().insert(ip, expiry);
        warn!(
            ip = %ip,
            reason = %reason,
            duration_secs = self.config.ban_duration_secs,
            "Banned IP"
        );
    }

    /// Unban an IP address
    pub fn unban_ip(&self, ip: &std::net::IpAddr) {
        self.banned_ips.write().remove(ip);
    }

    /// Clean up expired bans and stale bucket entries
    pub fn cleanup(&self) {
        let now = chrono::Utc::now().timestamp() as u64;

        // Remove expired bans
        self.banned_ips.write().retain(|_, expiry| *expiry > now);

        // Remove stale bucket entries (older than 1 hour)
        let one_hour_ago = now.saturating_sub(3600);
        self.buckets.write().retain(|_, (_, last_refill)| *last_refill > one_hour_ago);
    }

    /// Remove rate limit tracking for a miner
    pub fn remove_miner(&self, miner_id: &str) {
        self.buckets.write().remove(miner_id);
    }

    /// Get current banned IP count
    pub fn banned_count(&self) -> usize {
        self.banned_ips.read().len()
    }
}

/// Stratum server
pub struct StratumServer {
    /// Configuration
    config: StratumConfig,
    /// Round manager reference
    round_manager: Arc<RoundManager>,
    /// Connected miners
    miners: RwLock<HashMap<String, MinerConnection>>,
    /// Event sender
    event_tx: broadcast::Sender<StratumEvent>,
    /// Job notification sender
    job_tx: broadcast::Sender<JobNotification>,
    /// Running state
    running: RwLock<bool>,
    /// Next extranonce counter
    extranonce_counter: RwLock<u64>,
    /// Vardiff controller (optional)
    vardiff_controller: RwLock<Option<Arc<VardiffController>>>,
    /// Rate limiter
    rate_limiter: RateLimiter,
    /// Job cache for share verification
    job_cache: RwLock<HashMap<String, CachedJob>>,
}

/// Job notification for miners
#[derive(Debug, Clone)]
pub struct JobNotification {
    pub job_id: String,
    pub prev_hash: String,
    pub coinbase1: String,
    pub coinbase2: String,
    pub merkle_branches: Vec<String>,
    pub version: String,
    pub nbits: String,
    pub ntime: String,
    pub clean_jobs: bool,
}

/// Cached job data for share verification
///
/// Stores the job template data needed to reconstruct and verify
/// the block header hash from a miner's share submission.
#[derive(Debug, Clone)]
struct CachedJob {
    /// Previous block hash (32 bytes, little-endian hex)
    prev_hash: String,
    /// Coinbase transaction part 1 (hex)
    coinbase1: String,
    /// Coinbase transaction part 2 (hex)
    coinbase2: String,
    /// Merkle branches for computing merkle root
    merkle_branches: Vec<String>,
    /// Block version (4 bytes, little-endian hex)
    version: String,
    /// nBits (difficulty target, 4 bytes hex)
    nbits: String,
    /// Job creation timestamp
    created_at: u64,
}

impl CachedJob {
    fn from_notification(job: &JobNotification) -> Self {
        Self {
            prev_hash: job.prev_hash.clone(),
            coinbase1: job.coinbase1.clone(),
            coinbase2: job.coinbase2.clone(),
            merkle_branches: job.merkle_branches.clone(),
            version: job.version.clone(),
            nbits: job.nbits.clone(),
            created_at: chrono::Utc::now().timestamp() as u64,
        }
    }

    /// Verify a share submission by reconstructing the block header
    ///
    /// Returns the block header hash if valid, or an error description.
    fn verify_share(
        &self,
        extranonce1: &str,
        extranonce2: &str,
        ntime: &str,
        nonce: &str,
    ) -> Result<[u8; 32], String> {
        use sha2::{Digest, Sha256};

        // 1. Build complete coinbase transaction
        let coinbase_hex = format!("{}{}{}{}", self.coinbase1, extranonce1, extranonce2, self.coinbase2);
        let coinbase_bytes = hex::decode(&coinbase_hex)
            .map_err(|e| format!("Invalid coinbase hex: {}", e))?;

        // 2. Double SHA256 the coinbase to get coinbase hash
        let coinbase_hash = {
            let first = Sha256::digest(&coinbase_bytes);
            Sha256::digest(&first)
        };

        // 3. Compute merkle root from coinbase hash and merkle branches
        let mut current_hash: [u8; 32] = coinbase_hash.into();
        for branch in &self.merkle_branches {
            let branch_bytes = hex::decode(branch)
                .map_err(|e| format!("Invalid merkle branch: {}", e))?;
            if branch_bytes.len() != 32 {
                return Err("Invalid merkle branch length".to_string());
            }

            // Concatenate and double hash
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(&current_hash);
            combined.extend_from_slice(&branch_bytes);

            let first = Sha256::digest(&combined);
            let second = Sha256::digest(&first);
            current_hash = second.into();
        }

        // 4. Build 80-byte block header
        let mut header = [0u8; 80];

        // Version (4 bytes, little-endian)
        let version_bytes = hex::decode(&self.version)
            .map_err(|_| "Invalid version hex")?;
        if version_bytes.len() != 4 {
            return Err("Invalid version length".to_string());
        }
        header[0..4].copy_from_slice(&version_bytes);

        // Previous block hash (32 bytes)
        let prev_hash_bytes = hex::decode(&self.prev_hash)
            .map_err(|_| "Invalid prev_hash hex")?;
        if prev_hash_bytes.len() != 32 {
            return Err("Invalid prev_hash length".to_string());
        }
        header[4..36].copy_from_slice(&prev_hash_bytes);

        // Merkle root (32 bytes)
        header[36..68].copy_from_slice(&current_hash);

        // nTime (4 bytes, little-endian)
        let ntime_bytes = hex::decode(ntime)
            .map_err(|_| "Invalid ntime hex")?;
        if ntime_bytes.len() != 4 {
            return Err("Invalid ntime length".to_string());
        }
        header[68..72].copy_from_slice(&ntime_bytes);

        // nBits (4 bytes)
        let nbits_bytes = hex::decode(&self.nbits)
            .map_err(|_| "Invalid nbits hex")?;
        if nbits_bytes.len() != 4 {
            return Err("Invalid nbits length".to_string());
        }
        header[72..76].copy_from_slice(&nbits_bytes);

        // Nonce (4 bytes, little-endian)
        let nonce_bytes = hex::decode(nonce)
            .map_err(|_| "Invalid nonce hex")?;
        if nonce_bytes.len() != 4 {
            return Err("Invalid nonce length".to_string());
        }
        header[76..80].copy_from_slice(&nonce_bytes);

        // 5. Double SHA256 the header
        let first_hash = Sha256::digest(&header);
        let block_hash: [u8; 32] = Sha256::digest(&first_hash).into();

        Ok(block_hash)
    }
}

/// Maximum number of jobs to cache
const MAX_CACHED_JOBS: usize = 100;
/// Maximum age of cached jobs in seconds
const MAX_JOB_AGE_SECS: u64 = 600; // 10 minutes

impl StratumServer {
    /// Create a new Stratum server
    pub fn new(config: StratumConfig, round_manager: Arc<RoundManager>) -> Self {
        let (event_tx, _) = broadcast::channel(1000);
        let (job_tx, _) = broadcast::channel(100);
        let rate_limiter = RateLimiter::new(config.clone());

        Self {
            config,
            round_manager,
            miners: RwLock::new(HashMap::new()),
            event_tx,
            job_tx,
            running: RwLock::new(false),
            extranonce_counter: RwLock::new(0),
            vardiff_controller: RwLock::new(None),
            rate_limiter,
            job_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Cache a job for share verification
    fn cache_job(&self, job: &JobNotification) {
        let mut cache = self.job_cache.write();

        // Add new job
        cache.insert(job.job_id.clone(), CachedJob::from_notification(job));

        // Cleanup old jobs
        let now = chrono::Utc::now().timestamp() as u64;
        cache.retain(|_, cached| now - cached.created_at < MAX_JOB_AGE_SECS);

        // Enforce size limit
        while cache.len() > MAX_CACHED_JOBS {
            if let Some(oldest_key) = cache.iter()
                .min_by_key(|(_, v)| v.created_at)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest_key);
            } else {
                break;
            }
        }
    }

    /// Get a cached job for verification
    fn get_cached_job(&self, job_id: &str) -> Option<CachedJob> {
        self.job_cache.read().get(job_id).cloned()
    }

    /// Set the vardiff controller
    pub fn set_vardiff_controller(&self, controller: Arc<VardiffController>) {
        *self.vardiff_controller.write() = Some(controller);
    }

    /// Subscribe to stratum events
    pub fn subscribe_events(&self) -> broadcast::Receiver<StratumEvent> {
        self.event_tx.subscribe()
    }

    /// Subscribe to job notifications
    pub fn subscribe_jobs(&self) -> broadcast::Receiver<JobNotification> {
        self.job_tx.subscribe()
    }

    /// Start the server
    pub async fn start(self: Arc<Self>) -> anyhow::Result<()> {
        *self.running.write() = true;

        let listener = TcpListener::bind(self.config.listen_addr).await?;
        info!(
            addr = %self.config.listen_addr,
            "Stratum server listening"
        );

        while *self.running.read() {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    // Check if IP is banned
                    if self.rate_limiter.is_banned(&addr.ip()) {
                        debug!(addr = %addr, "Connection rejected: IP banned");
                        continue;
                    }

                    let miners_count = self.miners.read().len();
                    if miners_count >= self.config.max_connections {
                        warn!(addr = %addr, "Connection rejected: max connections reached");
                        continue;
                    }

                    let server = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_connection(stream, addr).await {
                            debug!(addr = %addr, error = %e, "Connection error");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "Accept error");
                }
            }
        }

        Ok(())
    }

    /// Stop the server
    pub fn stop(&self) {
        *self.running.write() = false;
    }

    /// Handle a single miner connection
    async fn handle_connection(
        self: Arc<Self>,
        mut stream: TcpStream,
        addr: SocketAddr,
    ) -> anyhow::Result<()> {
        debug!(addr = %addr, "New connection");

        // Generate unique extranonce
        let extranonce1 = self.generate_extranonce();
        let _session_id = format!("{}_{}", addr, chrono::Utc::now().timestamp());

        let mut miner_id: Option<String> = None;
        let mut buffer = vec![0u8; 4096];
        let mut partial_line = String::new();

        loop {
            let n = match tokio::time::timeout(
                std::time::Duration::from_secs(self.config.connection_timeout_secs),
                stream.read(&mut buffer),
            )
            .await
            {
                Ok(Ok(0)) => break, // Connection closed
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    debug!(addr = %addr, error = %e, "Read error");
                    break;
                }
                Err(_) => {
                    debug!(addr = %addr, "Connection timeout");
                    break;
                }
            };

            // Parse JSON-RPC messages (newline delimited)
            partial_line.push_str(&String::from_utf8_lossy(&buffer[..n]));

            while let Some(pos) = partial_line.find('\n') {
                let line = partial_line[..pos].trim().to_string();
                partial_line = partial_line[pos + 1..].to_string();

                if line.is_empty() {
                    continue;
                }

                match self
                    .handle_message(&line, &mut miner_id, &addr, &extranonce1, &mut stream)
                    .await
                {
                    Ok(response) => {
                        if let Some(resp) = response {
                            let msg = format!("{}\n", resp);
                            if stream.write_all(msg.as_bytes()).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        debug!(addr = %addr, error = %e, "Message handling error");
                    }
                }
            }
        }

        // Cleanup on disconnect
        if let Some(ref id) = miner_id {
            self.miners.write().remove(id);

            // Remove vardiff tracking for disconnected miner
            if let Some(ref controller) = *self.vardiff_controller.read() {
                controller.remove_miner(id);
            }

            // Remove rate limiter tracking
            self.rate_limiter.remove_miner(id);

            let _ = self.event_tx.send(StratumEvent::MinerDisconnected {
                miner_id: id.clone(),
            });
            debug!(miner = %id, "Miner disconnected");
        }

        Ok(())
    }

    /// Handle a single JSON-RPC message
    async fn handle_message(
        &self,
        line: &str,
        miner_id: &mut Option<String>,
        addr: &SocketAddr,
        extranonce1: &str,
        stream: &mut TcpStream,
    ) -> anyhow::Result<Option<String>> {
        let request: serde_json::Value = serde_json::from_str(line)?;

        let id = request.get("id").cloned();
        let method = request
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(serde_json::json!([]));

        match method {
            "mining.subscribe" => {
                let result = serde_json::json!([
                    [["mining.notify", extranonce1], ["mining.set_difficulty", extranonce1]],
                    extranonce1,
                    4  // extranonce2 size
                ]);

                Ok(Some(serde_json::json!({
                    "id": id,
                    "result": result,
                    "error": null
                }).to_string()))
            }

            "mining.authorize" => {
                let username = params
                    .get(0)
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let _password = params.get(1).and_then(|v| v.as_str()).unwrap_or("");

                // Parse username as "address.worker" format (industry standard)
                let (payout_address, worker_name) = parse_miner_username(username);

                // Validate the payout address
                if !is_valid_bitcoin_address(&payout_address) {
                    warn!(
                        username = %username,
                        address = %payout_address,
                        addr = %addr,
                        "Invalid payout address in miner username"
                    );
                    return Ok(Some(serde_json::json!({
                        "id": id,
                        "result": false,
                        "error": [20, "Invalid payout address. Use format: <btc_address.worker>", null]
                    }).to_string()));
                }

                // Register miner with unique ID (address + worker + connection addr)
                let id_str = format!("{}.{}@{}", payout_address, worker_name, addr);
                *miner_id = Some(id_str.clone());

                // Create notification channel for this miner
                let (notify_tx, _notify_rx) = mpsc::channel::<String>(100);

                let conn = MinerConnection {
                    miner_id: id_str.clone(),
                    addr: *addr,
                    payout_address: payout_address.clone(),
                    worker_name: worker_name.clone(),
                    difficulty: self.config.initial_difficulty,
                    shares_submitted: 0,
                    shares_accepted: 0,
                    last_share_time: 0,
                    connected_at: chrono::Utc::now().timestamp() as u64,
                    authorized: true,
                    subscribed: true,
                    extranonce1: extranonce1.to_string(),
                    notify_tx: Some(notify_tx),
                    invalid_shares: 0,
                };

                self.miners.write().insert(id_str.clone(), conn);

                let _ = self.event_tx.send(StratumEvent::MinerConnected {
                    miner_id: id_str.clone(),
                    addr: *addr,
                });

                info!(
                    address = %payout_address,
                    worker = %worker_name,
                    addr = %addr,
                    "Miner authorized"
                );

                // Send set_difficulty
                let diff_msg = serde_json::json!({
                    "id": null,
                    "method": "mining.set_difficulty",
                    "params": [self.config.initial_difficulty]
                });
                let msg = format!("{}\n", diff_msg);
                let _ = stream.write_all(msg.as_bytes()).await;

                Ok(Some(serde_json::json!({
                    "id": id,
                    "result": true,
                    "error": null
                }).to_string()))
            }

            "mining.submit" => {
                let username = params.get(0).and_then(|v| v.as_str()).unwrap_or("");
                let job_id = params.get(1).and_then(|v| v.as_str()).unwrap_or("");
                let extranonce2 = params.get(2).and_then(|v| v.as_str()).unwrap_or("");
                let ntime_hex = params.get(3).and_then(|v| v.as_str()).unwrap_or("");
                let nonce = params.get(4).and_then(|v| v.as_str()).unwrap_or("");

                // Parse and validate ntime
                let ntime_parsed = u32::from_str_radix(ntime_hex, 16).unwrap_or(0);
                let current_time = chrono::Utc::now().timestamp() as u32;

                // Validate timestamp bounds
                // MAX_FUTURE_TIME_SECS: shares cannot be more than 2 minutes in the future
                const MAX_FUTURE_TIME_SECS: u32 = 120;
                // MAX_PAST_TIME_SECS: shares cannot be more than 10 minutes in the past
                const MAX_PAST_TIME_SECS: u32 = 600;
                // GENESIS_TIME: Bitcoin genesis block timestamp
                const GENESIS_TIME: u32 = 1231006505;

                if ntime_parsed > current_time + MAX_FUTURE_TIME_SECS {
                    debug!(miner = %username, ntime = ntime_parsed, current = current_time, "Share ntime too far in future");
                    return Ok(Some(serde_json::json!({
                        "id": id,
                        "result": false,
                        "error": [20, "ntime too far in future", null]
                    }).to_string()));
                }

                if ntime_parsed < current_time.saturating_sub(MAX_PAST_TIME_SECS) {
                    debug!(miner = %username, ntime = ntime_parsed, current = current_time, "Share ntime too old");
                    return Ok(Some(serde_json::json!({
                        "id": id,
                        "result": false,
                        "error": [20, "ntime too old", null]
                    }).to_string()));
                }

                if ntime_parsed < GENESIS_TIME {
                    debug!(miner = %username, ntime = ntime_parsed, "Share ntime before Bitcoin genesis");
                    return Ok(Some(serde_json::json!({
                        "id": id,
                        "result": false,
                        "error": [20, "invalid ntime", null]
                    }).to_string()));
                }

                let miner_key = miner_id.clone().unwrap_or_default();

                // Rate limiting check
                if !self.rate_limiter.check_share(&miner_key) {
                    debug!(miner = %username, "Share rate limited");
                    return Ok(Some(serde_json::json!({
                        "id": id,
                        "result": false,
                        "error": [25, "rate limited", null]
                    }).to_string()));
                }

                // Get cached job for verification
                let cached_job = match self.get_cached_job(job_id) {
                    Some(job) => job,
                    None => {
                        debug!(miner = %username, job_id = %job_id, "Unknown or expired job");
                        return Ok(Some(serde_json::json!({
                            "id": id,
                            "result": false,
                            "error": [21, "job not found", null]
                        }).to_string()));
                    }
                };

                // Get miner difficulty
                let difficulty = self
                    .miners
                    .read()
                    .get(&miner_key)
                    .map(|m| m.difficulty)
                    .unwrap_or(self.config.initial_difficulty);

                // Verify the share by reconstructing and hashing the block header
                // This is CRITICAL for security - we must verify the hash was actually
                // computed from the correct block header, not just trust the miner
                let share_hash = match cached_job.verify_share(extranonce1, extranonce2, ntime_hex, nonce) {
                    Ok(hash) => hash,
                    Err(e) => {
                        warn!(miner = %username, error = %e, "Share verification failed");
                        // Track invalid shares for potential ban
                        if let Some(conn) = self.miners.write().get_mut(&miner_key) {
                            conn.invalid_shares += 1;
                            if conn.invalid_shares >= self.config.invalid_share_threshold {
                                self.rate_limiter.ban_ip(conn.addr.ip(), "too many invalid shares");
                                warn!(miner = %username, addr = %conn.addr, "Miner banned for too many invalid shares");
                            }
                        }
                        return Ok(Some(serde_json::json!({
                            "id": id,
                            "result": false,
                            "error": [20, format!("invalid share: {}", e), null]
                        }).to_string()));
                    }
                };

                // Submit to round manager
                let result = self
                    .round_manager
                    .submit_share(&miner_key, difficulty, share_hash);

                let accepted = result.is_ok();

                // Update miner stats
                if let Some(conn) = self.miners.write().get_mut(&miner_key) {
                    conn.shares_submitted += 1;
                    conn.last_share_time = chrono::Utc::now().timestamp() as u64;
                    if accepted {
                        conn.shares_accepted += 1;
                    }
                }

                // Record share for vardiff tracking
                if accepted {
                    if let Some(ref controller) = *self.vardiff_controller.read() {
                        controller.record_share(&miner_key, difficulty);
                    }
                }

                let _ = self.event_tx.send(StratumEvent::ShareSubmitted {
                    miner_id: miner_key.clone(),
                    difficulty,
                    accepted,
                });

                if let Ok(ref res) = result {
                    if res.is_block {
                        let _ = self.event_tx.send(StratumEvent::BlockFound {
                            miner_id: miner_key.clone(),
                            block_hash: hex::encode(&res.share_hash),
                        });
                    }
                }

                match result {
                    Ok(_) => {
                        debug!(miner = %username, "Share accepted");
                        Ok(Some(serde_json::json!({
                            "id": id,
                            "result": true,
                            "error": null
                        }).to_string()))
                    }
                    Err(e) => {
                        debug!(miner = %username, error = %e, "Share rejected");

                        // Track invalid shares and ban if threshold exceeded
                        let should_ban = {
                            let mut miners = self.miners.write();
                            if let Some(conn) = miners.get_mut(&miner_key) {
                                conn.invalid_shares += 1;
                                conn.invalid_shares >= self.config.invalid_share_threshold
                            } else {
                                false
                            }
                        };

                        if should_ban {
                            self.rate_limiter.ban_ip(addr.ip(), "too many invalid shares");
                            return Ok(Some(serde_json::json!({
                                "id": id,
                                "result": false,
                                "error": [24, "banned: too many invalid shares", null]
                            }).to_string()));
                        }

                        let error_msg = match e {
                            ShareError::DifficultyTooLow { .. } => "low difficulty",
                            ShareError::DuplicateShare => "duplicate",
                            ShareError::NoActiveRound => "no active round",
                            ShareError::InvalidShareHash => "invalid hash",
                            _ => "unknown error",
                        };
                        Ok(Some(serde_json::json!({
                            "id": id,
                            "result": false,
                            "error": [20, error_msg, null]
                        }).to_string()))
                    }
                }
            }

            "mining.extranonce.subscribe" => {
                Ok(Some(serde_json::json!({
                    "id": id,
                    "result": true,
                    "error": null
                }).to_string()))
            }

            _ => {
                debug!(method = %method, "Unknown stratum method");
                Ok(Some(serde_json::json!({
                    "id": id,
                    "result": null,
                    "error": [20, "unknown method", null]
                }).to_string()))
            }
        }
    }

    /// Generate a unique extranonce1
    fn generate_extranonce(&self) -> String {
        let mut counter = self.extranonce_counter.write();
        *counter += 1;
        format!("{:08x}", *counter)
    }

    /// Notify all miners of a new job
    ///
    /// Broadcasts mining.notify to all authorized miners with active connections.
    pub async fn notify_new_job(&self, job: JobNotification) {
        // Cache the job for share verification
        self.cache_job(&job);

        let notification = serde_json::json!({
            "id": null,
            "method": "mining.notify",
            "params": [
                job.job_id,
                job.prev_hash,
                job.coinbase1,
                job.coinbase2,
                job.merkle_branches,
                job.version,
                job.nbits,
                job.ntime,
                job.clean_jobs
            ]
        });

        let msg = notification.to_string();
        let mut sent_count = 0;
        let mut failed_count = 0;

        // Send to all connected miners via their notification channels
        {
            let miners = self.miners.read();
            for (miner_id, conn) in miners.iter() {
                if conn.authorized && conn.subscribed {
                    if let Some(ref tx) = conn.notify_tx {
                        match tx.try_send(msg.clone()) {
                            Ok(_) => sent_count += 1,
                            Err(_) => {
                                debug!(miner = %miner_id, "Notify channel full or closed");
                                failed_count += 1;
                            }
                        }
                    }
                }
            }
        }

        // Broadcast via job channel for external subscribers
        let _ = self.job_tx.send(job);

        debug!(
            job_id = %notification["params"][0],
            sent = sent_count,
            failed = failed_count,
            "Broadcasted new job to miners"
        );
    }

    /// Get current miner count
    pub fn miner_count(&self) -> usize {
        self.miners.read().len()
    }

    /// Get miner statistics
    pub fn miner_stats(&self) -> Vec<MinerStats> {
        self.miners
            .read()
            .values()
            .map(|m| MinerStats {
                miner_id: m.miner_id.clone(),
                addr: m.addr.to_string(),
                difficulty: m.difficulty,
                shares_submitted: m.shares_submitted,
                shares_accepted: m.shares_accepted,
                connected_secs: chrono::Utc::now().timestamp() as u64 - m.connected_at,
            })
            .collect()
    }

    /// Update difficulty for a specific miner (vardiff)
    pub fn update_miner_difficulty(&self, miner_id: &str, new_difficulty: f64) {
        if let Some(conn) = self.miners.write().get_mut(miner_id) {
            conn.difficulty = new_difficulty.clamp(
                self.config.min_difficulty,
                self.config.max_difficulty,
            );
        }
    }

    /// Get the number of currently banned IPs
    pub fn banned_ip_count(&self) -> usize {
        self.rate_limiter.banned_count()
    }

    /// Unban an IP address
    pub fn unban_ip(&self, ip: std::net::IpAddr) {
        self.rate_limiter.unban_ip(&ip);
    }

    /// Cleanup expired bans and stale rate limiter data
    pub fn cleanup_rate_limiter(&self) {
        self.rate_limiter.cleanup();
    }

    /// Run periodic cleanup task for rate limiter
    pub async fn run_rate_limiter_cleanup(self: Arc<Self>) {
        let cleanup_interval = std::time::Duration::from_secs(60);

        info!("Starting rate limiter cleanup task");

        loop {
            tokio::time::sleep(cleanup_interval).await;
            self.cleanup_rate_limiter();
            debug!(banned_ips = self.banned_ip_count(), "Rate limiter cleanup completed");
        }
    }
}

/// Miner statistics
#[derive(Debug, Clone)]
pub struct MinerStats {
    pub miner_id: String,
    pub addr: String,
    pub difficulty: f64,
    pub shares_submitted: u64,
    pub shares_accepted: u64,
    pub connected_secs: u64,
}

/// Variable difficulty controller
///
/// Adjusts miner difficulty to achieve target share rate.
/// Uses exponential moving average to smooth hashrate estimates.
pub struct VardiffController {
    /// Configuration
    config: StratumConfig,
    /// Last difficulty adjustment time per miner
    last_adjust: RwLock<HashMap<String, u64>>,
    /// Share count since last adjustment per miner
    shares_since_adjust: RwLock<HashMap<String, u64>>,
    /// EMA hashrate per miner (hashes per second)
    ema_hashrate: RwLock<HashMap<String, f64>>,
}

impl VardiffController {
    /// Create a new vardiff controller
    pub fn new(config: StratumConfig) -> Self {
        Self {
            config,
            last_adjust: RwLock::new(HashMap::new()),
            shares_since_adjust: RwLock::new(HashMap::new()),
            ema_hashrate: RwLock::new(HashMap::new()),
        }
    }

    /// Record a share submission from a miner
    pub fn record_share(&self, miner_id: &str, difficulty: f64) {
        let now = chrono::Utc::now().timestamp() as u64;

        // Initialize if first share
        {
            let mut last = self.last_adjust.write();
            last.entry(miner_id.to_string()).or_insert(now);
        }

        // Increment share count
        {
            let mut shares = self.shares_since_adjust.write();
            *shares.entry(miner_id.to_string()).or_insert(0) += 1;
        }

        // Update hashrate estimate (shares * difficulty = total hashes, approximately)
        // This is a rough estimate; real hashrate would be shares * difficulty / time
        let _ = difficulty; // Used for more accurate hashrate estimation if needed
    }

    /// Calculate new difficulty for a miner based on their share rate
    ///
    /// Returns Some(new_difficulty) if an adjustment is needed, None otherwise.
    pub fn calculate_adjustment(&self, miner_id: &str, current_difficulty: f64) -> Option<f64> {
        let now = chrono::Utc::now().timestamp() as u64;

        let last_time = *self.last_adjust.read().get(miner_id)?;
        let elapsed_secs = (now - last_time) as f64;

        // Only adjust after minimum observation window (30 seconds)
        if elapsed_secs < 30.0 {
            return None;
        }

        let shares = *self.shares_since_adjust.read().get(miner_id)?;

        // Need at least 3 shares to make an adjustment
        if shares < 3 {
            // If no shares in 2x target time, reduce difficulty
            if elapsed_secs > self.config.vardiff_target_secs * 2.0 * 3.0 {
                let new_diff = (current_difficulty * 0.5)
                    .max(self.config.min_difficulty);
                return Some(new_diff);
            }
            return None;
        }

        // Calculate actual time per share
        let actual_time_per_share = elapsed_secs / shares as f64;
        let target_time = self.config.vardiff_target_secs;

        // Calculate adjustment ratio
        // If shares come too fast (actual < target), increase difficulty
        // If shares come too slow (actual > target), decrease difficulty
        let ratio = actual_time_per_share / target_time;

        // Only adjust if more than 20% off target
        if ratio > 0.8 && ratio < 1.25 {
            return None;
        }

        // Calculate new difficulty
        // Use dampened adjustment (square root) to avoid oscillation
        let adjustment_factor = if ratio < 1.0 {
            // Shares too fast, increase difficulty
            (1.0 / ratio).sqrt()
        } else {
            // Shares too slow, decrease difficulty
            (1.0 / ratio).sqrt()
        };

        let new_difficulty = (current_difficulty * adjustment_factor)
            .clamp(self.config.min_difficulty, self.config.max_difficulty);

        // Only return if change is significant (>5%)
        let change_ratio = (new_difficulty - current_difficulty).abs() / current_difficulty;
        if change_ratio < 0.05 {
            return None;
        }

        Some(new_difficulty)
    }

    /// Reset tracking for a miner after difficulty adjustment
    pub fn reset_tracking(&self, miner_id: &str) {
        let now = chrono::Utc::now().timestamp() as u64;

        self.last_adjust.write().insert(miner_id.to_string(), now);
        self.shares_since_adjust.write().insert(miner_id.to_string(), 0);
    }

    /// Remove tracking for a disconnected miner
    pub fn remove_miner(&self, miner_id: &str) {
        self.last_adjust.write().remove(miner_id);
        self.shares_since_adjust.write().remove(miner_id);
        self.ema_hashrate.write().remove(miner_id);
    }
}

impl StratumServer {
    /// Run vardiff adjustment loop
    ///
    /// Should be spawned as a background task. Periodically checks all miners
    /// and adjusts their difficulty based on share submission rate.
    pub async fn run_vardiff_loop(self: Arc<Self>, controller: Arc<VardiffController>) {
        let check_interval = std::time::Duration::from_secs(15);

        info!("Starting vardiff controller");

        loop {
            tokio::time::sleep(check_interval).await;

            // Collect miners and their difficulties
            let miners: Vec<(String, f64)> = {
                self.miners.read()
                    .iter()
                    .filter(|(_, conn)| conn.authorized)
                    .map(|(id, conn)| (id.clone(), conn.difficulty))
                    .collect()
            };

            for (miner_id, current_difficulty) in miners {
                if let Some(new_difficulty) = controller.calculate_adjustment(&miner_id, current_difficulty) {
                    // Update miner difficulty
                    self.update_miner_difficulty(&miner_id, new_difficulty);

                    // Reset vardiff tracking
                    controller.reset_tracking(&miner_id);

                    // Send set_difficulty message to miner
                    if let Some(conn) = self.miners.read().get(&miner_id) {
                        if let Some(ref tx) = conn.notify_tx {
                            let msg = serde_json::json!({
                                "id": null,
                                "method": "mining.set_difficulty",
                                "params": [new_difficulty]
                            });
                            let _ = tx.try_send(msg.to_string());
                        }
                    }

                    debug!(
                        miner = %miner_id,
                        old_diff = current_difficulty,
                        new_diff = new_difficulty,
                        "Adjusted miner difficulty"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stratum_config_default() {
        let config = StratumConfig::default();
        assert_eq!(config.listen_addr.port(), 3333);
        assert_eq!(config.initial_difficulty, 1000.0);
    }

    #[test]
    fn test_parse_miner_username_with_worker() {
        let (addr, worker) = parse_miner_username("bc1qxyz123abc.rig1");
        assert_eq!(addr, "bc1qxyz123abc");
        assert_eq!(worker, "rig1");
    }

    #[test]
    fn test_parse_miner_username_no_worker() {
        let (addr, worker) = parse_miner_username("bc1qxyz123abc");
        assert_eq!(addr, "bc1qxyz123abc");
        assert_eq!(worker, "default");
    }

    #[test]
    fn test_parse_miner_username_multiple_dots() {
        // Should split at last dot (address formats may contain dots)
        let (addr, worker) = parse_miner_username("some.weird.address.format.worker1");
        assert_eq!(addr, "some.weird.address.format");
        assert_eq!(worker, "worker1");
    }

    #[test]
    fn test_parse_miner_username_empty_worker() {
        // Trailing dot should give "default" worker
        let (addr, worker) = parse_miner_username("bc1qxyz123abc.");
        assert_eq!(addr, "bc1qxyz123abc");
        assert_eq!(worker, "default");
    }

    #[test]
    fn test_parse_miner_username_only_dot() {
        // Edge case: just a dot
        let (addr, worker) = parse_miner_username(".");
        assert_eq!(addr, "");
        assert_eq!(worker, "default");
    }

    #[test]
    fn test_is_valid_bitcoin_address_legacy_mainnet() {
        // Legacy P2PKH (starts with 1)
        assert!(is_valid_bitcoin_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));
        // Legacy P2SH (starts with 3)
        assert!(is_valid_bitcoin_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"));
    }

    #[test]
    fn test_is_valid_bitcoin_address_bech32_mainnet() {
        // Bech32 P2WPKH (bc1q)
        assert!(is_valid_bitcoin_address("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"));
        // Bech32m P2TR (bc1p)
        assert!(is_valid_bitcoin_address("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"));
    }

    #[test]
    fn test_is_valid_bitcoin_address_testnet() {
        // Testnet bech32
        assert!(is_valid_bitcoin_address("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"));
        // Testnet legacy
        assert!(is_valid_bitcoin_address("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"));
    }

    #[test]
    fn test_is_valid_bitcoin_address_invalid() {
        // Empty
        assert!(!is_valid_bitcoin_address(""));
        // Too short
        assert!(!is_valid_bitcoin_address("bc1q"));
        // Invalid prefix (doesn't start with any valid prefix)
        assert!(!is_valid_bitcoin_address("xyz123456789012345678901234567890"));
        // Just garbage (avoid starting with n/m which are testnet prefixes)
        assert!(!is_valid_bitcoin_address("invalid_bitcoin_address_here!!!!!"));
    }
}
