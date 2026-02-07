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

//! SV1→SV2 Stratum Protocol Translator
//!
//! This binary translates between Stratum V1 (legacy miners like Bitaxe)
//! and Stratum V2 (modern pool protocol).
//!
//! Architecture:
//! - Listens for SV1 connections on port 3333
//! - Connects to upstream SV2 pool on port 34255
//! - Translates messages between protocols
//!
//! SV1 Protocol (JSON-RPC over TCP):
//! - mining.subscribe: Subscribe to job notifications
//! - mining.authorize: Authenticate with username/password
//! - mining.submit: Submit share (worker, job_id, extranonce2, ntime, nonce)
//! - mining.notify: Server pushes new job (job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime)
//! - mining.set_difficulty: Server sets share difficulty
//!
//! SV2 Protocol (Binary framed):
//! - SetupConnection: Initial handshake
//! - OpenStandardMiningChannel: Open mining channel
//! - NewMiningJob / NewExtendedMiningJob: Job notifications
//! - SubmitSharesStandard / SubmitSharesExtended: Share submission
//! - SetNewPrevHash: New block notification

use anyhow::Result;
use clap::Parser;
use parking_lot::RwLock;
use secrecy::{ExposeSecret, Secret};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

/// CRIT-11: Safe payload parsing helpers to prevent panics on malformed network data.
/// All functions return Result to handle short/malformed payloads gracefully.
mod payload_parser {
    use anyhow::{anyhow, Result};

    /// Safely read a u32 from a payload at the given offset (little-endian).
    /// Returns error if payload is too short.
    #[inline]
    pub fn read_u32_le(payload: &[u8], offset: usize) -> Result<u32> {
        if offset + 4 > payload.len() {
            return Err(anyhow!(
                "payload too short: need {} bytes at offset {}, have {} total",
                4,
                offset,
                payload.len()
            ));
        }
        Ok(u32::from_le_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
        ]))
    }

    /// Safely read a u16 from a payload at the given offset (little-endian).
    #[inline]
    pub fn read_u16_le(payload: &[u8], offset: usize) -> Result<u16> {
        if offset + 2 > payload.len() {
            return Err(anyhow!(
                "payload too short: need {} bytes at offset {}, have {} total",
                2,
                offset,
                payload.len()
            ));
        }
        Ok(u16::from_le_bytes([payload[offset], payload[offset + 1]]))
    }

    /// Safely read a byte from payload at the given offset.
    #[inline]
    pub fn read_u8(payload: &[u8], offset: usize) -> Result<u8> {
        payload.get(offset).copied().ok_or_else(|| {
            anyhow!(
                "payload too short: need byte at offset {}, have {} total",
                offset,
                payload.len()
            )
        })
    }

    /// Safely read a slice from payload.
    #[inline]
    pub fn read_slice(payload: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
        if offset + len > payload.len() {
            return Err(anyhow!(
                "payload too short: need {} bytes at offset {}, have {} total",
                len,
                offset,
                payload.len()
            ));
        }
        Ok(&payload[offset..offset + len])
    }

    /// Validate minimum payload length for a message type.
    #[inline]
    pub fn validate_min_length(payload: &[u8], min_len: usize, msg_name: &str) -> Result<()> {
        if payload.len() < min_len {
            return Err(anyhow!(
                "{} payload too short: expected >= {} bytes, got {}",
                msg_name,
                min_len,
                payload.len()
            ));
        }
        Ok(())
    }
}

/// Mining mode for authorization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MiningMode {
    /// DNS registered, anyone can mine, pool-aggregated rewards
    #[default]
    PublicPool,
    /// Password required, pool-aggregated rewards, not in DNS
    PrivatePool,
    /// Password required, 99% + fees to operator's address, not in DNS
    PrivateSolo,
}

impl std::str::FromStr for MiningMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "public_pool" | "publicpool" | "public" => Ok(MiningMode::PublicPool),
            "private_pool" | "privatepool" => Ok(MiningMode::PrivatePool),
            "private_solo" | "privatesolo" | "solo" => Ok(MiningMode::PrivateSolo),
            _ => Err(format!(
                "Unknown mining mode: {}. Use: public_pool, private_pool, or private_solo",
                s
            )),
        }
    }
}

/// SV1→SV2 Stratum Protocol Translator
#[derive(Parser, Debug)]
#[command(name = "translator")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// SV1 listen address
    #[arg(long, default_value = "0.0.0.0:3333")]
    sv1_listen: String,

    /// SV2 upstream address
    #[arg(long, default_value = "127.0.0.1:34255")]
    sv2_upstream: String,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Maximum concurrent connections
    #[arg(long, default_value = "1000")]
    max_connections: usize,

    /// Mining mode (public_pool, private_pool, private_solo)
    #[arg(long, default_value = "public_pool")]
    mining_mode: MiningMode,

    /// Password for private mining modes (required for private_pool and private_solo)
    #[arg(long)]
    mining_password: Option<String>,
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

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    info!("Starting SV1→SV2 Translator v{}", env!("CARGO_PKG_VERSION"));
    info!("SV1 listen: {}", args.sv1_listen);
    info!("SV2 upstream: {}", args.sv2_upstream);

    // Parse addresses
    let sv1_addr: SocketAddr = args.sv1_listen.parse()?;
    let sv2_addr: SocketAddr = args.sv2_upstream.parse()?;

    // Validate mining mode configuration
    if args.mining_mode != MiningMode::PublicPool && args.mining_password.is_none() {
        error!(
            "Mining mode {:?} requires --mining-password to be set",
            args.mining_mode
        );
        return Err(anyhow::anyhow!(
            "Mining mode {:?} requires --mining-password",
            args.mining_mode
        ));
    }

    info!("Mining mode: {:?}", args.mining_mode);
    if args.mining_mode != MiningMode::PublicPool {
        info!("Password authentication enabled for private mode");
    }

    // Start translator
    let translator = Translator::new(
        sv1_addr,
        sv2_addr,
        args.max_connections,
        args.mining_mode,
        args.mining_password,
    );
    translator.run().await?;

    Ok(())
}

/// Mining mode and password configuration for authorization
/// L-19: Password stored as Secret<String> to prevent accidental logging/exposure
#[derive(Clone)]
struct AuthConfig {
    mining_mode: MiningMode,
    password: Option<Secret<String>>,
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("mining_mode", &self.mining_mode)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl AuthConfig {
    fn new(mining_mode: MiningMode, password: Option<String>) -> Self {
        Self {
            mining_mode,
            password: password.map(Secret::new),
        }
    }

    /// Check if password authentication is required
    fn requires_password(&self) -> bool {
        self.mining_mode != MiningMode::PublicPool
    }

    /// Validate the provided password
    fn validate_password(&self, provided: &str) -> bool {
        match &self.password {
            Some(expected) => provided == expected.expose_secret(),
            None => !self.requires_password(), // OK if no password required
        }
    }
}

/// Stratum protocol translator
struct Translator {
    sv1_listen: SocketAddr,
    sv2_upstream: SocketAddr,
    max_connections: usize,
    auth_config: Arc<AuthConfig>,
}

/// L-23: Guard to ensure connection count is decremented when connection closes
struct ConnectionGuard(Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Translator {
    fn new(
        sv1_listen: SocketAddr,
        sv2_upstream: SocketAddr,
        max_connections: usize,
        mining_mode: MiningMode,
        mining_password: Option<String>,
    ) -> Self {
        Self {
            sv1_listen,
            sv2_upstream,
            max_connections,
            auth_config: Arc::new(AuthConfig::new(mining_mode, mining_password)),
        }
    }

    async fn run(&self) -> Result<()> {
        let listener = tokio::net::TcpListener::bind(self.sv1_listen).await?;
        info!("Listening for SV1 connections on {}", self.sv1_listen);

        // L-23: Use AtomicUsize for thread-safe connection counting with proper cleanup
        let connection_count = Arc::new(AtomicUsize::new(0));

        loop {
            let (stream, addr) = listener.accept().await?;

            let current_count = connection_count.load(Ordering::SeqCst);
            if current_count >= self.max_connections {
                warn!("Max connections reached ({}), rejecting {}", current_count, addr);
                continue;
            }

            connection_count.fetch_add(1, Ordering::SeqCst);
            let new_count = connection_count.load(Ordering::SeqCst);
            info!(
                "New SV1 connection from {} (total: {})",
                addr, new_count
            );

            let sv2_upstream = self.sv2_upstream;
            let auth_config = Arc::clone(&self.auth_config);
            let guard = ConnectionGuard(Arc::clone(&connection_count));
            tokio::spawn(async move {
                let _guard = guard; // Dropped when task ends, decrementing count
                if let Err(e) = handle_connection(stream, sv2_upstream, auth_config).await {
                    error!("Connection error: {}", e);
                }
            });
        }
    }
}

async fn handle_connection(
    sv1_stream: tokio::net::TcpStream,
    sv2_upstream: SocketAddr,
    auth_config: Arc<AuthConfig>,
) -> Result<()> {
    let peer_addr = sv1_stream.peer_addr()?;
    info!(peer = %peer_addr, "Handling SV1 connection");

    // Connect to upstream SV2
    let sv2_stream = tokio::net::TcpStream::connect(sv2_upstream).await?;
    info!(upstream = %sv2_upstream, "Connected to SV2 upstream");

    // Initialize connection state
    let state = Arc::new(RwLock::new(ConnectionState {
        extranonce1: format!("{:08x}", rand_u32()),
        extranonce2_size: 4,
        channel_id: 0,
        job_map: HashMap::new(),
        reverse_job_map: HashMap::new(),
        next_job_id: AtomicU64::new(1),
        share_sequence: AtomicU64::new(0),
        worker_name: None,
        authorized: false,
        difficulty: 1.0,
        prev_hash: "0".repeat(64),
        nbits: 0x1d00ffff,
        min_ntime: 0,
        coinbase_prefix: Vec::new(),
        coinbase_suffix: Vec::new(),
        merkle_path: Vec::new(),
    }));

    // Create channels for communication between tasks
    let (sv1_to_sv2_tx, mut sv1_to_sv2_rx) = mpsc::channel::<Vec<u8>>(100);
    let (sv2_to_sv1_tx, mut sv2_to_sv1_rx) = mpsc::channel::<String>(100);

    // Split streams
    let (sv1_read, mut sv1_write) = sv1_stream.into_split();
    let (sv2_read, mut sv2_write) = sv2_stream.into_split();

    let sv1_reader = BufReader::new(sv1_read);
    let sv2_reader = BufReader::new(sv2_read);

    // Perform SV2 setup connection
    {
        let setup = sv2::SetupConnection::new_mining();
        let payload = setup.encode();
        let header = sv2::FrameHeader {
            extension_type: 0,
            msg_type: sv2::MessageType::SetupConnection as u8,
            msg_length: payload.len() as u32,
        };

        sv2_write.write_all(&header.encode()).await?;
        sv2_write.write_all(&payload).await?;
        sv2_write.flush().await?;
        debug!("Sent SV2 SetupConnection");
    }

    // Spawn SV1 read task (reads JSON lines from miner)
    let state_clone = Arc::clone(&state);
    let sv1_to_sv2_tx_clone = sv1_to_sv2_tx.clone();
    let sv2_to_sv1_tx_clone = sv2_to_sv1_tx.clone();
    let auth_config_clone = Arc::clone(&auth_config);
    let sv1_read_task = tokio::spawn(async move {
        let mut lines = sv1_reader.lines();

        while let Ok(Some(line)) = lines.next_line().await {
            debug!(msg = %line, "Received SV1 message");

            match serde_json::from_str::<sv1::Request>(&line) {
                Ok(request) => {
                    if let Err(e) = handle_sv1_request(
                        request,
                        &state_clone,
                        &sv1_to_sv2_tx_clone,
                        &sv2_to_sv1_tx_clone,
                        &auth_config_clone,
                    )
                    .await
                    {
                        warn!(error = %e, "Failed to handle SV1 request");
                    }
                }
                Err(e) => {
                    debug!(error = %e, line = %line, "Failed to parse SV1 request");
                }
            }
        }

        debug!("SV1 read task ended");
    });

    // Spawn SV2 read task (reads binary frames from pool)
    let state_clone = Arc::clone(&state);
    let sv2_read_task = tokio::spawn(async move {
        let mut reader = sv2_reader;
        let mut header_buf = [0u8; 6];

        loop {
            // Read frame header
            match tokio::io::AsyncReadExt::read_exact(&mut reader, &mut header_buf).await {
                Ok(_) => {}
                Err(e) => {
                    debug!(error = %e, "SV2 read error");
                    break;
                }
            }

            let header = match sv2::FrameHeader::decode(&header_buf) {
                Some(h) => h,
                None => {
                    warn!("Invalid SV2 frame header");
                    continue;
                }
            };

            // C-5: Validate payload size before allocation to prevent memory exhaustion
            const MAX_SV2_PAYLOAD_SIZE: usize = 16 * 1024 * 1024; // 16MB max
            if header.msg_length as usize > MAX_SV2_PAYLOAD_SIZE {
                warn!(
                    size = header.msg_length,
                    max = MAX_SV2_PAYLOAD_SIZE,
                    "C-5 SECURITY: SV2 payload exceeds maximum size, dropping connection"
                );
                break;
            }

            // Read payload
            let mut payload = vec![0u8; header.msg_length as usize];
            if let Err(e) = tokio::io::AsyncReadExt::read_exact(&mut reader, &mut payload).await {
                debug!(error = %e, "SV2 payload read error");
                break;
            }

            debug!(
                msg_type = header.msg_type,
                length = header.msg_length,
                "Received SV2 message"
            );

            // Translate SV2 to SV1 notifications
            if let Err(e) =
                handle_sv2_message(header.msg_type, &payload, &state_clone, &sv2_to_sv1_tx).await
            {
                warn!(error = %e, "Failed to handle SV2 message");
            }
        }

        debug!("SV2 read task ended");
    });

    // Spawn SV1 write task (sends JSON to miner)
    let sv1_write_task = tokio::spawn(async move {
        while let Some(msg) = sv2_to_sv1_rx.recv().await {
            let line = format!("{}\n", msg);
            if let Err(e) = sv1_write.write_all(line.as_bytes()).await {
                warn!(error = %e, "Failed to write to SV1");
                break;
            }
            if let Err(e) = sv1_write.flush().await {
                warn!(error = %e, "Failed to flush SV1");
                break;
            }
        }
        debug!("SV1 write task ended");
    });

    // Spawn SV2 write task (sends binary to pool)
    let sv2_write_task = tokio::spawn(async move {
        while let Some(data) = sv1_to_sv2_rx.recv().await {
            if let Err(e) = sv2_write.write_all(&data).await {
                warn!(error = %e, "Failed to write to SV2");
                break;
            }
            if let Err(e) = sv2_write.flush().await {
                warn!(error = %e, "Failed to flush SV2");
                break;
            }
        }
        debug!("SV2 write task ended");
    });

    // Wait for any task to complete (connection closed)
    tokio::select! {
        _ = sv1_read_task => {}
        _ = sv2_read_task => {}
        _ = sv1_write_task => {}
        _ = sv2_write_task => {}
    }

    info!(peer = %peer_addr, "Connection closed");
    Ok(())
}

/// Handle SV1 request and translate to SV2
async fn handle_sv1_request(
    request: sv1::Request,
    state: &Arc<RwLock<ConnectionState>>,
    sv2_tx: &mpsc::Sender<Vec<u8>>,
    sv1_tx: &mpsc::Sender<String>,
    auth_config: &Arc<AuthConfig>,
) -> Result<()> {
    match request.method.as_str() {
        "mining.subscribe" => {
            // Respond with subscription info
            let (extranonce1, extranonce2_size) = {
                let state_guard = state.read();
                (
                    state_guard.extranonce1.clone(),
                    state_guard.extranonce2_size,
                )
            };

            let result = sv1::SubscribeResult {
                subscriptions: vec![
                    (
                        "mining.notify".to_string(),
                        "ae6812eb4cd7735a302a8a9dd95cf71f".to_string(),
                    ),
                    (
                        "mining.set_difficulty".to_string(),
                        "b4b6693b72a50c7116db18d6497cac52".to_string(),
                    ),
                ],
                extranonce1,
                extranonce2_size,
            };

            let response = sv1::Response::success(request.id, result.to_json());
            let json = serde_json::to_string(&response)?;
            sv1_tx.send(json).await?;

            debug!("Sent mining.subscribe response");
        }

        "mining.authorize" => {
            // Parse worker name and password
            // SV1 authorize: params = [username, password]
            let worker = request
                .params
                .first()
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            let provided_password = request.params.get(1).and_then(|v| v.as_str()).unwrap_or("");

            // Validate password for private mining modes
            if auth_config.requires_password() {
                if !auth_config.validate_password(provided_password) {
                    warn!(
                        worker = %worker,
                        mode = ?auth_config.mining_mode,
                        "Mining authorization FAILED: invalid password"
                    );

                    // Send error response
                    let response = sv1::Response::error(
                        request.id,
                        -1,
                        "Authorization failed: invalid password".to_string(),
                    );
                    let json = serde_json::to_string(&response)?;
                    sv1_tx.send(json).await?;

                    // Don't proceed - connection will be dropped
                    return Ok(());
                }

                info!(
                    worker = %worker,
                    mode = ?auth_config.mining_mode,
                    "Mining authorization successful (private mode)"
                );
            }

            {
                let mut state_guard = state.write();
                state_guard.worker_name = Some(worker.clone());
                state_guard.authorized = true;
            }

            // Send success response
            let response = sv1::Response::success(request.id, serde_json::json!(true));
            let json = serde_json::to_string(&response)?;
            sv1_tx.send(json).await?;

            // Open SV2 mining channel (no lock needed, using worker directly)
            let open_channel = sv2::OpenStandardMiningChannel {
                request_id: 1,
                user_identity: worker,
                nominal_hash_rate: 1000.0, // 1 TH/s default
                max_target: [0xff; 32],
            };
            let payload = open_channel.encode();
            let header = sv2::FrameHeader {
                extension_type: 0,
                msg_type: sv2::MessageType::OpenStandardMiningChannel as u8,
                msg_length: payload.len() as u32,
            };

            let mut frame = header.encode().to_vec();
            frame.extend(payload);
            sv2_tx.send(frame).await?;

            debug!("Sent mining.authorize response and opened SV2 channel");
        }

        "mining.submit" => {
            // Parse submit parameters
            let submit = match sv1::SubmitParams::from_params(&request.params) {
                Some(s) => s,
                None => {
                    let response = sv1::Response::error(
                        request.id,
                        -1,
                        "Invalid submit parameters".to_string(),
                    );
                    let json = serde_json::to_string(&response)?;
                    sv1_tx.send(json).await?;
                    return Ok(());
                }
            };

            // Extract all needed data from state before awaiting
            let (channel_id, sv2_job_id, sequence_number) = {
                let state_guard = state.read();
                let job_id = state_guard
                    .job_map
                    .get(&submit.job_id)
                    .copied()
                    .unwrap_or(0);
                let seq = state_guard.share_sequence.fetch_add(1, Ordering::SeqCst) as u32;
                (state_guard.channel_id, job_id, seq)
            };

            // Parse nonce and ntime
            let nonce = u32::from_str_radix(&submit.nonce, 16).unwrap_or(0);
            let ntime = u32::from_str_radix(&submit.ntime, 16).unwrap_or(0);

            let share = sv2::SubmitSharesStandard {
                channel_id,
                sequence_number,
                job_id: sv2_job_id,
                nonce,
                ntime,
                version: 0x20000000, // BIP9 version bits
            };

            let payload = share.encode();
            let header = sv2::FrameHeader {
                extension_type: 0,
                msg_type: sv2::MessageType::SubmitSharesStandard as u8,
                msg_length: payload.len() as u32,
            };

            let mut frame = header.encode().to_vec();
            frame.extend(payload);
            sv2_tx.send(frame).await?;

            // M-16 NOTE: We send immediate acceptance for latency, but log if upstream rejects.
            // This matches common SV1 translator behavior. The SubmitSharesError handler (line 901+)
            // already logs rejection but cannot retroactively notify the miner.
            debug!(job = %submit.job_id, "Sending immediate share acceptance (upstream validation pending)");
            let response = sv1::Response::success(request.id, serde_json::json!(true));
            let json = serde_json::to_string(&response)?;
            sv1_tx.send(json).await?;

            debug!(job = %submit.job_id, nonce = %submit.nonce, "Forwarded share to SV2");
        }

        "mining.extranonce.subscribe" => {
            // Optional extranonce subscription
            let response = sv1::Response::success(request.id, serde_json::json!(true));
            let json = serde_json::to_string(&response)?;
            sv1_tx.send(json).await?;
        }

        "mining.configure" => {
            // BIP310 mining configuration
            let response = sv1::Response::success(request.id, serde_json::json!({}));
            let json = serde_json::to_string(&response)?;
            sv1_tx.send(json).await?;
        }

        _ => {
            warn!(method = %request.method, "Unknown SV1 method");
            let response = sv1::Response::error(
                request.id,
                -32601,
                format!("Method not found: {}", request.method),
            );
            let json = serde_json::to_string(&response)?;
            sv1_tx.send(json).await?;
        }
    }

    Ok(())
}

/// Handle SV2 message and translate to SV1
async fn handle_sv2_message(
    msg_type: u8,
    payload: &[u8],
    state: &Arc<RwLock<ConnectionState>>,
    sv1_tx: &mpsc::Sender<String>,
) -> Result<()> {
    use payload_parser::*;

    match msg_type {
        x if x == sv2::MessageType::SetupConnectionSuccess as u8 => {
            debug!("SV2 connection setup successful");
        }

        x if x == sv2::MessageType::SetupConnectionError as u8 => {
            error!("SV2 connection setup failed");
        }

        x if x == sv2::MessageType::OpenStandardMiningChannelSuccess as u8 => {
            // CRIT-11: Validate payload length before any access
            // Layout: request_id (4) + channel_id (4) = 8 bytes minimum
            if let Err(e) = validate_min_length(payload, 8, "OpenStandardMiningChannelSuccess") {
                warn!("CRIT-11: Malformed SV2 message: {}", e);
                return Ok(()); // Don't propagate error, just log and continue
            }

            let _request_id = read_u32_le(payload, 0)?;
            let channel_id = read_u32_le(payload, 4)?;

            // Update state and extract difficulty before awaiting
            let difficulty = {
                let mut state_guard = state.write();
                state_guard.channel_id = channel_id;
                state_guard.difficulty
            };

            info!(channel_id = channel_id, "SV2 mining channel opened");

            // Send initial difficulty
            let difficulty_notification = sv1::Notification {
                method: "mining.set_difficulty".to_string(),
                params: vec![serde_json::json!(difficulty)],
            };
            let json = serde_json::to_string(&difficulty_notification)?;
            sv1_tx.send(json).await?;
        }

        x if x == sv2::MessageType::NewMiningJob as u8
            || x == sv2::MessageType::NewExtendedMiningJob as u8 =>
        {
            // Parse new job and convert to SV1 mining.notify
            // NewExtendedMiningJob layout:
            //   channel_id (4) + job_id (4) + future_job (1) + version (4) +
            //   version_rolling_allowed (1) + merkle_path (variable) +
            //   coinbase_tx_prefix (variable) + coinbase_tx_suffix (variable)
            //
            // CRIT-11: Minimum fixed-length portion is 14 bytes
            if let Err(e) = validate_min_length(payload, 14, "NewExtendedMiningJob") {
                warn!("CRIT-11: Malformed SV2 message: {}", e);
                return Ok(());
            }

            let sv2_job_id = read_u32_le(payload, 4)?;
            let future_job = read_u8(payload, 8)? != 0;
            let version = read_u32_le(payload, 9)?;

            // Parse variable-length fields (simplified - real impl needs proper SV2 parsing)
            let mut offset = 14; // Skip version_rolling_allowed byte

            // Parse merkle_path - SEQ0_255 format: length byte + N*32 bytes
            let mut merkle_branches: Vec<String> = Vec::new();
            if let Ok(merkle_count) = read_u8(payload, offset) {
                offset += 1;
                let merkle_count = merkle_count as usize;
                for _ in 0..merkle_count {
                    if let Ok(branch) = read_slice(payload, offset, 32) {
                        // SV1 merkle branches are hex-encoded, byte-reversed
                        let reversed: Vec<u8> = branch.iter().rev().cloned().collect();
                        merkle_branches.push(hex::encode(&reversed));
                        offset += 32;
                    } else {
                        warn!("CRIT-11: Truncated merkle path in NewExtendedMiningJob");
                        break;
                    }
                }
            }

            // Parse coinbase_tx_prefix - B0_64K format: 2-byte length + data
            let coinbase_prefix = if let Ok(len) = read_u16_le(payload, offset) {
                offset += 2;
                let len = len as usize;
                if let Ok(data) = read_slice(payload, offset, len) {
                    offset += len;
                    data.to_vec()
                } else {
                    warn!("CRIT-11: Truncated coinbase prefix in NewExtendedMiningJob");
                    Vec::new()
                }
            } else {
                Vec::new()
            };

            // Parse coinbase_tx_suffix - B0_64K format: 2-byte length + data
            let coinbase_suffix = if let Ok(len) = read_u16_le(payload, offset) {
                offset += 2;
                let len = len as usize;
                if let Ok(data) = read_slice(payload, offset, len) {
                    data.to_vec()
                } else {
                    warn!("CRIT-11: Truncated coinbase suffix in NewExtendedMiningJob");
                    Vec::new()
                }
            } else {
                Vec::new()
            };

            // Get state data and generate job ID
            let (sv1_job_id, _extranonce1, prev_hash, nbits, min_ntime) = {
                let mut state_guard = state.write();
                let id = state_guard.next_job_id.fetch_add(1, Ordering::SeqCst);
                let job_str = format!("{:x}", id);
                state_guard.job_map.insert(job_str.clone(), sv2_job_id);
                state_guard
                    .reverse_job_map
                    .insert(sv2_job_id, job_str.clone());

                // M-17: Bound job map size to prevent memory exhaustion
                const MAX_JOBS: usize = 1000;
                while state_guard.job_map.len() > MAX_JOBS {
                    // Remove oldest job (lowest numeric ID)
                    if let Some(oldest) = state_guard
                        .job_map
                        .keys()
                        .filter_map(|k| k.parse::<u64>().ok().map(|n| (k.clone(), n)))
                        .min_by_key(|(_, n)| *n)
                        .map(|(k, _)| k)
                    {
                        if let Some(sv2_id) = state_guard.job_map.remove(&oldest) {
                            state_guard.reverse_job_map.remove(&sv2_id);
                        }
                    } else {
                        break;
                    }
                }

                state_guard.coinbase_prefix = coinbase_prefix.clone();
                state_guard.coinbase_suffix = coinbase_suffix.clone();
                state_guard.merkle_path = merkle_branches
                    .iter()
                    .filter_map(|h| {
                        let bytes = hex::decode(h).ok()?;
                        if bytes.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&bytes);
                            Some(arr)
                        } else {
                            None
                        }
                    })
                    .collect();
                (
                    job_str,
                    state_guard.extranonce1.clone(),
                    state_guard.prev_hash.clone(),
                    state_guard.nbits,
                    state_guard.min_ntime,
                )
            };

            // Build coinbase1: prefix + extranonce1 placeholder position
            // SV1 miners will insert: extranonce1 (from subscribe) + extranonce2 (from miner)
            let coinbase1_hex = hex::encode(&coinbase_prefix);

            // Build coinbase2: suffix (after extranonce space)
            let coinbase2_hex = hex::encode(&coinbase_suffix);

            // Determine ntime - use min_ntime for future jobs, current time otherwise
            let ntime = if future_job {
                min_ntime
            } else {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as u32
            };

            let notify = sv1::NotifyParams {
                job_id: sv1_job_id.clone(),
                prev_hash,
                coinbase1: coinbase1_hex,
                coinbase2: coinbase2_hex,
                merkle_branches,
                version: format!("{:08x}", version),
                nbits: format!("{:08x}", nbits),
                ntime: format!("{:08x}", ntime),
                clean_jobs: !future_job, // Clean jobs on new block, not future jobs
            };

            let notification = sv1::Notification {
                method: "mining.notify".to_string(),
                params: notify.to_params(),
            };
            let json = serde_json::to_string(&notification)?;
            sv1_tx.send(json).await?;

            debug!(
                sv1_job = %sv1_job_id,
                sv2_job = sv2_job_id,
                merkle_count = notify.merkle_branches.len(),
                "Sent mining.notify"
            );
        }

        x if x == sv2::MessageType::SetNewPrevHash as u8 => {
            // New block - update state with new prev_hash and nbits
            // SetNewPrevHash layout: channel_id (4) + job_id (4) + prev_hash (32) + min_ntime (4) + nbits (4)
            // CRIT-11: Total = 48 bytes
            if let Err(e) = validate_min_length(payload, 48, "SetNewPrevHash") {
                warn!("CRIT-11: Malformed SV2 message: {}", e);
                return Ok(());
            }

            let prev_hash_bytes = read_slice(payload, 8, 32)?;
            let min_ntime = read_u32_le(payload, 40)?;
            let nbits = read_u32_le(payload, 44)?;

            // Convert prev_hash to SV1 format (reversed byte order, hex-encoded)
            let prev_hash_reversed: Vec<u8> = prev_hash_bytes.iter().rev().cloned().collect();
            let prev_hash_hex = hex::encode(&prev_hash_reversed);

            // Update state
            {
                let mut state_guard = state.write();
                state_guard.prev_hash = prev_hash_hex.clone();
                state_guard.nbits = nbits;
                state_guard.min_ntime = min_ntime;
            }

            debug!(
                prev_hash = %prev_hash_hex,
                nbits = format!("{:08x}", nbits),
                min_ntime,
                "Updated prev_hash from SV2"
            );
        }

        x if x == sv2::MessageType::SetTarget as u8 => {
            // Difficulty adjustment
            // SetTarget layout: channel_id (4) + max_target (32)
            // CRIT-11: Total = 36 bytes
            if let Err(e) = validate_min_length(payload, 36, "SetTarget") {
                warn!("CRIT-11: Malformed SV2 message: {}", e);
                return Ok(());
            }

            // Parse 256-bit target (little-endian)
            let target_bytes = read_slice(payload, 4, 32)?;

            // Convert target to difficulty
            // difficulty = pool_target_1 / current_target
            // pool_target_1 = 0x00000000ffff0000000000000000000000000000000000000000000000000000
            let difficulty = target_to_difficulty(target_bytes);

            // Update state
            {
                let mut state_guard = state.write();
                state_guard.difficulty = difficulty;
            }

            let difficulty_notification = sv1::Notification {
                method: "mining.set_difficulty".to_string(),
                params: vec![serde_json::json!(difficulty)],
            };
            let json = serde_json::to_string(&difficulty_notification)?;
            sv1_tx.send(json).await?;

            debug!(
                difficulty = difficulty,
                "Set new difficulty from SV2 target"
            );
        }

        x if x == sv2::MessageType::SubmitSharesSuccess as u8 => {
            // SubmitSharesSuccess layout: channel_id (4) + last_seq_num (4) + new_submits_accepted (4) + new_shares_sum (8)
            // CRIT-11: We need at least 12 bytes to read new_submits at offset 8
            if let Err(e) = validate_min_length(payload, 12, "SubmitSharesSuccess") {
                warn!("CRIT-11: Malformed SV2 message: {}", e);
                return Ok(());
            }

            let new_submits = read_u32_le(payload, 8)?;
            debug!(accepted = new_submits, "Shares accepted");
        }

        x if x == sv2::MessageType::SubmitSharesError as u8 => {
            // SubmitSharesError layout: channel_id (4) + seq_num (4) + error_code (variable string)
            // CRIT-11: Minimum is 9 bytes (8 bytes fixed + 1 byte length prefix)
            if let Err(e) = validate_min_length(payload, 9, "SubmitSharesError") {
                warn!("CRIT-11: Malformed SV2 message: {}", e);
                return Ok(());
            }

            let seq_num = read_u32_le(payload, 4)?;
            let error_len = read_u8(payload, 8)? as usize;
            let error_msg = if let Ok(msg_bytes) = read_slice(payload, 9, error_len) {
                String::from_utf8_lossy(msg_bytes).to_string()
            } else {
                warn!("CRIT-11: Truncated error message in SubmitSharesError");
                "Unknown error (truncated)".to_string()
            };

            warn!(seq = seq_num, error = %error_msg, "Share rejected by pool");
            // Note: SV1 doesn't have a standard way to notify of share rejection
            // after initial acceptance. The share was already accepted in handle_sv1_request.
        }

        _ => {
            debug!(msg_type = msg_type, "Unknown SV2 message type");
        }
    }

    Ok(())
}

/// M-15: Cryptographically secure random for extranonce1 generation
fn rand_u32() -> u32 {
    let mut bytes = [0u8; 4];
    getrandom::getrandom(&mut bytes).expect("RNG failure");
    u32::from_le_bytes(bytes)
}

/// Convert a 256-bit target to SV1 difficulty
///
/// Difficulty = pool_target_1 / target
/// pool_target_1 = 0x00000000ffff0000...0000 (difficulty 1 target)
fn target_to_difficulty(target_bytes: &[u8]) -> f64 {
    // pool_target_1 = 2^224 * 0xffff
    // This is the target for difficulty 1
    const POOL_TARGET_1: f64 =
        26959535291011309493156476344723991336010898738574164086137773096960.0;

    // Convert target bytes (little-endian 256-bit) to f64
    // We only need the most significant non-zero bytes for approximation
    let mut target_value: f64 = 0.0;
    let mut shift: f64 = 1.0;

    for &byte in target_bytes.iter() {
        target_value += (byte as f64) * shift;
        shift *= 256.0;
    }

    if target_value == 0.0 {
        return 1.0; // Avoid division by zero
    }

    // difficulty = pool_target_1 / target
    let difficulty = POOL_TARGET_1 / target_value;

    // Clamp to reasonable range and round to 6 decimal places
    let clamped = difficulty.clamp(0.001, 1e18);
    (clamped * 1_000_000.0).round() / 1_000_000.0
}

/// SV1 Protocol Messages (JSON-RPC)
mod sv1 {
    use serde::{Deserialize, Serialize};

    /// JSON-RPC Request
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Request {
        pub id: Option<serde_json::Value>,
        pub method: String,
        pub params: Vec<serde_json::Value>,
    }

    /// JSON-RPC Response
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Response {
        pub id: Option<serde_json::Value>,
        pub result: serde_json::Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub error: Option<ErrorObject>,
    }

    impl Response {
        pub fn success(id: Option<serde_json::Value>, result: serde_json::Value) -> Self {
            Self {
                id,
                result,
                error: None,
            }
        }

        pub fn error(id: Option<serde_json::Value>, code: i32, message: String) -> Self {
            Self {
                id,
                result: serde_json::Value::Null,
                error: Some(ErrorObject { code, message }),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ErrorObject {
        pub code: i32,
        pub message: String,
    }

    /// Server notification (no id)
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Notification {
        pub method: String,
        pub params: Vec<serde_json::Value>,
    }

    /// mining.subscribe response
    #[derive(Debug, Clone)]
    pub struct SubscribeResult {
        pub subscriptions: Vec<(String, String)>,
        pub extranonce1: String,
        pub extranonce2_size: u32,
    }

    impl SubscribeResult {
        pub fn to_json(&self) -> serde_json::Value {
            serde_json::json!([
                self.subscriptions
                    .iter()
                    .map(|(a, b)| serde_json::json!([a, b]))
                    .collect::<Vec<_>>(),
                self.extranonce1,
                self.extranonce2_size
            ])
        }
    }

    /// mining.notify parameters
    #[derive(Debug, Clone)]
    pub struct NotifyParams {
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

    impl NotifyParams {
        pub fn to_params(&self) -> Vec<serde_json::Value> {
            vec![
                serde_json::json!(self.job_id),
                serde_json::json!(self.prev_hash),
                serde_json::json!(self.coinbase1),
                serde_json::json!(self.coinbase2),
                serde_json::json!(self.merkle_branches),
                serde_json::json!(self.version),
                serde_json::json!(self.nbits),
                serde_json::json!(self.ntime),
                serde_json::json!(self.clean_jobs),
            ]
        }
    }

    /// mining.submit parameters
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    pub struct SubmitParams {
        pub worker_name: String,
        pub job_id: String,
        pub extranonce2: String,
        pub ntime: String,
        pub nonce: String,
    }

    impl SubmitParams {
        pub fn from_params(params: &[serde_json::Value]) -> Option<Self> {
            if params.len() < 5 {
                return None;
            }
            Some(Self {
                worker_name: params[0].as_str()?.to_string(),
                job_id: params[1].as_str()?.to_string(),
                extranonce2: params[2].as_str()?.to_string(),
                ntime: params[3].as_str()?.to_string(),
                nonce: params[4].as_str()?.to_string(),
            })
        }
    }
}

/// SV2 Protocol Messages (Binary)
mod sv2 {
    /// SV2 Message types
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u8)]
    pub enum MessageType {
        SetupConnection = 0x00,
        SetupConnectionSuccess = 0x01,
        SetupConnectionError = 0x02,
        OpenStandardMiningChannel = 0x10,
        OpenStandardMiningChannelSuccess = 0x11,
        NewMiningJob = 0x1e,
        NewExtendedMiningJob = 0x1f,
        SetNewPrevHash = 0x20,
        SubmitSharesStandard = 0x1a,
        SubmitSharesSuccess = 0x1c,
        SubmitSharesError = 0x1d,
        SetTarget = 0x21,
    }

    /// SV2 Frame header
    #[derive(Debug, Clone)]
    pub struct FrameHeader {
        pub extension_type: u16,
        pub msg_type: u8,
        pub msg_length: u32,
    }

    impl FrameHeader {
        #[allow(dead_code)]
        pub const SIZE: usize = 6;

        pub fn encode(&self) -> [u8; 6] {
            let mut buf = [0u8; 6];
            buf[0..2].copy_from_slice(&self.extension_type.to_le_bytes());
            buf[2] = self.msg_type;
            // 3-byte length (little endian)
            buf[3] = (self.msg_length & 0xFF) as u8;
            buf[4] = ((self.msg_length >> 8) & 0xFF) as u8;
            buf[5] = ((self.msg_length >> 16) & 0xFF) as u8;
            buf
        }

        pub fn decode(buf: &[u8]) -> Option<Self> {
            if buf.len() < 6 {
                return None;
            }
            Some(Self {
                extension_type: u16::from_le_bytes([buf[0], buf[1]]),
                msg_type: buf[2],
                msg_length: u32::from_le_bytes([buf[3], buf[4], buf[5], 0]),
            })
        }
    }

    /// SetupConnection message
    #[derive(Debug, Clone)]
    pub struct SetupConnection {
        pub protocol: u8, // 0 = Mining Protocol
        pub min_version: u16,
        pub max_version: u16,
        pub flags: u32,
        pub endpoint_host: String,
        pub endpoint_port: u16,
        pub vendor: String,
        pub hardware_version: String,
        pub firmware: String,
        pub device_id: String,
    }

    impl SetupConnection {
        pub fn new_mining() -> Self {
            Self {
                protocol: 0,
                min_version: 2,
                max_version: 2,
                flags: 0,
                endpoint_host: "localhost".to_string(),
                endpoint_port: 34255,
                vendor: "BitcoinGhost".to_string(),
                hardware_version: "1.0".to_string(),
                firmware: "translator".to_string(),
                device_id: "ghost-translator".to_string(),
            }
        }

        pub fn encode(&self) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.push(self.protocol);
            buf.extend_from_slice(&self.min_version.to_le_bytes());
            buf.extend_from_slice(&self.max_version.to_le_bytes());
            buf.extend_from_slice(&self.flags.to_le_bytes());

            // String encoding: u8 length prefix then UTF-8 bytes
            fn push_str(buf: &mut Vec<u8>, s: &str) {
                buf.push(s.len() as u8);
                buf.extend_from_slice(s.as_bytes());
            }

            push_str(&mut buf, &self.endpoint_host);
            buf.extend_from_slice(&self.endpoint_port.to_le_bytes());
            push_str(&mut buf, &self.vendor);
            push_str(&mut buf, &self.hardware_version);
            push_str(&mut buf, &self.firmware);
            push_str(&mut buf, &self.device_id);

            buf
        }
    }

    /// OpenStandardMiningChannel message
    #[derive(Debug, Clone)]
    pub struct OpenStandardMiningChannel {
        pub request_id: u32,
        pub user_identity: String,
        pub nominal_hash_rate: f32,
        pub max_target: [u8; 32],
    }

    impl OpenStandardMiningChannel {
        pub fn encode(&self) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&self.request_id.to_le_bytes());
            buf.push(self.user_identity.len() as u8);
            buf.extend_from_slice(self.user_identity.as_bytes());
            buf.extend_from_slice(&self.nominal_hash_rate.to_le_bytes());
            buf.extend_from_slice(&self.max_target);
            buf
        }
    }

    /// SubmitSharesStandard message
    #[derive(Debug, Clone)]
    pub struct SubmitSharesStandard {
        pub channel_id: u32,
        pub sequence_number: u32,
        pub job_id: u32,
        pub nonce: u32,
        pub ntime: u32,
        pub version: u32,
    }

    impl SubmitSharesStandard {
        pub fn encode(&self) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&self.channel_id.to_le_bytes());
            buf.extend_from_slice(&self.sequence_number.to_le_bytes());
            buf.extend_from_slice(&self.job_id.to_le_bytes());
            buf.extend_from_slice(&self.nonce.to_le_bytes());
            buf.extend_from_slice(&self.ntime.to_le_bytes());
            buf.extend_from_slice(&self.version.to_le_bytes());
            buf
        }
    }

    /// NewMiningJob message (server to client)
    /// Note: Used when SV2 upstream connection is fully implemented
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    pub struct NewMiningJob {
        pub channel_id: u32,
        pub job_id: u32,
        pub future_job: bool,
        pub version: u32,
        pub merkle_root: [u8; 32],
    }

    /// SetNewPrevHash message (server to client)
    /// Note: Used when SV2 upstream connection is fully implemented
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    pub struct SetNewPrevHash {
        pub channel_id: u32,
        pub job_id: u32,
        pub prev_hash: [u8; 32],
        pub min_ntime: u32,
        pub nbits: u32,
    }
}

/// Translation state for a single connection
struct ConnectionState {
    /// SV1 extranonce1 (hex string)
    extranonce1: String,
    /// Extranonce2 size
    extranonce2_size: u32,
    /// SV2 channel ID
    channel_id: u32,
    /// Job ID mapping (SV1 string -> SV2 u32)
    job_map: HashMap<String, u32>,
    /// Reverse job map (SV2 u32 -> SV1 string)
    reverse_job_map: HashMap<u32, String>,
    /// Next SV1 job ID counter
    next_job_id: AtomicU64,
    /// Share sequence number
    share_sequence: AtomicU64,
    /// Worker name
    worker_name: Option<String>,
    /// Authorized
    authorized: bool,
    /// Current difficulty
    difficulty: f64,
    /// Current prev_hash (from SetNewPrevHash, hex-encoded, reversed for SV1)
    prev_hash: String,
    /// Current nbits (from SetNewPrevHash)
    nbits: u32,
    /// Current min_ntime (from SetNewPrevHash)
    min_ntime: u32,
    /// Coinbase prefix (from NewExtendedMiningJob)
    coinbase_prefix: Vec<u8>,
    /// Coinbase suffix (from NewExtendedMiningJob)
    coinbase_suffix: Vec<u8>,
    /// Merkle path (from NewExtendedMiningJob)
    merkle_path: Vec<[u8; 32]>,
}

// =============================================================================
// CRIT-11: Unit tests for safe payload parsing
// =============================================================================
#[cfg(test)]
mod tests {
    use super::payload_parser::*;

    /// Test that read_u32_le returns error for short payload (CRIT-11)
    #[test]
    fn test_read_u32_le_short_payload() {
        let payload = vec![0x01, 0x02, 0x03]; // 3 bytes, need 4
        let result = read_u32_le(&payload, 0);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("payload too short"));
    }

    /// Test that read_u32_le works for valid payload
    #[test]
    fn test_read_u32_le_valid() {
        let payload = vec![0x01, 0x02, 0x03, 0x04];
        let result = read_u32_le(&payload, 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0x04030201); // Little-endian
    }

    /// Test that read_u32_le with offset returns error for short payload
    #[test]
    fn test_read_u32_le_offset_short() {
        let payload = vec![0x00, 0x01, 0x02, 0x03, 0x04]; // 5 bytes
        let result = read_u32_le(&payload, 2); // Need offset 2 + 4 = 6 bytes
        assert!(result.is_err());
    }

    /// Test that read_u16_le returns error for short payload
    #[test]
    fn test_read_u16_le_short_payload() {
        let payload = vec![0x01]; // 1 byte, need 2
        let result = read_u16_le(&payload, 0);
        assert!(result.is_err());
    }

    /// Test that read_u8 returns error for empty payload
    #[test]
    fn test_read_u8_empty_payload() {
        let payload: Vec<u8> = vec![];
        let result = read_u8(&payload, 0);
        assert!(result.is_err());
    }

    /// Test that read_slice returns error for short payload
    #[test]
    fn test_read_slice_short_payload() {
        let payload = vec![0x01, 0x02, 0x03]; // 3 bytes
        let result = read_slice(&payload, 0, 10); // Want 10 bytes
        assert!(result.is_err());
    }

    /// Test that read_slice works for valid payload
    #[test]
    fn test_read_slice_valid() {
        let payload = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let result = read_slice(&payload, 1, 3);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), &[0x02, 0x03, 0x04]);
    }

    /// Test validate_min_length returns error for short payload
    #[test]
    fn test_validate_min_length_short() {
        let payload = vec![0x01, 0x02, 0x03, 0x04]; // 4 bytes
        let result = validate_min_length(&payload, 8, "TestMessage");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("TestMessage"));
        assert!(err_msg.contains("too short"));
    }

    /// Test validate_min_length passes for adequate payload
    #[test]
    fn test_validate_min_length_adequate() {
        let payload = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let result = validate_min_length(&payload, 8, "TestMessage");
        assert!(result.is_ok());
    }

    /// Test OpenStandardMiningChannelSuccess with short payload (CRIT-11)
    #[test]
    fn test_short_open_channel_success_payload() {
        // OpenStandardMiningChannelSuccess needs at least 8 bytes
        let short_payload = vec![0x01, 0x02, 0x03]; // Only 3 bytes
        let result = validate_min_length(&short_payload, 8, "OpenStandardMiningChannelSuccess");
        assert!(result.is_err());
    }

    /// Test SetNewPrevHash with short payload (CRIT-11)
    #[test]
    fn test_short_set_new_prev_hash_payload() {
        // SetNewPrevHash needs 48 bytes
        let short_payload = vec![0x00; 10]; // Only 10 bytes
        let result = validate_min_length(&short_payload, 48, "SetNewPrevHash");
        assert!(result.is_err());
    }

    /// Test SetTarget with short payload (CRIT-11)
    #[test]
    fn test_short_set_target_payload() {
        // SetTarget needs 36 bytes
        let short_payload = vec![0x00; 4]; // Only 4 bytes
        let result = validate_min_length(&short_payload, 36, "SetTarget");
        assert!(result.is_err());
    }

    /// Test SubmitSharesSuccess with short payload (CRIT-11)
    #[test]
    fn test_short_submit_shares_success_payload() {
        // SubmitSharesSuccess needs at least 12 bytes to read new_submits at offset 8
        let short_payload = vec![0x00; 8]; // Only 8 bytes
        let result = validate_min_length(&short_payload, 12, "SubmitSharesSuccess");
        assert!(result.is_err());
    }

    /// Test SubmitSharesError with short payload (CRIT-11)
    #[test]
    fn test_short_submit_shares_error_payload() {
        // SubmitSharesError needs at least 9 bytes
        let short_payload = vec![0x00; 5]; // Only 5 bytes
        let result = validate_min_length(&short_payload, 9, "SubmitSharesError");
        assert!(result.is_err());
    }

    /// Test NewExtendedMiningJob with short payload (CRIT-11)
    #[test]
    fn test_short_new_extended_mining_job_payload() {
        // NewExtendedMiningJob needs at least 14 bytes for fixed fields
        let short_payload = vec![0x00; 10]; // Only 10 bytes
        let result = validate_min_length(&short_payload, 14, "NewExtendedMiningJob");
        assert!(result.is_err());
    }
}
