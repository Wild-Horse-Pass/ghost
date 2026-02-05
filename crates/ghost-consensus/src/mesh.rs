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
//| FILE: mesh.rs                                                                                                        |
//|======================================================================================================================|

//! P2P mesh network implementation
//!
//! Uses ZMQ for efficient message propagation across the node network.
//!
//! ## Architecture
//!
//! - PUB socket for broadcasting messages to peers
//! - SUB sockets for receiving messages from peers
//! - ROUTER/DEALER for request-response patterns
//!
//! ## Replay Attack Prevention (P2P-M2)
//!
//! Message replay attacks are prevented through a dual-layer defense:
//!
//! 1. **Deduplication Window** (`dedup_window_secs`, default 60s):
//!    Messages are tracked by (sender_id, sequence_number). Duplicate messages
//!    within this window are silently dropped.
//!
//! 2. **Timestamp Validation** (message_validator.rs):
//!    All messages must have timestamps within 5 minutes of current time.
//!    Messages with timestamps outside this window are rejected BEFORE
//!    deduplication checks.
//!
//! Together, these ensure that even after the dedup window expires, old messages
//! cannot be replayed because their timestamps will be too far in the past.
//! The timestamp validation window (5 minutes) is intentionally larger than the
//! dedup window (60 seconds) to provide defense in depth.

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tmq::{publish, subscribe, Context, Multipart};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Shared ZMQ context for all sockets (libzmq handles threading internally)
static ZMQ_CONTEXT: Lazy<Context> = Lazy::new(Context::new);

use ghost_common::config::P2PPortConfig;
use ghost_common::error::{GhostError, GhostResult};
use ghost_common::identity::NodeIdentity;
use ghost_common::types::NodeId;

use crate::message::{MessageEnvelope, MessageType};
use crate::message_validator::{validate_and_verify, ValidationStats};
use crate::noise_pool::{NoiseConnectionPool, NoisePoolConfig};
use crate::peer::{Peer, PeerManager};

/// Type alias for optional outbound message receiver storage
type OptionalOutboundReceiver = Option<mpsc::Receiver<(String, Vec<u8>)>>;

/// Mesh network configuration
#[derive(Debug, Clone)]
pub struct MeshConfig {
    /// Our public address
    pub public_address: String,
    /// Port configuration
    pub ports: P2PPortConfig,
    /// Maximum peers
    pub max_peers: usize,
    /// Message deduplication window (seconds)
    pub dedup_window_secs: u64,
    /// Health ping interval (seconds)
    pub health_ping_interval_secs: u64,
    /// Maximum seen messages to track (prevents memory exhaustion)
    pub max_seen_messages: usize,
    /// Node capabilities to advertise in health pings
    pub capabilities: ghost_common::types::NodeCapabilities,
    /// C-1: Enable Noise Protocol for transport encryption
    ///
    /// When enabled, sensitive P2P messages (shares, blocks, votes, payouts)
    /// are sent over encrypted Noise TCP channels instead of plaintext ZMQ.
    ///
    /// ZMQ is still used for:
    /// - Discovery messages (need broadcast for initial peer finding)
    /// - Health pings (broadcast liveness, no secrets)
    ///
    /// Noise TCP is used for:
    /// - Share propagation
    /// - Block announcements
    /// - Consensus votes
    /// - Payout proposals/transactions
    /// - Verification results
    ///
    /// Default: true for secure-by-default operation
    pub noise_enabled: bool,
    /// Port for Noise Protocol TCP connections (default: 8563)
    ///
    /// This port is used for encrypted point-to-point communication.
    /// Separate from ZMQ ports which handle discovery and health.
    pub noise_port: u16,
    /// Path to Noise keypair file
    ///
    /// If the file doesn't exist, a new keypair will be generated and saved.
    /// The keypair is used for X25519 Diffie-Hellman in Noise_XX handshakes.
    pub noise_keypair_path: Option<std::path::PathBuf>,
    /// Require Noise encryption for sensitive messages
    ///
    /// When true:
    /// - Peers without Noise support are rejected
    /// - Messages from unknown Noise identities are dropped
    ///
    /// When false:
    /// - Falls back to plaintext ZMQ if Noise connection fails
    /// - Useful during migration period
    ///
    /// Default: false (gradual rollout mode)
    pub noise_required: bool,
}

/// Default Noise port for encrypted TCP connections
pub const DEFAULT_NOISE_PORT: u16 = 8563;

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            public_address: "127.0.0.1".to_string(),
            ports: P2PPortConfig::default(),
            max_peers: 100,
            dedup_window_secs: 60,
            health_ping_interval_secs: 10,
            max_seen_messages: 100_000, // Cap at 100k messages (~3.2MB with 32-byte IDs)
            capabilities: ghost_common::types::NodeCapabilities::default(),
            // C-1: Enable Noise by default for secure-by-default operation
            noise_enabled: true,
            noise_port: DEFAULT_NOISE_PORT,
            noise_keypair_path: None, // Will generate ephemeral keypair
            noise_required: false,    // Allow fallback during migration
        }
    }
}

/// Message handler trait
#[async_trait]
pub trait MessageHandler: Send + Sync {
    /// Handle a received message
    async fn handle_message(&self, envelope: MessageEnvelope) -> GhostResult<()>;
}

/// ZMQ socket collection for a mesh node
/// Note: Currently unused - sockets managed through channels. Reserved for direct ZMQ integration.
#[allow(dead_code)]
pub struct MeshSockets {
    /// Publisher socket for broadcasting (tmq::publish::Publish)
    pub_socket: Option<tmq::publish::Publish>,
    /// Subscriber sockets for receiving (keyed by peer address)
    sub_sockets: HashMap<String, tmq::subscribe::Subscribe>,
}

#[allow(dead_code)]
impl MeshSockets {
    fn new() -> Self {
        Self {
            pub_socket: None,
            sub_sockets: HashMap::new(),
        }
    }
}

/// Channel for outbound messages
pub type OutboundSender = mpsc::Sender<(String, Vec<u8>)>;
pub type OutboundReceiver = mpsc::Receiver<(String, Vec<u8>)>;

/// Channel for inbound messages
pub type InboundSender = mpsc::Sender<Vec<u8>>;
pub type InboundReceiver = mpsc::Receiver<Vec<u8>>;

/// Mesh network manager
pub struct MeshNetwork {
    /// Our identity
    identity: Arc<NodeIdentity>,
    /// Configuration
    config: MeshConfig,
    /// Peer manager
    peers: Arc<PeerManager>,
    /// Message sequence counter
    sequence: AtomicU64,
    /// Seen message cache for deduplication (P2P-L1: O(1) eviction)
    seen_messages: RwLock<SeenMessageCache>,
    /// Message handlers
    handlers: RwLock<Vec<Arc<dyn MessageHandler>>>,
    /// Running state
    running: AtomicBool,
    /// Outbound message channel
    outbound_tx: mpsc::Sender<(String, Vec<u8>)>,
    outbound_rx: RwLock<OptionalOutboundReceiver>,
    /// Inbound message channel
    inbound_tx: mpsc::Sender<Vec<u8>>,
    inbound_rx: RwLock<Option<mpsc::Receiver<Vec<u8>>>>,
    /// Message statistics
    messages_sent: AtomicU64,
    messages_received: AtomicU64,
    /// Validation statistics for monitoring
    validation_stats: RwLock<ValidationStats>,
    /// C-1: Noise Protocol connection pool for encrypted P2P communication
    noise_pool: Option<Arc<NoiseConnectionPool>>,
}

/// Message identifier for deduplication
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageId {
    pub sender: NodeId,
    pub sequence: u64,
}

/// M-P2P-4: Maximum connection states to track (prevents unbounded memory growth)
const MAX_CONNECTION_STATES: usize = 1000;

/// P2P4-L6: Connection state for exponential backoff
///
/// Tracks connection attempts per peer to implement exponential backoff
/// for failed connections, preventing aggressive reconnection loops.
#[derive(Debug, Clone)]
struct PeerConnectionState {
    /// Last connection attempt time (monotonic)
    last_attempt: std::time::Instant,
    /// Current backoff duration in milliseconds (doubles on failure, up to max)
    backoff_ms: u64,
    /// Number of consecutive connection failures
    consecutive_failures: u32,
}

impl PeerConnectionState {
    /// Initial backoff: 100ms
    const INITIAL_BACKOFF_MS: u64 = 100;
    /// Maximum backoff: 30 seconds
    const MAX_BACKOFF_MS: u64 = 30_000;

    fn new() -> Self {
        Self {
            last_attempt: std::time::Instant::now(),
            backoff_ms: Self::INITIAL_BACKOFF_MS,
            consecutive_failures: 0,
        }
    }

    /// Check if enough time has passed to retry connection
    fn can_retry(&self) -> bool {
        self.last_attempt.elapsed().as_millis() as u64 >= self.backoff_ms
    }

    /// Record a failed connection attempt, increasing backoff
    fn record_failure(&mut self) {
        self.last_attempt = std::time::Instant::now();
        self.consecutive_failures += 1;
        self.backoff_ms = (self.backoff_ms * 2).min(Self::MAX_BACKOFF_MS);
    }

    /// Record a successful connection, resetting backoff
    fn record_success(&mut self) {
        self.last_attempt = std::time::Instant::now();
        self.consecutive_failures = 0;
        self.backoff_ms = Self::INITIAL_BACKOFF_MS;
    }
}

/// Per-sender message count for H3 security fix
const MAX_MESSAGES_PER_SENDER: usize = 10_000;

/// SEC-P2P-5: Maximum unique senders to track (prevents memory exhaustion)
/// An attacker could create many identities to exhaust memory.
/// With 5000 senders * ~1KB per sender = ~5MB worst case.
const MAX_UNIQUE_SENDERS: usize = 5_000;

/// M-2: Threshold for detecting sequence wrap-around
/// When a new sequence is much smaller than the highest seen, it indicates wrap-around
const WRAP_DETECTION_THRESHOLD: u64 = u64::MAX / 2;

/// M-2: Sequence state tracking with wrap-around epoch
/// Handles the case where sequence numbers wrap from MAX back to 1
#[derive(Debug, Clone, Default)]
struct SequenceState {
    /// Highest sequence number seen in the current epoch
    highest_seq: u64,
    /// Wrap-around epoch (increments each time sequences wrap)
    epoch: u32,
}

/// Bounded LRU-like cache for seen message deduplication (P2P-L1)
///
/// Uses a HashMap for O(1) lookups combined with a VecDeque for O(1) FIFO eviction.
/// This is simpler than a full LRU but provides good performance for deduplication
/// where we mainly care about recent messages.
///
/// Eviction Strategy (H3 security fix):
/// - Global capacity limit with FIFO eviction for overall memory protection
/// - Per-sender tracking ensures one malicious sender can't flush another sender's messages
/// - Each sender limited to MAX_MESSAGES_PER_SENDER (10k) entries
/// - When a sender exceeds their limit, only their oldest messages are evicted
///
/// Replay Prevention (H-P2P-4):
/// - Tracks highest sequence number seen from each sender
/// - Rejects messages with sequence <= highest seen (prevents replay of old messages)
struct SeenMessageCache {
    /// Map for O(1) lookup
    map: HashMap<MessageId, u64>, // MessageId -> timestamp
    /// Queue for O(1) FIFO eviction (oldest at front)
    queue: VecDeque<MessageId>,
    /// Per-sender message counts (H3 security fix)
    sender_counts: HashMap<NodeId, usize>,
    /// Per-sender queues for targeted eviction (H3 security fix)
    sender_queues: HashMap<NodeId, VecDeque<(u64, u64)>>, // sender -> (sequence, timestamp)
    /// M-2: Sequence state per sender with wrap-around epoch tracking
    /// Used to reject replayed messages while handling sequence wrap-around
    sequence_state: HashMap<NodeId, SequenceState>,
    /// Maximum global capacity
    capacity: usize,
    /// Maximum messages per sender (H3 security fix)
    max_per_sender: usize,
}

impl SeenMessageCache {
    fn new(capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(capacity),
            queue: VecDeque::with_capacity(capacity),
            sender_counts: HashMap::new(),
            sender_queues: HashMap::new(),
            sequence_state: HashMap::new(),
            capacity,
            max_per_sender: MAX_MESSAGES_PER_SENDER,
        }
    }

    /// M-2: Check if a sequence number is valid with wrap-around handling
    ///
    /// Returns true if this sequence is valid (not a replay).
    /// Handles wrap-around by detecting when a small sequence follows a very large one.
    fn is_sequence_valid(&self, sender: &NodeId, sequence: u64) -> bool {
        match self.sequence_state.get(sender) {
            Some(state) => {
                // M-2: Check for wrap-around detection
                // If current highest is very large and new sequence is very small,
                // this is likely a wrap-around, not a replay
                if state.highest_seq > WRAP_DETECTION_THRESHOLD
                    && sequence < WRAP_DETECTION_THRESHOLD
                {
                    // Appears to be a wrap-around - accept if sequence > 0
                    // The update_highest_seq will handle epoch increment
                    sequence > 0
                } else {
                    // Normal case: sequence must be strictly greater
                    sequence > state.highest_seq
                }
            }
            None => true, // No state for this sender yet, accept any sequence > 0
        }
    }

    /// M-2: Update the highest sequence seen from a sender with wrap-around handling
    ///
    /// Should be called after accepting a valid message.
    /// Detects wrap-around and increments epoch accordingly.
    fn update_highest_seq(&mut self, sender: &NodeId, sequence: u64) {
        self.sequence_state
            .entry(*sender)
            .and_modify(|state| {
                // M-2: Detect wrap-around
                if state.highest_seq > WRAP_DETECTION_THRESHOLD
                    && sequence < WRAP_DETECTION_THRESHOLD
                {
                    // Sequence wrapped around - increment epoch and reset
                    state.epoch = state.epoch.saturating_add(1);
                    debug!(
                        sender = %hex::encode(&sender[..8]),
                        old_seq = state.highest_seq,
                        new_seq = sequence,
                        epoch = state.epoch,
                        "Sequence wrap-around detected"
                    );
                }
                state.highest_seq = state.highest_seq.max(sequence);
            })
            .or_insert(SequenceState {
                highest_seq: sequence,
                epoch: 0,
            });
    }

    /// Check if a message has been seen
    fn contains(&self, id: &MessageId) -> bool {
        self.map.contains_key(id)
    }

    /// SEC-P2P-6: Evict the oldest sender to make room for new ones
    ///
    /// Finds the sender whose most recent message is oldest and removes them entirely.
    fn evict_oldest_sender(&mut self) {
        // Find sender with oldest last message timestamp
        let oldest_sender = self
            .sender_queues
            .iter()
            .filter_map(|(id, queue)| queue.back().map(|(_, ts)| (*id, *ts)))
            .min_by_key(|(_, ts)| *ts)
            .map(|(id, _)| id);

        if let Some(sender) = oldest_sender {
            // Remove all messages from this sender
            if let Some(queue) = self.sender_queues.remove(&sender) {
                for (seq, _) in queue {
                    let id = MessageId {
                        sender,
                        sequence: seq,
                    };
                    self.map.remove(&id);
                }
            }
            self.sender_counts.remove(&sender);
            self.sequence_state.remove(&sender);

            // Note: We don't clean the global queue here for efficiency
            // It will be cleaned up naturally during normal eviction
            debug!(
                sender = %hex::encode(&sender[..8]),
                "Evicted oldest sender from seen message cache"
            );
        }
    }

    /// Insert a message, evicting oldest if at capacity
    ///
    /// H3 security fix: Uses per-sender tracking to prevent cache flushing attacks.
    /// A malicious sender flooding messages can only evict their own entries,
    /// not messages from other legitimate senders.
    fn insert(&mut self, id: MessageId, timestamp: u64) {
        // If already present, don't add again (duplicate)
        if self.map.contains_key(&id) {
            return;
        }

        // SEC-P2P-7: Limit unique senders to prevent memory exhaustion
        if !self.sender_counts.contains_key(&id.sender)
            && self.sender_counts.len() >= MAX_UNIQUE_SENDERS
        {
            self.evict_oldest_sender();
        }

        // H3: Check per-sender limit first
        let sender_count = self.sender_counts.entry(id.sender).or_insert(0);
        if *sender_count >= self.max_per_sender {
            // Evict oldest message from THIS sender only
            if let Some(sender_queue) = self.sender_queues.get_mut(&id.sender) {
                if let Some((old_seq, _)) = sender_queue.pop_front() {
                    let old_id = MessageId {
                        sender: id.sender,
                        sequence: old_seq,
                    };
                    if self.map.remove(&old_id).is_some() {
                        *sender_count = sender_count.saturating_sub(1);
                    }
                }
            }
        }

        // Global capacity check (defense in depth)
        while self.queue.len() >= self.capacity {
            if let Some(old_id) = self.queue.pop_front() {
                if self.map.remove(&old_id).is_some() {
                    if let Some(count) = self.sender_counts.get_mut(&old_id.sender) {
                        *count = count.saturating_sub(1);
                    }
                }
            }
        }

        // Insert new entry
        self.map.insert(id, timestamp);
        self.queue.push_back(id);

        // Track per-sender
        *self.sender_counts.entry(id.sender).or_insert(0) += 1;
        self.sender_queues
            .entry(id.sender)
            .or_default()
            .push_back((id.sequence, timestamp));
    }

    /// Remove entries older than the given timestamp
    fn cleanup_older_than(&mut self, cutoff_timestamp: u64) {
        // Remove from front of queue while entries are older than cutoff
        while let Some(&id) = self.queue.front() {
            if let Some(&ts) = self.map.get(&id) {
                if ts < cutoff_timestamp {
                    self.queue.pop_front();
                    if self.map.remove(&id).is_some() {
                        if let Some(count) = self.sender_counts.get_mut(&id.sender) {
                            *count = count.saturating_sub(1);
                        }
                    }
                } else {
                    // Queue is ordered by insertion time, so we can stop
                    break;
                }
            } else {
                // Entry was already removed, just pop from queue
                self.queue.pop_front();
            }
        }

        // Also cleanup per-sender queues
        for (sender_id, sender_queue) in self.sender_queues.iter_mut() {
            while let Some(&(_, ts)) = sender_queue.front() {
                if ts < cutoff_timestamp {
                    sender_queue.pop_front();
                } else {
                    break;
                }
            }
            // Update count to match actual queue length
            if let Some(count) = self.sender_counts.get_mut(sender_id) {
                *count = sender_queue.len();
            }
        }

        // Remove empty sender entries to prevent unbounded growth of sender tracking
        self.sender_counts.retain(|_, &mut count| count > 0);
        self.sender_queues.retain(|_, queue| !queue.is_empty());

        // L-2: Also clean sequence_state for senders with no remaining messages
        // This prevents unbounded growth of the sequence_state HashMap
        let active_senders: std::collections::HashSet<_> =
            self.sender_queues.keys().copied().collect();
        self.sequence_state
            .retain(|sender, _| active_senders.contains(sender));
    }

    fn len(&self) -> usize {
        self.map.len()
    }
}

impl MeshNetwork {
    /// Create a new mesh network
    pub fn new(identity: Arc<NodeIdentity>, config: MeshConfig) -> Self {
        let our_node_id = identity.node_id();
        let peers = Arc::new(PeerManager::new(our_node_id, config.max_peers));

        // Create message channels
        let (outbound_tx, outbound_rx) = mpsc::channel(1000);
        let (inbound_tx, inbound_rx) = mpsc::channel(1000);

        // C-1: Initialize Noise connection pool if enabled
        let noise_pool = if config.noise_enabled {
            match Self::init_noise_pool(&config) {
                Ok(pool) => {
                    info!(
                        public_key = %pool.public_key_hex(),
                        "Noise Protocol enabled for encrypted P2P"
                    );
                    Some(Arc::new(pool))
                }
                Err(e) => {
                    error!(error = %e, "Failed to initialize Noise pool");
                    if config.noise_required {
                        panic!("Noise is required but failed to initialize: {}", e);
                    }
                    warn!("Falling back to plaintext P2P (Noise disabled)");
                    None
                }
            }
        } else {
            None
        };

        Self {
            identity,
            config: config.clone(),
            peers,
            sequence: AtomicU64::new(0),
            seen_messages: RwLock::new(SeenMessageCache::new(config.max_seen_messages)),
            handlers: RwLock::new(Vec::new()),
            running: AtomicBool::new(false),
            outbound_tx,
            outbound_rx: RwLock::new(Some(outbound_rx)),
            inbound_tx,
            inbound_rx: RwLock::new(Some(inbound_rx)),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            validation_stats: RwLock::new(ValidationStats::default()),
            noise_pool,
        }
    }

    /// Initialize the Noise connection pool
    fn init_noise_pool(
        config: &MeshConfig,
    ) -> Result<NoiseConnectionPool, crate::noise::NoiseError> {
        use crate::noise::{NoiseConfig, NoiseKeypair};

        // Load or generate keypair
        let keypair = if let Some(ref path) = config.noise_keypair_path {
            if path.exists() {
                // Load existing keypair
                let hex = std::fs::read_to_string(path).map_err(crate::noise::NoiseError::Io)?;
                NoiseKeypair::from_hex(hex.trim())?
            } else {
                // Generate and save new keypair
                let kp = NoiseKeypair::generate();
                if let Err(e) = std::fs::write(path, hex::encode(kp.private_key())) {
                    warn!(path = ?path, error = %e, "Failed to save Noise keypair");
                } else {
                    info!(path = ?path, "Generated and saved new Noise keypair");
                }
                kp
            }
        } else {
            // Ephemeral keypair
            debug!("Using ephemeral Noise keypair (not persisted)");
            NoiseKeypair::generate()
        };

        let noise_config = NoiseConfig {
            enabled: config.noise_enabled,
            required: config.noise_required,
            keypair_file: config
                .noise_keypair_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            trusted_peers: Vec::new(), // Accept all peers initially
            allow_unknown_peers: true,
        };

        let pool_config = NoisePoolConfig {
            noise: noise_config,
            ..Default::default()
        };

        NoiseConnectionPool::new(keypair, pool_config)
    }

    /// Register a message handler
    pub fn register_handler(&self, handler: Arc<dyn MessageHandler>) {
        self.handlers.write().push(handler);
    }

    /// Get peer manager
    pub fn peers(&self) -> &Arc<PeerManager> {
        &self.peers
    }

    /// Add a peer
    pub fn add_peer(&self, peer: Peer) {
        self.peers.upsert_peer(peer);
    }

    /// Remove a peer
    pub fn remove_peer(&self, node_id: &NodeId) {
        self.peers.remove_peer(node_id);
    }

    /// M-14: Maximum sequence number before wrapping
    /// We use a high threshold to detect approaching overflow
    const MAX_SEQUENCE: u64 = u64::MAX - 1_000_000;

    /// Get next sequence number
    /// M-14: Uses saturating arithmetic to prevent overflow
    fn next_sequence(&self) -> u64 {
        loop {
            let current = self.sequence.load(Ordering::SeqCst);
            // M-14: Prevent overflow by wrapping around if we approach MAX
            // This is safe because sequence validation also checks monotonicity per-sender
            let next = if current >= Self::MAX_SEQUENCE {
                warn!("Sequence number approaching overflow, wrapping to 1");
                1 // Reset to 1 (not 0, as 0 could be a special value)
            } else {
                current.saturating_add(1)
            };

            if self
                .sequence
                .compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return next;
            }
            // Another thread modified sequence, retry
        }
    }

    /// Check if message is duplicate or has invalid sequence (H-P2P-4)
    ///
    /// Returns true if the message should be rejected because:
    /// 1. We've already seen this exact (sender, sequence) pair, OR
    /// 2. The sequence is <= the highest sequence we've seen from this sender
    ///
    /// This prevents replay attacks where old messages are re-sent.
    fn is_duplicate(&self, msg_id: MessageId) -> bool {
        let seen = self.seen_messages.read();
        // Check both exact duplicate AND sequence monotonicity (H-P2P-4)
        seen.contains(&msg_id) || !seen.is_sequence_valid(&msg_id.sender, msg_id.sequence)
    }

    /// Mark message as seen (P2P-L1: O(1) insertion with automatic eviction)
    /// Also updates highest sequence tracking for H-P2P-4
    fn mark_seen(&self, msg_id: MessageId) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut seen = self.seen_messages.write();
        seen.insert(msg_id, now);
        // H-P2P-4: Update highest sequence tracking
        seen.update_highest_seq(&msg_id.sender, msg_id.sequence);
    }

    /// Create a message envelope
    pub fn create_envelope<T: serde::Serialize>(
        &self,
        msg_type: MessageType,
        payload: &T,
    ) -> GhostResult<MessageEnvelope> {
        let payload_bytes =
            serde_json::to_vec(payload).map_err(|e| GhostError::Serialization(e.to_string()))?;

        let sequence = self.next_sequence();

        // Sign the payload + sequence (verifier expects both)
        let mut signed_data = payload_bytes.clone();
        signed_data.extend_from_slice(&sequence.to_le_bytes());
        let signature = self.identity.sign(&signed_data);

        Ok(MessageEnvelope::new(
            msg_type,
            self.identity.node_id(),
            payload_bytes,
            sequence,
            signature,
        ))
    }

    /// Broadcast a message to all peers
    pub async fn broadcast(&self, envelope: MessageEnvelope) -> GhostResult<usize> {
        let peers = self.peers.get_connected_peers(60);
        let mut sent = 0;

        for peer in peers {
            if peer.node_id == self.identity.node_id() {
                continue; // Don't send to ourselves
            }

            match self.send_to_peer(&peer, &envelope).await {
                Ok(_) => sent += 1,
                Err(e) => {
                    warn!(
                        peer = %peer.node_id_short(),
                        error = %e,
                        "Failed to send to peer"
                    );
                }
            }
        }

        debug!(
            msg_type = ?envelope.msg_type,
            sent = sent,
            "Broadcast message"
        );

        Ok(sent)
    }

    /// Broadcast a typed message to all peers
    ///
    /// Creates an envelope with proper signing and broadcasts to all connected peers.
    pub async fn broadcast_message<T: serde::Serialize>(
        &self,
        msg_type: MessageType,
        payload: &T,
    ) -> GhostResult<usize> {
        let envelope = self.create_envelope(msg_type, payload)?;
        self.broadcast(envelope).await
    }

    /// C-1: Check if a message type should use encrypted Noise channels
    ///
    /// Sensitive messages go over Noise TCP, broadcast messages stay on ZMQ.
    fn should_use_noise(&self, msg_type: MessageType) -> bool {
        if self.noise_pool.is_none() {
            return false;
        }

        match msg_type {
            // Broadcast messages stay on ZMQ (need broadcast for discovery)
            MessageType::Discovery | MessageType::HealthPing => false,

            // Sensitive messages use Noise encryption
            MessageType::ShareProof
            | MessageType::ShareConvergence
            | MessageType::BlockFound
            | MessageType::Vote
            | MessageType::PayoutProposal
            | MessageType::ElderUpdate
            | MessageType::ZkBlockProposal
            | MessageType::ZkVote
            | MessageType::ZkPayoutProposal
            | MessageType::ZkPayoutVote
            | MessageType::VerificationResult
            | MessageType::EquivocationProof
            | MessageType::ElderRegistrationProposal
            | MessageType::ElderListProposal
            | MessageType::ElderListApproval
            | MessageType::MpcContribution
            | MessageType::MpcVerificationVote
            | MessageType::MpcParametersRequest
            | MessageType::MpcParametersResponse => true,
        }
    }

    /// C-1: Send message via Noise-encrypted channel to a specific peer
    ///
    /// Establishes or reuses an encrypted connection to the peer.
    pub async fn send_encrypted(&self, peer: &Peer, envelope: &MessageEnvelope) -> GhostResult<()> {
        let pool = self
            .noise_pool
            .as_ref()
            .ok_or_else(|| GhostError::P2PMessage("Noise not enabled".into()))?;

        // Serialize the envelope
        let data = envelope
            .serialize()
            .map_err(|e| GhostError::Serialization(e.to_string()))?;

        // Parse peer address for Noise port
        let host = peer
            .public_address
            .split(':')
            .next()
            .unwrap_or(&peer.public_address);
        let noise_addr: std::net::SocketAddr = format!("{}:{}", host, self.config.noise_port)
            .parse()
            .map_err(|e| GhostError::P2PMessage(format!("Invalid peer address: {}", e)))?;

        // Get or establish Noise connection
        let conn = pool
            .get_connection(noise_addr)
            .await
            .map_err(|e| GhostError::P2PMessage(format!("Noise connection failed: {}", e)))?;

        // Send encrypted
        conn.send(&data)
            .await
            .map_err(|e| GhostError::P2PMessage(format!("Noise send failed: {}", e)))?;

        debug!(
            peer = %peer.node_id_short(),
            msg_type = ?envelope.msg_type,
            bytes = data.len(),
            "Sent encrypted message via Noise"
        );

        self.messages_sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// C-1: Broadcast message via encrypted Noise channels to all peers
    ///
    /// For sensitive messages, this uses point-to-point encryption to each peer.
    pub async fn broadcast_encrypted(
        &self,
        envelope: &MessageEnvelope,
    ) -> GhostResult<BroadcastResult> {
        let pool = self
            .noise_pool
            .as_ref()
            .ok_or_else(|| GhostError::P2PMessage("Noise not enabled".into()))?;

        let peers = self.peers.get_connected_peers(60);
        let mut result = BroadcastResult::default();

        // Serialize once for all peers
        let data = envelope
            .serialize()
            .map_err(|e| GhostError::Serialization(e.to_string()))?;

        for peer in peers {
            if peer.node_id == self.identity.node_id() {
                continue; // Don't send to ourselves
            }

            // Parse peer address
            let host = peer
                .public_address
                .split(':')
                .next()
                .unwrap_or(&peer.public_address);
            let noise_addr: std::net::SocketAddr = match format!(
                "{}:{}",
                host, self.config.noise_port
            )
            .parse()
            {
                Ok(addr) => addr,
                Err(e) => {
                    warn!(peer = %peer.node_id_short(), error = %e, "Invalid peer address for Noise");
                    result.failed += 1;
                    continue;
                }
            };

            // Get or establish Noise connection
            match pool.get_connection(noise_addr).await {
                Ok(conn) => {
                    match conn.send(&data).await {
                        Ok(_) => {
                            result.success += 1;
                            self.messages_sent.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            warn!(peer = %peer.node_id_short(), error = %e, "Noise send failed");
                            result.failed += 1;
                            // Remove broken connection
                            pool.remove_connection(&conn.peer_key);
                        }
                    }
                }
                Err(e) => {
                    debug!(peer = %peer.node_id_short(), error = %e, "Noise connection failed");
                    result.failed += 1;
                }
            }
        }

        debug!(
            msg_type = ?envelope.msg_type,
            success = result.success,
            failed = result.failed,
            "Encrypted broadcast complete"
        );

        Ok(result)
    }

    /// C-1: Smart broadcast - uses Noise for sensitive messages, ZMQ for broadcast
    ///
    /// This is the recommended method for broadcasting messages. It automatically
    /// chooses the appropriate transport:
    /// - Discovery/Health pings: ZMQ broadcast (need to reach unknown peers)
    /// - Sensitive data: Noise encrypted point-to-point
    pub async fn smart_broadcast(&self, envelope: MessageEnvelope) -> GhostResult<usize> {
        if self.should_use_noise(envelope.msg_type) {
            // Use Noise for sensitive messages
            match self.broadcast_encrypted(&envelope).await {
                Ok(result) => Ok(result.success),
                Err(e) if !self.config.noise_required => {
                    // Fall back to ZMQ if Noise fails and not required
                    warn!(error = %e, "Noise broadcast failed, falling back to ZMQ");
                    self.broadcast(envelope).await
                }
                Err(e) => Err(e),
            }
        } else {
            // Use ZMQ for broadcast messages
            self.broadcast(envelope).await
        }
    }

    /// Get the Noise connection pool (if enabled)
    pub fn noise_pool(&self) -> Option<&Arc<NoiseConnectionPool>> {
        self.noise_pool.as_ref()
    }

    /// Send a message to a specific peer
    pub async fn send_to_peer(&self, peer: &Peer, envelope: &MessageEnvelope) -> GhostResult<()> {
        if !self.running.load(Ordering::SeqCst) {
            return Err(GhostError::NotRunning("Mesh network not running".into()));
        }

        // Serialize the envelope
        let data = envelope
            .serialize()
            .map_err(|e| GhostError::Serialization(e.to_string()))?;

        // Construct the endpoint based on message type
        let endpoint = self.endpoint_for_message(&peer.public_address, envelope.msg_type);

        debug!(
            peer = %peer.node_id_short(),
            msg_type = ?envelope.msg_type,
            endpoint = %endpoint,
            bytes = data.len(),
            "Sending message to peer"
        );

        // Queue for async send
        self.outbound_tx
            .send((endpoint, data))
            .await
            .map_err(|e| GhostError::P2PMessage(format!("Failed to queue message: {}", e)))?;

        self.messages_sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Get the endpoint for a message type
    fn endpoint_for_message(&self, host: &str, msg_type: MessageType) -> String {
        // Extract just the host if it includes a port
        let host_only = host.split(':').next().unwrap_or(host);

        let base_port = match msg_type {
            MessageType::ShareProof | MessageType::ShareConvergence => {
                self.config.ports.share_propagation
            }
            MessageType::BlockFound => self.config.ports.block_announcement,
            MessageType::Vote => self.config.ports.consensus_voting,
            MessageType::HealthPing => self.config.ports.health_monitoring,
            MessageType::Discovery => self.config.ports.discovery,
            MessageType::ElderUpdate => self.config.ports.elder_management,
            // P2P-C1/C2/C3: Elder registration messages use elder management port
            MessageType::ElderRegistrationProposal
            | MessageType::ElderListProposal
            | MessageType::ElderListApproval
            // MPC ceremony messages also use elder management port
            | MessageType::MpcContribution
            | MessageType::MpcVerificationVote
            | MessageType::MpcParametersRequest
            | MessageType::MpcParametersResponse => self.config.ports.elder_management,
            MessageType::PayoutProposal => self.config.ports.payout_proposal,
            // ZK-BFT messages use consensus voting port
            MessageType::ZkBlockProposal
            | MessageType::ZkVote
            | MessageType::ZkPayoutProposal
            | MessageType::ZkPayoutVote => self.config.ports.consensus_voting,
            // Verification results use health monitoring port
            MessageType::VerificationResult => self.config.ports.health_monitoring,
            // P2P-H3: Equivocation proofs use consensus voting port
            MessageType::EquivocationProof => self.config.ports.consensus_voting,
        };
        format!("tcp://{}:{}", host_only, base_port)
    }

    /// Handle a received message with full validation and signature verification
    pub async fn handle_received(&self, data: &[u8]) -> GhostResult<()> {
        // Use the full validation pipeline including signature verification
        let envelope = match validate_and_verify(data) {
            Ok(env) => env,
            Err(e) => {
                // Update stats and log the rejection
                let mut stats = self.validation_stats.write();
                stats.record(&Err(e.clone()));

                // Log ALL validation failures for diagnostics
                info!(
                    error = %e,
                    data_len = data.len(),
                    "DIAG: Message validation failed"
                );
                return Err(GhostError::P2PMessage(e.to_string()));
            }
        };

        // Record successful validation
        {
            let mut stats = self.validation_stats.write();
            stats.record(&Ok(envelope.clone()));
        }

        // Log verification messages for P2P debugging
        if matches!(envelope.msg_type, MessageType::VerificationResult) {
            let sender_hex = hex::encode(envelope.sender);
            info!(
                sender = %&sender_hex[..8],
                msg_type = ?envelope.msg_type,
                "DIAG: Message validated successfully"
            );
        }

        // Check for duplicate
        let msg_id = MessageId {
            sender: envelope.sender,
            sequence: envelope.sequence,
        };

        if self.is_duplicate(msg_id) {
            tracing::trace!(
                sender = %hex::encode(&envelope.sender[..8]),
                msg_type = ?envelope.msg_type,
                sequence = envelope.sequence,
                "Ignoring duplicate message"
            );
            return Ok(());
        }

        self.mark_seen(msg_id);

        // Update peer last seen
        self.peers.update_last_seen(&envelope.sender);

        // Dispatch to handlers
        let handlers = self.handlers.read().clone();
        for handler in handlers {
            if let Err(e) = handler.handle_message(envelope.clone()).await {
                error!(error = %e, "Handler error");
            }
        }

        Ok(())
    }

    /// Get validation statistics for monitoring
    pub fn validation_stats(&self) -> ValidationStats {
        self.validation_stats.read().clone()
    }

    /// Start the mesh network
    pub async fn start(self: &Arc<Self>) -> GhostResult<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(GhostError::AlreadyRunning(
                "Mesh network already running".into(),
            ));
        }

        info!(
            address = %self.config.public_address,
            ports = ?self.config.ports,
            "Starting mesh network"
        );

        // C-1: Log Noise Protocol status
        if self.config.noise_enabled {
            info!(
                noise_port = self.config.noise_port,
                noise_required = self.config.noise_required,
                "Noise Protocol encryption ENABLED for sensitive P2P traffic"
            );
        } else {
            warn!(
                "P2P transport encryption (Noise Protocol) is DISABLED. \
                 Sensitive messages are sent in plaintext. Set noise_enabled=true for production."
            );
        }

        self.running.store(true, Ordering::SeqCst);

        // Spawn publisher task
        let self_clone = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(e) = self_clone.run_publisher().await {
                error!(error = %e, "Publisher task failed");
            }
        });

        // Spawn subscriber task
        let self_clone = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(e) = self_clone.run_subscriber().await {
                error!(error = %e, "Subscriber task failed");
            }
        });

        // Spawn message handler task
        let self_clone = Arc::clone(self);
        tokio::spawn(async move {
            self_clone.run_message_handler().await;
        });

        // Spawn health ping task
        let self_clone = Arc::clone(self);
        tokio::spawn(async move {
            self_clone.run_health_pinger().await;
        });

        // Spawn cleanup task
        let self_clone = Arc::clone(self);
        tokio::spawn(async move {
            self_clone.run_cleanup_task().await;
        });

        info!("Mesh network started successfully");
        Ok(())
    }

    /// Run the publisher (sends outbound messages)
    async fn run_publisher(&self) -> GhostResult<()> {
        use tmq::AsZmqSocket;

        // Create PUB socket using tmq with shared context - bind first port
        let mut pub_socket = publish(&ZMQ_CONTEXT)
            .bind(&format!(
                "tcp://0.0.0.0:{}",
                self.config.ports.share_propagation
            ))
            .map_err(|e| {
                GhostError::P2PMessage(format!("Failed to bind share_propagation: {}", e))
            })?;

        // Bind additional ports using the underlying zmq socket
        let additional_ports = [
            (self.config.ports.block_announcement, "block_announcement"),
            (self.config.ports.consensus_voting, "consensus_voting"),
            (self.config.ports.health_monitoring, "health_monitoring"),
            (self.config.ports.discovery, "discovery"),
            (self.config.ports.elder_management, "elder_management"),
            (self.config.ports.payout_proposal, "payout_proposal"),
            (self.config.ports.payout_transaction, "payout_transaction"),
        ];

        for (port, name) in additional_ports {
            let endpoint = format!("tcp://0.0.0.0:{}", port);
            pub_socket
                .get_socket()
                .bind(&endpoint)
                .map_err(|e| GhostError::P2PMessage(format!("Failed to bind {}: {}", name, e)))?;
        }

        info!(
            ports = ?self.config.ports,
            "Bound PUB socket to all ports"
        );

        // Take the receiver from the RwLock
        let mut outbound_rx = self
            .outbound_rx
            .write()
            .take()
            .ok_or_else(|| GhostError::Internal("Outbound receiver already taken".into()))?;

        // Process outbound messages
        while self.running.load(Ordering::SeqCst) {
            match tokio::time::timeout(std::time::Duration::from_millis(100), outbound_rx.recv())
                .await
            {
                Ok(Some((_endpoint, data))) => {
                    // Extract topic from the serialized envelope
                    let (topic, msg_type_str) = match MessageEnvelope::deserialize(&data) {
                        Ok(env) => {
                            let topic = env.topic().to_vec();
                            let msg_type = format!("{:?}", env.msg_type);
                            (topic, msg_type)
                        }
                        Err(_) => {
                            // Fallback to generic topic if deserialization fails
                            warn!("Failed to deserialize envelope for topic extraction");
                            (b"msg".to_vec(), "Unknown".to_string())
                        }
                    };

                    // Send as single-frame ZMQ message with topic prefix for filtering
                    // Format: [topic + payload] in a single frame
                    let mut prefixed_data = topic.clone();
                    prefixed_data.extend_from_slice(&data);
                    let msg = Multipart::from(vec![prefixed_data]);

                    if let Err(e) = pub_socket.send(msg).await {
                        warn!(error = %e, msg_type = %msg_type_str, "Failed to send ZMQ message");
                    }
                }
                Ok(None) => break,  // Channel closed
                Err(_) => continue, // Timeout, check running state
            }
        }

        info!("Publisher task stopped");
        Ok(())
    }

    /// Run subscriber (receives messages from peers)
    ///
    /// Uses tmq with libzmq's built-in reconnection support via ZMQ_RECONNECT_IVL
    /// and ZMQ_RECONNECT_IVL_MAX socket options. No manual watchdog needed.
    async fn run_subscriber(&self) -> GhostResult<()> {
        use tmq::AsZmqSocket;

        info!("Starting mesh subscriber task");

        // Create SUB socket with tmq - we need to bind/connect to at least one endpoint
        // to create the socket, then we can add more endpoints dynamically.
        // We'll use a dummy inproc endpoint that we create just to bootstrap the socket.
        let dummy_endpoint = format!("inproc://mesh-sub-bootstrap-{}", std::process::id());

        // P2P4-5: Subscribe to specific known topics only (not empty filter)
        // This prevents processing of unknown/malicious topic prefixes
        use crate::message::topics;

        // bind() returns SubscribeWithoutTopic, then subscribe() returns Subscribe (which implements Stream)
        // P2P4-5: Subscribe to specific known topics only (not empty filter)
        // First subscribe() converts SubscribeWithoutTopic -> Subscribe, then we add more topics
        let mut sub_socket = subscribe(&ZMQ_CONTEXT)
            .set_reconnect_ivl(100) // Initial reconnect interval: 100ms
            .set_reconnect_ivl_max(5000) // Max reconnect interval: 5 seconds
            .bind(&dummy_endpoint)
            .map_err(|e| GhostError::P2PMessage(format!("Failed to create SUB socket: {}", e)))?
            .subscribe(topics::SHARE)
            .map_err(|e| GhostError::P2PMessage(format!("Failed to subscribe to share: {}", e)))?;

        // P2P4-5: Subscribe to remaining topics using mutable Subscribe reference
        // After the first subscribe(), we have a Subscribe struct that takes &mut self
        let additional_topics: &[(&[u8], &str)] = &[
            (topics::BLOCK, "block"),
            (topics::VOTE, "vote"),
            (topics::HEALTH, "health"),
            (topics::DISCOVERY, "discovery"),
            (topics::ELDER, "elder"),
            (topics::PAYOUT_PROPOSAL, "payout_proposal"),
            (topics::ZK_PROPOSAL, "zk_proposal"),
            (topics::ZK_VOTE, "zk_vote"),
            (topics::ZK_PAYOUT_PROPOSAL, "zk_payout_proposal"),
            (topics::ZK_PAYOUT_VOTE, "zk_payout_vote"),
            (topics::VERIFICATION, "verification"),
        ];

        for (topic, name) in additional_topics {
            sub_socket.subscribe(topic).map_err(|e| {
                GhostError::P2PMessage(format!("Failed to subscribe to {}: {}", name, e))
            })?;
        }

        info!("DIAG: SUB socket created with reconnection support (ivl=100ms, max=5000ms)");

        // Track which peers we've attempted to connect to
        let mut connected_addresses: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        // P2P4-L6: Track connection state for exponential backoff
        let mut connection_states: std::collections::HashMap<String, PeerConnectionState> =
            std::collections::HashMap::new();

        // Track message receive stats for debugging
        let mut last_stats_log = std::time::Instant::now();
        let mut receive_attempts: u64 = 0;
        let mut receive_timeouts: u64 = 0;
        let mut receive_errors: u64 = 0;

        while self.running.load(Ordering::SeqCst) {
            // Get ALL peers (not just connected ones) - we need to attempt connection first
            let peers = self.peers.get_all_peers();

            // Connect to any new peers using the underlying ZMQ socket
            for peer in peers {
                // Skip if we've already tried this address
                // Extract host from public_address (may be "host:port" or just "host")
                // Normalize to just the host for deduplication
                let host = peer
                    .public_address
                    .split(':')
                    .next()
                    .unwrap_or(&peer.public_address)
                    .to_string();

                // Skip if we've already connected to this host
                if connected_addresses.contains(&host) {
                    continue;
                }

                // M-P2P-4: Evict oldest entry if at capacity (LRU eviction)
                if connection_states.len() >= MAX_CONNECTION_STATES {
                    // Remove oldest entry (one with earliest last_attempt)
                    if let Some(oldest_key) = connection_states
                        .iter()
                        .min_by_key(|(_, state)| state.last_attempt)
                        .map(|(k, _)| k.clone())
                    {
                        connection_states.remove(&oldest_key);
                        debug!(
                            evicted = %oldest_key,
                            "Evicted oldest connection state (LRU)"
                        );
                    }
                }

                // P2P4-L6: Check backoff state before attempting connection
                let conn_state = connection_states
                    .entry(host.clone())
                    .or_insert_with(PeerConnectionState::new);
                if !conn_state.can_retry() {
                    debug!(
                        host = %host,
                        backoff_ms = conn_state.backoff_ms,
                        failures = conn_state.consecutive_failures,
                        "Skipping connection attempt (backoff)"
                    );
                    continue;
                }

                // Connect to all message type ports
                let ports = [
                    self.config.ports.share_propagation,
                    self.config.ports.block_announcement,
                    self.config.ports.consensus_voting,
                    self.config.ports.health_monitoring,
                    self.config.ports.discovery,
                    self.config.ports.elder_management,
                    self.config.ports.payout_proposal,
                    self.config.ports.payout_transaction,
                ];

                let mut connected_any = false;
                for port in ports {
                    let endpoint = format!("tcp://{}:{}", host, port);
                    // Use the underlying zmq socket to connect dynamically
                    match sub_socket.get_socket().connect(&endpoint) {
                        Ok(_) => {
                            debug!(endpoint = %endpoint, "Connected SUB socket");
                            connected_any = true;
                        }
                        Err(e) => {
                            debug!(endpoint = %endpoint, error = %e, "Failed to connect SUB socket");
                        }
                    }
                }

                if connected_any {
                    info!(
                        host = %host,
                        total_connected = connected_addresses.len() + 1,
                        "DIAG: SUB socket connected to peer on all ports (libzmq handles reconnection)"
                    );
                    connected_addresses.insert(host.clone());
                    // P2P4-L6: Reset backoff on success
                    if let Some(state) = connection_states.get_mut(&host) {
                        state.record_success();
                    }
                } else {
                    // P2P4-L6: Record failure and increase backoff
                    if let Some(state) = connection_states.get_mut(&host) {
                        state.record_failure();
                        warn!(
                            host = %host,
                            backoff_ms = state.backoff_ms,
                            failures = state.consecutive_failures,
                            "Failed to connect SUB socket to peer (will retry with backoff)"
                        );
                    }
                }
            }

            // Log stats every 30 seconds
            if last_stats_log.elapsed() > std::time::Duration::from_secs(30) {
                let total_received = self.messages_received.load(Ordering::Relaxed);
                info!(
                    connected_peers = connected_addresses.len(),
                    receive_attempts,
                    receive_timeouts,
                    receive_errors,
                    total_received,
                    "DIAG: SUB socket stats"
                );
                last_stats_log = std::time::Instant::now();
            }

            // Try to receive a message using StreamExt::next()
            receive_attempts += 1;
            match tokio::time::timeout(std::time::Duration::from_millis(100), sub_socket.next())
                .await
            {
                Ok(Some(Ok(msg))) => {
                    // ZMQ message with topic prefix - tmq returns Multipart
                    let raw_data: Vec<u8> = msg
                        .into_iter()
                        .flat_map(|frame: tmq::Message| frame.to_vec())
                        .collect();

                    if raw_data.is_empty() {
                        debug!("Received empty ZMQ message");
                        continue;
                    }

                    // Find where the payload starts (after the topic)
                    // Topics are known fixed strings: health, share, block, vote, discovery, elder, payout
                    use crate::message::topics;
                    let known_topics: &[(&str, &[u8])] = &[
                        ("health", topics::HEALTH),
                        ("share", topics::SHARE),
                        ("block", topics::BLOCK),
                        ("vote", topics::VOTE),
                        ("discovery", topics::DISCOVERY),
                        ("elder", topics::ELDER),
                        ("payout", topics::PAYOUT_PROPOSAL),
                        ("verify", topics::VERIFICATION),
                    ];

                    let (topic_name, data): (&str, Vec<u8>) = {
                        let mut found: Option<(&str, Vec<u8>)> = None;
                        for (name, topic_bytes) in known_topics {
                            if raw_data.starts_with(topic_bytes) {
                                found = Some((*name, raw_data[topic_bytes.len()..].to_vec()));
                                break;
                            }
                        }
                        found.unwrap_or(("unknown", raw_data))
                    };

                    // M-P2P-1: Validate topic matches envelope's msg_type
                    // Skip messages where the topic doesn't match the declared message type
                    if let Ok(envelope) = MessageEnvelope::deserialize(&data) {
                        let expected_topic = envelope.msg_type.topic_str();
                        if topic_name != expected_topic {
                            warn!(
                                received_topic = topic_name,
                                expected_topic = expected_topic,
                                msg_type = ?envelope.msg_type,
                                "Topic mismatch: received on '{}', envelope says '{:?}' (expected topic '{}')",
                                topic_name, envelope.msg_type, expected_topic
                            );
                            continue; // Skip this message
                        }
                    }

                    // Log verification messages for P2P debugging
                    if topic_name == "verify" {
                        info!(
                            topic = topic_name,
                            data_len = data.len(),
                            "DIAG: SUB received verification message"
                        );
                    }

                    self.messages_received.fetch_add(1, Ordering::Relaxed);

                    if let Err(e) = self.inbound_tx.send(data).await {
                        warn!(error = %e, "Failed to queue inbound message");
                    }
                }
                Ok(Some(Err(e))) => {
                    receive_errors += 1;
                    debug!(error = %e, "Receive error");
                }
                Ok(None) => {
                    // Stream ended (shouldn't happen with ZMQ)
                    warn!("SUB socket stream ended unexpectedly");
                    break;
                }
                Err(_) => {
                    receive_timeouts += 1;
                    continue; // Timeout
                }
            }
        }

        info!("Subscriber task stopped");
        Ok(())
    }

    /// Run the message handler (dispatches to registered handlers)
    async fn run_message_handler(&self) {
        // Take the receiver
        let mut inbound_rx = match self.inbound_rx.write().take() {
            Some(rx) => rx,
            None => {
                error!("Inbound receiver already taken");
                return;
            }
        };

        while self.running.load(Ordering::SeqCst) {
            match tokio::time::timeout(std::time::Duration::from_millis(100), inbound_rx.recv())
                .await
            {
                Ok(Some(data)) => {
                    if let Err(e) = self.handle_received(&data).await {
                        debug!(error = %e, "Failed to handle message");
                    }
                }
                Ok(None) => break,
                Err(_) => continue,
            }
        }

        info!("Message handler task stopped");
    }

    /// Run health pinger task
    async fn run_health_pinger(&self) {
        let interval = std::time::Duration::from_secs(self.config.health_ping_interval_secs);

        while self.running.load(Ordering::SeqCst) {
            tokio::time::sleep(interval).await;

            // Create and broadcast health ping with actual node capabilities
            // Include PoW proof for Sybil resistance
            let pow_proof = self.identity.pow_proof().map(|p| (p.nonce, p.difficulty));
            let ping = ghost_common::types::HealthPing {
                node_id: self.identity.node_id(),
                public_address: self.config.public_address.clone(),
                block_height: 0, // Would track actual height
                round_id: 0,     // Would track current round
                capabilities: self.config.capabilities,
                miner_count: self.peers.peer_count() as u32,
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
                pow_proof,
            };

            match self.create_envelope(
                MessageType::HealthPing,
                &crate::message::HealthPingMessage { ping },
            ) {
                Ok(envelope) => {
                    if let Err(e) = self.broadcast(envelope).await {
                        debug!(error = %e, "Failed to broadcast health ping");
                    } else {
                        debug!(peers = self.peers.peer_count(), "Broadcast health ping");
                    }
                }
                Err(e) => {
                    debug!(error = %e, "Failed to create health ping envelope");
                }
            }
        }

        info!("Health pinger task stopped");
    }

    /// Run cleanup task (removes old seen messages)
    async fn run_cleanup_task(&self) {
        let interval = std::time::Duration::from_secs(60);

        while self.running.load(Ordering::SeqCst) {
            tokio::time::sleep(interval).await;
            self.cleanup_seen_messages(self.config.dedup_window_secs);
        }

        info!("Cleanup task stopped");
    }

    /// Stop the mesh network
    pub async fn stop(&self) -> GhostResult<()> {
        info!("Stopping mesh network");
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get mesh statistics
    pub fn stats(&self) -> MeshStats {
        MeshStats {
            total_peers: self.peers.peer_count(),
            connected_peers: self.peers.connected_count(),
            elder_peers: self.peers.get_elder_peers().len(),
            messages_sent: self.messages_sent.load(Ordering::Relaxed),
            messages_received: self.messages_received.load(Ordering::Relaxed),
            seen_message_count: self.seen_messages.read().len(),
        }
    }

    /// Clean up old seen messages (P2P-L1: O(k) where k is number of expired entries)
    pub fn cleanup_seen_messages(&self, max_age_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = now.saturating_sub(max_age_secs);

        let mut seen = self.seen_messages.write();
        let before_len = seen.len();
        seen.cleanup_older_than(cutoff);
        let after_len = seen.len();

        if before_len != after_len {
            debug!(
                remaining = after_len,
                removed = before_len - after_len,
                "Cleaned up seen messages"
            );
        }
    }

    /// Connect to a peer
    pub async fn connect_peer(&self, address: &str) -> GhostResult<()> {
        info!(address = %address, "Connecting to peer");

        // Generate a temporary node ID from the address hash
        // (actual node ID will be learned from first health ping received)
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        address.hash(&mut hasher);
        let hash = hasher.finish();
        let mut temp_node_id = [0u8; 32];
        temp_node_id[..8].copy_from_slice(&hash.to_le_bytes());
        temp_node_id[8..16].copy_from_slice(&hash.to_be_bytes());

        // Create a new peer entry - mark as Connected initially
        // (stale detection will mark disconnected if we don't hear from them)
        let mut peer = Peer::new(temp_node_id, address.to_string());
        peer.state = crate::peer::PeerState::Connected;
        self.peers.upsert_peer(peer);

        Ok(())
    }

    /// Disconnect from a peer
    pub async fn disconnect_peer(&self, node_id: &NodeId) -> GhostResult<()> {
        info!(node_id = %hex::encode(node_id), "Disconnecting peer");
        self.peers.mark_disconnected(node_id);
        Ok(())
    }

    /// Get our node ID
    pub fn node_id(&self) -> NodeId {
        self.identity.node_id()
    }

    /// Get outbound sender for external use
    pub fn outbound_sender(&self) -> mpsc::Sender<(String, Vec<u8>)> {
        self.outbound_tx.clone()
    }

    /// Broadcast a raw message synchronously (non-blocking, best-effort)
    ///
    /// This queues the message for broadcast without waiting. Used for callbacks
    /// that cannot be async. Returns Ok if the message was queued successfully.
    pub fn broadcast_sync(&self, msg_type: MessageType, payload: Vec<u8>) -> GhostResult<()> {
        if !self.running.load(Ordering::SeqCst) {
            return Err(GhostError::NotRunning("Mesh network not running".into()));
        }

        let sequence = self.next_sequence();

        // Sign the payload + sequence (must match create_envelope for P2P4-M1 verification)
        let mut signed_data = payload.clone();
        signed_data.extend_from_slice(&sequence.to_le_bytes());
        let signature = self.identity.sign(&signed_data);

        // Create envelope
        let envelope = MessageEnvelope::new(
            msg_type,
            self.identity.node_id(),
            payload,
            sequence,
            signature,
        );

        // Serialize envelope
        let data = envelope
            .serialize()
            .map_err(|e| GhostError::Serialization(e.to_string()))?;

        // Get all connected peers and try to queue messages
        let peers = self.peers.get_connected_peers(60);
        let total_peers = self.peers.peer_count();
        let connected_count = peers.len();

        info!(
            msg_type = ?msg_type,
            total_peers = total_peers,
            connected_peers = connected_count,
            "Broadcasting message"
        );

        let mut queued = 0;

        for peer in peers {
            if peer.node_id == self.identity.node_id() {
                continue;
            }

            let endpoint = self.endpoint_for_message(&peer.public_address, msg_type);
            info!(endpoint = %endpoint, peer = %peer.node_id_short(), "Sending to peer");

            // Use try_send for non-blocking queue
            match self.outbound_tx.try_send((endpoint, data.clone())) {
                Ok(_) => queued += 1,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!(peer = %peer.node_id_short(), "Outbound queue full");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(GhostError::NotRunning("Outbound channel closed".into()));
                }
            }
        }

        self.messages_sent
            .fetch_add(queued as u64, Ordering::Relaxed);

        info!(
            msg_type = ?msg_type,
            queued = queued,
            "Queued sync broadcast"
        );

        Ok(())
    }
}

/// Mesh network statistics
#[derive(Debug, Clone, Default)]
pub struct MeshStats {
    pub total_peers: usize,
    pub connected_peers: usize,
    pub elder_peers: usize,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub seen_message_count: usize,
}

/// C-1: Result of an encrypted broadcast operation
#[derive(Debug, Clone, Default)]
pub struct BroadcastResult {
    /// Number of peers successfully sent to
    pub success: usize,
    /// Number of peers that failed
    pub failed: usize,
}

/// Builder for constructing ZMQ endpoints
pub struct EndpointBuilder {
    host: String,
    ports: P2PPortConfig,
}

impl EndpointBuilder {
    pub fn new(host: String, ports: P2PPortConfig) -> Self {
        Self { host, ports }
    }

    pub fn share_propagation(&self) -> String {
        format!("tcp://{}:{}", self.host, self.ports.share_propagation)
    }

    pub fn block_announcement(&self) -> String {
        format!("tcp://{}:{}", self.host, self.ports.block_announcement)
    }

    pub fn consensus_voting(&self) -> String {
        format!("tcp://{}:{}", self.host, self.ports.consensus_voting)
    }

    pub fn health_monitoring(&self) -> String {
        format!("tcp://{}:{}", self.host, self.ports.health_monitoring)
    }

    pub fn discovery(&self) -> String {
        format!("tcp://{}:{}", self.host, self.ports.discovery)
    }

    pub fn elder_management(&self) -> String {
        format!("tcp://{}:{}", self.host, self.ports.elder_management)
    }

    pub fn payout_proposal(&self) -> String {
        format!("tcp://{}:{}", self.host, self.ports.payout_proposal)
    }

    pub fn payout_transaction(&self) -> String {
        format!("tcp://{}:{}", self.host, self.ports.payout_transaction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_builder() {
        let ports = P2PPortConfig::default();
        let builder = EndpointBuilder::new("127.0.0.1".to_string(), ports);

        assert!(builder.share_propagation().contains("8555"));
        assert!(builder.block_announcement().contains("8556"));
    }

    #[test]
    fn test_message_deduplication() {
        let identity = Arc::new(NodeIdentity::generate());
        let config = MeshConfig::default();
        let mesh = MeshNetwork::new(identity, config);

        let msg_id = MessageId {
            sender: [1u8; 32],
            sequence: 1,
        };

        assert!(!mesh.is_duplicate(msg_id));
        mesh.mark_seen(msg_id);
        assert!(mesh.is_duplicate(msg_id));
    }

    #[test]
    fn test_seen_message_cache_eviction() {
        // Test with small capacity to verify FIFO eviction
        let mut cache = SeenMessageCache::new(3);

        let id1 = MessageId {
            sender: [1u8; 32],
            sequence: 1,
        };
        let id2 = MessageId {
            sender: [2u8; 32],
            sequence: 2,
        };
        let id3 = MessageId {
            sender: [3u8; 32],
            sequence: 3,
        };
        let id4 = MessageId {
            sender: [4u8; 32],
            sequence: 4,
        };

        // Insert 3 messages (at capacity)
        cache.insert(id1, 1000);
        cache.insert(id2, 1001);
        cache.insert(id3, 1002);

        assert!(cache.contains(&id1));
        assert!(cache.contains(&id2));
        assert!(cache.contains(&id3));
        assert_eq!(cache.len(), 3);

        // Insert 4th message - should evict oldest (id1)
        cache.insert(id4, 1003);

        assert!(!cache.contains(&id1), "id1 should have been evicted");
        assert!(cache.contains(&id2));
        assert!(cache.contains(&id3));
        assert!(cache.contains(&id4));
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn test_seen_message_cache_cleanup() {
        let mut cache = SeenMessageCache::new(10);

        let id1 = MessageId {
            sender: [1u8; 32],
            sequence: 1,
        };
        let id2 = MessageId {
            sender: [2u8; 32],
            sequence: 2,
        };
        let id3 = MessageId {
            sender: [3u8; 32],
            sequence: 3,
        };

        // Insert with different timestamps
        cache.insert(id1, 1000); // old
        cache.insert(id2, 1500); // old
        cache.insert(id3, 2000); // new

        assert_eq!(cache.len(), 3);

        // Cleanup entries older than 1600
        cache.cleanup_older_than(1600);

        assert!(!cache.contains(&id1), "id1 should have been cleaned up");
        assert!(!cache.contains(&id2), "id2 should have been cleaned up");
        assert!(cache.contains(&id3), "id3 should still exist");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_seen_message_cache_duplicate_insert() {
        let mut cache = SeenMessageCache::new(10);

        let id1 = MessageId {
            sender: [1u8; 32],
            sequence: 1,
        };

        cache.insert(id1, 1000);
        cache.insert(id1, 1001); // Duplicate - should not increase count

        assert_eq!(cache.len(), 1);
        assert!(cache.contains(&id1));
    }

    #[test]
    fn test_seen_message_cache_per_sender_limit() {
        // H3 security test: Verify per-sender limits prevent cache flushing attacks
        let mut cache = SeenMessageCache::new(100);
        // Override max_per_sender for testing
        cache.max_per_sender = 3;

        let sender1 = [1u8; 32];
        let sender2 = [2u8; 32];

        // Sender 1 inserts 3 messages (at their limit)
        for i in 0..3 {
            let id = MessageId {
                sender: sender1,
                sequence: i,
            };
            cache.insert(id, 1000 + i);
        }

        // Sender 2 inserts 2 messages
        for i in 0..2 {
            let id = MessageId {
                sender: sender2,
                sequence: i,
            };
            cache.insert(id, 2000 + i);
        }

        assert_eq!(cache.len(), 5);

        // All sender1 messages should exist
        for i in 0..3 {
            assert!(cache.contains(&MessageId {
                sender: sender1,
                sequence: i
            }));
        }
        // All sender2 messages should exist
        for i in 0..2 {
            assert!(cache.contains(&MessageId {
                sender: sender2,
                sequence: i
            }));
        }

        // Now sender1 sends another message (exceeds their limit)
        let new_msg = MessageId {
            sender: sender1,
            sequence: 10,
        };
        cache.insert(new_msg, 3000);

        // Sender1's OLDEST message should be evicted, not sender2's messages!
        assert!(
            !cache.contains(&MessageId {
                sender: sender1,
                sequence: 0
            }),
            "Sender1's oldest message should be evicted"
        );
        assert!(
            cache.contains(&MessageId {
                sender: sender1,
                sequence: 1
            }),
            "Sender1's newer messages should remain"
        );
        assert!(
            cache.contains(&MessageId {
                sender: sender1,
                sequence: 2
            }),
            "Sender1's newer messages should remain"
        );
        assert!(
            cache.contains(&new_msg),
            "Sender1's new message should be present"
        );

        // Sender2's messages should be UNAFFECTED
        assert!(
            cache.contains(&MessageId {
                sender: sender2,
                sequence: 0
            }),
            "Sender2's messages should be unaffected"
        );
        assert!(
            cache.contains(&MessageId {
                sender: sender2,
                sequence: 1
            }),
            "Sender2's messages should be unaffected"
        );

        // Total should still be 5 (sender1: 3, sender2: 2)
        assert_eq!(cache.len(), 5);
    }

    #[test]
    fn test_sequence_monotonicity_validation() {
        // H-P2P-4: Test that old sequence numbers are rejected
        let mut cache = SeenMessageCache::new(100);
        let sender = [1u8; 32];

        // Insert message with sequence 10
        let id1 = MessageId {
            sender,
            sequence: 10,
        };
        cache.insert(id1, 1000);
        cache.update_highest_seq(&sender, 10);

        // Sequence 11 should be valid (greater than highest)
        assert!(cache.is_sequence_valid(&sender, 11));

        // Sequence 10 should be invalid (equal to highest - replay)
        assert!(!cache.is_sequence_valid(&sender, 10));

        // Sequence 5 should be invalid (less than highest - old message replay)
        assert!(!cache.is_sequence_valid(&sender, 5));

        // Insert message with sequence 20, update highest
        let id2 = MessageId {
            sender,
            sequence: 20,
        };
        cache.insert(id2, 1001);
        cache.update_highest_seq(&sender, 20);

        // Sequence 15 should now be invalid (less than new highest of 20)
        assert!(!cache.is_sequence_valid(&sender, 15));

        // Sequence 21 should be valid
        assert!(cache.is_sequence_valid(&sender, 21));
    }

    #[test]
    fn test_sequence_validation_different_senders() {
        // H-P2P-4: Sequence tracking is per-sender
        let mut cache = SeenMessageCache::new(100);
        let sender1 = [1u8; 32];
        let sender2 = [2u8; 32];

        // Sender1 at sequence 100
        cache.update_highest_seq(&sender1, 100);

        // Sender2 at sequence 5
        cache.update_highest_seq(&sender2, 5);

        // Sender1's sequence 50 should be invalid (less than 100)
        assert!(!cache.is_sequence_valid(&sender1, 50));

        // Sender2's sequence 50 should be valid (greater than 5)
        assert!(cache.is_sequence_valid(&sender2, 50));

        // New sender (sender3) should accept any sequence
        let sender3 = [3u8; 32];
        assert!(cache.is_sequence_valid(&sender3, 1));
        assert!(cache.is_sequence_valid(&sender3, 1000));
    }

    #[test]
    fn test_mesh_deduplication_with_sequence_check() {
        // H-P2P-4: Integration test - MeshNetwork should reject old sequences
        let identity = Arc::new(NodeIdentity::generate());
        let config = MeshConfig::default();
        let mesh = MeshNetwork::new(identity, config);

        let sender = [1u8; 32];

        // First message with sequence 10 should not be duplicate
        let msg1 = MessageId {
            sender,
            sequence: 10,
        };
        assert!(!mesh.is_duplicate(msg1));
        mesh.mark_seen(msg1);

        // Same message should now be duplicate
        assert!(mesh.is_duplicate(msg1));

        // Message with sequence 5 (old) should be rejected as duplicate
        // even though we haven't seen this exact (sender, seq) pair
        let msg_old = MessageId {
            sender,
            sequence: 5,
        };
        assert!(
            mesh.is_duplicate(msg_old),
            "Old sequence should be rejected"
        );

        // Message with sequence 11 (new) should not be duplicate
        let msg_new = MessageId {
            sender,
            sequence: 11,
        };
        assert!(
            !mesh.is_duplicate(msg_new),
            "New sequence should be accepted"
        );
    }
}
