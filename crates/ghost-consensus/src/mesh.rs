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
//! Architecture:
//! - PUB socket for broadcasting messages to peers
//! - SUB sockets for receiving messages from peers
//! - ROUTER/DEALER for request-response patterns

use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use futures::{SinkExt, StreamExt};
use once_cell::sync::Lazy;
use tmq::{publish, subscribe, Context, Multipart};

/// Shared ZMQ context for all sockets (libzmq handles threading internally)
static ZMQ_CONTEXT: Lazy<Context> = Lazy::new(Context::new);

use ghost_common::config::P2PPortConfig;
use ghost_common::error::{GhostError, GhostResult};
use ghost_common::identity::NodeIdentity;
use ghost_common::types::NodeId;

use crate::message::{MessageEnvelope, MessageType};
use crate::message_validator::{validate_and_verify, ValidationStats};
use crate::peer::{Peer, PeerManager};

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
}

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
    /// Seen message IDs (for deduplication)
    seen_messages: RwLock<HashSet<MessageId>>,
    /// Seen message timestamps (for cleanup)
    seen_timestamps: RwLock<HashMap<MessageId, u64>>,
    /// Message handlers
    handlers: RwLock<Vec<Arc<dyn MessageHandler>>>,
    /// Running state
    running: AtomicBool,
    /// Outbound message channel
    outbound_tx: mpsc::Sender<(String, Vec<u8>)>,
    outbound_rx: RwLock<Option<mpsc::Receiver<(String, Vec<u8>)>>>,
    /// Inbound message channel
    inbound_tx: mpsc::Sender<Vec<u8>>,
    inbound_rx: RwLock<Option<mpsc::Receiver<Vec<u8>>>>,
    /// Message statistics
    messages_sent: AtomicU64,
    messages_received: AtomicU64,
    /// Validation statistics for monitoring
    validation_stats: RwLock<ValidationStats>,
}

/// Message identifier for deduplication
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageId {
    pub sender: NodeId,
    pub sequence: u64,
}

impl MeshNetwork {
    /// Create a new mesh network
    pub fn new(identity: Arc<NodeIdentity>, config: MeshConfig) -> Self {
        let our_node_id = identity.node_id();
        let peers = Arc::new(PeerManager::new(our_node_id, config.max_peers));

        // Create message channels
        let (outbound_tx, outbound_rx) = mpsc::channel(1000);
        let (inbound_tx, inbound_rx) = mpsc::channel(1000);

        Self {
            identity,
            config,
            peers,
            sequence: AtomicU64::new(0),
            seen_messages: RwLock::new(HashSet::new()),
            seen_timestamps: RwLock::new(HashMap::new()),
            handlers: RwLock::new(Vec::new()),
            running: AtomicBool::new(false),
            outbound_tx,
            outbound_rx: RwLock::new(Some(outbound_rx)),
            inbound_tx,
            inbound_rx: RwLock::new(Some(inbound_rx)),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            validation_stats: RwLock::new(ValidationStats::default()),
        }
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

    /// Get next sequence number
    fn next_sequence(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Check if message is duplicate
    fn is_duplicate(&self, msg_id: MessageId) -> bool {
        let seen = self.seen_messages.read();
        seen.contains(&msg_id)
    }

    /// Mark message as seen
    fn mark_seen(&self, msg_id: MessageId) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut seen = self.seen_messages.write();
        let mut timestamps = self.seen_timestamps.write();

        // Evict oldest entries if at capacity (prevents unbounded memory growth)
        if seen.len() >= self.config.max_seen_messages {
            // Find and remove oldest 10% of entries
            let to_remove_count = self.config.max_seen_messages / 10;
            let mut entries: Vec<_> = timestamps.iter().map(|(id, ts)| (*id, *ts)).collect();
            entries.sort_by_key(|(_, ts)| *ts);

            for (id, _) in entries.into_iter().take(to_remove_count) {
                seen.remove(&id);
                timestamps.remove(&id);
            }

            debug!(
                removed = to_remove_count,
                remaining = seen.len(),
                "Evicted oldest seen messages to prevent memory exhaustion"
            );
        }

        seen.insert(msg_id);
        timestamps.insert(msg_id, now);
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
            MessageType::PayoutProposal => self.config.ports.payout_proposal,
            // ZK-BFT messages use consensus voting port
            MessageType::ZkBlockProposal
            | MessageType::ZkVote
            | MessageType::ZkPayoutProposal
            | MessageType::ZkPayoutVote => self.config.ports.consensus_voting,
            // Verification results use health monitoring port
            MessageType::VerificationResult => self.config.ports.health_monitoring,
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
            let sender_hex = hex::encode(&envelope.sender);
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
        let mut pub_socket = publish(&*ZMQ_CONTEXT)
            .bind(&format!(
                "tcp://0.0.0.0:{}",
                self.config.ports.share_propagation
            ))
            .map_err(|e| {
                GhostError::P2PMessage(format!(
                    "Failed to bind share_propagation: {}",
                    e
                ))
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
            pub_socket.get_socket().bind(&endpoint).map_err(|e| {
                GhostError::P2PMessage(format!("Failed to bind {}: {}", name, e))
            })?;
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

        // bind() returns SubscribeWithoutTopic, then subscribe() returns Subscribe (which implements Stream)
        let mut sub_socket = subscribe(&*ZMQ_CONTEXT)
            .set_reconnect_ivl(100)      // Initial reconnect interval: 100ms
            .set_reconnect_ivl_max(5000) // Max reconnect interval: 5 seconds
            .bind(&dummy_endpoint)
            .map_err(|e| GhostError::P2PMessage(format!("Failed to create SUB socket: {}", e)))?
            .subscribe(b"")  // Subscribe to all topics (empty filter) - this returns Subscribe
            .map_err(|e| GhostError::P2PMessage(format!("Failed to subscribe: {}", e)))?;

        info!("DIAG: SUB socket created with reconnection support (ivl=100ms, max=5000ms)");

        // Track which peers we've attempted to connect to
        let mut connected_addresses: std::collections::HashSet<String> =
            std::collections::HashSet::new();

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
                    connected_addresses.insert(host);
                } else {
                    warn!(host = %host, "Failed to connect SUB socket to peer");
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
                    let raw_data: Vec<u8> = msg.into_iter().flat_map(|frame: tmq::Message| frame.to_vec()).collect();

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
            let ping = ghost_common::types::HealthPing {
                node_id: self.identity.node_id(),
                public_address: self.config.public_address.clone(),
                block_height: 0, // Would track actual height
                round_id: 0,     // Would track current round
                capabilities: self.config.capabilities.clone(),
                miner_count: self.peers.peer_count() as u32,
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
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

    /// Clean up old seen messages
    pub fn cleanup_seen_messages(&self, max_age_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = now.saturating_sub(max_age_secs);

        let mut seen = self.seen_messages.write();
        let mut timestamps = self.seen_timestamps.write();

        // Collect IDs to remove
        let to_remove: Vec<_> = timestamps
            .iter()
            .filter(|(_, &ts)| ts < cutoff)
            .map(|(id, _)| *id)
            .collect();

        for id in to_remove {
            seen.remove(&id);
            timestamps.remove(&id);
        }

        debug!(
            remaining = seen.len(),
            removed = timestamps.len(),
            "Cleaned up seen messages"
        );
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

        // Sign the payload
        let signature = self.identity.sign(&payload);

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
}
