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
//| FILE: zmq.rs                                                                                                         |
//|======================================================================================================================|

//! ZMQ subscriber for Bitcoin Core notifications
//!
//! Subscribes to Bitcoin Core's ZMQ notifications for new blocks and transactions.
//!
//! # Security Note
//!
//! ZMQ PUB/SUB does NOT support authentication in this implementation.
//! The zeromq crate used here does not implement CURVE authentication.
//!
//! **SECURITY REQUIREMENT**: Only connect to ZMQ endpoints on localhost (127.0.0.1).
//! Never expose ZMQ ports to the network. If remote block notifications are needed,
//! use an authenticated transport layer (SSH tunnel, VPN, etc.).

use tokio::sync::broadcast;
use tracing::{error, info, warn};
use zeromq::{Socket, SocketRecv};

/// ZMQ notification types
#[derive(Debug, Clone)]
pub enum ZmqNotification {
    /// New block hash
    HashBlock(String),
    /// New transaction hash
    HashTx(String),
    /// Raw block data
    RawBlock(Vec<u8>),
    /// Raw transaction data
    RawTx(Vec<u8>),
    /// Sequence number notification
    Sequence {
        hash: String,
        label: char,
        mempool_seq: u64,
    },
}

/// ZMQ subscriber configuration
#[derive(Debug, Clone)]
pub struct ZmqConfig {
    /// HashBlock endpoint (e.g., "tcp://127.0.0.1:28332")
    pub hashblock_endpoint: Option<String>,
    /// HashTx endpoint (e.g., "tcp://127.0.0.1:28333")
    pub hashtx_endpoint: Option<String>,
    /// RawBlock endpoint
    pub rawblock_endpoint: Option<String>,
    /// RawTx endpoint
    pub rawtx_endpoint: Option<String>,
    /// Sequence endpoint for reorg detection (e.g., "tcp://127.0.0.1:28334")
    pub sequence_endpoint: Option<String>,
}

impl Default for ZmqConfig {
    fn default() -> Self {
        Self {
            hashblock_endpoint: Some("tcp://127.0.0.1:28332".to_string()),
            hashtx_endpoint: Some("tcp://127.0.0.1:28333".to_string()),
            rawblock_endpoint: None,
            rawtx_endpoint: None,
            sequence_endpoint: Some("tcp://127.0.0.1:28334".to_string()),
        }
    }
}

/// Block event type for reorg detection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockEvent {
    /// Block connected to the main chain
    Connected { hash: String },
    /// Block disconnected from the main chain (reorg)
    Disconnected { hash: String },
}

/// ZMQ subscriber handle
pub struct ZmqSubscriber {
    /// Block notification sender
    block_tx: broadcast::Sender<String>,
    /// Transaction notification sender
    tx_tx: broadcast::Sender<String>,
    /// Block event sender (for reorg detection via sequence topic)
    block_event_tx: broadcast::Sender<BlockEvent>,
    /// Shutdown signal
    shutdown_tx: broadcast::Sender<()>,
}

/// Check if a ZMQ endpoint is localhost (safe to use without authentication)
fn is_localhost_endpoint(endpoint: &str) -> bool {
    endpoint.contains("://127.0.0.1")
        || endpoint.contains("://localhost")
        || endpoint.contains("://[::1]")
}

/// ZMQ security error
#[derive(Debug, Clone)]
pub struct ZmqSecurityError(pub String);

impl std::fmt::Display for ZmqSecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ZMQ security error: {}", self.0)
    }
}

impl std::error::Error for ZmqSecurityError {}

impl ZmqSubscriber {
    /// Create a new ZMQ subscriber
    ///
    /// # Security
    ///
    /// Only localhost endpoints are allowed. ZMQ does not support authentication
    /// in this implementation, so remote endpoints would allow anyone to inject
    /// fake block notifications.
    ///
    /// # Panics
    ///
    /// Panics if a non-localhost endpoint is provided. This is intentional -
    /// connecting to remote ZMQ without authentication is a critical security flaw.
    pub fn new(config: ZmqConfig) -> Self {
        // SECURITY: Validate all endpoints are localhost
        let endpoints = [
            &config.hashblock_endpoint,
            &config.hashtx_endpoint,
            &config.rawblock_endpoint,
            &config.rawtx_endpoint,
            &config.sequence_endpoint,
        ];
        for opt_endpoint in &endpoints {
            if let Some(endpoint) = opt_endpoint {
                if !is_localhost_endpoint(endpoint) {
                    panic!(
                        "ZMQ SECURITY ERROR: Non-localhost endpoint '{}' is not allowed. \
                         ZMQ does not support authentication - remote endpoints would allow \
                         attackers to inject fake block notifications. Use localhost only, \
                         or tunnel through SSH/VPN.",
                        endpoint
                    );
                }
            }
        }

        let (block_tx, _) = broadcast::channel(1000);
        let (tx_tx, _) = broadcast::channel(10000);
        let (block_event_tx, _) = broadcast::channel(1000);
        let (shutdown_tx, _) = broadcast::channel(1);

        let subscriber = Self {
            block_tx: block_tx.clone(),
            tx_tx: tx_tx.clone(),
            block_event_tx: block_event_tx.clone(),
            shutdown_tx: shutdown_tx.clone(),
        };

        // Spawn hashblock subscriber
        if let Some(endpoint) = config.hashblock_endpoint {
            let block_tx = block_tx.clone();
            let mut shutdown_rx = shutdown_tx.subscribe();

            tokio::spawn(async move {
                Self::run_subscriber(
                    &endpoint,
                    "hashblock",
                    move |data| {
                        let hash = hex::encode(data);
                        let _ = block_tx.send(hash);
                    },
                    &mut shutdown_rx,
                )
                .await;
            });
        }

        // Spawn hashtx subscriber
        if let Some(endpoint) = config.hashtx_endpoint {
            let tx_tx = tx_tx.clone();
            let mut shutdown_rx = shutdown_tx.subscribe();

            tokio::spawn(async move {
                Self::run_subscriber(
                    &endpoint,
                    "hashtx",
                    move |data| {
                        let hash = hex::encode(data);
                        let _ = tx_tx.send(hash);
                    },
                    &mut shutdown_rx,
                )
                .await;
            });
        }

        // Spawn sequence subscriber for reorg detection
        // Sequence messages have format: [hash (32 bytes), label (1 byte 'C' or 'D'), sequence (8 bytes)]
        // 'C' = block Connected, 'D' = block Disconnected (reorg)
        if let Some(endpoint) = config.sequence_endpoint {
            let block_event_tx = block_event_tx.clone();
            let mut shutdown_rx = shutdown_tx.subscribe();

            tokio::spawn(async move {
                Self::run_sequence_subscriber(&endpoint, block_event_tx, &mut shutdown_rx).await;
            });
        }

        subscriber
    }

    /// Validate ZMQ configuration for security
    ///
    /// Returns an error if any endpoint is not localhost.
    pub fn validate_config(config: &ZmqConfig) -> Result<(), ZmqSecurityError> {
        for (name, endpoint) in [
            ("hashblock", &config.hashblock_endpoint),
            ("hashtx", &config.hashtx_endpoint),
            ("rawblock", &config.rawblock_endpoint),
            ("rawtx", &config.rawtx_endpoint),
            ("sequence", &config.sequence_endpoint),
        ] {
            if let Some(ep) = endpoint {
                if !is_localhost_endpoint(ep) {
                    return Err(ZmqSecurityError(format!(
                        "{} endpoint '{}' is not localhost. \
                         ZMQ authentication is not supported - use localhost only.",
                        name, ep
                    )));
                }
            }
        }
        Ok(())
    }

    /// Subscribe to block notifications
    pub fn subscribe_blocks(&self) -> broadcast::Receiver<String> {
        self.block_tx.subscribe()
    }

    /// Subscribe to transaction notifications
    pub fn subscribe_transactions(&self) -> broadcast::Receiver<String> {
        self.tx_tx.subscribe()
    }

    /// Subscribe to block events (connect/disconnect for reorg detection)
    pub fn subscribe_block_events(&self) -> broadcast::Receiver<BlockEvent> {
        self.block_event_tx.subscribe()
    }

    /// Shutdown the subscriber
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Run a ZMQ subscriber loop
    async fn run_subscriber<F>(
        endpoint: &str,
        topic: &str,
        handler: F,
        shutdown_rx: &mut broadcast::Receiver<()>,
    ) where
        F: Fn(&[u8]) + Send + 'static,
    {
        info!(
            "Connecting ZMQ subscriber to {} for topic {}",
            endpoint, topic
        );

        // Create ZMQ socket
        let mut socket = zeromq::SubSocket::new();

        // Subscribe to topic
        if let Err(e) = socket.subscribe(topic).await {
            error!("Failed to subscribe to {}: {}", topic, e);
            return;
        }

        // Connect to endpoint
        if let Err(e) = socket.connect(endpoint).await {
            error!("Failed to connect to {}: {}", endpoint, e);
            return;
        }

        info!(
            "ZMQ subscriber connected to {} for topic {}",
            endpoint, topic
        );

        // Message loop
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("ZMQ subscriber shutting down");
                    break;
                }
                result = socket.recv() => {
                    match result {
                        Ok(msg) => {
                            // ZMQ message format: [topic, body, sequence]
                            let frames: Vec<_> = msg.into_vec();
                            if frames.len() >= 2 {
                                let data = &frames[1];
                                handler(data.as_ref());
                            }
                        }
                        Err(e) => {
                            warn!("ZMQ receive error: {}", e);
                        }
                    }
                }
            }
        }
    }

    /// Run the sequence subscriber for reorg detection
    ///
    /// Bitcoin Core sequence messages have format:
    /// - hash: 32 bytes (block hash, little-endian)
    /// - label: 1 byte ('C' for connect, 'D' for disconnect, 'R' for remove from mempool, etc.)
    /// - sequence: 8 bytes (uint64 mempool sequence number)
    async fn run_sequence_subscriber(
        endpoint: &str,
        block_event_tx: broadcast::Sender<BlockEvent>,
        shutdown_rx: &mut broadcast::Receiver<()>,
    ) {
        info!(
            "Connecting ZMQ subscriber to {} for sequence (reorg detection)",
            endpoint
        );

        let mut socket = zeromq::SubSocket::new();

        // Subscribe to sequence topic
        if let Err(e) = socket.subscribe("sequence").await {
            error!("Failed to subscribe to sequence: {}", e);
            return;
        }

        if let Err(e) = socket.connect(endpoint).await {
            error!("Failed to connect to sequence endpoint {}: {}", endpoint, e);
            return;
        }

        info!("ZMQ sequence subscriber connected for reorg detection");

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("ZMQ sequence subscriber shutting down");
                    break;
                }
                result = socket.recv() => {
                    match result {
                        Ok(msg) => {
                            let frames: Vec<_> = msg.into_vec();
                            // Format: [topic, hash (32), label (1), sequence (8)]
                            if frames.len() >= 3 {
                                let hash_bytes = &frames[1];
                                let label_bytes = &frames[2];

                                if hash_bytes.len() >= 32 && !label_bytes.is_empty() {
                                    // Reverse hash for display (Bitcoin uses little-endian internally)
                                    let mut hash_arr = [0u8; 32];
                                    hash_arr.copy_from_slice(&hash_bytes[..32]);
                                    hash_arr.reverse();
                                    let hash = hex::encode(hash_arr);

                                    let label = label_bytes[0] as char;

                                    match label {
                                        'C' => {
                                            // Block connected - normal new block
                                            let _ = block_event_tx.send(BlockEvent::Connected { hash: hash.clone() });
                                            info!(hash = %&hash[..16], "Block connected");
                                        }
                                        'D' => {
                                            // Block disconnected - REORG DETECTED!
                                            let _ = block_event_tx.send(BlockEvent::Disconnected { hash: hash.clone() });
                                            warn!(hash = %&hash[..16], "⚠️ REORG DETECTED: Block disconnected!");
                                        }
                                        _ => {
                                            // Other labels: 'R' (removed from mempool), 'A' (added to mempool)
                                            // We only care about block connect/disconnect
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("ZMQ sequence receive error: {}", e);
                        }
                    }
                }
            }
        }
    }
}

impl Drop for ZmqSubscriber {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Simple block watcher that uses ZMQ to detect new blocks and reorgs
pub struct BlockWatcher {
    subscriber: ZmqSubscriber,
}

impl BlockWatcher {
    /// Create a new block watcher with reorg detection
    pub fn new(hashblock_endpoint: &str) -> Self {
        Self::with_sequence(hashblock_endpoint, None)
    }

    /// Create a block watcher with explicit sequence endpoint for reorg detection
    pub fn with_sequence(hashblock_endpoint: &str, sequence_endpoint: Option<&str>) -> Self {
        let config = ZmqConfig {
            hashblock_endpoint: Some(hashblock_endpoint.to_string()),
            hashtx_endpoint: None,
            rawblock_endpoint: None,
            rawtx_endpoint: None,
            sequence_endpoint: sequence_endpoint.map(|s| s.to_string()),
        };

        Self {
            subscriber: ZmqSubscriber::new(config),
        }
    }

    /// Get a receiver for new block hashes
    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.subscriber.subscribe_blocks()
    }

    /// Get a receiver for block events (connect/disconnect for reorg detection)
    pub fn subscribe_events(&self) -> broadcast::Receiver<BlockEvent> {
        self.subscriber.subscribe_block_events()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zmq_config_default() {
        let config = ZmqConfig::default();
        assert!(config.hashblock_endpoint.is_some());
        assert!(config.hashtx_endpoint.is_some());
    }
}
