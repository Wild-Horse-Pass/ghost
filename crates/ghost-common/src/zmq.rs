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

use futures::StreamExt;
use once_cell::sync::Lazy;
use tmq::{subscribe, Context};
use tokio::sync::broadcast;
use tracing::{error, info, warn};

/// Shared ZMQ context for all sockets
static ZMQ_CONTEXT: Lazy<Context> = Lazy::new(Context::new);

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
    /// # Errors
    ///
    /// Returns `ZmqSecurityError` if a non-localhost endpoint is provided.
    /// Connecting to remote ZMQ without authentication is a critical security flaw.
    pub fn new(config: ZmqConfig) -> Result<Self, ZmqSecurityError> {
        // SECURITY: Validate all endpoints are localhost
        Self::validate_config(&config)?;

        let (block_tx, _) = broadcast::channel(1000);
        let (tx_tx, _) = broadcast::channel(10000);
        let (block_event_tx, _) = broadcast::channel(1000);
        let (shutdown_tx, _) = broadcast::channel(1);

        let subscriber = Ok(Self {
            block_tx: block_tx.clone(),
            tx_tx: tx_tx.clone(),
            block_event_tx: block_event_tx.clone(),
            shutdown_tx: shutdown_tx.clone(),
        });

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
    ///
    /// Uses tmq with libzmq's built-in reconnection support.
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

        // Create ZMQ socket with tmq
        // Order: context -> options -> connect -> subscribe (returns Subscribe which implements Stream)
        let mut socket = match subscribe(&ZMQ_CONTEXT)
            .set_reconnect_ivl(100) // Initial reconnect interval: 100ms
            .set_reconnect_ivl_max(5000) // Max reconnect interval: 5 seconds
            .connect(endpoint)
            .and_then(|s| s.subscribe(topic.as_bytes()))
        {
            Ok(s) => s,
            Err(e) => {
                error!(
                    "Failed to create subscriber for {} on {}: {}",
                    topic, endpoint, e
                );
                return;
            }
        };

        info!(
            "ZMQ subscriber connected to {} for topic {} (libzmq handles reconnection)",
            endpoint, topic
        );

        // Message loop
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("ZMQ subscriber shutting down");
                    break;
                }
                result = socket.next() => {
                    match result {
                        Some(Ok(msg)) => {
                            // ZMQ message format: [topic, body, sequence]
                            // tmq returns Multipart - collect frames as Vec<Message>
                            let frames: Vec<tmq::Message> = msg.into_iter().collect();
                            if frames.len() >= 2 {
                                let data = &frames[1];
                                handler(data.as_ref());
                            }
                        }
                        Some(Err(e)) => {
                            warn!("ZMQ receive error: {}", e);
                        }
                        None => {
                            warn!("ZMQ socket stream ended unexpectedly");
                            break;
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
    ///
    /// Uses tmq with libzmq's built-in reconnection support.
    async fn run_sequence_subscriber(
        endpoint: &str,
        block_event_tx: broadcast::Sender<BlockEvent>,
        shutdown_rx: &mut broadcast::Receiver<()>,
    ) {
        info!(
            "Connecting ZMQ subscriber to {} for sequence (reorg detection)",
            endpoint
        );

        // Create socket with tmq - connect then subscribe (returns Subscribe which implements Stream)
        let mut socket = match subscribe(&ZMQ_CONTEXT)
            .set_reconnect_ivl(100)
            .set_reconnect_ivl_max(5000)
            .connect(endpoint)
            .and_then(|s| s.subscribe(b"sequence"))
        {
            Ok(s) => s,
            Err(e) => {
                error!(
                    "Failed to create sequence subscriber on {}: {}",
                    endpoint, e
                );
                return;
            }
        };

        info!(
            "ZMQ sequence subscriber connected for reorg detection (libzmq handles reconnection)"
        );

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("ZMQ sequence subscriber shutting down");
                    break;
                }
                result = socket.next() => {
                    match result {
                        Some(Ok(msg)) => {
                            // tmq returns Multipart - collect frames as Vec<Message>
                            let frames: Vec<tmq::Message> = msg.into_iter().collect();
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
                        Some(Err(e)) => {
                            warn!("ZMQ sequence receive error: {}", e);
                        }
                        None => {
                            warn!("ZMQ sequence socket stream ended unexpectedly");
                            break;
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
    ///
    /// # Errors
    ///
    /// Returns `ZmqSecurityError` if the endpoint is not localhost.
    pub fn new(hashblock_endpoint: &str) -> Result<Self, ZmqSecurityError> {
        Self::with_sequence(hashblock_endpoint, None)
    }

    /// Create a block watcher with explicit sequence endpoint for reorg detection
    ///
    /// # Errors
    ///
    /// Returns `ZmqSecurityError` if any endpoint is not localhost.
    pub fn with_sequence(
        hashblock_endpoint: &str,
        sequence_endpoint: Option<&str>,
    ) -> Result<Self, ZmqSecurityError> {
        let config = ZmqConfig {
            hashblock_endpoint: Some(hashblock_endpoint.to_string()),
            hashtx_endpoint: None,
            rawblock_endpoint: None,
            rawtx_endpoint: None,
            sequence_endpoint: sequence_endpoint.map(|s| s.to_string()),
        };

        Ok(Self {
            subscriber: ZmqSubscriber::new(config)?,
        })
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

    #[test]
    fn test_localhost_endpoint_validation() {
        // Valid localhost endpoints
        assert!(is_localhost_endpoint("tcp://127.0.0.1:28332"));
        assert!(is_localhost_endpoint("tcp://localhost:28332"));
        assert!(is_localhost_endpoint("tcp://[::1]:28332"));

        // Invalid remote endpoints
        assert!(!is_localhost_endpoint("tcp://192.168.1.1:28332"));
        assert!(!is_localhost_endpoint("tcp://10.0.0.1:28332"));
        assert!(!is_localhost_endpoint("tcp://example.com:28332"));
    }

    #[test]
    fn test_zmq_subscriber_rejects_remote_endpoint() {
        let config = ZmqConfig {
            hashblock_endpoint: Some("tcp://192.168.1.100:28332".to_string()),
            hashtx_endpoint: None,
            rawblock_endpoint: None,
            rawtx_endpoint: None,
            sequence_endpoint: None,
        };

        let result = ZmqSubscriber::new(config);
        assert!(result.is_err());
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("Expected error but got Ok"),
        };
        assert!(err.0.contains("192.168.1.100"));
        assert!(err.0.contains("not localhost"));
    }

    #[test]
    fn test_zmq_subscriber_rejects_all_remote_endpoints() {
        // Test each endpoint type
        let test_cases = [
            (
                "hashblock",
                ZmqConfig {
                    hashblock_endpoint: Some("tcp://10.0.0.1:28332".to_string()),
                    hashtx_endpoint: None,
                    rawblock_endpoint: None,
                    rawtx_endpoint: None,
                    sequence_endpoint: None,
                },
            ),
            (
                "hashtx",
                ZmqConfig {
                    hashblock_endpoint: None,
                    hashtx_endpoint: Some("tcp://10.0.0.1:28333".to_string()),
                    rawblock_endpoint: None,
                    rawtx_endpoint: None,
                    sequence_endpoint: None,
                },
            ),
            (
                "sequence",
                ZmqConfig {
                    hashblock_endpoint: None,
                    hashtx_endpoint: None,
                    rawblock_endpoint: None,
                    rawtx_endpoint: None,
                    sequence_endpoint: Some("tcp://10.0.0.1:28334".to_string()),
                },
            ),
        ];

        for (name, config) in test_cases {
            let result = ZmqSubscriber::new(config);
            assert!(result.is_err(), "Expected {} endpoint to be rejected", name);
        }
    }

    #[test]
    fn test_block_watcher_rejects_remote_endpoint() {
        let result = BlockWatcher::new("tcp://192.168.1.100:28332");
        assert!(result.is_err());

        let result =
            BlockWatcher::with_sequence("tcp://127.0.0.1:28332", Some("tcp://192.168.1.100:28334"));
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_config_success() {
        let config = ZmqConfig::default();
        assert!(ZmqSubscriber::validate_config(&config).is_ok());
    }

    #[test]
    fn test_validate_config_failure() {
        let config = ZmqConfig {
            hashblock_endpoint: Some("tcp://evil.attacker.com:28332".to_string()),
            hashtx_endpoint: None,
            rawblock_endpoint: None,
            rawtx_endpoint: None,
            sequence_endpoint: None,
        };
        let result = ZmqSubscriber::validate_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().0.contains("evil.attacker.com"));
    }
}
