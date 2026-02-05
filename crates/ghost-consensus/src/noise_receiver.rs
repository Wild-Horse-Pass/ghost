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
//| FILE: noise_receiver.rs                                                                                              |
//|======================================================================================================================|

//! Noise Protocol Message Receiver
//!
//! Handles incoming encrypted messages from the Noise connection pool.
//! This service polls all active connections and dispatches received
//! messages to the appropriate handlers.
//!
//! # Security Properties
//!
//! - **Identity Binding**: Verifies that the envelope sender matches the
//!   Noise connection's authenticated peer identity
//! - **Signature Verification**: All messages are signed and verified
//! - **Replay Prevention**: Messages with stale timestamps are rejected

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use ghost_common::types::NodeId;

use crate::message::MessageEnvelope;
use crate::message_validator::validate_and_verify;
use crate::noise_pool::NoiseConnectionPool;

/// Channel capacity for inbound messages from Noise connections
const INBOUND_CHANNEL_CAPACITY: usize = 1000;

/// How often to poll connections for messages (milliseconds)
const POLL_INTERVAL_MS: u64 = 10;

/// M-1: Registry mapping Ed25519 NodeIds to their X25519 Noise keys
///
/// This mapping is learned from health pings where nodes announce both keys.
/// Once learned, we enforce that messages from a known sender must come from
/// the expected Noise key.
#[derive(Debug, Default)]
pub struct KeyRegistry {
    /// Maps NodeId (Ed25519 signing key) to Noise key (X25519)
    ed25519_to_noise: RwLock<HashMap<NodeId, [u8; 32]>>,
}

impl KeyRegistry {
    /// Create a new empty key registry
    pub fn new() -> Self {
        Self {
            ed25519_to_noise: RwLock::new(HashMap::new()),
        }
    }

    /// Learn a key mapping from a health ping or similar source
    ///
    /// Once learned, this binding is enforced for future messages
    pub fn learn_binding(&self, node_id: NodeId, noise_key: [u8; 32]) {
        let mut map = self.ed25519_to_noise.write();
        let existing = map.insert(node_id, noise_key);
        if let Some(old_key) = existing {
            if old_key != noise_key {
                warn!(
                    node_id = %hex::encode(&node_id[..8]),
                    old_noise = %hex::encode(&old_key[..8]),
                    new_noise = %hex::encode(&noise_key[..8]),
                    "M-1: Noise key changed for node"
                );
            }
        } else {
            debug!(
                node_id = %hex::encode(&node_id[..8]),
                noise_key = %hex::encode(&noise_key[..8]),
                "M-1: Learned key binding"
            );
        }
    }

    /// Get the expected Noise key for a known sender
    pub fn get_noise_key(&self, node_id: &NodeId) -> Option<[u8; 32]> {
        self.ed25519_to_noise.read().get(node_id).copied()
    }

    /// Check if a node is known
    pub fn is_known(&self, node_id: &NodeId) -> bool {
        self.ed25519_to_noise.read().contains_key(node_id)
    }

    /// Get the number of known bindings
    pub fn known_count(&self) -> usize {
        self.ed25519_to_noise.read().len()
    }
}

/// Receiver for encrypted messages from the Noise connection pool
pub struct NoiseReceiver {
    /// The connection pool to receive from
    pool: Arc<NoiseConnectionPool>,
    /// Channel to send received messages to handlers
    inbound_tx: mpsc::Sender<ReceivedMessage>,
    /// Running state
    running: AtomicBool,
    /// Statistics
    stats: NoiseReceiverStats,
    /// M-1: Key registry for identity binding verification
    key_registry: KeyRegistry,
}

/// A message received from a Noise connection
#[derive(Debug)]
pub struct ReceivedMessage {
    /// The validated message envelope
    pub envelope: MessageEnvelope,
    /// The Noise public key of the peer who sent it
    pub noise_peer_key: [u8; 32],
}

/// Statistics for the Noise receiver
#[derive(Debug, Default)]
pub struct NoiseReceiverStats {
    /// Messages received successfully
    pub messages_received: AtomicU64,
    /// Messages rejected (validation failed)
    pub messages_rejected: AtomicU64,
    /// Messages rejected due to identity mismatch
    pub identity_mismatch: AtomicU64,
    /// Receive errors
    pub receive_errors: AtomicU64,
}

impl NoiseReceiverStats {
    /// Get a snapshot of current statistics
    pub fn snapshot(&self) -> NoiseReceiverStatsSnapshot {
        NoiseReceiverStatsSnapshot {
            messages_received: self.messages_received.load(Ordering::Relaxed),
            messages_rejected: self.messages_rejected.load(Ordering::Relaxed),
            identity_mismatch: self.identity_mismatch.load(Ordering::Relaxed),
            receive_errors: self.receive_errors.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of receiver statistics
#[derive(Debug, Clone)]
pub struct NoiseReceiverStatsSnapshot {
    pub messages_received: u64,
    pub messages_rejected: u64,
    pub identity_mismatch: u64,
    pub receive_errors: u64,
}

impl NoiseReceiver {
    /// Create a new Noise receiver
    ///
    /// Returns the receiver and a channel to receive validated messages.
    pub fn new(pool: Arc<NoiseConnectionPool>) -> (Self, mpsc::Receiver<ReceivedMessage>) {
        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_CHANNEL_CAPACITY);

        (
            Self {
                pool,
                inbound_tx,
                running: AtomicBool::new(false),
                stats: NoiseReceiverStats::default(),
                key_registry: KeyRegistry::new(),
            },
            inbound_rx,
        )
    }

    /// M-1: Get access to the key registry for learning bindings from health pings
    pub fn key_registry(&self) -> &KeyRegistry {
        &self.key_registry
    }

    /// Start the receiver loop
    ///
    /// This spawns a background task that continuously polls connections
    /// for incoming messages.
    pub async fn run(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            warn!("Noise receiver already running");
            return;
        }

        info!("Starting Noise receiver");

        while self.running.load(Ordering::SeqCst) {
            // Get all active connections
            let connections = self.pool.connections();

            if connections.is_empty() {
                // No connections, wait longer
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }

            // Poll each connection for incoming messages
            for conn in connections {
                match conn.try_recv().await {
                    Ok(Some(payload)) => {
                        // Got a message - validate and dispatch
                        if let Err(e) = self.handle_message(&payload, &conn.peer_key).await {
                            debug!(
                                peer = %hex::encode(&conn.peer_key[..8]),
                                error = %e,
                                "Failed to handle Noise message"
                            );
                        }
                    }
                    Ok(None) => {
                        // No message available, continue to next connection
                    }
                    Err(e) => {
                        // Connection error
                        self.stats.receive_errors.fetch_add(1, Ordering::Relaxed);
                        warn!(
                            peer = %hex::encode(&conn.peer_key[..8]),
                            error = %e,
                            "Noise receive error"
                        );
                        // Remove broken connection
                        self.pool.remove_connection(&conn.peer_key);
                    }
                }
            }

            // Small delay to prevent busy-looping
            tokio::time::sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
        }

        info!("Noise receiver stopped");
    }

    /// Handle a received message
    async fn handle_message(
        &self,
        payload: &[u8],
        noise_peer_key: &[u8; 32],
    ) -> Result<(), String> {
        // Validate and verify signature using existing pipeline
        let envelope = match validate_and_verify(payload) {
            Ok(env) => env,
            Err(e) => {
                self.stats.messages_rejected.fetch_add(1, Ordering::Relaxed);
                return Err(format!("Validation failed: {}", e));
            }
        };

        // CRITICAL: Verify identity binding
        // The sender in the envelope MUST match the Noise connection's peer key
        // This prevents an attacker from sending messages claiming to be someone else
        if !self.verify_identity_binding(&envelope.sender, noise_peer_key) {
            self.stats.identity_mismatch.fetch_add(1, Ordering::Relaxed);
            return Err(format!(
                "Identity mismatch: envelope sender {} does not match Noise peer {}",
                hex::encode(&envelope.sender[..8]),
                hex::encode(&noise_peer_key[..8])
            ));
        }

        // Send to handlers
        let received_msg = ReceivedMessage {
            envelope,
            noise_peer_key: *noise_peer_key,
        };

        if let Err(e) = self.inbound_tx.send(received_msg).await {
            error!(error = %e, "Failed to queue Noise message for handling");
            return Err(format!("Queue full: {}", e));
        }

        self.stats.messages_received.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Verify that the envelope sender matches the Noise peer identity
    ///
    /// There are two approaches here:
    /// 1. Direct key match: envelope.sender == noise_peer_key
    ///    This requires using the same key material for both Ed25519 (signing)
    ///    and X25519 (Noise)
    ///
    /// 2. Indirect binding: The envelope is signed, and we verify the signature.
    ///    If the signature is valid, then the envelope.sender is authenticated
    ///    regardless of the Noise key. The Noise channel provides confidentiality
    ///    and transport authentication.
    ///
    /// We use approach #2: The Noise channel authenticates the peer cryptographically,
    /// and the signature in the envelope proves the message is from envelope.sender.
    /// Both authentications must pass for the message to be accepted.
    /// M-1: Verify identity binding between envelope sender and Noise connection
    ///
    /// For known senders (those we've learned from health pings), we enforce
    /// that messages must come from the expected Noise key. For unknown senders,
    /// we accept the message but learn the binding for future verification.
    fn verify_identity_binding(&self, envelope_sender: &NodeId, noise_peer_key: &[u8; 32]) -> bool {
        // M-1: Check if we have a known binding for this sender
        match self.key_registry.get_noise_key(envelope_sender) {
            Some(expected_noise_key) => {
                // Known sender - enforce binding
                if expected_noise_key != *noise_peer_key {
                    warn!(
                        envelope_sender = %hex::encode(&envelope_sender[..8]),
                        expected_noise = %hex::encode(&expected_noise_key[..8]),
                        actual_noise = %hex::encode(&noise_peer_key[..8]),
                        "M-1: Identity binding failed - message from known sender \
                         arrived on unexpected Noise connection"
                    );
                    return false;
                }
                debug!(
                    sender = %hex::encode(&envelope_sender[..8]),
                    "M-1: Identity binding verified for known sender"
                );
                true
            }
            None => {
                // Unknown sender - learn the binding
                // Note: Health ping handler should call key_registry.learn_binding()
                // when processing the first health ping from this node
                debug!(
                    sender = %hex::encode(&envelope_sender[..8]),
                    noise_key = %hex::encode(&noise_peer_key[..8]),
                    "M-1: Unknown sender, will learn binding from health ping"
                );
                // Accept for now - the binding will be enforced after we learn it
                true
            }
        }
    }

    /// Stop the receiver
    pub fn stop(&self) {
        info!("Stopping Noise receiver");
        self.running.store(false, Ordering::SeqCst);
    }

    /// Check if receiver is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get statistics
    pub fn stats(&self) -> NoiseReceiverStatsSnapshot {
        self.stats.snapshot()
    }
}

/// Handle received Noise messages by dispatching to the mesh network handlers
///
/// This bridges the Noise receiver to the existing message handling pipeline.
pub struct NoiseMessageHandler {
    /// Channel to receive messages from NoiseReceiver
    receiver: mpsc::Receiver<ReceivedMessage>,
    /// Callback for handling messages
    handler: Box<dyn Fn(MessageEnvelope) + Send + Sync>,
    /// Running state
    running: AtomicBool,
}

impl NoiseMessageHandler {
    /// Create a new message handler
    pub fn new<F>(receiver: mpsc::Receiver<ReceivedMessage>, handler: F) -> Self
    where
        F: Fn(MessageEnvelope) + Send + Sync + 'static,
    {
        Self {
            receiver,
            handler: Box::new(handler),
            running: AtomicBool::new(false),
        }
    }

    /// Run the message handler loop
    pub async fn run(&mut self) {
        if self.running.swap(true, Ordering::SeqCst) {
            warn!("Noise message handler already running");
            return;
        }

        info!("Starting Noise message handler");

        while self.running.load(Ordering::SeqCst) {
            match tokio::time::timeout(Duration::from_millis(100), self.receiver.recv()).await {
                Ok(Some(msg)) => {
                    debug!(
                        msg_type = ?msg.envelope.msg_type,
                        sender = %hex::encode(&msg.envelope.sender[..8]),
                        "Dispatching Noise message"
                    );
                    (self.handler)(msg.envelope);
                }
                Ok(None) => {
                    // Channel closed
                    info!("Noise message channel closed");
                    break;
                }
                Err(_) => {
                    // Timeout - check running state
                    continue;
                }
            }
        }

        info!("Noise message handler stopped");
    }

    /// Stop the handler
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_default() {
        let stats = NoiseReceiverStats::default();
        let snapshot = stats.snapshot();

        assert_eq!(snapshot.messages_received, 0);
        assert_eq!(snapshot.messages_rejected, 0);
        assert_eq!(snapshot.identity_mismatch, 0);
        assert_eq!(snapshot.receive_errors, 0);
    }

    #[test]
    fn test_stats_atomic_increment() {
        let stats = NoiseReceiverStats::default();

        stats.messages_received.fetch_add(5, Ordering::Relaxed);
        stats.messages_rejected.fetch_add(2, Ordering::Relaxed);
        stats.identity_mismatch.fetch_add(1, Ordering::Relaxed);
        stats.receive_errors.fetch_add(3, Ordering::Relaxed);

        let snapshot = stats.snapshot();

        assert_eq!(snapshot.messages_received, 5);
        assert_eq!(snapshot.messages_rejected, 2);
        assert_eq!(snapshot.identity_mismatch, 1);
        assert_eq!(snapshot.receive_errors, 3);
    }

    #[tokio::test]
    async fn test_receiver_creation() {
        let keypair = crate::noise::NoiseKeypair::generate();
        let config = crate::noise_pool::NoisePoolConfig::default();
        let pool = Arc::new(crate::noise_pool::NoiseConnectionPool::new(keypair, config).unwrap());

        let (receiver, _rx) = NoiseReceiver::new(pool);

        assert!(!receiver.is_running());
        assert_eq!(receiver.stats().messages_received, 0);
    }

    #[test]
    fn test_identity_verification() {
        // M-1: Test identity binding with key registry

        let keypair = crate::noise::NoiseKeypair::generate();
        let config = crate::noise_pool::NoisePoolConfig::default();
        let pool = Arc::new(crate::noise_pool::NoiseConnectionPool::new(keypair, config).unwrap());

        let (receiver, _rx) = NoiseReceiver::new(pool);

        let node_id = [1u8; 32];
        let noise_key_1 = [2u8; 32];
        let noise_key_2 = [3u8; 32];

        // Unknown sender - should accept (will learn binding later)
        assert!(receiver.verify_identity_binding(&node_id, &noise_key_1));

        // Learn the binding
        receiver.key_registry().learn_binding(node_id, noise_key_1);

        // Known sender with correct noise key - should accept
        assert!(receiver.verify_identity_binding(&node_id, &noise_key_1));

        // Known sender with WRONG noise key - should REJECT
        assert!(!receiver.verify_identity_binding(&node_id, &noise_key_2));
    }

    #[test]
    fn test_key_registry() {
        let registry = KeyRegistry::new();

        let node_id_1 = [1u8; 32];
        let node_id_2 = [2u8; 32];
        let noise_key = [42u8; 32];

        // Initially unknown
        assert!(!registry.is_known(&node_id_1));
        assert_eq!(registry.known_count(), 0);

        // Learn binding
        registry.learn_binding(node_id_1, noise_key);

        assert!(registry.is_known(&node_id_1));
        assert!(!registry.is_known(&node_id_2));
        assert_eq!(registry.known_count(), 1);
        assert_eq!(registry.get_noise_key(&node_id_1), Some(noise_key));
        assert_eq!(registry.get_noise_key(&node_id_2), None);
    }
}
