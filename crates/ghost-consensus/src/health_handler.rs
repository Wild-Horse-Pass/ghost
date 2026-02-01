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
//| FILE: health_handler.rs                                                                                              |
//|======================================================================================================================|

//! Health ping handler
//!
//! Handles incoming health pings and updates peer information in the database.
//! Also discovers elders dynamically from HealthPing capabilities.

use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};

use ghost_common::error::GhostResult;
use ghost_common::types::NodeId;
use ghost_storage::{Database, PeerRecord};

use crate::mesh::MessageHandler;
use crate::message::{HealthPingMessage, MessageEnvelope, MessageType};
use crate::peer::PeerManager;

/// Callback for registering discovered elders
pub type ElderCallback = Arc<dyn Fn(NodeId) + Send + Sync>;

/// Callback for registering node capabilities (for payout calculation)
pub type NodeCapabilitiesCallback = Arc<dyn Fn(NodeId, ghost_common::types::NodeCapabilities) + Send + Sync>;

/// Handler for health ping messages
pub struct HealthPingHandler {
    /// Peer manager for updating peer state
    peers: Arc<PeerManager>,
    /// Database for persisting peer info
    db: Option<Arc<Database>>,
    /// Callback to register discovered elders
    elder_callback: Option<ElderCallback>,
    /// Callback to register node capabilities for payout calculations
    node_capabilities_callback: Option<NodeCapabilitiesCallback>,
}

impl HealthPingHandler {
    /// Create a new health ping handler
    pub fn new(peers: Arc<PeerManager>, db: Option<Arc<Database>>) -> Self {
        Self {
            peers,
            db,
            elder_callback: None,
            node_capabilities_callback: None,
        }
    }

    /// Set the database for persistence
    pub fn with_database(mut self, db: Arc<Database>) -> Self {
        self.db = Some(db);
        self
    }

    /// Set callback for elder discovery
    ///
    /// When a HealthPing is received from a node with elder_status=true,
    /// this callback will be invoked to register the elder.
    pub fn with_elder_callback(mut self, callback: ElderCallback) -> Self {
        self.elder_callback = Some(callback);
        self
    }

    /// Set callback for node capabilities registration
    ///
    /// When a HealthPing is received, this callback will be invoked to
    /// register the node's capabilities for payout calculations.
    pub fn with_node_capabilities_callback(mut self, callback: NodeCapabilitiesCallback) -> Self {
        self.node_capabilities_callback = Some(callback);
        self
    }

    /// Handle a health ping message
    async fn handle_ping(&self, envelope: &MessageEnvelope) -> GhostResult<()> {
        // Deserialize the health ping
        let ping_msg: HealthPingMessage = serde_json::from_slice(&envelope.payload)
            .map_err(|e| ghost_common::error::GhostError::P2PMessage(e.to_string()))?;

        let ping = &ping_msg.ping;
        let node_id_hex = hex::encode(&envelope.sender);
        let short_id = node_id_hex[..8].to_string();

        debug!(
            node_id = %short_id,
            block_height = ping.block_height,
            round_id = ping.round_id,
            miner_count = ping.miner_count,
            elder = ping.capabilities.elder_status,
            "Received health ping"
        );

        // Register node as voter for BFT consensus (ALL active nodes can vote)
        // Elder status is just a capability flag, not a voting requirement
        if let Some(ref callback) = self.elder_callback {
            callback(envelope.sender);
            debug!(node_id = %short_id, "Registered node as BFT voter from health ping");
        }

        // Register node capabilities for payout calculations
        if let Some(ref callback) = self.node_capabilities_callback {
            callback(envelope.sender, ping.capabilities.clone());
            debug!(node_id = %short_id, "Registered node capabilities for payout");
        }

        // Update peer's last seen time in memory
        // If the peer doesn't exist (was registered with temp node_id), add it with real node_id
        if self.peers.get_peer(&envelope.sender).is_none() {
            // Create peer with real node_id and real public address from the ping
            let mut peer = crate::peer::Peer::new(envelope.sender, ping.public_address.clone());
            peer.state = crate::peer::PeerState::Connected;
            self.peers.upsert_peer(peer);
            debug!(node_id = %short_id, address = %ping.public_address, "Added new peer from health ping");
        }
        self.peers.update_last_seen(&envelope.sender);

        // Persist to database if available
        if let Some(ref db) = self.db {
            let now = chrono::Utc::now().timestamp();
            let capabilities_json = serde_json::to_string(&ping.capabilities).unwrap_or_default();

            // Create peer record for database
            let peer = PeerRecord {
                peer_id: node_id_hex.clone(),
                address: String::new(), // Will be updated when we know the address
                port: 8555,             // Default port
                node_id: Some(node_id_hex),
                first_seen: now,
                last_seen: now,
                last_success: Some(now),
                last_failure: None,
                connection_count: 1,
                failure_count: 0,
                is_banned: false,
                ban_until: None,
                capabilities: Some(capabilities_json),
                protocol_version: Some(1),
            };

            if let Err(e) = db.upsert_peer(&peer) {
                warn!(error = %e, peer_id = %short_id, "Failed to persist peer info");
            }
        }

        Ok(())
    }
}

#[async_trait]
impl MessageHandler for HealthPingHandler {
    async fn handle_message(&self, envelope: MessageEnvelope) -> GhostResult<()> {
        if envelope.msg_type == MessageType::HealthPing {
            self.handle_ping(&envelope).await?;
        }
        Ok(())
    }
}
