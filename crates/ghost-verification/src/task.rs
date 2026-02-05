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
//| FILE: task.rs                                                                                                        |
//|======================================================================================================================|

//! Periodic verification task
//!
//! Verifies peer capabilities every 5 minutes by:
//! 1. Selecting 3 random peers (excluding self)
//! 2. Querying their /health endpoint to discover claimed capabilities
//! 3. Issuing targeted challenges for each claimed capability
//! 4. Storing results in the local database
//! 5. Broadcasting results via P2P

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use ghost_common::rpc::BitcoinRpc;
use ghost_common::types::NodeId;
use ghost_storage::Database;

use crate::client::VerificationClient;

/// Verification task configuration
#[derive(Debug, Clone)]
pub struct VerificationTaskConfig {
    /// Interval between verification cycles (default: 5 minutes)
    pub interval: Duration,
    /// Number of peers to verify per cycle (default: 3)
    pub peers_per_cycle: usize,
    /// HTTP timeout for verification requests
    pub request_timeout: Duration,
}

impl Default for VerificationTaskConfig {
    fn default() -> Self {
        use ghost_common::constants::{
            NODES_TO_VERIFY_PER_ROUND, VERIFICATION_INTERVAL_SECS, VERIFICATION_TIMEOUT_SECS,
        };
        Self {
            interval: Duration::from_secs(VERIFICATION_INTERVAL_SECS),
            peers_per_cycle: NODES_TO_VERIFY_PER_ROUND,
            request_timeout: Duration::from_secs(VERIFICATION_TIMEOUT_SECS),
        }
    }
}

/// Information about a peer for verification
#[derive(Debug, Clone)]
pub struct VerifiablePeer {
    /// Node ID (32 bytes)
    pub node_id: NodeId,
    /// HTTP address for verification (e.g., "192.168.1.1:8080")
    pub http_address: String,
}

/// Trait for providing peers to verify
///
/// Implement this trait to provide the verification task with
/// a list of known peers that can be verified.
pub trait PeerProvider: Send + Sync {
    /// Get random peers for verification
    ///
    /// Should exclude the specified node_id (self) and return
    /// at most `count` peers that are currently connected.
    fn get_random_peers(&self, exclude: &NodeId, count: usize) -> Vec<VerifiablePeer>;
}

/// Result of a verification challenge that can be broadcast
#[derive(Debug, Clone)]
pub struct VerificationBroadcast {
    /// Target node ID
    pub target_node_id: NodeId,
    /// Challenger node ID
    pub challenger_id: NodeId,
    /// Capability type ("archive", "policy", "stratum", "ghostpay")
    pub capability: String,
    /// Whether the challenge passed
    pub passed: bool,
    /// Challenge data (JSON)
    pub challenge_data: String,
    /// Response data (JSON, optional)
    pub response_data: Option<String>,
    /// Timestamp
    pub timestamp: i64,
}

/// Channel for broadcasting verification results
pub type VerificationBroadcastSender = mpsc::Sender<VerificationBroadcast>;
pub type VerificationBroadcastReceiver = mpsc::Receiver<VerificationBroadcast>;

/// Create a broadcast channel for verification results
pub fn verification_broadcast_channel(
    buffer: usize,
) -> (VerificationBroadcastSender, VerificationBroadcastReceiver) {
    mpsc::channel(buffer)
}

/// Build a randomized T0 test transaction for policy verification (H-3)
///
/// # Security (H-3: Randomized Policy Challenge Transactions)
///
/// This function generates a cryptographically random test transaction each time
/// to prevent nodes from pre-computing policy classification responses. The
/// randomization includes:
/// - Random txid derived from cryptographic RNG
/// - Random output amounts within valid ranges
/// - Random script types (P2WPKH, P2TR, multisig)
/// - Random number of outputs (1-3)
fn build_test_transaction() -> String {
    use bitcoin::consensus::encode::serialize_hex;
    use bitcoin::hashes::{sha256d, Hash};
    use bitcoin::locktime::absolute::LockTime;
    use bitcoin::script::Builder;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::{Transaction, Version};
    use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, Txid, Witness};

    // H-3: Use cryptographic randomness for unpredictable challenge transactions
    let mut rng_bytes = [0u8; 64];
    if getrandom::getrandom(&mut rng_bytes).is_err() {
        warn!("H-3: Failed to get cryptographic randomness, using fallback");
        // Fallback: use timestamp-based randomness (less secure but functional)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        rng_bytes[..8].copy_from_slice(&now.to_le_bytes());
    }

    // H-3: Generate random txid from cryptographic randomness
    let txid = Txid::from_raw_hash(sha256d::Hash::hash(&rng_bytes[..32]));

    // H-3: Randomize output amount (10,000 - 100,000 sats)
    let rand_amount = u64::from_le_bytes(rng_bytes[8..16].try_into().unwrap_or([0u8; 8]));
    let amount = 10_000 + (rand_amount % 90_000);

    // H-3: Randomly select script type to test different classification scenarios
    let script_type = rng_bytes[16] % 4;
    let output_script = match script_type {
        0 => {
            // P2WPKH: OP_0 <20-byte-hash>
            let mut pubkey_hash = [0u8; 20];
            pubkey_hash.copy_from_slice(&rng_bytes[17..37]);
            Builder::new()
                .push_int(0)
                .push_slice(pubkey_hash)
                .into_script()
        }
        1 => {
            // P2TR (Taproot): OP_1 <32-byte-x-only-pubkey>
            let mut x_only_pubkey = [0u8; 32];
            x_only_pubkey.copy_from_slice(&rng_bytes[17..49]);
            Builder::new()
                .push_int(1)
                .push_slice(x_only_pubkey)
                .into_script()
        }
        2 => {
            // OP_RETURN with random 40-byte data
            let mut op_return_data = [0u8; 40];
            op_return_data.copy_from_slice(&rng_bytes[18..58]);
            Builder::new()
                .push_opcode(bitcoin::opcodes::all::OP_RETURN)
                .push_slice(op_return_data)
                .into_script()
        }
        _ => {
            // P2WSH (2-of-2 multisig witness hash)
            let mut script_hash = [0u8; 32];
            script_hash.copy_from_slice(&rng_bytes[17..49]);
            Builder::new()
                .push_int(0)
                .push_slice(script_hash)
                .into_script()
        }
    };

    // H-3: Randomly vary the number of outputs (1-3)
    let output_count = 1 + (rng_bytes[49] % 3) as usize;
    let mut outputs = Vec::with_capacity(output_count);

    // First output uses the selected script type
    outputs.push(TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: output_script,
    });

    // Additional outputs use P2WPKH for simplicity
    for i in 1..output_count {
        let mut pubkey_hash = [0u8; 20];
        let offset = 50 + (i - 1) * 20;
        if offset + 20 <= rng_bytes.len() {
            pubkey_hash.copy_from_slice(&rng_bytes[offset..offset + 20]);
        }
        let additional_amount = 5_000 + (u64::from(rng_bytes[50]) * 100);
        outputs.push(TxOut {
            value: Amount::from_sat(additional_amount),
            script_pubkey: Builder::new()
                .push_int(0)
                .push_slice(pubkey_hash)
                .into_script(),
        });
    }

    // H-3: Randomize vout index
    let vout = (rng_bytes[51] % 4) as u32;

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs,
    };

    debug!(
        script_type = script_type,
        output_count = output_count,
        amount = amount,
        "H-3: Built randomized policy challenge transaction"
    );

    serialize_hex(&tx)
}

/// Periodic verification task
///
/// Runs in the background and periodically verifies peer capabilities.
pub struct VerificationTask {
    /// HTTP client for issuing challenges
    client: VerificationClient,
    /// Database for storing results
    db: Arc<Database>,
    /// Our node ID (to exclude from verification)
    our_node_id: NodeId,
    /// Peer provider
    peer_provider: Arc<dyn PeerProvider>,
    /// Configuration
    config: VerificationTaskConfig,
    /// Broadcast channel for results
    broadcast_tx: Option<VerificationBroadcastSender>,
    /// Bitcoin RPC for fetching real block data
    rpc: Option<Arc<BitcoinRpc>>,
}

impl VerificationTask {
    /// Create a new verification task
    pub fn new(
        db: Arc<Database>,
        our_node_id: NodeId,
        peer_provider: Arc<dyn PeerProvider>,
    ) -> Self {
        Self {
            client: VerificationClient::new().expect("Failed to create verification client"),
            db,
            our_node_id,
            peer_provider,
            config: VerificationTaskConfig::default(),
            broadcast_tx: None,
            rpc: None,
        }
    }

    /// Create with custom configuration
    pub fn with_config(
        db: Arc<Database>,
        our_node_id: NodeId,
        peer_provider: Arc<dyn PeerProvider>,
        config: VerificationTaskConfig,
    ) -> Self {
        Self {
            client: VerificationClient::new().expect("Failed to create verification client"),
            db,
            our_node_id,
            peer_provider,
            config,
            broadcast_tx: None,
            rpc: None,
        }
    }

    /// Set the broadcast channel for verification results
    pub fn with_broadcast(mut self, tx: VerificationBroadcastSender) -> Self {
        self.broadcast_tx = Some(tx);
        self
    }

    /// Set the Bitcoin RPC client for fetching real block data
    pub fn with_rpc(mut self, rpc: Arc<BitcoinRpc>) -> Self {
        self.rpc = Some(rpc);
        self
    }

    /// Run the verification task loop
    ///
    /// This runs forever, periodically verifying peers.
    pub async fn run(&self) {
        info!(
            interval_secs = self.config.interval.as_secs(),
            peers_per_cycle = self.config.peers_per_cycle,
            "Starting verification task"
        );

        loop {
            // Perform verification cycle
            self.verify_cycle().await;

            // Wait for next cycle
            tokio::time::sleep(self.config.interval).await;
        }
    }

    /// Perform a single verification cycle
    pub async fn verify_cycle(&self) {
        // Get random peers to verify
        let peers = self
            .peer_provider
            .get_random_peers(&self.our_node_id, self.config.peers_per_cycle);

        if peers.is_empty() {
            debug!("No peers to verify");
            return;
        }

        info!(peer_count = peers.len(), "Starting verification cycle");

        // Verify each peer
        for peer in peers {
            self.verify_peer(&peer).await;
        }
    }

    /// Verify a single peer's capabilities
    async fn verify_peer(&self, peer: &VerifiablePeer) {
        let peer_id_hex = hex::encode(peer.node_id);
        let short_id = &peer_id_hex[..8];
        let our_id_hex = hex::encode(self.our_node_id);

        debug!(peer = %short_id, address = %peer.http_address, "Verifying peer");

        // First, query their health endpoint to discover claimed capabilities
        let health = match self.client.health(&peer.http_address).await {
            Ok(h) => h,
            Err(e) => {
                warn!(peer = %short_id, error = %e, "Failed to get peer health");
                return;
            }
        };

        let capabilities = health.capabilities;
        let timestamp = chrono::Utc::now().timestamp();

        // Verify each claimed capability
        if capabilities.archive_mode {
            self.verify_archive(peer, &peer_id_hex, &our_id_hex, timestamp)
                .await;
        }

        if capabilities.bitcoin_pure {
            self.verify_policy(peer, &peer_id_hex, &our_id_hex, timestamp)
                .await;
        }

        if capabilities.public_mining {
            self.verify_stratum(peer, &peer_id_hex, &our_id_hex, timestamp)
                .await;
        }

        if capabilities.ghost_pay {
            self.verify_ghostpay(peer, &peer_id_hex, &our_id_hex, timestamp)
                .await;
        }
    }

    /// Verify archive capability
    async fn verify_archive(
        &self,
        peer: &VerifiablePeer,
        peer_id_hex: &str,
        our_id_hex: &str,
        timestamp: i64,
    ) {
        // L-11: Get a real block hash from the blockchain via RPC
        // Fail closed: if RPC is unavailable, skip the challenge rather than using
        // a predictable genesis block that could be pre-computed
        let (block_hash, block_height) = match self.get_random_block_hash().await {
            Some((hash, height)) => (hash, height),
            None => {
                // L-11: Fail closed - do not use predictable fallback
                warn!(
                    peer = %peer_id_hex[..8],
                    "RPC unavailable, skipping archive verification (fail closed)"
                );
                // Record as inconclusive - don't pass or fail, just skip
                return;
            }
        };

        let challenge_data = serde_json::json!({
            "block_hash": block_hash,
            "block_height": block_height,
        })
        .to_string();

        let result = self
            .client
            .verify_archive(&peer.http_address, Some(&block_hash), None)
            .await;

        let (passed, response_data) = match result {
            Ok(resp) => (
                resp.success,
                Some(
                    serde_json::json!({
                        "success": resp.success,
                        "hash": resp.block_data.as_ref().map(|b| &b.hash),
                        "height": resp.block_data.as_ref().map(|b| b.height),
                    })
                    .to_string(),
                ),
            ),
            Err(e) => {
                debug!(error = %e, "Archive verification failed");
                (false, Some(format!("{{\"error\":\"{}\"}}", e)))
            }
        };

        info!(
            peer = %peer_id_hex[..8],
            block_height = block_height,
            passed = passed,
            "Archive verification complete"
        );

        // Store result
        let _ = self.db.insert_archive_challenge(
            peer_id_hex,
            our_id_hex,
            block_height,
            &block_hash,
            None,
            passed,
        );

        // Broadcast result
        self.broadcast_result(
            peer.node_id,
            "archive",
            passed,
            challenge_data,
            response_data,
            timestamp,
        )
        .await;
    }

    /// Get a random block hash from the blockchain for archive verification
    ///
    /// H-6: Uses cryptographic randomness via getrandom to ensure unpredictable
    /// block selection, preventing attackers from pre-computing challenge responses.
    async fn get_random_block_hash(&self) -> Option<(String, u64)> {
        let rpc = self.rpc.as_ref()?;

        // Get current chain height
        let height = match rpc.get_block_count().await {
            Ok(h) => h,
            Err(e) => {
                debug!(error = %e, "Failed to get block count");
                return None;
            }
        };

        if height < 100 {
            return None;
        }

        // H-6: Use cryptographic randomness for unpredictable block selection
        let max_height = height.saturating_sub(100);
        let mut rand_bytes = [0u8; 8];
        if getrandom::getrandom(&mut rand_bytes).is_err() {
            warn!("Failed to get cryptographic randomness for block selection");
            return None;
        }
        let rand_val = u64::from_le_bytes(rand_bytes);
        let challenge_height = rand_val % (max_height + 1);

        // Get block hash at that height
        match rpc.get_block_hash(challenge_height).await {
            Ok(hash) => Some((hash, challenge_height)),
            Err(e) => {
                debug!(error = %e, height = challenge_height, "Failed to get block hash");
                None
            }
        }
    }

    /// Verify policy capability
    async fn verify_policy(
        &self,
        peer: &VerifiablePeer,
        peer_id_hex: &str,
        our_id_hex: &str,
        timestamp: i64,
    ) {
        // Build valid T0 transaction for policy classification challenge
        let test_tx_hex = build_test_transaction();
        debug!(tx_hex_len = test_tx_hex.len(), tx_hex_prefix = %&test_tx_hex[..40.min(test_tx_hex.len())], "Built test transaction");

        let challenge_data = serde_json::json!({
            "tx_type": "T0",
            "expected_tier": "T0",
        })
        .to_string();

        let result = self
            .client
            .verify_policy(&peer.http_address, &test_tx_hex)
            .await;

        let (passed, tier, response_data) = match result {
            Ok(resp) => {
                // Success if:
                // 1. Response parsed successfully (success=true)
                // 2. Classification exists and is T0 or T1 (valid for simple tx)
                let tier = resp.classification.as_ref().map(|c| c.tier.clone());
                let tier_ok = tier
                    .as_ref()
                    .map(|t| t == "T0" || t == "T1")
                    .unwrap_or(false);
                let passed = resp.success && tier_ok;

                (
                    passed,
                    tier,
                    Some(
                        serde_json::json!({
                            "success": resp.success,
                            "tier": resp.classification.as_ref().map(|c| &c.tier),
                            "profile": resp.profile,
                            "accepted": resp.accepted,
                        })
                        .to_string(),
                    ),
                )
            }
            Err(e) => {
                warn!(error = %e, peer = %peer_id_hex[..8], "Policy verification failed");
                (false, None, Some(format!("{{\"error\":\"{}\"}}", e)))
            }
        };

        // Convert tier string to numeric value for database
        let tier_num = tier.as_ref().and_then(|t| match t.as_str() {
            "T0" => Some(0),
            "T1" => Some(1),
            "T2" => Some(2),
            "T3" => Some(3),
            _ => None,
        });

        info!(
            peer = %peer_id_hex[..8],
            tier = ?tier,
            passed = passed,
            "Policy verification complete"
        );

        // Store result
        let _ = self.db.insert_policy_challenge(
            peer_id_hex,
            our_id_hex,
            "T0_test",
            0, // expected_tier
            tier_num,
            passed,
        );

        // Broadcast result
        self.broadcast_result(
            peer.node_id,
            "policy",
            passed,
            challenge_data,
            response_data,
            timestamp,
        )
        .await;
    }

    /// Verify stratum capability
    async fn verify_stratum(
        &self,
        peer: &VerifiablePeer,
        peer_id_hex: &str,
        our_id_hex: &str,
        timestamp: i64,
    ) {
        use crate::challenge::StratumProtocol;

        let challenge_data = serde_json::json!({
            "protocol": "sv2",
        })
        .to_string();

        let result = self
            .client
            .verify_stratum(&peer.http_address, StratumProtocol::Sv2)
            .await;

        let short_id = &peer_id_hex[..8];
        let (passed, connected, latency_ms, response_data) = match result {
            Ok(resp) => (
                resp.success && resp.connected,
                resp.connected,
                resp.latency_ms,
                Some(
                    serde_json::json!({
                        "success": resp.success,
                        "connected": resp.connected,
                        "latency_ms": resp.latency_ms,
                    })
                    .to_string(),
                ),
            ),
            Err(e) => {
                warn!(peer = %short_id, error = %e, "Stratum verification failed");
                (false, false, None, Some(format!("{{\"error\":\"{}\"}}", e)))
            }
        };

        info!(peer = %short_id, passed = passed, connected = connected, "Stratum verification complete");

        // Store result
        let _ = self.db.insert_stratum_challenge(
            peer_id_hex,
            our_id_hex,
            connected,
            latency_ms,
            passed,
        );

        // Broadcast result
        self.broadcast_result(
            peer.node_id,
            "stratum",
            passed,
            challenge_data,
            response_data,
            timestamp,
        )
        .await;
    }

    /// Verify ghostpay capability
    async fn verify_ghostpay(
        &self,
        peer: &VerifiablePeer,
        peer_id_hex: &str,
        our_id_hex: &str,
        timestamp: i64,
    ) {
        let challenge_data = serde_json::json!({
            "endpoint": "ghostpay",
        })
        .to_string();

        let short_id = &peer_id_hex[..8];
        let result = self.client.verify_ghostpay(&peer.http_address, None).await;

        let (passed, response_valid, response_data) = match result {
            Ok(resp) => (
                resp.success && resp.l2_enabled,
                resp.l2_enabled,
                Some(
                    serde_json::json!({
                        "success": resp.success,
                        "valid": resp.l2_enabled,
                        "virtual_block": resp.virtual_block,
                        "epoch": resp.epoch,
                    })
                    .to_string(),
                ),
            ),
            Err(e) => {
                warn!(peer = %short_id, error = %e, "GhostPay verification failed");
                (false, false, Some(format!("{{\"error\":\"{}\"}}", e)))
            }
        };

        info!(peer = %short_id, passed = passed, l2_enabled = response_valid, "GhostPay verification complete");

        // Store result
        if let Err(e) = self.db.insert_ghostpay_challenge(
            peer_id_hex,
            our_id_hex,
            "ghostpay",
            response_valid,
            passed,
        ) {
            warn!(peer = %short_id, error = %e, "Failed to store GhostPay challenge");
        }

        // Broadcast result
        self.broadcast_result(
            peer.node_id,
            "ghostpay",
            passed,
            challenge_data,
            response_data,
            timestamp,
        )
        .await;
    }

    /// Broadcast a verification result via P2P
    async fn broadcast_result(
        &self,
        target_node_id: NodeId,
        capability: &str,
        passed: bool,
        challenge_data: String,
        response_data: Option<String>,
        timestamp: i64,
    ) {
        if let Some(ref tx) = self.broadcast_tx {
            let broadcast = VerificationBroadcast {
                target_node_id,
                challenger_id: self.our_node_id,
                capability: capability.to_string(),
                passed,
                challenge_data,
                response_data,
                timestamp,
            };

            if let Err(e) = tx.send(broadcast).await {
                warn!(error = %e, "Failed to broadcast verification result");
            }
        }
    }
}
