//! Connection manager abstracting over GSP WebSocket and direct RPC
//!
//! Provides a unified interface for wallet operations regardless of
//! the underlying transport. The application can switch between GSP
//! mode (WebSocket to a service provider) and direct RPC mode
//! (JSON-RPC to a Ghost daemon) at runtime.

use super::ghost_pay::{GhostPayClient, PayConfig};
use super::gsp::MobileGspClient;
use super::{GhostClient, NetworkError, NodeConfig};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// The transport mode for communicating with the Ghost network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionMode {
    /// Connect via a GSP WebSocket endpoint.
    Gsp,
    /// Connect directly to a Ghost daemon via JSON-RPC.
    DirectRpc,
}

impl std::fmt::Display for ConnectionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionMode::Gsp => write!(f, "GSP (WebSocket)"),
            ConnectionMode::DirectRpc => write!(f, "Direct RPC"),
        }
    }
}

/// Unified connection manager for Ghost network communication.
///
/// Wraps both `MobileGspClient` (WebSocket) and `GhostClient` (JSON-RPC)
/// behind a common set of high-level operations. The application code
/// calls `get_balance()`, `send_payment()`, etc. without worrying about
/// which transport is active.
pub struct ConnectionManager {
    /// Active connection mode.
    mode: Arc<Mutex<ConnectionMode>>,
    /// GSP WebSocket client (used in Gsp mode).
    gsp_client: Arc<MobileGspClient>,
    /// Direct RPC client (used in DirectRpc mode).
    rpc_client: Arc<tokio::sync::Mutex<Option<GhostClient>>>,
    /// RPC node configuration (needed to lazily create the RPC client).
    rpc_config: Arc<Mutex<NodeConfig>>,
    /// M-7: Track RPC client creation without lock contention.
    rpc_connected: Arc<AtomicBool>,
    /// Ghost Pay configuration for L2 operations.
    ghost_pay_config: Arc<Mutex<PayConfig>>,
}

impl ConnectionManager {
    /// Create a new connection manager.
    ///
    /// Starts in `DirectRpc` mode with default node configuration.
    /// Call `set_mode()` to switch to GSP mode after configuring the
    /// GSP client.
    pub fn new() -> Self {
        Self {
            mode: Arc::new(Mutex::new(ConnectionMode::DirectRpc)),
            gsp_client: Arc::new(MobileGspClient::new()),
            rpc_client: Arc::new(tokio::sync::Mutex::new(None)),
            rpc_config: Arc::new(Mutex::new(NodeConfig::default())),
            rpc_connected: Arc::new(AtomicBool::new(false)),
            ghost_pay_config: Arc::new(Mutex::new(PayConfig::default())),
        }
    }

    /// Create a connection manager with specific RPC and GSP clients.
    pub fn with_clients(
        rpc_config: NodeConfig,
        gsp_client: MobileGspClient,
        initial_mode: ConnectionMode,
    ) -> Self {
        Self {
            mode: Arc::new(Mutex::new(initial_mode)),
            gsp_client: Arc::new(gsp_client),
            rpc_client: Arc::new(tokio::sync::Mutex::new(None)),
            rpc_config: Arc::new(Mutex::new(rpc_config)),
            rpc_connected: Arc::new(AtomicBool::new(false)),
            ghost_pay_config: Arc::new(Mutex::new(PayConfig::default())),
        }
    }

    /// Get the current connection mode.
    pub fn mode(&self) -> ConnectionMode {
        *self.mode.lock()
    }

    /// Switch the connection mode.
    ///
    /// This does NOT automatically connect or disconnect. The caller
    /// is responsible for calling `connect_gsp()` or ensuring the RPC
    /// client is available after switching.
    pub fn set_mode(&self, mode: ConnectionMode) {
        *self.mode.lock() = mode;
    }

    /// Update the RPC node configuration.
    pub fn set_rpc_config(&self, config: NodeConfig) {
        *self.rpc_config.lock() = config;
    }

    /// Get a reference to the GSP client.
    pub fn gsp(&self) -> &MobileGspClient {
        &self.gsp_client
    }

    /// Check whether the active transport is connected.
    pub fn is_connected(&self) -> bool {
        match *self.mode.lock() {
            ConnectionMode::Gsp => self.gsp_client.is_connected(),
            ConnectionMode::DirectRpc => self.rpc_connected.load(Ordering::Relaxed),
        }
    }

    /// Ensure the RPC client exists, creating it lazily if needed.
    async fn ensure_rpc_client(&self) -> Result<(), NetworkError> {
        let mut guard = self.rpc_client.lock().await;
        if guard.is_none() {
            let config = self.rpc_config.lock().clone();
            let client = GhostClient::new(config)?;
            *guard = Some(client);
            self.rpc_connected.store(true, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Get the current wallet balance.
    ///
    /// Returns `(confirmed, pending)` in satoshis.
    pub async fn get_balance(&self) -> Result<(u64, u64), NetworkError> {
        let mode = *self.mode.lock();
        match mode {
            ConnectionMode::Gsp => self.gsp_client.get_balance().await,
            ConnectionMode::DirectRpc => {
                self.ensure_rpc_client().await?;
                let mut guard = self.rpc_client.lock().await;
                let client = guard.as_mut().ok_or_else(|| {
                    NetworkError::ConnectionFailed("RPC client not available".into())
                })?;

                let public = client.get_public_balance().await.unwrap_or(0.0);
                let confirmed = (public * 100_000_000.0).round() as u64;
                // RPC does not have a single "pending" call — return 0.
                Ok((confirmed, 0))
            }
        }
    }

    /// Send a payment.
    ///
    /// In GSP mode, prepares and submits a signed payment. In RPC mode,
    /// broadcasts a raw signed transaction hex.
    ///
    /// Returns the transaction ID on success.
    pub async fn send_payment(&self, signed_tx: &str) -> Result<String, NetworkError> {
        let mode = *self.mode.lock();
        match mode {
            ConnectionMode::Gsp => self.gsp_client.submit_payment(signed_tx).await,
            ConnectionMode::DirectRpc => {
                self.ensure_rpc_client().await?;
                let mut guard = self.rpc_client.lock().await;
                let client = guard.as_mut().ok_or_else(|| {
                    NetworkError::ConnectionFailed("RPC client not available".into())
                })?;

                client.send_raw_transaction(signed_tx).await
            }
        }
    }

    /// Estimate fee rate in sat/vB for a given confirmation target.
    ///
    /// In GSP mode, delegates to the GSP. In RPC mode, calls
    /// `estimatesmartfee`. Returns `None` if the estimate is unavailable.
    pub async fn estimate_fee(&self, conf_target: u32) -> Result<Option<u64>, NetworkError> {
        let mode = *self.mode.lock();
        match mode {
            ConnectionMode::Gsp => {
                // GSP does not currently support fee estimation — return None.
                Ok(None)
            }
            ConnectionMode::DirectRpc => {
                self.ensure_rpc_client().await?;
                let mut guard = self.rpc_client.lock().await;
                let client = guard.as_mut().ok_or_else(|| {
                    NetworkError::ConnectionFailed("RPC client not available".into())
                })?;

                match client.estimate_fee(conf_target).await {
                    Ok(estimate) => {
                        // FeeEstimate.feerate is in BTC/kB. Convert to sat/vB:
                        // sat/vB = feerate * 100_000_000 / 1000
                        if estimate.feerate > 0.0 {
                            let sat_per_vb = (estimate.feerate * 100_000.0).round() as u64;
                            Ok(Some(sat_per_vb.max(1)))
                        } else {
                            Ok(None)
                        }
                    }
                    Err(_) => Ok(None),
                }
            }
        }
    }

    /// Trigger a sync / refresh.
    ///
    /// In GSP mode, subscribes to balance and payment updates.
    /// In RPC mode, fetches the latest block height.
    pub async fn sync(&self) -> Result<(), NetworkError> {
        let mode = *self.mode.lock();
        match mode {
            ConnectionMode::Gsp => {
                self.gsp_client.subscribe_balance().await?;
                self.gsp_client.subscribe_payments().await?;
                Ok(())
            }
            ConnectionMode::DirectRpc => {
                self.ensure_rpc_client().await?;
                let mut guard = self.rpc_client.lock().await;
                let client = guard.as_mut().ok_or_else(|| {
                    NetworkError::ConnectionFailed("RPC client not available".into())
                })?;

                // Just ping the node and get block count to validate connectivity.
                let _ = client.get_block_count().await?;
                Ok(())
            }
        }
    }

    // --- Wraith Protocol Operations ---

    /// Generate a new stealth address for Wraith protocol.
    pub async fn get_stealth_address(&self) -> Result<String, NetworkError> {
        let mode = *self.mode.lock();
        match mode {
            ConnectionMode::Gsp => Err(NetworkError::ConnectionFailed(
                "Wraith operations not supported over GSP".into(),
            )),
            ConnectionMode::DirectRpc => {
                self.ensure_rpc_client().await?;
                let mut guard = self.rpc_client.lock().await;
                let client = guard.as_mut().ok_or_else(|| {
                    NetworkError::ConnectionFailed("RPC client not available".into())
                })?;
                let stealth = client.get_stealth_address(None).await?;
                Ok(stealth.address)
            }
        }
    }

    /// Send from public to private (enter Wraith). Returns txid.
    pub async fn send_public_to_private(
        &self,
        stealth_address: &str,
        amount_sats: u64,
    ) -> Result<String, NetworkError> {
        let mode = *self.mode.lock();
        match mode {
            ConnectionMode::Gsp => Err(NetworkError::ConnectionFailed(
                "Wraith operations not supported over GSP".into(),
            )),
            ConnectionMode::DirectRpc => {
                self.ensure_rpc_client().await?;
                let mut guard = self.rpc_client.lock().await;
                let client = guard.as_mut().ok_or_else(|| {
                    NetworkError::ConnectionFailed("RPC client not available".into())
                })?;
                let amount_ghost = amount_sats as f64 / 100_000_000.0;
                client
                    .send_public_to_private(stealth_address, amount_ghost)
                    .await
            }
        }
    }

    /// Send from private to public (exit Wraith). Returns txid.
    pub async fn send_private_to_public(
        &self,
        to_address: &str,
        amount_sats: u64,
    ) -> Result<String, NetworkError> {
        let mode = *self.mode.lock();
        match mode {
            ConnectionMode::Gsp => Err(NetworkError::ConnectionFailed(
                "Wraith operations not supported over GSP".into(),
            )),
            ConnectionMode::DirectRpc => {
                self.ensure_rpc_client().await?;
                let mut guard = self.rpc_client.lock().await;
                let client = guard.as_mut().ok_or_else(|| {
                    NetworkError::ConnectionFailed("RPC client not available".into())
                })?;
                let amount_ghost = amount_sats as f64 / 100_000_000.0;
                client
                    .send_private_to_public(to_address, amount_ghost)
                    .await
            }
        }
    }

    // --- Full Node RPC Access ---

    /// Require DirectRpc mode and return a mutable reference to the RPC client.
    /// Returns `NetworkError` if in GSP mode.
    async fn require_rpc(
        &self,
    ) -> Result<tokio::sync::MutexGuard<'_, Option<GhostClient>>, NetworkError> {
        if *self.mode.lock() == ConnectionMode::Gsp {
            return Err(NetworkError::ConnectionFailed(
                "Operation not available in Light (GSP) mode".into(),
            ));
        }
        self.ensure_rpc_client().await?;
        Ok(self.rpc_client.lock().await)
    }

    /// Get blockchain info from the connected ghostd node.
    /// Returns `None` in GSP mode.
    pub async fn get_blockchain_info(
        &self,
    ) -> Result<Option<super::types::BlockchainInfo>, NetworkError> {
        if *self.mode.lock() == ConnectionMode::Gsp {
            return Ok(None);
        }
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        Ok(Some(client.get_blockchain_info().await?))
    }

    /// Get network info. Returns `None` in GSP mode.
    pub async fn get_network_info(&self) -> Result<Option<serde_json::Value>, NetworkError> {
        if *self.mode.lock() == ConnectionMode::Gsp {
            return Ok(None);
        }
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        Ok(Some(client.get_network_info().await?))
    }

    /// Get peer info. Returns `None` in GSP mode.
    pub async fn get_peer_info(&self) -> Result<Option<serde_json::Value>, NetworkError> {
        if *self.mode.lock() == ConnectionMode::Gsp {
            return Ok(None);
        }
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        Ok(Some(serde_json::Value::Array(
            client.get_peer_info().await?,
        )))
    }

    /// Get wallet info. Returns `None` in GSP mode.
    pub async fn get_wallet_info(&self) -> Result<Option<serde_json::Value>, NetworkError> {
        if *self.mode.lock() == ConnectionMode::Gsp {
            return Ok(None);
        }
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        Ok(Some(client.get_wallet_info().await?))
    }

    // --- L1 Wallet Operations (Full Node mode) ---

    /// Sign a message with an address's private key.
    pub async fn sign_message(&self, address: &str, message: &str) -> Result<String, NetworkError> {
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        client.sign_message(address, message).await
    }

    /// Verify a signed message.
    pub async fn verify_message(
        &self,
        address: &str,
        signature: &str,
        message: &str,
    ) -> Result<bool, NetworkError> {
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        client.verify_message(address, signature, message).await
    }

    /// List address labels.
    pub async fn list_labels(&self) -> Result<Vec<String>, NetworkError> {
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        client.list_labels().await
    }

    /// Get addresses by label.
    pub async fn get_addresses_by_label(
        &self,
        label: &str,
    ) -> Result<serde_json::Value, NetworkError> {
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        client.get_addresses_by_label(label).await
    }

    /// Set label for an address.
    pub async fn set_label(&self, address: &str, label: &str) -> Result<(), NetworkError> {
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        client.set_label(address, label).await
    }

    /// List received by address.
    pub async fn list_received_by_address(
        &self,
        min_conf: u32,
        include_empty: bool,
    ) -> Result<Vec<serde_json::Value>, NetworkError> {
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        client
            .list_received_by_address(min_conf, include_empty)
            .await
    }

    /// Validate an address.
    pub async fn validate_address(&self, address: &str) -> Result<serde_json::Value, NetworkError> {
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        client.validate_address(address).await
    }

    // --- Coin Control (Full Node mode) ---

    /// List unspent transaction outputs.
    pub async fn list_unspent(
        &self,
        min_conf: u32,
        max_conf: u32,
    ) -> Result<Vec<serde_json::Value>, NetworkError> {
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        client.list_unspent(min_conf, max_conf).await
    }

    /// Lock or unlock unspent outputs.
    pub async fn lock_unspent(
        &self,
        unlock: bool,
        outputs: Vec<serde_json::Value>,
    ) -> Result<bool, NetworkError> {
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        client.lock_unspent(unlock, outputs).await
    }

    /// List locked unspent outputs.
    pub async fn list_lock_unspent(&self) -> Result<Vec<serde_json::Value>, NetworkError> {
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        client.list_lock_unspent().await
    }

    /// Build a transaction with specific inputs.
    pub async fn build_with_inputs(
        &self,
        inputs: Vec<serde_json::Value>,
        outputs: serde_json::Value,
        fee_rate: Option<f64>,
    ) -> Result<serde_json::Value, NetworkError> {
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        let hex = client.create_raw_transaction(inputs, outputs).await?;
        let mut opts = serde_json::json!({});
        if let Some(rate) = fee_rate {
            opts["feeRate"] = serde_json::json!(rate);
        }
        client.fund_raw_transaction(&hex, opts).await
    }

    /// Sign and broadcast a raw transaction.
    pub async fn sign_and_send_raw(&self, hex: &str) -> Result<String, NetworkError> {
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        let signed = client.sign_raw_transaction_with_wallet(hex).await?;
        let signed_hex = signed
            .get("hex")
            .and_then(|h| h.as_str())
            .ok_or_else(|| NetworkError::InvalidResponse("No hex in signed tx".into()))?;
        client.send_raw_transaction(signed_hex).await
    }

    // --- PSBT Operations (Full Node mode) ---

    /// Decode a PSBT.
    pub async fn decode_psbt(&self, psbt: &str) -> Result<serde_json::Value, NetworkError> {
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        client.decode_psbt(psbt).await
    }

    /// Analyze a PSBT.
    pub async fn analyze_psbt(&self, psbt: &str) -> Result<serde_json::Value, NetworkError> {
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        client.analyze_psbt(psbt).await
    }

    /// Process (sign) a PSBT with wallet keys.
    pub async fn wallet_process_psbt(&self, psbt: &str) -> Result<serde_json::Value, NetworkError> {
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        client.wallet_process_psbt(psbt).await
    }

    /// Combine multiple PSBTs.
    pub async fn combine_psbt(&self, psbts: Vec<String>) -> Result<String, NetworkError> {
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        client.combine_psbt(psbts).await
    }

    /// Finalize a PSBT.
    pub async fn finalize_psbt(&self, psbt: &str) -> Result<serde_json::Value, NetworkError> {
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        client.finalize_psbt(psbt).await
    }

    /// Finalize and broadcast a PSBT.
    pub async fn broadcast_psbt(&self, psbt: &str) -> Result<String, NetworkError> {
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        let finalized = client.finalize_psbt(psbt).await?;
        let complete = finalized
            .get("complete")
            .and_then(|c| c.as_bool())
            .unwrap_or(false);
        if !complete {
            return Err(NetworkError::InvalidResponse(
                "PSBT is not fully signed".into(),
            ));
        }
        let hex = finalized
            .get("hex")
            .and_then(|h| h.as_str())
            .ok_or_else(|| NetworkError::InvalidResponse("No hex in finalized PSBT".into()))?;
        client.send_raw_transaction(hex).await
    }

    // --- Wallet Encryption (Full Node mode) ---

    /// Encrypt the wallet.
    pub async fn encrypt_wallet(&self, passphrase: &str) -> Result<(), NetworkError> {
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        client.encrypt_wallet(passphrase).await
    }

    /// Unlock the wallet for a duration.
    pub async fn wallet_passphrase(
        &self,
        passphrase: &str,
        timeout_seconds: u32,
    ) -> Result<(), NetworkError> {
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        client
            .wallet_passphrase(passphrase, timeout_seconds, false)
            .await
    }

    /// Change the wallet passphrase.
    pub async fn wallet_passphrase_change(
        &self,
        old_passphrase: &str,
        new_passphrase: &str,
    ) -> Result<(), NetworkError> {
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        client
            .wallet_passphrase_change(old_passphrase, new_passphrase)
            .await
    }

    /// Lock the node wallet.
    pub async fn wallet_lock_node(&self) -> Result<(), NetworkError> {
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        client.wallet_lock().await
    }

    /// Execute an arbitrary RPC call (for RPC console).
    pub async fn rpc_call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, NetworkError> {
        let mut guard = self.require_rpc().await?;
        let client = guard
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("RPC client not available".into()))?;
        // Convert Value params to what call() expects
        client.call(method, params).await
    }

    // --- L2 Confidential Operations ---

    /// Configure the Ghost Pay connection for L2 operations.
    pub fn set_ghost_pay_config(&self, config: PayConfig) {
        *self.ghost_pay_config.lock() = config;
    }

    /// Create a new Ghost Pay client with the current configuration.
    ///
    /// Each call creates a fresh client instance. The underlying reqwest::Client
    /// is shared via connection pooling, so this is lightweight.
    pub fn create_ghost_pay_client(&self) -> Result<GhostPayClient, NetworkError> {
        let config = self.ghost_pay_config.lock().clone();
        GhostPayClient::new(config)
    }

    /// Get a new public receive address (for the exit leg of a wash).
    pub async fn get_new_address(&self) -> Result<String, NetworkError> {
        let mode = *self.mode.lock();
        match mode {
            ConnectionMode::Gsp => Err(NetworkError::ConnectionFailed(
                "Address generation not supported over GSP".into(),
            )),
            ConnectionMode::DirectRpc => {
                self.ensure_rpc_client().await?;
                let mut guard = self.rpc_client.lock().await;
                let client = guard.as_mut().ok_or_else(|| {
                    NetworkError::ConnectionFailed("RPC client not available".into())
                })?;
                client.get_new_address(Some("wash")).await
            }
        }
    }
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_mode() {
        let manager = ConnectionManager::new();
        assert_eq!(manager.mode(), ConnectionMode::DirectRpc);
    }

    #[test]
    fn test_set_mode() {
        let manager = ConnectionManager::new();
        manager.set_mode(ConnectionMode::Gsp);
        assert_eq!(manager.mode(), ConnectionMode::Gsp);

        manager.set_mode(ConnectionMode::DirectRpc);
        assert_eq!(manager.mode(), ConnectionMode::DirectRpc);
    }

    #[test]
    fn test_mode_display() {
        assert_eq!(ConnectionMode::Gsp.to_string(), "GSP (WebSocket)");
        assert_eq!(ConnectionMode::DirectRpc.to_string(), "Direct RPC");
    }

    #[test]
    fn test_not_connected_initially() {
        let manager = ConnectionManager::new();
        assert!(!manager.is_connected());
    }

    #[test]
    fn test_rpc_config_update() {
        let manager = ConnectionManager::new();
        let config = NodeConfig::testnet();
        manager.set_rpc_config(config);
        assert_eq!(manager.mode(), ConnectionMode::DirectRpc);
    }

    #[test]
    fn test_default_impl() {
        let manager = ConnectionManager::default();
        assert_eq!(manager.mode(), ConnectionMode::DirectRpc);
        assert!(!manager.is_connected());
    }

    #[test]
    fn test_with_clients_gsp_mode() {
        let config = NodeConfig::default();
        let gsp = MobileGspClient::new();
        let manager = ConnectionManager::with_clients(config, gsp, ConnectionMode::Gsp);
        assert_eq!(manager.mode(), ConnectionMode::Gsp);
    }

    #[test]
    fn test_with_clients_rpc_mode() {
        let config = NodeConfig::mainnet();
        let gsp = MobileGspClient::new();
        let manager = ConnectionManager::with_clients(config, gsp, ConnectionMode::DirectRpc);
        assert_eq!(manager.mode(), ConnectionMode::DirectRpc);
    }

    #[test]
    fn test_gsp_accessor() {
        let manager = ConnectionManager::new();
        // Should not panic — GSP client always exists
        let gsp = manager.gsp();
        assert!(!gsp.is_connected());
    }

    #[test]
    fn test_mode_switch_roundtrip() {
        let manager = ConnectionManager::new();
        assert_eq!(manager.mode(), ConnectionMode::DirectRpc);

        manager.set_mode(ConnectionMode::Gsp);
        assert_eq!(manager.mode(), ConnectionMode::Gsp);
        assert!(!manager.is_connected()); // GSP not connected

        manager.set_mode(ConnectionMode::DirectRpc);
        assert_eq!(manager.mode(), ConnectionMode::DirectRpc);
    }

    #[test]
    fn test_mode_equality() {
        assert_eq!(ConnectionMode::Gsp, ConnectionMode::Gsp);
        assert_eq!(ConnectionMode::DirectRpc, ConnectionMode::DirectRpc);
        assert_ne!(ConnectionMode::Gsp, ConnectionMode::DirectRpc);
    }

    #[test]
    fn test_mode_clone() {
        let mode = ConnectionMode::Gsp;
        let cloned = mode;
        assert_eq!(mode, cloned);
    }
}
