//! Ghost node RPC client
//!
//! Provides methods for interacting with Ghost daemon via JSON-RPC.

use super::types::*;
use super::NetworkError;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::time::Duration;

/// Node configuration
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// List of node endpoints to connect to
    pub endpoints: Vec<String>,
    /// RPC username (if authentication required)
    pub rpc_user: Option<String>,
    /// RPC password (if authentication required)
    pub rpc_password: Option<String>,
    /// Request timeout in milliseconds
    pub timeout_ms: u64,
    /// Number of retry attempts
    pub retry_count: u32,
    /// Whether to use SSL/TLS
    pub use_tls: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            endpoints: vec![
                "http://127.0.0.1:51725".into(), // Ghost mainnet default RPC port
            ],
            rpc_user: None,
            rpc_password: None,
            timeout_ms: 30_000,
            retry_count: 3,
            use_tls: false,
        }
    }
}

impl NodeConfig {
    /// Create config for Ghost mainnet
    pub fn mainnet() -> Self {
        Self {
            endpoints: vec!["http://127.0.0.1:51725".into()],
            ..Default::default()
        }
    }

    /// Create config for Ghost testnet
    pub fn testnet() -> Self {
        Self {
            endpoints: vec!["http://127.0.0.1:51925".into()],
            ..Default::default()
        }
    }

    /// Add authentication
    pub fn with_auth(mut self, user: &str, password: &str) -> Self {
        self.rpc_user = Some(user.to_string());
        self.rpc_password = Some(password.to_string());
        self
    }
}

/// JSON-RPC request
#[derive(Debug, Serialize)]
struct RpcRequest<T> {
    jsonrpc: &'static str,
    method: String,
    params: T,
    id: u64,
}

/// JSON-RPC response
#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    #[allow(dead_code)]
    jsonrpc: String,
    result: Option<T>,
    error: Option<RpcError>,
    #[allow(dead_code)]
    id: u64,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i32,
    message: String,
}

/// Ghost node RPC client
pub struct GhostClient {
    config: NodeConfig,
    client: reqwest::Client,
    current_endpoint: usize,
    request_id: u64,
    /// Current Wraith mode
    wraith_mode: WraithMode,
    /// Wraith configuration
    wraith_config: WraithConfig,
}

impl GhostClient {
    /// Create a new Ghost client
    pub fn new(config: NodeConfig) -> Result<Self, NetworkError> {
        let builder = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms));

        let client = builder
            .build()
            .map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?;

        Ok(Self {
            config,
            client,
            current_endpoint: 0,
            request_id: 0,
            wraith_mode: WraithMode::Public,
            wraith_config: WraithConfig::default(),
        })
    }

    /// Make an RPC call
    pub async fn call<P, R>(&mut self, method: &str, params: P) -> Result<R, NetworkError>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        self.request_id += 1;

        let request = RpcRequest {
            jsonrpc: "2.0",
            method: method.to_string(),
            params,
            id: self.request_id,
        };

        let mut last_error = None;

        for _ in 0..self.config.retry_count {
            let endpoint = &self.config.endpoints[self.current_endpoint];

            match self.make_request(endpoint, &request).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    last_error = Some(e);
                    self.rotate_endpoint();
                }
            }
        }

        Err(last_error.unwrap_or(NetworkError::NoAvailableNodes))
    }

    async fn make_request<P, R>(
        &self,
        endpoint: &str,
        request: &RpcRequest<P>,
    ) -> Result<R, NetworkError>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        let mut req_builder = self.client.post(endpoint).json(request);

        // Add authentication if configured
        if let (Some(user), Some(pass)) = (&self.config.rpc_user, &self.config.rpc_password) {
            req_builder = req_builder.basic_auth(user, Some(pass));
        }

        let response = req_builder
            .send()
            .await
            .map_err(|e| NetworkError::RequestFailed(e.to_string()))?;

        let rpc_response: RpcResponse<R> = response
            .json()
            .await
            .map_err(|e| NetworkError::InvalidResponse(e.to_string()))?;

        if let Some(error) = rpc_response.error {
            return Err(NetworkError::RequestFailed(format!(
                "RPC error {}: {}",
                error.code, error.message
            )));
        }

        rpc_response
            .result
            .ok_or_else(|| NetworkError::InvalidResponse("No result in response".into()))
    }

    fn rotate_endpoint(&mut self) {
        self.current_endpoint = (self.current_endpoint + 1) % self.config.endpoints.len();
    }

    // ========================================
    // Blockchain Info Methods
    // ========================================

    /// Get blockchain information
    pub async fn get_blockchain_info(&mut self) -> Result<BlockchainInfo, NetworkError> {
        self.call("getblockchaininfo", ()).await
    }

    /// Get current block height
    pub async fn get_block_count(&mut self) -> Result<u64, NetworkError> {
        self.call("getblockcount", ()).await
    }

    /// Get best block hash
    pub async fn get_best_block_hash(&mut self) -> Result<String, NetworkError> {
        self.call("getbestblockhash", ()).await
    }

    /// Get block hash at height
    pub async fn get_block_hash(&mut self, height: u64) -> Result<String, NetworkError> {
        self.call("getblockhash", (height,)).await
    }

    // ========================================
    // Wallet/Address Methods
    // ========================================

    /// Get address balance
    pub async fn get_address_balance(&mut self, address: &str) -> Result<AddressBalance, NetworkError> {
        self.call("getaddressbalance", (address,)).await
    }

    /// Get UTXOs for an address
    pub async fn get_address_utxos(&mut self, address: &str) -> Result<Vec<GhostUtxo>, NetworkError> {
        self.call("getaddressutxos", (address,)).await
    }

    /// Get transaction history for an address
    pub async fn get_address_txids(&mut self, address: &str) -> Result<Vec<String>, NetworkError> {
        self.call("getaddresstxids", (address,)).await
    }

    /// Get new address
    pub async fn get_new_address(&mut self, label: Option<&str>) -> Result<String, NetworkError> {
        match label {
            Some(l) => self.call("getnewaddress", (l,)).await,
            None => self.call("getnewaddress", ()).await,
        }
    }

    /// Validate an address
    pub async fn validate_address(&mut self, address: &str) -> Result<serde_json::Value, NetworkError> {
        self.call("validateaddress", (address,)).await
    }

    // ========================================
    // Transaction Methods
    // ========================================

    /// Get transaction details
    pub async fn get_transaction(&mut self, txid: &str) -> Result<GhostTransaction, NetworkError> {
        self.call("gettransaction", (txid,)).await
    }

    /// Get raw transaction
    pub async fn get_raw_transaction(&mut self, txid: &str, verbose: bool) -> Result<serde_json::Value, NetworkError> {
        self.call("getrawtransaction", (txid, verbose)).await
    }

    /// Broadcast a signed transaction
    pub async fn send_raw_transaction(&mut self, hex: &str) -> Result<String, NetworkError> {
        self.call("sendrawtransaction", (hex,)).await
    }

    /// Estimate fee for confirmation in n blocks
    pub async fn estimate_fee(&mut self, conf_target: u32) -> Result<FeeEstimate, NetworkError> {
        self.call("estimatesmartfee", (conf_target,)).await
    }

    /// Create a raw transaction
    pub async fn create_raw_transaction(
        &mut self,
        inputs: Vec<serde_json::Value>,
        outputs: serde_json::Value,
    ) -> Result<String, NetworkError> {
        self.call("createrawtransaction", (inputs, outputs)).await
    }

    // ========================================
    // Wraith Protocol Methods
    // ========================================

    /// Get current Wraith mode
    pub fn get_wraith_mode(&self) -> WraithMode {
        self.wraith_mode
    }

    /// Set Wraith mode (public or private)
    pub async fn set_wraith_mode(&mut self, mode: WraithMode) -> Result<(), NetworkError> {
        let mode_str = match mode {
            WraithMode::Public => "public",
            WraithMode::Private => "private",
        };

        let _: serde_json::Value = self.call("setwraithmode", (mode_str,)).await?;
        self.wraith_mode = mode;
        Ok(())
    }

    /// Generate a stealth address for receiving private payments
    pub async fn get_stealth_address(&mut self, label: Option<&str>) -> Result<StealthAddress, NetworkError> {
        match label {
            Some(l) => self.call("getnewstealthaddress", (l,)).await,
            None => self.call("getnewstealthaddress", ()).await,
        }
    }

    /// Send a private transaction using Wraith Protocol
    pub async fn send_private(
        &mut self,
        to_address: &str,
        amount: f64,
        ring_size: Option<u32>,
    ) -> Result<String, NetworkError> {
        let ring = ring_size.unwrap_or(self.wraith_config.default_ring_size);

        #[derive(Serialize)]
        struct PrivateSendParams<'a> {
            address: &'a str,
            amount: f64,
            ringsize: u32,
        }

        let params = PrivateSendParams {
            address: to_address,
            amount,
            ringsize: ring,
        };

        self.call("sendtypeto", ("anon", "anon", vec![params])).await
    }

    /// Send from private to public (exit Wraith)
    pub async fn send_private_to_public(
        &mut self,
        to_address: &str,
        amount: f64,
    ) -> Result<String, NetworkError> {
        #[derive(Serialize)]
        struct SendParams<'a> {
            address: &'a str,
            amount: f64,
        }

        let params = SendParams {
            address: to_address,
            amount,
        };

        self.call("sendtypeto", ("anon", "ghost", vec![params])).await
    }

    /// Send from public to private (enter Wraith)
    pub async fn send_public_to_private(
        &mut self,
        to_stealth_address: &str,
        amount: f64,
    ) -> Result<String, NetworkError> {
        #[derive(Serialize)]
        struct SendParams<'a> {
            address: &'a str,
            amount: f64,
        }

        let params = SendParams {
            address: to_stealth_address,
            amount,
        };

        self.call("sendtypeto", ("ghost", "anon", vec![params])).await
    }

    /// Get private (anon) balance
    pub async fn get_private_balance(&mut self) -> Result<f64, NetworkError> {
        self.call("getbalance", ("*", 1, false, false, true)).await
    }

    /// Get public balance
    pub async fn get_public_balance(&mut self) -> Result<f64, NetworkError> {
        self.call("getbalance", ()).await
    }

    /// List stealth addresses
    pub async fn list_stealth_addresses(&mut self) -> Result<Vec<StealthAddress>, NetworkError> {
        self.call("liststealthaddresses", ()).await
    }

    /// Scan for incoming private transactions
    pub async fn rescan_anon_outputs(&mut self) -> Result<(), NetworkError> {
        let _: serde_json::Value = self.call("rescananonoutputs", ()).await?;
        Ok(())
    }

    // ========================================
    // Ghost Locks (Staking) Methods
    // ========================================

    /// Get staking information
    pub async fn get_staking_info(&mut self) -> Result<StakingInfo, NetworkError> {
        self.call("getstakinginfo", ()).await
    }

    /// Enable staking
    pub async fn enable_staking(&mut self, enable: bool) -> Result<(), NetworkError> {
        let _: serde_json::Value = self.call("staking", (enable,)).await?;
        Ok(())
    }

    /// Create a Ghost Lock (cold staking)
    pub async fn create_ghost_lock(
        &mut self,
        amount: f64,
        duration_days: u32,
        staking_address: Option<&str>,
    ) -> Result<GhostLock, NetworkError> {
        #[derive(Serialize)]
        struct LockParams<'a> {
            amount: f64,
            duration: u32,
            #[serde(skip_serializing_if = "Option::is_none")]
            staking_address: Option<&'a str>,
        }

        let params = LockParams {
            amount,
            duration: duration_days,
            staking_address,
        };

        self.call("createghostlock", (params,)).await
    }

    /// Get all Ghost Locks for the wallet
    pub async fn list_ghost_locks(&mut self) -> Result<Vec<GhostLock>, NetworkError> {
        self.call("listghostlocks", ()).await
    }

    /// Get a specific Ghost Lock
    pub async fn get_ghost_lock(&mut self, lock_id: &str) -> Result<GhostLock, NetworkError> {
        self.call("getghostlock", (lock_id,)).await
    }

    /// Unlock a matured Ghost Lock
    pub async fn unlock_ghost_lock(&mut self, lock_id: &str) -> Result<String, NetworkError> {
        self.call("unlockghostlock", (lock_id,)).await
    }

    /// Get total locked amount
    pub async fn get_total_locked(&mut self) -> Result<f64, NetworkError> {
        self.call("gettotallocked", ()).await
    }

    /// Get estimated staking rewards
    pub async fn estimate_staking_rewards(
        &mut self,
        amount: f64,
        duration_days: u32,
    ) -> Result<f64, NetworkError> {
        self.call("estimatestakingrewards", (amount, duration_days)).await
    }

    // ========================================
    // Jump Locks (HTLC / Cross-chain) Methods
    // ========================================

    /// Create a Jump Lock (Hash Time-Locked Contract)
    pub async fn create_jump_lock(
        &mut self,
        amount: f64,
        recipient: &str,
        hash_lock: &str,
        time_lock_hours: u32,
    ) -> Result<JumpLock, NetworkError> {
        #[derive(Serialize)]
        struct JumpLockParams<'a> {
            amount: f64,
            recipient: &'a str,
            hashlock: &'a str,
            timelock_hours: u32,
        }

        let params = JumpLockParams {
            amount,
            recipient,
            hashlock: hash_lock,
            timelock_hours: time_lock_hours,
        };

        self.call("createjumplock", (params,)).await
    }

    /// Claim a Jump Lock with the preimage
    pub async fn claim_jump_lock(
        &mut self,
        lock_id: &str,
        preimage: &str,
    ) -> Result<String, NetworkError> {
        self.call("claimjumplock", (lock_id, preimage)).await
    }

    /// Refund an expired Jump Lock
    pub async fn refund_jump_lock(&mut self, lock_id: &str) -> Result<String, NetworkError> {
        self.call("refundjumplock", (lock_id,)).await
    }

    /// List all Jump Locks
    pub async fn list_jump_locks(&mut self) -> Result<Vec<JumpLock>, NetworkError> {
        self.call("listjumplocks", ()).await
    }

    /// Get Jump Lock details
    pub async fn get_jump_lock(&mut self, lock_id: &str) -> Result<JumpLock, NetworkError> {
        self.call("getjumplock", (lock_id,)).await
    }

    /// Generate a hash for creating a Jump Lock
    pub async fn generate_jump_lock_hash(&mut self) -> Result<(String, String), NetworkError> {
        // Returns (hash, preimage)
        #[derive(Deserialize)]
        struct HashResult {
            hash: String,
            preimage: String,
        }

        let result: HashResult = self.call("generatejumplockhash", ()).await?;
        Ok((result.hash, result.preimage))
    }

    // ========================================
    // Utility Methods
    // ========================================

    /// Ping the node
    pub async fn ping(&mut self) -> Result<(), NetworkError> {
        let _: serde_json::Value = self.call("ping", ()).await?;
        Ok(())
    }

    /// Get network info
    pub async fn get_network_info(&mut self) -> Result<serde_json::Value, NetworkError> {
        self.call("getnetworkinfo", ()).await
    }

    /// Get peer info
    pub async fn get_peer_info(&mut self) -> Result<Vec<serde_json::Value>, NetworkError> {
        self.call("getpeerinfo", ()).await
    }

    /// Get wallet info
    pub async fn get_wallet_info(&mut self) -> Result<serde_json::Value, NetworkError> {
        self.call("getwalletinfo", ()).await
    }

    /// Encrypt wallet
    pub async fn encrypt_wallet(&mut self, passphrase: &str) -> Result<(), NetworkError> {
        let _: serde_json::Value = self.call("encryptwallet", (passphrase,)).await?;
        Ok(())
    }

    /// Unlock wallet for a duration
    pub async fn wallet_passphrase(
        &mut self,
        passphrase: &str,
        timeout_seconds: u32,
        staking_only: bool,
    ) -> Result<(), NetworkError> {
        let _: serde_json::Value = self
            .call("walletpassphrase", (passphrase, timeout_seconds, staking_only))
            .await?;
        Ok(())
    }

    /// Lock wallet
    pub async fn wallet_lock(&mut self) -> Result<(), NetworkError> {
        let _: serde_json::Value = self.call("walletlock", ()).await?;
        Ok(())
    }
}

// Re-export NodeClient as alias for backwards compatibility
pub type NodeClient = GhostClient;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_config_default() {
        let config = NodeConfig::default();
        assert!(!config.endpoints.is_empty());
        assert!(config.timeout_ms > 0);
    }

    #[test]
    fn test_node_config_mainnet() {
        let config = NodeConfig::mainnet();
        assert!(config.endpoints[0].contains("51725"));
    }

    #[test]
    fn test_node_config_testnet() {
        let config = NodeConfig::testnet();
        assert!(config.endpoints[0].contains("51925"));
    }

    #[test]
    fn test_node_config_with_auth() {
        let config = NodeConfig::default().with_auth("user", "pass");
        assert_eq!(config.rpc_user, Some("user".to_string()));
        assert_eq!(config.rpc_password, Some("pass".to_string()));
    }
}
