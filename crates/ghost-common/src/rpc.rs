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
//| FILE: rpc.rs                                                                                                         |
//|======================================================================================================================|

//! Bitcoin Core RPC client
//!
//! Provides async communication with Bitcoin Core via JSON-RPC.
//!
//! Security features:
//! - TLS required for remote connections (enforced)
//! - Block template validation before use
//! - Bounded fields to prevent DoS

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::warn;

use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use crate::error::{GhostError, GhostResult};

// ============================================================
// Retry Configuration
// ============================================================

/// Configuration for RPC retry behavior
#[derive(Debug, Clone)]
pub struct RpcRetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Initial backoff delay
    pub initial_backoff: Duration,
    /// Maximum backoff delay
    pub max_backoff: Duration,
    /// Backoff multiplier (exponential factor)
    pub backoff_multiplier: f64,
}

impl Default for RpcRetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
            backoff_multiplier: 2.0,
        }
    }
}

impl RpcRetryConfig {
    /// Config for critical operations (more retries, longer waits)
    pub fn critical() -> Self {
        Self {
            max_retries: 5,
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(10),
            backoff_multiplier: 2.0,
        }
    }

    /// Config for quick operations (fewer retries)
    pub fn quick() -> Self {
        Self {
            max_retries: 2,
            initial_backoff: Duration::from_millis(50),
            max_backoff: Duration::from_secs(1),
            backoff_multiplier: 2.0,
        }
    }

    /// No retries
    pub fn no_retry() -> Self {
        Self {
            max_retries: 0,
            initial_backoff: Duration::from_millis(0),
            max_backoff: Duration::from_millis(0),
            backoff_multiplier: 1.0,
        }
    }
}

/// Check if an RPC error is retryable (transient)
fn is_retryable_error(error: &GhostError) -> bool {
    match error {
        GhostError::Rpc(msg) => {
            // Network/timeout errors are retryable
            let transient_patterns = [
                "Request failed",
                "timeout",
                "connection refused",
                "connection reset",
                "temporarily unavailable",
                "rate limit",
                "ETIMEDOUT",
                "ECONNRESET",
                "ECONNREFUSED",
            ];
            transient_patterns
                .iter()
                .any(|pattern| msg.to_lowercase().contains(&pattern.to_lowercase()))
        }
        GhostError::Internal(msg) => msg.contains("timeout") || msg.contains("connection"),
        _ => false,
    }
}

// ============================================================
// Security Constants
// ============================================================

/// Maximum transactions in a block template
pub const MAX_TEMPLATE_TRANSACTIONS: usize = 10_000;
/// Maximum coinbaseaux entries
pub const MAX_COINBASE_AUX_ENTRIES: usize = 32;
/// Maximum coinbaseaux key length
pub const MAX_COINBASE_AUX_KEY_LEN: usize = 64;
/// Maximum coinbaseaux value length
pub const MAX_COINBASE_AUX_VALUE_LEN: usize = 256;
/// Valid previousblockhash length (64 hex chars)
pub const BLOCK_HASH_HEX_LEN: usize = 64;
/// Valid bits field length (8 hex chars)
pub const BITS_HEX_LEN: usize = 8;
/// Maximum height deviation from current
pub const MAX_HEIGHT_DEVIATION: u64 = 10;
/// Maximum Bitcoin supply in satoshis
pub const MAX_SUPPLY_SATS: u64 = 21_000_000 * 100_000_000;

// ============================================================
// Template Validation
// ============================================================

/// Block template validation errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum TemplateValidationError {
    #[error("Invalid previousblockhash: expected {BLOCK_HASH_HEX_LEN} hex chars, got {0}")]
    InvalidPrevHash(usize),
    #[error("Invalid bits format: expected {BITS_HEX_LEN} hex chars, got {0}")]
    InvalidBits(usize),
    #[error("Too many transactions: {0} > {MAX_TEMPLATE_TRANSACTIONS}")]
    TooManyTransactions(usize),
    #[error("Too many coinbaseaux entries: {0} > {MAX_COINBASE_AUX_ENTRIES}")]
    TooManyCoinbaseAux(usize),
    #[error("Coinbaseaux key too long: {0} > {MAX_COINBASE_AUX_KEY_LEN}")]
    CoinbaseAuxKeyTooLong(usize),
    #[error("Coinbaseaux value too long: {0} > {MAX_COINBASE_AUX_VALUE_LEN}")]
    CoinbaseAuxValueTooLong(usize),
    #[error("Coinbase value exceeds max supply: {0}")]
    InvalidCoinbaseValue(u64),
    #[error("Height out of range: template={0}, expected near {1}")]
    HeightOutOfRange(u64, u64),
    #[error("Invalid target format: expected 64 hex chars")]
    InvalidTarget,
    #[error("Invalid hex in field {0}")]
    InvalidHex(String),
}

/// Validate a block template before use
pub fn validate_block_template(
    template: &BlockTemplate,
    current_height: Option<u64>,
) -> Result<(), TemplateValidationError> {
    // Validate previousblockhash format (64 hex chars)
    if template.previousblockhash.len() != BLOCK_HASH_HEX_LEN {
        return Err(TemplateValidationError::InvalidPrevHash(
            template.previousblockhash.len(),
        ));
    }
    if !template
        .previousblockhash
        .chars()
        .all(|c| c.is_ascii_hexdigit())
    {
        return Err(TemplateValidationError::InvalidHex(
            "previousblockhash".into(),
        ));
    }

    // Validate bits format (8 hex chars)
    if template.bits.len() != BITS_HEX_LEN {
        return Err(TemplateValidationError::InvalidBits(template.bits.len()));
    }
    if !template.bits.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(TemplateValidationError::InvalidHex("bits".into()));
    }

    // Validate transaction count
    if template.transactions.len() > MAX_TEMPLATE_TRANSACTIONS {
        return Err(TemplateValidationError::TooManyTransactions(
            template.transactions.len(),
        ));
    }

    // Validate coinbaseaux bounds
    if template.coinbaseaux.len() > MAX_COINBASE_AUX_ENTRIES {
        return Err(TemplateValidationError::TooManyCoinbaseAux(
            template.coinbaseaux.len(),
        ));
    }
    for (key, value) in &template.coinbaseaux {
        if key.len() > MAX_COINBASE_AUX_KEY_LEN {
            return Err(TemplateValidationError::CoinbaseAuxKeyTooLong(key.len()));
        }
        if value.len() > MAX_COINBASE_AUX_VALUE_LEN {
            return Err(TemplateValidationError::CoinbaseAuxValueTooLong(
                value.len(),
            ));
        }
    }

    // Validate coinbase value (can't exceed max supply)
    if template.coinbasevalue > MAX_SUPPLY_SATS {
        return Err(TemplateValidationError::InvalidCoinbaseValue(
            template.coinbasevalue,
        ));
    }

    // Validate height if current height known
    if let Some(current) = current_height {
        let min_height = current.saturating_sub(MAX_HEIGHT_DEVIATION);
        let max_height = current.saturating_add(MAX_HEIGHT_DEVIATION);
        if template.height < min_height || template.height > max_height {
            return Err(TemplateValidationError::HeightOutOfRange(
                template.height,
                current,
            ));
        }
    }

    // Validate target format (64 hex chars)
    if template.target.len() != 64 || !template.target.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(TemplateValidationError::InvalidTarget);
    }

    Ok(())
}

// ============================================================
// RPC Configuration
// ============================================================

/// RPC client configuration
#[derive(Debug, Clone)]
pub struct RpcConfig {
    /// Host address
    pub host: String,
    /// Port number
    pub port: u16,
    /// RPC username
    pub username: String,
    /// RPC password
    pub password: String,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
    /// Enable TLS (required for remote connections)
    pub tls_enabled: bool,
    /// Custom CA certificate path (for self-signed certs)
    pub tls_cert_path: Option<PathBuf>,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 8332,
            username: String::new(),
            password: String::new(),
            timeout_secs: 30,
            tls_enabled: false,
            tls_cert_path: None,
        }
    }
}

impl RpcConfig {
    /// Check if the host is localhost
    pub fn is_localhost(&self) -> bool {
        self.host == "127.0.0.1" || self.host == "localhost" || self.host == "::1"
    }

    /// Validate the configuration
    pub fn validate(&self) -> GhostResult<()> {
        // TLS required for remote connections
        if !self.is_localhost() && !self.tls_enabled {
            return Err(GhostError::Config(
                "TLS required for remote Bitcoin Core connections. \
                 Set tls_enabled=true or use localhost."
                    .into(),
            ));
        }
        Ok(())
    }
}

// ============================================================
// RPC Client
// ============================================================

/// Bitcoin Core RPC client
pub struct BitcoinRpc {
    /// HTTP client
    client: reqwest::Client,
    /// RPC URL
    url: String,
    /// Basic auth header value
    auth: String,
    /// Request ID counter
    id_counter: AtomicU64,
    /// Last known block height (for template validation)
    last_known_height: AtomicU64,
    /// Circuit breaker for fault tolerance
    circuit_breaker: Arc<CircuitBreaker>,
    /// Retry configuration
    retry_config: RpcRetryConfig,
}

impl std::fmt::Debug for BitcoinRpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitcoinRpc")
            .field("url", &self.url)
            .field("id_counter", &self.id_counter)
            .field("last_known_height", &self.last_known_height)
            .finish()
    }
}

impl BitcoinRpc {
    /// Create a new RPC client (legacy constructor for localhost)
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be created
    pub fn new(host: &str, port: u16, user: &str, password: &str) -> GhostResult<Self> {
        let config = RpcConfig {
            host: host.to_string(),
            port,
            username: user.to_string(),
            password: password.to_string(),
            ..Default::default()
        };
        Self::with_config(config)
    }

    /// Create a new RPC client with full configuration
    pub fn with_config(config: RpcConfig) -> GhostResult<Self> {
        Self::with_config_and_retry(config, RpcRetryConfig::default())
    }

    /// Create a new RPC client with full configuration and retry settings
    pub fn with_config_and_retry(
        config: RpcConfig,
        retry_config: RpcRetryConfig,
    ) -> GhostResult<Self> {
        use base64::Engine;

        // Validate configuration
        config.validate()?;

        // Warn about insecure localhost (but allow it)
        if config.is_localhost() && !config.tls_enabled {
            tracing::warn!(
                "Using unencrypted connection to Bitcoin Core on localhost. \
                 Consider enabling TLS for defense in depth."
            );
        }

        let scheme = if config.tls_enabled { "https" } else { "http" };
        let url = format!("{}://{}:{}", scheme, config.host, config.port);
        let auth = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", config.username, config.password));

        let mut client_builder =
            reqwest::Client::builder().timeout(std::time::Duration::from_secs(config.timeout_secs));

        // Add custom CA certificate if provided
        if let Some(ref cert_path) = config.tls_cert_path {
            let cert_pem = std::fs::read(cert_path).map_err(|e| {
                GhostError::Config(format!("Failed to read TLS cert at {:?}: {}", cert_path, e))
            })?;
            let cert = reqwest::Certificate::from_pem(&cert_pem)
                .map_err(|e| GhostError::Config(format!("Invalid TLS cert: {}", e)))?;
            client_builder = client_builder.add_root_certificate(cert);
        }

        let client = client_builder
            .build()
            .map_err(|e| GhostError::Internal(format!("Failed to create HTTP client: {}", e)))?;

        // Create circuit breaker for this RPC client
        let circuit_breaker = Arc::new(CircuitBreaker::new(
            format!("bitcoin_rpc_{}", config.host),
            CircuitBreakerConfig::default(),
        ));

        Ok(Self {
            client,
            url,
            auth,
            id_counter: AtomicU64::new(1),
            last_known_height: AtomicU64::new(0),
            circuit_breaker,
            retry_config,
        })
    }

    /// Get a reference to the circuit breaker for manual control
    pub fn circuit_breaker(&self) -> &CircuitBreaker {
        &self.circuit_breaker
    }

    /// Make an RPC call with retry and circuit breaker protection
    async fn call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: Vec<Value>,
    ) -> GhostResult<T> {
        self.call_with_retry(method, params, &self.retry_config)
            .await
    }

    /// Make an RPC call with custom retry configuration
    async fn call_with_retry<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: Vec<Value>,
        retry_config: &RpcRetryConfig,
    ) -> GhostResult<T> {
        let mut attempt = 0;
        let mut backoff = retry_config.initial_backoff;

        loop {
            // Check circuit breaker first
            if !self.circuit_breaker.is_allowed() {
                return Err(GhostError::Rpc(
                    "Circuit breaker open - Bitcoin Core RPC unavailable".to_string(),
                ));
            }

            match self.call_inner(method, &params).await {
                Ok(result) => {
                    self.circuit_breaker.record_success();
                    return Ok(result);
                }
                Err(e) => {
                    self.circuit_breaker.record_failure();

                    // Check if we should retry
                    if attempt < retry_config.max_retries && is_retryable_error(&e) {
                        attempt += 1;
                        warn!(
                            method,
                            attempt,
                            max_retries = retry_config.max_retries,
                            backoff_ms = backoff.as_millis(),
                            error = %e,
                            "RPC call failed, retrying"
                        );
                        sleep(backoff).await;
                        backoff = Duration::from_millis(
                            ((backoff.as_millis() as f64 * retry_config.backoff_multiplier) as u64)
                                .min(retry_config.max_backoff.as_millis() as u64),
                        );
                    } else {
                        if attempt > 0 {
                            warn!(
                                method,
                                attempts = attempt + 1,
                                "RPC call failed after retries"
                            );
                        }
                        return Err(e);
                    }
                }
            }
        }
    }

    /// Internal call without retry logic
    async fn call_inner<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: &[Value],
    ) -> GhostResult<T> {
        let id = self.id_counter.fetch_add(1, Ordering::SeqCst);

        let request = json!({
            "jsonrpc": "1.0",
            "id": id,
            "method": method,
            "params": params,
        });

        let response = self
            .client
            .post(&self.url)
            .header("Authorization", format!("Basic {}", self.auth))
            .json(&request)
            .send()
            .await
            .map_err(|e| GhostError::Rpc(format!("Request failed: {}", e)))?;

        let rpc_response: RpcResponse<T> = response
            .json()
            .await
            .map_err(|e| GhostError::Rpc(format!("Failed to parse response: {}", e)))?;

        if let Some(error) = rpc_response.error {
            return Err(GhostError::Rpc(format!(
                "RPC error {}: {}",
                error.code, error.message
            )));
        }

        rpc_response
            .result
            .ok_or_else(|| GhostError::Rpc("Empty response".to_string()))
    }

    /// Update last known height (call after successful blockchain queries)
    fn update_height(&self, height: u64) {
        self.last_known_height.store(height, Ordering::SeqCst);
    }

    /// Get last known height
    pub fn last_known_height(&self) -> u64 {
        self.last_known_height.load(Ordering::SeqCst)
    }

    /// Get blockchain info
    pub async fn get_blockchain_info(&self) -> GhostResult<BlockchainInfo> {
        let info: BlockchainInfo = self.call("getblockchaininfo", vec![]).await?;
        self.update_height(info.blocks);
        Ok(info)
    }

    /// Get best block hash
    pub async fn get_best_block_hash(&self) -> GhostResult<String> {
        self.call("getbestblockhash", vec![]).await
    }

    /// Get block by hash
    pub async fn get_block(&self, hash: &str, verbosity: u8) -> GhostResult<Value> {
        self.call("getblock", vec![json!(hash), json!(verbosity)])
            .await
    }

    /// Get block header
    pub async fn get_block_header(&self, hash: &str) -> GhostResult<BlockHeader> {
        self.call("getblockheader", vec![json!(hash), json!(true)])
            .await
    }

    /// Get block count (height)
    pub async fn get_block_count(&self) -> GhostResult<u64> {
        let height: u64 = self.call("getblockcount", vec![]).await?;
        self.update_height(height);
        Ok(height)
    }

    /// Get network difficulty
    pub async fn get_difficulty(&self) -> GhostResult<f64> {
        self.call("getdifficulty", vec![]).await
    }

    /// Get block template for mining (with validation)
    ///
    /// Validates the template before returning to prevent malicious/malformed templates.
    pub async fn get_block_template(&self, rules: Vec<&str>) -> GhostResult<BlockTemplate> {
        let params = json!({
            "rules": rules,
            "capabilities": ["coinbasetxn", "workid", "coinbase/append"],
        });
        let template: BlockTemplate = self.call("getblocktemplate", vec![params]).await?;

        // Validate template before returning
        let current_height = {
            let h = self.last_known_height.load(Ordering::SeqCst);
            if h > 0 {
                Some(h)
            } else {
                None
            }
        };

        validate_block_template(&template, current_height).map_err(|e| {
            tracing::error!("Block template validation failed: {}", e);
            GhostError::InvalidBlockTemplate(e.to_string())
        })?;

        // Update height from template
        self.update_height(template.height);

        Ok(template)
    }

    /// Get block template without validation (use with caution)
    ///
    /// Only use this if you're doing your own validation.
    pub async fn get_block_template_unchecked(
        &self,
        rules: Vec<&str>,
    ) -> GhostResult<BlockTemplate> {
        let params = json!({
            "rules": rules,
            "capabilities": ["coinbasetxn", "workid", "coinbase/append"],
        });
        self.call("getblocktemplate", vec![params]).await
    }

    /// Submit a block
    pub async fn submit_block(&self, block_hex: &str) -> GhostResult<Option<String>> {
        self.call("submitblock", vec![json!(block_hex)]).await
    }

    /// Get raw mempool
    pub async fn get_raw_mempool(&self, verbose: bool) -> GhostResult<Value> {
        self.call("getrawmempool", vec![json!(verbose)]).await
    }

    /// Get mempool entry
    pub async fn get_mempool_entry(&self, txid: &str) -> GhostResult<MempoolEntry> {
        self.call("getmempoolentry", vec![json!(txid)]).await
    }

    /// Get raw transaction
    pub async fn get_raw_transaction(&self, txid: &str, verbose: bool) -> GhostResult<Value> {
        self.call("getrawtransaction", vec![json!(txid), json!(verbose)])
            .await
    }

    /// Send raw transaction
    pub async fn send_raw_transaction(&self, tx_hex: &str) -> GhostResult<String> {
        self.call("sendrawtransaction", vec![json!(tx_hex)]).await
    }

    /// Decode raw transaction
    pub async fn decode_raw_transaction(&self, tx_hex: &str) -> GhostResult<Value> {
        self.call("decoderawtransaction", vec![json!(tx_hex)]).await
    }

    /// Get network info
    pub async fn get_network_info(&self) -> GhostResult<NetworkInfo> {
        self.call("getnetworkinfo", vec![]).await
    }

    /// Get mining info
    pub async fn get_mining_info(&self) -> GhostResult<MiningInfo> {
        self.call("getmininginfo", vec![]).await
    }

    /// Test mempool accept
    pub async fn test_mempool_accept(
        &self,
        tx_hexes: Vec<&str>,
    ) -> GhostResult<Vec<MempoolAcceptResult>> {
        self.call("testmempoolaccept", vec![json!(tx_hexes)]).await
    }

    /// Estimate smart fee
    pub async fn estimate_smart_fee(&self, conf_target: u32) -> GhostResult<FeeEstimate> {
        self.call("estimatesmartfee", vec![json!(conf_target)])
            .await
    }

    /// Get block hash by height
    pub async fn get_block_hash(&self, height: u64) -> GhostResult<String> {
        self.call("getblockhash", vec![json!(height)]).await
    }

    /// Get UTXO info
    pub async fn get_tx_out(
        &self,
        txid: &str,
        vout: u32,
        include_mempool: bool,
    ) -> GhostResult<Option<TxOut>> {
        self.call(
            "gettxout",
            vec![json!(txid), json!(vout), json!(include_mempool)],
        )
        .await
    }

    /// Validate an address
    pub async fn validate_address(&self, address: &str) -> GhostResult<AddressValidation> {
        self.call("validateaddress", vec![json!(address)]).await
    }

    /// Get address info (for wallet addresses)
    pub async fn get_address_info(&self, address: &str) -> GhostResult<Value> {
        self.call("getaddressinfo", vec![json!(address)]).await
    }

    /// List unspent outputs (requires wallet)
    pub async fn list_unspent(
        &self,
        min_conf: u32,
        max_conf: u32,
        addresses: Vec<&str>,
    ) -> GhostResult<Vec<UnspentOutput>> {
        self.call(
            "listunspent",
            vec![json!(min_conf), json!(max_conf), json!(addresses)],
        )
        .await
    }

    /// Create raw transaction
    pub async fn create_raw_transaction(
        &self,
        inputs: Vec<TxInput>,
        outputs: &serde_json::Map<String, Value>,
    ) -> GhostResult<String> {
        self.call("createrawtransaction", vec![json!(inputs), json!(outputs)])
            .await
    }

    /// Sign raw transaction with wallet
    pub async fn sign_raw_transaction_with_wallet(
        &self,
        tx_hex: &str,
    ) -> GhostResult<SignedTransaction> {
        self.call("signrawtransactionwithwallet", vec![json!(tx_hex)])
            .await
    }

    /// Get chain tips
    pub async fn get_chain_tips(&self) -> GhostResult<Vec<ChainTip>> {
        self.call("getchaintips", vec![]).await
    }

    /// Verify chain
    pub async fn verify_chain(&self, check_level: u32, num_blocks: u32) -> GhostResult<bool> {
        self.call("verifychain", vec![json!(check_level), json!(num_blocks)])
            .await
    }

    /// Get mempool info
    pub async fn get_mempool_info(&self) -> GhostResult<MempoolInfo> {
        self.call("getmempoolinfo", vec![]).await
    }

    // ============================================================
    // Ghost-Core Specific RPC Methods
    // ============================================================

    /// Get the wallet's Ghost ID (Silent Payment address)
    pub async fn get_silent_payment_address(&self) -> GhostResult<SilentPaymentAddress> {
        self.call("getsilentpaymentaddress", vec![]).await
    }

    /// Derive a one-time P2TR address from a Ghost ID
    pub async fn derive_silent_payment_address(
        &self,
        ghost_id: &str,
        index: u32,
        nonce: u16,
    ) -> GhostResult<DerivedAddress> {
        self.call(
            "derivesilentpaymentaddress",
            vec![json!(ghost_id), json!(index), json!(nonce)],
        )
        .await
    }

    /// Check if a transaction output belongs to this wallet via Silent Payment
    pub async fn check_silent_payment(
        &self,
        txid: &str,
        vout: u32,
        ephemeral_pubkey: &str,
    ) -> GhostResult<SilentPaymentCheck> {
        self.call(
            "checksilentpayment",
            vec![json!(txid), json!(vout), json!(ephemeral_pubkey)],
        )
        .await
    }

    /// Parse Ghost Lock OP_RETURN data
    pub async fn parse_ghost_op_return(&self, data_hex: &str) -> GhostResult<GhostOpReturnData> {
        self.call("parseghostopreturn", vec![json!(data_hex)]).await
    }

    /// Rescan blockchain for Silent Payment outputs
    pub async fn rescan_silent_payments(
        &self,
        start_height: Option<u64>,
        stop_height: Option<u64>,
    ) -> GhostResult<RescanResult> {
        let params = match (start_height, stop_height) {
            (Some(start), Some(stop)) => vec![json!(start), json!(stop)],
            (Some(start), None) => vec![json!(start)],
            _ => vec![],
        };
        self.call("rescansilentpayments", params).await
    }

    /// Get Silent Payment scanning statistics
    pub async fn get_silent_payment_stats(&self) -> GhostResult<SilentPaymentStats> {
        self.call("getsilentpaymentstats", vec![]).await
    }

    /// Create a Wraith Phase 1 (Split) transaction
    pub async fn create_wraith_tx(
        &self,
        inputs: Vec<WraithInputRpc>,
        intermediate_addresses: Vec<Vec<String>>,
        session_id: &str,
        denomination: &str,
    ) -> GhostResult<WraithTxResult> {
        self.call(
            "createwraithtx",
            vec![
                json!(inputs),
                json!(intermediate_addresses),
                json!(session_id),
                json!(denomination),
            ],
        )
        .await
    }

    /// Create a Wraith Phase 2 (Merge) transaction
    pub async fn create_wraith_final_tx(
        &self,
        intermediate_inputs: Vec<WraithInputRpc>,
        final_addresses: Vec<String>,
        session_id: &str,
    ) -> GhostResult<WraithTxResult> {
        self.call(
            "createwraithfinaltx",
            vec![
                json!(intermediate_inputs),
                json!(final_addresses),
                json!(session_id),
            ],
        )
        .await
    }

    /// Parse Wraith transaction metadata
    pub async fn parse_wraith_tx(&self, txid: &str) -> GhostResult<WraithTxInfo> {
        self.call("parsewraithtx", vec![json!(txid)]).await
    }

    /// Shuffle transaction outputs deterministically
    pub async fn shuffle_outputs(&self, tx_hex: &str, seed: &str) -> GhostResult<String> {
        self.call("shuffleoutputs", vec![json!(tx_hex), json!(seed)])
            .await
    }

    /// Create a reconciliation batch transaction
    pub async fn create_reconciliation_tx(
        &self,
        inputs: Vec<ReconciliationInputRpc>,
        outputs: Vec<ReconciliationOutputRpc>,
        epoch_id: u32,
        state_root: &str,
        treasury_address: Option<&str>,
        treasury_amount: Option<u64>,
    ) -> GhostResult<ReconciliationTxResult> {
        let mut params = vec![
            json!(inputs),
            json!(outputs),
            json!(epoch_id),
            json!(state_root),
        ];
        if let Some(addr) = treasury_address {
            params.push(json!(addr));
            params.push(json!(treasury_amount.unwrap_or(0)));
        }
        self.call("createreconciliationtx", params).await
    }

    /// Create a PSBT for batch signing coordination
    pub async fn coordinate_batch_signing(
        &self,
        inputs: Vec<ReconciliationInputRpc>,
        outputs: Vec<ReconciliationOutputRpc>,
    ) -> GhostResult<String> {
        self.call(
            "coordinatebatchsigning",
            vec![json!(inputs), json!(outputs)],
        )
        .await
    }

    /// Combine multiple PSBTs from batch signing participants
    pub async fn combine_batch_psbt(&self, psbts: Vec<String>) -> GhostResult<CombinedPsbtResult> {
        self.call("combinebatchpsbt", vec![json!(psbts)]).await
    }

    /// Estimate fee for a batch reconciliation transaction
    pub async fn estimate_batch_fee(
        &self,
        input_count: u32,
        output_count: u32,
        conf_target: u32,
    ) -> GhostResult<BatchFeeEstimate> {
        self.call(
            "estimatebatchfee",
            vec![json!(input_count), json!(output_count), json!(conf_target)],
        )
        .await
    }

    /// Derive reconciliation output addresses from Ghost IDs
    pub async fn derive_reconciliation_outputs(
        &self,
        ghost_ids: Vec<String>,
        amounts: Vec<u64>,
    ) -> GhostResult<Vec<DerivedAddress>> {
        self.call(
            "derivereconciliationoutputs",
            vec![json!(ghost_ids), json!(amounts)],
        )
        .await
    }
}

// ============================================================
// Response Types
// ============================================================

/// RPC response wrapper
#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
    #[allow(dead_code)]
    id: u64,
}

/// RPC error
#[derive(Debug, Deserialize)]
struct RpcError {
    code: i32,
    message: String,
}

/// Blockchain info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainInfo {
    pub chain: String,
    pub blocks: u64,
    pub headers: u64,
    pub bestblockhash: String,
    pub difficulty: f64,
    pub time: u64,
    pub mediantime: u64,
    pub verificationprogress: f64,
    pub initialblockdownload: bool,
    pub chainwork: String,
    pub size_on_disk: u64,
    pub pruned: bool,
}

/// Block header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub hash: String,
    pub confirmations: i64,
    pub height: u64,
    pub version: u32,
    #[serde(rename = "versionHex")]
    pub version_hex: Option<String>,
    pub merkleroot: String,
    pub time: u64,
    pub mediantime: u64,
    pub nonce: u64,
    pub bits: String,
    pub difficulty: f64,
    pub chainwork: String,
    #[serde(rename = "nTx")]
    pub n_tx: u64,
    pub previousblockhash: Option<String>,
    pub nextblockhash: Option<String>,
}

/// Block template from getblocktemplate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTemplate {
    pub version: u32,
    pub rules: Vec<String>,
    pub vbavailable: std::collections::HashMap<String, u32>,
    pub vbrequired: u32,
    pub previousblockhash: String,
    pub transactions: Vec<TemplateTransaction>,
    /// Coinbase auxiliary data (bounded during validation)
    pub coinbaseaux: std::collections::HashMap<String, String>,
    pub coinbasevalue: u64,
    pub longpollid: Option<String>,
    pub target: String,
    pub mintime: u64,
    pub mutable: Vec<String>,
    pub noncerange: String,
    pub sigoplimit: u64,
    pub sizelimit: u64,
    pub weightlimit: u64,
    pub curtime: u64,
    pub bits: String,
    pub height: u64,
    #[serde(default)]
    pub default_witness_commitment: Option<String>,
}

/// Transaction in block template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateTransaction {
    pub data: String,
    pub txid: String,
    pub hash: String,
    pub depends: Vec<u32>,
    pub fee: u64,
    pub sigops: u64,
    pub weight: u64,
}

/// Mempool entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolEntry {
    pub vsize: u64,
    pub weight: u64,
    pub fee: f64,
    pub modifiedfee: f64,
    pub time: u64,
    pub height: u64,
    pub descendantcount: u64,
    pub descendantsize: u64,
    pub descendantfees: u64,
    pub ancestorcount: u64,
    pub ancestorsize: u64,
    pub ancestorfees: u64,
    pub wtxid: String,
    pub fees: MempoolFees,
    pub depends: Vec<String>,
    pub spentby: Vec<String>,
    #[serde(rename = "bip125-replaceable")]
    pub bip125_replaceable: bool,
}

/// Mempool fees
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolFees {
    pub base: f64,
    pub modified: f64,
    pub ancestor: f64,
    pub descendant: f64,
}

/// Network info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub version: u64,
    pub subversion: String,
    pub protocolversion: u64,
    pub localservices: String,
    pub localservicesnames: Vec<String>,
    pub localrelay: bool,
    pub timeoffset: i64,
    pub networkactive: bool,
    pub connections: u64,
    pub connections_in: u64,
    pub connections_out: u64,
    pub networks: Vec<NetworkType>,
    pub relayfee: f64,
    pub incrementalfee: f64,
    pub localaddresses: Vec<LocalAddress>,
    pub warnings: String,
}

/// Network type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkType {
    pub name: String,
    pub limited: bool,
    pub reachable: bool,
    pub proxy: String,
    pub proxy_randomize_credentials: bool,
}

/// Local address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalAddress {
    pub address: String,
    pub port: u16,
    pub score: u64,
}

/// Mining info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningInfo {
    pub blocks: u64,
    pub difficulty: f64,
    pub networkhashps: f64,
    pub pooledtx: u64,
    pub chain: String,
    pub warnings: String,
}

/// Mempool accept result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolAcceptResult {
    pub txid: String,
    pub wtxid: String,
    pub allowed: Option<bool>,
    #[serde(rename = "reject-reason")]
    pub reject_reason: Option<String>,
    pub vsize: Option<u64>,
    pub fees: Option<MempoolAcceptFees>,
}

/// Mempool accept fees
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolAcceptFees {
    pub base: f64,
}

/// Fee estimate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimate {
    pub feerate: Option<f64>,
    pub errors: Option<Vec<String>>,
    pub blocks: u64,
}

/// Transaction output info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOut {
    pub bestblock: String,
    pub confirmations: i64,
    pub value: f64,
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: ScriptPubKey,
    pub coinbase: bool,
}

/// Script pubkey info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptPubKey {
    pub asm: String,
    pub desc: Option<String>,
    pub hex: String,
    pub address: Option<String>,
    #[serde(rename = "type")]
    pub script_type: String,
}

/// Address validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressValidation {
    pub isvalid: bool,
    pub address: Option<String>,
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: Option<String>,
    pub isscript: Option<bool>,
    pub iswitness: Option<bool>,
    pub witness_version: Option<u32>,
    pub witness_program: Option<String>,
}

/// Unspent output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnspentOutput {
    pub txid: String,
    pub vout: u32,
    pub address: Option<String>,
    pub label: Option<String>,
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: String,
    pub amount: f64,
    pub confirmations: u64,
    pub spendable: bool,
    pub solvable: bool,
    pub safe: bool,
}

/// Transaction input for creating raw transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInput {
    pub txid: String,
    pub vout: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u32>,
}

/// Signed transaction result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransaction {
    pub hex: String,
    pub complete: bool,
    pub errors: Option<Vec<SigningError>>,
}

/// Signing error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningError {
    pub txid: String,
    pub vout: u32,
    #[serde(rename = "scriptSig")]
    pub script_sig: String,
    pub sequence: u64,
    pub error: String,
}

/// Chain tip info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainTip {
    pub height: u64,
    pub hash: String,
    pub branchlen: u64,
    pub status: String,
}

/// Mempool info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolInfo {
    pub loaded: bool,
    pub size: u64,
    pub bytes: u64,
    pub usage: u64,
    pub total_fee: f64,
    pub maxmempool: u64,
    pub mempoolminfee: f64,
    pub minrelaytxfee: f64,
    pub incrementalrelayfee: f64,
    pub unbroadcastcount: u64,
    pub fullrbf: bool,
}

// ============================================================
// Ghost-Core Specific Types
// ============================================================

/// Silent Payment address (Ghost ID)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SilentPaymentAddress {
    pub address: String,
    pub scan_pubkey: String,
    pub spend_pubkey: String,
}

/// Derived address from Silent Payment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivedAddress {
    pub address: String,
    pub output_pubkey: String,
    pub ephemeral_pubkey: String,
    pub tweak: String,
}

/// Result of checking Silent Payment ownership
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SilentPaymentCheck {
    pub is_mine: bool,
    pub tweak: Option<String>,
    pub amount: Option<u64>,
}

/// Parsed Ghost Lock OP_RETURN data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostOpReturnData {
    pub valid: bool,
    pub ephemeral_pubkey: Option<String>,
    pub extra_data: Option<String>,
}

/// Result of Silent Payment rescan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RescanResult {
    pub outputs_found: u64,
    pub total_amount: u64,
    pub start_height: u64,
    pub end_height: u64,
}

/// Silent Payment statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SilentPaymentStats {
    pub output_count: u64,
    pub total_balance: u64,
    pub earliest_block: Option<u64>,
    pub latest_block: Option<u64>,
}

/// Input for Wraith RPC calls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WraithInputRpc {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub script_pubkey: Option<String>,
}

/// Result of Wraith transaction creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WraithTxResult {
    pub hex: String,
    pub txid: String,
    pub complete: bool,
    pub fee: u64,
    pub input_count: u32,
    pub output_count: u32,
}

/// Wraith transaction info from parsing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WraithTxInfo {
    pub session_id: String,
    pub phase: u8,
    pub participant_count: u16,
    pub valid: bool,
}

/// Input for Reconciliation RPC calls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationInputRpc {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub lock_id: String,
}

/// Output for Reconciliation RPC calls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationOutputRpc {
    pub ghost_id: String,
    pub amount: u64,
    pub output_type: String,
}

/// Result of Reconciliation transaction creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationTxResult {
    pub hex: String,
    pub txid: String,
    pub complete: bool,
    pub fee: u64,
    pub state_root: String,
    pub epoch_id: u32,
}

/// Result of combining PSBTs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinedPsbtResult {
    pub psbt: String,
    pub complete: bool,
    pub hex: Option<String>,
}

/// Batch fee estimate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchFeeEstimate {
    pub fee: u64,
    pub fee_rate: f64,
    pub vsize: u64,
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_client_creation() {
        let client = BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap();
        assert!(client.url.contains("127.0.0.1"));
    }

    #[test]
    fn test_rpc_config_localhost_no_tls() {
        let config = RpcConfig {
            host: "127.0.0.1".into(),
            port: 8332,
            tls_enabled: false,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_rpc_config_remote_requires_tls() {
        let config = RpcConfig {
            host: "192.168.1.100".into(),
            port: 8332,
            tls_enabled: false,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_rpc_config_remote_with_tls() {
        let config = RpcConfig {
            host: "192.168.1.100".into(),
            port: 8332,
            tls_enabled: true,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_template_validation_valid() {
        let template = BlockTemplate {
            version: 0x20000000,
            rules: vec!["segwit".into()],
            vbavailable: Default::default(),
            vbrequired: 0,
            previousblockhash: "0".repeat(64),
            transactions: vec![],
            coinbaseaux: Default::default(),
            coinbasevalue: 312_500_000,
            longpollid: None,
            target: "0".repeat(64),
            mintime: 0,
            mutable: vec![],
            noncerange: "00000000ffffffff".into(),
            sigoplimit: 80000,
            sizelimit: 4000000,
            weightlimit: 4000000,
            curtime: 1700000000,
            bits: "1a0377ae".into(),
            height: 800000,
            default_witness_commitment: None,
        };

        assert!(validate_block_template(&template, Some(800000)).is_ok());
    }

    #[test]
    fn test_template_validation_invalid_prev_hash() {
        let template = BlockTemplate {
            version: 0x20000000,
            rules: vec![],
            vbavailable: Default::default(),
            vbrequired: 0,
            previousblockhash: "short".into(), // Invalid
            transactions: vec![],
            coinbaseaux: Default::default(),
            coinbasevalue: 312_500_000,
            longpollid: None,
            target: "0".repeat(64),
            mintime: 0,
            mutable: vec![],
            noncerange: "00000000ffffffff".into(),
            sigoplimit: 80000,
            sizelimit: 4000000,
            weightlimit: 4000000,
            curtime: 1700000000,
            bits: "1a0377ae".into(),
            height: 800000,
            default_witness_commitment: None,
        };

        assert!(validate_block_template(&template, None).is_err());
    }

    #[test]
    fn test_template_validation_too_many_coinbaseaux() {
        let mut coinbaseaux = std::collections::HashMap::new();
        for i in 0..50 {
            coinbaseaux.insert(format!("key{}", i), "value".into());
        }

        let template = BlockTemplate {
            version: 0x20000000,
            rules: vec![],
            vbavailable: Default::default(),
            vbrequired: 0,
            previousblockhash: "0".repeat(64),
            transactions: vec![],
            coinbaseaux, // Too many entries
            coinbasevalue: 312_500_000,
            longpollid: None,
            target: "0".repeat(64),
            mintime: 0,
            mutable: vec![],
            noncerange: "00000000ffffffff".into(),
            sigoplimit: 80000,
            sizelimit: 4000000,
            weightlimit: 4000000,
            curtime: 1700000000,
            bits: "1a0377ae".into(),
            height: 800000,
            default_witness_commitment: None,
        };

        assert!(matches!(
            validate_block_template(&template, None),
            Err(TemplateValidationError::TooManyCoinbaseAux(_))
        ));
    }

    #[test]
    fn test_template_validation_height_out_of_range() {
        let template = BlockTemplate {
            version: 0x20000000,
            rules: vec![],
            vbavailable: Default::default(),
            vbrequired: 0,
            previousblockhash: "0".repeat(64),
            transactions: vec![],
            coinbaseaux: Default::default(),
            coinbasevalue: 312_500_000,
            longpollid: None,
            target: "0".repeat(64),
            mintime: 0,
            mutable: vec![],
            noncerange: "00000000ffffffff".into(),
            sigoplimit: 80000,
            sizelimit: 4000000,
            weightlimit: 4000000,
            curtime: 1700000000,
            bits: "1a0377ae".into(),
            height: 900000, // Way off from 800000
            default_witness_commitment: None,
        };

        assert!(matches!(
            validate_block_template(&template, Some(800000)),
            Err(TemplateValidationError::HeightOutOfRange(_, _))
        ));
    }

    #[test]
    fn test_template_validation_invalid_coinbase_value() {
        let template = BlockTemplate {
            version: 0x20000000,
            rules: vec![],
            vbavailable: Default::default(),
            vbrequired: 0,
            previousblockhash: "0".repeat(64),
            transactions: vec![],
            coinbaseaux: Default::default(),
            coinbasevalue: MAX_SUPPLY_SATS + 1, // Exceeds max
            longpollid: None,
            target: "0".repeat(64),
            mintime: 0,
            mutable: vec![],
            noncerange: "00000000ffffffff".into(),
            sigoplimit: 80000,
            sizelimit: 4000000,
            weightlimit: 4000000,
            curtime: 1700000000,
            bits: "1a0377ae".into(),
            height: 800000,
            default_witness_commitment: None,
        };

        assert!(matches!(
            validate_block_template(&template, None),
            Err(TemplateValidationError::InvalidCoinbaseValue(_))
        ));
    }

    #[test]
    fn test_retry_config_default() {
        let config = RpcRetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_backoff, Duration::from_millis(100));
    }

    #[test]
    fn test_retry_config_critical() {
        let config = RpcRetryConfig::critical();
        assert_eq!(config.max_retries, 5);
        assert!(config.initial_backoff > Duration::from_millis(100));
    }

    #[test]
    fn test_retry_config_quick() {
        let config = RpcRetryConfig::quick();
        assert_eq!(config.max_retries, 2);
        assert!(config.initial_backoff < Duration::from_millis(100));
    }

    #[test]
    fn test_retry_config_no_retry() {
        let config = RpcRetryConfig::no_retry();
        assert_eq!(config.max_retries, 0);
    }

    #[test]
    fn test_is_retryable_error() {
        // Transient errors should be retryable
        assert!(is_retryable_error(&GhostError::Rpc(
            "Request failed: timeout".to_string()
        )));
        assert!(is_retryable_error(&GhostError::Rpc(
            "Request failed: connection refused".to_string()
        )));
        assert!(is_retryable_error(&GhostError::Rpc(
            "Request failed: connection reset by peer".to_string()
        )));

        // RPC errors (like invalid method) should NOT be retryable
        assert!(!is_retryable_error(&GhostError::Rpc(
            "RPC error -32601: Method not found".to_string()
        )));
        assert!(!is_retryable_error(&GhostError::Rpc(
            "RPC error -8: Block height out of range".to_string()
        )));

        // Other error types
        assert!(!is_retryable_error(&GhostError::Database(
            "some db error".to_string()
        )));
    }

    #[test]
    fn test_rpc_client_has_circuit_breaker() {
        let client = BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap();
        // Circuit breaker should be initialized and closed
        assert!(client.circuit_breaker().is_allowed());
    }
}
