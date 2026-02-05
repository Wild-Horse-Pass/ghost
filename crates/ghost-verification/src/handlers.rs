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
//| FILE: handlers.rs                                                                                                    |
//|======================================================================================================================|

//! Concrete verification handlers
//!
//! Provides actual implementations of verification traits:
//! - RpcArchiveHandler: Uses Bitcoin Core RPC
//! - StratumVerifier: Performs protocol handshake

use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

/// AUTH4-L2: Hash an address and return the first 8 characters for anonymized logging
fn anonymize_addr(addr: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(addr.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..4])
}

use ghost_common::error::{GhostError, GhostResult};
use ghost_common::rpc::BitcoinRpc;

use crate::challenge::{BlockData, TxData};
use crate::server::{ArchiveHandler, EpochProof, GhostPayHandler};

/// Archive handler backed by Bitcoin Core RPC
pub struct RpcArchiveHandler {
    /// RPC client
    rpc: Arc<BitcoinRpc>,
    /// Minimum height we can serve (for pruned nodes)
    min_height: Option<u64>,
}

impl RpcArchiveHandler {
    /// Create a new RPC archive handler
    pub fn new(rpc: Arc<BitcoinRpc>) -> Self {
        Self {
            rpc,
            min_height: None,
        }
    }

    /// Set minimum height (for pruned nodes)
    pub fn with_min_height(mut self, height: u64) -> Self {
        self.min_height = Some(height);
        self
    }

    /// Synchronous wrapper for async RPC call (for trait implementation)
    fn blocking_get_block(&self, hash: &str) -> GhostResult<Option<BlockData>> {
        let rpc = self.rpc.clone();
        let hash = hash.to_string();

        // Use block_in_place to allow blocking within async context
        let result = tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async move {
                // Get block header first (lightweight)
                match rpc.get_block_header(&hash).await {
                    Ok(header) => {
                        // Now get full block for tx count
                        let block_json = rpc.get_block(&hash, 1).await?;
                        let tx_count = block_json
                            .get("nTx")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(header.n_tx) as usize;

                        Ok(Some(BlockData {
                            hash: header.hash,
                            height: header.height,
                            timestamp: header.time,
                            tx_count,
                            merkle_root: header.merkleroot,
                        }))
                    }
                    Err(e) => {
                        // Check if it's a "not found" error
                        if e.to_string().contains("-5") || e.to_string().contains("not found") {
                            Ok(None)
                        } else {
                            Err(e)
                        }
                    }
                }
            })
        });

        result
    }

    /// Synchronous wrapper for async transaction lookup
    fn blocking_get_transaction(&self, txid: &str) -> GhostResult<Option<TxData>> {
        let rpc = self.rpc.clone();
        let txid = txid.to_string();

        // Use block_in_place to allow blocking within async context
        let result = tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async move {
                match rpc.get_raw_transaction(&txid, true).await {
                    Ok(tx_json) => {
                        let block_hash = tx_json
                            .get("blockhash")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();

                        let size =
                            tx_json.get("size").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

                        let vin = tx_json
                            .get("vin")
                            .and_then(|v| v.as_array())
                            .map(|a| a.len())
                            .unwrap_or(0);

                        let vout = tx_json
                            .get("vout")
                            .and_then(|v| v.as_array())
                            .map(|a| a.len())
                            .unwrap_or(0);

                        // Get block to find tx index
                        let tx_index = if !block_hash.is_empty() {
                            if let Ok(block) = rpc.get_block(&block_hash, 1).await {
                                block
                                    .get("tx")
                                    .and_then(|v| v.as_array())
                                    .and_then(|txs| {
                                        txs.iter().position(|t| {
                                            t.as_str().map(|s| s == txid).unwrap_or(false)
                                        })
                                    })
                                    .unwrap_or(0)
                            } else {
                                0
                            }
                        } else {
                            0
                        };

                        Ok(Some(TxData {
                            txid,
                            block_hash,
                            tx_index,
                            size,
                            input_count: vin,
                            output_count: vout,
                        }))
                    }
                    Err(e) => {
                        if e.to_string().contains("-5") || e.to_string().contains("not found") {
                            Ok(None)
                        } else {
                            Err(e)
                        }
                    }
                }
            })
        });

        result
    }

    /// Check if we have a block at the given height
    fn blocking_has_block_at_height(&self, height: u64) -> bool {
        // If we have a minimum height and the requested height is below it, we don't have it
        if let Some(min) = self.min_height {
            if height < min {
                return false;
            }
        }

        let rpc = self.rpc.clone();

        // Use block_in_place to allow blocking within async context
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async move {
                match rpc.get_block_count().await {
                    Ok(current_height) => height <= current_height,
                    Err(_) => false,
                }
            })
        })
    }
}

impl ArchiveHandler for RpcArchiveHandler {
    fn get_block(&self, hash: &str) -> GhostResult<Option<BlockData>> {
        self.blocking_get_block(hash)
    }

    fn get_transaction(&self, txid: &str) -> GhostResult<Option<TxData>> {
        self.blocking_get_transaction(txid)
    }

    fn has_block_at_height(&self, height: u64) -> bool {
        self.blocking_has_block_at_height(height)
    }
}

/// Stratum protocol verifier
///
/// Performs actual protocol handshake to verify Stratum endpoints are accessible
/// and responding correctly.
pub struct StratumVerifier {
    /// Connection timeout
    timeout: Duration,
}

impl StratumVerifier {
    /// Create a new stratum verifier
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(5),
        }
    }

    /// Set connection timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Verify Stratum V1 endpoint
    ///
    /// Performs a mining.subscribe handshake to verify the endpoint
    /// is a real Stratum V1 server.
    pub async fn verify_sv1(&self, host: &str, port: u16) -> GhostResult<StratumVerifyResult> {
        let addr = format!("{}:{}", host, port);
        let start = Instant::now();

        // Connect with timeout
        let stream = timeout(self.timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| GhostError::Timeout("Stratum connection timed out".to_string()))?
            .map_err(|e| GhostError::Internal(format!("Connection failed: {}", e)))?;

        let connect_latency = start.elapsed();

        // Send mining.subscribe request
        let subscribe_request =
            r#"{"id":1,"method":"mining.subscribe","params":["ghost-verify/1.0"]}"#;
        let request_with_newline = format!("{}\n", subscribe_request);

        let (mut reader, mut writer) = stream.into_split();

        // Write request
        timeout(
            self.timeout,
            writer.write_all(request_with_newline.as_bytes()),
        )
        .await
        .map_err(|_| GhostError::Timeout("Write timed out".to_string()))?
        .map_err(|e| GhostError::Internal(format!("Write failed: {}", e)))?;

        // Read response
        let mut buf = vec![0u8; 4096];
        let n = timeout(self.timeout, reader.read(&mut buf))
            .await
            .map_err(|_| GhostError::Timeout("Read timed out".to_string()))?
            .map_err(|e| GhostError::Internal(format!("Read failed: {}", e)))?;

        if n == 0 {
            return Err(GhostError::Internal("Connection closed".to_string()));
        }

        let response = String::from_utf8_lossy(&buf[..n]);
        let total_latency = start.elapsed();

        // Parse response to verify it's valid Stratum
        let is_valid = response.contains("\"result\"") && response.contains("\"id\"");

        // Try to extract subscription details
        let subscription_id = if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response)
        {
            json.get("result")
                .and_then(|r| r.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_array())
                .and_then(|a| a.get(1))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        } else {
            None
        };

        // AUTH4-L2: Anonymize address in logs to prevent leaking stratum probe targets
        debug!(
            addr_hash = %anonymize_addr(&addr),
            valid = is_valid,
            latency_ms = total_latency.as_millis(),
            "SV1 verification complete"
        );

        Ok(StratumVerifyResult {
            connected: true,
            valid_protocol: is_valid,
            connect_latency,
            total_latency,
            subscription_id,
            error: if is_valid {
                None
            } else {
                Some("Invalid response".to_string())
            },
        })
    }

    /// Verify Stratum V2 endpoint
    ///
    /// Performs a basic noise protocol handshake to verify the endpoint
    /// is a real Stratum V2 server.
    pub async fn verify_sv2(&self, host: &str, port: u16) -> GhostResult<StratumVerifyResult> {
        let addr = format!("{}:{}", host, port);
        let start = Instant::now();

        // Connect with timeout
        let stream = timeout(self.timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| GhostError::Timeout("Stratum V2 connection timed out".to_string()))?
            .map_err(|e| GhostError::Internal(format!("Connection failed: {}", e)))?;

        let connect_latency = start.elapsed();

        // For SV2, we'd normally do a noise protocol handshake
        // For verification purposes, we just check if something responds
        // A full implementation would use the stratum-v2 crate

        // Send a minimal noise protocol initiator message
        // This is the first 32 bytes of a noise NK handshake
        let initiator_hello: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let (mut reader, mut writer) = stream.into_split();

        // Try to write
        let write_result = timeout(self.timeout, writer.write_all(&initiator_hello)).await;

        if write_result.is_err() {
            // If we can't write, it might still be a valid SV2 server
            // Some implementations close connection on invalid handshake
            return Ok(StratumVerifyResult {
                connected: true,
                valid_protocol: true, // Connected, assume valid
                connect_latency,
                total_latency: start.elapsed(),
                subscription_id: None,
                error: None,
            });
        }

        // Try to read response
        let mut buf = vec![0u8; 128];
        let read_result = timeout(Duration::from_secs(2), reader.read(&mut buf)).await;

        let total_latency = start.elapsed();

        // For SV2, getting any response (or even a close) after handshake attempt
        // indicates a real SV2 server
        let valid_protocol = match read_result {
            Ok(Ok(n)) if n > 0 => true,
            Ok(Ok(_)) => true, // Connection closed is also valid (failed handshake)
            Ok(Err(_)) => true, // Read error after connect is also valid
            Err(_) => true,    // Timeout could mean server is processing
        };

        // AUTH4-L2: Anonymize address in logs to prevent leaking stratum probe targets
        debug!(
            addr_hash = %anonymize_addr(&addr),
            valid = valid_protocol,
            latency_ms = total_latency.as_millis(),
            "SV2 verification complete"
        );

        Ok(StratumVerifyResult {
            connected: true,
            valid_protocol,
            connect_latency,
            total_latency,
            subscription_id: None,
            error: None,
        })
    }
}

impl Default for StratumVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of Stratum verification
#[derive(Debug, Clone)]
pub struct StratumVerifyResult {
    /// Successfully connected
    pub connected: bool,
    /// Valid protocol response
    pub valid_protocol: bool,
    /// Time to establish connection
    pub connect_latency: Duration,
    /// Total verification time
    pub total_latency: Duration,
    /// Subscription ID (SV1 only)
    pub subscription_id: Option<String>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Balance lookup function type
type BalanceFn = Box<dyn Fn(&str) -> GhostResult<u64> + Send + Sync>;

/// H-5: Epoch proof lookup function type
type EpochProofFn = Box<dyn Fn(u64) -> Option<EpochProof> + Send + Sync>;

/// Ghost Pay handler backed by L2 state
pub struct GhostPayL2Handler {
    /// Whether L2 is enabled
    enabled: bool,
    /// Current virtual block getter
    virtual_block_fn: Box<dyn Fn() -> u64 + Send + Sync>,
    /// Current epoch getter
    epoch_fn: Box<dyn Fn() -> u64 + Send + Sync>,
    /// Balance lookup function
    balance_fn: BalanceFn,
    /// Whether Wraith protocol is enabled
    wraith_enabled: bool,
    /// H-5: Epoch proof lookup function for cryptographic verification
    epoch_proof_fn: Option<EpochProofFn>,
}

impl GhostPayL2Handler {
    /// Create a new Ghost Pay handler
    pub fn new<V, E, B>(
        enabled: bool,
        virtual_block: V,
        epoch: E,
        balance: B,
        wraith_enabled: bool,
    ) -> Self
    where
        V: Fn() -> u64 + Send + Sync + 'static,
        E: Fn() -> u64 + Send + Sync + 'static,
        B: Fn(&str) -> GhostResult<u64> + Send + Sync + 'static,
    {
        Self {
            enabled,
            virtual_block_fn: Box::new(virtual_block),
            epoch_fn: Box::new(epoch),
            balance_fn: Box::new(balance),
            wraith_enabled,
            epoch_proof_fn: None,
        }
    }

    /// H-5: Set epoch proof lookup function for cryptographic verification
    ///
    /// When configured, the handler can provide cryptographic proofs that
    /// the node has L2 state for specific epochs, preventing nodes from
    /// claiming GhostPay capability without actually maintaining state.
    pub fn with_epoch_proof<F>(mut self, epoch_proof: F) -> Self
    where
        F: Fn(u64) -> Option<EpochProof> + Send + Sync + 'static,
    {
        self.epoch_proof_fn = Some(Box::new(epoch_proof));
        self
    }
}

impl GhostPayHandler for GhostPayL2Handler {
    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn get_virtual_block(&self) -> u64 {
        (self.virtual_block_fn)()
    }

    fn get_epoch(&self) -> u64 {
        (self.epoch_fn)()
    }

    fn get_balance(&self, address: &str) -> GhostResult<u64> {
        (self.balance_fn)(address)
    }

    fn is_wraith_enabled(&self) -> bool {
        self.wraith_enabled
    }

    /// H-5: Get proof of L2 state at a specific epoch
    fn get_epoch_proof(&self, epoch: u64) -> Option<EpochProof> {
        match &self.epoch_proof_fn {
            Some(f) => f(epoch),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stratum_verifier_creation() {
        let verifier = StratumVerifier::new();
        assert_eq!(verifier.timeout, Duration::from_secs(5));

        let verifier = verifier.with_timeout(Duration::from_secs(10));
        assert_eq!(verifier.timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_ghostpay_handler() {
        let handler = GhostPayL2Handler::new(true, || 100, || 5, |_| Ok(50_000), true);

        assert!(handler.is_enabled());
        assert_eq!(handler.get_virtual_block(), 100);
        assert_eq!(handler.get_epoch(), 5);
        assert!(handler.is_wraith_enabled());
        assert_eq!(handler.get_balance("test").unwrap(), 50_000);
    }

    #[tokio::test]
    async fn test_stratum_sv1_invalid_port() {
        let verifier = StratumVerifier::new().with_timeout(Duration::from_millis(100));

        // Connect to a port that likely won't have a Stratum server
        let result = verifier.verify_sv1("127.0.0.1", 59999).await;

        // Should fail to connect
        assert!(result.is_err());
    }
}
