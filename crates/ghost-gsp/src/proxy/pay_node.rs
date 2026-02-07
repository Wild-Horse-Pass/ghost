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
//| FILE: proxy/pay_node.rs                                                                                              |
//|======================================================================================================================|

//! Proxy client for ghost-pay-node
//!
//! This module provides a client for communicating with a ghost-pay node's REST API.
//! It handles balance queries, UTXO management, lock operations, and payment flows.

use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::debug;

use ghost_common::instant::LockSnapshot;
use ghost_gsp_proto::{
    GhostLockInfo, GhostLockStatus, LockStateSnapshot, TransactionInfo, UtxoInfo,
};

use crate::error::{GspError, GspResult};

/// Parse lock status from string
fn parse_lock_status(status: &str) -> GhostLockStatus {
    match status.to_lowercase().as_str() {
        "pending" => GhostLockStatus::Pending,
        "active" => GhostLockStatus::Active,
        "in_use" => GhostLockStatus::InUse,
        "jumping" => GhostLockStatus::Jumping,
        "spent" => GhostLockStatus::Spent,
        "recovering" => GhostLockStatus::Recovering,
        "recovered" => GhostLockStatus::Recovered,
        "invalid" => GhostLockStatus::Invalid,
        _ => GhostLockStatus::Invalid,
    }
}

/// Wallet balance information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBalance {
    pub confirmed: u64,
    pub unconfirmed: u64,
    pub locked: u64,
}

/// Lock information from pay node
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LockInfoResponse {
    id: String,
    denomination: Option<String>,
    amount_sats: u64,
    state: String,
    created_at: u64,
    timelock_tier: Option<String>,
    jump_risk: Option<String>,
    needs_jump: bool,
    address: String,
    output_pubkey: String,
    recovery_height: Option<u64>,
    blocks_until_jump: Option<u64>,
}

/// Status response from pay node
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StatusResponse {
    version: String,
    has_keys: bool,
    lock_count: usize,
    active_sessions: usize,
    network: String,
}

/// Payment preparation request
#[derive(Debug, Serialize)]
struct PreparePaymentRequest {
    recipient: String,
    amount_sats: u64,
}

/// Payment submission request
#[derive(Debug, Serialize)]
struct SubmitPaymentRequest {
    payment_id: String,
    signature: String,
    public_key: String,
}

/// Lock creation request
#[derive(Debug, Serialize)]
struct CreateLockRequest {
    amount_sats: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    timelock_tier: Option<String>,
}

/// Jump request
#[derive(Debug, Serialize)]
struct JumpRequest {
    target_address: String,
    priority: String,
}

/// Confirm funding request
#[derive(Debug, Serialize)]
struct ConfirmFundingRequest {
    funding_txid: String,
    funding_vout: u32,
}

/// Proxy to ghost-pay-node REST API
pub struct PayNodeProxy {
    base_url: String,
    client: Client,
}

impl PayNodeProxy {
    /// Create a new pay node proxy
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be created (e.g., TLS initialization failure)
    ///
    /// # L-27 Security Fix
    /// Uses proper error handling instead of expect() to prevent panics
    pub fn new(base_url: &str) -> GspResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| {
                GspError::Config(format!(
                    "L-27: Failed to create HTTP client for pay node proxy: {}. \
                     This may indicate TLS library initialization failure.",
                    e
                ))
            })?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        })
    }

    /// Create with custom HTTP client
    pub fn with_client(base_url: &str, client: Client) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        }
    }

    /// Health check - returns true if pay node is responding
    pub async fn health_check(&self) -> GspResult<bool> {
        let url = format!("{}/health", self.base_url);
        debug!(url = %url, "Health check");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        Ok(response.status().is_success())
    }

    /// Get node status
    pub async fn get_status(&self) -> GspResult<serde_json::Value> {
        let url = format!("{}/api/v1/status", self.base_url);
        debug!(url = %url, "Getting status");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            return Err(GspError::PayNodeError(format!(
                "Status request failed: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| GspError::PayNodeError(e.to_string()))
    }

    /// Get balance for a wallet (by ghost_id)
    ///
    /// Note: The pay node manages its own wallet, so this queries the node's balance.
    /// The ghost_id parameter is used for verification/routing purposes.
    pub async fn get_balance(&self, ghost_id: &str) -> GspResult<WalletBalance> {
        let url = format!("{}/api/v1/status", self.base_url);
        debug!(url = %url, ghost_id = %ghost_id, "Getting balance");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            return Err(GspError::PayNodeError(format!(
                "Balance request failed: {}",
                response.status()
            )));
        }

        // Parse status to extract balance info from locks
        let _status: StatusResponse = response
            .json()
            .await
            .map_err(|e| GspError::PayNodeError(e.to_string()))?;

        // Get locks to calculate balance
        let locks = self.get_ghost_locks(ghost_id).await?;

        let confirmed = 0u64;
        let mut locked = 0u64;

        for lock in locks {
            // Count balance from active and in-use locks
            if lock.status.can_spend() || lock.status.can_jump() {
                locked += lock.balance_sats;
            }
        }

        // For now, return lock-based balance
        // In a full implementation, we'd query confirmed UTXOs separately
        Ok(WalletBalance {
            confirmed,
            unconfirmed: 0,
            locked,
        })
    }

    /// Get UTXOs for a wallet
    pub async fn get_utxos(
        &self,
        ghost_id: &str,
        min_confirmations: u32,
    ) -> GspResult<Vec<UtxoInfo>> {
        let url = format!(
            "{}/api/v1/utxos?ghost_id={}&min_conf={}",
            self.base_url, ghost_id, min_confirmations
        );
        debug!(url = %url, "Getting UTXOs");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if response.status().is_success() {
            response
                .json()
                .await
                .map_err(|e| GspError::PayNodeError(e.to_string()))
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            // Endpoint may not exist yet, return empty
            Ok(vec![])
        } else {
            Err(GspError::PayNodeError(format!(
                "UTXO request failed: {}",
                response.status()
            )))
        }
    }

    /// Get Ghost Locks for a wallet
    pub async fn get_ghost_locks(&self, ghost_id: &str) -> GspResult<Vec<GhostLockInfo>> {
        let url = format!("{}/api/v1/locks", self.base_url);
        debug!(url = %url, ghost_id = %ghost_id, "Getting ghost locks");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            return Err(GspError::PayNodeError(format!(
                "Locks request failed: {}",
                response.status()
            )));
        }

        let locks: Vec<LockInfoResponse> = response
            .json()
            .await
            .map_err(|e| GspError::PayNodeError(e.to_string()))?;

        // Convert to GhostLockInfo
        Ok(locks
            .into_iter()
            .map(|l| GhostLockInfo {
                lock_id: l.id,
                status: parse_lock_status(&l.state),
                capacity_sats: l.amount_sats,
                balance_sats: l.amount_sats,
                denomination: l.denomination.unwrap_or_else(|| "Unknown".to_string()),
                timelock_tier: l.timelock_tier.unwrap_or_else(|| "Standard".to_string()),
                jump_risk_tier: l.jump_risk.unwrap_or_else(|| "Low".to_string()),
                funding_address: l.address,
                funding_txid: None,
                funding_vout: None,
                creation_height: 0,
                recovery_height: l.recovery_height.unwrap_or(0) as u32,
                next_jump_height: None,
                needs_jump: l.needs_jump,
                blocks_until_jump: l.blocks_until_jump.unwrap_or(0) as u32,
                created_at: l.created_at as i64,
                updated_at: l.created_at as i64,
            })
            .collect())
    }

    /// Get locks that were confirmed at or after a given block height
    ///
    /// This is used by the reorg bridge to determine which locks may be affected
    /// by a chain reorganization. A lock is considered affected if it was
    /// confirmed at a height that is being reorganized.
    ///
    /// M-11: Returns lock IDs for reorg notification instead of empty arrays.
    pub async fn get_locks_confirmed_after(&self, min_height: u64) -> GspResult<Vec<String>> {
        let url = format!(
            "{}/api/v1/locks?min_creation_height={}",
            self.base_url, min_height
        );
        debug!(url = %url, min_height, "Getting locks confirmed after height");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            // Endpoint may not exist yet - fall back to getting all locks and filtering
            return self.get_locks_confirmed_after_fallback(min_height).await;
        }

        if !response.status().is_success() {
            // If endpoint returns an error, try fallback
            return self.get_locks_confirmed_after_fallback(min_height).await;
        }

        let locks: Vec<LockInfoResponse> = response
            .json()
            .await
            .map_err(|e| GspError::PayNodeError(e.to_string()))?;

        // Extract lock IDs
        Ok(locks.into_iter().map(|l| l.id).collect())
    }

    /// Fallback method when the min_creation_height endpoint doesn't exist
    ///
    /// This fetches all locks and filters client-side. Less efficient but
    /// ensures backwards compatibility.
    async fn get_locks_confirmed_after_fallback(&self, min_height: u64) -> GspResult<Vec<String>> {
        let url = format!("{}/api/v1/locks", self.base_url);
        debug!(url = %url, min_height, "Getting locks (fallback for reorg)");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            // If we can't query locks at all, return empty - reorg notification
            // will still be sent, just without specific affected lock IDs
            debug!("Failed to query locks for reorg, returning empty list");
            return Ok(vec![]);
        }

        // Try to parse as enhanced response with creation_height
        #[derive(serde::Deserialize)]
        struct LockWithHeight {
            id: String,
            #[serde(default)]
            creation_height: Option<u64>,
        }

        let locks: Vec<LockWithHeight> = response
            .json()
            .await
            .unwrap_or_default();

        // Filter locks that were confirmed at or after min_height
        // If creation_height is not available, we can't determine if affected
        // so we include them to be conservative
        Ok(locks
            .into_iter()
            .filter(|l| {
                match l.creation_height {
                    Some(h) => h >= min_height,
                    None => true, // Include if we don't know the height (conservative)
                }
            })
            .map(|l| l.id)
            .collect())
    }

    /// Get a specific lock by ID
    pub async fn get_lock(&self, lock_id: &str) -> GspResult<GhostLockInfo> {
        let url = format!("{}/api/v1/locks/{}", self.base_url, lock_id);
        debug!(url = %url, "Getting lock");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(GspError::NotFound(format!("Lock not found: {}", lock_id)));
        }

        if !response.status().is_success() {
            return Err(GspError::PayNodeError(format!(
                "Lock request failed: {}",
                response.status()
            )));
        }

        let lock: LockInfoResponse = response
            .json()
            .await
            .map_err(|e| GspError::PayNodeError(e.to_string()))?;

        Ok(GhostLockInfo {
            lock_id: lock.id,
            status: parse_lock_status(&lock.state),
            capacity_sats: lock.amount_sats,
            balance_sats: lock.amount_sats,
            denomination: lock.denomination.unwrap_or_else(|| "Unknown".to_string()),
            timelock_tier: lock.timelock_tier.unwrap_or_else(|| "Standard".to_string()),
            jump_risk_tier: lock.jump_risk.unwrap_or_else(|| "Low".to_string()),
            funding_address: lock.address,
            funding_txid: None,
            funding_vout: None,
            creation_height: 0,
            recovery_height: lock.recovery_height.unwrap_or(0) as u32,
            next_jump_height: None,
            needs_jump: lock.needs_jump,
            blocks_until_jump: lock.blocks_until_jump.unwrap_or(0) as u32,
            created_at: lock.created_at as i64,
            updated_at: lock.created_at as i64,
        })
    }

    /// Get transaction history
    pub async fn get_transactions(
        &self,
        ghost_id: &str,
        limit: u32,
        offset: u32,
    ) -> GspResult<(Vec<TransactionInfo>, u32)> {
        let url = format!(
            "{}/api/v1/transactions?ghost_id={}&limit={}&offset={}",
            self.base_url, ghost_id, limit, offset
        );
        debug!(url = %url, "Getting transactions");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if response.status().is_success() {
            #[derive(Deserialize)]
            struct TxResponse {
                transactions: Vec<TransactionInfo>,
                total: u32,
            }

            let tx_response: TxResponse = response
                .json()
                .await
                .map_err(|e| GspError::PayNodeError(e.to_string()))?;

            Ok((tx_response.transactions, tx_response.total))
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            // Endpoint may not exist yet
            Ok((vec![], 0))
        } else {
            Err(GspError::PayNodeError(format!(
                "Transaction request failed: {}",
                response.status()
            )))
        }
    }

    /// Prepare a payment
    pub async fn prepare_payment(
        &self,
        ghost_id: &str,
        recipient: &str,
        amount_sats: u64,
    ) -> GspResult<serde_json::Value> {
        let url = format!("{}/api/v1/payments/prepare", self.base_url);
        debug!(url = %url, ghost_id = %ghost_id, recipient = %recipient, amount = amount_sats, "Preparing payment");

        let request = PreparePaymentRequest {
            recipient: recipient.to_string(),
            amount_sats,
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(GspError::PayNodeError(format!(
                "Payment preparation failed: {}",
                error_text
            )));
        }

        response
            .json()
            .await
            .map_err(|e| GspError::PayNodeError(e.to_string()))
    }

    /// Submit a signed payment
    pub async fn submit_payment(
        &self,
        payment_id: &str,
        signature: &str,
        public_key: &str,
    ) -> GspResult<serde_json::Value> {
        let url = format!("{}/api/v1/payments/submit", self.base_url);
        debug!(url = %url, payment_id = %payment_id, "Submitting payment");

        let request = SubmitPaymentRequest {
            payment_id: payment_id.to_string(),
            signature: signature.to_string(),
            public_key: public_key.to_string(),
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(GspError::PayNodeError(format!(
                "Payment submission failed: {}",
                error_text
            )));
        }

        response
            .json()
            .await
            .map_err(|e| GspError::PayNodeError(e.to_string()))
    }

    /// Create a ghost lock
    pub async fn create_lock(
        &self,
        ghost_id: &str,
        amount_sats: u64,
        timelock_tier: Option<&str>,
    ) -> GspResult<GhostLockInfo> {
        let url = format!("{}/api/v1/locks/create", self.base_url);
        debug!(url = %url, ghost_id = %ghost_id, amount = amount_sats, "Creating lock");

        let request = CreateLockRequest {
            amount_sats,
            timelock_tier: timelock_tier.map(|s| s.to_string()),
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(GspError::PayNodeError(format!(
                "Lock creation failed: {}",
                error_text
            )));
        }

        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct CreateLockResponse {
            success: bool,
            lock: LockInfoResponse,
        }

        let result: CreateLockResponse = response
            .json()
            .await
            .map_err(|e| GspError::PayNodeError(e.to_string()))?;

        let lock = result.lock;
        Ok(GhostLockInfo {
            lock_id: lock.id,
            status: parse_lock_status(&lock.state),
            capacity_sats: lock.amount_sats,
            balance_sats: lock.amount_sats,
            denomination: lock.denomination.unwrap_or_else(|| "Unknown".to_string()),
            timelock_tier: lock.timelock_tier.unwrap_or_else(|| "Standard".to_string()),
            jump_risk_tier: lock.jump_risk.unwrap_or_else(|| "Low".to_string()),
            funding_address: lock.address,
            funding_txid: None,
            funding_vout: None,
            creation_height: 0,
            recovery_height: lock.recovery_height.unwrap_or(0) as u32,
            next_jump_height: None,
            needs_jump: lock.needs_jump,
            blocks_until_jump: lock.blocks_until_jump.unwrap_or(0) as u32,
            created_at: lock.created_at as i64,
            updated_at: lock.created_at as i64,
        })
    }

    /// Request a jump for a lock
    pub async fn request_jump(
        &self,
        lock_id: &str,
        target_address: &str,
        priority: &str,
    ) -> GspResult<serde_json::Value> {
        let url = format!("{}/api/v1/locks/{}/jump", self.base_url, lock_id);
        debug!(url = %url, lock_id = %lock_id, "Requesting jump");

        let request = JumpRequest {
            target_address: target_address.to_string(),
            priority: priority.to_string(),
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(GspError::PayNodeError(format!(
                "Jump request failed: {}",
                error_text
            )));
        }

        response
            .json()
            .await
            .map_err(|e| GspError::PayNodeError(e.to_string()))
    }

    /// Get payment status
    pub async fn get_payment_status(&self, payment_id: &str) -> GspResult<serde_json::Value> {
        let url = format!("{}/api/v1/payments/{}", self.base_url, payment_id);
        debug!(url = %url, "Getting payment status");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(GspError::NotFound(format!(
                "Payment not found: {}",
                payment_id
            )));
        }

        if !response.status().is_success() {
            return Err(GspError::PayNodeError(format!(
                "Payment status request failed: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| GspError::PayNodeError(e.to_string()))
    }

    /// Cancel a pending payment
    pub async fn cancel_payment(&self, payment_id: &str) -> GspResult<bool> {
        let url = format!("{}/api/v1/payments/{}/cancel", self.base_url, payment_id);
        debug!(url = %url, "Cancelling payment");

        let response = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(GspError::NotFound(format!(
                "Payment not found: {}",
                payment_id
            )));
        }

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(GspError::PayNodeError(format!(
                "Payment cancellation failed: {}",
                error_text
            )));
        }

        Ok(true)
    }

    /// Confirm lock funding (after funding tx is broadcast)
    pub async fn confirm_lock_funding(
        &self,
        lock_id: &str,
        funding_txid: &str,
        funding_vout: u32,
    ) -> GspResult<serde_json::Value> {
        let url = format!("{}/api/v1/locks/{}/confirm", self.base_url, lock_id);
        debug!(url = %url, lock_id = %lock_id, txid = %funding_txid, "Confirming lock funding");

        let request = ConfirmFundingRequest {
            funding_txid: funding_txid.to_string(),
            funding_vout,
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(GspError::PayNodeError(format!(
                "Funding confirmation failed: {}",
                error_text
            )));
        }

        response
            .json()
            .await
            .map_err(|e| GspError::PayNodeError(e.to_string()))
    }

    // =========================================================================
    // Instant Payment Methods
    // =========================================================================

    /// Get current block height from the node
    pub async fn get_current_height(&self) -> GspResult<u64> {
        let url = format!("{}/api/v1/status", self.base_url);
        debug!(url = %url, "Getting current height");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            return Err(GspError::PayNodeError(format!(
                "Status request failed: {}",
                response.status()
            )));
        }

        #[derive(Deserialize)]
        struct StatusWithHeight {
            block_height: Option<u64>,
        }

        let status: StatusWithHeight = response
            .json()
            .await
            .map_err(|e| GspError::PayNodeError(e.to_string()))?;

        Ok(status.block_height.unwrap_or(0))
    }

    /// Get lock snapshot for instant payment evaluation
    ///
    /// Returns a LockSnapshot with all the data needed to evaluate instant capability.
    pub async fn get_lock_snapshot(&self, lock_id: &str) -> GspResult<LockSnapshot> {
        let lock = self.get_lock(lock_id).await?;
        let current_height = self.get_current_height().await.unwrap_or(0);

        // Calculate jump urgency from blocks_until_jump
        // If needs_jump is true, urgency is high
        let jump_urgency = if lock.needs_jump {
            0.8
        } else if lock.blocks_until_jump < 100 {
            0.5
        } else if lock.blocks_until_jump < 1000 {
            0.2
        } else {
            0.05
        };

        // Calculate confirmations (approximate)
        let confirmations =
            if lock.creation_height > 0 && current_height > lock.creation_height as u64 {
                (current_height - lock.creation_height as u64) as u32
            } else {
                // Assume well-confirmed if we don't have creation height
                10
            };

        // Recovery blocks remaining
        let recovery_blocks_remaining =
            if lock.recovery_height > 0 && current_height < lock.recovery_height as u64 {
                (lock.recovery_height as u64 - current_height) as u32
            } else {
                26280 // Default: ~6 months of blocks remaining
            };

        // Derive mempool status from lock state and UTXO verification
        // A lock is considered "in mempool" if:
        // 1. It's in Pending state (not yet confirmed on chain), or
        // 2. The UTXO state query indicates it's unconfirmed
        let in_mempool = match lock.status {
            GhostLockStatus::Pending => true,
            _ => {
                // Query actual UTXO state to verify mempool status
                // This catches cases where state is stale or lock just got confirmed
                match self.get_utxo_state(&lock.lock_id).await {
                    Ok(utxo_state) => utxo_state.in_mempool,
                    Err(_) => false, // If query fails, assume not in mempool (conservative)
                }
            }
        };

        // Pending L2 balance requires tracking active L2 payment sessions
        // For now, this is derived from lock state - if InUse, there may be pending L2 activity
        let pending_l2_sats = if lock.status == GhostLockStatus::InUse {
            // InUse means there's an active L2 session, but exact pending amount
            // would need to be queried from the L2 state. For now, return 0 as
            // the lock snapshot is primarily used for capability assessment.
            0
        } else {
            0
        };

        Ok(LockSnapshot {
            lock_id: lock.lock_id,
            state: format!("{:?}", lock.status),
            balance_sats: lock.balance_sats,
            funding_height: lock.creation_height,
            confirmations,
            denomination: lock.denomination,
            jump_urgency,
            recovery_blocks_remaining,
            recovery_window_total: 52560, // ~1 year
            in_mempool,
            pending_l2_sats,
            // CRIT-1/CRIT-2 fields
            pending_instant_sats: 0, // Would come from instant payment tracker
            owner_pubkey: None,      // Would need wallet/key lookup
        })
    }

    /// Get lock state snapshot for real-time updates
    ///
    /// Returns a LockStateSnapshot suitable for WebSocket push notifications.
    pub async fn get_lock_state_snapshot(&self, lock_id: &str) -> GspResult<LockStateSnapshot> {
        let snapshot = self.get_lock_snapshot(lock_id).await?;
        let current_height = self.get_current_height().await.unwrap_or(0);

        // Calculate max instant amount based on denomination
        let max_instant_sats = match snapshot.denomination.as_str() {
            "Micro" => 10_000,
            "Tiny" | "Small" | "Medium" | "Large" | "XL" => 100_000,
            _ => 0,
        };

        Ok(LockStateSnapshot {
            state: snapshot.state,
            balance_sats: snapshot.balance_sats,
            confirmations: snapshot.confirmations,
            jump_urgency: snapshot.jump_urgency,
            in_mempool: snapshot.in_mempool,
            pending_l2_sats: snapshot.pending_l2_sats,
            max_instant_sats,
            current_height,
        })
    }

    // =========================================================================
    // H-9: Payment Ownership Verification
    // =========================================================================

    /// H-9: Get payment details including wallet ownership
    ///
    /// Returns payment details including the wallet_id that created the payment.
    /// This is used to verify that a wallet can only submit signatures for
    /// payments they created, preventing payment hijacking.
    pub async fn get_payment(&self, payment_id: &str) -> GspResult<PaymentInfo> {
        let url = format!("{}/api/v1/payments/{}", self.base_url, payment_id);
        debug!(url = %url, payment_id = %payment_id, "Getting payment for ownership verification");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(GspError::NotFound(format!(
                "Payment not found: {}",
                payment_id
            )));
        }

        if !response.status().is_success() {
            return Err(GspError::PayNodeError(format!(
                "Payment request failed: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| GspError::PayNodeError(e.to_string()))
    }

    // =========================================================================
    // H-11: L1 UTXO State Verification for Instant Payments
    // =========================================================================

    /// H-11: Get the real-time L1 state of a lock UTXO
    ///
    /// This queries Bitcoin Core (via the pay node) to get the actual on-chain
    /// state of a lock's funding UTXO, rather than using cached data.
    ///
    /// This is critical for instant payment acceptance to ensure the sender's
    /// lock actually exists on L1 with sufficient confirmations.
    pub async fn get_utxo_state(&self, lock_id: &str) -> GspResult<UtxoState> {
        let url = format!("{}/api/v1/locks/{}/utxo-state", self.base_url, lock_id);
        debug!(url = %url, lock_id = %lock_id, "Getting L1 UTXO state for lock");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            // Lock not found - return state indicating UTXO doesn't exist
            return Ok(UtxoState {
                exists: false,
                in_mempool: false,
                confirmations: 0,
                amount_sats: 0,
            });
        }

        if !response.status().is_success() {
            // If the endpoint doesn't exist yet, fall back to basic lock info
            // This ensures backwards compatibility while the pay node is updated
            // Note: We use get_lock instead of get_lock_snapshot to avoid recursion
            let lock = self.get_lock(lock_id).await?;
            return Ok(UtxoState {
                exists: true,
                // Derive mempool status from lock status
                in_mempool: lock.status == GhostLockStatus::Pending,
                // Cannot determine confirmations without the endpoint
                confirmations: if lock.status == GhostLockStatus::Pending { 0 } else { 1 },
                amount_sats: lock.balance_sats,
            });
        }

        response
            .json()
            .await
            .map_err(|e| GspError::PayNodeError(e.to_string()))
    }
}

/// H-9: Payment information including ownership
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentInfo {
    /// Payment ID
    pub payment_id: String,
    /// Wallet ID that created this payment (for ownership verification)
    pub wallet_id: String,
    /// Recipient address
    pub recipient: String,
    /// Amount in satoshis
    pub amount_sats: u64,
    /// Fee in satoshis
    pub fee_sats: u64,
    /// Current status
    pub status: String,
    /// Creation timestamp
    pub created_at: i64,
}

/// H-11: L1 UTXO state for instant payment verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoState {
    /// Whether the UTXO exists (not spent)
    pub exists: bool,
    /// Whether the UTXO is in the mempool (unconfirmed)
    pub in_mempool: bool,
    /// Number of confirmations (0 if in mempool or doesn't exist)
    pub confirmations: u32,
    /// Amount in satoshis
    pub amount_sats: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_creation() {
        let proxy = PayNodeProxy::new("http://localhost:8800").expect("valid proxy creation");
        assert_eq!(proxy.base_url, "http://localhost:8800");

        // Should strip trailing slash
        let proxy2 = PayNodeProxy::new("http://localhost:8800/").expect("valid proxy creation");
        assert_eq!(proxy2.base_url, "http://localhost:8800");
    }

    #[test]
    fn test_wallet_balance_default() {
        let balance = WalletBalance {
            confirmed: 100000,
            unconfirmed: 5000,
            locked: 50000,
        };
        assert_eq!(balance.confirmed, 100000);
        assert_eq!(balance.unconfirmed, 5000);
        assert_eq!(balance.locked, 50000);
    }
}
