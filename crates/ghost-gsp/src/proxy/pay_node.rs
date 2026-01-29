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

use ghost_gsp_proto::{GhostLockInfo, GhostLockStatus, TransactionInfo, UtxoInfo};

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
    pub fn new(base_url: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_creation() {
        let proxy = PayNodeProxy::new("http://localhost:8800");
        assert_eq!(proxy.base_url, "http://localhost:8800");

        // Should strip trailing slash
        let proxy2 = PayNodeProxy::new("http://localhost:8800/");
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
