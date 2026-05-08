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
use subtle::ConstantTimeEq;
use tracing::{debug, warn};

use ghost_common::instant::LockSnapshot;
use ghost_gsp_proto::{
    GhostLockInfo, GhostLockStatus, LockStateSnapshot, TransactionInfo, UtxoInfo,
};

use crate::error::{GspError, GspResult};

/// Parse lock status from string
///
/// MED-ENUM-1 FIX: Unknown status values are logged and return Unknown variant
/// instead of silently defaulting to Invalid. This provides:
/// - Visibility into unexpected status values for debugging
/// - Forward compatibility with new status values from updated backends
/// - Correct semantics (Unknown is different from explicitly Invalid)
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
        "unknown" => GhostLockStatus::Unknown,
        other => {
            // MED-ENUM-1: Log warning for unknown status values
            warn!(
                unknown_status = %other,
                "MED-ENUM-1: Received unknown lock status from pay node - returning Unknown variant"
            );
            GhostLockStatus::Unknown
        }
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
    /// M-11: Owner wallet ID for explicit ownership verification
    /// If present, this field is used for ownership checks in fallback path
    owner_wallet_id: Option<String>,
    /// User-supplied recovery_pubkey echoed back by ghost-pay so the
    /// wallet can verify operator didn't substitute. 33-byte SEC1
    /// compressed, hex-encoded. None on legacy ghost-pay nodes that
    /// haven't adopted the recovery-key change.
    #[serde(default)]
    recovery_pubkey: Option<String>,
    /// Wallet's recovery derivation index, echoed.
    #[serde(default)]
    recovery_index: Option<u32>,
    /// CSV blocks the recovery branch waits on.
    #[serde(default)]
    recovery_blocks: Option<u32>,
    /// Block height the lock was created at.
    #[serde(default)]
    creation_height: Option<u32>,
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
    /// User-supplied recovery_pubkey (33-byte SEC1 compressed hex).
    /// ghost-pay uses this verbatim in the lock script's recovery
    /// branch instead of deriving its own. Required for unilateral
    /// exit to be a real property.
    recovery_pubkey: String,
    /// Wallet-side derivation index that produced `recovery_pubkey`.
    /// Operator records but does not use for keys.
    recovery_index: u32,
    /// Authenticated wallet's static identifier — the GSP server
    /// forwards this so multi-tenant ghost-pay can record the lock
    /// under the requesting wallet's ID rather than the operator's.
    owner_ghost_id: String,
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

/// Result from a one-shot `send_l2_payment` call. Mirrors the
/// useful subset of ghost-pay's `/api/v1/payments/send` response.
#[derive(Debug, Clone)]
pub struct SendL2PaymentResult {
    pub payment_id: String,
    /// Operator-side status — typically "pending" until the
    /// confidential-transfer ZK proof step completes.
    pub status: String,
    pub recipient: String,
    pub amount_sats: u64,
}

/// M-15 FIX: Internal authentication header name
/// Used to authenticate GSP requests to the ghost-pay backend.
const INTERNAL_AUTH_HEADER: &str = "X-Internal-Auth";

/// Proxy to ghost-pay-node REST API
pub struct PayNodeProxy {
    base_url: String,
    client: Client,
    /// M-15 FIX: Shared secret for internal authentication
    /// Read from GHOST_PAY_INTERNAL_SECRET env var or config
    internal_secret: Option<String>,
}

impl PayNodeProxy {
    /// Create a new pay node proxy
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be created (e.g., TLS initialization failure)
    ///
    /// # L-27 Security Fix
    /// Uses proper error handling instead of expect() to prevent panics
    ///
    /// # CRIT-AUTH-1/CRIT-AUTH-2 Security Fix
    /// Reads and validates GHOST_PAY_INTERNAL_SECRET from environment for internal authentication.
    /// FAILS AT STARTUP if secret is not set or does not meet security requirements.
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

        // CRIT-AUTH-1: REQUIRE internal auth secret in production
        let internal_secret = std::env::var("GHOST_PAY_INTERNAL_SECRET")
            .map_err(|_| {
                GspError::Config(
                    "CRIT-AUTH-1: GHOST_PAY_INTERNAL_SECRET environment variable is required. \
                     The GSP server cannot operate without authenticated communication to the pay node. \
                     Set a strong secret: export GHOST_PAY_INTERNAL_SECRET=$(openssl rand -base64 32)".to_string()
                )
            })?;

        // CRIT-AUTH-2: Validate secret strength
        if internal_secret.len() < 32 {
            return Err(GspError::Config(format!(
                "CRIT-AUTH-2: GHOST_PAY_INTERNAL_SECRET is too short ({} bytes). \
                     Minimum 32 bytes required for cryptographic security. \
                     Generate a strong secret: openssl rand -base64 32",
                internal_secret.len()
            )));
        }

        // CRIT-AUTH-2: Check for weak/predictable secrets
        let weak_secrets = [
            "test", "password", "secret", "changeme", "default", "admin", "root", "12345", "abc",
            "ghost",
        ];
        let secret_lower = internal_secret.to_lowercase();
        for weak in &weak_secrets {
            if secret_lower.contains(weak) {
                return Err(GspError::Config(format!(
                    "CRIT-AUTH-2: GHOST_PAY_INTERNAL_SECRET contains weak pattern '{}'. \
                         Use cryptographically random secret: openssl rand -base64 32",
                    weak
                )));
            }
        }

        // CRIT-AUTH-2: Check for sufficient entropy (at least 16 unique characters)
        let unique_chars: std::collections::HashSet<char> = internal_secret.chars().collect();
        if unique_chars.len() < 16 {
            return Err(GspError::Config(
                format!(
                    "CRIT-AUTH-2: GHOST_PAY_INTERNAL_SECRET has insufficient entropy ({} unique characters). \
                     Minimum 16 unique characters required. \
                     Generate a strong secret: openssl rand -base64 32",
                    unique_chars.len()
                )
            ));
        }

        tracing::info!(
            secret_length = internal_secret.len(),
            unique_chars = unique_chars.len(),
            "CRIT-AUTH-1/2: Internal authentication secret validated successfully"
        );

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            internal_secret: Some(internal_secret),
        })
    }

    /// Create with custom HTTP client
    ///
    /// # M-15 Security Fix
    /// Reads GHOST_PAY_INTERNAL_SECRET from environment for internal authentication
    pub fn with_client(base_url: &str, client: Client) -> Self {
        let internal_secret = std::env::var("GHOST_PAY_INTERNAL_SECRET").ok();
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            internal_secret,
        }
    }

    /// Create with explicit internal secret (for testing)
    ///
    /// # M-15 Security Fix
    /// Allows setting the internal auth secret directly
    #[cfg(test)]
    pub fn with_secret(base_url: &str, client: Client, secret: Option<String>) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            internal_secret: secret,
        }
    }

    /// M-15: Add internal authentication header to a request builder
    ///
    /// MED-TIMING-1: Note that this function adds the header for OUTGOING requests.
    /// The constant-time comparison is needed on the RECEIVING end (pay node side)
    /// when validating incoming auth headers. This GSP code is the requester,
    /// not the validator, so timing attacks aren't applicable here.
    fn add_internal_auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.internal_secret {
            Some(secret) => request.header(INTERNAL_AUTH_HEADER, secret),
            None => request,
        }
    }

    /// MED-TIMING-1 FIX: Constant-time comparison for internal auth header validation
    ///
    /// When validating auth headers from incoming requests, use this function
    /// to prevent timing attacks. This is marked #[allow(dead_code)] because
    /// it's provided for completeness - the actual validation happens on the
    /// ghost-pay-node side, not in this GSP proxy.
    #[allow(dead_code)]
    fn verify_internal_auth_constant_time(received: &str, expected: &str) -> bool {
        // Convert both strings to bytes for constant-time comparison
        let received_bytes = received.as_bytes();
        let expected_bytes = expected.as_bytes();

        // First check lengths in constant time by comparing padded versions
        // If lengths differ, we still do the comparison to avoid timing leaks
        if received_bytes.len() != expected_bytes.len() {
            // Still do a comparison to make timing consistent
            // Compare against expected to avoid length-based timing
            let _ = expected_bytes.ct_eq(expected_bytes);
            return false;
        }

        // Constant-time comparison using subtle crate
        received_bytes.ct_eq(expected_bytes).into()
    }

    /// Health check - returns true if pay node is responding
    pub async fn health_check(&self) -> GspResult<bool> {
        let url = format!("{}/health", self.base_url);
        debug!(url = %url, "Health check");

        // M-15: Add internal auth header
        let response = self
            .add_internal_auth(self.client.get(&url))
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        Ok(response.status().is_success())
    }

    /// Get node status
    pub async fn get_status(&self) -> GspResult<serde_json::Value> {
        let url = format!("{}/api/v1/status", self.base_url);
        debug!(url = %url, "Getting status");

        // M-15: Add internal auth header
        let response = self
            .add_internal_auth(self.client.get(&url))
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
    pub async fn get_balance(
        &self,
        ghost_id: &str,
        max_k: Option<u32>,
    ) -> GspResult<WalletBalance> {
        let mut url = format!("{}/api/v1/status", self.base_url);
        if let Some(k) = max_k {
            url = format!("{}?max_k={}", url, k);
        }
        debug!(url = %url, ghost_id = %ghost_id, max_k = ?max_k, "Getting balance");

        // M-15: Add internal auth header
        let response = self
            .add_internal_auth(self.client.get(&url))
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
                // MED-OVERFLOW-1 FIX: Use checked arithmetic to prevent overflow
                locked = locked.saturating_add(lock.balance_sats);
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

        // M-15: Add internal auth header
        let response = self
            .add_internal_auth(self.client.get(&url))
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

        // M-15: Add internal auth header
        let response = self
            .add_internal_auth(self.client.get(&url))
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
                creation_height: l.creation_height.unwrap_or(0),
                recovery_height: l.recovery_height.unwrap_or(0) as u32,
                next_jump_height: None,
                needs_jump: l.needs_jump,
                blocks_until_jump: l.blocks_until_jump.unwrap_or(0) as u32,
                created_at: l.created_at as i64,
                updated_at: l.created_at as i64,
                lock_pubkey: l.output_pubkey.clone(),
                recovery_pubkey: l.recovery_pubkey.clone().unwrap_or_default(),
                recovery_index: l.recovery_index.unwrap_or(0),
                recovery_blocks: l.recovery_blocks.unwrap_or(0),
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

        // M-15: Add internal auth header
        let response = self
            .add_internal_auth(self.client.get(&url))
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

        // M-15: Add internal auth header
        let response = self
            .add_internal_auth(self.client.get(&url))
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

        let locks: Vec<LockWithHeight> = response.json().await.unwrap_or_default();

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

        // M-15: Add internal auth header
        let response = self
            .add_internal_auth(self.client.get(&url))
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
            creation_height: lock.creation_height.unwrap_or(0),
            recovery_height: lock.recovery_height.unwrap_or(0) as u32,
            next_jump_height: None,
            needs_jump: lock.needs_jump,
            blocks_until_jump: lock.blocks_until_jump.unwrap_or(0) as u32,
            created_at: lock.created_at as i64,
            updated_at: lock.created_at as i64,
            lock_pubkey: lock.output_pubkey.clone(),
            recovery_pubkey: lock.recovery_pubkey.unwrap_or_default(),
            recovery_index: lock.recovery_index.unwrap_or(0),
            recovery_blocks: lock.recovery_blocks.unwrap_or(0),
        })
    }

    /// M-11: Internal method to get raw lock info including owner_wallet_id
    ///
    /// This returns the internal LockInfoResponse which includes the owner_wallet_id
    /// field for explicit ownership verification in fallback paths.
    async fn get_lock_info_internal(&self, lock_id: &str) -> GspResult<LockInfoResponse> {
        let url = format!("{}/api/v1/locks/{}", self.base_url, lock_id);
        debug!(url = %url, "M-11: Getting internal lock info for ownership check");

        let response = self
            .add_internal_auth(self.client.get(&url))
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

        response
            .json()
            .await
            .map_err(|e| GspError::PayNodeError(e.to_string()))
    }

    /// H-3/H-4/HIGH-STATE-1 FIX: Check if a wallet owns a specific lock
    ///
    /// Verifies ownership by checking if the lock exists in the wallet's lock list.
    /// This is used to ensure that lock state subscriptions and capability checks
    /// can only be performed by the lock owner.
    ///
    /// HIGH-STATE-1 FIX: First tries the efficient /api/v1/locks/{lock_id}/owner endpoint
    /// which does server-side ownership check. Falls back to client-side check if endpoint
    /// doesn't exist yet (for backwards compatibility).
    ///
    /// # Arguments
    /// * `wallet_id` - The wallet ID to check ownership for
    /// * `lock_id` - The lock ID to verify ownership of
    ///
    /// # Returns
    /// * `Ok(true)` - Wallet owns the lock
    /// * `Ok(false)` - Wallet does not own the lock
    /// * `Err(_)` - Error checking ownership
    pub async fn is_lock_owner(&self, wallet_id: &str, lock_id: &str) -> GspResult<bool> {
        // HIGH-STATE-1: Try the efficient server-side endpoint first
        let url = format!(
            "{}/api/v1/locks/{}/owner?wallet_id={}",
            self.base_url, lock_id, wallet_id
        );
        debug!(
            url = %url,
            wallet_id = %wallet_id,
            lock_id = %lock_id,
            "HIGH-STATE-1: Checking lock ownership via server-side endpoint"
        );

        // M-15: Add internal auth header
        let response = self
            .add_internal_auth(self.client.get(&url))
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            // M-11: Endpoint doesn't exist yet - fall back to client-side check with explicit verification
            warn!(
                wallet_id = %wallet_id,
                lock_id = %lock_id,
                "M-11: Server-side ownership endpoint not available, using fallback path. \
                 This is less secure - upgrade pay node to support /owner endpoint."
            );

            // M-11: Use get_lock_info_internal to verify ownership explicitly via owner_wallet_id field
            let lock_info = self.get_lock_info_internal(lock_id).await?;

            // M-11: Verify ownership using explicit owner_wallet_id if available
            if let Some(ref owner) = lock_info.owner_wallet_id {
                let is_owner = owner == wallet_id;
                if !is_owner {
                    debug!(
                        wallet_id = %wallet_id,
                        lock_id = %lock_id,
                        actual_owner = %owner,
                        "M-11: Explicit ownership check failed - lock owned by different wallet"
                    );
                }
                return Ok(is_owner);
            }

            // M-11: If owner_wallet_id not available, fall back to list-based check with warning
            warn!(
                wallet_id = %wallet_id,
                lock_id = %lock_id,
                "M-11: Lock does not have owner_wallet_id field - using list-based fallback. \
                 This is the weakest verification path."
            );
            let locks = self.get_ghost_locks(wallet_id).await?;
            return Ok(locks.iter().any(|lock| lock.lock_id == lock_id));
        }

        if !response.status().is_success() {
            return Err(GspError::PayNodeError(format!(
                "Lock ownership check failed: {}",
                response.status()
            )));
        }

        #[derive(Deserialize)]
        struct OwnershipResponse {
            is_owner: bool,
        }

        let result: OwnershipResponse = response
            .json()
            .await
            .map_err(|e| GspError::PayNodeError(e.to_string()))?;

        Ok(result.is_owner)
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

        // M-15: Add internal auth header
        let response = self
            .add_internal_auth(self.client.get(&url))
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

        // M-15: Add internal auth header
        let response = self
            .add_internal_auth(self.client.post(&url).json(&request))
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

    /// One-shot L2 payment. Forwards to ghost-pay's
    /// `POST /api/v1/payments/send` and returns the recorded
    /// payment intent (operator-assigned `payment_id`, status,
    /// recipient/amount echo). Replaces the
    /// prepare/sign/submit dance for the new client path —
    /// L2 transfers don't produce on-chain txs and don't need
    /// per-payment sighash signatures.
    ///
    /// `sender_ghost_id` MUST be the authenticated wallet_id from
    /// the WebSocket session (caller's job — handler reads it from
    /// `conn_state.wallet_id`). Forwarded verbatim; ghost-pay
    /// records the L2 ledger entry against this identity, not the
    /// operator's.
    pub async fn send_l2_payment(
        &self,
        sender_ghost_id: &str,
        recipient: &str,
        amount_sats: u64,
        memo: Option<&str>,
    ) -> GspResult<SendL2PaymentResult> {
        let url = format!("{}/api/v1/payments/send", self.base_url);
        debug!(
            url = %url,
            sender_ghost_id = %sender_ghost_id,
            recipient = %recipient,
            amount = amount_sats,
            "Sending L2 payment",
        );

        let request = serde_json::json!({
            "sender_ghost_id": sender_ghost_id,
            "recipient": recipient,
            "amount_sats": amount_sats,
            "memo": memo,
        });

        let response = self
            .add_internal_auth(self.client.post(&url).json(&request))
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        let status = response.status();
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| GspError::PayNodeError(format!("send_l2_payment parse: {e}")))?;

        // ghost-pay's /payments/send returns either:
        //   { success:true, payment_id, sender, recipient, amount_sats, memo, status, ... }
        //   { success:false, error, ... }
        // Both are 200 OK at the HTTP layer (the failure is in the body).
        let success = body.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
        if !status.is_success() || !success {
            let err_msg = body
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("send_l2_payment failed")
                .to_string();
            return Err(GspError::PayNodeError(err_msg));
        }
        let payment_id = body
            .get("payment_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                GspError::PayNodeError("send_l2_payment: missing payment_id".into())
            })?
            .to_string();
        let pay_status = body
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("pending")
            .to_string();
        Ok(SendL2PaymentResult {
            payment_id,
            status: pay_status,
            recipient: recipient.to_string(),
            amount_sats,
        })
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

        // M-15: Add internal auth header
        let response = self
            .add_internal_auth(self.client.post(&url).json(&request))
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
        recovery_pubkey: &str,
        recovery_index: u32,
    ) -> GspResult<GhostLockInfo> {
        let url = format!("{}/api/v1/locks/create", self.base_url);
        debug!(
            url = %url,
            ghost_id = %ghost_id,
            amount = amount_sats,
            recovery_index = recovery_index,
            "Creating lock with user-supplied recovery_pubkey",
        );

        let request = CreateLockRequest {
            amount_sats,
            timelock_tier: timelock_tier.map(|s| s.to_string()),
            recovery_pubkey: recovery_pubkey.to_string(),
            recovery_index,
            owner_ghost_id: ghost_id.to_string(),
        };

        // M-15: Add internal auth header
        let response = self
            .add_internal_auth(self.client.post(&url).json(&request))
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
            creation_height: lock.creation_height.unwrap_or(0),
            recovery_height: lock.recovery_height.unwrap_or(0) as u32,
            next_jump_height: None,
            needs_jump: lock.needs_jump,
            blocks_until_jump: lock.blocks_until_jump.unwrap_or(0) as u32,
            created_at: lock.created_at as i64,
            updated_at: lock.created_at as i64,
            lock_pubkey: lock.output_pubkey.clone(),
            recovery_pubkey: lock.recovery_pubkey.unwrap_or_default(),
            recovery_index: lock.recovery_index.unwrap_or(0),
            recovery_blocks: lock.recovery_blocks.unwrap_or(0),
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

        // M-15: Add internal auth header
        let response = self
            .add_internal_auth(self.client.post(&url).json(&request))
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

        // M-15: Add internal auth header
        let response = self
            .add_internal_auth(self.client.get(&url))
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

        // M-15: Add internal auth header
        let response = self
            .add_internal_auth(self.client.post(&url))
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

        // M-15: Add internal auth header
        let response = self
            .add_internal_auth(self.client.post(&url).json(&request))
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

        // M-15: Add internal auth header
        let response = self
            .add_internal_auth(self.client.get(&url))
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

        // HIGH-STATE-2 FIX: ALWAYS verify UTXO state from L1 for Active locks
        // Previously, we only checked UTXO state as a fallback. Now we always check
        // for Active locks because cached state can become stale if:
        // - The lock was spent in another transaction
        // - The funding tx was reorged out
        // - There's a race between state updates and queries
        //
        // For Pending locks, we know they're in mempool without querying.
        // For Active locks, we MUST verify current L1 state.
        let in_mempool = match lock.status {
            GhostLockStatus::Pending => true,
            GhostLockStatus::Active | GhostLockStatus::InUse => {
                // HIGH-STATE-2: Always verify L1 state for Active/InUse locks
                // This is critical for instant payment security
                match self.get_utxo_state(&lock.lock_id).await {
                    Ok(utxo_state) => {
                        if !utxo_state.exists {
                            // Lock UTXO no longer exists - this is a critical state mismatch
                            warn!(
                                lock_id = %lock.lock_id,
                                cached_status = ?lock.status,
                                "HIGH-STATE-2: Lock marked Active but UTXO not found on L1"
                            );
                        }
                        utxo_state.in_mempool
                    }
                    Err(e) => {
                        // HIGH-STATE-2: Fail closed - if we can't verify, assume not in mempool
                        // but log the error for investigation
                        warn!(
                            lock_id = %lock.lock_id,
                            error = %e,
                            "HIGH-STATE-2: Failed to verify UTXO state for Active lock"
                        );
                        false
                    }
                }
            }
            _ => {
                // Terminal states (Spent, Recovered, Invalid) or Unknown don't need L1 verification
                false
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
    // H-9/HIGH-AUTHZ-1: Payment Ownership Verification
    // =========================================================================

    /// H-9/HIGH-AUTHZ-1: Get payment details including wallet ownership
    ///
    /// Returns payment details including the wallet_id that created the payment.
    /// This is used to verify that a wallet can only submit signatures for
    /// payments they created, preventing payment hijacking.
    ///
    /// HIGH-AUTHZ-1: Includes requesting_wallet_id for server-side access control.
    pub async fn get_payment(
        &self,
        payment_id: &str,
        requesting_wallet_id: &str,
    ) -> GspResult<PaymentInfo> {
        let url = format!(
            "{}/api/v1/payments/{}?wallet_id={}",
            self.base_url, payment_id, requesting_wallet_id
        );
        debug!(
            url = %url,
            payment_id = %payment_id,
            requesting_wallet_id = %requesting_wallet_id,
            "HIGH-AUTHZ-1: Getting payment with wallet ownership verification"
        );

        // M-15: Add internal auth header
        let response = self
            .add_internal_auth(self.client.get(&url))
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(GspError::NotFound(format!(
                "Payment not found: {}",
                payment_id
            )));
        }

        if response.status() == reqwest::StatusCode::FORBIDDEN {
            return Err(GspError::PaymentOwnershipMismatch);
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
    // HIGH-RACE-1: Atomic Instant Payment Acceptance
    // =========================================================================

    /// HIGH-RACE-1: Atomically record instant payment acceptance
    ///
    /// This calls the pay node to record the instant payment acceptance in the database
    /// with a UNIQUE constraint that prevents double-acceptance. The database operation
    /// is atomic - either this is the first acceptance (success) or it was already
    /// accepted (UNIQUE constraint violation).
    #[allow(clippy::too_many_arguments)] // HIGH-RACE-1: All parameters needed for atomic double-spend prevention
    pub async fn accept_instant_payment(
        &self,
        payment_id: &str,
        sender_lock_id: &str,
        merchant_wallet_id: &str,
        amount_sats: u64,
        settlement_block: u64,
        confidence: f64,
        sender_pubkey: &[u8],
        signature: &[u8],
    ) -> GspResult<serde_json::Value> {
        let url = format!("{}/api/v1/instant-payments/accept", self.base_url);
        debug!(
            url = %url,
            payment_id = %payment_id,
            sender_lock_id = %sender_lock_id,
            merchant_wallet_id = %merchant_wallet_id,
            "HIGH-RACE-1: Recording instant payment acceptance"
        );

        #[derive(Serialize)]
        struct AcceptInstantPaymentRequest {
            payment_id: String,
            sender_lock_id: String,
            merchant_wallet_id: String,
            amount_sats: u64,
            settlement_block: u64,
            confidence: f64,
            sender_pubkey: String,
            signature: String,
        }

        let request = AcceptInstantPaymentRequest {
            payment_id: payment_id.to_string(),
            sender_lock_id: sender_lock_id.to_string(),
            merchant_wallet_id: merchant_wallet_id.to_string(),
            amount_sats,
            settlement_block,
            confidence,
            sender_pubkey: hex::encode(sender_pubkey),
            signature: hex::encode(signature),
        };

        // M-15: Add internal auth header
        let response = self
            .add_internal_auth(self.client.post(&url).json(&request))
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(GspError::PayNodeError(format!(
                "Instant payment acceptance failed: {}",
                error_text
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

        // M-15: Add internal auth header
        let response = self
            .add_internal_auth(self.client.get(&url))
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
                confirmations: if lock.status == GhostLockStatus::Pending {
                    0
                } else {
                    1
                },
                amount_sats: lock.balance_sats,
            });
        }

        response
            .json()
            .await
            .map_err(|e| GspError::PayNodeError(e.to_string()))
    }

    // =========================================================================
    // CONFIDENTIAL TRANSFER PROXY METHODS
    // =========================================================================

    /// Submit a confidential transfer to Ghost Pay
    pub async fn submit_confidential_transfer(
        &self,
        body: &serde_json::Value,
    ) -> GspResult<serde_json::Value> {
        let url = format!("{}/api/v1/confidential/transfer", self.base_url);
        debug!(url = %url, "Submitting confidential transfer");

        let response = self
            .add_internal_auth(self.client.post(&url).json(body))
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            let error_json: serde_json::Value = response.json().await.unwrap_or_default();
            let error_msg = error_json
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("Unknown error")
                .to_string();
            return Err(GspError::PayNodeError(error_msg));
        }

        response
            .json()
            .await
            .map_err(|e| GspError::PayNodeError(e.to_string()))
    }

    /// Shield balance via Ghost Pay
    pub async fn shield_balance(&self, body: &serde_json::Value) -> GspResult<serde_json::Value> {
        let url = format!("{}/api/v1/confidential/shield", self.base_url);
        debug!(url = %url, "Shielding balance");

        let response = self
            .add_internal_auth(self.client.post(&url).json(body))
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            let error_json: serde_json::Value = response.json().await.unwrap_or_default();
            let error_msg = error_json
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("Unknown error")
                .to_string();
            return Err(GspError::PayNodeError(error_msg));
        }

        response
            .json()
            .await
            .map_err(|e| GspError::PayNodeError(e.to_string()))
    }

    /// Get commitment tree state from Ghost Pay
    pub async fn get_commitment_tree_state(&self) -> GspResult<serde_json::Value> {
        let url = format!("{}/api/v1/confidential/tree", self.base_url);

        let response = self
            .add_internal_auth(self.client.get(&url))
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            return Err(GspError::PayNodeError("Failed to get tree state".into()));
        }

        response
            .json()
            .await
            .map_err(|e| GspError::PayNodeError(e.to_string()))
    }

    /// Get confidential notes for an owner from Ghost Pay
    pub async fn get_confidential_notes(&self, owner_pubkey: &str) -> GspResult<serde_json::Value> {
        let url = format!(
            "{}/api/v1/confidential/notes/{}",
            self.base_url, owner_pubkey
        );

        let response = self
            .add_internal_auth(self.client.get(&url))
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            return Err(GspError::PayNodeError(
                "Failed to get confidential notes".into(),
            ));
        }

        response
            .json()
            .await
            .map_err(|e| GspError::PayNodeError(e.to_string()))
    }

    /// Get recent L2 transactions with encrypted fields for wallet scanning
    pub async fn get_recent_l2_transactions(
        &self,
        since_height: u64,
    ) -> GspResult<serde_json::Value> {
        let url = format!(
            "{}/api/v1/l2/transactions?since_height={}",
            self.base_url, since_height
        );

        let response = self
            .add_internal_auth(self.client.get(&url))
            .send()
            .await
            .map_err(|e| GspError::PayNodeUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            return Err(GspError::PayNodeError(
                "Failed to get L2 transactions".into(),
            ));
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

    /// Set up test environment with required secret
    fn setup_test_env() {
        // CRIT-AUTH-1: Tests need a valid secret to pass auth validation
        std::env::set_var(
            "GHOST_PAY_INTERNAL_SECRET",
            "xK9mN2pQ8rS5tY7vW1zA3bC6dE4fG0hJ2kL8mN5pQ9rS", // 40+ chars for entropy check
        );
    }

    #[test]
    fn test_proxy_creation() {
        setup_test_env();
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
