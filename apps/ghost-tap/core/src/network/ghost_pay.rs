//! Ghost Pay API client
//!
//! HTTP client for interacting with the Ghost Pay L2 REST API.
//! Supports glyph operations (claim, lookup, availability check).
//! Includes retry with exponential backoff for transient failures.

use serde::{Deserialize, Serialize};
use tracing::warn;

use super::NetworkError;

/// Maximum number of retry attempts for transient failures.
const MAX_RETRIES: u32 = 3;

/// Initial backoff delay in milliseconds (doubles each retry: 200, 400, 800).
const INITIAL_BACKOFF_MS: u64 = 200;

/// Configuration for Ghost Pay API connection
#[derive(Debug, Clone)]
pub struct PayConfig {
    /// Ghost Pay API base URL (e.g. "http://127.0.0.1:8800")
    pub base_url: String,
    /// Request timeout in milliseconds
    pub timeout_ms: u64,
    /// API secret for HMAC authentication on write endpoints
    pub api_secret: Option<String>,
}

impl Default for PayConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:8800".to_string(),
            timeout_ms: 10_000,
            api_secret: None,
        }
    }
}

/// Ghost Pay REST API client
pub struct GhostPayClient {
    config: PayConfig,
    client: reqwest::Client,
}

/// Response from POST /api/v1/glyph/claim
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlyphClaimResponse {
    pub commitment: String,
    pub bitmap_hash: String,
    pub status: String,
}

/// Response from GET /api/v1/glyph/:ghost_id
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlyphInfo {
    pub ghost_id: String,
    pub pixels: Vec<u8>,
    pub bitmap_hash: String,
    pub commitment: String,
    pub funding_txid: Option<String>,
    pub registered_at: Option<u64>,
    pub status: String,
}

/// Response from GET /api/v1/glyph/check/:bitmap_hash_hex
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlyphAvailability {
    pub available: bool,
}

// =============================================================================
// L2 Confidential Payment Types
// =============================================================================

/// Request to submit a NoteSpend transfer
#[derive(Debug, Clone, Serialize)]
pub struct TransferRequest {
    pub proof_hex: String,
    pub commitment_root: String,
    pub nullifier: String,
    pub change_commitment: String,
    pub recipient_commitment: String,
    pub sender_index: u64,
    pub recipient_index: u64,
    pub recipient_owner_pubkey: String,
    pub epoch: u64,
    pub encrypted_change: String,
    pub encrypted_recipient: String,
}

/// Response from a successful transfer submission
#[derive(Debug, Clone, Deserialize)]
pub struct TransferResponse {
    pub status: String,
    #[serde(default)]
    pub change_index: Option<u64>,
    #[serde(default)]
    pub recipient_index: Option<u64>,
}

/// Request to consolidate up to 4 notes into 1
#[derive(Debug, Clone, Serialize)]
pub struct ConsolidateRequest {
    pub proof_hex: String,
    pub commitment_root: String,
    pub nullifiers: Vec<String>,
    pub output_commitment: String,
    pub encrypted_output: String,
    pub epoch: u64,
}

/// Response from a successful consolidation
#[derive(Debug, Clone, Deserialize)]
pub struct ConsolidateResponse {
    pub status: String,
    #[serde(default)]
    pub output_index: Option<u64>,
}

/// Request to unshield (withdraw L2 to L1)
#[derive(Debug, Clone, Serialize)]
pub struct UnshieldRequest {
    pub proof_hex: String,
    pub commitment_root: String,
    pub nullifier: String,
    pub withdrawal_amount_sats: u64,
    pub destination_address: String,
}

/// Response from a successful unshield
#[derive(Debug, Clone, Deserialize)]
pub struct UnshieldResponse {
    pub status: String,
    #[serde(default)]
    pub txid: Option<String>,
}

/// Request to shield L1 balance into L2
#[derive(Debug, Clone, Serialize)]
pub struct ShieldRequest {
    pub amount_sats: u64,
    pub blinding_hex: String,
    pub owner_pubkey: String,
}

/// Response from a successful shield
#[derive(Debug, Clone, Deserialize)]
pub struct ShieldResponse {
    pub status: String,
    #[serde(default)]
    pub note_index: Option<u64>,
    #[serde(default)]
    pub commitment: Option<String>,
}

/// Tree state from the server
#[derive(Debug, Clone, Deserialize)]
pub struct TreeStateResponse {
    pub root: String,
    pub note_count: u64,
    pub next_index: u64,
    pub tree_depth: u64,
    pub nullifier_count: u64,
    pub current_epoch: u64,
}

/// Merkle proof response
#[derive(Debug, Clone, Deserialize)]
pub struct MerkleProofResponse {
    pub leaf_index: u64,
    pub siblings: Vec<String>,
    pub tree_root: String,
    pub tree_depth: u64,
}

/// L2 note info from the server
#[derive(Debug, Clone, Deserialize)]
pub struct NoteInfo {
    pub index: u64,
    pub commitment: String,
    pub created_height: u64,
    #[serde(default)]
    pub spent: bool,
}

/// Whether an HTTP status code is retryable (server error or rate limited).
fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS
}

/// Whether a reqwest error is retryable (timeout or connection failure only).
fn is_retryable_error(err: &reqwest::Error) -> bool {
    err.is_timeout() || err.is_connect()
}

/// URL-encode a path segment to prevent path traversal and injection.
fn encode_path_segment(s: &str) -> String {
    // Percent-encode everything except alphanumeric and bech32m-safe characters
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c.to_string()
            } else {
                format!("%{:02X}", c as u32)
            }
        })
        .collect()
}

impl GhostPayClient {
    /// Create a new Ghost Pay API client
    pub fn new(config: PayConfig) -> Result<Self, NetworkError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?;

        Ok(Self { config, client })
    }

    /// Create a Ghost Pay API client using a shared reqwest::Client.
    ///
    /// This avoids creating a new connection pool per request — use when
    /// making repeated calls from a long-lived application (e.g. desktop).
    pub fn with_client(config: PayConfig, client: reqwest::Client) -> Self {
        Self { config, client }
    }

    /// Submit a glyph claim (design chosen, pending lock funding).
    ///
    /// This is a non-idempotent mutation — no automatic retry on failure.
    /// If the server commits but the response is lost, the client should
    /// call `get_glyph()` to check the claim status before retrying.
    pub async fn claim_glyph(
        &self,
        ghost_id: &str,
        pixels: &[u8],
    ) -> Result<GlyphClaimResponse, NetworkError> {
        let url = format!("{}/api/v1/glyph/claim", self.config.base_url);
        let body = serde_json::json!({
            "ghost_id": ghost_id,
            "pixels": pixels,
        });

        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| NetworkError::RequestFailed(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let resp_body = resp.text().await.unwrap_or_default();
            warn!(status = %status, body = %resp_body, "Glyph claim failed");
            return Err(NetworkError::RequestFailed(format!(
                "HTTP {}: {}", status, resp_body
            )));
        }

        resp.json::<GlyphClaimResponse>()
            .await
            .map_err(|e| NetworkError::InvalidResponse(e.to_string()))
    }

    /// Get glyph info by ghost ID
    pub async fn get_glyph(&self, ghost_id: &str) -> Result<Option<GlyphInfo>, NetworkError> {
        let url = format!("{}/api/v1/glyph/{}", self.config.base_url, encode_path_segment(ghost_id));

        let mut last_err = None;
        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                let delay_ms = INITIAL_BACKOFF_MS * (1 << (attempt - 1));
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }

            let result = self.client.get(&url).send().await;

            match result {
                Ok(resp) => {
                    if resp.status() == reqwest::StatusCode::NOT_FOUND {
                        return Ok(None);
                    }

                    if resp.status().is_success() {
                        return resp
                            .json::<GlyphInfo>()
                            .await
                            .map(Some)
                            .map_err(|e| NetworkError::InvalidResponse(e.to_string()));
                    }

                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();

                    if is_retryable_status(status) && attempt < MAX_RETRIES {
                        warn!(status = %status, attempt, "Get glyph got retryable status, retrying");
                        last_err = Some(NetworkError::RequestFailed(format!(
                            "HTTP {}: {}", status, body
                        )));
                        continue;
                    }

                    return Err(NetworkError::RequestFailed(format!(
                        "HTTP {}: {}", status, body
                    )));
                }
                Err(e) => {
                    if is_retryable_error(&e) && attempt < MAX_RETRIES {
                        warn!(error = %e, attempt, "Get glyph request failed, retrying");
                        last_err = Some(NetworkError::RequestFailed(e.to_string()));
                        continue;
                    }
                    return Err(NetworkError::RequestFailed(e.to_string()));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| NetworkError::RequestFailed("Max retries exceeded".into())))
    }

    // =========================================================================
    // L2 Read Endpoints (no auth required)
    // =========================================================================

    /// Get the current commitment tree state.
    pub async fn get_tree_state(&self) -> Result<TreeStateResponse, NetworkError> {
        let url = format!("{}/api/v1/confidential/tree", self.config.base_url);
        self.get_with_retry(&url).await
    }

    /// Get a Merkle proof for a note at the given index.
    pub async fn get_merkle_proof(&self, index: u64) -> Result<MerkleProofResponse, NetworkError> {
        let url = format!("{}/api/v1/confidential/proof/{}", self.config.base_url, index);
        self.get_with_retry(&url).await
    }

    /// Get notes for a specific owner pubkey.
    pub async fn get_notes(&self, owner_pubkey: &str) -> Result<Vec<NoteInfo>, NetworkError> {
        let url = format!(
            "{}/api/v1/confidential/notes/{}",
            self.config.base_url,
            encode_path_segment(owner_pubkey)
        );
        self.get_with_retry(&url).await
    }

    /// Get all notes in the tree (for tree building).
    pub async fn get_all_notes(&self) -> Result<Vec<NoteInfo>, NetworkError> {
        let url = format!("{}/api/v1/confidential/notes", self.config.base_url);
        self.get_with_retry(&url).await
    }

    /// Get recent L2 transactions for wallet scanning.
    pub async fn get_l2_transactions(
        &self,
        since_height: u64,
    ) -> Result<Vec<crate::l2::scanner::L2TransactionInfo>, NetworkError> {
        let url = format!(
            "{}/api/v1/confidential/transactions?since_height={}",
            self.config.base_url, since_height
        );
        self.get_with_retry(&url).await
    }

    // =========================================================================
    // L2 Write Endpoints (require HMAC auth)
    // =========================================================================

    /// Submit a NoteSpend transfer.
    pub async fn submit_transfer(
        &self,
        req: &TransferRequest,
    ) -> Result<TransferResponse, NetworkError> {
        let url = format!("{}/api/v1/confidential/transfer", self.config.base_url);
        self.post_authenticated(&url, req).await
    }

    /// Submit a consolidation (merge up to 4 notes into 1).
    pub async fn submit_consolidation(
        &self,
        req: &ConsolidateRequest,
    ) -> Result<ConsolidateResponse, NetworkError> {
        let url = format!("{}/api/v1/confidential/consolidate", self.config.base_url);
        self.post_authenticated(&url, req).await
    }

    /// Submit an unshield (withdraw L2 to L1).
    pub async fn submit_unshield(
        &self,
        req: &UnshieldRequest,
    ) -> Result<UnshieldResponse, NetworkError> {
        let url = format!("{}/api/v1/confidential/unshield", self.config.base_url);
        self.post_authenticated(&url, req).await
    }

    /// Shield L1 balance into L2 commitment.
    pub async fn shield_balance(
        &self,
        req: &ShieldRequest,
    ) -> Result<ShieldResponse, NetworkError> {
        let url = format!("{}/api/v1/confidential/shield", self.config.base_url);
        self.post_authenticated(&url, req).await
    }

    // =========================================================================
    // Helper methods
    // =========================================================================

    /// GET with retry and JSON deserialization.
    async fn get_with_retry<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<T, NetworkError> {
        let mut last_err = None;
        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                let delay_ms = INITIAL_BACKOFF_MS * (1 << (attempt - 1));
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }

            let result = self.client.get(url).send().await;

            match result {
                Ok(resp) => {
                    if resp.status().is_success() {
                        return resp
                            .json::<T>()
                            .await
                            .map_err(|e| NetworkError::InvalidResponse(e.to_string()));
                    }

                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();

                    if is_retryable_status(status) && attempt < MAX_RETRIES {
                        warn!(status = %status, attempt, "Retryable status, retrying");
                        last_err = Some(NetworkError::RequestFailed(format!(
                            "HTTP {}: {}", status, body
                        )));
                        continue;
                    }

                    return Err(NetworkError::RequestFailed(format!(
                        "HTTP {}: {}", status, body
                    )));
                }
                Err(e) => {
                    if is_retryable_error(&e) && attempt < MAX_RETRIES {
                        warn!(error = %e, attempt, "Retryable error, retrying");
                        last_err = Some(NetworkError::RequestFailed(e.to_string()));
                        continue;
                    }
                    return Err(NetworkError::RequestFailed(e.to_string()));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| NetworkError::RequestFailed("Max retries exceeded".into())))
    }

    /// POST with HMAC authentication (for write endpoints).
    ///
    /// Non-idempotent — no automatic retry.
    async fn post_authenticated<T, R>(&self, url: &str, body: &T) -> Result<R, NetworkError>
    where
        T: Serialize,
        R: serde::de::DeserializeOwned,
    {
        let mut request = self.client.post(url).json(body);

        // Add HMAC auth header if api_secret is configured
        if let Some(ref secret) = self.config.api_secret {
            use sha2::{Digest, Sha256};
            let body_bytes = serde_json::to_vec(body)
                .map_err(|e| NetworkError::RequestFailed(format!("Serialization failed: {}", e)))?;
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut hasher = Sha256::new();
            hasher.update(secret.as_bytes());
            hasher.update(timestamp.to_string().as_bytes());
            hasher.update(&body_bytes);
            let hmac = hex::encode(hasher.finalize());
            request = request
                .header("X-Ghost-Timestamp", timestamp.to_string())
                .header("X-Ghost-HMAC", hmac);
        }

        let resp = request
            .send()
            .await
            .map_err(|e| NetworkError::RequestFailed(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(status = %status, body = %body, "L2 write endpoint failed");
            return Err(NetworkError::RequestFailed(format!(
                "HTTP {}: {}", status, body
            )));
        }

        resp.json::<R>()
            .await
            .map_err(|e| NetworkError::InvalidResponse(e.to_string()))
    }

    // =========================================================================
    // Glyph Endpoints
    // =========================================================================

    /// Check if a bitmap hash is available for registration
    pub async fn check_glyph_availability(
        &self,
        bitmap_hash_hex: &str,
    ) -> Result<bool, NetworkError> {
        let url = format!(
            "{}/api/v1/glyph/check/{}",
            self.config.base_url, encode_path_segment(bitmap_hash_hex)
        );

        let mut last_err = None;
        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                let delay_ms = INITIAL_BACKOFF_MS * (1 << (attempt - 1));
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }

            let result = self.client.get(&url).send().await;

            match result {
                Ok(resp) => {
                    if resp.status().is_success() {
                        let avail: GlyphAvailability = resp
                            .json()
                            .await
                            .map_err(|e| NetworkError::InvalidResponse(e.to_string()))?;
                        return Ok(avail.available);
                    }

                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();

                    if is_retryable_status(status) && attempt < MAX_RETRIES {
                        warn!(status = %status, attempt, "Glyph availability check got retryable status, retrying");
                        last_err = Some(NetworkError::RequestFailed(format!(
                            "HTTP {}: {}", status, body
                        )));
                        continue;
                    }

                    return Err(NetworkError::RequestFailed(format!(
                        "HTTP {}: {}", status, body
                    )));
                }
                Err(e) => {
                    if is_retryable_error(&e) && attempt < MAX_RETRIES {
                        warn!(error = %e, attempt, "Glyph availability check failed, retrying");
                        last_err = Some(NetworkError::RequestFailed(e.to_string()));
                        continue;
                    }
                    return Err(NetworkError::RequestFailed(e.to_string()));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| NetworkError::RequestFailed("Max retries exceeded".into())))
    }

    // =========================================================================
    // Ghost Lock Endpoints
    // =========================================================================

    /// List all locks.
    pub async fn list_locks(&self) -> Result<Vec<LockInfo>, NetworkError> {
        let url = format!("{}/api/v1/locks", self.config.base_url);
        self.get_with_retry(&url).await
    }

    /// Get a specific lock by ID.
    pub async fn get_lock(&self, lock_id: &str) -> Result<LockInfo, NetworkError> {
        let url = format!("{}/api/v1/locks/{}", self.config.base_url, encode_path_segment(lock_id));
        self.get_with_retry(&url).await
    }

    /// Create a new ghost lock.
    pub async fn create_lock(&self, req: &CreateLockRequest) -> Result<CreateLockResponse, NetworkError> {
        let url = format!("{}/api/v1/locks/create", self.config.base_url);
        self.post_authenticated(&url, req).await
    }

    /// Initiate a key rotation jump on a lock.
    pub async fn jump_lock(&self, lock_id: &str) -> Result<SuccessResponse, NetworkError> {
        let url = format!("{}/api/v1/locks/{}/jump", self.config.base_url, encode_path_segment(lock_id));
        self.post_authenticated(&url, &serde_json::json!({})).await
    }

    /// Reconcile (settle) a lock to L1.
    pub async fn reconcile_lock(&self, lock_id: &str, req: &ReconcileRequest) -> Result<ReconcileResponse, NetworkError> {
        let url = format!("{}/api/v1/locks/{}/reconcile", self.config.base_url, encode_path_segment(lock_id));
        self.post_authenticated(&url, req).await
    }

    // =========================================================================
    // Wraith Session Endpoints
    // =========================================================================

    /// List active wraith sessions.
    pub async fn list_wraith_sessions(&self) -> Result<Vec<WraithSessionInfo>, NetworkError> {
        let url = format!("{}/api/v1/wraith/sessions", self.config.base_url);
        self.get_with_retry(&url).await
    }

    /// Get a specific wraith session.
    pub async fn get_wraith_session(&self, session_id: &str) -> Result<WraithSessionInfo, NetworkError> {
        let url = format!("{}/api/v1/wraith/sessions/{}", self.config.base_url, encode_path_segment(session_id));
        self.get_with_retry(&url).await
    }

    /// Join a wraith session.
    pub async fn join_wraith(&self, req: &JoinWraithRequest) -> Result<JoinWraithResponse, NetworkError> {
        let url = format!("{}/api/v1/wraith/join", self.config.base_url);
        self.post_authenticated(&url, req).await
    }

    /// Submit a UTXO input to a wraith session.
    pub async fn submit_wraith_input(&self, req: &WraithSubmitInputRequest) -> Result<SuccessResponse, NetworkError> {
        let url = format!("{}/api/v1/wraith/submit-input", self.config.base_url);
        self.post_authenticated(&url, req).await
    }

    // =========================================================================
    // Ghost ID Endpoints
    // =========================================================================

    /// Get the current Ghost ID.
    pub async fn get_ghost_id(&self) -> Result<GhostIdInfo, NetworkError> {
        let url = format!("{}/api/v1/keys/ghost-id", self.config.base_url);
        self.get_with_retry(&url).await
    }

    /// Generate a new Ghost ID.
    pub async fn generate_ghost_id(&self) -> Result<GenerateGhostIdResponse, NetworkError> {
        let url = format!("{}/api/v1/keys/generate", self.config.base_url);
        self.post_authenticated(&url, &serde_json::json!({})).await
    }

    /// Export ghost keys.
    pub async fn export_ghost_keys(&self) -> Result<GhostIdInfo, NetworkError> {
        let url = format!("{}/api/v1/keys/export", self.config.base_url);
        self.get_with_retry(&url).await  // This uses auth via get, but the endpoint may require it
    }

    // =========================================================================
    // L2 Payment Endpoints
    // =========================================================================

    /// Send an L2 payment.
    pub async fn send_l2_payment(&self, req: &SendL2PaymentRequest) -> Result<SuccessResponse, NetworkError> {
        let url = format!("{}/api/v1/payments/send", self.config.base_url);
        self.post_authenticated(&url, req).await
    }

    // =========================================================================
    // Withdrawal Endpoints
    // =========================================================================

    /// List all withdrawal requests.
    pub async fn list_withdrawals(&self) -> Result<Vec<WithdrawalInfo>, NetworkError> {
        let url = format!("{}/api/v1/withdrawals", self.config.base_url);
        self.get_with_retry(&url).await
    }

    /// Get a specific withdrawal.
    pub async fn get_withdrawal(&self, id: u64) -> Result<WithdrawalInfo, NetworkError> {
        let url = format!("{}/api/v1/withdrawals/{}", self.config.base_url, id);
        self.get_with_retry(&url).await
    }
}

// =============================================================================
// Ghost Lock Types
// =============================================================================

/// Lock info from GET /api/v1/locks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockInfo {
    pub id: String,
    pub denomination: String,
    pub amount_sats: u64,
    pub state: String,
    pub created_at: u64,
    #[serde(default)]
    pub timelock_tier: String,
    #[serde(default)]
    pub jump_risk: String,
    #[serde(default)]
    pub needs_jump: bool,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub output_pubkey: String,
    #[serde(default)]
    pub recovery_height: u32,
    #[serde(default)]
    pub blocks_until_jump: u32,
}

/// Request to create a lock
#[derive(Debug, Clone, Serialize)]
pub struct CreateLockRequest {
    pub amount_sats: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timelock_tier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// Response from lock creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateLockResponse {
    pub success: bool,
    pub lock: LockInfo,
}

/// Request to reconcile (settle) a lock to L1
#[derive(Debug, Clone, Serialize)]
pub struct ReconcileRequest {
    pub destination_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settlement_class: Option<String>,
}

/// Response from lock reconciliation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileResponse {
    pub success: bool,
    #[serde(default)]
    pub settlement_amount: u64,
    #[serde(default)]
    pub settlement_fee: u64,
    #[serde(default)]
    pub settlement_class: String,
    #[serde(default)]
    pub destination_address: String,
    #[serde(default)]
    pub message: String,
}

/// Generic success response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessResponse {
    pub success: bool,
    #[serde(default)]
    pub message: String,
}

// =============================================================================
// Wraith Session Types
// =============================================================================

/// Wraith session info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WraithSessionInfo {
    pub id: String,
    #[serde(default)]
    pub tier: String,
    #[serde(default)]
    pub denomination: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub participants: u32,
    #[serde(default)]
    pub fill_percentage: f64,
    #[serde(default)]
    pub auto_sign: bool,
}

/// Request to join a wraith session
#[derive(Debug, Clone, Serialize)]
pub struct JoinWraithRequest {
    pub tier: String,
    pub denomination: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_id: Option<String>,
}

/// Response from joining a wraith session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinWraithResponse {
    pub success: bool,
    pub session_id: String,
    #[serde(default)]
    pub participants: u32,
    #[serde(default)]
    pub fill_percentage: f64,
}

/// Request to submit a UTXO input
#[derive(Debug, Clone, Serialize)]
pub struct WraithSubmitInputRequest {
    pub session_id: String,
    pub ghost_id: String,
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub script_pubkey: String,
}

// =============================================================================
// Ghost ID Types
// =============================================================================

/// Ghost ID info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostIdInfo {
    pub ghost_id: String,
    #[serde(default)]
    pub scan_pubkey: String,
    #[serde(default)]
    pub spend_pubkey: String,
}

/// Response from generating a ghost ID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateGhostIdResponse {
    pub success: bool,
    #[serde(default)]
    pub ghost_id: String,
}

// =============================================================================
// L2 Payment Types
// =============================================================================

/// Request to send an L2 payment
#[derive(Debug, Clone, Serialize)]
pub struct SendL2PaymentRequest {
    pub recipient: String,
    pub amount_sats: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
}

// =============================================================================
// Withdrawal Types
// =============================================================================

/// Withdrawal request info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalInfo {
    pub id: u64,
    pub lock_id: String,
    pub destination_address: String,
    pub amount_sats: u64,
    #[serde(default)]
    pub fee_sats: u64,
    pub status: String,
    #[serde(default)]
    pub batch_id: Option<String>,
    #[serde(default)]
    pub l1_txid: Option<String>,
    #[serde(default)]
    pub created_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pay_config_default() {
        let config = PayConfig::default();
        assert_eq!(config.base_url, "http://127.0.0.1:8800");
        assert_eq!(config.timeout_ms, 10_000);
        assert!(config.api_secret.is_none());
    }

    #[test]
    fn test_ghost_pay_client_creation() {
        let config = PayConfig::default();
        let client = GhostPayClient::new(config);
        assert!(client.is_ok());
    }

    #[test]
    fn test_retryable_status_codes() {
        assert!(is_retryable_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR));
        assert!(is_retryable_status(reqwest::StatusCode::BAD_GATEWAY));
        assert!(is_retryable_status(reqwest::StatusCode::SERVICE_UNAVAILABLE));
        assert!(is_retryable_status(reqwest::StatusCode::TOO_MANY_REQUESTS));
        assert!(!is_retryable_status(reqwest::StatusCode::BAD_REQUEST));
        assert!(!is_retryable_status(reqwest::StatusCode::NOT_FOUND));
        assert!(!is_retryable_status(reqwest::StatusCode::OK));
    }
}
