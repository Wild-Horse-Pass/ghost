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
//| FILE: locks/create.rs                                                                                                |
//|======================================================================================================================|

//! Ghost Lock creation

use tracing::info;

use ghost_gsp_proto::{ClientMessage, GhostLockInfo};

use crate::error::{LightWalletError, WalletResult};
use crate::gsp::GspClient;
use crate::keys::MasterKey;
use crate::signing;

/// Minimum lock capacity in satoshis
pub const MIN_LOCK_CAPACITY: u64 = 10_000;

/// Maximum lock capacity in satoshis
pub const MAX_LOCK_CAPACITY: u64 = 100_000_000; // 1 BTC

/// Request to create a Ghost Lock
#[derive(Debug, Clone)]
pub struct LockRequest {
    /// Capacity in satoshis
    pub capacity_sats: u64,

    /// Optional label for the lock
    pub label: Option<String>,
}

impl LockRequest {
    /// Create a new lock request
    pub fn new(capacity_sats: u64) -> Self {
        Self {
            capacity_sats,
            label: None,
        }
    }

    /// Add a label
    pub fn with_label(mut self, label: &str) -> Self {
        self.label = Some(label.to_string());
        self
    }
}

/// Prepared Ghost Lock ready for funding
#[derive(Debug, Clone)]
pub struct PreparedLock {
    /// Lock ID (from GSP)
    pub lock_id: String,

    /// Funding address (P2TR)
    pub funding_address: String,

    /// Required funding amount
    pub funding_amount_sats: u64,

    /// Lock expiration (when it can be swept if unfunded)
    pub expires_at: i64,
}

/// Create a Ghost Lock
///
/// This is a two-step process:
/// 1. Prepare the lock (get funding address)
/// 2. Fund the lock (send BTC to funding address)
/// 3. Confirm funding (tell GSP the funding txid)
pub async fn create_lock(
    client: &GspClient,
    master_key: &MasterKey,
    request: &LockRequest,
) -> WalletResult<PreparedLock> {
    // Validate capacity
    if request.capacity_sats < MIN_LOCK_CAPACITY {
        return Err(LightWalletError::InvalidAmount(format!(
            "Lock capacity must be at least {} sats",
            MIN_LOCK_CAPACITY
        )));
    }

    if request.capacity_sats > MAX_LOCK_CAPACITY {
        return Err(LightWalletError::InvalidAmount(format!(
            "Lock capacity cannot exceed {} sats",
            MAX_LOCK_CAPACITY
        )));
    }

    info!(
        capacity = request.capacity_sats,
        "Preparing Ghost Lock creation"
    );

    // Get owner pubkey from master key
    let owner_pubkey = hex::encode(master_key.auth_pubkey());

    // Send prepare request to GSP
    let msg = ClientMessage::PrepareGhostLock {
        owner_pubkey: owner_pubkey.clone(),
        capacity_sats: request.capacity_sats,
    };

    let prepared = client.prepare_lock_request(msg).await?;

    info!(
        lock_id = prepared.lock_id,
        funding_address = prepared.funding_address,
        "Ghost Lock prepared via GSP"
    );

    Ok(PreparedLock {
        lock_id: prepared.lock_id,
        funding_address: prepared.funding_address,
        funding_amount_sats: prepared.funding_amount_sats,
        expires_at: prepared.expires_at,
    })
}

/// Confirm that a Ghost Lock has been funded
pub async fn confirm_funding(
    client: &GspClient,
    master_key: &MasterKey,
    lock_id: &str,
    funding_txid: &str,
) -> WalletResult<GhostLockInfo> {
    info!(
        lock_id = lock_id,
        funding_txid = funding_txid,
        "Confirming Ghost Lock funding"
    );

    // Create proof of ownership
    let proof = signing::create_wallet_proof(master_key, "confirm_lock")?;

    // Send confirmation to GSP
    let msg = ClientMessage::ConfirmGhostLockFunding {
        lock_id: lock_id.to_string(),
        funding_txid: funding_txid.to_string(),
        proof,
    };

    let lock_info = client.confirm_lock_funding(msg).await?;

    info!(
        lock_id = lock_id,
        status = ?lock_info.status,
        "Ghost Lock funding confirmed via GSP"
    );

    Ok(lock_info)
}

/// Get all Ghost Locks for this wallet
pub async fn get_locks(client: &GspClient) -> WalletResult<Vec<GhostLockInfo>> {
    // Send request to GSP
    client.get_ghost_locks().await?;

    // In a real implementation, we'd wait for the response
    // For now, return empty
    Ok(vec![])
}

/// Calculate the recommended lock capacity based on expected usage
pub fn recommend_capacity(monthly_volume_sats: u64) -> u64 {
    // Recommend 2x monthly volume, clamped to valid range
    let recommended = monthly_volume_sats * 2;
    recommended.clamp(MIN_LOCK_CAPACITY, MAX_LOCK_CAPACITY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_request() {
        let req = LockRequest::new(100_000);
        assert_eq!(req.capacity_sats, 100_000);
        assert!(req.label.is_none());

        let req = req.with_label("Main lock");
        assert_eq!(req.label, Some("Main lock".to_string()));
    }

    #[test]
    fn test_recommend_capacity() {
        // Below minimum
        assert_eq!(recommend_capacity(1_000), MIN_LOCK_CAPACITY);

        // Normal range
        assert_eq!(recommend_capacity(50_000), 100_000);

        // Above maximum
        assert_eq!(recommend_capacity(100_000_000_000), MAX_LOCK_CAPACITY);
    }
}
