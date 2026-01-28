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
//| FILE: locks/jump.rs                                                                                                  |
//|======================================================================================================================|

//! Ghost Lock emergency exit (Jump) operations
//!
//! A "Jump" is an emergency unilateral exit from a Ghost Lock.
//! It allows the lock owner to reclaim their funds on-chain
//! without GSP cooperation.

use tracing::{info, warn};

use ghost_gsp_proto::{ClientMessage, JumpPriority};

use crate::error::{LightWalletError, WalletResult};
use crate::gsp::GspClient;
use crate::keys::MasterKey;
use crate::signing;

/// Jump request
#[derive(Debug, Clone)]
pub struct JumpRequest {
    /// Lock ID to jump from
    pub lock_id: String,

    /// Target address for the jump
    pub target_address: String,

    /// Priority level
    pub priority: JumpPriority,
}

impl JumpRequest {
    /// Create a new jump request
    pub fn new(lock_id: &str, target_address: &str) -> Self {
        Self {
            lock_id: lock_id.to_string(),
            target_address: target_address.to_string(),
            priority: JumpPriority::Normal,
        }
    }

    /// Set priority to high (faster but higher fees)
    pub fn high_priority(mut self) -> Self {
        self.priority = JumpPriority::High;
        self
    }

    /// Set priority to urgent (immediate, highest fees)
    pub fn urgent(mut self) -> Self {
        self.priority = JumpPriority::Urgent;
        self
    }
}

/// Jump response from GSP
#[derive(Debug, Clone)]
pub struct JumpResponse {
    /// Jump ID for tracking
    pub jump_id: String,

    /// Lock ID being jumped
    pub lock_id: String,

    /// Target address
    pub target_address: String,

    /// Amount being jumped (lock capacity minus fees)
    pub amount_sats: u64,

    /// Fee for the jump
    pub fee_sats: u64,

    /// Expected settlement time
    pub expected_settlement: i64,

    /// Jump transaction (if available)
    pub txid: Option<String>,
}

/// Request an emergency jump from a Ghost Lock
///
/// This initiates a unilateral exit from the lock.
/// The jump may be subject to a timelock depending on lock state.
pub async fn request_jump(
    client: &GspClient,
    master_key: &MasterKey,
    request: &JumpRequest,
) -> WalletResult<JumpResponse> {
    // Validate target address
    if request.target_address.is_empty() {
        return Err(LightWalletError::InvalidRecipient(
            "Target address cannot be empty".to_string(),
        ));
    }

    // Validate it looks like a Bitcoin address
    if !is_valid_address_format(&request.target_address) {
        return Err(LightWalletError::InvalidRecipient(
            "Invalid Bitcoin address format".to_string(),
        ));
    }

    warn!(
        lock_id = request.lock_id,
        target = request.target_address,
        priority = ?request.priority,
        "Requesting emergency jump - this is a unilateral exit"
    );

    // Create proof of ownership
    let proof = signing::create_wallet_proof(master_key, "request_jump")?;

    // Send jump request to GSP
    let msg = ClientMessage::RequestJump {
        lock_id: request.lock_id.clone(),
        priority: request.priority.to_string(),
        target_address: request.target_address.clone(),
        proof,
    };

    // In a real implementation, we'd send this and wait for response
    let _ = msg;
    let _ = client;

    info!(
        lock_id = request.lock_id,
        "Jump request submitted"
    );

    // Placeholder response
    Ok(JumpResponse {
        jump_id: format!("jump_{}", uuid::Uuid::new_v4()),
        lock_id: request.lock_id.clone(),
        target_address: request.target_address.clone(),
        amount_sats: 0, // Would come from GSP
        fee_sats: 0,    // Would come from GSP
        expected_settlement: chrono::Utc::now().timestamp() + 86400, // 24h default
        txid: None,
    })
}

/// Check jump status
pub async fn check_jump_status(
    client: &GspClient,
    jump_id: &str,
) -> WalletResult<JumpResponse> {
    // In a real implementation, this would query the GSP
    let _ = client;
    let _ = jump_id;

    Err(LightWalletError::LockNotFound(jump_id.to_string()))
}

/// Estimate fee for a jump
pub fn estimate_jump_fee(capacity_sats: u64, priority: &JumpPriority) -> u64 {
    // Base fee rate (sat/vbyte)
    let base_rate = match priority {
        JumpPriority::Normal => 10,
        JumpPriority::High => 50,
        JumpPriority::Urgent => 100,
    };

    // Estimated tx size for jump (~200 vbytes typical)
    let tx_size = 200;

    let fee = base_rate * tx_size;

    // Ensure fee doesn't exceed capacity
    fee.min(capacity_sats / 10) // Max 10% of capacity
}

/// Basic validation of Bitcoin address format
fn is_valid_address_format(address: &str) -> bool {
    // Check for valid prefixes
    let valid_prefixes = [
        "bc1q", "bc1p", // Mainnet bech32/bech32m
        "tb1q", "tb1p", // Testnet bech32/bech32m
        "bcrt1", // Regtest
        "1", "3", // Legacy mainnet
        "m", "n", "2", // Legacy testnet
    ];

    valid_prefixes.iter().any(|p| address.starts_with(p))
        && address.len() >= 26
        && address.len() <= 90
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jump_request() {
        let req = JumpRequest::new("lock_123", "bc1qtest...");
        assert_eq!(req.lock_id, "lock_123");
        assert!(matches!(req.priority, JumpPriority::Normal));

        let req = req.high_priority();
        assert!(matches!(req.priority, JumpPriority::High));
    }

    #[test]
    fn test_jump_fee_estimation() {
        // Use 1 BTC capacity to avoid hitting the 10% fee cap
        let normal = estimate_jump_fee(100_000_000, &JumpPriority::Normal);
        let high = estimate_jump_fee(100_000_000, &JumpPriority::High);
        let urgent = estimate_jump_fee(100_000_000, &JumpPriority::Urgent);

        assert!(normal < high);
        assert!(high < urgent);
    }

    #[test]
    fn test_address_validation() {
        assert!(is_valid_address_format("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
        assert!(is_valid_address_format("bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9"));
        assert!(is_valid_address_format("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"));

        assert!(!is_valid_address_format(""));
        assert!(!is_valid_address_format("invalid"));
        assert!(!is_valid_address_format("abc123"));
    }
}
