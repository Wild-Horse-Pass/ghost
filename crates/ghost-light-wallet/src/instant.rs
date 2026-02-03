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
//| FILE: instant.rs                                                                                                     |
//|======================================================================================================================|

//! Instant Payment Support for Light Wallets
//!
//! Enables merchants to show "Confirmed ✓" immediately for small payments,
//! with actual settlement happening on the next virtual block (~10 seconds).
//!
//! # Usage
//!
//! ```ignore
//! use ghost_light_wallet::instant::InstantPaymentChecker;
//!
//! // Create checker with GSP client
//! let checker = InstantPaymentChecker::new(gsp_client);
//!
//! // Check if payment can be instant
//! let capability = checker.check_instant("lock123", 50_000, 200).await?;
//!
//! if capability.capable {
//!     // Show "Confirmed ✓" immediately
//!     display_confirmed();
//! } else {
//!     // Wait for block confirmation
//!     wait_for_confirmation();
//! }
//! ```

use parking_lot::RwLock;
use std::sync::Arc;
use tracing::{debug, info, warn};

use ghost_common::instant::{InstantCapability, InstantReceipt, LockSnapshot};

#[cfg(test)]
use ghost_common::instant::InstantCondition;

use crate::error::{LightWalletError, WalletResult};
use crate::gsp::GspClient;

/// Cached instant capability for a lock
#[derive(Debug, Clone)]
struct CachedCapability {
    lock_id: String,
    capability: InstantCapability,
    cached_at_height: u64,
}

impl CachedCapability {
    fn is_valid(&self, current_height: u64) -> bool {
        current_height <= self.capability.valid_until_height
    }
}

/// Instant payment checker for light wallets
pub struct InstantPaymentChecker {
    /// GSP client for lock queries
    gsp: Arc<GspClient>,
    /// Cached capabilities (lock_id -> capability)
    cache: RwLock<Vec<CachedCapability>>,
    /// Maximum cache size
    max_cache_size: usize,
    /// Current block height (updated externally)
    current_height: RwLock<u64>,
}

impl InstantPaymentChecker {
    /// Create a new instant payment checker
    pub fn new(gsp: Arc<GspClient>) -> Self {
        Self {
            gsp,
            cache: RwLock::new(Vec::new()),
            max_cache_size: 100,
            current_height: RwLock::new(0),
        }
    }

    /// Update current block height
    pub fn set_height(&self, height: u64) {
        *self.current_height.write() = height;
    }

    /// Get current block height
    pub fn height(&self) -> u64 {
        *self.current_height.read()
    }

    /// Check if a lock is instant-capable for the given amount
    ///
    /// This checks:
    /// 1. Cache for recent capability check
    /// 2. If not cached, queries GSP for lock state
    /// 3. Evaluates conditions and returns capability
    pub async fn check_instant(
        &self,
        lock_id: &str,
        amount_sats: u64,
    ) -> WalletResult<InstantCapability> {
        let current_height = self.height();

        // Check cache first
        if let Some(cached) = self.get_cached(lock_id, current_height) {
            debug!(lock_id, "Using cached instant capability");
            // Re-evaluate for the specific amount
            if cached.max_instant_sats >= amount_sats && cached.capable {
                return Ok(cached);
            }
        }

        // Query GSP for lock state
        let snapshot = self.fetch_lock_snapshot(lock_id).await?;

        // Evaluate instant capability
        let capability = snapshot.check_instant(amount_sats, current_height);

        // Cache the result
        self.cache_capability(lock_id, &capability, current_height);

        info!(
            lock_id,
            amount_sats,
            capable = capability.capable,
            max_instant = capability.max_instant_sats,
            confidence = capability.confidence,
            "Instant capability checked"
        );

        Ok(capability)
    }

    /// Quick check - is this lock generally instant-capable?
    ///
    /// Returns the maximum instant amount without specifying a payment amount.
    /// Useful for displaying "⚡ Instant: up to X sats" in wallet UI.
    pub async fn get_instant_limit(&self, lock_id: &str) -> WalletResult<u64> {
        let current_height = self.height();

        // Check cache
        if let Some(cached) = self.get_cached(lock_id, current_height) {
            return Ok(cached.max_instant_sats);
        }

        // Query and check with max possible amount
        let snapshot = self.fetch_lock_snapshot(lock_id).await?;
        let capability = snapshot.check_instant(u64::MAX, current_height);

        self.cache_capability(lock_id, &capability, current_height);

        Ok(capability.max_instant_sats)
    }

    /// Accept an instant payment (merchant side)
    ///
    /// Returns a receipt that can be shown to the customer as "Confirmed".
    /// The actual settlement will happen on the next virtual block.
    pub async fn accept_instant_payment(
        &self,
        sender_lock_id: &str,
        amount_sats: u64,
    ) -> WalletResult<InstantReceipt> {
        let current_height = self.height();

        // Verify instant capability
        let capability = self.check_instant(sender_lock_id, amount_sats).await?;

        if !capability.capable {
            return Err(LightWalletError::InvalidPayment(format!(
                "Lock not instant-capable. Failed conditions: {:?}",
                capability.conditions_failed
            )));
        }

        if amount_sats > capability.max_instant_sats {
            return Err(LightWalletError::InvalidPayment(format!(
                "Amount {} exceeds instant limit {}",
                amount_sats, capability.max_instant_sats
            )));
        }

        // Create receipt
        let payment_id = self.generate_payment_id(sender_lock_id, amount_sats, current_height);
        let settlement_block = current_height + 1; // Next virtual block

        let receipt = InstantReceipt {
            payment_id,
            sender_lock_id: sender_lock_id.to_string(),
            amount_sats,
            capability,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            settlement_block,
        };

        info!(
            sender_lock_id,
            amount_sats, settlement_block, "Instant payment accepted"
        );

        Ok(receipt)
    }

    /// Verify a receipt is still valid
    pub fn verify_receipt(&self, receipt: &InstantReceipt) -> bool {
        let current_height = self.height();
        receipt.is_valid(current_height)
    }

    /// Check if a receipt's payment has settled
    pub fn is_settled(&self, receipt: &InstantReceipt) -> bool {
        let current_height = self.height();
        receipt.is_settled(current_height)
    }

    /// Fetch lock snapshot from GSP
    async fn fetch_lock_snapshot(&self, lock_id: &str) -> WalletResult<LockSnapshot> {
        // In a real implementation, this would query the GSP via WebSocket
        // For now, return a placeholder that the GSP would fill in

        // TODO: Implement actual GSP query
        // let response = self.gsp.query_lock_state(lock_id).await?;
        // return Ok(response.into());

        // Placeholder - GSP would provide this data
        warn!(
            lock_id,
            "GSP lock query not yet implemented, using placeholder"
        );

        Ok(LockSnapshot {
            lock_id: lock_id.to_string(),
            state: "Active".to_string(),
            balance_sats: 0,
            funding_height: 0,
            confirmations: 0,
            denomination: "Unknown".to_string(),
            jump_urgency: 1.0, // Not capable by default
            recovery_blocks_remaining: 0,
            recovery_window_total: 52560,
            in_mempool: false,
            pending_l2_sats: 0,
        })
    }

    /// Get cached capability if valid
    fn get_cached(&self, lock_id: &str, current_height: u64) -> Option<InstantCapability> {
        let cache = self.cache.read();
        cache
            .iter()
            .find(|c| c.lock_id == lock_id && c.is_valid(current_height))
            .map(|c| c.capability.clone())
    }

    /// Cache a capability result
    fn cache_capability(&self, lock_id: &str, capability: &InstantCapability, height: u64) {
        let mut cache = self.cache.write();

        // Remove old entry for this lock
        cache.retain(|c| c.lock_id != lock_id);

        // Add new entry
        cache.push(CachedCapability {
            lock_id: lock_id.to_string(),
            capability: capability.clone(),
            cached_at_height: height,
        });

        // Prune if over limit
        if cache.len() > self.max_cache_size {
            // Remove oldest entries
            cache.sort_by(|a, b| b.cached_at_height.cmp(&a.cached_at_height));
            cache.truncate(self.max_cache_size);
        }
    }

    /// Clear expired entries from cache
    pub fn prune_cache(&self) {
        let current_height = self.height();
        let mut cache = self.cache.write();
        let before = cache.len();
        cache.retain(|c| c.is_valid(current_height));
        let pruned = before - cache.len();
        if pruned > 0 {
            debug!(pruned, "Pruned expired instant capability cache entries");
        }
    }

    /// Generate a unique payment ID
    fn generate_payment_id(&self, lock_id: &str, amount: u64, height: u64) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"ghost-instant-payment-v1");
        hasher.update(lock_id.as_bytes());
        hasher.update(amount.to_le_bytes());
        hasher.update(height.to_le_bytes());
        hasher.update(
            chrono::Utc::now()
                .timestamp_nanos_opt()
                .unwrap_or(0)
                .to_le_bytes(),
        );
        hasher.finalize().into()
    }
}

/// Display helper for wallet UI
#[derive(Debug, Clone)]
pub struct InstantStatus {
    /// Is instant payment available?
    pub available: bool,
    /// Maximum instant amount (sats)
    pub max_sats: u64,
    /// Human-readable status
    pub display: String,
    /// Confidence level (for color coding)
    pub confidence: f32,
}

impl InstantStatus {
    /// Create from capability
    pub fn from_capability(cap: &InstantCapability) -> Self {
        if cap.capable {
            Self {
                available: true,
                max_sats: cap.max_instant_sats,
                display: format!("⚡ Instant: up to {} sats", cap.max_instant_sats),
                confidence: cap.confidence,
            }
        } else {
            let reason = cap
                .conditions_failed
                .first()
                .map(|c| c.description())
                .unwrap_or("Unknown");
            Self {
                available: false,
                max_sats: 0,
                display: format!("⏳ Requires confirmation ({})", reason),
                confidence: 0.0,
            }
        }
    }

    /// Format for display with amount
    pub fn format_for_amount(&self, amount_sats: u64) -> String {
        if self.available && amount_sats <= self.max_sats {
            "⚡ Instant".to_string()
        } else if self.available {
            format!("⏳ Amount exceeds instant limit ({} sats)", self.max_sats)
        } else {
            self.display.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instant_status_from_capable() {
        let cap = InstantCapability::capable(100_000, 0.95, 300);
        let status = InstantStatus::from_capability(&cap);

        assert!(status.available);
        assert_eq!(status.max_sats, 100_000);
        assert!(status.display.contains("Instant"));
    }

    #[test]
    fn test_instant_status_not_capable() {
        let cap = InstantCapability::not_capable(vec![InstantCondition::NoPendingL1]);
        let status = InstantStatus::from_capability(&cap);

        assert!(!status.available);
        assert_eq!(status.max_sats, 0);
        assert!(status.display.contains("confirmation"));
    }

    #[test]
    fn test_format_for_amount() {
        let cap = InstantCapability::capable(100_000, 0.95, 300);
        let status = InstantStatus::from_capability(&cap);

        // Under limit
        assert_eq!(status.format_for_amount(50_000), "⚡ Instant");

        // At limit
        assert_eq!(status.format_for_amount(100_000), "⚡ Instant");

        // Over limit
        let over = status.format_for_amount(150_000);
        assert!(over.contains("exceeds"));
    }
}
