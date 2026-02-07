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
//! Enables merchants to show "Confirmed" immediately for small payments,
//! with actual settlement happening on the next virtual block (~10 seconds).
//!
//! ## Security Fixes
//!
//! - CRIT-1: Fund reservation prevents double-spending the same balance
//! - CRIT-2: Signature verification ensures sender owns the lock
//!
//! # Usage
//!
//! ```ignore
//! use ghost_light_wallet::instant::InstantPaymentChecker;
//!
//! // Create checker with GSP client and merchant ID
//! let checker = InstantPaymentChecker::new(gsp_client, "merchant123".to_string());
//!
//! // Accept a signed instant payment (CRIT-2: requires signature)
//! let receipt = checker.accept_signed_instant_payment(&signed_payment).await?;
//! ```

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

use ghost_common::instant::{
    InstantCapability, InstantPaymentError, InstantReceipt, LockSnapshot, ReservationTracker,
    SignedInstantPayment,
};

#[cfg(test)]
use ghost_common::instant::InstantCondition;

use crate::error::{LightWalletError, WalletResult};
use crate::gsp::GspClient;
use crate::signing::verify_signature;

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
///
/// SECURITY: This struct implements CRIT-1 and CRIT-2 fixes:
/// - CRIT-1: Tracks fund reservations per lock to prevent double-spend
/// - CRIT-2: Requires signature verification for payment acceptance
pub struct InstantPaymentChecker {
    /// GSP client for lock queries
    gsp: Arc<GspClient>,
    /// Cached capabilities (lock_id -> capability)
    cache: RwLock<Vec<CachedCapability>>,
    /// Maximum cache size
    max_cache_size: usize,
    /// Current block height (updated externally)
    current_height: RwLock<u64>,
    /// CRIT-1 FIX: Per-lock reservation trackers to prevent double-spend
    reservations: RwLock<HashMap<String, Arc<ReservationTracker>>>,
    /// Merchant's recipient identifier (for signature verification)
    merchant_id: String,
}

impl InstantPaymentChecker {
    /// Create a new instant payment checker
    ///
    /// # Arguments
    /// * `gsp` - GSP client for querying lock state
    /// * `merchant_id` - This merchant's identifier (for signature verification)
    pub fn new(gsp: Arc<GspClient>, merchant_id: String) -> Self {
        Self {
            gsp,
            cache: RwLock::new(Vec::new()),
            max_cache_size: 100,
            current_height: RwLock::new(0),
            reservations: RwLock::new(HashMap::new()),
            merchant_id,
        }
    }

    /// Get or create a reservation tracker for a lock
    fn get_reservation_tracker(&self, lock_id: &str) -> Arc<ReservationTracker> {
        let mut reservations = self.reservations.write();
        reservations
            .entry(lock_id.to_string())
            .or_insert_with(|| Arc::new(ReservationTracker::new()))
            .clone()
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
    pub async fn get_instant_limit(&self, lock_id: &str) -> WalletResult<u64> {
        let current_height = self.height();

        if let Some(cached) = self.get_cached(lock_id, current_height) {
            return Ok(cached.max_instant_sats);
        }

        let snapshot = self.fetch_lock_snapshot(lock_id).await?;
        let capability = snapshot.check_instant(u64::MAX, current_height);

        self.cache_capability(lock_id, &capability, current_height);

        Ok(capability.max_instant_sats)
    }

    /// Accept a signed instant payment (merchant side)
    ///
    /// SECURITY FIXES:
    /// - CRIT-1: Atomically reserves funds before confirming to prevent double-spend
    /// - CRIT-2: Verifies sender's signature to prove lock ownership
    ///
    /// Returns a receipt that can be shown to the customer as "Confirmed".
    /// The actual settlement will happen on the next virtual block.
    ///
    /// # Arguments
    /// * `signed_payment` - The signed payment request from the sender
    ///
    /// # Errors
    /// * `InvalidPayment` - If signature verification fails or lock is not instant-capable
    /// * `InsufficientBalance` - If funds are already reserved for another payment
    pub async fn accept_signed_instant_payment(
        &self,
        signed_payment: &SignedInstantPayment,
    ) -> WalletResult<InstantReceipt> {
        let current_height = self.height();
        let current_time = chrono::Utc::now().timestamp_millis() as u64;

        // CRIT-2 FIX STEP 1: Verify the signature proves ownership of the lock
        let message = signed_payment.signing_message();
        if !verify_signature(
            &signed_payment.sender_pubkey,
            &message,
            &signed_payment.signature,
        ) {
            warn!(
                sender_lock_id = signed_payment.sender_lock_id,
                "Instant payment rejected: invalid signature"
            );
            return Err(LightWalletError::InvalidPayment(
                "Signature verification failed - sender does not own the lock".to_string(),
            ));
        }

        // Verify the payment is addressed to this merchant
        if signed_payment.recipient != self.merchant_id {
            warn!(
                sender_lock_id = signed_payment.sender_lock_id,
                expected = self.merchant_id,
                got = signed_payment.recipient,
                "Instant payment rejected: wrong recipient"
            );
            return Err(LightWalletError::InvalidPayment(format!(
                "Payment addressed to '{}', not this merchant '{}'",
                signed_payment.recipient, self.merchant_id
            )));
        }

        // Query lock state to verify capability and get owner pubkey
        let snapshot = self
            .fetch_lock_snapshot(&signed_payment.sender_lock_id)
            .await?;

        // CRIT-2 FIX STEP 2: Verify the signer's pubkey matches the lock owner
        if let Some(owner_pubkey) = snapshot.owner_pubkey {
            if owner_pubkey != signed_payment.sender_pubkey {
                warn!(
                    sender_lock_id = signed_payment.sender_lock_id,
                    "Instant payment rejected: signer pubkey does not match lock owner"
                );
                return Err(LightWalletError::InvalidPayment(
                    "Signer public key does not match lock owner".to_string(),
                ));
            }
        } else {
            warn!(
                sender_lock_id = signed_payment.sender_lock_id,
                "Instant payment rejected: lock has no owner pubkey"
            );
            return Err(LightWalletError::InvalidPayment(
                "Lock does not have owner public key set".to_string(),
            ));
        }

        // Check instant capability
        let capability = snapshot.check_instant(signed_payment.amount_sats, current_height);

        if !capability.capable {
            return Err(LightWalletError::InvalidPayment(format!(
                "Lock not instant-capable. Failed conditions: {:?}",
                capability.conditions_failed
            )));
        }

        if signed_payment.amount_sats > capability.max_instant_sats {
            return Err(LightWalletError::InvalidPayment(format!(
                "Amount {} exceeds instant limit {}",
                signed_payment.amount_sats, capability.max_instant_sats
            )));
        }

        // CRIT-1 FIX: Atomically reserve funds to prevent double-spend
        let tracker = self.get_reservation_tracker(&signed_payment.sender_lock_id);
        let available_balance = snapshot
            .balance_sats
            .saturating_sub(snapshot.pending_l2_sats)
            .saturating_sub(snapshot.pending_instant_sats);

        match tracker.try_reserve(
            signed_payment.payment_id,
            signed_payment.amount_sats,
            available_balance,
            current_time,
        ) {
            Ok(_reservation) => {
                debug!(
                    sender_lock_id = signed_payment.sender_lock_id,
                    amount = signed_payment.amount_sats,
                    "Funds reserved for instant payment"
                );
            }
            Err(InstantPaymentError::InsufficientFunds {
                requested,
                available,
                reserved: _,
            }) => {
                warn!(
                    sender_lock_id = signed_payment.sender_lock_id,
                    requested,
                    available,
                    "Instant payment rejected: insufficient funds after reservations"
                );
                return Err(LightWalletError::InsufficientBalance {
                    required: requested,
                    available,
                });
            }
            Err(InstantPaymentError::DuplicatePayment) => {
                warn!(
                    sender_lock_id = signed_payment.sender_lock_id,
                    "Instant payment rejected: duplicate payment ID"
                );
                return Err(LightWalletError::InvalidPayment(
                    "Duplicate payment ID".to_string(),
                ));
            }
            Err(e) => {
                return Err(LightWalletError::InvalidPayment(format!(
                    "Reservation failed: {}",
                    e
                )));
            }
        }

        // Create receipt with signature proof
        let settlement_block = current_height + 1;

        // H-AUTH-3 FIX: Capture lock state hash for settlement verification
        let lock_state_hash = snapshot.state_hash();

        let receipt = InstantReceipt {
            payment_id: signed_payment.payment_id,
            sender_lock_id: signed_payment.sender_lock_id.clone(),
            recipient: signed_payment.recipient.clone(),
            amount_sats: signed_payment.amount_sats,
            capability,
            timestamp: current_time,
            settlement_block,
            sender_pubkey: signed_payment.sender_pubkey,
            signature: signed_payment.signature,
            lock_state_hash,
        };

        info!(
            sender_lock_id = signed_payment.sender_lock_id,
            amount_sats = signed_payment.amount_sats,
            settlement_block,
            "Signed instant payment accepted with reservation"
        );

        Ok(receipt)
    }

    /// Release a reservation (e.g., after settlement or cancellation)
    pub fn release_reservation(&self, lock_id: &str, payment_id: &[u8; 32]) {
        let tracker = self.get_reservation_tracker(lock_id);
        tracker.release(payment_id);
        debug!(lock_id, "Released instant payment reservation");
    }

    /// Get total reserved amount for a lock
    pub fn get_reserved_amount(&self, lock_id: &str) -> u64 {
        let current_time = chrono::Utc::now().timestamp_millis() as u64;
        let tracker = self.get_reservation_tracker(lock_id);
        tracker.total_reserved(current_time)
    }

    /// Prune expired reservations across all locks
    pub fn prune_reservations(&self) {
        let current_time = chrono::Utc::now().timestamp_millis() as u64;
        let reservations = self.reservations.read();
        for tracker in reservations.values() {
            tracker.prune_expired(current_time);
        }
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
        self.gsp.query_lock_state(lock_id).await
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

        cache.retain(|c| c.lock_id != lock_id);

        cache.push(CachedCapability {
            lock_id: lock_id.to_string(),
            capability: capability.clone(),
            cached_at_height: height,
        });

        if cache.len() > self.max_cache_size {
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
                display: format!("Instant: up to {} sats", cap.max_instant_sats),
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
                display: format!("Requires confirmation ({})", reason),
                confidence: 0.0,
            }
        }
    }

    /// Format for display with amount
    pub fn format_for_amount(&self, amount_sats: u64) -> String {
        if self.available && amount_sats <= self.max_sats {
            "Instant".to_string()
        } else if self.available {
            format!("Amount exceeds instant limit ({} sats)", self.max_sats)
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

        assert_eq!(status.format_for_amount(50_000), "Instant");
        assert_eq!(status.format_for_amount(100_000), "Instant");

        let over = status.format_for_amount(150_000);
        assert!(over.contains("exceeds"));
    }
}
