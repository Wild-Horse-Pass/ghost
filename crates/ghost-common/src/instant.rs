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

//! Instant Payment Capability for Light Wallets
//!
//! Enables "optimistic confirmation" for small L2 payments:
//! - Merchant shows "Confirmed ✓" immediately
//! - Actual settlement happens on next virtual block (~10 sec)
//! - Risk bounded by denomination and conditions
//!
//! # How It Works
//!
//! ```text
//! ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
//! │ Light Wallet│────►│     GSP     │────►│  L2 State   │
//! │  (Merchant) │query│             │     │             │
//! └─────────────┘     └─────────────┘     └─────────────┘
//!       │
//!       ▼
//!  "Is lock instant-capable for 5000 sats?"
//!       │
//!       ▼
//!  ┌────────────────────────────────┐
//!  │ InstantCapability {            │
//!  │   capable: true,               │
//!  │   max_instant_sats: 100_000,   │
//!  │   confidence: 0.99,            │
//!  │   conditions: [...],           │
//!  │ }                              │
//!  └────────────────────────────────┘
//! ```

use serde::{Deserialize, Serialize};

/// Maximum instant payment by denomination tier
/// Cap at Tiny (~$100) - larger amounts require confirmation
pub const INSTANT_LIMIT_MICRO: u64 = 10_000; // 10k sats (~$10)
pub const INSTANT_LIMIT_TINY: u64 = 100_000; // 100k sats (~$100) - MAX
                                             // Small, Medium, Large, XL all capped at Tiny limit for instant
                                             // Anything over $100 should wait for confirmation (~10 sec)

/// Minimum confirmations for instant payment eligibility
pub const MIN_CONFIRMATIONS_INSTANT: u32 = 6;

/// Maximum jump urgency for instant payments (20%)
pub const MAX_JUMP_URGENCY_INSTANT: f32 = 0.2;

/// Minimum recovery window remaining (50%)
pub const MIN_RECOVERY_WINDOW_PERCENT: f32 = 0.5;

/// Instant capability validity window (blocks)
pub const INSTANT_VALIDITY_BLOCKS: u32 = 6; // ~1 hour

/// Conditions that must be met for instant payments
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InstantCondition {
    /// Lock is in Active state
    ActiveState,
    /// Lock has sufficient confirmations
    SufficientConfirmations,
    /// Denomination is within instant limit
    DenominationEligible,
    /// Jump urgency is low (not due for rotation)
    LowJumpUrgency,
    /// Recovery timelock has sufficient buffer
    RecoveryWindowSafe,
    /// No pending L1 transactions (mempool clear)
    NoPendingL1,
    /// No pending L2 payments that would exhaust balance
    NoPendingL2,
    /// L2 balance sufficient for payment + buffer
    SufficientBalance,
}

impl InstantCondition {
    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::ActiveState => "Lock is active and spendable",
            Self::SufficientConfirmations => "Lock has 6+ confirmations",
            Self::DenominationEligible => "Amount within instant limit",
            Self::LowJumpUrgency => "Key rotation not urgent",
            Self::RecoveryWindowSafe => "Recovery timelock has buffer",
            Self::NoPendingL1 => "No pending L1 transactions",
            Self::NoPendingL2 => "No pending L2 payments",
            Self::SufficientBalance => "Balance covers payment + fees",
        }
    }

    /// Get condition as a bit flag
    pub fn bit_flag(&self) -> u8 {
        match self {
            Self::ActiveState => 0b0000_0001,
            Self::SufficientConfirmations => 0b0000_0010,
            Self::DenominationEligible => 0b0000_0100,
            Self::LowJumpUrgency => 0b0000_1000,
            Self::RecoveryWindowSafe => 0b0001_0000,
            Self::NoPendingL1 => 0b0010_0000,
            Self::NoPendingL2 => 0b0100_0000,
            Self::SufficientBalance => 0b1000_0000,
        }
    }
}

/// Result of checking instant payment capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstantCapability {
    /// Whether instant payment is possible
    pub capable: bool,
    /// Maximum amount for instant payment (sats)
    pub max_instant_sats: u64,
    /// Confidence level (0.0 - 1.0)
    /// Higher = lower risk of failure/double-spend
    pub confidence: f32,
    /// Block height when this capability expires
    pub valid_until_height: u64,
    /// Conditions that were met
    pub conditions_met: Vec<InstantCondition>,
    /// Conditions that failed (if not capable)
    pub conditions_failed: Vec<InstantCondition>,
}

impl InstantCapability {
    /// Create a new "not capable" result
    pub fn not_capable(failed: Vec<InstantCondition>) -> Self {
        Self {
            capable: false,
            max_instant_sats: 0,
            confidence: 0.0,
            valid_until_height: 0,
            conditions_met: vec![],
            conditions_failed: failed,
        }
    }

    /// Create a new "capable" result
    pub fn capable(max_sats: u64, confidence: f32, valid_until: u64) -> Self {
        Self {
            capable: true,
            max_instant_sats: max_sats,
            confidence,
            valid_until_height: valid_until,
            conditions_met: vec![
                InstantCondition::ActiveState,
                InstantCondition::SufficientConfirmations,
                InstantCondition::DenominationEligible,
                InstantCondition::LowJumpUrgency,
                InstantCondition::RecoveryWindowSafe,
                InstantCondition::NoPendingL1,
                InstantCondition::NoPendingL2,
                InstantCondition::SufficientBalance,
            ],
            conditions_failed: vec![],
        }
    }

    /// Encode conditions as a bitmap for compact transmission
    pub fn conditions_bitmap(&self) -> u8 {
        self.conditions_met
            .iter()
            .fold(0u8, |acc, c| acc | c.bit_flag())
    }

    /// Decode conditions from a bitmap
    pub fn from_bitmap(bitmap: u8) -> Vec<InstantCondition> {
        let all_conditions = [
            InstantCondition::ActiveState,
            InstantCondition::SufficientConfirmations,
            InstantCondition::DenominationEligible,
            InstantCondition::LowJumpUrgency,
            InstantCondition::RecoveryWindowSafe,
            InstantCondition::NoPendingL1,
            InstantCondition::NoPendingL2,
            InstantCondition::SufficientBalance,
        ];

        all_conditions
            .into_iter()
            .filter(|c| bitmap & c.bit_flag() != 0)
            .collect()
    }
}

/// Request to check instant payment capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstantCheckRequest {
    /// Lock ID to check
    pub lock_id: String,
    /// Amount to pay (sats)
    pub amount_sats: u64,
    /// Current block height (for expiry calculation)
    pub current_height: u64,
}

/// Lock state snapshot for instant payment evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockSnapshot {
    /// Lock identifier
    pub lock_id: String,
    /// Current state (must be "Active")
    pub state: String,
    /// Total balance in sats
    pub balance_sats: u64,
    /// Block height when lock was funded
    pub funding_height: u32,
    /// Confirmations since funding
    pub confirmations: u32,
    /// Denomination tier
    pub denomination: String,
    /// Jump urgency (0.0 = fresh, 1.0 = needs rotation)
    pub jump_urgency: f32,
    /// Blocks until recovery timelock
    pub recovery_blocks_remaining: u32,
    /// Total recovery window blocks
    pub recovery_window_total: u32,
    /// Whether lock is in mempool (pending L1 tx)
    pub in_mempool: bool,
    /// Pending L2 payment amount (sats)
    pub pending_l2_sats: u64,
}

impl LockSnapshot {
    /// Check if this lock meets instant payment conditions for the given amount
    pub fn check_instant(&self, amount_sats: u64, current_height: u64) -> InstantCapability {
        let mut met = Vec::new();
        let mut failed = Vec::new();

        // 1. Active state
        if self.state == "Active" {
            met.push(InstantCondition::ActiveState);
        } else {
            failed.push(InstantCondition::ActiveState);
        }

        // 2. Sufficient confirmations
        if self.confirmations >= MIN_CONFIRMATIONS_INSTANT {
            met.push(InstantCondition::SufficientConfirmations);
        } else {
            failed.push(InstantCondition::SufficientConfirmations);
        }

        // 3. Denomination eligible
        let max_for_denomination = self.instant_limit_for_denomination();
        if amount_sats <= max_for_denomination {
            met.push(InstantCondition::DenominationEligible);
        } else {
            failed.push(InstantCondition::DenominationEligible);
        }

        // 4. Low jump urgency
        if self.jump_urgency < MAX_JUMP_URGENCY_INSTANT {
            met.push(InstantCondition::LowJumpUrgency);
        } else {
            failed.push(InstantCondition::LowJumpUrgency);
        }

        // 5. Recovery window safe
        let recovery_ratio =
            self.recovery_blocks_remaining as f32 / self.recovery_window_total.max(1) as f32;
        if recovery_ratio >= MIN_RECOVERY_WINDOW_PERCENT {
            met.push(InstantCondition::RecoveryWindowSafe);
        } else {
            failed.push(InstantCondition::RecoveryWindowSafe);
        }

        // 6. No pending L1
        if !self.in_mempool {
            met.push(InstantCondition::NoPendingL1);
        } else {
            failed.push(InstantCondition::NoPendingL1);
        }

        // 7. No pending L2 that would exhaust balance
        let available = self.balance_sats.saturating_sub(self.pending_l2_sats);
        if self.pending_l2_sats == 0 || available >= amount_sats {
            met.push(InstantCondition::NoPendingL2);
        } else {
            failed.push(InstantCondition::NoPendingL2);
        }

        // 8. Sufficient balance (with 10% buffer for fees)
        let required = amount_sats + (amount_sats / 10);
        if available >= required {
            met.push(InstantCondition::SufficientBalance);
        } else {
            failed.push(InstantCondition::SufficientBalance);
        }

        // Determine capability
        if failed.is_empty() {
            // Calculate confidence based on conditions
            let confidence = self.calculate_confidence();
            let max_instant = max_for_denomination.min(available.saturating_sub(available / 10));
            let valid_until = current_height + INSTANT_VALIDITY_BLOCKS as u64;

            InstantCapability {
                capable: true,
                max_instant_sats: max_instant,
                confidence,
                valid_until_height: valid_until,
                conditions_met: met,
                conditions_failed: failed,
            }
        } else {
            InstantCapability {
                capable: false,
                max_instant_sats: 0,
                confidence: 0.0,
                valid_until_height: 0,
                conditions_met: met,
                conditions_failed: failed,
            }
        }
    }

    /// Get instant limit based on denomination
    /// Capped at 100k sats (~$100) regardless of lock size
    fn instant_limit_for_denomination(&self) -> u64 {
        match self.denomination.as_str() {
            "Micro" => INSTANT_LIMIT_MICRO, // 10k sats
            // Everything else caps at Tiny limit (~$100)
            "Tiny" | "Small" | "Medium" | "Large" | "XL" => INSTANT_LIMIT_TINY,
            _ => 0,
        }
    }

    /// Calculate confidence score based on lock health
    fn calculate_confidence(&self) -> f32 {
        let mut score = 1.0f32;

        // Lower confidence if confirmations are borderline
        if self.confirmations < 10 {
            score *= 0.9;
        }

        // Lower confidence if jump is approaching
        if self.jump_urgency > 0.1 {
            score *= 1.0 - (self.jump_urgency * 0.3);
        }

        // Lower confidence if recovery window is getting tight
        let recovery_ratio =
            self.recovery_blocks_remaining as f32 / self.recovery_window_total.max(1) as f32;
        if recovery_ratio < 0.7 {
            score *= recovery_ratio + 0.3;
        }

        score.clamp(0.5, 1.0)
    }
}

/// Instant payment receipt (for merchant confirmation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstantReceipt {
    /// Payment ID
    pub payment_id: [u8; 32],
    /// Sender's lock ID
    pub sender_lock_id: String,
    /// Amount in sats
    pub amount_sats: u64,
    /// Capability snapshot at time of payment
    pub capability: InstantCapability,
    /// Timestamp
    pub timestamp: u64,
    /// Expected settlement block
    pub settlement_block: u64,
}

impl InstantReceipt {
    /// Check if receipt is still valid
    pub fn is_valid(&self, current_height: u64) -> bool {
        current_height <= self.capability.valid_until_height
    }

    /// Check if payment has likely settled
    pub fn is_settled(&self, current_height: u64) -> bool {
        current_height >= self.settlement_block
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_healthy_lock() -> LockSnapshot {
        LockSnapshot {
            lock_id: "abc123".to_string(),
            state: "Active".to_string(),
            balance_sats: 500_000,
            funding_height: 100,
            confirmations: 10,
            denomination: "Small".to_string(),
            jump_urgency: 0.05,
            recovery_blocks_remaining: 40_000,
            recovery_window_total: 52_560,
            in_mempool: false,
            pending_l2_sats: 0,
        }
    }

    #[test]
    fn test_healthy_lock_is_instant_capable() {
        let lock = create_healthy_lock();
        let result = lock.check_instant(100_000, 200);

        assert!(result.capable);
        assert!(result.max_instant_sats >= 100_000);
        assert!(result.confidence > 0.9);
        assert!(result.conditions_failed.is_empty());
    }

    #[test]
    fn test_inactive_lock_not_capable() {
        let mut lock = create_healthy_lock();
        lock.state = "Frozen".to_string();

        let result = lock.check_instant(100_000, 200);

        assert!(!result.capable);
        assert!(result
            .conditions_failed
            .contains(&InstantCondition::ActiveState));
    }

    #[test]
    fn test_insufficient_confirmations() {
        let mut lock = create_healthy_lock();
        lock.confirmations = 3;

        let result = lock.check_instant(100_000, 200);

        assert!(!result.capable);
        assert!(result
            .conditions_failed
            .contains(&InstantCondition::SufficientConfirmations));
    }

    #[test]
    fn test_amount_exceeds_denomination_limit() {
        let lock = create_healthy_lock(); // Small denomination, but capped at 100k
        let result = lock.check_instant(150_000, 200); // Over 100k limit

        assert!(!result.capable);
        assert!(result
            .conditions_failed
            .contains(&InstantCondition::DenominationEligible));
    }

    #[test]
    fn test_high_jump_urgency() {
        let mut lock = create_healthy_lock();
        lock.jump_urgency = 0.5; // 50% - needs rotation soon

        let result = lock.check_instant(100_000, 200);

        assert!(!result.capable);
        assert!(result
            .conditions_failed
            .contains(&InstantCondition::LowJumpUrgency));
    }

    #[test]
    fn test_lock_in_mempool() {
        let mut lock = create_healthy_lock();
        lock.in_mempool = true;

        let result = lock.check_instant(100_000, 200);

        assert!(!result.capable);
        assert!(result
            .conditions_failed
            .contains(&InstantCondition::NoPendingL1));
    }

    #[test]
    fn test_insufficient_balance() {
        let mut lock = create_healthy_lock();
        lock.balance_sats = 50_000; // Not enough for 100k payment

        let result = lock.check_instant(100_000, 200);

        assert!(!result.capable);
        assert!(result
            .conditions_failed
            .contains(&InstantCondition::SufficientBalance));
    }

    #[test]
    fn test_pending_l2_reduces_available() {
        let mut lock = create_healthy_lock();
        lock.pending_l2_sats = 400_000; // Leaves only 100k available

        let result = lock.check_instant(150_000, 200); // Wants more than available

        assert!(!result.capable);
    }

    #[test]
    fn test_large_denomination_capped_at_100k() {
        let mut lock = create_healthy_lock();
        lock.denomination = "Large".to_string();
        lock.balance_sats = 100_000_000; // 1 BTC

        // Can do instant up to 100k even with Large lock
        let result = lock.check_instant(50_000, 200);
        assert!(result.capable);
        assert_eq!(result.max_instant_sats, INSTANT_LIMIT_TINY); // Capped at 100k

        // But not over 100k
        let result = lock.check_instant(150_000, 200);
        assert!(!result.capable);
        assert!(result
            .conditions_failed
            .contains(&InstantCondition::DenominationEligible));
    }

    #[test]
    fn test_conditions_bitmap() {
        let capability = InstantCapability::capable(100_000, 0.95, 300);
        let bitmap = capability.conditions_bitmap();

        // All 8 conditions met = 0xFF
        assert_eq!(bitmap, 0xFF);

        // Decode and verify
        let decoded = InstantCapability::from_bitmap(bitmap);
        assert_eq!(decoded.len(), 8);
    }

    #[test]
    fn test_micro_denomination_limits() {
        let mut lock = create_healthy_lock();
        lock.denomination = "Micro".to_string();
        lock.balance_sats = 10_000;

        // Can do 5k instant
        let result = lock.check_instant(5_000, 200);
        assert!(result.capable);

        // Cannot exceed 10k limit
        let result = lock.check_instant(15_000, 200);
        assert!(!result.capable);
    }

    #[test]
    fn test_confidence_calculation() {
        // High confidence - healthy lock
        let lock = create_healthy_lock();
        let result = lock.check_instant(100_000, 200);
        assert!(result.confidence > 0.95);

        // Lower confidence - borderline confirmations
        let mut lock2 = create_healthy_lock();
        lock2.confirmations = 7;
        let result2 = lock2.check_instant(100_000, 200);
        assert!(result2.capable);
        assert!(result2.confidence < result.confidence);
    }

    #[test]
    fn test_instant_receipt() {
        let receipt = InstantReceipt {
            payment_id: [1u8; 32],
            sender_lock_id: "abc123".to_string(),
            amount_sats: 50_000,
            capability: InstantCapability::capable(100_000, 0.95, 210),
            timestamp: 1700000000,
            settlement_block: 205,
        };

        // Valid before expiry
        assert!(receipt.is_valid(200));
        assert!(receipt.is_valid(210));
        assert!(!receipt.is_valid(211));

        // Settlement check
        assert!(!receipt.is_settled(204));
        assert!(receipt.is_settled(205));
        assert!(receipt.is_settled(300));
    }
}
