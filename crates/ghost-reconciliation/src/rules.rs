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
//| FILE: rules.rs                                                                                                       |
//|======================================================================================================================|

//! Settlement rules and validation

use crate::error::{ReconciliationError, ReconciliationResult};
use crate::{DISPUTE_WINDOW_BLOCKS, MIN_SETTLEMENT_SATS};

/// Validate a settlement request
pub fn validate_settlement(
    source_ghost_id: &str,
    destination_address: &str,
    amount_sats: u64,
) -> ReconciliationResult<()> {
    // Check minimum amount
    if amount_sats < MIN_SETTLEMENT_SATS {
        return Err(ReconciliationError::BelowMinimum {
            amount: amount_sats,
            minimum: MIN_SETTLEMENT_SATS,
        });
    }

    // Validate source ghost ID format
    if !source_ghost_id.starts_with("ghost1") {
        return Err(ReconciliationError::InvalidProof {
            reason: "Invalid source ghost ID format".to_string(),
        });
    }

    // Validate destination address (basic check)
    if destination_address.is_empty() {
        return Err(ReconciliationError::InvalidProof {
            reason: "Empty destination address".to_string(),
        });
    }

    // QUANTUM SAFETY: Reject P2TR addresses (bc1p...)
    // P2TR exposes public keys on-chain, making them vulnerable to quantum attacks
    if destination_address.starts_with("bc1p")
        || destination_address.starts_with("tb1p")
        || destination_address.starts_with("bcrt1p")
    {
        return Err(ReconciliationError::QuantumUnsafe);
    }

    // Check Bitcoin address prefix
    let valid_prefix = destination_address.starts_with("bc1")
        || destination_address.starts_with("tb1")
        || destination_address.starts_with("bcrt1")
        || destination_address.starts_with("1")
        || destination_address.starts_with("3")
        || destination_address.starts_with("m")
        || destination_address.starts_with("n")
        || destination_address.starts_with("2");

    if !valid_prefix {
        return Err(ReconciliationError::InvalidProof {
            reason: "Invalid Bitcoin address prefix".to_string(),
        });
    }

    Ok(())
}

/// M-11: Maximum settlement fee (0.01 BTC = 1,000,000 sats)
/// This prevents unreasonably high fees on very large settlements.
/// Any settlement that would generate a fee higher than this will be rejected.
pub const MAX_FEE_SATS: u64 = 1_000_000;

/// Calculate settlement fee
///
/// # PAY-M1: Use integer arithmetic to avoid floating-point precision errors
/// # H-9: Use ceiling division to ensure fee is always rounded UP
/// # M-11: Enforce upper bound on fees
///
/// This ensures small amounts don't result in 0 fees. The formula:
/// `(amount + divisor - 1) / divisor` computes the ceiling of integer division.
///
/// Additionally, we enforce:
/// - Minimum fee of 1 satoshi (H-9)
/// - Maximum fee of 1,000,000 satoshis / 0.01 BTC (M-11)
pub fn calculate_fee(amount_sats: u64) -> u64 {
    // H-9: Ceiling division
    let divisor = crate::SETTLEMENT_FEE_DIVISOR;
    let fee = amount_sats.div_ceil(divisor);
    // H-9/M-11: Clamp between minimum (1 sat) and maximum fee
    fee.clamp(1, MAX_FEE_SATS)
}

/// Validate that a calculated fee is within acceptable bounds (M-11)
///
/// Returns Ok(()) if the fee is valid, or an error if it exceeds the maximum.
/// This should be called after calculate_fee() when additional validation is needed.
pub fn validate_fee(fee_sats: u64) -> ReconciliationResult<()> {
    if fee_sats > MAX_FEE_SATS {
        return Err(ReconciliationError::InvalidSettlement(format!(
            "M-11: Fee {} sats exceeds maximum allowed {} sats (0.01 BTC)",
            fee_sats, MAX_FEE_SATS
        )));
    }
    Ok(())
}

/// Calculate net amount after fee
pub fn calculate_net_amount(amount_sats: u64) -> u64 {
    amount_sats.saturating_sub(calculate_fee(amount_sats))
}

/// Check if dispute window has passed
pub fn is_dispute_window_passed(confirmation_height: u32, current_height: u32) -> bool {
    current_height >= confirmation_height + DISPUTE_WINDOW_BLOCKS
}

/// Get remaining dispute blocks
pub fn remaining_dispute_blocks(confirmation_height: u32, current_height: u32) -> u32 {
    let deadline = confirmation_height + DISPUTE_WINDOW_BLOCKS;
    deadline.saturating_sub(current_height)
}

/// Batch formation rules
#[derive(Debug)]
pub struct BatchRules {
    /// Minimum settlements per batch
    pub min_settlements: usize,
    /// Maximum settlements per batch
    pub max_settlements: usize,
    /// Batch timeout in seconds
    pub timeout_secs: u64,
    /// Force batch threshold (pending sats)
    pub force_batch_threshold_sats: u64,
}

impl Default for BatchRules {
    fn default() -> Self {
        Self {
            min_settlements: crate::MIN_BATCH_SIZE,
            max_settlements: crate::MAX_BATCH_SIZE,
            timeout_secs: crate::BATCH_TIMEOUT_SECS,
            force_batch_threshold_sats: 10_000_000_000, // 100 BTC
        }
    }
}

impl BatchRules {
    /// Check if batch should be formed
    pub fn should_form_batch(
        &self,
        pending_count: usize,
        pending_total_sats: u64,
        oldest_pending_age_secs: u64,
    ) -> bool {
        // Form if we have enough settlements
        if pending_count >= self.min_settlements {
            return true;
        }

        // Form if timeout reached and we have any pending
        if pending_count > 0 && oldest_pending_age_secs >= self.timeout_secs {
            return true;
        }

        // Form if total pending exceeds threshold
        if pending_total_sats >= self.force_batch_threshold_sats {
            return true;
        }

        false
    }

    /// Calculate priority score for batch formation
    pub fn batch_priority(&self, pending_count: usize, pending_total_sats: u64) -> f64 {
        let count_factor = pending_count as f64 / self.max_settlements as f64;
        let value_factor = pending_total_sats as f64 / self.force_batch_threshold_sats as f64;

        (count_factor * 0.4 + value_factor * 0.6).min(1.0)
    }
}

/// Dispute rules
pub struct DisputeRules {
    /// Dispute window in blocks
    pub window_blocks: u32,
    /// Minimum bond for dispute (satoshis)
    pub min_bond_sats: u64,
    /// Evidence submission deadline (blocks after dispute)
    pub evidence_deadline_blocks: u32,
}

impl Default for DisputeRules {
    fn default() -> Self {
        Self {
            window_blocks: DISPUTE_WINDOW_BLOCKS,
            min_bond_sats: 100_000,       // 0.001 BTC
            evidence_deadline_blocks: 36, // ~6 hours
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_settlement() {
        // Valid settlement
        assert!(validate_settlement("ghost1abc", "bc1qtest", 100_000).is_ok());

        // Below minimum
        assert!(validate_settlement("ghost1abc", "bc1qtest", 1_000).is_err());

        // Invalid ghost ID
        assert!(validate_settlement("invalid", "bc1qtest", 100_000).is_err());

        // Empty address
        assert!(validate_settlement("ghost1abc", "", 100_000).is_err());
    }

    #[test]
    fn test_validate_settlement_rejects_p2tr() {
        // QUANTUM SAFETY: P2TR addresses must be rejected

        // Mainnet P2TR
        let result = validate_settlement(
            "ghost1abc",
            "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
            100_000,
        );
        assert!(matches!(result, Err(ReconciliationError::QuantumUnsafe)));

        // Testnet P2TR
        let result = validate_settlement(
            "ghost1abc",
            "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
            100_000,
        );
        assert!(matches!(result, Err(ReconciliationError::QuantumUnsafe)));

        // Regtest P2TR
        let result = validate_settlement("ghost1abc", "bcrt1ptest", 100_000);
        assert!(matches!(result, Err(ReconciliationError::QuantumUnsafe)));

        // P2WPKH should still work
        assert!(validate_settlement("ghost1abc", "bc1qtest", 100_000).is_ok());
    }

    #[test]
    fn test_calculate_fee() {
        // Standard amounts
        assert_eq!(calculate_fee(100_000), 100); // 0.1%
        assert_eq!(calculate_fee(10_000_000), 10_000);

        // H-9: Test ceiling division (rounds UP)
        // 999 / 1000 = 0.999, ceiling is 1
        assert_eq!(calculate_fee(999), 1);
        // 1001 / 1000 = 1.001, ceiling is 2
        assert_eq!(calculate_fee(1001), 2);

        // H-9: Test minimum fee of 1 sat
        assert_eq!(calculate_fee(0), 1);
        assert_eq!(calculate_fee(1), 1);
        assert_eq!(calculate_fee(500), 1);

        // M-11: Test maximum fee cap
        // 1 BTC = 100_000_000 sats -> 0.1% = 100_000 sats (under cap)
        assert_eq!(calculate_fee(100_000_000), 100_000);
        // 10 BTC = 1_000_000_000 sats -> 0.1% = 1_000_000 sats (at cap)
        assert_eq!(calculate_fee(1_000_000_000), MAX_FEE_SATS);
        // 100 BTC = 10_000_000_000 sats -> 0.1% = 10_000_000 sats (capped to 1M)
        assert_eq!(calculate_fee(10_000_000_000), MAX_FEE_SATS);
        // 1000 BTC = 100_000_000_000 sats -> capped to MAX_FEE_SATS
        assert_eq!(calculate_fee(100_000_000_000), MAX_FEE_SATS);
    }

    #[test]
    fn test_m11_validate_fee() {
        // Valid fees
        assert!(validate_fee(1).is_ok());
        assert!(validate_fee(100_000).is_ok());
        assert!(validate_fee(MAX_FEE_SATS).is_ok());

        // Invalid fees (over max)
        assert!(validate_fee(MAX_FEE_SATS + 1).is_err());
        assert!(validate_fee(10_000_000).is_err());
    }

    #[test]
    fn test_dispute_window() {
        assert!(!is_dispute_window_passed(800_000, 800_100));
        assert!(is_dispute_window_passed(800_000, 800_144));
        assert!(is_dispute_window_passed(800_000, 800_200));

        assert_eq!(remaining_dispute_blocks(800_000, 800_100), 44);
        assert_eq!(remaining_dispute_blocks(800_000, 800_200), 0);
    }

    #[test]
    fn test_batch_rules() {
        let rules = BatchRules::default();

        // Enough settlements
        assert!(rules.should_form_batch(10, 1_000_000, 0));

        // Not enough settlements, no timeout
        assert!(!rules.should_form_batch(5, 1_000_000, 0));

        // Not enough settlements but timeout reached
        assert!(rules.should_form_batch(5, 1_000_000, 7 * 60 * 60));

        // High value forces batch
        assert!(rules.should_form_batch(1, 20_000_000_000, 0));
    }
}
