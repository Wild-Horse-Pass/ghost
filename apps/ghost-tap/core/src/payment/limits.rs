//! NFC payment limits
//!
//! Enforces a configurable satoshi cap for NFC tap-to-pay transactions,
//! anchored to a fiat limit of 250 GBP. When an exchange rate is available
//! the satoshi cap is recalculated; otherwise a placeholder cap is used.

/// Result of checking an NFC payment amount against limits.
#[derive(Debug, Clone, PartialEq)]
pub enum NfcLimitResult {
    /// The amount is within the NFC limit.
    Allowed,
    /// The amount exceeds the NFC limit.
    Exceeded {
        /// The attempted amount in satoshis.
        amount: u64,
        /// The current limit in satoshis.
        limit: u64,
        /// Suggestion text for the user.
        suggestion: String,
    },
}

/// NFC payment limit configuration.
///
/// Enforces a maximum satoshi amount for NFC payments. When an exchange rate
/// is provided, the limit is derived from the fiat ceiling (250 GBP).
#[derive(Debug, Clone)]
pub struct NfcLimits {
    /// Maximum allowed amount in satoshis for NFC payments.
    pub max_amount_sats: u64,
    /// Optional GHOST/GBP exchange rate (1 GHOST = rate GBP).
    pub exchange_rate: Option<f64>,
    /// Fiat ceiling in GBP.
    pub fiat_limit: f64,
}

impl NfcLimits {
    /// Default placeholder satoshi cap (before a real exchange rate is available).
    /// 250 GHOST (25_000_000_000 sats) is a conservative placeholder.
    const DEFAULT_SAT_CAP: u64 = 25_000_000_000;

    /// Create a new NfcLimits with default placeholder cap.
    pub fn new() -> Self {
        Self {
            max_amount_sats: Self::DEFAULT_SAT_CAP,
            exchange_rate: None,
            fiat_limit: 250.0,
        }
    }

    /// Create limits with a specific satoshi cap.
    pub fn with_cap(max_amount_sats: u64) -> Self {
        Self {
            max_amount_sats,
            exchange_rate: None,
            fiat_limit: 250.0,
        }
    }

    /// Create limits from an exchange rate (recalculates satoshi cap).
    pub fn with_rate(rate: f64) -> Self {
        let mut limits = Self::new();
        limits.update_rate(rate);
        limits
    }

    /// Update the exchange rate and recalculate the satoshi cap.
    ///
    /// `rate` is the price of 1 GHOST in GBP.
    /// For example, if 1 GHOST = 2.50 GBP, then rate = 2.50.
    /// The cap becomes: (fiat_limit / rate) * 100_000_000 sats.
    pub fn update_rate(&mut self, rate: f64) {
        self.exchange_rate = Some(rate);
        if rate > 0.0 {
            let ghost_amount = self.fiat_limit / rate;
            self.max_amount_sats = (ghost_amount * 100_000_000.0) as u64;
        }
    }

    /// Check if an amount (in satoshis) is within the NFC limit.
    pub fn check(&self, amount_sats: u64) -> NfcLimitResult {
        if amount_sats <= self.max_amount_sats {
            NfcLimitResult::Allowed
        } else {
            NfcLimitResult::Exceeded {
                amount: amount_sats,
                limit: self.max_amount_sats,
                suggestion: "Amount exceeds NFC limit. Please use QR code.".into(),
            }
        }
    }
}

impl Default for NfcLimits {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowed() {
        let limits = NfcLimits::with_cap(1_000_000);
        assert_eq!(limits.check(500_000), NfcLimitResult::Allowed);
        assert_eq!(limits.check(1_000_000), NfcLimitResult::Allowed);
    }

    #[test]
    fn test_exceeded() {
        let limits = NfcLimits::with_cap(1_000_000);
        match limits.check(1_000_001) {
            NfcLimitResult::Exceeded { amount, limit, suggestion } => {
                assert_eq!(amount, 1_000_001);
                assert_eq!(limit, 1_000_000);
                assert!(suggestion.contains("QR code"));
            }
            NfcLimitResult::Allowed => panic!("should be exceeded"),
        }
    }

    #[test]
    fn test_rate_update_recalculates() {
        let mut limits = NfcLimits::new();
        assert_eq!(limits.fiat_limit, 250.0);

        // 1 GHOST = 2.50 GBP → 250 GBP = 100 GHOST = 10_000_000_000 sats
        limits.update_rate(2.50);
        assert_eq!(limits.max_amount_sats, 10_000_000_000);
        assert_eq!(limits.exchange_rate, Some(2.50));
    }

    #[test]
    fn test_with_rate() {
        // 1 GHOST = 0.50 GBP → 250 GBP = 500 GHOST = 50_000_000_000 sats
        let limits = NfcLimits::with_rate(0.50);
        assert_eq!(limits.max_amount_sats, 50_000_000_000);
    }

    #[test]
    fn test_boundary_values() {
        let limits = NfcLimits::with_cap(100);
        assert_eq!(limits.check(0), NfcLimitResult::Allowed);
        assert_eq!(limits.check(100), NfcLimitResult::Allowed);
        assert!(matches!(limits.check(101), NfcLimitResult::Exceeded { .. }));
    }

    #[test]
    fn test_default_cap() {
        let limits = NfcLimits::new();
        assert_eq!(limits.max_amount_sats, NfcLimits::DEFAULT_SAT_CAP);
        assert!(limits.exchange_rate.is_none());
    }
}
