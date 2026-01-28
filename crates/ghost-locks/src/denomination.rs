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
//| FILE: denomination.rs                                                                                                |
//|======================================================================================================================|

//! Standard denominations for Ghost Locks
//!
//! Standard denominations enable:
//! - Efficient batching in Wraith mixing
//! - Privacy through uniformity
//! - Predictable fee calculations

use serde::{Deserialize, Serialize};

/// Standard Ghost Lock denominations
///
/// Using standard denominations provides privacy by making all locks
/// of the same tier indistinguishable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Denomination {
    /// 10,000 satoshis (0.0001 BTC)
    Micro,
    /// 100,000 satoshis (0.001 BTC)
    Tiny,
    /// 1,000,000 satoshis (0.01 BTC)
    Small,
    /// 10,000,000 satoshis (0.1 BTC)
    Medium,
    /// 100,000,000 satoshis (1 BTC)
    Large,
    /// 1,000,000,000 satoshis (10 BTC)
    XL,
}

impl Denomination {
    /// Get the satoshi value for this denomination
    pub fn sats(&self) -> u64 {
        match self {
            Denomination::Micro => 10_000,
            Denomination::Tiny => 100_000,
            Denomination::Small => 1_000_000,
            Denomination::Medium => 10_000_000,
            Denomination::Large => 100_000_000,
            Denomination::XL => 1_000_000_000,
        }
    }

    /// Get the BTC value for this denomination
    pub fn btc(&self) -> f64 {
        self.sats() as f64 / 100_000_000.0
    }

    /// Get the name of this denomination
    pub fn name(&self) -> &'static str {
        match self {
            Denomination::Micro => "Micro",
            Denomination::Tiny => "Tiny",
            Denomination::Small => "Small",
            Denomination::Medium => "Medium",
            Denomination::Large => "Large",
            Denomination::XL => "Extra Large",
        }
    }

    /// Get a short code for this denomination
    pub fn code(&self) -> &'static str {
        match self {
            Denomination::Micro => "M",
            Denomination::Tiny => "T",
            Denomination::Small => "S",
            Denomination::Medium => "M",
            Denomination::Large => "L",
            Denomination::XL => "XL",
        }
    }

    /// Get the denomination from a satoshi value (exact match required)
    pub fn from_sats(sats: u64) -> Option<Self> {
        match sats {
            10_000 => Some(Denomination::Micro),
            100_000 => Some(Denomination::Tiny),
            1_000_000 => Some(Denomination::Small),
            10_000_000 => Some(Denomination::Medium),
            100_000_000 => Some(Denomination::Large),
            1_000_000_000 => Some(Denomination::XL),
            _ => None,
        }
    }

    /// Get the closest denomination for a given amount (rounds down)
    pub fn closest_for_amount(sats: u64) -> Option<Self> {
        if sats >= 1_000_000_000 {
            Some(Denomination::XL)
        } else if sats >= 100_000_000 {
            Some(Denomination::Large)
        } else if sats >= 10_000_000 {
            Some(Denomination::Medium)
        } else if sats >= 1_000_000 {
            Some(Denomination::Small)
        } else if sats >= 100_000 {
            Some(Denomination::Tiny)
        } else if sats >= 10_000 {
            Some(Denomination::Micro)
        } else {
            None // Below minimum
        }
    }

    /// Get all denominations in order (smallest to largest)
    pub fn all() -> &'static [Denomination] {
        &[
            Denomination::Micro,
            Denomination::Tiny,
            Denomination::Small,
            Denomination::Medium,
            Denomination::Large,
            Denomination::XL,
        ]
    }

    /// Calculate how many locks of this denomination fit in an amount
    pub fn count_in_amount(&self, sats: u64) -> u64 {
        sats / self.sats()
    }

    /// Calculate remainder after filling with this denomination
    pub fn remainder_from_amount(&self, sats: u64) -> u64 {
        sats % self.sats()
    }
}

impl std::fmt::Display for Denomination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({:.8} BTC)", self.name(), self.btc())
    }
}

/// Break an amount into optimal denominations
///
/// Returns a list of (denomination, count) pairs, largest first
pub fn optimal_denominations(mut sats: u64) -> Vec<(Denomination, u64)> {
    let mut result = Vec::new();

    // Work from largest to smallest
    for denom in Denomination::all().iter().rev() {
        let count = denom.count_in_amount(sats);
        if count > 0 {
            result.push((*denom, count));
            sats = denom.remainder_from_amount(sats);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_denomination_values() {
        assert_eq!(Denomination::Micro.sats(), 10_000);
        assert_eq!(Denomination::Tiny.sats(), 100_000);
        assert_eq!(Denomination::Small.sats(), 1_000_000);
        assert_eq!(Denomination::Medium.sats(), 10_000_000);
        assert_eq!(Denomination::Large.sats(), 100_000_000);
        assert_eq!(Denomination::XL.sats(), 1_000_000_000);
    }

    #[test]
    fn test_from_sats() {
        assert_eq!(Denomination::from_sats(1_000_000), Some(Denomination::Small));
        assert_eq!(Denomination::from_sats(500_000), None);
    }

    #[test]
    fn test_closest_for_amount() {
        assert_eq!(
            Denomination::closest_for_amount(1_500_000),
            Some(Denomination::Small)
        );
        assert_eq!(
            Denomination::closest_for_amount(5_000),
            None
        );
    }

    #[test]
    fn test_optimal_denominations() {
        let result = optimal_denominations(111_000_000);

        // Should break into 1 Large + 1 Medium + 1 Small
        assert!(result.iter().any(|(d, c)| *d == Denomination::Large && *c == 1));
        assert!(result.iter().any(|(d, c)| *d == Denomination::Medium && *c == 1));
        assert!(result.iter().any(|(d, c)| *d == Denomination::Small && *c == 1));
    }

    #[test]
    fn test_count_in_amount() {
        assert_eq!(Denomination::Small.count_in_amount(5_500_000), 5);
        assert_eq!(Denomination::Small.remainder_from_amount(5_500_000), 500_000);
    }
}
