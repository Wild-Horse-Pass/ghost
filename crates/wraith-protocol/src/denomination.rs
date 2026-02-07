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

//! Wraith mixing denominations
//!
//! Standard denominations ensure all participants in a mix are
//! indistinguishable from each other.

use serde::{Deserialize, Serialize};

use crate::FEE_PERCENTAGE;
use crate::SPLIT_RATIO;

/// Standard Wraith mixing denominations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WraithDenomination {
    /// 10,000 sats output (micro)
    Micro,
    /// 1,000,000 sats output (0.01 BTC)
    Small,
    /// 10,000,000 sats output (0.1 BTC)
    Medium,
    /// 100,000,000 sats output (1 BTC)
    Large,
}

impl WraithDenomination {
    /// Get the output amount in satoshis (what you receive)
    pub fn output_sats(&self) -> u64 {
        match self {
            WraithDenomination::Micro => 10_000,
            WraithDenomination::Small => 1_000_000,
            WraithDenomination::Medium => 10_000_000,
            WraithDenomination::Large => 100_000_000,
        }
    }

    /// Get the fee amount in satoshis (1% of output)
    pub fn fee_sats(&self) -> u64 {
        (self.output_sats() as f64 * FEE_PERCENTAGE) as u64
    }

    /// Get the required input amount in satoshis (output + fee)
    pub fn input_sats(&self) -> u64 {
        self.output_sats() + self.fee_sats()
    }

    /// Get the base intermediate UTXO size (output / SPLIT_RATIO)
    ///
    /// This returns the fixed base amount. For privacy-enhanced intermediate amounts
    /// with random offsets, use `intermediate_sats_randomized()`.
    pub fn intermediate_sats(&self) -> u64 {
        self.output_sats() / SPLIT_RATIO as u64
    }

    /// Get intermediate UTXO size with random offset (3.17 privacy fix)
    ///
    /// Adds a random offset of ±5% to the intermediate amount to prevent
    /// amount fingerprinting. This makes it harder for chain analysis to
    /// correlate intermediate UTXOs based on their exact values.
    ///
    /// M-5 FIX: Uses rejection sampling instead of modulo to eliminate bias.
    ///
    /// # Returns
    /// The base intermediate amount plus a random offset in range [-5%, +5%]
    pub fn intermediate_sats_randomized(&self) -> u64 {
        let base = self.intermediate_sats();

        // 5% variance range (±5% of base)
        let variance_range = base / 20; // 5% = 1/20

        if variance_range == 0 {
            return base; // Too small for meaningful variance
        }

        // Total range is [0, 2 * variance_range] inclusive
        let range_size = 2 * variance_range + 1;

        // M-5 FIX: Use rejection sampling to eliminate modulo bias
        // We need an unbiased random number in [0, range_size)
        // Compute the largest multiple of range_size that fits in u64
        let max_valid = u64::MAX - (u64::MAX % range_size);

        let offset_magnitude = loop {
            let mut rng_bytes = [0u8; 8];
            if getrandom::getrandom(&mut rng_bytes).is_err() {
                return base; // Fallback to base on RNG failure
            }

            let random_value = u64::from_le_bytes(rng_bytes);

            // Reject values that would cause bias
            if random_value < max_valid {
                break random_value % range_size;
            }
            // Otherwise, retry with fresh random bytes
        };

        // Apply offset: base + offset - variance_range gives us [-variance_range, +variance_range]
        // Use saturating arithmetic to prevent underflow
        base.saturating_add(offset_magnitude)
            .saturating_sub(variance_range)
    }

    /// Get the output amount in BTC
    pub fn output_btc(&self) -> f64 {
        self.output_sats() as f64 / 100_000_000.0
    }

    /// Get the name of this denomination
    pub fn name(&self) -> &'static str {
        match self {
            WraithDenomination::Micro => "Micro",
            WraithDenomination::Small => "Small",
            WraithDenomination::Medium => "Medium",
            WraithDenomination::Large => "Large",
        }
    }

    /// 4.9 SECURITY: Get distinctive 2-char code for protocol messages
    ///
    /// Uses 2-character codes to prevent ambiguity in protocol messages and logs.
    /// Single-char codes (M, S, M, L) would have collision between Micro and Medium.
    pub fn short_code(&self) -> &'static str {
        match self {
            WraithDenomination::Micro => "MI",  // Micro
            WraithDenomination::Small => "SM",  // Small
            WraithDenomination::Medium => "MD", // Medium
            WraithDenomination::Large => "LG",  // Large
        }
    }

    /// 4.9: Parse denomination from 2-char short code
    pub fn from_short_code(code: &str) -> Option<Self> {
        match code {
            "MI" => Some(WraithDenomination::Micro),
            "SM" => Some(WraithDenomination::Small),
            "MD" => Some(WraithDenomination::Medium),
            "LG" => Some(WraithDenomination::Large),
            _ => None,
        }
    }

    /// Get all denominations
    pub fn all() -> &'static [WraithDenomination] {
        &[
            WraithDenomination::Micro,
            WraithDenomination::Small,
            WraithDenomination::Medium,
            WraithDenomination::Large,
        ]
    }

    /// Find denomination by output amount
    pub fn from_output_sats(sats: u64) -> Option<Self> {
        match sats {
            10_000 => Some(WraithDenomination::Micro),
            1_000_000 => Some(WraithDenomination::Small),
            10_000_000 => Some(WraithDenomination::Medium),
            100_000_000 => Some(WraithDenomination::Large),
            _ => None,
        }
    }

    /// Find the largest denomination that fits in an amount
    pub fn largest_fitting(sats: u64) -> Option<Self> {
        if sats >= WraithDenomination::Large.input_sats() {
            Some(WraithDenomination::Large)
        } else if sats >= WraithDenomination::Medium.input_sats() {
            Some(WraithDenomination::Medium)
        } else if sats >= WraithDenomination::Small.input_sats() {
            Some(WraithDenomination::Small)
        } else if sats >= WraithDenomination::Micro.input_sats() {
            Some(WraithDenomination::Micro)
        } else {
            None
        }
    }
}

impl std::fmt::Display for WraithDenomination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({:.8} BTC)", self.name(), self.output_btc())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_denomination_values() {
        assert_eq!(WraithDenomination::Micro.output_sats(), 10_000);
        assert_eq!(WraithDenomination::Small.output_sats(), 1_000_000);
        assert_eq!(WraithDenomination::Medium.output_sats(), 10_000_000);
        assert_eq!(WraithDenomination::Large.output_sats(), 100_000_000);
    }

    #[test]
    fn test_fees() {
        // 1% fee
        assert_eq!(WraithDenomination::Small.fee_sats(), 10_000);
        assert_eq!(WraithDenomination::Small.input_sats(), 1_010_000);
    }

    #[test]
    fn test_intermediates() {
        // 10x split
        assert_eq!(WraithDenomination::Small.intermediate_sats(), 100_000);
    }

    #[test]
    fn test_from_output_sats() {
        assert_eq!(
            WraithDenomination::from_output_sats(1_000_000),
            Some(WraithDenomination::Small)
        );
        assert_eq!(WraithDenomination::from_output_sats(500_000), None);
    }
}
