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
//!
//! Fee model (v2): Fixed service fee per denomination + at-cost mining.
//! Jump sessions (key rotation) charge mining cost only (0 service fee).

use serde::{Deserialize, Serialize};

/// Standard Wraith mixing denominations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WraithDenomination {
    /// 100,000 sats output (0.001 BTC) — raised from 10K to cover mining overhead
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
            WraithDenomination::Micro => 100_000,
            WraithDenomination::Small => 1_000_000,
            WraithDenomination::Medium => 10_000_000,
            WraithDenomination::Large => 100_000_000,
        }
    }

    /// Get the fixed service fee for this denomination (charged on Mix sessions only)
    ///
    /// Jump sessions (key rotation) have 0 service fee — mining cost only.
    pub fn service_fee(&self) -> u64 {
        match self {
            WraithDenomination::Micro => 500,
            WraithDenomination::Small => 2_000,
            WraithDenomination::Medium => 5_000,
            WraithDenomination::Large => 10_000,
        }
    }

    /// Get the minimum required input (denomination output only, excludes mining cost)
    ///
    /// Service fees are now charged at the L2 layer (shielded note = denomination - service_fee),
    /// not at L1 input time. Mining cost is handled separately by the executor's fee estimation.
    pub fn min_input_sats(&self) -> u64 {
        self.output_sats()
    }

    /// Get the intermediate UTXO size (output / outputs_per_participant)
    ///
    /// Privacy: All intermediates MUST be identical to prevent output clustering.
    /// Variable amounts would create a correlation vector allowing chain analysis
    /// to link split outputs by matching their unique sizes.
    ///
    /// M-23: Asserts exact divisibility — a remainder would create non-uniform
    /// intermediate sizes, breaking the privacy invariant.
    pub fn intermediate_sats(&self, outputs_per_participant: usize) -> u64 {
        let output = self.output_sats();
        let opp = outputs_per_participant as u64;
        assert_eq!(
            output % opp,
            0,
            "M-23: denomination {} sats not evenly divisible by OPP {}",
            output,
            opp
        );
        output / opp
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
            100_000 => Some(WraithDenomination::Micro),
            1_000_000 => Some(WraithDenomination::Small),
            10_000_000 => Some(WraithDenomination::Medium),
            100_000_000 => Some(WraithDenomination::Large),
            _ => None,
        }
    }

    /// Find the largest denomination that fits in an amount
    pub fn largest_fitting(sats: u64) -> Option<Self> {
        if sats >= WraithDenomination::Large.min_input_sats() {
            Some(WraithDenomination::Large)
        } else if sats >= WraithDenomination::Medium.min_input_sats() {
            Some(WraithDenomination::Medium)
        } else if sats >= WraithDenomination::Small.min_input_sats() {
            Some(WraithDenomination::Small)
        } else if sats >= WraithDenomination::Micro.min_input_sats() {
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
        assert_eq!(WraithDenomination::Micro.output_sats(), 100_000);
        assert_eq!(WraithDenomination::Small.output_sats(), 1_000_000);
        assert_eq!(WraithDenomination::Medium.output_sats(), 10_000_000);
        assert_eq!(WraithDenomination::Large.output_sats(), 100_000_000);
    }

    #[test]
    fn test_service_fees() {
        assert_eq!(WraithDenomination::Micro.service_fee(), 500);
        assert_eq!(WraithDenomination::Small.service_fee(), 2_000);
        assert_eq!(WraithDenomination::Medium.service_fee(), 5_000);
        assert_eq!(WraithDenomination::Large.service_fee(), 10_000);
    }

    #[test]
    fn test_min_input_sats() {
        // min_input = output only (service fees charged at L2 layer)
        assert_eq!(WraithDenomination::Micro.min_input_sats(), 100_000);
        assert_eq!(WraithDenomination::Small.min_input_sats(), 1_000_000);
        assert_eq!(WraithDenomination::Medium.min_input_sats(), 10_000_000);
        assert_eq!(WraithDenomination::Large.min_input_sats(), 100_000_000);
    }

    #[test]
    fn test_intermediates() {
        // Each OPP value must divide all denominations evenly (M-23)
        for opp in [2, 4, 5, 8, 10] {
            for denom in WraithDenomination::all() {
                let intermediate = denom.intermediate_sats(opp);
                assert_eq!(
                    intermediate * opp as u64,
                    denom.output_sats(),
                    "OPP {} doesn't divide {:?} evenly",
                    opp,
                    denom
                );
            }
        }
    }

    #[test]
    fn test_intermediate_specific_values() {
        // Micro (100K) / 2 = 50K
        assert_eq!(WraithDenomination::Micro.intermediate_sats(2), 50_000);
        // Small (1M) / 4 = 250K
        assert_eq!(WraithDenomination::Small.intermediate_sats(4), 250_000);
        // Medium (10M) / 5 = 2M
        assert_eq!(WraithDenomination::Medium.intermediate_sats(5), 2_000_000);
        // Large (100M) / 8 = 12.5M
        assert_eq!(WraithDenomination::Large.intermediate_sats(8), 12_500_000);
    }

    #[test]
    fn test_from_output_sats() {
        assert_eq!(
            WraithDenomination::from_output_sats(100_000),
            Some(WraithDenomination::Micro)
        );
        assert_eq!(
            WraithDenomination::from_output_sats(1_000_000),
            Some(WraithDenomination::Small)
        );
        assert_eq!(WraithDenomination::from_output_sats(500_000), None);
        // Old Micro value should not match
        assert_eq!(WraithDenomination::from_output_sats(10_000), None);
    }

    #[test]
    fn test_largest_fitting() {
        // Below Micro min_input (100,000) → None
        assert_eq!(WraithDenomination::largest_fitting(99_999), None);
        // At Micro min_input → Micro
        assert_eq!(
            WraithDenomination::largest_fitting(100_000),
            Some(WraithDenomination::Micro)
        );
        // At Small min_input (1,000,000) → Small
        assert_eq!(
            WraithDenomination::largest_fitting(1_000_000),
            Some(WraithDenomination::Small)
        );
        // 2 BTC should fit Large (100,000,000)
        assert_eq!(
            WraithDenomination::largest_fitting(200_000_000),
            Some(WraithDenomination::Large)
        );
    }
}
