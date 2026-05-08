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
//| FILE: timelock.rs                                                                                                    |
//|======================================================================================================================|

//! Timelock tiers for Ghost Lock recovery
//!
//! Timelocks protect against key loss by allowing recovery
//! via a separate recovery key after a specified duration.

use serde::{Deserialize, Serialize};

/// Minimum recovery timelock in blocks (~1 week at 144 blocks/day)
///
/// This matches the C++ implementation's MIN_RECOVERY_TIMELOCK constant.
/// Enforcing this minimum prevents locks with dangerously short recovery windows.
pub const MIN_RECOVERY_BLOCKS: u32 = 1008;

/// Maximum allowed creation height to prevent overflow issues
///
/// This is well beyond any realistic Bitcoin block height (current ~850k).
pub const MAX_CREATION_HEIGHT: u32 = 100_000_000;

/// Timelock duration tiers for recovery
///
/// Longer timelocks provide more security against theft attempts
/// but require longer wait for legitimate recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum TimelockTier {
    /// 6 months (~26,280 blocks)
    Short,
    /// 1 year (~52,560 blocks)
    #[default]
    Standard,
    /// Maximum (~455 days, 65,535 blocks - BIP-68 limit)
    Long,
}

impl TimelockTier {
    /// Average blocks per day (assuming 10-minute blocks)
    const BLOCKS_PER_DAY: u32 = 144;

    /// BIP-68 maximum relative timelock (16-bit block count)
    const BIP68_MAX_BLOCKS: u32 = 65535;

    /// Get the timelock duration in blocks (relative block count for CSV)
    ///
    /// This is the number of blocks that must pass after UTXO confirmation
    /// before the recovery script can be used. Used with OP_CHECKSEQUENCEVERIFY.
    ///
    /// Note: All tiers are capped at BIP-68 maximum of 65,535 blocks (~455 days).
    pub fn blocks(&self) -> u32 {
        match self {
            TimelockTier::Short => Self::BLOCKS_PER_DAY * 365 / 2, // ~6 months (26,280 blocks)
            TimelockTier::Standard => Self::BLOCKS_PER_DAY * 365,  // ~1 year (52,560 blocks)
            TimelockTier::Long => Self::BIP68_MAX_BLOCKS,          // ~455 days (BIP-68 max)
        }
    }

    /// Get the timelock duration in blocks, network-aware.
    ///
    /// Production networks (mainnet/testnet/signet) use the real
    /// `blocks()` durations defined above. Regtest collapses every
    /// tier to a sub-50-block window so the recovery demo (which has
    /// to mine past the timelock) runs in seconds rather than tens
    /// of minutes.
    ///
    /// Callers that go through `from_pubkeys` or `new` should prefer
    /// this over `blocks()` so the lock script's CSV value matches
    /// the wallet's mined-blocks expectation on regtest.
    pub fn blocks_for_network(&self, network: bitcoin::Network) -> u32 {
        match network {
            bitcoin::Network::Regtest => match self {
                TimelockTier::Short => 5,
                TimelockTier::Standard => 10,
                TimelockTier::Long => 20,
            },
            _ => self.blocks(),
        }
    }

    /// Get the relative block count for CSV recovery
    ///
    /// This is an alias for `blocks()` that makes the CSV/relative nature explicit.
    /// Use this when building recovery scripts with OP_CHECKSEQUENCEVERIFY.
    #[inline]
    pub fn recovery_blocks(&self) -> u32 {
        self.blocks()
    }

    /// Get the approximate duration in days
    pub fn days(&self) -> u32 {
        self.blocks() / Self::BLOCKS_PER_DAY
    }

    /// Get the approximate duration in months
    pub fn months(&self) -> u32 {
        self.days() / 30
    }

    /// Get the tier name
    pub fn name(&self) -> &'static str {
        match self {
            TimelockTier::Short => "Short (6 months)",
            TimelockTier::Standard => "Standard (1 year)",
            TimelockTier::Long => "Long (455 days max)",
        }
    }

    /// Calculate recovery height from creation height
    pub fn recovery_height(&self, creation_height: u32) -> u32 {
        creation_height.saturating_add(self.blocks())
    }

    /// Check if recovery is available at given height
    pub fn is_recovery_available(&self, creation_height: u32, current_height: u32) -> bool {
        current_height >= self.recovery_height(creation_height)
    }

    /// Get blocks remaining until recovery
    pub fn blocks_until_recovery(&self, creation_height: u32, current_height: u32) -> u32 {
        let recovery = self.recovery_height(creation_height);
        recovery.saturating_sub(current_height)
    }

    /// Get all tiers
    pub fn all() -> &'static [TimelockTier] {
        &[
            TimelockTier::Short,
            TimelockTier::Standard,
            TimelockTier::Long,
        ]
    }
}

impl std::fmt::Display for TimelockTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_counts() {
        // Short: ~6 months, Standard: ~1 year, Long: BIP-68 max (~455 days)
        assert_eq!(TimelockTier::Short.blocks(), 26_280);
        assert_eq!(TimelockTier::Standard.blocks(), 52_560);
        assert_eq!(TimelockTier::Long.blocks(), 65_535); // BIP-68 maximum
    }

    #[test]
    fn test_days() {
        assert_eq!(TimelockTier::Short.days(), 182); // ~6 months
        assert_eq!(TimelockTier::Standard.days(), 365); // ~1 year
        assert_eq!(TimelockTier::Long.days(), 455); // BIP-68 max (~15 months)
    }

    #[test]
    fn test_recovery_height() {
        let creation = 800_000;

        assert_eq!(
            TimelockTier::Short.recovery_height(creation),
            800_000 + 26_280
        );
        assert_eq!(
            TimelockTier::Standard.recovery_height(creation),
            800_000 + 52_560
        );
        assert_eq!(
            TimelockTier::Long.recovery_height(creation),
            800_000 + 65_535 // BIP-68 maximum
        );
    }

    #[test]
    fn test_recovery_available() {
        let creation = 800_000;
        let tier = TimelockTier::Short;
        let recovery = tier.recovery_height(creation);

        assert!(!tier.is_recovery_available(creation, creation));
        assert!(!tier.is_recovery_available(creation, recovery - 1));
        assert!(tier.is_recovery_available(creation, recovery));
        assert!(tier.is_recovery_available(creation, recovery + 100));
    }

    #[test]
    fn test_blocks_until_recovery() {
        let creation = 800_000;
        let tier = TimelockTier::Standard;

        assert_eq!(tier.blocks_until_recovery(creation, creation), 52_560);
        assert_eq!(
            tier.blocks_until_recovery(creation, creation + 1000),
            51_560
        );
        assert_eq!(tier.blocks_until_recovery(creation, creation + 52_560), 0);
        assert_eq!(tier.blocks_until_recovery(creation, creation + 100_000), 0);
    }

    #[test]
    fn test_min_recovery_blocks_constant() {
        // GL-L3: Minimum recovery blocks should be 1 week (1008 blocks)
        assert_eq!(MIN_RECOVERY_BLOCKS, 1008);

        // All tiers should exceed the minimum
        for tier in TimelockTier::all() {
            assert!(
                tier.blocks() >= MIN_RECOVERY_BLOCKS,
                "Tier {:?} has {} blocks, less than minimum {}",
                tier,
                tier.blocks(),
                MIN_RECOVERY_BLOCKS
            );
        }
    }

    #[test]
    fn test_max_creation_height_constant() {
        // GL-L2: Max creation height should be reasonable (100 million)
        assert_eq!(MAX_CREATION_HEIGHT, 100_000_000);

        // Should be well above current Bitcoin block height (~850k)
        const { assert!(MAX_CREATION_HEIGHT > 1_000_000) };
    }
}
