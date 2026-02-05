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
//| FILE: config.rs                                                                                                      |
//|======================================================================================================================|

//! Scan configuration for Silent Payment v2
//!
//! Provides user-configurable scanning parameters for payment detection.

use serde::{Deserialize, Serialize};

use crate::{DEFAULT_MAX_K, MAX_MAX_K};

/// Configuration for Silent Payment scanning
///
/// Controls the maximum k value to scan when detecting payments.
/// Higher values find more payments but take longer to scan.
///
/// # Examples
///
/// ```
/// use ghost_keys::ScanConfig;
///
/// // Default config (max_k = 10)
/// let config = ScanConfig::default();
/// assert_eq!(config.max_k(), 10);
///
/// // Custom config for recovery scanning
/// let recovery = ScanConfig::new(1000);
/// assert_eq!(recovery.max_k(), 1000);
///
/// // Values are clamped to valid range
/// let clamped = ScanConfig::new(100_000);
/// assert_eq!(clamped.max_k(), 10_000); // Clamped to MAX_MAX_K
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanConfig {
    max_k: u32,
}

impl ScanConfig {
    /// Create a new scan config with the specified max_k
    ///
    /// Values are clamped to the valid range [1, MAX_MAX_K].
    pub fn new(max_k: u32) -> Self {
        Self {
            max_k: max_k.clamp(1, MAX_MAX_K),
        }
    }

    /// Create a recovery scan config with max_k = 1000
    ///
    /// Use this when scanning for potentially missed payments.
    pub fn recovery() -> Self {
        Self::new(1000)
    }

    /// Create a deep recovery scan config with max_k = MAX_MAX_K
    ///
    /// Use this for thorough recovery scanning (slower).
    pub fn deep_recovery() -> Self {
        Self::new(MAX_MAX_K)
    }

    /// Get the maximum k value to scan
    pub fn max_k(&self) -> u32 {
        self.max_k
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_K)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = ScanConfig::default();
        assert_eq!(config.max_k(), DEFAULT_MAX_K);
    }

    #[test]
    fn test_config_custom() {
        let config = ScanConfig::new(100);
        assert_eq!(config.max_k(), 100);
    }

    #[test]
    fn test_config_clamp_min() {
        let config = ScanConfig::new(0);
        assert_eq!(config.max_k(), 1);
    }

    #[test]
    fn test_config_clamp_max() {
        let config = ScanConfig::new(100_000);
        assert_eq!(config.max_k(), MAX_MAX_K);
    }

    #[test]
    fn test_config_recovery() {
        let config = ScanConfig::recovery();
        assert_eq!(config.max_k(), 1000);
    }

    #[test]
    fn test_config_deep_recovery() {
        let config = ScanConfig::deep_recovery();
        assert_eq!(config.max_k(), MAX_MAX_K);
    }
}
