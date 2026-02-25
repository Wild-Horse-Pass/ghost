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

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReaperConfig {
    pub enabled: bool,

    // Per-vector toggles
    pub reject_inscription_envelope: bool,
    pub reject_drop_stuffing: bool,
    pub reject_fake_pubkeys: bool,
    pub reject_annex: bool,
    pub reject_unreachable_code: bool,

    // Output thresholds
    pub max_op_return_bytes: usize,

    // Detection thresholds
    pub min_drop_data_size: usize,

    // Computational validity
    pub reject_excess_witness: bool,
    pub min_excess_witness_bytes: usize,

    // Legacy analysis
    pub reject_legacy_data_stuffing: bool,
    pub legacy_max_push_bytes: usize,

    // EC point validation
    pub validate_pubkey_curve_point: bool,
}

impl ReaperConfig {
    /// Validate configuration invariants.
    ///
    /// Returns an error string describing the first violated invariant, or Ok(()).
    /// Call this after deserializing from config files to catch misconfigurations
    /// before they cause runtime failures.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_op_return_bytes == 0 {
            return Err("max_op_return_bytes must be > 0".to_string());
        }
        if self.min_drop_data_size == 0 {
            return Err("min_drop_data_size must be > 0".to_string());
        }
        if self.min_excess_witness_bytes == 0 && self.reject_excess_witness {
            return Err(
                "min_excess_witness_bytes must be > 0 when reject_excess_witness is enabled"
                    .to_string(),
            );
        }
        if self.legacy_max_push_bytes == 0 && self.reject_legacy_data_stuffing {
            return Err(
                "legacy_max_push_bytes must be > 0 when reject_legacy_data_stuffing is enabled"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }
}

impl Default for ReaperConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            reject_inscription_envelope: true,
            reject_drop_stuffing: true,
            reject_fake_pubkeys: true,
            reject_annex: true,
            reject_unreachable_code: true,
            max_op_return_bytes: 82,
            min_drop_data_size: 76,
            reject_excess_witness: true,
            min_excess_witness_bytes: 500,
            reject_legacy_data_stuffing: true,
            legacy_max_push_bytes: 80,
            validate_pubkey_curve_point: true,
        }
    }
}
