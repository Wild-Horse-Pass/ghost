use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReaperMode {
    Strict,
    Moderate,
    Monitor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReaperConfig {
    pub enabled: bool,
    pub mode: ReaperMode,

    // Strict mode: any dead bytes → reject
    pub strict_max_dead_bytes: usize,

    // Moderate mode: allow small amounts
    pub moderate_max_dead_bytes: usize,
    pub moderate_max_dead_ratio: f64,

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
    pub fn strict() -> Self {
        Self {
            enabled: true,
            mode: ReaperMode::Strict,
            strict_max_dead_bytes: 0,
            moderate_max_dead_bytes: 80,
            moderate_max_dead_ratio: 0.10,
            reject_inscription_envelope: true,
            reject_drop_stuffing: true,
            reject_fake_pubkeys: true,
            reject_annex: true,
            reject_unreachable_code: true,
            max_op_return_bytes: 83,
            min_drop_data_size: 76,
            reject_excess_witness: true,
            min_excess_witness_bytes: 500,
            reject_legacy_data_stuffing: true,
            legacy_max_push_bytes: 80,
            validate_pubkey_curve_point: true,
        }
    }

    pub fn moderate() -> Self {
        Self {
            mode: ReaperMode::Moderate,
            ..Self::strict()
        }
    }

    pub fn monitor() -> Self {
        Self {
            mode: ReaperMode::Monitor,
            ..Self::strict()
        }
    }

    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::strict()
        }
    }
}

impl Default for ReaperConfig {
    fn default() -> Self {
        Self::strict()
    }
}
