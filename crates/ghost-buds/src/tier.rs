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
//| FILE: tier.rs                                                                                                        |
//|======================================================================================================================|

//! BUDS transaction tier definitions

use serde::{Deserialize, Serialize};
use std::fmt;

/// BUDS transaction tier
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub enum BudsTier {
    /// T0: Core financial transactions
    ///
    /// Standard Bitcoin payments:
    /// - P2PKH, P2WPKH, P2SH-P2WPKH (single-sig)
    /// - Standard P2WSH with simple spending conditions
    /// - No OP_RETURN outputs
    /// - Witness size ≤ 108 bytes per input (standard sig + pubkey)
    #[default]
    T0,

    /// T1: Extended financial transactions
    ///
    /// Complex but legitimate financial use:
    /// - Multisig (any m-of-n)
    /// - Timelocked transactions (CLTV, CSV)
    /// - HTLCs (Hash Time-Locked Contracts)
    /// - Complex scripts with multiple conditions
    /// - Witness size ≤ 400 bytes per input
    T1,

    /// T2: Data-anchoring transactions
    ///
    /// Small data commitments:
    /// - OP_RETURN ≤ 80 bytes (Lightning commitments, timestamps)
    /// - Witness size up to ~1KB per input
    /// - No inscription patterns
    T2,

    /// T3: Heavy data transactions
    ///
    /// Data-heavy or exotic use cases:
    /// - Inscriptions (Ordinals)
    /// - Large witness data (>1KB per input)
    /// - Runes protocol
    /// - BRC-20 tokens
    /// - Large OP_RETURN (>80 bytes)
    T3,
}

impl BudsTier {
    /// Get the numeric tier value (0-3)
    pub fn value(&self) -> u8 {
        match self {
            Self::T0 => 0,
            Self::T1 => 1,
            Self::T2 => 2,
            Self::T3 => 3,
        }
    }

    /// Create tier from numeric value
    pub fn from_value(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::T0),
            1 => Some(Self::T1),
            2 => Some(Self::T2),
            3 => Some(Self::T3),
            _ => None,
        }
    }

    /// Human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::T0 => "Core financial (simple payments)",
            Self::T1 => "Extended financial (multisig, timelocks)",
            Self::T2 => "Data-anchoring (small OP_RETURN)",
            Self::T3 => "Heavy data (inscriptions, large witness)",
        }
    }

    /// Check if this tier is allowed by a set of allowed tiers
    pub fn is_allowed_by(&self, allowed: &[BudsTier]) -> bool {
        allowed.contains(self)
    }
}

impl fmt::Display for BudsTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::T0 => write!(f, "T0"),
            Self::T1 => write!(f, "T1"),
            Self::T2 => write!(f, "T2"),
            Self::T3 => write!(f, "T3"),
        }
    }
}

/// Detailed classification result with reasoning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationResult {
    /// Assigned tier
    pub tier: BudsTier,
    /// Reason for classification
    pub reason: ClassificationReason,
    /// Additional details
    pub details: Option<String>,
    /// Detected features that influenced classification
    pub features: Vec<DetectedFeature>,
}

/// Reason for tier classification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClassificationReason {
    /// Standard single-sig payment
    StandardPayment,
    /// Standard multisig
    Multisig { m: u8, n: u8 },
    /// Timelock present
    Timelock,
    /// HTLC detected
    Htlc,
    /// Complex script
    ComplexScript,
    /// Small OP_RETURN (≤80 bytes)
    SmallOpReturn { size: usize },
    /// Large OP_RETURN (>80 bytes)
    LargeOpReturn { size: usize },
    /// Inscription detected
    Inscription,
    /// Large witness data
    LargeWitness { total_bytes: usize },
    /// Runes protocol
    Runes,
    /// BRC-20 token
    Brc20,
    /// Unknown/exotic pattern
    Unknown,
}

impl fmt::Display for ClassificationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StandardPayment => write!(f, "Standard payment"),
            Self::Multisig { m, n } => write!(f, "{}-of-{} multisig", m, n),
            Self::Timelock => write!(f, "Timelock"),
            Self::Htlc => write!(f, "HTLC"),
            Self::ComplexScript => write!(f, "Complex script"),
            Self::SmallOpReturn { size } => write!(f, "Small OP_RETURN ({} bytes)", size),
            Self::LargeOpReturn { size } => write!(f, "Large OP_RETURN ({} bytes)", size),
            Self::Inscription => write!(f, "Inscription"),
            Self::LargeWitness { total_bytes } => {
                write!(f, "Large witness ({} bytes)", total_bytes)
            }
            Self::Runes => write!(f, "Runes protocol"),
            Self::Brc20 => write!(f, "BRC-20 token"),
            Self::Unknown => write!(f, "Unknown pattern"),
        }
    }
}

/// Detected feature in a transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectedFeature {
    /// P2PKH output
    P2pkh,
    /// P2WPKH output
    P2wpkh,
    /// P2SH output
    P2sh,
    /// P2WSH output
    P2wsh,
    /// P2TR (taproot) output
    P2tr,
    /// OP_RETURN output
    OpReturn { size: usize },
    /// Multisig script
    Multisig { m: u8, n: u8 },
    /// CLTV timelock
    Cltv,
    /// CSV timelock
    Csv,
    /// HTLC pattern
    Htlc,
    /// Inscription envelope
    InscriptionEnvelope,
    /// Runes runestone
    RunesRunestone,
    /// BRC-20 pattern
    Brc20Pattern,
    /// Large witness
    LargeWitness { bytes: usize },
}

impl fmt::Display for DetectedFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::P2pkh => write!(f, "P2PKH"),
            Self::P2wpkh => write!(f, "P2WPKH"),
            Self::P2sh => write!(f, "P2SH"),
            Self::P2wsh => write!(f, "P2WSH"),
            Self::P2tr => write!(f, "P2TR"),
            Self::OpReturn { size } => write!(f, "OP_RETURN({} bytes)", size),
            Self::Multisig { m, n } => write!(f, "Multisig({}/{})", m, n),
            Self::Cltv => write!(f, "CLTV"),
            Self::Csv => write!(f, "CSV"),
            Self::Htlc => write!(f, "HTLC"),
            Self::InscriptionEnvelope => write!(f, "Inscription"),
            Self::RunesRunestone => write!(f, "Runes"),
            Self::Brc20Pattern => write!(f, "BRC-20"),
            Self::LargeWitness { bytes } => write!(f, "LargeWitness({} bytes)", bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_ordering() {
        assert!(BudsTier::T0 < BudsTier::T1);
        assert!(BudsTier::T1 < BudsTier::T2);
        assert!(BudsTier::T2 < BudsTier::T3);
    }

    #[test]
    fn test_tier_value() {
        assert_eq!(BudsTier::T0.value(), 0);
        assert_eq!(BudsTier::T3.value(), 3);
    }

    #[test]
    fn test_tier_from_value() {
        assert_eq!(BudsTier::from_value(0), Some(BudsTier::T0));
        assert_eq!(BudsTier::from_value(4), None);
    }

    #[test]
    fn test_is_allowed_by() {
        let allowed = vec![BudsTier::T0, BudsTier::T1];
        assert!(BudsTier::T0.is_allowed_by(&allowed));
        assert!(BudsTier::T1.is_allowed_by(&allowed));
        assert!(!BudsTier::T2.is_allowed_by(&allowed));
    }
}
