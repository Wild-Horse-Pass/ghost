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
//| FILE: detector.rs                                                                                                    |
//|======================================================================================================================|

//! Transaction pattern detection
//!
//! Detects specific patterns in transactions like inscriptions, Runes, HTLCs, etc.

use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::Instruction;
use bitcoin::Script;

use crate::tier::DetectedFeature;
use ghost_common::constants::MAX_OP_RETURN_SMALL_BYTES;

/// Inscription envelope magic bytes
const INSCRIPTION_ENVELOPE_START: [u8; 3] = [0x00, 0x63, 0x03]; // OP_FALSE OP_IF OP_PUSHBYTES_3
const INSCRIPTION_CONTENT_TYPE: &[u8] = b"ord";

/// Runes protocol magic (OP_RETURN OP_13)
const RUNES_MAGIC: [u8; 2] = [0x6a, 0x5d]; // OP_RETURN OP_13

/// BRC-20 JSON pattern
const BRC20_PATTERN: &[u8] = b"\"p\":\"brc-20\"";

/// Pattern detector for transaction analysis
#[derive(Debug, Default)]
pub struct PatternDetector {
    /// Detected features
    pub features: Vec<DetectedFeature>,
}

impl PatternDetector {
    /// Create a new pattern detector
    pub fn new() -> Self {
        Self::default()
    }

    /// Detect patterns in a script
    pub fn analyze_script(&mut self, script: &Script) -> Vec<DetectedFeature> {
        let mut features = Vec::new();

        // Check output type
        if script.is_p2pkh() {
            features.push(DetectedFeature::P2pkh);
        } else if script.is_p2wpkh() {
            features.push(DetectedFeature::P2wpkh);
        } else if script.is_p2sh() {
            features.push(DetectedFeature::P2sh);
        } else if script.is_p2wsh() {
            features.push(DetectedFeature::P2wsh);
        } else if script.is_p2tr() {
            features.push(DetectedFeature::P2tr);
        } else if script.is_op_return() {
            let data_size = script.len().saturating_sub(2); // Minus OP_RETURN + push
            features.push(DetectedFeature::OpReturn { size: data_size });
        }

        // Check for multisig
        if let Some((m, n)) = detect_multisig(script) {
            features.push(DetectedFeature::Multisig { m, n });
        }

        // Check for timelocks
        if contains_cltv(script) {
            features.push(DetectedFeature::Cltv);
        }
        if contains_csv(script) {
            features.push(DetectedFeature::Csv);
        }

        // Check for HTLC pattern
        if is_htlc_pattern(script) {
            features.push(DetectedFeature::Htlc);
        }

        // Check for Runes
        if is_runes_script(script) {
            features.push(DetectedFeature::RunesRunestone);
        }

        features
    }

    /// Detect patterns in witness data
    pub fn analyze_witness(&mut self, witness: &[Vec<u8>]) -> Vec<DetectedFeature> {
        let mut features = Vec::new();

        // Calculate total witness size
        let total_size: usize = witness.iter().map(|w| w.len()).sum();
        if total_size > 400 {
            features.push(DetectedFeature::LargeWitness { bytes: total_size });
        }

        // Check for inscription envelope in witness
        for item in witness {
            if is_inscription_envelope(item) {
                features.push(DetectedFeature::InscriptionEnvelope);
                break;
            }

            if contains_brc20_pattern(item) {
                features.push(DetectedFeature::Brc20Pattern);
            }
        }

        features
    }

    /// Analyze a full transaction's scripts and witnesses
    pub fn analyze_full(
        &mut self,
        output_scripts: &[&Script],
        input_witnesses: &[&[Vec<u8>]],
    ) -> Vec<DetectedFeature> {
        let mut all_features = Vec::new();

        for script in output_scripts {
            all_features.extend(self.analyze_script(script));
        }

        for witness in input_witnesses {
            all_features.extend(self.analyze_witness(witness));
        }

        // Deduplicate features
        all_features.sort_by_key(|f| format!("{:?}", f));
        all_features.dedup_by_key(|f| format!("{:?}", f));

        self.features = all_features.clone();
        all_features
    }
}

/// Detect multisig pattern in script
pub fn detect_multisig(script: &Script) -> Option<(u8, u8)> {
    let bytes = script.as_bytes();

    // Standard multisig: OP_M <pubkey1> ... <pubkeyN> OP_N OP_CHECKMULTISIG
    if bytes.len() < 3 {
        return None;
    }

    let last_byte = bytes[bytes.len() - 1];
    if last_byte != OP_CHECKMULTISIG.to_u8() {
        return None;
    }

    // Get M (first byte should be OP_1 through OP_16)
    let first_byte = bytes[0];
    let m = if first_byte >= OP_PUSHNUM_1.to_u8() && first_byte <= OP_PUSHNUM_16.to_u8() {
        first_byte - OP_PUSHNUM_1.to_u8() + 1
    } else {
        return None;
    };

    // Get N (byte before OP_CHECKMULTISIG)
    let n_byte = bytes[bytes.len() - 2];
    let n = if n_byte >= OP_PUSHNUM_1.to_u8() && n_byte <= OP_PUSHNUM_16.to_u8() {
        n_byte - OP_PUSHNUM_1.to_u8() + 1
    } else {
        return None;
    };

    if m <= n && n <= 16 {
        Some((m, n))
    } else {
        None
    }
}

/// Check if script contains CHECKLOCKTIMEVERIFY
pub fn contains_cltv(script: &Script) -> bool {
    for instruction in script.instructions() {
        if let Ok(Instruction::Op(op)) = instruction {
            if op == OP_CLTV {
                return true;
            }
        }
    }
    false
}

/// Check if script contains CHECKSEQUENCEVERIFY
pub fn contains_csv(script: &Script) -> bool {
    for instruction in script.instructions() {
        if let Ok(Instruction::Op(op)) = instruction {
            if op == OP_CSV {
                return true;
            }
        }
    }
    false
}

/// Check if script appears to be an HTLC pattern
pub fn is_htlc_pattern(script: &Script) -> bool {
    let mut has_hash_check = false;
    let mut has_timelock = false;
    let mut has_if = false;

    for instruction in script.instructions() {
        if let Ok(Instruction::Op(op)) = instruction {
            match op {
                OP_HASH160 | OP_SHA256 | OP_HASH256 => has_hash_check = true,
                OP_CLTV | OP_CSV => has_timelock = true,
                OP_IF | OP_NOTIF => has_if = true,
                _ => {}
            }
        }
    }

    // HTLC typically has: hash check + timelock + conditional branching
    has_hash_check && has_timelock && has_if
}

/// Check if script is a Runes runestone
pub fn is_runes_script(script: &Script) -> bool {
    let bytes = script.as_bytes();

    // Runes use OP_RETURN OP_13 prefix
    if bytes.len() >= 2 {
        bytes[0] == RUNES_MAGIC[0] && bytes[1] == RUNES_MAGIC[1]
    } else {
        false
    }
}

/// Check if witness data contains an inscription envelope
pub fn is_inscription_envelope(data: &[u8]) -> bool {
    // Look for inscription envelope pattern: OP_FALSE OP_IF "ord" ...
    if data.len() < 10 {
        return false;
    }

    // Check for envelope start sequence
    if data.starts_with(&INSCRIPTION_ENVELOPE_START) {
        // Check for "ord" content type marker
        if let Some(pos) = data
            .windows(INSCRIPTION_CONTENT_TYPE.len())
            .position(|w| w == INSCRIPTION_CONTENT_TYPE)
        {
            return pos < 20; // Should be near the start
        }
    }

    // Also check for the common patterns
    for window in data.windows(3) {
        if window == INSCRIPTION_CONTENT_TYPE {
            return true;
        }
    }

    false
}

/// Check if data contains BRC-20 JSON pattern
pub fn contains_brc20_pattern(data: &[u8]) -> bool {
    data.windows(BRC20_PATTERN.len())
        .any(|w| w == BRC20_PATTERN)
}

/// Calculate the "data weight" of a transaction
///
/// Higher values indicate more data-heavy transactions
pub fn calculate_data_weight(
    witness_sizes: &[usize],
    op_return_sizes: &[usize],
    has_inscription: bool,
) -> usize {
    let witness_weight: usize = witness_sizes.iter().sum();
    let op_return_weight: usize = op_return_sizes.iter().sum();

    let mut total = witness_weight + (op_return_weight * 4); // OP_RETURN weighted higher

    if has_inscription {
        total += 10000; // Heavy penalty for inscriptions
    }

    total
}

/// Check if an OP_RETURN is "small" (≤80 bytes, allowed for Lightning/commitments)
pub fn is_small_op_return(script: &Script) -> bool {
    if !script.is_op_return() {
        return false;
    }

    // Calculate actual data size (script length minus opcodes)
    let data_size = script.len().saturating_sub(2);
    data_size <= MAX_OP_RETURN_SMALL_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::blockdata::script::Builder;
    use bitcoin::blockdata::opcodes;

    #[test]
    fn test_detect_p2wpkh() {
        // Standard P2WPKH: OP_0 <20-byte-pubkey-hash>
        // Build manually since WPubkeyHash::all_zeros() may not be available
        let script = Builder::new()
            .push_int(0)
            .push_slice([0u8; 20])
            .into_script();

        let mut detector = PatternDetector::new();
        let features = detector.analyze_script(&script);

        assert!(features.contains(&DetectedFeature::P2wpkh));
    }

    #[test]
    fn test_detect_op_return() {
        // OP_RETURN with small data
        let script = Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_slice([1, 2, 3, 4, 5])
            .into_script();

        let mut detector = PatternDetector::new();
        let features = detector.analyze_script(&script);

        assert!(features
            .iter()
            .any(|f| matches!(f, DetectedFeature::OpReturn { size } if *size <= 80)));
    }

    #[test]
    fn test_is_small_op_return() {
        let small = Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_slice([0u8; 40])
            .into_script();

        // For "large" OP_RETURN (>80 bytes data), push multiple chunks
        // 50 + 50 = 100 bytes data, which exceeds 80-byte threshold
        let large = Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_slice([0u8; 50])
            .push_slice([0u8; 50])
            .into_script();

        assert!(is_small_op_return(&small));
        assert!(!is_small_op_return(&large));
    }

    #[test]
    fn test_large_witness_detection() {
        let witness = vec![vec![0u8; 500]]; // 500 bytes

        let mut detector = PatternDetector::new();
        let features = detector.analyze_witness(&witness);

        assert!(features
            .iter()
            .any(|f| matches!(f, DetectedFeature::LargeWitness { .. })));
    }

    #[test]
    fn test_brc20_pattern() {
        let data = br#"{"p":"brc-20","op":"transfer","tick":"ordi","amt":"100"}"#;
        assert!(contains_brc20_pattern(data));

        let normal_data = b"just some random data";
        assert!(!contains_brc20_pattern(normal_data));
    }
}
