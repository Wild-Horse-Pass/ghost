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
//| FILE: payout_validator.rs                                                                                            |
//|======================================================================================================================|

//! Payout proposal validation
//!
//! Multi-layer validation to prevent fund theft through malformed
//! or malicious payout proposals. All arithmetic uses checked operations.

use std::collections::HashSet;
use thiserror::Error;
use tracing::warn;

use ghost_common::types::{PayoutEntry, PayoutProposal, PayoutType};

/// Dust threshold in satoshis (Bitcoin Core default)
pub const DUST_THRESHOLD: u64 = 546;

/// Maximum Bitcoin supply in satoshis (21 million BTC)
pub const MAX_SUPPLY_SATS: u64 = 21_000_000 * 100_000_000;

/// Maximum block reward (subsidy + fees) we'd ever expect
/// This is a sanity check - early blocks had 50 BTC subsidy
pub const MAX_BLOCK_REWARD_SATS: u64 = 100 * 100_000_000; // 100 BTC

/// Maximum number of payout outputs
pub const MAX_PAYOUT_OUTPUTS: usize = 500;

/// Payout validation errors
#[derive(Debug, Error)]
pub enum PayoutValidationError {
    #[error("Arithmetic overflow in {0}")]
    Overflow(&'static str),

    #[error("Total distributed ({distributed} sats) exceeds available ({available} sats)")]
    ExceedsAvailable { distributed: u64, available: u64 },

    #[error("Block reward ({0} sats) exceeds maximum expected ({MAX_BLOCK_REWARD_SATS} sats)")]
    UnreasonableReward(u64),

    #[error("Payout amount ({0} sats) exceeds maximum supply")]
    ExceedsSupply(u64),

    #[error("Dust output: {0} sats is below threshold of {DUST_THRESHOLD} sats")]
    DustOutput(u64),

    #[error("Empty payout address for recipient")]
    EmptyAddress,

    #[error("Invalid output script: {0}")]
    InvalidScript(String),

    #[error("Duplicate recipient: {0}")]
    DuplicateRecipient(String),

    #[error("Too many outputs: {0} (max {MAX_PAYOUT_OUTPUTS})")]
    TooManyOutputs(usize),

    #[error("No miner payouts in proposal")]
    NoMinerPayouts,

    #[error("Proposal timestamp in future: {0}")]
    FutureTimestamp(u64),

    #[error("Proposal timestamp too old: {0}")]
    StaleTimestamp(u64),

    #[error("Round ID mismatch: proposal has {proposal}, expected {expected}")]
    RoundMismatch { proposal: u64, expected: u64 },

    #[error("Block hash mismatch")]
    BlockHashMismatch,

    #[error("Negative payout detected")]
    NegativeAmount,
}

/// Block data for validation context
#[derive(Debug, Clone)]
pub struct BlockContext {
    /// Block subsidy in satoshis
    pub subsidy: u64,
    /// Transaction fees in satoshis
    pub fees: u64,
    /// Block height
    pub height: u64,
    /// Block hash
    pub block_hash: [u8; 32],
    /// Current round ID
    pub round_id: u64,
    /// Current timestamp
    pub current_time: u64,
}

/// Validate a payout proposal thoroughly
pub fn validate_payout_proposal(
    proposal: &PayoutProposal,
    context: &BlockContext,
) -> Result<(), PayoutValidationError> {
    // 1. Basic sanity checks
    validate_basic_sanity(proposal, context)?;

    // 2. Validate amounts don't overflow and sum correctly
    validate_amounts(proposal, context)?;

    // 3. Validate all addresses
    validate_addresses(proposal)?;

    // 4. Check for duplicates
    validate_no_duplicates(proposal)?;

    // 5. Validate timestamps
    validate_timestamps(proposal, context)?;

    Ok(())
}

/// Basic sanity checks
fn validate_basic_sanity(
    proposal: &PayoutProposal,
    context: &BlockContext,
) -> Result<(), PayoutValidationError> {
    // Must have miner payouts
    if proposal.miner_payouts.is_empty() {
        return Err(PayoutValidationError::NoMinerPayouts);
    }

    // Output count limit
    let total_outputs = proposal.miner_payouts.len() + proposal.node_payouts.len();
    if total_outputs > MAX_PAYOUT_OUTPUTS {
        return Err(PayoutValidationError::TooManyOutputs(total_outputs));
    }

    // Round ID must match
    if proposal.round_id != context.round_id {
        return Err(PayoutValidationError::RoundMismatch {
            proposal: proposal.round_id,
            expected: context.round_id,
        });
    }

    // Block hash must match
    if proposal.block_hash != context.block_hash {
        return Err(PayoutValidationError::BlockHashMismatch);
    }

    // Subsidy and fees must match
    let claimed_total = proposal.subsidy
        .checked_add(proposal.tx_fees)
        .ok_or(PayoutValidationError::Overflow("claimed total"))?;

    let actual_total = context.subsidy
        .checked_add(context.fees)
        .ok_or(PayoutValidationError::Overflow("actual total"))?;

    // Allow small discrepancy due to fee estimation
    if claimed_total > actual_total {
        return Err(PayoutValidationError::ExceedsAvailable {
            distributed: claimed_total,
            available: actual_total,
        });
    }

    // Sanity check on block reward
    if actual_total > MAX_BLOCK_REWARD_SATS {
        warn!(
            actual = actual_total,
            max = MAX_BLOCK_REWARD_SATS,
            "Unusually large block reward"
        );
        return Err(PayoutValidationError::UnreasonableReward(actual_total));
    }

    Ok(())
}

/// Validate all amounts using checked arithmetic
fn validate_amounts(
    proposal: &PayoutProposal,
    context: &BlockContext,
) -> Result<(), PayoutValidationError> {
    // Calculate available funds
    let available = context.subsidy
        .checked_add(context.fees)
        .ok_or(PayoutValidationError::Overflow("available funds"))?;

    // Sum miner payouts with overflow checking
    let mut miner_total: u64 = 0;
    for payout in &proposal.miner_payouts {
        // Check individual amount
        if payout.amount > MAX_SUPPLY_SATS {
            return Err(PayoutValidationError::ExceedsSupply(payout.amount));
        }

        // Check for dust (unless zero, which will be filtered)
        if payout.amount > 0 && payout.amount < DUST_THRESHOLD {
            return Err(PayoutValidationError::DustOutput(payout.amount));
        }

        miner_total = miner_total
            .checked_add(payout.amount)
            .ok_or(PayoutValidationError::Overflow("miner payouts sum"))?;
    }

    // Sum node payouts with overflow checking
    let mut node_total: u64 = 0;
    for payout in &proposal.node_payouts {
        if payout.amount > MAX_SUPPLY_SATS {
            return Err(PayoutValidationError::ExceedsSupply(payout.amount));
        }

        if payout.amount > 0 && payout.amount < DUST_THRESHOLD {
            return Err(PayoutValidationError::DustOutput(payout.amount));
        }

        node_total = node_total
            .checked_add(payout.amount)
            .ok_or(PayoutValidationError::Overflow("node payouts sum"))?;
    }

    // Total distributed
    let total_distributed = miner_total
        .checked_add(node_total)
        .ok_or(PayoutValidationError::Overflow("miner + node sum"))?
        .checked_add(proposal.treasury_amount)
        .ok_or(PayoutValidationError::Overflow("total distribution"))?;

    // Must not exceed available
    if total_distributed > available {
        return Err(PayoutValidationError::ExceedsAvailable {
            distributed: total_distributed,
            available,
        });
    }

    Ok(())
}

/// Validate all output addresses/scripts
fn validate_addresses(proposal: &PayoutProposal) -> Result<(), PayoutValidationError> {
    for payout in proposal.miner_payouts.iter().chain(proposal.node_payouts.iter()) {
        // Skip zero-amount payouts
        if payout.amount == 0 {
            continue;
        }

        // Address must not be empty
        if payout.address.is_empty() {
            return Err(PayoutValidationError::EmptyAddress);
        }

        // Validate script format
        validate_output_script(&payout.address)?;
    }

    Ok(())
}

/// Validate a Bitcoin output script (scriptPubKey)
fn validate_output_script(script: &[u8]) -> Result<(), PayoutValidationError> {
    // Standard script types and their expected lengths
    match script.len() {
        // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        25 if script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14
            && script[23] == 0x88 && script[24] == 0xac => Ok(()),

        // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
        23 if script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 => Ok(()),

        // P2WPKH: OP_0 <20 bytes>
        22 if script[0] == 0x00 && script[1] == 0x14 => Ok(()),

        // P2WSH: OP_0 <32 bytes>
        34 if script[0] == 0x00 && script[1] == 0x20 => Ok(()),

        // P2TR: OP_1 <32 bytes>
        34 if script[0] == 0x51 && script[1] == 0x20 => Ok(()),

        // Unknown format
        _ => {
            let hex = hex::encode(script);
            let preview = if hex.len() > 40 {
                format!("{}...", &hex[..40])
            } else {
                hex
            };
            Err(PayoutValidationError::InvalidScript(preview))
        }
    }
}

/// Check for duplicate recipients
fn validate_no_duplicates(proposal: &PayoutProposal) -> Result<(), PayoutValidationError> {
    let mut seen = HashSet::new();

    for payout in proposal.miner_payouts.iter().chain(proposal.node_payouts.iter()) {
        // Skip zero amounts
        if payout.amount == 0 {
            continue;
        }

        if !seen.insert(&payout.recipient_id) {
            let id_hex = hex::encode(&payout.recipient_id[..8]);
            return Err(PayoutValidationError::DuplicateRecipient(id_hex));
        }
    }

    Ok(())
}

/// Validate proposal timestamps
fn validate_timestamps(
    proposal: &PayoutProposal,
    context: &BlockContext,
) -> Result<(), PayoutValidationError> {
    // Not too far in future (5 minutes)
    const MAX_FUTURE_SECS: u64 = 300;
    if proposal.timestamp > context.current_time + MAX_FUTURE_SECS {
        return Err(PayoutValidationError::FutureTimestamp(proposal.timestamp));
    }

    // Not too old (1 hour)
    const MAX_AGE_SECS: u64 = 3600;
    if proposal.timestamp + MAX_AGE_SECS < context.current_time {
        return Err(PayoutValidationError::StaleTimestamp(proposal.timestamp));
    }

    Ok(())
}

/// Quick pre-validation before expensive signature verification
pub fn quick_validate(proposal: &PayoutProposal) -> Result<(), PayoutValidationError> {
    // Just check structure, not amounts
    if proposal.miner_payouts.is_empty() {
        return Err(PayoutValidationError::NoMinerPayouts);
    }

    let total_outputs = proposal.miner_payouts.len() + proposal.node_payouts.len();
    if total_outputs > MAX_PAYOUT_OUTPUTS {
        return Err(PayoutValidationError::TooManyOutputs(total_outputs));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::types::NodeId;

    fn test_context() -> BlockContext {
        BlockContext {
            subsidy: 625_000_000,  // 6.25 BTC
            fees: 10_000_000,      // 0.1 BTC
            height: 800_000,
            block_hash: [1u8; 32],
            round_id: 1,
            current_time: 1700000000,
        }
    }

    fn valid_p2wpkh_script() -> Vec<u8> {
        let mut script = vec![0x00, 0x14]; // OP_0 <20 bytes>
        script.extend_from_slice(&[0u8; 20]);
        script
    }

    fn test_payout(amount: u64) -> PayoutEntry {
        PayoutEntry {
            address: valid_p2wpkh_script(),
            amount,
            recipient_id: [1u8; 32],
            payout_type: PayoutType::Mining,
        }
    }

    fn valid_proposal() -> PayoutProposal {
        PayoutProposal {
            proposal_hash: [0u8; 32],
            round_id: 1,
            block_hash: [1u8; 32],
            block_height: 800_000,
            proposer: [0u8; 32],
            miner_payouts: vec![test_payout(300_000_000)],
            node_payouts: vec![],
            treasury_amount: 6_350_000, // ~1%
            tx_fees: 10_000_000,
            subsidy: 625_000_000,
            timestamp: 1700000000,
        }
    }

    #[test]
    fn test_valid_proposal() {
        let proposal = valid_proposal();
        let context = test_context();
        assert!(validate_payout_proposal(&proposal, &context).is_ok());
    }

    #[test]
    fn test_exceeds_available() {
        let mut proposal = valid_proposal();
        proposal.miner_payouts[0].amount = 700_000_000; // More than available
        let context = test_context();

        let result = validate_payout_proposal(&proposal, &context);
        assert!(matches!(result, Err(PayoutValidationError::ExceedsAvailable { .. })));
    }

    #[test]
    fn test_dust_output() {
        let mut proposal = valid_proposal();
        proposal.miner_payouts.push(test_payout(100)); // Dust
        let context = test_context();

        let result = validate_payout_proposal(&proposal, &context);
        assert!(matches!(result, Err(PayoutValidationError::DustOutput(_))));
    }

    #[test]
    fn test_empty_address() {
        let mut proposal = valid_proposal();
        proposal.miner_payouts[0].address = vec![]; // Empty
        let context = test_context();

        let result = validate_payout_proposal(&proposal, &context);
        assert!(matches!(result, Err(PayoutValidationError::EmptyAddress)));
    }

    #[test]
    fn test_invalid_script() {
        let mut proposal = valid_proposal();
        proposal.miner_payouts[0].address = vec![0x01, 0x02, 0x03]; // Invalid
        let context = test_context();

        let result = validate_payout_proposal(&proposal, &context);
        assert!(matches!(result, Err(PayoutValidationError::InvalidScript(_))));
    }

    #[test]
    fn test_duplicate_recipient() {
        let mut proposal = valid_proposal();
        proposal.miner_payouts.push(test_payout(100_000_000)); // Same recipient_id
        let context = test_context();

        let result = validate_payout_proposal(&proposal, &context);
        assert!(matches!(result, Err(PayoutValidationError::DuplicateRecipient(_))));
    }

    #[test]
    fn test_too_many_outputs() {
        let mut proposal = valid_proposal();
        for i in 0..MAX_PAYOUT_OUTPUTS + 1 {
            let mut payout = test_payout(1000);
            payout.recipient_id = [i as u8; 32];
            proposal.miner_payouts.push(payout);
        }
        let context = test_context();

        let result = validate_payout_proposal(&proposal, &context);
        assert!(matches!(result, Err(PayoutValidationError::TooManyOutputs(_))));
    }

    #[test]
    fn test_valid_scripts() {
        // P2PKH
        let mut p2pkh = vec![0x76, 0xa9, 0x14];
        p2pkh.extend_from_slice(&[0u8; 20]);
        p2pkh.extend_from_slice(&[0x88, 0xac]);
        assert!(validate_output_script(&p2pkh).is_ok());

        // P2SH
        let mut p2sh = vec![0xa9, 0x14];
        p2sh.extend_from_slice(&[0u8; 20]);
        p2sh.push(0x87);
        assert!(validate_output_script(&p2sh).is_ok());

        // P2WPKH
        let mut p2wpkh = vec![0x00, 0x14];
        p2wpkh.extend_from_slice(&[0u8; 20]);
        assert!(validate_output_script(&p2wpkh).is_ok());

        // P2TR
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&[0u8; 32]);
        assert!(validate_output_script(&p2tr).is_ok());
    }
}
