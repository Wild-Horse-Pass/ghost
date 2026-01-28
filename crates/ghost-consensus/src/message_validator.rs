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
//| FILE: message_validator.rs                                                                                           |
//|======================================================================================================================|

//! Message validation for P2P protocol
//!
//! Validates message envelopes BEFORE full deserialization to prevent
//! attacks via malformed messages. All external data is untrusted.

use thiserror::Error;
use tracing::warn;

use ghost_common::identity::verify_signature;
use ghost_common::types::NodeId;

use crate::message::{MessageEnvelope, MessageType};

/// Minimum envelope size: version(1) + type(1) + sender(32) + seq(8) + sig(64) + min_payload(1)
pub const MIN_ENVELOPE_SIZE: usize = 107;

/// Maximum envelope size (1MB)
pub const MAX_ENVELOPE_SIZE: usize = 1_000_000;

/// Maximum payload sizes by message type
pub const MAX_SHARE_PROOF_SIZE: usize = 10_000;
pub const MAX_BLOCK_FOUND_SIZE: usize = 100_000;
pub const MAX_VOTE_SIZE: usize = 1_000;
pub const MAX_HEALTH_PING_SIZE: usize = 2_000;
pub const MAX_DISCOVERY_SIZE: usize = 50_000;
pub const MAX_PAYOUT_PROPOSAL_SIZE: usize = 500_000;
pub const MAX_ELDER_UPDATE_SIZE: usize = 10_000;

/// Message validation errors
#[derive(Debug, Clone, Error)]
pub enum MessageValidationError {
    #[error("Message too small: {0} bytes (min {MIN_ENVELOPE_SIZE})")]
    TooSmall(usize),

    #[error("Message too large: {0} bytes (max {MAX_ENVELOPE_SIZE})")]
    TooLarge(usize),

    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("Invalid message type: {0}")]
    InvalidType(u8),

    #[error("Payload too large for {0:?}: {1} bytes (max {2})")]
    PayloadTooLarge(MessageType, usize, usize),

    #[error("Invalid signature from {0}")]
    InvalidSignature(String),

    #[error("Sender node ID is all zeros")]
    ZeroSender,

    #[error("Sequence number is zero")]
    ZeroSequence,

    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),
}

/// Validate raw message bytes before any deserialization
///
/// This performs quick checks that can reject obviously malformed
/// messages without expensive parsing.
pub fn validate_envelope_header(data: &[u8]) -> Result<(), MessageValidationError> {
    // Size bounds
    if data.len() < MIN_ENVELOPE_SIZE {
        return Err(MessageValidationError::TooSmall(data.len()));
    }

    if data.len() > MAX_ENVELOPE_SIZE {
        return Err(MessageValidationError::TooLarge(data.len()));
    }

    // Version check (first byte)
    let version = data[0];
    if version != 1 {
        return Err(MessageValidationError::UnsupportedVersion(version));
    }

    // Message type check (second byte)
    let msg_type_byte = data[1];
    if msg_type_byte > 7 {
        // We have 8 message types (0-7)
        return Err(MessageValidationError::InvalidType(msg_type_byte));
    }

    Ok(())
}

/// Get the maximum allowed payload size for a message type
pub fn max_payload_size(msg_type: MessageType) -> usize {
    match msg_type {
        MessageType::ShareProof => MAX_SHARE_PROOF_SIZE,
        MessageType::ShareConvergence => MAX_SHARE_PROOF_SIZE,
        MessageType::BlockFound => MAX_BLOCK_FOUND_SIZE,
        MessageType::Vote => MAX_VOTE_SIZE,
        MessageType::HealthPing => MAX_HEALTH_PING_SIZE,
        MessageType::Discovery => MAX_DISCOVERY_SIZE,
        MessageType::PayoutProposal => MAX_PAYOUT_PROPOSAL_SIZE,
        MessageType::ElderUpdate => MAX_ELDER_UPDATE_SIZE,
    }
}

/// Validate payload size against message type limits
pub fn validate_payload_size(msg_type: MessageType, payload_size: usize) -> Result<(), MessageValidationError> {
    let max_size = max_payload_size(msg_type);
    if payload_size > max_size {
        return Err(MessageValidationError::PayloadTooLarge(
            msg_type,
            payload_size,
            max_size,
        ));
    }
    Ok(())
}

/// Validate a deserialized envelope
pub fn validate_envelope(envelope: &MessageEnvelope) -> Result<(), MessageValidationError> {
    // Check sender is not all zeros
    if envelope.sender == [0u8; 32] {
        return Err(MessageValidationError::ZeroSender);
    }

    // Check sequence is not zero (indicates uninitialized)
    if envelope.sequence == 0 {
        return Err(MessageValidationError::ZeroSequence);
    }

    // Validate payload size for message type
    validate_payload_size(envelope.msg_type, envelope.payload.len())?;

    Ok(())
}

/// Verify envelope signature
///
/// MUST be called before trusting any message content.
pub fn verify_envelope_signature(envelope: &MessageEnvelope) -> Result<(), MessageValidationError> {
    // Reconstruct signed data (payload + sequence)
    let mut signed_data = envelope.payload.clone();
    signed_data.extend_from_slice(&envelope.sequence.to_le_bytes());

    // Verify using sender's public key (which IS their node ID)
    let is_valid = verify_signature(&envelope.sender, &signed_data, &envelope.signature)
        .unwrap_or(false);

    if !is_valid {
        let sender_hex = hex::encode(&envelope.sender[..8]);
        warn!(
            sender = %sender_hex,
            msg_type = ?envelope.msg_type,
            seq = envelope.sequence,
            "INVALID SIGNATURE - potential spoofing attempt"
        );
        return Err(MessageValidationError::InvalidSignature(sender_hex));
    }

    Ok(())
}

/// Full validation pipeline for incoming messages
///
/// 1. Validate raw bytes (size, version, type)
/// 2. Deserialize
/// 3. Validate envelope fields
/// 4. Verify signature
pub fn validate_and_verify(data: &[u8]) -> Result<MessageEnvelope, MessageValidationError> {
    // Step 1: Header validation (fast, no alloc)
    validate_envelope_header(data)?;

    // Step 2: Deserialize
    let envelope = MessageEnvelope::deserialize(data)
        .map_err(|e| MessageValidationError::DeserializationFailed(e.to_string()))?;

    // Step 3: Envelope validation
    validate_envelope(&envelope)?;

    // Step 4: Signature verification (expensive, do last)
    verify_envelope_signature(&envelope)?;

    Ok(envelope)
}

/// Batch validation result
#[derive(Debug, Default, Clone)]
pub struct ValidationStats {
    pub total: u64,
    pub valid: u64,
    pub too_small: u64,
    pub too_large: u64,
    pub bad_version: u64,
    pub bad_type: u64,
    pub bad_signature: u64,
    pub other_errors: u64,
}

impl ValidationStats {
    pub fn record(&mut self, result: &Result<MessageEnvelope, MessageValidationError>) {
        self.total += 1;
        match result {
            Ok(_) => self.valid += 1,
            Err(MessageValidationError::TooSmall(_)) => self.too_small += 1,
            Err(MessageValidationError::TooLarge(_)) => self.too_large += 1,
            Err(MessageValidationError::UnsupportedVersion(_)) => self.bad_version += 1,
            Err(MessageValidationError::InvalidType(_)) => self.bad_type += 1,
            Err(MessageValidationError::InvalidSignature(_)) => self.bad_signature += 1,
            Err(_) => self.other_errors += 1,
        }
    }

    pub fn rejection_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.total - self.valid) as f64 / self.total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_header_too_small() {
        let data = vec![0u8; 10];
        assert!(matches!(
            validate_envelope_header(&data),
            Err(MessageValidationError::TooSmall(_))
        ));
    }

    #[test]
    fn test_validate_header_too_large() {
        let data = vec![0u8; MAX_ENVELOPE_SIZE + 1];
        assert!(matches!(
            validate_envelope_header(&data),
            Err(MessageValidationError::TooLarge(_))
        ));
    }

    #[test]
    fn test_validate_header_bad_version() {
        let mut data = vec![0u8; MIN_ENVELOPE_SIZE];
        data[0] = 99; // Invalid version
        assert!(matches!(
            validate_envelope_header(&data),
            Err(MessageValidationError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn test_validate_header_bad_type() {
        let mut data = vec![0u8; MIN_ENVELOPE_SIZE];
        data[0] = 1; // Valid version
        data[1] = 99; // Invalid type
        assert!(matches!(
            validate_envelope_header(&data),
            Err(MessageValidationError::InvalidType(99))
        ));
    }

    #[test]
    fn test_payload_size_limits() {
        assert!(validate_payload_size(MessageType::Vote, 500).is_ok());
        assert!(validate_payload_size(MessageType::Vote, MAX_VOTE_SIZE + 1).is_err());
    }

    #[test]
    fn test_validation_stats() {
        let mut stats = ValidationStats::default();

        stats.record(&Err(MessageValidationError::TooSmall(10)));
        stats.record(&Err(MessageValidationError::InvalidSignature("abc".into())));

        assert_eq!(stats.total, 2);
        assert_eq!(stats.valid, 0);
        assert_eq!(stats.too_small, 1);
        assert_eq!(stats.bad_signature, 1);
        assert_eq!(stats.rejection_rate(), 1.0);
    }
}
