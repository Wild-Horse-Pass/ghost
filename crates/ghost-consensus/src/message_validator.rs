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
/// ZK block proposal can include transactions + proof (up to 2MB)
pub const MAX_ZK_PROPOSAL_SIZE: usize = 2_000_000;
/// ZK vote is small (just signature + metadata)
pub const MAX_ZK_VOTE_SIZE: usize = 1_000;
/// ZK payout proposal includes proof + merkle root (up to 1MB)
pub const MAX_ZK_PAYOUT_PROPOSAL_SIZE: usize = 1_000_000;
/// ZK payout vote is small (signature + approval + optional rejection reason)
pub const MAX_ZK_PAYOUT_VOTE_SIZE: usize = 1_000;
/// Verification result is small (node IDs + capability + result + signature)
pub const MAX_VERIFICATION_SIZE: usize = 5_000;

/// Maximum allowed timestamp drift from current time (5 minutes in milliseconds)
/// Messages with timestamps too far in the future or past are rejected
pub const MAX_TIMESTAMP_DRIFT_MS: u64 = 5 * 60 * 1000;

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

    #[error("Timestamp too far in the future: {0}ms ahead")]
    TimestampInFuture(u64),

    #[error("Timestamp too far in the past: {0}ms behind")]
    TimestampInPast(u64),
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

    // Check if this is JSON-serialized (starts with '{')
    // MessageEnvelope uses serde_json for serialization, so valid messages start with '{'
    if data[0] == b'{' {
        // JSON format - can't validate header bytes, will validate during deserialization
        return Ok(());
    }

    // Binary format (future use) - validate header bytes
    // Version check (first byte)
    let version = data[0];
    if version != 1 {
        return Err(MessageValidationError::UnsupportedVersion(version));
    }

    // Message type check (second byte)
    let msg_type_byte = data[1];
    if msg_type_byte > 12 {
        // We have 13 message types (0-12) including ZK payout types and verification result
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
        MessageType::ZkBlockProposal => MAX_ZK_PROPOSAL_SIZE,
        MessageType::ZkVote => MAX_ZK_VOTE_SIZE,
        MessageType::ZkPayoutProposal => MAX_ZK_PAYOUT_PROPOSAL_SIZE,
        MessageType::ZkPayoutVote => MAX_ZK_PAYOUT_VOTE_SIZE,
        MessageType::VerificationResult => MAX_VERIFICATION_SIZE,
    }
}

/// Validate payload size against message type limits
pub fn validate_payload_size(
    msg_type: MessageType,
    payload_size: usize,
) -> Result<(), MessageValidationError> {
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

    // Validate timestamp is within acceptable range
    validate_timestamp(envelope.timestamp)?;

    Ok(())
}

/// Validate that a timestamp is within acceptable range
///
/// Rejects messages with timestamps that are:
/// - More than MAX_TIMESTAMP_DRIFT_MS in the future (prevents replay attacks with future timestamps)
/// - More than MAX_TIMESTAMP_DRIFT_MS in the past (prevents replay of old messages)
pub fn validate_timestamp(timestamp_ms: u64) -> Result<(), MessageValidationError> {
    let now_ms = chrono::Utc::now().timestamp_millis() as u64;

    // Check if timestamp is too far in the future
    if timestamp_ms > now_ms + MAX_TIMESTAMP_DRIFT_MS {
        let drift = timestamp_ms - now_ms;
        warn!(
            timestamp_ms,
            now_ms,
            drift_ms = drift,
            "Message timestamp too far in the future"
        );
        return Err(MessageValidationError::TimestampInFuture(drift));
    }

    // Check if timestamp is too far in the past
    if now_ms > timestamp_ms + MAX_TIMESTAMP_DRIFT_MS {
        let drift = now_ms - timestamp_ms;
        warn!(
            timestamp_ms,
            now_ms,
            drift_ms = drift,
            "Message timestamp too far in the past"
        );
        return Err(MessageValidationError::TimestampInPast(drift));
    }

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
    let is_valid =
        verify_signature(&envelope.sender, &signed_data, &envelope.signature).unwrap_or(false);

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
    pub bad_timestamp: u64,
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
            Err(MessageValidationError::TimestampInFuture(_)) => self.bad_timestamp += 1,
            Err(MessageValidationError::TimestampInPast(_)) => self.bad_timestamp += 1,
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

    #[test]
    fn test_timestamp_validation_current() {
        // Current timestamp should be valid
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        assert!(validate_timestamp(now_ms).is_ok());
    }

    #[test]
    fn test_timestamp_validation_slight_future() {
        // Slightly in the future (1 minute) should be valid
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let future_ms = now_ms + 60_000; // 1 minute ahead
        assert!(validate_timestamp(future_ms).is_ok());
    }

    #[test]
    fn test_timestamp_validation_slight_past() {
        // Slightly in the past (1 minute) should be valid
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let past_ms = now_ms - 60_000; // 1 minute behind
        assert!(validate_timestamp(past_ms).is_ok());
    }

    #[test]
    fn test_timestamp_validation_too_far_future() {
        // 10 minutes in the future should be rejected
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let future_ms = now_ms + 10 * 60_000; // 10 minutes ahead
        assert!(matches!(
            validate_timestamp(future_ms),
            Err(MessageValidationError::TimestampInFuture(_))
        ));
    }

    #[test]
    fn test_timestamp_validation_too_far_past() {
        // 10 minutes in the past should be rejected
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let past_ms = now_ms - 10 * 60_000; // 10 minutes behind
        assert!(matches!(
            validate_timestamp(past_ms),
            Err(MessageValidationError::TimestampInPast(_))
        ));
    }

    #[test]
    fn test_timestamp_validation_edge_case() {
        // Exactly at the boundary should be valid
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let boundary_future = now_ms + MAX_TIMESTAMP_DRIFT_MS;
        let boundary_past = now_ms - MAX_TIMESTAMP_DRIFT_MS;

        // Boundary should be valid (or just barely invalid due to timing)
        // We allow a small tolerance for test timing
        let future_result = validate_timestamp(boundary_future);
        let past_result = validate_timestamp(boundary_past);

        // At least one of these should pass (timing dependent)
        // The test verifies the boundary logic works
        assert!(future_result.is_ok() || matches!(future_result, Err(MessageValidationError::TimestampInFuture(d)) if d < 1000));
        assert!(past_result.is_ok() || matches!(past_result, Err(MessageValidationError::TimestampInPast(d)) if d < 1000));
    }
}
