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
/// P2P-H3: Equivocation proof (two votes + metadata)
pub const MAX_EQUIVOCATION_PROOF_SIZE: usize = 10_000;
/// P2P-C1: Elder registration proposal (candidate + PoW + signatures)
pub const MAX_ELDER_REGISTRATION_PROPOSAL_SIZE: usize = 1_000;
/// P2P-C2: Elder list proposal (full list of up to 101 elders + metadata)
pub const MAX_ELDER_LIST_PROPOSAL_SIZE: usize = 100_000;
/// P2P-C3: Elder list approval (signature + epoch + merkle root)
pub const MAX_ELDER_LIST_APPROVAL_SIZE: usize = 500;
/// MPC-C1: MPC contribution (proof + params hash + signature)
pub const MAX_MPC_CONTRIBUTION_SIZE: usize = 50_000;
/// MPC-C2: MPC verification vote (signature + approval)
pub const MAX_MPC_VERIFICATION_VOTE_SIZE: usize = 500;
/// MPC-C3: MPC parameters request (hash + chunk indices)
pub const MAX_MPC_PARAMS_REQUEST_SIZE: usize = 5_000;
/// MPC-C4: MPC parameters response (chunked data ~1MB)
pub const MAX_MPC_PARAMS_RESPONSE_SIZE: usize = 1_100_000;

/// SEC-TIME-1: Default timestamp drift window (60 seconds in milliseconds)
///
/// This is the default value used when no explicit drift is configured.
/// 60 seconds provides a good balance between:
/// - Security: Limits the window for replay attacks
/// - Usability: Allows for clock drift across geographically distributed nodes
/// - Network: Accounts for message propagation delays
///
/// Nodes should run NTP to maintain clock synchronization within this window.
pub const DEFAULT_TIMESTAMP_DRIFT_MS: u64 = 60 * 1000;

/// SEC-TIME-1: Legacy constant for backwards compatibility
/// Use DEFAULT_TIMESTAMP_DRIFT_MS for new code.
pub const MAX_TIMESTAMP_DRIFT_MS: u64 = DEFAULT_TIMESTAMP_DRIFT_MS;

/// Minimum allowed timestamp drift (1 second)
/// Setting drift below this is dangerous as it may cause legitimate message rejection
pub const MIN_TIMESTAMP_DRIFT_MS: u64 = 1000;

/// Maximum allowed timestamp drift (5 minutes)
/// Higher values increase replay attack window
pub const MAX_TIMESTAMP_DRIFT_LIMIT_MS: u64 = 5 * 60 * 1000;

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

    /// H-P2P-2: Signature is all zeros (indicates uninitialized/forged message)
    #[error("Signature is all zeros")]
    ZeroSignature,

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
    if msg_type_byte > 13 {
        // We have 14 message types (0-13) including ZK payout types, verification, and equivocation
        return Err(MessageValidationError::InvalidType(msg_type_byte));
    }

    Ok(())
}

/// P2P-H1: Extract message type from raw JSON data without full deserialization
///
/// This enables topic validation BEFORE expensive full deserialization.
/// Messages received on a specific topic/socket must have the matching message type.
/// This prevents attackers from sending messages on the wrong topic to confuse handlers.
///
/// # Arguments
/// * `data` - Raw message bytes (expected to be JSON)
///
/// # Returns
/// * `Ok(Some(MessageType))` - Successfully extracted message type
/// * `Ok(None)` - Could not extract type (invalid format)
/// * `Err(MessageValidationError)` - Message too small/large
pub fn extract_message_type_fast(
    data: &[u8],
) -> Result<Option<MessageType>, MessageValidationError> {
    // Size bounds
    if data.len() < MIN_ENVELOPE_SIZE {
        return Err(MessageValidationError::TooSmall(data.len()));
    }

    if data.len() > MAX_ENVELOPE_SIZE {
        return Err(MessageValidationError::TooLarge(data.len()));
    }

    // Only handle JSON format (starts with '{')
    if data[0] != b'{' {
        // Binary format - extract type from second byte
        let msg_type_byte = data[1];
        let msg_type = match msg_type_byte {
            0 => Some(MessageType::ShareProof),
            1 => Some(MessageType::BlockFound),
            2 => Some(MessageType::PayoutProposal),
            3 => Some(MessageType::Vote),
            4 => Some(MessageType::HealthPing),
            5 => Some(MessageType::Discovery),
            6 => Some(MessageType::ElderUpdate),
            7 => Some(MessageType::ShareConvergence),
            8 => Some(MessageType::ZkBlockProposal),
            9 => Some(MessageType::ZkVote),
            10 => Some(MessageType::ZkPayoutProposal),
            11 => Some(MessageType::ZkPayoutVote),
            12 => Some(MessageType::VerificationResult),
            13 => Some(MessageType::EquivocationProof),
            _ => None,
        };
        return Ok(msg_type);
    }

    // JSON format - look for "msg_type" field without full parsing
    // The JSON format uses: {"msg_type":"ShareProof", ...}
    // We search for the pattern and extract just the type string

    // Convert to string for simple pattern matching
    // This is safe because JSON is UTF-8 and we're looking for ASCII patterns
    let data_str = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return Ok(None), // Invalid UTF-8, can't extract
    };

    // Look for "msg_type":"<TYPE>" pattern
    // We use a simple search rather than full JSON parsing
    let type_marker = r#""msg_type":"#;
    let type_pos = match data_str.find(type_marker) {
        Some(pos) => pos + type_marker.len(),
        None => return Ok(None), // No msg_type field found
    };

    // Extract the type value (should be a quoted string)
    if type_pos >= data_str.len() || data_str.as_bytes()[type_pos] != b'"' {
        return Ok(None);
    }

    let type_start = type_pos + 1;
    let type_end = match data_str[type_start..].find('"') {
        Some(pos) => type_start + pos,
        None => return Ok(None),
    };

    let type_str = &data_str[type_start..type_end];

    // Map string to MessageType
    let msg_type = match type_str {
        "ShareProof" => MessageType::ShareProof,
        "ShareConvergence" => MessageType::ShareConvergence,
        "BlockFound" => MessageType::BlockFound,
        "Vote" => MessageType::Vote,
        "HealthPing" => MessageType::HealthPing,
        "Discovery" => MessageType::Discovery,
        "PayoutProposal" => MessageType::PayoutProposal,
        "ElderUpdate" => MessageType::ElderUpdate,
        "ZkBlockProposal" => MessageType::ZkBlockProposal,
        "ZkVote" => MessageType::ZkVote,
        "ZkPayoutProposal" => MessageType::ZkPayoutProposal,
        "ZkPayoutVote" => MessageType::ZkPayoutVote,
        "VerificationResult" => MessageType::VerificationResult,
        "EquivocationProof" => MessageType::EquivocationProof,
        _ => return Ok(None), // Unknown type
    };

    Ok(Some(msg_type))
}

/// P2P-H1: Validate that a message's type matches the expected topic
///
/// Call this BEFORE full deserialization to reject messages sent on the wrong topic.
/// This prevents type confusion attacks where an attacker sends a message on one
/// socket but with a different message type.
///
/// # Arguments
/// * `data` - Raw message bytes
/// * `expected_type` - The message type expected for this topic/socket
///
/// # Returns
/// * `Ok(())` - Type matches or could not be extracted (will be validated after deser)
/// * `Err(InvalidType)` - Extracted type does not match expected type
pub fn validate_topic_before_deser(
    data: &[u8],
    expected_type: MessageType,
) -> Result<(), MessageValidationError> {
    match extract_message_type_fast(data)? {
        Some(msg_type) if msg_type != expected_type => {
            warn!(
                expected = ?expected_type,
                actual = ?msg_type,
                "Message type mismatch - wrong topic"
            );
            // We return InvalidType but with a specific byte value to indicate topic mismatch
            // The actual type byte doesn't matter here since it's JSON
            Err(MessageValidationError::InvalidType(255))
        }
        _ => Ok(()), // Either matches or couldn't extract (validate after deser)
    }
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
        MessageType::EquivocationProof => MAX_EQUIVOCATION_PROOF_SIZE,
        MessageType::ElderRegistrationProposal => MAX_ELDER_REGISTRATION_PROPOSAL_SIZE,
        MessageType::ElderListProposal => MAX_ELDER_LIST_PROPOSAL_SIZE,
        MessageType::ElderListApproval => MAX_ELDER_LIST_APPROVAL_SIZE,
        MessageType::MpcContribution => MAX_MPC_CONTRIBUTION_SIZE,
        MessageType::MpcVerificationVote => MAX_MPC_VERIFICATION_VOTE_SIZE,
        MessageType::MpcParametersRequest => MAX_MPC_PARAMS_REQUEST_SIZE,
        MessageType::MpcParametersResponse => MAX_MPC_PARAMS_RESPONSE_SIZE,
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
    // H-P2P-2: Check for zero signatures (must be checked in all handlers, not just vote_handler)
    // Zero signatures indicate uninitialized or forged messages
    if envelope.signature == [0u8; 64] {
        return Err(MessageValidationError::ZeroSignature);
    }

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

/// Validate that a timestamp is within acceptable range using default drift window
///
/// Rejects messages with timestamps that are:
/// - More than DEFAULT_TIMESTAMP_DRIFT_MS in the future (prevents replay attacks with future timestamps)
/// - More than DEFAULT_TIMESTAMP_DRIFT_MS in the past (prevents replay of old messages)
pub fn validate_timestamp(timestamp_ms: u64) -> Result<(), MessageValidationError> {
    validate_timestamp_with_drift(timestamp_ms, DEFAULT_TIMESTAMP_DRIFT_MS)
}

/// Validate that a timestamp is within a configurable drift window
///
/// # Arguments
/// * `timestamp_ms` - The timestamp to validate (Unix milliseconds)
/// * `drift_ms` - Maximum allowed drift in milliseconds (clamped to MIN..MAX range)
///
/// # Returns
/// * `Ok(())` if timestamp is within the acceptable window
/// * `Err(TimestampInFuture)` if timestamp is too far in the future
/// * `Err(TimestampInPast)` if timestamp is too far in the past
pub fn validate_timestamp_with_drift(
    timestamp_ms: u64,
    drift_ms: u64,
) -> Result<(), MessageValidationError> {
    // Clamp drift to safe bounds
    let drift_ms = drift_ms.clamp(MIN_TIMESTAMP_DRIFT_MS, MAX_TIMESTAMP_DRIFT_LIMIT_MS);

    let now_ms = chrono::Utc::now().timestamp_millis() as u64;

    // Check if timestamp is too far in the future
    if timestamp_ms > now_ms.saturating_add(drift_ms) {
        let drift = timestamp_ms - now_ms;
        warn!(
            timestamp_ms,
            now_ms,
            drift_ms = drift,
            allowed_drift_ms = drift_ms,
            "Message timestamp too far in the future"
        );
        return Err(MessageValidationError::TimestampInFuture(drift));
    }

    // Check if timestamp is too far in the past
    if now_ms > timestamp_ms.saturating_add(drift_ms) {
        let drift = now_ms - timestamp_ms;
        warn!(
            timestamp_ms,
            now_ms,
            drift_ms = drift,
            allowed_drift_ms = drift_ms,
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

    // SEC-MSG-1: Log verification errors instead of silently treating as invalid
    let is_valid = match verify_signature(&envelope.sender, &signed_data, &envelope.signature) {
        Ok(valid) => valid,
        Err(e) => {
            warn!(
                sender = %hex::encode(&envelope.sender[..8]),
                msg_type = ?envelope.msg_type,
                error = %e,
                "Envelope signature verification error"
            );
            false
        }
    };

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
        // Slightly in the future (20 seconds) should be valid
        // SEC-TIME-1: Using 20s to stay within 30s drift limit
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let future_ms = now_ms + 20_000; // 20 seconds ahead
        assert!(validate_timestamp(future_ms).is_ok());
    }

    #[test]
    fn test_timestamp_validation_slight_past() {
        // Slightly in the past (20 seconds) should be valid
        // SEC-TIME-1: Using 20s to stay within 30s drift limit
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let past_ms = now_ms - 20_000; // 20 seconds behind
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
        assert!(
            future_result.is_ok()
                || matches!(future_result, Err(MessageValidationError::TimestampInFuture(d)) if d < 1000)
        );
        assert!(
            past_result.is_ok()
                || matches!(past_result, Err(MessageValidationError::TimestampInPast(d)) if d < 1000)
        );
    }

    #[test]
    fn test_zero_signature_rejected() {
        // H-P2P-2: Test that zero signatures are rejected by validate_envelope
        let envelope = MessageEnvelope {
            msg_type: MessageType::Vote,
            sender: [1u8; 32],
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            sequence: 1,
            signature: [0u8; 64], // Zero signature
            payload: vec![1, 2, 3],
            ttl: 10,
        };

        let result = validate_envelope(&envelope);
        assert!(matches!(result, Err(MessageValidationError::ZeroSignature)));
    }

    #[test]
    fn test_non_zero_signature_passes_validation() {
        // Non-zero signature should pass the zero check (actual sig verification is separate)
        let envelope = MessageEnvelope {
            msg_type: MessageType::Vote,
            sender: [1u8; 32],
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            sequence: 1,
            signature: [1u8; 64], // Non-zero signature (but invalid - that's ok for this test)
            payload: vec![1, 2, 3],
            ttl: 10,
        };

        // Should pass validate_envelope (signature validity check is separate)
        let result = validate_envelope(&envelope);
        assert!(result.is_ok());
    }

    // P2P-H1: Tests for extract_message_type_fast and validate_topic_before_deser

    #[test]
    fn test_extract_message_type_from_json() {
        // Valid JSON with msg_type field
        let json = r#"{"msg_type":"HealthPing","sender":"abc123","timestamp":1234567890}"#;
        let data = json.as_bytes();

        // Need enough bytes to pass size check
        let mut padded = data.to_vec();
        padded.resize(MIN_ENVELOPE_SIZE + 100, b' ');

        let result = extract_message_type_fast(&padded);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(MessageType::HealthPing));
    }

    #[test]
    fn test_extract_message_type_vote() {
        let json = r#"{"msg_type":"Vote","sender":"abc123"}"#;
        let mut padded = json.as_bytes().to_vec();
        padded.resize(MIN_ENVELOPE_SIZE + 100, b' ');

        let result = extract_message_type_fast(&padded);
        assert_eq!(result.unwrap(), Some(MessageType::Vote));
    }

    #[test]
    fn test_extract_message_type_share_proof() {
        let json = r#"{"msg_type":"ShareProof","data":"..."}"#;
        let mut padded = json.as_bytes().to_vec();
        padded.resize(MIN_ENVELOPE_SIZE + 100, b' ');

        let result = extract_message_type_fast(&padded);
        assert_eq!(result.unwrap(), Some(MessageType::ShareProof));
    }

    #[test]
    fn test_extract_message_type_unknown() {
        let json = r#"{"msg_type":"UnknownType","data":"..."}"#;
        let mut padded = json.as_bytes().to_vec();
        padded.resize(MIN_ENVELOPE_SIZE + 100, b' ');

        let result = extract_message_type_fast(&padded);
        assert_eq!(result.unwrap(), None); // Unknown type returns None
    }

    #[test]
    fn test_extract_message_type_no_type_field() {
        let json = r#"{"sender":"abc123","timestamp":1234567890}"#;
        let mut padded = json.as_bytes().to_vec();
        padded.resize(MIN_ENVELOPE_SIZE + 100, b' ');

        let result = extract_message_type_fast(&padded);
        assert_eq!(result.unwrap(), None); // No msg_type field returns None
    }

    #[test]
    fn test_validate_topic_correct_type() {
        let json = r#"{"msg_type":"HealthPing","sender":"abc123"}"#;
        let mut padded = json.as_bytes().to_vec();
        padded.resize(MIN_ENVELOPE_SIZE + 100, b' ');

        // Should pass when expected type matches
        let result = validate_topic_before_deser(&padded, MessageType::HealthPing);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_topic_wrong_type() {
        let json = r#"{"msg_type":"Vote","sender":"abc123"}"#;
        let mut padded = json.as_bytes().to_vec();
        padded.resize(MIN_ENVELOPE_SIZE + 100, b' ');

        // Should fail when expected type doesn't match
        let result = validate_topic_before_deser(&padded, MessageType::HealthPing);
        assert!(matches!(
            result,
            Err(MessageValidationError::InvalidType(255))
        ));
    }

    #[test]
    fn test_validate_topic_missing_type_passes() {
        // When type can't be extracted, we pass validation
        // (will be validated after full deserialization)
        let json = r#"{"sender":"abc123","timestamp":1234567890}"#;
        let mut padded = json.as_bytes().to_vec();
        padded.resize(MIN_ENVELOPE_SIZE + 100, b' ');

        let result = validate_topic_before_deser(&padded, MessageType::HealthPing);
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_binary_format() {
        // Binary format: version(1) + type(1) + rest
        let mut data = vec![0u8; MIN_ENVELOPE_SIZE + 10];
        data[0] = 1; // Version 1
        data[1] = 4; // MessageType::HealthPing

        let result = extract_message_type_fast(&data);
        assert_eq!(result.unwrap(), Some(MessageType::HealthPing));
    }

    #[test]
    fn test_extract_binary_format_invalid_type() {
        let mut data = vec![0u8; MIN_ENVELOPE_SIZE + 10];
        data[0] = 1; // Version 1
        data[1] = 99; // Invalid type

        let result = extract_message_type_fast(&data);
        assert_eq!(result.unwrap(), None);
    }
}
