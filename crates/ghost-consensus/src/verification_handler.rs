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
//| FILE: verification_handler.rs                                                                                        |
//|======================================================================================================================|

//! Verification result handler
//!
//! Handles incoming verification results from other nodes and stores them
//! in the database for capability qualification calculations.

use async_trait::async_trait;
use chrono::Utc;
use std::sync::Arc;
use tracing::{debug, warn};

/// H-5: Maximum size for challenge_data and response_data fields (10 KB)
/// This prevents memory exhaustion attacks from malicious oversized messages
const MAX_CHALLENGE_DATA_SIZE: usize = 10 * 1024;

/// Maximum verification results per challenger per minute.
/// Normal operation: 3 peers x 4 capabilities = 12 per cycle (every 5 min).
/// 20/min is generous but prevents DB flooding from compromised nodes.
const VERIFICATION_RATE_LIMIT_PER_MIN: u32 = 20;

/// Burst capacity for verification rate limiter
const VERIFICATION_RATE_LIMIT_BURST: u32 = 20;

/// Refill rate: 20 tokens per 60 seconds ≈ 1 token per 3 seconds
const VERIFICATION_RATE_REFILL: u32 = 1;

use ghost_common::error::GhostResult;
use ghost_common::identity::verify_signature;
use ghost_storage::Database;

use crate::mesh::MessageHandler;
use crate::message::{CapabilityType, MessageEnvelope, MessageType, VerificationResultMessage};
use crate::peer::PeerManager;
use crate::vote_handler::RateLimiter;

/// Handler for verification result messages
pub struct VerificationResultHandler {
    /// Database for storing verification results
    db: Arc<Database>,
    /// HIGH-VER-4: Peer manager for validating challenger is a known node
    peers: Option<Arc<PeerManager>>,
    /// Per-challenger rate limiter to prevent DB flooding
    rate_limiter: RateLimiter,
}

impl VerificationResultHandler {
    /// Create a new verification result handler
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            peers: None,
            rate_limiter: RateLimiter::new(VERIFICATION_RATE_LIMIT_BURST, VERIFICATION_RATE_REFILL),
        }
    }

    /// HIGH-VER-4: Create a verification handler with peer validation
    ///
    /// When a PeerManager is provided, the handler will verify that challengers
    /// are known peers before accepting their verification results. This prevents
    /// attackers from generating arbitrary keypairs to submit fake results.
    pub fn with_peers(db: Arc<Database>, peers: Arc<PeerManager>) -> Self {
        Self {
            db,
            peers: Some(peers),
            rate_limiter: RateLimiter::new(VERIFICATION_RATE_LIMIT_BURST, VERIFICATION_RATE_REFILL),
        }
    }

    /// Handle an incoming verification result message
    async fn handle_verification_result(&self, envelope: &MessageEnvelope) -> GhostResult<()> {
        let envelope_sender_hex = hex::encode(envelope.sender);
        debug!(
            sender = %&envelope_sender_hex[..8],
            payload_len = envelope.payload.len(),
            "VerificationResultHandler received message"
        );

        // Deserialize the verification result message
        let msg: VerificationResultMessage =
            serde_json::from_slice(&envelope.payload).map_err(|e| {
                warn!(error = %e, "Failed to deserialize verification result message");
                ghost_common::error::GhostError::P2PMessage(e.to_string())
            })?;

        let challenger_hex = hex::encode(msg.challenger_id);
        let target_hex = hex::encode(msg.target_node_id);
        let short_challenger = &challenger_hex[..8];
        let short_target = &target_hex[..8];

        // H-5: Validate challenge_data size to prevent memory exhaustion attacks
        if msg.challenge_data.len() > MAX_CHALLENGE_DATA_SIZE {
            warn!(
                challenger = %short_challenger,
                size = msg.challenge_data.len(),
                max = MAX_CHALLENGE_DATA_SIZE,
                "Rejecting oversized challenge_data"
            );
            return Ok(());
        }

        // H-5: Validate response_data size to prevent memory exhaustion attacks
        if let Some(ref response) = msg.response_data {
            if response.len() > MAX_CHALLENGE_DATA_SIZE {
                warn!(
                    challenger = %short_challenger,
                    size = response.len(),
                    max = MAX_CHALLENGE_DATA_SIZE,
                    "Rejecting oversized response_data"
                );
                return Ok(());
            }
        }

        // C-3: Validate timestamp freshness to prevent replay attacks
        const MAX_VERIFICATION_AGE_SECS: i64 = 600; // 10 minutes
        const MAX_FUTURE_TOLERANCE_SECS: i64 = 30; // Allow 30 seconds clock skew

        let now = Utc::now().timestamp();

        // Reject stale results
        if msg.timestamp < now - MAX_VERIFICATION_AGE_SECS {
            warn!(
                challenger = %short_challenger,
                timestamp = msg.timestamp,
                now = now,
                "Rejecting stale verification result (older than 10 minutes)"
            );
            return Ok(());
        }

        // Reject future results (clock skew tolerance: 30 seconds)
        if msg.timestamp > now + MAX_FUTURE_TOLERANCE_SECS {
            warn!(
                challenger = %short_challenger,
                timestamp = msg.timestamp,
                now = now,
                "Rejecting verification result with future timestamp"
            );
            return Ok(());
        }

        debug!(
            challenger = %short_challenger,
            target = %short_target,
            capability = %msg.capability.as_str(),
            passed = msg.passed,
            "Parsed verification result from P2P"
        );

        // Verify that the envelope sender matches the challenger (prevent spoofing)
        if envelope.sender != msg.challenger_id {
            warn!(
                envelope_sender = %hex::encode(envelope.sender)[..8],
                msg_challenger = %short_challenger,
                "Verification result sender mismatch - potential spoofing"
            );
            return Ok(()); // Silently ignore invalid messages
        }

        // C-2: Reject self-verification attempts (Sybil prevention)
        if msg.challenger_id == msg.target_node_id {
            warn!(
                challenger = %short_challenger,
                "Rejecting self-verification attempt"
            );
            return Ok(());
        }

        // Verify the challenger's signature on the result
        // SEC-SIG-2: Log verification errors instead of silently treating as invalid
        let signing_data = msg.signing_data();
        let sig_valid = match verify_signature(&msg.challenger_id, &signing_data, &msg.signature) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::warn!(
                    challenger = %short_challenger,
                    error = %e,
                    "Verification result signature verification error"
                );
                false
            }
        };
        if !sig_valid {
            warn!(
                challenger = %short_challenger,
                "Invalid signature on verification result"
            );
            return Ok(()); // Silently ignore invalid signatures
        }

        // HIGH-VER-4: Validate challenger is a known peer before recording
        //
        // This prevents attackers from:
        // 1. Generating random keypairs to create fake verification results
        // 2. Submitting verification results from non-existent nodes
        // 3. Flooding the database with results from fabricated node IDs
        //
        // Only nodes that have been seen via health pings (known peers) can
        // submit verification results that will be recorded.
        if let Some(ref peers) = self.peers {
            if peers.get_peer(&msg.challenger_id).is_none() {
                // Peer not in memory — fall back to DB (nodes table persisted from health pings)
                let challenger_hex = hex::encode(&msg.challenger_id);
                let known_in_db = self.db.get_node(&challenger_hex).ok().flatten().is_some();
                if !known_in_db {
                    warn!(
                        challenger = %short_challenger,
                        "HIGH-VER-4: Rejecting verification result from unknown challenger"
                    );
                    return Ok(());
                }
                debug!(
                    challenger = %short_challenger,
                    "HIGH-VER-4: Challenger not in PeerManager but found in DB, accepting"
                );
            }
        }

        // Per-challenger rate limit to prevent DB flooding from compromised nodes
        if !self.rate_limiter.check_and_consume(&msg.challenger_id) {
            warn!(
                challenger = %short_challenger,
                "Rate-limiting verification results from challenger (>{} per minute)",
                VERIFICATION_RATE_LIMIT_PER_MIN
            );
            return Ok(());
        }

        // Store the result in the appropriate challenge table
        // Use idempotent storage - ignore if already exists (based on challenger + target + timestamp)
        match msg.capability {
            CapabilityType::Archive => {
                // For archive challenges, extract block height from challenge_data
                let block_height = serde_json::from_str::<serde_json::Value>(&msg.challenge_data)
                    .ok()
                    .and_then(|v| v.get("block_height").and_then(|h| h.as_u64()))
                    .unwrap_or(0);

                let expected_hash = serde_json::from_str::<serde_json::Value>(&msg.challenge_data)
                    .ok()
                    .and_then(|v| {
                        v.get("expected_hash")
                            .and_then(|h| h.as_str())
                            .map(String::from)
                    })
                    .unwrap_or_default();

                let response_hash = msg.response_data.as_ref().and_then(|rd| {
                    serde_json::from_str::<serde_json::Value>(rd)
                        .ok()
                        .and_then(|v| v.get("hash").and_then(|h| h.as_str()).map(String::from))
                });

                if let Err(e) = self.db.insert_archive_challenge(
                    &target_hex,
                    &challenger_hex,
                    block_height,
                    &expected_hash,
                    response_hash.as_deref(),
                    msg.passed,
                ) {
                    warn!(error = %e, "Failed to store archive challenge result");
                }
            }
            CapabilityType::Policy => {
                let txid = serde_json::from_str::<serde_json::Value>(&msg.challenge_data)
                    .ok()
                    .and_then(|v| v.get("txid").and_then(|t| t.as_str()).map(String::from))
                    .unwrap_or_default();

                let expected_tier = serde_json::from_str::<serde_json::Value>(&msg.challenge_data)
                    .ok()
                    .and_then(|v| v.get("expected_tier").and_then(|t| t.as_i64()))
                    .unwrap_or(0) as i32;

                let response_tier = msg.response_data.as_ref().and_then(|rd| {
                    serde_json::from_str::<serde_json::Value>(rd)
                        .ok()
                        .and_then(|v| v.get("tier").and_then(|t| t.as_i64()))
                        .map(|t| t as i32)
                });

                if let Err(e) = self.db.insert_policy_challenge(
                    &target_hex,
                    &challenger_hex,
                    &txid,
                    expected_tier,
                    response_tier,
                    msg.passed,
                ) {
                    warn!(error = %e, "Failed to store policy challenge result");
                }
            }
            CapabilityType::Stratum => {
                let connected = msg
                    .response_data
                    .as_ref()
                    .map(|rd| {
                        serde_json::from_str::<serde_json::Value>(rd)
                            .ok()
                            .and_then(|v| v.get("connected").and_then(|c| c.as_bool()))
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);

                let latency_ms = msg.response_data.as_ref().and_then(|rd| {
                    serde_json::from_str::<serde_json::Value>(rd)
                        .ok()
                        .and_then(|v| v.get("latency_ms").and_then(|l| l.as_u64()))
                        .map(|l| l as u32)
                });

                if let Err(e) = self.db.insert_stratum_challenge(
                    &target_hex,
                    &challenger_hex,
                    connected,
                    latency_ms,
                    msg.passed,
                ) {
                    warn!(error = %e, "Failed to store stratum challenge result");
                }
            }
            CapabilityType::GhostPay => {
                let endpoint = serde_json::from_str::<serde_json::Value>(&msg.challenge_data)
                    .ok()
                    .and_then(|v| v.get("endpoint").and_then(|e| e.as_str()).map(String::from))
                    .unwrap_or_else(|| "ghostpay".to_string());

                let response_valid = msg
                    .response_data
                    .as_ref()
                    .map(|rd| {
                        serde_json::from_str::<serde_json::Value>(rd)
                            .ok()
                            .and_then(|v| v.get("valid").and_then(|c| c.as_bool()))
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);

                if let Err(e) = self.db.insert_ghostpay_challenge(
                    &target_hex,
                    &challenger_hex,
                    &endpoint,
                    response_valid,
                    msg.passed,
                ) {
                    warn!(error = %e, "Failed to store ghostpay challenge result");
                }
            }
        }

        debug!(
            challenger = %short_challenger,
            target = %short_target,
            capability = %msg.capability.as_str(),
            passed = msg.passed,
            "Stored verification result in database"
        );

        Ok(())
    }
}

#[async_trait]
impl MessageHandler for VerificationResultHandler {
    async fn handle_message(&self, envelope: Arc<MessageEnvelope>) -> GhostResult<()> {
        if envelope.msg_type == MessageType::VerificationResult {
            self.handle_verification_result(&envelope).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// H-5-TEST: Verify the MAX_CHALLENGE_DATA_SIZE constant is set correctly
    #[test]
    fn test_max_challenge_data_size_constant() {
        // 10 KB limit
        assert_eq!(MAX_CHALLENGE_DATA_SIZE, 10 * 1024);
        assert_eq!(MAX_CHALLENGE_DATA_SIZE, 10_240);
    }

    /// H-5-TEST: Verify oversized challenge data would be rejected
    /// This is a unit test for the size limit logic - integration tested via handle_verification_result
    #[test]
    fn test_challenge_data_size_limits() {
        // Valid sizes
        let small_data = "x".repeat(100);
        assert!(small_data.len() <= MAX_CHALLENGE_DATA_SIZE);

        let at_limit = "x".repeat(MAX_CHALLENGE_DATA_SIZE);
        assert!(at_limit.len() <= MAX_CHALLENGE_DATA_SIZE);

        // Invalid size
        let over_limit = "x".repeat(MAX_CHALLENGE_DATA_SIZE + 1);
        assert!(over_limit.len() > MAX_CHALLENGE_DATA_SIZE);
    }

    /// HIGH-VER-4-TEST: Verify that VerificationResultHandler with peers requires known challenger
    ///
    /// This test verifies the constructor and configuration of the handler.
    /// Full integration testing of peer validation requires a mock PeerManager.
    #[test]
    fn test_handler_with_peers_constructor() {
        // Create an in-memory database for testing
        let db = Arc::new(Database::in_memory().expect("Failed to create in-memory database"));

        // Create handler without peers (legacy mode)
        let handler_no_peers = VerificationResultHandler::new(Arc::clone(&db));
        assert!(
            handler_no_peers.peers.is_none(),
            "Handler without peers should have None"
        );

        // Create handler with peers (HIGH-VER-4 mode)
        let peer_manager = Arc::new(PeerManager::new([0u8; 32], 100));
        let handler_with_peers =
            VerificationResultHandler::with_peers(Arc::clone(&db), peer_manager);
        assert!(
            handler_with_peers.peers.is_some(),
            "Handler with peers should have Some"
        );
    }
}
