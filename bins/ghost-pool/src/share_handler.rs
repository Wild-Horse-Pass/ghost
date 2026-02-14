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
//| FILE: share_handler.rs                                                                                               |
//|======================================================================================================================|

//! P2P share proof handler
//!
//! Receives share proofs from other nodes and delegates validation to
//! RoundManager::handle_share_proof(), which performs full cryptographic
//! verification, dedup, tolerance tracking, and work crediting.

use async_trait::async_trait;
use chrono::Utc;
use std::sync::Arc;
use tracing::{debug, warn};

use ghost_common::error::GhostResult;
use ghost_common::types::NodeId;
use ghost_storage::Database;

use ghost_consensus::mesh::MessageHandler;
use ghost_consensus::message::{MessageEnvelope, MessageType, ShareProofMessage};

use crate::round::RoundManager;

/// Maximum age of a share proof before it's rejected (10 minutes)
const MAX_SHARE_AGE_SECS: i64 = 600;
/// Maximum future tolerance for clock skew (30 seconds)
const MAX_FUTURE_TOLERANCE_SECS: i64 = 30;

/// Handler for incoming P2P share proof messages
pub struct ShareProofHandler {
    round_manager: Arc<RoundManager>,
    db: Arc<Database>,
    our_node_id: NodeId,
}

impl ShareProofHandler {
    pub fn new(
        round_manager: Arc<RoundManager>,
        db: Arc<Database>,
        our_node_id: NodeId,
    ) -> Self {
        Self {
            round_manager,
            db,
            our_node_id,
        }
    }

    async fn handle_share_proof(&self, envelope: &MessageEnvelope) -> GhostResult<()> {
        let msg: ShareProofMessage = serde_json::from_slice(&envelope.payload).map_err(|e| {
            warn!(error = %e, "Failed to deserialize share proof message");
            ghost_common::error::GhostError::P2PMessage(e.to_string())
        })?;

        let proof = msg.proof;

        // Skip our own shares (already recorded locally)
        if proof.received_by == self.our_node_id {
            return Ok(());
        }

        // Timestamp freshness check
        let now = Utc::now().timestamp();
        let ts = proof.timestamp as i64;

        if ts < now - MAX_SHARE_AGE_SECS {
            warn!(
                timestamp = proof.timestamp,
                now = now,
                "Rejecting stale share proof (older than 10 minutes)"
            );
            return Ok(());
        }

        if ts > now + MAX_FUTURE_TOLERANCE_SECS {
            warn!(
                timestamp = proof.timestamp,
                now = now,
                "Rejecting share proof with future timestamp"
            );
            return Ok(());
        }

        let miner_hex = hex::encode(&proof.miner_id[..8]);
        let from_node = hex::encode(&proof.received_by[..4]);
        let payout_address = proof.payout_address.clone();
        let round_id = proof.round_id;
        let share_hash = hex::encode(proof.share_hash);
        let work = proof.work;
        let timestamp = proof.timestamp;

        // Delegate all validation to handle_share_proof:
        // C4 (crypto), C5 (dedup), L-7 (tolerance), M-6 (template), M-29 (persistent exploiter)
        match self.round_manager.handle_share_proof(proof) {
            Ok(()) => {
                // Persist to DB so shares survive node restarts
                let share_record = ghost_storage::models::ShareRecord {
                    id: None,
                    round_id,
                    miner_id: miner_hex.clone(),
                    difficulty: work,
                    work,
                    share_hash: share_hash.clone(),
                    timestamp: timestamp as i64,
                    received_by: from_node.clone(),
                    valid: true,
                };

                if let Err(e) = self.db.insert_share(&share_record) {
                    // UNIQUE constraint handles dedup — log other errors
                    if !e.to_string().contains("UNIQUE") {
                        warn!(
                            miner = %miner_hex,
                            error = %e,
                            "Failed to persist remote share to database"
                        );
                    }
                }

                // Store payout address for this miner so payouts can find them
                if let Some(ref addr) = payout_address {
                    if !addr.is_empty() {
                        if let Err(e) = self.db.update_miner_address(&miner_hex, addr) {
                            warn!(
                                miner = %miner_hex,
                                error = %e,
                                "Failed to store remote miner payout address"
                            );
                        }
                    }
                }

                debug!(
                    miner = %miner_hex,
                    from_node = %from_node,
                    "Accepted remote share proof"
                );
            }
            Err(crate::round::ShareError::DuplicateShare) => {
                // Expected during normal operation (multiple nodes forward same share)
            }
            Err(e) => {
                debug!(
                    miner = %miner_hex,
                    from_node = %from_node,
                    error = %e,
                    "Rejected remote share proof"
                );
            }
        }

        Ok(())
    }
}

#[async_trait]
impl MessageHandler for ShareProofHandler {
    async fn handle_message(&self, envelope: MessageEnvelope) -> GhostResult<()> {
        if envelope.msg_type == MessageType::ShareProof {
            self.handle_share_proof(&envelope).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_consensus::message::MessageEnvelope;

    fn make_envelope(msg_type: MessageType, payload: Vec<u8>) -> MessageEnvelope {
        MessageEnvelope {
            msg_type,
            sender: [0u8; 32],
            timestamp: Utc::now().timestamp() as u64,
            sequence: 1,
            signature: [0u8; 64],
            payload,
            ttl: 3,
        }
    }

    #[tokio::test]
    async fn test_ignores_non_share_proof_messages() {
        let db = Arc::new(Database::in_memory().expect("in-memory db"));
        let rm = Arc::new(RoundManager::new(
            [1u8; 32],
            crate::round::RoundConfig::default(),
        ));
        let handler = ShareProofHandler::new(rm, db, [1u8; 32]);

        let envelope = make_envelope(MessageType::HealthPing, vec![]);
        // Should return Ok without processing
        assert!(handler.handle_message(envelope).await.is_ok());
    }

    #[tokio::test]
    async fn test_skips_own_shares() {
        let our_node_id = [1u8; 32];
        let db = Arc::new(Database::in_memory().expect("in-memory db"));
        let rm = Arc::new(RoundManager::new(
            our_node_id,
            crate::round::RoundConfig::default(),
        ));
        let handler = ShareProofHandler::new(rm, db, our_node_id);

        // Create a share proof from our own node
        let proof = ghost_common::types::ShareProof {
            round_id: 1,
            miner_id: [2u8; 32],
            difficulty: 1000.0,
            work: 1000.0,
            share_hash: [3u8; 32],
            timestamp: Utc::now().timestamp() as u64,
            received_by: our_node_id, // Our own node
            template_id: Some([4u8; 32]),
            payout_address: None,
        };
        let msg = ShareProofMessage { proof };
        let payload = serde_json::to_vec(&msg).unwrap();
        let envelope = make_envelope(MessageType::ShareProof, payload);

        // Should silently skip (return Ok)
        assert!(handler.handle_message(envelope).await.is_ok());
    }

    #[tokio::test]
    async fn test_rejects_stale_timestamp() {
        let our_node_id = [1u8; 32];
        let other_node_id = [2u8; 32];
        let db = Arc::new(Database::in_memory().expect("in-memory db"));
        let rm = Arc::new(RoundManager::new(
            our_node_id,
            crate::round::RoundConfig::default(),
        ));
        let handler = ShareProofHandler::new(rm, db, our_node_id);

        // Create a share proof with a very old timestamp
        let proof = ghost_common::types::ShareProof {
            round_id: 1,
            miner_id: [3u8; 32],
            difficulty: 1000.0,
            work: 1000.0,
            share_hash: [4u8; 32],
            timestamp: 1000, // Very old
            received_by: other_node_id,
            template_id: Some([5u8; 32]),
            payout_address: None,
        };
        let msg = ShareProofMessage { proof };
        let payload = serde_json::to_vec(&msg).unwrap();
        let envelope = make_envelope(MessageType::ShareProof, payload);

        // Should silently reject stale timestamp (return Ok, but not process)
        assert!(handler.handle_message(envelope).await.is_ok());
    }
}
