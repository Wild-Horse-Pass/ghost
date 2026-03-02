//! GhostGlyph P2P handler
//!
//! Processes glyph claim and registration messages from the mesh network.
//! Claims are validated and stored; registrations complete pending claims.

use async_trait::async_trait;
use parking_lot::RwLock;
use std::sync::Arc;
use tracing::{debug, info, warn};

use ghost_common::error::GhostResult;
use ghost_glyph::{GhostGlyph, GLYPH_SIZE};
use ghost_storage::Database;

use ghost_consensus::mesh::MessageHandler;
use ghost_consensus::message::{
    GhostGlyphClaimMessage, GhostGlyphRegisteredMessage, MessageEnvelope, MessageType,
};
use ghost_consensus::vote_handler::BroadcastFn;

/// Handler for GhostGlyph P2P messages
pub struct GlyphRegistrationHandler {
    db: Arc<Database>,
    broadcast_fn: RwLock<Option<BroadcastFn>>,
}

impl GlyphRegistrationHandler {
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            broadcast_fn: RwLock::new(None),
        }
    }

    /// Set the broadcast function for relaying claims/registrations to mesh
    pub fn set_broadcast_fn(&self, f: BroadcastFn) {
        *self.broadcast_fn.write() = Some(f);
    }

    /// Relay a glyph claim from ghost-pay: validate, store locally, broadcast to mesh.
    /// Called via the localhost-only relay endpoint.
    pub fn relay_claim(&self, data: Vec<u8>) -> GhostResult<()> {
        let msg: GhostGlyphClaimMessage = serde_json::from_slice(&data).map_err(|e| {
            ghost_common::error::GhostError::Serialization(format!(
                "Invalid GhostGlyphClaimMessage: {}",
                e
            ))
        })?;

        // Validate pixel array
        if msg.pixels.len() != GLYPH_SIZE {
            return Err(ghost_common::error::GhostError::Internal(format!(
                "Invalid pixel array size: {} (expected {})",
                msg.pixels.len(),
                GLYPH_SIZE
            )));
        }

        let pixels: [u8; GLYPH_SIZE] = msg.pixels.as_slice().try_into().map_err(|_| {
            ghost_common::error::GhostError::Internal("Invalid pixel array".to_string())
        })?;

        if GhostGlyph::validate_pixels(&pixels).is_err() {
            return Err(ghost_common::error::GhostError::Internal(
                "Pixel values out of range".to_string(),
            ));
        }

        // Verify commitment
        let expected_commitment =
            GhostGlyph::compute_commitment(&pixels, msg.ghost_id.as_bytes());
        if msg.commitment != expected_commitment {
            return Err(ghost_common::error::GhostError::Internal(
                "Commitment mismatch".to_string(),
            ));
        }

        // Verify bitmap hash
        let expected_bitmap_hash = GhostGlyph::compute_bitmap_hash(&pixels);
        if msg.bitmap_hash != expected_bitmap_hash {
            return Err(ghost_common::error::GhostError::Internal(
                "Bitmap hash mismatch".to_string(),
            ));
        }

        // Store locally (idempotent — UNIQUE constraint races are fine)
        let _ = self.db.insert_glyph_claim(
            &msg.ghost_id,
            &msg.pixels,
            &msg.bitmap_hash,
            &msg.commitment,
            msg.timestamp,
        );

        // Broadcast to mesh
        if let Some(ref broadcast) = *self.broadcast_fn.read() {
            if let Err(e) = broadcast(MessageType::GhostGlyphClaim, data) {
                warn!(error = %e, "Failed to broadcast glyph claim to mesh");
            }
        }

        info!(ghost_id = %msg.ghost_id, "Glyph claim relayed to mesh");
        Ok(())
    }

    /// Relay a glyph registration from ghost-pay: store locally, broadcast to mesh.
    pub fn relay_registered(&self, data: Vec<u8>) -> GhostResult<()> {
        let msg: GhostGlyphRegisteredMessage = serde_json::from_slice(&data).map_err(|e| {
            ghost_common::error::GhostError::Serialization(format!(
                "Invalid GhostGlyphRegisteredMessage: {}",
                e
            ))
        })?;

        // Complete registration locally
        let _ = self.db.complete_glyph_registration(
            &msg.ghost_id,
            &msg.funding_txid,
            msg.registered_at,
        );

        // Broadcast to mesh
        if let Some(ref broadcast) = *self.broadcast_fn.read() {
            if let Err(e) = broadcast(MessageType::GhostGlyphRegistered, data) {
                warn!(error = %e, "Failed to broadcast glyph registration to mesh");
            }
        }

        info!(ghost_id = %msg.ghost_id, "Glyph registration relayed to mesh");
        Ok(())
    }

    async fn handle_claim(&self, envelope: &MessageEnvelope) -> GhostResult<()> {
        let msg: GhostGlyphClaimMessage =
            serde_json::from_slice(&envelope.payload).map_err(|e| {
                warn!(error = %e, "Failed to deserialize GhostGlyphClaimMessage");
                ghost_common::error::GhostError::P2PMessage(e.to_string())
            })?;

        // Validate pixel array size
        if msg.pixels.len() != GLYPH_SIZE {
            warn!(
                got = msg.pixels.len(),
                expected = GLYPH_SIZE,
                "Rejecting glyph claim: invalid pixel array size"
            );
            return Ok(());
        }

        // Validate pixel values (all 0..25)
        let pixels: [u8; GLYPH_SIZE] = msg.pixels.as_slice().try_into().map_err(|_| {
            ghost_common::error::GhostError::P2PMessage("Invalid pixel array".to_string())
        })?;

        if GhostGlyph::validate_pixels(&pixels).is_err() {
            warn!(ghost_id = %msg.ghost_id, "Rejecting glyph claim: pixel values out of range");
            return Ok(());
        }

        // Verify commitment matches
        let expected_commitment =
            GhostGlyph::compute_commitment(&pixels, msg.ghost_id.as_bytes());
        if msg.commitment != expected_commitment {
            warn!(ghost_id = %msg.ghost_id, "Rejecting glyph claim: commitment mismatch");
            return Ok(());
        }

        // Verify bitmap hash matches
        let expected_bitmap_hash = GhostGlyph::compute_bitmap_hash(&pixels);
        if msg.bitmap_hash != expected_bitmap_hash {
            warn!(ghost_id = %msg.ghost_id, "Rejecting glyph claim: bitmap_hash mismatch");
            return Ok(());
        }

        // Check bitmap not already taken
        if let Ok(false) = self.db.is_bitmap_available(&msg.bitmap_hash) {
            debug!(ghost_id = %msg.ghost_id, "Glyph claim rejected: bitmap already taken");
            return Ok(());
        }

        // Check ghost_id not already claimed
        if let Ok(Some(_)) = self.db.get_glyph_by_ghost_id(&msg.ghost_id) {
            debug!(ghost_id = %msg.ghost_id, "Glyph claim rejected: ghost_id already has a glyph");
            return Ok(());
        }

        // Insert pending claim
        match self.db.insert_glyph_claim(
            &msg.ghost_id,
            &msg.pixels,
            &msg.bitmap_hash,
            &msg.commitment,
            msg.timestamp,
        ) {
            Ok(()) => {
                info!(ghost_id = %msg.ghost_id, "GhostGlyph claim accepted (pending funding)");
            }
            Err(e) => {
                // UNIQUE constraint violations are expected races — not errors
                if !e.to_string().contains("UNIQUE") && !e.to_string().contains("already") {
                    warn!(error = %e, ghost_id = %msg.ghost_id, "Failed to insert glyph claim");
                }
            }
        }

        Ok(())
    }

    async fn handle_registered(&self, envelope: &MessageEnvelope) -> GhostResult<()> {
        let msg: GhostGlyphRegisteredMessage =
            serde_json::from_slice(&envelope.payload).map_err(|e| {
                warn!(error = %e, "Failed to deserialize GhostGlyphRegisteredMessage");
                ghost_common::error::GhostError::P2PMessage(e.to_string())
            })?;

        // Verify ghost_id has a pending claim
        match self.db.get_glyph_by_ghost_id(&msg.ghost_id) {
            Ok(Some(record)) => {
                if record.funding_txid.is_some() {
                    // Already registered, idempotent
                    return Ok(());
                }
            }
            Ok(None) => {
                debug!(ghost_id = %msg.ghost_id, "Ignoring registration: no pending claim found");
                return Ok(());
            }
            Err(e) => {
                warn!(error = %e, ghost_id = %msg.ghost_id, "Failed to look up glyph claim");
                return Ok(());
            }
        }

        // Complete registration
        match self.db.complete_glyph_registration(
            &msg.ghost_id,
            &msg.funding_txid,
            msg.registered_at,
        ) {
            Ok(()) => {
                info!(
                    ghost_id = %msg.ghost_id,
                    txid = %msg.funding_txid,
                    "GhostGlyph registration confirmed via P2P"
                );
            }
            Err(e) => {
                warn!(
                    error = %e,
                    ghost_id = %msg.ghost_id,
                    "Failed to complete glyph registration from P2P"
                );
            }
        }

        Ok(())
    }
}

#[async_trait]
impl MessageHandler for GlyphRegistrationHandler {
    async fn handle_message(&self, envelope: Arc<MessageEnvelope>) -> GhostResult<()> {
        match envelope.msg_type {
            MessageType::GhostGlyphClaim => self.handle_claim(&envelope).await?,
            MessageType::GhostGlyphRegistered => self.handle_registered(&envelope).await?,
            _ => {}
        }
        Ok(())
    }
}
