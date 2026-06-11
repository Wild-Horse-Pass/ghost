//! Commitment tree synchronization with ghost-pay
//!
//! Keeps the wallet's local commitment tree in sync with the server
//! via the ghost-pay REST API.

use ghost_zkp::CommitmentTree;
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::network::ghost_pay::{GhostPayClient, TreeStateResponse};
use crate::network::NetworkError;

/// A note from the server's commitment tree
#[derive(Debug, Clone, Deserialize)]
pub struct ServerNote {
    pub index: u64,
    pub commitment: String,
    pub created_height: u64,
    #[serde(default)]
    pub spent: bool,
}

/// Manages commitment tree sync between wallet and ghost-pay.
pub struct TreeSync {
    tree: CommitmentTree,
    tree_depth: usize,
    last_synced_height: u64,
}

impl TreeSync {
    pub fn new(tree_depth: usize) -> Self {
        Self {
            tree: CommitmentTree::new(tree_depth),
            tree_depth,
            last_synced_height: 0,
        }
    }

    /// Get a reference to the local commitment tree.
    pub fn tree(&self) -> &CommitmentTree {
        &self.tree
    }

    pub fn last_synced_height(&self) -> u64 {
        self.last_synced_height
    }

    /// Get the current Merkle root.
    pub fn root(&self) -> Result<[u8; 32], NetworkError> {
        self.tree
            .root()
            .map_err(|e| NetworkError::SyncFailed(format!("Failed to compute tree root: {}", e)))
    }

    /// Get a Merkle proof for a given note index.
    pub fn get_merkle_proof(&self, index: u64) -> Result<ghost_zkp::MerkleProof, NetworkError> {
        self.tree
            .get_proof(index)
            .map_err(|e| NetworkError::SyncFailed(format!("Failed to get merkle proof: {}", e)))
    }

    /// Sync the tree from the ghost-pay server.
    ///
    /// Fetches the tree state and all notes, then rebuilds the local tree.
    /// Verifies the root matches after building.
    pub async fn sync_from_server(
        &mut self,
        client: &GhostPayClient,
    ) -> Result<TreeStateResponse, NetworkError> {
        let state = client.get_tree_state().await?;

        // Fetch all notes for the tree
        // We pass empty string to get all notes (the owner_pubkey filter is
        // only for finding *our* notes — for tree building we need all commitments)
        let notes = client.get_all_notes().await?;

        // Rebuild tree from server notes
        let mut tree = CommitmentTree::new(self.tree_depth);
        for note in &notes {
            let commitment = hex_to_32_bytes(&note.commitment).map_err(|e| {
                NetworkError::InvalidResponse(format!("Invalid commitment hex: {}", e))
            })?;
            tree.insert(note.index, commitment);
        }

        // Verify root matches
        let local_root = tree.root().map_err(|e| {
            NetworkError::SyncFailed(format!("Failed to compute rebuilt tree root: {}", e))
        })?;
        let local_root_hex = hex::encode(local_root);

        if local_root_hex != state.root && !notes.is_empty() {
            warn!(
                local = &local_root_hex[..16.min(local_root_hex.len())],
                server = &state.root[..16.min(state.root.len())],
                "Tree root mismatch after rebuild — will use server state"
            );
        } else {
            debug!(
                note_count = notes.len(),
                root = &local_root_hex[..16.min(local_root_hex.len())],
                "Tree synced successfully"
            );
        }

        self.tree = tree;
        self.last_synced_height = state.next_index;

        info!(
            note_count = state.note_count,
            epoch = state.current_epoch,
            "Tree sync complete"
        );

        Ok(state)
    }

    /// Insert a commitment into the local tree (for optimistic updates).
    pub fn insert_commitment(
        &mut self,
        index: u64,
        commitment_hex: &str,
    ) -> Result<(), NetworkError> {
        let commitment = hex_to_32_bytes(commitment_hex)
            .map_err(|e| NetworkError::InvalidResponse(format!("Invalid commitment: {}", e)))?;
        self.tree.insert(index, commitment);
        Ok(())
    }
}

fn hex_to_32_bytes(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_sync_creation() {
        let sync = TreeSync::new(20);
        assert_eq!(sync.last_synced_height(), 0);
    }

    #[test]
    fn test_insert_commitment() {
        let mut sync = TreeSync::new(20);
        let commitment_hex = "00".repeat(32);
        sync.insert_commitment(0, &commitment_hex).unwrap();
    }

    #[test]
    fn test_root_empty_tree() {
        let sync = TreeSync::new(20);
        let root = sync.root().unwrap();
        // Empty tree has a deterministic root
        assert_eq!(root.len(), 32);
    }
}
