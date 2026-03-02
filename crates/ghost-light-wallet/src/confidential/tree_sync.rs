//! Commitment tree synchronization with GSP
//!
//! Keeps the wallet's local commitment tree in sync with the server.
//! On connect, fetches the current tree state and owned notes.
//! During the session, processes push notifications for new transfers.

use tracing::{debug, info, warn};

use ghost_gsp_proto::{ClientMessage, ConfidentialNoteInfo};
use ghost_zkp::CommitmentTree;

use crate::error::{LightWalletError, WalletResult};
use crate::gsp::GspClient;

/// Commitment tree state from the server
#[derive(Debug, Clone)]
pub struct TreeState {
    /// Current merkle root (hex)
    pub root: String,
    /// Number of notes in tree
    pub note_count: u64,
    /// Next available index
    pub next_index: u64,
    /// Tree depth
    pub tree_depth: usize,
    /// Number of spent nullifiers
    pub nullifier_count: u64,
    /// Current epoch (increments after compaction)
    pub current_epoch: u64,
}

/// Server note info for owned notes
#[derive(Debug, Clone)]
pub struct ServerNote {
    /// Tree index
    pub index: u64,
    /// Commitment (hex)
    pub commitment: String,
    /// Block height when created
    pub created_height: u64,
    /// Whether spent
    pub spent: bool,
}

impl From<ConfidentialNoteInfo> for ServerNote {
    fn from(info: ConfidentialNoteInfo) -> Self {
        Self {
            index: info.index,
            commitment: info.commitment,
            created_height: info.created_height,
            spent: info.spent,
        }
    }
}

/// Result of checking for an epoch transition
#[derive(Debug, Clone)]
pub struct EpochCheck {
    /// Whether the epoch changed
    pub changed: bool,
    /// The server's current epoch
    pub server_epoch: u64,
}

/// Manages tree sync between wallet and server.
///
/// # Race Condition Warning
///
/// Tree synchronization is inherently susceptible to race conditions when
/// transfers occur during the sync process:
///
/// 1. **Initial sync**: The wallet fetches the tree state and owned notes from
///    the GSP server. If a transfer is finalized between the tree state fetch
///    and the notes fetch, the local tree may have a stale root that does not
///    reflect the latest notes.
///
/// 2. **Concurrent transfers**: If a transfer notification arrives via
///    `apply_received_transfer` while an initial sync is in progress, the
///    tree may contain duplicate or out-of-order insertions.
///
/// **Mitigation**: After initial sync, always call `verify_root()` to confirm
/// the local tree matches the server's root. If there is a mismatch, discard
/// the local tree and re-sync from scratch. The GSP server is the source of
/// truth for the commitment tree state.
pub struct TreeSync {
    /// The commitment tree depth
    tree_depth: usize,
}

impl TreeSync {
    /// Create a new tree sync manager
    pub fn new(tree_depth: usize) -> Self {
        Self { tree_depth }
    }

    /// Build a local commitment tree from server notes
    ///
    /// Called on initial sync to reconstruct the tree from known notes.
    pub fn build_tree_from_notes(&self, notes: &[ServerNote]) -> WalletResult<CommitmentTree> {
        let mut tree = CommitmentTree::new(self.tree_depth);

        for note in notes {
            let commitment = hex_to_32_bytes(&note.commitment)?;
            tree.insert(note.index, commitment);
        }

        info!(
            note_count = notes.len(),
            "Built local commitment tree from server notes"
        );

        Ok(tree)
    }

    /// Verify that the local tree root matches the server's root
    pub fn verify_root(tree: &CommitmentTree, expected_root_hex: &str) -> WalletResult<bool> {
        let local_root = tree.root().map_err(|e| {
            LightWalletError::Internal(format!("Failed to compute tree root: {}", e))
        })?;
        let local_root_hex = hex::encode(local_root);

        if local_root_hex == expected_root_hex {
            debug!("Tree root verified: {}", &local_root_hex[..16]);
            Ok(true)
        } else {
            warn!(
                local = &local_root_hex[..16],
                server = &expected_root_hex[..16.min(expected_root_hex.len())],
                "Tree root mismatch - resync needed"
            );
            Ok(false)
        }
    }

    /// Apply a received transfer notification to the local tree
    ///
    /// Called when the server pushes a `ConfidentialTransferReceived` message.
    pub fn apply_received_transfer(
        tree: &mut CommitmentTree,
        recipient_commitment_hex: &str,
        note_index: u64,
    ) -> WalletResult<()> {
        let commitment = hex_to_32_bytes(recipient_commitment_hex)?;
        tree.insert(note_index, commitment);

        debug!(
            index = note_index,
            "Applied received confidential transfer to local tree"
        );

        Ok(())
    }

    /// Request tree state from server via GSP client
    pub async fn fetch_tree_state(client: &GspClient) -> WalletResult<()> {
        client
            .send_confidential_message(ClientMessage::GetCommitmentTreeState)
            .await
    }

    /// Request owned notes from server via GSP client
    pub async fn fetch_notes(client: &GspClient, owner_pubkey: &str) -> WalletResult<()> {
        client
            .send_confidential_message(ClientMessage::GetConfidentialNotes {
                owner_pubkey: owner_pubkey.to_string(),
            })
            .await
    }

    /// Check if the server epoch differs from the wallet's epoch.
    ///
    /// If the epoch changed, the wallet must invalidate old-epoch notes and
    /// re-scan (compaction may have changed tree indices).
    pub fn check_epoch_transition(
        server_state: &TreeState,
        wallet_epoch: u64,
    ) -> EpochCheck {
        let changed = server_state.current_epoch > wallet_epoch;
        if changed {
            warn!(
                wallet_epoch,
                server_epoch = server_state.current_epoch,
                "Epoch transition detected — wallet needs re-scan"
            );
        }
        EpochCheck {
            changed,
            server_epoch: server_state.current_epoch,
        }
    }

    /// Subscribe to confidential transfer notifications
    pub async fn subscribe(client: &GspClient) -> WalletResult<()> {
        client
            .send_confidential_message(ClientMessage::SubscribeConfidential)
            .await
    }
}

/// Parse hex string to 32-byte array
fn hex_to_32_bytes(hex_str: &str) -> WalletResult<[u8; 32]> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| LightWalletError::Internal(format!("Invalid hex: {}", e)))?;
    if bytes.len() != 32 {
        return Err(LightWalletError::Internal(format!(
            "Expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_32_bytes() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let result = hex_to_32_bytes(hex).unwrap();
        assert_eq!(result[31], 1);
        assert_eq!(result[0], 0);
    }

    #[test]
    fn test_hex_to_32_bytes_invalid() {
        // Wrong length
        assert!(hex_to_32_bytes("0001").is_err());
        // Invalid hex
        assert!(hex_to_32_bytes("zzzz").is_err());
    }

    #[test]
    fn test_build_tree_from_notes() {
        let sync = TreeSync::new(4);
        let notes = vec![
            ServerNote {
                index: 0,
                commitment: "0000000000000000000000000000000000000000000000000000000000000001"
                    .to_string(),
                created_height: 100,
                spent: false,
            },
            ServerNote {
                index: 1,
                commitment: "0000000000000000000000000000000000000000000000000000000000000002"
                    .to_string(),
                created_height: 101,
                spent: false,
            },
        ];

        let tree = sync.build_tree_from_notes(&notes).unwrap();
        assert_eq!(tree.note_count(), 2);
        assert_eq!(tree.next_index(), 2);
    }

    #[test]
    fn test_verify_root() {
        let tree = CommitmentTree::new(4);
        let root = tree.root().unwrap();
        let root_hex = hex::encode(root);

        assert!(TreeSync::verify_root(&tree, &root_hex).unwrap());
        assert!(!TreeSync::verify_root(&tree, "ff".repeat(32).as_str()).unwrap());
    }

    #[test]
    fn test_apply_received_transfer() {
        let mut tree = CommitmentTree::new(4);
        let old_root = tree.root().unwrap();

        let commitment = "0000000000000000000000000000000000000000000000000000000000000042";
        TreeSync::apply_received_transfer(&mut tree, commitment, 0).unwrap();

        let new_root = tree.root().unwrap();
        assert_ne!(old_root, new_root, "Root should change after insert");
        assert_eq!(tree.note_count(), 1);
    }

    #[test]
    fn test_server_note_from_info() {
        let info = ConfidentialNoteInfo {
            index: 5,
            commitment: "aa".repeat(32),
            created_height: 200,
            spent: true,
        };
        let note: ServerNote = info.into();
        assert_eq!(note.index, 5);
        assert!(note.spent);
    }

    #[test]
    fn test_epoch_transition_detected() {
        let state = TreeState {
            root: "00".repeat(32),
            note_count: 10,
            next_index: 10,
            tree_depth: 20,
            nullifier_count: 2,
            current_epoch: 3,
        };

        let check = TreeSync::check_epoch_transition(&state, 1);
        assert!(check.changed);
        assert_eq!(check.server_epoch, 3);
    }

    #[test]
    fn test_no_epoch_transition() {
        let state = TreeState {
            root: "00".repeat(32),
            note_count: 10,
            next_index: 10,
            tree_depth: 20,
            nullifier_count: 2,
            current_epoch: 1,
        };

        let check = TreeSync::check_epoch_transition(&state, 1);
        assert!(!check.changed);
        assert_eq!(check.server_epoch, 1);
    }
}
