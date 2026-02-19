//! Client-side ZK proof generation for confidential transfers
//!
//! The wallet generates Groth16 proofs locally because only the wallet
//! knows the note values and blinding factors. The server only sees
//! commitments and the zero-knowledge proof.

use tracing::info;

use ghost_zkp::{
    CommitmentTree, ConfidentialProver as ZkProver, ConfidentialTransferProof,
};

use crate::confidential::notes::{NoteStore, OwnedNote};
use crate::error::{LightWalletError, WalletResult};

/// Result of creating a confidential transfer proof
#[derive(Debug)]
pub struct ConfidentialTransferResult {
    /// The Groth16 proof and public inputs
    pub proof: ConfidentialTransferProof,
    /// Hex-encoded proof bytes for transmission
    pub proof_hex: String,
    /// Old commitment tree root (hex)
    pub old_commitment_root: String,
    /// New commitment tree root (hex)
    pub new_commitment_root: String,
    /// Nullifier (hex)
    pub nullifier: String,
    /// Sender's new commitment (hex)
    pub sender_new_commitment: String,
    /// Recipient's new commitment (hex)
    pub recipient_new_commitment: String,
    /// Sender's tree index
    pub sender_index: u64,
    /// Recipient's tree index
    pub recipient_index: u64,
    /// New note to add to local store (sender's change)
    pub change_note: OwnedNote,
}

/// Client-side prover for confidential transfers
pub struct ClientProver {
    /// The ZK prover (holds Groth16 params)
    prover: ZkProver,
}

impl ClientProver {
    /// Create a new client prover for the given tree depth
    ///
    /// Note: This creates a prover without Groth16 parameters.
    /// For proof generation, use `new_with_setup()` (test/dev) or provide
    /// MPC-generated parameters.
    pub fn new(tree_depth: usize) -> Self {
        Self {
            prover: ZkProver::new(tree_depth),
        }
    }

    /// Create a client prover with random Groth16 setup (TESTING ONLY)
    ///
    /// Generates random trusted setup parameters. This is insecure for
    /// production but allows local proof generation during development.
    #[cfg(not(feature = "zk-production"))]
    pub fn new_with_setup(tree_depth: usize) -> WalletResult<Self> {
        let prover = ZkProver::new_with_setup(tree_depth).map_err(|e| {
            LightWalletError::Internal(format!("ZK setup failed: {}", e))
        })?;
        Ok(Self { prover })
    }

    /// Create a transfer proof
    ///
    /// This:
    /// 1. Looks up the sender note from the NoteStore
    /// 2. Generates fresh random blindings for new notes
    /// 3. Calls CommitmentTree::apply_transfer() to get witness data
    /// 4. Calls the ZK prover to generate a Groth16 proof
    /// 5. Returns proof + metadata for submission
    #[allow(clippy::too_many_arguments)]
    pub fn create_transfer(
        &self,
        tree: &mut CommitmentTree,
        note_store: &NoteStore,
        sender_note_index: u64,
        amount: u64,
        recipient_index: u64,
        recipient_old_value: u64,
        recipient_old_blinding: [u8; 32],
        block_height: u64,
    ) -> WalletResult<ConfidentialTransferResult> {
        // Look up sender note
        let sender_note = note_store
            .get_note(sender_note_index)
            .ok_or_else(|| {
                LightWalletError::PaymentFailed(format!(
                    "Note at index {} not found in local store",
                    sender_note_index
                ))
            })?;

        if sender_note.spent {
            return Err(LightWalletError::PaymentFailed(
                "Cannot spend an already-spent note".to_string(),
            ));
        }

        if sender_note.value < amount {
            return Err(LightWalletError::InsufficientBalance {
                required: amount,
                available: sender_note.value,
            });
        }

        // Generate fresh random blindings
        let sender_new_blinding = random_blinding()?;
        let recipient_new_blinding = random_blinding()?;

        // Convert byte arrays to field elements for CommitmentTree
        let sender_blinding_fr = bytes_to_fr(&sender_note.blinding)?;
        let spending_key_fr = bytes_to_fr(note_store.spending_key())?;
        let sender_new_blinding_fr = bytes_to_fr(&sender_new_blinding)?;
        let recipient_old_blinding_fr = bytes_to_fr(&recipient_old_blinding)?;
        let recipient_new_blinding_fr = bytes_to_fr(&recipient_new_blinding)?;

        // Get old root before transfer
        let old_root = tree.root().map_err(|e| {
            LightWalletError::Internal(format!("Failed to compute tree root: {}", e))
        })?;

        // Apply transfer to tree (generates witness + updates tree state)
        let witness = tree
            .apply_transfer(
                sender_note_index,
                sender_note.value,
                sender_blinding_fr,
                spending_key_fr,
                amount,
                sender_new_blinding_fr,
                recipient_index,
                recipient_old_value,
                recipient_old_blinding_fr,
                recipient_new_blinding_fr,
            )
            .map_err(|e| {
                LightWalletError::PaymentFailed(format!("Transfer failed: {}", e))
            })?;

        // Get new root after transfer
        let new_root = tree.root().map_err(|e| {
            LightWalletError::Internal(format!("Failed to compute new tree root: {}", e))
        })?;

        // Generate ZK proof
        let proof = self.prover.prove(&witness).map_err(|e| {
            LightWalletError::PaymentFailed(format!("Proof generation failed: {}", e))
        })?;

        info!(
            sender_index = sender_note_index,
            recipient_index = recipient_index,
            proof_size = proof.proof.len(),
            "Confidential transfer proof generated"
        );

        // Build change note for local tracking
        let change_note = OwnedNote {
            index: sender_note_index,
            value: sender_note.value - amount,
            blinding: sender_new_blinding,
            spent: false,
            created_height: block_height,
        };

        Ok(ConfidentialTransferResult {
            proof_hex: hex::encode(&proof.proof),
            old_commitment_root: hex::encode(old_root),
            new_commitment_root: hex::encode(new_root),
            nullifier: hex::encode(proof.public_inputs.nullifier),
            sender_new_commitment: hex::encode(proof.public_inputs.sender_new_commitment),
            recipient_new_commitment: hex::encode(proof.public_inputs.recipient_new_commitment),
            sender_index: sender_note_index,
            recipient_index,
            change_note,
            proof,
        })
    }
}

/// Generate a random 32-byte blinding factor
fn random_blinding() -> WalletResult<[u8; 32]> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| LightWalletError::Internal(format!("RNG error: {}", e)))?;
    // Ensure the value is within the BLS12-381 scalar field by zeroing the top byte
    // (field modulus is ~255 bits, so clearing top bit is sufficient)
    bytes[31] &= 0x3F;
    Ok(bytes)
}

/// Convert 32-byte array to BLS12-381 scalar field element
fn bytes_to_fr(bytes: &[u8; 32]) -> WalletResult<blstrs::Scalar> {
    ghost_zkp::field_utils::bytes_to_field(bytes)
        .map_err(|e| LightWalletError::Internal(format!("Field conversion error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::notes::NoteStore;

    fn test_spending_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0] = 42;
        key[31] &= 0x3F; // Ensure valid field element
        key
    }

    #[test]
    fn test_random_blinding() {
        let b1 = random_blinding().unwrap();
        let b2 = random_blinding().unwrap();
        assert_ne!(b1, b2, "Random blindings should differ");
        assert_eq!(b1[31] & 0xC0, 0, "Top 2 bits should be cleared");
    }

    #[test]
    fn test_client_prover_creation() {
        let prover = ClientProver::new(4);
        assert_eq!(prover.prover.tree_depth(), 4);
    }

    #[test]
    fn test_create_transfer_with_groth16() {
        let depth = 4;
        let spending_key = test_spending_key();
        let mut note_store = NoteStore::new(spending_key);

        // Create initial notes in tree
        let sender_blinding = [1u8; 32];
        let recipient_old_blinding = [2u8; 32];
        let sender_blinding_fr = bytes_to_fr(&sender_blinding).unwrap();
        let recipient_blinding_fr = bytes_to_fr(&recipient_old_blinding).unwrap();

        let mut tree = CommitmentTree::new(depth);
        tree.insert_note(0, 1000, sender_blinding_fr);
        tree.insert_note(1, 500, recipient_blinding_fr);

        // Add sender note to store
        note_store.add_note(OwnedNote {
            index: 0,
            value: 1000,
            blinding: sender_blinding,
            spent: false,
            created_height: 100,
        });

        let prover = ClientProver::new_with_setup(depth).unwrap();
        let result = prover
            .create_transfer(
                &mut tree,
                &note_store,
                0,    // sender_note_index
                300,  // amount
                1,    // recipient_index
                500,  // recipient_old_value
                recipient_old_blinding,
                101,  // block_height
            )
            .unwrap();

        // Verify result
        assert!(!result.proof_hex.is_empty());
        assert!(!result.old_commitment_root.is_empty());
        assert!(!result.new_commitment_root.is_empty());
        assert_ne!(result.old_commitment_root, result.new_commitment_root);
        assert!(!result.nullifier.is_empty());
        assert_eq!(result.sender_index, 0);
        assert_eq!(result.recipient_index, 1);

        // Change note should have correct value
        assert_eq!(result.change_note.value, 700); // 1000 - 300
        assert_eq!(result.change_note.index, 0);
        assert!(!result.change_note.spent);

        // Proof should be real Groth16 (192 bytes)
        assert!(result.proof.is_real_proof());
    }

    #[test]
    fn test_create_transfer_insufficient_balance() {
        let depth = 4;
        let spending_key = test_spending_key();
        let mut note_store = NoteStore::new(spending_key);

        let sender_blinding = [1u8; 32];
        let sender_blinding_fr = bytes_to_fr(&sender_blinding).unwrap();

        let mut tree = CommitmentTree::new(depth);
        tree.insert_note(0, 100, sender_blinding_fr);
        tree.insert_note(1, 0, blstrs::Scalar::from(0u64));

        note_store.add_note(OwnedNote {
            index: 0,
            value: 100,
            blinding: sender_blinding,
            spent: false,
            created_height: 100,
        });

        let prover = ClientProver::new(depth);
        let result = prover.create_transfer(
            &mut tree,
            &note_store,
            0,
            200, // more than sender has
            1,
            0,
            [0u8; 32],
            101,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_create_transfer_spent_note_rejected() {
        let depth = 4;
        let spending_key = test_spending_key();
        let mut note_store = NoteStore::new(spending_key);

        let sender_blinding = [1u8; 32];
        let sender_blinding_fr = bytes_to_fr(&sender_blinding).unwrap();

        let mut tree = CommitmentTree::new(depth);
        tree.insert_note(0, 1000, sender_blinding_fr);
        tree.insert_note(1, 0, blstrs::Scalar::from(0u64));

        note_store.add_note(OwnedNote {
            index: 0,
            value: 1000,
            blinding: sender_blinding,
            spent: true, // already spent
            created_height: 100,
        });

        let prover = ClientProver::new(depth);
        let result = prover.create_transfer(
            &mut tree,
            &note_store,
            0,
            300,
            1,
            0,
            [0u8; 32],
            101,
        );

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("already-spent"));
    }
}
