//! Client-side ZK proof generation for NoteSpend transfers
//!
//! The wallet generates Groth16 proofs locally because only the wallet
//! knows the note values and blinding factors. The server only sees
//! commitments and the zero-knowledge proof.
//!
//! `NoteSpendClientProver` wraps `GhostNoteProver` with a wallet-friendly API.

use ghost_common::constants::L2_TRANSFER_FEE_SATS;
use ghost_zkp::{
    CommitmentTree, GhostNoteProver, GhostNoteSpendProof, GhostNoteSpendWitness,
};

use std::path::Path;
use tracing::info;

use crate::confidential::notes::{NoteStore, OwnedNote};
use crate::error::{LightWalletError, WalletResult};

// =============================================================================
// NoteSpend Client Prover (Current — replaces ConfidentialTransfer)
// =============================================================================

/// Result of a NoteSpend proof generation
#[derive(Debug)]
pub struct NoteSpendTransferResult {
    /// The Groth16 proof with public inputs
    pub proof: GhostNoteSpendProof,
    /// Hex-encoded proof bytes for transmission
    pub proof_hex: String,
    /// Nullifier (hex) — deterministically routes to validator
    pub nullifier: String,
    /// Commitment root at time of spend (hex)
    pub commitment_root: String,
    /// Change commitment (hex) — sender's new note
    pub change_commitment: String,
    /// Recipient commitment (hex) — recipient's new note
    pub recipient_commitment: String,
    /// New note to add to local store (sender's change)
    pub change_note: OwnedNote,
    /// Epoch the proof was generated for
    pub epoch: u64,
    /// ECIES-encrypted change note data (for sender's wallet)
    pub encrypted_change: Vec<u8>,
    /// ECIES-encrypted recipient note data (for recipient's wallet)
    pub encrypted_recipient: Vec<u8>,
}

/// Client-side prover for NoteSpend transfers (current L2 system)
///
/// Wraps `GhostNoteProver` with wallet-friendly API. Load MPC params
/// via `from_params_file()` for production use.
pub struct NoteSpendClientProver {
    prover: GhostNoteProver,
}

impl NoteSpendClientProver {
    /// Load prover from MPC parameters file on disk (production)
    ///
    /// Reads and deserializes a `note_spend_params_current.bin` file.
    pub fn from_params_file(path: &Path, tree_depth: usize) -> WalletResult<Self> {
        use bellperson::groth16::Parameters;
        use blstrs::Bls12;
        use std::io::BufReader;
        use std::sync::Arc;

        let file = std::fs::File::open(path).map_err(|e| {
            LightWalletError::Internal(format!(
                "Failed to open NoteSpend params at {}: {}",
                path.display(),
                e
            ))
        })?;
        let reader = BufReader::new(file);
        let params: Parameters<Bls12> = Parameters::read(reader, false).map_err(|e| {
            LightWalletError::Internal(format!("Failed to deserialize NoteSpend params: {}", e))
        })?;

        Ok(Self {
            prover: GhostNoteProver::new_with_params(Arc::new(params), tree_depth),
        })
    }

    /// Create a prover with random Groth16 setup (TESTING ONLY)
    #[cfg(not(feature = "zk-production"))]
    pub fn new_with_setup(tree_depth: usize) -> WalletResult<Self> {
        let prover = GhostNoteProver::new_with_setup(tree_depth)
            .map_err(|e| LightWalletError::Internal(format!("ZK setup failed: {}", e)))?;
        Ok(Self { prover })
    }

    /// Get the prover ID (needed for verifier matching)
    pub fn prover_id(&self) -> [u8; 32] {
        self.prover.prover_id()
    }

    /// Check if Groth16 parameters are loaded
    pub fn has_params(&self) -> bool {
        self.prover.has_groth16_params()
    }

    /// Generate a NoteSpend proof for a transfer
    ///
    /// 1. Selects the sender note from NoteStore
    /// 2. Gets merkle path from CommitmentTree
    /// 3. Generates fresh random blindings for change + recipient notes
    /// 4. Builds GhostNoteSpendWitness and calls GhostNoteProver::prove()
    /// 5. Encrypts change note for sender and recipient note for recipient
    /// 6. Returns proof + encrypted note data for submission
    pub fn create_note_spend(
        &self,
        tree: &CommitmentTree,
        note_store: &NoteStore,
        sender_note_index: u64,
        amount: u64,
        epoch: u64,
        block_height: u64,
        sender_pubkey: &secp256k1::PublicKey,
        recipient_pubkey: &secp256k1::PublicKey,
    ) -> WalletResult<NoteSpendTransferResult> {
        // Look up sender note
        let sender_note = note_store.get_note(sender_note_index).ok_or_else(|| {
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

        let total_deduction = amount + L2_TRANSFER_FEE_SATS;
        if sender_note.value < total_deduction {
            return Err(LightWalletError::InsufficientBalance {
                required: total_deduction,
                available: sender_note.value,
            });
        }

        // Get merkle proof (siblings) for the sender note
        let merkle_proof = tree.get_proof(sender_note_index).map_err(|e| {
            LightWalletError::PaymentFailed(format!("Failed to get merkle proof: {}", e))
        })?;

        // Generate fresh random blindings for new notes
        let change_blinding = random_blinding()?;
        let recipient_blinding = random_blinding()?;

        // Build witness
        let witness = GhostNoteSpendWitness {
            spending_key: *note_store.spending_key(),
            note_value: sender_note.value,
            note_blinding: sender_note.blinding,
            note_index: sender_note_index,
            epoch,
            merkle_siblings: merkle_proof.siblings.clone(),
            amount,
            change_blinding,
            recipient_blinding,
        };

        // Generate proof
        let proof = self.prover.prove(&witness).map_err(|e| {
            LightWalletError::PaymentFailed(format!("Proof generation failed: {}", e))
        })?;

        info!(
            sender_index = sender_note_index,
            amount = amount,
            epoch = epoch,
            proof_size = proof.proof.len(),
            "NoteSpend proof generated"
        );

        // Build change note for local tracking (deduct fee)
        let change_value = sender_note.value - amount - L2_TRANSFER_FEE_SATS;
        let change_note = OwnedNote {
            index: sender_note_index, // Change reuses the sender's index (new commitment at same position)
            value: change_value,
            blinding: change_blinding,
            spent: false,
            created_height: block_height,
            epoch,
        };

        // Encrypt note data for sender (change) and recipient
        let encrypted_change = ghost_keys::NoteData {
            value: change_value,
            blinding: change_blinding,
            note_index: sender_note_index,
        }
        .encrypt(sender_pubkey)
        .map_err(|e| LightWalletError::Internal(format!("Change encryption failed: {}", e)))?;

        let encrypted_recipient = ghost_keys::NoteData {
            value: amount,
            blinding: recipient_blinding,
            note_index: sender_note_index, // Recipient note index is assigned by the validator
        }
        .encrypt(recipient_pubkey)
        .map_err(|e| {
            LightWalletError::Internal(format!("Recipient encryption failed: {}", e))
        })?;

        Ok(NoteSpendTransferResult {
            proof_hex: hex::encode(&proof.proof),
            nullifier: hex::encode(proof.public_inputs.nullifier),
            commitment_root: hex::encode(proof.public_inputs.commitment_root),
            change_commitment: hex::encode(proof.public_inputs.change_commitment),
            recipient_commitment: hex::encode(proof.public_inputs.recipient_commitment),
            change_note,
            epoch,
            proof,
            encrypted_change,
            encrypted_recipient,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::notes::NoteStore;

    /// Convert 32-byte array to BLS12-381 scalar field element
    fn bytes_to_fr(bytes: &[u8; 32]) -> WalletResult<blstrs::Scalar> {
        ghost_zkp::field_utils::bytes_to_field(bytes)
            .map_err(|e| LightWalletError::Internal(format!("Field conversion error: {}", e)))
    }

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

    fn test_keypair() -> (secp256k1::SecretKey, secp256k1::PublicKey) {
        let secp = secp256k1::Secp256k1::new();
        secp.generate_keypair(&mut rand::rngs::OsRng)
    }

    #[test]
    fn test_note_spend_client_prover_creation_with_setup() {
        let prover = NoteSpendClientProver::new_with_setup(4).unwrap();
        assert!(prover.has_params(), "Prover should have Groth16 params after setup");
        assert_ne!(prover.prover_id(), [0u8; 32], "Prover ID should be non-zero");
    }

    #[test]
    fn test_note_spend_create_proof_success() {
        let depth = 4;
        let spending_key = test_spending_key();
        let mut note_store = NoteStore::new(spending_key);

        // Insert sender note into commitment tree using the same blinding
        // that the note_store tracks (must match for proof generation)
        let sender_blinding = [1u8; 32];
        let sender_blinding_fr = bytes_to_fr(&sender_blinding).unwrap();

        let mut tree = CommitmentTree::new(depth);
        tree.insert_note(0, 1000, sender_blinding_fr);

        note_store.add_note(OwnedNote {
            index: 0,
            value: 1000,
            blinding: sender_blinding,
            spent: false,
            created_height: 100,
            epoch: 0,
        });

        let (_, sender_pubkey) = test_keypair();
        let (recipient_sk, recipient_pubkey) = test_keypair();

        let prover = NoteSpendClientProver::new_with_setup(depth).unwrap();
        let result = prover
            .create_note_spend(
                &tree,
                &note_store,
                0,   // sender_note_index
                300, // amount
                0,   // epoch
                101, // block_height
                &sender_pubkey,
                &recipient_pubkey,
            )
            .unwrap();

        // Verify result structure
        assert!(!result.proof_hex.is_empty());
        assert!(!result.nullifier.is_empty());
        assert!(!result.commitment_root.is_empty());
        assert!(!result.change_commitment.is_empty());
        assert!(!result.recipient_commitment.is_empty());

        // Change note should have correct value: 1000 - 300 - 10 (fee) = 690
        assert_eq!(result.change_note.value, 690);
        assert_eq!(result.change_note.index, 0);
        assert!(!result.change_note.spent);
        assert_eq!(result.epoch, 0);

        // Proof should be real Groth16 (192 bytes)
        assert!(result.proof.is_real_proof());

        // Encrypted fields should be 109 bytes (48-byte plaintext + 61-byte overhead)
        assert_eq!(result.encrypted_change.len(), 109);
        assert_eq!(result.encrypted_recipient.len(), 109);

        // Recipient should be able to decrypt their note
        let decrypted = ghost_keys::NoteData::decrypt(&recipient_sk, &result.encrypted_recipient).unwrap();
        assert_eq!(decrypted.value, 300);
    }

    #[test]
    fn test_note_spend_insufficient_balance() {
        let depth = 4;
        let spending_key = test_spending_key();
        let mut note_store = NoteStore::new(spending_key);

        let sender_blinding = [1u8; 32];
        let sender_blinding_fr = bytes_to_fr(&sender_blinding).unwrap();

        let mut tree = CommitmentTree::new(depth);
        tree.insert_note(0, 100, sender_blinding_fr);

        note_store.add_note(OwnedNote {
            index: 0,
            value: 100,
            blinding: sender_blinding,
            spent: false,
            created_height: 100,
            epoch: 0,
        });

        let (_, sender_pk) = test_keypair();
        let (_, recipient_pk) = test_keypair();

        let prover = NoteSpendClientProver::new_with_setup(depth).unwrap();
        let result = prover.create_note_spend(&tree, &note_store, 0, 200, 0, 101, &sender_pk, &recipient_pk);

        assert!(result.is_err(), "Should reject transfer exceeding note value");
        match result.unwrap_err() {
            LightWalletError::InsufficientBalance { required, available } => {
                assert_eq!(required, 210); // 200 + 10 fee
                assert_eq!(available, 100);
            }
            other => panic!("Expected InsufficientBalance, got: {:?}", other),
        }
    }

    #[test]
    fn test_note_spend_spent_note_rejected() {
        let depth = 4;
        let spending_key = test_spending_key();
        let mut note_store = NoteStore::new(spending_key);

        let sender_blinding = [1u8; 32];
        let sender_blinding_fr = bytes_to_fr(&sender_blinding).unwrap();

        let mut tree = CommitmentTree::new(depth);
        tree.insert_note(0, 1000, sender_blinding_fr);

        note_store.add_note(OwnedNote {
            index: 0,
            value: 1000,
            blinding: sender_blinding,
            spent: true, // already spent
            created_height: 100,
            epoch: 0,
        });

        let (_, sender_pk) = test_keypair();
        let (_, recipient_pk) = test_keypair();

        let prover = NoteSpendClientProver::new_with_setup(depth).unwrap();
        let result = prover.create_note_spend(&tree, &note_store, 0, 300, 0, 101, &sender_pk, &recipient_pk);

        assert!(result.is_err(), "Should reject already-spent notes");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("already-spent"));
    }

    #[test]
    fn test_note_spend_result_proof_hex_roundtrip() {
        let depth = 4;
        let spending_key = test_spending_key();
        let mut note_store = NoteStore::new(spending_key);

        let sender_blinding = [1u8; 32];
        let sender_blinding_fr = bytes_to_fr(&sender_blinding).unwrap();

        let mut tree = CommitmentTree::new(depth);
        tree.insert_note(0, 1000, sender_blinding_fr);

        note_store.add_note(OwnedNote {
            index: 0,
            value: 1000,
            blinding: sender_blinding,
            spent: false,
            created_height: 100,
            epoch: 0,
        });

        let (_, sender_pk) = test_keypair();
        let (_, recipient_pk) = test_keypair();

        let prover = NoteSpendClientProver::new_with_setup(depth).unwrap();
        let result = prover
            .create_note_spend(&tree, &note_store, 0, 300, 0, 101, &sender_pk, &recipient_pk)
            .unwrap();

        // proof_hex should decode back to the exact same proof bytes
        let decoded = hex::decode(&result.proof_hex).unwrap();
        assert_eq!(decoded, result.proof.proof, "proof_hex roundtrip must match proof bytes");
        assert_eq!(decoded.len(), 192, "Groth16 proof must be 192 bytes");
    }
}
