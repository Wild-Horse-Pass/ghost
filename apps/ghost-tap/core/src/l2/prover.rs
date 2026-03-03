//! Client-side ZK proof generation for L2 operations
//!
//! Wraps GhostNoteProver, GhostConsolidateProver, and GhostUnshieldProver
//! with wallet-friendly APIs.

use ghost_common::constants::L2_TRANSFER_FEE_SATS;
use ghost_zkp::{
    CommitmentTree, ConsolidationInputNote, ConsolidationWitness, GhostConsolidateProver,
    GhostNoteProver, GhostNoteSpendWitness, GhostUnshieldProver, UnshieldWitness,
};
use std::path::Path;
use std::sync::Arc;
use tracing::info;

use super::note_store::{NoteStore, OwnedNote};
use crate::network::NetworkError;

/// Result of a NoteSpend proof generation
#[derive(Debug)]
pub struct TransferResult {
    pub proof_hex: String,
    pub nullifier: String,
    pub commitment_root: String,
    pub change_commitment: String,
    pub recipient_commitment: String,
    pub change_note: OwnedNote,
    pub epoch: u64,
    pub encrypted_change: Vec<u8>,
    pub encrypted_recipient: Vec<u8>,
}

/// Result of a consolidation proof generation
#[derive(Debug)]
pub struct ConsolidationResult {
    pub proof_hex: String,
    pub commitment_root: String,
    pub nullifiers: Vec<String>,
    pub output_commitment: String,
    pub output_note: OwnedNote,
    pub epoch: u64,
    pub encrypted_output: Vec<u8>,
}

/// Result of an unshield proof generation
#[derive(Debug)]
pub struct UnshieldResult {
    pub proof_hex: String,
    pub commitment_root: String,
    pub nullifier: String,
    pub withdrawal_amount_sats: u64,
    pub epoch: u64,
}

/// Client-side prover for all L2 operations.
pub struct L2Prover {
    note_spend_prover: GhostNoteProver,
    consolidation_prover: GhostConsolidateProver,
    unshield_prover: GhostUnshieldProver,
}

impl L2Prover {
    /// Load all three provers from MPC parameter files on disk.
    ///
    /// Expected files in `params_dir`:
    /// - `note_spend_params_current.bin`
    /// - `consolidation_params_current.bin`
    /// - `unshield_params_current.bin`
    pub fn from_params_dir(params_dir: &Path, tree_depth: usize) -> Result<Self, NetworkError> {
        use bellperson::groth16::Parameters;
        use blstrs::Bls12;
        use std::io::BufReader;

        let load_params = |filename: &str| -> Result<Arc<Parameters<Bls12>>, NetworkError> {
            let path = params_dir.join(filename);
            let file = std::fs::File::open(&path).map_err(|e| {
                NetworkError::RequestFailed(format!(
                    "Failed to open params at {}: {}",
                    path.display(),
                    e
                ))
            })?;
            let reader = BufReader::new(file);
            let params: Parameters<Bls12> = Parameters::read(reader, false).map_err(|e| {
                NetworkError::RequestFailed(format!(
                    "Failed to deserialize params {}: {}",
                    filename, e
                ))
            })?;
            Ok(Arc::new(params))
        };

        let note_spend_params = load_params("note_spend_params_current.bin")?;
        let consolidation_params = load_params("consolidation_params_current.bin")?;
        let unshield_params = load_params("unshield_params_current.bin")?;

        Ok(Self {
            note_spend_prover: GhostNoteProver::new_with_params(note_spend_params, tree_depth),
            consolidation_prover: GhostConsolidateProver::new_with_params(
                consolidation_params,
                tree_depth,
            ),
            unshield_prover: GhostUnshieldProver::new_with_params(unshield_params, tree_depth),
        })
    }

    /// Create provers with random Groth16 setup (TESTING ONLY).
    #[cfg(test)]
    pub fn new_with_setup(tree_depth: usize) -> Result<Self, NetworkError> {
        let note_spend = GhostNoteProver::new_with_setup(tree_depth)
            .map_err(|e| NetworkError::RequestFailed(format!("NoteSpend setup failed: {}", e)))?;
        let consolidation = GhostConsolidateProver::new(tree_depth);
        let unshield = GhostUnshieldProver::new(tree_depth);

        Ok(Self {
            note_spend_prover: note_spend,
            consolidation_prover: consolidation,
            unshield_prover: unshield,
        })
    }

    /// Generate a NoteSpend proof for a transfer.
    #[allow(clippy::too_many_arguments)]
    pub fn create_transfer(
        &self,
        tree: &CommitmentTree,
        note_store: &NoteStore,
        sender_note_index: u64,
        amount: u64,
        epoch: u64,
        block_height: u64,
        sender_pubkey: &secp256k1::PublicKey,
        recipient_pubkey: &secp256k1::PublicKey,
    ) -> Result<TransferResult, NetworkError> {
        let sender_note = note_store.get_note(sender_note_index).ok_or_else(|| {
            NetworkError::RequestFailed(format!(
                "Note at index {} not found in local store",
                sender_note_index
            ))
        })?;

        if sender_note.spent {
            return Err(NetworkError::RequestFailed(
                "Cannot spend an already-spent note".into(),
            ));
        }

        let total_deduction = amount + L2_TRANSFER_FEE_SATS;
        if sender_note.value < total_deduction {
            return Err(NetworkError::RequestFailed(format!(
                "Insufficient note value: need {}, have {}",
                total_deduction, sender_note.value
            )));
        }

        let merkle_proof = tree.get_proof(sender_note_index).map_err(|e| {
            NetworkError::RequestFailed(format!("Failed to get merkle proof: {}", e))
        })?;

        let change_blinding = random_blinding()?;
        let recipient_blinding = random_blinding()?;

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

        let proof = self.note_spend_prover.prove(&witness).map_err(|e| {
            NetworkError::RequestFailed(format!("NoteSpend proof generation failed: {}", e))
        })?;

        let change_value = sender_note.value - amount - L2_TRANSFER_FEE_SATS;
        let change_note = OwnedNote {
            index: sender_note_index, // Will be updated by server
            value: change_value,
            blinding: change_blinding,
            spent: false,
            created_height: block_height,
            epoch,
        };

        let encrypted_change = ghost_keys::NoteData {
            value: change_value,
            blinding: change_blinding,
            note_index: sender_note_index,
        }
        .encrypt(sender_pubkey)
        .map_err(|e| NetworkError::RequestFailed(format!("Change encryption failed: {}", e)))?;

        let encrypted_recipient = ghost_keys::NoteData {
            value: amount,
            blinding: recipient_blinding,
            note_index: sender_note_index,
        }
        .encrypt(recipient_pubkey)
        .map_err(|e| {
            NetworkError::RequestFailed(format!("Recipient encryption failed: {}", e))
        })?;

        info!(
            sender_index = sender_note_index,
            amount,
            epoch,
            "NoteSpend proof generated"
        );

        Ok(TransferResult {
            proof_hex: hex::encode(&proof.proof),
            nullifier: hex::encode(proof.public_inputs.nullifier),
            commitment_root: hex::encode(proof.public_inputs.commitment_root),
            change_commitment: hex::encode(proof.public_inputs.change_commitment),
            recipient_commitment: hex::encode(proof.public_inputs.recipient_commitment),
            change_note,
            epoch,
            encrypted_change,
            encrypted_recipient,
        })
    }

    /// Generate a consolidation proof to merge up to 4 notes into 1.
    pub fn create_consolidation(
        &self,
        tree: &CommitmentTree,
        note_store: &NoteStore,
        note_indices: &[u64],
        epoch: u64,
        block_height: u64,
        owner_pubkey: &secp256k1::PublicKey,
    ) -> Result<ConsolidationResult, NetworkError> {
        if note_indices.is_empty() || note_indices.len() > 4 {
            return Err(NetworkError::RequestFailed(
                "Consolidation requires 1-4 input notes".into(),
            ));
        }

        let mut inputs = Vec::new();
        let mut total_value = 0u64;

        for &idx in note_indices {
            let note = note_store.get_note(idx).ok_or_else(|| {
                NetworkError::RequestFailed(format!("Note {} not found", idx))
            })?;
            if note.spent {
                return Err(NetworkError::RequestFailed(format!(
                    "Note {} is already spent",
                    idx
                )));
            }

            let proof = tree.get_proof(idx).map_err(|e| {
                NetworkError::RequestFailed(format!("Merkle proof failed for {}: {}", idx, e))
            })?;

            inputs.push(ConsolidationInputNote {
                value: note.value,
                blinding: note.blinding,
                index: idx,
                epoch,
                merkle_siblings: proof.siblings,
            });
            total_value += note.value;
        }

        let output_blinding = random_blinding()?;

        let witness = ConsolidationWitness {
            spending_key: *note_store.spending_key(),
            inputs,
            output_blinding,
        };

        let proof = self.consolidation_prover.prove(&witness).map_err(|e| {
            NetworkError::RequestFailed(format!("Consolidation proof failed: {}", e))
        })?;

        let nullifiers: Vec<String> = proof
            .public_inputs
            .nullifiers
            .iter()
            .map(hex::encode)
            .collect();

        let output_note = OwnedNote {
            index: 0, // Will be assigned by server
            value: total_value,
            blinding: output_blinding,
            spent: false,
            created_height: block_height,
            epoch,
        };

        let encrypted_output = ghost_keys::NoteData {
            value: total_value,
            blinding: output_blinding,
            note_index: 0,
        }
        .encrypt(owner_pubkey)
        .map_err(|e| NetworkError::RequestFailed(format!("Output encryption failed: {}", e)))?;

        info!(
            input_count = note_indices.len(),
            total_value,
            epoch,
            "Consolidation proof generated"
        );

        Ok(ConsolidationResult {
            proof_hex: hex::encode(&proof.proof),
            commitment_root: hex::encode(proof.public_inputs.commitment_root),
            nullifiers,
            output_commitment: hex::encode(proof.public_inputs.output_commitment),
            output_note,
            epoch,
            encrypted_output,
        })
    }

    /// Generate an unshield proof to withdraw a full note to L1.
    pub fn create_unshield(
        &self,
        tree: &CommitmentTree,
        note_store: &NoteStore,
        note_index: u64,
        epoch: u64,
    ) -> Result<UnshieldResult, NetworkError> {
        let note = note_store.get_note(note_index).ok_or_else(|| {
            NetworkError::RequestFailed(format!("Note {} not found", note_index))
        })?;

        if note.spent {
            return Err(NetworkError::RequestFailed(format!(
                "Note {} is already spent",
                note_index
            )));
        }

        let merkle_proof = tree.get_proof(note_index).map_err(|e| {
            NetworkError::RequestFailed(format!("Merkle proof failed: {}", e))
        })?;

        let witness = UnshieldWitness {
            spending_key: *note_store.spending_key(),
            note_value: note.value,
            note_blinding: note.blinding,
            note_index,
            epoch,
            merkle_siblings: merkle_proof.siblings,
        };

        let proof = self.unshield_prover.prove(&witness).map_err(|e| {
            NetworkError::RequestFailed(format!("Unshield proof failed: {}", e))
        })?;

        info!(
            note_index,
            withdrawal_amount = note.value,
            epoch,
            "Unshield proof generated"
        );

        Ok(UnshieldResult {
            proof_hex: hex::encode(&proof.proof),
            commitment_root: hex::encode(proof.public_inputs.commitment_root),
            nullifier: hex::encode(proof.public_inputs.nullifier),
            withdrawal_amount_sats: note.value,
            epoch,
        })
    }
}

/// Generate a random 32-byte blinding factor (BLS12-381 safe).
fn random_blinding() -> Result<[u8; 32], NetworkError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| NetworkError::RequestFailed(format!("RNG error: {}", e)))?;
    // Ensure valid BLS12-381 scalar
    bytes[31] &= 0x3F;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_blinding_is_valid() {
        let b = random_blinding().unwrap();
        // Top 2 bits should be cleared
        assert_eq!(b[31] & 0xC0, 0);
    }
}
