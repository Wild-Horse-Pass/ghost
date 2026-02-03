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
//| FILE: executor.rs                                                                                                    |
//|======================================================================================================================|

//! Wraith Transaction Executor
//!
//! Builds and manages the actual Bitcoin transactions for split and merge phases.

use bitcoin::absolute::LockTime;
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::transaction::Version;
use bitcoin::{
    opcodes, Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};
use std::str::FromStr;

use crate::denomination::WraithDenomination;
use crate::error::WraithError;
use crate::{SPLIT_RATIO, WRAITH_PHASE1_MARKER, WRAITH_PHASE2_MARKER};

/// Input UTXO for Wraith participation
#[derive(Debug, Clone)]
pub struct WraithInput {
    /// Transaction ID containing the UTXO
    pub txid: Txid,
    /// Output index
    pub vout: u32,
    /// Amount in satoshis
    pub amount: u64,
    /// Script pubkey (for validation)
    pub script_pubkey: ScriptBuf,
    /// Participant ID (index)
    pub participant_id: u32,
}

/// Output destination for Wraith transaction
#[derive(Debug, Clone)]
pub struct WraithOutput {
    /// Destination address
    pub address: String,
    /// Amount in satoshis
    pub amount: u64,
    /// Participant ID (index)
    pub participant_id: u32,
    /// Output index within participant's outputs
    pub output_index: u32,
}

/// Wraith transaction builder
#[derive(Debug)]
pub struct WraithTransactionBuilder {
    /// Session ID
    pub session_id: String,
    /// Denomination for this session
    pub denomination: WraithDenomination,
    /// Network (mainnet, testnet, etc.)
    pub network: Network,
    /// Collected inputs
    inputs: Vec<WraithInput>,
    /// Collected outputs (for merge phase)
    outputs: Vec<WraithOutput>,
    /// Fee rate in sat/vbyte
    fee_rate: u64,
}

impl WraithTransactionBuilder {
    /// Create a new transaction builder
    pub fn new(session_id: String, denomination: WraithDenomination, network: Network) -> Self {
        Self {
            session_id,
            denomination,
            network,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee_rate: 10, // Default 10 sat/vbyte
        }
    }

    /// Set fee rate
    pub fn with_fee_rate(mut self, fee_rate: u64) -> Self {
        self.fee_rate = fee_rate;
        self
    }

    /// Add an input UTXO
    pub fn add_input(&mut self, input: WraithInput) -> Result<(), WraithError> {
        // Validate input amount matches denomination
        let expected = self.denomination.input_sats();
        if input.amount < expected {
            return Err(WraithError::InvalidInput(format!(
                "Input amount {} too small, expected at least {}",
                input.amount, expected
            )));
        }
        self.inputs.push(input);
        Ok(())
    }

    /// Add an output destination (for merge phase)
    pub fn add_output(&mut self, output: WraithOutput) -> Result<(), WraithError> {
        self.outputs.push(output);
        Ok(())
    }

    /// Get participant count
    pub fn participant_count(&self) -> usize {
        self.inputs.len()
    }

    /// Build Phase 1 (Split) transaction with CSPRNG entropy
    ///
    /// Takes N inputs and creates 10N intermediate outputs.
    /// Each participant's input is split into 10 equal-sized intermediate Ghost Locks.
    ///
    /// This version uses CSPRNG entropy for unpredictable output ordering,
    /// enhancing privacy by preventing timing attacks on shuffle ordering.
    pub fn build_split_transaction_with_entropy(
        &self,
        intermediate_addresses: &[Vec<String>],
    ) -> Result<SplitTransaction, WraithError> {
        // Generate fresh CSPRNG entropy
        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy)
            .map_err(|e| WraithError::InvalidInput(format!("Failed to generate entropy: {}", e)))?;

        self.build_split_transaction_internal(intermediate_addresses, &entropy)
    }

    /// Build Phase 1 (Split) transaction
    ///
    /// Takes N inputs and creates 10N intermediate outputs.
    /// Each participant's input is split into 10 equal-sized intermediate Ghost Locks.
    ///
    /// Note: For production use, prefer `build_split_transaction_with_entropy()` which
    /// adds CSPRNG randomness to prevent predictable output ordering.
    pub fn build_split_transaction(
        &self,
        intermediate_addresses: &[Vec<String>], // [participant_id][output_index]
    ) -> Result<SplitTransaction, WraithError> {
        self.build_split_transaction_internal(intermediate_addresses, &[0u8; 32])
    }

    /// Internal implementation of split transaction building
    fn build_split_transaction_internal(
        &self,
        intermediate_addresses: &[Vec<String>],
        entropy: &[u8; 32],
    ) -> Result<SplitTransaction, WraithError> {
        if self.inputs.is_empty() {
            return Err(WraithError::NotEnoughParticipants(0, 1));
        }

        // Validate we have addresses for all participants
        if intermediate_addresses.len() != self.inputs.len() {
            return Err(WraithError::InvalidInput(format!(
                "Expected {} address sets, got {}",
                self.inputs.len(),
                intermediate_addresses.len()
            )));
        }

        // Each participant needs SPLIT_RATIO intermediate addresses
        for (i, addrs) in intermediate_addresses.iter().enumerate() {
            if addrs.len() != SPLIT_RATIO {
                return Err(WraithError::InvalidInput(format!(
                    "Participant {} needs {} addresses, got {}",
                    i,
                    SPLIT_RATIO,
                    addrs.len()
                )));
            }
        }

        let intermediate_amount = self.denomination.intermediate_sats();
        let mut tx_inputs = Vec::new();
        let mut tx_outputs = Vec::new();

        // Create inputs
        for input in &self.inputs {
            tx_inputs.push(TxIn {
                previous_output: OutPoint {
                    txid: input.txid,
                    vout: input.vout,
                },
                script_sig: ScriptBuf::new(), // Will be filled by signing
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(), // Will be filled by signing
            });
        }

        // Create outputs - 10 per participant, shuffled
        // Note: In production, outputs should be shuffled to break linkability
        let mut all_outputs: Vec<(usize, usize, &str)> = Vec::new();
        for (p_idx, addrs) in intermediate_addresses.iter().enumerate() {
            for (o_idx, addr) in addrs.iter().enumerate() {
                all_outputs.push((p_idx, o_idx, addr));
            }
        }

        // Shuffle outputs using session_id combined with entropy for unpredictability
        let seed = self.session_shuffle_seed_with_entropy(entropy);
        shuffle_outputs(&mut all_outputs, seed);

        // Create TxOut for each intermediate
        for (_p_idx, _o_idx, addr_str) in &all_outputs {
            let address = Address::from_str(addr_str)
                .map_err(|e| WraithError::InvalidInput(format!("Invalid address: {}", e)))?
                .require_network(self.network)
                .map_err(|e| WraithError::InvalidInput(format!("Network mismatch: {}", e)))?;

            tx_outputs.push(TxOut {
                value: Amount::from_sat(intermediate_amount),
                script_pubkey: address.script_pubkey(),
            });
        }

        // Add OP_RETURN marker
        let op_return_data = self.build_phase1_op_return();
        let op_return_script = build_op_return_script(&op_return_data);
        tx_outputs.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: op_return_script,
        });

        // Calculate fee (estimate based on typical P2TR tx size)
        let estimated_vsize = self.estimate_split_vsize();
        let fee = estimated_vsize * self.fee_rate;

        // Collect change (fees come from inputs, any remainder goes to fee)
        let total_in: u64 = self.inputs.iter().map(|i| i.amount).sum();
        let total_out: u64 = tx_outputs.iter().map(|o| o.value.to_sat()).sum();
        let implicit_fee = total_in.saturating_sub(total_out);

        if implicit_fee < fee {
            return Err(WraithError::InsufficientFee(fee, implicit_fee));
        }

        let transaction = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: tx_inputs,
            output: tx_outputs,
        };

        Ok(SplitTransaction {
            transaction,
            session_id: self.session_id.clone(),
            participant_count: self.inputs.len(),
            intermediate_count: self.inputs.len() * SPLIT_RATIO,
            fee_sats: implicit_fee,
        })
    }

    /// Build Phase 2 (Merge) transaction with CSPRNG entropy
    ///
    /// Takes 10N intermediate inputs and creates N final outputs.
    /// Each participant's 10 intermediates are merged into 1 final Ghost Lock.
    ///
    /// This version uses CSPRNG entropy for unpredictable ordering.
    pub fn build_merge_transaction_with_entropy(
        &self,
        intermediate_inputs: &[Vec<WraithInput>],
        final_addresses: &[String],
    ) -> Result<MergeTransaction, WraithError> {
        // Generate fresh CSPRNG entropy
        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy)
            .map_err(|e| WraithError::InvalidInput(format!("Failed to generate entropy: {}", e)))?;

        self.build_merge_transaction_internal(intermediate_inputs, final_addresses, &entropy)
    }

    /// Build Phase 2 (Merge) transaction
    ///
    /// Takes 10N intermediate inputs and creates N final outputs.
    /// Each participant's 10 intermediates are merged into 1 final Ghost Lock.
    ///
    /// Note: For production use, prefer `build_merge_transaction_with_entropy()` which
    /// adds CSPRNG randomness to prevent predictable ordering.
    pub fn build_merge_transaction(
        &self,
        intermediate_inputs: &[Vec<WraithInput>], // [participant_id][input_index]
        final_addresses: &[String],               // [participant_id]
    ) -> Result<MergeTransaction, WraithError> {
        self.build_merge_transaction_internal(intermediate_inputs, final_addresses, &[0u8; 32])
    }

    /// Internal implementation of merge transaction building
    fn build_merge_transaction_internal(
        &self,
        intermediate_inputs: &[Vec<WraithInput>],
        final_addresses: &[String],
        entropy: &[u8; 32],
    ) -> Result<MergeTransaction, WraithError> {
        if intermediate_inputs.is_empty() {
            return Err(WraithError::NotEnoughParticipants(0, 1));
        }

        // Validate counts
        if intermediate_inputs.len() != final_addresses.len() {
            return Err(WraithError::InvalidInput(format!(
                "Participant count mismatch: {} inputs vs {} addresses",
                intermediate_inputs.len(),
                final_addresses.len()
            )));
        }

        // Each participant should have SPLIT_RATIO inputs
        for (i, inputs) in intermediate_inputs.iter().enumerate() {
            if inputs.len() != SPLIT_RATIO {
                return Err(WraithError::InvalidInput(format!(
                    "Participant {} needs {} inputs, got {}",
                    i,
                    SPLIT_RATIO,
                    inputs.len()
                )));
            }
        }

        let output_amount = self.denomination.output_sats();
        let mut tx_inputs = Vec::new();
        let mut tx_outputs = Vec::new();

        // Collect all inputs (shuffled)
        let mut all_inputs: Vec<(usize, &WraithInput)> = Vec::new();
        for (p_idx, inputs) in intermediate_inputs.iter().enumerate() {
            for input in inputs {
                all_inputs.push((p_idx, input));
            }
        }

        // Shuffle inputs using session_id combined with entropy
        let seed = self.session_shuffle_seed_with_entropy(entropy).wrapping_add(1);
        shuffle_inputs(&mut all_inputs, seed);

        // Create TxIn for each intermediate
        for (_p_idx, input) in &all_inputs {
            tx_inputs.push(TxIn {
                previous_output: OutPoint {
                    txid: input.txid,
                    vout: input.vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            });
        }

        // Shuffle output order too
        let mut output_indices: Vec<usize> = (0..final_addresses.len()).collect();
        shuffle_indices(&mut output_indices, seed.wrapping_add(2));

        // Create outputs (one per participant)
        for &idx in &output_indices {
            let addr_str = &final_addresses[idx];
            let address = Address::from_str(addr_str)
                .map_err(|e| WraithError::InvalidInput(format!("Invalid address: {}", e)))?
                .require_network(self.network)
                .map_err(|e| WraithError::InvalidInput(format!("Network mismatch: {}", e)))?;

            tx_outputs.push(TxOut {
                value: Amount::from_sat(output_amount),
                script_pubkey: address.script_pubkey(),
            });
        }

        // Add OP_RETURN marker
        let op_return_data = self.build_phase2_op_return();
        let op_return_script = build_op_return_script(&op_return_data);
        tx_outputs.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: op_return_script,
        });

        // Calculate fee
        let total_in: u64 = all_inputs.iter().map(|(_, i)| i.amount).sum();
        let total_out: u64 = tx_outputs.iter().map(|o| o.value.to_sat()).sum();
        let implicit_fee = total_in.saturating_sub(total_out);

        let transaction = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: tx_inputs,
            output: tx_outputs,
        };

        Ok(MergeTransaction {
            transaction,
            session_id: self.session_id.clone(),
            participant_count: final_addresses.len(),
            fee_sats: implicit_fee,
        })
    }

    /// Build OP_RETURN data for Phase 1
    fn build_phase1_op_return(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(WRAITH_PHASE1_MARKER);
        // Add session ID hash (first 8 bytes)
        let session_hash = sha256_first_8(&self.session_id);
        data.extend_from_slice(&session_hash);
        // Add participant count (2 bytes)
        data.extend_from_slice(&(self.inputs.len() as u16).to_le_bytes());
        data
    }

    /// Build OP_RETURN data for Phase 2
    fn build_phase2_op_return(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(WRAITH_PHASE2_MARKER);
        // Add session ID hash (first 8 bytes)
        let session_hash = sha256_first_8(&self.session_id);
        data.extend_from_slice(&session_hash);
        // Add participant count (2 bytes)
        data.extend_from_slice(&(self.inputs.len() as u16).to_le_bytes());
        data
    }

    /// Generate shuffle seed from session ID and optional entropy
    ///
    /// The entropy parameter adds CSPRNG randomness to the shuffle seed,
    /// making it impossible to predict output ordering even knowing the session ID.
    /// This enhances privacy by preventing timing attacks on shuffle ordering.
    fn session_shuffle_seed(&self) -> u64 {
        self.session_shuffle_seed_with_entropy(&[0u8; 32])
    }

    /// Generate shuffle seed with explicit entropy
    ///
    /// Combines the session ID with additional entropy (from CSPRNG) to create
    /// an unpredictable shuffle seed. The entropy should be generated fresh
    /// for each phase transaction using `rand::thread_rng()`.
    fn session_shuffle_seed_with_entropy(&self, entropy: &[u8; 32]) -> u64 {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.session_id.as_bytes());
        hasher.update(entropy);
        let hash = hasher.finalize();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash[..8]);
        u64::from_le_bytes(bytes)
    }

    /// Estimate vsize for split transaction
    fn estimate_split_vsize(&self) -> u64 {
        // P2TR input: ~58 vbytes
        // P2TR output: ~43 vbytes
        // OP_RETURN: ~12 vbytes
        // Overhead: ~10 vbytes
        let input_vsize = self.inputs.len() as u64 * 58;
        let output_vsize = (self.inputs.len() * SPLIT_RATIO) as u64 * 43;
        let op_return_vsize = 12;
        let overhead = 10;
        input_vsize + output_vsize + op_return_vsize + overhead
    }
}

/// Result of building a split transaction
#[derive(Debug)]
pub struct SplitTransaction {
    /// The unsigned transaction
    pub transaction: Transaction,
    /// Session ID
    pub session_id: String,
    /// Number of participants
    pub participant_count: usize,
    /// Number of intermediate outputs
    pub intermediate_count: usize,
    /// Fee in satoshis
    pub fee_sats: u64,
}

impl SplitTransaction {
    /// Get the transaction ID (for unsigned tx, this will change after signing)
    pub fn txid(&self) -> Txid {
        self.transaction.compute_txid()
    }
}

/// Result of building a merge transaction
#[derive(Debug)]
pub struct MergeTransaction {
    /// The unsigned transaction
    pub transaction: Transaction,
    /// Session ID
    pub session_id: String,
    /// Number of participants
    pub participant_count: usize,
    /// Fee in satoshis
    pub fee_sats: u64,
}

impl MergeTransaction {
    /// Get the transaction ID
    pub fn txid(&self) -> Txid {
        self.transaction.compute_txid()
    }
}

/// SHA256 hash, return first 8 bytes
fn sha256_first_8(data: &str) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(data.as_bytes());
    let mut result = [0u8; 8];
    result.copy_from_slice(&hash[..8]);
    result
}

/// Build OP_RETURN script from data
fn build_op_return_script(data: &[u8]) -> ScriptBuf {
    let mut push_bytes = PushBytesBuf::new();
    // PushBytesBuf has a limit, but OP_RETURN data should be under 80 bytes
    for &byte in data.iter().take(80) {
        push_bytes.push(byte).ok();
    }
    Builder::new()
        .push_opcode(opcodes::all::OP_RETURN)
        .push_slice(push_bytes.as_push_bytes())
        .into_script()
}

/// Deterministic shuffle for outputs (Fisher-Yates with seeded RNG)
fn shuffle_outputs(items: &mut [(usize, usize, &str)], seed: u64) {
    let mut rng_state = seed;
    for i in (1..items.len()).rev() {
        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let j = (rng_state as usize) % (i + 1);
        items.swap(i, j);
    }
}

/// Deterministic shuffle for inputs
fn shuffle_inputs(items: &mut [(usize, &WraithInput)], seed: u64) {
    let mut rng_state = seed;
    for i in (1..items.len()).rev() {
        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let j = (rng_state as usize) % (i + 1);
        items.swap(i, j);
    }
}

/// Deterministic shuffle for indices
fn shuffle_indices(items: &mut [usize], seed: u64) {
    let mut rng_state = seed;
    for i in (1..items.len()).rev() {
        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let j = (rng_state as usize) % (i + 1);
        items.swap(i, j);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_txid() -> Txid {
        Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap()
    }

    #[test]
    fn test_builder_creation() {
        let builder = WraithTransactionBuilder::new(
            "session123".to_string(),
            WraithDenomination::Small,
            Network::Regtest,
        );
        assert_eq!(builder.participant_count(), 0);
    }

    #[test]
    fn test_add_input() {
        let mut builder = WraithTransactionBuilder::new(
            "session123".to_string(),
            WraithDenomination::Small,
            Network::Regtest,
        );

        let input = WraithInput {
            txid: test_txid(),
            vout: 0,
            amount: 1_010_000, // Small denomination input
            script_pubkey: ScriptBuf::new(),
            participant_id: 0,
        };

        builder.add_input(input).unwrap();
        assert_eq!(builder.participant_count(), 1);
    }

    #[test]
    fn test_input_amount_validation() {
        let mut builder = WraithTransactionBuilder::new(
            "session123".to_string(),
            WraithDenomination::Small,
            Network::Regtest,
        );

        let input = WraithInput {
            txid: test_txid(),
            vout: 0,
            amount: 100_000, // Too small
            script_pubkey: ScriptBuf::new(),
            participant_id: 0,
        };

        assert!(builder.add_input(input).is_err());
    }

    #[test]
    fn test_shuffle_determinism() {
        let mut items1 = vec![(0, 0, "a"), (1, 0, "b"), (2, 0, "c")];
        let mut items2 = vec![(0, 0, "a"), (1, 0, "b"), (2, 0, "c")];

        shuffle_outputs(&mut items1, 12345);
        shuffle_outputs(&mut items2, 12345);

        assert_eq!(items1, items2);
    }

    #[test]
    fn test_op_return_data() {
        let builder = WraithTransactionBuilder::new(
            "session123".to_string(),
            WraithDenomination::Small,
            Network::Regtest,
        );

        let data = builder.build_phase1_op_return();
        assert!(data.starts_with(WRAITH_PHASE1_MARKER));
        assert!(data.len() <= 80); // OP_RETURN limit
    }
}
