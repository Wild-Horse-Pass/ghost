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

//! Batch Executor - Orchestrates L1 Settlement
//!
//! Manages the complete lifecycle of settlement batches from collection
//! through L1 commitment and finalization.

use std::collections::HashMap;

use bitcoin::{Network, OutPoint, Txid};

use crate::batch::{Batch, BatchState};
use crate::commitment::L1Commitment;
use crate::error::ReconciliationError;
use crate::rules::BatchRules;
use crate::settlement::Settlement;
use crate::transaction::{ReconciliationTx, TxOutput};
use crate::{DISPUTE_WINDOW_BLOCKS, MAX_BATCH_SIZE, MIN_BATCH_SIZE};

/// Input UTXO for reconciliation
#[derive(Debug, Clone)]
pub struct ReconciliationInput {
    /// Transaction ID
    pub txid: Txid,
    /// Output index
    pub vout: u32,
    /// Amount in satoshis
    pub amount: u64,
    /// Owner's ghost ID
    pub ghost_id: String,
    /// Lock ID (if from Ghost Lock)
    pub lock_id: Option<[u8; 32]>,
}

/// Batch executor state
#[derive(Debug)]
pub struct BatchExecutor {
    /// Pending settlements waiting for batching
    pending_settlements: Vec<Settlement>,
    /// Current batch being formed
    current_batch: Option<Batch>,
    /// Settlements in current batch (needed for transaction building)
    current_batch_settlements: Vec<Settlement>,
    /// Available input UTXOs
    available_inputs: HashMap<String, Vec<ReconciliationInput>>, // ghost_id -> inputs
    /// Batch rules
    rules: BatchRules,
    /// Network
    network: Network,
    /// Treasury address for fees
    treasury_address: String,
    /// Current block height
    current_height: u32,
    /// Oldest pending settlement timestamp
    oldest_pending_timestamp: Option<u64>,
    /// Total pending sats
    pending_total_sats: u64,
    /// Next batch ID
    next_batch_id: u32,
}

impl BatchExecutor {
    /// Create a new batch executor
    pub fn new(network: Network, treasury_address: String) -> Self {
        Self {
            pending_settlements: Vec::new(),
            current_batch: None,
            current_batch_settlements: Vec::new(),
            available_inputs: HashMap::new(),
            rules: BatchRules::default(),
            network,
            treasury_address,
            current_height: 0,
            oldest_pending_timestamp: None,
            pending_total_sats: 0,
            next_batch_id: 1,
        }
    }

    /// Set batch rules
    pub fn with_rules(mut self, rules: BatchRules) -> Self {
        self.rules = rules;
        self
    }

    /// Update current block height
    pub fn set_block_height(&mut self, height: u32) {
        self.current_height = height;
    }

    /// Add available input UTXO
    pub fn add_input(&mut self, input: ReconciliationInput) {
        self.available_inputs
            .entry(input.ghost_id.clone())
            .or_default()
            .push(input);
    }

    /// Add a settlement request
    pub fn add_settlement(&mut self, settlement: Settlement) -> Result<(), ReconciliationError> {
        // Validate settlement
        crate::rules::validate_settlement(
            settlement.source_ghost_id(),
            settlement.destination_address(),
            settlement.amount_sats(),
        )?;

        // Track oldest timestamp for timeout
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if self.oldest_pending_timestamp.is_none() {
            self.oldest_pending_timestamp = Some(now);
        }

        self.pending_total_sats += settlement.amount_sats();
        self.pending_settlements.push(settlement);
        Ok(())
    }

    /// Get pending settlement count
    pub fn pending_count(&self) -> usize {
        self.pending_settlements.len()
    }

    /// Check if we should form a batch now
    pub fn should_form_batch(&self) -> bool {
        let oldest_age = self.oldest_pending_timestamp
            .map(|ts| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                now.saturating_sub(ts)
            })
            .unwrap_or(0);

        self.rules.should_form_batch(
            self.pending_settlements.len(),
            self.pending_total_sats,
            oldest_age,
        )
    }

    /// Form a new batch from pending settlements
    pub fn form_batch(&mut self) -> Result<Batch, ReconciliationError> {
        if self.pending_settlements.len() < MIN_BATCH_SIZE {
            return Err(ReconciliationError::InsufficientSettlements {
                have: self.pending_settlements.len(),
                need: MIN_BATCH_SIZE,
            });
        }

        // Take settlements up to max batch size
        let batch_size = self.pending_settlements.len().min(MAX_BATCH_SIZE);
        let settlements: Vec<Settlement> = self.pending_settlements.drain(..batch_size).collect();

        // Update pending tracking
        self.pending_total_sats = self.pending_settlements.iter()
            .map(|s| s.amount_sats())
            .sum();
        if self.pending_settlements.is_empty() {
            self.oldest_pending_timestamp = None;
        }

        // Create batch
        let mut batch = Batch::new();
        for settlement in &settlements {
            batch.add_settlement(settlement)?;
        }

        // Seal the batch
        batch.seal()?;

        // Store settlements for transaction building
        self.current_batch_settlements = settlements;
        self.current_batch = Some(batch.clone());
        Ok(batch)
    }

    /// Build the L1 reconciliation transaction for a batch
    pub fn build_transaction(
        &mut self,
        batch: &Batch,
        fee_rate: u64,
    ) -> Result<BatchTransaction, ReconciliationError> {
        if batch.state() != BatchState::Ready {
            return Err(ReconciliationError::InvalidState(format!(
                "Batch must be Ready, got {:?}",
                batch.state()
            )));
        }

        let mut input_outpoints = Vec::new();
        let mut total_input_sats: u64 = 0;
        let mut total_output_sats: u64 = 0;
        let mut input_lock_ids: Vec<[u8; 32]> = Vec::new();
        let mut input_amounts: Vec<u64> = Vec::new();

        // Collect inputs for each settlement
        for settlement in &self.current_batch_settlements {
            // Find available inputs for this ghost_id
            let inputs = match self.available_inputs.get_mut(settlement.source_ghost_id()) {
                Some(inputs) if !inputs.is_empty() => inputs,
                _ => {
                    return Err(ReconciliationError::InsufficientFunds {
                        ghost_id: settlement.source_ghost_id().to_string(),
                        required: settlement.amount_sats(),
                        available: 0,
                    });
                }
            };

            // Find input(s) that cover the settlement amount
            let mut collected = 0u64;
            let mut used_indices = Vec::new();

            for (i, input) in inputs.iter().enumerate() {
                if collected >= settlement.amount_sats() {
                    break;
                }
                collected += input.amount;
                used_indices.push(i);

                input_outpoints.push(OutPoint {
                    txid: input.txid,
                    vout: input.vout,
                });

                // Use lock_id if available, otherwise generate from txid:vout
                let lock_id = input.lock_id.unwrap_or_else(|| {
                    use sha2::{Sha256, Digest};
                    let mut hasher = Sha256::new();
                    hasher.update(<bitcoin::Txid as AsRef<[u8]>>::as_ref(&input.txid));
                    hasher.update(&input.vout.to_le_bytes());
                    hasher.finalize().into()
                });
                input_lock_ids.push(lock_id);
                input_amounts.push(input.amount);
                total_input_sats += input.amount;
            }

            if collected < settlement.amount_sats() {
                return Err(ReconciliationError::InsufficientFunds {
                    ghost_id: settlement.source_ghost_id().to_string(),
                    required: settlement.amount_sats(),
                    available: collected,
                });
            }

            // Remove used inputs (in reverse order to maintain indices)
            for i in used_indices.into_iter().rev() {
                inputs.remove(i);
            }

            total_output_sats += settlement.net_amount_sats();
        }

        // Calculate fees
        let total_settlement_fees = self.current_batch_settlements.iter()
            .map(|s| s.fee_sats())
            .sum::<u64>();

        // Treasury fee (50% of settlement fees)
        let treasury_amount = total_settlement_fees / 2;

        // Estimate mining fee
        let estimated_vsize = estimate_transaction_vsize(
            input_outpoints.len(),
            self.current_batch_settlements.len() + 2, // settlements + treasury + op_return
        );
        let mining_fee = estimated_vsize * fee_rate;

        // Node rewards (remaining 50% of settlement fees)
        let node_rewards = total_settlement_fees - treasury_amount;

        // Build ReconciliationTx
        let batch_id = self.next_batch_id;
        self.next_batch_id += 1;

        let state_root = batch.merkle_root()
            .copied()
            .ok_or_else(|| ReconciliationError::InvalidState(
                "Batch in Ready state but missing merkle root".to_string()
            ))?;

        let mut recon_tx = ReconciliationTx::new(batch_id, state_root, mining_fee);

        // Add inputs
        for (lock_id, amount) in input_lock_ids.iter().zip(input_amounts.iter()) {
            recon_tx.add_input(*lock_id, *amount);
        }

        // Add settlement outputs
        for settlement in &self.current_batch_settlements {
            recon_tx.add_output(TxOutput::Payment {
                address: settlement.destination_address().to_string(),
                amount: settlement.net_amount_sats(),
                from_lock: *settlement.source_lock_id(),
            });
        }

        // Add treasury fee output
        if treasury_amount > 0 {
            recon_tx.add_output(TxOutput::TreasuryFee {
                address: self.treasury_address.clone(),
                amount: treasury_amount,
            });
        }

        // Add OP_RETURN
        recon_tx.add_op_return();

        // Build actual Bitcoin transaction
        let bitcoin_tx = recon_tx.to_bitcoin_transaction(&input_outpoints, self.network)?;

        // Create commitment
        let commitment = L1Commitment::new(
            *batch.id(),
            state_root,
            batch.settlement_count() as u32,
            batch.total_amount_sats(),
        );

        Ok(BatchTransaction {
            batch_id: batch.id_hex(),
            transaction: bitcoin_tx,
            commitment,
            total_input_sats,
            total_output_sats,
            settlement_fees: total_settlement_fees,
            treasury_amount,
            node_rewards,
            mining_fee,
            input_outpoints,
        })
    }

    /// Mark batch as submitted to L1
    pub fn mark_submitted(
        &mut self,
        batch_id: &str,
        txid: Txid,
    ) -> Result<(), ReconciliationError> {
        if let Some(ref mut batch) = self.current_batch {
            if batch.id_hex() == batch_id {
                batch.mark_submitted(txid.to_string())?;
                return Ok(());
            }
        }
        Err(ReconciliationError::BatchNotFound { id: batch_id.to_string() })
    }

    /// Mark batch as confirmed
    pub fn mark_confirmed(
        &mut self,
        batch_id: &str,
        block_height: u32,
    ) -> Result<(), ReconciliationError> {
        if let Some(ref mut batch) = self.current_batch {
            if batch.id_hex() == batch_id {
                batch.mark_confirmed(block_height)?;
                return Ok(());
            }
        }
        Err(ReconciliationError::BatchNotFound { id: batch_id.to_string() })
    }

    /// Finalize batch after dispute window
    pub fn finalize_batch(&mut self, batch_id: &str) -> Result<(), ReconciliationError> {
        if let Some(ref mut batch) = self.current_batch {
            if batch.id_hex() == batch_id {
                // Check dispute window has passed
                if let Some(confirm_height) = batch.l1_height() {
                    let dispute_end = confirm_height + DISPUTE_WINDOW_BLOCKS;
                    if self.current_height < dispute_end {
                        return Err(ReconciliationError::DisputeWindowActive {
                            ends_at: dispute_end as u64,
                            current: self.current_height as u64,
                        });
                    }
                }

                batch.mark_finalized()?;

                // Clear current batch
                self.current_batch = None;
                self.current_batch_settlements.clear();
                return Ok(());
            }
        }
        Err(ReconciliationError::BatchNotFound { id: batch_id.to_string() })
    }

    /// Get current batch
    pub fn current_batch(&self) -> Option<&Batch> {
        self.current_batch.as_ref()
    }
}

/// Result of building a batch transaction
#[derive(Debug)]
pub struct BatchTransaction {
    /// Batch ID
    pub batch_id: String,
    /// The Bitcoin transaction
    pub transaction: bitcoin::Transaction,
    /// L1 commitment data
    pub commitment: L1Commitment,
    /// Total input satoshis
    pub total_input_sats: u64,
    /// Total output satoshis
    pub total_output_sats: u64,
    /// Total settlement fees collected
    pub settlement_fees: u64,
    /// Amount going to treasury
    pub treasury_amount: u64,
    /// Amount going to nodes
    pub node_rewards: u64,
    /// Mining fee
    pub mining_fee: u64,
    /// Input outpoints (for signing)
    pub input_outpoints: Vec<OutPoint>,
}

impl BatchTransaction {
    /// Get transaction ID (will change after signing)
    pub fn txid(&self) -> Txid {
        self.transaction.compute_txid()
    }

    /// Get settlement count from commitment
    pub fn settlement_count(&self) -> u64 {
        self.commitment.settlement_count as u64
    }
}

/// Estimate transaction vsize
fn estimate_transaction_vsize(input_count: usize, output_count: usize) -> u64 {
    // P2TR input: ~58 vbytes
    // P2TR output: ~43 vbytes
    // OP_RETURN: ~12 vbytes
    // Overhead: ~10 vbytes
    let input_vsize = input_count as u64 * 58;
    let output_vsize = output_count as u64 * 43;
    let overhead = 10;
    input_vsize + output_vsize + overhead
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn test_txid() -> Txid {
        Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap()
    }

    #[test]
    fn test_executor_creation() {
        let executor = BatchExecutor::new(
            Network::Regtest,
            "bcrt1qtest".to_string(),
        );
        assert_eq!(executor.pending_count(), 0);
    }

    fn test_lock_id(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn test_add_settlement() {
        let mut executor = BatchExecutor::new(
            Network::Regtest,
            "bcrt1qtest".to_string(),
        );

        let settlement = Settlement::new(
            "ghost1abc".to_string(),
            test_lock_id(1),
            "bcrt1qoutput".to_string(),
            100_000,
        ).unwrap();

        executor.add_settlement(settlement).unwrap();
        assert_eq!(executor.pending_count(), 1);
    }

    #[test]
    fn test_add_input() {
        let mut executor = BatchExecutor::new(
            Network::Regtest,
            "bcrt1qtest".to_string(),
        );

        let input = ReconciliationInput {
            txid: test_txid(),
            vout: 0,
            amount: 1_000_000,
            ghost_id: "ghost1abc".to_string(),
            lock_id: None,
        };

        executor.add_input(input);
        assert!(executor.available_inputs.contains_key("ghost1abc"));
    }

    #[test]
    fn test_should_form_batch_min_size() {
        let mut executor = BatchExecutor::new(
            Network::Regtest,
            "bcrt1qtest".to_string(),
        );

        // Add less than minimum
        for i in 0..5 {
            let settlement = Settlement::new(
                format!("ghost1{}", i),
                test_lock_id(i as u8),
                format!("bcrt1qoutput{}", i),
                100_000,
            ).unwrap();
            executor.add_settlement(settlement).unwrap();
        }

        assert!(!executor.should_form_batch());

        // Add more to reach minimum
        for i in 5..10 {
            let settlement = Settlement::new(
                format!("ghost1{}", i),
                test_lock_id(i as u8),
                format!("bcrt1qoutput{}", i),
                100_000,
            ).unwrap();
            executor.add_settlement(settlement).unwrap();
        }

        assert!(executor.should_form_batch());
    }
}
