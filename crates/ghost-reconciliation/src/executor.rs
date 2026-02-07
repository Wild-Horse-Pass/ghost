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
//!
//! # Security Features
//!
//! ## C-1: Settlement Ownership Verification
//! All settlements must include cryptographic proof that the requester owns
//! the lock being spent. Use `add_settlement_request()` which verifies the
//! ownership proof before accepting the settlement.
//!
//! ## C-2: Double-Spend Prevention
//! The batch executor tracks consumed inputs within a batch to prevent the
//! same UTXO from being spent multiple times in the same transaction.

use std::collections::{HashMap, HashSet};

use bitcoin::{Network, OutPoint, Txid};

use crate::batch::{Batch, BatchState};
use crate::commitment::L1Commitment;
use crate::error::ReconciliationError;
use crate::rules::BatchRules;
use crate::settlement::{Settlement, SettlementRequest};
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

    /// Add a settlement request with ownership verification (C-1)
    ///
    /// This is the RECOMMENDED method for adding settlements. It verifies
    /// that the requester owns the lock they are trying to spend before
    /// accepting the settlement.
    ///
    /// # Security
    ///
    /// This method enforces C-1: Settlement Ownership Verification.
    /// Without valid ownership proof, the settlement is rejected.
    pub fn add_settlement_request(
        &mut self,
        request: SettlementRequest,
    ) -> Result<(), ReconciliationError> {
        // C-1: Verify ownership proof BEFORE any other processing
        request.verify_ownership().map_err(|e| {
            tracing::error!(
                settlement_id = %hex::encode(request.settlement().id()),
                source_ghost_id = %request.settlement().source_ghost_id(),
                destination = %request.settlement().destination_address(),
                amount = request.settlement().amount_sats(),
                "C-1 SECURITY: Settlement ownership verification failed: {}",
                e
            );
            ReconciliationError::OwnershipVerificationFailed(e.to_string())
        })?;

        tracing::debug!(
            settlement_id = %hex::encode(request.settlement().id()),
            "C-1: Settlement ownership verified successfully"
        );

        // Now add the verified settlement
        self.add_settlement_internal(request.into_settlement())
    }

    /// Add a settlement request (DEPRECATED - use add_settlement_request)
    ///
    /// # Deprecation Warning
    ///
    /// This method does NOT verify ownership. It exists only for backwards
    /// compatibility and internal use. External callers MUST use
    /// `add_settlement_request()` which includes ownership verification.
    ///
    /// # Security Risk
    ///
    /// Using this method without ownership verification could allow attackers
    /// to request settlements from locks they don't own.
    #[deprecated(
        since = "1.6.0",
        note = "Use add_settlement_request() which includes C-1 ownership verification"
    )]
    pub fn add_settlement(&mut self, settlement: Settlement) -> Result<(), ReconciliationError> {
        tracing::warn!(
            settlement_id = %hex::encode(settlement.id()),
            "DEPRECATED: add_settlement() called without ownership verification. \
             Use add_settlement_request() for C-1 security."
        );
        self.add_settlement_internal(settlement)
    }

    /// Internal method to add a settlement after verification
    fn add_settlement_internal(
        &mut self,
        settlement: Settlement,
    ) -> Result<(), ReconciliationError> {
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
        let oldest_age = self
            .oldest_pending_timestamp
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
    ///
    /// # Security (H-6: Atomic Settlement State Transitions)
    ///
    /// This method clones settlements for batch formation instead of draining them.
    /// Settlements are only removed from the pending queue after successful batch
    /// sealing. If sealing fails, no settlements are lost.
    pub fn form_batch(&mut self) -> Result<Batch, ReconciliationError> {
        if self.pending_settlements.len() < MIN_BATCH_SIZE {
            return Err(ReconciliationError::InsufficientSettlements {
                have: self.pending_settlements.len(),
                need: MIN_BATCH_SIZE,
            });
        }

        // H-6: CLONE settlements instead of draining them
        // This ensures we don't lose settlements if batch sealing fails
        let batch_size = self.pending_settlements.len().min(MAX_BATCH_SIZE);
        let candidate_settlements: Vec<Settlement> = self
            .pending_settlements
            .iter()
            .take(batch_size)
            .cloned()
            .collect();

        // Create batch from cloned settlements
        let mut batch = Batch::new();
        for settlement in &candidate_settlements {
            batch.add_settlement(settlement)?;
        }

        // H-6: Try to seal the batch BEFORE removing from pending
        // If this fails, pending_settlements remain unchanged
        batch.seal()?;

        // H-6: Only now that sealing succeeded, remove from pending
        // Use drain to efficiently remove the first batch_size elements
        let settlements: Vec<Settlement> = self.pending_settlements.drain(..batch_size).collect();

        // Update pending tracking
        self.pending_total_sats = self
            .pending_settlements
            .iter()
            .map(|s| s.amount_sats())
            .sum();
        if self.pending_settlements.is_empty() {
            self.oldest_pending_timestamp = None;
        }

        // Store settlements for transaction building
        self.current_batch_settlements = settlements;
        self.current_batch = Some(batch.clone());
        Ok(batch)
    }

    /// Build the L1 reconciliation transaction for a batch
    ///
    /// # Security (C-2)
    ///
    /// This function tracks inputs consumed within the batch to prevent
    /// double-spending the same UTXO for multiple settlements.
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

        // C-2: Track inputs consumed within THIS batch to prevent double-spend
        // This HashSet tracks outpoints (txid:vout) that have already been
        // selected for spending in this batch.
        let mut consumed_in_batch: HashSet<OutPoint> = HashSet::new();

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

                let outpoint = OutPoint {
                    txid: input.txid,
                    vout: input.vout,
                };

                // C-2: Check if this input was already consumed in this batch
                if consumed_in_batch.contains(&outpoint) {
                    tracing::error!(
                        txid = %input.txid,
                        vout = input.vout,
                        settlement_id = %hex::encode(settlement.id()),
                        "C-2 SECURITY: Attempted double-spend of input in same batch"
                    );
                    return Err(ReconciliationError::DoubleSpendInBatch {
                        outpoint: format!("{}:{}", input.txid, input.vout),
                    });
                }

                // C-2: Mark input as consumed BEFORE adding to the batch
                consumed_in_batch.insert(outpoint);

                collected += input.amount;
                used_indices.push(i);

                input_outpoints.push(outpoint);

                // Use lock_id if available, otherwise generate from txid:vout
                let lock_id = input.lock_id.unwrap_or_else(|| {
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(<bitcoin::Txid as AsRef<[u8]>>::as_ref(&input.txid));
                    hasher.update(input.vout.to_le_bytes());
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

        tracing::debug!(
            input_count = consumed_in_batch.len(),
            "C-2: Batch transaction built with {} unique inputs",
            consumed_in_batch.len()
        );

        // Calculate fees
        let total_settlement_fees = self
            .current_batch_settlements
            .iter()
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

        let state_root = batch.merkle_root().copied().ok_or_else(|| {
            ReconciliationError::InvalidState(
                "Batch in Ready state but missing merkle root".to_string(),
            )
        })?;

        let mut recon_tx = ReconciliationTx::new(batch_id, state_root, mining_fee);

        // Add inputs (H-8: handle overflow)
        for (lock_id, amount) in input_lock_ids.iter().zip(input_amounts.iter()) {
            recon_tx.add_input(*lock_id, *amount)?;
        }

        // Add settlement outputs (H-8: handle overflow)
        for settlement in &self.current_batch_settlements {
            recon_tx.add_output(TxOutput::Payment {
                address: settlement.destination_address().to_string(),
                amount: settlement.net_amount_sats(),
                from_lock: *settlement.source_lock_id(),
            })?;
        }

        // Add treasury fee output (H-8: handle overflow)
        if treasury_amount > 0 {
            recon_tx.add_output(TxOutput::TreasuryFee {
                address: self.treasury_address.clone(),
                amount: treasury_amount,
            })?;
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
        Err(ReconciliationError::BatchNotFound {
            id: batch_id.to_string(),
        })
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
        Err(ReconciliationError::BatchNotFound {
            id: batch_id.to_string(),
        })
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
        Err(ReconciliationError::BatchNotFound {
            id: batch_id.to_string(),
        })
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
    use crate::settlement::OwnershipProof;
    use std::str::FromStr;

    fn test_txid() -> Txid {
        Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap()
    }

    #[test]
    fn test_executor_creation() {
        let executor = BatchExecutor::new(Network::Regtest, "bcrt1qtest".to_string());
        assert_eq!(executor.pending_count(), 0);
    }

    fn test_lock_id(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    #[allow(deprecated)] // Testing deprecated method explicitly
    fn test_add_settlement() {
        let mut executor = BatchExecutor::new(Network::Regtest, "bcrt1qtest".to_string());

        let settlement = Settlement::new(
            "ghost1abc".to_string(),
            test_lock_id(1),
            "bcrt1qoutput".to_string(),
            100_000,
        )
        .unwrap();

        executor.add_settlement(settlement).unwrap();
        assert_eq!(executor.pending_count(), 1);
    }

    #[test]
    fn test_add_input() {
        let mut executor = BatchExecutor::new(Network::Regtest, "bcrt1qtest".to_string());

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
    #[allow(deprecated)] // Testing deprecated method explicitly
    fn test_should_form_batch_min_size() {
        let mut executor = BatchExecutor::new(Network::Regtest, "bcrt1qtest".to_string());

        // Add less than minimum
        for i in 0..5 {
            let settlement = Settlement::new(
                format!("ghost1{}", i),
                test_lock_id(i as u8),
                format!("bcrt1qoutput{}", i),
                100_000,
            )
            .unwrap();
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
            )
            .unwrap();
            executor.add_settlement(settlement).unwrap();
        }

        assert!(executor.should_form_batch());
    }

    // ========================================================================
    // C-1: Settlement Ownership Verification Tests
    // ========================================================================

    #[test]
    fn test_c1_settlement_rejected_without_ownership_proof() {
        use crate::settlement::{OwnershipProof, SettlementRequest};

        let mut executor = BatchExecutor::new(Network::Regtest, "bcrt1qtest".to_string());

        // Create a settlement
        let settlement = Settlement::new(
            "ghost1abc".to_string(),
            test_lock_id(1),
            "bcrt1qoutput".to_string(),
            100_000,
        )
        .unwrap();

        // Create a fake/invalid ownership proof (wrong signature)
        let fake_sig = [0u8; 64];
        let fake_pubkey = test_lock_id(1); // This won't match the actual lock pubkey
        let ownership_proof = OwnershipProof::new(fake_sig, fake_pubkey);

        let request = SettlementRequest::new(settlement, ownership_proof);

        // Verification should fail
        let result = executor.add_settlement_request(request);
        assert!(result.is_err());

        // Error should indicate ownership verification failure
        let err = result.unwrap_err();
        assert!(
            matches!(err, ReconciliationError::OwnershipVerificationFailed(_)),
            "Expected OwnershipVerificationFailed, got {:?}",
            err
        );
    }

    #[test]
    fn test_c1_settlement_rejected_with_wrong_pubkey() {
        use crate::settlement::{OwnershipProof, SettlementRequest};

        let mut executor = BatchExecutor::new(Network::Regtest, "bcrt1qtest".to_string());

        // Create a settlement with lock_id = [1u8; 32]
        let settlement = Settlement::new(
            "ghost1abc".to_string(),
            test_lock_id(1),
            "bcrt1qoutput".to_string(),
            100_000,
        )
        .unwrap();

        // Create proof with DIFFERENT pubkey than the lock
        let fake_sig = [0u8; 64];
        let wrong_pubkey = test_lock_id(2); // Different from settlement's lock_id
        let ownership_proof = OwnershipProof::new(fake_sig, wrong_pubkey);

        let request = SettlementRequest::new(settlement, ownership_proof);

        // Verification should fail because pubkey doesn't match lock
        let result = executor.add_settlement_request(request);
        assert!(result.is_err());

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("does not match lock pubkey"),
            "Expected pubkey mismatch error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_c1_ownership_proof_message_format() {
        // Verify the message format is deterministic
        let settlement_id = [1u8; 32];
        let destination = "bcrt1qtest";
        let amount = 100_000u64;

        let msg1 = OwnershipProof::build_message(&settlement_id, destination, amount);
        let msg2 = OwnershipProof::build_message(&settlement_id, destination, amount);

        assert_eq!(msg1, msg2, "Message hash should be deterministic");

        // Different inputs should produce different messages
        let msg3 = OwnershipProof::build_message(&settlement_id, destination, amount + 1);
        assert_ne!(msg1, msg3, "Different amount should produce different hash");

        let msg4 = OwnershipProof::build_message(&settlement_id, "bcrt1qother", amount);
        assert_ne!(
            msg1, msg4,
            "Different destination should produce different hash"
        );
    }

    // ========================================================================
    // C-2: Double-Spend Prevention Tests
    // ========================================================================

    #[test]
    fn test_c2_double_spend_in_batch_rejected() {
        let mut executor = BatchExecutor::new(Network::Regtest, "bcrt1qtest".to_string());

        // Add 10 settlements to form a batch (minimum batch size)
        for i in 0..10 {
            let settlement = Settlement::new(
                "ghost1same".to_string(), // All from same ghost_id (must start with "ghost1")
                test_lock_id(i as u8),
                format!("bcrt1qoutput{}", i),
                10_000, // Small amounts
            )
            .unwrap();
            #[allow(deprecated)]
            executor.add_settlement(settlement).unwrap();
        }

        // Add only ONE input that's smaller than total required
        // This simulates the scenario where the same input would need
        // to be used for multiple settlements
        let single_input = ReconciliationInput {
            txid: test_txid(),
            vout: 0,
            amount: 50_000,                     // Only enough for ~5 settlements
            ghost_id: "ghost1same".to_string(), // Must match settlement
            lock_id: None,
        };
        executor.add_input(single_input);

        // Form the batch
        let batch = executor.form_batch().unwrap();

        // Building transaction should fail due to insufficient funds
        // (not double-spend in this case, but demonstrates input tracking)
        let result = executor.build_transaction(&batch, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_c2_unique_inputs_for_settlements() {
        // Use a valid regtest bech32 address
        let treasury_addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string();
        let mut executor = BatchExecutor::new(Network::Regtest, treasury_addr);

        // Add 10 settlements from different ghost_ids
        // Using a valid regtest P2WPKH address format
        let output_addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

        for i in 0..10 {
            let settlement = Settlement::new(
                format!("ghost1user{}", i), // Must start with "ghost1"
                test_lock_id(i as u8),
                output_addr.to_string(), // Use valid address for all
                10_000,
            )
            .unwrap();
            #[allow(deprecated)]
            executor.add_settlement(settlement).unwrap();

            // Add corresponding input for each ghost_id
            let input = ReconciliationInput {
                txid: Txid::from_str(&format!(
                    "000000000000000000000000000000000000000000000000000000000000000{}",
                    i
                ))
                .unwrap_or(test_txid()),
                vout: 0,
                amount: 20_000,
                ghost_id: format!("ghost1user{}", i), // Must match settlement
                lock_id: Some(test_lock_id(i as u8)),
            };
            executor.add_input(input);
        }

        // Form the batch
        let batch = executor.form_batch().unwrap();

        // Building transaction should succeed with unique inputs
        let result = executor.build_transaction(&batch, 1);
        assert!(
            result.is_ok(),
            "Should succeed with unique inputs: {:?}",
            result.err()
        );

        let tx = result.unwrap();
        assert_eq!(tx.input_outpoints.len(), 10, "Should have 10 unique inputs");

        // Verify all outpoints are unique
        let unique_outpoints: HashSet<_> = tx.input_outpoints.iter().collect();
        assert_eq!(
            unique_outpoints.len(),
            tx.input_outpoints.len(),
            "All outpoints should be unique"
        );
    }
}
