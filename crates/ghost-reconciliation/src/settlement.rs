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
//| FILE: settlement.rs                                                                                                  |
//|======================================================================================================================|

//! Settlement types and management

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{ReconciliationError, ReconciliationResult};
use crate::MIN_SETTLEMENT_SATS;

/// Settlement state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SettlementState {
    /// Pending inclusion in batch
    Pending,
    /// Included in batch, awaiting L1 confirmation
    Batched,
    /// L1 transaction confirmed, in dispute window
    Confirming,
    /// Dispute window passed, fully settled
    Finalized,
    /// Settlement was disputed and rejected
    Rejected,
    /// Settlement was cancelled by user
    Cancelled,
}

impl SettlementState {
    /// Check if settlement is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            SettlementState::Finalized | SettlementState::Rejected | SettlementState::Cancelled
        )
    }

    /// Check if settlement can be cancelled
    pub fn can_cancel(&self) -> bool {
        matches!(self, SettlementState::Pending)
    }

    /// Get state name
    pub fn name(&self) -> &'static str {
        match self {
            SettlementState::Pending => "Pending",
            SettlementState::Batched => "Batched",
            SettlementState::Confirming => "Confirming",
            SettlementState::Finalized => "Finalized",
            SettlementState::Rejected => "Rejected",
            SettlementState::Cancelled => "Cancelled",
        }
    }
}

impl std::fmt::Display for SettlementState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// A settlement request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settlement {
    /// Unique settlement ID
    id: [u8; 32],
    /// Source Ghost ID (L2 account)
    source_ghost_id: String,
    /// Source lock ID (the Ghost Lock being spent)
    source_lock_id: [u8; 32],
    /// Destination Bitcoin address
    destination_address: String,
    /// Amount in satoshis
    amount_sats: u64,
    /// Fee in satoshis
    fee_sats: u64,
    /// Current state
    state: SettlementState,
    /// Created timestamp
    created_at: u64,
    /// Updated timestamp
    updated_at: u64,
    /// Batch ID (if batched)
    batch_id: Option<[u8; 32]>,
    /// Merkle proof (if batched)
    merkle_proof: Option<Vec<[u8; 32]>>,
    /// L1 transaction ID (if confirmed)
    l1_txid: Option<String>,
}

impl Settlement {
    /// Create a new settlement
    pub fn new(
        source_ghost_id: String,
        source_lock_id: [u8; 32],
        destination_address: String,
        amount_sats: u64,
    ) -> ReconciliationResult<Self> {
        // Validate minimum amount
        if amount_sats < MIN_SETTLEMENT_SATS {
            return Err(ReconciliationError::BelowMinimum {
                amount: amount_sats,
                minimum: MIN_SETTLEMENT_SATS,
            });
        }

        // Calculate fee (0.1%)
        // PAY-M1: Use integer arithmetic to avoid floating-point precision errors
        let fee_sats = amount_sats / crate::SETTLEMENT_FEE_DIVISOR;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Generate unique ID with cryptographic nonce for collision resistance
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).expect("System RNG failure is unrecoverable");

        let mut hasher = Sha256::new();
        hasher.update(b"GhostSettlement/v2");
        hasher.update(&nonce);
        hasher.update(&source_ghost_id);
        hasher.update(source_lock_id);
        hasher.update(&destination_address);
        hasher.update(amount_sats.to_le_bytes());
        hasher.update(now.to_le_bytes());
        let id: [u8; 32] = hasher.finalize().into();

        Ok(Self {
            id,
            source_ghost_id,
            source_lock_id,
            destination_address,
            amount_sats,
            fee_sats,
            state: SettlementState::Pending,
            created_at: now,
            updated_at: now,
            batch_id: None,
            merkle_proof: None,
            l1_txid: None,
        })
    }

    /// Get settlement ID
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// Get settlement ID as hex
    pub fn id_hex(&self) -> String {
        hex::encode(self.id)
    }

    /// Get source ghost ID
    pub fn source_ghost_id(&self) -> &str {
        &self.source_ghost_id
    }

    /// Get source lock ID
    pub fn source_lock_id(&self) -> &[u8; 32] {
        &self.source_lock_id
    }

    /// Get destination address
    pub fn destination_address(&self) -> &str {
        &self.destination_address
    }

    /// Get amount in satoshis
    pub fn amount_sats(&self) -> u64 {
        self.amount_sats
    }

    /// Get fee in satoshis
    pub fn fee_sats(&self) -> u64 {
        self.fee_sats
    }

    /// Get net amount (amount - fee)
    pub fn net_amount_sats(&self) -> u64 {
        self.amount_sats.saturating_sub(self.fee_sats)
    }

    /// Get current state
    pub fn state(&self) -> SettlementState {
        self.state
    }

    /// Get batch ID
    pub fn batch_id(&self) -> Option<&[u8; 32]> {
        self.batch_id.as_ref()
    }

    /// Get merkle proof
    pub fn merkle_proof(&self) -> Option<&Vec<[u8; 32]>> {
        self.merkle_proof.as_ref()
    }

    /// Get L1 transaction ID
    pub fn l1_txid(&self) -> Option<&str> {
        self.l1_txid.as_deref()
    }

    /// Compute the settlement hash (leaf in merkle tree)
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.id);
        hasher.update(&self.source_ghost_id);
        hasher.update(self.source_lock_id);
        hasher.update(&self.destination_address);
        hasher.update(self.amount_sats.to_le_bytes());
        hasher.update(self.fee_sats.to_le_bytes());
        hasher.finalize().into()
    }

    /// Mark as batched
    pub fn mark_batched(
        &mut self,
        batch_id: [u8; 32],
        merkle_proof: Vec<[u8; 32]>,
    ) -> ReconciliationResult<()> {
        if self.state != SettlementState::Pending {
            return Err(ReconciliationError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Batched".to_string(),
            });
        }

        self.state = SettlementState::Batched;
        self.batch_id = Some(batch_id);
        self.merkle_proof = Some(merkle_proof);
        self.updated_at = Self::now();
        Ok(())
    }

    /// Mark as confirming (L1 tx confirmed)
    pub fn mark_confirming(&mut self, l1_txid: String) -> ReconciliationResult<()> {
        if self.state != SettlementState::Batched {
            return Err(ReconciliationError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Confirming".to_string(),
            });
        }

        self.state = SettlementState::Confirming;
        self.l1_txid = Some(l1_txid);
        self.updated_at = Self::now();
        Ok(())
    }

    /// Mark as finalized
    pub fn mark_finalized(&mut self) -> ReconciliationResult<()> {
        if self.state != SettlementState::Confirming {
            return Err(ReconciliationError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Finalized".to_string(),
            });
        }

        self.state = SettlementState::Finalized;
        self.updated_at = Self::now();
        Ok(())
    }

    /// Mark as rejected
    pub fn mark_rejected(&mut self) -> ReconciliationResult<()> {
        if self.state == SettlementState::Finalized {
            return Err(ReconciliationError::AlreadyFinalized { id: self.id_hex() });
        }

        self.state = SettlementState::Rejected;
        self.updated_at = Self::now();
        Ok(())
    }

    /// Cancel the settlement
    pub fn cancel(&mut self) -> ReconciliationResult<()> {
        if !self.state.can_cancel() {
            return Err(ReconciliationError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Cancelled".to_string(),
            });
        }

        self.state = SettlementState::Cancelled;
        self.updated_at = Self::now();
        Ok(())
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_lock_id() -> [u8; 32] {
        [1u8; 32]
    }

    #[test]
    fn test_settlement_creation() {
        let settlement = Settlement::new(
            "ghost1abc".to_string(),
            test_lock_id(),
            "bc1qtest".to_string(),
            100_000,
        )
        .unwrap();

        assert_eq!(settlement.state(), SettlementState::Pending);
        assert_eq!(settlement.amount_sats(), 100_000);
        assert_eq!(settlement.fee_sats(), 100); // 0.1%
        assert_eq!(settlement.net_amount_sats(), 99_900);
        assert_eq!(settlement.source_lock_id(), &test_lock_id());
    }

    #[test]
    fn test_minimum_amount() {
        let result = Settlement::new(
            "ghost1abc".to_string(),
            test_lock_id(),
            "bc1qtest".to_string(),
            1_000, // Below minimum
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_state_transitions() {
        let mut settlement = Settlement::new(
            "ghost1abc".to_string(),
            test_lock_id(),
            "bc1qtest".to_string(),
            100_000,
        )
        .unwrap();

        // Pending -> Batched
        settlement.mark_batched([0u8; 32], vec![]).unwrap();
        assert_eq!(settlement.state(), SettlementState::Batched);

        // Batched -> Confirming
        settlement.mark_confirming("txid123".to_string()).unwrap();
        assert_eq!(settlement.state(), SettlementState::Confirming);

        // Confirming -> Finalized
        settlement.mark_finalized().unwrap();
        assert_eq!(settlement.state(), SettlementState::Finalized);
    }

    #[test]
    fn test_cancel() {
        let mut settlement = Settlement::new(
            "ghost1abc".to_string(),
            test_lock_id(),
            "bc1qtest".to_string(),
            100_000,
        )
        .unwrap();

        settlement.cancel().unwrap();
        assert_eq!(settlement.state(), SettlementState::Cancelled);
    }

    #[test]
    fn test_settlement_id_collision_prevention() {
        // C-5: Verify that settlements with identical params created in the same second
        // still have different IDs due to cryptographic nonce
        use std::collections::HashSet;

        let source_ghost_id = "ghost1abc".to_string();
        let lock_id = test_lock_id();
        let destination = "bc1qtest".to_string();
        let amount = 100_000u64;

        // Create multiple settlements with identical parameters rapidly
        let mut ids = HashSet::new();
        for _ in 0..100 {
            let settlement = Settlement::new(
                source_ghost_id.clone(),
                lock_id,
                destination.clone(),
                amount,
            )
            .unwrap();
            let id = *settlement.id();
            assert!(
                ids.insert(id),
                "CRITICAL: Settlement ID collision detected - same-second settlements must have unique IDs"
            );
        }
        assert_eq!(ids.len(), 100, "All 100 settlement IDs must be unique");
    }
}
