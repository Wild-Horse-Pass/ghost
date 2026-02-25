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
//| FILE: lib.rs                                                                                                         |
//|======================================================================================================================|

//! Ghost Reconciliation - L1 Settlement
//!
//! This crate handles the settlement of L2 Ghost Pay balances to L1 Bitcoin.
//!
//! # Architecture
//!
//! Ghost Pay operates as an L2 layer with periodic L1 settlement:
//!
//! 1. **Batch Formation**: Collect pending settlements into batches
//! 2. **Merkle Commitment**: Create merkle tree of settlements
//! 3. **L1 Transaction**: Publish commitment to Bitcoin
//! 4. **Proof Generation**: Generate inclusion proofs for users
//! 5. **Dispute Window**: Allow challenges during dispute period
//! 6. **Finalization**: Mark settlements as complete
//!
//! # Security Features
//!
//! ## C-1: Settlement Ownership Verification
//!
//! All settlement requests must include cryptographic proof that the requester
//! owns the lock being spent. Use [`SettlementRequest`] with an [`OwnershipProof`]
//! to submit settlements via [`BatchExecutor::add_settlement_request()`].
//!
//! ## C-2: Double-Spend Prevention
//!
//! The batch executor tracks consumed inputs within a batch to prevent the same
//! UTXO from being spent multiple times in the same transaction.
//!
//! # Settlement Rules
//!
//! - Minimum batch size: 10 settlements
//! - Maximum batch size: 1000 settlements
//! - Batch timeout: 6 hours (force batch if pending > threshold)
//! - Minimum settlement: 10,000 sats
//! - Dispute window: 144 blocks (1 day)

pub mod batch;
pub mod broadcaster;
pub mod commitment;
pub mod coordinator;
pub mod error;
pub mod executor;
pub mod proof;
pub mod rpc;
pub mod rules;
pub mod settlement;
pub mod transaction;
pub mod verifier;

pub use batch::*;
pub use broadcaster::*;
pub use commitment::*;
pub use coordinator::*;
pub use error::*;
pub use executor::*;
pub use proof::*;
pub use rules::*;
pub use settlement::*;
pub use transaction::*;
pub use verifier::*;

/// Default minimum settlements per batch
pub const MIN_BATCH_SIZE: usize = 10;

/// Default maximum settlements per batch
pub const MAX_BATCH_SIZE: usize = 1000;

/// Batch timeout in seconds (6 hours)
pub const BATCH_TIMEOUT_SECS: u64 = 6 * 60 * 60;

/// Minimum settlement amount in satoshis
pub const MIN_SETTLEMENT_SATS: u64 = 10_000;

/// Dispute window in blocks (1 day)
pub const DISPUTE_WINDOW_BLOCKS: u32 = 144;

/// Settlement fee divisor for integer arithmetic (1000 = 0.1%)
/// M-19: Float constant removed -- all fee calculations use integer division
pub const SETTLEMENT_FEE_DIVISOR: u64 = 1000;

/// L-12: Configurable batch size parameters for settlement reconciliation.
///
/// These were previously hardcoded constants. Making them configurable allows
/// operators to tune batch sizes based on network conditions and L1 fee rates.
#[derive(Debug, Clone)]
pub struct ReconciliationConfig {
    /// Minimum settlements required before a batch can be sealed.
    /// Default: 10. Must be >= 1.
    pub min_batch_size: usize,
    /// Maximum settlements allowed in a single batch.
    /// Default: 1000. Must be >= min_batch_size.
    pub max_batch_size: usize,
    /// Batch timeout in seconds before force-sealing.
    /// Default: 21600 (6 hours).
    pub batch_timeout_secs: u64,
}

impl Default for ReconciliationConfig {
    fn default() -> Self {
        Self {
            min_batch_size: MIN_BATCH_SIZE,
            max_batch_size: MAX_BATCH_SIZE,
            batch_timeout_secs: BATCH_TIMEOUT_SECS,
        }
    }
}

impl ReconciliationConfig {
    /// Validate configuration values
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.min_batch_size == 0 {
            return Err("min_batch_size must be >= 1".to_string());
        }
        if self.max_batch_size < self.min_batch_size {
            return Err(format!(
                "max_batch_size ({}) must be >= min_batch_size ({})",
                self.max_batch_size, self.min_batch_size
            ));
        }
        if self.batch_timeout_secs == 0 {
            return Err("batch_timeout_secs must be > 0".to_string());
        }
        Ok(())
    }
}
