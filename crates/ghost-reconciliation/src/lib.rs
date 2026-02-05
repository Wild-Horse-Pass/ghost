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

/// Minimum settlements per batch
pub const MIN_BATCH_SIZE: usize = 10;

/// Maximum settlements per batch
pub const MAX_BATCH_SIZE: usize = 1000;

/// Batch timeout in seconds (6 hours)
pub const BATCH_TIMEOUT_SECS: u64 = 6 * 60 * 60;

/// Minimum settlement amount in satoshis
pub const MIN_SETTLEMENT_SATS: u64 = 10_000;

/// Dispute window in blocks (1 day)
pub const DISPUTE_WINDOW_BLOCKS: u32 = 144;

/// Settlement fee percentage (0.1%)
/// PAY-M1: Use integer arithmetic to avoid floating-point rounding errors
/// Fee = amount / 1000 (equivalent to 0.1%)
pub const SETTLEMENT_FEE_PERCENT: f64 = 0.001;

/// Settlement fee divisor for integer arithmetic (1000 = 0.1%)
/// PAY-M1: Prefer this over SETTLEMENT_FEE_PERCENT for fee calculations
pub const SETTLEMENT_FEE_DIVISOR: u64 = 1000;
