//! ZK Circuit definitions for Ghost Pay
//!
//! This module contains the circuits that prove block validity:
//!
//! - `payment`: Single payment validity (balance check, signature)
//! - `merkle`: Merkle tree inclusion and update proofs
//! - `block`: Full block validity (batch of payments)
//! - `payout`: Payout distribution validity
//! - `state_transition`: Payment state transition with merkle proofs

pub mod block;
pub mod merkle;
pub mod mimc;
pub mod payment;
pub mod payout;
pub mod state_transition;

pub use block::{BlockCircuit, BlockCircuitBuilder};
pub use merkle::{MerkleCircuit, MerkleUpdateCircuit};
pub use mimc::{bytes_to_field, field_to_bytes, mimc_hash, mimc_hash_native, MIMC_ROUNDS};
pub use payment::{PaymentCircuit, PaymentCircuitError, PaymentOutputs};
pub use payout::PayoutCircuit;
pub use state_transition::{PaymentStateTransitionCircuit, StateTransitionOutputs};

/// Maximum supported transactions per block
pub const MAX_TXS_PER_BLOCK: usize = 100;

/// Default merkle tree depth (supports 2^20 = ~1M accounts)
pub const DEFAULT_TREE_DEPTH: usize = 20;

/// Number of bits for balance representation (64-bit)
pub const BALANCE_BITS: usize = 64;
