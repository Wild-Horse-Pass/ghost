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
pub mod commitment;
pub mod confidential_transfer;
pub mod merkle;
pub mod mimc;
pub mod payment;
pub mod payout;
pub mod range_proof;
pub mod state_transition;

pub use block::{BlockCircuit, BlockCircuitBuilder};
pub use commitment::{
    compute_note_id, compute_note_id_native, compute_nullifier, compute_nullifier_native,
    pedersen_commit, pedersen_commit_native, COMMITMENT_DOMAIN_SEPARATOR,
    NULLIFIER_DOMAIN_SEPARATOR,
};
pub use merkle::{MerkleCircuit, MerkleUpdateCircuit};
pub use mimc::{bytes_to_field, field_to_bytes, mimc_hash, mimc_hash_native, MIMC_ROUNDS};
pub use payment::{PaymentCircuit, PaymentCircuitError, PaymentOutputs};
pub use payout::PayoutCircuit;
pub use confidential_transfer::ConfidentialTransferCircuit;
pub use range_proof::enforce_range;
pub use state_transition::{PaymentStateTransitionCircuit, StateTransitionOutputs};

/// Maximum supported transactions per block
pub const MAX_TXS_PER_BLOCK: usize = 100;

/// Default merkle tree depth (supports 2^20 = ~1M accounts)
pub const DEFAULT_TREE_DEPTH: usize = 20;

/// Number of bits for balance representation (64-bit)
pub const BALANCE_BITS: usize = 64;
