//! Ghost ZKP - Zero-Knowledge Proof Infrastructure for Ghost Pay
//!
//! This crate provides ZK validity proofs for Ghost Pay's BFT consensus.
//! Each block is proven valid by the proposer and verified by validators
//! in approximately 10ms. Proofs are ephemeral - once verified and the
//! block is finalized, they are discarded.
//!
//! # Proving Modes
//!
//! ## Legacy Mode (prove)
//! Proves payment validity only. Validators must re-execute state to verify
//! the state root transition.
//!
//! ## Full ZK Mode (prove_v2)
//! Proves complete state root transitions cryptographically. Validators verify
//! the proof only - no re-execution required. This makes Ghost Pay fully trustless.
//!
//! # Architecture
//!
//! ```text
//! Proposer                    Validators
//! ┌──────────────┐           ┌──────────────┐
//! │ 1. Execute   │           │ 1. Receive   │
//! │    txs       │           │    proposal  │
//! │              │           │              │
//! │ 2. Generate  │──────────►│ 2. Verify    │
//! │    witness   │           │    proof     │
//! │              │           │    (~10ms)   │
//! │ 3. Generate  │           │              │
//! │    proof     │           │ 3. Vote      │
//! │    (~2 sec)  │           │    approve   │
//! └──────────────┘           └──────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use ghost_zkp::{BlockProver, BlockVerifier, BlockWitness, BlockWitnessV2};
//!
//! // One-time setup (slow)
//! let prover = BlockProver::new_with_state_transitions(100, 20);
//! let verifier = BlockVerifier::new(prover.verification_key());
//!
//! // Per-block proving with full state transition proof (~2 seconds)
//! let witness = BlockWitnessV2::new(height, prev_root, new_root, transitions, 20);
//! let proof = prover.prove_v2(&witness)?;
//!
//! // Per-block verification (~10ms) - NO RE-EXECUTION NEEDED
//! assert!(verifier.verify(&proof)?);
//! ```

pub mod circuit;
pub mod errors;
pub mod payout_prover;
pub mod payout_verifier;
pub mod prover;
pub mod state_tree;
pub mod types;
pub mod verifier;

// Re-export main types
pub use errors::{ZkError, ZkResult};
pub use prover::BlockProver;
pub use types::{
    BlockProof, BlockWitness, BlockWitnessV2, MerkleProof, PaymentTransitionWitness,
    PaymentWitness, ProvingParams, StateSnapshot, VerificationKey,
};
pub use verifier::BlockVerifier;

// Re-export state tree utilities
pub use state_tree::{BalanceTree, BalanceTreeBuilder};

// Re-export payout types
pub use payout_prover::{PayoutProof, PayoutProver, PayoutWitness};
pub use payout_verifier::{verify_payout, PayoutVerificationResult, PayoutVerifier};

// Re-export circuit types for advanced usage
pub use circuit::{
    BlockCircuit, BlockCircuitBuilder, MerkleCircuit, PaymentCircuit,
    PaymentStateTransitionCircuit, StateTransitionOutputs,
};
