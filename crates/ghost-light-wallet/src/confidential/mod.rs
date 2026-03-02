//! Confidential transfer support for the light wallet
//!
//! This module provides client-side ZK proof generation for confidential
//! transfers. The wallet generates Groth16 proofs locally (only it knows
//! values + blindings) and the server verifies and applies the proof.
//!
//! # Submodules
//!
//! - [`notes`] - Owned note tracking and management
//! - [`prover`] - Local ZK proof generation
//! - [`tree_sync`] - Commitment tree synchronization with GSP

pub mod notes;
pub mod params_cache;
pub mod prover;
pub mod scanner;
pub mod tree_sync;

pub use notes::{ConsolidationPlan, NoteSelection, NoteStore, OwnedNote};
pub use params_cache::{default_params_cache_dir, ParamsCache};
#[allow(deprecated)]
pub use prover::{
    ClientProver, ConfidentialTransferResult, NoteSpendClientProver, NoteSpendTransferResult,
};
pub use scanner::{DiscoveredNote, NoteScanner};
pub use tree_sync::TreeSync;
