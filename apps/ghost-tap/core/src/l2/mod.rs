//! L2 Confidential Payment Support
//!
//! Client-side ZK proof generation, note tracking, and tree sync
//! for Ghost's L2 confidential payment system. Adapted from
//! `ghost-light-wallet::confidential` for the ghost-tap mobile architecture.

pub mod note_store;
pub mod params_cache;
pub mod prover;
pub mod scanner;
pub mod tree_sync;

pub use note_store::{ConsolidationPlan, NoteSelection, NoteStore, OwnedNote};
pub use params_cache::ParamsCache;
pub use prover::{ConsolidationResult, L2Prover, TransferResult, UnshieldResult};
pub use scanner::{DiscoveredNote, NoteScanner};
pub use tree_sync::TreeSync;
