//! Load test runner
//!
//! Run with: cargo test --test load_tests
//!
//! For large-scale tests (ignored by default):
//!   cargo test --test load_tests -- --ignored

#[path = "load_tests_mod/mod.rs"]
mod load_tests_mod;

// Re-export for easier access
pub use load_tests_mod::consensus_load;
pub use load_tests_mod::mining_load;
pub use load_tests_mod::stratum_stress;
