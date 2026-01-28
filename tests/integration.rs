//! Integration test runner
//!
//! Run with: cargo test --test integration

#[path = "integration_tests/mod.rs"]
mod integration_tests;

// Re-export for easier access
pub use integration_tests::helpers;
