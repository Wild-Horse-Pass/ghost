//! Integration Tests for Bitcoin Ghost
//!
//! These tests verify end-to-end functionality across multiple components.
//!
//! # Test Categories (~600 tests total)
//!
//! | Category | Module | Tests |
//! |----------|--------|-------|
//! | 1 | cryptography | 40 - Ed25519, PoW, HMAC, signatures |
//! | 2 | config_validation | 50 - Configuration validation |
//! | 3 | rpc_client | 55 - Bitcoin Core RPC client |
//! | 4 | stratum_validation | 70 - Stratum protocol validation |
//! | 5 | consensus_voting | 60 - BFT consensus and voting |
//! | 6 | buds_classification | 27 - BUDS transaction classification |
//! | 7 | policy_enforcement | 35 - Fee and policy rules |
//! | 8 | block_template | 45 - Block template management |
//! | 9 | storage | 50 - Database and persistence |
//! | 10 | wraith_protocol | 55 - Wraith mixing protocol |
//! | 11 | ghost_pay | 40 - L2 payment channels |
//! | 13 | round_management | 30 - Mining round lifecycle |
//! | 18 | security | 25 - Security-focused tests |
//! | 19 | edge_cases | 50 - Boundary conditions |
//! | 20 | fund_safety | 16 - Fund loss prevention |
//! | 21 | historical_bugs | 25 - CVE-2010-5139, 2013 fork, CVE-2018-17144 |
//! | 22 | hypothetical_bugs | 29 - Undiscovered vulnerability patterns |
//!
//! # Running Tests
//!
//! ```bash
//! # Run all integration tests
//! cargo test --test integration
//!
//! # Run specific category
//! cargo test --test integration cryptography
//! cargo test --test integration config_validation
//! cargo test --test integration stratum_validation
//! cargo test --test integration consensus_voting
//! cargo test --test integration buds_classification
//! cargo test --test integration wraith_protocol
//! cargo test --test integration security
//! cargo test --test integration ghost_pay
//! cargo test --test integration round_management
//! cargo test --test integration edge_cases
//! ```

pub mod cryptography;
pub mod config_validation;
pub mod stratum_validation;
pub mod consensus_voting;
pub mod buds_classification;
pub mod wraith_protocol;
pub mod security;
pub mod rpc_client;
pub mod policy_enforcement;
pub mod block_template;
pub mod storage;
pub mod ghost_pay;
pub mod round_management;
pub mod edge_cases;
pub mod pool_cycle;
pub mod consensus;
pub mod fund_safety;
pub mod historical_bugs;
pub mod hypothetical_bugs;
pub mod stratum_payout_consensus;
pub mod gsp;
pub mod helpers;
