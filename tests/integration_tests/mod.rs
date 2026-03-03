//! Integration Tests for Bitcoin Ghost
//!
//! These tests verify end-to-end functionality across multiple components.
//!
//! # Test Categories (~875 tests total)
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
//! | 23 | wraith_transactions | 30 - Wraith tx builder, denomination math (700-729) |
//! | 24 | wraith_blind_signatures | 20 - Blind signature protocol (730-749) |
//! | 25 | ghost_lock_types | 30 - Ghost Lock creation, state machine (750-779) |
//! | 26 | settlement_reconciliation | 40 - Settlement, batches, merkle proofs (780-819) |
//! | 27 | gsp_payment_messages | 30 - GSP payment/lock/reorg messages (820-849) |
//! | 28 | l2_cross_layer | 20 - Cross-layer L2 integration (850-869) |
//! | 29 | l2_nullifier_route | 20 - L2 nullifier route, sender proofs (870-889) |
//! | 30 | wraith_e2e | 19 - Wraith E2E sessions, Jump Lock lifecycle, affordability (890-908) |
//! | 31 | wraith_fee_routing | 20 - Wraith fee routing pipeline, epoch tracking, settlement (910-929) |
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
//! cargo test --test integration wraith_transactions
//! cargo test --test integration wraith_blind_signatures
//! cargo test --test integration ghost_lock_types
//! cargo test --test integration settlement_reconciliation
//! cargo test --test integration gsp_payment_messages
//! cargo test --test integration l2_cross_layer
//! cargo test --test integration l2_nullifier_route
//! cargo test --test integration wraith_e2e
//! ```

pub mod block_template;
pub mod buds_classification;
pub mod config_validation;
pub mod consensus;
pub mod consensus_voting;
pub mod cryptography;
pub mod e2e;
pub mod edge_cases;
pub mod fund_safety;
pub mod ghost_lock_types;
pub mod ghost_pay;
pub mod gsp;
pub mod gsp_payment_messages;
pub mod helpers;
pub mod historical_bugs;
pub mod hypothetical_bugs;
pub mod l2_cross_layer;
pub mod l2_nullifier_route;
pub mod policy_enforcement;
pub mod pool_cycle;
pub mod round_management;
pub mod rpc_client;
pub mod security;
pub mod settlement_reconciliation;
pub mod silent_payment_v2;
pub mod storage;
pub mod stratum_payout_consensus;
pub mod stratum_validation;
pub mod wraith_blind_signatures;
pub mod wraith_e2e;
pub mod wraith_fee_routing;
pub mod wraith_protocol;
pub mod wraith_transactions;
