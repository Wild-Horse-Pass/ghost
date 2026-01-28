//! Load Testing Infrastructure for Bitcoin Ghost
//!
//! Tests system performance under heavy load:
//! - 1000+ concurrent miner connections
//! - High throughput share submissions
//! - Consensus message flooding
//! - Memory usage under load

pub mod mining_load;
pub mod stratum_stress;
pub mod consensus_load;
