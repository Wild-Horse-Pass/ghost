//! Live Cluster Chaos & Load Tests
//!
//! Tests that hit the real 4-node signet cluster via HTTP and SSH.
//! Run with: cargo test --test cluster_chaos -- --ignored --test-threads=1 --nocapture

pub mod client;
pub mod config;
pub mod metrics;
pub mod ssh;

pub mod phase1_baseline;
pub mod phase2_load;
pub mod phase3_chaos;
pub mod phase4_recovery;
pub mod phase5_multi_kill;
pub mod phase6_rolling_restart;
pub mod phase7_network_partition;
pub mod phase8_endpoint_coverage;
pub mod phase9_rate_limiter;

pub mod phase10_node_flapping;
pub mod phase11_asymmetric_partition;
pub mod phase12_compound_failures;
pub mod phase13_genesis_resilience;

pub mod phase14_deploy_heterogeneous;
pub mod phase15_hetero_baseline;
pub mod phase16_hetero_chaos;
pub mod phase17_restore_configs;

pub mod phase18_deploy_core_modes;
pub mod phase19_core_mode_chaos;
pub mod phase20_restore_core_configs;
