//! Live Cluster Chaos & Load Tests (67 tests across 9 phases)
//!
//! Hits the 4-node signet cluster via HTTP and SSH to verify:
//! - Phase 1: Baseline health and consistency (8 tests)
//! - Phase 2: Load handling under concurrent requests (8 tests)
//! - Phase 3: Single-node failure/recovery (8 tests)
//! - Phase 4: Post-chaos cluster consistency (7 tests)
//! - Phase 5: Multi-node kill (50% failure) and staged recovery (8 tests)
//! - Phase 6: Rolling restart with varying delays (6 tests)
//! - Phase 7: Network partition via iptables (single-node + split-brain) (8 tests)
//! - Phase 8: Endpoint coverage (~50 endpoints, degraded mode) (8 tests)
//! - Phase 9: Rate limiter characterization (measurement-only) (6 tests)
//!
//! All tests are `#[ignore]` — run explicitly:
//!
//! ```bash
//! # Full suite (sequential, ~20-25 minutes)
//! cargo test --test cluster_chaos -- --ignored --test-threads=1 --nocapture
//!
//! # Individual phases
//! cargo test --test cluster_chaos phase1_baseline -- --ignored --test-threads=1 --nocapture
//! cargo test --test cluster_chaos phase2_load -- --ignored --test-threads=1 --nocapture
//! cargo test --test cluster_chaos phase3_chaos -- --ignored --test-threads=1 --nocapture
//! cargo test --test cluster_chaos phase4_recovery -- --ignored --test-threads=1 --nocapture
//! cargo test --test cluster_chaos phase5_multi_kill -- --ignored --test-threads=1 --nocapture
//! cargo test --test cluster_chaos phase6_rolling -- --ignored --test-threads=1 --nocapture
//! cargo test --test cluster_chaos phase7_network -- --ignored --test-threads=1 --nocapture
//! cargo test --test cluster_chaos phase8_endpoint -- --ignored --test-threads=1 --nocapture
//! cargo test --test cluster_chaos phase9_rate -- --ignored --test-threads=1 --nocapture
//! ```

#[path = "cluster_chaos_mod/mod.rs"]
mod cluster_chaos_mod;
