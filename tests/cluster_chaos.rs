//! Live Cluster Chaos & Load Tests (139 tests across 20 phases)
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
//! - Phase 10: Node flapping — rapid kill/restart cycling (7 tests)
//! - Phase 11: Asymmetric partition — one-directional network failures (8 tests)
//! - Phase 12: Compound failures — simultaneous partition + kill (8 tests)
//! - Phase 13: Genesis resilience — force-stop genesis node (8 tests)
//! - Phase 14: Deploy heterogeneous configs — mixed archive/pruned/reaper/policy (6 tests)
//! - Phase 15: Heterogeneous baseline — verify mixed configs work together (8 tests)
//! - Phase 16: Heterogeneous chaos — load + kills + partitions with mixed configs (8 tests)
//! - Phase 17: Restore original configs — undo Phase 14 deployment (4 tests)
//! - Phase 18: Deploy Ghost Core modes — enable tormode on VM3 (4 tests)
//! - Phase 19: Ghost Core mode chaos — load + kills + partitions with Tor/clearnet mix (8 tests)
//! - Phase 20: Restore Ghost Core configs — undo Phase 18 deployment (3 tests)
//!
//! All tests are `#[ignore]` — run explicitly:
//!
//! ```bash
//! # Full suite (sequential, ~90-120 minutes)
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
//! cargo test --test cluster_chaos phase10 -- --ignored --test-threads=1 --nocapture
//! cargo test --test cluster_chaos phase11 -- --ignored --test-threads=1 --nocapture
//! cargo test --test cluster_chaos phase12 -- --ignored --test-threads=1 --nocapture
//! cargo test --test cluster_chaos phase13 -- --ignored --test-threads=1 --nocapture
//! cargo test --test cluster_chaos phase14 -- --ignored --test-threads=1 --nocapture
//! cargo test --test cluster_chaos phase15 -- --ignored --test-threads=1 --nocapture
//! cargo test --test cluster_chaos phase16 -- --ignored --test-threads=1 --nocapture
//! cargo test --test cluster_chaos phase17 -- --ignored --test-threads=1 --nocapture
//! cargo test --test cluster_chaos phase18 -- --ignored --test-threads=1 --nocapture
//! cargo test --test cluster_chaos phase19 -- --ignored --test-threads=1 --nocapture
//! cargo test --test cluster_chaos phase20 -- --ignored --test-threads=1 --nocapture
//!
//! # Heterogeneous config suite (phases 14-17 together)
//! cargo test --test cluster_chaos "phase1[4-7]" -- --ignored --test-threads=1 --nocapture
//!
//! # Ghost Core mode suite (phases 18-20 together)
//! cargo test --test cluster_chaos "phase1[8-9]\|phase20" -- --ignored --test-threads=1 --nocapture
//! ```

#[path = "cluster_chaos_mod/mod.rs"]
mod cluster_chaos_mod;
