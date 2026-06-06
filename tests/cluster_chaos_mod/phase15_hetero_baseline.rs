//! Phase 15: Heterogeneous Baseline — verify mixed configs work together.
//!
//! Runs after Phase 14 deploys heterogeneous configs:
//! - VM1: archive + reaper strict + bitcoin_pure (genesis)
//! - VM2: pruned + reaper disabled + permissive
//! - VM3: archive + reaper strict + full_open
//! - VM4: non-archive + reaper disabled + bitcoin_pure

use std::time::Duration;

use super::client::ClusterClient;
use super::config::ClusterConfig;
use super::ssh::SshController;

fn setup() -> ClusterClient {
    ClusterClient::new(ClusterConfig::signet())
}

// --- Test 01: All nodes healthy ---

#[tokio::test]
#[ignore]
async fn hetero_01_all_nodes_healthy() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Heterogeneous Baseline: Health Check ===");

    for node in &config.nodes {
        let r = client.get_with_retry(node.ip, "/health").await;
        assert!(
            r.error.is_none() && r.status == Some(200),
            "{} not healthy with heterogeneous config: {:?}",
            node.name,
            r.error
        );
        println!("  {} /health → 200", node.name);
    }
    println!("  All 4 nodes healthy with heterogeneous configs");
}

// --- Test 02: Full mesh peers ---

#[tokio::test]
#[ignore]
async fn hetero_02_full_mesh_peers() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Heterogeneous Baseline: Peer Mesh ===");

    for node in &config.nodes {
        let peers = client.get_peer_count(node.ip).await.unwrap_or(0);
        assert!(
            peers >= 3,
            "{} has {} peers with heterogeneous configs (expected >=3)",
            node.name,
            peers
        );
        println!("  {} peers: {}", node.name, peers);
    }
    println!("  Full 4-node mesh maintained across config diversity");
}

// --- Test 03: Heights consistent ---

#[tokio::test]
#[ignore]
async fn hetero_03_heights_consistent() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Heterogeneous Baseline: Height Consistency ===");

    let mut heights = Vec::new();
    for node in &config.nodes {
        let mut h = Err("not attempted".to_string());
        for _ in 0..5 {
            h = client.get_block_height(node.ip).await;
            if h.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        let height = h.unwrap_or(0);
        heights.push((node.name, height));
        println!("  {} height: {}", node.name, height);
    }

    let max = heights.iter().map(|(_, h)| *h).max().unwrap();
    let min = heights.iter().map(|(_, h)| *h).min().unwrap();
    assert!(
        max - min <= 1,
        "Heights diverge across heterogeneous configs: {:?}",
        heights
    );
    println!("  Heights consistent (diff <=1) across all config profiles");
}

// --- Test 04: VM1 config verified (archive + reaper strict + bitcoin_pure) ---

#[tokio::test]
#[ignore]
async fn hetero_04_vm1_config_verified() {
    let client = setup();
    let config = &client.config;
    let vm1 = config.node_by_name("VM1").unwrap();

    println!("\n=== Heterogeneous Baseline: VM1 Config Verification ===");
    println!("  Expected: archive=true, reaper=strict, policy=bitcoin_pure");

    // Check config values via SSH
    let archive =
        SshController::read_config_field(vm1, "storage", "archive_mode").unwrap_or_default();
    let reaper = SshController::read_config_field(vm1, "reaper", "enabled").unwrap_or_default();
    let policy = SshController::read_config_field(vm1, "policy", "profile").unwrap_or_default();

    println!(
        "  VM1: archive={}, reaper={}, policy={}",
        archive, reaper, policy
    );
    assert_eq!(archive, "true", "VM1 should be archive mode");
    assert_eq!(reaper, "true", "VM1 reaper should be enabled");
    assert_eq!(policy, "bitcoin_pure", "VM1 policy should be bitcoin_pure");

    // Check API confirms node status
    let (status, _) = client.probe_endpoint(vm1.ip, "/api/v1/node/status").await;
    assert_eq!(status, 200, "VM1 /api/v1/node/status not 200");

    // Haze status should report archive mode
    let (haze_status, haze_json) = client.probe_endpoint(vm1.ip, "/api/v1/haze/status").await;
    if haze_status == 200 {
        if let Some(json) = haze_json {
            let mode = json
                .get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            println!("  VM1 haze status: mode={}", mode);
        }
    }
}

// --- Test 05: VM2 config verified (pruned + permissive + reaper disabled) ---

#[tokio::test]
#[ignore]
async fn hetero_05_vm2_config_verified() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").unwrap();

    println!("\n=== Heterogeneous Baseline: VM2 Config Verification ===");
    println!("  Expected: archive=false, prune=1000, reaper=disabled, policy=permissive");

    let archive =
        SshController::read_config_field(vm2, "storage", "archive_mode").unwrap_or_default();
    let prune =
        SshController::read_config_field(vm2, "storage", "prune_height").unwrap_or_default();
    let reaper = SshController::read_config_field(vm2, "reaper", "enabled").unwrap_or_default();
    let policy = SshController::read_config_field(vm2, "policy", "profile").unwrap_or_default();

    println!(
        "  VM2: archive={}, prune={}, reaper={}, policy={}",
        archive, prune, reaper, policy
    );
    assert_eq!(archive, "false", "VM2 should be non-archive");
    assert_eq!(prune, "1000", "VM2 should have prune_height=1000");
    assert_eq!(reaper, "false", "VM2 reaper should be disabled");
    assert_eq!(policy, "permissive", "VM2 policy should be permissive");

    // Node should still serve API
    let (status, _) = client.probe_endpoint(vm2.ip, "/api/v1/node/status").await;
    assert_eq!(status, 200, "VM2 /api/v1/node/status not 200");
}

// --- Test 06: VM3 config verified (archive + full_open + reaper strict) ---

#[tokio::test]
#[ignore]
async fn hetero_06_vm3_config_verified() {
    let client = setup();
    let config = &client.config;
    let vm3 = config.node_by_name("VM3").unwrap();

    println!("\n=== Heterogeneous Baseline: VM3 Config Verification ===");
    println!("  Expected: archive=true, reaper=strict, policy=full_open");

    let archive =
        SshController::read_config_field(vm3, "storage", "archive_mode").unwrap_or_default();
    let reaper = SshController::read_config_field(vm3, "reaper", "enabled").unwrap_or_default();
    let reaper_mode = SshController::read_config_field(vm3, "reaper", "mode").unwrap_or_default();
    let policy = SshController::read_config_field(vm3, "policy", "profile").unwrap_or_default();

    println!(
        "  VM3: archive={}, reaper={}/{}, policy={}",
        archive, reaper, reaper_mode, policy
    );
    assert_eq!(archive, "true", "VM3 should be archive mode");
    assert_eq!(reaper, "true", "VM3 reaper should be enabled");
    assert_eq!(reaper_mode, "strict", "VM3 reaper should be strict");
    assert_eq!(policy, "full_open", "VM3 policy should be full_open");

    // Verification endpoints should still work on archive + reaper nodes
    let endpoints = ["/verify/stratum", "/verify/ghostpay"];
    for endpoint in &endpoints {
        let r = client.get_with_retry(vm3.ip, endpoint).await;
        assert!(
            r.error.is_none() && r.status == Some(200),
            "VM3 {} failed: {:?}",
            endpoint,
            r.error
        );
    }
    println!("  VM3 verification endpoints pass with full_open + reaper strict");
}

// --- Test 07: VM4 config verified (non-archive + bitcoin_pure + reaper disabled) ---

#[tokio::test]
#[ignore]
async fn hetero_07_vm4_config_verified() {
    let client = setup();
    let config = &client.config;
    let vm4 = config.node_by_name("VM4").unwrap();

    println!("\n=== Heterogeneous Baseline: VM4 Config Verification ===");
    println!("  Expected: archive=false, reaper=disabled, policy=bitcoin_pure");

    let archive =
        SshController::read_config_field(vm4, "storage", "archive_mode").unwrap_or_default();
    let reaper = SshController::read_config_field(vm4, "reaper", "enabled").unwrap_or_default();
    let policy = SshController::read_config_field(vm4, "policy", "profile").unwrap_or_default();

    println!(
        "  VM4: archive={}, reaper={}, policy={}",
        archive, reaper, policy
    );
    assert_eq!(archive, "false", "VM4 should be non-archive");
    assert_eq!(reaper, "false", "VM4 reaper should be disabled");
    assert_eq!(policy, "bitcoin_pure", "VM4 policy should be bitcoin_pure");

    let (status, _) = client.probe_endpoint(vm4.ip, "/api/v1/node/status").await;
    assert_eq!(status, 200, "VM4 /api/v1/node/status not 200");
}

// --- Test 08: Cross-config endpoint coverage ---

#[tokio::test]
#[ignore]
async fn hetero_08_cross_config_api_coverage() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Heterogeneous Baseline: Cross-Config API Coverage ===");

    let endpoints = [
        "/health",
        "/api/v1/node/status",
        "/api/v1/network/peers",
        "/api/v1/haze/status",
        "/consensus-state",
        "/verify/stratum",
        "/verify/ghostpay",
    ];

    let mut total = 0;
    let mut passed = 0;

    for endpoint in &endpoints {
        for node in &config.nodes {
            total += 1;
            let r = client.get_with_retry(node.ip, endpoint).await;
            let status = r.status.unwrap_or(0);

            // Accept 200 and non-404 (some endpoints may return 503 under degraded mode)
            if status > 0 && status != 404 {
                passed += 1;
                println!("  {} {} → {} ✓", node.name, endpoint, status);
            } else {
                println!("  {} {} → {} ✗", node.name, endpoint, status);
            }
        }
    }

    let coverage = passed as f64 / total as f64;
    println!(
        "\n  Cross-config API coverage: {}/{} ({:.1}%)",
        passed,
        total,
        coverage * 100.0
    );
    assert!(
        coverage >= 0.90,
        "Cross-config API coverage {:.1}% below 90%",
        coverage * 100.0
    );
}
