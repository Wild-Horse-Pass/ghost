//! Phase 10: Node Flapping — rapid kill/restart cycling to stress exponential backoff.
//!
//! Tests the reconnect logic (100ms initial, 30s max backoff) by rapidly cycling
//! nodes without waiting for full health between cycles.

use std::sync::Arc;
use std::time::Duration;

use super::client::ClusterClient;
use super::config::{ClusterConfig, NodeInfo};
use super::ssh::SshController;

fn setup() -> Arc<ClusterClient> {
    Arc::new(ClusterClient::new(ClusterConfig::signet()))
}

/// Rapidly cycle a node: stop → wait gap → start → wait gap, repeated `cycles` times.
/// Does NOT wait for full health between cycles — that's the point.
async fn flap_node(node: &NodeInfo, service: &str, cycles: usize, gap: Duration) {
    for i in 1..=cycles {
        println!("  [FLAP] {} cycle {}/{}: stopping", node.name, i, cycles);
        SshController::stop_node(node, service).expect(&format!(
            "failed to stop {} on cycle {}",
            node.name, i
        ));
        tokio::time::sleep(gap).await;

        println!("  [FLAP] {} cycle {}/{}: starting", node.name, i, cycles);
        SshController::start_node(node, service).expect(&format!(
            "failed to start {} on cycle {}",
            node.name, i
        ));
        tokio::time::sleep(gap).await;
    }
}

// --- Test 01: Moderate flapping (5 cycles, 5s gaps) ---

#[tokio::test]
#[ignore]
async fn flap_01_vm2_moderate_5x5s() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").expect("VM2 not found");

    println!("\n=== Node Flapping: VM2 Moderate (5×5s) ===");

    flap_node(vm2, config.service_name, 5, Duration::from_secs(5)).await;

    // Allow settling time for backoff reconnect
    println!("  Waiting 60s for mesh reconvergence...");
    tokio::time::sleep(Duration::from_secs(60)).await;

    assert!(
        client
            .wait_for_node_healthy(vm2.ip, config.recovery_timeout)
            .await,
        "VM2 not healthy after moderate flapping"
    );

    let peers = client.get_peer_count(vm2.ip).await.unwrap_or(0);
    assert!(
        peers >= 3,
        "VM2 has {} peers after moderate flap (expected >=3)",
        peers
    );
    println!("  VM2 recovered: healthy with {} peers", peers);
}

// --- Test 02: Aggressive flapping (5 cycles, 2s gaps) ---

#[tokio::test]
#[ignore]
async fn flap_02_vm2_aggressive_5x2s() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").expect("VM2 not found");

    println!("\n=== Node Flapping: VM2 Aggressive (5×2s) ===");

    flap_node(vm2, config.service_name, 5, Duration::from_secs(2)).await;

    // Longer settling time — aggressive flapping may trigger systemd rate limits
    println!("  Waiting 90s for mesh reconvergence...");
    tokio::time::sleep(Duration::from_secs(90)).await;

    assert!(
        client
            .wait_for_node_healthy(vm2.ip, Duration::from_secs(120))
            .await,
        "VM2 not healthy after aggressive flapping"
    );

    let peers = client.get_peer_count(vm2.ip).await.unwrap_or(0);
    assert!(
        peers >= 3,
        "VM2 has {} peers after aggressive flap (expected >=3)",
        peers
    );
    println!("  VM2 recovered: healthy with {} peers", peers);
}

// --- Test 03: Alternating VM2/VM3 flapping ---

#[tokio::test]
#[ignore]
async fn flap_03_alternating_vm2_vm3() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").expect("VM2 not found");
    let vm3 = config.node_by_name("VM3").expect("VM3 not found");
    let svc = config.service_name;

    println!("\n=== Node Flapping: Alternating VM2/VM3 (3 cycles) ===");

    for i in 1..=3 {
        println!("  [CYCLE {}] stop VM2, stop VM3, start VM2, start VM3", i);
        SshController::stop_node(vm2, svc).expect("failed to stop VM2");
        tokio::time::sleep(Duration::from_secs(2)).await;

        SshController::stop_node(vm3, svc).expect("failed to stop VM3");
        tokio::time::sleep(Duration::from_secs(2)).await;

        SshController::start_node(vm2, svc).expect("failed to start VM2");
        tokio::time::sleep(Duration::from_secs(2)).await;

        SshController::start_node(vm3, svc).expect("failed to start VM3");
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    // Allow settling
    println!("  Waiting 60s for mesh reconvergence...");
    tokio::time::sleep(Duration::from_secs(60)).await;

    for node in [vm2, vm3] {
        assert!(
            client
                .wait_for_node_healthy(node.ip, config.recovery_timeout)
                .await,
            "{} not healthy after alternating flap",
            node.name
        );

        let peers = client.get_peer_count(node.ip).await.unwrap_or(0);
        assert!(
            peers >= 3,
            "{} has {} peers after alternating flap (expected >=3)",
            node.name,
            peers
        );
        println!("  {} recovered: healthy with {} peers", node.name, peers);
    }
}

// --- Test 04: Survivors healthy during VM2 flap ---

#[tokio::test]
#[ignore]
async fn flap_04_survivors_healthy_during_flap() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").expect("VM2 not found");
    let svc = config.service_name;

    println!("\n=== Node Flapping: Survivor Health During VM2 Flap ===");

    let survivor_ips: Vec<String> = config
        .all_ips()
        .into_iter()
        .filter(|ip| *ip != vm2.ip)
        .map(String::from)
        .collect();

    // Track health polls per node
    let mut polls_per_node: Vec<(String, usize, usize)> = survivor_ips
        .iter()
        .map(|ip| (ip.clone(), 0usize, 0usize)) // (ip, total, healthy)
        .collect();

    // Flap VM2 in background while polling survivors
    let vm2_clone = vm2.clone();
    let svc_owned = svc.to_string();
    let flap_handle = tokio::task::spawn_blocking(move || {
        for i in 1..=5 {
            println!("  [BG-FLAP] VM2 cycle {}/5", i);
            SshController::stop_node(&vm2_clone, &svc_owned).ok();
            std::thread::sleep(std::time::Duration::from_secs(3));
            SshController::start_node(&vm2_clone, &svc_owned).ok();
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
    });

    // Poll survivors during the flap (~30s)
    let poll_deadline =
        tokio::time::Instant::now() + Duration::from_secs(35);
    while tokio::time::Instant::now() < poll_deadline {
        for entry in &mut polls_per_node {
            let r = client.get(&entry.0, "/health").await;
            entry.1 += 1;
            if r.error.is_none() && r.status == Some(200) {
                entry.2 += 1;
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    flap_handle.await.ok();

    // VM1 (genesis) should be 100%, others >=95%
    for (ip, total, healthy) in &polls_per_node {
        let rate = if *total > 0 {
            *healthy as f64 / *total as f64
        } else {
            0.0
        };
        println!(
            "  {} health rate: {}/{} ({:.1}%)",
            ip,
            healthy,
            total,
            rate * 100.0
        );

        let is_vm1 = ip == config.nodes[0].ip;
        let threshold = if is_vm1 { 1.0 } else { 0.95 };
        assert!(
            rate >= threshold,
            "Survivor {} health rate {:.1}% below {:.0}% during flap",
            ip,
            rate * 100.0,
            threshold * 100.0
        );
    }
}

// --- Test 05: Full mesh reconvergence after settling ---

#[tokio::test]
#[ignore]
async fn flap_05_mesh_reconverges() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Node Flapping: Mesh Reconvergence Check ===");

    for ip in config.all_ips() {
        assert!(
            client
                .wait_for_node_healthy(ip, config.recovery_timeout)
                .await,
            "{} not healthy after flapping tests",
            ip
        );

        let peers = client.get_peer_count(ip).await.unwrap_or(0);
        assert!(
            peers >= 3,
            "{} has {} peers (expected >=3)",
            ip,
            peers
        );
        println!("  {} healthy, {} peers", ip, peers);
    }
    println!("  Full 4-node mesh reconverged");
}

// --- Test 06: Block heights consistent ---

#[tokio::test]
#[ignore]
async fn flap_06_heights_consistent() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Node Flapping: Height Consistency ===");

    let mut heights = Vec::new();
    for ip in config.all_ips() {
        let mut h = Err("not attempted".to_string());
        for _ in 0..5 {
            h = client.get_block_height(ip).await;
            if h.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        let height = h.unwrap_or(0);
        heights.push((ip, height));
        println!("  {} height: {}", ip, height);
    }

    let max = heights.iter().map(|(_, h)| *h).max().unwrap();
    let min = heights.iter().map(|(_, h)| *h).min().unwrap();
    assert!(
        max - min <= 1,
        "Post-flap heights diverge: {:?}",
        heights
    );
    println!("  Heights consistent (diff <=1)");
}

// --- Test 07: Zero panics ---

#[tokio::test]
#[ignore]
async fn flap_07_zero_panics() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Node Flapping: Zero Panics Check ===");

    for node in &config.nodes {
        let panics = SshController::count_log_matches(
            node,
            config.service_name,
            "panic",
            "20 min ago",
        )
        .unwrap_or(0);
        assert_eq!(
            panics, 0,
            "Post-flap: {} had {} panics in last 20 min",
            node.name, panics
        );
        println!("  {} — zero panics", node.name);
    }
    println!("  All nodes panic-free after flapping tests");
}
