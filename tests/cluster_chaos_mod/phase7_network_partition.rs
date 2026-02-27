//! Phase 7: Network Partition — iptables-based partition without killing processes.
//!
//! Every test starts with `cleanup_all_partitions()` as a safety reset.
//!
//! Scenario A (tests 01-04): Single-node isolation (VM2 partitioned from all peers).
//! Scenario B (tests 05-08): Split-brain (VM1+VM2 vs VM3+VM4).

use std::time::Duration;

use super::client::ClusterClient;
use super::config::ClusterConfig;
use super::ssh::SshController;

fn setup() -> ClusterClient {
    let config = ClusterConfig::signet();
    // Safety: always clean up before starting
    SshController::cleanup_all_partitions(&config).ok();
    ClusterClient::new(config)
}

/// Wait for a node to reach a target peer count within a timeout.
async fn wait_for_peers(
    client: &ClusterClient,
    ip: &str,
    min_peers: usize,
    timeout: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if let Ok(peers) = client.get_peer_count(ip).await {
            if peers >= min_peers {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    false
}

// ========== Scenario A: Single-node isolation ==========

#[tokio::test]
#[ignore]
async fn partition_01_isolate_vm2() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").expect("VM2 not found");

    println!("\n=== Network Partition: Isolating VM2 ===");

    // Set up partition chain on all nodes, then block VM2 from each peer
    for node in &config.nodes {
        SshController::setup_partition_chain(node).expect(&format!(
            "failed to setup chain on {}",
            node.name
        ));
    }

    // Block VM2 ↔ every other node (bidirectional)
    for node in &config.nodes {
        if node.ip == vm2.ip {
            // On VM2, block all peers
            for peer in &config.nodes {
                if peer.ip != vm2.ip {
                    SshController::block_peer(vm2, peer.ip)
                        .expect(&format!("failed to block {} on VM2", peer.name));
                }
            }
        } else {
            // On each peer, block VM2
            SshController::block_peer(node, vm2.ip)
                .expect(&format!("failed to block VM2 on {}", node.name));
        }
    }

    // Wait for partition to take effect
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Verify VM1+VM3+VM4 still see each other
    let survivors: Vec<&str> = config
        .all_ips()
        .into_iter()
        .filter(|ip| *ip != vm2.ip)
        .collect();

    for ip in &survivors {
        let r = client.get_with_retry(ip, "/health").await;
        assert!(
            r.error.is_none() && r.status == Some(200),
            "Survivor {} not healthy after partition: {:?}",
            ip,
            r.error
        );
    }
    println!("  VM2 isolated — VM1+VM3+VM4 still healthy");
}

#[tokio::test]
#[ignore]
async fn partition_02_isolated_api_reachable() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").unwrap();

    println!("\n=== Network Partition: Isolated VM2 API Check ===");

    // VM2's API should still respond (SSH and HTTP port 8080 not blocked for test client)
    // Note: we're connecting from the test runner, not from other nodes
    let r = client.get_with_retry(vm2.ip, "/health").await;
    let status = r.status.unwrap_or(0);
    println!("  VM2 /health → {} (API reachable from test runner)", status);

    // Peer count should drop to 0 (partitioned from all mesh peers)
    // Allow some time for the node to detect lost peers
    tokio::time::sleep(Duration::from_secs(5)).await;
    let peers = client.get_peer_count(vm2.ip).await.unwrap_or(999);
    println!("  VM2 peer count: {} (expected 0 or near-0)", peers);
    assert!(
        peers <= 1,
        "VM2 should have 0-1 peers while partitioned, got {}",
        peers
    );
}

#[tokio::test]
#[ignore]
async fn partition_03_survivors_maintain_mesh() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").unwrap();

    println!("\n=== Network Partition: Survivor Mesh Check ===");

    let survivors: Vec<&str> = config
        .all_ips()
        .into_iter()
        .filter(|ip| *ip != vm2.ip)
        .collect();

    for ip in &survivors {
        let peers = client.get_peer_count(ip).await.unwrap_or(0);
        assert!(
            peers >= 2,
            "Survivor {} has only {} peers (expected >=2)",
            ip,
            peers
        );
        println!("  {} has {} peers", ip, peers);
    }

    // Check height consistency among survivors
    let mut heights = Vec::new();
    for ip in &survivors {
        if let Ok(h) = client.get_block_height(ip).await {
            heights.push((*ip, h));
            println!("  {} height: {}", ip, h);
        }
    }
    if heights.len() >= 2 {
        let max = heights.iter().map(|(_, h)| *h).max().unwrap();
        let min = heights.iter().map(|(_, h)| *h).min().unwrap();
        assert!(
            max - min <= 1,
            "Survivor heights diverge during partition: {:?}",
            heights
        );
    }
    println!("  Survivors maintain consistent mesh during VM2 isolation");
}

#[tokio::test]
#[ignore]
async fn partition_04_heal_and_reconverge() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").unwrap();

    println!("\n=== Network Partition: Healing VM2 ===");

    // Remove all partition rules
    SshController::cleanup_all_partitions(config).ok();
    println!("  Partition rules removed");

    // Wait for VM2 to rejoin
    let rejoined = wait_for_peers(&client, vm2.ip, 3, config.recovery_timeout).await;
    let final_peers = client.get_peer_count(vm2.ip).await.unwrap_or(0);
    println!("  VM2 peers after heal: {}", final_peers);
    assert!(
        rejoined,
        "VM2 did not regain 3 peers after partition heal (got {})",
        final_peers
    );
    println!("  VM2 reconverged with full mesh");
}

// ========== Scenario B: Split-brain ==========

#[tokio::test]
#[ignore]
async fn partition_05_split_brain_setup() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Network Partition: Split-Brain Setup (VM1+VM2 vs VM3+VM4) ===");

    let group_a = ["VM1", "VM2"]; // IPs for group A
    let group_b = ["VM3", "VM4"]; // IPs for group B

    // Set up partition chains on all nodes
    for node in &config.nodes {
        SshController::setup_partition_chain(node).expect(&format!(
            "failed to setup chain on {}",
            node.name
        ));
    }

    // Block cross-group traffic: each node in group A blocks each node in group B and vice versa
    for a_name in &group_a {
        let a_node = config.node_by_name(a_name).unwrap();
        for b_name in &group_b {
            let b_node = config.node_by_name(b_name).unwrap();
            SshController::block_peer(a_node, b_node.ip)
                .expect(&format!("failed to block {} on {}", b_name, a_name));
        }
    }
    for b_name in &group_b {
        let b_node = config.node_by_name(b_name).unwrap();
        for a_name in &group_a {
            let a_node = config.node_by_name(a_name).unwrap();
            SshController::block_peer(b_node, a_node.ip)
                .expect(&format!("failed to block {} on {}", a_name, b_name));
        }
    }

    // Wait for partition to take effect
    tokio::time::sleep(Duration::from_secs(10)).await;

    // All 4 APIs should still be reachable from the test runner
    for ip in config.all_ips() {
        let r = client.get_with_retry(ip, "/health").await;
        let status = r.status.unwrap_or(0);
        println!("  {} /health → {}", ip, status);
        // Don't assert 200 — node might report degraded, but route must exist
        assert_ne!(status, 0, "Cannot reach {} at all during split-brain", ip);
    }
    println!("  Split-brain established — all APIs reachable from test runner");
}

#[tokio::test]
#[ignore]
async fn partition_06_split_brain_peer_counts() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Network Partition: Split-Brain Peer Counts ===");

    // Group A: VM1+VM2 should see ~1 peer (each other)
    // Group B: VM3+VM4 should see ~1 peer (each other)
    let groups = [
        ("Group A (VM1+VM2)", vec!["VM1", "VM2"]),
        ("Group B (VM3+VM4)", vec!["VM3", "VM4"]),
    ];

    for (label, names) in &groups {
        println!("  {}:", label);
        for name in names {
            let node = config.node_by_name(name).unwrap();
            let peers = client.get_peer_count(node.ip).await.unwrap_or(0);
            println!("    {} has {} peers", name, peers);
            // Each side should see roughly 1 peer (their partner)
            assert!(
                peers <= 2,
                "{} sees {} peers — partition may not be effective",
                name,
                peers
            );
        }
    }
}

#[tokio::test]
#[ignore]
async fn partition_07_split_brain_api_works() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Network Partition: Split-Brain API Check ===");

    let endpoints = ["/health", "/api/v1/node/status"];

    for endpoint in &endpoints {
        for ip in config.all_ips() {
            let r = client.get_with_retry(ip, endpoint).await;
            let status = r.status.unwrap_or(0);
            println!("  {} {} → {}", ip, endpoint, status);
            assert_ne!(
                status, 0,
                "Cannot reach {} {} during split-brain",
                ip, endpoint
            );
        }
    }
    println!("  All 4 nodes serve API during split-brain");
}

#[tokio::test]
#[ignore]
async fn partition_08_heal_split_brain() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Network Partition: Healing Split-Brain ===");

    // Remove all partition rules
    SshController::cleanup_all_partitions(config).ok();
    println!("  All partition rules removed");

    // Wait for all nodes to regain 3 peers
    for ip in config.all_ips() {
        let rejoined = wait_for_peers(&client, ip, 3, config.recovery_timeout).await;
        let peers = client.get_peer_count(ip).await.unwrap_or(0);
        println!("  {} peers: {}", ip, peers);
        assert!(
            rejoined,
            "{} did not regain 3 peers after split-brain heal (got {})",
            ip,
            peers
        );
    }

    // Heights converge
    tokio::time::sleep(Duration::from_secs(5)).await;
    let mut heights = Vec::new();
    for ip in config.all_ips() {
        if let Ok(h) = client.get_block_height(ip).await {
            heights.push((ip, h));
            println!("  {} height: {}", ip, h);
        }
    }
    if heights.len() == config.nodes.len() {
        let max = heights.iter().map(|(_, h)| *h).max().unwrap();
        let min = heights.iter().map(|(_, h)| *h).min().unwrap();
        assert!(
            max - min <= 1,
            "Heights diverge after split-brain heal: {:?}",
            heights
        );
    }

    // Zero panics
    for node in &config.nodes {
        let panics = SshController::count_log_matches(
            node,
            config.service_name,
            "panic",
            "15 min ago",
        )
        .unwrap_or(0);
        assert_eq!(
            panics, 0,
            "Post split-brain: {} had {} panics",
            node.name, panics
        );
    }
    println!("  Full mesh restored, heights converged, zero panics");
}
