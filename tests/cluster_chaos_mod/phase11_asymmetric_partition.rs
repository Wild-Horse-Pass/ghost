//! Phase 11: Asymmetric Partition — one-directional network failures.
//!
//! Tests "phantom peer" scenarios where A thinks it's connected to B but B disagrees.
//! Uses `block_peer_outgoing` for one-way blocks instead of bidirectional `block_peer`.
//!
//! Scenario A (tests 01-04): One-Way Block — VM2 can't send to VM3, but VM3 can send to VM2.
//! Scenario B (tests 05-08): Ring Partition — information flows only one direction around the ring.
#![allow(clippy::expect_fun_call)]

use std::time::Duration;

use super::client::ClusterClient;
use super::config::ClusterConfig;
use super::metrics::TestMetrics;
use super::ssh::SshController;

fn setup() -> ClusterClient {
    ClusterClient::new(ClusterConfig::signet())
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

// ========== Scenario A: One-Way Block (VM2 → VM3 blocked) ==========

#[tokio::test]
#[ignore]
async fn asymmetric_01_one_way_block_setup() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").expect("VM2 not found");
    let vm3 = config.node_by_name("VM3").expect("VM3 not found");

    // Safety cleanup
    SshController::cleanup_all_partitions(config).ok();

    println!("\n=== Asymmetric Partition: One-Way Block Setup (VM2 → VM3) ===");

    // Set up chain on VM2 only — we only block outgoing from VM2 to VM3
    SshController::setup_partition_chain(vm2)
        .expect("failed to setup chain on VM2");

    // Block VM2 → VM3 outgoing only (VM3 can still send to VM2)
    SshController::block_peer_outgoing(vm2, vm3.ip)
        .expect("failed to block VM2 → VM3 outgoing");

    // Wait for partition to take effect
    println!("  Waiting 30s for peer detection timeout...");
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Verify iptables is actively rejecting packets
    let hits_before = SshController::partition_hit_count(vm2).unwrap_or(0);
    tokio::time::sleep(Duration::from_secs(10)).await;
    let hits_after = SshController::partition_hit_count(vm2).unwrap_or(0);
    let new_hits = hits_after.saturating_sub(hits_before);

    println!(
        "  VM2 iptables: {} total rejected, {} new in 10s",
        hits_after, new_hits
    );
    assert!(
        new_hits > 0,
        "No packets rejected on VM2 — one-way block not effective"
    );
    println!("  One-way block VM2 → VM3 established");
}

#[tokio::test]
#[ignore]
async fn asymmetric_02_one_way_peer_behavior() {
    let client = setup();
    let config = &client.config;
    let vm1 = config.node_by_name("VM1").unwrap();
    let vm2 = config.node_by_name("VM2").unwrap();
    let vm3 = config.node_by_name("VM3").unwrap();
    let vm4 = config.node_by_name("VM4").unwrap();

    println!("\n=== Asymmetric Partition: Peer Behavior Check ===");

    // Report peer counts (informational — asymmetric partitions have complex behavior)
    for node in [vm1, vm2, vm3, vm4] {
        let peers = client.get_peer_count(node.ip).await.unwrap_or(0);
        let health = client.get(node.ip, "/health").await;
        let status = health.status.unwrap_or(0);
        println!(
            "  {} — /health: {}, peers: {} (informational)",
            node.name, status, peers
        );
    }

    // VM1 and VM4 should be unaffected (≥2 peers)
    for node in [vm1, vm4] {
        let peers = client.get_peer_count(node.ip).await.unwrap_or(0);
        assert!(
            peers >= 2,
            "Unaffected {} has only {} peers (expected >=2)",
            node.name,
            peers
        );
    }
    println!("  VM1 + VM4 unaffected (≥2 peers each)");
}

#[tokio::test]
#[ignore]
async fn asymmetric_03_traffic_during_asymmetric() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Asymmetric Partition: Traffic Test (80 requests) ===");

    let all_ips: Vec<String> = config.all_ips().into_iter().map(String::from).collect();

    let mut metrics = TestMetrics::new();
    for i in 0..80 {
        let ip = &all_ips[i % all_ips.len()];
        let r = client.get(ip, "/health").await;
        metrics.record(r);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    metrics.finish();
    metrics.print_report("Asymmetric Partition: 80 Requests Across All Nodes");

    let rate = metrics.success_rate_excluding_429();
    assert!(
        rate > 0.95,
        "Success rate {:.1}% below 95% during asymmetric partition",
        rate * 100.0
    );
    println!("  Traffic success rate (excl 429): {:.1}%", rate * 100.0);
}

#[tokio::test]
#[ignore]
async fn asymmetric_04_heal_one_way() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Asymmetric Partition: Healing One-Way Block ===");

    SshController::cleanup_all_partitions(config).ok();
    println!("  Partition rules removed");

    // Wait for all nodes to regain 3 peers
    for ip in config.all_ips() {
        let rejoined = wait_for_peers(&client, ip, 3, config.recovery_timeout).await;
        let peers = client.get_peer_count(ip).await.unwrap_or(0);
        println!("  {} peers: {}", ip, peers);
        assert!(
            rejoined,
            "{} did not regain 3 peers after heal (got {})",
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
            "Heights diverge after one-way heal: {:?}",
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
            "Post one-way heal: {} had {} panics",
            node.name, panics
        );
    }
    println!("  Full mesh restored, heights converged, zero panics");
}

// ========== Scenario B: Ring Partition ==========

#[tokio::test]
#[ignore]
async fn asymmetric_05_ring_partition_setup() {
    let client = setup();
    let config = &client.config;

    // Safety cleanup
    SshController::cleanup_all_partitions(config).ok();

    println!("\n=== Asymmetric Partition: Ring Partition Setup ===");
    println!("  Ring: VM1→VM2 blocked, VM2→VM3 blocked, VM3→VM4 blocked, VM4→VM1 blocked");

    // Set up chains on all nodes
    for node in &config.nodes {
        SshController::setup_partition_chain(node).expect(&format!(
            "failed to setup chain on {}",
            node.name
        ));
    }

    // Create ring: each node can't send to its clockwise neighbor
    let ring = [("VM1", "VM2"), ("VM2", "VM3"), ("VM3", "VM4"), ("VM4", "VM1")];
    for (from_name, to_name) in &ring {
        let from_node = config.node_by_name(from_name).unwrap();
        let to_node = config.node_by_name(to_name).unwrap();
        SshController::block_peer_outgoing(from_node, to_node.ip).expect(&format!(
            "failed to block {} → {} outgoing",
            from_name, to_name
        ));
    }

    // Wait for partition to take effect
    println!("  Waiting 30s for peer detection timeout...");
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Verify iptables activity on all nodes
    let mut total_hits = 0u64;
    for node in &config.nodes {
        let hits = SshController::partition_hit_count(node).unwrap_or(0);
        total_hits += hits;
        println!("  {} iptables hits: {}", node.name, hits);
    }
    assert!(
        total_hits > 0,
        "No iptables hits across any node — ring partition not effective"
    );
    println!("  Ring partition established ({} total iptables hits)", total_hits);
}

#[tokio::test]
#[ignore]
async fn asymmetric_06_ring_peer_counts() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Asymmetric Partition: Ring Peer Counts ===");

    for node in &config.nodes {
        let health = client.get(node.ip, "/health").await;
        let status = health.status.unwrap_or(0);
        let peers = client.get_peer_count(node.ip).await.unwrap_or(0);
        println!("  {} — /health: {}, peers: {}", node.name, status, peers);

        // In a ring partition, each node should still have at least 1 peer
        // (the counter-clockwise neighbor can still reach it)
        assert!(
            peers >= 1,
            "{} has 0 peers during ring partition (expected >=1)",
            node.name
        );
    }
    println!("  All nodes have >=1 peer during ring partition");
}

#[tokio::test]
#[ignore]
async fn asymmetric_07_ring_api_serves() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Asymmetric Partition: Ring API Check ===");

    let endpoints = ["/health", "/api/v1/node/status", "/api/v1/network/peers"];

    for endpoint in &endpoints {
        for node in &config.nodes {
            let r = client.get_with_retry(node.ip, endpoint).await;
            let status = r.status.unwrap_or(0);
            println!("  {} {} → {}", node.name, endpoint, status);
            assert_ne!(
                status, 0,
                "Cannot reach {} {} during ring partition",
                node.name, endpoint
            );
        }
    }
    println!("  All endpoints reachable on all nodes during ring partition");
}

#[tokio::test]
#[ignore]
async fn asymmetric_08_heal_ring() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Asymmetric Partition: Healing Ring ===");

    SshController::cleanup_all_partitions(config).ok();
    println!("  All partition rules removed");

    // Wait for all nodes to regain 3 peers
    for ip in config.all_ips() {
        let rejoined = wait_for_peers(&client, ip, 3, config.recovery_timeout).await;
        let peers = client.get_peer_count(ip).await.unwrap_or(0);
        println!("  {} peers: {}", ip, peers);
        assert!(
            rejoined,
            "{} did not regain 3 peers after ring heal (got {})",
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
            "Heights diverge after ring heal: {:?}",
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
            "Post ring heal: {} had {} panics",
            node.name, panics
        );
    }
    println!("  Full mesh restored, heights converged, zero panics");
}
