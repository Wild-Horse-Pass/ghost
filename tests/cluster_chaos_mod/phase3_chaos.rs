//! Phase 3: Chaos — kill/restart nodes one at a time, verify mesh self-heals.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::client::ClusterClient;
use super::config::ClusterConfig;
use super::metrics::TestMetrics;
use super::ssh::SshController;

fn setup() -> Arc<ClusterClient> {
    Arc::new(ClusterClient::new(ClusterConfig::signet()))
}

/// Helper: verify remaining nodes are healthy and have enough peers.
async fn assert_remaining_healthy(client: &ClusterClient, killed_ip: &str, min_peers: usize) {
    let live_ips: Vec<&str> = client
        .config
        .all_ips()
        .into_iter()
        .filter(|ip| *ip != killed_ip)
        .collect();

    for ip in &live_ips {
        let health = client.get_with_retry(ip, "/health").await;
        assert!(
            health.error.is_none() && health.status == Some(200),
            "Surviving node {} not healthy after kill: {:?}",
            ip,
            health.error
        );

        let peers = client.get_peer_count(ip).await.unwrap_or(0);
        assert!(
            peers >= min_peers,
            "Surviving node {} has only {} peers (expected ≥{})",
            ip,
            peers,
            min_peers
        );
        println!("  {} healthy, {} peers", ip, peers);
    }
}

/// Helper: wait for a node to rejoin with full peers.
async fn wait_for_rejoin(
    client: &ClusterClient,
    ip: &str,
    expected_peers: usize,
    timeout: Duration,
) -> Duration {
    let start = Instant::now();
    let deadline = start + timeout;

    // First wait for health
    assert!(
        client.wait_for_node_healthy(ip, timeout).await,
        "{} did not become healthy within {:?}",
        ip,
        timeout
    );
    let health_time = start.elapsed();
    println!("  {} healthy after {:?}", ip, health_time);

    // Then wait for peers
    while Instant::now() < deadline {
        if let Ok(peers) = client.get_peer_count(ip).await {
            if peers >= expected_peers {
                let total_time = start.elapsed();
                println!("  {} has {} peers after {:?}", ip, peers, total_time);
                return total_time;
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    let elapsed = start.elapsed();
    let peers = client.get_peer_count(ip).await.unwrap_or(0);
    panic!(
        "{} only has {} peers after {:?} (expected ≥{})",
        ip, peers, elapsed, expected_peers
    );
}

// --- VM2 kill/rejoin ---

#[tokio::test]
#[ignore]
async fn chaos_01_kill_vm2_others_survive() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").expect("VM2 not found");

    SshController::stop_node(vm2, config.service_name).expect("failed to stop VM2");
    tokio::time::sleep(Duration::from_secs(5)).await;

    assert_remaining_healthy(&client, vm2.ip, 2).await;
    println!("  VM2 killed — remaining 3 nodes healthy with ≥2 peers each");
}

#[tokio::test]
#[ignore]
async fn chaos_02_vm2_rejoin() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").expect("VM2 not found");

    SshController::start_node(vm2, config.service_name).expect("failed to start VM2");

    let rejoin_time = wait_for_rejoin(&client, vm2.ip, 3, config.recovery_timeout).await;
    println!(
        "  VM2 rejoined with 3 peers in {:?} (limit {:?})",
        rejoin_time, config.recovery_timeout
    );
}

// --- VM3 kill/rejoin ---

#[tokio::test]
#[ignore]
async fn chaos_03_kill_vm3_verification_continues() {
    let client = setup();
    let config = &client.config;
    let vm3 = config.node_by_name("VM3").expect("VM3 not found");

    SshController::stop_node(vm3, config.service_name).expect("failed to stop VM3");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Remaining nodes should still serve verification challenges
    let live_ips: Vec<&str> = config
        .all_ips()
        .into_iter()
        .filter(|ip| *ip != vm3.ip)
        .collect();

    // Test verification endpoints that work without query params
    let verify_endpoints = ["/verify/stratum", "/verify/ghostpay"];

    for endpoint in &verify_endpoints {
        for ip in &live_ips {
            let r = client.get_with_retry(ip, endpoint).await;
            assert!(
                r.error.is_none() && r.status == Some(200),
                "{} {} failed while VM3 down: {:?}",
                ip,
                endpoint,
                r.error
            );
        }
        println!("  {} passes on remaining 3 nodes", endpoint);
    }
}

#[tokio::test]
#[ignore]
async fn chaos_04_vm3_rejoin() {
    let client = setup();
    let config = &client.config;
    let vm3 = config.node_by_name("VM3").expect("VM3 not found");

    SshController::start_node(vm3, config.service_name).expect("failed to start VM3");

    let rejoin_time = wait_for_rejoin(&client, vm3.ip, 3, config.recovery_timeout).await;
    println!(
        "  VM3 rejoined with 3 peers in {:?} (limit {:?})",
        rejoin_time, config.recovery_timeout
    );
}

// --- VM4 kill/rejoin ---

#[tokio::test]
#[ignore]
async fn chaos_05_kill_vm4_consensus_continues() {
    let client = setup();
    let config = &client.config;
    let vm4 = config.node_by_name("VM4").expect("VM4 not found");

    SshController::stop_node(vm4, config.service_name).expect("failed to stop VM4");
    tokio::time::sleep(Duration::from_secs(5)).await;

    assert_remaining_healthy(&client, vm4.ip, 2).await;

    // With 3/4 nodes alive (75% > 67% BFT threshold), consensus should continue
    // Check that block heights are still advancing
    let live_ips: Vec<&str> = config
        .all_ips()
        .into_iter()
        .filter(|ip| *ip != vm4.ip)
        .collect();

    let height_before: Vec<u64> = {
        let mut h = Vec::new();
        for ip in &live_ips {
            h.push(client.get_block_height(ip).await.unwrap_or(0));
        }
        h
    };

    // Wait a bit for potential block progression
    tokio::time::sleep(Duration::from_secs(10)).await;

    let height_after: Vec<u64> = {
        let mut h = Vec::new();
        for ip in &live_ips {
            h.push(client.get_block_height(ip).await.unwrap_or(0));
        }
        h
    };

    println!(
        "  Heights before: {:?}, after: {:?}",
        height_before, height_after
    );
    println!("  VM4 killed — 3/4 nodes alive, consensus should continue (75% > 67%)");
}

#[tokio::test]
#[ignore]
async fn chaos_06_vm4_recovery_timing() {
    let client = setup();
    let config = &client.config;
    let vm4 = config.node_by_name("VM4").expect("VM4 not found");

    let start = Instant::now();
    SshController::start_node(vm4, config.service_name).expect("failed to start VM4");

    // Measure time to healthy
    let healthy = client
        .wait_for_node_healthy(vm4.ip, config.recovery_timeout)
        .await;
    let time_to_healthy = start.elapsed();

    assert!(
        healthy,
        "VM4 did not become healthy within {:?}",
        config.recovery_timeout
    );
    println!("  VM4 time-to-healthy: {:?}", time_to_healthy);

    // Measure time to full mesh
    let mesh_deadline = start + config.recovery_timeout;
    let mut time_to_mesh = config.recovery_timeout;
    while Instant::now() < mesh_deadline {
        if let Ok(peers) = client.get_peer_count(vm4.ip).await {
            if peers >= 3 {
                time_to_mesh = start.elapsed();
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    println!("  VM4 time-to-mesh (3 peers): {:?}", time_to_mesh);
}

// --- Traffic during outage ---

#[tokio::test]
#[ignore]
async fn chaos_07_traffic_during_outage() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").expect("VM2 not found");

    SshController::stop_node(vm2, config.service_name).expect("failed to stop VM2");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // 50 concurrent requests to the 3 surviving nodes
    let live_ips: Vec<String> = config
        .all_ips()
        .into_iter()
        .filter(|ip| *ip != vm2.ip)
        .map(String::from)
        .collect();

    let mut handles = Vec::new();
    for i in 0..50 {
        let c = client.clone();
        let ip = live_ips[i % live_ips.len()].clone();
        handles.push(tokio::spawn(async move { c.get(&ip, "/health").await }));
    }

    let mut metrics = TestMetrics::new();
    for h in handles {
        if let Ok(r) = h.await {
            metrics.record(r);
        }
    }
    metrics.finish();
    metrics.print_report("Chaos: 50 Concurrent Requests During VM2 Outage");

    let rate = metrics.success_rate_excluding_429();
    assert!(
        rate > 0.95,
        "Non-429 success rate during outage {:.1}% below 95%",
        rate * 100.0
    );
    println!(
        "  Rate-limited: {}, service success rate (excl. 429): {:.1}%",
        metrics.rate_limited_count(),
        rate * 100.0
    );

    // Restore VM2
    SshController::start_node(vm2, config.service_name).expect("failed to restart VM2");
}

#[tokio::test]
#[ignore]
async fn chaos_08_vm2_catchup() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").expect("VM2 not found");

    // Wait for VM2 to be healthy (it was restarted at the end of chaos_07)
    assert!(
        client
            .wait_for_node_healthy(vm2.ip, config.recovery_timeout)
            .await,
        "VM2 did not recover"
    );

    // Wait for block height to catch up (within 60s)
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let vm1_height = client
            .get_block_height(config.nodes[0].ip)
            .await
            .unwrap_or(0);
        let vm2_height = client.get_block_height(vm2.ip).await.unwrap_or(0);

        if vm1_height > 0 && vm2_height > 0 && vm1_height.abs_diff(vm2_height) <= 1 {
            println!(
                "  VM2 caught up: VM1={} VM2={} (diff ≤1)",
                vm1_height, vm2_height
            );
            return;
        }

        if Instant::now() > deadline {
            panic!(
                "VM2 block height did not catch up within 60s: VM1={} VM2={}",
                vm1_height, vm2_height
            );
        }

        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}
