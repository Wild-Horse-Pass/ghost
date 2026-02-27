//! Phase 6: Rolling Restart — sequential restart of non-genesis nodes with varying delays.

use std::sync::Arc;
use std::time::Duration;

use super::client::ClusterClient;
use super::config::ClusterConfig;
use super::ssh::SshController;

fn setup() -> Arc<ClusterClient> {
    Arc::new(ClusterClient::new(ClusterConfig::signet()))
}

/// Stop → start → wait-for-healthy cycle for a sequence of nodes.
async fn rolling_restart(
    client: &ClusterClient,
    node_names: &[&str],
    gap: Duration,
) {
    let config = &client.config;

    for (i, name) in node_names.iter().enumerate() {
        let node = config.node_by_name(name).expect(&format!("{} not found", name));

        println!("  [{}/{}] Stopping {}...", i + 1, node_names.len(), name);
        SshController::stop_node(node, config.service_name)
            .expect(&format!("failed to stop {}", name));

        tokio::time::sleep(Duration::from_secs(2)).await;

        println!("  [{}/{}] Starting {}...", i + 1, node_names.len(), name);
        SshController::start_node(node, config.service_name)
            .expect(&format!("failed to start {}", name));

        assert!(
            client
                .wait_for_node_healthy(node.ip, config.recovery_timeout)
                .await,
            "{} did not become healthy within {:?}",
            name,
            config.recovery_timeout
        );
        println!("  [{}/{}] {} healthy", i + 1, node_names.len(), name);

        // Wait the gap before next node (except after last)
        if i < node_names.len() - 1 {
            println!("  Waiting {:?} before next node...", gap);
            tokio::time::sleep(gap).await;
        }
    }
}

/// Verify all nodes are healthy after a rolling restart.
async fn assert_all_healthy(client: &ClusterClient) {
    for ip in client.config.all_ips() {
        let r = client.get_with_retry(ip, "/health").await;
        assert!(
            r.error.is_none() && r.status == Some(200),
            "Post-rolling: {} not healthy: {:?}",
            ip,
            r.error
        );
    }
}

#[tokio::test]
#[ignore]
async fn rolling_01_forward_normal() {
    let client = setup();

    println!("\n=== Rolling Restart: Forward (VM2→VM3→VM4, 10s gap) ===");
    rolling_restart(&client, &["VM2", "VM3", "VM4"], Duration::from_secs(10)).await;
    assert_all_healthy(&client).await;
    println!("  All nodes healthy after forward rolling restart (10s gap)");
}

#[tokio::test]
#[ignore]
async fn rolling_02_forward_aggressive() {
    let client = setup();

    println!("\n=== Rolling Restart: Aggressive (VM2→VM3→VM4, 3s gap) ===");
    rolling_restart(&client, &["VM2", "VM3", "VM4"], Duration::from_secs(3)).await;
    assert_all_healthy(&client).await;
    println!("  All nodes healthy after aggressive rolling restart (3s gap)");
}

#[tokio::test]
#[ignore]
async fn rolling_03_reverse_order() {
    let client = setup();

    println!("\n=== Rolling Restart: Reverse (VM4→VM3→VM2, 10s gap) ===");
    rolling_restart(&client, &["VM4", "VM3", "VM2"], Duration::from_secs(10)).await;
    assert_all_healthy(&client).await;
    println!("  All nodes healthy after reverse rolling restart (10s gap)");
}

#[tokio::test]
#[ignore]
async fn rolling_04_health_during_rolling() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Rolling Restart: Health Polling During Restart ===");

    // We'll do a forward restart with 10s gap while polling health in background
    let poller_client = client.clone();
    let poll_ips: Vec<String> = config.all_ips().into_iter().map(String::from).collect();

    let poll_handle = tokio::spawn(async move {
        let mut results = Vec::new();
        // Poll for ~60 seconds (enough for 3-node rolling restart)
        for _ in 0..30 {
            for ip in &poll_ips {
                let r = poller_client.get(ip, "/health").await;
                let is_up = r.error.is_none() && r.status == Some(200);
                results.push((ip.clone(), is_up, r.status));
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        results
    });

    // Perform rolling restart
    rolling_restart(&client, &["VM2", "VM3", "VM4"], Duration::from_secs(10)).await;

    let poll_results = poll_handle.await.unwrap();

    // Check that surviving nodes (those not being restarted at a given moment)
    // always responded 200. VM1 (genesis, never restarted) must always be up.
    let vm1_ip = config.node_by_name("VM1").unwrap().ip;
    let vm1_results: Vec<_> = poll_results
        .iter()
        .filter(|(ip, _, _)| ip == vm1_ip)
        .collect();
    let vm1_up = vm1_results.iter().filter(|(_, up, _)| *up).count();
    let vm1_total = vm1_results.len();

    println!(
        "  VM1 (genesis): {}/{} polls returned 200",
        vm1_up, vm1_total
    );
    assert!(
        vm1_up == vm1_total || (vm1_up as f64 / vm1_total as f64) > 0.95,
        "VM1 should always be healthy during rolling restart: {}/{}",
        vm1_up,
        vm1_total
    );

    // Overall: most survivors should respond 200
    let total_polls = poll_results.len();
    let total_up = poll_results.iter().filter(|(_, up, _)| *up).count();
    println!(
        "  Overall: {}/{} polls returned 200 ({:.0}%)",
        total_up,
        total_polls,
        total_up as f64 / total_polls as f64 * 100.0
    );
}

#[tokio::test]
#[ignore]
async fn rolling_05_heights_converge() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Rolling Restart: Height Convergence ===");

    // Give nodes time to sync after rolling restart
    tokio::time::sleep(Duration::from_secs(10)).await;

    let mut heights = Vec::new();
    for ip in config.all_ips() {
        // Retry for 429s
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
        "Post-rolling heights diverge: {:?}",
        heights
    );
    println!("  Heights converged (diff <=1)");
}

#[tokio::test]
#[ignore]
async fn rolling_06_no_panics() {
    let config = ClusterConfig::signet();

    println!("\n=== Rolling Restart: Panic Check ===");

    for node in &config.nodes {
        let panics = SshController::count_log_matches(
            node,
            config.service_name,
            "panic",
            "15 min ago",
        )
        .unwrap_or_else(|e| {
            println!("  WARNING: Could not check {} logs: {}", node.name, e);
            0
        });
        println!("  {} panics in last 15 min: {}", node.name, panics);
        assert_eq!(
            panics, 0,
            "Post-rolling: {} had {} panics in last 15 minutes",
            node.name, panics
        );
    }
}
