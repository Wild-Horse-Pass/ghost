//! Phase 14: Deploy Heterogeneous Configs — assign different config profiles to each VM.
//!
//! Config matrix:
//! | VM  | archive | prune  | reaper  | policy       |
//! |-----|---------|--------|---------|--------------|
//! | VM1 | true    | 0      | strict  | bitcoin_pure | (unchanged — genesis)
//! | VM2 | false   | 1000   | disabled| permissive   |
//! | VM3 | true    | 0      | strict  | full_open    |
//! | VM4 | false   | 0      | disabled| bitcoin_pure |
//!
//! This gives: 2 archive + 2 non-archive, 1 pruned, 2 reaper + 2 non-reaper,
//! 2 bitcoin_pure + 1 permissive + 1 full_open.
//!
//! Scenario entry point (test 01) backs up all configs. Phase 17 restores them.
#![allow(clippy::expect_fun_call)]

use std::time::Duration;

use super::client::ClusterClient;
use super::config::ClusterConfig;
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

// --- Test 01: Backup all configs ---

#[tokio::test]
#[ignore]
async fn deploy_01_backup_all_configs() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Heterogeneous Deploy: Backing Up All Configs ===");

    for node in &config.nodes {
        // If backup already exists (from a failed previous run), restore it first
        if SshController::has_config_backup(node).unwrap_or(false) {
            println!("  {} already has backup — restoring first for clean state", node.name);
            SshController::restore_config(node).expect(&format!(
                "failed to restore existing backup on {}",
                node.name
            ));
        }

        SshController::backup_config(node).expect(&format!(
            "failed to backup config on {}",
            node.name
        ));
        assert!(
            SshController::has_config_backup(node).unwrap_or(false),
            "Backup not created on {}",
            node.name
        );
        println!("  {} config backed up", node.name);
    }
    println!("  All 4 configs backed up safely");
}

// --- Test 02: Deploy VM2 — Pruned + Permissive + Reaper Disabled ---

#[tokio::test]
#[ignore]
async fn deploy_02_vm2_pruned_permissive() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").expect("VM2 not found");

    println!("\n=== Heterogeneous Deploy: VM2 → Pruned + Permissive ===");

    // archive_mode = false
    SshController::patch_config_field(vm2, "storage", "archive_mode", "false")
        .expect("failed to patch archive_mode on VM2");

    // prune_height = 1000
    SshController::patch_config_field(vm2, "storage", "prune_height", "1000")
        .expect("failed to patch prune_height on VM2");

    // policy = permissive
    SshController::patch_config_field(vm2, "policy", "profile", "permissive")
        .expect("failed to patch policy on VM2");

    // reaper.enabled = false, mode = monitor
    SshController::patch_config_field(vm2, "reaper", "enabled", "false")
        .expect("failed to patch reaper enabled on VM2");
    SshController::patch_config_field(vm2, "reaper", "mode", "monitor")
        .expect("failed to patch reaper mode on VM2");

    // Verify patches applied
    let archive = SshController::read_config_field(vm2, "storage", "archive_mode")
        .unwrap_or_default();
    let prune = SshController::read_config_field(vm2, "storage", "prune_height")
        .unwrap_or_default();
    let policy = SshController::read_config_field(vm2, "policy", "profile")
        .unwrap_or_default();
    let reaper = SshController::read_config_field(vm2, "reaper", "enabled")
        .unwrap_or_default();

    println!("  VM2 config: archive={}, prune={}, policy={}, reaper={}", archive, prune, policy, reaper);
    assert_eq!(archive, "false", "VM2 archive_mode not patched");
    assert_eq!(prune, "1000", "VM2 prune_height not patched");
    assert_eq!(policy, "permissive", "VM2 policy not patched");
    assert_eq!(reaper, "false", "VM2 reaper not patched");
}

// --- Test 03: Deploy VM3 — Archive + Full Open + Reaper Strict ---

#[tokio::test]
#[ignore]
async fn deploy_03_vm3_archive_fullopen_reaper() {
    let client = setup();
    let config = &client.config;
    let vm3 = config.node_by_name("VM3").expect("VM3 not found");

    println!("\n=== Heterogeneous Deploy: VM3 → Archive + Full Open + Reaper Strict ===");

    // archive_mode = true (may already be true, but set explicitly)
    SshController::patch_config_field(vm3, "storage", "archive_mode", "true")
        .expect("failed to patch archive_mode on VM3");

    // policy = full_open
    SshController::patch_config_field(vm3, "policy", "profile", "full_open")
        .expect("failed to patch policy on VM3");

    // reaper.enabled = true, mode = strict
    SshController::patch_config_field(vm3, "reaper", "enabled", "true")
        .expect("failed to patch reaper enabled on VM3");
    SshController::patch_config_field(vm3, "reaper", "mode", "strict")
        .expect("failed to patch reaper mode on VM3");

    // Verify
    let policy = SshController::read_config_field(vm3, "policy", "profile")
        .unwrap_or_default();
    let reaper = SshController::read_config_field(vm3, "reaper", "enabled")
        .unwrap_or_default();

    println!("  VM3 config: policy={}, reaper={}", policy, reaper);
    assert_eq!(policy, "full_open", "VM3 policy not patched");
    assert_eq!(reaper, "true", "VM3 reaper not patched");
}

// --- Test 04: Deploy VM4 — Non-Archive + Bitcoin Pure + Reaper Disabled ---

#[tokio::test]
#[ignore]
async fn deploy_04_vm4_nonarchive_pure() {
    let client = setup();
    let config = &client.config;
    let vm4 = config.node_by_name("VM4").expect("VM4 not found");

    println!("\n=== Heterogeneous Deploy: VM4 → Non-Archive + Bitcoin Pure ===");

    // archive_mode = false
    SshController::patch_config_field(vm4, "storage", "archive_mode", "false")
        .expect("failed to patch archive_mode on VM4");

    // policy = bitcoin_pure
    SshController::patch_config_field(vm4, "policy", "profile", "bitcoin_pure")
        .expect("failed to patch policy on VM4");

    // reaper stays disabled (already false on VM4)

    // Verify
    let archive = SshController::read_config_field(vm4, "storage", "archive_mode")
        .unwrap_or_default();
    let policy = SshController::read_config_field(vm4, "policy", "profile")
        .unwrap_or_default();

    println!("  VM4 config: archive={}, policy={}", archive, policy);
    assert_eq!(archive, "false", "VM4 archive_mode not patched");
    assert_eq!(policy, "bitcoin_pure", "VM4 policy not patched");
}

// --- Test 05: Restart modified services ---

#[tokio::test]
#[ignore]
async fn deploy_05_restart_modified_services() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Heterogeneous Deploy: Restarting Modified Services ===");

    // Restart VM2, VM3, VM4 (VM1 unchanged, skip to avoid genesis disruption)
    // Use reset-failed first in case a prior test left systemd in a bad state
    for name in ["VM2", "VM3", "VM4"] {
        let node = config.node_by_name(name).unwrap();
        let _ = SshController::run_raw(
            node,
            &format!("sudo systemctl reset-failed {}", config.service_name),
        );
        SshController::restart_service(node, config.service_name).expect(&format!(
            "failed to restart {} service",
            name
        ));
        println!("  {} restarted", name);
    }

    // Wait for all modified nodes to become healthy
    println!("  Waiting for nodes to become healthy...");
    for name in ["VM2", "VM3", "VM4"] {
        let node = config.node_by_name(name).unwrap();
        if !client
            .wait_for_node_healthy(node.ip, Duration::from_secs(120))
            .await
        {
            // Retry once: reset-failed and force restart
            println!("  {} not healthy, retrying with reset-failed...", name);
            let _ = SshController::run_raw(
                node,
                &format!("sudo systemctl reset-failed {}", config.service_name),
            );
            let _ = SshController::restart_service(node, config.service_name);
            assert!(
                client
                    .wait_for_node_healthy(node.ip, Duration::from_secs(120))
                    .await,
                "{} did not become healthy after config change (even after retry)",
                name
            );
        }
        println!("  {} healthy", name);
    }

    // Verify VM1 was unaffected
    let vm1 = config.node_by_name("VM1").unwrap();
    let r = client.get_with_retry(vm1.ip, "/health").await;
    assert!(
        r.error.is_none() && r.status == Some(200),
        "VM1 (unchanged) not healthy: {:?}",
        r.error
    );
    println!("  VM1 still healthy (config unchanged)");
}

// --- Test 06: Full mesh convergence with mixed configs ---

#[tokio::test]
#[ignore]
async fn deploy_06_mesh_convergence() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Heterogeneous Deploy: Mesh Convergence ===");

    // Wait for all nodes to have 3 peers
    for ip in config.all_ips() {
        let rejoined = wait_for_peers(&client, ip, 3, Duration::from_secs(120)).await;
        let peers = client.get_peer_count(ip).await.unwrap_or(0);
        println!("  {} peers: {}", ip, peers);
        assert!(
            rejoined,
            "{} did not reach 3 peers with heterogeneous configs (got {})",
            ip,
            peers
        );
    }

    // Heights consistent
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
            "Heights diverge with heterogeneous configs: {:?}",
            heights
        );
    }

    println!("  Full mesh converged with heterogeneous configs");
}
