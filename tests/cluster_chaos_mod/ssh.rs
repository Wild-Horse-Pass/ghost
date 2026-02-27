//! SSH controller using std::process::Command.
//!
//! Shells out to `ssh ghost-vmN "sudo ..."` using the host's SSH config.

use std::process::Command;

use super::config::{ClusterConfig, NodeInfo};

pub struct SshController;

impl SshController {
    /// Run a command on a remote node via SSH.
    fn run(node: &NodeInfo, cmd: &str) -> Result<String, String> {
        let output = Command::new("ssh")
            .arg(node.ssh_alias)
            .arg(cmd)
            .output()
            .map_err(|e| format!("SSH to {} failed: {}", node.ssh_alias, e))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            // Some commands (like systemctl is-active) use exit code to indicate state
            if !stdout.is_empty() {
                Ok(stdout)
            } else {
                Err(format!(
                    "SSH command failed on {}: {}",
                    node.ssh_alias, stderr
                ))
            }
        }
    }

    /// Stop the ghost-pool service. Refuses if node is genesis.
    pub fn stop_node(node: &NodeInfo, service: &str) -> Result<String, String> {
        if node.is_genesis {
            return Err(format!(
                "REFUSED: cannot stop genesis node {} ({})",
                node.name, node.ip
            ));
        }
        println!("  [SSH] Stopping {} on {}", service, node.name);
        Self::run(node, &format!("sudo systemctl stop {}", service))
    }

    /// Start the ghost-pool service.
    pub fn start_node(node: &NodeInfo, service: &str) -> Result<String, String> {
        println!("  [SSH] Starting {} on {}", service, node.name);
        Self::run(node, &format!("sudo systemctl start {}", service))
    }

    /// Check if the service is active.
    pub fn is_node_active(node: &NodeInfo, service: &str) -> Result<bool, String> {
        let output = Self::run(node, &format!("systemctl is-active {}", service))?;
        Ok(output.trim() == "active")
    }

    // --- iptables partition methods ---

    /// Create (or flush) a dedicated iptables chain for chaos partitioning.
    /// Never touches port 22 (SSH) — only mesh ports 8080, 8555-8562.
    pub fn setup_partition_chain(node: &NodeInfo) -> Result<String, String> {
        println!("  [SSH] Setting up GHOST_CHAOS iptables chain on {}", node.name);
        // Create chain if it doesn't exist, flush it if it does
        Self::run(
            node,
            "sudo iptables -N GHOST_CHAOS 2>/dev/null || sudo iptables -F GHOST_CHAOS; \
             sudo iptables -C INPUT -j GHOST_CHAOS 2>/dev/null || sudo iptables -I INPUT 1 -j GHOST_CHAOS; \
             sudo iptables -C OUTPUT -j GHOST_CHAOS 2>/dev/null || sudo iptables -I OUTPUT 1 -j GHOST_CHAOS",
        )
    }

    /// Block traffic between this node and a peer on mesh ports (8080, 8555-8562).
    /// Never blocks port 22 — SSH access is always preserved.
    pub fn block_peer(node: &NodeInfo, peer_ip: &str) -> Result<String, String> {
        println!(
            "  [SSH] Blocking {} ↔ {} on mesh ports",
            node.name, peer_ip
        );
        Self::run(
            node,
            &format!(
                "sudo iptables -A GHOST_CHAOS -s {} -p tcp --dport 8080 -j DROP; \
                 sudo iptables -A GHOST_CHAOS -s {} -p tcp --match multiport --dports 8555:8562 -j DROP; \
                 sudo iptables -A GHOST_CHAOS -d {} -p tcp --dport 8080 -j DROP; \
                 sudo iptables -A GHOST_CHAOS -d {} -p tcp --match multiport --dports 8555:8562 -j DROP",
                peer_ip, peer_ip, peer_ip, peer_ip
            ),
        )
    }

    /// Flush and remove the GHOST_CHAOS chain, restoring normal connectivity.
    pub fn cleanup_partition(node: &NodeInfo) -> Result<String, String> {
        println!("  [SSH] Cleaning up GHOST_CHAOS chain on {}", node.name);
        Self::run(
            node,
            "sudo iptables -F GHOST_CHAOS 2>/dev/null; \
             sudo iptables -D INPUT -j GHOST_CHAOS 2>/dev/null; \
             sudo iptables -D OUTPUT -j GHOST_CHAOS 2>/dev/null; \
             sudo iptables -X GHOST_CHAOS 2>/dev/null; true",
        )
    }

    /// Safety cleanup: remove partition rules from all nodes in the cluster.
    pub fn cleanup_all_partitions(config: &ClusterConfig) -> Result<(), String> {
        println!("  [SSH] Cleaning up partitions on all nodes");
        for node in &config.nodes {
            // Best-effort: don't fail if chain doesn't exist
            let _ = Self::cleanup_partition(node);
        }
        Ok(())
    }

    /// Count log lines matching a pattern since a given time.
    pub fn count_log_matches(
        node: &NodeInfo,
        service: &str,
        pattern: &str,
        since: &str,
    ) -> Result<u64, String> {
        let output = Self::run(
            node,
            &format!(
                "sudo journalctl -u {} --since='{}' --no-pager | grep -ci '{}' || true",
                service, since, pattern
            ),
        )?;
        output.trim().parse::<u64>().map_err(|e| {
            format!(
                "failed to parse count from '{}': {}",
                output.trim(),
                e
            )
        })
    }
}
