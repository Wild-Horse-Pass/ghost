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
                "sudo iptables -A GHOST_CHAOS -s {} -p tcp --dport 8080 -j REJECT --reject-with tcp-reset; \
                 sudo iptables -A GHOST_CHAOS -s {} -p tcp --match multiport --dports 8555:8562 -j REJECT --reject-with tcp-reset; \
                 sudo iptables -A GHOST_CHAOS -d {} -p tcp --dport 8080 -j REJECT --reject-with tcp-reset; \
                 sudo iptables -A GHOST_CHAOS -d {} -p tcp --match multiport --dports 8555:8562 -j REJECT --reject-with tcp-reset",
                peer_ip, peer_ip, peer_ip, peer_ip
            ),
        )
    }

    /// Get the total packet count rejected by the GHOST_CHAOS chain on a node.
    /// Returns 0 if the chain doesn't exist.
    pub fn partition_hit_count(node: &NodeInfo) -> Result<u64, String> {
        let output = Self::run(
            node,
            "sudo iptables -L GHOST_CHAOS -n -v 2>/dev/null | awk 'NR>2 {sum+=$1} END {print sum+0}'",
        )?;
        output
            .trim()
            .parse::<u64>()
            .map_err(|e| format!("failed to parse hit count '{}': {}", output.trim(), e))
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

    /// Force-stop a node, bypassing the genesis guard.
    /// Used only by Phase 13 (genesis resilience) tests.
    pub fn force_stop_node(node: &NodeInfo, service: &str) -> Result<String, String> {
        println!(
            "  [SSH] FORCE stopping {} on {} (genesis guard bypassed)",
            service, node.name
        );
        Self::run(node, &format!("sudo systemctl stop {}", service))
    }

    /// Block only outgoing traffic from this node to a peer on mesh ports.
    /// Creates an asymmetric partition: node cannot send to peer, but peer can send to node.
    pub fn block_peer_outgoing(node: &NodeInfo, peer_ip: &str) -> Result<String, String> {
        println!(
            "  [SSH] Blocking {} → {} outgoing on mesh ports",
            node.name, peer_ip
        );
        Self::run(
            node,
            &format!(
                "sudo iptables -A GHOST_CHAOS -d {} -p tcp --dport 8080 -j REJECT --reject-with tcp-reset; \
                 sudo iptables -A GHOST_CHAOS -d {} -p tcp --match multiport --dports 8555:8562 -j REJECT --reject-with tcp-reset",
                peer_ip, peer_ip
            ),
        )
    }

    /// Block only incoming traffic from a peer to this node on mesh ports.
    /// Creates an asymmetric partition: peer cannot send to node, but node can send to peer.
    #[allow(dead_code)]
    pub fn block_peer_incoming(node: &NodeInfo, peer_ip: &str) -> Result<String, String> {
        println!(
            "  [SSH] Blocking {} ← {} incoming on mesh ports",
            node.name, peer_ip
        );
        Self::run(
            node,
            &format!(
                "sudo iptables -A GHOST_CHAOS -s {} -p tcp --dport 8080 -j REJECT --reject-with tcp-reset; \
                 sudo iptables -A GHOST_CHAOS -s {} -p tcp --match multiport --dports 8555:8562 -j REJECT --reject-with tcp-reset",
                peer_ip, peer_ip
            ),
        )
    }

    // --- Config management methods ---

    /// Config file path on remote nodes.
    const CONFIG_PATH: &'static str = "/etc/ghost/pool.toml";
    const CONFIG_BACKUP: &'static str = "/etc/ghost/pool.toml.chaos_backup";

    /// Backup the current config file. Fails if backup already exists (prevents double-backup).
    pub fn backup_config(node: &NodeInfo) -> Result<String, String> {
        println!("  [SSH] Backing up config on {}", node.name);
        Self::run(
            node,
            &format!(
                "test ! -f {} && sudo cp {} {}",
                Self::CONFIG_BACKUP,
                Self::CONFIG_PATH,
                Self::CONFIG_BACKUP
            ),
        )
    }

    /// Restore config from backup. Removes the backup file after restore.
    pub fn restore_config(node: &NodeInfo) -> Result<String, String> {
        println!("  [SSH] Restoring config on {}", node.name);
        Self::run(
            node,
            &format!(
                "sudo cp {} {} && sudo rm -f {}",
                Self::CONFIG_BACKUP,
                Self::CONFIG_PATH,
                Self::CONFIG_BACKUP
            ),
        )
    }

    /// Check if a config backup exists.
    pub fn has_config_backup(node: &NodeInfo) -> Result<bool, String> {
        let output = Self::run(
            node,
            &format!("test -f {} && echo yes || echo no", Self::CONFIG_BACKUP),
        )?;
        Ok(output.trim() == "yes")
    }

    /// Patch a TOML field within a specific section using section-aware sed.
    /// Example: `patch_config_field(node, "storage", "archive_mode", "false")`
    pub fn patch_config_field(
        node: &NodeInfo,
        section: &str,
        key: &str,
        value: &str,
    ) -> Result<String, String> {
        println!(
            "  [SSH] Patching {}.{} = {} on {}",
            section, key, value, node.name
        );
        // Section-aware sed: only modify lines between [section] and the next [
        Self::run(
            node,
            &format!(
                r#"sudo sed -i '/^\[{}\]/,/^\[/{{s/^{} = .*/{} = {}/}}' {}"#,
                section,
                key,
                key,
                value,
                Self::CONFIG_PATH
            ),
        )
    }

    /// Read a TOML field value from a specific section.
    pub fn read_config_field(
        node: &NodeInfo,
        section: &str,
        key: &str,
    ) -> Result<String, String> {
        let output = Self::run(
            node,
            &format!(
                r#"sed -n '/^\[{}\]/,/^\[/{{/^{} = /p}}' {} | head -1 | sed 's/.*= //' | tr -d '"'"#,
                section,
                key,
                Self::CONFIG_PATH
            ),
        )?;
        Ok(output.trim().to_string())
    }

    /// Restart the service (stop + start). Does NOT use genesis guard.
    pub fn restart_service(node: &NodeInfo, service: &str) -> Result<String, String> {
        println!("  [SSH] Restarting {} on {}", service, node.name);
        Self::run(
            node,
            &format!("sudo systemctl restart {}", service),
        )
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
