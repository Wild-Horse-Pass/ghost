//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: health_checker.rs                                                                                              |
//|======================================================================================================================|

//! Background health checker and DNS updater

use crate::cloudflare::{group_regions_by_prefix, CloudflareClient};
use crate::config::HealthConfig;
use crate::db::RegistryDb;
use ghost_common::config::Region;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

/// Health checker that runs in the background
pub struct HealthChecker {
    db: Arc<RegistryDb>,
    cloudflare: Arc<CloudflareClient>,
    config: HealthConfig,
    max_nodes_per_region: usize,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new(
        db: Arc<RegistryDb>,
        cloudflare: Arc<CloudflareClient>,
        config: HealthConfig,
        max_nodes_per_region: usize,
    ) -> Self {
        Self {
            db,
            cloudflare,
            config,
            max_nodes_per_region,
        }
    }

    /// Start the health checker background task
    pub async fn start(self: Arc<Self>, mut shutdown_rx: broadcast::Receiver<()>) {
        info!(
            interval_secs = self.config.check_interval_secs,
            timeout_secs = self.config.heartbeat_timeout_secs,
            "Starting health checker"
        );

        let mut interval =
            tokio::time::interval(Duration::from_secs(self.config.check_interval_secs));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.run_health_check().await {
                        error!(error = %e, "Health check failed");
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Health checker shutting down");
                    break;
                }
            }
        }
    }

    /// Run a single health check cycle
    async fn run_health_check(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Mark stale nodes as unhealthy
        let stale_count = self
            .db
            .mark_stale_nodes_unhealthy(self.config.heartbeat_timeout_secs as i64)?;

        if stale_count > 0 {
            warn!(count = stale_count, "Marked stale nodes as unhealthy");
        }

        // Update load exclusion flags (hysteresis)
        let (excluded, included) = self.db.update_load_exclusions(
            self.config.max_load_percent,
            self.config.resume_load_percent,
        )?;

        if excluded > 0 {
            warn!(
                count = excluded,
                threshold = self.config.max_load_percent,
                "Excluded overloaded nodes from DNS"
            );
        }
        if included > 0 {
            info!(
                count = included,
                threshold = self.config.resume_load_percent,
                "Re-included recovered nodes in DNS"
            );
        }

        // Update DNS if cloudflare is enabled
        if self.cloudflare.is_enabled() {
            self.update_dns().await?;
        }

        // Log stats
        let total = self.db.get_node_count()?;
        let healthy = self.db.get_healthy_node_count()?;
        debug!(
            total_nodes = total,
            healthy_nodes = healthy,
            "Health check completed"
        );

        Ok(())
    }

    /// Update DNS records based on current node state
    async fn update_dns(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Group regions by DNS prefix and collect best nodes for each
        let region_groups = group_regions_by_prefix();
        let mut region_ips: Vec<(Region, Vec<String>)> = Vec::new();

        for (prefix, regions) in region_groups {
            // Collect best nodes across all regions in this group
            let mut best_nodes: Vec<(f64, String)> = Vec::new();

            for region in &regions {
                match self.db.get_healthy_nodes_by_region(*region) {
                    Ok(nodes) => {
                        for node in nodes {
                            best_nodes.push((node.load_score(), node.host.clone()));
                        }
                    }
                    Err(e) => {
                        warn!(region = %region, error = %e, "Failed to get nodes for region");
                    }
                }
            }

            // Sort by load score and take best N
            best_nodes.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
            let ips: Vec<String> = best_nodes
                .into_iter()
                .take(self.max_nodes_per_region)
                .map(|(_, ip)| ip)
                .collect();

            // Use first region in group as the representative for DNS
            if !regions.is_empty() {
                // Only add if we have at least one IP
                if !ips.is_empty() {
                    region_ips.push((regions[0], ips));
                } else {
                    debug!(prefix = %prefix, "No healthy nodes for region group");
                }
            }
        }

        // Sync with Cloudflare
        let (added, removed) = self.cloudflare.sync_all_regions(&region_ips).await?;

        if added > 0 || removed > 0 {
            info!(added = added, removed = removed, "DNS records updated");
        }

        Ok(())
    }

    /// Get current health summary
    pub fn get_health_summary(
        &self,
    ) -> Result<HealthSummary, Box<dyn std::error::Error + Send + Sync>> {
        let total_nodes = self.db.get_node_count()?;
        let healthy_nodes = self.db.get_healthy_node_count()?;
        let region_stats = self.db.get_region_stats()?;

        let mut nodes_by_region: HashMap<String, u32> = HashMap::new();
        let mut miners_by_region: HashMap<String, u32> = HashMap::new();

        for stat in region_stats {
            let region_name = format!("{:?}", stat.region).to_lowercase();
            nodes_by_region.insert(region_name.clone(), stat.healthy_nodes);
            miners_by_region.insert(region_name, stat.total_miners);
        }

        Ok(HealthSummary {
            total_nodes: total_nodes as u32,
            healthy_nodes: healthy_nodes as u32,
            nodes_by_region,
            miners_by_region,
        })
    }
}

/// Health summary for API response
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthSummary {
    pub total_nodes: u32,
    pub healthy_nodes: u32,
    pub nodes_by_region: HashMap<String, u32>,
    pub miners_by_region: HashMap<String, u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CloudflareConfig, DnsConfig};
    use tempfile::tempdir;

    fn create_test_db() -> Arc<RegistryDb> {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        Arc::new(RegistryDb::open(&db_path).unwrap())
    }

    fn create_disabled_cloudflare() -> Arc<CloudflareClient> {
        let config = CloudflareConfig {
            enabled: false,
            ..Default::default()
        };
        Arc::new(CloudflareClient::new(config, DnsConfig::default()).unwrap())
    }

    #[test]
    fn test_health_summary() {
        let db = create_test_db();
        let cloudflare = create_disabled_cloudflare();
        let config = HealthConfig::default();

        let checker = HealthChecker::new(db, cloudflare, config, 3);

        let summary = checker.get_health_summary().unwrap();
        assert_eq!(summary.total_nodes, 0);
        assert_eq!(summary.healthy_nodes, 0);
    }
}
