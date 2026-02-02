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
//| FILE: qualification.rs                                                                                               |
//|======================================================================================================================|

//! Qualified capability provider
//!
//! Provides VERIFIED capabilities for payout calculations based on:
//! 1. Uptime gatekeeper: 95% uptime over trailing 7 days
//! 2. Per-capability verification: 10+ challenges with 95% pass rate

use std::sync::Arc;
use tracing::{debug, info, warn};

use ghost_common::types::{NodeCapabilities, NodeId};
use ghost_storage::Database;

/// Seconds in a day
const SECONDS_PER_DAY: i64 = 86_400;

/// Configuration for capability qualification
#[derive(Debug, Clone)]
pub struct QualificationConfig {
    /// Minimum number of challenges required per capability
    pub min_challenges: u32,
    /// Minimum pass rate required (0.0 to 1.0)
    pub min_pass_rate: f64,
    /// Lookback period in days for uptime and challenges
    pub lookback_days: u32,
    /// Minimum uptime percentage required (gatekeeper)
    pub min_uptime: f64,
}

impl Default for QualificationConfig {
    fn default() -> Self {
        use ghost_common::constants::{
            MIN_CHALLENGES_FOR_QUALIFICATION,
            ARCHIVE_PASS_RATE,
            UPTIME_WINDOW_DAYS,
            UPTIME_GATEKEEPER_THRESHOLD,
        };
        Self {
            min_challenges: MIN_CHALLENGES_FOR_QUALIFICATION as u32,
            min_pass_rate: ARCHIVE_PASS_RATE,
            lookback_days: UPTIME_WINDOW_DAYS as u32,
            min_uptime: UPTIME_GATEKEEPER_THRESHOLD / 100.0, // 95% -> 0.95
        }
    }
}

/// Provides qualified (verified) capabilities for nodes
///
/// This replaces CLAIMED capabilities with VERIFIED capabilities
/// based on challenge results and uptime tracking.
pub struct QualifiedCapabilityProvider {
    /// Database for looking up challenge results and uptime
    db: Arc<Database>,
    /// Qualification configuration
    config: QualificationConfig,
}

impl QualifiedCapabilityProvider {
    /// Create a new qualified capability provider
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            config: QualificationConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(db: Arc<Database>, config: QualificationConfig) -> Self {
        Self { db, config }
    }

    /// Get the lookback timestamp
    fn lookback_timestamp(&self) -> i64 {
        chrono::Utc::now().timestamp() - (self.config.lookback_days as i64 * SECONDS_PER_DAY)
    }

    /// Check if a node passes the uptime gatekeeper
    ///
    /// A node must have 95% uptime over the trailing 7 days before
    /// ANY capabilities count for payout shares.
    pub fn check_uptime_gatekeeper(&self, node_id: &NodeId) -> bool {
        let node_id_hex = hex::encode(node_id);
        let since = self.lookback_timestamp();

        match self.db.get_uptime_percent(&node_id_hex, since) {
            Ok(uptime) => {
                if uptime >= self.config.min_uptime {
                    info!(
                        node = %&node_id_hex[..8],
                        uptime = format!("{:.1}%", uptime * 100.0),
                        "DIAG: Node passes uptime gatekeeper"
                    );
                    true
                } else {
                    info!(
                        node = %&node_id_hex[..8],
                        uptime = format!("{:.1}%", uptime * 100.0),
                        required = format!("{:.1}%", self.config.min_uptime * 100.0),
                        "DIAG: Node fails uptime gatekeeper"
                    );
                    false
                }
            }
            Err(e) => {
                info!(
                    node = %&node_id_hex[..8],
                    error = %e,
                    "DIAG: Failed to get uptime - treating as 0"
                );
                false
            }
        }
    }

    /// Get qualified capabilities for a node
    ///
    /// Returns only capabilities that:
    /// 1. Pass the uptime gatekeeper (95% over 7 days)
    /// 2. Have 10+ challenges with 95% pass rate
    ///
    /// Returns default (all false) capabilities if the node doesn't
    /// meet the requirements.
    pub fn get_qualified(&self, node_id: &NodeId) -> NodeCapabilities {
        let node_id_hex = hex::encode(node_id);
        let since = self.lookback_timestamp();

        // Log challenge stats for debugging (before gatekeeper check)
        let archive_stats = self.db.get_archive_pass_rate(&node_id_hex, since).unwrap_or((0, 0));
        let policy_stats = self.db.get_policy_pass_rate(&node_id_hex, since).unwrap_or((0, 0));
        let stratum_stats = self.db.get_stratum_pass_rate(&node_id_hex, since).unwrap_or((0, 0));
        let ghostpay_stats = self.db.get_ghostpay_pass_rate(&node_id_hex, since).unwrap_or((0, 0));

        info!(
            node = %&node_id_hex[..8],
            archive = format!("{}/{}", archive_stats.0, archive_stats.1),
            policy = format!("{}/{}", policy_stats.0, policy_stats.1),
            stratum = format!("{}/{}", stratum_stats.0, stratum_stats.1),
            ghostpay = format!("{}/{}", ghostpay_stats.0, ghostpay_stats.1),
            min_challenges = self.config.min_challenges,
            min_pass_rate = format!("{:.0}%", self.config.min_pass_rate * 100.0),
            "DIAG: Node challenge stats"
        );

        // GATEKEEPER: Check uptime first
        if !self.check_uptime_gatekeeper(node_id) {
            return NodeCapabilities::default(); // 0 shares if uptime < 95%
        }

        // Get qualified capabilities from database
        match self.db.get_qualified_capabilities(
            &node_id_hex,
            since,
            self.config.min_challenges,
            self.config.min_pass_rate,
        ) {
            Ok(caps) => {
                info!(
                    node = %&node_id_hex[..8],
                    archive = caps.archive_mode,
                    ghost_pay = caps.ghost_pay,
                    public_mining = caps.public_mining,
                    bitcoin_pure = caps.bitcoin_pure,
                    total_shares = caps.total_shares(),
                    "DIAG: Qualified capabilities result"
                );
                caps
            }
            Err(e) => {
                warn!(
                    node = %&node_id_hex[..8],
                    error = %e,
                    "Failed to get qualified capabilities - using defaults"
                );
                NodeCapabilities::default()
            }
        }
    }

    /// Get qualified capabilities for a node by hex string
    pub fn get_qualified_by_hex(&self, node_id_hex: &str) -> NodeCapabilities {
        let since = self.lookback_timestamp();

        // GATEKEEPER: Check uptime first
        match self.db.get_uptime_percent(node_id_hex, since) {
            Ok(uptime) => {
                if uptime < self.config.min_uptime {
                    return NodeCapabilities::default();
                }
            }
            Err(_) => return NodeCapabilities::default(),
        }

        // Get qualified capabilities from database
        self.db.get_qualified_capabilities(
            node_id_hex,
            since,
            self.config.min_challenges,
            self.config.min_pass_rate,
        ).unwrap_or_default()
    }

    /// Get all nodes with qualified (verified) capabilities
    ///
    /// Returns Vec<(NodeId, shares)> for all known nodes that have
    /// verified capabilities. Used for payout calculations.
    ///
    /// Queries the `nodes` table (not `peers`) to include the local node.
    pub fn get_all_qualified_nodes(&self) -> Vec<(NodeId, i32)> {
        let since = self.lookback_timestamp();
        let mut qualified_nodes = Vec::new();

        // Get all nodes with payout addresses from database (includes local node)
        let node_ids = match self.db.get_all_node_ids_with_payout() {
            Ok(ids) => ids,
            Err(e) => {
                warn!(error = %e, "Failed to get nodes for qualification");
                return qualified_nodes;
            }
        };

        info!(
            total_nodes = node_ids.len(),
            "DIAG: Checking qualification for all nodes with payout addresses"
        );

        for node_id_hex in &node_ids {
            // GATEKEEPER: Check uptime first
            let uptime = match self.db.get_uptime_percent(node_id_hex, since) {
                Ok(u) => u,
                Err(_) => continue,
            };

            if uptime < self.config.min_uptime {
                info!(
                    node = %&node_id_hex[..8.min(node_id_hex.len())],
                    uptime = format!("{:.1}%", uptime * 100.0),
                    "DIAG: Node fails uptime gatekeeper"
                );
                continue; // Doesn't pass uptime gatekeeper
            }

            // Get qualified capabilities
            let caps = self.db.get_qualified_capabilities(
                node_id_hex,
                since,
                self.config.min_challenges,
                self.config.min_pass_rate,
            ).unwrap_or_default();

            let shares = caps.total_shares();
            if shares > 0 {
                // Convert hex string to NodeId
                if let Ok(bytes) = hex::decode(node_id_hex) {
                    if bytes.len() >= 32 {
                        let mut node_id = [0u8; 32];
                        node_id.copy_from_slice(&bytes[..32]);

                        info!(
                            node = %&node_id_hex[..8],
                            shares = shares,
                            archive = caps.archive_mode,
                            bitcoin_pure = caps.bitcoin_pure,
                            "DIAG: Qualified node for payout"
                        );

                        qualified_nodes.push((node_id, shares));
                    }
                }
            }
        }

        info!(
            total_nodes = node_ids.len(),
            qualified_nodes = qualified_nodes.len(),
            "DIAG: Qualification complete"
        );

        qualified_nodes
    }

    /// Get statistics for a node's qualification status
    pub fn get_qualification_stats(&self, node_id: &NodeId) -> QualificationStats {
        let node_id_hex = hex::encode(node_id);
        let since = self.lookback_timestamp();

        let uptime = self.db.get_uptime_percent(&node_id_hex, since).unwrap_or(0.0);
        let passes_uptime = uptime >= self.config.min_uptime;

        let archive = self.db.get_archive_pass_rate(&node_id_hex, since).unwrap_or((0, 0));
        let policy = self.db.get_policy_pass_rate(&node_id_hex, since).unwrap_or((0, 0));
        let stratum = self.db.get_stratum_pass_rate(&node_id_hex, since).unwrap_or((0, 0));
        let ghostpay = self.db.get_ghostpay_pass_rate(&node_id_hex, since).unwrap_or((0, 0));

        QualificationStats {
            node_id: node_id_hex,
            uptime_percent: uptime,
            passes_uptime_gate: passes_uptime,
            archive_challenges: archive.1,
            archive_passed: archive.0,
            policy_challenges: policy.1,
            policy_passed: policy.0,
            stratum_challenges: stratum.1,
            stratum_passed: stratum.0,
            ghostpay_challenges: ghostpay.1,
            ghostpay_passed: ghostpay.0,
            qualified_capabilities: if passes_uptime {
                self.db.get_qualified_capabilities(
                    &hex::encode(node_id),
                    since,
                    self.config.min_challenges,
                    self.config.min_pass_rate,
                ).unwrap_or_default()
            } else {
                NodeCapabilities::default()
            },
        }
    }
}

/// Statistics about a node's qualification status
#[derive(Debug, Clone)]
pub struct QualificationStats {
    /// Node ID (hex)
    pub node_id: String,
    /// Uptime percentage over lookback period
    pub uptime_percent: f64,
    /// Whether node passes uptime gatekeeper
    pub passes_uptime_gate: bool,
    /// Total archive challenges
    pub archive_challenges: u32,
    /// Passed archive challenges
    pub archive_passed: u32,
    /// Total policy challenges
    pub policy_challenges: u32,
    /// Passed policy challenges
    pub policy_passed: u32,
    /// Total stratum challenges
    pub stratum_challenges: u32,
    /// Passed stratum challenges
    pub stratum_passed: u32,
    /// Total ghostpay challenges
    pub ghostpay_challenges: u32,
    /// Passed ghostpay challenges
    pub ghostpay_passed: u32,
    /// Final qualified capabilities
    pub qualified_capabilities: NodeCapabilities,
}

impl QualificationStats {
    /// Get pass rate for a capability (0.0 if no challenges)
    pub fn archive_pass_rate(&self) -> f64 {
        if self.archive_challenges == 0 { 0.0 } else { self.archive_passed as f64 / self.archive_challenges as f64 }
    }

    pub fn policy_pass_rate(&self) -> f64 {
        if self.policy_challenges == 0 { 0.0 } else { self.policy_passed as f64 / self.policy_challenges as f64 }
    }

    pub fn stratum_pass_rate(&self) -> f64 {
        if self.stratum_challenges == 0 { 0.0 } else { self.stratum_passed as f64 / self.stratum_challenges as f64 }
    }

    pub fn ghostpay_pass_rate(&self) -> f64 {
        if self.ghostpay_challenges == 0 { 0.0 } else { self.ghostpay_passed as f64 / self.ghostpay_challenges as f64 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = QualificationConfig::default();
        assert_eq!(config.min_challenges, ghost_common::constants::MIN_CHALLENGES_FOR_QUALIFICATION as u32);
        assert!((config.min_pass_rate - 0.95).abs() < 0.001);
        assert_eq!(config.lookback_days, 7);
        assert!((config.min_uptime - 0.95).abs() < 0.001);
    }

    #[test]
    fn test_qualification_stats_pass_rates() {
        let stats = QualificationStats {
            node_id: "test".to_string(),
            uptime_percent: 0.98,
            passes_uptime_gate: true,
            archive_challenges: 20,
            archive_passed: 19,
            policy_challenges: 15,
            policy_passed: 15,
            stratum_challenges: 0,
            stratum_passed: 0,
            ghostpay_challenges: 10,
            ghostpay_passed: 8,
            qualified_capabilities: NodeCapabilities::default(),
        };

        assert!((stats.archive_pass_rate() - 0.95).abs() < 0.001);
        assert!((stats.policy_pass_rate() - 1.0).abs() < 0.001);
        assert!((stats.stratum_pass_rate() - 0.0).abs() < 0.001);
        assert!((stats.ghostpay_pass_rate() - 0.8).abs() < 0.001);
    }
}
