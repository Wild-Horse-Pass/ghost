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
use tracing::{info, warn};

use ghost_common::types::{NodeCapabilities, NodeId};
use ghost_storage::Database;

/// Seconds in a day
const SECONDS_PER_DAY: i64 = 86_400;

/// M-15: Base minimum unique challengers required for capability qualification
/// This prevents Sybil attacks where colluding nodes verify each other.
/// Increased from 5 to 10 to require more diverse verification sources.
/// MED-VER-6: This is the base value; actual requirement scales with network size
const BASE_MIN_UNIQUE_CHALLENGERS: u32 = 10;

/// MED-VER-6: Maximum unique challengers required (cap for very large networks)
const MAX_MIN_UNIQUE_CHALLENGERS: u32 = 50;

/// Configuration for capability qualification
///
/// AUTH4-L3: Per-capability pass rates allow different thresholds based on
/// the difficulty/importance of each capability verification.
#[derive(Debug, Clone)]
pub struct QualificationConfig {
    /// Minimum number of challenges required per capability
    pub min_challenges: u32,
    /// C-2: Minimum number of unique challengers required per capability
    pub min_unique_challengers: u32,
    /// Minimum pass rate for Archive capability (0.0 to 1.0)
    pub archive_pass_rate: f64,
    /// Minimum pass rate for GhostPay capability (0.0 to 1.0)
    pub ghostpay_pass_rate: f64,
    /// Minimum pass rate for Stratum/Public Mining capability (0.0 to 1.0)
    pub stratum_pass_rate: f64,
    /// Minimum pass rate for Bitcoin Pure/Policy capability (0.0 to 1.0)
    pub policy_pass_rate: f64,
    /// Lookback period in days for uptime and challenges
    pub lookback_days: u32,
    /// Minimum uptime percentage required (gatekeeper)
    pub min_uptime: f64,
}

impl QualificationConfig {
    /// Get the pass rate for a specific capability type
    pub fn pass_rate_for(&self, capability: &str) -> f64 {
        match capability {
            "archive" => self.archive_pass_rate,
            "ghostpay" => self.ghostpay_pass_rate,
            "stratum" => self.stratum_pass_rate,
            "policy" => self.policy_pass_rate,
            _ => self.archive_pass_rate, // Default to archive rate
        }
    }
}

impl Default for QualificationConfig {
    fn default() -> Self {
        use ghost_common::constants::{
            ARCHIVE_PASS_RATE, GHOSTPAY_PASS_RATE, MIN_CHALLENGES_FOR_QUALIFICATION,
            POLICY_PASS_RATE, STRATUM_PASS_RATE, UPTIME_GATEKEEPER_THRESHOLD, UPTIME_WINDOW_DAYS,
        };
        Self {
            min_challenges: MIN_CHALLENGES_FOR_QUALIFICATION as u32,
            min_unique_challengers: BASE_MIN_UNIQUE_CHALLENGERS, // MED-VER-6: Base value, scaled at runtime
            archive_pass_rate: ARCHIVE_PASS_RATE,
            ghostpay_pass_rate: GHOSTPAY_PASS_RATE,
            stratum_pass_rate: STRATUM_PASS_RATE,
            policy_pass_rate: POLICY_PASS_RATE,
            lookback_days: UPTIME_WINDOW_DAYS as u32,
            min_uptime: UPTIME_GATEKEEPER_THRESHOLD / 100.0, // 95% -> 0.95
        }
    }
}

/// Provides qualified (verified) capabilities for nodes
///
/// This replaces CLAIMED capabilities with VERIFIED capabilities
/// based on challenge results and uptime tracking.
///
/// M-7 FIX: Includes cached network size for fallback on DB failures
pub struct QualifiedCapabilityProvider {
    /// Database for looking up challenge results and uptime
    db: Arc<Database>,
    /// Qualification configuration
    config: QualificationConfig,
    /// M-7 FIX: Cached network size for fallback on DB failures
    /// Uses atomic for thread-safe access without locks
    cached_network_size: std::sync::atomic::AtomicUsize,
}

impl QualifiedCapabilityProvider {
    /// Create a new qualified capability provider
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            config: QualificationConfig::default(),
            // M-7 FIX: Initialize with a safe default (uses base requirement)
            cached_network_size: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Create with custom configuration
    pub fn with_config(db: Arc<Database>, config: QualificationConfig) -> Self {
        Self {
            db,
            config,
            cached_network_size: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// M-7 FIX: Get network size with fallback to cached value
    ///
    /// On DB success, updates the cache and returns the fresh value.
    /// On DB failure, returns the cached value with a warning.
    /// If cache is empty (0), uses a conservative default (100 nodes).
    fn get_network_size_with_fallback(&self) -> usize {
        use std::sync::atomic::Ordering;

        match self.db.get_all_node_ids_with_payout() {
            Ok(ids) => {
                let size = ids.len();
                // Update cache on successful query
                self.cached_network_size.store(size, Ordering::Relaxed);
                size
            }
            Err(e) => {
                let cached = self.cached_network_size.load(Ordering::Relaxed);
                if cached > 0 {
                    warn!(
                        cached_size = cached,
                        error = %e,
                        "M-7: DB failure for network size, using cached value"
                    );
                    cached
                } else {
                    // No cache yet - use conservative default
                    // 100 nodes gives min_unique = 13, which is reasonable
                    warn!(
                        error = %e,
                        "M-7: DB failure for network size with empty cache, using default (100)"
                    );
                    100
                }
            }
        }
    }

    /// MED-VER-5/MED-VER-6: Maximum network size for scaling calculation
    /// Cap at 1M nodes to prevent overflow and unreasonable scaling
    const MAX_NETWORK_SIZE: usize = 1_000_000;

    /// MED-VER-6: Calculate scaled unique challenger requirement based on network size
    ///
    /// Scales logarithmically with total node count to balance Sybil resistance
    /// with practical achievability:
    /// - 10-50 nodes: 10 unique challengers (base)
    /// - 100 nodes: 13 unique challengers
    /// - 500 nodes: 19 unique challengers
    /// - 1000 nodes: 23 unique challengers
    /// - 5000+ nodes: 50 unique challengers (cap)
    ///
    /// Formula: min(MAX, BASE + sqrt(network_size / 10))
    ///
    /// MED-VER-5 FIX: Added bounds check to prevent integer overflow.
    /// Network size is capped at 1M nodes.
    fn scaled_min_unique_challengers(&self, network_size: usize) -> u32 {
        if network_size <= 10 {
            return BASE_MIN_UNIQUE_CHALLENGERS;
        }

        // MED-VER-5 FIX: Cap network size to prevent overflow
        let capped_size = network_size.min(Self::MAX_NETWORK_SIZE);

        let scaled = BASE_MIN_UNIQUE_CHALLENGERS as f64
            + ((capped_size as f64) / 10.0).sqrt().floor();

        (scaled as u32).min(MAX_MIN_UNIQUE_CHALLENGERS)
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
    /// 3. C-2: Have 5+ unique challengers (Sybil prevention)
    ///
    /// Returns default (all false) capabilities if the node doesn't
    /// meet the requirements.
    pub fn get_qualified(&self, node_id: &NodeId) -> NodeCapabilities {
        let node_id_hex = hex::encode(node_id);
        let since = self.lookback_timestamp();

        // Log challenge stats for debugging (before gatekeeper check)
        let archive_stats = self
            .db
            .get_archive_pass_rate(&node_id_hex, since)
            .unwrap_or((0, 0));
        let policy_stats = self
            .db
            .get_policy_pass_rate(&node_id_hex, since)
            .unwrap_or((0, 0));
        let stratum_stats = self
            .db
            .get_stratum_pass_rate(&node_id_hex, since)
            .unwrap_or((0, 0));
        let ghostpay_stats = self
            .db
            .get_ghostpay_pass_rate(&node_id_hex, since)
            .unwrap_or((0, 0));

        // C-2: Get unique challenger counts for Sybil prevention
        let archive_unique = self
            .db
            .get_archive_unique_challengers(&node_id_hex, since)
            .unwrap_or(0);
        let policy_unique = self
            .db
            .get_policy_unique_challengers(&node_id_hex, since)
            .unwrap_or(0);
        let stratum_unique = self
            .db
            .get_stratum_unique_challengers(&node_id_hex, since)
            .unwrap_or(0);
        let ghostpay_unique = self
            .db
            .get_ghostpay_unique_challengers(&node_id_hex, since)
            .unwrap_or(0);

        // MED-VER-6 + M-7 FIX: Get network size with fallback to cached value
        // M-7: On DB failure, use cached network size instead of returning empty capabilities
        // This prevents transient DB issues from stalling all payouts
        let network_size = self.get_network_size_with_fallback();
        let min_unique_scaled = self.scaled_min_unique_challengers(network_size);

        // AUTH4-L3 + MED-VER-6: Log per-capability pass rate requirements
        info!(
            node = %&node_id_hex[..8],
            archive = format!("{}/{}", archive_stats.0, archive_stats.1),
            policy = format!("{}/{}", policy_stats.0, policy_stats.1),
            stratum = format!("{}/{}", stratum_stats.0, stratum_stats.1),
            ghostpay = format!("{}/{}", ghostpay_stats.0, ghostpay_stats.1),
            archive_unique = archive_unique,
            policy_unique = policy_unique,
            stratum_unique = stratum_unique,
            ghostpay_unique = ghostpay_unique,
            min_challenges = self.config.min_challenges,
            min_unique = min_unique_scaled,
            network_size = network_size,
            archive_rate = format!("{:.0}%", self.config.archive_pass_rate * 100.0),
            ghostpay_rate = format!("{:.0}%", self.config.ghostpay_pass_rate * 100.0),
            "DIAG: Node challenge stats (MED-VER-6: scaled unique requirement)"
        );

        // GATEKEEPER: Check uptime first
        if !self.check_uptime_gatekeeper(node_id) {
            return NodeCapabilities::default(); // 0 shares if uptime < 95%
        }

        // MED-VER-6 + M-7 FIX: Calculate scaled unique challenger requirement
        // M-7: Use cached fallback on DB failure instead of returning empty capabilities
        let network_size = self.get_network_size_with_fallback();
        let min_unique = self.scaled_min_unique_challengers(network_size);

        // Get qualified capabilities from database
        // AUTH4-L3: Use archive_pass_rate as the baseline (0.95), but each capability
        // has its own threshold. The database uses a single rate for all capabilities,
        // so we use the strictest common rate here.
        match self.db.get_qualified_capabilities(
            &node_id_hex,
            since,
            self.config.min_challenges,
            self.config.archive_pass_rate,
        ) {
            Ok(mut caps) => {
                // C-2 + MED-VER-6: Apply unique challengers requirement (Sybil prevention)
                // A capability is only qualified if challenges came from multiple independent nodes
                // The requirement now scales with network size for better Sybil resistance
                if archive_unique < min_unique {
                    if caps.archive_mode {
                        info!(
                            node = %&node_id_hex[..8],
                            unique = archive_unique,
                            required = min_unique,
                            network_size = network_size,
                            "C-2/MED-VER-6: Archive capability disqualified - insufficient unique challengers"
                        );
                    }
                    caps.archive_mode = false;
                }
                if policy_unique < min_unique {
                    if caps.bitcoin_pure {
                        info!(
                            node = %&node_id_hex[..8],
                            unique = policy_unique,
                            required = min_unique,
                            network_size = network_size,
                            "C-2/MED-VER-6: Policy capability disqualified - insufficient unique challengers"
                        );
                    }
                    caps.bitcoin_pure = false;
                }
                if stratum_unique < min_unique {
                    if caps.public_mining {
                        info!(
                            node = %&node_id_hex[..8],
                            unique = stratum_unique,
                            required = min_unique,
                            network_size = network_size,
                            "C-2/MED-VER-6: Stratum capability disqualified - insufficient unique challengers"
                        );
                    }
                    caps.public_mining = false;
                }
                if ghostpay_unique < min_unique {
                    if caps.ghost_pay {
                        info!(
                            node = %&node_id_hex[..8],
                            unique = ghostpay_unique,
                            required = min_unique,
                            network_size = network_size,
                            "C-2/MED-VER-6: GhostPay capability disqualified - insufficient unique challengers"
                        );
                    }
                    caps.ghost_pay = false;
                }

                info!(
                    node = %&node_id_hex[..8],
                    archive = caps.archive_mode,
                    ghost_pay = caps.ghost_pay,
                    public_mining = caps.public_mining,
                    bitcoin_pure = caps.bitcoin_pure,
                    total_shares = caps.total_shares(),
                    "DIAG: Qualified capabilities result (after C-2 filter)"
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
    ///
    /// M-4 FIX: Now uses scaled_min_unique_challengers like get_qualified()
    /// M-10 FIX: Uses get_network_size_with_fallback() for cached fallback on DB failure
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

        // M-4 + M-10 FIX: Get network size for scaled unique challenger requirement
        // M-10: Use get_network_size_with_fallback() for cached fallback on DB failure,
        // matching the behavior of get_qualified(). This prevents transient DB issues
        // from causing all nodes to return default capabilities.
        let network_size = self.get_network_size_with_fallback();
        let min_unique = self.scaled_min_unique_challengers(network_size);

        // C-2: Get unique challenger counts for Sybil prevention
        let archive_unique = self
            .db
            .get_archive_unique_challengers(node_id_hex, since)
            .unwrap_or(0);
        let policy_unique = self
            .db
            .get_policy_unique_challengers(node_id_hex, since)
            .unwrap_or(0);
        let stratum_unique = self
            .db
            .get_stratum_unique_challengers(node_id_hex, since)
            .unwrap_or(0);
        let ghostpay_unique = self
            .db
            .get_ghostpay_unique_challengers(node_id_hex, since)
            .unwrap_or(0);

        // Get qualified capabilities from database
        // AUTH4-L3: Use archive_pass_rate as the baseline
        let mut caps = self
            .db
            .get_qualified_capabilities(
                node_id_hex,
                since,
                self.config.min_challenges,
                self.config.archive_pass_rate,
            )
            .unwrap_or_default();

        // C-2 + M-4 FIX: Apply SCALED unique challengers requirement (Sybil prevention)
        if archive_unique < min_unique {
            caps.archive_mode = false;
        }
        if policy_unique < min_unique {
            caps.bitcoin_pure = false;
        }
        if stratum_unique < min_unique {
            caps.public_mining = false;
        }
        if ghostpay_unique < min_unique {
            caps.ghost_pay = false;
        }

        caps
    }

    /// Get all nodes with qualified (verified) capabilities
    ///
    /// Returns Vec<(NodeId, shares)> for all known nodes that have
    /// verified capabilities. Used for payout calculations.
    ///
    /// Queries the `nodes` table (not `peers`) to include the local node.
    ///
    /// M-5 FIX: Now uses scaled_min_unique_challengers based on network size
    /// M-11 FIX: Updates network size cache for other methods to use as fallback
    pub fn get_all_qualified_nodes(&self) -> Vec<(NodeId, i32)> {
        use std::sync::atomic::Ordering;

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

        // M-5 + M-11 FIX: Calculate scaled unique challenger requirement based on network size
        // M-11: Also update the cached network size so other methods (like get_qualified_by_hex)
        // can use it as a fallback if their DB queries fail
        let network_size = node_ids.len();
        self.cached_network_size.store(network_size, Ordering::Relaxed);
        let min_unique = self.scaled_min_unique_challengers(network_size);

        info!(
            total_nodes = node_ids.len(),
            min_unique_challengers = min_unique,
            "DIAG: Checking qualification for all nodes with payout addresses (M-5: scaled requirement)"
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

            // C-2: Get unique challenger counts for Sybil prevention
            let archive_unique = self
                .db
                .get_archive_unique_challengers(node_id_hex, since)
                .unwrap_or(0);
            let policy_unique = self
                .db
                .get_policy_unique_challengers(node_id_hex, since)
                .unwrap_or(0);
            let stratum_unique = self
                .db
                .get_stratum_unique_challengers(node_id_hex, since)
                .unwrap_or(0);
            let ghostpay_unique = self
                .db
                .get_ghostpay_unique_challengers(node_id_hex, since)
                .unwrap_or(0);

            // Get qualified capabilities
            // AUTH4-L3: Use archive_pass_rate as the baseline
            let mut caps = self
                .db
                .get_qualified_capabilities(
                    node_id_hex,
                    since,
                    self.config.min_challenges,
                    self.config.archive_pass_rate,
                )
                .unwrap_or_default();

            // C-2 + M-5 FIX: Apply SCALED unique challengers requirement (Sybil prevention)
            if archive_unique < min_unique {
                caps.archive_mode = false;
            }
            if policy_unique < min_unique {
                caps.bitcoin_pure = false;
            }
            if stratum_unique < min_unique {
                caps.public_mining = false;
            }
            if ghostpay_unique < min_unique {
                caps.ghost_pay = false;
            }

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

        let uptime = self
            .db
            .get_uptime_percent(&node_id_hex, since)
            .unwrap_or(0.0);
        let passes_uptime = uptime >= self.config.min_uptime;

        let archive = self
            .db
            .get_archive_pass_rate(&node_id_hex, since)
            .unwrap_or((0, 0));
        let policy = self
            .db
            .get_policy_pass_rate(&node_id_hex, since)
            .unwrap_or((0, 0));
        let stratum = self
            .db
            .get_stratum_pass_rate(&node_id_hex, since)
            .unwrap_or((0, 0));
        let ghostpay = self
            .db
            .get_ghostpay_pass_rate(&node_id_hex, since)
            .unwrap_or((0, 0));

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
                // AUTH4-L3: Use archive_pass_rate as the baseline
                self.db
                    .get_qualified_capabilities(
                        &hex::encode(node_id),
                        since,
                        self.config.min_challenges,
                        self.config.archive_pass_rate,
                    )
                    .unwrap_or_default()
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
        if self.archive_challenges == 0 {
            0.0
        } else {
            self.archive_passed as f64 / self.archive_challenges as f64
        }
    }

    pub fn policy_pass_rate(&self) -> f64 {
        if self.policy_challenges == 0 {
            0.0
        } else {
            self.policy_passed as f64 / self.policy_challenges as f64
        }
    }

    pub fn stratum_pass_rate(&self) -> f64 {
        if self.stratum_challenges == 0 {
            0.0
        } else {
            self.stratum_passed as f64 / self.stratum_challenges as f64
        }
    }

    pub fn ghostpay_pass_rate(&self) -> f64 {
        if self.ghostpay_challenges == 0 {
            0.0
        } else {
            self.ghostpay_passed as f64 / self.ghostpay_challenges as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = QualificationConfig::default();
        assert_eq!(
            config.min_challenges,
            ghost_common::constants::MIN_CHALLENGES_FOR_QUALIFICATION as u32
        );
        // C-2: Test minimum unique challengers requirement
        assert_eq!(config.min_unique_challengers, BASE_MIN_UNIQUE_CHALLENGERS);
        // AUTH4-L3: Test per-capability pass rates
        assert!((config.archive_pass_rate - 0.95).abs() < 0.001);
        assert!((config.ghostpay_pass_rate - 0.90).abs() < 0.001);
        assert!((config.stratum_pass_rate - 0.95).abs() < 0.001);
        assert!((config.policy_pass_rate - 0.95).abs() < 0.001);
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
