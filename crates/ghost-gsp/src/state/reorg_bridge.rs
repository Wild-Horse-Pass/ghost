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
//| FILE: state/reorg_bridge.rs                                                                                          |
//|======================================================================================================================|

//! Reorg Bridge - Connects consensus layer reorg detection to GSP notifications
//!
//! This module subscribes to L1ChainMonitor and L2ForkDetector events and
//! forwards them to the ReorgNotifier for WebSocket push notifications.

use std::sync::Arc;

use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use ghost_consensus::reorg::{L1ChainMonitor, L1Event, L2Event, L2ForkDetector};
use ghost_gsp_proto::{L2ReorgReason, ReorgLayer};

use super::ReorgNotifier;
use crate::proxy::PayNodeProxy;

/// Configuration for the reorg bridge
#[derive(Debug, Clone)]
pub struct ReorgBridgeConfig {
    /// Minimum reorg depth to notify about (filter noise)
    pub min_l1_reorg_depth: u32,
    /// Whether to notify on L2 forks
    pub notify_l2_forks: bool,
    /// Whether to notify on equivocations
    pub notify_equivocations: bool,
    /// Confirmations needed before declaring chain stable after reorg
    pub stability_confirmations: u32,
}

impl Default for ReorgBridgeConfig {
    fn default() -> Self {
        Self {
            min_l1_reorg_depth: 1, // Notify on any reorg
            notify_l2_forks: true,
            notify_equivocations: true,
            stability_confirmations: 6, // 6 blocks for stability
        }
    }
}

/// Bridge that forwards consensus reorg events to GSP notifications
pub struct ReorgBridge {
    config: ReorgBridgeConfig,
    notifier: Arc<ReorgNotifier>,
    /// Optional pay node proxy for querying affected locks (M-11)
    pay_node: Option<Arc<PayNodeProxy>>,
    /// Track blocks since last reorg for stability detection
    l1_blocks_since_reorg: std::sync::atomic::AtomicU32,
    l2_blocks_since_reorg: std::sync::atomic::AtomicU32,
    /// Track last reorg heights
    last_l1_reorg_height: std::sync::atomic::AtomicU64,
    last_l2_reorg_height: std::sync::atomic::AtomicU64,
}

impl ReorgBridge {
    /// Create a new reorg bridge
    pub fn new(notifier: Arc<ReorgNotifier>, config: ReorgBridgeConfig) -> Self {
        Self {
            config,
            notifier,
            pay_node: None,
            l1_blocks_since_reorg: std::sync::atomic::AtomicU32::new(0),
            l2_blocks_since_reorg: std::sync::atomic::AtomicU32::new(0),
            last_l1_reorg_height: std::sync::atomic::AtomicU64::new(0),
            last_l2_reorg_height: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Create a new reorg bridge with pay node access (M-11)
    ///
    /// When a PayNodeProxy is provided, the bridge can query for affected locks
    /// during reorg notifications, providing more specific information to clients.
    pub fn with_pay_node(
        notifier: Arc<ReorgNotifier>,
        config: ReorgBridgeConfig,
        pay_node: Arc<PayNodeProxy>,
    ) -> Self {
        Self {
            config,
            notifier,
            pay_node: Some(pay_node),
            l1_blocks_since_reorg: std::sync::atomic::AtomicU32::new(0),
            l2_blocks_since_reorg: std::sync::atomic::AtomicU32::new(0),
            last_l1_reorg_height: std::sync::atomic::AtomicU64::new(0),
            last_l2_reorg_height: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Start the bridge, subscribing to chain monitor events
    ///
    /// This spawns background tasks that forward events to the notifier.
    pub fn start(
        self: Arc<Self>,
        l1_monitor: Option<Arc<L1ChainMonitor>>,
        l2_detector: Option<Arc<L2ForkDetector>>,
    ) {
        // Start L1 event handler
        if let Some(monitor) = l1_monitor {
            let bridge = Arc::clone(&self);
            let mut rx = monitor.subscribe();

            tokio::spawn(async move {
                info!("Reorg bridge: Started L1 event listener");
                loop {
                    match rx.recv().await {
                        Ok(event) => bridge.handle_l1_event(event).await,
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!(skipped = n, "Reorg bridge: L1 events lagged");
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            info!("Reorg bridge: L1 event channel closed");
                            break;
                        }
                    }
                }
            });
        }

        // Start L2 event handler
        if let Some(detector) = l2_detector {
            let bridge = Arc::clone(&self);
            let mut rx = detector.subscribe();

            tokio::spawn(async move {
                info!("Reorg bridge: Started L2 event listener");
                loop {
                    match rx.recv().await {
                        Ok(event) => bridge.handle_l2_event(event),
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!(skipped = n, "Reorg bridge: L2 events lagged");
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            info!("Reorg bridge: L2 event channel closed");
                            break;
                        }
                    }
                }
            });
        }
    }

    /// Handle an L1 (Bitcoin) chain event
    ///
    /// M-11: Made async to support querying affected locks from pay node.
    async fn handle_l1_event(&self, event: L1Event) {
        use std::sync::atomic::Ordering;

        match event {
            L1Event::NewBlock { height, hash } => {
                debug!(height, "L1 new block");

                // Track blocks since last reorg
                let blocks = self.l1_blocks_since_reorg.fetch_add(1, Ordering::SeqCst) + 1;
                let last_reorg = self.last_l1_reorg_height.load(Ordering::SeqCst);

                // Check if chain has stabilized after a reorg
                if last_reorg > 0 && blocks >= self.config.stability_confirmations {
                    self.notifier.notify_reorg_resolved(
                        ReorgLayer::L1,
                        height,
                        hex::encode(hash),
                        blocks,
                    );
                    // Reset tracking
                    self.last_l1_reorg_height.store(0, Ordering::SeqCst);
                    self.l1_blocks_since_reorg.store(0, Ordering::SeqCst);
                }
            }

            L1Event::Reorg {
                from_height,
                old_tip,
                new_tip,
                depth,
            } => {
                // Filter by minimum depth
                if depth < self.config.min_l1_reorg_depth {
                    debug!(
                        depth,
                        min = self.config.min_l1_reorg_depth,
                        "L1 reorg below threshold"
                    );
                    return;
                }

                warn!(from_height, depth, "L1 REORG: Notifying subscribers");

                // Track reorg state
                self.last_l1_reorg_height
                    .store(from_height, Ordering::SeqCst);
                self.l1_blocks_since_reorg.store(0, Ordering::SeqCst);

                // M-11: Query affected locks from pay node
                // Locks confirmed at or after the reorg height may have been affected
                let affected_locks = match &self.pay_node {
                    Some(pay_node) => {
                        match pay_node.get_locks_confirmed_after(from_height).await {
                            Ok(locks) => {
                                if !locks.is_empty() {
                                    info!(
                                        count = locks.len(),
                                        from_height,
                                        "Found locks potentially affected by L1 reorg"
                                    );
                                }
                                locks
                            }
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    "Failed to query affected locks for reorg notification"
                                );
                                vec![]
                            }
                        }
                    }
                    None => {
                        debug!("No pay node configured - cannot query affected locks");
                        vec![]
                    }
                };

                // For L1 reorgs, affected payments are L2 payments that were confirmed
                // on the L1 chain (settlements). Currently L2 is tracked separately,
                // so we return empty for L1 payments. In the future, this could
                // query for settlement transactions.
                let affected_payments: Vec<String> = vec![];

                // Send notification with affected items
                self.notifier.notify_l1_reorg(
                    from_height,
                    depth,
                    hex::encode(old_tip),
                    hex::encode(new_tip),
                    affected_payments,
                    affected_locks,
                );
            }

            L1Event::TxConfirmed {
                txid,
                tx_type,
                confirmations,
            } => {
                debug!(
                    txid = hex::encode(&txid[..8]),
                    tx_type = ?tx_type,
                    confirmations,
                    "L1 tx confirmed"
                );
                // Could notify about specific payment/lock confirmations
            }

            L1Event::TxReorged { txid, tx_type } => {
                warn!(
                    txid = hex::encode(&txid[..8]),
                    tx_type = ?tx_type,
                    "L1 tx reorged out"
                );

                // Notify about the specific transaction being reorged
                // This would need mapping from txid to payment_id/lock_id
                // For now, the general reorg notification covers this
            }
        }
    }

    /// Handle an L2 (Ghost Pay) chain event
    fn handle_l2_event(&self, event: L2Event) {
        use std::sync::atomic::Ordering;

        match event {
            L2Event::NewBlock {
                height,
                state_root,
                block_hash: _,
            } => {
                debug!(height, "L2 new block");

                // Track blocks since last reorg/fork
                let blocks = self.l2_blocks_since_reorg.fetch_add(1, Ordering::SeqCst) + 1;
                let last_reorg = self.last_l2_reorg_height.load(Ordering::SeqCst);

                // Check if chain has stabilized
                if last_reorg > 0 && blocks >= self.config.stability_confirmations {
                    self.notifier.notify_reorg_resolved(
                        ReorgLayer::L2,
                        height,
                        hex::encode(state_root),
                        blocks,
                    );
                    self.last_l2_reorg_height.store(0, Ordering::SeqCst);
                    self.l2_blocks_since_reorg.store(0, Ordering::SeqCst);
                }
            }

            L2Event::ForkDetected {
                fork_height,
                our_state_root,
                their_state_root,
                common_ancestor,
            } => {
                if !self.config.notify_l2_forks {
                    return;
                }

                let depth = common_ancestor
                    .map(|a| (fork_height - a) as u32)
                    .unwrap_or(1);

                warn!(
                    fork_height,
                    depth,
                    common_ancestor = ?common_ancestor,
                    "L2 FORK: Notifying subscribers"
                );

                // Track fork state
                self.last_l2_reorg_height
                    .store(fork_height, Ordering::SeqCst);
                self.l2_blocks_since_reorg.store(0, Ordering::SeqCst);

                self.notifier.notify_l2_reorg(
                    fork_height,
                    depth,
                    hex::encode(our_state_root),
                    hex::encode(their_state_root),
                    L2ReorgReason::ForkResolution,
                    vec![], // affected_payments - to be populated
                    0,      // transfers_rolled_back - to be calculated
                );
            }

            L2Event::EquivocationDetected {
                proposer,
                height,
                block_hash_a,
                block_hash_b,
            } => {
                if !self.config.notify_equivocations {
                    return;
                }

                error!(
                    height,
                    proposer = hex::encode(&proposer[..8]),
                    block_a = hex::encode(&block_hash_a[..8]),
                    block_b = hex::encode(&block_hash_b[..8]),
                    "L2 EQUIVOCATION: Proposer double-signed!"
                );

                // Track as potential reorg
                self.last_l2_reorg_height.store(height, Ordering::SeqCst);
                self.l2_blocks_since_reorg.store(0, Ordering::SeqCst);

                self.notifier.notify_l2_reorg(
                    height,
                    1, // Equivocation is typically depth 1
                    hex::encode(block_hash_a),
                    hex::encode(block_hash_b),
                    L2ReorgReason::Equivocation,
                    vec![],
                    0,
                );
            }

            L2Event::ChainStabilized {
                height,
                state_root,
                blocks_since_fork,
            } => {
                info!(height, blocks_since_fork, "L2 chain stabilized");

                self.notifier.notify_reorg_resolved(
                    ReorgLayer::L2,
                    height,
                    hex::encode(state_root),
                    blocks_since_fork,
                );

                // Reset tracking
                self.last_l2_reorg_height.store(0, Ordering::SeqCst);
                self.l2_blocks_since_reorg.store(0, Ordering::SeqCst);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ReorgBridgeConfig::default();
        assert_eq!(config.min_l1_reorg_depth, 1);
        assert!(config.notify_l2_forks);
        assert!(config.notify_equivocations);
        assert_eq!(config.stability_confirmations, 6);
    }

    #[test]
    fn test_bridge_creation() {
        let notifier = Arc::new(ReorgNotifier::new());
        let bridge = ReorgBridge::new(notifier, ReorgBridgeConfig::default());

        assert_eq!(
            bridge
                .l1_blocks_since_reorg
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }
}
