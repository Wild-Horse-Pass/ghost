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
//| FILE: state/reorg_notifier.rs                                                                                        |
//|======================================================================================================================|

//! Reorg notification service for push notifications to subscribed wallets
//!
//! This module provides a broadcast system for notifying wallets when chain
//! reorganizations occur on either L1 (Bitcoin) or L2 (Ghost Pay).

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use ghost_gsp_proto::{L2ReorgReason, PaymentStatus, ReorgLayer, ServerMessage};

/// Internal reorg event type for broadcasting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReorgEvent {
    /// L1 (Bitcoin) chain reorganization
    L1Reorg {
        reorg_height: u64,
        depth: u32,
        old_tip: String,
        new_tip: String,
        affected_payments: Vec<String>,
        affected_locks: Vec<String>,
    },
    /// L2 (Ghost Pay) chain reorganization
    L2Reorg {
        reorg_height: u64,
        depth: u32,
        old_state_root: String,
        new_state_root: String,
        reason: L2ReorgReason,
        affected_payments: Vec<String>,
        transfers_rolled_back: u32,
    },
    /// A specific payment was affected by a reorg
    PaymentReorged {
        payment_id: String,
        layer: ReorgLayer,
        old_confirmations: u32,
        new_confirmations: u32,
        new_status: PaymentStatus,
        reason: String,
    },
    /// A specific lock was affected by a reorg
    LockReorged {
        lock_id: String,
        layer: ReorgLayer,
        old_state: String,
        new_state: String,
        old_confirmations: u32,
        new_confirmations: u32,
        reason: String,
    },
    /// Chain reorganization resolved (back to stable)
    ReorgResolved {
        layer: ReorgLayer,
        height: u64,
        tip: String,
        confirmations_since_reorg: u32,
    },
}

impl ReorgEvent {
    /// Convert to ServerMessage for WebSocket delivery
    pub fn to_server_message(&self) -> ServerMessage {
        let detected_at = chrono::Utc::now().timestamp();

        match self {
            ReorgEvent::L1Reorg {
                reorg_height,
                depth,
                old_tip,
                new_tip,
                affected_payments,
                affected_locks,
            } => ServerMessage::L1ReorgDetected {
                reorg_height: *reorg_height,
                depth: *depth,
                old_tip: old_tip.clone(),
                new_tip: new_tip.clone(),
                affected_payments: affected_payments.clone(),
                affected_locks: affected_locks.clone(),
                detected_at,
            },
            ReorgEvent::L2Reorg {
                reorg_height,
                depth,
                old_state_root,
                new_state_root,
                reason,
                affected_payments,
                transfers_rolled_back,
            } => ServerMessage::L2ReorgDetected {
                reorg_height: *reorg_height,
                depth: *depth,
                old_state_root: old_state_root.clone(),
                new_state_root: new_state_root.clone(),
                reason: *reason,
                affected_payments: affected_payments.clone(),
                transfers_rolled_back: *transfers_rolled_back,
                detected_at,
            },
            ReorgEvent::PaymentReorged {
                payment_id,
                layer,
                old_confirmations,
                new_confirmations,
                new_status,
                reason,
            } => ServerMessage::PaymentReorged {
                payment_id: payment_id.clone(),
                layer: *layer,
                old_confirmations: *old_confirmations,
                new_confirmations: *new_confirmations,
                new_status: *new_status,
                reason: reason.clone(),
            },
            ReorgEvent::LockReorged {
                lock_id,
                layer,
                old_state,
                new_state,
                old_confirmations,
                new_confirmations,
                reason,
            } => ServerMessage::LockReorged {
                lock_id: lock_id.clone(),
                layer: *layer,
                old_state: old_state.clone(),
                new_state: new_state.clone(),
                old_confirmations: *old_confirmations,
                new_confirmations: *new_confirmations,
                reason: reason.clone(),
            },
            ReorgEvent::ReorgResolved {
                layer,
                height,
                tip,
                confirmations_since_reorg,
            } => ServerMessage::ReorgResolved {
                layer: *layer,
                height: *height,
                tip: tip.clone(),
                confirmations_since_reorg: *confirmations_since_reorg,
            },
        }
    }
}

/// Channel capacity for reorg events
const REORG_CHANNEL_CAPACITY: usize = 64;

/// Reorg notification broadcaster
///
/// This service receives reorg events and broadcasts them to all
/// wallets that have subscribed to reorg notifications.
pub struct ReorgNotifier {
    /// Sender for broadcasting reorg events
    sender: broadcast::Sender<ReorgEvent>,
}

impl ReorgNotifier {
    /// Create a new reorg notifier
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(REORG_CHANNEL_CAPACITY);
        Self { sender }
    }

    /// Get a receiver for reorg events
    pub fn subscribe(&self) -> broadcast::Receiver<ReorgEvent> {
        self.sender.subscribe()
    }

    /// Broadcast an L1 reorg event
    pub fn notify_l1_reorg(
        &self,
        reorg_height: u64,
        depth: u32,
        old_tip: String,
        new_tip: String,
        affected_payments: Vec<String>,
        affected_locks: Vec<String>,
    ) {
        let event = ReorgEvent::L1Reorg {
            reorg_height,
            depth,
            old_tip: old_tip.clone(),
            new_tip: new_tip.clone(),
            affected_payments: affected_payments.clone(),
            affected_locks: affected_locks.clone(),
        };

        info!(
            reorg_height,
            depth,
            old_tip = %old_tip,
            new_tip = %new_tip,
            affected_payments = affected_payments.len(),
            affected_locks = affected_locks.len(),
            "Broadcasting L1 reorg notification"
        );

        if let Err(e) = self.sender.send(event) {
            debug!("No reorg subscribers ({})", e);
        }
    }

    /// Broadcast an L2 reorg event
    #[allow(clippy::too_many_arguments)]
    pub fn notify_l2_reorg(
        &self,
        reorg_height: u64,
        depth: u32,
        old_state_root: String,
        new_state_root: String,
        reason: L2ReorgReason,
        affected_payments: Vec<String>,
        transfers_rolled_back: u32,
    ) {
        let event = ReorgEvent::L2Reorg {
            reorg_height,
            depth,
            old_state_root: old_state_root.clone(),
            new_state_root: new_state_root.clone(),
            reason,
            affected_payments: affected_payments.clone(),
            transfers_rolled_back,
        };

        info!(
            reorg_height,
            depth,
            old_state_root = %old_state_root,
            new_state_root = %new_state_root,
            reason = ?reason,
            affected_payments = affected_payments.len(),
            transfers_rolled_back,
            "Broadcasting L2 reorg notification"
        );

        if let Err(e) = self.sender.send(event) {
            debug!("No reorg subscribers ({})", e);
        }
    }

    /// Broadcast payment reorg notification
    pub fn notify_payment_reorged(
        &self,
        payment_id: String,
        layer: ReorgLayer,
        old_confirmations: u32,
        new_confirmations: u32,
        new_status: PaymentStatus,
        reason: String,
    ) {
        let event = ReorgEvent::PaymentReorged {
            payment_id: payment_id.clone(),
            layer,
            old_confirmations,
            new_confirmations,
            new_status,
            reason: reason.clone(),
        };

        warn!(
            payment_id = %payment_id,
            layer = ?layer,
            old_confirmations,
            new_confirmations,
            new_status = ?new_status,
            "Payment affected by reorg"
        );

        if let Err(e) = self.sender.send(event) {
            debug!("No reorg subscribers ({})", e);
        }
    }

    /// Broadcast lock reorg notification
    #[allow(clippy::too_many_arguments)]
    pub fn notify_lock_reorged(
        &self,
        lock_id: String,
        layer: ReorgLayer,
        old_state: String,
        new_state: String,
        old_confirmations: u32,
        new_confirmations: u32,
        reason: String,
    ) {
        let event = ReorgEvent::LockReorged {
            lock_id: lock_id.clone(),
            layer,
            old_state: old_state.clone(),
            new_state: new_state.clone(),
            old_confirmations,
            new_confirmations,
            reason: reason.clone(),
        };

        warn!(
            lock_id = %lock_id,
            layer = ?layer,
            old_state = %old_state,
            new_state = %new_state,
            "Lock affected by reorg"
        );

        if let Err(e) = self.sender.send(event) {
            debug!("No reorg subscribers ({})", e);
        }
    }

    /// Broadcast reorg resolved notification
    pub fn notify_reorg_resolved(
        &self,
        layer: ReorgLayer,
        height: u64,
        tip: String,
        confirmations_since_reorg: u32,
    ) {
        let event = ReorgEvent::ReorgResolved {
            layer,
            height,
            tip: tip.clone(),
            confirmations_since_reorg,
        };

        info!(
            layer = ?layer,
            height,
            tip = %tip,
            confirmations_since_reorg,
            "Reorg resolved - chain stabilized"
        );

        if let Err(e) = self.sender.send(event) {
            debug!("No reorg subscribers ({})", e);
        }
    }

    /// Get the number of active subscribers
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

impl Default for ReorgNotifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reorg_notifier_creation() {
        let notifier = ReorgNotifier::new();
        assert_eq!(notifier.subscriber_count(), 0);
    }

    #[test]
    fn test_subscribe_receive() {
        let notifier = ReorgNotifier::new();
        let mut rx = notifier.subscribe();
        assert_eq!(notifier.subscriber_count(), 1);

        notifier.notify_l1_reorg(
            100,
            2,
            "old_tip_hash".to_string(),
            "new_tip_hash".to_string(),
            vec!["payment1".to_string()],
            vec!["lock1".to_string()],
        );

        // Should receive the event
        let event = rx.try_recv().unwrap();
        match event {
            ReorgEvent::L1Reorg {
                reorg_height,
                depth,
                ..
            } => {
                assert_eq!(reorg_height, 100);
                assert_eq!(depth, 2);
            }
            _ => panic!("Expected L1Reorg event"),
        }
    }

    #[test]
    fn test_l2_reorg_notification() {
        let notifier = ReorgNotifier::new();
        let mut rx = notifier.subscribe();

        notifier.notify_l2_reorg(
            500,
            1,
            "old_state_root".to_string(),
            "new_state_root".to_string(),
            L2ReorgReason::ForkResolution,
            vec!["payment2".to_string()],
            5,
        );

        let event = rx.try_recv().unwrap();
        match event {
            ReorgEvent::L2Reorg {
                reorg_height,
                reason,
                transfers_rolled_back,
                ..
            } => {
                assert_eq!(reorg_height, 500);
                assert!(matches!(reason, L2ReorgReason::ForkResolution));
                assert_eq!(transfers_rolled_back, 5);
            }
            _ => panic!("Expected L2Reorg event"),
        }
    }

    #[test]
    fn test_reorg_event_to_server_message() {
        let event = ReorgEvent::L1Reorg {
            reorg_height: 100,
            depth: 2,
            old_tip: "old".to_string(),
            new_tip: "new".to_string(),
            affected_payments: vec![],
            affected_locks: vec![],
        };

        let msg = event.to_server_message();
        match msg {
            ServerMessage::L1ReorgDetected {
                reorg_height,
                depth,
                ..
            } => {
                assert_eq!(reorg_height, 100);
                assert_eq!(depth, 2);
            }
            _ => panic!("Expected L1ReorgDetected message"),
        }
    }

    #[test]
    fn test_no_subscribers_ok() {
        let notifier = ReorgNotifier::new();
        // Should not panic even with no subscribers
        notifier.notify_l1_reorg(100, 1, "old".to_string(), "new".to_string(), vec![], vec![]);
    }
}
