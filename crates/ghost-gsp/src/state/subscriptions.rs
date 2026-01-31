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
//| FILE: state/subscriptions.rs                                                                                         |
//|======================================================================================================================|

//! Subscription manager for real-time push notifications

use std::collections::{HashMap, HashSet};

use parking_lot::RwLock;

use ghost_gsp_proto::WalletId;

/// Subscription types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubscriptionType {
    /// Balance updates
    Balance,
    /// Payment notifications
    Payments,
    /// Lock state changes
    Locks,
    /// Chain reorganization notifications (L1 and L2)
    Reorgs,
}

impl SubscriptionType {
    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "balance" => Some(SubscriptionType::Balance),
            "payments" => Some(SubscriptionType::Payments),
            "locks" => Some(SubscriptionType::Locks),
            "reorgs" => Some(SubscriptionType::Reorgs),
            _ => None,
        }
    }

    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            SubscriptionType::Balance => "balance",
            SubscriptionType::Payments => "payments",
            SubscriptionType::Locks => "locks",
            SubscriptionType::Reorgs => "reorgs",
        }
    }
}

/// Manager for WebSocket subscriptions
pub struct SubscriptionManager {
    /// wallet_id -> set of subscription types
    subscriptions: RwLock<HashMap<String, HashSet<SubscriptionType>>>,

    /// lock_id -> set of wallet_ids subscribed to that lock's state updates
    lock_state_subscriptions: RwLock<HashMap<String, HashSet<String>>>,
}

impl SubscriptionManager {
    /// Create a new subscription manager
    pub fn new() -> Self {
        Self {
            subscriptions: RwLock::new(HashMap::new()),
            lock_state_subscriptions: RwLock::new(HashMap::new()),
        }
    }

    /// Add a subscription for a wallet
    pub fn subscribe(&self, wallet_id: &WalletId, subscription: &str) {
        if let Some(sub_type) = SubscriptionType::from_str(subscription) {
            let mut subs = self.subscriptions.write();
            subs.entry(wallet_id.to_string())
                .or_insert_with(HashSet::new)
                .insert(sub_type);
        }
    }

    /// Remove a subscription for a wallet
    pub fn unsubscribe(&self, wallet_id: &WalletId, subscription: &str) {
        if let Some(sub_type) = SubscriptionType::from_str(subscription) {
            let mut subs = self.subscriptions.write();
            if let Some(wallet_subs) = subs.get_mut(&wallet_id.to_string()) {
                wallet_subs.remove(&sub_type);
                if wallet_subs.is_empty() {
                    subs.remove(&wallet_id.to_string());
                }
            }
        }
    }

    /// Remove all subscriptions for a wallet
    pub fn unsubscribe_all(&self, wallet_id: &WalletId) {
        let mut subs = self.subscriptions.write();
        subs.remove(&wallet_id.to_string());
    }

    /// Check if a wallet is subscribed to a type
    pub fn is_subscribed(&self, wallet_id: &WalletId, sub_type: SubscriptionType) -> bool {
        let subs = self.subscriptions.read();
        subs.get(&wallet_id.to_string())
            .map(|s| s.contains(&sub_type))
            .unwrap_or(false)
    }

    /// Get all wallet IDs subscribed to a type
    pub fn get_subscribers(&self, sub_type: SubscriptionType) -> Vec<WalletId> {
        let subs = self.subscriptions.read();
        subs.iter()
            .filter(|(_, types)| types.contains(&sub_type))
            .map(|(id, _)| WalletId::from(id.clone()))
            .collect()
    }

    /// Get subscription count
    pub fn subscription_count(&self) -> usize {
        let subs = self.subscriptions.read();
        subs.values().map(|s| s.len()).sum()
    }

    /// Get unique wallet count with subscriptions
    pub fn wallet_count(&self) -> usize {
        self.subscriptions.read().len()
    }

    // =========================================================================
    // Lock State Subscriptions (for instant payments)
    // =========================================================================

    /// Subscribe a wallet to lock state updates for a specific lock
    pub fn subscribe_lock_state(&self, wallet_id: &WalletId, lock_id: &str) {
        let mut subs = self.lock_state_subscriptions.write();
        subs.entry(lock_id.to_string())
            .or_insert_with(HashSet::new)
            .insert(wallet_id.to_string());
    }

    /// Unsubscribe a wallet from lock state updates for a specific lock
    pub fn unsubscribe_lock_state(&self, wallet_id: &WalletId, lock_id: &str) {
        let mut subs = self.lock_state_subscriptions.write();
        if let Some(lock_subs) = subs.get_mut(lock_id) {
            lock_subs.remove(&wallet_id.to_string());
            if lock_subs.is_empty() {
                subs.remove(lock_id);
            }
        }
    }

    /// Unsubscribe a wallet from all lock state subscriptions
    pub fn unsubscribe_all_lock_states(&self, wallet_id: &WalletId) {
        let wallet_str = wallet_id.to_string();
        let mut subs = self.lock_state_subscriptions.write();

        // Remove wallet from all lock subscriptions
        let empty_locks: Vec<String> = subs
            .iter_mut()
            .filter_map(|(lock_id, wallets)| {
                wallets.remove(&wallet_str);
                if wallets.is_empty() {
                    Some(lock_id.clone())
                } else {
                    None
                }
            })
            .collect();

        // Clean up empty lock entries
        for lock_id in empty_locks {
            subs.remove(&lock_id);
        }
    }

    /// Get all wallet IDs subscribed to a specific lock's state updates
    pub fn get_lock_state_subscribers(&self, lock_id: &str) -> Vec<WalletId> {
        let subs = self.lock_state_subscriptions.read();
        subs.get(lock_id)
            .map(|wallets| {
                wallets
                    .iter()
                    .map(|id| WalletId::from(id.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Check if a wallet is subscribed to a lock's state updates
    pub fn is_subscribed_lock_state(&self, wallet_id: &WalletId, lock_id: &str) -> bool {
        let subs = self.lock_state_subscriptions.read();
        subs.get(lock_id)
            .map(|wallets| wallets.contains(&wallet_id.to_string()))
            .unwrap_or(false)
    }

    /// Get count of lock state subscriptions
    pub fn lock_state_subscription_count(&self) -> usize {
        let subs = self.lock_state_subscriptions.read();
        subs.values().map(|s| s.len()).sum()
    }

    // =========================================================================
    // Reorg Subscriptions
    // =========================================================================

    /// Subscribe a wallet to chain reorganization notifications
    pub fn subscribe_reorgs(&self, wallet_id: &WalletId) {
        let mut subs = self.subscriptions.write();
        subs.entry(wallet_id.to_string())
            .or_insert_with(HashSet::new)
            .insert(SubscriptionType::Reorgs);
    }

    /// Unsubscribe a wallet from chain reorganization notifications
    pub fn unsubscribe_reorgs(&self, wallet_id: &WalletId) {
        let mut subs = self.subscriptions.write();
        if let Some(wallet_subs) = subs.get_mut(&wallet_id.to_string()) {
            wallet_subs.remove(&SubscriptionType::Reorgs);
            if wallet_subs.is_empty() {
                subs.remove(&wallet_id.to_string());
            }
        }
    }

    /// Get all wallet IDs subscribed to reorg notifications
    pub fn get_reorg_subscribers(&self) -> Vec<WalletId> {
        self.get_subscribers(SubscriptionType::Reorgs)
    }

    /// Check if a wallet is subscribed to reorg notifications
    pub fn is_subscribed_reorgs(&self, wallet_id: &WalletId) -> bool {
        self.is_subscribed(wallet_id, SubscriptionType::Reorgs)
    }
}

impl Default for SubscriptionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscribe_unsubscribe() {
        let manager = SubscriptionManager::new();
        let wallet_id = WalletId::from("test_wallet".to_string());

        // Initially not subscribed
        assert!(!manager.is_subscribed(&wallet_id, SubscriptionType::Balance));

        // Subscribe
        manager.subscribe(&wallet_id, "balance");
        assert!(manager.is_subscribed(&wallet_id, SubscriptionType::Balance));

        // Unsubscribe
        manager.unsubscribe(&wallet_id, "balance");
        assert!(!manager.is_subscribed(&wallet_id, SubscriptionType::Balance));
    }

    #[test]
    fn test_multiple_subscriptions() {
        let manager = SubscriptionManager::new();
        let wallet_id = WalletId::from("test_wallet".to_string());

        manager.subscribe(&wallet_id, "balance");
        manager.subscribe(&wallet_id, "payments");
        manager.subscribe(&wallet_id, "locks");

        assert!(manager.is_subscribed(&wallet_id, SubscriptionType::Balance));
        assert!(manager.is_subscribed(&wallet_id, SubscriptionType::Payments));
        assert!(manager.is_subscribed(&wallet_id, SubscriptionType::Locks));

        assert_eq!(manager.subscription_count(), 3);
        assert_eq!(manager.wallet_count(), 1);
    }

    #[test]
    fn test_unsubscribe_all() {
        let manager = SubscriptionManager::new();
        let wallet_id = WalletId::from("test_wallet".to_string());

        manager.subscribe(&wallet_id, "balance");
        manager.subscribe(&wallet_id, "payments");

        manager.unsubscribe_all(&wallet_id);

        assert!(!manager.is_subscribed(&wallet_id, SubscriptionType::Balance));
        assert!(!manager.is_subscribed(&wallet_id, SubscriptionType::Payments));
        assert_eq!(manager.wallet_count(), 0);
    }

    #[test]
    fn test_get_subscribers() {
        let manager = SubscriptionManager::new();
        let wallet1 = WalletId::from("wallet1".to_string());
        let wallet2 = WalletId::from("wallet2".to_string());

        manager.subscribe(&wallet1, "balance");
        manager.subscribe(&wallet2, "balance");
        manager.subscribe(&wallet1, "payments");

        let balance_subs = manager.get_subscribers(SubscriptionType::Balance);
        assert_eq!(balance_subs.len(), 2);

        let payment_subs = manager.get_subscribers(SubscriptionType::Payments);
        assert_eq!(payment_subs.len(), 1);
    }

    #[test]
    fn test_invalid_subscription_type() {
        let manager = SubscriptionManager::new();
        let wallet_id = WalletId::from("test_wallet".to_string());

        // Invalid type should be ignored
        manager.subscribe(&wallet_id, "invalid");
        assert_eq!(manager.wallet_count(), 0);
    }
}
