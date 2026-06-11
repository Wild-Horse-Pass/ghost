//! Peer discovery and management

use super::NetworkError;
use std::collections::HashSet;

/// Peer information
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Peer {
    /// Peer endpoint URL
    pub endpoint: String,
    /// Whether this is a trusted/hardcoded peer
    pub is_seed: bool,
    /// Last successful connection time (unix timestamp)
    pub last_seen: Option<u64>,
    /// Number of failed connection attempts
    pub failures: u32,
}

/// Peer discovery and management
pub struct PeerManager {
    peers: HashSet<Peer>,
    max_peers: usize,
}

impl PeerManager {
    /// Create a new peer manager with seed peers
    pub fn new(seed_endpoints: Vec<String>) -> Self {
        let peers: HashSet<_> = seed_endpoints
            .into_iter()
            .map(|endpoint| Peer {
                endpoint,
                is_seed: true,
                last_seen: None,
                failures: 0,
            })
            .collect();

        Self {
            peers,
            max_peers: 8,
        }
    }

    /// Add a discovered peer
    pub fn add_peer(&mut self, endpoint: String) {
        if self.peers.len() < self.max_peers {
            self.peers.insert(Peer {
                endpoint,
                is_seed: false,
                last_seen: None,
                failures: 0,
            });
        }
    }

    /// Get the best peer to connect to
    pub fn get_best_peer(&self) -> Option<&Peer> {
        // Prefer peers with recent successful connections
        // Fall back to seed peers
        self.peers
            .iter()
            .filter(|p| p.failures < 3)
            .min_by_key(|p| p.failures)
    }

    /// Mark a peer as failed
    pub fn mark_failed(&mut self, endpoint: &str) {
        if let Some(peer) = self.peers.iter().find(|p| p.endpoint == endpoint).cloned() {
            self.peers.remove(&peer);
            self.peers.insert(Peer {
                failures: peer.failures + 1,
                ..peer
            });
        }
    }

    /// Mark a peer as successful
    pub fn mark_success(&mut self, endpoint: &str, timestamp: u64) {
        if let Some(peer) = self.peers.iter().find(|p| p.endpoint == endpoint).cloned() {
            self.peers.remove(&peer);
            self.peers.insert(Peer {
                last_seen: Some(timestamp),
                failures: 0,
                ..peer
            });
        }
    }

    /// Discover peers from a connected node.
    ///
    /// Queries `getpeerinfo` and adds any new endpoints up to `max_peers`.
    /// Rejects loopback, private-network, and non-HTTP(S) addresses.
    pub async fn discover_peers(
        &mut self,
        client: &mut super::NodeClient,
    ) -> Result<(), NetworkError> {
        let peers_info = client.get_peer_info().await?;

        for info in peers_info {
            // Ghost Core returns "addr" as "ip:port" in getpeerinfo.
            if let Some(addr) = info.get("addr").and_then(|v| v.as_str()) {
                let endpoint = if addr.contains("://") {
                    addr.to_string()
                } else {
                    format!("http://{addr}")
                };

                // --- Address validation ---
                // Reject non-HTTP(S) schemes.
                if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
                    continue;
                }

                // Extract the host portion (after "://" up to the next '/' or ':' or end).
                let host_part = endpoint
                    .split("://")
                    .nth(1)
                    .unwrap_or("")
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .split(':')
                    .next()
                    .unwrap_or("");

                // Reject loopback addresses.
                if host_part == "127.0.0.1"
                    || host_part == "localhost"
                    || host_part == "0.0.0.0"
                    || host_part == "::1"
                {
                    continue;
                }

                // Reject private IP ranges (RFC 1918).
                if host_part.starts_with("10.")
                    || host_part.starts_with("192.168.")
                    || is_private_172(host_part)
                {
                    continue;
                }

                // Don't add if we already know this peer or we're at capacity.
                if self.peers.len() >= self.max_peers {
                    break;
                }
                if self.peers.iter().any(|p| p.endpoint == endpoint) {
                    continue;
                }

                self.peers.insert(Peer {
                    endpoint,
                    is_seed: false,
                    last_seen: info.get("lastrecv").and_then(|v| v.as_u64()),
                    failures: 0,
                });
            }
        }

        Ok(())
    }
}

/// Check whether a host string falls in the 172.16.0.0/12 private range
/// (172.16.x.x through 172.31.x.x).
fn is_private_172(host: &str) -> bool {
    if let Some(rest) = host.strip_prefix("172.") {
        if let Some(second_octet_str) = rest.split('.').next() {
            if let Ok(second_octet) = second_octet_str.parse::<u8>() {
                return (16..=31).contains(&second_octet);
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_manager() {
        let mut manager = PeerManager::new(vec![
            "https://node1.ghost.network".into(),
            "https://node2.ghost.network".into(),
        ]);

        assert_eq!(manager.peers.len(), 2);

        let endpoint = {
            let best = manager.get_best_peer().unwrap();
            assert!(best.is_seed);
            best.endpoint.clone()
        };

        manager.mark_failed(&endpoint);
        manager.mark_failed(&endpoint);
        manager.mark_failed(&endpoint);

        // After 3 failures, should prefer the other peer
        let best = manager.get_best_peer().unwrap();
        assert_eq!(best.failures, 0);
    }

    #[test]
    fn test_empty_seed_list() {
        let manager = PeerManager::new(vec![]);
        assert_eq!(manager.peers.len(), 0);
        assert!(manager.get_best_peer().is_none());
    }

    #[test]
    fn test_add_peer() {
        let mut manager = PeerManager::new(vec!["seed1".into()]);
        manager.add_peer("discovered1".into());
        assert_eq!(manager.peers.len(), 2);

        // Added peer should not be a seed
        let discovered = manager
            .peers
            .iter()
            .find(|p| p.endpoint == "discovered1")
            .unwrap();
        assert!(!discovered.is_seed);
    }

    #[test]
    fn test_max_peers_cap() {
        let mut manager = PeerManager::new(vec![]);
        for i in 0..10 {
            manager.add_peer(format!("peer{i}"));
        }
        // max_peers is 8
        assert_eq!(manager.peers.len(), 8);
    }

    #[test]
    fn test_mark_success_resets_failures() {
        let mut manager = PeerManager::new(vec!["node1".into()]);
        manager.mark_failed("node1");
        manager.mark_failed("node1");

        let peer = manager
            .peers
            .iter()
            .find(|p| p.endpoint == "node1")
            .unwrap();
        assert_eq!(peer.failures, 2);

        manager.mark_success("node1", 1000);

        let peer = manager
            .peers
            .iter()
            .find(|p| p.endpoint == "node1")
            .unwrap();
        assert_eq!(peer.failures, 0);
        assert_eq!(peer.last_seen, Some(1000));
    }

    #[test]
    fn test_mark_failed_nonexistent() {
        let mut manager = PeerManager::new(vec!["node1".into()]);
        // Should not panic
        manager.mark_failed("nonexistent");
        assert_eq!(manager.peers.len(), 1);
    }

    #[test]
    fn test_mark_success_nonexistent() {
        let mut manager = PeerManager::new(vec!["node1".into()]);
        manager.mark_success("nonexistent", 999);
        assert_eq!(manager.peers.len(), 1);
    }

    #[test]
    fn test_best_peer_prefers_fewer_failures() {
        let mut manager = PeerManager::new(vec!["a".into(), "b".into()]);
        manager.mark_failed("a");

        let best = manager.get_best_peer().unwrap();
        assert_eq!(best.endpoint, "b");
        assert_eq!(best.failures, 0);
    }

    #[test]
    fn test_all_peers_exhausted() {
        let mut manager = PeerManager::new(vec!["a".into()]);
        for _ in 0..3 {
            manager.mark_failed("a");
        }
        // 3 failures → filtered out
        assert!(manager.get_best_peer().is_none());
    }

    #[test]
    fn test_duplicate_seed_endpoints() {
        let manager = PeerManager::new(vec!["same".into(), "same".into()]);
        // HashSet deduplicates
        assert_eq!(manager.peers.len(), 1);
    }

    #[test]
    fn test_is_private_172() {
        // In range (172.16 - 172.31)
        assert!(is_private_172("172.16.0.1"));
        assert!(is_private_172("172.31.255.255"));
        assert!(is_private_172("172.24.0.1"));

        // Out of range
        assert!(!is_private_172("172.15.0.1"));
        assert!(!is_private_172("172.32.0.1"));
        assert!(!is_private_172("172.0.0.1"));

        // Not 172.x at all
        assert!(!is_private_172("10.0.0.1"));
        assert!(!is_private_172("192.168.1.1"));
        assert!(!is_private_172("8.8.8.8"));
    }
}
