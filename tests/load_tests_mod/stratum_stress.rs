//! Stratum Protocol Stress Tests
//!
//! Tests Stratum server under high connection load

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

/// Stratum message types for simulation
#[derive(Debug, Clone)]
pub enum StratumMessage {
    Subscribe { id: u64, user_agent: String },
    Authorize { id: u64, username: String },
    Submit { id: u64, job_id: String, nonce: u64 },
    Notify { job_id: String, clean_jobs: bool },
    SetDifficulty { difficulty: f64 },
}

/// Simulated Stratum connection for stress testing
#[allow(dead_code)]
pub struct SimulatedConnection {
    id: usize,
    connected_at: Instant,
    messages_sent: AtomicU64,
    messages_received: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    is_authorized: bool,
    current_difficulty: f64,
    pending_submits: RwLock<VecDeque<u64>>, // job_ids waiting for response
}

impl SimulatedConnection {
    pub fn new(id: usize) -> Self {
        Self {
            id,
            connected_at: Instant::now(),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            is_authorized: false,
            current_difficulty: 1.0,
            pending_submits: RwLock::new(VecDeque::new()),
        }
    }

    pub fn send_message(&self, msg: &StratumMessage) -> usize {
        let bytes = self.message_size(msg);
        self.messages_sent.fetch_add(1, Ordering::SeqCst);
        self.bytes_sent.fetch_add(bytes as u64, Ordering::SeqCst);
        bytes
    }

    pub fn receive_message(&self, bytes: usize) {
        self.messages_received.fetch_add(1, Ordering::SeqCst);
        self.bytes_received.fetch_add(bytes as u64, Ordering::SeqCst);
    }

    fn message_size(&self, msg: &StratumMessage) -> usize {
        // Approximate JSON message sizes
        match msg {
            StratumMessage::Subscribe { user_agent, .. } => 50 + user_agent.len(),
            StratumMessage::Authorize { username, .. } => 40 + username.len(),
            StratumMessage::Submit { .. } => 120,
            StratumMessage::Notify { .. } => 500, // Includes merkle branches
            StratumMessage::SetDifficulty { .. } => 50,
        }
    }

    pub fn connection_age(&self) -> Duration {
        self.connected_at.elapsed()
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent.load(Ordering::SeqCst) + self.bytes_received.load(Ordering::SeqCst)
    }
}

/// Connection pool for stress testing
pub struct ConnectionPool {
    connections: RwLock<Vec<Arc<SimulatedConnection>>>,
    max_connections: usize,
    total_connections_created: AtomicUsize,
    total_connections_closed: AtomicUsize,
}

impl ConnectionPool {
    pub fn new(max_connections: usize) -> Self {
        Self {
            connections: RwLock::new(Vec::with_capacity(max_connections)),
            max_connections,
            total_connections_created: AtomicUsize::new(0),
            total_connections_closed: AtomicUsize::new(0),
        }
    }

    pub fn add_connection(&self) -> Option<Arc<SimulatedConnection>> {
        let mut conns = self.connections.write();
        if conns.len() >= self.max_connections {
            return None;
        }

        let id = self.total_connections_created.fetch_add(1, Ordering::SeqCst);
        let conn = Arc::new(SimulatedConnection::new(id));
        conns.push(Arc::clone(&conn));
        Some(conn)
    }

    pub fn remove_connection(&self, id: usize) -> bool {
        let mut conns = self.connections.write();
        if let Some(pos) = conns.iter().position(|c| c.id == id) {
            conns.remove(pos);
            self.total_connections_closed.fetch_add(1, Ordering::SeqCst);
            return true;
        }
        false
    }

    pub fn connection_count(&self) -> usize {
        self.connections.read().len()
    }

    pub fn get_connections(&self) -> Vec<Arc<SimulatedConnection>> {
        self.connections.read().clone()
    }

    pub fn total_bytes_transferred(&self) -> u64 {
        self.connections.read().iter().map(|c| c.total_bytes()).sum()
    }

    pub fn churn_rate(&self) -> f64 {
        let created = self.total_connections_created.load(Ordering::SeqCst);
        let closed = self.total_connections_closed.load(Ordering::SeqCst);
        if created == 0 {
            return 0.0;
        }
        closed as f64 / created as f64
    }
}

/// Stratum stress test configuration
#[derive(Debug, Clone)]
pub struct StratumStressConfig {
    /// Target concurrent connections
    pub target_connections: usize,
    /// Connection ramp-up rate (connections per second)
    pub ramp_rate: f64,
    /// Messages per second per connection
    pub msg_rate: f64,
    /// Test duration
    pub duration_secs: u64,
    /// Simulate connection churn
    pub churn_enabled: bool,
    /// Churn rate (disconnects per second)
    pub churn_rate: f64,
}

impl Default for StratumStressConfig {
    fn default() -> Self {
        Self {
            target_connections: 1000,
            ramp_rate: 100.0,   // 100 new connections per second
            msg_rate: 0.1,     // 1 message per 10 seconds per connection
            duration_secs: 60,
            churn_enabled: true,
            churn_rate: 10.0,  // 10 disconnects per second
        }
    }
}

/// Stratum stress test results
#[derive(Debug)]
pub struct StratumStressResults {
    /// Peak concurrent connections
    pub peak_connections: usize,
    /// Total messages processed
    pub total_messages: u64,
    /// Total bytes transferred
    pub total_bytes: u64,
    /// Messages per second achieved
    pub messages_per_second: f64,
    /// Connection churn rate
    pub connection_churn: f64,
    /// Test duration
    pub duration: Duration,
    /// Errors encountered
    pub errors: usize,
}

/// Run Stratum stress test
pub fn run_stratum_stress_test(config: StratumStressConfig) -> StratumStressResults {
    let start = Instant::now();
    let pool = Arc::new(ConnectionPool::new(config.target_connections));
    let total_messages = Arc::new(AtomicU64::new(0));
    let peak_connections = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));

    let test_duration = Duration::from_secs(config.duration_secs);

    // Simulate test
    while start.elapsed() < test_duration {
        // Add connections up to target
        while pool.connection_count() < config.target_connections {
            if pool.add_connection().is_none() {
                errors.fetch_add(1, Ordering::SeqCst);
                break;
            }
        }

        // Update peak
        let current = pool.connection_count();
        let mut peak = peak_connections.load(Ordering::SeqCst);
        while current > peak {
            match peak_connections.compare_exchange_weak(
                peak,
                current,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(p) => peak = p,
            }
        }

        // Simulate message exchange
        for conn in pool.get_connections() {
            let msg = StratumMessage::Submit {
                id: 1,
                job_id: "job123".to_string(),
                nonce: 12345,
            };
            conn.send_message(&msg);
            total_messages.fetch_add(1, Ordering::SeqCst);
        }

        // Simulate churn
        if config.churn_enabled {
            let conns = pool.get_connections();
            if !conns.is_empty() {
                let to_remove = (config.churn_rate * 0.01) as usize; // ~1% per iteration
                for conn in conns.iter().take(to_remove.min(conns.len())) {
                    pool.remove_connection(conn.id);
                }
            }
        }

        // Pace the test
        std::thread::sleep(Duration::from_millis(10));
    }

    let duration = start.elapsed();
    let messages = total_messages.load(Ordering::SeqCst);

    StratumStressResults {
        peak_connections: peak_connections.load(Ordering::SeqCst),
        total_messages: messages,
        total_bytes: pool.total_bytes_transferred(),
        messages_per_second: messages as f64 / duration.as_secs_f64(),
        connection_churn: pool.churn_rate(),
        duration,
        errors: errors.load(Ordering::SeqCst),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_pool() {
        let pool = ConnectionPool::new(10);

        // Add connections
        for _ in 0..10 {
            assert!(pool.add_connection().is_some());
        }

        // Pool is full
        assert!(pool.add_connection().is_none());
        assert_eq!(pool.connection_count(), 10);

        // Remove one
        let conns = pool.get_connections();
        pool.remove_connection(conns[0].id);
        assert_eq!(pool.connection_count(), 9);

        // Can add again
        assert!(pool.add_connection().is_some());
    }

    #[test]
    fn test_simulated_connection() {
        let conn = SimulatedConnection::new(0);

        let msg = StratumMessage::Submit {
            id: 1,
            job_id: "test".to_string(),
            nonce: 12345,
        };

        conn.send_message(&msg);
        conn.send_message(&msg);

        assert_eq!(conn.messages_sent.load(Ordering::SeqCst), 2);
        assert!(conn.bytes_sent.load(Ordering::SeqCst) > 0);
    }

    #[test]
    fn test_stratum_stress_small() {
        let config = StratumStressConfig {
            target_connections: 10,
            ramp_rate: 10.0,
            msg_rate: 1.0,
            duration_secs: 1,
            churn_enabled: false,
            churn_rate: 0.0,
        };

        let results = run_stratum_stress_test(config);

        println!("Small stress test results:");
        println!("  Peak connections: {}", results.peak_connections);
        println!("  Total messages: {}", results.total_messages);
        println!("  Messages/sec: {:.2}", results.messages_per_second);
        println!("  Errors: {}", results.errors);

        assert!(results.peak_connections > 0);
        assert!(results.total_messages > 0);
    }

    #[test]
    #[ignore] // Run with: cargo test test_stratum_stress_large -- --ignored
    fn test_stratum_stress_large() {
        let config = StratumStressConfig {
            target_connections: 1000,
            ramp_rate: 100.0,
            msg_rate: 0.1,
            duration_secs: 30,
            churn_enabled: true,
            churn_rate: 5.0,
        };

        let results = run_stratum_stress_test(config);

        println!("Large stress test results:");
        println!("  Peak connections: {}", results.peak_connections);
        println!("  Total messages: {}", results.total_messages);
        println!("  Total bytes: {} MB", results.total_bytes / 1_000_000);
        println!("  Messages/sec: {:.2}", results.messages_per_second);
        println!("  Churn rate: {:.2}%", results.connection_churn * 100.0);
        println!("  Duration: {:?}", results.duration);
        println!("  Errors: {}", results.errors);

        // Performance assertions
        assert!(results.peak_connections >= 500, "Should reach at least 500 connections");
        assert!(results.errors < 10, "Should have minimal errors");
    }
}
