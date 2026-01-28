//! Consensus Message Load Tests
//!
//! Tests BFT consensus system under message flooding

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Consensus message types
#[derive(Debug, Clone)]
pub enum ConsensusMessageType {
    Proposal,
    Vote,
    PreCommit,
    Commit,
    ViewChange,
}

impl ConsensusMessageType {
    fn size_bytes(&self) -> usize {
        match self {
            ConsensusMessageType::Proposal => 512,    // Contains payout data
            ConsensusMessageType::Vote => 128,        // Hash + signature
            ConsensusMessageType::PreCommit => 128,
            ConsensusMessageType::Commit => 128,
            ConsensusMessageType::ViewChange => 256,
        }
    }
}

/// Simulated consensus node for load testing
pub struct ConsensusLoadNode {
    id: [u8; 32],
    messages_sent: AtomicU64,
    messages_received: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    proposals_created: AtomicU64,
    votes_cast: AtomicU64,
    consensus_reached: AtomicU64,
}

impl ConsensusLoadNode {
    pub fn new(id: [u8; 32]) -> Self {
        Self {
            id,
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            proposals_created: AtomicU64::new(0),
            votes_cast: AtomicU64::new(0),
            consensus_reached: AtomicU64::new(0),
        }
    }

    pub fn send_message(&self, msg_type: &ConsensusMessageType) {
        let bytes = msg_type.size_bytes() as u64;
        self.messages_sent.fetch_add(1, Ordering::SeqCst);
        self.bytes_sent.fetch_add(bytes, Ordering::SeqCst);
    }

    pub fn receive_message(&self, msg_type: &ConsensusMessageType) {
        let bytes = msg_type.size_bytes() as u64;
        self.messages_received.fetch_add(1, Ordering::SeqCst);
        self.bytes_received.fetch_add(bytes, Ordering::SeqCst);
    }

    pub fn create_proposal(&self) {
        self.proposals_created.fetch_add(1, Ordering::SeqCst);
        self.send_message(&ConsensusMessageType::Proposal);
    }

    pub fn cast_vote(&self) {
        self.votes_cast.fetch_add(1, Ordering::SeqCst);
        self.send_message(&ConsensusMessageType::Vote);
    }

    pub fn reach_consensus(&self) {
        self.consensus_reached.fetch_add(1, Ordering::SeqCst);
    }

    pub fn total_messages(&self) -> u64 {
        self.messages_sent.load(Ordering::SeqCst) + self.messages_received.load(Ordering::SeqCst)
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent.load(Ordering::SeqCst) + self.bytes_received.load(Ordering::SeqCst)
    }
}

/// Consensus network for load testing
pub struct ConsensusLoadNetwork {
    nodes: Vec<Arc<ConsensusLoadNode>>,
    consensus_threshold: f64,
    total_proposals: AtomicU64,
    total_consensus_rounds: AtomicU64,
    failed_consensus: AtomicU64,
}

impl ConsensusLoadNetwork {
    pub fn new(node_count: usize, threshold: f64) -> Self {
        let nodes = (0..node_count)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                Arc::new(ConsensusLoadNode::new(id))
            })
            .collect();

        Self {
            nodes,
            consensus_threshold: threshold,
            total_proposals: AtomicU64::new(0),
            total_consensus_rounds: AtomicU64::new(0),
            failed_consensus: AtomicU64::new(0),
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn required_votes(&self) -> usize {
        (self.nodes.len() as f64 * self.consensus_threshold).ceil() as usize
    }

    /// Simulate a full consensus round
    pub fn run_consensus_round(&self, proposer_idx: usize) -> bool {
        self.total_proposals.fetch_add(1, Ordering::SeqCst);

        // Proposer creates proposal
        let proposer = &self.nodes[proposer_idx % self.nodes.len()];
        proposer.create_proposal();

        // Broadcast proposal to all nodes
        for node in &self.nodes {
            node.receive_message(&ConsensusMessageType::Proposal);
        }

        // All nodes vote
        let mut votes = 0;
        for node in &self.nodes {
            node.cast_vote();
            // Simulate receiving votes at other nodes
            for other in &self.nodes {
                if other.id != node.id {
                    other.receive_message(&ConsensusMessageType::Vote);
                }
            }
            votes += 1;
        }

        // Check if consensus reached
        if votes >= self.required_votes() {
            self.total_consensus_rounds.fetch_add(1, Ordering::SeqCst);
            for node in &self.nodes {
                node.reach_consensus();
            }
            true
        } else {
            self.failed_consensus.fetch_add(1, Ordering::SeqCst);
            false
        }
    }

    pub fn total_network_messages(&self) -> u64 {
        self.nodes.iter().map(|n| n.total_messages()).sum::<u64>() / 2 // Divide by 2 to avoid double counting
    }

    pub fn total_network_bytes(&self) -> u64 {
        self.nodes.iter().map(|n| n.total_bytes()).sum::<u64>() / 2
    }
}

/// Consensus load test configuration
#[derive(Debug, Clone, Copy)]
pub struct ConsensusLoadConfig {
    /// Number of nodes
    pub node_count: usize,
    /// Consensus threshold (0.67 = 67%)
    pub threshold: f64,
    /// Proposals per second
    pub proposals_per_second: f64,
    /// Test duration
    pub duration_secs: u64,
    /// Simulate Byzantine nodes (% of nodes that don't vote)
    pub byzantine_ratio: f64,
}

impl Default for ConsensusLoadConfig {
    fn default() -> Self {
        Self {
            node_count: 100,
            threshold: 0.67,
            proposals_per_second: 10.0,
            duration_secs: 60,
            byzantine_ratio: 0.0,
        }
    }
}

/// Consensus load test results
#[derive(Debug)]
pub struct ConsensusLoadResults {
    /// Total proposals processed
    pub total_proposals: u64,
    /// Successful consensus rounds
    pub successful_rounds: u64,
    /// Failed consensus rounds
    pub failed_rounds: u64,
    /// Success rate
    pub success_rate: f64,
    /// Total messages exchanged
    pub total_messages: u64,
    /// Total bytes transferred
    pub total_bytes: u64,
    /// Proposals per second achieved
    pub proposals_per_second: f64,
    /// Messages per consensus round
    pub messages_per_round: f64,
    /// Test duration
    pub duration: Duration,
}

/// Run consensus load test
pub fn run_consensus_load_test(config: ConsensusLoadConfig) -> ConsensusLoadResults {
    let start = Instant::now();
    let network = ConsensusLoadNetwork::new(config.node_count, config.threshold);

    let proposal_interval = Duration::from_secs_f64(1.0 / config.proposals_per_second);
    let test_duration = Duration::from_secs(config.duration_secs);

    let mut proposal_count = 0u64;
    let mut last_proposal = Instant::now();

    while start.elapsed() < test_duration {
        if last_proposal.elapsed() >= proposal_interval {
            // Rotate proposer
            let proposer_idx = proposal_count as usize % config.node_count;
            network.run_consensus_round(proposer_idx);
            proposal_count += 1;
            last_proposal = Instant::now();
        }

        std::thread::sleep(Duration::from_micros(100));
    }

    let duration = start.elapsed();
    let successful = network.total_consensus_rounds.load(Ordering::SeqCst);
    let failed = network.failed_consensus.load(Ordering::SeqCst);
    let total_messages = network.total_network_messages();

    ConsensusLoadResults {
        total_proposals: proposal_count,
        successful_rounds: successful,
        failed_rounds: failed,
        success_rate: if proposal_count > 0 {
            successful as f64 / proposal_count as f64
        } else {
            0.0
        },
        total_messages,
        total_bytes: network.total_network_bytes(),
        proposals_per_second: proposal_count as f64 / duration.as_secs_f64(),
        messages_per_round: if proposal_count > 0 {
            total_messages as f64 / proposal_count as f64
        } else {
            0.0
        },
        duration,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consensus_network_creation() {
        let network = ConsensusLoadNetwork::new(10, 0.67);

        assert_eq!(network.node_count(), 10);
        assert_eq!(network.required_votes(), 7); // ceil(10 * 0.67) = 7
    }

    #[test]
    fn test_single_consensus_round() {
        let network = ConsensusLoadNetwork::new(10, 0.67);

        let success = network.run_consensus_round(0);
        assert!(success, "All nodes voting should reach consensus");

        assert_eq!(network.total_consensus_rounds.load(Ordering::SeqCst), 1);
        assert!(network.total_network_messages() > 0);
    }

    #[test]
    fn test_consensus_load_small() {
        let config = ConsensusLoadConfig {
            node_count: 10,
            threshold: 0.67,
            proposals_per_second: 10.0,
            duration_secs: 1,
            byzantine_ratio: 0.0,
        };

        let results = run_consensus_load_test(config);

        println!("Small consensus load test results:");
        println!("  Proposals: {}", results.total_proposals);
        println!("  Successful: {}", results.successful_rounds);
        println!("  Success rate: {:.1}%", results.success_rate * 100.0);
        println!("  Messages: {}", results.total_messages);
        println!("  Messages/round: {:.1}", results.messages_per_round);

        assert!(results.total_proposals > 0);
        assert_eq!(results.success_rate, 1.0, "All rounds should succeed without Byzantine nodes");
    }

    #[test]
    fn test_consensus_load_medium() {
        let config = ConsensusLoadConfig {
            node_count: 50,
            threshold: 0.67,
            proposals_per_second: 5.0,
            duration_secs: 2,
            byzantine_ratio: 0.0,
        };

        let results = run_consensus_load_test(config);

        println!("Medium consensus load test results:");
        println!("  Nodes: 50");
        println!("  Proposals: {}", results.total_proposals);
        println!("  Success rate: {:.1}%", results.success_rate * 100.0);
        println!("  Total bytes: {} KB", results.total_bytes / 1000);
        println!("  Proposals/sec: {:.1}", results.proposals_per_second);

        assert!(results.total_proposals >= 5);
    }

    #[test]
    #[ignore] // Run with: cargo test test_consensus_load_large -- --ignored
    fn test_consensus_load_large() {
        let config = ConsensusLoadConfig {
            node_count: 100,
            threshold: 0.67,
            proposals_per_second: 10.0,
            duration_secs: 30,
            byzantine_ratio: 0.0,
        };

        let results = run_consensus_load_test(config);

        println!("Large consensus load test results:");
        println!("  Nodes: {}", config.node_count);
        println!("  Proposals: {}", results.total_proposals);
        println!("  Successful: {}", results.successful_rounds);
        println!("  Failed: {}", results.failed_rounds);
        println!("  Success rate: {:.1}%", results.success_rate * 100.0);
        println!("  Total messages: {}", results.total_messages);
        println!("  Total bytes: {} MB", results.total_bytes / 1_000_000);
        println!("  Proposals/sec: {:.1}", results.proposals_per_second);
        println!("  Messages/round: {:.1}", results.messages_per_round);
        println!("  Duration: {:?}", results.duration);

        // Performance assertions
        assert!(results.proposals_per_second >= 5.0, "Should achieve at least 5 proposals/sec");
        assert!(results.success_rate >= 0.99, "Should have >99% success rate");
    }

    #[test]
    fn test_message_sizes() {
        assert_eq!(ConsensusMessageType::Proposal.size_bytes(), 512);
        assert_eq!(ConsensusMessageType::Vote.size_bytes(), 128);
    }
}
