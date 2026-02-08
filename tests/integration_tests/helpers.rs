// Allow common test-code patterns that clippy flags
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(unused_mut)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_div_ceil)]
#![allow(clippy::let_and_return)]
#![allow(clippy::iter_nth_zero)]
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::manual_repeat_n)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::unnecessary_unwrap)]
#![allow(clippy::manual_memcpy)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::needless_character_iteration)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::bool_assert_comparison)]

//! Test helpers for integration tests

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash, Transaction, Txid};
use parking_lot::RwLock;

/// Mock Bitcoin RPC for testing without a real node
pub struct MockBitcoinRpc {
    /// Current block height
    height: AtomicU64,
    /// Block templates by height
    templates: RwLock<HashMap<u64, MockTemplate>>,
    /// Submitted blocks
    submitted_blocks: RwLock<Vec<Block>>,
    /// Mempool transactions
    mempool: RwLock<Vec<Transaction>>,
    /// Block hash by height
    block_hashes: RwLock<HashMap<u64, BlockHash>>,
}

impl MockBitcoinRpc {
    pub fn new() -> Self {
        Self {
            height: AtomicU64::new(800_000),
            templates: RwLock::new(HashMap::new()),
            submitted_blocks: RwLock::new(Vec::new()),
            mempool: RwLock::new(Vec::new()),
            block_hashes: RwLock::new(HashMap::new()),
        }
    }

    pub fn set_height(&self, height: u64) {
        self.height.store(height, Ordering::SeqCst);
    }

    pub fn get_height(&self) -> u64 {
        self.height.load(Ordering::SeqCst)
    }

    pub fn increment_height(&self) -> u64 {
        self.height.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn add_template(&self, height: u64, template: MockTemplate) {
        self.templates.write().insert(height, template);
    }

    pub fn submit_block(&self, block: Block) -> Result<(), String> {
        self.submitted_blocks.write().push(block);
        self.increment_height();
        Ok(())
    }

    pub fn get_submitted_blocks(&self) -> Vec<Block> {
        self.submitted_blocks.read().clone()
    }

    pub fn add_mempool_tx(&self, tx: Transaction) {
        self.mempool.write().push(tx);
    }

    pub fn get_mempool(&self) -> Vec<Transaction> {
        self.mempool.read().clone()
    }

    pub fn clear_mempool(&self) {
        self.mempool.write().clear();
    }

    pub fn set_block_hash(&self, height: u64, hash: BlockHash) {
        self.block_hashes.write().insert(height, hash);
    }

    pub fn get_block_hash(&self, height: u64) -> Option<BlockHash> {
        self.block_hashes.read().get(&height).copied()
    }
}

impl Default for MockBitcoinRpc {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock block template for testing
#[derive(Debug, Clone)]
pub struct MockTemplate {
    pub height: u64,
    pub prev_hash: BlockHash,
    pub transactions: Vec<MockTemplateTx>,
    pub coinbase_value: u64,
    pub target: String,
    pub bits: String,
    pub cur_time: u64,
    pub version: i32,
}

impl MockTemplate {
    pub fn new(height: u64) -> Self {
        Self {
            height,
            prev_hash: BlockHash::all_zeros(),
            transactions: Vec::new(),
            coinbase_value: 312_500_000, // 3.125 BTC subsidy
            target: "00000000ffff0000000000000000000000000000000000000000000000000000".to_string(),
            bits: "1d00ffff".to_string(),
            cur_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            version: 0x20000000,
        }
    }

    pub fn with_transactions(mut self, txs: Vec<MockTemplateTx>) -> Self {
        self.transactions = txs;
        self
    }

    pub fn with_prev_hash(mut self, hash: BlockHash) -> Self {
        self.prev_hash = hash;
        self
    }
}

/// Mock transaction in template
#[derive(Debug, Clone)]
pub struct MockTemplateTx {
    pub txid: Txid,
    pub data: Vec<u8>,
    pub fee: u64,
    pub weight: u64,
}

impl MockTemplateTx {
    pub fn new(txid: Txid, fee: u64, weight: u64) -> Self {
        Self {
            txid,
            data: Vec::new(),
            fee,
            weight,
        }
    }
}

/// Mock Stratum miner connection
pub struct MockMiner {
    pub id: String,
    pub addr: SocketAddr,
    pub difficulty: f64,
    pub shares_submitted: AtomicU64,
    pub last_job_id: RwLock<Option<String>>,
}

impl MockMiner {
    pub fn new(id: &str, addr: SocketAddr) -> Self {
        Self {
            id: id.to_string(),
            addr,
            difficulty: 1.0,
            shares_submitted: AtomicU64::new(0),
            last_job_id: RwLock::new(None),
        }
    }

    pub fn submit_share(&self) -> u64 {
        self.shares_submitted.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn get_shares(&self) -> u64 {
        self.shares_submitted.load(Ordering::SeqCst)
    }

    pub fn set_job_id(&self, job_id: String) {
        *self.last_job_id.write() = Some(job_id);
    }

    pub fn get_job_id(&self) -> Option<String> {
        self.last_job_id.read().clone()
    }
}

/// Test node for multi-node consensus tests
pub struct TestNode {
    pub id: [u8; 32],
    pub addr: SocketAddr,
    pub peers: RwLock<Vec<[u8; 32]>>,
    pub votes_sent: RwLock<Vec<TestVote>>,
    pub votes_received: RwLock<Vec<TestVote>>,
}

impl TestNode {
    pub fn new(id: [u8; 32], port: u16) -> Self {
        Self {
            id,
            addr: format!("127.0.0.1:{}", port).parse().unwrap(),
            peers: RwLock::new(Vec::new()),
            votes_sent: RwLock::new(Vec::new()),
            votes_received: RwLock::new(Vec::new()),
        }
    }

    pub fn add_peer(&self, peer_id: [u8; 32]) {
        self.peers.write().push(peer_id);
    }

    pub fn peer_count(&self) -> usize {
        self.peers.read().len()
    }

    pub fn send_vote(&self, vote: TestVote) {
        self.votes_sent.write().push(vote);
    }

    pub fn receive_vote(&self, vote: TestVote) {
        self.votes_received.write().push(vote);
    }

    pub fn votes_sent_count(&self) -> usize {
        self.votes_sent.read().len()
    }

    pub fn votes_received_count(&self) -> usize {
        self.votes_received.read().len()
    }
}

/// Test vote for consensus tests
#[derive(Debug, Clone)]
pub struct TestVote {
    pub proposal_hash: [u8; 32],
    pub voter_id: [u8; 32],
    pub approve: bool,
    pub timestamp: u64,
}

impl TestVote {
    pub fn approve(proposal_hash: [u8; 32], voter_id: [u8; 32]) -> Self {
        Self {
            proposal_hash,
            voter_id,
            approve: true,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    pub fn reject(proposal_hash: [u8; 32], voter_id: [u8; 32]) -> Self {
        Self {
            proposal_hash,
            voter_id,
            approve: false,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

/// Generate random 32-byte ID
pub fn random_id() -> [u8; 32] {
    let mut id = [0u8; 32];
    for byte in &mut id {
        *byte = rand::random();
    }
    id
}

/// Generate sequential node IDs for deterministic testing
pub fn sequential_node_ids(count: usize) -> Vec<[u8; 32]> {
    (0..count)
        .map(|i| {
            let mut id = [0u8; 32];
            id[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            id
        })
        .collect()
}

/// Wait for a condition with timeout
pub async fn wait_for<F>(mut condition: F, timeout_ms: u64, poll_ms: u64) -> bool
where
    F: FnMut() -> bool,
{
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_millis(timeout_ms);
    let poll = std::time::Duration::from_millis(poll_ms);

    while start.elapsed() < timeout {
        if condition() {
            return true;
        }
        tokio::time::sleep(poll).await;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_rpc_height() {
        let rpc = MockBitcoinRpc::new();
        assert_eq!(rpc.get_height(), 800_000);

        rpc.set_height(850_000);
        assert_eq!(rpc.get_height(), 850_000);

        let new_height = rpc.increment_height();
        assert_eq!(new_height, 850_001);
    }

    #[test]
    fn test_mock_miner() {
        let addr = "127.0.0.1:3333".parse().unwrap();
        let miner = MockMiner::new("test_miner", addr);

        assert_eq!(miner.get_shares(), 0);
        miner.submit_share();
        assert_eq!(miner.get_shares(), 1);
        miner.submit_share();
        miner.submit_share();
        assert_eq!(miner.get_shares(), 3);
    }

    #[test]
    fn test_test_node() {
        let id = random_id();
        let node = TestNode::new(id, 8080);

        assert_eq!(node.peer_count(), 0);
        node.add_peer(random_id());
        node.add_peer(random_id());
        assert_eq!(node.peer_count(), 2);
    }

    #[test]
    fn test_sequential_ids() {
        let ids = sequential_node_ids(5);
        assert_eq!(ids.len(), 5);

        // Verify they're different
        for i in 0..4 {
            assert_ne!(ids[i], ids[i + 1]);
        }
    }
}
