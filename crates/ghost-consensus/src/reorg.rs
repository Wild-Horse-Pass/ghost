//! Reorg Detection and Handling for ZK-BFT
//!
//! Handles both L1 (Bitcoin) and L2 (Ghost Pay) reorgs:
//!
//! ## L2 Reorg Scenarios
//! - Network partition: Nodes see different blocks at same height
//! - Proposer equivocation: Same proposer proposes two different blocks
//! - BFT failure: >33% malicious/offline (very rare)
//!
//! ## L1 Reorg Scenarios
//! - Deposit reorged: Rollback pending credit
//! - Reconciliation reorged: Re-broadcast settlement tx
//! - Wraith tx reorged: Abort mixing, refund participants
//!
//! ## Fork Resolution Strategy (P2P-M5)
//!
//! When a fork is detected, the system follows these resolution rules:
//!
//! 1. **Equivocation Detection**: If a proposer signs two different blocks at
//!    the same height, create an `EquivocationProof` and slash/ban the proposer.
//!    The valid chain is determined by BFT voting - the chain that received
//!    67%+ approval is canonical.
//!
//! 2. **Vote-Based Resolution**: For forks without equivocation, the chain
//!    with more BFT approvals wins. The `L2ReorgAction::SwitchChain` action
//!    is emitted when we need to switch to a different chain.
//!
//! 3. **Weight-Based Tiebreaker**: If vote counts are equal (rare in BFT),
//!    prefer the chain proposed by the elder with higher stake/reputation.
//!
//! 4. **Automatic Rollback**: When switching chains, the `handle_reorg` method
//!    in `ZkVoteHandler` automatically:
//!    - Cancels pending proposals above the fork point
//!    - Restores state from the last known-good snapshot
//!    - Emits L2Event::ForkDetected for subscribers
//!
//! ## Integration via ReorgCoordinator (P2P-H7)
//!
//! The `ReorgCoordinator` integrates all components for automatic resolution:
//! - `L2ForkDetector`: Detects forks and equivocation
//! - `ZkVoteHandler`: Tracks BFT vote counts and can rollback state
//! - P2P broadcast: Sends equivocation proofs to the network
//!
//! When auto_resolve is enabled, the coordinator automatically:
//! 1. Listens for fork/equivocation events
//! 2. Determines the resolution action based on BFT vote counts
//! 3. Applies rollback/chain-switch via ZkVoteHandler
//! 4. Broadcasts equivocation proofs for slashing

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::broadcast;
use tracing::{debug, warn};

use ghost_common::types::NodeId;

/// Channel capacity for reorg event broadcasts
const REORG_EVENT_CHANNEL_CAPACITY: usize = 64;

/// Type alias for proposer block tracking (height, proposer) -> (block_hash, signature)
type ProposerBlocks = HashMap<(u64, NodeId), ([u8; 32], [u8; 64])>;

// =============================================================================
// L2 (Ghost Pay) Reorg Handling
// =============================================================================

/// L2 block reference for fork tracking
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct L2BlockRef {
    /// Block height
    pub height: u64,
    /// State root after this block
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub state_root: [u8; 32],
    /// Hash of the block
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub block_hash: [u8; 32],
    /// Proposer node ID
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub proposer: NodeId,
    /// Proposer's signature on the block hash (for equivocation proof)
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
    /// Timestamp when received
    pub timestamp: u64,
}

/// Evidence of a proposer creating two different blocks at same height
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivocationProof {
    /// The proposer who equivocated
    pub proposer: NodeId,
    /// Block height
    pub height: u64,
    /// First block hash
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub block_hash_a: [u8; 32],
    /// Second block hash (different from first)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub block_hash_b: [u8; 32],
    /// Signature on first block
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature_a: [u8; 64],
    /// Signature on second block
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature_b: [u8; 64],
    /// When detected
    pub detected_at: u64,
}

impl EquivocationProof {
    /// Verify this proof is valid (two different blocks, same proposer, same height)
    ///
    /// Validates:
    /// 1. Block hashes are different (actual equivocation)
    /// 2. Both signatures are valid from the same proposer
    pub fn is_valid(&self) -> bool {
        // Must be different blocks
        if self.block_hash_a == self.block_hash_b {
            return false;
        }

        // Verify both signatures are from the proposer
        let sig_a_valid = ghost_common::identity::verify_signature(
            &self.proposer,
            &self.block_hash_a,
            &self.signature_a,
        )
        .unwrap_or(false);
        let sig_b_valid = ghost_common::identity::verify_signature(
            &self.proposer,
            &self.block_hash_b,
            &self.signature_b,
        )
        .unwrap_or(false);

        sig_a_valid && sig_b_valid
    }
}

/// Result of fork detection
#[derive(Debug, Clone)]
pub enum ForkDetectionResult {
    /// No fork, chains agree
    NoFork,
    /// Fork detected at given height
    ForkDetected {
        /// Height where chains diverge
        fork_height: u64,
        /// Our chain tip
        our_tip: L2BlockRef,
        /// Their chain tip
        their_tip: L2BlockRef,
        /// Common ancestor (if found)
        common_ancestor: Option<u64>,
    },
    /// Equivocation detected
    Equivocation(EquivocationProof),
}

/// Tracks L2 chain state for fork detection
pub struct L2ForkDetector {
    /// Our current chain: height -> block ref
    our_chain: RwLock<HashMap<u64, L2BlockRef>>,
    /// Known blocks from peers: (height, block_hash) -> block ref
    peer_blocks: RwLock<HashMap<(u64, [u8; 32]), L2BlockRef>>,
    /// Track proposers by (height, proposer) -> (block_hash, signature) for equivocation detection
    proposer_blocks: RwLock<ProposerBlocks>,
    /// Maximum history to keep
    max_history: u64,
    /// Broadcast sender for L2 events
    event_sender: broadcast::Sender<L2Event>,
}

impl L2ForkDetector {
    /// Create a new fork detector
    pub fn new(max_history: u64) -> Self {
        let (event_sender, _) = broadcast::channel(REORG_EVENT_CHANNEL_CAPACITY);
        Self {
            our_chain: RwLock::new(HashMap::new()),
            peer_blocks: RwLock::new(HashMap::new()),
            proposer_blocks: RwLock::new(HashMap::new()),
            max_history,
            event_sender,
        }
    }

    /// Subscribe to L2 chain events
    pub fn subscribe(&self) -> broadcast::Receiver<L2Event> {
        self.event_sender.subscribe()
    }

    /// Record a block we've accepted to our chain
    pub fn record_our_block(&self, block: L2BlockRef) {
        let height = block.height;
        let state_root = block.state_root;
        let block_hash = block.block_hash;

        // Record in our chain
        self.our_chain.write().insert(height, block.clone());

        // Record for equivocation detection (with signature for proof creation)
        self.proposer_blocks.write().insert(
            (height, block.proposer),
            (block.block_hash, block.signature),
        );

        // Cleanup old history
        self.cleanup_old_blocks(height);

        // Emit new block event
        let _ = self.event_sender.send(L2Event::NewBlock {
            height,
            state_root,
            block_hash,
        });
        debug!(height, "L2 block recorded");
    }

    /// Record a block seen from a peer (may conflict with ours)
    pub fn record_peer_block(&self, block: L2BlockRef) -> Option<EquivocationProof> {
        let height = block.height;
        let proposer = block.proposer;
        let block_hash = block.block_hash;
        let signature = block.signature;

        // Check for equivocation
        let mut proposer_blocks = self.proposer_blocks.write();
        if let Some(&(existing_hash, existing_sig)) = proposer_blocks.get(&(height, proposer)) {
            if existing_hash != block_hash {
                // Equivocation detected!
                warn!(
                    height,
                    proposer = hex::encode(&proposer[..8]),
                    "EQUIVOCATION DETECTED: Proposer signed two different blocks"
                );

                // Emit equivocation event
                let _ = self.event_sender.send(L2Event::EquivocationDetected {
                    proposer,
                    height,
                    block_hash_a: existing_hash,
                    block_hash_b: block_hash,
                });

                // Create proof with actual signatures for cryptographic verification
                return Some(EquivocationProof {
                    proposer,
                    height,
                    block_hash_a: existing_hash,
                    block_hash_b: block_hash,
                    signature_a: existing_sig,
                    signature_b: signature,
                    detected_at: chrono::Utc::now().timestamp_millis() as u64,
                });
            }
        } else {
            proposer_blocks.insert((height, proposer), (block_hash, signature));
        }
        drop(proposer_blocks);

        // Record the block
        self.peer_blocks.write().insert((height, block_hash), block);

        None
    }

    /// Detect if there's a fork between our chain and a peer's reported state
    pub fn detect_fork(
        &self,
        their_height: u64,
        their_state_root: [u8; 32],
    ) -> ForkDetectionResult {
        let our_chain = self.our_chain.read();

        // Check if they have a different state root at the same height
        if let Some(our_block) = our_chain.get(&their_height) {
            if our_block.state_root != their_state_root {
                // Fork detected - find common ancestor
                let common_ancestor = self.find_common_ancestor(&our_chain, their_height);

                warn!(
                    fork_height = their_height,
                    common_ancestor = ?common_ancestor,
                    "L2 FORK DETECTED: Chains diverged"
                );

                // Emit fork detection event
                let _ = self.event_sender.send(L2Event::ForkDetected {
                    fork_height: their_height,
                    our_state_root: our_block.state_root,
                    their_state_root,
                    common_ancestor,
                });

                return ForkDetectionResult::ForkDetected {
                    fork_height: their_height,
                    our_tip: our_block.clone(),
                    their_tip: L2BlockRef {
                        height: their_height,
                        state_root: their_state_root,
                        block_hash: [0u8; 32], // Unknown
                        proposer: [0u8; 32],   // Unknown
                        signature: [0u8; 64],  // Unknown
                        timestamp: 0,
                    },
                    common_ancestor,
                };
            }
        }

        ForkDetectionResult::NoFork
    }

    /// Find the highest height where both chains agree
    fn find_common_ancestor(
        &self,
        our_chain: &HashMap<u64, L2BlockRef>,
        their_height: u64,
    ) -> Option<u64> {
        // Start from the fork height and go backwards
        let peer_blocks = self.peer_blocks.read();

        let mut height = their_height.saturating_sub(1);
        while height > 0 {
            if let Some(our_block) = our_chain.get(&height) {
                // Check if peer has a matching block at this height
                for ((h, _), peer_block) in peer_blocks.iter() {
                    if *h == height && peer_block.state_root == our_block.state_root {
                        return Some(height);
                    }
                }
            }
            height = height.saturating_sub(1);
        }

        None
    }

    /// Get our current chain tip
    pub fn get_tip(&self) -> Option<L2BlockRef> {
        self.our_chain
            .read()
            .iter()
            .max_by_key(|(h, _)| *h)
            .map(|(_, b)| b.clone())
    }

    /// Determine the action to take for a detected fork (P2P-M5)
    ///
    /// This method helps resolve forks by examining the evidence and
    /// recommending an appropriate action. The caller is responsible
    /// for executing the returned action.
    ///
    /// # Arguments
    /// * `fork_result` - The result from `detect_fork()`
    /// * `our_vote_count` - Number of BFT votes for our chain at the fork point
    /// * `their_vote_count` - Number of BFT votes for their chain at the fork point
    ///
    /// # Returns
    /// An `L2ReorgAction` indicating what should be done to resolve the fork
    pub fn determine_resolution(
        &self,
        fork_result: &ForkDetectionResult,
        our_vote_count: u32,
        their_vote_count: u32,
    ) -> L2ReorgAction {
        match fork_result {
            ForkDetectionResult::NoFork => L2ReorgAction::None,

            ForkDetectionResult::Equivocation(proof) => {
                // Equivocation is always slashable, regardless of vote counts
                L2ReorgAction::SlashProposer {
                    proof: proof.clone(),
                }
            }

            ForkDetectionResult::ForkDetected {
                fork_height,
                their_tip,
                common_ancestor,
                ..
            } => {
                // Compare vote counts to determine which chain is canonical
                if their_vote_count > our_vote_count {
                    // They have more votes - we should switch to their chain
                    debug!(
                        fork_height,
                        our_votes = our_vote_count,
                        their_votes = their_vote_count,
                        "Fork resolution: switching to chain with more votes"
                    );

                    L2ReorgAction::SwitchChain {
                        from_height: common_ancestor.unwrap_or(*fork_height - 1),
                        new_blocks: vec![their_tip.clone()], // Would need full chain in practice
                    }
                } else if our_vote_count > their_vote_count {
                    // We have more votes - stay on our chain
                    debug!(
                        fork_height,
                        our_votes = our_vote_count,
                        their_votes = their_vote_count,
                        "Fork resolution: staying on chain with more votes"
                    );
                    L2ReorgAction::None
                } else {
                    // Equal votes - use tiebreaker (lower block hash wins)
                    // This provides deterministic resolution when votes are tied
                    debug!(
                        fork_height,
                        our_votes = our_vote_count,
                        their_votes = their_vote_count,
                        "Fork resolution: equal votes, using hash tiebreaker"
                    );

                    // In a tie, the chain with the lexicographically lower block hash wins
                    // This is deterministic and doesn't favor any particular node
                    if let Some(our_tip) = self.get_tip() {
                        if their_tip.block_hash < our_tip.block_hash {
                            L2ReorgAction::SwitchChain {
                                from_height: common_ancestor.unwrap_or(*fork_height - 1),
                                new_blocks: vec![their_tip.clone()],
                            }
                        } else {
                            L2ReorgAction::None
                        }
                    } else {
                        // No tip, accept their chain
                        L2ReorgAction::SwitchChain {
                            from_height: common_ancestor.unwrap_or(*fork_height - 1),
                            new_blocks: vec![their_tip.clone()],
                        }
                    }
                }
            }
        }
    }

    /// Cleanup old block history
    fn cleanup_old_blocks(&self, current_height: u64) {
        if current_height <= self.max_history {
            return;
        }

        let min_height = current_height - self.max_history;

        self.our_chain.write().retain(|h, _| *h >= min_height);
        self.peer_blocks
            .write()
            .retain(|(h, _), _| *h >= min_height);
        self.proposer_blocks
            .write()
            .retain(|(h, _), _| *h >= min_height);
    }
}

/// Action to take in response to L2 reorg
#[derive(Debug, Clone)]
pub enum L2ReorgAction {
    /// Rollback to a specific height and re-process
    Rollback {
        to_height: u64,
        new_tip_hash: [u8; 32],
    },
    /// Switch to a different chain (received more votes)
    SwitchChain {
        from_height: u64,
        new_blocks: Vec<L2BlockRef>,
    },
    /// Slash proposer for equivocation
    SlashProposer { proof: EquivocationProof },
    /// No action needed
    None,
}

/// L2 chain events emitted by the fork detector
#[derive(Debug, Clone)]
pub enum L2Event {
    /// New L2 block accepted to our chain
    NewBlock {
        height: u64,
        state_root: [u8; 32],
        block_hash: [u8; 32],
    },
    /// Fork detected between our chain and a peer
    ForkDetected {
        fork_height: u64,
        our_state_root: [u8; 32],
        their_state_root: [u8; 32],
        common_ancestor: Option<u64>,
    },
    /// Equivocation detected (proposer double-signed)
    EquivocationDetected {
        proposer: NodeId,
        height: u64,
        block_hash_a: [u8; 32],
        block_hash_b: [u8; 32],
    },
    /// Chain stabilized after a fork resolution
    ChainStabilized {
        height: u64,
        state_root: [u8; 32],
        blocks_since_fork: u32,
    },
}

// =============================================================================
// L1 (Bitcoin) Reorg Handling
// =============================================================================

/// Confirmation status for L1 transactions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L1ConfirmationStatus {
    /// Transaction seen but not confirmed
    Unconfirmed,
    /// Transaction has some confirmations but not enough
    PartiallyConfirmed { confirmations: u32 },
    /// Transaction has enough confirmations
    Confirmed,
    /// Transaction was reorged out
    Reorged,
}

/// L1 confirmation requirements
#[derive(Debug, Clone)]
pub struct L1ConfirmationConfig {
    /// Confirmations required for deposits
    pub deposit_confirmations: u32,
    /// Confirmations required for epoch reconciliation
    pub reconciliation_confirmations: u32,
    /// Confirmations required for Wraith transactions
    pub wraith_confirmations: u32,
}

impl Default for L1ConfirmationConfig {
    fn default() -> Self {
        Self {
            deposit_confirmations: 6,
            reconciliation_confirmations: 6,
            wraith_confirmations: 3,
        }
    }
}

/// Type of L1 transaction we're tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L1TxType {
    /// User deposit to Ghost Pay
    Deposit,
    /// Epoch reconciliation (settlement)
    Reconciliation,
    /// Wraith protocol transaction
    Wraith,
}

/// Pending L1 transaction being tracked
#[derive(Debug, Clone)]
pub struct PendingL1Tx {
    /// Transaction ID
    pub txid: [u8; 32],
    /// Type of transaction
    pub tx_type: L1TxType,
    /// L1 block height where first seen
    pub first_seen_height: u64,
    /// L1 block hash where first seen
    pub first_seen_block: [u8; 32],
    /// Current confirmation count
    pub confirmations: u32,
    /// Associated L2 data (user id, epoch, etc.)
    pub metadata: Vec<u8>,
}

/// Event emitted when L1 state changes
#[derive(Debug, Clone)]
pub enum L1Event {
    /// New L1 block received
    NewBlock { height: u64, hash: [u8; 32] },
    /// L1 reorg detected
    Reorg {
        from_height: u64,
        old_tip: [u8; 32],
        new_tip: [u8; 32],
        depth: u32,
    },
    /// Transaction confirmed
    TxConfirmed {
        txid: [u8; 32],
        tx_type: L1TxType,
        confirmations: u32,
    },
    /// Transaction reorged out
    TxReorged { txid: [u8; 32], tx_type: L1TxType },
}

/// Tracks L1 chain state for reorg detection
pub struct L1ChainMonitor {
    /// Known L1 blocks: height -> block_hash
    blocks: RwLock<HashMap<u64, [u8; 32]>>,
    /// Current tip height
    tip_height: RwLock<u64>,
    /// Pending transactions being tracked
    pending_txs: RwLock<HashMap<[u8; 32], PendingL1Tx>>,
    /// Confirmation config
    config: L1ConfirmationConfig,
    /// Maximum block history to keep
    max_history: u64,
    /// Broadcast sender for L1 events
    event_sender: broadcast::Sender<L1Event>,
}

impl L1ChainMonitor {
    /// Create a new L1 chain monitor
    pub fn new(config: L1ConfirmationConfig) -> Self {
        let (event_sender, _) = broadcast::channel(REORG_EVENT_CHANNEL_CAPACITY);
        Self {
            blocks: RwLock::new(HashMap::new()),
            tip_height: RwLock::new(0),
            pending_txs: RwLock::new(HashMap::new()),
            config,
            max_history: 144, // ~24 hours of Bitcoin blocks
            event_sender,
        }
    }

    /// Subscribe to L1 chain events
    pub fn subscribe(&self) -> broadcast::Receiver<L1Event> {
        self.event_sender.subscribe()
    }

    /// Process a new L1 block
    pub fn process_block(&self, height: u64, hash: [u8; 32]) -> Vec<L1Event> {
        let mut events = Vec::new();
        let current_tip = *self.tip_height.read();

        // Check for reorg
        if height <= current_tip {
            // This is a potential reorg - block at existing height
            if let Some(&existing_hash) = self.blocks.read().get(&height) {
                if existing_hash != hash {
                    // Reorg detected!
                    let depth = (current_tip - height + 1) as u32;

                    warn!(
                        from_height = height,
                        depth,
                        old_tip = hex::encode(&existing_hash[..8]),
                        new_tip = hex::encode(&hash[..8]),
                        "L1 REORG DETECTED: Bitcoin chain reorganized"
                    );

                    events.push(L1Event::Reorg {
                        from_height: height,
                        old_tip: existing_hash,
                        new_tip: hash,
                        depth,
                    });

                    // Handle reorged transactions
                    self.handle_reorg(height, &mut events);
                }
            }
        }

        // Update block tracking
        {
            let mut blocks = self.blocks.write();
            blocks.insert(height, hash);

            // Cleanup old blocks
            if height > self.max_history {
                let min_height = height - self.max_history;
                blocks.retain(|h, _| *h >= min_height);
            }
        }

        // Update tip
        if height > current_tip {
            *self.tip_height.write() = height;
        }

        // Update confirmations for pending txs
        self.update_confirmations(height, &mut events);

        events.push(L1Event::NewBlock { height, hash });

        // Broadcast all events to subscribers
        for event in &events {
            let _ = self.event_sender.send(event.clone());
        }

        events
    }

    /// Handle reorg by checking for affected transactions
    fn handle_reorg(&self, reorg_height: u64, events: &mut Vec<L1Event>) {
        let mut pending = self.pending_txs.write();

        for (txid, tx) in pending.iter_mut() {
            if tx.first_seen_height >= reorg_height {
                // This transaction might have been reorged out
                events.push(L1Event::TxReorged {
                    txid: *txid,
                    tx_type: tx.tx_type,
                });
                // Reset confirmations - tx needs to be re-seen
                tx.confirmations = 0;
            } else if tx.first_seen_height + tx.confirmations as u64 >= reorg_height {
                // Transaction still valid but lost some confirmations
                tx.confirmations = (reorg_height - tx.first_seen_height) as u32;
            }
        }
    }

    /// Update confirmation counts for pending transactions
    fn update_confirmations(&self, current_height: u64, events: &mut Vec<L1Event>) {
        let mut pending = self.pending_txs.write();

        for (txid, tx) in pending.iter_mut() {
            if tx.first_seen_height <= current_height {
                let new_confirmations = (current_height - tx.first_seen_height + 1) as u32;

                if new_confirmations > tx.confirmations {
                    tx.confirmations = new_confirmations;

                    // Check if confirmed
                    let required = match tx.tx_type {
                        L1TxType::Deposit => self.config.deposit_confirmations,
                        L1TxType::Reconciliation => self.config.reconciliation_confirmations,
                        L1TxType::Wraith => self.config.wraith_confirmations,
                    };

                    if tx.confirmations >= required {
                        events.push(L1Event::TxConfirmed {
                            txid: *txid,
                            tx_type: tx.tx_type,
                            confirmations: tx.confirmations,
                        });
                    }
                }
            }
        }
    }

    /// Add a transaction to track
    pub fn track_tx(&self, tx: PendingL1Tx) {
        self.pending_txs.write().insert(tx.txid, tx);
    }

    /// Stop tracking a transaction
    pub fn untrack_tx(&self, txid: &[u8; 32]) {
        self.pending_txs.write().remove(txid);
    }

    /// Get confirmation status for a transaction
    pub fn get_tx_status(&self, txid: &[u8; 32]) -> L1ConfirmationStatus {
        let pending = self.pending_txs.read();
        match pending.get(txid) {
            None => L1ConfirmationStatus::Unconfirmed,
            Some(tx) => {
                let required = match tx.tx_type {
                    L1TxType::Deposit => self.config.deposit_confirmations,
                    L1TxType::Reconciliation => self.config.reconciliation_confirmations,
                    L1TxType::Wraith => self.config.wraith_confirmations,
                };

                if tx.confirmations >= required {
                    L1ConfirmationStatus::Confirmed
                } else if tx.confirmations > 0 {
                    L1ConfirmationStatus::PartiallyConfirmed {
                        confirmations: tx.confirmations,
                    }
                } else {
                    L1ConfirmationStatus::Unconfirmed
                }
            }
        }
    }

    /// Get current tip height
    pub fn tip_height(&self) -> u64 {
        *self.tip_height.read()
    }

    /// Get count of pending transactions
    pub fn pending_count(&self) -> usize {
        self.pending_txs.read().len()
    }
}

// =============================================================================
// Reorg Coordinator - Integrates Fork Detection with ZK Vote Handler (P2P-H7)
// =============================================================================

use crate::message::{EquivocationProofMessage, MessageType};
use crate::zk_vote_handler::ZkVoteHandler;
use ghost_common::error::GhostResult;
use ghost_common::identity::NodeIdentity;
use std::sync::Arc;

/// Callback for broadcasting equivocation proofs to the network
pub type EquivocationBroadcastFn =
    Arc<dyn Fn(MessageType, Vec<u8>) -> GhostResult<()> + Send + Sync>;

/// Callback for getting BFT vote counts for a chain at a specific height
/// Returns (our_vote_count, their_vote_count) for fork resolution
pub type VoteCountFn = Arc<dyn Fn(u64, [u8; 32], [u8; 32]) -> (u32, u32) + Send + Sync>;

/// Callback for loading snapshot state root from storage
/// Returns the state root at the target height, or None if not found
pub type SnapshotLoaderFn = Arc<dyn Fn(u64) -> Option<[u8; 32]> + Send + Sync>;

/// Configuration for the reorg coordinator
#[derive(Debug, Clone)]
pub struct ReorgCoordinatorConfig {
    /// Minimum votes required to consider fork resolution (prevents resolution on sparse data)
    pub min_votes_for_resolution: u32,
    /// Whether to automatically apply resolution actions
    pub auto_resolve: bool,
    /// Default snapshot interval (blocks between snapshots)
    pub snapshot_interval: u64,
}

impl Default for ReorgCoordinatorConfig {
    fn default() -> Self {
        Self {
            min_votes_for_resolution: 2,
            auto_resolve: true,
            snapshot_interval: 100,
        }
    }
}

/// Result of a reorg coordination action
#[derive(Debug, Clone)]
pub enum ReorgResult {
    /// No action needed
    NoAction,
    /// Successfully rolled back to target height
    RolledBack {
        from_height: u64,
        to_height: u64,
        new_state_root: [u8; 32],
    },
    /// Switched to a different chain
    ChainSwitched {
        from_height: u64,
        new_tip_height: u64,
        new_state_root: [u8; 32],
    },
    /// Equivocation proof broadcast
    EquivocationBroadcast { proposer: NodeId, height: u64 },
    /// Resolution deferred (insufficient data or auto_resolve disabled)
    Deferred { reason: String },
    /// Error during resolution
    Error { reason: String },
}

/// Coordinates reorg detection, resolution, and state rollback (P2P-H7)
///
/// This is the integration point between:
/// - `L2ForkDetector`: Detects forks and equivocation
/// - `ZkVoteHandler`: Manages L2 state and can rollback
/// - P2P network: Broadcasts equivocation proofs
///
/// # Usage
///
/// ```ignore
/// let coordinator = ReorgCoordinator::new(
///     identity,
///     fork_detector,
///     zk_vote_handler,
///     ReorgCoordinatorConfig::default(),
/// );
///
/// // Set callbacks
/// coordinator.set_vote_count_fn(vote_fn);
/// coordinator.set_snapshot_loader(loader_fn);
/// coordinator.set_broadcast_fn(broadcast_fn);
///
/// // Start the event listener
/// coordinator.start().await;
/// ```
pub struct ReorgCoordinator {
    /// Our node identity (for signing equivocation proofs)
    identity: Arc<NodeIdentity>,
    /// Fork detector for tracking chain state
    fork_detector: Arc<L2ForkDetector>,
    /// ZK vote handler for state management and rollback
    zk_vote_handler: Arc<ZkVoteHandler>,
    /// Configuration
    config: ReorgCoordinatorConfig,
    /// Broadcast function for equivocation proofs
    broadcast_fn: parking_lot::RwLock<Option<EquivocationBroadcastFn>>,
    /// Function to get vote counts for fork resolution
    vote_count_fn: parking_lot::RwLock<Option<VoteCountFn>>,
    /// Function to load snapshot state root
    snapshot_loader: parking_lot::RwLock<Option<SnapshotLoaderFn>>,
}

impl ReorgCoordinator {
    /// Create a new reorg coordinator
    pub fn new(
        identity: Arc<NodeIdentity>,
        fork_detector: Arc<L2ForkDetector>,
        zk_vote_handler: Arc<ZkVoteHandler>,
        config: ReorgCoordinatorConfig,
    ) -> Self {
        Self {
            identity,
            fork_detector,
            zk_vote_handler,
            config,
            broadcast_fn: parking_lot::RwLock::new(None),
            vote_count_fn: parking_lot::RwLock::new(None),
            snapshot_loader: parking_lot::RwLock::new(None),
        }
    }

    /// Set the broadcast function for equivocation proofs
    pub fn set_broadcast_fn(&self, f: EquivocationBroadcastFn) {
        *self.broadcast_fn.write() = Some(f);
    }

    /// Set the vote count function for fork resolution
    pub fn set_vote_count_fn(&self, f: VoteCountFn) {
        *self.vote_count_fn.write() = Some(f);
    }

    /// Set the snapshot loader function
    pub fn set_snapshot_loader(&self, f: SnapshotLoaderFn) {
        *self.snapshot_loader.write() = Some(f);
    }

    /// Start the coordinator event listener
    ///
    /// This spawns a background task that listens for L2 events and
    /// automatically handles fork resolution when configured.
    pub fn start(self: Arc<Self>) {
        let coordinator = Arc::clone(&self);
        let mut rx = self.fork_detector.subscribe();

        tokio::spawn(async move {
            tracing::info!("ReorgCoordinator: Started event listener");

            loop {
                match rx.recv().await {
                    Ok(event) => {
                        if let Err(e) = coordinator.handle_l2_event(event).await {
                            tracing::error!(error = %e, "ReorgCoordinator: Error handling event");
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(skipped = n, "ReorgCoordinator: Events lagged");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        tracing::info!("ReorgCoordinator: Event channel closed");
                        break;
                    }
                }
            }
        });
    }

    /// Handle an L2 chain event
    async fn handle_l2_event(&self, event: L2Event) -> GhostResult<()> {
        match event {
            L2Event::ForkDetected {
                fork_height,
                our_state_root,
                their_state_root,
                common_ancestor,
            } => {
                tracing::warn!(
                    fork_height,
                    common_ancestor = ?common_ancestor,
                    "ReorgCoordinator: Fork detected, determining resolution"
                );

                // Get vote counts if we have the function
                let (our_votes, their_votes) = if let Some(ref vote_fn) = *self.vote_count_fn.read()
                {
                    vote_fn(fork_height, our_state_root, their_state_root)
                } else {
                    // No vote count function - defer resolution
                    tracing::debug!("ReorgCoordinator: No vote count function, deferring");
                    return Ok(());
                };

                // Detect fork result for resolution
                let fork_result = self
                    .fork_detector
                    .detect_fork(fork_height, their_state_root);

                // Determine and apply resolution
                let result = self.resolve_fork(&fork_result, our_votes, their_votes)?;

                tracing::info!(
                    fork_height,
                    result = ?result,
                    "ReorgCoordinator: Fork resolution complete"
                );
            }

            L2Event::EquivocationDetected {
                proposer,
                height,
                block_hash_a,
                block_hash_b,
            } => {
                tracing::error!(
                    height,
                    proposer = hex::encode(&proposer[..8]),
                    "ReorgCoordinator: Equivocation detected, creating proof"
                );

                // Get the signatures for the proof from the fork detector
                // The proof should have been created when the peer block was recorded
                // Here we just broadcast it if we have the broadcast function
                if let Some(ref broadcast) = *self.broadcast_fn.read() {
                    let proof_msg = EquivocationProofMessage {
                        equivocator: proposer,
                        round_id: height,
                        vote_type: "block_proposal".to_string(),
                        vote1_data: block_hash_a.to_vec(),
                        vote2_data: block_hash_b.to_vec(),
                        reporter: self.identity.node_id(),
                        reporter_signature: self.identity.sign(&self.create_proof_signing_message(
                            &proposer,
                            height,
                            &block_hash_a,
                            &block_hash_b,
                        )),
                        timestamp: chrono::Utc::now().timestamp_millis() as u64,
                    };

                    let payload = serde_json::to_vec(&proof_msg).map_err(|e| {
                        ghost_common::error::GhostError::Serialization(e.to_string())
                    })?;

                    broadcast(MessageType::EquivocationProof, payload)?;

                    tracing::info!(
                        proposer = hex::encode(&proposer[..8]),
                        height,
                        "ReorgCoordinator: Equivocation proof broadcast"
                    );
                }

                // Remove the equivocator from validators
                self.zk_vote_handler.remove_validator(&proposer);
            }

            L2Event::NewBlock { height, .. } => {
                // Track if we should create a snapshot
                if self
                    .zk_vote_handler
                    .should_create_snapshot(height, self.config.snapshot_interval)
                {
                    tracing::debug!(height, "ReorgCoordinator: Snapshot point reached");
                    // Note: Actual snapshot creation is done by the caller
                    // We just provide the trigger point
                }
            }

            L2Event::ChainStabilized { height, .. } => {
                tracing::info!(height, "ReorgCoordinator: Chain stabilized");
            }
        }

        Ok(())
    }

    /// Create the message to sign for an equivocation proof report
    fn create_proof_signing_message(
        &self,
        equivocator: &NodeId,
        height: u64,
        block_hash_a: &[u8; 32],
        block_hash_b: &[u8; 32],
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(32 + 8 + 32 + 32);
        msg.extend_from_slice(equivocator);
        msg.extend_from_slice(&height.to_le_bytes());
        msg.extend_from_slice(block_hash_a);
        msg.extend_from_slice(block_hash_b);
        msg
    }

    /// Resolve a detected fork by determining and applying the appropriate action
    pub fn resolve_fork(
        &self,
        fork_result: &ForkDetectionResult,
        our_vote_count: u32,
        their_vote_count: u32,
    ) -> GhostResult<ReorgResult> {
        // Check minimum votes
        if our_vote_count + their_vote_count < self.config.min_votes_for_resolution {
            return Ok(ReorgResult::Deferred {
                reason: format!(
                    "Insufficient votes: {} < {}",
                    our_vote_count + their_vote_count,
                    self.config.min_votes_for_resolution
                ),
            });
        }

        // Determine the action
        let action =
            self.fork_detector
                .determine_resolution(fork_result, our_vote_count, their_vote_count);

        // Apply if auto_resolve is enabled
        if !self.config.auto_resolve {
            return Ok(ReorgResult::Deferred {
                reason: "Auto-resolve disabled".to_string(),
            });
        }

        self.apply_reorg_action(action)
    }

    /// Apply a reorg action to the ZK vote handler
    pub fn apply_reorg_action(&self, action: L2ReorgAction) -> GhostResult<ReorgResult> {
        match action {
            L2ReorgAction::None => Ok(ReorgResult::NoAction),

            L2ReorgAction::Rollback {
                to_height,
                new_tip_hash,
            } => {
                // Load the snapshot state root for the target height
                let snapshot_root = if let Some(ref loader) = *self.snapshot_loader.read() {
                    loader(to_height)
                } else {
                    None
                };

                let state_root = snapshot_root.unwrap_or(new_tip_hash);

                let (current_height, _) = self.zk_vote_handler.get_state();

                // Apply the rollback
                self.zk_vote_handler.handle_reorg(to_height, state_root)?;

                tracing::info!(
                    from_height = current_height,
                    to_height,
                    state_root = hex::encode(state_root),
                    "ReorgCoordinator: Applied rollback"
                );

                Ok(ReorgResult::RolledBack {
                    from_height: current_height,
                    to_height,
                    new_state_root: state_root,
                })
            }

            L2ReorgAction::SwitchChain {
                from_height,
                new_blocks,
            } => {
                if new_blocks.is_empty() {
                    return Ok(ReorgResult::Error {
                        reason: "No blocks to switch to".to_string(),
                    });
                }

                // Get the new tip
                let new_tip = new_blocks.last().expect("checked non-empty");

                // Load snapshot for the fork point
                let snapshot_root = if let Some(ref loader) = *self.snapshot_loader.read() {
                    loader(from_height)
                } else {
                    None
                };

                // Rollback to the fork point
                let rollback_root = snapshot_root.unwrap_or(new_tip.state_root);
                self.zk_vote_handler
                    .handle_reorg(from_height, rollback_root)?;

                // Apply the new blocks by setting state to the new tip
                // In a full implementation, we would replay each block
                self.zk_vote_handler
                    .set_state(new_tip.height, new_tip.state_root);

                // Record the new blocks in the fork detector
                for block in &new_blocks {
                    self.fork_detector.record_our_block(block.clone());
                }

                tracing::info!(
                    from_height,
                    new_tip_height = new_tip.height,
                    state_root = hex::encode(new_tip.state_root),
                    "ReorgCoordinator: Switched chain"
                );

                Ok(ReorgResult::ChainSwitched {
                    from_height,
                    new_tip_height: new_tip.height,
                    new_state_root: new_tip.state_root,
                })
            }

            L2ReorgAction::SlashProposer { proof } => {
                // Broadcast the equivocation proof
                if let Some(ref broadcast) = *self.broadcast_fn.read() {
                    let proof_msg = EquivocationProofMessage {
                        equivocator: proof.proposer,
                        round_id: proof.height,
                        vote_type: "block_proposal".to_string(),
                        vote1_data: proof.block_hash_a.to_vec(),
                        vote2_data: proof.block_hash_b.to_vec(),
                        reporter: self.identity.node_id(),
                        reporter_signature: self.identity.sign(&self.create_proof_signing_message(
                            &proof.proposer,
                            proof.height,
                            &proof.block_hash_a,
                            &proof.block_hash_b,
                        )),
                        timestamp: chrono::Utc::now().timestamp_millis() as u64,
                    };

                    let payload = serde_json::to_vec(&proof_msg).map_err(|e| {
                        ghost_common::error::GhostError::Serialization(e.to_string())
                    })?;

                    broadcast(MessageType::EquivocationProof, payload)?;
                }

                // Remove the proposer from validators
                self.zk_vote_handler.remove_validator(&proof.proposer);

                tracing::warn!(
                    proposer = hex::encode(&proof.proposer[..8]),
                    height = proof.height,
                    "ReorgCoordinator: Slashed proposer for equivocation"
                );

                Ok(ReorgResult::EquivocationBroadcast {
                    proposer: proof.proposer,
                    height: proof.height,
                })
            }
        }
    }

    /// Get the current L2 state from the ZK vote handler
    pub fn get_state(&self) -> (u64, [u8; 32]) {
        self.zk_vote_handler.get_state()
    }

    /// Get the fork detector for direct access
    pub fn fork_detector(&self) -> &Arc<L2ForkDetector> {
        &self.fork_detector
    }

    /// Get the ZK vote handler for direct access
    pub fn zk_vote_handler(&self) -> &Arc<ZkVoteHandler> {
        &self.zk_vote_handler
    }
}

/// User balance with pending amounts
#[derive(Debug, Clone, Default)]
pub struct UserBalance {
    /// Confirmed balance (final, can spend)
    pub confirmed: u64,
    /// Pending credits (awaiting L1 confirmations)
    pub pending_credits: u64,
    /// Pending debits (withdrawals not yet settled)
    pub pending_debits: u64,
}

impl UserBalance {
    /// Get the spendable balance
    pub fn spendable(&self) -> u64 {
        self.confirmed.saturating_sub(self.pending_debits)
    }

    /// Get the total balance (including pending)
    pub fn total(&self) -> u64 {
        self.confirmed
            .saturating_add(self.pending_credits)
            .saturating_sub(self.pending_debits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_l2_fork_detector_creation() {
        let detector = L2ForkDetector::new(100);
        assert!(detector.get_tip().is_none());
    }

    #[test]
    fn test_l2_block_recording() {
        let detector = L2ForkDetector::new(100);

        let block = L2BlockRef {
            height: 1,
            state_root: [1u8; 32],
            block_hash: [2u8; 32],
            proposer: [3u8; 32],
            signature: [0u8; 64],
            timestamp: 1000,
        };

        detector.record_our_block(block.clone());

        let tip = detector.get_tip().unwrap();
        assert_eq!(tip.height, 1);
        assert_eq!(tip.state_root, [1u8; 32]);
    }

    #[test]
    fn test_equivocation_detection() {
        use ghost_common::identity::NodeIdentity;

        let detector = L2ForkDetector::new(100);

        // Create a real identity for valid signatures
        let identity = NodeIdentity::generate();
        let proposer = identity.node_id();

        // Create and sign first block hash
        let block_hash_1 = [3u8; 32];
        let signature_1 = identity.sign(&block_hash_1);

        // First block
        let block1 = L2BlockRef {
            height: 10,
            state_root: [2u8; 32],
            block_hash: block_hash_1,
            proposer,
            signature: signature_1,
            timestamp: 1000,
        };
        detector.record_our_block(block1);

        // Create and sign second (different) block hash
        let block_hash_2 = [5u8; 32];
        let signature_2 = identity.sign(&block_hash_2);

        // Same proposer, same height, different block hash = equivocation
        let block2 = L2BlockRef {
            height: 10,
            state_root: [4u8; 32],
            block_hash: block_hash_2,
            proposer,
            signature: signature_2,
            timestamp: 1001,
        };

        let result = detector.record_peer_block(block2);
        assert!(result.is_some());

        let proof = result.unwrap();
        assert_eq!(proof.proposer, proposer);
        assert_eq!(proof.height, 10);
        // With real signatures, is_valid() should now pass
        assert!(proof.is_valid());
    }

    #[test]
    fn test_fork_detection() {
        let detector = L2ForkDetector::new(100);

        // Record our chain
        detector.record_our_block(L2BlockRef {
            height: 10,
            state_root: [1u8; 32],
            block_hash: [2u8; 32],
            proposer: [3u8; 32],
            signature: [0u8; 64],
            timestamp: 1000,
        });

        // Peer has different state root at same height
        let result = detector.detect_fork(10, [9u8; 32]);

        match result {
            ForkDetectionResult::ForkDetected { fork_height, .. } => {
                assert_eq!(fork_height, 10);
            }
            _ => panic!("Expected fork to be detected"),
        }
    }

    #[test]
    fn test_l1_chain_monitor_creation() {
        let monitor = L1ChainMonitor::new(L1ConfirmationConfig::default());
        assert_eq!(monitor.tip_height(), 0);
        assert_eq!(monitor.pending_count(), 0);
    }

    #[test]
    fn test_l1_block_processing() {
        let monitor = L1ChainMonitor::new(L1ConfirmationConfig::default());

        let events = monitor.process_block(100, [1u8; 32]);

        assert_eq!(monitor.tip_height(), 100);
        assert!(events
            .iter()
            .any(|e| matches!(e, L1Event::NewBlock { height: 100, .. })));
    }

    #[test]
    fn test_l1_reorg_detection() {
        let monitor = L1ChainMonitor::new(L1ConfirmationConfig::default());

        // Process some blocks
        monitor.process_block(100, [1u8; 32]);
        monitor.process_block(101, [2u8; 32]);
        monitor.process_block(102, [3u8; 32]);

        // Reorg: different hash at height 101
        let events = monitor.process_block(101, [9u8; 32]);

        assert!(events.iter().any(|e| matches!(
            e,
            L1Event::Reorg {
                from_height: 101,
                ..
            }
        )));
    }

    #[test]
    fn test_l1_tx_tracking() {
        let monitor = L1ChainMonitor::new(L1ConfirmationConfig::default());

        // Track a deposit
        let tx = PendingL1Tx {
            txid: [1u8; 32],
            tx_type: L1TxType::Deposit,
            first_seen_height: 100,
            first_seen_block: [2u8; 32],
            confirmations: 1,
            metadata: vec![],
        };

        monitor.track_tx(tx);

        // Initial status - partially confirmed
        let status = monitor.get_tx_status(&[1u8; 32]);
        assert!(matches!(
            status,
            L1ConfirmationStatus::PartiallyConfirmed { confirmations: 1 }
        ));

        // Process more blocks
        for height in 101..106 {
            monitor.process_block(height, [height as u8; 32]);
        }

        // Now should be confirmed (6 confirmations)
        let status = monitor.get_tx_status(&[1u8; 32]);
        assert!(matches!(status, L1ConfirmationStatus::Confirmed));
    }

    #[test]
    fn test_user_balance() {
        let balance = UserBalance {
            confirmed: 1000,
            pending_credits: 500,
            pending_debits: 200,
        };

        assert_eq!(balance.spendable(), 800); // 1000 - 200
        assert_eq!(balance.total(), 1300); // 1000 + 500 - 200
    }

    #[test]
    fn test_fork_resolution_more_votes_wins() {
        let detector = L2ForkDetector::new(100);

        // Record our chain
        detector.record_our_block(L2BlockRef {
            height: 10,
            state_root: [1u8; 32],
            block_hash: [2u8; 32],
            proposer: [3u8; 32],
            signature: [0u8; 64],
            timestamp: 1000,
        });

        // Detect fork
        let fork_result = detector.detect_fork(10, [9u8; 32]);

        // They have more votes - should switch
        let action = detector.determine_resolution(&fork_result, 3, 5);
        assert!(matches!(action, L2ReorgAction::SwitchChain { .. }));

        // We have more votes - should stay
        let action = detector.determine_resolution(&fork_result, 5, 3);
        assert!(matches!(action, L2ReorgAction::None));
    }

    #[test]
    fn test_fork_resolution_no_fork() {
        let detector = L2ForkDetector::new(100);

        let action = detector.determine_resolution(&ForkDetectionResult::NoFork, 5, 5);
        assert!(matches!(action, L2ReorgAction::None));
    }

    #[test]
    fn test_fork_resolution_equivocation() {
        use ghost_common::identity::NodeIdentity;

        let detector = L2ForkDetector::new(100);
        let identity = NodeIdentity::generate();
        let proposer = identity.node_id();

        let proof = EquivocationProof {
            proposer,
            height: 10,
            block_hash_a: [1u8; 32],
            block_hash_b: [2u8; 32],
            signature_a: identity.sign(&[1u8; 32]),
            signature_b: identity.sign(&[2u8; 32]),
            detected_at: 1000,
        };

        let fork_result = ForkDetectionResult::Equivocation(proof);

        // Equivocation always results in slash, regardless of votes
        let action = detector.determine_resolution(&fork_result, 5, 3);
        assert!(matches!(action, L2ReorgAction::SlashProposer { .. }));
    }

    // ==========================================================================
    // ReorgCoordinator Tests (P2P-H7)
    // ==========================================================================

    #[test]
    fn test_reorg_coordinator_creation() {
        use crate::zk_vote_handler::ZkVoteHandler;
        use ghost_common::identity::NodeIdentity;

        let identity = Arc::new(NodeIdentity::generate());
        let detector = Arc::new(L2ForkDetector::new(100));
        let zk_handler = Arc::new(ZkVoteHandler::new(Arc::clone(&identity)));

        let coordinator = ReorgCoordinator::new(
            identity,
            detector,
            zk_handler,
            ReorgCoordinatorConfig::default(),
        );

        assert_eq!(coordinator.get_state(), (0, [0u8; 32]));
    }

    #[test]
    fn test_reorg_coordinator_rollback() {
        use crate::zk_vote_handler::ZkVoteHandler;
        use ghost_common::identity::NodeIdentity;

        let identity = Arc::new(NodeIdentity::generate());
        let detector = Arc::new(L2ForkDetector::new(100));
        let zk_handler = Arc::new(ZkVoteHandler::new(Arc::clone(&identity)));

        // Set initial state at height 100
        zk_handler.set_state(100, [1u8; 32]);

        let coordinator = ReorgCoordinator::new(
            identity,
            detector,
            Arc::clone(&zk_handler),
            ReorgCoordinatorConfig::default(),
        );

        // Apply rollback action
        let action = L2ReorgAction::Rollback {
            to_height: 90,
            new_tip_hash: [2u8; 32],
        };

        let result = coordinator.apply_reorg_action(action).unwrap();

        match result {
            ReorgResult::RolledBack {
                from_height,
                to_height,
                new_state_root,
            } => {
                assert_eq!(from_height, 100);
                assert_eq!(to_height, 90);
                assert_eq!(new_state_root, [2u8; 32]);
            }
            _ => panic!("Expected RolledBack result"),
        }

        // Verify state was updated
        assert_eq!(zk_handler.get_state(), (90, [2u8; 32]));
    }

    #[test]
    fn test_reorg_coordinator_chain_switch() {
        use crate::zk_vote_handler::ZkVoteHandler;
        use ghost_common::identity::NodeIdentity;

        let identity = Arc::new(NodeIdentity::generate());
        let detector = Arc::new(L2ForkDetector::new(100));
        let zk_handler = Arc::new(ZkVoteHandler::new(Arc::clone(&identity)));

        // Set initial state
        zk_handler.set_state(100, [1u8; 32]);

        let coordinator = ReorgCoordinator::new(
            identity,
            Arc::clone(&detector),
            Arc::clone(&zk_handler),
            ReorgCoordinatorConfig::default(),
        );

        // Create new blocks for the chain switch
        let new_blocks = vec![
            L2BlockRef {
                height: 95,
                state_root: [10u8; 32],
                block_hash: [11u8; 32],
                proposer: [12u8; 32],
                signature: [0u8; 64],
                timestamp: 1000,
            },
            L2BlockRef {
                height: 96,
                state_root: [20u8; 32],
                block_hash: [21u8; 32],
                proposer: [22u8; 32],
                signature: [0u8; 64],
                timestamp: 1001,
            },
        ];

        let action = L2ReorgAction::SwitchChain {
            from_height: 94,
            new_blocks,
        };

        let result = coordinator.apply_reorg_action(action).unwrap();

        match result {
            ReorgResult::ChainSwitched {
                from_height,
                new_tip_height,
                new_state_root,
            } => {
                assert_eq!(from_height, 94);
                assert_eq!(new_tip_height, 96);
                assert_eq!(new_state_root, [20u8; 32]);
            }
            _ => panic!("Expected ChainSwitched result"),
        }

        // Verify state was updated to new chain tip
        assert_eq!(zk_handler.get_state(), (96, [20u8; 32]));
    }

    #[test]
    fn test_reorg_coordinator_no_action() {
        use crate::zk_vote_handler::ZkVoteHandler;
        use ghost_common::identity::NodeIdentity;

        let identity = Arc::new(NodeIdentity::generate());
        let detector = Arc::new(L2ForkDetector::new(100));
        let zk_handler = Arc::new(ZkVoteHandler::new(Arc::clone(&identity)));

        zk_handler.set_state(100, [1u8; 32]);

        let coordinator = ReorgCoordinator::new(
            identity,
            detector,
            Arc::clone(&zk_handler),
            ReorgCoordinatorConfig::default(),
        );

        let result = coordinator.apply_reorg_action(L2ReorgAction::None).unwrap();
        assert!(matches!(result, ReorgResult::NoAction));

        // State should be unchanged
        assert_eq!(zk_handler.get_state(), (100, [1u8; 32]));
    }

    #[test]
    fn test_reorg_coordinator_resolve_fork_deferred_insufficient_votes() {
        use crate::zk_vote_handler::ZkVoteHandler;
        use ghost_common::identity::NodeIdentity;

        let identity = Arc::new(NodeIdentity::generate());
        let detector = Arc::new(L2ForkDetector::new(100));
        let zk_handler = Arc::new(ZkVoteHandler::new(Arc::clone(&identity)));

        // Record our chain
        detector.record_our_block(L2BlockRef {
            height: 10,
            state_root: [1u8; 32],
            block_hash: [2u8; 32],
            proposer: [3u8; 32],
            signature: [0u8; 64],
            timestamp: 1000,
        });

        let coordinator = ReorgCoordinator::new(
            identity,
            Arc::clone(&detector),
            zk_handler,
            ReorgCoordinatorConfig {
                min_votes_for_resolution: 5,
                ..Default::default()
            },
        );

        // Detect fork
        let fork_result = detector.detect_fork(10, [9u8; 32]);

        // Insufficient votes (1 + 1 = 2 < 5)
        let result = coordinator.resolve_fork(&fork_result, 1, 1).unwrap();

        match result {
            ReorgResult::Deferred { reason } => {
                assert!(reason.contains("Insufficient votes"));
            }
            _ => panic!("Expected Deferred result"),
        }
    }

    #[test]
    fn test_reorg_coordinator_resolve_fork_deferred_auto_resolve_disabled() {
        use crate::zk_vote_handler::ZkVoteHandler;
        use ghost_common::identity::NodeIdentity;

        let identity = Arc::new(NodeIdentity::generate());
        let detector = Arc::new(L2ForkDetector::new(100));
        let zk_handler = Arc::new(ZkVoteHandler::new(Arc::clone(&identity)));

        // Record our chain
        detector.record_our_block(L2BlockRef {
            height: 10,
            state_root: [1u8; 32],
            block_hash: [2u8; 32],
            proposer: [3u8; 32],
            signature: [0u8; 64],
            timestamp: 1000,
        });

        let coordinator = ReorgCoordinator::new(
            identity,
            Arc::clone(&detector),
            zk_handler,
            ReorgCoordinatorConfig {
                auto_resolve: false,
                ..Default::default()
            },
        );

        // Detect fork
        let fork_result = detector.detect_fork(10, [9u8; 32]);

        // Should defer because auto_resolve is disabled
        let result = coordinator.resolve_fork(&fork_result, 5, 3).unwrap();

        match result {
            ReorgResult::Deferred { reason } => {
                assert!(reason.contains("Auto-resolve disabled"));
            }
            _ => panic!("Expected Deferred result"),
        }
    }

    #[test]
    fn test_reorg_coordinator_slash_proposer() {
        use crate::zk_vote_handler::ZkVoteHandler;
        use ghost_common::identity::NodeIdentity;
        use std::sync::atomic::{AtomicBool, Ordering};

        let identity = Arc::new(NodeIdentity::generate());
        let equivocator = NodeIdentity::generate();
        let detector = Arc::new(L2ForkDetector::new(100));
        let zk_handler = Arc::new(ZkVoteHandler::new(Arc::clone(&identity)));

        // Add equivocator as a validator
        zk_handler.add_validator(equivocator.node_id());
        assert_eq!(zk_handler.validator_count(), 1);

        let coordinator = ReorgCoordinator::new(
            identity,
            detector,
            Arc::clone(&zk_handler),
            ReorgCoordinatorConfig::default(),
        );

        // Track if broadcast was called
        let broadcast_called = Arc::new(AtomicBool::new(false));
        let broadcast_called_clone = Arc::clone(&broadcast_called);

        coordinator.set_broadcast_fn(Arc::new(move |_msg_type, _payload| {
            broadcast_called_clone.store(true, Ordering::SeqCst);
            Ok(())
        }));

        // Create equivocation proof
        let proof = EquivocationProof {
            proposer: equivocator.node_id(),
            height: 10,
            block_hash_a: [1u8; 32],
            block_hash_b: [2u8; 32],
            signature_a: equivocator.sign(&[1u8; 32]),
            signature_b: equivocator.sign(&[2u8; 32]),
            detected_at: 1000,
        };

        let action = L2ReorgAction::SlashProposer { proof };

        let result = coordinator.apply_reorg_action(action).unwrap();

        match result {
            ReorgResult::EquivocationBroadcast { proposer, height } => {
                assert_eq!(proposer, equivocator.node_id());
                assert_eq!(height, 10);
            }
            _ => panic!("Expected EquivocationBroadcast result"),
        }

        // Verify broadcast was called
        assert!(broadcast_called.load(Ordering::SeqCst));

        // Verify equivocator was removed from validators
        assert_eq!(zk_handler.validator_count(), 0);
    }

    #[test]
    fn test_reorg_coordinator_with_snapshot_loader() {
        use crate::zk_vote_handler::ZkVoteHandler;
        use ghost_common::identity::NodeIdentity;

        let identity = Arc::new(NodeIdentity::generate());
        let detector = Arc::new(L2ForkDetector::new(100));
        let zk_handler = Arc::new(ZkVoteHandler::new(Arc::clone(&identity)));

        zk_handler.set_state(100, [1u8; 32]);

        let coordinator = ReorgCoordinator::new(
            identity,
            detector,
            Arc::clone(&zk_handler),
            ReorgCoordinatorConfig::default(),
        );

        // Set snapshot loader that returns a specific root for height 90
        coordinator.set_snapshot_loader(Arc::new(|height| {
            if height == 90 {
                Some([99u8; 32]) // Snapshot state root
            } else {
                None
            }
        }));

        // Apply rollback action
        let action = L2ReorgAction::Rollback {
            to_height: 90,
            new_tip_hash: [2u8; 32], // This should be overridden by snapshot
        };

        let result = coordinator.apply_reorg_action(action).unwrap();

        match result {
            ReorgResult::RolledBack { new_state_root, .. } => {
                // Should use snapshot root instead of new_tip_hash
                assert_eq!(new_state_root, [99u8; 32]);
            }
            _ => panic!("Expected RolledBack result"),
        }

        assert_eq!(zk_handler.get_state(), (90, [99u8; 32]));
    }

    #[test]
    fn test_reorg_coordinator_config_default() {
        let config = ReorgCoordinatorConfig::default();
        assert_eq!(config.min_votes_for_resolution, 2);
        assert!(config.auto_resolve);
        assert_eq!(config.snapshot_interval, 100);
    }

    #[test]
    fn test_reorg_result_variants() {
        // Test all ReorgResult variants can be created
        let _no_action = ReorgResult::NoAction;
        let _rolled_back = ReorgResult::RolledBack {
            from_height: 100,
            to_height: 90,
            new_state_root: [1u8; 32],
        };
        let _chain_switched = ReorgResult::ChainSwitched {
            from_height: 90,
            new_tip_height: 100,
            new_state_root: [2u8; 32],
        };
        let _equivocation = ReorgResult::EquivocationBroadcast {
            proposer: [3u8; 32],
            height: 10,
        };
        let _deferred = ReorgResult::Deferred {
            reason: "test".to_string(),
        };
        let _error = ReorgResult::Error {
            reason: "test error".to_string(),
        };
    }
}
