//! L2 Block Producer
//!
//! Produces L2 blocks every 10 seconds using ZK proofs.
//! Proposer election is deterministic round-robin based on sorted validator set.
//! Includes stuck-chain detection: if the designated proposer doesn't produce
//! within a grace period, any node will step in.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ghost_common::identity::NodeIdentity;
use ghost_consensus::message::ZkBlockProposalMessage;
use ghost_consensus::zk_vote_handler::ZkVoteHandler;
use ghost_storage::Database;
use ghost_zkp::{BlockProver, BlockWitnessV2, MerkleProof, PaymentTransitionWitness};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use tracing::{debug, error, info, warn};

/// L2 block production interval
const L2_BLOCK_INTERVAL: Duration = Duration::from_secs(10);

/// Tree depth for commitment tree (must match ghost-pay's COMMITMENT_TREE_DEPTH)
const TREE_DEPTH: usize = 20;

/// Number of missed slots before any node can step in as proposer.
/// With 10s blocks, 3 missed slots = 30 seconds of no progress.
const STUCK_CHAIN_GRACE_SLOTS: u64 = 3;

pub struct L2BlockProducer {
    identity: Arc<NodeIdentity>,
    prover: Arc<tokio::sync::OnceCell<Arc<BlockProver>>>,
    vote_handler: Arc<ZkVoteHandler>,
    #[allow(dead_code)]
    db: Arc<Database>,
    ghost_pay_url: String,
    client: reqwest::Client,
    /// Tracks the last height we observed advancing (for stuck-chain detection)
    last_observed: Mutex<(u64, Instant)>,
}

impl L2BlockProducer {
    pub fn new(
        identity: Arc<NodeIdentity>,
        prover: Arc<tokio::sync::OnceCell<Arc<BlockProver>>>,
        vote_handler: Arc<ZkVoteHandler>,
        db: Arc<Database>,
        ghost_pay_url: String,
    ) -> Self {
        Self {
            identity,
            prover,
            vote_handler,
            db,
            ghost_pay_url,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("Failed to build HTTP client"),
            last_observed: Mutex::new((0, Instant::now())),
        }
    }

    /// Main production loop — runs every 10 seconds
    pub async fn run(&self) {
        // Wait for initial setup to complete
        tokio::time::sleep(Duration::from_secs(15)).await;
        info!("L2 block producer starting (10s interval)");

        let mut interval = tokio::time::interval(L2_BLOCK_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            if let Err(e) = self.try_produce_block().await {
                warn!(error = %e, "L2 block production failed");
            }
        }
    }

    async fn try_produce_block(&self) -> anyhow::Result<()> {
        // 1. Check prover AND verifier are ready
        // Both must be initialized or the proposer will reject its own proofs
        let prover = match self.prover.get() {
            Some(p) => p,
            None => {
                debug!("ZK prover not ready yet, skipping block production");
                return Ok(());
            }
        };
        if !self.vote_handler.has_verifier() {
            debug!("ZK verifier not ready yet, skipping block production");
            return Ok(());
        }

        // 2. Get current L2 state
        let (current_height, current_state_root) = self.vote_handler.get_state();
        let next_height = current_height + 1;

        // Skip if we already have an active proposal for this height
        // (avoids wasting ~14s on proof generation for a duplicate)
        if self.vote_handler.has_pending_proposal(next_height) {
            debug!(height = next_height, "Proposal already pending, skipping");
            return Ok(());
        }

        // Update stuck-chain tracker
        {
            let mut last = self.last_observed.lock();
            if current_height > last.0 {
                *last = (current_height, Instant::now());
            }
        }

        // 3. Proposer election — deterministic round-robin with stuck-chain fallback
        if !self.should_propose(next_height) {
            return Ok(());
        }

        // 4. Fetch pending transfers from ghost-pay
        let witness = match self.fetch_witness(next_height, current_state_root).await {
            Ok(w) => w,
            Err(e) => {
                // Ghost-pay may not be running — produce empty block with current state
                debug!(error = %e, "Ghost-pay unreachable, producing empty block");
                BlockWitnessV2::empty(next_height, current_state_root, TREE_DEPTH)
            }
        };

        let tx_count = witness.tx_count() as u32;

        // 5. Generate ZK proof (CPU-bound Groth16 ~14s — must not block tokio runtime)
        let prover_clone = Arc::clone(prover);
        let witness_clone = witness.clone();
        let proof =
            match tokio::task::spawn_blocking(move || prover_clone.prove(&witness_clone)).await {
                Ok(Ok(p)) => p,
                Ok(Err(e)) => {
                    error!(error = %e, height = next_height, "ZK proof generation failed");
                    return Ok(());
                }
                Err(e) => {
                    error!(error = %e, height = next_height, "ZK proof task panicked");
                    return Ok(());
                }
            };

        // 6. Build proposal message
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Compute transactions hash (empty for now)
        let transactions_hash = {
            let mut hasher = Sha256::new();
            hasher.update(b"L2BlockTxs/v1");
            hasher.update(next_height.to_le_bytes());
            hasher.update(tx_count.to_le_bytes());
            let result: [u8; 32] = hasher.finalize().into();
            result
        };

        let mut proposal = ZkBlockProposalMessage {
            height: next_height,
            prev_state_root: witness.prev_state_root,
            new_state_root: witness.new_state_root,
            tx_count,
            transactions_hash,
            transactions: Vec::new(),
            proof: proof.proof,
            proposer_signature: [0u8; 64],
            timestamp,
        };

        // Sign the proposal
        let proposal_hash = proposal.proposal_hash();
        proposal.proposer_signature = self.identity.sign(&proposal_hash);

        info!(
            height = next_height,
            tx_count,
            state_root = hex::encode(witness.new_state_root),
            "Proposing L2 block"
        );

        // 7. Submit to vote handler (broadcasts to mesh)
        if let Err(e) = self.vote_handler.handle_proposal(proposal) {
            error!(error = %e, height = next_height, "Failed to submit L2 proposal");
        }

        Ok(())
    }

    /// Determine if we should propose this block.
    /// Primary: deterministic round-robin (sorted_validators[height % len]).
    /// Fallback: if the chain is stuck (no progress for STUCK_CHAIN_GRACE_SLOTS),
    /// any node can step in to keep the chain alive.
    fn should_propose(&self, height: u64) -> bool {
        let validators = self.vote_handler.get_sorted_validators();
        if validators.is_empty() {
            return true;
        }

        let our_id = self.identity.node_id();

        // Check if it's our designated turn
        let index = (height as usize) % validators.len();
        if validators[index] == our_id {
            return true;
        }

        // Not our turn — check if chain is stuck
        let last = self.last_observed.lock();
        let stale_duration = L2_BLOCK_INTERVAL * STUCK_CHAIN_GRACE_SLOTS as u32;
        if last.1.elapsed() > stale_duration {
            warn!(
                height,
                stale_secs = last.1.elapsed().as_secs(),
                "L2 chain stuck — stepping in as fallback proposer"
            );
            return true;
        }

        false
    }

    /// Fetch block witness from ghost-pay's /api/v1/l2/pending endpoint
    async fn fetch_witness(
        &self,
        height: u64,
        current_state_root: [u8; 32],
    ) -> anyhow::Result<BlockWitnessV2> {
        let url = format!("{}/api/v1/l2/pending", self.ghost_pay_url);
        let resp = self.client.get(&url).send().await?;

        if !resp.status().is_success() {
            anyhow::bail!("Ghost-pay returned status {}", resp.status());
        }

        let body: serde_json::Value = resp.json().await?;
        let tx_count = body["tx_count"].as_u64().unwrap_or(0);

        if tx_count == 0 {
            return Ok(BlockWitnessV2::empty(
                height,
                current_state_root,
                TREE_DEPTH,
            ));
        }

        let prev_root = parse_hex_root(&body["prev_state_root"])?;
        let new_root = parse_hex_root(&body["new_state_root"])?;
        let transitions = parse_transitions(&body["transitions"])?;
        let intermediate_roots = parse_intermediate_roots(&body["intermediate_roots"])?;

        info!(
            height,
            tx_count,
            prev_root = hex::encode(prev_root),
            new_root = hex::encode(new_root),
            "Fetched L2 witness with transfers"
        );

        Ok(BlockWitnessV2::new_with_roots(
            height,
            prev_root,
            new_root,
            transitions,
            intermediate_roots,
            TREE_DEPTH,
        ))
    }
}

/// Parse a hex-encoded 32-byte root from a JSON value
fn parse_hex_root(value: &serde_json::Value) -> anyhow::Result<[u8; 32]> {
    let hex_str = value
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Expected hex string for state root"))?;
    let mut root = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut root)?;
    Ok(root)
}

/// Parse transitions array from the ghost-pay response
fn parse_transitions(value: &serde_json::Value) -> anyhow::Result<Vec<PaymentTransitionWitness>> {
    let arr = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Expected transitions array"))?;

    let mut transitions = Vec::with_capacity(arr.len());
    for (i, t) in arr.iter().enumerate() {
        let sender_index = t["sender_index"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing sender_index in transition {}", i))?;
        let recipient_index = t["recipient_index"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing recipient_index in transition {}", i))?;
        let amount = t["amount"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing amount in transition {}", i))?;
        let sender_balance_before = t["sender_balance_before"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing sender_balance_before in transition {}", i))?;
        let recipient_balance_before = t["recipient_balance_before"].as_u64().ok_or_else(|| {
            anyhow::anyhow!("Missing recipient_balance_before in transition {}", i)
        })?;

        let sender_proof = parse_merkle_proof(&t["sender_merkle_proof"], i, "sender")?;
        let recipient_proof = parse_merkle_proof(&t["recipient_merkle_proof"], i, "recipient")?;

        transitions.push(PaymentTransitionWitness::new(
            sender_balance_before,
            recipient_balance_before,
            amount,
            sender_index,
            sender_proof,
            recipient_index,
            recipient_proof,
        ));
    }

    Ok(transitions)
}

/// Parse a single merkle proof from JSON
fn parse_merkle_proof(
    value: &serde_json::Value,
    tx_idx: usize,
    role: &str,
) -> anyhow::Result<MerkleProof> {
    let index = value["index"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("Missing {} proof index in transition {}", role, tx_idx))?;

    let siblings_arr = value["siblings"].as_array().ok_or_else(|| {
        anyhow::anyhow!("Missing {} proof siblings in transition {}", role, tx_idx)
    })?;

    let mut siblings = Vec::with_capacity(siblings_arr.len());
    for (j, s) in siblings_arr.iter().enumerate() {
        let hex_str = s.as_str().ok_or_else(|| {
            anyhow::anyhow!("Invalid {} sibling {} in transition {}", role, j, tx_idx)
        })?;
        let mut sibling = [0u8; 32];
        hex::decode_to_slice(hex_str, &mut sibling)?;
        siblings.push(sibling);
    }

    Ok(MerkleProof::new(index, siblings))
}

/// Parse intermediate roots array from the ghost-pay response
fn parse_intermediate_roots(value: &serde_json::Value) -> anyhow::Result<Vec<[u8; 32]>> {
    let arr = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Expected intermediate_roots array"))?;

    let mut roots = Vec::with_capacity(arr.len());
    for (i, r) in arr.iter().enumerate() {
        let hex_str = r
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid intermediate root at index {}", i))?;
        let mut root = [0u8; 32];
        hex::decode_to_slice(hex_str, &mut root)?;
        roots.push(root);
    }

    Ok(roots)
}
