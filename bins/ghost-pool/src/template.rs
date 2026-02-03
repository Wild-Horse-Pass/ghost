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
//| FILE: template.rs                                                                                                    |
//|======================================================================================================================|

//! Template processor for block template management
//!
//! Fetches templates from Bitcoin Core, applies BUDS filtering,
//! and manages coinbase construction for the pool.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use bitcoin::consensus::deserialize;
use ghost_accounting::CoinbaseBuilder;
use ghost_buds::BudsClassifier;
use ghost_common::config::{BitcoinNetwork, MiningMode};
use ghost_common::rpc::{BitcoinRpc, BlockTemplate, TemplateTransaction};
use ghost_common::types::{PayoutProposal, TreasuryAddress};
use ghost_policy::PolicyProfile;

/// Type alias for coinbase build result:
/// (coinbase1, coinbase2, witness_data, outputs_serialized, outputs_count)
type CoinbaseBuildResult = (Vec<u8>, Vec<u8>, WitnessData, Vec<u8>, u32);

/// Template processor configuration
#[derive(Debug, Clone)]
pub struct TemplateConfig {
    /// Template refresh interval (milliseconds)
    pub refresh_interval_ms: u64,
    /// Minimum fee rate to include (sat/vB)
    pub min_fee_rate: f64,
    /// Target block weight
    pub target_weight: u64,
    /// Coinbase extra data (pool signature)
    pub coinbase_extra: String,
    /// Treasury address for pool fees (supports multi-sig)
    pub treasury_address: TreasuryAddress,
    /// Pool payout address for fallback coinbase (bech32)
    /// Used when no approved payout proposal exists
    pub pool_payout_address: String,
    /// Bitcoin network (mainnet, signet, testnet, regtest)
    pub network: BitcoinNetwork,
    /// Mining mode (PublicPool, PrivatePool, PrivateSolo)
    pub mining_mode: MiningMode,
    /// Solo payout address (required for PrivateSolo mode)
    /// All rewards (99% subsidy + 100% tx fees) go to this address
    pub solo_payout_address: Option<String>,
}

impl Default for TemplateConfig {
    fn default() -> Self {
        Self {
            refresh_interval_ms: 500,
            min_fee_rate: 1.0,
            target_weight: 3_992_000, // ~99% of 4MW limit
            coinbase_extra: "GHOST".to_string(),
            treasury_address: TreasuryAddress::default(), // Must be configured
            pool_payout_address: String::new(),           // Must be configured
            network: BitcoinNetwork::Mainnet,
            mining_mode: MiningMode::PublicPool,
            solo_payout_address: None,
        }
    }
}

/// Current work state for miners
#[derive(Debug, Clone)]
pub struct WorkState {
    /// Job ID
    pub job_id: String,
    /// Previous block hash (little-endian hex)
    pub prev_hash: String,
    /// Coinbase part 1 (before extranonce) - NON-WITNESS serialization for TXID
    pub coinbase1: Vec<u8>,
    /// Coinbase part 2 (after extranonce) - NON-WITNESS serialization for TXID
    pub coinbase2: Vec<u8>,
    /// Witness data to append for full transaction (marker + flag prefix, witness suffix)
    pub witness_data: WitnessData,
    /// Merkle branches
    pub merkle_branches: Vec<[u8; 32]>,
    /// Block version
    pub version: u32,
    /// nBits (difficulty target)
    pub nbits: String,
    /// nTime
    pub ntime: u32,
    /// Block height
    pub height: u64,
    /// Total fees in template
    pub total_fees: u64,
    /// Transaction count (including coinbase)
    pub tx_count: usize,
    /// Total weight of transactions (for block weight validation)
    pub total_weight: u64,
    /// Original template (for block submission)
    pub template: BlockTemplate,
    /// Serialized coinbase outputs (Bitcoin consensus format for TDP)
    /// This is the raw TxOut data that SRI Pool should use
    pub coinbase_outputs_serialized: Vec<u8>,
    /// Number of coinbase outputs
    pub coinbase_outputs_count: u32,
    /// H-MINE-2: Snapshot of approved payout hash at template creation time
    /// This prevents TOCTOU race conditions where the approved payout could change
    /// between template creation and coinbase building.
    pub payout_snapshot: Option<[u8; 32]>,
}

/// Witness data for SegWit coinbase transaction
/// Kept separate from coinbase1/coinbase2 so miners compute correct TXID for merkle root
#[derive(Debug, Clone, Default)]
pub struct WitnessData {
    /// Witness commitment output script (if present)
    pub commitment_script: Option<Vec<u8>>,
    /// Witness nonce (32 bytes of zeros per BIP141)
    pub nonce: [u8; 32],
}

/// Events from the template processor
#[derive(Debug, Clone)]
pub enum TemplateEvent {
    /// New work available
    NewWork { job_id: String, height: u64 },
    /// Template fetch failed
    FetchFailed { error: String },
    /// Transactions filtered
    TransactionsFiltered {
        original_count: usize,
        filtered_count: usize,
        removed_fees: u64,
    },
}

/// Template processor
pub struct TemplateProcessor {
    /// Configuration
    config: TemplateConfig,
    /// Bitcoin RPC client
    rpc: Arc<BitcoinRpc>,
    /// Policy profile
    policy: PolicyProfile,
    /// BUDS classifier
    classifier: BudsClassifier,
    /// Current work state
    current_work: RwLock<Option<WorkState>>,
    /// Work states by template_id (for SubmitSolution lookup)
    work_states: RwLock<HashMap<u64, WorkState>>,
    /// Job counter
    job_counter: RwLock<u64>,
    /// Event sender
    event_tx: broadcast::Sender<TemplateEvent>,
    /// Running state
    running: RwLock<bool>,
    /// Approved payout proposal hash (from consensus)
    approved_payout: RwLock<Option<[u8; 32]>>,
    /// Cached payout proposals (hash -> proposal)
    payout_proposals: RwLock<HashMap<[u8; 32], PayoutProposal>>,
}

impl TemplateProcessor {
    /// Create a new template processor
    pub fn new(config: TemplateConfig, rpc: Arc<BitcoinRpc>, policy: PolicyProfile) -> Self {
        let (event_tx, _) = broadcast::channel(100);

        Self {
            config,
            rpc,
            policy,
            classifier: BudsClassifier::new(),
            current_work: RwLock::new(None),
            work_states: RwLock::new(HashMap::new()),
            job_counter: RwLock::new(0),
            event_tx,
            running: RwLock::new(false),
            approved_payout: RwLock::new(None),
            payout_proposals: RwLock::new(HashMap::new()),
        }
    }

    /// Store a payout proposal (called when proposal is received)
    pub fn store_proposal(&self, proposal: PayoutProposal) {
        let hash = proposal.proposal_hash;
        let miners = proposal.miner_payouts.len();
        let nodes = proposal.node_payouts.len();
        self.payout_proposals.write().insert(hash, proposal);
        info!(
            hash = %hex::encode(&hash[..8]),
            miners = miners,
            nodes = nodes,
            "Stored payout proposal in template processor"
        );
    }

    /// Get a stored proposal by hash
    pub fn get_proposal(&self, hash: &[u8; 32]) -> Option<PayoutProposal> {
        self.payout_proposals.read().get(hash).cloned()
    }

    /// Set the approved payout proposal hash (from consensus)
    ///
    /// This is called when consensus approves a payout proposal.
    /// The template processor uses this to include proper payout
    /// outputs in the coinbase transaction.
    pub fn set_approved_payout(&self, proposal_hash: [u8; 32]) {
        *self.approved_payout.write() = Some(proposal_hash);
        info!(
            hash = %hex::encode(&proposal_hash[..8]),
            "Set approved payout for coinbase"
        );
    }

    /// Clear the approved payout (after block is found)
    pub fn clear_approved_payout(&self) {
        *self.approved_payout.write() = None;
    }

    /// Get the current approved payout hash
    pub fn approved_payout(&self) -> Option<[u8; 32]> {
        *self.approved_payout.read()
    }

    /// Build a complete coinbase transaction using the approved payout
    ///
    /// This is used for final block assembly when we have an approved
    /// payout proposal from consensus.
    ///
    /// H-MINE-2: This method reads from the live approved_payout lock.
    /// For TOCTOU-safe operation when reconstructing from a template,
    /// use build_approved_coinbase_from_snapshot() with the WorkState's payout_snapshot.
    pub fn build_approved_coinbase(
        &self,
        height: u64,
        witness_commitment: &Option<String>,
    ) -> Option<bitcoin::Transaction> {
        // H-MINE-2: Capture hash once, atomically
        let payout_hash = (*self.approved_payout.read())?;
        self.build_approved_coinbase_from_snapshot(height, witness_commitment, payout_hash)
    }

    /// H-MINE-2: Build coinbase using a pre-captured payout hash snapshot
    ///
    /// This is the TOCTOU-safe version that uses a snapshot of the approved payout
    /// hash captured at template creation time (stored in WorkState.payout_snapshot).
    pub fn build_approved_coinbase_from_snapshot(
        &self,
        height: u64,
        witness_commitment: &Option<String>,
        payout_hash: [u8; 32],
    ) -> Option<bitcoin::Transaction> {
        // Look up the proposal using the snapshot hash
        let proposal = self.get_proposal(&payout_hash)?;

        // Build using CoinbaseBuilder
        let builder = CoinbaseBuilder::new(height)
            .with_pool_tag(self.config.coinbase_extra.as_bytes())
            .with_extra_nonce_size(8);

        // Combine all payout entries
        let mut entries = Vec::new();
        entries.extend(proposal.miner_payouts.iter().cloned());
        entries.extend(proposal.node_payouts.iter().cloned());

        // H-MINE-3: Add treasury output using address from proposal (snapshot), not live config
        if proposal.treasury_amount > 0 {
            let treasury_addr = if !proposal.treasury_address.is_empty() {
                // H-MINE-3: Use the snapshot address from the proposal
                proposal.treasury_address.clone()
            } else if !self.config.treasury_address.is_empty() {
                // Fallback to config if proposal has no address (legacy proposals)
                warn!("Using treasury address from config (proposal has no snapshot)");
                self.config.treasury_address.address().as_bytes().to_vec()
            } else {
                warn!("Treasury amount specified but no treasury address available");
                Vec::new()
            };

            if !treasury_addr.is_empty() {
                entries.push(ghost_common::types::PayoutEntry {
                    address: treasury_addr,
                    amount: proposal.treasury_amount,
                    recipient_id: [0u8; 32],
                    payout_type: ghost_common::types::PayoutType::Treasury,
                });
            }
        }

        match builder.build_from_entries(&entries) {
            Ok(mut tx) => {
                // Add witness commitment output if present
                if let Some(commitment) = witness_commitment {
                    if let Ok(commitment_bytes) = hex::decode(commitment) {
                        tx.output.push(bitcoin::TxOut {
                            value: bitcoin::Amount::ZERO,
                            script_pubkey: bitcoin::ScriptBuf::from(commitment_bytes),
                        });
                    }
                }

                info!(
                    height = height,
                    outputs = tx.output.len(),
                    miner_payouts = proposal.miner_payouts.len(),
                    node_payouts = proposal.node_payouts.len(),
                    "Built approved coinbase"
                );

                Some(tx)
            }
            Err(e) => {
                error!(error = %e, "Failed to build approved coinbase");
                None
            }
        }
    }

    /// Build coinbase for stratum (split into coinbase1/coinbase2)
    ///
    /// IMPORTANT: coinbase1/coinbase2 use NON-WITNESS serialization so miners
    /// compute the correct TXID (not WTXID) for the merkle root.
    /// Witness data is returned separately for block assembly.
    ///
    /// When there's an approved payout, this includes all payout outputs.
    /// Otherwise falls back to placeholder single output.
    ///
    /// H-MINE-2: This method reads from the live approved_payout lock.
    /// For TOCTOU-safe operation, use build_coinbase_parts_with_payout_snapshot() instead.
    ///
    /// Returns: (coinbase1, coinbase2, witness_data, outputs_serialized, outputs_count)
    #[allow(dead_code)]
    fn build_coinbase_parts_with_payout(
        &self,
        height: u64,
        total_value: u64,
        witness_commitment: &Option<String>,
    ) -> (Vec<u8>, Vec<u8>, WitnessData, Vec<u8>, u32) {
        // Check for approved payout - reads live lock (TOCTOU-vulnerable path)
        let payout_hash = *self.approved_payout.read();
        self.build_coinbase_parts_with_payout_snapshot(height, total_value, witness_commitment, payout_hash)
    }

    /// H-MINE-2: Build coinbase using a pre-captured payout snapshot
    ///
    /// This is the TOCTOU-safe version that uses a snapshot of the approved payout
    /// hash captured at template creation time.
    ///
    /// IMPORTANT: coinbase1/coinbase2 use NON-WITNESS serialization so miners
    /// compute the correct TXID (not WTXID) for the merkle root.
    /// Witness data is returned separately for block assembly.
    ///
    /// When there's an approved payout, this includes all payout outputs.
    /// Otherwise falls back to placeholder single output.
    ///
    /// Returns: (coinbase1, coinbase2, witness_data, outputs_serialized, outputs_count)
    fn build_coinbase_parts_with_payout_snapshot(
        &self,
        height: u64,
        total_value: u64,
        witness_commitment: &Option<String>,
        payout_snapshot: Option<[u8; 32]>,
    ) -> (Vec<u8>, Vec<u8>, WitnessData, Vec<u8>, u32) {
        // H-MINE-2: Use the snapshot instead of reading from the lock
        let proposal = payout_snapshot.and_then(|h| self.get_proposal(&h));

        // Build coinbase1 - NON-WITNESS format (no marker/flag)
        // Format: version | input_count | prev_txhash | prev_outindex | scriptsig_len | scriptsig_data
        let mut coinbase1 = Vec::new();

        // Version (4 bytes, little-endian)
        coinbase1.extend_from_slice(&2u32.to_le_bytes()); // Version 2 for BIP68

        // NO marker/flag here - those are only for witness serialization (wtxid)
        // Input count (for txid computation, this comes right after version)
        coinbase1.push(0x01);

        // Previous tx hash (all zeros for coinbase)
        coinbase1.extend_from_slice(&[0u8; 32]);

        // Previous output index (0xffffffff for coinbase)
        coinbase1.extend_from_slice(&0xffffffffu32.to_le_bytes());

        // Script sig (height in BIP34 format + extra data)
        let height_bytes = self.encode_height(height);
        let extra = self.config.coinbase_extra.as_bytes();
        let script_len = height_bytes.len() + extra.len() + 8; // +8 for extranonce space

        coinbase1.push(script_len as u8);
        coinbase1.extend_from_slice(&height_bytes);
        coinbase1.extend_from_slice(extra);

        // Coinbase2: extranonce end + sequence + outputs + locktime
        // NO witness data here - that's separate for block assembly
        let mut coinbase2 = Vec::new();

        // Sequence
        coinbase2.extend_from_slice(&0xffffffffu32.to_le_bytes());

        // Track witness commitment for WitnessData
        let mut witness_data = WitnessData::default();

        // Track serialized outputs for TDP (Bitcoin consensus format: Vec<TxOut>)
        // This is sent to SRI Pool so it uses Ghost's coinbase outputs
        let mut outputs_serialized = Vec::new();
        let outputs_count: u32;

        // Build outputs based on whether we have an approved payout
        // Note: witness commitment output is NOT included in txid outputs
        // It goes in the witness serialization only
        if let Some(ref prop) = proposal {
            // Build outputs from approved payout
            // Count only non-zero value entries
            let miner_output_count = prop.miner_payouts.iter().filter(|e| e.amount > 0).count();
            let node_output_count = prop.node_payouts.iter().filter(|e| e.amount > 0).count();
            let treasury_output_count = if prop.treasury_amount > 0 { 1 } else { 0 };
            let base_output_count = miner_output_count + node_output_count + treasury_output_count;

            // Add 1 for witness commitment if present (it IS part of outputs, just 0-value)
            let output_count = base_output_count + if witness_commitment.is_some() { 1 } else { 0 };
            outputs_count = output_count as u32;

            self.encode_varint(&mut coinbase2, output_count);

            // Miner payouts (skip 0-value entries)
            for entry in &prop.miner_payouts {
                if entry.amount == 0 {
                    continue;
                }
                coinbase2.extend_from_slice(&entry.amount.to_le_bytes());
                self.encode_script(&mut coinbase2, &entry.address);
                // Also add to outputs_serialized for TDP
                outputs_serialized.extend_from_slice(&entry.amount.to_le_bytes());
                self.encode_script(&mut outputs_serialized, &entry.address);
            }

            // Node payouts (skip 0-value entries)
            for entry in &prop.node_payouts {
                if entry.amount == 0 {
                    continue; // Skip 0-value outputs
                }
                coinbase2.extend_from_slice(&entry.amount.to_le_bytes());
                self.encode_script(&mut coinbase2, &entry.address);
                // Also add to outputs_serialized for TDP
                outputs_serialized.extend_from_slice(&entry.amount.to_le_bytes());
                self.encode_script(&mut outputs_serialized, &entry.address);
            }

            // Treasury
            // H-MINE-3: Use treasury_address from proposal (snapshot) instead of live config
            if prop.treasury_amount > 0 {
                coinbase2.extend_from_slice(&prop.treasury_amount.to_le_bytes());
                if !prop.treasury_address.is_empty() {
                    // H-MINE-3: Use the snapshot address from the proposal
                    self.encode_script(&mut coinbase2, &prop.treasury_address);
                    outputs_serialized.extend_from_slice(&prop.treasury_amount.to_le_bytes());
                    self.encode_script(&mut outputs_serialized, &prop.treasury_address);
                } else {
                    // Fallback to config if proposal has no address (legacy proposals)
                    let treasury_addr = self.config.treasury_address.address();
                    self.encode_address_script(&mut coinbase2, treasury_addr, "treasury");
                    outputs_serialized.extend_from_slice(&prop.treasury_amount.to_le_bytes());
                    self.encode_address_script(&mut outputs_serialized, treasury_addr, "treasury_tdp");
                    warn!("Using treasury address from config (proposal has no snapshot)");
                }
            }

            info!(
                height = height,
                miners = prop.miner_payouts.len(),
                nodes = prop.node_payouts.len(),
                treasury = prop.treasury_amount,
                "Built coinbase with approved payout outputs"
            );
        } else {
            // Fallback: single output with total value (plus witness commitment if present)
            let output_count = if witness_commitment.is_some() { 2 } else { 1 };
            outputs_count = output_count as u32;
            coinbase2.push(output_count as u8);

            // Single pool reward output
            coinbase2.extend_from_slice(&total_value.to_le_bytes());
            self.encode_address_script(
                &mut coinbase2,
                &self.config.pool_payout_address,
                "pool_payout",
            );
            // Also add to outputs_serialized for TDP
            outputs_serialized.extend_from_slice(&total_value.to_le_bytes());
            self.encode_address_script(
                &mut outputs_serialized,
                &self.config.pool_payout_address,
                "pool_payout_tdp",
            );
        }

        // Witness commitment output (0-value OP_RETURN with commitment)
        // This IS included in the txid serialization (it's a regular output)
        if let Some(commitment) = witness_commitment {
            coinbase2.extend_from_slice(&0u64.to_le_bytes()); // 0 value
            if let Ok(commitment_bytes) = hex::decode(commitment) {
                coinbase2.push(commitment_bytes.len() as u8);
                coinbase2.extend_from_slice(&commitment_bytes);
                witness_data.commitment_script = Some(commitment_bytes.clone());
                // Also add to outputs_serialized for TDP
                outputs_serialized.extend_from_slice(&0u64.to_le_bytes());
                outputs_serialized.push(commitment_bytes.len() as u8);
                outputs_serialized.extend_from_slice(&commitment_bytes);
            }
        }

        // Locktime (end of non-witness serialization)
        coinbase2.extend_from_slice(&0u32.to_le_bytes());

        // Witness data is stored separately - NOT appended to coinbase2
        // This ensures hash(coinbase1 + extranonce + coinbase2) = TXID (not WTXID)
        // The witness nonce is all zeros per BIP141 default
        witness_data.nonce = [0u8; 32];

        (
            coinbase1,
            coinbase2,
            witness_data,
            outputs_serialized,
            outputs_count,
        )
    }

    /// Build coinbase for solo mining mode
    ///
    /// Solo mode reward structure:
    /// - Output 0: 99% subsidy + ALL TX fees → solo_payout_address
    /// - Output 1: Treasury portion of 1% pool fee → treasury_address
    /// - Output 2: Node pool portion of 1% pool fee → treasury_address (node pool)
    /// - Output 3: Witness commitment (if SegWit)
    ///
    /// The 1% pool fee is split between treasury and node pool per decay schedule.
    /// The hosting node participates in the node reward pool calculation.
    ///
    /// Returns: (coinbase1, coinbase2, witness_data, outputs_serialized, outputs_count)
    pub fn build_coinbase_solo_mode(
        &self,
        height: u64,
        subsidy: u64,
        tx_fees: u64,
        treasury_amount: u64,
        node_pool_amount: u64,
        witness_commitment: &Option<String>,
    ) -> Option<CoinbaseBuildResult> {
        // Solo mode requires solo_payout_address to be configured
        let solo_address = self.config.solo_payout_address.as_ref()?;
        if solo_address.is_empty() {
            warn!("Solo mode requires solo_payout_address to be configured");
            return None;
        }

        // Calculate solo miner's share: 99% of subsidy + ALL tx fees
        // The 1% pool fee (treasury_amount + node_pool_amount) comes from the caller
        let miner_pool = subsidy
            .saturating_sub(treasury_amount)
            .saturating_sub(node_pool_amount);
        let solo_miner_amount = miner_pool.saturating_add(tx_fees);

        info!(
            height = height,
            subsidy = subsidy,
            tx_fees = tx_fees,
            solo_miner_amount = solo_miner_amount,
            treasury = treasury_amount,
            node_pool = node_pool_amount,
            "Building solo mode coinbase"
        );

        // Build coinbase1 - NON-WITNESS format
        let mut coinbase1 = Vec::new();

        // Version (4 bytes, little-endian)
        coinbase1.extend_from_slice(&2u32.to_le_bytes()); // Version 2 for BIP68

        // Input count
        coinbase1.push(0x01);

        // Previous tx hash (all zeros for coinbase)
        coinbase1.extend_from_slice(&[0u8; 32]);

        // Previous output index (0xffffffff for coinbase)
        coinbase1.extend_from_slice(&0xffffffffu32.to_le_bytes());

        // Script sig (height in BIP34 format + extra data)
        let height_bytes = self.encode_height(height);
        let extra = self.config.coinbase_extra.as_bytes();
        let script_len = height_bytes.len() + extra.len() + 8; // +8 for extranonce space

        coinbase1.push(script_len as u8);
        coinbase1.extend_from_slice(&height_bytes);
        coinbase1.extend_from_slice(extra);

        // Coinbase2: extranonce end + sequence + outputs + locktime
        let mut coinbase2 = Vec::new();

        // Sequence
        coinbase2.extend_from_slice(&0xffffffffu32.to_le_bytes());

        // Track witness commitment for WitnessData
        let mut witness_data = WitnessData::default();

        // Track serialized outputs for TDP
        let mut outputs_serialized = Vec::new();

        // Count outputs: solo miner + treasury (if > 0) + node pool (if > 0) + witness commitment
        let mut output_count = 1; // solo miner always present
        if treasury_amount > 0 {
            output_count += 1;
        }
        if node_pool_amount > 0 {
            output_count += 1;
        }
        if witness_commitment.is_some() {
            output_count += 1;
        }

        self.encode_varint(&mut coinbase2, output_count);

        // Output 0: Solo miner (99% subsidy + ALL tx fees)
        coinbase2.extend_from_slice(&solo_miner_amount.to_le_bytes());
        self.encode_address_script(&mut coinbase2, solo_address, "solo_miner");
        outputs_serialized.extend_from_slice(&solo_miner_amount.to_le_bytes());
        self.encode_address_script(&mut outputs_serialized, solo_address, "solo_miner_tdp");

        // Output 1: Treasury (portion of 1% pool fee per decay schedule)
        if treasury_amount > 0 {
            let treasury_addr = self.config.treasury_address.address();
            coinbase2.extend_from_slice(&treasury_amount.to_le_bytes());
            self.encode_address_script(&mut coinbase2, treasury_addr, "treasury");
            outputs_serialized.extend_from_slice(&treasury_amount.to_le_bytes());
            self.encode_address_script(&mut outputs_serialized, treasury_addr, "treasury_tdp");
        }

        // Output 2: Node pool (portion of 1% pool fee per decay schedule)
        // In solo mode, this typically goes to the hosting node (operator)
        // For simplicity, we use treasury address as the destination (can be separate)
        if node_pool_amount > 0 {
            let treasury_addr = self.config.treasury_address.address();
            coinbase2.extend_from_slice(&node_pool_amount.to_le_bytes());
            self.encode_address_script(&mut coinbase2, treasury_addr, "node_pool");
            outputs_serialized.extend_from_slice(&node_pool_amount.to_le_bytes());
            self.encode_address_script(&mut outputs_serialized, treasury_addr, "node_pool_tdp");
        }

        // Output 3: Witness commitment (0-value OP_RETURN)
        if let Some(commitment) = witness_commitment {
            coinbase2.extend_from_slice(&0u64.to_le_bytes()); // 0 value
            if let Ok(commitment_bytes) = hex::decode(commitment) {
                coinbase2.push(commitment_bytes.len() as u8);
                coinbase2.extend_from_slice(&commitment_bytes);
                witness_data.commitment_script = Some(commitment_bytes.clone());
                outputs_serialized.extend_from_slice(&0u64.to_le_bytes());
                outputs_serialized.push(commitment_bytes.len() as u8);
                outputs_serialized.extend_from_slice(&commitment_bytes);
            }
        }

        // Locktime
        coinbase2.extend_from_slice(&0u32.to_le_bytes());

        // Witness nonce
        witness_data.nonce = [0u8; 32];

        Some((
            coinbase1,
            coinbase2,
            witness_data,
            outputs_serialized,
            output_count as u32,
        ))
    }

    /// Encode a varint
    fn encode_varint(&self, buf: &mut Vec<u8>, value: usize) {
        if value < 0xfd {
            buf.push(value as u8);
        } else if value <= 0xffff {
            buf.push(0xfd);
            buf.extend_from_slice(&(value as u16).to_le_bytes());
        } else {
            buf.push(0xfe);
            buf.extend_from_slice(&(value as u32).to_le_bytes());
        }
    }

    /// Encode a script (address bytes with length prefix)
    fn encode_script(&self, buf: &mut Vec<u8>, address: &[u8]) {
        // Try to parse as address string and get script pubkey
        if let Ok(addr_str) = std::str::from_utf8(address) {
            if let Ok(addr) =
                addr_str.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            {
                let script = addr.assume_checked().script_pubkey();
                let script_bytes = script.as_bytes();
                self.encode_varint(buf, script_bytes.len());
                buf.extend_from_slice(script_bytes);
                return;
            }
        }

        // Fallback: treat as raw script bytes
        self.encode_varint(buf, address.len());
        buf.extend_from_slice(address);
    }

    /// Parse a bech32 address to script pubkey bytes
    ///
    /// Returns the raw script pubkey bytes for the given address.
    /// Returns None if the address is empty or invalid.
    fn address_to_script(&self, address: &str) -> Option<Vec<u8>> {
        if address.is_empty() {
            return None;
        }

        address
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .ok()
            .map(|addr| addr.assume_checked().script_pubkey().into_bytes())
    }

    /// Encode a script pubkey directly to the buffer
    ///
    /// If address is valid, encodes its script pubkey.
    /// Otherwise, encodes a placeholder P2WPKH script and logs a warning.
    fn encode_address_script(&self, buf: &mut Vec<u8>, address: &str, context: &str) {
        match self.address_to_script(address) {
            Some(script_bytes) => {
                buf.push(script_bytes.len() as u8);
                buf.extend_from_slice(&script_bytes);
            }
            None => {
                // Fallback to placeholder - this should not happen in production
                warn!(
                    context = %context,
                    "No valid address configured, using placeholder script"
                );
                buf.push(0x16); // Script length (22 bytes for P2WPKH)
                buf.push(0x00); // OP_0
                buf.push(0x14); // PUSH 20
                buf.extend_from_slice(&[0u8; 20]);
            }
        }
    }

    /// Subscribe to template events
    pub fn subscribe(&self) -> broadcast::Receiver<TemplateEvent> {
        self.event_tx.subscribe()
    }

    /// Start the template processor
    pub async fn start(self: Arc<Self>) -> anyhow::Result<()> {
        *self.running.write() = true;
        info!("Template processor started");

        let mut interval = tokio::time::interval(std::time::Duration::from_millis(
            self.config.refresh_interval_ms,
        ));

        while *self.running.read() {
            interval.tick().await;

            if let Err(e) = self.refresh_template().await {
                error!(error = %e, "Failed to refresh template");
                let _ = self.event_tx.send(TemplateEvent::FetchFailed {
                    error: e.to_string(),
                });
            }
        }

        Ok(())
    }

    /// Stop the processor
    pub fn stop(&self) {
        *self.running.write() = false;
    }

    /// Refresh the block template
    pub async fn refresh_template(&self) -> anyhow::Result<()> {
        // Build rules based on network
        let rules: Vec<&str> = match self.config.network {
            BitcoinNetwork::Signet => vec!["segwit", "signet"],
            BitcoinNetwork::Testnet => vec!["segwit"],
            BitcoinNetwork::Regtest => vec!["segwit"],
            BitcoinNetwork::Mainnet => vec!["segwit"],
        };

        // Fetch template from Bitcoin Core
        let template = self
            .rpc
            .get_block_template(rules)
            .await
            .map_err(|e| anyhow::anyhow!("RPC error: {}", e))?;

        // Check if template changed (height or significant curtime drift)
        let should_update = {
            let current = self.current_work.read();
            current
                .as_ref()
                .map(|w| {
                    // Update if height changed (new block)
                    let height_changed = w.height != template.height;
                    // Update if curtime drifted more than 60 seconds (keeps ntime fresh for miners)
                    let curtime_drift = (template.curtime as u32).saturating_sub(w.ntime) > 60;
                    height_changed || curtime_drift
                })
                .unwrap_or(true)
        };

        if !should_update {
            return Ok(());
        }

        // Apply BUDS filtering
        let (filtered_txs, filter_stats) = self.filter_transactions(&template.transactions);

        if filter_stats.removed > 0 {
            let _ = self.event_tx.send(TemplateEvent::TransactionsFiltered {
                original_count: filter_stats.original,
                filtered_count: filter_stats.kept,
                removed_fees: filter_stats.removed_fees,
            });

            info!(
                original = filter_stats.original,
                kept = filter_stats.kept,
                removed = filter_stats.removed,
                removed_fees = filter_stats.removed_fees,
                "Filtered transactions by policy"
            );
        }

        // Calculate total fees and weight
        let total_fees: u64 = filtered_txs.iter().map(|tx| tx.fee).sum();
        let total_weight: u64 = filtered_txs.iter().map(|tx| tx.weight).sum();

        // Generate new job ID
        let job_id = {
            let mut counter = self.job_counter.write();
            *counter += 1;
            format!("{:08x}", *counter)
        };

        // Build merkle tree
        let merkle_branches = self.build_merkle_branches(&filtered_txs);

        // H-MINE-2: Capture payout snapshot ATOMICALLY at template creation time
        // This prevents TOCTOU race conditions where the approved payout could change
        // between template creation and coinbase building
        let payout_snapshot = *self.approved_payout.read();

        // Build coinbase transaction parts (uses approved payout if available)
        // Returns NON-WITNESS serialization for TXID computation + separate witness data
        // Also returns serialized outputs for TDP to send to SRI Pool
        //
        // Note: template.coinbasevalue from Bitcoin Core includes subsidy + ALL original tx fees
        // but we may have filtered some transactions, so we calculate the correct value:
        // subsidy (from halving schedule) + filtered tx fees
        let subsidy = Self::calculate_subsidy(template.height);
        let coinbase_value = subsidy + total_fees;
        // H-MINE-2: Pass snapshot to coinbase builder to use consistent payout data
        let (
            coinbase1,
            coinbase2,
            witness_data,
            coinbase_outputs_serialized,
            coinbase_outputs_count,
        ) = self.build_coinbase_parts_with_payout_snapshot(
            template.height,
            coinbase_value,
            &template.default_witness_commitment,
            payout_snapshot,
        );

        // Create work state
        // Note: template.coinbasevalue from Bitcoin Core = subsidy + all tx fees
        // We store just the tx fees separately for payout calculations
        let work = WorkState {
            job_id: job_id.clone(),
            prev_hash: self.reverse_hex(&template.previousblockhash),
            coinbase1,
            coinbase2,
            witness_data,
            merkle_branches,
            version: template.version,
            nbits: template.bits.clone(),
            ntime: template.curtime as u32,
            height: template.height,
            total_fees, // Just the TX fees, NOT coinbasevalue (which includes subsidy)
            tx_count: filtered_txs.len() + 1, // +1 for coinbase
            total_weight,
            template: template.clone(),
            coinbase_outputs_serialized,
            coinbase_outputs_count,
            payout_snapshot, // H-MINE-2: Store snapshot for consistent coinbase reconstruction
        };

        *self.current_work.write() = Some(work);

        let _ = self.event_tx.send(TemplateEvent::NewWork {
            job_id,
            height: template.height,
        });

        debug!(
            height = template.height,
            txs = filtered_txs.len(),
            fees = total_fees,
            "New block template"
        );

        Ok(())
    }

    /// Filter transactions according to policy
    fn filter_transactions(
        &self,
        transactions: &[TemplateTransaction],
    ) -> (Vec<TemplateTransaction>, FilterStats) {
        let original_count = transactions.len();
        let mut kept = Vec::with_capacity(original_count);
        let mut removed_fees = 0u64;

        for tx in transactions {
            // Decode transaction for classification
            let tx_bytes = match hex::decode(&tx.data) {
                Ok(b) => b,
                Err(_) => {
                    removed_fees += tx.fee;
                    continue;
                }
            };

            // Parse as Bitcoin transaction
            let btc_tx: bitcoin::Transaction = match deserialize(&tx_bytes) {
                Ok(t) => t,
                Err(_) => {
                    removed_fees += tx.fee;
                    continue;
                }
            };

            // Classify transaction
            let result = self.classifier.classify(&btc_tx);
            let tier = result.tier;

            // Check if tier is allowed by policy
            if self.policy.allows_tier(tier) {
                // Additional policy checks
                let fee_rate = tx.fee as f64 / (tx.weight as f64 / 4.0);
                if fee_rate >= self.config.min_fee_rate {
                    kept.push(tx.clone());
                } else {
                    removed_fees += tx.fee;
                }
            } else {
                removed_fees += tx.fee;
                debug!(
                    txid = %tx.txid,
                    tier = ?tier,
                    "Transaction filtered by policy"
                );
            }
        }

        let stats = FilterStats {
            original: original_count,
            kept: kept.len(),
            removed: original_count - kept.len(),
            removed_fees,
        };

        (kept, stats)
    }

    /// Build merkle branches for stratum
    fn build_merkle_branches(&self, transactions: &[TemplateTransaction]) -> Vec<[u8; 32]> {
        if transactions.is_empty() {
            return Vec::new();
        }

        // Get transaction hashes
        let mut hashes: Vec<[u8; 32]> = transactions
            .iter()
            .map(|tx| {
                let mut hash = [0u8; 32];
                if let Ok(bytes) = hex::decode(&tx.hash) {
                    if bytes.len() == 32 {
                        hash.copy_from_slice(&bytes);
                    }
                }
                hash
            })
            .collect();

        // Build merkle tree, collecting branches
        let mut branches = Vec::new();

        while hashes.len() > 1 {
            // First hash is our branch
            if !hashes.is_empty() {
                branches.push(hashes[0]);
            }

            // Combine pairs
            let mut next_level = Vec::new();
            for chunk in hashes.chunks(2) {
                let combined = if chunk.len() == 2 {
                    self.double_sha256_pair(&chunk[0], &chunk[1])
                } else {
                    self.double_sha256_pair(&chunk[0], &chunk[0])
                };
                next_level.push(combined);
            }
            hashes = next_level;
        }

        branches
    }

    /// Double SHA256 of two hashes
    fn double_sha256_pair(&self, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(a);
        hasher.update(b);
        let first = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(first);
        let result = hasher.finalize();

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Build coinbase transaction parts
    ///
    /// Legacy method kept for Stratum V1 compatibility.
    /// Uses NON-WITNESS serialization for TXID computation.
    #[allow(dead_code)]
    fn build_coinbase_parts(
        &self,
        height: u64,
        value: u64,
        witness_commitment: &Option<String>,
    ) -> (Vec<u8>, Vec<u8>, WitnessData) {
        // Coinbase1: version + input count + prev tx + prev index + script length + height push
        // NON-WITNESS format (no marker/flag) for correct TXID computation
        let mut coinbase1 = Vec::new();

        // Version (4 bytes, little-endian)
        coinbase1.extend_from_slice(&2u32.to_le_bytes()); // Version 2 for BIP68

        // NO marker/flag - those are only for witness serialization
        // Input count
        coinbase1.push(0x01);

        // Previous tx hash (all zeros for coinbase)
        coinbase1.extend_from_slice(&[0u8; 32]);

        // Previous output index (0xffffffff for coinbase)
        coinbase1.extend_from_slice(&0xffffffffu32.to_le_bytes());

        // Script sig (height in BIP34 format + extra data)
        let height_bytes = self.encode_height(height);
        let extra = self.config.coinbase_extra.as_bytes();
        let script_len = height_bytes.len() + extra.len() + 8; // +8 for extranonce space

        coinbase1.push(script_len as u8);
        coinbase1.extend_from_slice(&height_bytes);
        coinbase1.extend_from_slice(extra);

        // Coinbase2: extranonce end + sequence + outputs + locktime
        // NO witness data - that's tracked separately
        let mut coinbase2 = Vec::new();

        // Sequence
        coinbase2.extend_from_slice(&0xffffffffu32.to_le_bytes());

        // Output count (will be 1 or 2 depending on witness commitment)
        let output_count = if witness_commitment.is_some() { 2 } else { 1 };
        coinbase2.push(output_count);

        // Main output (pool reward)
        coinbase2.extend_from_slice(&value.to_le_bytes());

        // Pool payout script
        self.encode_address_script(
            &mut coinbase2,
            &self.config.pool_payout_address,
            "pool_payout_legacy",
        );

        // Witness commitment output (if present) - this IS part of txid serialization
        let mut witness_data = WitnessData::default();
        if let Some(commitment) = witness_commitment {
            coinbase2.extend_from_slice(&0u64.to_le_bytes()); // 0 value
            if let Ok(commitment_bytes) = hex::decode(commitment) {
                coinbase2.push(commitment_bytes.len() as u8);
                coinbase2.extend_from_slice(&commitment_bytes);
                witness_data.commitment_script = Some(commitment_bytes);
            }
        }

        // Locktime (end of non-witness serialization)
        coinbase2.extend_from_slice(&0u32.to_le_bytes());

        // Witness data stored separately - NOT in coinbase2
        witness_data.nonce = [0u8; 32];

        (coinbase1, coinbase2, witness_data)
    }

    /// Encode block height for coinbase (BIP34)
    fn encode_height(&self, height: u64) -> Vec<u8> {
        let mut bytes = Vec::new();

        if height == 0 {
            bytes.push(0x01);
            bytes.push(0x00);
        } else if height <= 0x7f {
            bytes.push(0x01);
            bytes.push(height as u8);
        } else if height <= 0x7fff {
            bytes.push(0x02);
            bytes.extend_from_slice(&(height as u16).to_le_bytes());
        } else if height <= 0x7fffff {
            bytes.push(0x03);
            bytes.push((height & 0xff) as u8);
            bytes.push(((height >> 8) & 0xff) as u8);
            bytes.push(((height >> 16) & 0xff) as u8);
        } else {
            bytes.push(0x04);
            bytes.extend_from_slice(&(height as u32).to_le_bytes());
        }

        bytes
    }

    /// Reverse a hex string (for block hashes)
    fn reverse_hex(&self, hex: &str) -> String {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
            .collect();

        bytes.iter().rev().map(|b| format!("{:02x}", b)).collect()
    }

    /// Convert non-witness coinbase serialization to witness serialization
    ///
    /// Non-witness format: version(4) | input_count | inputs | output_count | outputs | locktime(4)
    /// Witness format:     version(4) | marker(1) | flag(1) | input_count | inputs | output_count | outputs | locktime(4) | witness
    ///
    /// This is needed because:
    /// - Miners compute TXID from non-witness serialization (for merkle root)
    /// - Blocks must contain witness serialization (for SegWit compatibility)
    fn convert_to_witness_serialization(
        &self,
        non_witness: &[u8],
        witness_data: &WitnessData,
    ) -> anyhow::Result<Vec<u8>> {
        if non_witness.len() < 10 {
            return Err(anyhow::anyhow!("Coinbase too short for conversion"));
        }

        let mut witness = Vec::with_capacity(non_witness.len() + 40);

        // Version (4 bytes) - copy as-is
        witness.extend_from_slice(&non_witness[0..4]);

        // Insert SegWit marker and flag
        witness.push(0x00); // marker
        witness.push(0x01); // flag

        // Copy everything from input_count to locktime (inclusive)
        // This is non_witness[4..] which contains: input_count | inputs | outputs | locktime
        witness.extend_from_slice(&non_witness[4..]);

        // Append witness stack for coinbase input
        // BIP141 coinbase witness: single 32-byte nonce (all zeros by default)
        witness.push(0x01); // witness stack count (1 item)
        witness.push(0x20); // item length (32 bytes)
        witness.extend_from_slice(&witness_data.nonce);

        Ok(witness)
    }

    /// Get current work state
    pub fn current_work(&self) -> Option<WorkState> {
        self.current_work.read().clone()
    }

    /// Store work state by template_id (for SubmitSolution lookup)
    pub fn store_work_state(&self, template_id: u64, work_state: WorkState) {
        let mut states = self.work_states.write();
        states.insert(template_id, work_state);
        // Keep only the last 10 work states to prevent memory growth
        if states.len() > 10 {
            if let Some(&oldest_id) = states.keys().min() {
                states.remove(&oldest_id);
            }
        }
    }

    /// Get work state by template_id
    pub fn get_work_state(&self, template_id: u64) -> Option<WorkState> {
        self.work_states.read().get(&template_id).cloned()
    }

    /// Get current block height
    pub fn current_height(&self) -> Option<u64> {
        self.current_work.read().as_ref().map(|w| w.height)
    }

    /// Get current block info for payout calculation
    /// Returns (subsidy_sats, tx_fees_sats, height)
    pub fn get_current_block_info(&self) -> (u64, u64, u64) {
        let work = self.current_work.read();
        match work.as_ref() {
            Some(w) => {
                // Calculate subsidy from height (Bitcoin halving schedule)
                let subsidy = Self::calculate_subsidy(w.height);
                (subsidy, w.total_fees, w.height)
            }
            None => (0, 0, 0),
        }
    }

    /// Calculate block subsidy for a given height (Bitcoin halving schedule)
    fn calculate_subsidy(height: u64) -> u64 {
        // Initial subsidy is 50 BTC = 5_000_000_000 satoshis
        // Halving every 210,000 blocks
        const INITIAL_SUBSIDY: u64 = 5_000_000_000;
        const HALVING_INTERVAL: u64 = 210_000;

        let halvings = height / HALVING_INTERVAL;
        if halvings >= 64 {
            return 0; // After 64 halvings, subsidy is 0
        }

        INITIAL_SUBSIDY >> halvings
    }

    /// Submit a solved block
    ///
    /// Assembles the complete block from:
    /// - 80-byte block header
    /// - Coinbase transaction
    /// - Other transactions from the template
    ///
    /// Performs validation before submitting:
    /// - Header length must be exactly 80 bytes
    /// - Previous block hash must match current template
    /// - Block version must be valid
    /// - Block weight must be within limits (4M WU)
    pub async fn submit_block(
        &self,
        coinbase_non_witness: &[u8],
        header: &[u8],
    ) -> anyhow::Result<()> {
        // Get current work state for transaction data
        let work = self
            .current_work
            .read()
            .clone()
            .ok_or_else(|| anyhow::anyhow!("No active work state"))?;

        // === BLOCK VALIDATION BEFORE SUBMISSION ===

        // 1. Validate header length
        if header.len() != 80 {
            return Err(anyhow::anyhow!(
                "Invalid header length: {} (expected 80)",
                header.len()
            ));
        }

        // 2. Validate previous block hash matches template
        // Header bytes 4-36 contain previousblockhash (little-endian)
        let prev_hash_from_header: String = header[4..36]
            .iter()
            .rev()
            .map(|b| format!("{:02x}", b))
            .collect();

        if prev_hash_from_header != work.template.previousblockhash {
            error!(
                expected = %work.template.previousblockhash,
                found = %prev_hash_from_header,
                "Block previousblockhash mismatch - possible stale work"
            );
            return Err(anyhow::anyhow!(
                "Block previousblockhash mismatch: expected {}, got {}",
                work.template.previousblockhash,
                prev_hash_from_header
            ));
        }

        // 3. Validate block version (bytes 0-4, little-endian)
        let version = u32::from_le_bytes(header[0..4].try_into().unwrap());
        // Version 0 is invalid, and versions above 0x3FFFFFFF are reserved for BIP9
        if version == 0 || version > 0x3FFFFFFF {
            error!(version = version, "Invalid block version");
            return Err(anyhow::anyhow!("Invalid block version: {}", version));
        }

        // 4. Convert non-witness coinbase to witness serialization
        // The coinbase passed in is non-witness format (for TXID computation)
        // We need to add marker, flag, and witness data for block submission
        let coinbase_witness =
            self.convert_to_witness_serialization(coinbase_non_witness, &work.witness_data)?;

        // Assemble the full block
        let mut block_data = Vec::new();

        // 1. Block header (80 bytes) - already validated
        block_data.extend_from_slice(header);

        // 2. Transaction count (varint)
        let tx_count = work.tx_count;
        if tx_count < 0xfd {
            block_data.push(tx_count as u8);
        } else if tx_count <= 0xffff {
            block_data.push(0xfd);
            block_data.extend_from_slice(&(tx_count as u16).to_le_bytes());
        } else {
            block_data.push(0xfe);
            block_data.extend_from_slice(&(tx_count as u32).to_le_bytes());
        }

        // 3. Coinbase transaction (witness serialization)
        block_data.extend_from_slice(&coinbase_witness);

        // 4. Other transactions from template
        for tx in &work.template.transactions {
            if let Ok(tx_bytes) = hex::decode(&tx.data) {
                block_data.extend_from_slice(&tx_bytes);
            }
        }

        // 5. Validate block weight (max 4M weight units per BIP141)
        // Coinbase weight: non-witness bytes * 4 + witness bytes * 1
        let coinbase_non_witness_len = coinbase_non_witness.len();
        let coinbase_witness_extra = coinbase_witness.len() - coinbase_non_witness_len;
        let coinbase_weight = (coinbase_non_witness_len * 4 + coinbase_witness_extra) as u64;

        // Total weight = coinbase weight + transaction weights from template
        let total_weight = coinbase_weight + work.total_weight;

        const MAX_BLOCK_WEIGHT: u64 = 4_000_000; // 4M weight units (BIP141)
        const MIN_BLOCK_SIZE: usize = 81; // 80 byte header + 1 byte tx count minimum

        if block_data.len() < MIN_BLOCK_SIZE {
            error!(size = block_data.len(), "Block too small");
            return Err(anyhow::anyhow!(
                "Block too small: {} bytes (minimum {})",
                block_data.len(),
                MIN_BLOCK_SIZE
            ));
        }

        if total_weight > MAX_BLOCK_WEIGHT {
            error!(weight = total_weight, "Block weight exceeds limit");
            return Err(anyhow::anyhow!(
                "Block weight {} exceeds maximum {}",
                total_weight,
                MAX_BLOCK_WEIGHT
            ));
        }

        let block_hex = hex::encode(&block_data);
        info!(
            height = work.height,
            tx_count = tx_count,
            block_size = block_data.len(),
            block_weight = total_weight,
            prev_hash = %prev_hash_from_header,
            "Block validated, submitting to Bitcoin Core"
        );

        match self.rpc.submit_block(&block_hex).await {
            Ok(None) => {
                info!(height = work.height, "Block accepted!");
                Ok(())
            }
            Ok(Some(rejection)) => {
                warn!(height = work.height, reason = %rejection, "Block rejected");
                Err(anyhow::anyhow!("Block rejected: {}", rejection))
            }
            Err(e) => {
                error!(height = work.height, error = %e, "Block submission failed");
                Err(anyhow::anyhow!("Submission failed: {}", e))
            }
        }
    }

    /// Submit a block using the original witness coinbase from SRI
    ///
    /// This method is used when receiving a SubmitSolution from SRI Pool.
    /// SRI sends us the complete witness coinbase it constructed, so we use
    /// it directly instead of reconstructing the witness data.
    ///
    /// Arguments:
    /// - coinbase_witness: The original witness coinbase from SRI (for block data)
    /// - coinbase_non_witness: The stripped non-witness coinbase (for weight calculation)
    /// - header: The 80-byte block header
    pub async fn submit_block_with_coinbase(
        &self,
        coinbase_witness: &[u8],
        coinbase_non_witness: &[u8],
        header: &[u8],
    ) -> anyhow::Result<()> {
        // Get current work state for transaction data
        let work = self
            .current_work
            .read()
            .clone()
            .ok_or_else(|| anyhow::anyhow!("No active work state"))?;

        // === BLOCK VALIDATION BEFORE SUBMISSION ===

        // 1. Validate header length
        if header.len() != 80 {
            return Err(anyhow::anyhow!(
                "Invalid header length: {} (expected 80)",
                header.len()
            ));
        }

        // 2. Validate previous block hash matches template
        let prev_hash_from_header: String = header[4..36]
            .iter()
            .rev()
            .map(|b| format!("{:02x}", b))
            .collect();

        if prev_hash_from_header != work.template.previousblockhash {
            error!(
                expected = %work.template.previousblockhash,
                found = %prev_hash_from_header,
                "Block previousblockhash mismatch - possible stale work"
            );
            return Err(anyhow::anyhow!(
                "Block previousblockhash mismatch: expected {}, got {}",
                work.template.previousblockhash,
                prev_hash_from_header
            ));
        }

        // 3. Validate block version
        let version = u32::from_le_bytes(header[0..4].try_into().unwrap());
        if version == 0 || version > 0x3FFFFFFF {
            error!(version = version, "Invalid block version");
            return Err(anyhow::anyhow!("Invalid block version: {}", version));
        }

        // Assemble the full block using the ORIGINAL witness coinbase from SRI
        let mut block_data = Vec::new();

        // 1. Block header (80 bytes)
        block_data.extend_from_slice(header);

        // 2. Transaction count (varint)
        let tx_count = work.tx_count;
        if tx_count < 0xfd {
            block_data.push(tx_count as u8);
        } else if tx_count <= 0xffff {
            block_data.push(0xfd);
            block_data.extend_from_slice(&(tx_count as u16).to_le_bytes());
        } else {
            block_data.push(0xfe);
            block_data.extend_from_slice(&(tx_count as u32).to_le_bytes());
        }

        // 3. Coinbase transaction - use the ORIGINAL witness coinbase from SRI
        block_data.extend_from_slice(coinbase_witness);

        // 4. Other transactions from template
        for tx in &work.template.transactions {
            if let Ok(tx_bytes) = hex::decode(&tx.data) {
                block_data.extend_from_slice(&tx_bytes);
            }
        }

        // 5. Validate block weight
        let coinbase_non_witness_len = coinbase_non_witness.len();
        let coinbase_witness_extra = coinbase_witness.len() - coinbase_non_witness_len;
        let coinbase_weight = (coinbase_non_witness_len * 4 + coinbase_witness_extra) as u64;
        let total_weight = coinbase_weight + work.total_weight;

        const MAX_BLOCK_WEIGHT: u64 = 4_000_000;
        const MIN_BLOCK_SIZE: usize = 81;

        if block_data.len() < MIN_BLOCK_SIZE {
            error!(size = block_data.len(), "Block too small");
            return Err(anyhow::anyhow!(
                "Block too small: {} bytes (minimum {})",
                block_data.len(),
                MIN_BLOCK_SIZE
            ));
        }

        if total_weight > MAX_BLOCK_WEIGHT {
            error!(weight = total_weight, "Block weight exceeds limit");
            return Err(anyhow::anyhow!(
                "Block weight {} exceeds maximum {}",
                total_weight,
                MAX_BLOCK_WEIGHT
            ));
        }

        let block_hex = hex::encode(&block_data);
        info!(
            height = work.height,
            tx_count = tx_count,
            block_size = block_data.len(),
            block_weight = total_weight,
            coinbase_witness_len = coinbase_witness.len(),
            prev_hash = %prev_hash_from_header,
            "Block validated, submitting to Bitcoin Core (using SRI coinbase)"
        );

        match self.rpc.submit_block(&block_hex).await {
            Ok(None) => {
                info!(height = work.height, "Block accepted!");
                Ok(())
            }
            Ok(Some(rejection)) => {
                warn!(height = work.height, reason = %rejection, "Block rejected");
                Err(anyhow::anyhow!("Block rejected: {}", rejection))
            }
            Err(e) => {
                error!(height = work.height, error = %e, "Block submission failed");
                Err(anyhow::anyhow!("Submission failed: {}", e))
            }
        }
    }
}

/// Filter statistics
#[derive(Debug, Clone)]
struct FilterStats {
    original: usize,
    kept: usize,
    removed: usize,
    removed_fees: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_height_encoding() {
        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        let processor =
            TemplateProcessor::new(TemplateConfig::default(), rpc, PolicyProfile::permissive());

        // Test various heights
        assert_eq!(processor.encode_height(0), vec![0x01, 0x00]);
        assert_eq!(processor.encode_height(1), vec![0x01, 0x01]);
        assert_eq!(processor.encode_height(127), vec![0x01, 0x7f]);
        assert_eq!(processor.encode_height(256), vec![0x02, 0x00, 0x01]);
    }

    #[test]
    fn test_reverse_hex() {
        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        let processor =
            TemplateProcessor::new(TemplateConfig::default(), rpc, PolicyProfile::permissive());

        let hex = "0102030405060708";
        let reversed = processor.reverse_hex(hex);
        assert_eq!(reversed, "0807060504030201");
    }

    #[test]
    fn test_witness_conversion() {
        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        let processor =
            TemplateProcessor::new(TemplateConfig::default(), rpc, PolicyProfile::permissive());

        // Create a minimal non-witness coinbase:
        // version(4) | input_count(1) | prev_hash(32) | prev_index(4) | scriptsig_len(1) | scriptsig(4) | sequence(4) | output_count(1) | value(8) | scriptpubkey_len(1) | scriptpubkey(22) | locktime(4)
        let mut non_witness = Vec::new();
        non_witness.extend_from_slice(&2u32.to_le_bytes()); // version
        non_witness.push(0x01); // input count
        non_witness.extend_from_slice(&[0u8; 32]); // prev hash
        non_witness.extend_from_slice(&0xffffffffu32.to_le_bytes()); // prev index
        non_witness.push(0x04); // scriptsig len
        non_witness.extend_from_slice(&[0x03, 0x01, 0x02, 0x03]); // scriptsig (height)
        non_witness.extend_from_slice(&0xffffffffu32.to_le_bytes()); // sequence
        non_witness.push(0x01); // output count
        non_witness.extend_from_slice(&50_0000_0000u64.to_le_bytes()); // value (50 BTC)
        non_witness.push(22); // scriptpubkey len (P2WPKH)
        non_witness.extend_from_slice(&[0x00, 0x14]); // OP_0 PUSH20
        non_witness.extend_from_slice(&[0xab; 20]); // pubkey hash
        non_witness.extend_from_slice(&0u32.to_le_bytes()); // locktime

        let witness_data = WitnessData {
            commitment_script: None,
            nonce: [0u8; 32],
        };

        let witness = processor
            .convert_to_witness_serialization(&non_witness, &witness_data)
            .unwrap();

        // Witness serialization should be:
        // version(4) | marker(1) | flag(1) | rest... | witness_stack
        assert_eq!(&witness[0..4], &non_witness[0..4]); // version unchanged
        assert_eq!(witness[4], 0x00); // marker
        assert_eq!(witness[5], 0x01); // flag
        assert_eq!(&witness[6..6 + (non_witness.len() - 4)], &non_witness[4..]); // rest of tx

        // Last 34 bytes should be witness: stack_count(1) + item_len(1) + nonce(32)
        let witness_start = witness.len() - 34;
        assert_eq!(witness[witness_start], 0x01); // stack count
        assert_eq!(witness[witness_start + 1], 0x20); // item len (32)
        assert_eq!(&witness[witness_start + 2..], &[0u8; 32]); // nonce
    }

    #[test]
    fn test_coinbase_non_witness_format() {
        // Verify coinbase1/coinbase2 do NOT include marker/flag/witness
        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        let processor = TemplateProcessor::new(
            TemplateConfig {
                pool_payout_address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                ..Default::default()
            },
            rpc,
            PolicyProfile::permissive(),
        );

        let (coinbase1, coinbase2, _witness_data) = processor.build_coinbase_parts(
            800_000,
            312_500_000, // 3.125 BTC
            &None,
        );

        // coinbase1 should start with version (4 bytes), then input_count (NOT marker/flag)
        // Version 2 = 0x02000000 in little-endian
        assert_eq!(&coinbase1[0..4], &[0x02, 0x00, 0x00, 0x00]);
        // Next byte should be input_count (0x01), NOT marker (0x00)
        assert_eq!(coinbase1[4], 0x01);

        // coinbase2 should end with locktime (4 bytes), NOT witness data
        let len = coinbase2.len();
        assert_eq!(&coinbase2[len - 4..], &[0x00, 0x00, 0x00, 0x00]); // locktime = 0
    }
}
