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
//| FILE: job.rs                                                                                |
//|======================================================================================================================|

//! Mining job creation and management.
//!
//! Jobs are work units distributed to miners containing the data needed
//! to search for valid proof-of-work.

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::Arc;

use ghost_primitives::{BlockHash, Txid};

/// Unique identifier for a mining job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JobId(u64);

impl JobId {
    /// Create a new job ID.
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Get the inner value.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for JobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// A mining job distributed to miners.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningJob {
    /// Unique job identifier.
    pub id: JobId,
    /// Previous block hash.
    pub prev_block_hash: BlockHash,
    /// Coinbase transaction part 1 (before extranonce).
    pub coinbase1: Vec<u8>,
    /// Coinbase transaction part 2 (after extranonce).
    pub coinbase2: Vec<u8>,
    /// Merkle branches for transaction tree.
    pub merkle_branches: Vec<[u8; 32]>,
    /// Raw transaction data (excluding coinbase) for block reconstruction.
    pub transactions: Vec<Vec<u8>>,
    /// Block version.
    pub version: u32,
    /// Network difficulty bits.
    pub nbits: u32,
    /// Block timestamp.
    pub ntime: u32,
    /// Whether this job should replace all others.
    pub clean_jobs: bool,
    /// When the job was created (wall clock).
    pub created_at: i64,
    /// When the job expires (wall clock).
    pub expires_at: i64,
    /// Job TTL in seconds (used for monotonic expiration check).
    #[serde(default = "default_job_ttl")]
    pub ttl_secs: i64,
    /// Monotonic creation time (seconds since process start).
    /// SECURITY: Prevents clock manipulation from accepting expired jobs.
    #[serde(skip, default)]
    pub monotonic_created_at: Option<u64>,
}

fn default_job_ttl() -> i64 {
    120 // 2 minutes default
}

use once_cell::sync::Lazy;

/// Global monotonic time reference for job expiration.
static JOB_MONOTONIC_START: Lazy<std::time::Instant> = Lazy::new(std::time::Instant::now);

/// Get current monotonic time in seconds since process start.
fn get_monotonic_secs() -> u64 {
    JOB_MONOTONIC_START.elapsed().as_secs()
}

impl MiningJob {
    /// Check if the job has expired.
    ///
    /// SECURITY: Uses both wall clock and monotonic time to detect clock manipulation.
    /// If either check says expired, the job is expired.
    pub fn is_expired(&self) -> bool {
        // Wall clock check
        let wall_expired = chrono::Utc::now().timestamp() > self.expires_at;

        // Monotonic time check (if available)
        let monotonic_expired = if let Some(created_at) = self.monotonic_created_at {
            let now = get_monotonic_secs();
            now > created_at + self.ttl_secs as u64
        } else {
            // Deserialized jobs don't have monotonic time, fall back to wall clock only
            false
        };

        // Expired if EITHER check says expired
        wall_expired || monotonic_expired
    }

    /// Calculate the coinbase transaction hash.
    pub fn coinbase_hash(&self, extranonce1: &[u8], extranonce2: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.coinbase1);
        hasher.update(extranonce1);
        hasher.update(extranonce2);
        hasher.update(&self.coinbase2);
        let first = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(first);
        hasher.finalize().into()
    }

    /// Calculate the merkle root.
    pub fn merkle_root(&self, coinbase_hash: &[u8; 32]) -> [u8; 32] {
        let mut current = *coinbase_hash;

        for branch in &self.merkle_branches {
            let mut hasher = Sha256::new();
            hasher.update(current);
            hasher.update(branch);
            let first = hasher.finalize();

            let mut hasher = Sha256::new();
            hasher.update(first);
            current = hasher.finalize().into();
        }

        current
    }

    /// Build the complete coinbase transaction.
    pub fn build_coinbase(&self, extranonce1: &[u8], extranonce2: &[u8]) -> Vec<u8> {
        let mut coinbase = Vec::with_capacity(
            self.coinbase1.len() + extranonce1.len() + extranonce2.len() + self.coinbase2.len()
        );
        coinbase.extend_from_slice(&self.coinbase1);
        coinbase.extend_from_slice(extranonce1);
        coinbase.extend_from_slice(extranonce2);
        coinbase.extend_from_slice(&self.coinbase2);
        coinbase
    }

    /// Build a complete serialized block for submission to Bitcoin Core.
    ///
    /// This reconstructs the full block from the job and miner submission data.
    /// Returns the block as raw bytes (use hex::encode for submitblock RPC).
    pub fn build_block(
        &self,
        extranonce1: &[u8],
        extranonce2: &[u8],
        nonce: u32,
        ntime: u32,
        version: Option<u32>, // For version rolling
    ) -> Vec<u8> {
        // Use version rolling if provided, otherwise use job version
        let block_version = version.unwrap_or(self.version);

        // Build coinbase transaction
        let coinbase = self.build_coinbase(extranonce1, extranonce2);

        // Calculate coinbase hash and merkle root
        let coinbase_hash = self.coinbase_hash(extranonce1, extranonce2);
        let merkle_root = self.merkle_root(&coinbase_hash);

        // Build block header (80 bytes)
        let mut block = Vec::new();

        // Version (4 bytes, little-endian)
        block.extend_from_slice(&block_version.to_le_bytes());

        // Previous block hash (32 bytes, internal byte order)
        block.extend_from_slice(self.prev_block_hash.as_bytes());

        // Merkle root (32 bytes)
        block.extend_from_slice(&merkle_root);

        // Timestamp (4 bytes, little-endian)
        block.extend_from_slice(&ntime.to_le_bytes());

        // Difficulty bits (4 bytes, little-endian)
        block.extend_from_slice(&self.nbits.to_le_bytes());

        // Nonce (4 bytes, little-endian)
        block.extend_from_slice(&nonce.to_le_bytes());

        // Transaction count (varint)
        let tx_count = 1 + self.transactions.len(); // coinbase + regular txs
        write_varint(&mut block, tx_count as u64);

        // Coinbase transaction
        block.extend_from_slice(&coinbase);

        // Other transactions
        for tx_data in &self.transactions {
            block.extend_from_slice(tx_data);
        }

        block
    }

    /// Build a block and return its hash along with the serialized data.
    ///
    /// Returns (block_hash, serialized_block).
    pub fn build_block_with_hash(
        &self,
        extranonce1: &[u8],
        extranonce2: &[u8],
        nonce: u32,
        ntime: u32,
        version: Option<u32>,
    ) -> ([u8; 32], Vec<u8>) {
        let block = self.build_block(extranonce1, extranonce2, nonce, ntime, version);

        // Block hash is double SHA256 of the 80-byte header
        let header = &block[..80];
        let mut hasher = Sha256::new();
        hasher.update(header);
        let first = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(first);
        let hash: [u8; 32] = hasher.finalize().into();

        (hash, block)
    }
}

/// Write a Bitcoin varint to the buffer.
fn write_varint(buf: &mut Vec<u8>, value: u64) {
    if value < 0xFD {
        buf.push(value as u8);
    } else if value <= 0xFFFF {
        buf.push(0xFD);
        buf.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xFFFFFFFF {
        buf.push(0xFE);
        buf.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&value.to_le_bytes());
    }
}

/// Builder for creating mining jobs.
#[derive(Debug)]
pub struct JobBuilder {
    prev_block_hash: Option<BlockHash>,
    transactions: Vec<TransactionData>,
    block_reward: u64,
    coinbase_outputs: Vec<CoinbaseOutput>,
    version: u32,
    nbits: u32,
    job_ttl_secs: i64,
    /// Block height for BIP34 compliance.
    block_height: u32,
    /// Pool identifier to include in coinbase.
    pool_tag: Vec<u8>,
    /// Extranonce1 size in bytes.
    extranonce1_size: usize,
    /// Extranonce2 size in bytes.
    extranonce2_size: usize,
}

/// Transaction data for inclusion in a block.
#[derive(Debug, Clone)]
pub struct TransactionData {
    /// Transaction ID (hash of non-witness data).
    pub txid: Txid,
    /// Witness transaction ID (hash of all data including witness).
    /// For non-segwit transactions, this equals txid.
    pub wtxid: [u8; 32],
    /// Raw transaction bytes.
    pub data: Vec<u8>,
    /// Transaction fee in satoshis.
    pub fee: u64,
    /// Transaction weight.
    pub weight: u32,
}

/// Output to include in the coinbase transaction.
#[derive(Debug, Clone)]
pub struct CoinbaseOutput {
    /// Output script.
    pub script: Vec<u8>,
    /// Output value in satoshis.
    pub value: u64,
}

impl Default for JobBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl JobBuilder {
    /// Create a new job builder.
    pub fn new() -> Self {
        Self {
            prev_block_hash: None,
            transactions: Vec::new(),
            block_reward: 0,
            coinbase_outputs: Vec::new(),
            version: 0x20000000, // BIP9 version bits
            nbits: 0,
            job_ttl_secs: 120, // 2 minute default TTL
            block_height: 0,
            pool_tag: b"/GhostPool/".to_vec(),
            extranonce1_size: 4,
            extranonce2_size: 4,
        }
    }

    /// Set the previous block hash.
    pub fn prev_block_hash(mut self, hash: BlockHash) -> Self {
        self.prev_block_hash = Some(hash);
        self
    }

    /// Set the block version.
    pub fn version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    /// Set the difficulty bits.
    pub fn nbits(mut self, nbits: u32) -> Self {
        self.nbits = nbits;
        self
    }

    /// Set the block reward.
    pub fn block_reward(mut self, reward: u64) -> Self {
        self.block_reward = reward;
        self
    }

    /// Add a coinbase output.
    pub fn add_coinbase_output(mut self, script: Vec<u8>, value: u64) -> Self {
        self.coinbase_outputs.push(CoinbaseOutput { script, value });
        self
    }

    /// Add a transaction.
    pub fn add_transaction(mut self, tx: TransactionData) -> Self {
        self.transactions.push(tx);
        self
    }

    /// Set the job TTL.
    pub fn ttl_secs(mut self, secs: i64) -> Self {
        self.job_ttl_secs = secs;
        self
    }

    /// Set the block height for BIP34 compliance.
    pub fn block_height(mut self, height: u32) -> Self {
        self.block_height = height;
        self
    }

    /// Set the pool tag to include in coinbase.
    pub fn pool_tag(mut self, tag: Vec<u8>) -> Self {
        self.pool_tag = tag;
        self
    }

    /// Set extranonce sizes.
    pub fn extranonce_sizes(mut self, extranonce1: usize, extranonce2: usize) -> Self {
        self.extranonce1_size = extranonce1;
        self.extranonce2_size = extranonce2;
        self
    }

    /// Build the mining job.
    pub fn build(mut self, job_id: JobId) -> MiningJob {
        let prev_hash = self.prev_block_hash.unwrap_or_else(|| BlockHash::from_bytes([0u8; 32]));

        // Add witness commitment output if we have SegWit transactions
        // The witness commitment must be the LAST output in the coinbase
        if self.has_witness_transactions() {
            let witness_commitment = self.build_witness_commitment_output();
            self.coinbase_outputs.push(witness_commitment);
        }

        // Build coinbase transaction
        let coinbase1 = self.build_coinbase1();
        let coinbase2 = self.build_coinbase2();

        // Build merkle branches from transactions
        let merkle_branches = self.compute_merkle_branches();

        // Extract raw transaction data for block reconstruction
        let transactions: Vec<Vec<u8>> = self.transactions.iter()
            .map(|tx| tx.data.clone())
            .collect();

        let now = chrono::Utc::now().timestamp();

        MiningJob {
            id: job_id,
            prev_block_hash: prev_hash,
            coinbase1,
            coinbase2,
            merkle_branches,
            transactions,
            version: self.version,
            nbits: self.nbits,
            ntime: now as u32,
            clean_jobs: true,
            created_at: now,
            expires_at: now + self.job_ttl_secs,
            ttl_secs: self.job_ttl_secs,
            // SECURITY: Set monotonic time for clock manipulation protection
            monotonic_created_at: Some(get_monotonic_secs()),
        }
    }

    /// Check if any transactions have witness data.
    fn has_witness_transactions(&self) -> bool {
        // If there are any transactions, we need witness commitment
        // (Modern Bitcoin blocks essentially always have witness data)
        !self.transactions.is_empty()
    }

    /// Build the witness commitment output.
    ///
    /// Format: OP_RETURN OP_PUSHBYTES_36 0xaa21a9ed <32-byte commitment>
    /// The commitment is SHA256(SHA256(witness_root || witness_reserved))
    fn build_witness_commitment_output(&self) -> CoinbaseOutput {
        // Calculate witness root from transaction wtxids
        // Note: coinbase wtxid is 32 zero bytes
        let witness_root = self.calculate_witness_root();

        // Witness reserved value (32 zero bytes, matches what we put in coinbase witness)
        let witness_reserved = [0u8; 32];

        // Calculate commitment: SHA256(SHA256(witness_root || witness_reserved))
        let mut hasher = Sha256::new();
        hasher.update(witness_root);
        hasher.update(witness_reserved);
        let first = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(first);
        let commitment: [u8; 32] = hasher.finalize().into();

        // Build script: OP_RETURN OP_PUSHBYTES_36 0xaa21a9ed <commitment>
        let mut script = Vec::with_capacity(38);
        script.push(0x6a); // OP_RETURN
        script.push(0x24); // OP_PUSHBYTES_36 (36 bytes follow)
        script.extend_from_slice(&[0xaa, 0x21, 0xa9, 0xed]); // Witness commitment header
        script.extend_from_slice(&commitment);

        CoinbaseOutput {
            script,
            value: 0, // Witness commitment has zero value
        }
    }

    /// Calculate the witness root from transaction wtxids.
    ///
    /// The witness root is a merkle root of all wtxids in the block,
    /// with the coinbase wtxid being 32 zero bytes.
    fn calculate_witness_root(&self) -> [u8; 32] {
        // Start with coinbase wtxid (32 zero bytes)
        let mut hashes: Vec<[u8; 32]> = vec![[0u8; 32]];

        // Add all transaction wtxids
        for tx in &self.transactions {
            hashes.push(tx.wtxid);
        }

        // Build merkle tree
        while hashes.len() > 1 {
            // Duplicate last if odd
            if hashes.len() % 2 == 1 {
                if let Some(&last) = hashes.last() {
                    hashes.push(last);
                }
            }

            let mut next_level = Vec::with_capacity(hashes.len() / 2);
            for chunk in hashes.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(chunk[0]);
                hasher.update(chunk[1]);
                let first = hasher.finalize();

                let mut hasher = Sha256::new();
                hasher.update(first);
                next_level.push(hasher.finalize().into());
            }
            hashes = next_level;
        }

        hashes.first().copied().unwrap_or([0u8; 32])
    }

    /// Build coinbase1: transaction version through the scriptSig prefix.
    ///
    /// Coinbase1 ends just before where extranonce1 will be inserted.
    /// Format:
    /// - Version (4 bytes, little-endian)
    /// - Marker + Flag (if SegWit: 0x00 0x01)
    /// - Input count (1 byte, always 0x01 for coinbase)
    /// - Null prevout txid (32 bytes of zeros)
    /// - Null prevout vout (4 bytes, 0xFFFFFFFF)
    /// - ScriptSig length (varint)
    /// - ScriptSig prefix: block height (BIP34) + pool tag
    fn build_coinbase1(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Transaction version (4 bytes, little-endian)
        // Version 2 for BIP68 relative lock-time
        data.extend_from_slice(&2u32.to_le_bytes());

        // SegWit marker and flag (for witness transactions)
        data.push(0x00); // Marker
        data.push(0x01); // Flag

        // Input count (always 1 for coinbase)
        data.push(0x01);

        // Null previous output (coinbase has no real input)
        data.extend_from_slice(&[0x00; 32]); // Null txid
        data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // Null vout index

        // Build the scriptSig content (before extranonce)
        let script_prefix = self.build_scriptsig_prefix();

        // Total scriptSig length = prefix + extranonce1 + extranonce2 + pool_tag
        let total_script_len = script_prefix.len()
            + self.extranonce1_size
            + self.extranonce2_size
            + self.pool_tag.len();

        // ScriptSig length as varint
        self.write_varint(&mut data, total_script_len as u64);

        // ScriptSig prefix (block height in BIP34 format)
        data.extend_from_slice(&script_prefix);

        data
    }

    /// Build the scriptSig prefix containing BIP34 block height.
    fn build_scriptsig_prefix(&self) -> Vec<u8> {
        let mut prefix = Vec::new();

        // BIP34: Block height must be encoded in scriptSig
        // Format: push opcode + height bytes (little-endian, minimal encoding)
        if self.block_height == 0 {
            // Special case: height 0 is OP_0
            prefix.push(0x00);
        } else if self.block_height <= 16 {
            // OP_1 through OP_16
            prefix.push(0x50 + self.block_height as u8);
        } else {
            // Encode as little-endian with minimal bytes
            let height_bytes = self.encode_height_minimal(self.block_height);
            prefix.push(height_bytes.len() as u8); // Push opcode for length
            prefix.extend_from_slice(&height_bytes);
        }

        prefix
    }

    /// Encode block height with minimal byte representation (BIP34).
    fn encode_height_minimal(&self, height: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut n = height;

        while n > 0 {
            bytes.push((n & 0xFF) as u8);
            n >>= 8;
        }

        // If the most significant bit is set, add a 0x00 byte
        // to prevent it being interpreted as negative.
        // Safety: bytes is non-empty here because we only call this when height > 16,
        // and the while loop always adds at least one byte when n > 0.
        if let Some(&last) = bytes.last() {
            if (last & 0x80) != 0 {
                bytes.push(0x00);
            }
        }

        bytes
    }

    /// Build coinbase2: from after extranonce through the end of the transaction.
    ///
    /// Format:
    /// - Remainder of scriptSig (pool tag)
    /// - Sequence (4 bytes, typically 0xFFFFFFFF)
    /// - Output count (varint)
    /// - Outputs (value + scriptPubKey for each)
    /// - Witness (empty for coinbase, just the commitment)
    /// - Locktime (4 bytes)
    fn build_coinbase2(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Pool tag (remainder of scriptSig after extranonce)
        data.extend_from_slice(&self.pool_tag);

        // Sequence number (0xFFFFFFFF for no relative lock-time)
        data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());

        // Output count (varint)
        self.write_varint(&mut data, self.coinbase_outputs.len() as u64);

        // Outputs
        for output in &self.coinbase_outputs {
            // Value (8 bytes, little-endian)
            data.extend_from_slice(&output.value.to_le_bytes());

            // ScriptPubKey length (varint)
            self.write_varint(&mut data, output.script.len() as u64);

            // ScriptPubKey
            data.extend_from_slice(&output.script);
        }

        // Witness data for coinbase (BIP141)
        // Single witness element with 32 zero bytes for witness reserved value
        data.push(0x01); // Number of witness elements
        data.push(0x20); // Length of witness element (32 bytes)
        data.extend_from_slice(&[0x00; 32]); // Witness reserved value

        // Locktime (4 bytes, typically 0 for coinbase)
        data.extend_from_slice(&0u32.to_le_bytes());

        data
    }

    /// Write a Bitcoin varint to the buffer.
    fn write_varint(&self, buf: &mut Vec<u8>, value: u64) {
        if value < 0xFD {
            buf.push(value as u8);
        } else if value <= 0xFFFF {
            buf.push(0xFD);
            buf.extend_from_slice(&(value as u16).to_le_bytes());
        } else if value <= 0xFFFFFFFF {
            buf.push(0xFE);
            buf.extend_from_slice(&(value as u32).to_le_bytes());
        } else {
            buf.push(0xFF);
            buf.extend_from_slice(&value.to_le_bytes());
        }
    }

    /// Compute merkle branches for Stratum protocol.
    ///
    /// Stratum provides merkle branches so miners can compute the merkle root
    /// by combining the coinbase hash with each branch in sequence:
    /// `merkle_root = hash(hash(hash(coinbase || branch[0]) || branch[1]) || ...)`
    ///
    /// The coinbase is always at position 0 in the transaction list.
    fn compute_merkle_branches(&self) -> Vec<[u8; 32]> {
        if self.transactions.is_empty() {
            return Vec::new();
        }

        // Build the full hash list including a placeholder for coinbase at index 0.
        // The actual coinbase hash will be computed by the miner with their extranonce.
        let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(1 + self.transactions.len());

        // Coinbase placeholder at position 0 (will be replaced by miner's coinbase hash)
        hashes.push([0u8; 32]);

        // Add all transaction txids
        for tx in &self.transactions {
            hashes.push(*tx.txid.as_bytes());
        }

        let mut branches = Vec::new();

        // Track the position of the coinbase through the tree
        // Coinbase starts at position 0
        let mut coinbase_pos = 0usize;

        while hashes.len() > 1 {
            // Duplicate last hash for odd-length levels
            if hashes.len() % 2 == 1 {
                if let Some(&last) = hashes.last() {
                    hashes.push(last);
                }
            }

            // The branch is the sibling of the coinbase at this level
            // If coinbase is at even position, sibling is at pos+1
            // If coinbase is at odd position, sibling is at pos-1
            let sibling_pos = if coinbase_pos % 2 == 0 {
                coinbase_pos + 1
            } else {
                coinbase_pos - 1
            };

            if sibling_pos < hashes.len() {
                branches.push(hashes[sibling_pos]);
            }

            // Compute next level
            let mut next_level = Vec::new();
            for chunk in hashes.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(chunk[0]);
                hasher.update(chunk[1]);
                let first = hasher.finalize();

                let mut hasher = Sha256::new();
                hasher.update(first);
                next_level.push(hasher.finalize().into());
            }
            hashes = next_level;

            // Coinbase position in next level is its current position / 2
            coinbase_pos /= 2;
        }

        branches
    }
}

/// Manager for active mining jobs.
#[derive(Debug)]
pub struct JobManager {
    /// Active jobs.
    jobs: HashMap<JobId, Arc<MiningJob>>,
    /// Next job ID.
    next_id: u64,
    /// Maximum active jobs.
    max_jobs: usize,
}

impl Default for JobManager {
    fn default() -> Self {
        Self::new(100)
    }
}

impl JobManager {
    /// Create a new job manager.
    pub fn new(max_jobs: usize) -> Self {
        Self {
            jobs: HashMap::new(),
            next_id: 1,
            max_jobs,
        }
    }

    /// Generate a new job ID.
    ///
    /// SECURITY: Wraps at MAX_JOB_ID to prevent unbounded growth that would
    /// cause Stratum validation to reject all shares after ~1M jobs.
    pub fn next_job_id(&mut self) -> JobId {
        let id = JobId::new(self.next_id);
        self.next_id += 1;

        // Wrap around at MAX_JOB_ID to prevent overflow and Stratum validation failures
        if self.next_id > ghost_primitives::MAX_JOB_ID {
            self.next_id = 1;
            tracing::info!("Job ID wrapped around to 1 (reached MAX_JOB_ID)");
        }

        id
    }

    /// Add a job.
    pub fn add_job(&mut self, job: MiningJob) {
        // Clean up expired jobs first
        self.cleanup_expired();

        // Enforce max jobs limit
        while self.jobs.len() >= self.max_jobs {
            // Remove oldest job
            if let Some(&oldest_id) = self.jobs.keys().min_by_key(|id| id.0) {
                self.jobs.remove(&oldest_id);
            }
        }

        self.jobs.insert(job.id, Arc::new(job));
    }

    /// Get a job by ID.
    pub fn get_job(&self, id: &JobId) -> Option<Arc<MiningJob>> {
        self.jobs.get(id).cloned()
    }

    /// Check if a job exists and is valid.
    pub fn is_valid_job(&self, id: &JobId) -> bool {
        self.jobs
            .get(id)
            .map(|j| !j.is_expired())
            .unwrap_or(false)
    }

    /// Get all active jobs.
    pub fn active_jobs(&self) -> Vec<Arc<MiningJob>> {
        self.jobs
            .values()
            .filter(|j| !j.is_expired())
            .cloned()
            .collect()
    }

    /// Remove expired jobs.
    pub fn cleanup_expired(&mut self) {
        self.jobs.retain(|_, job| !job.is_expired());
    }

    /// Get the most recent job.
    pub fn latest_job(&self) -> Option<Arc<MiningJob>> {
        self.jobs
            .values()
            .filter(|j| !j.is_expired())
            .max_by_key(|j| j.created_at)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_id() {
        let id = JobId::new(12345);
        assert_eq!(id.as_u64(), 12345);
        assert_eq!(format!("{}", id), "0000000000003039");
    }

    #[test]
    fn test_job_builder() {
        let job = JobBuilder::new()
            .prev_block_hash(BlockHash::from_bytes([1u8; 32]))
            .version(0x20000000)
            .nbits(0x1d00ffff)
            .block_reward(312_500_000)
            .ttl_secs(60)
            .build(JobId::new(1));

        assert_eq!(job.id, JobId::new(1));
        assert!(!job.is_expired());
    }

    #[test]
    fn test_job_manager() {
        let mut manager = JobManager::new(10);

        let job1 = JobBuilder::new().build(manager.next_job_id());
        let job2 = JobBuilder::new().build(manager.next_job_id());

        manager.add_job(job1);
        manager.add_job(job2);

        assert!(manager.is_valid_job(&JobId::new(1)));
        assert!(manager.is_valid_job(&JobId::new(2)));
        assert!(!manager.is_valid_job(&JobId::new(999)));
    }

    #[test]
    fn test_coinbase_format() {
        let job = JobBuilder::new()
            .prev_block_hash(BlockHash::from_bytes([1u8; 32]))
            .block_height(800000)
            .block_reward(312_500_000)
            .add_coinbase_output(vec![0x51], 312_500_000) // OP_1 as simple output
            .build(JobId::new(1));

        // Verify coinbase1 contains SegWit marker
        assert!(job.coinbase1.len() > 44); // Version(4) + marker(2) + inputs(1) + prevout(36) + script_len(1+)
        assert_eq!(job.coinbase1[4], 0x00); // SegWit marker
        assert_eq!(job.coinbase1[5], 0x01); // SegWit flag

        // Verify coinbase2 contains output and witness
        assert!(job.coinbase2.len() > 20); // pool_tag + seq + outputs + witness + locktime
    }

    #[test]
    fn test_bip34_height_encoding() {
        // Test various block heights
        let builder = JobBuilder::new();

        // Height 0 -> OP_0
        let prefix = JobBuilder { block_height: 0, ..builder.clone() }.build_scriptsig_prefix();
        assert_eq!(prefix, vec![0x00]);

        // Height 1 -> OP_1
        let prefix = JobBuilder { block_height: 1, ..builder.clone() }.build_scriptsig_prefix();
        assert_eq!(prefix, vec![0x51]);

        // Height 16 -> OP_16
        let prefix = JobBuilder { block_height: 16, ..builder.clone() }.build_scriptsig_prefix();
        assert_eq!(prefix, vec![0x60]);

        // Height 100 -> 0x01 0x64
        let prefix = JobBuilder { block_height: 100, ..builder.clone() }.build_scriptsig_prefix();
        assert_eq!(prefix, vec![0x01, 0x64]);

        // Height 500000 (0x7A120) -> 0x03 0x20 0xA1 0x07
        let prefix = JobBuilder { block_height: 500000, ..builder.clone() }.build_scriptsig_prefix();
        assert_eq!(prefix.len(), 4); // 1 byte length + 3 bytes data
        assert_eq!(prefix[0], 0x03); // Push 3 bytes
    }

    #[test]
    fn test_coinbase_hash_computation() {
        let job = JobBuilder::new()
            .prev_block_hash(BlockHash::from_bytes([1u8; 32]))
            .block_height(800000)
            .add_coinbase_output(vec![0x51], 312_500_000)
            .build(JobId::new(1));

        let extranonce1 = [0x12, 0x34, 0x56, 0x78];
        let extranonce2 = [0xAB, 0xCD, 0xEF, 0x00];

        let hash = job.coinbase_hash(&extranonce1, &extranonce2);

        // Hash should be 32 bytes
        assert_eq!(hash.len(), 32);

        // Same inputs should produce same hash
        let hash2 = job.coinbase_hash(&extranonce1, &extranonce2);
        assert_eq!(hash, hash2);

        // Different extranonce should produce different hash
        let extranonce2_diff = [0x00, 0x00, 0x00, 0x01];
        let hash3 = job.coinbase_hash(&extranonce1, &extranonce2_diff);
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_varint_encoding() {
        let builder = JobBuilder::new();
        let mut buf = Vec::new();

        // Test single byte encoding (< 0xFD)
        builder.write_varint(&mut buf, 100);
        assert_eq!(buf, vec![100]);

        // Test two byte encoding
        buf.clear();
        builder.write_varint(&mut buf, 0xFD);
        assert_eq!(buf, vec![0xFD, 0xFD, 0x00]);

        buf.clear();
        builder.write_varint(&mut buf, 1000);
        assert_eq!(buf, vec![0xFD, 0xE8, 0x03]); // 1000 in little-endian

        // Test four byte encoding
        buf.clear();
        builder.write_varint(&mut buf, 0x10000);
        assert_eq!(buf, vec![0xFE, 0x00, 0x00, 0x01, 0x00]);
    }

    impl Clone for JobBuilder {
        fn clone(&self) -> Self {
            Self {
                prev_block_hash: self.prev_block_hash,
                transactions: self.transactions.clone(),
                block_reward: self.block_reward,
                coinbase_outputs: self.coinbase_outputs.clone(),
                version: self.version,
                nbits: self.nbits,
                job_ttl_secs: self.job_ttl_secs,
                block_height: self.block_height,
                pool_tag: self.pool_tag.clone(),
                extranonce1_size: self.extranonce1_size,
                extranonce2_size: self.extranonce2_size,
            }
        }
    }

    #[test]
    fn test_witness_commitment_output() {
        // Create a job with transactions (which triggers witness commitment)
        let tx1 = TransactionData {
            txid: Txid::from_bytes([1u8; 32]),
            wtxid: [2u8; 32], // Different from txid to simulate segwit
            data: vec![],
            fee: 1000,
            weight: 400,
        };

        let job = JobBuilder::new()
            .prev_block_hash(BlockHash::from_bytes([1u8; 32]))
            .block_height(800000)
            .add_coinbase_output(vec![0x51], 312_500_000)
            .add_transaction(tx1)
            .build(JobId::new(1));

        // Parse coinbase2 to find the witness commitment output
        // The witness commitment should be the last output before witness data
        // It's an OP_RETURN output with format: 6a 24 aa21a9ed <32 bytes>
        let coinbase2 = &job.coinbase2;

        // Search for witness commitment marker in coinbase2
        let marker = [0xaa, 0x21, 0xa9, 0xed];
        let found = coinbase2.windows(4).any(|w| w == marker);
        assert!(found, "Witness commitment marker aa21a9ed not found in coinbase2");
    }

    #[test]
    fn test_witness_commitment_not_added_without_transactions() {
        // Create a job without transactions
        let job = JobBuilder::new()
            .prev_block_hash(BlockHash::from_bytes([1u8; 32]))
            .block_height(800000)
            .add_coinbase_output(vec![0x51], 312_500_000)
            .build(JobId::new(1));

        // Witness commitment marker should NOT be present
        let marker = [0xaa, 0x21, 0xa9, 0xed];
        let found = job.coinbase2.windows(4).any(|w| w == marker);
        assert!(!found, "Witness commitment should not be present without transactions");
    }

    #[test]
    fn test_witness_root_calculation() {
        let builder = JobBuilder::new();

        // Empty transactions -> witness root is just coinbase (zeros)
        let root = builder.calculate_witness_root();
        assert_eq!(root, [0u8; 32]);

        // With transactions
        let tx1 = TransactionData {
            txid: Txid::from_bytes([1u8; 32]),
            wtxid: [0x11u8; 32],
            data: vec![],
            fee: 1000,
            weight: 400,
        };

        let builder_with_tx = JobBuilder::new().add_transaction(tx1);
        let root = builder_with_tx.calculate_witness_root();

        // Root should not be zeros anymore
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn test_build_block() {
        // Create a job with a transaction
        let tx1 = TransactionData {
            txid: Txid::from_bytes([1u8; 32]),
            wtxid: [2u8; 32],
            data: vec![0x01, 0x02, 0x03, 0x04], // Minimal fake tx data
            fee: 1000,
            weight: 400,
        };

        let job = JobBuilder::new()
            .prev_block_hash(BlockHash::from_bytes([0xABu8; 32]))
            .block_height(800000)
            .version(0x20000000)
            .nbits(0x1d00ffff)
            .add_coinbase_output(vec![0x51], 312_500_000)
            .add_transaction(tx1)
            .build(JobId::new(1));

        let extranonce1 = [0x12, 0x34, 0x56, 0x78];
        let extranonce2 = [0xAB, 0xCD, 0xEF, 0x00];
        let nonce = 0x12345678u32;
        let ntime = 0x60000000u32;

        let block = job.build_block(&extranonce1, &extranonce2, nonce, ntime, None);

        // Block header is 80 bytes
        assert!(block.len() > 80, "Block should be > 80 bytes");

        // Verify header structure
        // Version (4 bytes)
        let version = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        assert_eq!(version, 0x20000000);

        // Previous block hash (32 bytes starting at offset 4)
        let prev_hash = &block[4..36];
        assert_eq!(prev_hash, &[0xABu8; 32]);

        // ntime (4 bytes at offset 68)
        let block_ntime = u32::from_le_bytes([block[68], block[69], block[70], block[71]]);
        assert_eq!(block_ntime, ntime);

        // nbits (4 bytes at offset 72)
        let block_nbits = u32::from_le_bytes([block[72], block[73], block[74], block[75]]);
        assert_eq!(block_nbits, 0x1d00ffff);

        // nonce (4 bytes at offset 76)
        let block_nonce = u32::from_le_bytes([block[76], block[77], block[78], block[79]]);
        assert_eq!(block_nonce, nonce);

        // Transaction count (varint at offset 80)
        // We have coinbase + 1 tx = 2 transactions
        assert_eq!(block[80], 2, "Should have 2 transactions (coinbase + 1 tx)");
    }

    #[test]
    fn test_build_block_with_hash() {
        let job = JobBuilder::new()
            .prev_block_hash(BlockHash::from_bytes([0x00u8; 32]))
            .block_height(100)
            .version(0x20000000)
            .nbits(0x1d00ffff)
            .add_coinbase_output(vec![0x51], 5000000000)
            .build(JobId::new(1));

        let extranonce1 = [0x00, 0x00, 0x00, 0x01];
        let extranonce2 = [0x00, 0x00, 0x00, 0x00];
        let nonce = 0u32;
        let ntime = 1700000000u32;

        let (hash, block) = job.build_block_with_hash(&extranonce1, &extranonce2, nonce, ntime, None);

        // Hash should be 32 bytes
        assert_eq!(hash.len(), 32);

        // Block should start with version
        assert_eq!(&block[0..4], &0x20000000u32.to_le_bytes());

        // Hash should be double SHA256 of header
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&block[..80]);
        let first = hasher.finalize();
        let mut hasher = Sha256::new();
        hasher.update(first);
        let expected_hash: [u8; 32] = hasher.finalize().into();

        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_build_coinbase() {
        let job = JobBuilder::new()
            .prev_block_hash(BlockHash::from_bytes([1u8; 32]))
            .block_height(100)
            .add_coinbase_output(vec![0x51], 5000000000)
            .build(JobId::new(1));

        let extranonce1 = [0x11, 0x22, 0x33, 0x44];
        let extranonce2 = [0x55, 0x66, 0x77, 0x88];

        let coinbase = job.build_coinbase(&extranonce1, &extranonce2);

        // Coinbase should contain both extranonces
        assert!(coinbase.len() > extranonce1.len() + extranonce2.len());

        // The coinbase should be coinbase1 + extranonce1 + extranonce2 + coinbase2
        let expected_len = job.coinbase1.len() + extranonce1.len() + extranonce2.len() + job.coinbase2.len();
        assert_eq!(coinbase.len(), expected_len);
    }
}
