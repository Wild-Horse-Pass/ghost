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
//| FILE: coordinator.rs                                                                        |
//|======================================================================================================================|

//! Pool coordinator - orchestrates pool operations.
//!
//! The coordinator manages the overall pool lifecycle:
//! - Creates jobs when new blocks are found
//! - Distributes work to miners
//! - Collects and validates shares
//! - Reports found blocks

use std::sync::Arc;
use serde::{Deserialize, Serialize};

use ghost_primitives::{NodeId, BlockHash, types::PayoutAddress};
use crate::job::{JobId, JobManager, JobBuilder, MiningJob};
use crate::share::{ShareSubmission, ShareValidator, ShareAggregator, ValidatedShare};
use crate::miner::{MinerId, MinerManager, Miner, PayoutCommitment, PoolSecretError};
use crate::difficulty::{DifficultyConfig, DifficultyAdjuster};
use crate::stratum::JobNotification;
use crate::error::PoolError;

/// Maximum number of found blocks to keep in memory.
/// SECURITY: Prevents memory exhaustion if block submissions repeatedly fail.
/// Each FoundBlock contains the full block hex (up to 4MB), so 100 blocks = 400MB max.
const MAX_FOUND_BLOCKS: usize = 100;

/// Default max retry attempts for block submission before giving up.
const DEFAULT_MAX_RETRY_ATTEMPTS: u32 = 5;

/// Pool configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    /// Pool name.
    pub name: String,
    /// Pool operator's node ID.
    pub node_id: NodeId,
    /// Pool fee (0.0 to 1.0).
    pub pool_fee: f64,
    /// Maximum connected miners.
    pub max_miners: usize,
    /// Extranonce1 size in bytes.
    pub extranonce1_size: usize,
    /// Extranonce2 size in bytes.
    pub extranonce2_size: usize,
    /// Job TTL in seconds.
    pub job_ttl_secs: i64,
    /// Maximum active jobs.
    pub max_jobs: usize,
    /// Difficulty configuration.
    pub difficulty_config: DifficultyConfig,
    /// Miner idle timeout in seconds.
    pub miner_idle_timeout_secs: i64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            name: "Ghost Pool".into(),
            node_id: NodeId::from_bytes([0u8; 32]),
            pool_fee: 0.0, // No pool fee by default
            max_miners: 10_000,
            extranonce1_size: 4,
            extranonce2_size: 4,
            job_ttl_secs: 120,
            max_jobs: 100,
            difficulty_config: DifficultyConfig::default(),
            miner_idle_timeout_secs: 600, // 10 minutes
        }
    }
}

/// Pool statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolStats {
    /// Pool name.
    pub name: String,
    /// Connected miners.
    pub connected_miners: u32,
    /// Active miners (authorized).
    pub active_miners: u32,
    /// Total hashrate (H/s).
    pub total_hashrate: f64,
    /// Shares submitted.
    pub shares_submitted: u64,
    /// Valid shares.
    pub valid_shares: u64,
    /// Stale shares.
    pub stale_shares: u64,
    /// Blocks found.
    pub blocks_found: u64,
    /// Current block height.
    pub current_height: u64,
    /// Uptime in seconds.
    pub uptime_secs: i64,
}

/// Block submission status for tracking.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BlockSubmissionStatus {
    /// Block found but not yet submitted.
    Pending,
    /// Block submitted successfully to Bitcoin Core.
    Submitted,
    /// Block submission failed.
    Failed,
    /// Block accepted by network.
    Accepted,
    /// Block rejected by network.
    Rejected,
}

impl Default for BlockSubmissionStatus {
    fn default() -> Self {
        Self::Pending
    }
}

/// A found block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundBlock {
    /// Block hash.
    pub hash: BlockHash,
    /// Block height.
    pub height: u64,
    /// Miner who found it.
    pub miner_id: MinerId,
    /// Cryptographic payout commitment (Fix 3).
    /// Binds the payout address cryptographically to prevent spoofing.
    pub payout_commitment: PayoutCommitment,
    /// Job ID.
    pub job_id: JobId,
    /// Timestamp.
    pub found_at: i64,
    /// Serialized block data (hex) for submission to Bitcoin Core.
    pub block_hex: String,
    /// Number of submission attempts (HIGH: tracking for retry/alerting).
    #[serde(default)]
    pub submission_attempts: u32,
    /// Current submission status.
    #[serde(default)]
    pub status: BlockSubmissionStatus,
    /// Last submission error message (if any).
    #[serde(default)]
    pub last_error: Option<String>,
    /// Timestamp of last submission attempt.
    #[serde(default)]
    pub last_submission_at: Option<i64>,
}

impl FoundBlock {
    /// Get the payout address from the commitment.
    pub fn payout_address(&self) -> &PayoutAddress {
        &self.payout_commitment.address
    }

    /// Record a successful submission.
    pub fn record_submission_success(&mut self) {
        self.submission_attempts += 1;
        self.status = BlockSubmissionStatus::Submitted;
        self.last_error = None;
        self.last_submission_at = Some(chrono::Utc::now().timestamp());
    }

    /// Record a submission failure.
    pub fn record_submission_failure(&mut self, error: String) {
        self.submission_attempts += 1;
        self.status = BlockSubmissionStatus::Failed;
        self.last_error = Some(error);
        self.last_submission_at = Some(chrono::Utc::now().timestamp());
    }

    /// Record that the block was accepted by the network.
    pub fn record_accepted(&mut self) {
        self.status = BlockSubmissionStatus::Accepted;
    }

    /// Record that the block was rejected by the network.
    pub fn record_rejected(&mut self, reason: String) {
        self.status = BlockSubmissionStatus::Rejected;
        self.last_error = Some(reason);
    }

    /// Check if the block should be retried.
    ///
    /// Returns true if the block failed and hasn't exceeded max attempts.
    pub fn should_retry(&self, max_attempts: u32) -> bool {
        self.status == BlockSubmissionStatus::Failed
            && self.submission_attempts < max_attempts
    }

    /// Check if the block is pending submission.
    pub fn is_pending(&self) -> bool {
        self.status == BlockSubmissionStatus::Pending
    }
}

/// Mining pool coordinator.
pub struct PoolCoordinator {
    /// Configuration.
    config: PoolConfig,
    /// Job manager.
    jobs: JobManager,
    /// Miner manager.
    miners: MinerManager,
    /// Share validator.
    share_validator: ShareValidator,
    /// Share aggregator.
    shares: ShareAggregator,
    /// Difficulty adjuster.
    difficulty: DifficultyAdjuster,
    /// Current block height.
    current_height: u64,
    /// Network difficulty.
    network_difficulty: f64,
    /// Found blocks.
    found_blocks: Vec<FoundBlock>,
    /// Pending job notifications for each miner.
    pending_notifications: Vec<(MinerId, JobNotification)>,
    /// Statistics.
    stats: PoolStatsInner,
    /// Start time.
    started_at: i64,
}

#[derive(Debug, Default)]
struct PoolStatsInner {
    shares_submitted: u64,
    valid_shares: u64,
    stale_shares: u64,
    invalid_shares: u64,
    blocks_found: u64,
}

impl PoolCoordinator {
    /// Create a new pool coordinator.
    pub fn new(config: PoolConfig) -> Self {
        let now = chrono::Utc::now().timestamp();

        Self {
            jobs: JobManager::new(config.max_jobs),
            miners: MinerManager::new(config.max_miners, config.extranonce1_size),
            share_validator: ShareValidator::new(1.0),
            shares: ShareAggregator::new(),
            difficulty: DifficultyAdjuster::new(config.difficulty_config.clone()),
            current_height: 0,
            network_difficulty: 1.0,
            found_blocks: Vec::new(),
            pending_notifications: Vec::new(),
            stats: PoolStatsInner::default(),
            started_at: now,
            config,
        }
    }

    /// Get pool configuration.
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    /// Set the pool secret for payout commitments.
    ///
    /// SECURITY: This MUST be called with a cryptographically secure secret
    /// before accepting miner authorizations. The secret is used to sign
    /// payout commitments, preventing address spoofing.
    ///
    /// # Errors
    /// Returns an error if the secret doesn't meet security requirements:
    /// - Must be at least 32 bytes
    /// - Must not be all zeros
    /// - Must have sufficient entropy
    pub fn set_pool_secret(&mut self, secret: Vec<u8>) -> Result<(), PoolSecretError> {
        self.miners.set_pool_secret(secret)
    }

    /// Register a new miner connection.
    pub fn connect_miner(&mut self) -> Result<Miner, PoolError> {
        self.miners.register_miner()
    }

    /// Authorize a miner.
    pub fn authorize_miner(
        &mut self,
        miner_id: MinerId,
        payout_address: PayoutAddress,
        worker_name: Option<String>,
    ) -> Result<f64, PoolError> {
        self.miners.authorize(&miner_id, payout_address, worker_name)?;

        // Get initial difficulty
        let difficulty = self.difficulty.initial_difficulty();
        self.miners.set_difficulty(&miner_id, difficulty)?;

        Ok(difficulty)
    }

    /// Disconnect a miner.
    pub fn disconnect_miner(&mut self, miner_id: MinerId) {
        self.miners.disconnect(&miner_id);
        self.difficulty.remove_miner(miner_id.as_u64());
    }

    /// Create a new job from block template.
    ///
    /// This creates the job and queues notifications for all connected miners.
    pub fn create_job(&mut self, builder: JobBuilder) -> Arc<MiningJob> {
        let job_id = self.jobs.next_job_id();
        let job = builder.ttl_secs(self.config.job_ttl_secs).build(job_id);

        self.jobs.add_job(job.clone());

        // Queue notifications for all authorized miners
        self.notify_all_miners(&job, false);

        Arc::new(job)
    }

    /// Create a new job and mark it as urgent (new block on network).
    ///
    /// This should be called when a new block is detected on the network.
    /// Miners should immediately abandon current work and switch to this job.
    pub fn create_urgent_job(&mut self, builder: JobBuilder) -> Arc<MiningJob> {
        let job_id = self.jobs.next_job_id();
        let job = builder.ttl_secs(self.config.job_ttl_secs).build(job_id);

        self.jobs.add_job(job.clone());

        // Queue urgent notifications for all authorized miners
        self.notify_all_miners(&job, true);

        Arc::new(job)
    }

    /// Queue job notifications for all authorized miners.
    fn notify_all_miners(&mut self, job: &MiningJob, urgent: bool) {
        let miner_ids: Vec<MinerId> = self.miners
            .authorized_miners()
            .iter()
            .map(|m| m.id)
            .collect();

        for miner_id in miner_ids {
            // Use channel_id = miner_id for simplicity
            // In a full implementation, miners might have multiple channels
            let channel_id = miner_id.as_u64() as u32;

            let notification = if urgent {
                JobNotification::UrgentNewJob {
                    job: job.to_extended_job_message(channel_id),
                    prev_hash: job.to_new_prev_hash_message(channel_id),
                }
            } else {
                JobNotification::NewJob {
                    job: job.to_extended_job_message(channel_id),
                    prev_hash: job.to_new_prev_hash_message(channel_id),
                }
            };

            self.pending_notifications.push((miner_id, notification));
        }
    }

    /// Notify a specific miner about a new job.
    pub fn notify_miner(&mut self, miner_id: MinerId, job: &MiningJob, urgent: bool) {
        let channel_id = miner_id.as_u64() as u32;

        let notification = if urgent {
            JobNotification::UrgentNewJob {
                job: job.to_extended_job_message(channel_id),
                prev_hash: job.to_new_prev_hash_message(channel_id),
            }
        } else {
            JobNotification::NewJob {
                job: job.to_extended_job_message(channel_id),
                prev_hash: job.to_new_prev_hash_message(channel_id),
            }
        };

        self.pending_notifications.push((miner_id, notification));
    }

    /// Queue a difficulty update notification for a miner.
    pub fn notify_difficulty_change(&mut self, miner_id: MinerId, new_difficulty: f64) {
        let channel_id = miner_id.as_u64() as u32;
        let notification = JobNotification::SetTarget(
            MiningJob::to_set_target_message(channel_id, new_difficulty)
        );
        self.pending_notifications.push((miner_id, notification));
    }

    /// Get the latest job.
    pub fn latest_job(&self) -> Option<Arc<MiningJob>> {
        self.jobs.latest_job()
    }

    /// Submit a share.
    pub fn submit_share(
        &mut self,
        submission: ShareSubmission,
    ) -> Result<ValidatedShare, PoolError> {
        // Get miner
        let miner = self
            .miners
            .get_miner(&submission.miner_id)
            .ok_or_else(|| PoolError::MinerNotFound(submission.miner_id.to_string()))?;

        if !miner.is_authorized() {
            return Err(PoolError::NotAuthorized);
        }

        let extranonce1 = miner.extranonce1.clone();
        let pool_difficulty = miner.difficulty;

        // Get job
        let job = self
            .jobs
            .get_job(&submission.job_id)
            .ok_or_else(|| PoolError::UnknownJob(submission.job_id.to_string()))?;

        // Validate share
        self.stats.shares_submitted += 1;

        let result = match self.share_validator.validate(
            &submission,
            &job,
            &extranonce1,
            pool_difficulty,
        ) {
            Ok(result) => {
                self.stats.valid_shares += 1;
                result
            }
            Err(PoolError::StaleShare(_)) => {
                self.stats.stale_shares += 1;
                if let Some(m) = self.miners.get_miner_mut(&submission.miner_id) {
                    m.record_stale_share();
                }
                return Err(PoolError::StaleShare(submission.job_id.to_string()));
            }
            Err(e) => {
                self.stats.invalid_shares += 1;
                if let Some(m) = self.miners.get_miner_mut(&submission.miner_id) {
                    m.record_invalid_share();
                }
                return Err(e);
            }
        };

        // Record share for miner
        if let Some(m) = self.miners.get_miner_mut(&submission.miner_id) {
            m.record_valid_share();
        }

        // Record for difficulty adjustment
        self.difficulty.record_share(submission.miner_id.as_u64());

        // Record for work tracking
        self.shares.record_share(submission.miner_id, result.difficulty);

        // Check if it's a block!
        if result.meets_network_difficulty {
            self.handle_found_block(&submission, &result, &extranonce1)?;
        }

        Ok(ValidatedShare {
            submission,
            result,
            extranonce1,
            pool_difficulty,
        })
    }

    /// Handle a found block.
    fn handle_found_block(
        &mut self,
        submission: &ShareSubmission,
        result: &crate::share::ShareResult,
        extranonce1: &[u8],
    ) -> Result<(), PoolError> {
        let miner = self
            .miners
            .get_miner(&submission.miner_id)
            .ok_or_else(|| PoolError::MinerNotFound(submission.miner_id.to_string()))?;

        // Get payout commitment (Fix 3: cryptographic binding)
        let payout_commitment = miner
            .payout_commitment
            .clone()
            .ok_or(PoolError::NotAuthorized)?;

        // Verify the commitment is valid AND not expired
        // SECURITY: Using verify_with_expiry() prevents accepting blocks from
        // miners with stale commitments that may have been compromised
        if !payout_commitment.verify_with_expiry(
            self.miners.pool_secret(),
            self.miners.commitment_expiry_secs(),
        ) {
            tracing::error!(
                "Payout commitment verification failed for miner {} (invalid signature or expired)",
                submission.miner_id
            );
            return Err(PoolError::NotAuthorized);
        }

        // Get the job to build the full block
        let job = self
            .jobs
            .get_job(&submission.job_id)
            .ok_or_else(|| PoolError::UnknownJob(submission.job_id.to_string()))?;

        // Build the complete block for submission
        let block_data = job.build_block(
            extranonce1,
            &submission.extranonce2,
            submission.nonce,
            submission.ntime,
            submission.version,
        );
        let block_hex = hex::encode(&block_data);

        let found_block = FoundBlock {
            hash: BlockHash::from_bytes(result.hash),
            height: self.current_height,
            miner_id: submission.miner_id,
            payout_commitment,
            job_id: submission.job_id,
            found_at: chrono::Utc::now().timestamp(),
            block_hex,
            submission_attempts: 0,
            status: BlockSubmissionStatus::Pending,
            last_error: None,
            last_submission_at: None,
        };

        tracing::info!(
            "Block found! Hash: {:?}, Height: {}, Miner: {}, Payout: {}, BlockSize: {} bytes",
            found_block.hash,
            found_block.height,
            found_block.miner_id,
            found_block.payout_address().as_str(),
            block_data.len()
        );

        // SECURITY: Auto-cleanup if approaching memory limit
        // This prevents unbounded growth if block submissions keep failing
        if self.found_blocks.len() >= MAX_FOUND_BLOCKS {
            tracing::warn!(
                "Found blocks at capacity ({}), triggering cleanup",
                MAX_FOUND_BLOCKS
            );
            self.cleanup_submitted_blocks(DEFAULT_MAX_RETRY_ATTEMPTS);

            // If still at capacity after cleanup, remove oldest failed block
            if self.found_blocks.len() >= MAX_FOUND_BLOCKS {
                if let Some(idx) = self.found_blocks.iter().position(|b| {
                    b.status == BlockSubmissionStatus::Failed
                }) {
                    let removed = self.found_blocks.remove(idx);
                    tracing::warn!(
                        "Removed failed block {:?} to make room for new block",
                        removed.hash
                    );
                }
            }
        }

        self.found_blocks.push(found_block);
        self.stats.blocks_found += 1;

        Ok(())
    }

    /// Check and apply difficulty retarget for a miner.
    ///
    /// If difficulty changes, queues a notification for the miner.
    pub fn check_difficulty_retarget(&mut self, miner_id: MinerId) -> Option<f64> {
        if let Some(new_diff) = self.difficulty.check_retarget(miner_id.as_u64()) {
            if let Err(e) = self.miners.set_difficulty(&miner_id, new_diff) {
                tracing::warn!(
                    "Failed to set difficulty for miner {}: {:?}",
                    miner_id, e
                );
            } else {
                // Queue difficulty change notification
                self.notify_difficulty_change(miner_id, new_diff);
            }
            Some(new_diff)
        } else {
            None
        }
    }

    /// Update block height.
    pub fn set_block_height(&mut self, height: u64) {
        self.current_height = height;
    }

    /// Update network difficulty.
    pub fn set_network_difficulty(&mut self, difficulty: f64) {
        self.network_difficulty = difficulty;
        self.share_validator.set_network_difficulty(difficulty);
    }

    /// Get pool statistics.
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            name: self.config.name.clone(),
            connected_miners: self.miners.miner_count() as u32,
            active_miners: self.miners.active_count() as u32,
            total_hashrate: self.miners.total_hashrate(),
            shares_submitted: self.stats.shares_submitted,
            valid_shares: self.stats.valid_shares,
            stale_shares: self.stats.stale_shares,
            blocks_found: self.stats.blocks_found,
            current_height: self.current_height,
            uptime_secs: chrono::Utc::now().timestamp() - self.started_at,
        }
    }

    /// Get work shares for all miners.
    pub fn work_shares(&self) -> Vec<(MinerId, f64)> {
        self.shares.miners_by_work()
    }

    /// Get found blocks.
    pub fn found_blocks(&self) -> &[FoundBlock] {
        &self.found_blocks
    }

    /// Take a found block for submission.
    ///
    /// Removes and returns the oldest found block, if any.
    /// Use this to submit blocks to Bitcoin Core.
    pub fn take_found_block(&mut self) -> Option<FoundBlock> {
        if self.found_blocks.is_empty() {
            None
        } else {
            Some(self.found_blocks.remove(0))
        }
    }

    /// Take all found blocks for submission.
    ///
    /// Removes and returns all found blocks.
    pub fn take_all_found_blocks(&mut self) -> Vec<FoundBlock> {
        std::mem::take(&mut self.found_blocks)
    }

    /// Get blocks that need submission (pending or failed with retry available).
    ///
    /// Returns references to blocks that should be submitted, without removing them.
    /// Use `record_submission_result` to update status after submission.
    pub fn blocks_to_submit(&self, max_retry_attempts: u32) -> Vec<&FoundBlock> {
        self.found_blocks
            .iter()
            .filter(|b| b.is_pending() || b.should_retry(max_retry_attempts))
            .collect()
    }

    /// Get mutable references to blocks that need submission.
    pub fn blocks_to_submit_mut(&mut self, max_retry_attempts: u32) -> Vec<&mut FoundBlock> {
        self.found_blocks
            .iter_mut()
            .filter(|b| b.is_pending() || b.should_retry(max_retry_attempts))
            .collect()
    }

    /// Record the result of a block submission attempt.
    ///
    /// HIGH: Tracks submission attempts and errors for alerting and retry logic.
    pub fn record_submission_result(
        &mut self,
        block_hash: &BlockHash,
        success: bool,
        error: Option<String>,
    ) {
        if let Some(block) = self.found_blocks.iter_mut().find(|b| &b.hash == block_hash) {
            if success {
                block.record_submission_success();
                tracing::info!(
                    "Block {} submitted successfully (attempt {})",
                    block_hash,
                    block.submission_attempts
                );
            } else {
                let err_msg = error.unwrap_or_else(|| "Unknown error".to_string());
                block.record_submission_failure(err_msg.clone());
                tracing::error!(
                    "Block {} submission failed (attempt {}): {}",
                    block_hash,
                    block.submission_attempts,
                    err_msg
                );
            }
        }
    }

    /// Get count of failed block submissions.
    pub fn failed_block_count(&self) -> usize {
        self.found_blocks
            .iter()
            .filter(|b| b.status == BlockSubmissionStatus::Failed)
            .count()
    }

    /// Get count of pending block submissions.
    pub fn pending_block_count(&self) -> usize {
        self.found_blocks
            .iter()
            .filter(|b| b.status == BlockSubmissionStatus::Pending)
            .count()
    }

    /// Remove blocks that have been successfully submitted or permanently failed.
    ///
    /// Call this periodically to clean up the found_blocks list.
    pub fn cleanup_submitted_blocks(&mut self, max_retry_attempts: u32) {
        self.found_blocks.retain(|b| {
            match b.status {
                BlockSubmissionStatus::Pending => true,
                BlockSubmissionStatus::Submitted => false, // Successfully submitted
                BlockSubmissionStatus::Failed => {
                    b.submission_attempts < max_retry_attempts // Keep for retry
                }
                BlockSubmissionStatus::Accepted => false, // Confirmed
                BlockSubmissionStatus::Rejected => false, // Give up
            }
        });
    }

    /// Get pending notifications for a specific miner.
    ///
    /// Removes and returns all pending notifications for the miner.
    pub fn take_notifications(&mut self, miner_id: MinerId) -> Vec<JobNotification> {
        let mut notifications = Vec::new();
        self.pending_notifications.retain(|(id, notif)| {
            if *id == miner_id {
                notifications.push(notif.clone());
                false
            } else {
                true
            }
        });
        notifications
    }

    /// Get all pending notifications grouped by miner.
    ///
    /// Removes and returns all pending notifications.
    pub fn take_all_notifications(&mut self) -> Vec<(MinerId, JobNotification)> {
        std::mem::take(&mut self.pending_notifications)
    }

    /// Check if there are pending notifications.
    pub fn has_pending_notifications(&self) -> bool {
        !self.pending_notifications.is_empty()
    }

    /// Get count of pending notifications.
    pub fn pending_notification_count(&self) -> usize {
        self.pending_notifications.len()
    }

    /// Clean up idle miners.
    pub fn cleanup(&mut self) {
        self.miners.cleanup_idle(self.config.miner_idle_timeout_secs);
        self.miners.cleanup_disconnected();
        self.jobs.cleanup_expired();
    }

    /// Reset shares for new round.
    pub fn reset_round(&mut self) {
        self.shares.reset();
    }

    // =========================================================================
    // Share Hash Persistence (Replay Attack Prevention)
    // =========================================================================

    /// Export share hashes for persistence before shutdown.
    ///
    /// SECURITY: Call this before shutdown to prevent replay attacks.
    /// The returned hashes should be persisted to disk and loaded on startup
    /// via `import_share_hashes()`.
    ///
    /// # Returns
    /// Vector of share hashes that should be persisted.
    pub fn export_share_hashes(&self) -> Vec<[u8; 32]> {
        self.share_validator.export_hashes()
    }

    /// Export recent share hashes (limited count) for efficient persistence.
    ///
    /// Only exports the most recent hashes up to the specified count.
    /// This is more efficient than exporting all hashes.
    ///
    /// # Arguments
    /// * `count` - Maximum number of hashes to export
    pub fn export_recent_share_hashes(&self, count: usize) -> Vec<[u8; 32]> {
        self.share_validator.recent_hashes(count)
    }

    /// Import previously persisted share hashes on startup.
    ///
    /// SECURITY: Call this on startup before accepting any share submissions
    /// to prevent replay attacks using shares from before the restart.
    ///
    /// # Arguments
    /// * `hashes` - Share hashes that were persisted before shutdown
    pub fn import_share_hashes(&mut self, hashes: impl IntoIterator<Item = [u8; 32]>) {
        let count_before = self.share_validator.tracked_count();
        self.share_validator.import_hashes(hashes);
        let count_after = self.share_validator.tracked_count();
        tracing::info!(
            "Imported {} share hashes for replay protection (total: {})",
            count_after - count_before,
            count_after
        );
    }

    /// Get count of tracked share hashes.
    pub fn tracked_share_count(&self) -> usize {
        self.share_validator.tracked_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_coordinator_creation() {
        let config = PoolConfig::default();
        let coordinator = PoolCoordinator::new(config);

        let stats = coordinator.stats();
        assert_eq!(stats.connected_miners, 0);
        assert_eq!(stats.blocks_found, 0);
    }

    #[test]
    fn test_miner_connection() {
        let config = PoolConfig::default();
        let mut coordinator = PoolCoordinator::new(config);

        // SECURITY: Must configure pool secret before authorization
        coordinator
            .set_pool_secret(b"test_pool_secret_32_bytes_long!!".to_vec())
            .expect("pool secret should be valid");

        let miner = coordinator.connect_miner().unwrap();
        assert_eq!(coordinator.stats().connected_miners, 1);

        let diff = coordinator
            .authorize_miner(miner.id, PayoutAddress::new("test"), Some("worker".into()))
            .unwrap();
        assert!(diff > 0.0);
    }
}
