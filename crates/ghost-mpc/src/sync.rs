//! P2P Parameter Synchronization
//!
//! Parameters are ~200MB - too large for broadcast messages.
//! This module handles chunked transfer of parameters between nodes.
//!
//! ## Security Features (3.10, 3.11)
//!
//! - **Per-chunk hash verification**: Each chunk is verified against its hash
//!   before storage, preventing partial corruption attacks
//! - **Rate limiting**: Chunk requests are rate-limited per-peer to prevent
//!   bandwidth exhaustion attacks

use crate::errors::{MpcError, MpcResult};
use crate::params::{hash_params_file, load_parameters, ParameterFiles};
use crate::PARAM_CHUNK_SIZE;
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::Instant;
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

/// 3.11 SECURITY: Rate limiter for chunk requests
/// Prevents bandwidth exhaustion attacks from malicious peers
struct ChunkRateLimiter {
    /// Last request time per peer (peer_id -> last_request_time)
    last_request: HashMap<[u8; 32], Instant>,
    /// Minimum interval between requests from same peer (100ms)
    min_interval_ms: u64,
    /// Maximum chunks per second per peer
    max_chunks_per_sec: u32,
    /// Request counts per peer (peer_id -> (count, window_start))
    request_counts: HashMap<[u8; 32], (u32, Instant)>,
}

impl ChunkRateLimiter {
    fn new() -> Self {
        Self {
            last_request: HashMap::new(),
            min_interval_ms: 100,
            max_chunks_per_sec: 20,
            request_counts: HashMap::new(),
        }
    }

    /// Check if request should be allowed, returns true if allowed
    fn check_and_record(&mut self, peer_id: &[u8; 32]) -> bool {
        let now = Instant::now();

        // Check minimum interval
        if let Some(last) = self.last_request.get(peer_id) {
            if now.duration_since(*last).as_millis() < self.min_interval_ms as u128 {
                return false;
            }
        }

        // Check rate limit window
        let (count, window_start) = self
            .request_counts
            .entry(*peer_id)
            .or_insert((0, now));

        // Reset window if expired (1 second)
        if now.duration_since(*window_start).as_secs() >= 1 {
            *count = 0;
            *window_start = now;
        }

        if *count >= self.max_chunks_per_sec {
            return false;
        }

        *count += 1;
        self.last_request.insert(*peer_id, now);
        true
    }

    /// Cleanup old entries (call periodically)
    fn cleanup(&mut self) {
        let now = Instant::now();
        self.last_request.retain(|_, last| now.duration_since(*last).as_secs() < 60);
        self.request_counts.retain(|_, (_, start)| now.duration_since(*start).as_secs() < 60);
    }
}

/// State of an in-progress download
struct DownloadState {
    /// Expected hash of the complete parameters
    _expected_hash: [u8; 32],
    /// Expected total size in bytes
    _total_size: u64,
    /// Chunks received (chunk index -> data)
    chunks: HashMap<u32, Vec<u8>>,
    /// 3.10: Per-chunk hashes for verification (chunk index -> expected hash)
    /// If provided, each chunk is verified before storage
    chunk_hashes: Option<HashMap<u32, [u8; 32]>>,
    /// Number of chunks expected
    total_chunks: u32,
    /// Completion notifier
    completion_tx: Option<oneshot::Sender<MpcResult<PathBuf>>>,
}

/// Parameter synchronization manager
pub struct ParameterSync {
    /// Parameter file paths
    files: ParameterFiles,
    /// In-progress downloads keyed by params hash
    pending_downloads: RwLock<HashMap<[u8; 32], DownloadState>>,
    /// 3.11: Rate limiter for chunk requests
    rate_limiter: RwLock<ChunkRateLimiter>,
}

impl ParameterSync {
    /// Create a new parameter sync manager
    pub fn new(params_dir: PathBuf) -> Self {
        Self {
            files: ParameterFiles::new(params_dir),
            pending_downloads: RwLock::new(HashMap::new()),
            rate_limiter: RwLock::new(ChunkRateLimiter::new()),
        }
    }

    /// 3.11: Check rate limit for a peer requesting chunks
    ///
    /// Returns true if the request is allowed, false if rate-limited.
    /// Call this before serving chunk requests to prevent bandwidth exhaustion.
    pub fn check_rate_limit(&self, peer_id: &[u8; 32]) -> bool {
        self.rate_limiter.write().check_and_record(peer_id)
    }

    /// Cleanup rate limiter state (call periodically)
    pub fn cleanup_rate_limiter(&self) {
        self.rate_limiter.write().cleanup();
    }

    /// 3.10: Compute hash for a chunk (for verification)
    pub fn compute_chunk_hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Start a download for parameters with the given hash
    ///
    /// Returns a receiver that will be notified when download completes
    ///
    /// # Arguments
    /// * `params_hash` - Expected hash of the complete parameters
    /// * `total_size` - Total size in bytes
    /// * `chunk_hashes` - Optional per-chunk hashes for 3.10 verification
    pub fn start_download(
        &self,
        params_hash: [u8; 32],
        total_size: u64,
    ) -> oneshot::Receiver<MpcResult<PathBuf>> {
        self.start_download_with_hashes(params_hash, total_size, None)
    }

    /// Start a download with per-chunk hash verification (3.10 enhanced security)
    ///
    /// When chunk_hashes is provided, each chunk is verified against its
    /// expected hash before storage. This prevents partial corruption attacks.
    pub fn start_download_with_hashes(
        &self,
        params_hash: [u8; 32],
        total_size: u64,
        chunk_hashes: Option<HashMap<u32, [u8; 32]>>,
    ) -> oneshot::Receiver<MpcResult<PathBuf>> {
        let (tx, rx) = oneshot::channel();

        let total_chunks =
            ((total_size + PARAM_CHUNK_SIZE as u64 - 1) / PARAM_CHUNK_SIZE as u64) as u32;

        // 3.10: Capture this before state is moved
        let has_per_chunk_verification = chunk_hashes.is_some();

        let state = DownloadState {
            _expected_hash: params_hash,
            _total_size: total_size,
            chunks: HashMap::new(),
            chunk_hashes,
            total_chunks,
            completion_tx: Some(tx),
        };

        self.pending_downloads.write().insert(params_hash, state);

        info!(
            params_hash = %hex::encode(params_hash),
            total_size = total_size,
            total_chunks = total_chunks,
            per_chunk_verification = has_per_chunk_verification,
            "Started parameter download"
        );

        rx
    }

    /// Handle an incoming parameter chunk
    ///
    /// Returns true if this completes the download
    ///
    /// 3.10 SECURITY: If chunk_hashes were provided at download start,
    /// each chunk is verified before storage to prevent corruption attacks.
    pub fn handle_chunk(
        &self,
        params_hash: [u8; 32],
        chunk_index: u32,
        chunk_data: Vec<u8>,
    ) -> MpcResult<bool> {
        let mut downloads = self.pending_downloads.write();

        let state = downloads.get_mut(&params_hash).ok_or_else(|| {
            MpcError::Internal(format!(
                "No pending download for params {}",
                hex::encode(params_hash)
            ))
        })?;

        // Validate chunk index
        if chunk_index >= state.total_chunks {
            return Err(MpcError::InvalidParams(format!(
                "Chunk index {} exceeds total chunks {}",
                chunk_index, state.total_chunks
            )));
        }

        // 3.10 SECURITY: Verify chunk hash if hashes were provided
        if let Some(ref chunk_hashes) = state.chunk_hashes {
            if let Some(expected_hash) = chunk_hashes.get(&chunk_index) {
                let actual_hash = Self::compute_chunk_hash(&chunk_data);
                if &actual_hash != expected_hash {
                    warn!(
                        params_hash = %hex::encode(params_hash),
                        chunk_index = chunk_index,
                        expected = %hex::encode(expected_hash),
                        actual = %hex::encode(actual_hash),
                        "Chunk hash mismatch - rejecting corrupted chunk"
                    );
                    return Err(MpcError::HashMismatch {
                        expected: hex::encode(expected_hash),
                        actual: hex::encode(actual_hash),
                    });
                }
            }
        }

        // Store chunk
        if state.chunks.insert(chunk_index, chunk_data).is_some() {
            debug!(
                chunk_index = chunk_index,
                "Received duplicate chunk, ignoring"
            );
        }

        debug!(
            params_hash = %hex::encode(params_hash),
            chunk_index = chunk_index,
            received = state.chunks.len(),
            total = state.total_chunks,
            "Received parameter chunk"
        );

        // Check if download is complete
        if state.chunks.len() as u32 == state.total_chunks {
            // Download complete - assemble and verify
            let result = self.finalize_download(params_hash, state);

            // Remove from pending
            let state = downloads.remove(&params_hash);

            // Notify completion
            if let Some(mut state) = state {
                if let Some(tx) = state.completion_tx.take() {
                    let _ = tx.send(result.clone());
                }
            }

            return result.map(|_| true);
        }

        Ok(false)
    }

    /// Assemble and verify a completed download
    fn finalize_download(
        &self,
        params_hash: [u8; 32],
        state: &DownloadState,
    ) -> MpcResult<PathBuf> {
        self.files.ensure_dir()?;

        // Create temp file
        let temp_path = self.files.dir.join(format!(
            "params_download_{}.tmp",
            hex::encode(&params_hash[..8])
        ));
        let mut file = File::create(&temp_path)?;

        // Write chunks in order
        for i in 0..state.total_chunks {
            let chunk = state.chunks.get(&i).ok_or_else(|| {
                MpcError::Internal(format!("Missing chunk {} during assembly", i))
            })?;
            file.write_all(chunk)?;
        }

        file.flush()?;
        drop(file);

        // Verify hash
        let actual_hash = hash_params_file(&temp_path)?;
        if actual_hash != params_hash {
            fs::remove_file(&temp_path)?;
            return Err(MpcError::HashMismatch {
                expected: hex::encode(params_hash),
                actual: hex::encode(actual_hash),
            });
        }

        // Verify it loads correctly
        let _params = load_parameters(&temp_path)?;

        // Move to final location
        let final_path = self
            .files
            .dir
            .join(format!("params_{}.bin", hex::encode(&params_hash[..8])));
        fs::rename(&temp_path, &final_path)?;

        info!(
            params_hash = %hex::encode(params_hash),
            path = %final_path.display(),
            "Parameter download completed and verified"
        );

        Ok(final_path)
    }

    /// Get the number of missing chunks for a download
    pub fn missing_chunks(&self, params_hash: [u8; 32]) -> Option<Vec<u32>> {
        let downloads = self.pending_downloads.read();
        let state = downloads.get(&params_hash)?;

        let mut missing = Vec::new();
        for i in 0..state.total_chunks {
            if !state.chunks.contains_key(&i) {
                missing.push(i);
            }
        }

        Some(missing)
    }

    /// Cancel a pending download
    pub fn cancel_download(&self, params_hash: [u8; 32]) {
        let mut downloads = self.pending_downloads.write();
        if let Some(mut state) = downloads.remove(&params_hash) {
            if let Some(tx) = state.completion_tx.take() {
                let _ = tx.send(Err(MpcError::Internal("Download cancelled".into())));
            }
        }
    }

    /// Check if we have parameters with the given hash
    pub fn has_params(&self, params_hash: [u8; 32]) -> bool {
        let path = self
            .files
            .dir
            .join(format!("params_{}.bin", hex::encode(&params_hash[..8])));
        path.exists()
    }

    /// Get the path to parameters with the given hash
    pub fn params_path(&self, params_hash: [u8; 32]) -> PathBuf {
        self.files
            .dir
            .join(format!("params_{}.bin", hex::encode(&params_hash[..8])))
    }

    /// Read chunks from a parameters file for serving to peers
    pub fn read_chunks(&self, params_path: &PathBuf) -> MpcResult<ChunkIterator> {
        ChunkIterator::new(params_path)
    }
}

/// Iterator over chunks of a parameters file
pub struct ChunkIterator {
    file: File,
    total_size: u64,
    current_chunk: u32,
    total_chunks: u32,
}

impl ChunkIterator {
    fn new(path: &PathBuf) -> MpcResult<Self> {
        let file = File::open(path)?;
        let total_size = file.metadata()?.len();
        let total_chunks =
            ((total_size + PARAM_CHUNK_SIZE as u64 - 1) / PARAM_CHUNK_SIZE as u64) as u32;

        Ok(Self {
            file,
            total_size,
            current_chunk: 0,
            total_chunks,
        })
    }

    /// Get total number of chunks
    pub fn total_chunks(&self) -> u32 {
        self.total_chunks
    }

    /// Get total size in bytes
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// Read a specific chunk
    pub fn read_chunk(&mut self, chunk_index: u32) -> MpcResult<Vec<u8>> {
        if chunk_index >= self.total_chunks {
            return Err(MpcError::InvalidParams(format!(
                "Chunk index {} exceeds total {}",
                chunk_index, self.total_chunks
            )));
        }

        let offset = chunk_index as u64 * PARAM_CHUNK_SIZE as u64;
        self.file.seek(SeekFrom::Start(offset))?;

        let remaining = self.total_size - offset;
        let chunk_size = (remaining as usize).min(PARAM_CHUNK_SIZE);

        let mut buffer = vec![0u8; chunk_size];
        self.file.read_exact(&mut buffer)?;

        Ok(buffer)
    }
}

impl Iterator for ChunkIterator {
    type Item = MpcResult<(u32, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_chunk >= self.total_chunks {
            return None;
        }

        let chunk_index = self.current_chunk;
        self.current_chunk += 1;

        Some(self.read_chunk(chunk_index).map(|data| (chunk_index, data)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_chunk_iterator() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.bin");

        // Create a test file
        let data = vec![0u8; PARAM_CHUNK_SIZE * 2 + 100];
        fs::write(&file_path, &data).unwrap();

        let mut iter = ChunkIterator::new(&file_path).unwrap();
        assert_eq!(iter.total_chunks(), 3);

        let (idx, chunk) = iter.next().unwrap().unwrap();
        assert_eq!(idx, 0);
        assert_eq!(chunk.len(), PARAM_CHUNK_SIZE);

        let (idx, chunk) = iter.next().unwrap().unwrap();
        assert_eq!(idx, 1);
        assert_eq!(chunk.len(), PARAM_CHUNK_SIZE);

        let (idx, chunk) = iter.next().unwrap().unwrap();
        assert_eq!(idx, 2);
        assert_eq!(chunk.len(), 100);

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_parameter_sync_start_download() {
        let temp_dir = TempDir::new().unwrap();
        let sync = ParameterSync::new(temp_dir.path().to_path_buf());

        let params_hash = [1u8; 32];
        let total_size = 1000;

        let _rx = sync.start_download(params_hash, total_size);

        // Should have pending download
        assert!(sync.missing_chunks(params_hash).is_some());
    }
}
