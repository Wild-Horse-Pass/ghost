//! P2P Parameter Synchronization
//!
//! Parameters are ~200MB - too large for broadcast messages.
//! This module handles chunked transfer of parameters between nodes.

use crate::errors::{MpcError, MpcResult};
use crate::params::{hash_params_file, load_parameters, ParameterFiles};
use crate::PARAM_CHUNK_SIZE;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use tokio::sync::oneshot;
use tracing::{debug, info};

/// State of an in-progress download
struct DownloadState {
    /// Expected hash of the complete parameters
    _expected_hash: [u8; 32],
    /// Expected total size in bytes
    _total_size: u64,
    /// Chunks received (chunk index -> data)
    chunks: HashMap<u32, Vec<u8>>,
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
}

impl ParameterSync {
    /// Create a new parameter sync manager
    pub fn new(params_dir: PathBuf) -> Self {
        Self {
            files: ParameterFiles::new(params_dir),
            pending_downloads: RwLock::new(HashMap::new()),
        }
    }

    /// Start a download for parameters with the given hash
    ///
    /// Returns a receiver that will be notified when download completes
    pub fn start_download(
        &self,
        params_hash: [u8; 32],
        total_size: u64,
    ) -> oneshot::Receiver<MpcResult<PathBuf>> {
        let (tx, rx) = oneshot::channel();

        let total_chunks =
            ((total_size + PARAM_CHUNK_SIZE as u64 - 1) / PARAM_CHUNK_SIZE as u64) as u32;

        let state = DownloadState {
            _expected_hash: params_hash,
            _total_size: total_size,
            chunks: HashMap::new(),
            total_chunks,
            completion_tx: Some(tx),
        };

        self.pending_downloads.write().insert(params_hash, state);

        info!(
            params_hash = %hex::encode(params_hash),
            total_size = total_size,
            total_chunks = total_chunks,
            "Started parameter download"
        );

        rx
    }

    /// Handle an incoming parameter chunk
    ///
    /// Returns true if this completes the download
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
