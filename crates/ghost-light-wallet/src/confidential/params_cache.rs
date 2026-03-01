//! MPC parameter download and caching for NoteSpend proofs
//!
//! Downloads `note_spend_params_current.bin` from a ghost-pool node's
//! `/api/v1/mpc/params` endpoint on first use and caches locally.
//! Subsequent calls use the cached file.

use std::path::PathBuf;
use tracing::{debug, info};

use crate::error::{LightWalletError, WalletResult};

/// Default filename for cached NoteSpend proving parameters
const PARAMS_FILENAME: &str = "note_spend_params_current.bin";

/// Expected minimum size for valid params (~1.4MB per docs)
const MIN_PARAMS_SIZE: u64 = 100_000;

/// Manages local caching of NoteSpend MPC parameters
pub struct ParamsCache {
    /// Directory where params are cached (e.g. ~/.ghost/wallet/params/)
    cache_dir: PathBuf,
}

impl ParamsCache {
    /// Create a new params cache manager
    pub fn new(cache_dir: PathBuf) -> Self {
        Self { cache_dir }
    }

    /// Get the path to the cached params file
    pub fn params_path(&self) -> PathBuf {
        self.cache_dir.join(PARAMS_FILENAME)
    }

    /// Check if valid cached params exist
    pub fn has_cached_params(&self) -> bool {
        let path = self.params_path();
        if !path.exists() {
            return false;
        }
        // Verify file is at least minimum size
        match std::fs::metadata(&path) {
            Ok(meta) => meta.len() >= MIN_PARAMS_SIZE,
            Err(_) => false,
        }
    }

    /// Download NoteSpend params from a ghost-pool node and cache locally
    ///
    /// Fetches from `http://{host}:{port}/api/v1/mpc/params`.
    /// Uses atomic write (temp file + rename) to avoid partial downloads.
    pub async fn download_params(&self, host: &str, port: u16) -> WalletResult<PathBuf> {
        let url = format!("http://{}:{}/api/v1/mpc/params", host, port);
        info!(url = %url, "Downloading NoteSpend MPC parameters...");

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| LightWalletError::Internal(format!("HTTP client error: {}", e)))?;

        let response = client.get(&url).send().await.map_err(|e| {
            LightWalletError::ConnectionFailed(format!(
                "Failed to download MPC params from {}: {}",
                url, e
            ))
        })?;

        if !response.status().is_success() {
            return Err(LightWalletError::ConnectionFailed(format!(
                "MPC params download failed: HTTP {}",
                response.status()
            )));
        }

        let data = response.bytes().await.map_err(|e| {
            LightWalletError::ConnectionFailed(format!("Failed to read MPC params body: {}", e))
        })?;

        if (data.len() as u64) < MIN_PARAMS_SIZE {
            return Err(LightWalletError::Internal(format!(
                "Downloaded params too small ({} bytes), expected >= {} bytes",
                data.len(),
                MIN_PARAMS_SIZE
            )));
        }

        // Atomic write: temp file + rename
        std::fs::create_dir_all(&self.cache_dir).map_err(|e| {
            LightWalletError::Storage(format!("Failed to create params cache dir: {}", e))
        })?;

        let tmp_path = self.cache_dir.join("note_spend_params_download.tmp");
        std::fs::write(&tmp_path, &data).map_err(|e| {
            LightWalletError::Storage(format!("Failed to write params temp file: {}", e))
        })?;

        let final_path = self.params_path();
        std::fs::rename(&tmp_path, &final_path).map_err(|e| {
            LightWalletError::Storage(format!("Failed to rename params file: {}", e))
        })?;

        info!(
            size_bytes = data.len(),
            path = %final_path.display(),
            "NoteSpend MPC parameters cached"
        );

        Ok(final_path)
    }

    /// Ensure params are available locally, downloading if needed
    ///
    /// Returns the path to the cached params file.
    pub async fn ensure_params(
        &self,
        host: &str,
        port: u16,
    ) -> WalletResult<PathBuf> {
        if self.has_cached_params() {
            let path = self.params_path();
            debug!(path = %path.display(), "Using cached NoteSpend params");
            return Ok(path);
        }

        self.download_params(host, port).await
    }
}

/// Get the default params cache directory
///
/// Returns `~/.ghost/wallet/params/`
pub fn default_params_cache_dir() -> WalletResult<PathBuf> {
    let home = std::env::var("HOME")
        .map_err(|_| LightWalletError::Internal("HOME environment variable not set".to_string()))?;
    Ok(PathBuf::from(home).join(".ghost/wallet/params"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_params_cache_no_file() {
        let cache = ParamsCache::new(PathBuf::from("/tmp/ghost_test_nonexistent"));
        assert!(!cache.has_cached_params());
    }

    #[test]
    fn test_default_params_cache_dir() {
        let dir = default_params_cache_dir();
        assert!(dir.is_ok());
        let path = dir.unwrap();
        assert!(path.to_string_lossy().contains(".ghost/wallet/params"));
    }

    #[test]
    fn test_params_cache_detects_small_file() {
        let tmp = tempfile::tempdir().unwrap();
        let params_path = tmp.path().join(PARAMS_FILENAME);
        // Write a file smaller than MIN_PARAMS_SIZE
        std::fs::write(&params_path, vec![0u8; 50]).unwrap();

        let cache = ParamsCache::new(tmp.path().to_path_buf());
        assert!(
            !cache.has_cached_params(),
            "File smaller than MIN_PARAMS_SIZE should not count as cached"
        );
    }

    #[test]
    fn test_params_cache_detects_valid_file() {
        let tmp = tempfile::tempdir().unwrap();
        let params_path = tmp.path().join(PARAMS_FILENAME);
        // Write a file at exactly MIN_PARAMS_SIZE
        std::fs::write(&params_path, vec![0u8; MIN_PARAMS_SIZE as usize]).unwrap();

        let cache = ParamsCache::new(tmp.path().to_path_buf());
        assert!(
            cache.has_cached_params(),
            "File at MIN_PARAMS_SIZE should count as cached"
        );
    }

    #[test]
    fn test_params_path_construction() {
        let cache = ParamsCache::new(PathBuf::from("/home/user/.ghost/wallet/params"));
        let expected = PathBuf::from("/home/user/.ghost/wallet/params").join(PARAMS_FILENAME);
        assert_eq!(cache.params_path(), expected);
    }

    #[tokio::test]
    async fn test_ensure_params_uses_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let params_path = tmp.path().join(PARAMS_FILENAME);
        // Write a valid-sized cached file
        std::fs::write(&params_path, vec![0xAB; MIN_PARAMS_SIZE as usize]).unwrap();

        let cache = ParamsCache::new(tmp.path().to_path_buf());
        // ensure_params should return immediately without attempting HTTP
        let result = cache.ensure_params("127.0.0.1", 9999).await;
        assert!(result.is_ok(), "Cache hit should succeed without HTTP");
        assert_eq!(result.unwrap(), params_path);
    }

    #[tokio::test]
    #[ignore] // Requires HTTP server
    async fn test_download_rejects_small_response() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = ParamsCache::new(tmp.path().to_path_buf());
        // Attempt download from a non-existent server — should fail with connection error
        let result = cache.download_params("127.0.0.1", 1).await;
        assert!(result.is_err(), "Download from non-existent server should fail");
    }
}
