//! MPC parameter download and caching
//!
//! Downloads proving parameters from a ghost-pay node's API on first use
//! and caches them locally. Subsequent calls use the cached files.

use std::path::PathBuf;
use tracing::{debug, info};

use crate::network::NetworkError;

/// Filenames for the three proving parameter files
const NOTE_SPEND_PARAMS: &str = "note_spend_params_current.bin";
const CONSOLIDATION_PARAMS: &str = "consolidation_params_current.bin";
const UNSHIELD_PARAMS: &str = "unshield_params_current.bin";

/// Expected minimum size for valid params (~1.4MB per file)
const MIN_PARAMS_SIZE: u64 = 100_000;

/// Manages local caching of MPC proving parameters.
pub struct ParamsCache {
    cache_dir: PathBuf,
}

impl ParamsCache {
    pub fn new(cache_dir: PathBuf) -> Self {
        Self { cache_dir }
    }

    pub fn cache_dir(&self) -> &PathBuf {
        &self.cache_dir
    }

    /// Check if all three parameter files are cached and valid.
    pub fn has_cached_params(&self) -> bool {
        Self::check_file(&self.cache_dir.join(NOTE_SPEND_PARAMS))
            && Self::check_file(&self.cache_dir.join(CONSOLIDATION_PARAMS))
            && Self::check_file(&self.cache_dir.join(UNSHIELD_PARAMS))
    }

    fn check_file(path: &PathBuf) -> bool {
        match std::fs::metadata(path) {
            Ok(meta) => meta.len() >= MIN_PARAMS_SIZE,
            Err(_) => false,
        }
    }

    /// Download all three parameter files from a ghost-pay node.
    ///
    /// Uses atomic write (temp file + rename) to avoid partial downloads.
    pub async fn download_params(&self, host: &str, port: u16) -> Result<PathBuf, NetworkError> {
        std::fs::create_dir_all(&self.cache_dir).map_err(|e| {
            NetworkError::RequestFailed(format!("Failed to create params cache dir: {}", e))
        })?;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .map_err(|e| NetworkError::ConnectionFailed(format!("HTTP client error: {}", e)))?;

        // Download all three param files
        for filename in &[NOTE_SPEND_PARAMS, CONSOLIDATION_PARAMS, UNSHIELD_PARAMS] {
            let url = format!("http://{}:{}/api/v1/mpc/params/{}", host, port, filename);
            info!(url = %url, "Downloading MPC parameters...");

            let response = client.get(&url).send().await.map_err(|e| {
                NetworkError::ConnectionFailed(format!("Failed to download {}: {}", filename, e))
            })?;

            if !response.status().is_success() {
                return Err(NetworkError::RequestFailed(format!(
                    "Download {} failed: HTTP {}",
                    filename,
                    response.status()
                )));
            }

            let data = response.bytes().await.map_err(|e| {
                NetworkError::RequestFailed(format!("Failed to read {} body: {}", filename, e))
            })?;

            if (data.len() as u64) < MIN_PARAMS_SIZE {
                return Err(NetworkError::RequestFailed(format!(
                    "{} too small ({} bytes), expected >= {}",
                    filename,
                    data.len(),
                    MIN_PARAMS_SIZE
                )));
            }

            // Atomic write
            let tmp_path = self.cache_dir.join(format!("{}.tmp", filename));
            std::fs::write(&tmp_path, &data).map_err(|e| {
                NetworkError::RequestFailed(format!("Failed to write temp file: {}", e))
            })?;

            let final_path = self.cache_dir.join(filename);
            std::fs::rename(&tmp_path, &final_path).map_err(|e| {
                NetworkError::RequestFailed(format!("Failed to rename params file: {}", e))
            })?;

            info!(size_bytes = data.len(), file = %filename, "Parameter file cached");
        }

        Ok(self.cache_dir.clone())
    }

    /// Ensure params are available locally, downloading if needed.
    pub async fn ensure_params(&self, host: &str, port: u16) -> Result<PathBuf, NetworkError> {
        if self.has_cached_params() {
            debug!(path = %self.cache_dir.display(), "Using cached MPC params");
            return Ok(self.cache_dir.clone());
        }
        self.download_params(host, port).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_params_cache_creation() {
        let cache = ParamsCache::new(PathBuf::from("/tmp/ghost-test-params"));
        assert!(!cache.has_cached_params());
    }
}
