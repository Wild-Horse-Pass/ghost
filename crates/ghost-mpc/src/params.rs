//! Parameter file I/O and management
//!
//! Handles loading and saving of ZK parameters to disk, with support for
//! both block proving parameters and payout proving parameters.

use crate::errors::{MpcError, MpcResult};
use bellperson::groth16::{Parameters, PreparedVerifyingKey, VerifyingKey};
use blstrs::Bls12;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Container for both block and payout parameters
/// Note: Not Clone because PreparedVerifyingKey doesn't implement Clone.
/// Use Arc<MpcParameters> for shared ownership.
pub struct MpcParameters {
    /// Parameters for block proofs
    pub block_params: Option<Parameters<Bls12>>,
    /// Parameters for payout proofs
    pub payout_params: Option<Parameters<Bls12>>,
    /// Prepared verifying key for block proofs (for fast verification)
    pub block_vk: Option<PreparedVerifyingKey<Bls12>>,
    /// Prepared verifying key for payout proofs
    pub payout_vk: Option<PreparedVerifyingKey<Bls12>>,
}

impl Default for MpcParameters {
    fn default() -> Self {
        Self {
            block_params: None,
            payout_params: None,
            block_vk: None,
            payout_vk: None,
        }
    }
}

/// File paths for parameter storage
pub struct ParameterFiles {
    /// Base directory for parameter files
    pub dir: PathBuf,
}

impl ParameterFiles {
    /// Create a new parameter files manager
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Path to block parameters file
    pub fn block_params_path(&self, contribution_count: u32) -> PathBuf {
        self.dir.join(format!("block_params_v{}.bin", contribution_count))
    }

    /// Path to payout parameters file
    pub fn payout_params_path(&self, contribution_count: u32) -> PathBuf {
        self.dir.join(format!("payout_params_v{}.bin", contribution_count))
    }

    /// Path to the current (latest) block parameters
    pub fn current_block_params_path(&self) -> PathBuf {
        self.dir.join("block_params_current.bin")
    }

    /// Path to the current (latest) payout parameters
    pub fn current_payout_params_path(&self) -> PathBuf {
        self.dir.join("payout_params_current.bin")
    }

    /// Path to the block verifying key
    pub fn block_vk_path(&self) -> PathBuf {
        self.dir.join("block_vk.bin")
    }

    /// Path to the payout verifying key
    pub fn payout_vk_path(&self) -> PathBuf {
        self.dir.join("payout_vk.bin")
    }

    /// Ensure the parameters directory exists
    pub fn ensure_dir(&self) -> MpcResult<()> {
        if !self.dir.exists() {
            fs::create_dir_all(&self.dir)?;
            info!(path = %self.dir.display(), "Created MPC parameters directory");
        }
        Ok(())
    }

    /// List all parameter versions available
    pub fn list_versions(&self) -> MpcResult<Vec<u32>> {
        let mut versions = Vec::new();

        if !self.dir.exists() {
            return Ok(versions);
        }

        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if let Some(rest) = name_str.strip_prefix("block_params_v") {
                if let Some(version_str) = rest.strip_suffix(".bin") {
                    if let Ok(version) = version_str.parse::<u32>() {
                        versions.push(version);
                    }
                }
            }
        }

        versions.sort();
        Ok(versions)
    }

    /// Get the highest version number available
    pub fn latest_version(&self) -> MpcResult<Option<u32>> {
        Ok(self.list_versions()?.into_iter().max())
    }
}

/// Save parameters to a file
pub fn save_parameters(path: &Path, params: &Parameters<Bls12>) -> MpcResult<()> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);

    // Use bellperson's built-in serialization
    params
        .write(&mut writer)
        .map_err(|e| MpcError::Serialization(e.to_string()))?;

    writer.flush()?;

    let file_size = fs::metadata(path)?.len();
    info!(
        path = %path.display(),
        size_bytes = file_size,
        "Saved MPC parameters"
    );

    Ok(())
}

/// Load parameters from a file
pub fn load_parameters(path: &Path) -> MpcResult<Parameters<Bls12>> {
    if !path.exists() {
        return Err(MpcError::ParamsNotFound(path.display().to_string()));
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let params = Parameters::read(reader, false) // false = don't check for safety
        .map_err(|e| MpcError::InvalidParams(e.to_string()))?;

    debug!(path = %path.display(), "Loaded MPC parameters");

    Ok(params)
}

/// Save a verifying key to a file
pub fn save_verifying_key(path: &Path, vk: &VerifyingKey<Bls12>) -> MpcResult<()> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);

    vk.write(&mut writer)
        .map_err(|e| MpcError::Serialization(e.to_string()))?;

    writer.flush()?;

    info!(path = %path.display(), "Saved verifying key");

    Ok(())
}

/// Load a verifying key from a file
pub fn load_verifying_key(path: &Path) -> MpcResult<VerifyingKey<Bls12>> {
    if !path.exists() {
        return Err(MpcError::ParamsNotFound(path.display().to_string()));
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let vk = VerifyingKey::read(reader)
        .map_err(|e| MpcError::InvalidParams(e.to_string()))?;

    debug!(path = %path.display(), "Loaded verifying key");

    Ok(vk)
}

/// Hash a parameters file for verification
pub fn hash_params_file(path: &Path) -> MpcResult<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();

    let mut buffer = [0u8; 8192];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hasher.finalize().into())
}

/// Atomically update the "current" symlink/copy to point to new version
pub fn update_current_params(files: &ParameterFiles, version: u32) -> MpcResult<()> {
    let block_src = files.block_params_path(version);
    let payout_src = files.payout_params_path(version);
    let block_dst = files.current_block_params_path();
    let payout_dst = files.current_payout_params_path();

    // On Unix, we'd use symlinks. For portability, we copy.
    // This is atomic enough for our purposes since we only read "current"
    // after initialization.

    if block_src.exists() {
        fs::copy(&block_src, &block_dst)?;
        info!(
            version = version,
            path = %block_dst.display(),
            "Updated current block parameters"
        );
    }

    if payout_src.exists() {
        fs::copy(&payout_src, &payout_dst)?;
        info!(
            version = version,
            path = %payout_dst.display(),
            "Updated current payout parameters"
        );
    }

    Ok(())
}

/// Metadata about a parameter file
#[derive(Debug, Clone)]
pub struct ParamsMetadata {
    /// Hash of the parameters
    pub hash: [u8; 32],
    /// File size in bytes
    pub size_bytes: u64,
    /// Contribution count (version)
    pub contribution_count: u32,
    /// Path to the file
    pub path: PathBuf,
}

impl ParamsMetadata {
    /// Load metadata for a parameter file
    pub fn from_file(path: &Path, contribution_count: u32) -> MpcResult<Self> {
        let hash = hash_params_file(path)?;
        let size_bytes = fs::metadata(path)?.len();

        Ok(Self {
            hash,
            size_bytes,
            contribution_count,
            path: path.to_path_buf(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_parameter_files_paths() {
        let dir = PathBuf::from("/tmp/mpc");
        let files = ParameterFiles::new(&dir);

        assert_eq!(
            files.block_params_path(5),
            PathBuf::from("/tmp/mpc/block_params_v5.bin")
        );
        assert_eq!(
            files.payout_params_path(10),
            PathBuf::from("/tmp/mpc/payout_params_v10.bin")
        );
    }

    #[test]
    fn test_list_versions_empty() {
        let temp_dir = TempDir::new().unwrap();
        let files = ParameterFiles::new(temp_dir.path());

        let versions = files.list_versions().unwrap();
        assert!(versions.is_empty());
    }

    #[test]
    fn test_ensure_dir_creates() {
        let temp_dir = TempDir::new().unwrap();
        let subdir = temp_dir.path().join("mpc");
        let files = ParameterFiles::new(&subdir);

        assert!(!subdir.exists());
        files.ensure_dir().unwrap();
        assert!(subdir.exists());
    }
}
