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
//| FILE: config.rs                                                                                                      |
//|======================================================================================================================|

//! Node configuration with disk persistence
//!
//! Manages runtime node settings that persist across restarts.

use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{debug, error, warn};

use ghost_common::error::{GhostError, GhostResult};

/// Node configuration that persists to disk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Ghost mode: do not relay/announce unconfirmed transactions
    pub ghost_mode: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            ghost_mode: false,
        }
    }
}

impl NodeConfig {
    /// Load configuration from a JSON file
    ///
    /// Returns default config if the file doesn't exist.
    /// Returns an error only if the file exists but is corrupted.
    pub fn load(path: &Path) -> GhostResult<Self> {
        if !path.exists() {
            debug!("Config file does not exist, using defaults: {:?}", path);
            return Ok(Self::default());
        }

        let contents = std::fs::read_to_string(path).map_err(|e| {
            GhostError::Config(format!("Failed to read config file {:?}: {}", path, e))
        })?;

        serde_json::from_str(&contents).map_err(|e| {
            error!("Failed to parse config file {:?}: {}", path, e);
            GhostError::Config(format!("Failed to parse config file: {}", e))
        })
    }

    /// Save configuration to a JSON file
    ///
    /// Creates parent directories if they don't exist.
    pub fn save(&self, path: &Path) -> GhostResult<()> {
        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    GhostError::Config(format!(
                        "Failed to create config directory {:?}: {}",
                        parent, e
                    ))
                })?;
            }
        }

        let contents = serde_json::to_string_pretty(self).map_err(|e| {
            GhostError::Config(format!("Failed to serialize config: {}", e))
        })?;

        std::fs::write(path, contents).map_err(|e| {
            GhostError::Config(format!("Failed to write config file {:?}: {}", path, e))
        })?;

        debug!("Saved config to {:?}", path);
        Ok(())
    }

    /// Load config, logging any errors but returning defaults on failure
    pub fn load_or_default(path: &Path) -> Self {
        match Self::load(path) {
            Ok(config) => config,
            Err(e) => {
                warn!("Failed to load config from {:?}: {}. Using defaults.", path, e);
                Self::default()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = NodeConfig::default();
        assert!(!config.ghost_mode);
    }

    #[test]
    fn test_save_and_load() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        let config = NodeConfig { ghost_mode: true };
        config.save(path).unwrap();

        let loaded = NodeConfig::load(path).unwrap();
        assert!(loaded.ghost_mode);
    }

    #[test]
    fn test_load_missing_file() {
        let path = Path::new("/nonexistent/path/config.json");
        let config = NodeConfig::load(path).unwrap();
        assert!(!config.ghost_mode); // Should return defaults
    }

    #[test]
    fn test_load_corrupted_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"not valid json").unwrap();

        let result = NodeConfig::load(temp_file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_load_or_default() {
        let path = Path::new("/nonexistent/path/config.json");
        let config = NodeConfig::load_or_default(path);
        assert!(!config.ghost_mode);
    }
}
