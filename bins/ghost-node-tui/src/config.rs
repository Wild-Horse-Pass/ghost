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

//! Configuration management for Ghost Node TUI

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main configuration for the TUI
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SwarmConfig {
    /// Configured nodes
    #[serde(default)]
    pub nodes: Vec<NodeEntry>,

    /// TUI settings
    #[serde(default)]
    pub settings: TuiSettings,
}

/// A single node entry in the swarm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeEntry {
    /// User-defined display name
    pub name: String,

    /// Node API URL (e.g., http://192.168.1.100:8080)
    pub url: String,

    /// Whether this is the default node on startup
    #[serde(default)]
    pub default: bool,

    /// Optional authentication token (Bearer)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,

    /// Optional HMAC secret for authenticated POST actions
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac_secret: Option<String>,

    /// Optional group for organization
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    /// Optional notes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// TUI display and behavior settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuiSettings {
    /// Refresh interval in milliseconds
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval_ms: u64,

    /// Refresh interval in seconds (convenience)
    #[serde(default = "default_refresh_secs")]
    pub refresh_interval_secs: u64,

    /// Show stale data indicators
    #[serde(default = "default_true")]
    pub show_stale_indicators: bool,

    /// Auto-reconnect on connection loss
    #[serde(default = "default_true")]
    pub auto_reconnect: bool,

    /// Reconnect delay in seconds
    #[serde(default = "default_reconnect_delay")]
    pub reconnect_delay_secs: u64,

    /// Color theme
    #[serde(default = "default_theme")]
    pub theme: String,

    /// Enable notifications
    #[serde(default = "default_true")]
    pub notifications_enabled: bool,
}

fn default_refresh_interval() -> u64 {
    1000
}

fn default_refresh_secs() -> u64 {
    5
}

fn default_reconnect_delay() -> u64 {
    5
}

fn default_true() -> bool {
    true
}

fn default_theme() -> String {
    "retro".to_string()
}

impl Default for TuiSettings {
    fn default() -> Self {
        Self {
            refresh_interval_ms: default_refresh_interval(),
            refresh_interval_secs: default_refresh_secs(),
            show_stale_indicators: true,
            auto_reconnect: true,
            reconnect_delay_secs: default_reconnect_delay(),
            theme: default_theme(),
            notifications_enabled: true,
        }
    }
}

impl SwarmConfig {
    /// Get the default config file path
    pub fn config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("ghost-node-tui")
            .join("swarm.toml")
    }

    /// Load configuration from file
    pub fn load() -> Result<Self> {
        let path = Self::config_path();

        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))
    }

    /// Load from a specific path
    pub fn load_from(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))
    }

    /// Save configuration to file
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path();

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create config directory: {}", parent.display())
            })?;
        }

        let content = toml::to_string_pretty(self).context("Failed to serialize config")?;

        std::fs::write(&path, content)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;

        Ok(())
    }

    /// Save to a specific path
    #[allow(dead_code)]
    pub fn save_to(&self, path: &PathBuf) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create config directory: {}", parent.display())
            })?;
        }

        let content = toml::to_string_pretty(self).context("Failed to serialize config")?;

        std::fs::write(path, content)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;

        Ok(())
    }

    /// Add a new node
    #[allow(dead_code)]
    pub fn add_node(&mut self, node: NodeEntry) {
        // If this is the first node, make it default
        let make_default = self.nodes.is_empty();

        let mut node = node;
        if make_default {
            node.default = true;
        }

        self.nodes.push(node);
    }

    /// Remove a node by index
    #[allow(dead_code)]
    pub fn remove_node(&mut self, idx: usize) -> Option<NodeEntry> {
        if idx >= self.nodes.len() {
            return None;
        }

        let removed = self.nodes.remove(idx);

        // If removed node was default, make first node default
        if removed.default && !self.nodes.is_empty() {
            self.nodes[0].default = true;
        }

        Some(removed)
    }

    /// Set a node as default
    #[allow(dead_code)]
    pub fn set_default(&mut self, idx: usize) {
        for (i, node) in self.nodes.iter_mut().enumerate() {
            node.default = i == idx;
        }
    }

    /// Get the default node index
    #[allow(dead_code)]
    pub fn default_node_idx(&self) -> Option<usize> {
        self.nodes.iter().position(|n| n.default)
    }
}

impl NodeEntry {
    /// Create a new node entry
    #[allow(dead_code)]
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
            default: false,
            auth_token: None,
            hmac_secret: None,
            group: None,
            notes: None,
        }
    }

    /// Create with URL only (name will be set later from API)
    #[allow(dead_code)]
    pub fn from_url(url: impl Into<String>) -> Self {
        let url = url.into();
        let name = url
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split(':')
            .next()
            .unwrap_or("unknown")
            .to_string();

        Self::new(name, url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SwarmConfig::default();
        assert!(config.nodes.is_empty());
        assert_eq!(config.settings.refresh_interval_ms, 1000);
    }

    #[test]
    fn test_add_first_node_is_default() {
        let mut config = SwarmConfig::default();
        config.add_node(NodeEntry::new("test", "http://localhost:8080"));
        assert!(config.nodes[0].default);
    }

    #[test]
    fn test_set_default() {
        let mut config = SwarmConfig::default();
        config.add_node(NodeEntry::new("node1", "http://localhost:8080"));
        config.add_node(NodeEntry::new("node2", "http://localhost:8081"));

        config.set_default(1);

        assert!(!config.nodes[0].default);
        assert!(config.nodes[1].default);
    }
}
