//! Node setup and configuration wizard backends.
//!
//! Provides `apply_*` functions that modify `NodeConfig` based on wizard field values.
//! Used by both the TUI wizard dispatch and the headless `ghost-setup` CLI.

use crate::config::{GhostPayConfig, HazeMode, NodeConfig, PolicyProfile};
use crate::identity::NodeIdentity;
use crate::types::TreasuryAddress;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Field values stored per field key (shared between wizard UI and setup backends)
#[derive(Debug, Clone)]
pub enum FieldValue {
    Text(String),
    Bool(bool),
    Selected(usize),
}

impl FieldValue {
    pub fn as_text(&self) -> &str {
        match self {
            FieldValue::Text(s) => s,
            _ => "",
        }
    }

    pub fn as_bool(&self) -> bool {
        match self {
            FieldValue::Bool(b) => *b,
            _ => false,
        }
    }

    pub fn as_selected(&self) -> usize {
        match self {
            FieldValue::Selected(i) => *i,
            _ => 0,
        }
    }
}

/// Result of initial setup
pub struct SetupResult {
    pub config_path: PathBuf,
    pub node_id_hex: String,
}

/// Load existing config, apply wizard changes, save atomically.
/// Used by all config-modifying wizards (change_setup, reaper, pool_setup, etc.)
fn load_and_modify(
    config_path: &Path,
    modify: impl FnOnce(&mut NodeConfig),
) -> Result<String, String> {
    let content = std::fs::read_to_string(config_path)
        .map_err(|e| format!("Load config {}: {e}", config_path.display()))?;
    let mut config: NodeConfig =
        toml::from_str(&content).map_err(|e| format!("Parse config: {e}"))?;
    modify(&mut config);
    config
        .save_atomic(config_path)
        .map_err(|e| format!("Save config: {e}"))?;
    Ok(format!("Config updated: {}", config_path.display()))
}

/// Initial setup — creates new config from scratch (first-run wizard)
pub fn apply_initial_setup(
    fields: &HashMap<String, FieldValue>,
    config_dir: &Path,
    data_dir: &Path,
) -> Result<SetupResult, String> {
    let nickname = fields
        .get("nickname")
        .map(|v| v.as_text().to_string())
        .unwrap_or_default();
    // The wizard's "public_mining" toggle maps to mining_mode = PublicPool.
    // Disabled → keeps the default mining_mode (PublicPool unless overridden
    // elsewhere). Operators choosing private modes use a different setup flow.
    let public_mining_intent = fields
        .get("public_mining")
        .map(|v| v.as_bool())
        .unwrap_or(false);
    let payout_address = fields
        .get("payout_address")
        .map(|v| v.as_text().to_string())
        .unwrap_or_default();
    let archive_mode = fields
        .get("archive_mode")
        .map(|v| v.as_bool())
        .unwrap_or(true);
    let ghost_pay_enabled = fields.get("ghost_pay").map(|v| v.as_bool()).unwrap_or(true);
    let reaper_enabled = fields.get("reaper").map(|v| v.as_bool()).unwrap_or(true);
    let mempool_idx = fields
        .get("mempool_profile")
        .map(|v| v.as_selected())
        .unwrap_or(0);

    std::fs::create_dir_all(data_dir)
        .map_err(|e| format!("Failed to create {}: {}", data_dir.display(), e))?;
    std::fs::create_dir_all(config_dir)
        .map_err(|e| format!("Failed to create {}: {}", config_dir.display(), e))?;

    let config_path = config_dir.join("pool.toml");
    if config_path.exists() {
        return Err(format!("Config already exists: {}", config_path.display()));
    }

    // Generate or load Ed25519 identity (with PoW)
    let key_path = data_dir.join("node.key");
    let identity = if key_path.exists() {
        NodeIdentity::load(&key_path).map_err(|e| format!("Load key: {e}"))?
    } else {
        let id = NodeIdentity::generate();
        id.save(&key_path).map_err(|e| format!("Save key: {e}"))?;
        id
    };
    let node_id_hex = hex::encode(identity.node_id());

    // Generate API secret
    let mut secret_bytes = [0u8; 32];
    getrandom::getrandom(&mut secret_bytes).map_err(|e| format!("RNG: {e}"))?;
    let api_secret = hex::encode(secret_bytes);

    let profile = match mempool_idx {
        1 => PolicyProfile::BitcoinPure,
        2 => PolicyProfile::FullOpen,
        _ => PolicyProfile::Permissive,
    };

    let mut config = NodeConfig::default();
    config.identity.key_path = key_path;
    if !nickname.is_empty() {
        config.identity.display_name = Some(nickname);
    }
    config.network.mining_mode = if public_mining_intent {
        crate::config::MiningMode::PublicPool
    } else {
        crate::config::MiningMode::PrivatePool
    };
    config.network.noise_enabled = true;
    config.network.internal_api_secret = Some(api_secret);
    config.storage.archive_mode = archive_mode;
    config.policy.profile = profile;
    if !payout_address.is_empty() {
        config.pool.treasury_address = TreasuryAddress::from(payout_address);
    }
    if ghost_pay_enabled {
        config.ghost_pay = Some(GhostPayConfig::default());
    }
    config.reaper.enabled = reaper_enabled;

    config
        .save_atomic(&config_path)
        .map_err(|e| format!("Write config: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod: {e}"))?;
    }

    Ok(SetupResult {
        config_path,
        node_id_hex,
    })
}

/// Change setup — modify existing config fields
pub fn apply_change_setup(
    fields: &HashMap<String, FieldValue>,
    config_path: &Path,
) -> Result<String, String> {
    load_and_modify(config_path, |config| {
        if let Some(v) = fields.get("nickname") {
            let name = v.as_text().to_string();
            if !name.is_empty() {
                config.identity.display_name = Some(name);
            }
        }
        if let Some(v) = fields.get("public_mining") {
            config.network.mining_mode = if v.as_bool() {
                crate::config::MiningMode::PublicPool
            } else {
                crate::config::MiningMode::PrivatePool
            };
        }
        if let Some(v) = fields.get("payout_address") {
            let addr = v.as_text().to_string();
            if !addr.is_empty() {
                config.pool.treasury_address = TreasuryAddress::from(addr);
            }
        }
        if let Some(v) = fields.get("archive_mode") {
            config.storage.archive_mode = v.as_bool();
        }
        if let Some(v) = fields.get("ghost_pay") {
            if v.as_bool() {
                config.ghost_pay.get_or_insert(GhostPayConfig::default());
            } else {
                config.ghost_pay = None;
            }
        }
        if let Some(v) = fields.get("reaper") {
            config.reaper.enabled = v.as_bool();
        }
        if let Some(v) = fields.get("ghost_mode") {
            config.network.ghost_mode = v.as_bool();
        }
        if let Some(v) = fields.get("mempool_profile") {
            config.policy.profile = match v.as_selected() {
                1 => PolicyProfile::BitcoinPure,
                2 => PolicyProfile::FullOpen,
                _ => PolicyProfile::Permissive,
            };
        }
    })
}

/// Reaper — toggle reaper + configure custom policy filters
pub fn apply_reaper(
    fields: &HashMap<String, FieldValue>,
    config_path: &Path,
) -> Result<String, String> {
    load_and_modify(config_path, |config| {
        if let Some(v) = fields.get("reaper") {
            config.reaper.enabled = v.as_bool();
        }
        if config.reaper.enabled {
            let mut custom = config.policy.custom.clone().unwrap_or_default();
            if let Some(v) = fields.get("filter_inscriptions") {
                custom.allow_inscriptions = !v.as_bool();
            }
            if let Some(v) = fields.get("filter_runes") {
                custom.allow_runes = !v.as_bool();
            }
            if let Some(v) = fields.get("max_witness_size") {
                if let Ok(n) = v.as_text().parse::<usize>() {
                    custom.max_witness_per_input = n;
                }
            }
            config.policy.custom = Some(custom);
        }
    })
}

/// Pool setup — configure mining pool settings
pub fn apply_pool_setup(
    fields: &HashMap<String, FieldValue>,
    config_path: &Path,
) -> Result<String, String> {
    load_and_modify(config_path, |config| {
        if let Some(v) = fields.get("public_mining") {
            config.network.mining_mode = if v.as_bool() {
                crate::config::MiningMode::PublicPool
            } else {
                crate::config::MiningMode::PrivatePool
            };
        }
        if let Some(v) = fields.get("payout_address") {
            let addr = v.as_text().to_string();
            if !addr.is_empty() {
                config.pool.treasury_address = TreasuryAddress::from(addr);
            }
        }
    })
}

/// Ghost Mode — toggle privacy-enhanced relay
pub fn apply_ghost_mode(
    fields: &HashMap<String, FieldValue>,
    config_path: &Path,
) -> Result<String, String> {
    load_and_modify(config_path, |config| {
        if let Some(v) = fields.get("ghost_mode") {
            config.network.ghost_mode = v.as_bool();
        }
    })
}

/// Ghost Shroud — toggle relay delay privacy
pub fn apply_shroud(
    fields: &HashMap<String, FieldValue>,
    config_path: &Path,
) -> Result<String, String> {
    load_and_modify(config_path, |config| {
        if let Some(v) = fields.get("enabled") {
            config.network.shroud_enabled = v.as_bool();
        }
    })
}

/// Ghost Haze — configure block storage mode
pub fn apply_haze(
    fields: &HashMap<String, FieldValue>,
    config_path: &Path,
) -> Result<String, String> {
    load_and_modify(config_path, |config| {
        if let Some(v) = fields.get("haze_mode") {
            config.storage.haze_mode = match v.as_selected() {
                1 => HazeMode::Hazed,
                2 => HazeMode::FullArchive,
                _ => HazeMode::Standard,
            };
        }
    })
}

/// Mempool policy — select mempool acceptance profile
pub fn apply_mempool_policy(
    fields: &HashMap<String, FieldValue>,
    config_path: &Path,
) -> Result<String, String> {
    load_and_modify(config_path, |config| {
        if let Some(v) = fields.get("mempool_profile") {
            config.policy.profile = match v.as_selected() {
                1 => PolicyProfile::BitcoinPure,
                2 => PolicyProfile::FullOpen,
                _ => PolicyProfile::Permissive,
            };
        }
    })
}
