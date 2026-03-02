use ghost_common::config::{GhostPayConfig, NodeConfig, PolicyProfile};
use ghost_common::identity::NodeIdentity;
use ghost_common::types::TreasuryAddress;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::wizard::FieldValue;

pub struct SetupResult {
    pub config_path: PathBuf,
    pub node_id_hex: String,
}

pub fn apply_initial_setup(
    fields: &HashMap<String, FieldValue>,
    config_dir: &Path,
    data_dir: &Path,
) -> Result<SetupResult, String> {
    let nickname = fields
        .get("nickname")
        .map(|v| v.as_text().to_string())
        .unwrap_or_default();
    let public_mining = fields
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
    let ghost_pay_enabled = fields
        .get("ghost_pay")
        .map(|v| v.as_bool())
        .unwrap_or(true);
    let reaper_enabled = fields
        .get("reaper")
        .map(|v| v.as_bool())
        .unwrap_or(true);
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
    config.network.public_mining = public_mining;
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
