use clap::Parser;
use ghost_common::setup::{self, FieldValue};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ghost-setup", about = "Ghost Pool node setup (headless)")]
struct Args {
    /// Node nickname
    #[arg(long)]
    nickname: Option<String>,
    /// Enable public mining
    #[arg(long)]
    public_mining: bool,
    /// Payout address (bech32)
    #[arg(long)]
    payout_address: Option<String>,
    /// Enable archive mode
    #[arg(long, default_value = "true")]
    archive: bool,
    /// Enable Ghost Pay
    #[arg(long, default_value = "true")]
    ghost_pay: bool,
    /// Enable Reaper
    #[arg(long, default_value = "true")]
    reaper: bool,
    /// Mempool profile: permissive (0), bitcoin_pure (1), full_open (2)
    #[arg(long, default_value = "permissive")]
    mempool_profile: String,
    /// Config directory
    #[arg(long, default_value = "/etc/ghost")]
    config_dir: PathBuf,
    /// Data directory
    #[arg(long, default_value = "~/.ghost/data")]
    data_dir: PathBuf,
}

fn main() {
    let args = Args::parse();

    // Expand ~ in data_dir
    let data_dir = if args.data_dir.starts_with("~") {
        if let Some(home) = dirs::home_dir() {
            home.join(args.data_dir.strip_prefix("~").unwrap_or(&args.data_dir))
        } else {
            args.data_dir.clone()
        }
    } else {
        args.data_dir.clone()
    };

    let mut fields = HashMap::new();
    if let Some(ref name) = args.nickname {
        fields.insert("nickname".to_string(), FieldValue::Text(name.clone()));
    }
    fields.insert(
        "public_mining".to_string(),
        FieldValue::Bool(args.public_mining),
    );
    if let Some(ref addr) = args.payout_address {
        fields.insert("payout_address".to_string(), FieldValue::Text(addr.clone()));
    }
    fields.insert("archive_mode".to_string(), FieldValue::Bool(args.archive));
    fields.insert("ghost_pay".to_string(), FieldValue::Bool(args.ghost_pay));
    fields.insert("reaper".to_string(), FieldValue::Bool(args.reaper));

    let profile_idx = match args.mempool_profile.as_str() {
        "bitcoin_pure" => 1,
        "full_open" => 2,
        _ => 0, // permissive
    };
    fields.insert(
        "mempool_profile".to_string(),
        FieldValue::Selected(profile_idx),
    );

    match setup::apply_initial_setup(&fields, &args.config_dir, &data_dir) {
        Ok(result) => {
            println!("Setup complete!");
            println!("  Node ID: {}", result.node_id_hex);
            println!("  Config:  {}", result.config_path.display());
        }
        Err(e) => {
            eprintln!("Setup failed: {e}");
            std::process::exit(1);
        }
    }
}
