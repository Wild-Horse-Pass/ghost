//! Network support demo

use bitcoin::Network;
use ghost_light_wallet::{LightWallet, WalletConfig};
use std::path::PathBuf;

fn main() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║        GHOST LIGHT WALLET - NETWORK SUPPORT                  ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    let networks = [
        ("Mainnet", Network::Bitcoin),
        ("Testnet", Network::Testnet),
        ("Signet", Network::Signet),
        ("Regtest", Network::Regtest),
    ];

    for (name, network) in networks {
        let config = WalletConfig {
            data_dir: PathBuf::from(format!("/tmp/ghost-{}", name.to_lowercase())),
            network,
            gsp_urls: vec![],
            auto_reconnect: false,
            reconnect_interval_secs: 5,
            params_node: None,
        };

        match LightWallet::from_mnemonic(mnemonic, "password", config) {
            Ok(wallet) => {
                println!("┌─────────────────────────────────────────────────────────────┐");
                println!("│ {:^59} │", name);
                println!("├─────────────────────────────────────────────────────────────┤");
                println!("│ Network:   {:?}", wallet.network());
                println!("│ Ghost ID:  {}...", &wallet.ghost_id().unwrap()[..40]);
                println!("│ Wallet ID: {}", wallet.wallet_id().unwrap());
                println!("│ Status:    ✓ Working",);
                println!("└─────────────────────────────────────────────────────────────┘\n");
            }
            Err(e) => {
                println!("│ {}: ✗ Error: {}", name, e);
            }
        }
    }

    println!("All networks supported!");
}
