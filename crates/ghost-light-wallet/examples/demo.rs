//! Ghost Light Wallet Demo

use ghost_light_wallet::{LightWallet, WalletConfig};
use bitcoin::Network;

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           GHOST LIGHT WALLET DEMO                            ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    // Create wallet from test mnemonic
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let config = WalletConfig::default();

    println!("Creating wallet from mnemonic...\n");
    let wallet = LightWallet::from_mnemonic(mnemonic, "demopassword", config).unwrap();

    println!("✓ Wallet created successfully!\n");

    // Show wallet info
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ WALLET INFO                                                 │");
    println!("├─────────────────────────────────────────────────────────────┤");
    println!("│ Ghost ID:  {}", wallet.ghost_id().unwrap());
    println!("│ Wallet ID: {}", wallet.wallet_id().unwrap());
    println!("│ Network:   {:?}", wallet.network());
    println!("│ Status:    {:?}", wallet.status());
    println!("└─────────────────────────────────────────────────────────────┘\n");

    // Show balance (cached, not connected to GSP)
    let balance = wallet.balance();
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ BALANCE (offline - cached)                                  │");
    println!("├─────────────────────────────────────────────────────────────┤");
    println!("│ Confirmed:   {:>12} sats", balance.confirmed);
    println!("│ Unconfirmed: {:>12} sats", balance.unconfirmed);
    println!("│ Locked:      {:>12} sats", balance.locked);
    println!("│ Available:   {:>12} sats", balance.available());
    println!("└─────────────────────────────────────────────────────────────┘\n");

    // Lock wallet
    wallet.lock();
    println!("✓ Wallet locked. Status: {:?}\n", wallet.status());

    println!("Demo complete!");
    println!("\nNote: Balance shows 0 because we're not connected to a GSP.");
    println!("Run with: ghost-wallet --gsp wss://your-gsp.com/ws/v1 balance");
}
