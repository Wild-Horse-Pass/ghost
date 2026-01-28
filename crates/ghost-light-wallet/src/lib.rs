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
//| FILE: lib.rs                                                                                                         |
//|======================================================================================================================|

// Allow dead code for stub implementations pending completion
#![allow(dead_code)]

//! Ghost Light Wallet - Privacy-preserving light wallet for Ghost Pay
//!
//! This crate provides a light wallet implementation that connects to
//! Ghost Service Providers (GSPs) without running a full node.
//!
//! # Key Features
//!
//! - **Keys stay local**: All signing happens on device
//! - **Encrypted storage**: Keys protected with scrypt + ChaCha20
//! - **GSP connection**: WebSocket-based real-time updates
//! - **Multi-GSP failover**: Automatic fallback if GSP unavailable
//! - **Offline operations**: Key derivation and signing work offline
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      Light Wallet                            │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐     │
//! │  │   Keys   │ │ Signing  │ │ Balance  │ │   Cache    │     │
//! │  │(encrypted│ │ (local)  │ │ Tracker  │ │ (SQLite)   │     │
//! │  └──────────┘ └──────────┘ └──────────┘ └────────────┘     │
//! │                           │                                  │
//! │  ┌────────────────────────┴────────────────────────────────┐│
//! │  │                  GSP Client Layer                        ││
//! │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐              ││
//! │  │  │WebSocket │  │ Session  │  │ Failover │              ││
//! │  │  │  Client  │  │ Manager  │  │ Handler  │              ││
//! │  │  └──────────┘  └──────────┘  └──────────┘              ││
//! │  └─────────────────────────────────────────────────────────┘│
//! └───────────────────────────┬─────────────────────────────────┘
//!                             │ WSS (TLS)
//!                             ▼
//!                          [GSP]
//! ```
//!
//! # Example
//!
//! ```no_run
//! use ghost_light_wallet::{LightWallet, WalletConfig};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Create wallet from mnemonic
//!     let config = WalletConfig::default();
//!     let wallet = LightWallet::from_mnemonic(
//!         "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
//!         "password123",
//!         config,
//!     ).unwrap();
//!
//!     // Connect to GSP
//!     wallet.connect("wss://gsp.example.com/ws/v1").await.unwrap();
//!
//!     // Get balance
//!     let balance = wallet.balance();
//!     println!("Balance: {} sats", balance.confirmed);
//! }
//! ```

mod error;
pub mod gsp;
pub mod keys;
pub mod locks;
pub mod payments;
mod signing;
pub mod state;
mod wallet;

pub use error::LightWalletError;
pub use wallet::{LightWallet, WalletConfig, WalletStatus};

/// Light wallet version
pub const WALLET_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!WALLET_VERSION.is_empty());
    }
}
