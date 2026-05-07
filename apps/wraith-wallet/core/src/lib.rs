//! Wraith Wallet — core library.
//!
//! All wallet logic (keystore, modules, ghost-pay client, IPC server) lives here.
//! Binaries (`wraithd`, `wraith`) and the GUI shell are thin wrappers over this crate.

pub mod auth;
pub mod chain;
pub mod gsp;
pub mod keystore;
pub mod light;
pub mod mainnet_guard;
pub mod signer;
pub mod wraith;
pub mod wraith_signer;
