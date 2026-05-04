//! Wraith Wallet — core library.
//!
//! All wallet logic (keystore, modules, ghost-pay client, IPC server) lives here.
//! Binaries (`wraithd`, `wraith`) and the GUI shell are thin wrappers over this crate.

pub mod chain;
pub mod gsp;
