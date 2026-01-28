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

//! Ghost Locks - P2TR UTXO management for Ghost Pay
//!
//! Ghost Locks are the on-chain representation of funds in Ghost Pay. They use
//! Taproot outputs with:
//! - Key path: Normal spending with Ghost Key (efficient, private)
//! - Script path: Recovery after timelock expires
//!
//! # Features
//!
//! - **Standard Denominations**: Micro (10k sats) to XL (10 BTC) for privacy
//! - **Timelock Recovery**: 6 month, 1 year, or 2 year recovery options
//! - **Jump Locks**: Risk-tiered automatic key rotation
//!
//! # Example
//!
//! ```
//! use ghost_locks::{GhostLock, Denomination, TimelockTier};
//! use bitcoin::secp256k1::{Secp256k1, SecretKey, rand::rngs::OsRng};
//!
//! let secp = Secp256k1::new();
//! let lock_secret = SecretKey::new(&mut OsRng);
//! let recovery_secret = SecretKey::new(&mut OsRng);
//!
//! let lock = GhostLock::new(
//!     &secp,
//!     &lock_secret,
//!     &recovery_secret,
//!     Denomination::Small,
//!     TimelockTier::Standard,
//!     800_000,
//! );
//!
//! assert!(lock.is_ok());
//! ```

mod denomination;
mod error;
mod jump;
mod lock;
mod script;
mod state;
mod timelock;

pub use denomination::{optimal_denominations, Denomination};
pub use error::GhostLockError;
pub use jump::JumpRiskTier;
pub use lock::{GhostLock, GhostLockData};
pub use script::{
    build_lock_script, build_recovery_script, compute_output_key, ghost_lock_id, to_x_only,
};
pub use state::{LockState, StateTransition};
pub use timelock::TimelockTier;

/// OP_RETURN marker for Ghost Lock creation
pub const GHOST_LOCK_MARKER: &[u8] = b"GPGL";

/// Minimum lock amount (dust threshold)
pub const MIN_LOCK_SATS: u64 = 546;

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{rand::rngs::OsRng, Secp256k1, SecretKey};

    #[test]
    fn test_create_lock() {
        let secp = Secp256k1::new();
        let lock_secret = SecretKey::new(&mut OsRng);
        let recovery_secret = SecretKey::new(&mut OsRng);

        let lock = GhostLock::new(
            &secp,
            &lock_secret,
            &recovery_secret,
            Denomination::Small,
            TimelockTier::Standard,
            800_000,
        );

        assert!(lock.is_ok());
        let lock = lock.unwrap();
        assert_eq!(lock.denomination(), Denomination::Small);
        assert_eq!(lock.timelock_tier(), TimelockTier::Standard);
        assert_eq!(lock.creation_height(), 800_000);
    }

    #[test]
    fn test_lock_address() {
        let secp = Secp256k1::new();
        let lock_secret = SecretKey::new(&mut OsRng);
        let recovery_secret = SecretKey::new(&mut OsRng);

        let lock = GhostLock::new(
            &secp,
            &lock_secret,
            &recovery_secret,
            Denomination::Medium,
            TimelockTier::Short,
            800_000,
        )
        .unwrap();

        // Should have a valid output key
        let _output_key = lock.output_key();
    }

    #[test]
    fn test_recovery_available() {
        let secp = Secp256k1::new();
        let lock_secret = SecretKey::new(&mut OsRng);
        let recovery_secret = SecretKey::new(&mut OsRng);

        let lock = GhostLock::new(
            &secp,
            &lock_secret,
            &recovery_secret,
            Denomination::Small,
            TimelockTier::Short, // 6 months
            800_000,
        )
        .unwrap();

        // Not available yet
        assert!(!lock.is_recovery_available(800_000));
        assert!(!lock.is_recovery_available(810_000));

        // Available after timelock
        let recovery_height = lock.recovery_height();
        assert!(lock.is_recovery_available(recovery_height));
        assert!(lock.is_recovery_available(recovery_height + 1000));
    }
}
