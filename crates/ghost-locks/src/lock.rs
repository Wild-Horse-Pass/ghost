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
//| FILE: lock.rs                                                                                                        |
//|======================================================================================================================|

//! Ghost Lock - P2TR UTXO with timelock recovery
//!
//! A Ghost Lock is a Taproot output that can be spent via:
//! - Key path: Using the lock key (normal, efficient)
//! - Script path: Using the recovery key after timelock (emergency)

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::taproot::TaprootSpendInfo;
use serde::{Deserialize, Serialize};

use crate::denomination::Denomination;
use crate::error::GhostLockError;
use crate::jump::{JumpRiskTier, JumpSchedule};
use crate::script::{build_lock_script, ghost_lock_id, to_x_only};
use crate::state::LockState;
use crate::timelock::TimelockTier;

/// A Ghost Lock - P2TR UTXO with timelock recovery
#[derive(Debug, Clone)]
pub struct GhostLock {
    /// Lock public key (x-only for key path)
    lock_pubkey: XOnlyPublicKey,
    /// Recovery public key (for script path)
    recovery_pubkey: XOnlyPublicKey,
    /// Standard denomination
    denomination: Denomination,
    /// Timelock tier for recovery
    timelock_tier: TimelockTier,
    /// Block height when created
    creation_height: u32,
    /// Taproot spend info
    spend_info: TaprootSpendInfo,
    /// Unique lock ID
    lock_id: [u8; 32],
    /// Current state
    state: LockState,
    /// Jump schedule
    jump_schedule: JumpSchedule,
}

impl GhostLock {
    /// Create a new Ghost Lock
    pub fn new<C: bitcoin::secp256k1::Signing>(
        secp: &Secp256k1<C>,
        lock_secret: &SecretKey,
        recovery_secret: &SecretKey,
        denomination: Denomination,
        timelock_tier: TimelockTier,
        creation_height: u32,
    ) -> Result<Self, GhostLockError> {
        let lock_pubkey_full = PublicKey::from_secret_key(secp, lock_secret);
        let recovery_pubkey_full = PublicKey::from_secret_key(secp, recovery_secret);

        let lock_pubkey = to_x_only(&lock_pubkey_full);
        let recovery_pubkey = to_x_only(&recovery_pubkey_full);

        Self::from_pubkeys(
            lock_pubkey,
            recovery_pubkey,
            denomination,
            timelock_tier,
            creation_height,
        )
    }

    /// Create from existing public keys
    pub fn from_pubkeys(
        lock_pubkey: XOnlyPublicKey,
        recovery_pubkey: XOnlyPublicKey,
        denomination: Denomination,
        timelock_tier: TimelockTier,
        creation_height: u32,
    ) -> Result<Self, GhostLockError> {
        // Build taproot script
        let spend_info = build_lock_script(
            &lock_pubkey,
            &recovery_pubkey,
            creation_height,
            timelock_tier,
        )?;

        // Compute lock ID
        let lock_id = ghost_lock_id(
            &lock_pubkey,
            &recovery_pubkey,
            creation_height,
            denomination.sats(),
        );

        // Create jump schedule
        let jump_schedule = JumpSchedule::from_denomination(denomination, creation_height);

        Ok(Self {
            lock_pubkey,
            recovery_pubkey,
            denomination,
            timelock_tier,
            creation_height,
            spend_info,
            lock_id,
            state: LockState::Active,
            jump_schedule,
        })
    }

    /// Get the lock public key
    pub fn lock_pubkey(&self) -> &XOnlyPublicKey {
        &self.lock_pubkey
    }

    /// Get the recovery public key
    pub fn recovery_pubkey(&self) -> &XOnlyPublicKey {
        &self.recovery_pubkey
    }

    /// Get the denomination
    pub fn denomination(&self) -> Denomination {
        self.denomination
    }

    /// Get the satoshi value
    pub fn sats(&self) -> u64 {
        self.denomination.sats()
    }

    /// Get the timelock tier
    pub fn timelock_tier(&self) -> TimelockTier {
        self.timelock_tier
    }

    /// Get the creation height
    pub fn creation_height(&self) -> u32 {
        self.creation_height
    }

    /// Get the taproot spend info
    pub fn spend_info(&self) -> &TaprootSpendInfo {
        &self.spend_info
    }

    /// Get the taproot output key (for scriptPubKey)
    pub fn output_key(&self) -> XOnlyPublicKey {
        self.spend_info.output_key().to_x_only_public_key()
    }

    /// Get the unique lock ID
    pub fn lock_id(&self) -> &[u8; 32] {
        &self.lock_id
    }

    /// Get the lock ID as hex string
    pub fn lock_id_hex(&self) -> String {
        hex::encode(self.lock_id)
    }

    /// Get current state
    pub fn state(&self) -> LockState {
        self.state
    }

    /// Set state
    pub fn set_state(&mut self, state: LockState) {
        self.state = state;
    }

    /// Get jump schedule
    pub fn jump_schedule(&self) -> &JumpSchedule {
        &self.jump_schedule
    }

    /// Get jump risk tier
    pub fn jump_risk_tier(&self) -> JumpRiskTier {
        self.jump_schedule.tier
    }

    /// Calculate the recovery height
    pub fn recovery_height(&self) -> u32 {
        self.timelock_tier.recovery_height(self.creation_height)
    }

    /// Check if recovery is available at given height
    pub fn is_recovery_available(&self, current_height: u32) -> bool {
        self.timelock_tier
            .is_recovery_available(self.creation_height, current_height)
    }

    /// Get blocks until recovery is available
    pub fn blocks_until_recovery(&self, current_height: u32) -> u32 {
        self.timelock_tier
            .blocks_until_recovery(self.creation_height, current_height)
    }

    /// Check if jump is needed
    pub fn needs_jump(&self, current_height: u32) -> bool {
        self.jump_schedule.needs_jump(current_height)
    }

    /// Get blocks until jump is needed
    pub fn blocks_until_jump(&self, current_height: u32) -> u32 {
        self.jump_schedule.blocks_until_jump(current_height)
    }

    /// Get jump urgency (0.0 = just created, 1.0 = overdue)
    pub fn jump_urgency(&self, current_height: u32) -> f64 {
        self.jump_schedule.urgency(current_height)
    }

    /// Check if jump warning should be shown
    pub fn should_warn_jump(&self, current_height: u32) -> bool {
        self.jump_schedule.should_warn(current_height)
    }
}

/// Serializable Ghost Lock data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostLockData {
    pub lock_pubkey: String,
    pub recovery_pubkey: String,
    pub denomination: Denomination,
    pub timelock_tier: TimelockTier,
    pub creation_height: u32,
    pub lock_id: String,
    pub state: LockState,
}

impl From<&GhostLock> for GhostLockData {
    fn from(lock: &GhostLock) -> Self {
        Self {
            lock_pubkey: hex::encode(lock.lock_pubkey.serialize()),
            recovery_pubkey: hex::encode(lock.recovery_pubkey.serialize()),
            denomination: lock.denomination,
            timelock_tier: lock.timelock_tier,
            creation_height: lock.creation_height,
            lock_id: lock.lock_id_hex(),
            state: lock.state,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn generate_secret_key() -> SecretKey {
        let mut rng = rand::thread_rng();
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        SecretKey::from_slice(&secret_bytes).expect("32 bytes, within curve order")
    }

    #[test]
    fn test_create_lock() {
        let secp = Secp256k1::new();
        let lock_secret = generate_secret_key();
        let recovery_secret = generate_secret_key();

        let lock = GhostLock::new(
            &secp,
            &lock_secret,
            &recovery_secret,
            Denomination::Small,
            TimelockTier::Standard,
            800_000,
        )
        .unwrap();

        assert_eq!(lock.sats(), 1_000_000);
        assert_eq!(lock.creation_height(), 800_000);
        assert_eq!(lock.state(), LockState::Active);
    }

    #[test]
    fn test_lock_id_unique() {
        let secp = Secp256k1::new();

        let lock1 = GhostLock::new(
            &secp,
            &generate_secret_key(),
            &generate_secret_key(),
            Denomination::Small,
            TimelockTier::Standard,
            800_000,
        )
        .unwrap();

        let lock2 = GhostLock::new(
            &secp,
            &generate_secret_key(),
            &generate_secret_key(),
            Denomination::Small,
            TimelockTier::Standard,
            800_000,
        )
        .unwrap();

        assert_ne!(lock1.lock_id(), lock2.lock_id());
    }

    #[test]
    fn test_jump_schedule() {
        let secp = Secp256k1::new();

        let lock = GhostLock::new(
            &secp,
            &generate_secret_key(),
            &generate_secret_key(),
            Denomination::Large, // High risk tier
            TimelockTier::Standard,
            800_000,
        )
        .unwrap();

        assert_eq!(lock.jump_risk_tier(), JumpRiskTier::High);
        assert!(!lock.needs_jump(800_000));
        assert!(lock.needs_jump(800_000 + 144 * 7 + 1)); // After 7 days
    }

    #[test]
    fn test_serialization() {
        let secp = Secp256k1::new();

        let lock = GhostLock::new(
            &secp,
            &generate_secret_key(),
            &generate_secret_key(),
            Denomination::Medium,
            TimelockTier::Short,
            800_000,
        )
        .unwrap();

        let data = GhostLockData::from(&lock);
        assert_eq!(data.denomination, Denomination::Medium);
        assert_eq!(data.timelock_tier, TimelockTier::Short);
    }
}
