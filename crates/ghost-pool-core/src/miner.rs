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
//| FILE: miner.rs                                                                              |
//|======================================================================================================================|

//! Miner connection management.
//!
//! Tracks connected miners, their subscriptions, and assigned work.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use ghost_primitives::types::PayoutAddress;
use crate::stratum::StratumVersion;
use crate::error::PoolError;

type HmacSha256 = Hmac<Sha256>;

// =============================================================================
// Cryptographic Payout Commitment (Fix 3)
// =============================================================================

/// Cryptographic commitment to a payout address.
///
/// This prevents payout address spoofing by binding the address
/// to a timestamp and signing with the pool's secret.
///
/// # Security
///
/// The commitment ensures:
/// - Payout addresses cannot be changed without the pool's secret
/// - Replay attacks are mitigated via timestamps
/// - Address ownership is cryptographically verifiable
/// - Clock manipulation is detected via monotonic time tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutCommitment {
    /// The committed payout address.
    pub address: PayoutAddress,
    /// When the commitment was created (wall clock).
    pub timestamp: u64,
    /// HMAC-SHA256 signature binding address to timestamp.
    #[serde(with = "hex_array")]
    pub signature: [u8; 32],
    /// Monotonic timestamp for clock skew detection (not serialized for network).
    /// HIGH: Prevents attackers from manipulating system clock to bypass expiration.
    #[serde(skip, default)]
    pub monotonic_created_at: Option<u64>,
}

/// Hex serialization for 32-byte arrays.
mod hex_array {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Thread-local monotonic time reference for clock manipulation detection.
/// Stored as Instant converted to duration since program start.
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use once_cell::sync::Lazy;

/// Global monotonic counter that only increases, used to detect clock rollback.
static MONOTONIC_COUNTER: Lazy<(std::time::Instant, AtomicU64)> = Lazy::new(|| {
    (std::time::Instant::now(), AtomicU64::new(0))
});

/// Get current monotonic time as seconds since program start.
fn get_monotonic_secs() -> u64 {
    let (start, counter) = &*MONOTONIC_COUNTER;
    let elapsed = start.elapsed().as_secs();
    // Update counter to at least the current value (never goes backwards)
    let mut current = counter.load(AtomicOrdering::SeqCst);
    loop {
        let new_val = current.max(elapsed);
        match counter.compare_exchange(current, new_val, AtomicOrdering::SeqCst, AtomicOrdering::SeqCst) {
            Ok(_) => return new_val,
            Err(actual) => current = actual,
        }
    }
}

impl PayoutCommitment {
    /// Create a new commitment signed with the pool's secret.
    ///
    /// # Arguments
    /// * `address` - The payout address to commit to
    /// * `pool_secret` - The pool's secret key for signing
    pub fn new(address: PayoutAddress, pool_secret: &[u8]) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs();

        let mut mac = HmacSha256::new_from_slice(pool_secret)
            .expect("HMAC accepts any key size");
        mac.update(address.as_bytes());
        mac.update(&timestamp.to_le_bytes());

        let signature: [u8; 32] = mac.finalize().into_bytes().into();

        Self {
            address,
            timestamp,
            signature,
            // HIGH: Track monotonic time for clock manipulation detection
            monotonic_created_at: Some(get_monotonic_secs()),
        }
    }

    /// Verify the commitment is valid.
    ///
    /// # Arguments
    /// * `pool_secret` - The pool's secret key used for signing
    ///
    /// # Returns
    /// `true` if the commitment is valid, `false` otherwise
    pub fn verify(&self, pool_secret: &[u8]) -> bool {
        let mut mac = HmacSha256::new_from_slice(pool_secret)
            .expect("HMAC accepts any key size");
        mac.update(self.address.as_bytes());
        mac.update(&self.timestamp.to_le_bytes());

        mac.verify_slice(&self.signature).is_ok()
    }

    /// Verify the commitment is valid and not expired.
    ///
    /// # Arguments
    /// * `pool_secret` - The pool's secret key used for signing
    /// * `max_age_secs` - Maximum age of the commitment in seconds
    ///
    /// # Returns
    /// `true` if the commitment is valid and not expired, `false` otherwise
    pub fn verify_with_expiry(&self, pool_secret: &[u8], max_age_secs: u64) -> bool {
        // First verify the signature
        if !self.verify(pool_secret) {
            return false;
        }

        // Then check expiration
        !self.is_expired(max_age_secs)
    }

    /// Check if the commitment has expired.
    ///
    /// # Arguments
    /// * `max_age_secs` - Maximum age in seconds (e.g., 86400 for 24 hours)
    ///
    /// # Returns
    /// `true` if the commitment is older than max_age_secs
    ///
    /// # Security
    /// Uses both wall clock and monotonic time to detect clock manipulation.
    /// If the system clock has been rolled back, the monotonic check will still
    /// correctly detect expired commitments.
    pub fn is_expired(&self, max_age_secs: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Wall clock check
        let wall_expired = now > self.timestamp + max_age_secs;

        // HIGH: Monotonic time check for clock manipulation detection
        // If monotonic time says it's expired, it is expired regardless of wall clock
        let monotonic_expired = if let Some(created_at) = self.monotonic_created_at {
            let monotonic_now = get_monotonic_secs();
            monotonic_now > created_at + max_age_secs
        } else {
            // No monotonic timestamp (deserialized from network) - fall back to wall clock only
            // Note: Commitments from restarts won't have monotonic time, which is expected
            false
        };

        // Expired if EITHER check says expired (defense in depth)
        wall_expired || monotonic_expired
    }

    /// Get the age of this commitment in seconds.
    pub fn age_secs(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        now.saturating_sub(self.timestamp)
    }

    /// Get the committed address.
    pub fn address(&self) -> &PayoutAddress {
        &self.address
    }
}

/// Unique identifier for a connected miner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MinerId(u64);

impl MinerId {
    /// Create a new miner ID.
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Get the inner value.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for MinerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "miner-{}", self.0)
    }
}

/// State of a miner connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MinerState {
    /// Just connected, not yet subscribed.
    Connected,
    /// Subscribed to pool.
    Subscribed,
    /// Authorized with valid credentials.
    Authorized,
    /// Actively mining.
    Mining,
    /// Disconnected.
    Disconnected,
}

/// A connected miner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Miner {
    /// Unique miner ID.
    pub id: MinerId,
    /// Miner's payout address (for backwards compatibility).
    #[deprecated(note = "Use payout_commitment instead for security")]
    pub payout_address: Option<PayoutAddress>,
    /// Cryptographic payout commitment (Fix 3).
    /// This binds the payout address cryptographically to prevent spoofing.
    pub payout_commitment: Option<PayoutCommitment>,
    /// Worker name (optional).
    pub worker_name: Option<String>,
    /// Stratum protocol version.
    pub protocol_version: StratumVersion,
    /// Current state.
    pub state: MinerState,
    /// Assigned extranonce1.
    pub extranonce1: Vec<u8>,
    /// Channel ID (for SV2).
    pub channel_id: Option<u32>,
    /// Current difficulty target.
    pub difficulty: f64,
    /// Reported hashrate (H/s).
    pub reported_hashrate: Option<f64>,
    /// Observed hashrate (H/s).
    pub observed_hashrate: f64,
    /// Connection timestamp.
    pub connected_at: i64,
    /// Last activity timestamp.
    pub last_activity_at: i64,
    /// Total shares submitted.
    pub shares_submitted: u64,
    /// Valid shares.
    pub shares_valid: u64,
    /// Stale shares.
    pub shares_stale: u64,
    /// Invalid shares.
    pub shares_invalid: u64,
    /// User agent string.
    pub user_agent: Option<String>,
}

impl Miner {
    /// Create a new miner.
    #[allow(deprecated)]
    pub fn new(id: MinerId, extranonce1: Vec<u8>) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            id,
            payout_address: None,
            payout_commitment: None,
            worker_name: None,
            protocol_version: StratumVersion::V2,
            state: MinerState::Connected,
            extranonce1,
            channel_id: None,
            difficulty: 1.0,
            reported_hashrate: None,
            observed_hashrate: 0.0,
            connected_at: now,
            last_activity_at: now,
            shares_submitted: 0,
            shares_valid: 0,
            shares_stale: 0,
            shares_invalid: 0,
            user_agent: None,
        }
    }

    /// Get the miner's committed payout address.
    ///
    /// Returns the address from the payout commitment if available,
    /// otherwise falls back to the legacy payout_address field.
    #[allow(deprecated)]
    pub fn get_payout_address(&self) -> Option<&PayoutAddress> {
        self.payout_commitment
            .as_ref()
            .map(|c| &c.address)
            .or(self.payout_address.as_ref())
    }

    /// Check if miner is authorized.
    pub fn is_authorized(&self) -> bool {
        matches!(self.state, MinerState::Authorized | MinerState::Mining)
    }

    /// Check if miner is active.
    pub fn is_active(&self) -> bool {
        !matches!(self.state, MinerState::Disconnected)
    }

    /// Record activity.
    pub fn touch(&mut self) {
        self.last_activity_at = chrono::Utc::now().timestamp();
    }

    /// Record a valid share.
    pub fn record_valid_share(&mut self) {
        self.shares_submitted += 1;
        self.shares_valid += 1;
        self.touch();
    }

    /// Record a stale share.
    pub fn record_stale_share(&mut self) {
        self.shares_submitted += 1;
        self.shares_stale += 1;
        self.touch();
    }

    /// Record an invalid share.
    pub fn record_invalid_share(&mut self) {
        self.shares_submitted += 1;
        self.shares_invalid += 1;
        self.touch();
    }

    /// Get share acceptance rate.
    pub fn acceptance_rate(&self) -> f64 {
        if self.shares_submitted == 0 {
            return 0.0;
        }
        self.shares_valid as f64 / self.shares_submitted as f64
    }

    /// Get connection duration in seconds.
    pub fn connection_duration(&self) -> i64 {
        chrono::Utc::now().timestamp() - self.connected_at
    }

    /// Get idle time in seconds.
    pub fn idle_time(&self) -> i64 {
        chrono::Utc::now().timestamp() - self.last_activity_at
    }
}

/// Default payout commitment expiry time (24 hours in seconds).
pub const DEFAULT_COMMITMENT_EXPIRY_SECS: u64 = 86400;

/// Minimum required pool secret length in bytes.
pub const MIN_POOL_SECRET_LEN: usize = 32;

/// Pool secret configuration errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PoolSecretError {
    #[error("Pool secret not configured - call set_pool_secret() before accepting miners")]
    NotConfigured,
    #[error("Pool secret too short: {0} bytes < {MIN_POOL_SECRET_LEN} required")]
    TooShort(usize),
    #[error("Pool secret is all zeros - use a cryptographically secure random value")]
    AllZeros,
    #[error("Pool secret has insufficient entropy")]
    InsufficientEntropy,
}

/// Manager for connected miners.
pub struct MinerManager {
    /// Miners by ID.
    miners: HashMap<MinerId, Miner>,
    /// Next miner ID.
    next_id: u64,
    /// Extranonce size.
    extranonce1_size: usize,
    /// Maximum miners.
    max_miners: usize,
    /// Next extranonce1 counter.
    extranonce_counter: u64,
    /// Pool secret for payout commitments.
    pool_secret: Vec<u8>,
    /// Commitment expiry time in seconds.
    commitment_expiry_secs: u64,
    /// Whether pool secret has been properly configured.
    /// CRITICAL: Must be true before accepting miner authorizations.
    pool_secret_configured: bool,
}

impl Default for MinerManager {
    fn default() -> Self {
        Self::new(10_000, 4)
    }
}

impl MinerManager {
    /// Create a new miner manager.
    ///
    /// SECURITY: The pool secret is NOT configured by default. You MUST call
    /// `set_pool_secret()` with a cryptographically secure secret before
    /// accepting any miner authorizations.
    pub fn new(max_miners: usize, extranonce1_size: usize) -> Self {
        Self {
            miners: HashMap::new(),
            next_id: 1,
            extranonce1_size,
            max_miners,
            extranonce_counter: 0,
            pool_secret: Vec::new(), // Empty until configured
            commitment_expiry_secs: DEFAULT_COMMITMENT_EXPIRY_SECS,
            pool_secret_configured: false, // CRITICAL: Must be set before use
        }
    }

    /// Set the commitment expiry time.
    pub fn set_commitment_expiry(&mut self, expiry_secs: u64) {
        self.commitment_expiry_secs = expiry_secs;
    }

    /// Get the commitment expiry time in seconds.
    pub fn commitment_expiry_secs(&self) -> u64 {
        self.commitment_expiry_secs
    }

    /// Validate that a pool secret meets security requirements.
    fn validate_pool_secret(secret: &[u8]) -> Result<(), PoolSecretError> {
        // Check minimum length
        if secret.len() < MIN_POOL_SECRET_LEN {
            return Err(PoolSecretError::TooShort(secret.len()));
        }

        // Check not all zeros
        if secret.iter().all(|&b| b == 0) {
            return Err(PoolSecretError::AllZeros);
        }

        // Check entropy (at least 16 unique bytes required)
        // SECURITY: 8 unique bytes = only 2^8 permutations, easily brute-forced
        // 16 unique bytes provides adequate protection against commitment forgery
        let unique_bytes: std::collections::HashSet<_> = secret.iter().collect();
        if unique_bytes.len() < 16 {
            return Err(PoolSecretError::InsufficientEntropy);
        }

        Ok(())
    }

    /// Set the pool secret for payout commitments.
    ///
    /// SECURITY: This MUST be called with a cryptographically secure secret
    /// before accepting miner authorizations. The secret should be:
    /// - At least 32 bytes long
    /// - Generated from a CSPRNG (e.g., `rand::thread_rng().gen::<[u8; 32]>()`)
    /// - Unique per pool instance
    /// - Kept confidential
    ///
    /// # Errors
    /// Returns an error if the secret doesn't meet security requirements.
    pub fn set_pool_secret(&mut self, secret: Vec<u8>) -> Result<(), PoolSecretError> {
        Self::validate_pool_secret(&secret)?;
        self.pool_secret = secret;
        self.pool_secret_configured = true;
        tracing::info!("Pool secret configured successfully ({} bytes)", self.pool_secret.len());
        Ok(())
    }

    /// Check if the pool secret has been properly configured.
    ///
    /// CRITICAL: This should return true before accepting any miner authorizations.
    pub fn is_pool_secret_configured(&self) -> bool {
        self.pool_secret_configured
    }

    /// Get the pool secret (for verification).
    ///
    /// # Panics
    /// Panics if pool secret has not been configured. Use `is_pool_secret_configured()`
    /// to check first, or ensure `set_pool_secret()` is called during initialization.
    pub fn pool_secret(&self) -> &[u8] {
        if !self.pool_secret_configured {
            panic!(
                "CRITICAL: Pool secret not configured! Call set_pool_secret() before use. \
                 This is a security vulnerability - payout commitments cannot be verified."
            );
        }
        &self.pool_secret
    }

    /// Register a new miner.
    ///
    /// SECURITY: Registration is blocked until the pool secret is configured.
    /// This prevents the race condition where miners connect before the pool
    /// is fully initialized, which could lead to weak payout commitments.
    pub fn register_miner(&mut self) -> Result<Miner, PoolError> {
        // CRITICAL: Block ALL miner registrations until pool is initialized
        // This closes the race window between pool creation and secret setup
        if !self.pool_secret_configured {
            return Err(PoolError::Configuration(
                "Pool not initialized - waiting for pool secret configuration".into(),
            ));
        }

        if self.miners.len() >= self.max_miners {
            return Err(PoolError::PoolFull);
        }

        let id = MinerId::new(self.next_id);
        self.next_id += 1;

        let extranonce1 = self.generate_extranonce1();
        let miner = Miner::new(id, extranonce1);

        self.miners.insert(id, miner.clone());
        Ok(miner)
    }

    /// Generate a unique extranonce1.
    fn generate_extranonce1(&mut self) -> Vec<u8> {
        self.extranonce_counter += 1;
        let bytes = self.extranonce_counter.to_be_bytes();
        bytes[8 - self.extranonce1_size..].to_vec()
    }

    /// Get a miner by ID.
    pub fn get_miner(&self, id: &MinerId) -> Option<&Miner> {
        self.miners.get(id)
    }

    /// Get a mutable miner by ID.
    pub fn get_miner_mut(&mut self, id: &MinerId) -> Option<&mut Miner> {
        self.miners.get_mut(id)
    }

    /// Authorize a miner with a payout commitment.
    ///
    /// Creates a cryptographic commitment binding the payout address
    /// to prevent spoofing attacks.
    #[allow(deprecated)]
    pub fn authorize(
        &mut self,
        id: &MinerId,
        payout_address: PayoutAddress,
        worker_name: Option<String>,
    ) -> Result<(), PoolError> {
        // CRITICAL: Ensure pool secret is configured before authorization
        // This prevents creating commitments with an empty/zero secret
        if !self.pool_secret_configured {
            return Err(PoolError::Configuration(
                "Pool secret not configured - call set_pool_secret() before accepting miners".into(),
            ));
        }

        let miner = self
            .miners
            .get_mut(id)
            .ok_or_else(|| PoolError::MinerNotFound(id.to_string()))?;

        // SECURITY: Prevent commitment override attack
        // If miner already has a valid (non-expired) commitment, reject re-authorization
        // with a different address. This prevents attackers from stealing payouts by
        // overwriting legitimate commitments.
        if let Some(ref existing) = miner.payout_commitment {
            // Check if existing commitment is still valid (not expired)
            if !existing.is_expired(self.commitment_expiry_secs) {
                // Only allow re-auth with SAME address (e.g., to refresh commitment)
                if existing.address != payout_address {
                    return Err(PoolError::Protocol(format!(
                        "Cannot change payout address while commitment is valid. \
                         Current: {}, Requested: {}. Wait for commitment to expire or disconnect.",
                        existing.address.as_str(),
                        payout_address.as_str()
                    )));
                }
                // Same address - allow refreshing the commitment
                tracing::debug!(
                    "Refreshing commitment for miner {} with same address",
                    id
                );
            } else {
                // Expired commitment - allow changing address
                tracing::info!(
                    "Miner {} commitment expired, allowing new address",
                    id
                );
            }
        }

        // Create cryptographic commitment (Fix 3)
        let commitment = PayoutCommitment::new(payout_address.clone(), &self.pool_secret);
        miner.payout_commitment = Some(commitment);

        // Keep legacy field for backwards compatibility
        miner.payout_address = Some(payout_address);
        miner.worker_name = worker_name;
        miner.state = MinerState::Authorized;
        miner.touch();

        Ok(())
    }

    /// Verify a miner's payout commitment.
    ///
    /// Returns true if the commitment is valid and not expired, false otherwise.
    pub fn verify_payout_commitment(&self, id: &MinerId) -> bool {
        self.miners
            .get(id)
            .and_then(|m| m.payout_commitment.as_ref())
            .map(|c| c.verify_with_expiry(&self.pool_secret, self.commitment_expiry_secs))
            .unwrap_or(false)
    }

    /// Check if a miner's commitment has expired and needs renewal.
    ///
    /// Returns true if the commitment exists but is expired.
    pub fn is_commitment_expired(&self, id: &MinerId) -> bool {
        self.miners
            .get(id)
            .and_then(|m| m.payout_commitment.as_ref())
            .map(|c| c.is_expired(self.commitment_expiry_secs))
            .unwrap_or(false)
    }

    /// Cleanup miners with expired commitments.
    ///
    /// Disconnects miners whose payout commitments have expired.
    /// Returns the number of miners cleaned up.
    pub fn cleanup_expired_commitments(&mut self) -> usize {
        let expired: Vec<MinerId> = self
            .miners
            .iter()
            .filter(|(_, m)| {
                m.payout_commitment
                    .as_ref()
                    .map(|c| c.is_expired(self.commitment_expiry_secs))
                    .unwrap_or(false)
            })
            .map(|(id, _)| *id)
            .collect();

        let count = expired.len();
        for id in expired {
            if let Some(miner) = self.miners.get_mut(&id) {
                miner.state = MinerState::Disconnected;
            }
        }
        count
    }

    /// Set miner difficulty.
    ///
    /// SECURITY: Validates difficulty bounds to prevent:
    /// - Zero difficulty (accept any hash, waste resources)
    /// - Infinite/NaN difficulty (hang share processing)
    /// - Negative difficulty (undefined behavior)
    pub fn set_difficulty(&mut self, id: &MinerId, difficulty: f64) -> Result<(), PoolError> {
        // Validate difficulty bounds
        if !difficulty.is_finite() {
            return Err(PoolError::Configuration(
                "Difficulty must be finite (not NaN or infinity)".into(),
            ));
        }

        if difficulty <= 0.0 {
            return Err(PoolError::Configuration(
                "Difficulty must be positive".into(),
            ));
        }

        // Sanity check: difficulty shouldn't exceed Bitcoin's theoretical max
        // Network difficulty ~100T (10^14), so we allow up to 10^18 for safety margin
        const MAX_DIFFICULTY: f64 = 1e18;
        if difficulty > MAX_DIFFICULTY {
            return Err(PoolError::Configuration(format!(
                "Difficulty {} exceeds maximum {}",
                difficulty, MAX_DIFFICULTY
            )));
        }

        let miner = self
            .miners
            .get_mut(id)
            .ok_or_else(|| PoolError::MinerNotFound(id.to_string()))?;

        miner.difficulty = difficulty;
        Ok(())
    }

    /// Disconnect a miner.
    pub fn disconnect(&mut self, id: &MinerId) {
        if let Some(miner) = self.miners.get_mut(id) {
            miner.state = MinerState::Disconnected;
        }
    }

    /// Remove disconnected miners.
    pub fn cleanup_disconnected(&mut self) {
        self.miners.retain(|_, m| m.state != MinerState::Disconnected);
    }

    /// Remove miners idle for too long.
    pub fn cleanup_idle(&mut self, max_idle_secs: i64) {
        let now = chrono::Utc::now().timestamp();
        self.miners.retain(|_, m| now - m.last_activity_at < max_idle_secs);
    }

    /// Get all active miners.
    pub fn active_miners(&self) -> Vec<&Miner> {
        self.miners.values().filter(|m| m.is_active()).collect()
    }

    /// Get authorized miners.
    pub fn authorized_miners(&self) -> Vec<&Miner> {
        self.miners.values().filter(|m| m.is_authorized()).collect()
    }

    /// Get miner count.
    pub fn miner_count(&self) -> usize {
        self.miners.len()
    }

    /// Get active miner count.
    pub fn active_count(&self) -> usize {
        self.miners.values().filter(|m| m.is_active()).count()
    }

    /// Get total hashrate.
    pub fn total_hashrate(&self) -> f64 {
        self.miners
            .values()
            .filter(|m| m.is_active())
            .map(|m| m.observed_hashrate)
            .sum()
    }
}

/// Miner statistics summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerStats {
    /// Miner ID.
    pub miner_id: MinerId,
    /// Payout address.
    pub payout_address: Option<PayoutAddress>,
    /// Worker name.
    pub worker_name: Option<String>,
    /// Current hashrate.
    pub hashrate: f64,
    /// Total valid shares.
    pub valid_shares: u64,
    /// Acceptance rate.
    pub acceptance_rate: f64,
    /// Connection duration.
    pub connected_secs: i64,
}

impl From<&Miner> for MinerStats {
    #[allow(deprecated)]
    fn from(miner: &Miner) -> Self {
        // Prefer getting address from commitment, fall back to legacy field
        let payout_address = miner
            .payout_commitment
            .as_ref()
            .map(|c| c.address.clone())
            .or_else(|| miner.payout_address.clone());

        Self {
            miner_id: miner.id,
            payout_address,
            worker_name: miner.worker_name.clone(),
            hashrate: miner.observed_hashrate,
            valid_shares: miner.shares_valid,
            acceptance_rate: miner.acceptance_rate(),
            connected_secs: miner.connection_duration(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_miner_manager() {
        let mut manager = MinerManager::new(100, 4);

        // SECURITY: Must configure pool secret before registration
        manager
            .set_pool_secret(b"test_secret_32_bytes_long_min!!!".to_vec())
            .expect("pool secret should be valid");

        let miner = manager.register_miner().unwrap();
        assert_eq!(miner.id, MinerId::new(1));
        assert_eq!(miner.extranonce1.len(), 4);

        let miner2 = manager.register_miner().unwrap();
        assert_eq!(miner2.id, MinerId::new(2));
        assert_ne!(miner.extranonce1, miner2.extranonce1);
    }

    #[test]
    fn test_miner_authorization() {
        let mut manager = MinerManager::new(100, 4);

        // SECURITY: Must configure pool secret before authorization (32 bytes)
        manager
            .set_pool_secret(b"test_secret_32_bytes_long_min!!!".to_vec())
            .expect("pool secret should be valid");

        let miner = manager.register_miner().unwrap();

        manager
            .authorize(&miner.id, PayoutAddress::new("test_address"), Some("worker1".into()))
            .unwrap();

        let miner = manager.get_miner(&miner.id).unwrap();
        assert!(miner.is_authorized());
        assert_eq!(miner.worker_name, Some("worker1".into()));
    }

    #[test]
    fn test_miner_pool_full() {
        let mut manager = MinerManager::new(2, 4);

        // SECURITY: Must configure pool secret before registration
        manager
            .set_pool_secret(b"test_secret_32_bytes_long_min!!!".to_vec())
            .expect("pool secret should be valid");

        manager.register_miner().unwrap();
        manager.register_miner().unwrap();

        let result = manager.register_miner();
        assert!(matches!(result, Err(PoolError::PoolFull)));
    }

    #[test]
    fn test_payout_commitment_creation_and_verification() {
        let secret = b"test_secret_key_for_pool";
        let address = PayoutAddress::new("bc1qtest");

        let commitment = PayoutCommitment::new(address.clone(), secret);

        // Should verify with correct secret
        assert!(commitment.verify(secret));

        // Should not verify with wrong secret
        assert!(!commitment.verify(b"wrong_secret"));

        // Should not be expired with long expiry
        assert!(!commitment.is_expired(86400)); // 24 hours

        // Should verify with expiry check
        assert!(commitment.verify_with_expiry(secret, 86400));
    }

    #[test]
    fn test_payout_commitment_expiration() {
        let secret = b"test_secret_key_for_pool";
        let address = PayoutAddress::new("bc1qtest");

        // Create a commitment with a past timestamp (simulating an old commitment)
        let mut commitment = PayoutCommitment::new(address, secret);

        // Fresh commitment should not be expired
        assert!(!commitment.is_expired(60)); // 1 minute

        // Manually set timestamp to the past to test expiration
        commitment.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 120; // 2 minutes ago

        // Now it should be expired with 1 minute expiry
        assert!(commitment.is_expired(60));

        // But not with 3 minute expiry
        assert!(!commitment.is_expired(180));

        // verify_with_expiry should fail for expired commitment
        // Note: signature will be invalid because we changed timestamp after signing
        // This is expected - in practice you wouldn't manually modify timestamp
    }

    #[test]
    fn test_commitment_age() {
        let secret = b"test_secret";
        let address = PayoutAddress::new("bc1qtest");

        let commitment = PayoutCommitment::new(address, secret);

        // Age should be close to 0 for fresh commitment
        assert!(commitment.age_secs() < 2);
    }

    #[test]
    fn test_miner_manager_commitment_verification() {
        let mut manager = MinerManager::new(100, 4);

        // SECURITY: Pool secret must be at least 32 bytes
        manager
            .set_pool_secret(b"test_pool_secret_32_bytes_long!!".to_vec())
            .expect("pool secret should be valid");

        let miner = manager.register_miner().unwrap();
        let miner_id = miner.id;

        // No commitment yet - verification should fail
        assert!(!manager.verify_payout_commitment(&miner_id));

        // Authorize with a payout address (creates commitment)
        manager
            .authorize(&miner_id, PayoutAddress::new("bc1qtest"), None)
            .unwrap();

        // Now verification should succeed
        assert!(manager.verify_payout_commitment(&miner_id));

        // Commitment should not be expired
        assert!(!manager.is_commitment_expired(&miner_id));
    }
}
