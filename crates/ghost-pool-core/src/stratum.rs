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
//| FILE: stratum.rs                                                                            |
//|======================================================================================================================|

//! Stratum V2 protocol types.
//!
//! Implements message types and protocol handling for Stratum V2,
//! the modern Bitcoin mining protocol.

use serde::{Deserialize, Serialize};

/// Maximum length for string fields to prevent memory exhaustion attacks.
pub const MAX_STRING_LENGTH: usize = 256;

/// Maximum length for vendor/device info strings.
pub const MAX_DEVICE_INFO_LENGTH: usize = 128;

/// Maximum length for extranonce data.
pub const MAX_EXTRANONCE_LENGTH: usize = 32;

/// Maximum merkle path length.
pub const MAX_MERKLE_PATH_LENGTH: usize = 32;

/// Maximum coinbase transaction prefix/suffix length.
pub const MAX_COINBASE_LENGTH: usize = 4096;

/// Validation error for Stratum protocol messages.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ValidationError {
    #[error("String too long: {field} ({len} > {max})")]
    StringTooLong { field: &'static str, len: usize, max: usize },
    #[error("Invalid hostname: {0}")]
    InvalidHostname(String),
    #[error("Invalid port: {0}")]
    InvalidPort(u16),
    #[error("Invalid hashrate: {0}")]
    InvalidHashrate(f32),
    #[error("Data too long: {field} ({len} > {max})")]
    DataTooLong { field: &'static str, len: usize, max: usize },
    #[error("Invalid protocol version: {0}")]
    InvalidProtocolVersion(u16),
    #[error("Invalid user identity: {0}")]
    InvalidUserIdentity(String),
    #[error("Quantum-unsafe address: P2TR addresses (bc1p...) are quantum-vulnerable. Use P2WPKH (bc1q...) instead.")]
    QuantumUnsafeAddress,
}

/// Stratum protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StratumVersion {
    /// Legacy Stratum V1.
    V1,
    /// Modern Stratum V2.
    V2,
}

impl Default for StratumVersion {
    fn default() -> Self {
        Self::V2
    }
}

/// Stratum V2 message types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StratumMessage {
    // Mining Protocol Messages
    /// Setup connection.
    SetupConnection(SetupConnection),
    /// Setup connection success.
    SetupConnectionSuccess(SetupConnectionSuccess),
    /// Setup connection error.
    SetupConnectionError(SetupConnectionError),
    /// Open standard mining channel.
    OpenStandardMiningChannel(OpenStandardMiningChannel),
    /// Open standard mining channel success.
    OpenStandardMiningChannelSuccess(OpenStandardMiningChannelSuccess),
    /// New mining job.
    NewMiningJob(NewMiningJob),
    /// New extended mining job.
    NewExtendedMiningJob(NewExtendedMiningJob),
    /// Set new prev hash.
    SetNewPrevHash(SetNewPrevHash),
    /// Submit shares standard.
    SubmitSharesStandard(SubmitSharesStandard),
    /// Submit shares extended.
    SubmitSharesExtended(SubmitSharesExtended),
    /// Submit shares success.
    SubmitSharesSuccess(SubmitSharesSuccess),
    /// Submit shares error.
    SubmitSharesError(SubmitSharesError),
    /// Update channel.
    UpdateChannel(UpdateChannel),
    /// Set target.
    SetTarget(SetTarget),
    /// Reconnect.
    Reconnect(Reconnect),
    /// Set version mask.
    SetVersionMask(SetVersionMask),
}

/// Setup connection request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupConnection {
    /// Protocol version.
    pub protocol: u16,
    /// Minimum protocol version.
    pub min_version: u16,
    /// Maximum protocol version.
    pub max_version: u16,
    /// Connection flags.
    pub flags: u32,
    /// Endpoint host.
    pub endpoint_host: String,
    /// Endpoint port.
    pub endpoint_port: u16,
    /// Vendor string.
    pub vendor: String,
    /// Hardware version.
    pub hardware_version: String,
    /// Firmware version.
    pub firmware: String,
    /// Device ID.
    pub device_id: String,
}

impl SetupConnection {
    /// Validate the setup connection request.
    pub fn validate(&self) -> Result<(), ValidationError> {
        // Validate protocol version range
        if self.min_version > self.max_version {
            return Err(ValidationError::InvalidProtocolVersion(self.min_version));
        }
        if self.protocol < self.min_version || self.protocol > self.max_version {
            return Err(ValidationError::InvalidProtocolVersion(self.protocol));
        }

        // Validate string lengths
        if self.endpoint_host.len() > MAX_STRING_LENGTH {
            return Err(ValidationError::StringTooLong {
                field: "endpoint_host",
                len: self.endpoint_host.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if self.vendor.len() > MAX_DEVICE_INFO_LENGTH {
            return Err(ValidationError::StringTooLong {
                field: "vendor",
                len: self.vendor.len(),
                max: MAX_DEVICE_INFO_LENGTH,
            });
        }
        if self.hardware_version.len() > MAX_DEVICE_INFO_LENGTH {
            return Err(ValidationError::StringTooLong {
                field: "hardware_version",
                len: self.hardware_version.len(),
                max: MAX_DEVICE_INFO_LENGTH,
            });
        }
        if self.firmware.len() > MAX_DEVICE_INFO_LENGTH {
            return Err(ValidationError::StringTooLong {
                field: "firmware",
                len: self.firmware.len(),
                max: MAX_DEVICE_INFO_LENGTH,
            });
        }
        if self.device_id.len() > MAX_DEVICE_INFO_LENGTH {
            return Err(ValidationError::StringTooLong {
                field: "device_id",
                len: self.device_id.len(),
                max: MAX_DEVICE_INFO_LENGTH,
            });
        }

        // Validate hostname (basic check - no control characters)
        if self.endpoint_host.chars().any(|c| c.is_control()) {
            return Err(ValidationError::InvalidHostname(self.endpoint_host.clone()));
        }

        // Validate port (0 is invalid)
        if self.endpoint_port == 0 {
            return Err(ValidationError::InvalidPort(self.endpoint_port));
        }

        Ok(())
    }
}

/// Setup connection success response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupConnectionSuccess {
    /// Used protocol version.
    pub used_version: u16,
    /// Connection flags.
    pub flags: u32,
}

/// Setup connection error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupConnectionError {
    /// Error flags.
    pub flags: u32,
    /// Error code.
    pub error_code: String,
}

/// Open standard mining channel request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenStandardMiningChannel {
    /// Request ID.
    pub request_id: u32,
    /// User identity (e.g., wallet address).
    pub user_identity: String,
    /// Nominal hashrate (H/s).
    pub nominal_hash_rate: f32,
    /// Maximum target.
    pub max_target: [u8; 32],
}

impl OpenStandardMiningChannel {
    /// Validate the open channel request.
    ///
    /// # Quantum Safety
    ///
    /// Rejects P2TR addresses (bc1p...) for quantum safety. P2TR exposes
    /// public keys on-chain, making them vulnerable to quantum computer
    /// attacks while funds are locked.
    pub fn validate(&self) -> Result<(), ValidationError> {
        // Validate user identity length
        if self.user_identity.len() > MAX_STRING_LENGTH {
            return Err(ValidationError::StringTooLong {
                field: "user_identity",
                len: self.user_identity.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        // Validate user identity content (no control characters)
        if self.user_identity.chars().any(|c| c.is_control()) {
            return Err(ValidationError::InvalidUserIdentity(self.user_identity.clone()));
        }

        // QUANTUM SAFETY: Reject P2TR addresses
        // User identity format: <address>.<worker_name> or just <address>
        let address = self.user_identity.split('.').next().unwrap_or(&self.user_identity);
        if address.starts_with("bc1p") || address.starts_with("tb1p") || address.starts_with("bcrt1p") {
            return Err(ValidationError::QuantumUnsafeAddress);
        }

        // Validate hashrate (must be positive and finite)
        if !self.nominal_hash_rate.is_finite() || self.nominal_hash_rate < 0.0 {
            return Err(ValidationError::InvalidHashrate(self.nominal_hash_rate));
        }

        Ok(())
    }
}

/// Open standard mining channel success.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenStandardMiningChannelSuccess {
    /// Request ID.
    pub request_id: u32,
    /// Channel ID.
    pub channel_id: u32,
    /// Target.
    pub target: [u8; 32],
    /// Extranonce prefix.
    pub extranonce_prefix: Vec<u8>,
    /// Group channel ID.
    pub group_channel_id: u32,
}

/// New mining job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewMiningJob {
    /// Channel ID.
    pub channel_id: u32,
    /// Job ID.
    pub job_id: u32,
    /// Future job flag.
    pub future_job: bool,
    /// Version.
    pub version: u32,
    /// Version rolling mask.
    pub version_rolling_allowed: bool,
}

/// New extended mining job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewExtendedMiningJob {
    /// Channel ID.
    pub channel_id: u32,
    /// Job ID.
    pub job_id: u32,
    /// Future job flag.
    pub future_job: bool,
    /// Version.
    pub version: u32,
    /// Version rolling allowed.
    pub version_rolling_allowed: bool,
    /// Merkle path.
    pub merkle_path: Vec<[u8; 32]>,
    /// Coinbase tx prefix.
    pub coinbase_tx_prefix: Vec<u8>,
    /// Coinbase tx suffix.
    pub coinbase_tx_suffix: Vec<u8>,
}

impl NewExtendedMiningJob {
    /// Validate the mining job.
    pub fn validate(&self) -> Result<(), ValidationError> {
        // Validate merkle path length
        if self.merkle_path.len() > MAX_MERKLE_PATH_LENGTH {
            return Err(ValidationError::DataTooLong {
                field: "merkle_path",
                len: self.merkle_path.len(),
                max: MAX_MERKLE_PATH_LENGTH,
            });
        }
        // Validate coinbase prefix length
        if self.coinbase_tx_prefix.len() > MAX_COINBASE_LENGTH {
            return Err(ValidationError::DataTooLong {
                field: "coinbase_tx_prefix",
                len: self.coinbase_tx_prefix.len(),
                max: MAX_COINBASE_LENGTH,
            });
        }
        // Validate coinbase suffix length
        if self.coinbase_tx_suffix.len() > MAX_COINBASE_LENGTH {
            return Err(ValidationError::DataTooLong {
                field: "coinbase_tx_suffix",
                len: self.coinbase_tx_suffix.len(),
                max: MAX_COINBASE_LENGTH,
            });
        }
        Ok(())
    }
}

/// Set new prev hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetNewPrevHash {
    /// Channel ID.
    pub channel_id: u32,
    /// Job ID.
    pub job_id: u32,
    /// Previous hash.
    pub prev_hash: [u8; 32],
    /// Minimum ntime.
    pub min_ntime: u32,
    /// NBits.
    pub nbits: u32,
}

/// Submit shares standard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitSharesStandard {
    /// Channel ID.
    pub channel_id: u32,
    /// Sequence number.
    pub sequence_number: u32,
    /// Job ID.
    pub job_id: u32,
    /// Nonce.
    pub nonce: u32,
    /// Ntime.
    pub ntime: u32,
    /// Version.
    pub version: u32,
}

/// Submit shares extended.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitSharesExtended {
    /// Channel ID.
    pub channel_id: u32,
    /// Sequence number.
    pub sequence_number: u32,
    /// Job ID.
    pub job_id: u32,
    /// Nonce.
    pub nonce: u32,
    /// Ntime.
    pub ntime: u32,
    /// Version.
    pub version: u32,
    /// Extranonce.
    pub extranonce: Vec<u8>,
}

impl SubmitSharesExtended {
    /// Validate the share submission.
    pub fn validate(&self) -> Result<(), ValidationError> {
        // Validate extranonce length
        if self.extranonce.len() > MAX_EXTRANONCE_LENGTH {
            return Err(ValidationError::DataTooLong {
                field: "extranonce",
                len: self.extranonce.len(),
                max: MAX_EXTRANONCE_LENGTH,
            });
        }
        Ok(())
    }
}

/// Submit shares success.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitSharesSuccess {
    /// Channel ID.
    pub channel_id: u32,
    /// Last sequence number.
    pub last_sequence_number: u32,
    /// New submits accepted count.
    pub new_submits_accepted_count: u32,
    /// New shares sum.
    pub new_shares_sum: u64,
}

/// Submit shares error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitSharesError {
    /// Channel ID.
    pub channel_id: u32,
    /// Sequence number.
    pub sequence_number: u32,
    /// Error code.
    pub error_code: String,
}

/// Update channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateChannel {
    /// Channel ID.
    pub channel_id: u32,
    /// Nominal hashrate.
    pub nominal_hash_rate: f32,
    /// Maximum target.
    pub maximum_target: [u8; 32],
}

/// Set target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetTarget {
    /// Channel ID.
    pub channel_id: u32,
    /// Maximum target.
    pub maximum_target: [u8; 32],
}

/// Reconnect message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reconnect {
    /// New host.
    pub new_host: String,
    /// New port.
    pub new_port: u16,
}

impl Reconnect {
    /// Validate the reconnect message.
    pub fn validate(&self) -> Result<(), ValidationError> {
        // Validate hostname length
        if self.new_host.len() > MAX_STRING_LENGTH {
            return Err(ValidationError::StringTooLong {
                field: "new_host",
                len: self.new_host.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        // Validate hostname content
        if self.new_host.chars().any(|c| c.is_control()) {
            return Err(ValidationError::InvalidHostname(self.new_host.clone()));
        }
        // Validate port
        if self.new_port == 0 {
            return Err(ValidationError::InvalidPort(self.new_port));
        }
        Ok(())
    }
}

/// Set version mask.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetVersionMask {
    /// Channel ID.
    pub channel_id: u32,
    /// Version mask.
    pub version_mask: u32,
}

// ============================================================================
// Job Notification Helpers
// ============================================================================

use crate::job::MiningJob;

impl MiningJob {
    /// Convert this mining job to a NewExtendedMiningJob message.
    ///
    /// Used for Stratum V2 extended channels where the miner
    /// constructs the coinbase transaction.
    pub fn to_extended_job_message(&self, channel_id: u32) -> NewExtendedMiningJob {
        NewExtendedMiningJob {
            channel_id,
            job_id: self.id.as_u64() as u32,
            future_job: false,
            version: self.version,
            version_rolling_allowed: true,
            merkle_path: self.merkle_branches.clone(),
            coinbase_tx_prefix: self.coinbase1.clone(),
            coinbase_tx_suffix: self.coinbase2.clone(),
        }
    }

    /// Convert this mining job to a SetNewPrevHash message.
    ///
    /// Used when a new block is found and all work must be updated.
    pub fn to_new_prev_hash_message(&self, channel_id: u32) -> SetNewPrevHash {
        SetNewPrevHash {
            channel_id,
            job_id: self.id.as_u64() as u32,
            prev_hash: *self.prev_block_hash.as_bytes(),
            min_ntime: self.ntime,
            nbits: self.nbits,
        }
    }

    /// Convert this job to a SetTarget message for a specific difficulty.
    ///
    /// The target is derived from the pool difficulty.
    pub fn to_set_target_message(channel_id: u32, difficulty: f64) -> SetTarget {
        use crate::difficulty::difficulty_to_target;
        SetTarget {
            channel_id,
            maximum_target: difficulty_to_target(difficulty),
        }
    }
}

/// A job notification to send to miners.
#[derive(Debug, Clone)]
pub enum JobNotification {
    /// New job available (normal priority).
    NewJob {
        /// The extended mining job message.
        job: NewExtendedMiningJob,
        /// Previous block hash message.
        prev_hash: SetNewPrevHash,
    },
    /// Urgent new work - new block found on network.
    /// Miners should immediately switch to this job.
    UrgentNewJob {
        /// The extended mining job message.
        job: NewExtendedMiningJob,
        /// Previous block hash message (with updated prev_hash).
        prev_hash: SetNewPrevHash,
    },
    /// Update difficulty target.
    SetTarget(SetTarget),
}

/// Stratum error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StratumError {
    /// Unknown error.
    Unknown,
    /// Invalid job.
    JobNotFound,
    /// Stale share.
    StaleShare,
    /// Duplicate share.
    DuplicateShare,
    /// Low difficulty.
    LowDifficulty,
    /// Unauthorized.
    Unauthorized,
    /// Not subscribed.
    NotSubscribed,
}

impl std::fmt::Display for StratumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::JobNotFound => write!(f, "job-not-found"),
            Self::StaleShare => write!(f, "stale-share"),
            Self::DuplicateShare => write!(f, "duplicate-share"),
            Self::LowDifficulty => write!(f, "low-difficulty-share"),
            Self::Unauthorized => write!(f, "unauthorized"),
            Self::NotSubscribed => write!(f, "not-subscribed"),
        }
    }
}

/// Stratum connection flags.
pub mod flags {
    /// Requires standard jobs.
    pub const REQUIRES_STANDARD_JOBS: u32 = 1 << 0;
    /// Requires extended jobs.
    pub const REQUIRES_EXTENDED_JOBS: u32 = 1 << 1;
    /// Requires version rolling.
    pub const REQUIRES_VERSION_ROLLING: u32 = 1 << 2;
    /// Requires minimum difficulty.
    pub const REQUIRES_MINIMUM_DIFFICULTY: u32 = 1 << 3;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stratum_version() {
        assert_eq!(StratumVersion::default(), StratumVersion::V2);
    }

    #[test]
    fn test_stratum_error_display() {
        assert_eq!(format!("{}", StratumError::StaleShare), "stale-share");
        assert_eq!(format!("{}", StratumError::LowDifficulty), "low-difficulty-share");
    }

    #[test]
    fn test_setup_connection_validation() {
        let valid = SetupConnection {
            protocol: 2,
            min_version: 2,
            max_version: 2,
            flags: 0,
            endpoint_host: "pool.example.com".to_string(),
            endpoint_port: 3333,
            vendor: "Test Miner".to_string(),
            hardware_version: "1.0".to_string(),
            firmware: "1.0.0".to_string(),
            device_id: "device-001".to_string(),
        };
        assert!(valid.validate().is_ok());

        // Test protocol version mismatch
        let bad_version = SetupConnection {
            protocol: 1,
            min_version: 2,
            max_version: 2,
            ..valid.clone()
        };
        assert!(bad_version.validate().is_err());

        // Test too-long hostname
        let bad_host = SetupConnection {
            endpoint_host: "x".repeat(MAX_STRING_LENGTH + 1),
            ..valid.clone()
        };
        assert!(bad_host.validate().is_err());

        // Test invalid port
        let bad_port = SetupConnection {
            endpoint_port: 0,
            ..valid.clone()
        };
        assert!(bad_port.validate().is_err());

        // Test control character in hostname
        let bad_hostname = SetupConnection {
            endpoint_host: "host\nwith\nnewlines".to_string(),
            ..valid.clone()
        };
        assert!(bad_hostname.validate().is_err());
    }

    #[test]
    fn test_open_channel_validation() {
        let valid = OpenStandardMiningChannel {
            request_id: 1,
            user_identity: "bc1qexample".to_string(),
            nominal_hash_rate: 1000.0,
            max_target: [0u8; 32],
        };
        assert!(valid.validate().is_ok());

        // Test invalid hashrate (NaN)
        let bad_hashrate = OpenStandardMiningChannel {
            nominal_hash_rate: f32::NAN,
            ..valid.clone()
        };
        assert!(bad_hashrate.validate().is_err());

        // Test negative hashrate
        let neg_hashrate = OpenStandardMiningChannel {
            nominal_hash_rate: -100.0,
            ..valid.clone()
        };
        assert!(neg_hashrate.validate().is_err());

        // Test too-long user identity
        let bad_identity = OpenStandardMiningChannel {
            user_identity: "x".repeat(MAX_STRING_LENGTH + 1),
            ..valid.clone()
        };
        assert!(bad_identity.validate().is_err());
    }

    #[test]
    fn test_open_channel_rejects_p2tr_address() {
        // P2TR addresses should be rejected for quantum safety
        let p2tr_mainnet = OpenStandardMiningChannel {
            request_id: 1,
            user_identity: "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr".to_string(),
            nominal_hash_rate: 1000.0,
            max_target: [0u8; 32],
        };
        assert!(matches!(p2tr_mainnet.validate(), Err(ValidationError::QuantumUnsafeAddress)));

        // With worker name
        let p2tr_with_worker = OpenStandardMiningChannel {
            request_id: 1,
            user_identity: "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr.worker1".to_string(),
            nominal_hash_rate: 1000.0,
            max_target: [0u8; 32],
        };
        assert!(matches!(p2tr_with_worker.validate(), Err(ValidationError::QuantumUnsafeAddress)));

        // Testnet P2TR
        let p2tr_testnet = OpenStandardMiningChannel {
            request_id: 1,
            user_identity: "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c".to_string(),
            nominal_hash_rate: 1000.0,
            max_target: [0u8; 32],
        };
        assert!(matches!(p2tr_testnet.validate(), Err(ValidationError::QuantumUnsafeAddress)));

        // P2WPKH should be accepted (quantum-safe)
        let p2wpkh = OpenStandardMiningChannel {
            request_id: 1,
            user_identity: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            nominal_hash_rate: 1000.0,
            max_target: [0u8; 32],
        };
        assert!(p2wpkh.validate().is_ok());
    }

    #[test]
    fn test_submit_shares_extended_validation() {
        let valid = SubmitSharesExtended {
            channel_id: 1,
            sequence_number: 1,
            job_id: 1,
            nonce: 12345,
            ntime: 1234567890,
            version: 0x20000000,
            extranonce: vec![0x00, 0x01, 0x02, 0x03],
        };
        assert!(valid.validate().is_ok());

        // Test too-long extranonce
        let bad_extranonce = SubmitSharesExtended {
            extranonce: vec![0u8; MAX_EXTRANONCE_LENGTH + 1],
            ..valid.clone()
        };
        assert!(bad_extranonce.validate().is_err());
    }

    #[test]
    fn test_new_extended_job_validation() {
        let valid = NewExtendedMiningJob {
            channel_id: 1,
            job_id: 1,
            future_job: false,
            version: 0x20000000,
            version_rolling_allowed: true,
            merkle_path: vec![[0u8; 32]; 10],
            coinbase_tx_prefix: vec![0u8; 100],
            coinbase_tx_suffix: vec![0u8; 100],
        };
        assert!(valid.validate().is_ok());

        // Test too-long merkle path
        let bad_merkle = NewExtendedMiningJob {
            merkle_path: vec![[0u8; 32]; MAX_MERKLE_PATH_LENGTH + 1],
            ..valid.clone()
        };
        assert!(bad_merkle.validate().is_err());

        // Test too-long coinbase prefix
        let bad_prefix = NewExtendedMiningJob {
            coinbase_tx_prefix: vec![0u8; MAX_COINBASE_LENGTH + 1],
            ..valid.clone()
        };
        assert!(bad_prefix.validate().is_err());
    }

    #[test]
    fn test_reconnect_validation() {
        let valid = Reconnect {
            new_host: "pool2.example.com".to_string(),
            new_port: 3334,
        };
        assert!(valid.validate().is_ok());

        // Test invalid port
        let bad_port = Reconnect {
            new_port: 0,
            ..valid.clone()
        };
        assert!(bad_port.validate().is_err());

        // Test too-long hostname
        let bad_host = Reconnect {
            new_host: "x".repeat(MAX_STRING_LENGTH + 1),
            ..valid.clone()
        };
        assert!(bad_host.validate().is_err());
    }
}
