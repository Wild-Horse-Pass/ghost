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
//| FILE: identity_rotation.rs                                                                                           |
//|======================================================================================================================|

//! Identity rotation policy and automation
//!
//! Provides warnings and tools for rotating Ghost IDs to prevent
//! long-term correlation attacks.
//!
//! # Privacy Rationale
//!
//! Persistent identities create correlation opportunities:
//! - Transaction patterns accumulate over time
//! - Network observers can build activity profiles
//! - Historical data becomes linkable to current activity
//!
//! Regular rotation limits the time window for correlation.
//!
//! # Rotation Policy
//!
//! Default recommendations:
//! - **Warning**: After 30 days of active use
//! - **Critical**: After 90 days of active use
//! - **After breach**: Immediately if compromise suspected
//!
//! # Usage
//!
//! ```ignore
//! use ghost_common::identity_rotation::{RotationPolicy, RotationManager};
//!
//! let policy = RotationPolicy::default();
//! let manager = RotationManager::new(policy);
//!
//! // Check if rotation is recommended
//! let status = manager.check_rotation(&identity_metadata);
//! if status.should_rotate() {
//!     warn!("{}", status.reason);
//! }
//!
//! // Perform rotation
//! let new_identity = manager.rotate(old_identity)?;
//! ```

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

use crate::identity::NodeIdentity;
use crate::types::NodeId;

/// Rotation policy errors
#[derive(Debug, Error)]
pub enum RotationError {
    #[error("Identity creation failed: {0}")]
    IdentityCreation(String),

    #[error("Key storage failed: {0}")]
    KeyStorage(String),

    #[error("Migration failed: {0}")]
    Migration(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Rotation urgency level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RotationUrgency {
    /// No rotation needed
    None,
    /// Rotation recommended for best practices
    Advisory,
    /// Rotation strongly recommended
    Warning,
    /// Rotation critical (potential compromise or very old)
    Critical,
    /// Immediate rotation required (known compromise)
    Emergency,
}

impl RotationUrgency {
    /// Check if rotation should be performed
    pub fn should_rotate(&self) -> bool {
        *self >= RotationUrgency::Warning
    }

    /// Check if rotation is urgent
    pub fn is_urgent(&self) -> bool {
        *self >= RotationUrgency::Critical
    }

    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::None => "No rotation needed",
            Self::Advisory => "Rotation recommended for privacy",
            Self::Warning => "Rotation strongly recommended",
            Self::Critical => "Rotation critical - please rotate soon",
            Self::Emergency => "EMERGENCY - Rotate immediately!",
        }
    }
}

/// Rotation status with details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationStatus {
    /// Urgency level
    pub urgency: RotationUrgency,
    /// Human-readable reason
    pub reason: String,
    /// Identity age in days
    pub age_days: u64,
    /// Days until recommended rotation
    pub days_until_warning: Option<i64>,
    /// Last activity timestamp
    pub last_activity: Option<u64>,
    /// Number of transactions made
    pub transaction_count: Option<u64>,
    /// Previous rotation count
    pub rotation_count: u32,
}

impl RotationStatus {
    /// Check if rotation should be performed
    pub fn should_rotate(&self) -> bool {
        self.urgency.should_rotate()
    }
}

/// Configuration for rotation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    /// Days until advisory notification
    pub advisory_days: u64,
    /// Days until warning
    pub warning_days: u64,
    /// Days until critical
    pub critical_days: u64,
    /// Transaction count triggering advisory
    pub advisory_tx_count: u64,
    /// Transaction count triggering warning
    pub warning_tx_count: u64,
    /// Enable automatic rotation reminders
    pub reminders_enabled: bool,
    /// Auto-rotate after critical threshold
    pub auto_rotate_critical: bool,
    /// Backup old keys when rotating
    pub backup_old_keys: bool,
    /// Backup directory for old keys
    pub backup_dir: Option<PathBuf>,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            advisory_days: 30,
            warning_days: 60,
            critical_days: 90,
            advisory_tx_count: 1000,
            warning_tx_count: 5000,
            reminders_enabled: true,
            auto_rotate_critical: false,
            backup_old_keys: true,
            backup_dir: None,
        }
    }
}

impl RotationPolicy {
    /// Create a high-privacy policy (more frequent rotation)
    pub fn high_privacy() -> Self {
        Self {
            advisory_days: 7,
            warning_days: 14,
            critical_days: 30,
            advisory_tx_count: 100,
            warning_tx_count: 500,
            reminders_enabled: true,
            auto_rotate_critical: true,
            backup_old_keys: true,
            backup_dir: None,
        }
    }

    /// Create a convenience policy (less frequent rotation)
    pub fn convenience() -> Self {
        Self {
            advisory_days: 90,
            warning_days: 180,
            critical_days: 365,
            advisory_tx_count: 10000,
            warning_tx_count: 50000,
            reminders_enabled: true,
            auto_rotate_critical: false,
            backup_old_keys: true,
            backup_dir: None,
        }
    }
}

/// Metadata about an identity for rotation decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityMetadata {
    /// The node ID (public key)
    pub node_id: NodeId,
    /// When this identity was created
    pub created_at: u64,
    /// Last activity timestamp
    pub last_activity: u64,
    /// Number of transactions made
    pub transaction_count: u64,
    /// Number of times rotated to this identity
    pub rotation_count: u32,
    /// Previous identity (for chain tracking)
    pub previous_id: Option<NodeId>,
    /// Whether this identity is marked as compromised
    pub compromised: bool,
    /// Compromise reason if any
    pub compromise_reason: Option<String>,
}

impl IdentityMetadata {
    /// Create metadata for a new identity
    pub fn new(node_id: NodeId) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            node_id,
            created_at: now,
            last_activity: now,
            transaction_count: 0,
            rotation_count: 0,
            previous_id: None,
            compromised: false,
            compromise_reason: None,
        }
    }

    /// Get age in seconds
    pub fn age_secs(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now.saturating_sub(self.created_at)
    }

    /// Get age in days
    pub fn age_days(&self) -> u64 {
        self.age_secs() / (24 * 60 * 60)
    }

    /// Mark identity as compromised
    pub fn mark_compromised(&mut self, reason: &str) {
        self.compromised = true;
        self.compromise_reason = Some(reason.to_string());
    }

    /// Record a transaction
    pub fn record_transaction(&mut self) {
        self.transaction_count += 1;
        self.last_activity = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
}

/// Manager for identity rotation
pub struct RotationManager {
    policy: RotationPolicy,
}

impl RotationManager {
    /// Create a new rotation manager
    pub fn new(policy: RotationPolicy) -> Self {
        Self { policy }
    }

    /// Check rotation status for an identity
    pub fn check_rotation(&self, metadata: &IdentityMetadata) -> RotationStatus {
        // Emergency: compromised identity
        if metadata.compromised {
            return RotationStatus {
                urgency: RotationUrgency::Emergency,
                reason: format!(
                    "Identity marked as compromised: {}",
                    metadata
                        .compromise_reason
                        .as_deref()
                        .unwrap_or("unknown reason")
                ),
                age_days: metadata.age_days(),
                days_until_warning: None,
                last_activity: Some(metadata.last_activity),
                transaction_count: Some(metadata.transaction_count),
                rotation_count: metadata.rotation_count,
            };
        }

        let age_days = metadata.age_days();

        // Critical: very old identity
        if age_days >= self.policy.critical_days {
            return RotationStatus {
                urgency: RotationUrgency::Critical,
                reason: format!(
                    "Identity is {} days old (critical threshold: {} days)",
                    age_days, self.policy.critical_days
                ),
                age_days,
                days_until_warning: None,
                last_activity: Some(metadata.last_activity),
                transaction_count: Some(metadata.transaction_count),
                rotation_count: metadata.rotation_count,
            };
        }

        // Warning: transaction count exceeded
        if metadata.transaction_count >= self.policy.warning_tx_count {
            return RotationStatus {
                urgency: RotationUrgency::Warning,
                reason: format!(
                    "Identity has {} transactions (warning threshold: {})",
                    metadata.transaction_count, self.policy.warning_tx_count
                ),
                age_days,
                days_until_warning: None,
                last_activity: Some(metadata.last_activity),
                transaction_count: Some(metadata.transaction_count),
                rotation_count: metadata.rotation_count,
            };
        }

        // Warning: old identity
        if age_days >= self.policy.warning_days {
            return RotationStatus {
                urgency: RotationUrgency::Warning,
                reason: format!(
                    "Identity is {} days old (warning threshold: {} days)",
                    age_days, self.policy.warning_days
                ),
                age_days,
                days_until_warning: None,
                last_activity: Some(metadata.last_activity),
                transaction_count: Some(metadata.transaction_count),
                rotation_count: metadata.rotation_count,
            };
        }

        // Advisory: transaction count approaching
        if metadata.transaction_count >= self.policy.advisory_tx_count {
            return RotationStatus {
                urgency: RotationUrgency::Advisory,
                reason: format!(
                    "Identity has {} transactions (advisory threshold: {})",
                    metadata.transaction_count, self.policy.advisory_tx_count
                ),
                age_days,
                days_until_warning: Some((self.policy.warning_days - age_days) as i64),
                last_activity: Some(metadata.last_activity),
                transaction_count: Some(metadata.transaction_count),
                rotation_count: metadata.rotation_count,
            };
        }

        // Advisory: approaching warning threshold
        if age_days >= self.policy.advisory_days {
            return RotationStatus {
                urgency: RotationUrgency::Advisory,
                reason: format!(
                    "Identity is {} days old (advisory threshold: {} days)",
                    age_days, self.policy.advisory_days
                ),
                age_days,
                days_until_warning: Some((self.policy.warning_days - age_days) as i64),
                last_activity: Some(metadata.last_activity),
                transaction_count: Some(metadata.transaction_count),
                rotation_count: metadata.rotation_count,
            };
        }

        // No rotation needed
        RotationStatus {
            urgency: RotationUrgency::None,
            reason: "Identity is healthy".to_string(),
            age_days,
            days_until_warning: Some((self.policy.warning_days - age_days) as i64),
            last_activity: Some(metadata.last_activity),
            transaction_count: Some(metadata.transaction_count),
            rotation_count: metadata.rotation_count,
        }
    }

    /// Perform identity rotation
    ///
    /// Returns (new_identity, new_metadata)
    pub fn rotate(
        &self,
        old_metadata: &IdentityMetadata,
    ) -> Result<(NodeIdentity, IdentityMetadata), RotationError> {
        info!(
            old_id = %hex::encode(&old_metadata.node_id[..8]),
            rotation_count = old_metadata.rotation_count,
            "Starting identity rotation"
        );

        // Backup old key if configured
        if self.policy.backup_old_keys {
            if let Some(ref backup_dir) = self.policy.backup_dir {
                self.backup_identity(old_metadata, backup_dir)?;
            }
        }

        // Generate new identity
        let new_identity = NodeIdentity::generate();
        let new_node_id = new_identity.node_id();

        // Create metadata for new identity
        let mut new_metadata = IdentityMetadata::new(new_node_id);
        new_metadata.rotation_count = old_metadata.rotation_count + 1;
        new_metadata.previous_id = Some(old_metadata.node_id);

        info!(
            new_id = %hex::encode(&new_node_id[..8]),
            rotation_count = new_metadata.rotation_count,
            "Identity rotation complete"
        );

        Ok((new_identity, new_metadata))
    }

    /// Backup identity before rotation
    fn backup_identity(
        &self,
        metadata: &IdentityMetadata,
        backup_dir: &std::path::Path,
    ) -> Result<(), RotationError> {
        // Create backup directory if needed
        std::fs::create_dir_all(backup_dir)?;

        // Create backup filename with timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let filename = format!(
            "identity_backup_{}_{}.json",
            hex::encode(&metadata.node_id[..8]),
            timestamp
        );
        let backup_path = backup_dir.join(filename);

        // Serialize metadata
        let json = serde_json::to_string_pretty(metadata)
            .map_err(|e| RotationError::KeyStorage(e.to_string()))?;

        std::fs::write(&backup_path, json)?;

        info!(
            path = %backup_path.display(),
            "Backed up identity metadata"
        );

        Ok(())
    }

    /// Get policy
    pub fn policy(&self) -> &RotationPolicy {
        &self.policy
    }

    /// Update policy
    pub fn set_policy(&mut self, policy: RotationPolicy) {
        self.policy = policy;
    }

    /// Check if auto-rotation should trigger
    pub fn should_auto_rotate(&self, metadata: &IdentityMetadata) -> bool {
        if !self.policy.auto_rotate_critical {
            return false;
        }

        let status = self.check_rotation(metadata);
        status.urgency >= RotationUrgency::Critical
    }
}

/// Helper to generate rotation reminder messages
pub fn rotation_reminder_message(status: &RotationStatus) -> String {
    match status.urgency {
        RotationUrgency::None => {
            format!(
                "Your identity is healthy. {} days until rotation recommended.",
                status.days_until_warning.unwrap_or(0)
            )
        }
        RotationUrgency::Advisory => {
            format!(
                "Advisory: {} Consider rotating your identity for better privacy.",
                status.reason
            )
        }
        RotationUrgency::Warning => {
            format!(
                "⚠️ Warning: {} Please rotate your identity soon.",
                status.reason
            )
        }
        RotationUrgency::Critical => {
            format!(
                "🔴 Critical: {} Rotation strongly recommended!",
                status.reason
            )
        }
        RotationUrgency::Emergency => {
            format!("🚨 EMERGENCY: {} ROTATE IMMEDIATELY!", status.reason)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_metadata(age_days: u64, tx_count: u64) -> IdentityMetadata {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        IdentityMetadata {
            node_id: [1u8; 32],
            created_at: now - (age_days * 24 * 60 * 60),
            last_activity: now,
            transaction_count: tx_count,
            rotation_count: 0,
            previous_id: None,
            compromised: false,
            compromise_reason: None,
        }
    }

    #[test]
    fn test_no_rotation_needed() {
        let policy = RotationPolicy::default();
        let manager = RotationManager::new(policy);
        let metadata = test_metadata(5, 100); // 5 days, 100 tx

        let status = manager.check_rotation(&metadata);
        assert_eq!(status.urgency, RotationUrgency::None);
        assert!(!status.should_rotate());
    }

    #[test]
    fn test_advisory_age() {
        let policy = RotationPolicy::default();
        let manager = RotationManager::new(policy);
        let metadata = test_metadata(35, 100); // 35 days

        let status = manager.check_rotation(&metadata);
        assert_eq!(status.urgency, RotationUrgency::Advisory);
        assert!(!status.should_rotate());
    }

    #[test]
    fn test_warning_age() {
        let policy = RotationPolicy::default();
        let manager = RotationManager::new(policy);
        let metadata = test_metadata(65, 100); // 65 days

        let status = manager.check_rotation(&metadata);
        assert_eq!(status.urgency, RotationUrgency::Warning);
        assert!(status.should_rotate());
    }

    #[test]
    fn test_critical_age() {
        let policy = RotationPolicy::default();
        let manager = RotationManager::new(policy);
        let metadata = test_metadata(100, 100); // 100 days

        let status = manager.check_rotation(&metadata);
        assert_eq!(status.urgency, RotationUrgency::Critical);
        assert!(status.should_rotate());
        assert!(status.urgency.is_urgent());
    }

    #[test]
    fn test_emergency_compromised() {
        let policy = RotationPolicy::default();
        let manager = RotationManager::new(policy);
        let mut metadata = test_metadata(1, 10); // Very new
        metadata.mark_compromised("Test compromise");

        let status = manager.check_rotation(&metadata);
        assert_eq!(status.urgency, RotationUrgency::Emergency);
        assert!(status.should_rotate());
        assert!(status.reason.contains("compromised"));
    }

    #[test]
    fn test_transaction_count_warning() {
        let policy = RotationPolicy::default();
        let manager = RotationManager::new(policy);
        let metadata = test_metadata(10, 5500); // 10 days, 5500 tx

        let status = manager.check_rotation(&metadata);
        assert_eq!(status.urgency, RotationUrgency::Warning);
        assert!(status.reason.contains("transactions"));
    }

    #[test]
    fn test_high_privacy_policy() {
        let policy = RotationPolicy::high_privacy();
        let manager = RotationManager::new(policy);
        let metadata = test_metadata(10, 100); // 10 days

        let status = manager.check_rotation(&metadata);
        // High privacy: 7 day advisory, 14 day warning
        assert_eq!(status.urgency, RotationUrgency::Advisory);
    }

    #[test]
    fn test_convenience_policy() {
        let policy = RotationPolicy::convenience();
        let manager = RotationManager::new(policy);
        let metadata = test_metadata(60, 1000); // 60 days

        let status = manager.check_rotation(&metadata);
        // Convenience: 90 day advisory
        assert_eq!(status.urgency, RotationUrgency::None);
    }

    #[test]
    fn test_rotation() {
        let policy = RotationPolicy {
            backup_old_keys: false,
            ..Default::default()
        };
        let manager = RotationManager::new(policy);
        let old_metadata = test_metadata(100, 5000);

        let (new_identity, new_metadata) = manager.rotate(&old_metadata).unwrap();

        // New identity should have new node_id
        assert_ne!(new_identity.node_id(), old_metadata.node_id);

        // New metadata should track rotation
        assert_eq!(new_metadata.rotation_count, 1);
        assert_eq!(new_metadata.previous_id, Some(old_metadata.node_id));
        assert_eq!(new_metadata.transaction_count, 0);
    }

    #[test]
    fn test_auto_rotate_disabled() {
        let policy = RotationPolicy {
            auto_rotate_critical: false,
            ..Default::default()
        };
        let manager = RotationManager::new(policy);
        let metadata = test_metadata(100, 10000);

        assert!(!manager.should_auto_rotate(&metadata));
    }

    #[test]
    fn test_auto_rotate_enabled() {
        let policy = RotationPolicy {
            auto_rotate_critical: true,
            ..Default::default()
        };
        let manager = RotationManager::new(policy);
        let metadata = test_metadata(100, 10000); // Critical age

        assert!(manager.should_auto_rotate(&metadata));
    }

    #[test]
    fn test_reminder_messages() {
        let manager = RotationManager::new(RotationPolicy::default());

        let healthy = manager.check_rotation(&test_metadata(5, 100));
        let msg = rotation_reminder_message(&healthy);
        assert!(msg.contains("healthy"));

        let critical = manager.check_rotation(&test_metadata(100, 100));
        let msg = rotation_reminder_message(&critical);
        assert!(msg.contains("Critical"));

        let mut compromised_meta = test_metadata(1, 10);
        compromised_meta.mark_compromised("leak");
        let emergency = manager.check_rotation(&compromised_meta);
        let msg = rotation_reminder_message(&emergency);
        assert!(msg.contains("EMERGENCY"));
    }

    #[test]
    fn test_urgency_ordering() {
        assert!(RotationUrgency::None < RotationUrgency::Advisory);
        assert!(RotationUrgency::Advisory < RotationUrgency::Warning);
        assert!(RotationUrgency::Warning < RotationUrgency::Critical);
        assert!(RotationUrgency::Critical < RotationUrgency::Emergency);
    }

    #[test]
    fn test_identity_metadata_new() {
        let node_id = [42u8; 32];
        let metadata = IdentityMetadata::new(node_id);

        assert_eq!(metadata.node_id, node_id);
        assert_eq!(metadata.transaction_count, 0);
        assert_eq!(metadata.rotation_count, 0);
        assert!(!metadata.compromised);
    }

    #[test]
    fn test_record_transaction() {
        let mut metadata = IdentityMetadata::new([1u8; 32]);
        assert_eq!(metadata.transaction_count, 0);

        metadata.record_transaction();
        assert_eq!(metadata.transaction_count, 1);

        metadata.record_transaction();
        metadata.record_transaction();
        assert_eq!(metadata.transaction_count, 3);
    }
}
