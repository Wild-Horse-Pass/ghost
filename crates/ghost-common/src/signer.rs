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
//| FILE: signer.rs                                                                                                      |
//|======================================================================================================================|

//! Signer abstraction for HSM/KMS support
//!
//! This module provides a `Signer` trait that abstracts signing operations,
//! enabling future integration with Hardware Security Modules (HSM) and
//! Key Management Services (KMS) without changing calling code.
//!
//! # Architecture
//!
//! The signing abstraction consists of:
//! - [`Signer`] trait: Core interface for signing operations
//! - [`LocalSigner`]: File-based Ed25519 implementation (default)
//! - [`SignerConfig`]: Configuration enum for signer backends
//!
//! # Example
//!
//! ```ignore
//! use ghost_common::signer::{Signer, LocalSigner, SignerConfig};
//!
//! // Create from config
//! let config = SignerConfig::Local {
//!     key_path: PathBuf::from("~/.ghost/node.key"),
//! };
//! let signer = create_signer(&config)?;
//!
//! // Use the signer
//! let signature = signer.sign(b"message");
//! assert!(signer.verify(b"message", &signature));
//! ```
//!
//! # Future HSM Support
//!
//! When HSM support is implemented, the config will support:
//! ```toml
//! [identity.signer]
//! type = "hsm"
//! slot = 0
//! pin_env = "HSM_PIN"  # Read PIN from environment variable
//! ```

use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::{Signature, Signer as DalekSigner, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::error::GhostResult;

/// Errors that can occur during signing operations
#[derive(Debug, Error)]
pub enum SignerError {
    /// Key file not found
    #[error("Key file not found: {0}")]
    KeyNotFound(String),

    /// Invalid key format
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// HSM/KMS connection error
    #[error("Backend connection failed: {0}")]
    ConnectionFailed(String),

    /// Signing operation failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// HSM slot not available
    #[error("HSM slot {0} not available")]
    SlotNotAvailable(u64),

    /// PIN required but not provided
    #[error("PIN required for HSM access")]
    PinRequired,

    /// KMS key not found
    #[error("KMS key not found: {0}")]
    KmsKeyNotFound(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Configuration for different signer backends
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SignerConfig {
    /// Local file-based Ed25519 key (default)
    Local {
        /// Path to the key file
        key_path: PathBuf,
    },

    /// Hardware Security Module
    /// Note: HSM integration requires additional dependencies
    Hsm {
        /// PKCS#11 library path
        #[serde(default)]
        library_path: Option<PathBuf>,
        /// HSM slot number
        slot: u64,
        /// Environment variable containing PIN
        pin_env: String,
        /// Key label in HSM
        #[serde(default)]
        key_label: Option<String>,
    },

    /// Cloud Key Management Service (AWS KMS, GCP KMS, Azure Key Vault)
    Kms {
        /// KMS key ID or ARN
        key_id: String,
        /// Cloud region
        region: String,
        /// KMS provider type
        #[serde(default)]
        provider: KmsProvider,
    },
}

/// KMS provider types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum KmsProvider {
    /// Amazon Web Services KMS
    #[default]
    Aws,
    /// Google Cloud KMS
    Gcp,
    /// Azure Key Vault
    Azure,
}

impl Default for SignerConfig {
    fn default() -> Self {
        Self::Local {
            key_path: PathBuf::from("~/.ghost/node.key"),
        }
    }
}

impl SignerConfig {
    /// Create a local signer config
    pub fn local(key_path: impl Into<PathBuf>) -> Self {
        Self::Local {
            key_path: key_path.into(),
        }
    }

    /// Create an HSM signer config
    pub fn hsm(slot: u64, pin_env: impl Into<String>) -> Self {
        Self::Hsm {
            library_path: None,
            slot,
            pin_env: pin_env.into(),
            key_label: None,
        }
    }

    /// Create a KMS signer config
    pub fn kms(
        key_id: impl Into<String>,
        region: impl Into<String>,
        provider: KmsProvider,
    ) -> Self {
        Self::Kms {
            key_id: key_id.into(),
            region: region.into(),
            provider,
        }
    }

    /// Check if this is a local signer
    pub fn is_local(&self) -> bool {
        matches!(self, Self::Local { .. })
    }

    /// Check if this is an HSM signer
    pub fn is_hsm(&self) -> bool {
        matches!(self, Self::Hsm { .. })
    }

    /// Check if this is a KMS signer
    pub fn is_kms(&self) -> bool {
        matches!(self, Self::Kms { .. })
    }
}

/// Core signing trait for all signer implementations
///
/// This trait abstracts signing operations to support multiple backends:
/// - Local file-based keys
/// - Hardware Security Modules (HSM)
/// - Cloud Key Management Services (KMS)
///
/// All implementations must be thread-safe (`Send + Sync`).
pub trait Signer: Send + Sync + Debug {
    /// Sign a message and return the signature
    ///
    /// Returns a 64-byte Ed25519 signature.
    fn sign(&self, message: &[u8]) -> [u8; 64];

    /// Get the public key (32 bytes)
    ///
    /// This is the Node ID in Ghost protocol.
    fn public_key(&self) -> [u8; 32];

    /// Verify a signature against a message
    ///
    /// Returns true if the signature is valid for the message.
    fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool;

    /// Get the signer type for logging/debugging
    fn signer_type(&self) -> &'static str;

    /// Downcast to concrete type for operations like key export
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Local file-based Ed25519 signer
///
/// This is the default signer implementation that stores keys in a local file.
/// The key file format is 32 bytes (private key) optionally followed by
/// 12 bytes (PoW proof for Sybil resistance).
///
/// L-22 FIX: Custom Debug implementation to prevent accidental key exposure in logs.
pub struct LocalSigner {
    /// Ed25519 signing key
    signing_key: SigningKey,
    /// Ed25519 verifying key (derived from signing key)
    verifying_key: VerifyingKey,
}

/// L-22 FIX: Custom Debug that redacts the signing key to prevent accidental exposure.
///
/// The signing key is sensitive material that should never appear in logs.
/// Only the public key (verifying key) is shown for debugging purposes.
impl std::fmt::Debug for LocalSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalSigner")
            .field("signing_key", &"[REDACTED]")
            .field("verifying_key", &hex::encode(self.verifying_key.as_bytes()))
            .finish()
    }
}

impl LocalSigner {
    /// Create a new LocalSigner with a random key
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Load a LocalSigner from a key file
    ///
    /// Supports both 32-byte (private key only) and 44-byte (key + PoW proof) formats.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, SignerError> {
        let path = path.as_ref();

        if !path.exists() {
            return Err(SignerError::KeyNotFound(path.to_string_lossy().to_string()));
        }

        let key_bytes = std::fs::read(path)?;

        if key_bytes.len() != 32 && key_bytes.len() != 44 {
            return Err(SignerError::InvalidKey(format!(
                "Invalid key length: expected 32 or 44, got {}",
                key_bytes.len()
            )));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes[..32]);

        let signing_key = SigningKey::from_bytes(&key_array);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Create from hex-encoded private key
    pub fn from_hex(hex_str: &str) -> Result<Self, SignerError> {
        let key_bytes = hex::decode(hex_str)
            .map_err(|e| SignerError::InvalidKey(format!("Invalid hex: {}", e)))?;

        if key_bytes.len() != 32 {
            return Err(SignerError::InvalidKey(format!(
                "Invalid key length: expected 32, got {}",
                key_bytes.len()
            )));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);

        let signing_key = SigningKey::from_bytes(&key_array);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Create from raw 32-byte private key
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Save the private key to a file
    ///
    /// Only saves the 32-byte private key. Use NodeIdentity::save() to include PoW proof.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), SignerError> {
        let path = path.as_ref();

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(path, self.signing_key.to_bytes())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }

        Ok(())
    }

    /// Get the raw signing key bytes (for backup/migration)
    pub fn signing_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Get the verifying key for external signature verification
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

impl Signer for LocalSigner {
    fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signature: Signature = self.signing_key.sign(message);
        signature.to_bytes()
    }

    fn public_key(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        let sig = Signature::from_bytes(signature);
        self.verifying_key.verify(message, &sig).is_ok()
    }

    fn signer_type(&self) -> &'static str {
        "local"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Create a signer from configuration
///
/// Currently only LocalSigner is implemented. HSM and KMS signers
/// will return an error indicating they are not yet available.
pub fn create_signer(config: &SignerConfig) -> Result<Arc<dyn Signer>, SignerError> {
    match config {
        SignerConfig::Local { key_path } => {
            // Expand ~ in path
            let expanded_path = expand_tilde(key_path);

            if expanded_path.exists() {
                Ok(Arc::new(LocalSigner::load(&expanded_path)?))
            } else {
                // Generate new key if file doesn't exist
                let signer = LocalSigner::generate();
                signer.save(&expanded_path)?;
                Ok(Arc::new(signer))
            }
        }

        SignerConfig::Hsm { slot, .. } => Err(SignerError::ConnectionFailed(format!(
            "HSM signer not yet implemented (slot {}). \
             Use 'type = \"local\"' or contribute HSM support.",
            slot
        ))),

        SignerConfig::Kms {
            key_id, provider, ..
        } => Err(SignerError::KmsKeyNotFound(format!(
            "KMS signer not yet implemented ({:?}: {}). \
             Use 'type = \"local\"' or contribute KMS support.",
            provider, key_id
        ))),
    }
}

/// Create a signer or generate a new one if the key doesn't exist
pub fn create_or_generate_signer(config: &SignerConfig) -> Result<Arc<dyn Signer>, SignerError> {
    create_signer(config)
}

/// Expand ~ in path to home directory
fn expand_tilde(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    if let Some(stripped) = path_str.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
            return PathBuf::from(home).join(stripped);
        }
    }
    path.to_path_buf()
}

/// Verify a signature using a public key (no signer instance needed)
pub fn verify_with_public_key(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> GhostResult<bool> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|e| crate::error::GhostError::InvalidKey(format!("Invalid public key: {}", e)))?;

    let sig = Signature::from_bytes(signature);

    Ok(verifying_key.verify(message, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_local_signer_generate() {
        let signer = LocalSigner::generate();
        let public_key = signer.public_key();
        assert_eq!(public_key.len(), 32);
    }

    #[test]
    fn test_local_signer_sign_verify() {
        let signer = LocalSigner::generate();
        let message = b"Hello, Ghost!";

        let signature = signer.sign(message);
        assert!(signer.verify(message, &signature));

        // Wrong message should fail
        assert!(!signer.verify(b"Wrong message", &signature));
    }

    #[test]
    fn test_local_signer_save_load() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test.key");

        let signer = LocalSigner::generate();
        let original_pubkey = signer.public_key();

        signer.save(&key_path).unwrap();
        let loaded = LocalSigner::load(&key_path).unwrap();

        assert_eq!(loaded.public_key(), original_pubkey);

        // Verify signatures are compatible
        let message = b"Test message";
        let signature = signer.sign(message);
        assert!(loaded.verify(message, &signature));
    }

    #[test]
    fn test_local_signer_from_hex() {
        let signer = LocalSigner::generate();
        let hex = hex::encode(signer.signing_key_bytes());

        let loaded = LocalSigner::from_hex(&hex).unwrap();
        assert_eq!(loaded.public_key(), signer.public_key());
    }

    #[test]
    fn test_signer_config_default() {
        let config = SignerConfig::default();
        assert!(config.is_local());
    }

    #[test]
    fn test_signer_config_constructors() {
        let local = SignerConfig::local("/path/to/key");
        assert!(local.is_local());

        let hsm = SignerConfig::hsm(0, "HSM_PIN");
        assert!(hsm.is_hsm());

        let kms = SignerConfig::kms("key-id", "us-east-1", KmsProvider::Aws);
        assert!(kms.is_kms());
    }

    #[test]
    fn test_create_signer_local() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("new.key");

        let config = SignerConfig::Local {
            key_path: key_path.clone(),
        };

        // Should generate new key since file doesn't exist
        let signer = create_signer(&config).unwrap();
        assert!(key_path.exists());
        assert_eq!(signer.signer_type(), "local");

        // Load again - should use existing key
        let signer2 = create_signer(&config).unwrap();
        assert_eq!(signer.public_key(), signer2.public_key());
    }

    #[test]
    fn test_create_signer_hsm_not_implemented() {
        let config = SignerConfig::Hsm {
            library_path: None,
            slot: 0,
            pin_env: "PIN".to_string(),
            key_label: None,
        };

        let result = create_signer(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_signer_kms_not_implemented() {
        let config = SignerConfig::Kms {
            key_id: "test-key".to_string(),
            region: "us-east-1".to_string(),
            provider: KmsProvider::Aws,
        };

        let result = create_signer(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_with_public_key() {
        let signer = LocalSigner::generate();
        let public_key = signer.public_key();
        let message = b"Test message";
        let signature = signer.sign(message);

        let result = verify_with_public_key(&public_key, message, &signature).unwrap();
        assert!(result);

        // Wrong message should fail
        let result = verify_with_public_key(&public_key, b"wrong", &signature).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_signer_config_serde() {
        let local = SignerConfig::Local {
            key_path: PathBuf::from("/path/to/key"),
        };
        let json = serde_json::to_string(&local).unwrap();
        let parsed: SignerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(local, parsed);

        let hsm = SignerConfig::Hsm {
            library_path: Some(PathBuf::from("/lib/pkcs11.so")),
            slot: 1,
            pin_env: "HSM_PIN".to_string(),
            key_label: Some("ghost-key".to_string()),
        };
        let json = serde_json::to_string(&hsm).unwrap();
        let parsed: SignerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(hsm, parsed);

        let kms = SignerConfig::Kms {
            key_id: "key-123".to_string(),
            region: "eu-west-1".to_string(),
            provider: KmsProvider::Gcp,
        };
        let json = serde_json::to_string(&kms).unwrap();
        let parsed: SignerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(kms, parsed);
    }

    #[test]
    fn test_l22_local_signer_debug_redacts_key() {
        // L-22 FIX: Verify that Debug output does not expose the signing key
        let signer = LocalSigner::generate();

        // Get the actual signing key bytes (to verify they're NOT in debug output)
        let signing_key_bytes = signer.signing_key_bytes();
        let signing_key_hex = hex::encode(signing_key_bytes);

        // Get debug output
        let debug_output = format!("{:?}", signer);

        // Verify the signing key is redacted
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output should contain [REDACTED]: {}",
            debug_output
        );

        // Verify the actual signing key bytes are NOT in the output
        assert!(
            !debug_output.contains(&signing_key_hex),
            "Debug output must NOT contain the signing key: {}",
            debug_output
        );

        // Verify the public key IS present (for debugging utility)
        let public_key_hex = hex::encode(signer.public_key());
        assert!(
            debug_output.contains(&public_key_hex),
            "Debug output should contain the public key for debugging: {}",
            debug_output
        );
    }

    #[test]
    fn test_l22_local_signer_debug_format() {
        // L-22 FIX: Verify the exact format of Debug output
        let signer = LocalSigner::generate();
        let debug_output = format!("{:?}", signer);

        // Should be a proper debug struct format
        assert!(debug_output.starts_with("LocalSigner {"));
        assert!(debug_output.contains("signing_key: \"[REDACTED]\""));
        assert!(debug_output.contains("verifying_key:"));
    }
}
