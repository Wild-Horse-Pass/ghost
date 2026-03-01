//! Platform keychain integration
//!
//! Provides secure storage using platform-native keystores:
//! - iOS: Keychain Services (registered via FFI callback)
//! - Android: Android Keystore (registered via FFI callback)
//!
//! The Rust side defines the `PlatformKeychain` trait. Native code
//! registers an implementation at startup via `register_keychain()`.

use super::StorageError;
use std::sync::{Arc, Mutex, OnceLock};

/// Keychain access level
#[derive(Debug, Clone, Copy)]
pub enum KeychainAccess {
    /// Available when device is unlocked
    WhenUnlocked,
    /// Available when device is unlocked, not backed up
    WhenUnlockedThisDeviceOnly,
    /// Available after first unlock (until reboot)
    AfterFirstUnlock,
}

/// Trait for platform-specific keychain implementations.
///
/// Android implements via Keystore + BiometricPrompt.
/// iOS implements via Keychain Services + LAContext.
/// Desktop provides an insecure fallback for testing.
pub trait PlatformKeychain: Send + Sync {
    /// Store a secret value with the given access level
    fn store(&self, key: &str, value: &[u8], access: KeychainAccess) -> Result<(), StorageError>;

    /// Retrieve a secret value
    fn retrieve(&self, key: &str) -> Result<Vec<u8>, StorageError>;

    /// Delete a secret
    fn delete(&self, key: &str) -> Result<(), StorageError>;

    /// Check if biometric authentication is available
    fn biometric_available(&self) -> bool;

    /// Authenticate with biometrics (returns true if successful)
    fn authenticate_biometric(&self, reason: &str) -> Result<bool, StorageError>;
}

/// Global keychain singleton
static KEYCHAIN: OnceLock<Arc<dyn PlatformKeychain>> = OnceLock::new();

/// Register the platform keychain implementation.
/// Called once at startup from native code (Android/iOS).
pub fn register_keychain(keychain: Arc<dyn PlatformKeychain>) {
    let _ = KEYCHAIN.set(keychain);
}

/// Get the registered keychain, or install the desktop fallback on first access.
fn get_keychain() -> Arc<dyn PlatformKeychain> {
    KEYCHAIN
        .get_or_init(|| {
            Arc::new(DesktopFallbackKeychain::new()) as Arc<dyn PlatformKeychain>
        })
        .clone()
}

/// High-level keychain accessor that delegates to the registered platform implementation.
pub struct Keychain {
    /// Service identifier
    pub(crate) service: String,
    /// Access level (passed to platform implementation as metadata)
    access: KeychainAccess,
}

impl Keychain {
    /// Create a new keychain accessor
    pub fn new(service: &str, access: KeychainAccess) -> Self {
        Self {
            service: service.to_string(),
            access,
        }
    }

    /// Get the access level
    pub fn access(&self) -> KeychainAccess {
        self.access
    }

    fn prefixed_key(&self, key: &str) -> String {
        format!("{}:{}", self.service, key)
    }

    /// Store a secret in the keychain
    pub fn store(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        get_keychain().store(&self.prefixed_key(key), value, self.access)
    }

    /// Retrieve a secret from the keychain
    pub fn retrieve(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        get_keychain().retrieve(&self.prefixed_key(key))
    }

    /// Delete a secret from the keychain
    pub fn delete(&self, key: &str) -> Result<(), StorageError> {
        get_keychain().delete(&self.prefixed_key(key))
    }

    /// Check if biometric authentication is available
    pub fn biometric_available() -> bool {
        get_keychain().biometric_available()
    }

    /// Authenticate with biometrics
    pub fn authenticate_biometric(reason: &str) -> Result<bool, StorageError> {
        get_keychain().authenticate_biometric(reason)
    }
}

/// Insecure in-memory keychain for desktop testing.
/// NOT for production use.
struct DesktopFallbackKeychain {
    store: Mutex<std::collections::HashMap<String, Vec<u8>>>,
}

impl DesktopFallbackKeychain {
    fn new() -> Self {
        tracing::warn!("Using insecure desktop fallback keychain — NOT for production");
        Self {
            store: Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl PlatformKeychain for DesktopFallbackKeychain {
    fn store(&self, key: &str, value: &[u8], _access: KeychainAccess) -> Result<(), StorageError> {
        self.store
            .lock()
            .map_err(|e| StorageError::Keychain(e.to_string()))?
            .insert(key.to_string(), value.to_vec());
        Ok(())
    }

    fn retrieve(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        self.store
            .lock()
            .map_err(|e| StorageError::Keychain(e.to_string()))?
            .get(key)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(key.to_string()))
    }

    fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.store
            .lock()
            .map_err(|e| StorageError::Keychain(e.to_string()))?
            .remove(key);
        Ok(())
    }

    fn biometric_available(&self) -> bool {
        false
    }

    fn authenticate_biometric(&self, _reason: &str) -> Result<bool, StorageError> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keychain_creation() {
        let keychain = Keychain::new("com.ghost.tap", KeychainAccess::WhenUnlockedThisDeviceOnly);
        assert_eq!(keychain.service, "com.ghost.tap");
    }

    #[test]
    fn test_desktop_fallback_roundtrip() {
        let kc = DesktopFallbackKeychain::new();
        kc.store("test_key", b"secret_value", KeychainAccess::WhenUnlocked).unwrap();
        let retrieved = kc.retrieve("test_key").unwrap();
        assert_eq!(retrieved, b"secret_value");
        kc.delete("test_key").unwrap();
        assert!(kc.retrieve("test_key").is_err());
    }

    #[test]
    fn test_keychain_store_retrieve() {
        let keychain = Keychain::new("test.service", KeychainAccess::WhenUnlocked);
        // Uses desktop fallback
        keychain.store("master_key", b"key_data").unwrap();
        let val = keychain.retrieve("master_key").unwrap();
        assert_eq!(val, b"key_data");
    }

    #[test]
    fn test_biometric_not_available() {
        assert!(!Keychain::biometric_available());
    }
}
