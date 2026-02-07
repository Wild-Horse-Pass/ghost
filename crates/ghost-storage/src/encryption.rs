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
//| FILE: encryption.rs                                                                                                  |
//|======================================================================================================================|

//! H-6: Encryption for sensitive database fields
//!
//! Provides field-level encryption for sensitive data stored in the database,
//! such as payout addresses. Uses ChaCha20-Poly1305 for authenticated encryption.
//!
//! # Usage
//!
//! ```ignore
//! use ghost_storage::encryption::{encrypt_sensitive, decrypt_sensitive};
//!
//! // Encrypt before storing
//! let key = get_encryption_key();
//! let encrypted = encrypt_sensitive("bc1q...", &key)?;
//! db.store_address(&encrypted)?;
//!
//! // Decrypt after retrieval
//! let encrypted = db.get_address()?;
//! let plaintext = decrypt_sensitive(&encrypted, &key)?;
//! ```
//!
//! # Key Management
//!
//! The encryption key should be:
//! - 32 bytes (256 bits)
//! - Derived from a user password using a KDF (e.g., scrypt, Argon2)
//! - Stored securely (environment variable, HSM, or secure enclave)
//! - NEVER stored in the database
//!
//! For mainnet, the key MUST come from GHOST_ENCRYPTION_KEY environment variable
//! or be provided via configuration.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ghost_common::error::{GhostError, GhostResult};

/// Nonce size for ChaCha20-Poly1305 (12 bytes)
const NONCE_SIZE: usize = 12;

/// Encrypt a sensitive string before storing in database.
///
/// Uses ChaCha20-Poly1305 for authenticated encryption.
/// Output format: base64(nonce || ciphertext || tag)
///
/// # Arguments
/// * `plaintext` - The sensitive data to encrypt
/// * `key` - 32-byte encryption key
///
/// # Returns
/// Base64-encoded encrypted data suitable for database storage
///
/// # Security
/// - Uses a random nonce for each encryption
/// - Provides authentication (tampering detection)
/// - Ciphertext is base64-encoded for safe text storage
pub fn encrypt_sensitive(plaintext: &str, key: &[u8; 32]) -> GhostResult<String> {
    // Create cipher
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| GhostError::Crypto(format!("Invalid encryption key: {}", e)))?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| GhostError::Crypto(format!("RNG failed: {}", e)))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| GhostError::Crypto(format!("Encryption failed: {}", e)))?;

    // Combine: nonce || ciphertext (tag is included in ciphertext by AEAD)
    let mut combined = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    // Base64 encode for database storage
    Ok(BASE64.encode(&combined))
}

/// Decrypt a sensitive string retrieved from database.
///
/// Expects base64(nonce || ciphertext || tag) format.
///
/// # Arguments
/// * `encrypted` - Base64-encoded encrypted data from database
/// * `key` - 32-byte encryption key (must match encryption key)
///
/// # Returns
/// The original plaintext string
///
/// # Errors
/// - `GhostError::Crypto` if decryption fails (wrong key, tampered data, etc.)
pub fn decrypt_sensitive(encrypted: &str, key: &[u8; 32]) -> GhostResult<String> {
    // Decode base64
    let combined = BASE64
        .decode(encrypted)
        .map_err(|e| GhostError::Crypto(format!("Invalid base64: {}", e)))?;

    // Validate minimum length (nonce + at least 1 byte + tag)
    if combined.len() < NONCE_SIZE + 16 {
        return Err(GhostError::Crypto("Encrypted data too short".into()));
    }

    // Split nonce and ciphertext
    let nonce = Nonce::from_slice(&combined[..NONCE_SIZE]);
    let ciphertext = &combined[NONCE_SIZE..];

    // Create cipher and decrypt
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| GhostError::Crypto(format!("Invalid encryption key: {}", e)))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| GhostError::Crypto("Decryption failed - wrong key or tampered data".into()))?;

    // Convert to string
    String::from_utf8(plaintext).map_err(|e| GhostError::Crypto(format!("Invalid UTF-8: {}", e)))
}

/// Check if a string appears to be encrypted (base64 format with sufficient length).
///
/// This is a heuristic check to help with migration from plaintext to encrypted storage.
/// It checks if the string is valid base64 and decodes to at least nonce + tag size.
pub fn is_likely_encrypted(value: &str) -> bool {
    if let Ok(decoded) = BASE64.decode(value) {
        // Encrypted data must be at least nonce (12) + tag (16) = 28 bytes
        decoded.len() >= NONCE_SIZE + 16
    } else {
        false
    }
}

/// Get encryption key from environment or return None.
///
/// For production, the key should be set via GHOST_ENCRYPTION_KEY environment variable.
/// Returns None if not configured, allowing callers to decide how to handle.
pub fn get_encryption_key_from_env() -> Option<[u8; 32]> {
    std::env::var("GHOST_ENCRYPTION_KEY").ok().and_then(|key| {
        // Key should be 64 hex chars (32 bytes)
        if key.len() == 64 {
            hex::decode(&key)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

        let encrypted = encrypt_sensitive(plaintext, &key).unwrap();
        let decrypted = decrypt_sensitive(&encrypted, &key).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypted_differs_from_plaintext() {
        let key = test_key();
        let plaintext = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

        let encrypted = encrypt_sensitive(plaintext, &key).unwrap();

        assert_ne!(plaintext, encrypted);
        assert!(encrypted.len() > plaintext.len()); // Adds nonce + tag
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = test_key();
        let mut key2 = test_key();
        key2[0] = 0xFF; // Different key

        let plaintext = "secret address";
        let encrypted = encrypt_sensitive(plaintext, &key1).unwrap();

        let result = decrypt_sensitive(&encrypted, &key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_data_fails() {
        let key = test_key();
        let plaintext = "secret address";
        let mut encrypted = encrypt_sensitive(plaintext, &key).unwrap();

        // Tamper with the encrypted data
        let mut bytes = BASE64.decode(&encrypted).unwrap();
        bytes[NONCE_SIZE] ^= 0xFF;
        encrypted = BASE64.encode(&bytes);

        let result = decrypt_sensitive(&encrypted, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_likely_encrypted() {
        let key = test_key();
        let encrypted = encrypt_sensitive("test", &key).unwrap();

        assert!(is_likely_encrypted(&encrypted));
        assert!(!is_likely_encrypted("bc1qtest")); // Plaintext address
        assert!(!is_likely_encrypted("short")); // Too short
    }

    #[test]
    fn test_empty_string() {
        let key = test_key();
        let encrypted = encrypt_sensitive("", &key).unwrap();
        let decrypted = decrypt_sensitive(&encrypted, &key).unwrap();
        assert_eq!("", decrypted);
    }
}
