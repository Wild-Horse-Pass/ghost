//! Cryptographic primitives and utilities

mod secure_mem;

pub use secure_mem::*;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid key")]
    InvalidKey,

    #[error("Random generation failed")]
    RandomFailed,
}

/// Generate cryptographically secure random bytes
pub fn random_bytes(len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = vec![0u8; len];
    getrandom::getrandom(&mut bytes).map_err(|_| CryptoError::RandomFailed)?;
    Ok(bytes)
}

/// Encrypt data with AES-256-GCM
pub fn encrypt_aes_gcm(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;

    // Generate random nonce
    let nonce_bytes = random_bytes(12)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    // Prepend nonce to ciphertext
    let mut result = nonce_bytes;
    result.extend(ciphertext);
    Ok(result)
}

/// Decrypt data with AES-256-GCM.
///
/// Plaintext is held in a `SecureBuffer` during decryption so it is
/// zeroized if this function panics or the caller drops the result
/// without consuming the bytes.
pub fn decrypt_aes_gcm(ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    if ciphertext.len() < 12 {
        return Err(CryptoError::DecryptionFailed("Ciphertext too short".into()));
    }

    let (nonce_bytes, encrypted) = ciphertext.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;

    let plaintext_raw = cipher
        .decrypt(nonce, encrypted)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    // Wrap in SecureBuffer so the plaintext is zeroized on drop.
    let secure = SecureBuffer::from_vec(plaintext_raw);
    Ok(secure.as_slice().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let plaintext = b"Hello, Ghost Pay!";

        let encrypted = encrypt_aes_gcm(plaintext, &key).unwrap();
        let decrypted = decrypt_aes_gcm(&encrypted, &key).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_random_bytes() {
        let bytes1 = random_bytes(32).unwrap();
        let bytes2 = random_bytes(32).unwrap();

        assert_eq!(bytes1.len(), 32);
        assert_ne!(bytes1, bytes2);
    }
}
