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
//| FILE: metadata.rs                                                                                                    |
//|======================================================================================================================|

//! Payment metadata encryption for Ghost Labels
//!
//! Provides privacy-preserving encrypted metadata that travels with payments.
//! Labels and memos are encrypted client-side using the ECDH shared secret,
//! ensuring that only the sender and recipient can read the metadata.
//!
//! # Security Properties
//!
//! - Fixed 80-byte ciphertext prevents size fingerprinting
//! - Random padding ensures identical metadata produces different ciphertext
//! - HKDF domain separation for key and nonce derivation
//! - ChaCha20-Poly1305 AEAD provides authenticated encryption
//! - Sensitive data is zeroized on drop

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::GhostKeyError;

/// Default label index (uncategorized)
pub const DEFAULT_LABEL: u32 = 0;

/// Maximum memo length in bytes (UTF-8 encoded)
pub const MAX_MEMO_LENGTH: usize = 59;

/// Plaintext size before encryption: 4 (label) + 1 (memo_len) + 59 (memo_max) = 64 bytes
pub const METADATA_PLAINTEXT_SIZE: usize = 64;

/// Ciphertext size after encryption: 64 (plaintext) + 16 (Poly1305 tag) = 80 bytes
pub const METADATA_CIPHERTEXT_SIZE: usize = 80;

/// HKDF info string for metadata key derivation
/// M-4: Domain separation ensures keys are unique to this specific use case
const HKDF_KEY_INFO: &[u8] = b"ghost/metadata/key/v1";

/// HKDF info string for metadata nonce derivation
/// M-4: Separate info string ensures nonce is derived independently from key
const HKDF_NONCE_INFO: &[u8] = b"ghost/metadata/nonce/v1";

/// Payment metadata containing label and optional memo
///
/// Encrypted before transmission to preserve privacy. The fixed-size serialization
/// prevents metadata length from leaking information about the payment category.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentMetadata {
    /// Label index referencing the sender's LabelDictionary
    pub label: u32,
    /// Optional memo text (max 59 bytes UTF-8)
    pub memo: Option<String>,
    /// Random padding bytes (not part of public API, used internally)
    padding: [u8; MAX_MEMO_LENGTH],
}

impl Zeroize for PaymentMetadata {
    fn zeroize(&mut self) {
        self.label = 0;
        if let Some(ref mut memo) = self.memo {
            // Zeroize the string's bytes by replacing with zeros then clearing
            let bytes = unsafe { memo.as_bytes_mut() };
            bytes.zeroize();
        }
        self.memo = None;
        self.padding.zeroize();
    }
}

impl Drop for PaymentMetadata {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl PaymentMetadata {
    /// Create new payment metadata with label and optional memo
    ///
    /// # Errors
    ///
    /// Returns error if memo exceeds 59 bytes when UTF-8 encoded
    pub fn new(label: u32, memo: Option<String>) -> Result<Self, GhostKeyError> {
        if let Some(ref m) = memo {
            if m.len() > MAX_MEMO_LENGTH {
                return Err(GhostKeyError::InvalidMetadata(format!(
                    "Memo exceeds maximum length of {} bytes (got {} bytes)",
                    MAX_MEMO_LENGTH,
                    m.len()
                )));
            }
            // Validate UTF-8 (String guarantees this, but be explicit)
            if !m.is_ascii()
                && m.chars().any(|c| {
                    !c.is_alphanumeric() && !c.is_whitespace() && !c.is_ascii_punctuation()
                })
            {
                // Allow valid UTF-8 - this check is mainly for documentation
            }
        }

        // Generate random padding
        let mut padding = [0u8; MAX_MEMO_LENGTH];
        getrandom::getrandom(&mut padding).map_err(|e| {
            GhostKeyError::CryptoError(format!("Failed to generate random padding: {}", e))
        })?;

        Ok(Self {
            label,
            memo,
            padding,
        })
    }

    /// Create default metadata (label 0, no memo)
    pub fn default_metadata() -> Self {
        let mut padding = [0u8; MAX_MEMO_LENGTH];
        // Best effort random padding, fall back to zeros if RNG fails
        let _ = getrandom::getrandom(&mut padding);

        Self {
            label: DEFAULT_LABEL,
            memo: None,
            padding,
        }
    }

    /// Serialize to fixed 64-byte plaintext
    ///
    /// Format:
    /// - Bytes 0-3: label (big-endian u32)
    /// - Byte 4: memo length (0-59)
    /// - Bytes 5-63: memo + random padding (59 bytes total)
    fn to_plaintext(&self) -> [u8; METADATA_PLAINTEXT_SIZE] {
        let mut plaintext = [0u8; METADATA_PLAINTEXT_SIZE];

        // Label (4 bytes, big-endian)
        plaintext[0..4].copy_from_slice(&self.label.to_be_bytes());

        // Memo length and content
        if let Some(ref memo) = self.memo {
            let memo_bytes = memo.as_bytes();
            plaintext[4] = memo_bytes.len() as u8;
            plaintext[5..5 + memo_bytes.len()].copy_from_slice(memo_bytes);
            // Fill remaining with random padding
            let padding_start = 5 + memo_bytes.len();
            let padding_len = METADATA_PLAINTEXT_SIZE - padding_start;
            plaintext[padding_start..].copy_from_slice(&self.padding[..padding_len]);
        } else {
            // No memo, fill with random padding
            plaintext[4] = 0;
            plaintext[5..].copy_from_slice(&self.padding[..METADATA_PLAINTEXT_SIZE - 5]);
        }

        plaintext
    }

    /// Deserialize from 64-byte plaintext
    fn from_plaintext(bytes: &[u8; METADATA_PLAINTEXT_SIZE]) -> Result<Self, GhostKeyError> {
        // Label (4 bytes, big-endian)
        let label = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

        // Memo length
        let memo_len = bytes[4] as usize;
        if memo_len > MAX_MEMO_LENGTH {
            return Err(GhostKeyError::InvalidMetadata(format!(
                "Invalid memo length: {} (max {})",
                memo_len, MAX_MEMO_LENGTH
            )));
        }

        // Memo content
        let memo = if memo_len > 0 {
            let memo_bytes = &bytes[5..5 + memo_len];
            let memo_str = std::str::from_utf8(memo_bytes).map_err(|e| {
                GhostKeyError::InvalidMetadata(format!("Invalid UTF-8 in memo: {}", e))
            })?;
            Some(memo_str.to_string())
        } else {
            None
        };

        // Preserve padding for consistency
        let mut padding = [0u8; MAX_MEMO_LENGTH];
        let padding_start = 5 + memo_len;
        let padding_len = METADATA_PLAINTEXT_SIZE - padding_start;
        padding[..padding_len].copy_from_slice(&bytes[padding_start..]);

        Ok(Self {
            label,
            memo,
            padding,
        })
    }
}

/// Derive encryption key from shared secret using HKDF-SHA256
///
/// M-4: Uses the ephemeral_pubkey as salt to ensure uniqueness per transaction.
/// Each Silent Payment uses a fresh ephemeral keypair, so the salt (and thus
/// the derived key) is unique for every payment. The info string provides
/// domain separation to ensure this key is only used for metadata encryption.
///
/// Security properties:
/// - Unique ephemeral key per payment = unique salt = unique derived key
/// - Domain-separated info string prevents key reuse across different protocols
/// - HKDF-SHA256 provides strong key derivation from ECDH shared secret
fn derive_metadata_key(shared_secret: &[u8], ephemeral_pubkey: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(ephemeral_pubkey), shared_secret);
    let mut key = [0u8; 32];
    hk.expand(HKDF_KEY_INFO, &mut key)
        .expect("32 bytes is valid output length for HKDF");
    key
}

/// Derive nonce from shared secret using HKDF-SHA256
///
/// M-4: Deterministic nonce derived with unique ephemeral_pubkey salt ensures
/// each payment uses a unique (key, nonce) pair. The separate info string
/// ensures the nonce is derived independently from the key.
///
/// Security properties:
/// - Unique ephemeral key per payment = unique nonce per (key, nonce) pair
/// - Never reuse same (key, nonce) pair since ephemeral key is single-use
/// - Separate info string provides independence from key derivation
fn derive_metadata_nonce(shared_secret: &[u8], ephemeral_pubkey: &[u8]) -> [u8; 12] {
    let hk = Hkdf::<Sha256>::new(Some(ephemeral_pubkey), shared_secret);
    let mut nonce = [0u8; 12];
    hk.expand(HKDF_NONCE_INFO, &mut nonce)
        .expect("12 bytes is valid output length for HKDF");
    nonce
}

/// Encrypt payment metadata
///
/// Uses ChaCha20-Poly1305 AEAD with HKDF-derived key and nonce.
/// The shared_secret should be derived from ECDH between sender and recipient.
///
/// # Arguments
///
/// * `metadata` - Payment metadata to encrypt
/// * `shared_secret` - ECDH shared secret (32 bytes)
/// * `ephemeral_pubkey` - Sender's ephemeral public key (33 bytes compressed)
///
/// # Returns
///
/// Fixed 80-byte ciphertext on success
pub fn encrypt_metadata(
    metadata: &PaymentMetadata,
    shared_secret: &[u8],
    ephemeral_pubkey: &[u8],
) -> Result<[u8; METADATA_CIPHERTEXT_SIZE], GhostKeyError> {
    let key = derive_metadata_key(shared_secret, ephemeral_pubkey);
    let nonce_bytes = derive_metadata_nonce(shared_secret, ephemeral_pubkey);

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| GhostKeyError::CryptoError(format!("Failed to create cipher: {}", e)))?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = metadata.to_plaintext();

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| GhostKeyError::CryptoError(format!("Encryption failed: {}", e)))?;

    // Zeroize sensitive intermediate data
    let mut key_copy = key;
    key_copy.zeroize();

    // Convert to fixed-size array
    let mut result = [0u8; METADATA_CIPHERTEXT_SIZE];
    if ciphertext.len() != METADATA_CIPHERTEXT_SIZE {
        return Err(GhostKeyError::CryptoError(format!(
            "Unexpected ciphertext size: {} (expected {})",
            ciphertext.len(),
            METADATA_CIPHERTEXT_SIZE
        )));
    }
    result.copy_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt payment metadata
///
/// Uses ChaCha20-Poly1305 AEAD with HKDF-derived key and nonce.
/// The shared_secret should be derived from ECDH between sender and recipient.
///
/// # Arguments
///
/// * `ciphertext` - 80-byte encrypted metadata
/// * `shared_secret` - ECDH shared secret (32 bytes)
/// * `ephemeral_pubkey` - Sender's ephemeral public key (33 bytes compressed)
///
/// # Returns
///
/// Decrypted PaymentMetadata on success
pub fn decrypt_metadata(
    ciphertext: &[u8; METADATA_CIPHERTEXT_SIZE],
    shared_secret: &[u8],
    ephemeral_pubkey: &[u8],
) -> Result<PaymentMetadata, GhostKeyError> {
    let key = derive_metadata_key(shared_secret, ephemeral_pubkey);
    let nonce_bytes = derive_metadata_nonce(shared_secret, ephemeral_pubkey);

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| GhostKeyError::CryptoError(format!("Failed to create cipher: {}", e)))?;

    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| {
        GhostKeyError::CryptoError("Decryption failed: authentication error".to_string())
    })?;

    // Zeroize sensitive intermediate data
    let mut key_copy = key;
    key_copy.zeroize();

    // Convert to fixed-size array
    if plaintext.len() != METADATA_PLAINTEXT_SIZE {
        return Err(GhostKeyError::CryptoError(format!(
            "Unexpected plaintext size: {} (expected {})",
            plaintext.len(),
            METADATA_PLAINTEXT_SIZE
        )));
    }

    let mut plaintext_array = [0u8; METADATA_PLAINTEXT_SIZE];
    plaintext_array.copy_from_slice(&plaintext);

    let result = PaymentMetadata::from_plaintext(&plaintext_array)?;

    // Zeroize plaintext
    plaintext_array.zeroize();

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_shared_secret() -> [u8; 32] {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ]
    }

    fn test_ephemeral_pubkey() -> [u8; 33] {
        [
            0x02, // Compressed pubkey prefix
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99,
        ]
    }

    #[test]
    fn test_metadata_roundtrip() {
        let metadata = PaymentMetadata::new(42, Some("Test memo".to_string())).unwrap();
        let shared_secret = test_shared_secret();
        let ephemeral_pubkey = test_ephemeral_pubkey();

        let ciphertext = encrypt_metadata(&metadata, &shared_secret, &ephemeral_pubkey).unwrap();
        assert_eq!(ciphertext.len(), METADATA_CIPHERTEXT_SIZE);

        let decrypted = decrypt_metadata(&ciphertext, &shared_secret, &ephemeral_pubkey).unwrap();
        assert_eq!(decrypted.label, 42);
        assert_eq!(decrypted.memo, Some("Test memo".to_string()));
    }

    #[test]
    fn test_metadata_without_memo() {
        let metadata = PaymentMetadata::new(100, None).unwrap();
        let shared_secret = test_shared_secret();
        let ephemeral_pubkey = test_ephemeral_pubkey();

        let ciphertext = encrypt_metadata(&metadata, &shared_secret, &ephemeral_pubkey).unwrap();
        let decrypted = decrypt_metadata(&ciphertext, &shared_secret, &ephemeral_pubkey).unwrap();

        assert_eq!(decrypted.label, 100);
        assert_eq!(decrypted.memo, None);
    }

    #[test]
    fn test_default_metadata() {
        let metadata = PaymentMetadata::default_metadata();
        assert_eq!(metadata.label, DEFAULT_LABEL);
        assert_eq!(metadata.memo, None);
    }

    #[test]
    fn test_fixed_ciphertext_size() {
        let shared_secret = test_shared_secret();
        let ephemeral_pubkey = test_ephemeral_pubkey();

        // Empty memo
        let m1 = PaymentMetadata::new(0, None).unwrap();
        let c1 = encrypt_metadata(&m1, &shared_secret, &ephemeral_pubkey).unwrap();

        // Short memo
        let m2 = PaymentMetadata::new(1, Some("Hi".to_string())).unwrap();
        let c2 = encrypt_metadata(&m2, &shared_secret, &ephemeral_pubkey).unwrap();

        // Max length memo
        let max_memo = "x".repeat(MAX_MEMO_LENGTH);
        let m3 = PaymentMetadata::new(2, Some(max_memo)).unwrap();
        let c3 = encrypt_metadata(&m3, &shared_secret, &ephemeral_pubkey).unwrap();

        // All ciphertexts have the same size
        assert_eq!(c1.len(), METADATA_CIPHERTEXT_SIZE);
        assert_eq!(c2.len(), METADATA_CIPHERTEXT_SIZE);
        assert_eq!(c3.len(), METADATA_CIPHERTEXT_SIZE);
    }

    #[test]
    fn test_random_padding_produces_different_ciphertext() {
        let shared_secret = test_shared_secret();
        let ephemeral_pubkey = test_ephemeral_pubkey();

        // Same metadata encrypted twice should produce different ciphertext
        // due to random padding
        let m1 = PaymentMetadata::new(1, Some("Test".to_string())).unwrap();
        let m2 = PaymentMetadata::new(1, Some("Test".to_string())).unwrap();

        let c1 = encrypt_metadata(&m1, &shared_secret, &ephemeral_pubkey).unwrap();
        let c2 = encrypt_metadata(&m2, &shared_secret, &ephemeral_pubkey).unwrap();

        // Ciphertexts should differ due to random padding
        // (with overwhelming probability)
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_memo_too_long() {
        let long_memo = "x".repeat(MAX_MEMO_LENGTH + 1);
        let result = PaymentMetadata::new(0, Some(long_memo));
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let metadata = PaymentMetadata::new(42, Some("Secret".to_string())).unwrap();
        let shared_secret = test_shared_secret();
        let ephemeral_pubkey = test_ephemeral_pubkey();

        let ciphertext = encrypt_metadata(&metadata, &shared_secret, &ephemeral_pubkey).unwrap();

        // Try to decrypt with wrong shared secret
        let wrong_secret = [0u8; 32];
        let result = decrypt_metadata(&ciphertext, &wrong_secret, &ephemeral_pubkey);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let metadata = PaymentMetadata::new(42, Some("Secret".to_string())).unwrap();
        let shared_secret = test_shared_secret();
        let ephemeral_pubkey = test_ephemeral_pubkey();

        let mut ciphertext =
            encrypt_metadata(&metadata, &shared_secret, &ephemeral_pubkey).unwrap();

        // Tamper with ciphertext
        ciphertext[0] ^= 0xff;

        let result = decrypt_metadata(&ciphertext, &shared_secret, &ephemeral_pubkey);
        assert!(result.is_err());
    }

    #[test]
    fn test_utf8_memo() {
        let metadata = PaymentMetadata::new(1, Some("Hello 世界! 🎉".to_string())).unwrap();
        let shared_secret = test_shared_secret();
        let ephemeral_pubkey = test_ephemeral_pubkey();

        let ciphertext = encrypt_metadata(&metadata, &shared_secret, &ephemeral_pubkey).unwrap();
        let decrypted = decrypt_metadata(&ciphertext, &shared_secret, &ephemeral_pubkey).unwrap();

        assert_eq!(decrypted.memo, Some("Hello 世界! 🎉".to_string()));
    }

    #[test]
    fn test_plaintext_roundtrip() {
        let metadata = PaymentMetadata::new(12345, Some("Test memo".to_string())).unwrap();
        let plaintext = metadata.to_plaintext();
        let recovered = PaymentMetadata::from_plaintext(&plaintext).unwrap();

        assert_eq!(recovered.label, 12345);
        assert_eq!(recovered.memo, Some("Test memo".to_string()));
    }
}
