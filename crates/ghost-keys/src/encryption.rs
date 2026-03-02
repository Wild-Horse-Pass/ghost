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

//! L2 note encryption using ECIES (Elliptic Curve Integrated Encryption Scheme)
//!
//! Provides end-to-end encryption for L2 note data using ephemeral ECDH key agreement
//! with ChaCha20-Poly1305 AEAD. Only the note recipient can decrypt the encrypted data.
//!
//! # Protocol
//!
//! **Encrypt:**
//! 1. Generate ephemeral secp256k1 keypair
//! 2. ECDH: `shared_point = ephemeral_secret * recipient_pubkey`
//! 3. KDF: HKDF-SHA256 with info `"ghost/note-encryption/v1"` derives 32-byte key
//! 4. Generate random 12-byte nonce
//! 5. Encrypt with ChaCha20-Poly1305 (produces ciphertext + 16-byte auth tag)
//! 6. Output: `ephemeral_pubkey (33) || nonce (12) || ciphertext+tag`
//!
//! **Decrypt:**
//! 1. Parse ephemeral_pubkey (33 bytes), nonce (12 bytes), ciphertext+tag (remainder)
//! 2. ECDH: `shared_point = secret_key * ephemeral_pubkey`
//! 3. KDF: same HKDF derivation
//! 4. Decrypt and authenticate with ChaCha20-Poly1305
//!
//! # Security Properties
//!
//! - Fresh ephemeral keypair per encryption ensures unique shared secrets
//! - HKDF domain separation prevents cross-protocol key confusion
//! - ChaCha20-Poly1305 provides authenticated encryption (integrity + confidentiality)
//! - Ephemeral secret key is zeroized after use
//! - Derived symmetric key is zeroized after use

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use secp256k1::{ecdh::SharedSecret, PublicKey, Secp256k1, SecretKey};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::GhostKeyError;

/// Size of a compressed secp256k1 public key
const COMPRESSED_PUBKEY_SIZE: usize = 33;

/// Size of a ChaCha20-Poly1305 nonce
const NONCE_SIZE: usize = 12;

/// Minimum ciphertext size: pubkey (33) + nonce (12) + tag (16) + at least 1 byte plaintext
const MIN_ENCRYPTED_SIZE: usize = COMPRESSED_PUBKEY_SIZE + NONCE_SIZE + 16 + 1;

/// HKDF info string for note encryption key derivation
const HKDF_NOTE_INFO: &[u8] = b"ghost/note-encryption/v1";

/// Derive a 32-byte ChaCha20 key from an ECDH shared secret using HKDF-SHA256.
///
/// Uses the compressed ephemeral public key as HKDF salt for per-message uniqueness.
fn derive_note_key(
    shared_secret: &[u8],
    ephemeral_pubkey_bytes: &[u8],
) -> Result<Zeroizing<[u8; 32]>, GhostKeyError> {
    let hk = Hkdf::<Sha256>::new(Some(ephemeral_pubkey_bytes), shared_secret);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_NOTE_INFO, &mut *key).map_err(|_| {
        GhostKeyError::CryptoError(
            "HKDF note key derivation failed: invalid output length".to_string(),
        )
    })?;
    Ok(key)
}

/// Encrypt note data for a specific recipient.
///
/// Generates an ephemeral secp256k1 keypair, performs ECDH with the recipient's public key,
/// derives a symmetric key via HKDF-SHA256, and encrypts using ChaCha20-Poly1305.
///
/// # Output Format
///
/// ```text
/// [ephemeral_pubkey: 33 bytes] [nonce: 12 bytes] [ciphertext + poly1305 tag]
/// ```
///
/// Total overhead: 33 (pubkey) + 12 (nonce) + 16 (auth tag) = 61 bytes
///
/// # Arguments
///
/// * `recipient_pubkey` - The recipient's secp256k1 public key
/// * `note_data` - Arbitrary plaintext note data to encrypt
///
/// # Errors
///
/// Returns `GhostKeyError::CryptoError` if key derivation or encryption fails.
pub fn encrypt_note_data(
    recipient_pubkey: &PublicKey,
    note_data: &[u8],
) -> Result<Vec<u8>, GhostKeyError> {
    if note_data.is_empty() {
        return Err(GhostKeyError::CryptoError(
            "Cannot encrypt empty note data".to_string(),
        ));
    }

    let secp = Secp256k1::new();

    // Generate ephemeral keypair (fresh per encryption)
    let (ephemeral_secret, ephemeral_pubkey) = secp.generate_keypair(&mut OsRng);

    // ECDH: shared_point = ephemeral_secret * recipient_pubkey
    let shared = SharedSecret::new(recipient_pubkey, &ephemeral_secret);

    // Zeroize ephemeral secret key immediately after ECDH
    // SecretKey is Copy so we shadow with a zeroized version to prevent further use
    let mut ephemeral_secret_bytes = ephemeral_secret.secret_bytes();

    // Derive symmetric key via HKDF
    let ephemeral_pubkey_bytes = ephemeral_pubkey.serialize(); // 33-byte compressed
    let key = derive_note_key(shared.as_ref(), &ephemeral_pubkey_bytes)?;

    // Zeroize ephemeral secret bytes now that ECDH is done
    ephemeral_secret_bytes.zeroize();

    // Generate random 12-byte nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| {
        GhostKeyError::CryptoError(format!("Failed to generate random nonce: {}", e))
    })?;

    // Encrypt with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(&*key)
        .map_err(|e| GhostKeyError::CryptoError(format!("Failed to create cipher: {}", e)))?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, note_data)
        .map_err(|e| GhostKeyError::CryptoError(format!("Note encryption failed: {}", e)))?;

    // Assemble output: ephemeral_pubkey (33) || nonce (12) || ciphertext+tag
    let mut output = Vec::with_capacity(COMPRESSED_PUBKEY_SIZE + NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&ephemeral_pubkey_bytes);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypt note data using the recipient's secret key.
///
/// Parses the ephemeral public key and nonce from the ciphertext header, performs ECDH
/// with the recipient's secret key, derives the symmetric key, and decrypts.
///
/// # Input Format
///
/// ```text
/// [ephemeral_pubkey: 33 bytes] [nonce: 12 bytes] [ciphertext + poly1305 tag]
/// ```
///
/// # Arguments
///
/// * `secret_key` - The recipient's secp256k1 secret key
/// * `encrypted` - The full encrypted payload (pubkey || nonce || ciphertext+tag)
///
/// # Errors
///
/// Returns `GhostKeyError::DecryptionFailed` if the input is too short, the embedded
/// public key is invalid, or authentication/decryption fails (wrong key or tampered data).
pub fn decrypt_note_data(
    secret_key: &SecretKey,
    encrypted: &[u8],
) -> Result<Vec<u8>, GhostKeyError> {
    // Validate minimum size: pubkey(33) + nonce(12) + tag(16) + at least 1 byte
    if encrypted.len() < MIN_ENCRYPTED_SIZE {
        return Err(GhostKeyError::DecryptionFailed(format!(
            "Encrypted data too short: {} bytes (minimum {})",
            encrypted.len(),
            MIN_ENCRYPTED_SIZE
        )));
    }

    // Parse components
    let ephemeral_pubkey_bytes = &encrypted[..COMPRESSED_PUBKEY_SIZE];
    let nonce_bytes = &encrypted[COMPRESSED_PUBKEY_SIZE..COMPRESSED_PUBKEY_SIZE + NONCE_SIZE];
    let ciphertext = &encrypted[COMPRESSED_PUBKEY_SIZE + NONCE_SIZE..];

    // Deserialize ephemeral public key
    let ephemeral_pubkey = PublicKey::from_slice(ephemeral_pubkey_bytes).map_err(|e| {
        GhostKeyError::DecryptionFailed(format!("Invalid ephemeral public key: {}", e))
    })?;

    // ECDH: shared_point = secret_key * ephemeral_pubkey
    let shared = SharedSecret::new(&ephemeral_pubkey, secret_key);

    // Derive symmetric key via HKDF (same derivation as encrypt)
    let key = derive_note_key(shared.as_ref(), ephemeral_pubkey_bytes)?;

    // Decrypt with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(&*key)
        .map_err(|e| GhostKeyError::CryptoError(format!("Failed to create cipher: {}", e)))?;

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
        GhostKeyError::DecryptionFailed(
            "Authentication failed: wrong key or tampered ciphertext".to_string(),
        )
    })?;

    Ok(plaintext)
}

/// Structured note data for L2 encrypted transfers.
///
/// Contains the private information a recipient needs to discover and spend a note:
/// value, blinding factor, and tree index. Serialized as a fixed 48-byte plaintext
/// before ECIES encryption.
///
/// # Plaintext Format (48 bytes)
///
/// ```text
/// [value: u64 LE (8)] [blinding: [u8; 32] (32)] [note_index: u64 LE (8)]
/// ```
///
/// # Encrypted Format (~109 bytes)
///
/// ```text
/// [ephemeral_pubkey: 33] [nonce: 12] [ciphertext+tag: 48+16]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteData {
    /// Note value in satoshis
    pub value: u64,
    /// Blinding factor for Pedersen commitment
    pub blinding: [u8; 32],
    /// Index in the commitment tree
    pub note_index: u64,
}

/// Size of serialized NoteData plaintext
const NOTE_DATA_SIZE: usize = 8 + 32 + 8; // 48 bytes

impl NoteData {
    /// Serialize to fixed 48-byte plaintext.
    pub fn to_bytes(&self) -> [u8; NOTE_DATA_SIZE] {
        let mut buf = [0u8; NOTE_DATA_SIZE];
        buf[0..8].copy_from_slice(&self.value.to_le_bytes());
        buf[8..40].copy_from_slice(&self.blinding);
        buf[40..48].copy_from_slice(&self.note_index.to_le_bytes());
        buf
    }

    /// Deserialize from 48-byte plaintext.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GhostKeyError> {
        if bytes.len() != NOTE_DATA_SIZE {
            return Err(GhostKeyError::CryptoError(format!(
                "NoteData must be {} bytes, got {}",
                NOTE_DATA_SIZE,
                bytes.len()
            )));
        }
        let value = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let mut blinding = [0u8; 32];
        blinding.copy_from_slice(&bytes[8..40]);
        let note_index = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
        Ok(Self {
            value,
            blinding,
            note_index,
        })
    }

    /// Encrypt this note data for a recipient's public key.
    pub fn encrypt(&self, recipient_pubkey: &PublicKey) -> Result<Vec<u8>, GhostKeyError> {
        encrypt_note_data(recipient_pubkey, &self.to_bytes())
    }

    /// Decrypt note data using the recipient's secret key.
    pub fn decrypt(secret_key: &SecretKey, encrypted: &[u8]) -> Result<Self, GhostKeyError> {
        let bytes = decrypt_note_data(secret_key, encrypted)?;
        Self::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: generate a fresh secp256k1 keypair for testing.
    fn generate_keypair() -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        secp.generate_keypair(&mut OsRng)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (secret_key, public_key) = generate_keypair();
        let note_data = b"test note: 1000 sats to Alice";

        let encrypted = encrypt_note_data(&public_key, note_data).unwrap();

        // Verify overhead: 33 (pubkey) + 12 (nonce) + 16 (tag) = 61 bytes overhead
        assert_eq!(encrypted.len(), note_data.len() + 61);

        let decrypted = decrypt_note_data(&secret_key, &encrypted).unwrap();
        assert_eq!(decrypted, note_data);
    }

    #[test]
    fn test_encrypt_decrypt_large_payload() {
        let (secret_key, public_key) = generate_keypair();
        let note_data = vec![0xAB; 4096]; // 4KB payload

        let encrypted = encrypt_note_data(&public_key, &note_data).unwrap();
        let decrypted = decrypt_note_data(&secret_key, &encrypted).unwrap();
        assert_eq!(decrypted, note_data);
    }

    #[test]
    fn test_encrypt_decrypt_single_byte() {
        let (secret_key, public_key) = generate_keypair();
        let note_data = &[0xFF];

        let encrypted = encrypt_note_data(&public_key, note_data).unwrap();
        let decrypted = decrypt_note_data(&secret_key, &encrypted).unwrap();
        assert_eq!(decrypted, note_data);
    }

    #[test]
    fn test_empty_plaintext_rejected() {
        let (_, public_key) = generate_keypair();
        let result = encrypt_note_data(&public_key, b"");
        assert!(result.is_err());
        match result.unwrap_err() {
            GhostKeyError::CryptoError(msg) => {
                assert!(msg.contains("empty"), "Expected empty error, got: {}", msg);
            }
            other => panic!("Expected CryptoError, got: {:?}", other),
        }
    }

    #[test]
    fn test_wrong_key_fails_to_decrypt() {
        let (_, recipient_pubkey) = generate_keypair();
        let (wrong_secret_key, _) = generate_keypair();

        let note_data = b"secret note data";
        let encrypted = encrypt_note_data(&recipient_pubkey, note_data).unwrap();

        // Decrypting with wrong key must fail
        let result = decrypt_note_data(&wrong_secret_key, &encrypted);
        assert!(result.is_err());
        match result.unwrap_err() {
            GhostKeyError::DecryptionFailed(msg) => {
                assert!(
                    msg.contains("Authentication failed"),
                    "Expected auth failure, got: {}",
                    msg
                );
            }
            other => panic!("Expected DecryptionFailed, got: {:?}", other),
        }
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (secret_key, public_key) = generate_keypair();
        let note_data = b"integrity-protected note";

        let mut encrypted = encrypt_note_data(&public_key, note_data).unwrap();

        // Tamper with the ciphertext portion (after pubkey + nonce header)
        let tamper_idx = COMPRESSED_PUBKEY_SIZE + NONCE_SIZE + 1;
        encrypted[tamper_idx] ^= 0xFF;

        let result = decrypt_note_data(&secret_key, &encrypted);
        assert!(result.is_err());
        match result.unwrap_err() {
            GhostKeyError::DecryptionFailed(_) => {} // Expected
            other => panic!("Expected DecryptionFailed, got: {:?}", other),
        }
    }

    #[test]
    fn test_tampered_nonce_fails() {
        let (secret_key, public_key) = generate_keypair();
        let note_data = b"nonce-sensitive data";

        let mut encrypted = encrypt_note_data(&public_key, note_data).unwrap();

        // Tamper with the nonce (bytes 33..45)
        encrypted[COMPRESSED_PUBKEY_SIZE] ^= 0x01;

        let result = decrypt_note_data(&secret_key, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ephemeral_pubkey_fails() {
        let (secret_key, public_key) = generate_keypair();
        let note_data = b"pubkey-bound data";

        let mut encrypted = encrypt_note_data(&public_key, note_data).unwrap();

        // Tamper with the ephemeral pubkey (first 33 bytes)
        // Flipping a bit will either produce an invalid point or a different shared secret
        encrypted[1] ^= 0x01;

        let result = decrypt_note_data(&secret_key, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_input_rejected() {
        let (secret_key, _) = generate_keypair();

        // Too short to contain pubkey + nonce + tag + 1 byte
        let short_data = vec![0u8; MIN_ENCRYPTED_SIZE - 1];
        let result = decrypt_note_data(&secret_key, &short_data);
        assert!(result.is_err());
        match result.unwrap_err() {
            GhostKeyError::DecryptionFailed(msg) => {
                assert!(
                    msg.contains("too short"),
                    "Expected too-short error, got: {}",
                    msg
                );
            }
            other => panic!("Expected DecryptionFailed, got: {:?}", other),
        }
    }

    #[test]
    fn test_each_encryption_produces_unique_ciphertext() {
        let (_, public_key) = generate_keypair();
        let note_data = b"same plaintext every time";

        let encrypted1 = encrypt_note_data(&public_key, note_data).unwrap();
        let encrypted2 = encrypt_note_data(&public_key, note_data).unwrap();

        // Different ephemeral keys + different nonces = different ciphertext
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_note_data_roundtrip() {
        let data = NoteData {
            value: 100_000,
            blinding: [0xAB; 32],
            note_index: 42,
        };
        let bytes = data.to_bytes();
        assert_eq!(bytes.len(), 48);
        let restored = NoteData::from_bytes(&bytes).unwrap();
        assert_eq!(data, restored);
    }

    #[test]
    fn test_note_data_encrypt_decrypt() {
        let (secret_key, public_key) = generate_keypair();
        let data = NoteData {
            value: 500_000,
            blinding: [0x42; 32],
            note_index: 7,
        };

        let encrypted = data.encrypt(&public_key).unwrap();
        // 48-byte plaintext + 61-byte overhead = 109 bytes
        assert_eq!(encrypted.len(), 109);

        let decrypted = NoteData::decrypt(&secret_key, &encrypted).unwrap();
        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_note_data_wrong_key_fails() {
        let (_, public_key) = generate_keypair();
        let (wrong_key, _) = generate_keypair();
        let data = NoteData {
            value: 1000,
            blinding: [1u8; 32],
            note_index: 0,
        };

        let encrypted = data.encrypt(&public_key).unwrap();
        let result = NoteData::decrypt(&wrong_key, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_note_data_invalid_length() {
        let result = NoteData::from_bytes(&[0u8; 47]);
        assert!(result.is_err());
        let result = NoteData::from_bytes(&[0u8; 49]);
        assert!(result.is_err());
    }

    #[test]
    fn test_output_format_structure() {
        let (_, public_key) = generate_keypair();
        let note_data = b"format check";

        let encrypted = encrypt_note_data(&public_key, note_data).unwrap();

        // First byte should be 0x02 or 0x03 (compressed pubkey prefix)
        assert!(
            encrypted[0] == 0x02 || encrypted[0] == 0x03,
            "First byte should be compressed pubkey prefix, got: 0x{:02x}",
            encrypted[0]
        );

        // Embedded pubkey should be valid
        let pubkey_result = PublicKey::from_slice(&encrypted[..COMPRESSED_PUBKEY_SIZE]);
        assert!(
            pubkey_result.is_ok(),
            "Embedded ephemeral pubkey should be valid"
        );
    }
}
