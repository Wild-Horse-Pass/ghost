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
//| FILE: payout_commitment.rs                                                                                           |
//|======================================================================================================================|

//! Cryptographic Payout Commitment
//!
//! Provides HMAC-based commitment for payout addresses to prevent
//! address manipulation attacks. Each commitment binds:
//! - The payout address
//! - A timestamp
//! - The pool's signing secret
//!
//! This ensures that a miner's payout address cannot be changed after
//! authorization without detection.

use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// HMAC-SHA256 implementation for payout commitments
/// Uses the pool's signing key as the secret
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    const OPAD: u8 = 0x5c;
    const IPAD: u8 = 0x36;

    // If key is longer than block size, hash it
    let key_bytes: Vec<u8> = if key.len() > BLOCK_SIZE {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.finalize().to_vec()
    } else {
        key.to_vec()
    };

    // Pad key to block size
    let mut padded_key = [0u8; BLOCK_SIZE];
    padded_key[..key_bytes.len()].copy_from_slice(&key_bytes);

    // Create inner and outer padded keys
    let mut o_key_pad = [0u8; BLOCK_SIZE];
    let mut i_key_pad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        o_key_pad[i] = padded_key[i] ^ OPAD;
        i_key_pad[i] = padded_key[i] ^ IPAD;
    }

    // Inner hash: H(i_key_pad || message)
    let mut inner_hasher = Sha256::new();
    inner_hasher.update(&i_key_pad);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    // Outer hash: H(o_key_pad || inner_hash)
    let mut outer_hasher = Sha256::new();
    outer_hasher.update(&o_key_pad);
    outer_hasher.update(&inner_hash);

    let result = outer_hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut result = 0u8;
    for i in 0..32 {
        result |= a[i] ^ b[i];
    }
    result == 0
}

/// Cryptographic commitment to a payout address
///
/// Binds the payout address to the pool's secret key via HMAC,
/// making it impossible to forge or modify addresses without detection.
#[derive(Debug, Clone)]
pub struct PayoutCommitment {
    /// The committed payout address (as script pubkey bytes)
    pub address: Vec<u8>,
    /// Timestamp when the commitment was created
    pub timestamp: u64,
    /// HMAC-SHA256 signature binding address + timestamp to pool secret
    pub signature: [u8; 32],
}

impl PayoutCommitment {
    /// Create a new commitment signed with the pool's secret
    ///
    /// # Arguments
    /// * `address` - Bitcoin script pubkey bytes for the payout address
    /// * `pool_secret` - The pool's secret key (at least 32 bytes recommended)
    pub fn new(address: Vec<u8>, pool_secret: &[u8]) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let signature = Self::compute_signature(&address, timestamp, pool_secret);

        Self {
            address,
            timestamp,
            signature,
        }
    }

    /// Create a commitment with a specific timestamp (for restoration)
    pub fn with_timestamp(address: Vec<u8>, timestamp: u64, pool_secret: &[u8]) -> Self {
        let signature = Self::compute_signature(&address, timestamp, pool_secret);

        Self {
            address,
            timestamp,
            signature,
        }
    }

    /// Restore a commitment from stored values (for database)
    pub fn restore(address: Vec<u8>, timestamp: u64, signature: [u8; 32]) -> Self {
        Self {
            address,
            timestamp,
            signature,
        }
    }

    /// Compute the HMAC signature
    fn compute_signature(address: &[u8], timestamp: u64, pool_secret: &[u8]) -> [u8; 32] {
        // Build message: address || timestamp
        let mut message = Vec::with_capacity(address.len() + 8);
        message.extend_from_slice(address);
        message.extend_from_slice(&timestamp.to_le_bytes());

        hmac_sha256(pool_secret, &message)
    }

    /// Verify the commitment is valid against the pool's secret
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    pub fn verify(&self, pool_secret: &[u8]) -> bool {
        let expected = Self::compute_signature(&self.address, self.timestamp, pool_secret);
        constant_time_eq(&self.signature, &expected)
    }

    /// Verify the commitment and check that it's not too old
    ///
    /// # Arguments
    /// * `pool_secret` - The pool's secret key
    /// * `max_age_secs` - Maximum age in seconds (0 = no age check)
    pub fn verify_with_age(&self, pool_secret: &[u8], max_age_secs: u64) -> bool {
        // First verify the signature
        if !self.verify(pool_secret) {
            return false;
        }

        // Check age if max_age_secs is non-zero
        if max_age_secs > 0 {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            if now > self.timestamp && now - self.timestamp > max_age_secs {
                return false;
            }
        }

        true
    }

    /// Get the address as hex string
    pub fn address_hex(&self) -> String {
        hex::encode(&self.address)
    }

    /// Get the signature as hex string
    pub fn signature_hex(&self) -> String {
        hex::encode(self.signature)
    }

    /// Create from hex strings (for database restoration)
    pub fn from_hex(address_hex: &str, timestamp: u64, signature_hex: &str) -> Option<Self> {
        let address = hex::decode(address_hex).ok()?;
        let sig_bytes = hex::decode(signature_hex).ok()?;
        if sig_bytes.len() != 32 {
            return None;
        }
        let mut signature = [0u8; 32];
        signature.copy_from_slice(&sig_bytes);

        Some(Self {
            address,
            timestamp,
            signature,
        })
    }
}

/// Miner authorization with cryptographic commitment
///
/// Extended miner info that includes a verified payout commitment.
#[derive(Debug, Clone)]
pub struct AuthorizedMiner {
    /// Unique miner identifier
    pub miner_id: String,
    /// Worker name (optional)
    pub worker_name: Option<String>,
    /// Committed payout address
    pub payout_commitment: PayoutCommitment,
    /// When the miner was authorized
    pub authorized_at: u64,
}

impl AuthorizedMiner {
    /// Create a new authorized miner with payout commitment
    pub fn new(
        miner_id: String,
        worker_name: Option<String>,
        payout_address: Vec<u8>,
        pool_secret: &[u8],
    ) -> Self {
        let authorized_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            miner_id,
            worker_name,
            payout_commitment: PayoutCommitment::new(payout_address, pool_secret),
            authorized_at,
        }
    }

    /// Verify the miner's payout commitment is valid
    pub fn verify_commitment(&self, pool_secret: &[u8]) -> bool {
        self.payout_commitment.verify(pool_secret)
    }

    /// Get the committed payout address
    pub fn payout_address(&self) -> &[u8] {
        &self.payout_commitment.address
    }
}

/// Commitment manager for a pool
///
/// Manages the pool secret and provides commitment operations.
#[derive(Debug)]
pub struct CommitmentManager {
    /// The pool's signing secret (should be cryptographically random)
    pool_secret: [u8; 32],
}

impl CommitmentManager {
    /// Create a new commitment manager with the given secret
    pub fn new(pool_secret: [u8; 32]) -> Self {
        Self { pool_secret }
    }

    /// Create from hex string
    pub fn from_hex(secret_hex: &str) -> Option<Self> {
        let bytes = hex::decode(secret_hex).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes);
        Some(Self { pool_secret: secret })
    }

    /// Generate a new random pool secret
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).expect("Failed to generate random secret");
        Self { pool_secret: secret }
    }

    /// Create a commitment for a payout address
    pub fn commit(&self, address: Vec<u8>) -> PayoutCommitment {
        PayoutCommitment::new(address, &self.pool_secret)
    }

    /// Verify a commitment
    pub fn verify(&self, commitment: &PayoutCommitment) -> bool {
        commitment.verify(&self.pool_secret)
    }

    /// Verify with age check
    pub fn verify_with_age(&self, commitment: &PayoutCommitment, max_age_secs: u64) -> bool {
        commitment.verify_with_age(&self.pool_secret, max_age_secs)
    }

    /// Create an authorized miner
    pub fn authorize_miner(
        &self,
        miner_id: String,
        worker_name: Option<String>,
        payout_address: Vec<u8>,
    ) -> AuthorizedMiner {
        AuthorizedMiner::new(miner_id, worker_name, payout_address, &self.pool_secret)
    }

    /// Get the secret as hex (for secure storage)
    pub fn secret_hex(&self) -> String {
        hex::encode(self.pool_secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> [u8; 32] {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        ]
    }

    fn test_address() -> Vec<u8> {
        // P2WPKH script: OP_0 <20 bytes>
        let mut addr = vec![0x00, 0x14];
        addr.extend_from_slice(&[0xab; 20]);
        addr
    }

    #[test]
    fn test_commitment_creation() {
        let secret = test_secret();
        let address = test_address();

        let commitment = PayoutCommitment::new(address.clone(), &secret);

        assert_eq!(commitment.address, address);
        assert!(commitment.timestamp > 0);
        assert!(commitment.signature != [0u8; 32]);
    }

    #[test]
    fn test_commitment_verification() {
        let secret = test_secret();
        let address = test_address();

        let commitment = PayoutCommitment::new(address, &secret);

        // Should verify with correct secret
        assert!(commitment.verify(&secret));

        // Should fail with wrong secret
        let wrong_secret = [0xff; 32];
        assert!(!commitment.verify(&wrong_secret));
    }

    #[test]
    fn test_commitment_tamper_detection() {
        let secret = test_secret();
        let address = test_address();

        let mut commitment = PayoutCommitment::new(address, &secret);

        // Original should verify
        assert!(commitment.verify(&secret));

        // Tamper with address
        commitment.address[5] ^= 0xff;

        // Tampered should not verify
        assert!(!commitment.verify(&secret));
    }

    #[test]
    fn test_commitment_timestamp_tamper() {
        let secret = test_secret();
        let address = test_address();

        let mut commitment = PayoutCommitment::new(address, &secret);

        // Original should verify
        assert!(commitment.verify(&secret));

        // Tamper with timestamp
        commitment.timestamp += 1;

        // Tampered should not verify
        assert!(!commitment.verify(&secret));
    }

    #[test]
    fn test_commitment_hex_roundtrip() {
        let secret = test_secret();
        let address = test_address();

        let commitment = PayoutCommitment::new(address.clone(), &secret);
        let addr_hex = commitment.address_hex();
        let sig_hex = commitment.signature_hex();

        let restored = PayoutCommitment::from_hex(&addr_hex, commitment.timestamp, &sig_hex)
            .expect("Should restore from hex");

        assert_eq!(restored.address, commitment.address);
        assert_eq!(restored.timestamp, commitment.timestamp);
        assert_eq!(restored.signature, commitment.signature);
        assert!(restored.verify(&secret));
    }

    #[test]
    fn test_commitment_manager() {
        let manager = CommitmentManager::new(test_secret());
        let address = test_address();

        let commitment = manager.commit(address.clone());

        assert!(manager.verify(&commitment));
    }

    #[test]
    fn test_commitment_manager_generate() {
        let manager = CommitmentManager::generate();
        let address = test_address();

        let commitment = manager.commit(address);

        assert!(manager.verify(&commitment));
    }

    #[test]
    fn test_commitment_manager_from_hex() {
        let secret = test_secret();
        let hex = hex::encode(secret);

        let manager = CommitmentManager::from_hex(&hex).expect("Should parse hex");
        let address = test_address();

        let commitment = manager.commit(address);
        assert!(manager.verify(&commitment));

        // Should match direct verification
        assert!(commitment.verify(&secret));
    }

    #[test]
    fn test_authorized_miner() {
        let manager = CommitmentManager::new(test_secret());
        let address = test_address();

        let miner = manager.authorize_miner(
            "bc1qtest.worker1".to_string(),
            Some("worker1".to_string()),
            address.clone(),
        );

        assert_eq!(miner.miner_id, "bc1qtest.worker1");
        assert_eq!(miner.worker_name, Some("worker1".to_string()));
        assert_eq!(miner.payout_address(), address.as_slice());
        assert!(miner.verify_commitment(&test_secret()));
    }

    #[test]
    fn test_hmac_known_vector() {
        // Test vector for HMAC-SHA256
        let key = b"key";
        let message = b"The quick brown fox jumps over the lazy dog";

        let hmac = hmac_sha256(key, message);
        let hex = hex::encode(hmac);

        // Known correct HMAC-SHA256 for this input
        assert_eq!(
            hex,
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8; 32];
        let b = [1u8; 32];
        let c = [2u8; 32];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }

    #[test]
    fn test_commitment_age_verification() {
        let secret = test_secret();
        let address = test_address();

        // Create commitment with current timestamp
        let commitment = PayoutCommitment::new(address.clone(), &secret);

        // Should pass with large max age
        assert!(commitment.verify_with_age(&secret, 3600));

        // Should pass with zero max age (no age check)
        assert!(commitment.verify_with_age(&secret, 0));

        // Create old commitment
        let old_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(7200); // 2 hours ago

        let old_commitment = PayoutCommitment::with_timestamp(address, old_timestamp, &secret);

        // Signature should still verify
        assert!(old_commitment.verify(&secret));

        // But age check should fail with 1 hour max
        assert!(!old_commitment.verify_with_age(&secret, 3600));

        // And pass with 3 hour max
        assert!(old_commitment.verify_with_age(&secret, 10800));
    }
}
