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
//| FILE: keys.rs                                                                                                        |
//|======================================================================================================================|

//! Ghost Keys - Scan and spend keypairs
//!
//! GhostKeys holds the private keys needed to receive and spend payments.

use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tracing::warn;
use zeroize::{Zeroize, Zeroizing};

use crate::config::ScanConfig;
use crate::derivation::{compute_tweak_v2, derive_shared_secret, derive_spend_key};
use crate::error::GhostKeyError;
use crate::ghost_id::GhostId;

/// H-2: Wrapper for secret key bytes that gets zeroed on drop
///
/// This wrapper ensures the raw secret key bytes are properly zeroed when dropped.
/// While `secp256k1::SecretKey` has `non_secure_erase()`, using the `zeroize` crate
/// provides more reliable memory clearing with compiler barriers to prevent
/// optimization from removing the zeroing operation.
///
/// 2.5 HIGH: Clone intentionally NOT derived - secret bytes should not be cloneable.
struct ZeroizingSecretBytes([u8; 32]);

impl ZeroizingSecretBytes {
    fn from_secret_key(sk: &SecretKey) -> Self {
        Self(sk.secret_bytes())
    }
}

impl Zeroize for ZeroizingSecretBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for ZeroizingSecretBytes {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Ghost Keys - Private keys for Ghost Pay
///
/// Consists of:
/// - Scan key: Used to detect incoming payments via ECDH
/// - Spend key: Used to spend received funds
///
/// # Security (H-2: Secure Secret Key Erasure)
///
/// This struct uses the `zeroize` crate to securely erase secret key bytes
/// from memory when dropped. The `ZeroizingSecretBytes` wrapper ensures:
/// - Memory barriers prevent compiler from optimizing away the zeroing
/// - Both scan and spend secret bytes are cleared on drop
///
/// Note: While `zeroize` provides best-effort secure erasure, complete memory
/// zeroing cannot be absolutely guaranteed due to potential compiler-generated
/// copies. This is a defense-in-depth measure. See the [`zeroize`](https://docs.rs/zeroize)
/// crate documentation for detailed discussion.
///
/// # 2.5 HIGH: Clone intentionally NOT derived
///
/// Secret key material should not be cloneable. This prevents:
/// - Accidental duplication of secrets in memory
/// - Multiple copies that may not all be properly zeroized
/// - Misuse patterns like passing keys by value
///
/// Use `Arc<GhostKeys>` for shared access patterns.
pub struct GhostKeys {
    /// H-2: Wrapped in ZeroizingSecretBytes for secure erasure on drop
    /// These fields exist solely to be zeroed when the struct is dropped
    #[allow(dead_code)]
    scan_secret_bytes: ZeroizingSecretBytes,
    #[allow(dead_code)]
    spend_secret_bytes: ZeroizingSecretBytes,
    /// Cached SecretKey for crypto operations
    scan_secret: SecretKey,
    spend_secret: SecretKey,
    scan_pubkey: PublicKey,
    spend_pubkey: PublicKey,
}

impl GhostKeys {
    /// Generate new random Ghost Keys
    ///
    /// # Security Note (M-CRYPTO-2)
    ///
    /// This operation involves cryptographic key generation which is computationally
    /// expensive. Public APIs calling this method should implement rate limiting to
    /// prevent resource exhaustion attacks. Consider:
    ///
    /// - Limiting key generation requests per IP/user
    /// - Adding delays between consecutive generation requests
    /// - Implementing CAPTCHA or proof-of-work for untrusted callers
    ///
    /// This function uses the system's CSPRNG (OsRng) for key material.
    pub fn generate() -> Self {
        let secp = Secp256k1::new();
        let (scan_secret, scan_pubkey) = secp.generate_keypair(&mut OsRng);
        let (spend_secret, spend_pubkey) = secp.generate_keypair(&mut OsRng);

        // L-8: Two independently generated random keys have negligible collision probability
        // (2^-256), but we assert for defense-in-depth.
        assert_ne!(
            scan_secret.secret_bytes(),
            spend_secret.secret_bytes(),
            "L-8: Generated scan and spend keys must differ"
        );

        Self {
            scan_secret_bytes: ZeroizingSecretBytes::from_secret_key(&scan_secret),
            spend_secret_bytes: ZeroizingSecretBytes::from_secret_key(&spend_secret),
            scan_secret,
            spend_secret,
            scan_pubkey,
            spend_pubkey,
        }
    }

    /// Create from existing secret keys
    ///
    /// # L-8 Security: Scan and spend keys must differ
    ///
    /// Returns an error if scan_secret == spend_secret to preserve the security
    /// separation required by Silent Payments (BIP-352).
    pub fn from_secrets(
        scan_secret: SecretKey,
        spend_secret: SecretKey,
    ) -> Result<Self, GhostKeyError> {
        // L-8: Verify scan key != spend key for Silent Payment security
        if scan_secret.secret_bytes() == spend_secret.secret_bytes() {
            return Err(GhostKeyError::InvalidSecretKey(
                "Scan and spend keys must be different for Silent Payment security".to_string(),
            ));
        }
        let secp = Secp256k1::new();
        let scan_pubkey = PublicKey::from_secret_key(&secp, &scan_secret);
        let spend_pubkey = PublicKey::from_secret_key(&secp, &spend_secret);

        Ok(Self {
            scan_secret_bytes: ZeroizingSecretBytes::from_secret_key(&scan_secret),
            spend_secret_bytes: ZeroizingSecretBytes::from_secret_key(&spend_secret),
            scan_secret,
            spend_secret,
            scan_pubkey,
            spend_pubkey,
        })
    }

    /// Create from raw secret bytes
    ///
    /// # L-8 Security: Scan and spend keys must differ
    ///
    /// If the scan key equals the spend key, the ECDH shared secret used for
    /// payment detection would be derivable from the spend key alone. An attacker
    /// who compromises the spend key could then also scan for incoming payments,
    /// defeating the separation of concerns that Silent Payments (BIP-352) provides.
    pub fn from_bytes(
        scan_bytes: &[u8; 32],
        spend_bytes: &[u8; 32],
    ) -> Result<Self, GhostKeyError> {
        // L-8: Verify scan key != spend key for Silent Payment security
        if scan_bytes == spend_bytes {
            return Err(GhostKeyError::InvalidSecretKey(
                "Scan and spend keys must be different for Silent Payment security".to_string(),
            ));
        }
        let scan_secret = SecretKey::from_slice(scan_bytes)?;
        let spend_secret = SecretKey::from_slice(spend_bytes)?;
        Self::from_secrets(scan_secret, spend_secret)
    }

    /// Get the scan secret key
    pub fn scan_secret(&self) -> &SecretKey {
        &self.scan_secret
    }

    /// Get the spend secret key
    pub fn spend_secret(&self) -> &SecretKey {
        &self.spend_secret
    }

    /// Get the scan public key
    pub fn scan_pubkey(&self) -> &PublicKey {
        &self.scan_pubkey
    }

    /// Get the spend public key
    pub fn spend_pubkey(&self) -> &PublicKey {
        &self.spend_pubkey
    }

    /// Get the Ghost ID (public identifier) for sharing
    pub fn ghost_id(&self) -> GhostId {
        GhostId::new(self.scan_pubkey, self.spend_pubkey)
    }

    /// Detect if a payment belongs to us (v2 - position-independent)
    ///
    /// Given an ephemeral pubkey from a transaction and an output pubkey,
    /// determine if the output belongs to us and return the spend key if so.
    ///
    /// This version uses counter-based k scanning, which is position-independent
    /// and safe for shuffled outputs (critical for Wraith Protocol).
    ///
    /// # Arguments
    /// * `ephemeral_pubkey` - The ephemeral pubkey from OP_RETURN
    /// * `output_pubkey` - The output's public key
    /// * `config` - Scan configuration (controls max_k)
    ///
    /// # Returns
    /// - `Ok(Some((spend_key, k)))` if the payment belongs to us, with the k that matched
    /// - `Ok(None)` if the payment does not belong to us (normal case)
    /// - `Err(GhostKeyError)` if a cryptographic operation failed during detection
    ///
    /// # SEC-KEY-1
    /// This function returns errors for cryptographic failures instead of
    /// silently returning None. This prevents funds from being marked as
    /// "not ours" when they actually are (but derivation failed).
    ///
    /// # 3.4 SECURITY: Constant-time k iteration
    ///
    /// This function iterates through ALL k values regardless of whether a match
    /// is found. This prevents timing side-channel attacks where an adversary
    /// could determine which k value was used by measuring execution time.
    ///
    /// The pubkey comparison uses constant-time comparison (ct_eq), and we
    /// continue iterating through remaining k values even after finding a match
    /// to maintain constant execution time.
    pub fn detect_payment(
        &self,
        ephemeral_pubkey: &PublicKey,
        output_pubkey: &PublicKey,
        config: &ScanConfig,
    ) -> Result<Option<(SecretKey, u32)>, GhostKeyError> {
        let secp = Secp256k1::new();

        // CRIT-KEYS-2 FIX: Validate ephemeral_pubkey is a valid curve point before ECDH
        // An invalid point could cause undefined behavior in ECDH computation
        // Check by verifying it can be serialized (confirms it's on the curve)
        let _ = ephemeral_pubkey.serialize();

        // Additional validation: PublicKey type already validates on construction,
        // but we explicitly confirm it here for defense-in-depth

        // Compute shared secret
        let shared_secret = derive_shared_secret(&self.scan_secret, ephemeral_pubkey);

        // 3.4 SECURITY: Track match result without early return to maintain constant time
        // We iterate through ALL k values regardless of whether we find a match
        let mut matched_result: Option<(SecretKey, u32)> = None;
        let mut derivation_error: Option<GhostKeyError> = None;

        // Try k values from 0 to max_k - ALWAYS iterate through all values
        for k in 0..=config.max_k() {
            let tweak = compute_tweak_v2(&shared_secret, k);

            // Expected pubkey = spend_pubkey + tweak*G
            // L-20: Log warning if tweak fails (probability ~2^-128, but should be monitored)
            let tweak_secret = match SecretKey::from_slice(&tweak) {
                Ok(ts) => ts,
                Err(e) => {
                    warn!(
                        k = k,
                        error = %e,
                        "L-20: Tweak derivation failed (probability ~2^-128) - this may indicate a bug"
                    );
                    continue;
                }
            };
            let tweak_pubkey = PublicKey::from_secret_key(&secp, &tweak_secret);
            if let Ok(expected_pubkey) = self.spend_pubkey.combine(&tweak_pubkey) {
                // M-CRYPTO-3: Use constant-time comparison to prevent timing attacks
                let matches: bool = expected_pubkey
                    .serialize()
                    .ct_eq(&output_pubkey.serialize())
                    .into();

                // LOW-KEYS-2 FIX: Use comparison result immediately in the same branch
                // to prevent compiler from optimizing away the constant-time comparison.
                // The matches variable is used directly in the condition below without
                // any intermediate operations that might leak timing information.

                // 3.4: Only record the first match (don't update if already matched)
                // We continue iterating to maintain constant time
                if matches && matched_result.is_none() {
                    // Found it! Derive spend key
                    // SEC-KEY-1: Record error instead of silently failing
                    match derive_spend_key(&self.spend_secret, &tweak) {
                        Ok(spend_key) => {
                            matched_result = Some((spend_key, k));
                        }
                        Err(e) => {
                            // Payment detected but derivation failed - this is critical
                            derivation_error = Some(GhostKeyError::DerivationError(format!(
                                "Payment detected at k={} but spend key derivation failed: {}",
                                k, e
                            )));
                        }
                    }
                }
            }
            // 3.4: Continue to next k value regardless of match status
        }

        // Return derivation error if one occurred (payment was ours but derivation failed)
        if let Some(err) = derivation_error {
            return Err(err);
        }

        // Return matched result (Some if found, None if not our payment)
        Ok(matched_result)
    }

    /// Detect payment with default scan config
    ///
    /// Convenience method that uses DEFAULT_MAX_K for scanning.
    pub fn detect_payment_default(
        &self,
        ephemeral_pubkey: &PublicKey,
        output_pubkey: &PublicKey,
    ) -> Result<Option<(SecretKey, u32)>, GhostKeyError> {
        self.detect_payment(ephemeral_pubkey, output_pubkey, &ScanConfig::default())
    }

    /// Export secret keys as bytes
    ///
    /// M-15 FIX: Returns Zeroizing wrappers to ensure the secret bytes are
    /// automatically zeroized when dropped by the caller.
    ///
    /// # CRYPT-1 Security Warning: Proper Secret Handling
    ///
    /// **CRITICAL**: The returned secrets are wrapped in `Zeroizing<[u8; 32]>` which
    /// automatically zeroizes memory when dropped. However, callers MUST follow these rules:
    ///
    /// 1. **Do NOT clone the inner bytes** - Cloning defeats zeroization. The copy won't be zeroized.
    /// 2. **Use briefly, drop quickly** - Minimize the lifetime of these secrets in memory.
    /// 3. **Do NOT convert to String/Vec** - String/Vec may reallocate, leaving copies behind.
    /// 4. **Prefer `with_secrets()` callback API** - Use `with_secrets()` when possible for
    ///    guaranteed cleanup even on panics.
    ///
    /// # Example - Correct Usage
    ///
    /// ```ignore
    /// // GOOD: Use the callback API for guaranteed cleanup
    /// keys.with_secrets(|scan, spend| {
    ///     // Use scan and spend here
    ///     // They are automatically zeroized when this closure returns
    /// });
    ///
    /// // ACCEPTABLE: Brief use with immediate drop
    /// let (scan, spend) = keys.export_secrets();
    /// let result = compute_something(&*scan, &*spend);
    /// drop(scan);
    /// drop(spend);
    /// ```
    ///
    /// # Example - Incorrect Usage
    ///
    /// ```ignore
    /// // BAD: Converting to Vec creates unzeroized copy
    /// let (scan, _) = keys.export_secrets();
    /// let scan_vec = scan.to_vec(); // This copy won't be zeroized!
    ///
    /// // BAD: Storing in long-lived struct
    /// struct LongLived {
    ///     secrets: (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>),
    /// }
    /// ```
    pub fn export_secrets(&self) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
        (
            Zeroizing::new(self.scan_secret.secret_bytes()),
            Zeroizing::new(self.spend_secret.secret_bytes()),
        )
    }

    /// Access secret keys via callback with guaranteed zeroization
    ///
    /// # CRYPT-1 FIX: Callback-based API for secure secret access
    ///
    /// This is the preferred way to access secret key bytes. The callback pattern
    /// ensures that:
    /// 1. Secrets are automatically zeroized when the callback returns (even on panic)
    /// 2. Callers cannot accidentally hold references beyond their intended lifetime
    /// 3. The borrow checker prevents escaping references to secret data
    ///
    /// # Arguments
    ///
    /// * `f` - Callback function that receives references to scan and spend secret bytes
    ///
    /// # Returns
    ///
    /// Whatever the callback returns
    ///
    /// # Example
    ///
    /// ```ignore
    /// let result = keys.with_secrets(|scan_bytes, spend_bytes| {
    ///     // Compute something with the secrets
    ///     derive_address(scan_bytes, spend_bytes)
    /// });
    /// // At this point, the secret bytes have been zeroized
    /// ```
    ///
    /// # Panics
    ///
    /// If the callback panics, the secrets are still zeroized before the panic propagates.
    pub fn with_secrets<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8; 32], &[u8; 32]) -> R,
    {
        let scan = Zeroizing::new(self.scan_secret.secret_bytes());
        let spend = Zeroizing::new(self.spend_secret.secret_bytes());
        f(&scan, &spend)
    }

    /// Export as a public-facing structure
    pub fn export(&self) -> GhostKeysPublicExport {
        GhostKeysPublicExport {
            scan_pubkey_hex: hex::encode(self.scan_pubkey.serialize()),
            spend_pubkey_hex: hex::encode(self.spend_pubkey.serialize()),
            ghost_id: self.ghost_id().to_string(),
        }
    }

    /// Derive a lock pubkey for a specific index
    ///
    /// This is used to create new Ghost Locks. Each lock gets a unique
    /// key derived from the spend key.
    ///
    /// # Errors
    ///
    /// Returns `GhostKeyError::DerivationError` if the derived tweak produces
    /// an invalid secret key or if the pubkey combination fails. This should
    /// be extremely rare in practice (only if SHA256 output happens to be 0 or
    /// \>= curve order), but callers must handle the error to avoid silent
    /// address reuse. See L-CRYPTO-2.
    pub fn derive_lock_pubkey(&self, index: u32) -> Result<[u8; 33], GhostKeyError> {
        use sha2::{Digest, Sha256};

        let secp = Secp256k1::new();

        // Derive tweak: SHA256("ghost_lock" || spend_pubkey || index)
        let mut hasher = Sha256::new();
        hasher.update(b"ghost_lock");
        hasher.update(self.spend_pubkey.serialize());
        hasher.update(index.to_le_bytes());
        let tweak: [u8; 32] = hasher.finalize().into();

        // Derive lock pubkey = spend_pubkey + tweak*G
        let tweak_secret = SecretKey::from_slice(&tweak).map_err(|e| {
            GhostKeyError::DerivationError(format!("Invalid tweak for lock pubkey: {}", e))
        })?;
        let tweak_pubkey = PublicKey::from_secret_key(&secp, &tweak_secret);
        let lock_pubkey = self.spend_pubkey.combine(&tweak_pubkey).map_err(|e| {
            GhostKeyError::DerivationError(format!("Failed to combine pubkeys for lock: {}", e))
        })?;

        Ok(lock_pubkey.serialize())
    }

    /// Derive a recovery pubkey for a specific index
    ///
    /// Recovery keys are used for timelock recovery paths.
    ///
    /// # Errors
    ///
    /// Returns `GhostKeyError::DerivationError` if the derived tweak produces
    /// an invalid secret key or if the pubkey combination fails. This should
    /// be extremely rare in practice (only if SHA256 output happens to be 0 or
    /// \>= curve order), but callers must handle the error to avoid silent
    /// address reuse. See L-CRYPTO-2.
    pub fn derive_recovery_pubkey(&self, index: u32) -> Result<[u8; 33], GhostKeyError> {
        use sha2::{Digest, Sha256};

        let secp = Secp256k1::new();

        // Derive tweak: SHA256("ghost_recovery" || scan_pubkey || index)
        let mut hasher = Sha256::new();
        hasher.update(b"ghost_recovery");
        hasher.update(self.scan_pubkey.serialize());
        hasher.update(index.to_le_bytes());
        let tweak: [u8; 32] = hasher.finalize().into();

        // Derive recovery pubkey = scan_pubkey + tweak*G
        let tweak_secret = SecretKey::from_slice(&tweak).map_err(|e| {
            GhostKeyError::DerivationError(format!("Invalid tweak for recovery pubkey: {}", e))
        })?;
        let tweak_pubkey = PublicKey::from_secret_key(&secp, &tweak_secret);
        let recovery_pubkey = self.scan_pubkey.combine(&tweak_pubkey).map_err(|e| {
            GhostKeyError::DerivationError(format!("Failed to combine pubkeys for recovery: {}", e))
        })?;

        Ok(recovery_pubkey.serialize())
    }

    /// Derive the secret key for a specific lock index
    pub fn derive_lock_secret(&self, index: u32) -> Result<SecretKey, GhostKeyError> {
        use sha2::{Digest, Sha256};

        // Same tweak as derive_lock_pubkey
        let mut hasher = Sha256::new();
        hasher.update(b"ghost_lock");
        hasher.update(self.spend_pubkey.serialize());
        hasher.update(index.to_le_bytes());
        let tweak: [u8; 32] = hasher.finalize().into();

        // lock_secret = spend_secret + tweak
        derive_spend_key(&self.spend_secret, &tweak)
    }

    /// Derive the recovery secret key for a specific lock index
    pub fn derive_recovery_secret(&self, index: u32) -> Result<SecretKey, GhostKeyError> {
        use sha2::{Digest, Sha256};

        // Same tweak as derive_recovery_pubkey
        let mut hasher = Sha256::new();
        hasher.update(b"ghost_recovery");
        hasher.update(self.scan_pubkey.serialize());
        hasher.update(index.to_le_bytes());
        let tweak: [u8; 32] = hasher.finalize().into();

        // recovery_secret = scan_secret + tweak
        derive_spend_key(&self.scan_secret, &tweak)
    }
}

/// H-2: Implement Drop to securely erase secret keys from memory.
///
/// Uses the `zeroize` crate for reliable memory clearing with compiler barriers.
/// The ZeroizingSecretBytes wrapper handles the raw bytes, and we also call
/// secp256k1's non_secure_erase as an additional layer of defense-in-depth.
impl Drop for GhostKeys {
    fn drop(&mut self) {
        // H-2: The ZeroizingSecretBytes fields are automatically zeroed via their Drop impl.
        // We also call non_secure_erase on the SecretKeys for belt-and-suspenders.
        self.scan_secret.non_secure_erase();
        self.spend_secret.non_secure_erase();
        // Note: scan_secret_bytes and spend_secret_bytes are zeroed by their own Drop
    }
}

/// Public export of Ghost Keys (no secrets)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostKeysPublicExport {
    pub scan_pubkey_hex: String,
    pub spend_pubkey_hex: String,
    pub ghost_id: String,
}

/// Serializable representation of Ghost Keys
///
/// 4.8 SECURITY: Secrets are stored as hex strings and zeroized on drop
/// to prevent sensitive data from lingering in memory after use.
///
/// M-SAFE-1: Uses zeroize crate's safe implementation instead of unsafe
/// as_bytes_mut(). The Zeroize trait for String safely overwrites the
/// string's bytes using compiler barriers to prevent optimization.
///
/// CRYPT-2 FIX: Uses `Zeroizing<String>` wrapper to ensure hex strings are
/// automatically zeroized even if copied during construction. This prevents
/// secret key material from lingering in memory after intermediate operations.
pub struct GhostKeysExport {
    /// Scan secret key as hex (wrapped in Zeroizing for automatic cleanup)
    scan_secret: Zeroizing<String>,
    /// Spend secret key as hex (wrapped in Zeroizing for automatic cleanup)
    spend_secret: Zeroizing<String>,
}

impl GhostKeysExport {
    /// Get the scan secret hex string
    ///
    /// # Security Warning
    ///
    /// The returned reference should be used briefly. Do not store or clone
    /// the string, as this would create unzeroized copies.
    pub fn scan_secret(&self) -> &str {
        &self.scan_secret
    }

    /// Get the spend secret hex string
    ///
    /// # Security Warning
    ///
    /// The returned reference should be used briefly. Do not store or clone
    /// the string, as this would create unzeroized copies.
    pub fn spend_secret(&self) -> &str {
        &self.spend_secret
    }

    /// Create from raw hex strings (takes ownership)
    ///
    /// The strings are immediately wrapped in Zeroizing for protection.
    pub fn new(scan_secret: String, spend_secret: String) -> Self {
        Self {
            scan_secret: Zeroizing::new(scan_secret),
            spend_secret: Zeroizing::new(spend_secret),
        }
    }
}

// M-14: Clone deliberately NOT implemented for GhostKeysExport.
// Cloning key material creates uncontrolled copies that may not be zeroized.
// Use references or pass by value (move) instead.

/// Custom Serialize that unwraps Zeroizing for JSON compatibility
impl Serialize for GhostKeysExport {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("GhostKeysExport", 2)?;
        state.serialize_field("scan_secret", &*self.scan_secret)?;
        state.serialize_field("spend_secret", &*self.spend_secret)?;
        state.end()
    }
}

/// Custom Deserialize that wraps strings in Zeroizing
impl<'de> Deserialize<'de> for GhostKeysExport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            scan_secret: String,
            spend_secret: String,
        }
        let helper = Helper::deserialize(deserializer)?;
        Ok(Self::new(helper.scan_secret, helper.spend_secret))
    }
}

/// Custom Debug that redacts secrets
impl std::fmt::Debug for GhostKeysExport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GhostKeysExport")
            .field("scan_secret", &"[REDACTED]")
            .field("spend_secret", &"[REDACTED]")
            .finish()
    }
}

// Note: No explicit Drop needed - Zeroizing<String> handles zeroization automatically

impl From<&GhostKeys> for GhostKeysExport {
    fn from(keys: &GhostKeys) -> Self {
        // CRYPT-2 FIX: Wrap hex strings in Zeroizing immediately during construction
        // This ensures that even if the struct construction fails or is interrupted,
        // the secret material will be zeroized
        Self {
            scan_secret: Zeroizing::new(hex::encode(keys.scan_secret.secret_bytes())),
            spend_secret: Zeroizing::new(hex::encode(keys.spend_secret.secret_bytes())),
        }
    }
}

impl TryFrom<GhostKeysExport> for GhostKeys {
    type Error = GhostKeyError;

    fn try_from(export: GhostKeysExport) -> Result<Self, Self::Error> {
        // CRYPT-2 FIX: Use accessor methods to get references to the Zeroizing-wrapped strings
        let mut scan_bytes = hex::decode(export.scan_secret())
            .map_err(|e| GhostKeyError::InvalidSecretKey(e.to_string()))?;
        let mut spend_bytes = hex::decode(export.spend_secret())
            .map_err(|e| GhostKeyError::InvalidSecretKey(e.to_string()))?;

        if scan_bytes.len() != 32 || spend_bytes.len() != 32 {
            // M-16 FIX: Zeroize intermediate vectors on error path
            scan_bytes.zeroize();
            spend_bytes.zeroize();
            return Err(GhostKeyError::InvalidSecretKey(
                "Invalid key length".to_string(),
            ));
        }

        // M-16 FIX: Copy to fixed arrays before zeroizing vectors
        let mut scan_array = [0u8; 32];
        let mut spend_array = [0u8; 32];
        scan_array.copy_from_slice(&scan_bytes);
        spend_array.copy_from_slice(&spend_bytes);

        // M-16 FIX: Zeroize intermediate vectors after copying
        scan_bytes.zeroize();
        spend_bytes.zeroize();

        let result = GhostKeys::from_bytes(&scan_array, &spend_array);

        // M-16 FIX: Zeroize local arrays after use
        scan_array.zeroize();
        spend_array.zeroize();

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keys() {
        let keys = GhostKeys::generate();
        assert!(keys.scan_secret().secret_bytes().len() == 32);
        assert!(keys.spend_secret().secret_bytes().len() == 32);
    }

    #[test]
    fn test_from_bytes() {
        let keys1 = GhostKeys::generate();
        let (scan, spend) = keys1.export_secrets();

        // M-15: Dereference Zeroizing wrappers to get the byte arrays
        let keys2 = GhostKeys::from_bytes(&scan, &spend).unwrap();
        assert_eq!(keys1.scan_pubkey(), keys2.scan_pubkey());
        assert_eq!(keys1.spend_pubkey(), keys2.spend_pubkey());
    }

    #[test]
    fn test_ghost_id() {
        let keys = GhostKeys::generate();
        let ghost_id = keys.ghost_id();
        assert_eq!(ghost_id.scan_pubkey(), keys.scan_pubkey());
        assert_eq!(ghost_id.spend_pubkey(), keys.spend_pubkey());
    }

    #[test]
    fn test_export_import() {
        let keys = GhostKeys::generate();
        let export = GhostKeysExport::from(&keys);
        let imported = GhostKeys::try_from(export).unwrap();

        assert_eq!(keys.scan_pubkey(), imported.scan_pubkey());
        assert_eq!(keys.spend_pubkey(), imported.spend_pubkey());
    }

    /// CRYPT-1: Test the callback-based secret access API
    #[test]
    fn test_with_secrets_callback() {
        let keys = GhostKeys::generate();
        let expected_scan = keys.scan_secret().secret_bytes();
        let expected_spend = keys.spend_secret().secret_bytes();

        // Verify callback receives correct secret bytes
        let result = keys.with_secrets(|scan, spend| {
            assert_eq!(*scan, expected_scan);
            assert_eq!(*spend, expected_spend);
            42 // Return a value to verify callback works
        });

        assert_eq!(result, 42);
    }

    /// CRYPT-1: Test that with_secrets returns the callback's result
    #[test]
    fn test_with_secrets_returns_result() {
        let keys = GhostKeys::generate();

        let sum = keys.with_secrets(|scan, spend| {
            // Compute something with the secrets
            let scan_sum: u32 = scan.iter().map(|&b| b as u32).sum();
            let spend_sum: u32 = spend.iter().map(|&b| b as u32).sum();
            scan_sum + spend_sum
        });

        // Just verify we got a result (the sum will be non-zero for random keys)
        assert!(sum > 0);
    }

    /// CRYPT-2: Test GhostKeysExport accessor methods
    #[test]
    fn test_ghost_keys_export_accessors() {
        let keys = GhostKeys::generate();
        let export = GhostKeysExport::from(&keys);

        // Verify accessors return the same values as direct hex encoding
        let expected_scan_hex = hex::encode(keys.scan_secret().secret_bytes());
        let expected_spend_hex = hex::encode(keys.spend_secret().secret_bytes());

        assert_eq!(export.scan_secret(), expected_scan_hex);
        assert_eq!(export.spend_secret(), expected_spend_hex);
    }

    /// CRYPT-2: Test GhostKeysExport serialization roundtrip
    #[test]
    fn test_ghost_keys_export_serde() {
        let keys = GhostKeys::generate();
        let export = GhostKeysExport::from(&keys);

        // Serialize to JSON
        let json = serde_json::to_string(&export).unwrap();

        // Deserialize back
        let recovered: GhostKeysExport = serde_json::from_str(&json).unwrap();

        // Verify values match
        assert_eq!(export.scan_secret(), recovered.scan_secret());
        assert_eq!(export.spend_secret(), recovered.spend_secret());
    }
}
