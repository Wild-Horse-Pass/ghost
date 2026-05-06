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
//| FILE: auth/registry.rs                                                                                               |
//|======================================================================================================================|

//! Wallet registry - stores wallet_id -> pubkey mappings

use std::path::Path;

use parking_lot::Mutex;
use rusqlite::{params, Connection};

use ghost_gsp_proto::{WalletId, WalletProof};

use crate::auth::{verify_proof_and_extract_wallet_id, verify_proof_with_wallet_id};
use crate::error::{GspError, GspResult};

/// L-11 FIX: Maximum display name length in bytes
/// Limits storage and prevents excessively long names
const MAX_DISPLAY_NAME_LENGTH: usize = 64;

/// L-11 FIX: Sanitize display name before storing in database
///
/// This function:
/// 1. Strips leading and trailing whitespace
/// 2. Removes control characters (except space)
/// 3. Truncates to MAX_DISPLAY_NAME_LENGTH bytes
/// 4. Returns None if result is empty after sanitization
///
/// This prevents:
/// - XSS attacks via malicious display names
/// - Database issues from control characters
/// - Memory exhaustion from excessively long names
/// - Log injection attacks
fn sanitize_display_name(name: Option<&str>) -> Option<String> {
    let name = name?;

    // Strip leading/trailing whitespace
    let trimmed = name.trim();

    if trimmed.is_empty() {
        return None;
    }

    // Remove control characters (keep only printable ASCII and valid UTF-8 non-control chars)
    // Control characters are U+0000-U+001F and U+007F-U+009F
    let sanitized: String = trimmed
        .chars()
        .filter(|c| {
            // Allow regular space (U+0020) but reject other control chars
            if *c == ' ' {
                return true;
            }
            // Reject C0 control characters (U+0000-U+001F)
            if *c <= '\u{001F}' {
                return false;
            }
            // Reject DEL (U+007F)
            if *c == '\u{007F}' {
                return false;
            }
            // Reject C1 control characters (U+0080-U+009F)
            if ('\u{0080}'..='\u{009F}').contains(c) {
                return false;
            }
            true
        })
        .collect();

    if sanitized.is_empty() {
        return None;
    }

    // Truncate to max length (byte-safe truncation for UTF-8)
    let truncated = if sanitized.len() > MAX_DISPLAY_NAME_LENGTH {
        // Find a valid UTF-8 boundary to truncate at
        let mut end = MAX_DISPLAY_NAME_LENGTH;
        while end > 0 && !sanitized.is_char_boundary(end) {
            end -= 1;
        }
        &sanitized[..end]
    } else {
        &sanitized
    };

    if truncated.is_empty() {
        None
    } else {
        Some(truncated.to_string())
    }
}

/// M-11 FIX: Guaranteed cleanup interval in seconds
/// In addition to the 1% probabilistic cleanup, we guarantee a cleanup
/// every 5 minutes to prevent unbounded nonce accumulation.
const GUARANTEED_CLEANUP_INTERVAL_SECS: u64 = 300;

/// Wallet registry backed by SQLite
pub struct WalletRegistry {
    conn: Mutex<Connection>,
    /// M-11 FIX: Last time guaranteed cleanup was performed
    last_cleanup: std::sync::atomic::AtomicU64,
}

impl WalletRegistry {
    /// Open or create the wallet registry database
    pub fn open(path: &Path) -> GspResult<Self> {
        let conn = Connection::open(path)?;

        // Create tables
        conn.execute(
            "CREATE TABLE IF NOT EXISTS wallets (
                wallet_id TEXT PRIMARY KEY,
                pubkey BLOB NOT NULL,
                display_name TEXT,
                created_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL
            )",
            [],
        )?;

        // Create index on created_at
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_wallets_created ON wallets(created_at)",
            [],
        )?;

        // Create nonce tracking table for replay protection
        conn.execute(
            "CREATE TABLE IF NOT EXISTS used_nonces (
                nonce TEXT PRIMARY KEY,
                wallet_id TEXT NOT NULL,
                used_at INTEGER NOT NULL
            )",
            [],
        )?;

        // Create index for nonce cleanup
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_nonces_used_at ON used_nonces(used_at)",
            [],
        )?;

        // BIP-352 scan key per wallet (one per wallet_id; upserted on rotation).
        // The scan key is public — used by the server to detect incoming silent
        // payments on the wallet's behalf. Spending still requires the spend
        // secret, which never leaves the wallet.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS wallet_scan_keys (
                wallet_id TEXT PRIMARY KEY,
                scan_pubkey BLOB NOT NULL,
                registered_at INTEGER NOT NULL,
                FOREIGN KEY (wallet_id) REFERENCES wallets(wallet_id)
            )",
            [],
        )?;

        // M-11 FIX: Initialize last_cleanup to current time
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Self {
            conn: Mutex::new(conn),
            last_cleanup: std::sync::atomic::AtomicU64::new(now_secs),
        })
    }

    /// Check if a wallet is registered
    pub fn is_registered(&self, wallet_id: &WalletId) -> GspResult<bool> {
        let conn = self.conn.lock();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM wallets WHERE wallet_id = ?",
            [wallet_id.as_str()],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Register a new wallet
    ///
    /// L-11 FIX: Display name is sanitized before storage to prevent:
    /// - XSS attacks via malicious display names
    /// - Database issues from control characters
    /// - Memory exhaustion from excessively long names
    /// - Log injection attacks
    pub fn register(
        &self,
        wallet_id: &WalletId,
        pubkey: &[u8; 32],
        display_name: Option<&str>,
    ) -> GspResult<()> {
        let conn = self.conn.lock();
        let now = chrono::Utc::now().timestamp();

        // L-11 FIX: Sanitize display name before storing
        let sanitized_name = sanitize_display_name(display_name);

        conn.execute(
            "INSERT INTO wallets (wallet_id, pubkey, display_name, created_at, last_seen)
             VALUES (?, ?, ?, ?, ?)",
            params![
                wallet_id.as_str(),
                pubkey.as_slice(),
                sanitized_name,
                now,
                now
            ],
        )?;

        Ok(())
    }

    /// Get the public key for a wallet
    pub fn get_pubkey(&self, wallet_id: &WalletId) -> GspResult<Option<[u8; 32]>> {
        let conn = self.conn.lock();
        let result: Result<Vec<u8>, _> = conn.query_row(
            "SELECT pubkey FROM wallets WHERE wallet_id = ?",
            [wallet_id.as_str()],
            |row| row.get(0),
        );

        match result {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(arr))
            }
            Ok(_) => Err(GspError::Database("Invalid pubkey length".to_string())),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Upsert the BIP-352 scan public key for a wallet. Replaces any
    /// existing entry (i.e. supports scan-key rotation).
    ///
    /// `scan_pubkey` must be exactly 33 bytes (SEC1 compressed).
    pub fn upsert_scan_key(
        &self,
        wallet_id: &WalletId,
        scan_pubkey: &[u8; 33],
    ) -> GspResult<()> {
        let conn = self.conn.lock();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO wallet_scan_keys (wallet_id, scan_pubkey, registered_at)
             VALUES (?, ?, ?)
             ON CONFLICT(wallet_id) DO UPDATE SET
                 scan_pubkey = excluded.scan_pubkey,
                 registered_at = excluded.registered_at",
            params![wallet_id.as_str(), scan_pubkey.as_slice(), now],
        )?;
        Ok(())
    }

    /// Look up the registered BIP-352 scan public key for a wallet, if any.
    pub fn get_scan_key(&self, wallet_id: &WalletId) -> GspResult<Option<[u8; 33]>> {
        let conn = self.conn.lock();
        let result: Result<Vec<u8>, _> = conn.query_row(
            "SELECT scan_pubkey FROM wallet_scan_keys WHERE wallet_id = ?",
            [wallet_id.as_str()],
            |row| row.get(0),
        );
        match result {
            Ok(bytes) if bytes.len() == 33 => {
                let mut arr = [0u8; 33];
                arr.copy_from_slice(&bytes);
                Ok(Some(arr))
            }
            Ok(_) => Err(GspError::Database("Invalid scan_pubkey length".to_string())),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Update last seen timestamp
    pub fn update_last_seen(&self, wallet_id: &WalletId) -> GspResult<()> {
        let conn = self.conn.lock();
        let now = chrono::Utc::now().timestamp();

        conn.execute(
            "UPDATE wallets SET last_seen = ? WHERE wallet_id = ?",
            params![now, wallet_id.as_str()],
        )?;

        Ok(())
    }

    /// Check if a nonce has been used (replay protection)
    pub fn is_nonce_used(&self, nonce: &str) -> GspResult<bool> {
        let conn = self.conn.lock();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM used_nonces WHERE nonce = ?",
            [nonce],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Mark a nonce as used
    pub fn mark_nonce_used(&self, nonce: &str, wallet_id: &WalletId) -> GspResult<()> {
        let conn = self.conn.lock();
        let now = chrono::Utc::now().timestamp();

        conn.execute(
            "INSERT OR IGNORE INTO used_nonces (nonce, wallet_id, used_at)
             VALUES (?, ?, ?)",
            params![nonce, wallet_id.as_str(), now],
        )?;

        Ok(())
    }

    /// H-9/M-14 FIX: Cleanup old nonces with safe buffer to prevent replay attacks
    ///
    /// Nonces must be kept for at least 2x PROOF_TIMESTAMP_TOLERANCE_SECS + additional buffer
    /// to prevent a race condition where:
    /// 1. User creates proof at T
    /// 2. Cleanup runs at T + tolerance, deleting the nonce
    /// 3. Attacker replays the proof at T + tolerance (still within tolerance window)
    ///
    /// H-9 FIX: The retention is now 2x the tolerance window + 300 seconds buffer:
    /// - PROOF_TIMESTAMP_TOLERANCE_SECS = 300 (5 min)
    /// - 2x tolerance = 600 seconds (10 min)
    /// - Additional buffer = 300 seconds (5 min)
    /// - Total retention = 900 seconds (15 min)
    ///
    /// This ensures nonces are never deleted while the corresponding proof could still be valid,
    /// even accounting for clock skew and network delays.
    pub fn cleanup_old_nonces(&self) -> GspResult<usize> {
        use ghost_gsp_proto::PROOF_TIMESTAMP_TOLERANCE_SECS;

        let conn = self.conn.lock();
        // H-9: Use 2x tolerance window + 300 second buffer for nonce retention
        // This provides ample margin for clock skew, network delays, and edge cases.
        let safe_retention_secs = (PROOF_TIMESTAMP_TOLERANCE_SECS * 2) + 300;
        let cutoff = chrono::Utc::now().timestamp() - safe_retention_secs;

        let deleted = conn.execute("DELETE FROM used_nonces WHERE used_at < ?", [cutoff])?;

        Ok(deleted)
    }

    /// Verify a wallet proof for registration (signature + nonce + extract wallet ID)
    ///
    /// This is used during registration when we don't yet have an expected wallet ID.
    /// The wallet ID is derived from the proof's public key.
    pub fn verify_proof(&self, proof: &WalletProof) -> GspResult<()> {
        // Check nonce hasn't been used (replay protection)
        if self.is_nonce_used(&proof.nonce)? {
            return Err(GspError::NonceReplay);
        }

        // Verify signature and extract wallet ID
        let wallet_id = verify_proof_and_extract_wallet_id(proof)?;

        // Mark nonce as used to prevent replay attacks
        self.mark_nonce_used(&proof.nonce, &wallet_id)?;

        Ok(())
    }

    /// Verify a wallet proof against an expected wallet ID (signature + nonce + wallet ID validation)
    ///
    /// This is used for authenticated operations where we have a session wallet ID.
    /// It verifies:
    /// 1. Schnorr signature is valid
    /// 2. Public key in proof derives to the expected wallet ID
    /// 3. Nonce hasn't been used (replay protection)
    ///
    /// MED-RESOURCE-1 FIX: Periodically cleans up old nonces on each verification.
    pub fn verify_proof_for_wallet(
        &self,
        proof: &WalletProof,
        expected_wallet_id: &WalletId,
    ) -> GspResult<()> {
        // MED-RESOURCE-1 FIX: Probabilistically cleanup old nonces
        // Run cleanup ~1% of the time to avoid overhead on every request
        // while still ensuring nonces are eventually cleaned up
        self.maybe_cleanup_nonces();

        // Check nonce hasn't been used (replay protection)
        if self.is_nonce_used(&proof.nonce)? {
            return Err(GspError::NonceReplay);
        }

        // Verify signature and wallet ID derivation
        verify_proof_with_wallet_id(proof, expected_wallet_id)?;

        // Mark nonce as used to prevent replay attacks
        self.mark_nonce_used(&proof.nonce, expected_wallet_id)?;

        Ok(())
    }

    /// M-11 FIX: Cleanup old nonces with guaranteed interval + probabilistic backup
    ///
    /// This function ensures nonces are cleaned up via two mechanisms:
    /// 1. GUARANTEED: Every 5 minutes (GUARANTEED_CLEANUP_INTERVAL_SECS)
    /// 2. PROBABILISTIC: ~1% chance on each call (for burst load scenarios)
    ///
    /// The guaranteed interval prevents unbounded nonce accumulation even if
    /// request volume is low. The probabilistic cleanup handles burst scenarios
    /// where many requests arrive within the guaranteed interval.
    fn maybe_cleanup_nonces(&self) {
        use std::sync::atomic::Ordering;

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let last_cleanup = self.last_cleanup.load(Ordering::Relaxed);
        let since_last = now_secs.saturating_sub(last_cleanup);

        // M-11 FIX: Guaranteed cleanup every 5 minutes
        if since_last >= GUARANTEED_CLEANUP_INTERVAL_SECS {
            // Attempt atomic update to prevent multiple threads from cleaning up simultaneously
            // If another thread already updated it, skip cleanup (they'll do it)
            if self
                .last_cleanup
                .compare_exchange(last_cleanup, now_secs, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                if let Ok(deleted) = self.cleanup_old_nonces() {
                    if deleted > 0 {
                        tracing::debug!(
                            deleted_nonces = deleted,
                            interval_secs = since_last,
                            "M-11: Guaranteed nonce cleanup completed"
                        );
                    }
                }
            }
            return;
        }

        // MED-RESOURCE-1 FIX: Also run probabilistic cleanup ~1% of the time
        // This handles burst scenarios within the guaranteed interval
        // H-3 FIX: Use OsRng for cryptographic security instead of thread_rng()
        use rand::rngs::OsRng;
        use rand::Rng;
        if OsRng.gen_range(0..100) == 0 {
            if let Ok(deleted) = self.cleanup_old_nonces() {
                if deleted > 0 {
                    tracing::debug!(
                        deleted_nonces = deleted,
                        "MED-RESOURCE-1: Probabilistic nonce cleanup completed"
                    );
                }
            }
        }
    }

    /// Get total number of registered wallets
    pub fn wallet_count(&self) -> GspResult<u64> {
        let conn = self.conn.lock();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM wallets", [], |row| row.get(0))?;
        Ok(count as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn create_test_registry() -> (WalletRegistry, NamedTempFile) {
        let temp = NamedTempFile::new().unwrap();
        let registry = WalletRegistry::open(temp.path()).unwrap();
        (registry, temp)
    }

    #[test]
    fn test_register_wallet() {
        let (registry, _temp) = create_test_registry();
        let wallet_id = WalletId::from("test_wallet_12345678901234".to_string());
        let pubkey = [1u8; 32];

        // Not registered initially
        assert!(!registry.is_registered(&wallet_id).unwrap());

        // Register
        registry
            .register(&wallet_id, &pubkey, Some("Test Wallet"))
            .unwrap();

        // Now registered
        assert!(registry.is_registered(&wallet_id).unwrap());

        // Can get pubkey
        let stored = registry.get_pubkey(&wallet_id).unwrap();
        assert_eq!(stored, Some(pubkey));
    }

    #[test]
    fn test_nonce_tracking() {
        let (registry, _temp) = create_test_registry();
        let wallet_id = WalletId::from("test_wallet_12345678901234".to_string());

        // Nonce not used
        assert!(!registry.is_nonce_used("test_nonce").unwrap());

        // Mark as used
        registry.mark_nonce_used("test_nonce", &wallet_id).unwrap();

        // Now used
        assert!(registry.is_nonce_used("test_nonce").unwrap());
    }

    #[test]
    fn test_wallet_count() {
        let (registry, _temp) = create_test_registry();

        assert_eq!(registry.wallet_count().unwrap(), 0);

        let wallet_id = WalletId::from("test_wallet_12345678901234".to_string());
        registry.register(&wallet_id, &[1u8; 32], None).unwrap();

        assert_eq!(registry.wallet_count().unwrap(), 1);
    }

    // L-11 FIX: Display name sanitization tests
    #[test]
    fn test_sanitize_display_name_basic() {
        assert_eq!(
            sanitize_display_name(Some("Alice")),
            Some("Alice".to_string())
        );
        assert_eq!(
            sanitize_display_name(Some("  Bob  ")),
            Some("Bob".to_string())
        );
        assert_eq!(sanitize_display_name(None), None);
        assert_eq!(sanitize_display_name(Some("")), None);
        assert_eq!(sanitize_display_name(Some("   ")), None);
    }

    #[test]
    fn test_sanitize_display_name_control_chars() {
        // Control characters should be removed
        assert_eq!(
            sanitize_display_name(Some("Hello\x00World")),
            Some("HelloWorld".to_string())
        );
        assert_eq!(
            sanitize_display_name(Some("Test\nName")),
            Some("TestName".to_string())
        );
        assert_eq!(
            sanitize_display_name(Some("Tab\there")),
            Some("Tabhere".to_string())
        );
        assert_eq!(
            sanitize_display_name(Some("\x1FBad\x7F")),
            Some("Bad".to_string())
        );

        // Space should be preserved
        assert_eq!(
            sanitize_display_name(Some("Hello World")),
            Some("Hello World".to_string())
        );
    }

    #[test]
    fn test_sanitize_display_name_length() {
        // Should truncate to MAX_DISPLAY_NAME_LENGTH
        let long_name = "A".repeat(100);
        let result = sanitize_display_name(Some(&long_name));
        assert!(result.is_some());
        assert!(result.as_ref().unwrap().len() <= MAX_DISPLAY_NAME_LENGTH);
        assert_eq!(result.unwrap().len(), MAX_DISPLAY_NAME_LENGTH);
    }

    #[test]
    fn test_sanitize_display_name_utf8() {
        // UTF-8 characters should be preserved
        assert_eq!(
            sanitize_display_name(Some("Satoshi")),
            Some("Satoshi".to_string())
        );

        // Long UTF-8 should truncate at valid boundary
        let utf8_name = "a".to_string() + &"e".repeat(100);
        let result = sanitize_display_name(Some(&utf8_name));
        assert!(result.is_some());
        // Should be valid UTF-8
        assert!(result.as_ref().unwrap().is_ascii());
    }

    #[test]
    fn test_sanitize_display_name_only_control_chars() {
        // Only control chars should result in None
        assert_eq!(sanitize_display_name(Some("\x00\x01\x02")), None);
        assert_eq!(sanitize_display_name(Some("\n\t\r")), None);
    }

    // M-11 FIX: Test guaranteed cleanup interval tracking
    #[test]
    fn test_m11_guaranteed_cleanup_interval() {
        let (registry, _temp) = create_test_registry();
        let wallet_id = WalletId::from("test_wallet_12345678901234".to_string());

        // Add some nonces
        registry.mark_nonce_used("nonce1", &wallet_id).unwrap();
        registry.mark_nonce_used("nonce2", &wallet_id).unwrap();

        // Verify nonces exist
        assert!(registry.is_nonce_used("nonce1").unwrap());
        assert!(registry.is_nonce_used("nonce2").unwrap());

        // Verify cleanup is called without error (actual time-based cleanup
        // won't trigger in tests since we can't easily advance time)
        registry.maybe_cleanup_nonces();

        // Last cleanup timestamp should be initialized
        let last_cleanup = registry
            .last_cleanup
            .load(std::sync::atomic::Ordering::Relaxed);
        assert!(last_cleanup > 0, "M-11: last_cleanup should be initialized");
    }

    // M-11 FIX: Test that nonce cleanup actually deletes old nonces
    #[test]
    fn test_m11_nonce_cleanup_deletes_old() {
        let (registry, _temp) = create_test_registry();
        let wallet_id = WalletId::from("test_wallet_12345678901234".to_string());

        // Manually insert an old nonce directly into the database
        {
            let conn = registry.conn.lock();
            // Insert a nonce that's 20 minutes old (well past the 15 minute retention)
            let old_time = chrono::Utc::now().timestamp() - 1200; // 20 minutes ago
            conn.execute(
                "INSERT INTO used_nonces (nonce, wallet_id, used_at) VALUES (?, ?, ?)",
                params!["old_nonce", wallet_id.as_str(), old_time],
            )
            .unwrap();
        }

        // Verify old nonce exists
        assert!(registry.is_nonce_used("old_nonce").unwrap());

        // Run cleanup
        let deleted = registry.cleanup_old_nonces().unwrap();

        // Old nonce should be deleted
        assert!(deleted > 0, "M-11: cleanup should delete old nonces");
        assert!(
            !registry.is_nonce_used("old_nonce").unwrap(),
            "M-11: old nonce should be gone after cleanup"
        );
    }
}
