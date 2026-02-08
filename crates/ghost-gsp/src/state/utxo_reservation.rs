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
//| FILE: state/utxo_reservation.rs                                                                                      |
//|======================================================================================================================|

//! C-6 FIX: UTXO Reservation System for Instant Payments
//!
//! This module provides a thread-safe UTXO reservation system that prevents race conditions
//! where the same UTXO could be used for multiple instant payments before L1 verification
//! completes.
//!
//! # Security Properties
//!
//! - **Mutual Exclusion**: Only one instant payment can use a UTXO at a time
//! - **Atomicity**: Reserve operation is atomic (check + insert in one lock)
//! - **Automatic Cleanup**: Expired reservations are cleaned up periodically
//! - **Crash Recovery**: Reservations are persisted to database for recovery
//!
//! # Usage Pattern
//!
//! ```ignore
//! // Reserve UTXO before async L1 verification
//! let guard = reservations.reserve(&lock_id)?;
//!
//! // Perform async L1 verification...
//! let result = verify_on_l1(&lock_id).await;
//!
//! // Guard automatically releases on drop if we don't commit
//! if result.is_ok() {
//!     guard.commit(); // Payment succeeded, keep reservation
//! }
//! // Otherwise guard drops and releases reservation
//! ```

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rusqlite::{params, Connection};
use tracing::{debug, info, warn};

use crate::error::{GspError, GspResult};

/// Default reservation expiry time (5 minutes)
/// This should be longer than the longest expected L1 verification time
const DEFAULT_RESERVATION_EXPIRY_SECS: u64 = 300;

/// How often to run cleanup of expired reservations
const CLEANUP_INTERVAL_SECS: u64 = 60;

/// C-6: A UTXO reservation entry
#[derive(Debug, Clone)]
struct Reservation {
    /// When the reservation was created (in-memory tracking)
    #[allow(dead_code)]
    created_at: Instant,
    /// When the reservation expires (in-memory tracking)
    expires_at: Instant,
    /// Absolute expiry timestamp in seconds since UNIX epoch (for database persistence)
    expires_at_unix: i64,
    /// Payment ID that made this reservation
    payment_id: String,
    /// Wallet ID that owns this reservation
    #[allow(dead_code)]
    wallet_id: String,
}

/// C-6: UTXO Reservation Manager
///
/// Thread-safe manager for UTXO reservations that prevents race conditions
/// during instant payment acceptance.
///
/// H-11: Reservations are persisted to SQLite for crash recovery. The in-memory
/// HashMap is the primary data structure for performance, while SQLite provides
/// durability across restarts.
pub struct UtxoReservationManager {
    /// Active reservations: lock_id -> Reservation
    reservations: Mutex<HashMap<String, Reservation>>,
    /// Reservation expiry duration
    expiry_duration: Duration,
    /// Last cleanup time
    last_cleanup: Mutex<Instant>,
    /// H-11: SQLite connection for persistence (None for in-memory only mode)
    db: Option<Mutex<Connection>>,
}

impl std::fmt::Debug for UtxoReservationManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UtxoReservationManager")
            .field("reservations", &self.reservations)
            .field("expiry_duration", &self.expiry_duration)
            .field("last_cleanup", &self.last_cleanup)
            .field("db", &self.db.is_some())
            .finish()
    }
}

impl Default for UtxoReservationManager {
    fn default() -> Self {
        Self::new()
    }
}

impl UtxoReservationManager {
    /// Create a new reservation manager with default settings (in-memory only)
    pub fn new() -> Self {
        Self {
            reservations: Mutex::new(HashMap::new()),
            expiry_duration: Duration::from_secs(DEFAULT_RESERVATION_EXPIRY_SECS),
            last_cleanup: Mutex::new(Instant::now()),
            db: None,
        }
    }

    /// Create a reservation manager with custom expiry duration (in-memory only)
    pub fn with_expiry(expiry_secs: u64) -> Self {
        Self {
            reservations: Mutex::new(HashMap::new()),
            expiry_duration: Duration::from_secs(expiry_secs),
            last_cleanup: Mutex::new(Instant::now()),
            db: None,
        }
    }

    /// H-11: Create a reservation manager with SQLite persistence
    ///
    /// This enables crash recovery by persisting reservations to disk.
    /// On startup, any unexpired reservations are loaded back into memory.
    pub fn with_persistence(db_path: &Path) -> GspResult<Self> {
        Self::with_persistence_and_expiry(db_path, DEFAULT_RESERVATION_EXPIRY_SECS)
    }

    /// H-11: Create a reservation manager with SQLite persistence and custom expiry
    pub fn with_persistence_and_expiry(db_path: &Path, expiry_secs: u64) -> GspResult<Self> {
        let conn = Connection::open(db_path).map_err(|e| {
            GspError::Database(format!("H-11: Failed to open reservation database: {}", e))
        })?;

        // Create reservations table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS utxo_reservations (
                lock_id TEXT PRIMARY KEY,
                payment_id TEXT NOT NULL,
                wallet_id TEXT NOT NULL,
                created_at_unix INTEGER NOT NULL,
                expires_at_unix INTEGER NOT NULL
            )",
            [],
        )
        .map_err(|e| {
            GspError::Database(format!(
                "H-11: Failed to create reservation table: {}",
                e
            ))
        })?;

        // Create index for cleanup queries
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_reservations_expires ON utxo_reservations(expires_at_unix)",
            [],
        )
        .map_err(|e| {
            GspError::Database(format!("H-11: Failed to create reservation index: {}", e))
        })?;

        let mut manager = Self {
            reservations: Mutex::new(HashMap::new()),
            expiry_duration: Duration::from_secs(expiry_secs),
            last_cleanup: Mutex::new(Instant::now()),
            db: Some(Mutex::new(conn)),
        };

        // Load unexpired reservations from database
        manager.load_reservations_from_db()?;

        Ok(manager)
    }

    /// H-11: Load unexpired reservations from database on startup
    fn load_reservations_from_db(&mut self) -> GspResult<()> {
        let db = match &self.db {
            Some(db) => db,
            None => return Ok(()), // No persistence configured
        };

        let conn = db.lock();
        let now_unix = chrono::Utc::now().timestamp();

        // First, cleanup expired reservations from DB
        conn.execute(
            "DELETE FROM utxo_reservations WHERE expires_at_unix <= ?",
            [now_unix],
        )
        .map_err(|e| {
            GspError::Database(format!("H-11: Failed to cleanup expired reservations: {}", e))
        })?;

        // Load unexpired reservations
        let mut stmt = conn
            .prepare(
                "SELECT lock_id, payment_id, wallet_id, created_at_unix, expires_at_unix
                 FROM utxo_reservations WHERE expires_at_unix > ?",
            )
            .map_err(|e| {
                GspError::Database(format!("H-11: Failed to prepare load statement: {}", e))
            })?;

        let rows = stmt
            .query_map([now_unix], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .map_err(|e| {
                GspError::Database(format!("H-11: Failed to query reservations: {}", e))
            })?;

        let mut reservations = self.reservations.lock();
        let now = Instant::now();
        let mut loaded_count = 0;

        for row_result in rows {
            let (lock_id, payment_id, wallet_id, _created_at_unix, expires_at_unix) =
                row_result.map_err(|e| {
                    GspError::Database(format!("H-11: Failed to read reservation row: {}", e))
                })?;

            // Convert absolute timestamp to relative Instant
            let remaining_secs = (expires_at_unix - now_unix).max(0) as u64;
            let expires_at = now + Duration::from_secs(remaining_secs);

            reservations.insert(
                lock_id,
                Reservation {
                    created_at: now,
                    expires_at,
                    expires_at_unix,
                    payment_id,
                    wallet_id,
                },
            );
            loaded_count += 1;
        }

        if loaded_count > 0 {
            info!(
                loaded = loaded_count,
                "H-11: Loaded unexpired UTXO reservations from database"
            );
        }

        Ok(())
    }

    /// H-11: Persist a reservation to database
    fn persist_reservation(
        &self,
        lock_id: &str,
        payment_id: &str,
        wallet_id: &str,
        created_at_unix: i64,
        expires_at_unix: i64,
    ) -> GspResult<()> {
        let db = match &self.db {
            Some(db) => db,
            None => return Ok(()), // No persistence configured
        };

        let conn = db.lock();
        conn.execute(
            "INSERT OR REPLACE INTO utxo_reservations
             (lock_id, payment_id, wallet_id, created_at_unix, expires_at_unix)
             VALUES (?, ?, ?, ?, ?)",
            params![lock_id, payment_id, wallet_id, created_at_unix, expires_at_unix],
        )
        .map_err(|e| {
            GspError::Database(format!("H-11: Failed to persist reservation: {}", e))
        })?;

        Ok(())
    }

    /// H-11: Remove a reservation from database
    fn remove_from_db(&self, lock_id: &str) {
        if let Some(db) = &self.db {
            let conn = db.lock();
            if let Err(e) = conn.execute(
                "DELETE FROM utxo_reservations WHERE lock_id = ?",
                [lock_id],
            ) {
                warn!(
                    lock_id = lock_id,
                    error = %e,
                    "H-11: Failed to remove reservation from database"
                );
            }
        }
    }

    /// C-6: Reserve a UTXO for instant payment processing
    ///
    /// This must be called BEFORE starting any async L1 verification.
    /// The returned guard will automatically release the reservation on drop
    /// unless `commit()` is called.
    ///
    /// # Arguments
    /// * `lock_id` - The lock ID (UTXO identifier) to reserve
    /// * `payment_id` - Unique payment ID for tracking
    /// * `wallet_id` - Wallet ID making the reservation
    ///
    /// # Returns
    /// * `Ok(ReservationGuard)` - Reservation acquired successfully
    /// * `Err(GspError::UtxoAlreadyReserved)` - UTXO is already reserved
    ///
    /// # H-11 Persistence
    /// Reservations are persisted to SQLite if persistence is configured,
    /// enabling crash recovery.
    pub fn reserve(
        self: &Arc<Self>,
        lock_id: &str,
        payment_id: &str,
        wallet_id: &str,
    ) -> GspResult<ReservationGuard> {
        // Periodically cleanup expired reservations
        self.maybe_cleanup();

        let now = Instant::now();
        let now_unix = chrono::Utc::now().timestamp();
        let expires_at = now + self.expiry_duration;
        let expires_at_unix = now_unix + self.expiry_duration.as_secs() as i64;

        let mut reservations = self.reservations.lock();

        // Check for existing reservation
        if let Some(existing) = reservations.get(lock_id) {
            // Check if existing reservation has expired
            if now >= existing.expires_at {
                // Expired, remove it and allow new reservation
                debug!(
                    lock_id = lock_id,
                    old_payment_id = existing.payment_id,
                    "C-6: Replacing expired UTXO reservation"
                );
            } else {
                // Active reservation exists - reject
                warn!(
                    lock_id = lock_id,
                    existing_payment_id = existing.payment_id,
                    new_payment_id = payment_id,
                    "C-6: UTXO already reserved - preventing race condition"
                );
                return Err(GspError::UtxoAlreadyReserved);
            }
        }

        // Create new reservation
        let reservation = Reservation {
            created_at: now,
            expires_at,
            expires_at_unix,
            payment_id: payment_id.to_string(),
            wallet_id: wallet_id.to_string(),
        };

        reservations.insert(lock_id.to_string(), reservation);

        // H-11: Persist to database for crash recovery
        // Release the lock before persisting to avoid holding it during I/O
        drop(reservations);
        self.persist_reservation(lock_id, payment_id, wallet_id, now_unix, expires_at_unix)?;

        debug!(
            lock_id = lock_id,
            payment_id = payment_id,
            expires_in_secs = self.expiry_duration.as_secs(),
            persisted = self.db.is_some(),
            "C-6: UTXO reserved for instant payment"
        );

        Ok(ReservationGuard {
            manager: Arc::clone(self),
            lock_id: lock_id.to_string(),
            committed: false,
        })
    }

    /// Release a reservation (called by guard on drop or explicitly)
    ///
    /// H-11: Also removes from database if persistence is configured.
    fn release(&self, lock_id: &str) {
        let mut reservations = self.reservations.lock();
        if reservations.remove(lock_id).is_some() {
            // H-11: Also remove from database
            drop(reservations);
            self.remove_from_db(lock_id);
            debug!(lock_id = lock_id, "C-6: UTXO reservation released");
        }
    }

    /// Check if a UTXO is currently reserved
    pub fn is_reserved(&self, lock_id: &str) -> bool {
        let reservations = self.reservations.lock();
        if let Some(reservation) = reservations.get(lock_id) {
            Instant::now() < reservation.expires_at
        } else {
            false
        }
    }

    /// Get the number of active reservations
    pub fn active_count(&self) -> usize {
        let reservations = self.reservations.lock();
        let now = Instant::now();
        reservations
            .values()
            .filter(|r| now < r.expires_at)
            .count()
    }

    /// Cleanup expired reservations periodically
    ///
    /// H-11: Also cleans up expired reservations from database.
    fn maybe_cleanup(&self) {
        let mut last_cleanup = self.last_cleanup.lock();
        let now = Instant::now();

        if now.duration_since(*last_cleanup) < Duration::from_secs(CLEANUP_INTERVAL_SECS) {
            return;
        }

        *last_cleanup = now;
        drop(last_cleanup);

        let mut reservations = self.reservations.lock();
        let before_count = reservations.len();
        reservations.retain(|lock_id, r| {
            let keep = now < r.expires_at;
            if !keep {
                debug!(
                    lock_id = lock_id,
                    payment_id = r.payment_id,
                    "C-6: Cleaning up expired UTXO reservation"
                );
            }
            keep
        });
        let removed = before_count - reservations.len();
        drop(reservations);

        // H-11: Also cleanup expired reservations from database
        if let Some(db) = &self.db {
            let conn = db.lock();
            let now_unix = chrono::Utc::now().timestamp();
            match conn.execute(
                "DELETE FROM utxo_reservations WHERE expires_at_unix <= ?",
                [now_unix],
            ) {
                Ok(db_removed) if db_removed > 0 => {
                    debug!(
                        removed = db_removed,
                        "H-11: Cleaned up expired reservations from database"
                    );
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "H-11: Failed to cleanup expired reservations from database"
                    );
                }
                _ => {}
            }
        }

        if removed > 0 {
            debug!(
                removed = removed,
                "C-6: Cleaned up expired UTXO reservations from memory"
            );
        }
    }

    /// Force cleanup of all expired reservations (for testing)
    #[cfg(test)]
    pub fn force_cleanup(&self) {
        let mut reservations = self.reservations.lock();
        let now = Instant::now();
        reservations.retain(|_, r| now < r.expires_at);
    }

    /// H-11: Check if database persistence is enabled
    pub fn has_persistence(&self) -> bool {
        self.db.is_some()
    }
}

/// C-6: RAII guard for UTXO reservations
///
/// The reservation is automatically released when this guard is dropped,
/// unless `commit()` is called to indicate the payment succeeded.
#[derive(Debug)]
pub struct ReservationGuard {
    manager: Arc<UtxoReservationManager>,
    lock_id: String,
    committed: bool,
}

impl ReservationGuard {
    /// Commit the reservation - the UTXO will remain reserved until expiry
    ///
    /// Call this after the instant payment has been successfully recorded.
    /// After commit, the guard will NOT release the reservation on drop.
    pub fn commit(mut self) {
        self.committed = true;
        debug!(
            lock_id = self.lock_id,
            "C-6: UTXO reservation committed (will expire naturally)"
        );
    }

    /// Get the lock_id this guard is for
    pub fn lock_id(&self) -> &str {
        &self.lock_id
    }
}

impl Drop for ReservationGuard {
    fn drop(&mut self) {
        if !self.committed {
            // Payment failed or was abandoned - release the reservation
            self.manager.release(&self.lock_id);
        }
        // If committed, let the reservation expire naturally
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c6_basic_reservation() {
        let manager = Arc::new(UtxoReservationManager::new());

        // Should be able to reserve
        let guard = manager
            .reserve("lock1", "payment1", "wallet1")
            .expect("Should reserve successfully");

        assert!(manager.is_reserved("lock1"));
        assert_eq!(manager.active_count(), 1);

        // Drop guard without commit - should release
        drop(guard);

        assert!(!manager.is_reserved("lock1"));
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn test_c6_double_reservation_blocked() {
        let manager = Arc::new(UtxoReservationManager::new());

        // First reservation succeeds
        let _guard1 = manager
            .reserve("lock1", "payment1", "wallet1")
            .expect("First reservation should succeed");

        // Second reservation for same lock should fail
        let result = manager.reserve("lock1", "payment2", "wallet2");
        assert!(
            result.is_err(),
            "C-6: Second reservation should fail for same lock"
        );
        assert!(matches!(result.unwrap_err(), GspError::UtxoAlreadyReserved));
    }

    #[test]
    fn test_c6_different_locks_allowed() {
        let manager = Arc::new(UtxoReservationManager::new());

        // Reservations for different locks should both succeed
        let _guard1 = manager
            .reserve("lock1", "payment1", "wallet1")
            .expect("First lock reservation should succeed");
        let _guard2 = manager
            .reserve("lock2", "payment2", "wallet1")
            .expect("Second lock reservation should succeed");

        assert!(manager.is_reserved("lock1"));
        assert!(manager.is_reserved("lock2"));
        assert_eq!(manager.active_count(), 2);
    }

    #[test]
    fn test_c6_commit_keeps_reservation() {
        let manager = Arc::new(UtxoReservationManager::new());

        let guard = manager
            .reserve("lock1", "payment1", "wallet1")
            .expect("Should reserve successfully");

        // Commit the reservation
        guard.commit();

        // Reservation should still be active after commit
        assert!(manager.is_reserved("lock1"));
    }

    #[test]
    fn test_c6_guard_drop_releases() {
        let manager = Arc::new(UtxoReservationManager::new());

        {
            let _guard = manager
                .reserve("lock1", "payment1", "wallet1")
                .expect("Should reserve successfully");
            assert!(manager.is_reserved("lock1"));
        }

        // Guard dropped without commit - should be released
        assert!(!manager.is_reserved("lock1"));
    }

    #[test]
    fn test_c6_expired_reservation_replaced() {
        // Use very short expiry for testing
        let manager = Arc::new(UtxoReservationManager::with_expiry(0));

        // Make a reservation that expires immediately
        let guard = manager
            .reserve("lock1", "payment1", "wallet1")
            .expect("Should reserve successfully");
        guard.commit(); // Keep it but it's already expired

        // Should be able to make new reservation since old one expired
        let _guard2 = manager
            .reserve("lock1", "payment2", "wallet2")
            .expect("C-6: Should replace expired reservation");
    }

    #[test]
    fn test_h11_persistence() {
        use tempfile::NamedTempFile;

        // Create a temp file for the database
        let temp = NamedTempFile::new().unwrap();
        let db_path = temp.path();

        // Create manager with persistence and make a reservation
        {
            let manager = Arc::new(
                UtxoReservationManager::with_persistence_and_expiry(db_path, 600)
                    .expect("H-11: Should create manager with persistence"),
            );

            assert!(manager.has_persistence());

            let guard = manager
                .reserve("lock1", "payment1", "wallet1")
                .expect("Should reserve successfully");

            guard.commit(); // Keep it persisted

            assert!(manager.is_reserved("lock1"));
            assert_eq!(manager.active_count(), 1);
        }

        // Create a NEW manager from the same database - reservation should be loaded
        {
            let manager = Arc::new(
                UtxoReservationManager::with_persistence_and_expiry(db_path, 600)
                    .expect("H-11: Should create manager from existing database"),
            );

            // Reservation should have been loaded from database
            assert!(
                manager.is_reserved("lock1"),
                "H-11: Reservation should be loaded from database on startup"
            );
            assert_eq!(manager.active_count(), 1);
        }
    }

    #[test]
    fn test_h11_persistence_cleanup_on_startup() {
        use tempfile::NamedTempFile;

        // Create a temp file for the database
        let temp = NamedTempFile::new().unwrap();
        let db_path = temp.path();

        // Create manager with 0 expiry (expires immediately)
        {
            let manager = Arc::new(
                UtxoReservationManager::with_persistence_and_expiry(db_path, 0)
                    .expect("H-11: Should create manager with persistence"),
            );

            let guard = manager
                .reserve("lock1", "payment1", "wallet1")
                .expect("Should reserve successfully");

            guard.commit();
        }

        // Wait a moment for expiry
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Create a NEW manager - expired reservation should NOT be loaded
        {
            let manager = Arc::new(
                UtxoReservationManager::with_persistence_and_expiry(db_path, 600)
                    .expect("H-11: Should create manager from existing database"),
            );

            // Expired reservation should have been cleaned up on startup
            assert!(
                !manager.is_reserved("lock1"),
                "H-11: Expired reservation should be cleaned up on startup"
            );
            assert_eq!(manager.active_count(), 0);
        }
    }

    #[test]
    fn test_h11_persistence_release_removes_from_db() {
        use tempfile::NamedTempFile;

        // Create a temp file for the database
        let temp = NamedTempFile::new().unwrap();
        let db_path = temp.path();

        // Create manager, make reservation, then release it
        {
            let manager = Arc::new(
                UtxoReservationManager::with_persistence_and_expiry(db_path, 600)
                    .expect("H-11: Should create manager with persistence"),
            );

            let guard = manager
                .reserve("lock1", "payment1", "wallet1")
                .expect("Should reserve successfully");

            // Drop without commit - should release and remove from DB
            drop(guard);

            assert!(!manager.is_reserved("lock1"));
        }

        // Create a NEW manager - reservation should NOT be present
        {
            let manager = Arc::new(
                UtxoReservationManager::with_persistence_and_expiry(db_path, 600)
                    .expect("H-11: Should create manager from existing database"),
            );

            // Released reservation should not be in database
            assert!(
                !manager.is_reserved("lock1"),
                "H-11: Released reservation should be removed from database"
            );
            assert_eq!(manager.active_count(), 0);
        }
    }
}
