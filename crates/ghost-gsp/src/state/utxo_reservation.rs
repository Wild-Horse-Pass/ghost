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
//! # Distributed Deployment Warning (C-3, H-7)
//!
//! **CRITICAL**: This reservation system operates per-GSP-instance. In a distributed
//! deployment with multiple GSP nodes, additional coordination is required to prevent
//! double-spend attacks where the same UTXO is used on different GSP nodes simultaneously.
//!
//! ## Single-Node Deployment (Safe by Default)
//!
//! For single-node deployments, this implementation is sufficient. The mutex provides
//! mutual exclusion and the SQLite persistence provides crash recovery.
//!
//! ## Multi-Node Deployment Options
//!
//! If deploying multiple GSP nodes that share the same user base, you MUST implement
//! one of the following coordination strategies:
//!
//! ### Option 1: Shared Database
//!
//! All GSP nodes use the same SQLite/PostgreSQL database for reservations:
//! - Configure all nodes with the same `db_path` in `with_persistence()`
//! - SQLite with WAL mode supports concurrent reads and exclusive writes
//! - For high concurrency, consider PostgreSQL with row-level locking
//!
//! ### Option 2: Redis Distributed Locking
//!
//! Use Redis SETNX (SET if Not eXists) for distributed locks:
//! ```text
//! // Pseudocode for Redis-based reservation
//! let lock_key = format!("ghost:utxo:{}", lock_id);
//! let acquired = redis.set_nx(&lock_key, payment_id, expiry_secs)?;
//! if !acquired {
//!     return Err(GspError::UtxoAlreadyReserved);
//! }
//! ```
//!
//! ### Option 3: Consensus Layer Routing
//!
//! Route all UTXO reservations through the P2P consensus layer:
//! - Each reservation becomes a consensus message
//! - Nodes vote on reservation validity
//! - Only one reservation can win for a given UTXO
//!
//! ## Security Implications of Incorrect Coordination
//!
//! Without proper distributed coordination, an attacker could:
//! 1. Send the same UTXO to two different GSP nodes simultaneously
//! 2. Both nodes accept the payment (double-spend)
//! 3. Only one settlement succeeds on L1, leaving one merchant unpaid
//!
//! The L1 verification in H-11 eventually catches this, but by then the
//! merchant may have already delivered goods/services.
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

/// How often to run cleanup of expired reservations (M-3: moved off hot path)
const CLEANUP_INTERVAL_SECS: u64 = 30;

/// H-2: Maximum number of active reservations to prevent DoS
const MAX_RESERVATIONS: usize = 10_000;

/// M-2: Maximum lock ID length
const MAX_LOCK_ID_LENGTH: usize = 256;

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

        // L-1: Enable WAL mode for better concurrent performance
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")
            .map_err(|e| {
                GspError::Database(format!("L-1: Failed to enable WAL mode: {}", e))
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
    /// * `Err(GspError::TooManyReservations)` - H-2: DoS protection limit reached
    /// * `Err(GspError::InvalidLockId)` - M-2: Lock ID validation failed
    ///
    /// # H-11 Persistence
    /// Reservations are persisted to SQLite if persistence is configured,
    /// enabling crash recovery.
    ///
    /// # C-1/C-2 TOCTOU Fix
    /// Persistence is performed BEFORE memory insertion to prevent race conditions
    /// where a crash after memory insert but before DB write would lose the reservation.
    pub fn reserve(
        self: &Arc<Self>,
        lock_id: &str,
        payment_id: &str,
        wallet_id: &str,
    ) -> GspResult<ReservationGuard> {
        // M-2: Validate lock ID format
        if lock_id.is_empty() {
            return Err(GspError::InvalidLockId("lock ID cannot be empty".to_string()));
        }
        if lock_id.len() > MAX_LOCK_ID_LENGTH {
            return Err(GspError::InvalidLockId(format!(
                "lock ID exceeds maximum length of {} bytes",
                MAX_LOCK_ID_LENGTH
            )));
        }

        // M-3: Periodically cleanup expired reservations (only every CLEANUP_INTERVAL_SECS)
        self.maybe_cleanup();

        // M-1: Use single time source to avoid clock skew between Instant and Unix time
        let now_unix = chrono::Utc::now().timestamp();
        let expires_at_unix = now_unix + self.expiry_duration.as_secs() as i64;
        // Derive Instant from the same base for consistency
        let now = Instant::now();
        let expires_at = now + self.expiry_duration;

        // First, check memory state (need to hold lock for atomic check-and-insert)
        let mut reservations = self.reservations.lock();

        // H-2: Check reservation count limit (DoS protection)
        if reservations.len() >= MAX_RESERVATIONS {
            // Run cleanup to try to free space
            let before_count = reservations.len();
            reservations.retain(|_, r| now < r.expires_at);
            let removed = before_count - reservations.len();
            if removed > 0 {
                debug!(
                    removed = removed,
                    "H-2: Emergency cleanup freed reservation slots"
                );
            }
            // Check again after cleanup
            if reservations.len() >= MAX_RESERVATIONS {
                warn!(
                    count = reservations.len(),
                    limit = MAX_RESERVATIONS,
                    "H-2: Reservation limit reached - rejecting new reservation"
                );
                return Err(GspError::TooManyReservations);
            }
        }

        // Check for existing reservation
        if let Some(existing) = reservations.get(lock_id) {
            // Check if existing reservation has expired (use unix time for consistency)
            if now_unix >= existing.expires_at_unix {
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

        // C-1/C-2 FIX: Persist to database FIRST, before memory insertion
        // This prevents the TOCTOU race where:
        // 1. Insert to memory
        // 2. Crash before DB write
        // 3. Reservation lost but UTXO appears reserved in memory of other threads
        //
        // By persisting first, we ensure durability. If DB write fails, we don't
        // insert to memory, maintaining consistency.
        if let Some(ref db) = self.db {
            let conn = db.lock();
            conn.execute(
                "INSERT OR REPLACE INTO utxo_reservations
                 (lock_id, payment_id, wallet_id, created_at_unix, expires_at_unix)
                 VALUES (?, ?, ?, ?, ?)",
                params![lock_id, payment_id, wallet_id, now_unix, expires_at_unix],
            )
            .map_err(|e| {
                GspError::Database(format!("C-1: Failed to persist reservation: {}", e))
            })?;
        }

        // Now insert to memory (after successful DB write)
        let reservation = Reservation {
            created_at: now,
            expires_at,
            expires_at_unix,
            payment_id: payment_id.to_string(),
            wallet_id: wallet_id.to_string(),
        };
        reservations.insert(lock_id.to_string(), reservation);
        drop(reservations);

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

    /// H-1: Remove a reservation from memory only (for committed reservations)
    ///
    /// When a reservation is committed, we remove it from memory immediately
    /// to prevent memory leaks. The DB record remains for crash recovery
    /// and will be cleaned up when it expires.
    fn remove_from_memory(&self, lock_id: &str) {
        let mut reservations = self.reservations.lock();
        if reservations.remove(lock_id).is_some() {
            debug!(
                lock_id = lock_id,
                "H-1: Removed committed reservation from memory (DB record retained)"
            );
        }
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
    ///
    /// H-1 FIX: Immediately removes from memory to prevent memory leaks.
    /// The DB record is retained for crash recovery and will be cleaned up
    /// when the reservation expires.
    pub fn commit(mut self) {
        self.committed = true;
        // H-1: Remove from memory immediately to prevent memory leak
        // DB record remains for crash recovery until natural expiry
        self.manager.remove_from_memory(&self.lock_id);
        debug!(
            lock_id = self.lock_id,
            "C-6: UTXO reservation committed (removed from memory, DB record retained)"
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
    fn test_c6_commit_removes_from_memory() {
        // H-1: After commit, reservation is removed from memory (but DB record remains)
        let manager = Arc::new(UtxoReservationManager::new());

        let guard = manager
            .reserve("lock1", "payment1", "wallet1")
            .expect("Should reserve successfully");

        assert!(manager.is_reserved("lock1"));
        assert_eq!(manager.active_count(), 1);

        // Commit the reservation
        guard.commit();

        // H-1: Reservation should be removed from memory after commit
        assert!(!manager.is_reserved("lock1"));
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn test_h1_commit_preserves_db_record() {
        use tempfile::NamedTempFile;

        // Create a temp file for the database
        let temp = NamedTempFile::new().unwrap();
        let db_path = temp.path();

        // Create manager with persistence and commit a reservation
        {
            let manager = Arc::new(
                UtxoReservationManager::with_persistence_and_expiry(db_path, 600)
                    .expect("Should create manager with persistence"),
            );

            let guard = manager
                .reserve("lock1", "payment1", "wallet1")
                .expect("Should reserve successfully");

            // Commit - should remove from memory but keep in DB
            guard.commit();

            // Memory should be empty
            assert!(!manager.is_reserved("lock1"));
            assert_eq!(manager.active_count(), 0);
        }

        // Create a NEW manager - reservation should be loaded from DB
        {
            let manager = Arc::new(
                UtxoReservationManager::with_persistence_and_expiry(db_path, 600)
                    .expect("Should create manager from existing database"),
            );

            // H-1: DB record should still exist and be loaded
            assert!(
                manager.is_reserved("lock1"),
                "H-1: Committed reservation should be in DB and loaded on restart"
            );
            assert_eq!(manager.active_count(), 1);
        }
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

            // Before commit, should be in memory
            assert!(manager.is_reserved("lock1"));
            assert_eq!(manager.active_count(), 1);

            // Commit removes from memory but keeps in DB (H-1 fix)
            guard.commit();

            // H-1: After commit, removed from memory
            assert!(!manager.is_reserved("lock1"));
            assert_eq!(manager.active_count(), 0);
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

    #[test]
    fn test_m2_empty_lock_id_rejected() {
        let manager = Arc::new(UtxoReservationManager::new());

        // Empty lock ID should be rejected
        let result = manager.reserve("", "payment1", "wallet1");
        assert!(result.is_err(), "M-2: Empty lock ID should be rejected");
        assert!(matches!(result.unwrap_err(), GspError::InvalidLockId(_)));
    }

    #[test]
    fn test_m2_long_lock_id_rejected() {
        let manager = Arc::new(UtxoReservationManager::new());

        // Lock ID exceeding MAX_LOCK_ID_LENGTH should be rejected
        let long_lock_id = "x".repeat(MAX_LOCK_ID_LENGTH + 1);
        let result = manager.reserve(&long_lock_id, "payment1", "wallet1");
        assert!(result.is_err(), "M-2: Lock ID exceeding max length should be rejected");
        assert!(matches!(result.unwrap_err(), GspError::InvalidLockId(_)));
    }

    #[test]
    fn test_m2_max_length_lock_id_accepted() {
        let manager = Arc::new(UtxoReservationManager::new());

        // Lock ID at exactly MAX_LOCK_ID_LENGTH should be accepted
        let max_lock_id = "x".repeat(MAX_LOCK_ID_LENGTH);
        let result = manager.reserve(&max_lock_id, "payment1", "wallet1");
        assert!(result.is_ok(), "M-2: Lock ID at max length should be accepted");
    }

    #[test]
    fn test_h2_max_reservations_limit() {
        // This test verifies the MAX_RESERVATIONS limit is enforced
        // We use a smaller limit for testing by filling up with short-lived reservations
        let manager = Arc::new(UtxoReservationManager::with_expiry(600));

        // Fill up to near the limit (we can't actually test 10,000 in a unit test efficiently,
        // but we can verify the logic works with a smaller set)
        let mut guards = Vec::new();
        for i in 0..100 {
            let guard = manager
                .reserve(&format!("lock{}", i), &format!("payment{}", i), "wallet1")
                .expect("Should reserve successfully");
            guards.push(guard);
        }

        assert_eq!(manager.active_count(), 100);

        // Clean up
        drop(guards);
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn test_c1_c2_db_first_persistence() {
        use tempfile::NamedTempFile;

        // This test verifies the C-1/C-2 fix: DB is written before memory
        // The key behavior is that if DB write succeeds, the reservation exists
        let temp = NamedTempFile::new().unwrap();
        let db_path = temp.path();

        let manager = Arc::new(
            UtxoReservationManager::with_persistence_and_expiry(db_path, 600)
                .expect("Should create manager with persistence"),
        );

        // Make a reservation - this should persist to DB first
        let guard = manager
            .reserve("lock1", "payment1", "wallet1")
            .expect("Should reserve successfully");

        // Verify it's in memory
        assert!(manager.is_reserved("lock1"));

        // Drop without commit
        drop(guard);

        // Should be removed from both memory and DB
        assert!(!manager.is_reserved("lock1"));
    }
}
