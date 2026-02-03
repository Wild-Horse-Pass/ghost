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
//| FILE: database.rs                                                                                                    |
//|======================================================================================================================|

//! Database connection and management

use parking_lot::Mutex;
use rusqlite::{Connection, OpenFlags};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::{debug, info, warn};

use ghost_common::error::{GhostError, GhostResult};

/// Configuration for database retry behavior
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Initial backoff delay in milliseconds
    pub initial_backoff_ms: u64,
    /// Maximum backoff delay in milliseconds
    pub max_backoff_ms: u64,
    /// Backoff multiplier (exponential factor)
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            initial_backoff_ms: 10,
            max_backoff_ms: 1000,
            backoff_multiplier: 2.0,
        }
    }
}

impl RetryConfig {
    /// Create a config for aggressive retries (more attempts, longer waits)
    pub fn aggressive() -> Self {
        Self {
            max_retries: 10,
            initial_backoff_ms: 50,
            max_backoff_ms: 5000,
            backoff_multiplier: 2.0,
        }
    }

    /// Create a config for quick operations (fewer retries, shorter waits)
    pub fn quick() -> Self {
        Self {
            max_retries: 3,
            initial_backoff_ms: 5,
            max_backoff_ms: 100,
            backoff_multiplier: 2.0,
        }
    }
}

/// Check if a database error is transient and should be retried
fn is_transient_error(error: &GhostError) -> bool {
    match error {
        GhostError::Database(msg) => {
            // SQLite error codes that are transient
            let transient_patterns = [
                "database is locked",
                "SQLITE_BUSY",
                "SQLITE_LOCKED",
                "database table is locked",
                "cannot start a transaction within a transaction",
                "disk I/O error",
            ];
            transient_patterns
                .iter()
                .any(|pattern| msg.contains(pattern))
        }
        _ => false,
    }
}

/// Execute a fallible operation with retry logic
fn retry_with_backoff<F, T>(config: &RetryConfig, operation_name: &str, mut f: F) -> GhostResult<T>
where
    F: FnMut() -> GhostResult<T>,
{
    let mut attempt = 0;
    let mut backoff_ms = config.initial_backoff_ms;

    loop {
        match f() {
            Ok(result) => return Ok(result),
            Err(e) if is_transient_error(&e) && attempt < config.max_retries => {
                attempt += 1;
                warn!(
                    operation = operation_name,
                    attempt,
                    max_retries = config.max_retries,
                    backoff_ms,
                    error = %e,
                    "Transient database error, retrying"
                );
                thread::sleep(Duration::from_millis(backoff_ms));
                backoff_ms = ((backoff_ms as f64 * config.backoff_multiplier) as u64)
                    .min(config.max_backoff_ms);
            }
            Err(e) => {
                if attempt > 0 {
                    warn!(
                        operation = operation_name,
                        attempts = attempt + 1,
                        "Database operation failed after retries"
                    );
                }
                return Err(e);
            }
        }
    }
}

use crate::migrations::run_migrations;

/// Database handle with connection pooling
#[derive(Clone)]
pub struct Database {
    inner: Arc<DatabaseInner>,
}

struct DatabaseInner {
    /// Primary connection (write)
    write_conn: Mutex<Connection>,
    /// Database path
    path: String,
    /// Whether this is an in-memory database
    in_memory: bool,
}

impl Database {
    /// Open a database at the given path
    pub fn open<P: AsRef<Path>>(path: P) -> GhostResult<Self> {
        let path = path.as_ref();
        let path_str = path.to_string_lossy().to_string();

        info!(path = %path_str, "Opening database");

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
        )
        .map_err(|e| GhostError::Database(e.to_string()))?;

        Self::initialize_connection(&conn)?;

        let db = Self {
            inner: Arc::new(DatabaseInner {
                write_conn: Mutex::new(conn),
                path: path_str,
                in_memory: false,
            }),
        };

        // Run migrations
        db.with_connection(run_migrations)?;

        Ok(db)
    }

    /// Create an in-memory database (for testing)
    pub fn in_memory() -> GhostResult<Self> {
        debug!("Creating in-memory database");

        let conn = Connection::open_in_memory().map_err(|e| GhostError::Database(e.to_string()))?;

        Self::initialize_connection(&conn)?;

        let db = Self {
            inner: Arc::new(DatabaseInner {
                write_conn: Mutex::new(conn),
                path: ":memory:".to_string(),
                in_memory: true,
            }),
        };

        // Run migrations
        db.with_connection(run_migrations)?;

        Ok(db)
    }

    /// Initialize connection settings
    fn initialize_connection(conn: &Connection) -> GhostResult<()> {
        // Enable WAL mode for better concurrency
        // Auto-checkpoint when WAL reaches 1000 pages (~4MB with 4KB pages)
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA foreign_keys = ON;
            PRAGMA busy_timeout = 5000;
            PRAGMA cache_size = -64000;
            PRAGMA wal_autocheckpoint = 1000;
            ",
        )
        .map_err(|e| GhostError::Database(format!("Failed to initialize connection: {}", e)))?;

        Ok(())
    }

    /// Execute a function with the database connection
    pub fn with_connection<F, T>(&self, f: F) -> GhostResult<T>
    where
        F: FnOnce(&Connection) -> GhostResult<T>,
    {
        let conn = self.inner.write_conn.lock();
        f(&conn)
    }

    /// Execute a function with the database connection, with retry logic for transient errors
    ///
    /// This is the preferred method for operations that may encounter SQLITE_BUSY
    /// or similar transient errors. Uses the default retry configuration.
    pub fn with_connection_retry<F, T>(&self, operation_name: &str, f: F) -> GhostResult<T>
    where
        F: Fn(&Connection) -> GhostResult<T>,
    {
        self.with_connection_retry_config(operation_name, &RetryConfig::default(), f)
    }

    /// Execute a function with the database connection, with custom retry configuration
    pub fn with_connection_retry_config<F, T>(
        &self,
        operation_name: &str,
        config: &RetryConfig,
        f: F,
    ) -> GhostResult<T>
    where
        F: Fn(&Connection) -> GhostResult<T>,
    {
        retry_with_backoff(config, operation_name, || {
            let conn = self.inner.write_conn.lock();
            f(&conn)
        })
    }

    /// Execute a function with a mutable connection reference
    pub fn with_connection_mut<F, T>(&self, f: F) -> GhostResult<T>
    where
        F: FnOnce(&mut Connection) -> GhostResult<T>,
    {
        let mut conn = self.inner.write_conn.lock();
        f(&mut conn)
    }

    /// Execute a transaction
    pub fn transaction<F, T>(&self, f: F) -> GhostResult<T>
    where
        F: FnOnce(&rusqlite::Transaction) -> GhostResult<T>,
    {
        let mut conn = self.inner.write_conn.lock();
        let tx = conn
            .transaction()
            .map_err(|e| GhostError::Database(e.to_string()))?;

        let result = f(&tx)?;

        tx.commit()
            .map_err(|e| GhostError::Database(e.to_string()))?;

        Ok(result)
    }

    /// Execute a transaction with retry logic for transient errors
    ///
    /// This retries the entire transaction if a transient error occurs.
    /// Uses the default retry configuration.
    pub fn transaction_retry<F, T>(&self, operation_name: &str, f: F) -> GhostResult<T>
    where
        F: Fn(&rusqlite::Transaction) -> GhostResult<T>,
    {
        self.transaction_retry_config(operation_name, &RetryConfig::default(), f)
    }

    /// Execute a transaction with custom retry configuration
    pub fn transaction_retry_config<F, T>(
        &self,
        operation_name: &str,
        config: &RetryConfig,
        f: F,
    ) -> GhostResult<T>
    where
        F: Fn(&rusqlite::Transaction) -> GhostResult<T>,
    {
        retry_with_backoff(config, operation_name, || {
            let mut conn = self.inner.write_conn.lock();
            let tx = conn
                .transaction()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let result = f(&tx)?;

            tx.commit()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(result)
        })
    }

    /// Get the database path
    pub fn path(&self) -> &str {
        &self.inner.path
    }

    /// Check if this is an in-memory database
    pub fn is_in_memory(&self) -> bool {
        self.inner.in_memory
    }

    /// Checkpoint WAL (force writes to main database)
    pub fn checkpoint(&self) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .map_err(|e| GhostError::Database(e.to_string()))
        })
    }

    /// Get database statistics
    pub fn stats(&self) -> GhostResult<DatabaseStats> {
        self.with_connection(|conn| {
            let page_count: i64 = conn
                .query_row("PRAGMA page_count;", [], |row| row.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let page_size: i64 = conn
                .query_row("PRAGMA page_size;", [], |row| row.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let freelist_count: i64 = conn
                .query_row("PRAGMA freelist_count;", [], |row| row.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(DatabaseStats {
                size_bytes: page_count * page_size,
                page_count: page_count as u64,
                page_size: page_size as u64,
                freelist_pages: freelist_count as u64,
            })
        })
    }

    /// Optimize the database (vacuum and analyze)
    pub fn optimize(&self) -> GhostResult<()> {
        info!("Optimizing database");
        self.with_connection(|conn| {
            conn.execute_batch("VACUUM; ANALYZE;")
                .map_err(|e| GhostError::Database(e.to_string()))
        })
    }

    /// Prune old shares from the database
    ///
    /// Deletes shares older than the specified number of rounds.
    /// Returns the number of shares deleted.
    pub fn prune_old_shares(&self, keep_rounds: u64) -> GhostResult<usize> {
        self.with_connection(|conn| {
            // Find the minimum round ID to keep
            let current_round: Option<u64> = conn
                .query_row("SELECT MAX(round_id) FROM rounds", [], |row| row.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let Some(current) = current_round else {
                return Ok(0);
            };

            let min_round_to_keep = current.saturating_sub(keep_rounds);

            let deleted = conn
                .execute(
                    "DELETE FROM shares WHERE round_id < ?1",
                    [min_round_to_keep],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if deleted > 0 {
                info!(deleted, min_round = min_round_to_keep, "Pruned old shares");
            }

            Ok(deleted)
        })
    }

    /// Prune old rounds from the database
    ///
    /// Deletes rounds older than the specified number and their associated data.
    /// Only deletes rounds that are confirmed or orphaned.
    /// Returns the number of rounds deleted.
    pub fn prune_old_rounds(&self, keep_rounds: u64) -> GhostResult<usize> {
        self.with_connection(|conn| {
            // Find the minimum round ID to keep
            let current_round: Option<u64> = conn
                .query_row(
                    "SELECT MAX(round_id) FROM rounds",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let Some(current) = current_round else {
                return Ok(0);
            };

            let min_round_to_keep = current.saturating_sub(keep_rounds);

            // Only delete confirmed or orphaned rounds
            let deleted = conn.execute(
                "DELETE FROM rounds WHERE round_id < ?1 AND payout_status IN ('confirmed', 'orphaned', 'failed')",
                [min_round_to_keep],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            if deleted > 0 {
                info!(
                    deleted,
                    min_round = min_round_to_keep,
                    "Pruned old rounds"
                );
            }

            Ok(deleted)
        })
    }

    /// Prune old health pings
    ///
    /// Deletes health pings older than the specified number of days.
    pub fn prune_old_health_pings(&self, keep_days: u32) -> GhostResult<usize> {
        self.with_connection(|conn| {
            let cutoff = chrono::Utc::now().timestamp() - (keep_days as i64 * 86400);

            let deleted = conn
                .execute("DELETE FROM health_pings WHERE timestamp < ?1", [cutoff])
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if deleted > 0 {
                info!(deleted, keep_days, "Pruned old health pings");
            }

            Ok(deleted)
        })
    }

    /// Prune old vote records
    ///
    /// Deletes vote records for rounds older than the specified number.
    pub fn prune_old_votes(&self, keep_rounds: u64) -> GhostResult<usize> {
        self.with_connection(|conn| {
            let current_round: Option<u64> = conn
                .query_row("SELECT MAX(round_id) FROM rounds", [], |row| row.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let Some(current) = current_round else {
                return Ok(0);
            };

            let min_round_to_keep = current.saturating_sub(keep_rounds);

            let deleted = conn
                .execute("DELETE FROM votes WHERE round_id < ?1", [min_round_to_keep])
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if deleted > 0 {
                info!(deleted, min_round = min_round_to_keep, "Pruned old votes");
            }

            Ok(deleted)
        })
    }

    /// Prune old uptime samples
    ///
    /// Deletes uptime samples older than the specified number of days.
    /// STOR-1: uptime_samples grows ~8,640/day/node without cleanup.
    pub fn prune_old_uptime_samples(&self, keep_days: u32) -> GhostResult<usize> {
        self.with_connection(|conn| {
            let cutoff = chrono::Utc::now().timestamp() - (keep_days as i64 * 86400);

            let deleted = conn
                .execute(
                    "DELETE FROM uptime_samples WHERE sample_time < ?1",
                    [cutoff],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if deleted > 0 {
                info!(deleted, keep_days, "Pruned old uptime samples");
            }

            Ok(deleted)
        })
    }

    /// Prune old challenge results
    ///
    /// Deletes challenge records older than the specified number of days from all
    /// challenge tables: archive_challenges, policy_challenges, stratum_challenges,
    /// and ghostpay_challenges.
    /// STOR-2/3/4/5: Each table grows ~864/day without cleanup.
    pub fn prune_old_challenges(&self, keep_days: u32) -> GhostResult<ChallengesPruneResult> {
        self.with_connection(|conn| {
            let cutoff = chrono::Utc::now().timestamp() - (keep_days as i64 * 86400);

            let archive = conn
                .execute(
                    "DELETE FROM archive_challenges WHERE timestamp < ?1",
                    [cutoff],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let policy = conn
                .execute(
                    "DELETE FROM policy_challenges WHERE timestamp < ?1",
                    [cutoff],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let stratum = conn
                .execute(
                    "DELETE FROM stratum_challenges WHERE timestamp < ?1",
                    [cutoff],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let ghostpay = conn
                .execute(
                    "DELETE FROM ghostpay_challenges WHERE timestamp < ?1",
                    [cutoff],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let total = archive + policy + stratum + ghostpay;
            if total > 0 {
                info!(
                    archive,
                    policy, stratum, ghostpay, keep_days, "Pruned old challenges"
                );
            }

            Ok(ChallengesPruneResult {
                archive,
                policy,
                stratum,
                ghostpay,
            })
        })
    }

    /// Prune old verification records
    ///
    /// Deletes verification records older than the specified number of days.
    /// STOR-6: verifications grows ~864/day without cleanup.
    pub fn prune_old_verifications(&self, keep_days: u32) -> GhostResult<usize> {
        self.with_connection(|conn| {
            let cutoff = chrono::Utc::now().timestamp() - (keep_days as i64 * 86400);

            let deleted = conn
                .execute(
                    "DELETE FROM verifications WHERE completed_at < ?1 OR (completed_at IS NULL AND started_at < ?1)",
                    [cutoff],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if deleted > 0 {
                info!(deleted, keep_days, "Pruned old verifications");
            }

            Ok(deleted)
        })
    }

    /// Run full maintenance (prune + checkpoint + optimize)
    ///
    /// This should be called periodically (e.g., once per hour).
    pub fn run_maintenance(&self, config: MaintenanceConfig) -> GhostResult<MaintenanceResult> {
        info!("Running database maintenance");

        let shares_deleted = self.prune_old_shares(config.keep_rounds)?;
        let rounds_deleted = self.prune_old_rounds(config.keep_rounds)?;
        let pings_deleted = self.prune_old_health_pings(config.keep_health_ping_days)?;
        let votes_deleted = self.prune_old_votes(config.keep_rounds)?;
        let uptime_deleted = self.prune_old_uptime_samples(config.keep_uptime_sample_days)?;
        let challenges_deleted = self.prune_old_challenges(config.keep_challenge_days)?;
        let verifications_deleted = self.prune_old_verifications(config.keep_verification_days)?;

        // Checkpoint WAL
        self.checkpoint()?;

        // Optimize if significant data was deleted
        let total_deleted = shares_deleted
            + rounds_deleted
            + pings_deleted
            + votes_deleted
            + uptime_deleted
            + challenges_deleted.total()
            + verifications_deleted;
        if total_deleted > 1000 || config.force_optimize {
            self.optimize()?;
        }

        let stats = self.stats()?;

        info!(
            shares_deleted,
            rounds_deleted,
            pings_deleted,
            votes_deleted,
            uptime_deleted,
            challenges_deleted = challenges_deleted.total(),
            verifications_deleted,
            db_size_mb = stats.size_mb(),
            "Database maintenance complete"
        );

        Ok(MaintenanceResult {
            shares_deleted,
            rounds_deleted,
            pings_deleted,
            votes_deleted,
            uptime_deleted,
            challenges_deleted,
            verifications_deleted,
            db_size_bytes: stats.size_bytes,
        })
    }
}

/// Configuration for database maintenance
#[derive(Debug, Clone)]
pub struct MaintenanceConfig {
    /// Number of rounds to keep
    pub keep_rounds: u64,
    /// Number of days to keep health pings
    pub keep_health_ping_days: u32,
    /// Number of days to keep uptime samples (STOR-1)
    pub keep_uptime_sample_days: u32,
    /// Number of days to keep challenge results (STOR-2/3/4/5)
    pub keep_challenge_days: u32,
    /// Number of days to keep verification records (STOR-6)
    pub keep_verification_days: u32,
    /// Force optimize even if little was deleted
    pub force_optimize: bool,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            keep_rounds: 1000,          // Keep ~1000 rounds of data
            keep_health_ping_days: 7,   // 7 days of health pings
            keep_uptime_sample_days: 7, // 7 days of uptime samples (STOR-1)
            keep_challenge_days: 30,    // 30 days of challenge results (STOR-2/3/4/5)
            keep_verification_days: 30, // 30 days of verification records (STOR-6)
            force_optimize: false,
        }
    }
}

/// Result of database maintenance
#[derive(Debug, Clone)]
pub struct MaintenanceResult {
    pub shares_deleted: usize,
    pub rounds_deleted: usize,
    pub pings_deleted: usize,
    pub votes_deleted: usize,
    pub uptime_deleted: usize,
    pub challenges_deleted: ChallengesPruneResult,
    pub verifications_deleted: usize,
    pub db_size_bytes: i64,
}

/// Result of pruning challenge tables
#[derive(Debug, Clone, Default)]
pub struct ChallengesPruneResult {
    pub archive: usize,
    pub policy: usize,
    pub stratum: usize,
    pub ghostpay: usize,
}

impl ChallengesPruneResult {
    /// Get total challenges deleted across all tables
    pub fn total(&self) -> usize {
        self.archive + self.policy + self.stratum + self.ghostpay
    }
}

/// Database statistics
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    pub size_bytes: i64,
    pub page_count: u64,
    pub page_size: u64,
    pub freelist_pages: u64,
}

impl DatabaseStats {
    pub fn size_mb(&self) -> f64 {
        self.size_bytes as f64 / (1024.0 * 1024.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn test_in_memory_database() {
        let db = Database::in_memory().unwrap();
        assert!(db.is_in_memory());
    }

    #[test]
    fn test_database_stats() {
        let db = Database::in_memory().unwrap();
        let stats = db.stats().unwrap();
        assert!(stats.page_count > 0);
    }

    #[test]
    fn test_transaction() {
        let db = Database::in_memory().unwrap();

        let result = db.transaction(|tx| {
            // Use a statement that doesn't return results
            tx.execute(
                "CREATE TABLE IF NOT EXISTS test_tx (id INTEGER PRIMARY KEY)",
                [],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(42)
        });

        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_is_transient_error() {
        // Test transient errors
        assert!(is_transient_error(&GhostError::Database(
            "database is locked".to_string()
        )));
        assert!(is_transient_error(&GhostError::Database(
            "SQLITE_BUSY (5)".to_string()
        )));
        assert!(is_transient_error(&GhostError::Database(
            "SQLITE_LOCKED".to_string()
        )));
        assert!(is_transient_error(&GhostError::Database(
            "database table is locked".to_string()
        )));

        // Test non-transient errors
        assert!(!is_transient_error(&GhostError::Database(
            "syntax error".to_string()
        )));
        assert!(!is_transient_error(&GhostError::Database(
            "no such table".to_string()
        )));
        assert!(!is_transient_error(&GhostError::Internal(
            "some error".to_string()
        )));
    }

    #[test]
    fn test_retry_succeeds_after_transient_errors() {
        let attempt_count = AtomicU32::new(0);
        let config = RetryConfig {
            max_retries: 3,
            initial_backoff_ms: 1,
            max_backoff_ms: 10,
            backoff_multiplier: 2.0,
        };

        let result = retry_with_backoff(&config, "test_op", || {
            let count = attempt_count.fetch_add(1, Ordering::SeqCst);
            if count < 2 {
                Err(GhostError::Database("database is locked".to_string()))
            } else {
                Ok(42)
            }
        });

        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempt_count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_retry_fails_after_max_retries() {
        let attempt_count = AtomicU32::new(0);
        let config = RetryConfig {
            max_retries: 2,
            initial_backoff_ms: 1,
            max_backoff_ms: 10,
            backoff_multiplier: 2.0,
        };

        let result: GhostResult<i32> = retry_with_backoff(&config, "test_op", || {
            attempt_count.fetch_add(1, Ordering::SeqCst);
            Err(GhostError::Database("database is locked".to_string()))
        });

        assert!(result.is_err());
        // Initial attempt + 2 retries = 3 total
        assert_eq!(attempt_count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_retry_does_not_retry_non_transient_errors() {
        let attempt_count = AtomicU32::new(0);
        let config = RetryConfig::default();

        let result: GhostResult<i32> = retry_with_backoff(&config, "test_op", || {
            attempt_count.fetch_add(1, Ordering::SeqCst);
            Err(GhostError::Database("syntax error".to_string()))
        });

        assert!(result.is_err());
        // Should not retry, only 1 attempt
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_with_connection_retry() {
        let db = Database::in_memory().unwrap();

        // Create a test table
        db.with_connection(|conn| {
            conn.execute(
                "CREATE TABLE IF NOT EXISTS retry_test (id INTEGER PRIMARY KEY, val INTEGER)",
                [],
            )
            .map_err(|e| GhostError::Database(e.to_string()))
        })
        .unwrap();

        // Test retry method works for normal operations
        let result = db.with_connection_retry("insert_test", |conn| {
            conn.execute("INSERT INTO retry_test (val) VALUES (42)", [])
                .map_err(|e| GhostError::Database(e.to_string()))
        });

        assert!(result.is_ok());
    }

    #[test]
    fn test_transaction_retry() {
        let db = Database::in_memory().unwrap();

        // Create a test table
        db.with_connection(|conn| {
            conn.execute(
                "CREATE TABLE IF NOT EXISTS tx_retry_test (id INTEGER PRIMARY KEY, val INTEGER)",
                [],
            )
            .map_err(|e| GhostError::Database(e.to_string()))
        })
        .unwrap();

        // Test retry method works for transactions
        let result = db.transaction_retry("tx_test", |tx| {
            tx.execute("INSERT INTO tx_retry_test (val) VALUES (1)", [])
                .map_err(|e| GhostError::Database(e.to_string()))?;
            tx.execute("INSERT INTO tx_retry_test (val) VALUES (2)", [])
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        });

        assert!(result.is_ok());

        // Verify both inserts happened
        let count: i64 = db
            .with_connection(|conn| {
                conn.query_row("SELECT COUNT(*) FROM tx_retry_test", [], |row| row.get(0))
                    .map_err(|e| GhostError::Database(e.to_string()))
            })
            .unwrap();

        assert_eq!(count, 2);
    }

    #[test]
    fn test_retry_config_presets() {
        let default = RetryConfig::default();
        assert_eq!(default.max_retries, 5);

        let aggressive = RetryConfig::aggressive();
        assert_eq!(aggressive.max_retries, 10);
        assert!(aggressive.max_backoff_ms > default.max_backoff_ms);

        let quick = RetryConfig::quick();
        assert_eq!(quick.max_retries, 3);
        assert!(quick.max_backoff_ms < default.max_backoff_ms);
    }
}
