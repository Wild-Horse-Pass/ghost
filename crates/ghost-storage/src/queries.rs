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
//| FILE: queries.rs                                                                                                     |
//|======================================================================================================================|

//! Database query operations

use rusqlite::{params, Connection, OptionalExtension};

use ghost_common::error::{GhostError, GhostResult};

use crate::database::Database;
use crate::models::*;

// =============================================================================
// SHARE QUERIES
// =============================================================================

impl Database {
    /// Insert a new share
    pub fn insert_share(&self, share: &ShareRecord) -> GhostResult<i64> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO shares (round_id, miner_id, difficulty, work, share_hash, timestamp, received_by, valid)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    share.round_id,
                    share.miner_id,
                    share.difficulty,
                    share.work,
                    share.share_hash,
                    share.timestamp,
                    share.received_by,
                    share.valid,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(conn.last_insert_rowid())
        })
    }

    /// Get shares for a round
    pub fn get_shares_by_round(&self, round_id: u64) -> GhostResult<Vec<ShareRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, round_id, miner_id, difficulty, work, share_hash, timestamp, received_by, valid
                     FROM shares WHERE round_id = ?1 ORDER BY timestamp",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let shares = stmt
                .query_map([round_id], |row| {
                    Ok(ShareRecord {
                        id: Some(row.get(0)?),
                        round_id: row.get(1)?,
                        miner_id: row.get(2)?,
                        difficulty: row.get(3)?,
                        work: row.get(4)?,
                        share_hash: row.get(5)?,
                        timestamp: row.get(6)?,
                        received_by: row.get(7)?,
                        valid: row.get(8)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(shares)
        })
    }

    /// Get miner shares for a round
    pub fn get_miner_shares(&self, round_id: u64, miner_id: &str) -> GhostResult<Vec<ShareRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, round_id, miner_id, difficulty, work, share_hash, timestamp, received_by, valid
                     FROM shares WHERE round_id = ?1 AND miner_id = ?2 ORDER BY timestamp",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let shares = stmt
                .query_map([round_id.to_string(), miner_id.to_string()], |row| {
                    Ok(ShareRecord {
                        id: Some(row.get(0)?),
                        round_id: row.get(1)?,
                        miner_id: row.get(2)?,
                        difficulty: row.get(3)?,
                        work: row.get(4)?,
                        share_hash: row.get(5)?,
                        timestamp: row.get(6)?,
                        received_by: row.get(7)?,
                        valid: row.get(8)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(shares)
        })
    }

    /// Get total work for a miner in a round
    pub fn get_miner_work(&self, round_id: u64, miner_id: &str) -> GhostResult<f64> {
        self.with_connection(|conn| {
            let work: f64 = conn
                .query_row(
                    "SELECT COALESCE(SUM(work), 0) FROM shares WHERE round_id = ?1 AND miner_id = ?2 AND valid = 1",
                    params![round_id, miner_id],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(work)
        })
    }

    /// Get all miners with work in a round
    pub fn get_round_miners(&self, round_id: u64) -> GhostResult<Vec<(String, f64)>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT miner_id, SUM(work) as total_work
                     FROM shares WHERE round_id = ?1 AND valid = 1
                     GROUP BY miner_id ORDER BY total_work DESC",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let miners = stmt
                .query_map([round_id], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(miners)
        })
    }

    /// Search miners by ID/address (partial match) and get their stats
    pub fn search_miners(&self, query: &str) -> GhostResult<Vec<MinerSearchResult>> {
        self.with_connection(|conn| {
            let search_pattern = format!("%{}%", query);
            let mut stmt = conn
                .prepare(
                    "SELECT
                        miner_id,
                        COUNT(*) as total_shares,
                        SUM(work) as total_work,
                        SUM(CASE WHEN valid = 1 THEN 1 ELSE 0 END) as valid_shares,
                        MIN(timestamp) as first_seen,
                        MAX(timestamp) as last_seen,
                        AVG(difficulty) as avg_difficulty
                     FROM shares
                     WHERE miner_id LIKE ?1
                     GROUP BY miner_id
                     ORDER BY total_work DESC
                     LIMIT 50",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let results = stmt
                .query_map([&search_pattern], |row| {
                    Ok(MinerSearchResult {
                        miner_id: row.get(0)?,
                        total_shares: row.get(1)?,
                        total_work: row.get(2)?,
                        valid_shares: row.get(3)?,
                        first_seen: row.get(4)?,
                        last_seen: row.get(5)?,
                        avg_difficulty: row.get(6)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(results)
        })
    }

    /// Get detailed stats for a specific miner
    pub fn get_miner_stats(&self, miner_id: &str) -> GhostResult<Option<MinerDetailedStats>> {
        self.with_connection(|conn| {
            // Get aggregate stats
            let stats: Option<MinerDetailedStats> = conn
                .query_row(
                    "SELECT
                        miner_id,
                        COUNT(*) as total_shares,
                        SUM(work) as total_work,
                        SUM(CASE WHEN valid = 1 THEN 1 ELSE 0 END) as valid_shares,
                        SUM(CASE WHEN valid = 0 THEN 1 ELSE 0 END) as invalid_shares,
                        MIN(timestamp) as first_seen,
                        MAX(timestamp) as last_seen,
                        AVG(difficulty) as avg_difficulty,
                        COUNT(DISTINCT round_id) as rounds_participated
                     FROM shares
                     WHERE miner_id = ?1
                     GROUP BY miner_id",
                    params![miner_id],
                    |row| {
                        Ok(MinerDetailedStats {
                            miner_id: row.get(0)?,
                            total_shares: row.get(1)?,
                            total_work: row.get(2)?,
                            valid_shares: row.get(3)?,
                            invalid_shares: row.get(4)?,
                            first_seen: row.get(5)?,
                            last_seen: row.get(6)?,
                            avg_difficulty: row.get(7)?,
                            rounds_participated: row.get(8)?,
                            recent_shares: vec![],
                        })
                    },
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            // Get recent shares if miner exists
            if let Some(mut stats) = stats {
                let mut stmt = conn
                    .prepare(
                        "SELECT round_id, difficulty, work, timestamp, valid
                         FROM shares WHERE miner_id = ?1
                         ORDER BY timestamp DESC LIMIT 10",
                    )
                    .map_err(|e| GhostError::Database(e.to_string()))?;

                let recent = stmt
                    .query_map([miner_id], |row| {
                        Ok(RecentShare {
                            round_id: row.get(0)?,
                            difficulty: row.get(1)?,
                            work: row.get(2)?,
                            timestamp: row.get(3)?,
                            valid: row.get(4)?,
                        })
                    })
                    .map_err(|e| GhostError::Database(e.to_string()))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| GhostError::Database(e.to_string()))?;

                stats.recent_shares = recent;
                Ok(Some(stats))
            } else {
                Ok(None)
            }
        })
    }
}

// =============================================================================
// ROUND QUERIES
// =============================================================================

impl Database {
    /// Create a new round
    pub fn create_round(&self, round: &RoundRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO rounds (round_id, block_height, start_time, payout_status)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    round.round_id,
                    round.block_height,
                    round.start_time,
                    round.payout_status.as_str(),
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get a round by ID
    pub fn get_round(&self, round_id: u64) -> GhostResult<Option<RoundRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT round_id, block_height, block_hash, start_time, end_time,
                            total_shares, total_work, winning_miner, found_by_node,
                            payout_status, subsidy_sats, tx_fees_sats
                     FROM rounds WHERE round_id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let round = stmt
                .query_row([round_id], |row| {
                    let status_str: String = row.get(9)?;
                    Ok(RoundRecord {
                        round_id: row.get(0)?,
                        block_height: row.get(1)?,
                        block_hash: row.get(2)?,
                        start_time: row.get(3)?,
                        end_time: row.get(4)?,
                        total_shares: row.get(5)?,
                        total_work: row.get(6)?,
                        winning_miner: row.get(7)?,
                        found_by_node: row.get(8)?,
                        payout_status: PayoutStatus::from_str(&status_str)
                            .unwrap_or(PayoutStatus::Active),
                        subsidy_sats: row.get(10)?,
                        tx_fees_sats: row.get(11)?,
                    })
                })
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(round)
        })
    }

    /// Update round with block found
    pub fn update_round_block_found(
        &self,
        round_id: u64,
        block_hash: &str,
        winning_miner: &str,
        found_by_node: &str,
        subsidy_sats: u64,
        tx_fees_sats: u64,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE rounds SET
                    block_hash = ?1, winning_miner = ?2, found_by_node = ?3,
                    subsidy_sats = ?4, tx_fees_sats = ?5, payout_status = 'pending'
                 WHERE round_id = ?6",
                params![
                    block_hash,
                    winning_miner,
                    found_by_node,
                    subsidy_sats,
                    tx_fees_sats,
                    round_id
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// End a round
    pub fn end_round(&self, round_id: u64, end_time: i64) -> GhostResult<()> {
        self.with_connection(|conn| {
            // Update round totals
            conn.execute(
                "UPDATE rounds SET
                    end_time = ?1,
                    total_shares = (SELECT COUNT(*) FROM shares WHERE round_id = ?2 AND valid = 1),
                    total_work = (SELECT COALESCE(SUM(work), 0) FROM shares WHERE round_id = ?2 AND valid = 1)
                 WHERE round_id = ?2",
                params![end_time, round_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update round payout status
    pub fn update_round_status(&self, round_id: u64, status: PayoutStatus) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE rounds SET payout_status = ?1 WHERE round_id = ?2",
                params![status.as_str(), round_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Mark rounds as orphaned by block hash (called on reorg)
    ///
    /// Returns the number of rounds affected.
    /// Only affects rounds that haven't been confirmed yet.
    pub fn mark_rounds_orphaned_by_hash(&self, block_hash: &str) -> GhostResult<usize> {
        self.with_connection(|conn| {
            // Only orphan rounds that are pending/approved/broadcast - not already confirmed
            let affected = conn
                .execute(
                    "UPDATE rounds SET payout_status = 'orphaned'
                 WHERE block_hash = ?1
                   AND payout_status IN ('pending', 'approved', 'broadcast')",
                    params![block_hash],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(affected)
        })
    }

    /// Get rounds by block hash
    pub fn get_rounds_by_block_hash(&self, block_hash: &str) -> GhostResult<Vec<RoundRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT round_id, block_height, block_hash, start_time, end_time,
                            total_shares, total_work, winning_miner, found_by_node,
                            payout_status, subsidy_sats, tx_fees_sats
                     FROM rounds WHERE block_hash = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rounds = stmt
                .query_map([block_hash], |row| {
                    let status_str: String = row.get(9)?;
                    Ok(RoundRecord {
                        round_id: row.get(0)?,
                        block_height: row.get(1)?,
                        block_hash: row.get(2)?,
                        start_time: row.get(3)?,
                        end_time: row.get(4)?,
                        total_shares: row.get(5)?,
                        total_work: row.get(6)?,
                        winning_miner: row.get(7)?,
                        found_by_node: row.get(8)?,
                        payout_status: PayoutStatus::from_str(&status_str)
                            .unwrap_or(PayoutStatus::Active),
                        subsidy_sats: row.get(10)?,
                        tx_fees_sats: row.get(11)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(rounds)
        })
    }

    /// Get recent rounds
    pub fn get_recent_rounds(&self, limit: u32) -> GhostResult<Vec<RoundRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT round_id, block_height, block_hash, start_time, end_time,
                            total_shares, total_work, winning_miner, found_by_node,
                            payout_status, subsidy_sats, tx_fees_sats
                     FROM rounds ORDER BY round_id DESC LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rounds = stmt
                .query_map([limit], |row| {
                    let status_str: String = row.get(9)?;
                    Ok(RoundRecord {
                        round_id: row.get(0)?,
                        block_height: row.get(1)?,
                        block_hash: row.get(2)?,
                        start_time: row.get(3)?,
                        end_time: row.get(4)?,
                        total_shares: row.get(5)?,
                        total_work: row.get(6)?,
                        winning_miner: row.get(7)?,
                        found_by_node: row.get(8)?,
                        payout_status: PayoutStatus::from_str(&status_str)
                            .unwrap_or(PayoutStatus::Active),
                        subsidy_sats: row.get(10)?,
                        tx_fees_sats: row.get(11)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(rounds)
        })
    }
}

// =============================================================================
// NODE QUERIES
// =============================================================================

impl Database {
    /// Upsert a node record
    pub fn upsert_node(&self, node: &NodeRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO nodes (node_id, public_address, display_name, first_seen, last_seen,
                                   is_elder, elder_order, capabilities, payout_address)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(node_id) DO UPDATE SET
                    public_address = COALESCE(?2, public_address),
                    display_name = COALESCE(?3, display_name),
                    last_seen = ?5,
                    is_elder = ?6,
                    elder_order = ?7,
                    capabilities = ?8,
                    payout_address = COALESCE(?9, payout_address)",
                params![
                    node.node_id,
                    node.public_address,
                    node.display_name,
                    node.first_seen,
                    node.last_seen,
                    node.is_elder,
                    node.elder_order,
                    node.capabilities,
                    node.payout_address,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get a node by ID
    pub fn get_node(&self, node_id: &str) -> GhostResult<Option<NodeRecord>> {
        self.with_connection(|conn| get_node_internal(conn, node_id))
    }

    /// Get all elders (ordered by registration)
    pub fn get_elders(&self) -> GhostResult<Vec<NodeRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT node_id, public_address, display_name, first_seen, last_seen,
                            is_elder, elder_order, capabilities, total_uptime_secs,
                            uptime_7d_percent, verification_pass_rate, total_shares_received,
                            total_blocks_found, payout_address
                     FROM nodes WHERE is_elder = 1 ORDER BY elder_order",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let nodes = stmt
                .query_map([], node_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(nodes)
        })
    }

    /// Get all node IDs with payout addresses
    ///
    /// Returns node IDs from the nodes table that have a payout address configured.
    /// Used for payout calculations to include all registered nodes.
    pub fn get_all_node_ids_with_payout(&self) -> GhostResult<Vec<String>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT node_id FROM nodes WHERE payout_address IS NOT NULL AND payout_address != ''",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let node_ids = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(node_ids)
        })
    }

    /// Get top N nodes by shares received
    pub fn get_top_nodes_by_shares(&self, limit: u32) -> GhostResult<Vec<NodeRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT node_id, public_address, display_name, first_seen, last_seen,
                            is_elder, elder_order, capabilities, total_uptime_secs,
                            uptime_7d_percent, verification_pass_rate, total_shares_received,
                            total_blocks_found, payout_address
                     FROM nodes ORDER BY total_shares_received DESC LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let nodes = stmt
                .query_map([limit], node_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(nodes)
        })
    }

    /// Update node last seen timestamp
    pub fn update_node_last_seen(&self, node_id: &str, timestamp: i64) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE nodes SET last_seen = ?1 WHERE node_id = ?2",
                params![timestamp, node_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Register a node and check if it should be an elder
    /// Returns (is_elder, elder_order) - elder_order is Some(n) if node is elder
    ///
    /// Uses deterministic elder selection: lowest node_id (lexicographically) wins ties.
    /// This prevents race conditions at genesis where multiple nodes register simultaneously.
    ///
    /// **Sybil Resistance**: Nodes must provide valid PoW proof to be eligible for elder status.
    /// Call `register_node_with_elder_check_and_pow` for the full-featured version.
    ///
    /// The algorithm:
    /// 1. Insert the node if it doesn't exist (IGNORE on conflict)
    /// 2. Within an IMMEDIATE transaction (exclusive write lock):
    ///    - Count current elders
    ///    - If < MAX_ELDERS, promote eligible non-elder nodes by node_id order
    /// 3. Return the node's final elder status
    pub fn register_node_with_elder_check(
        &self,
        node_id: &str,
        public_address: Option<&str>,
        display_name: Option<&str>,
        capabilities: &str,
    ) -> GhostResult<(bool, Option<u32>)> {
        // Delegate to the version with PoW (using None for backwards compatibility)
        self.register_node_with_elder_check_and_pow(
            node_id,
            public_address,
            display_name,
            capabilities,
            None,
        )
    }

    /// Register a node with PoW proof for Sybil-resistant elder eligibility
    ///
    /// **IMPORTANT**: Nodes without valid PoW proofs will NOT be eligible for elder status.
    /// This prevents Sybil attacks where attackers generate many node_ids to capture elder slots.
    ///
    /// Uses deterministic elder selection: lowest node_id (lexicographically) wins ties.
    /// This prevents race conditions at genesis where multiple nodes register simultaneously.
    ///
    /// This is safe because:
    /// - IMMEDIATE transaction takes write lock before reading
    /// - Elder promotion is deterministic (by node_id)
    /// - Same result regardless of registration order
    pub fn register_node_with_elder_check_and_pow(
        &self,
        node_id: &str,
        public_address: Option<&str>,
        display_name: Option<&str>,
        capabilities: &str,
        pow_proof: Option<&str>,
    ) -> GhostResult<(bool, Option<u32>)> {
        use ghost_common::identity::{verify_node_id_pow_hex, NODE_ID_POW_DIFFICULTY};

        let now = chrono::Utc::now().timestamp();
        let max_elders = ghost_common::constants::MAX_ELDERS;

        // Verify PoW if provided
        let has_valid_pow = if let Some(proof) = pow_proof {
            verify_node_id_pow_hex(node_id, proof, NODE_ID_POW_DIFFICULTY)
        } else {
            false
        };

        self.with_connection(|conn| {
            // Step 1: Insert node if not exists (doesn't need transaction)
            conn.execute(
                "INSERT OR IGNORE INTO nodes (node_id, public_address, display_name, first_seen, last_seen,
                                              is_elder, elder_order, capabilities, pow_proof)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, NULL, ?6, ?7)",
                params![
                    node_id,
                    public_address,
                    display_name,
                    now,
                    now,
                    capabilities,
                    pow_proof,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            // Update last_seen and pow_proof if node already existed
            conn.execute(
                "UPDATE nodes SET last_seen = ?1, public_address = COALESCE(?2, public_address),
                                  pow_proof = COALESCE(?3, pow_proof)
                 WHERE node_id = ?4",
                params![now, public_address, pow_proof, node_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            // Step 2: Atomic elder promotion with IMMEDIATE transaction (write lock)
            // This ensures deterministic elder selection even with concurrent registrations
            conn.execute("BEGIN IMMEDIATE", [])
                .map_err(|e| GhostError::Database(format!("Failed to begin transaction: {}", e)))?;

            let result = (|| -> GhostResult<(bool, Option<u32>)> {
                // Count current elders
                let elder_count: u32 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM nodes WHERE is_elder = 1",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(|e| GhostError::Database(e.to_string()))?;

                // If we have room for more elders, promote by node_id order (deterministic)
                // SYBIL RESISTANCE: Only nodes with valid PoW are eligible for elder status
                if elder_count < max_elders {
                    let slots_available = max_elders - elder_count;

                    // Promote non-elder nodes with lowest node_ids first
                    // BUT only if they have a valid PoW proof!
                    // (pow_proof IS NOT NULL means they submitted a proof - validated on insert)
                    conn.execute(
                        "UPDATE nodes SET is_elder = 1, elder_order = (
                            SELECT COUNT(*) + 1 FROM nodes n2 WHERE n2.is_elder = 1
                        )
                        WHERE node_id IN (
                            SELECT node_id FROM nodes
                            WHERE is_elder = 0 AND pow_proof IS NOT NULL
                            ORDER BY node_id ASC
                            LIMIT ?1
                        )",
                        params![slots_available],
                    )
                    .map_err(|e| GhostError::Database(e.to_string()))?;
                }

                // Fetch final status for this node
                let (is_elder, elder_order): (bool, Option<u32>) = conn
                    .query_row(
                        "SELECT is_elder, elder_order FROM nodes WHERE node_id = ?1",
                        [node_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .map_err(|e| GhostError::Database(e.to_string()))?;

                // Log warning if node could have been elder but lacks PoW
                if !is_elder && !has_valid_pow && elder_count < max_elders {
                    tracing::warn!(
                        node_id = %&node_id[..8.min(node_id.len())],
                        "Node not eligible for elder status: missing or invalid proof-of-work"
                    );
                }

                Ok((is_elder, elder_order))
            })();

            // Commit or rollback based on result
            match &result {
                Ok(_) => {
                    conn.execute("COMMIT", [])
                        .map_err(|e| GhostError::Database(format!("Failed to commit: {}", e)))?;
                }
                Err(_) => {
                    let _ = conn.execute("ROLLBACK", []);
                }
            }

            result
        })
    }

    /// Get elder status for a node (queries database)
    /// Returns (is_elder, elder_order)
    pub fn get_node_elder_status(&self, node_id: &str) -> GhostResult<(bool, Option<u32>)> {
        self.with_connection(|conn| {
            let result: Option<(bool, Option<u32>)> = conn
                .query_row(
                    "SELECT is_elder, elder_order FROM nodes WHERE node_id = ?1",
                    [node_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(result.unwrap_or((false, None)))
        })
    }

    // =========================================================================
    // ELDER BOND MANAGEMENT (Nothing-at-Stake Prevention)
    // =========================================================================

    /// Minimum bond required to be eligible as an elder (0.001 BTC = 100k sats)
    /// This is enough to have skin in the game without being prohibitive
    pub const MIN_ELDER_BOND_SATS: u64 = 100_000;

    /// Register an elder bond UTXO
    /// The bond must be confirmed before the node becomes eligible for elder status
    pub fn register_elder_bond(
        &self,
        node_id: &str,
        txid: &str,
        vout: u32,
        amount_sats: u64,
        script_pubkey: &str,
    ) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();

        self.with_connection(|conn| {
            // Insert or update the bond
            conn.execute(
                "INSERT INTO elder_bonds (node_id, txid, vout, amount_sats, script_pubkey, status, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?7)
                 ON CONFLICT(node_id) DO UPDATE SET
                     txid = excluded.txid,
                     vout = excluded.vout,
                     amount_sats = excluded.amount_sats,
                     script_pubkey = excluded.script_pubkey,
                     status = 'pending',
                     confirmation_height = NULL,
                     spent_txid = NULL,
                     updated_at = excluded.updated_at",
                params![node_id, txid, vout, amount_sats, script_pubkey, now, now],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            // Also update the node's elder_bond_sats and elder_bond_txid
            conn.execute(
                "UPDATE nodes SET elder_bond_sats = ?1, elder_bond_txid = ?2 WHERE node_id = ?3",
                params![amount_sats, txid, node_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            tracing::info!(
                node_id = %&node_id[..8.min(node_id.len())],
                txid = %&txid[..16.min(txid.len())],
                amount_sats,
                "Elder bond registered"
            );

            Ok(())
        })
    }

    /// Confirm an elder bond (called when UTXO is confirmed on-chain)
    pub fn confirm_elder_bond(&self, node_id: &str, confirmation_height: u64) -> GhostResult<bool> {
        let now = chrono::Utc::now().timestamp();

        self.with_connection(|conn| {
            let updated = conn.execute(
                "UPDATE elder_bonds SET status = 'confirmed', confirmation_height = ?1, updated_at = ?2
                 WHERE node_id = ?3 AND status = 'pending'",
                params![confirmation_height, now, node_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            if updated > 0 {
                tracing::info!(
                    node_id = %&node_id[..8.min(node_id.len())],
                    height = confirmation_height,
                    "Elder bond confirmed"
                );
            }

            Ok(updated > 0)
        })
    }

    /// Check if a node has a sufficient confirmed bond
    pub fn has_valid_elder_bond(&self, node_id: &str) -> GhostResult<bool> {
        self.with_connection(|conn| {
            let amount: Option<u64> = conn
                .query_row(
                    "SELECT amount_sats FROM elder_bonds
                     WHERE node_id = ?1 AND status = 'confirmed' AND spent_txid IS NULL",
                    [node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(amount.unwrap_or(0) >= Self::MIN_ELDER_BOND_SATS)
        })
    }

    /// Mark an elder bond as spent (slashed or withdrawn)
    pub fn spend_elder_bond(&self, node_id: &str, spent_txid: &str) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();

        self.with_connection(|conn| {
            conn.execute(
                "UPDATE elder_bonds SET status = 'spent', spent_txid = ?1, updated_at = ?2
                 WHERE node_id = ?3 AND status = 'confirmed'",
                params![spent_txid, now, node_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            // Update node's bond info
            conn.execute(
                "UPDATE nodes SET elder_bond_sats = 0, elder_bond_txid = NULL WHERE node_id = ?1",
                params![node_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(())
        })
    }

    /// Record a slashing event for an elder
    /// This is called when an elder is caught misbehaving (e.g., double-voting)
    pub fn record_elder_slashing(
        &self,
        node_id: &str,
        reason: &str,
        evidence_hash: &str,
        slashed_amount_sats: u64,
        slashing_txid: Option<&str>,
    ) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();

        self.with_connection(|conn| {
            // Record the slashing event
            conn.execute(
                "INSERT INTO elder_slashing (node_id, reason, evidence_hash, slashed_amount_sats, slashing_txid, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![node_id, reason, evidence_hash, slashed_amount_sats, slashing_txid, now],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            // Mark the node as slashed and remove elder status
            conn.execute(
                "UPDATE nodes SET is_elder = 0, elder_order = NULL, slashed_at = ?1 WHERE node_id = ?2",
                params![now, node_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            tracing::warn!(
                node_id = %&node_id[..8.min(node_id.len())],
                reason,
                slashed_amount_sats,
                "Elder slashed for misbehavior"
            );

            Ok(())
        })
    }

    /// Check if a node has been slashed
    pub fn is_node_slashed(&self, node_id: &str) -> GhostResult<bool> {
        self.with_connection(|conn| {
            let slashed_at: Option<i64> = conn
                .query_row(
                    "SELECT slashed_at FROM nodes WHERE node_id = ?1",
                    [node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?
                .flatten();

            Ok(slashed_at.is_some())
        })
    }

    /// Get elder bond info for a node
    pub fn get_elder_bond(&self, node_id: &str) -> GhostResult<Option<ElderBondRecord>> {
        self.with_connection(|conn| {
            let record: Option<ElderBondRecord> = conn
                .query_row(
                    "SELECT node_id, txid, vout, amount_sats, script_pubkey, confirmation_height, spent_txid, status, created_at, updated_at
                     FROM elder_bonds WHERE node_id = ?1",
                    [node_id],
                    |row| {
                        Ok(ElderBondRecord {
                            node_id: row.get(0)?,
                            txid: row.get(1)?,
                            vout: row.get(2)?,
                            amount_sats: row.get(3)?,
                            script_pubkey: row.get(4)?,
                            confirmation_height: row.get(5)?,
                            spent_txid: row.get(6)?,
                            status: row.get(7)?,
                            created_at: row.get(8)?,
                            updated_at: row.get(9)?,
                        })
                    },
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(record)
        })
    }

    /// Get elder count
    pub fn get_elder_count(&self) -> GhostResult<u32> {
        self.with_connection(|conn| {
            let count: u32 = conn
                .query_row("SELECT COUNT(*) FROM nodes WHERE is_elder = 1", [], |row| {
                    row.get(0)
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count)
        })
    }

    /// Increment node share count
    pub fn increment_node_shares(&self, node_id: &str, count: u64) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE nodes SET total_shares_received = total_shares_received + ?1 WHERE node_id = ?2",
                params![count, node_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }
}

// =============================================================================
// MINER QUERIES
// =============================================================================

impl Database {
    /// Get a miner by ID
    pub fn get_miner(&self, miner_id: &str) -> GhostResult<Option<MinerRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT miner_id, payout_address, first_seen, last_seen,
                            connected_node, total_shares, total_work, blocks_won,
                            total_payouts_sats, avg_hashrate_ths
                     FROM miners WHERE miner_id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let miner = stmt
                .query_row([miner_id], |row| {
                    Ok(MinerRecord {
                        miner_id: row.get(0)?,
                        payout_address: row.get(1)?,
                        first_seen: row.get(2)?,
                        last_seen: row.get(3)?,
                        connected_node: row.get(4)?,
                        total_shares: row.get(5)?,
                        total_work: row.get(6)?,
                        blocks_won: row.get(7)?,
                        total_payouts_sats: row.get(8)?,
                        avg_hashrate_ths: row.get(9)?,
                    })
                })
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(miner)
        })
    }

    /// Get miner's payout address by ID
    pub fn get_miner_payout_address(&self, miner_id: &str) -> GhostResult<Option<String>> {
        self.with_connection(|conn| {
            let address: Option<String> = conn
                .query_row(
                    "SELECT payout_address FROM miners WHERE miner_id = ?1",
                    [miner_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(address)
        })
    }

    /// Upsert a miner (insert or update)
    pub fn upsert_miner(&self, miner: &MinerRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO miners (
                    miner_id, payout_address, first_seen, last_seen,
                    connected_node, total_shares, total_work, blocks_won,
                    total_payouts_sats, avg_hashrate_ths
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                ON CONFLICT(miner_id) DO UPDATE SET
                    payout_address = ?2,
                    last_seen = ?4,
                    connected_node = ?5,
                    total_shares = ?6,
                    total_work = ?7,
                    blocks_won = ?8,
                    total_payouts_sats = ?9,
                    avg_hashrate_ths = ?10",
                params![
                    miner.miner_id,
                    miner.payout_address,
                    miner.first_seen,
                    miner.last_seen,
                    miner.connected_node,
                    miner.total_shares,
                    miner.total_work,
                    miner.blocks_won,
                    miner.total_payouts_sats,
                    miner.avg_hashrate_ths,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update miner's payout address
    pub fn update_miner_address(&self, miner_id: &str, payout_address: &str) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();

        self.with_connection(|conn| {
            // Try update first
            let updated = conn
                .execute(
                    "UPDATE miners SET payout_address = ?1, last_seen = ?2 WHERE miner_id = ?3",
                    params![payout_address, now, miner_id],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            // If no row updated, insert new miner
            if updated == 0 {
                conn.execute(
                    "INSERT INTO miners (miner_id, payout_address, first_seen, last_seen)
                     VALUES (?1, ?2, ?3, ?3)",
                    params![miner_id, payout_address, now],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            }

            Ok(())
        })
    }

    /// Increment miner share count and work
    pub fn increment_miner_stats(&self, miner_id: &str, shares: u64, work: f64) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();

        self.with_connection(|conn| {
            conn.execute(
                "UPDATE miners SET
                    total_shares = total_shares + ?1,
                    total_work = total_work + ?2,
                    last_seen = ?3
                 WHERE miner_id = ?4",
                params![shares, work, now, miner_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get node's payout address by ID
    pub fn get_node_payout_address(&self, node_id: &str) -> GhostResult<Option<String>> {
        self.with_connection(|conn| {
            let address: Option<String> = conn
                .query_row(
                    "SELECT payout_address FROM nodes WHERE node_id = ?1",
                    [node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?
                .flatten();
            Ok(address)
        })
    }

    /// Update node's payout address
    pub fn update_node_payout_address(
        &self,
        node_id: &str,
        payout_address: &str,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE nodes SET payout_address = ?1 WHERE node_id = ?2",
                params![payout_address, node_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }
}

fn get_node_internal(conn: &Connection, node_id: &str) -> GhostResult<Option<NodeRecord>> {
    let mut stmt = conn
        .prepare(
            "SELECT node_id, public_address, display_name, first_seen, last_seen,
                    is_elder, elder_order, capabilities, total_uptime_secs,
                    uptime_7d_percent, verification_pass_rate, total_shares_received,
                    total_blocks_found, payout_address
             FROM nodes WHERE node_id = ?1",
        )
        .map_err(|e| GhostError::Database(e.to_string()))?;

    let node = stmt
        .query_row([node_id], node_from_row)
        .optional()
        .map_err(|e| GhostError::Database(e.to_string()))?;

    Ok(node)
}

fn node_from_row(row: &rusqlite::Row) -> rusqlite::Result<NodeRecord> {
    Ok(NodeRecord {
        node_id: row.get(0)?,
        public_address: row.get(1)?,
        display_name: row.get(2)?,
        first_seen: row.get(3)?,
        last_seen: row.get(4)?,
        is_elder: row.get(5)?,
        elder_order: row.get(6)?,
        capabilities: row.get(7)?,
        total_uptime_secs: row.get(8)?,
        uptime_7d_percent: row.get(9)?,
        verification_pass_rate: row.get(10)?,
        total_shares_received: row.get(11)?,
        total_blocks_found: row.get(12)?,
        payout_address: row.get(13)?,
    })
}

// =============================================================================
// NODE REWARD LEDGER QUERIES
// =============================================================================

impl Database {
    /// Get or create node reward entry
    pub fn get_or_create_node_reward(&self, node_id: &str) -> GhostResult<NodeRewardEntry> {
        let now = chrono::Utc::now().timestamp();

        self.with_connection(|conn| {
            // Try to get existing
            let mut stmt = conn
                .prepare(
                    "SELECT node_id, balance_sats, last_credited_round, total_credits_sats,
                            total_withdrawals_sats, created_at, updated_at
                     FROM node_rewards WHERE node_id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if let Some(entry) = stmt
                .query_row([node_id], |row| {
                    Ok(NodeRewardEntry {
                        node_id: row.get(0)?,
                        balance_sats: row.get(1)?,
                        last_credited_round: row.get(2)?,
                        total_credits_sats: row.get(3)?,
                        total_withdrawals_sats: row.get(4)?,
                        created_at: row.get(5)?,
                        updated_at: row.get(6)?,
                    })
                })
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?
            {
                return Ok(entry);
            }

            // Create new entry
            conn.execute(
                "INSERT INTO node_rewards (node_id, balance_sats, created_at, updated_at)
                 VALUES (?1, 0, ?2, ?2)",
                params![node_id, now],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(NodeRewardEntry {
                node_id: node_id.to_string(),
                balance_sats: 0,
                last_credited_round: 0,
                total_credits_sats: 0,
                total_withdrawals_sats: 0,
                created_at: now,
                updated_at: now,
            })
        })
    }

    /// Credit node reward
    pub fn credit_node_reward(&self, node_id: &str, amount: u64, round_id: u64) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();

        self.with_connection(|conn| {
            conn.execute(
                "UPDATE node_rewards SET
                    balance_sats = balance_sats + ?1,
                    last_credited_round = ?2,
                    total_credits_sats = total_credits_sats + ?1,
                    updated_at = ?3
                 WHERE node_id = ?4",
                params![amount, round_id, now, node_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get nodes with balance above threshold
    pub fn get_nodes_with_balance(&self, min_balance: u64) -> GhostResult<Vec<NodeRewardEntry>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT node_id, balance_sats, last_credited_round, total_credits_sats,
                            total_withdrawals_sats, created_at, updated_at
                     FROM node_rewards WHERE balance_sats >= ?1 ORDER BY balance_sats DESC",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let entries = stmt
                .query_map([min_balance], |row| {
                    Ok(NodeRewardEntry {
                        node_id: row.get(0)?,
                        balance_sats: row.get(1)?,
                        last_credited_round: row.get(2)?,
                        total_credits_sats: row.get(3)?,
                        total_withdrawals_sats: row.get(4)?,
                        created_at: row.get(5)?,
                        updated_at: row.get(6)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(entries)
        })
    }
}

// =============================================================================
// KEY-VALUE STORE
// =============================================================================

impl Database {
    /// Get a value from the key-value store
    pub fn kv_get(&self, key: &str) -> GhostResult<Option<String>> {
        self.with_connection(|conn| {
            let value: Option<String> = conn
                .query_row("SELECT value FROM kv_store WHERE key = ?1", [key], |row| {
                    row.get(0)
                })
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(value)
        })
    }

    /// Set a value in the key-value store
    pub fn kv_set(&self, key: &str, value: &str) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();

        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO kv_store (key, value, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = ?3",
                params![key, value, now],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Delete a key from the key-value store
    pub fn kv_delete(&self, key: &str) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute("DELETE FROM kv_store WHERE key = ?1", [key])
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }
}

// =============================================================================
// GHOST LOCK QUERIES
// =============================================================================

impl Database {
    /// Insert a new Ghost Lock
    pub fn insert_ghost_lock(&self, lock: &GhostLockRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO ghost_locks (
                    lock_id, owner_ghost_id, lock_pubkey, recovery_pubkey,
                    denomination, amount_sats, timelock_tier, creation_height,
                    recovery_height, state, funding_txid, funding_vout,
                    spend_txid, output_script, jump_risk_tier, next_jump_height,
                    created_at, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
                params![
                    lock.lock_id,
                    lock.owner_ghost_id,
                    lock.lock_pubkey,
                    lock.recovery_pubkey,
                    lock.denomination,
                    lock.amount_sats,
                    lock.timelock_tier,
                    lock.creation_height,
                    lock.recovery_height,
                    lock.state.as_str(),
                    lock.funding_txid,
                    lock.funding_vout,
                    lock.spend_txid,
                    lock.output_script,
                    lock.jump_risk_tier,
                    lock.next_jump_height,
                    lock.created_at,
                    lock.updated_at,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get a Ghost Lock by ID
    pub fn get_ghost_lock(&self, lock_id: &str) -> GhostResult<Option<GhostLockRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT lock_id, owner_ghost_id, lock_pubkey, recovery_pubkey,
                            denomination, amount_sats, timelock_tier, creation_height,
                            recovery_height, state, funding_txid, funding_vout,
                            spend_txid, output_script, jump_risk_tier, next_jump_height,
                            created_at, updated_at
                     FROM ghost_locks WHERE lock_id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let lock = stmt
                .query_row([lock_id], ghost_lock_from_row)
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(lock)
        })
    }

    /// Get all Ghost Locks for an owner
    pub fn get_ghost_locks_by_owner(
        &self,
        owner_ghost_id: &str,
    ) -> GhostResult<Vec<GhostLockRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT lock_id, owner_ghost_id, lock_pubkey, recovery_pubkey,
                            denomination, amount_sats, timelock_tier, creation_height,
                            recovery_height, state, funding_txid, funding_vout,
                            spend_txid, output_script, jump_risk_tier, next_jump_height,
                            created_at, updated_at
                     FROM ghost_locks WHERE owner_ghost_id = ?1 ORDER BY created_at DESC",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let locks = stmt
                .query_map([owner_ghost_id], ghost_lock_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(locks)
        })
    }

    /// Get active Ghost Locks for an owner
    pub fn get_active_ghost_locks(
        &self,
        owner_ghost_id: &str,
    ) -> GhostResult<Vec<GhostLockRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT lock_id, owner_ghost_id, lock_pubkey, recovery_pubkey,
                            denomination, amount_sats, timelock_tier, creation_height,
                            recovery_height, state, funding_txid, funding_vout,
                            spend_txid, output_script, jump_risk_tier, next_jump_height,
                            created_at, updated_at
                     FROM ghost_locks
                     WHERE owner_ghost_id = ?1 AND state = 'active'
                     ORDER BY created_at DESC",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let locks = stmt
                .query_map([owner_ghost_id], ghost_lock_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(locks)
        })
    }

    /// Get Ghost Locks that need to jump by a certain height
    pub fn get_locks_needing_jump(&self, current_height: u32) -> GhostResult<Vec<GhostLockRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT lock_id, owner_ghost_id, lock_pubkey, recovery_pubkey,
                            denomination, amount_sats, timelock_tier, creation_height,
                            recovery_height, state, funding_txid, funding_vout,
                            spend_txid, output_script, jump_risk_tier, next_jump_height,
                            created_at, updated_at
                     FROM ghost_locks
                     WHERE state = 'active' AND next_jump_height IS NOT NULL AND next_jump_height <= ?1
                     ORDER BY next_jump_height ASC",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let locks = stmt
                .query_map([current_height], ghost_lock_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(locks)
        })
    }

    /// Update Ghost Lock state
    pub fn update_ghost_lock_state(&self, lock_id: &str, state: GhostLockState) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE ghost_locks SET state = ?1, updated_at = ?2 WHERE lock_id = ?3",
                params![state.as_str(), now, lock_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update Ghost Lock funding info
    pub fn update_ghost_lock_funding(
        &self,
        lock_id: &str,
        txid: &str,
        vout: u32,
    ) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE ghost_locks SET
                    funding_txid = ?1, funding_vout = ?2, state = 'active', updated_at = ?3
                 WHERE lock_id = ?4",
                params![txid, vout, now, lock_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update Ghost Lock spend info
    pub fn update_ghost_lock_spent(&self, lock_id: &str, spend_txid: &str) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE ghost_locks SET
                    spend_txid = ?1, state = 'spent', updated_at = ?2
                 WHERE lock_id = ?3",
                params![spend_txid, now, lock_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update Ghost Lock next jump height
    pub fn update_ghost_lock_jump_height(
        &self,
        lock_id: &str,
        next_jump_height: u32,
    ) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE ghost_locks SET next_jump_height = ?1, updated_at = ?2 WHERE lock_id = ?3",
                params![next_jump_height, now, lock_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get total balance in active Ghost Locks for an owner
    pub fn get_ghost_lock_balance(&self, owner_ghost_id: &str) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let balance: u64 = conn
                .query_row(
                    "SELECT COALESCE(SUM(amount_sats), 0) FROM ghost_locks
                     WHERE owner_ghost_id = ?1 AND state = 'active'",
                    [owner_ghost_id],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(balance)
        })
    }
}

fn ghost_lock_from_row(row: &rusqlite::Row) -> rusqlite::Result<GhostLockRecord> {
    let state_str: String = row.get(9)?;
    Ok(GhostLockRecord {
        lock_id: row.get(0)?,
        owner_ghost_id: row.get(1)?,
        lock_pubkey: row.get(2)?,
        recovery_pubkey: row.get(3)?,
        denomination: row.get(4)?,
        amount_sats: row.get(5)?,
        timelock_tier: row.get(6)?,
        creation_height: row.get(7)?,
        recovery_height: row.get(8)?,
        state: GhostLockState::from_str(&state_str).unwrap_or(GhostLockState::Pending),
        funding_txid: row.get(10)?,
        funding_vout: row.get(11)?,
        spend_txid: row.get(12)?,
        output_script: row.get(13)?,
        jump_risk_tier: row.get(14)?,
        next_jump_height: row.get(15)?,
        created_at: row.get(16)?,
        updated_at: row.get(17)?,
    })
}

// =============================================================================
// PEER QUERIES
// =============================================================================

impl Database {
    /// Upsert a peer record
    pub fn upsert_peer(&self, peer: &PeerRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO peers (
                    peer_id, address, port, node_id, first_seen, last_seen,
                    last_success, last_failure, connection_count, failure_count,
                    is_banned, ban_until, capabilities, protocol_version
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                ON CONFLICT(peer_id) DO UPDATE SET
                    address = COALESCE(NULLIF(?2, ''), address),
                    last_seen = ?6,
                    last_success = COALESCE(?7, last_success),
                    last_failure = COALESCE(?8, last_failure),
                    connection_count = ?9,
                    failure_count = ?10,
                    is_banned = ?11,
                    ban_until = ?12,
                    capabilities = COALESCE(?13, capabilities),
                    protocol_version = COALESCE(?14, protocol_version)",
                params![
                    peer.peer_id,
                    peer.address,
                    peer.port,
                    peer.node_id,
                    peer.first_seen,
                    peer.last_seen,
                    peer.last_success,
                    peer.last_failure,
                    peer.connection_count,
                    peer.failure_count,
                    peer.is_banned,
                    peer.ban_until,
                    peer.capabilities,
                    peer.protocol_version,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get a peer by ID
    pub fn get_peer(&self, peer_id: &str) -> GhostResult<Option<PeerRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT peer_id, address, port, node_id, first_seen, last_seen,
                            last_success, last_failure, connection_count, failure_count,
                            is_banned, ban_until, capabilities, protocol_version
                     FROM peers WHERE peer_id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let peer = stmt
                .query_row([peer_id], peer_from_row)
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(peer)
        })
    }

    /// Get active (non-banned) peers
    pub fn get_active_peers(&self, limit: u32) -> GhostResult<Vec<PeerRecord>> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT peer_id, address, port, node_id, first_seen, last_seen,
                            last_success, last_failure, connection_count, failure_count,
                            is_banned, ban_until, capabilities, protocol_version
                     FROM peers
                     WHERE is_banned = 0 OR ban_until < ?1
                     ORDER BY last_success DESC NULLS LAST
                     LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let peers = stmt
                .query_map(params![now, limit], peer_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(peers)
        })
    }

    /// Ban a peer
    pub fn ban_peer(&self, peer_id: &str, ban_until: i64) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE peers SET is_banned = 1, ban_until = ?1 WHERE peer_id = ?2",
                params![ban_until, peer_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }
}

fn peer_from_row(row: &rusqlite::Row) -> rusqlite::Result<PeerRecord> {
    Ok(PeerRecord {
        peer_id: row.get(0)?,
        address: row.get(1)?,
        port: row.get(2)?,
        node_id: row.get(3)?,
        first_seen: row.get(4)?,
        last_seen: row.get(5)?,
        last_success: row.get(6)?,
        last_failure: row.get(7)?,
        connection_count: row.get(8)?,
        failure_count: row.get(9)?,
        is_banned: row.get(10)?,
        ban_until: row.get(11)?,
        capabilities: row.get(12)?,
        protocol_version: row.get(13)?,
    })
}

// =============================================================================
// WRAITH ROUND QUERIES
// =============================================================================

impl Database {
    /// Insert a new Wraith round
    pub fn insert_wraith_round(&self, round: &WraithRoundRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO wraith_rounds (
                    round_id, coordinator_id, denomination, amount_sats, phase,
                    participant_count, min_participants, max_participants,
                    registration_deadline, execution_deadline, split_txid, merge_txid,
                    status, created_at, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    round.round_id,
                    round.coordinator_id,
                    round.denomination,
                    round.amount_sats,
                    round.phase.as_str(),
                    round.participant_count,
                    round.min_participants,
                    round.max_participants,
                    round.registration_deadline,
                    round.execution_deadline,
                    round.split_txid,
                    round.merge_txid,
                    round.status.as_str(),
                    round.created_at,
                    round.updated_at,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get a Wraith round by ID
    pub fn get_wraith_round(&self, round_id: &str) -> GhostResult<Option<WraithRoundRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT round_id, coordinator_id, denomination, amount_sats, phase,
                            participant_count, min_participants, max_participants,
                            registration_deadline, execution_deadline, split_txid, merge_txid,
                            status, created_at, updated_at
                     FROM wraith_rounds WHERE round_id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let round = stmt
                .query_row([round_id], wraith_round_from_row)
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(round)
        })
    }

    /// Get active Wraith rounds
    pub fn get_active_wraith_rounds(&self) -> GhostResult<Vec<WraithRoundRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT round_id, coordinator_id, denomination, amount_sats, phase,
                            participant_count, min_participants, max_participants,
                            registration_deadline, execution_deadline, split_txid, merge_txid,
                            status, created_at, updated_at
                     FROM wraith_rounds WHERE status = 'active'
                     ORDER BY registration_deadline ASC",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rounds = stmt
                .query_map([], wraith_round_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(rounds)
        })
    }

    /// Update Wraith round phase
    pub fn update_wraith_round_phase(&self, round_id: &str, phase: WraithPhase) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE wraith_rounds SET phase = ?1, updated_at = ?2 WHERE round_id = ?3",
                params![phase.as_str(), now, round_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update Wraith round status
    pub fn update_wraith_round_status(
        &self,
        round_id: &str,
        status: WraithStatus,
    ) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE wraith_rounds SET status = ?1, updated_at = ?2 WHERE round_id = ?3",
                params![status.as_str(), now, round_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }
}

fn wraith_round_from_row(row: &rusqlite::Row) -> rusqlite::Result<WraithRoundRecord> {
    let phase_str: String = row.get(4)?;
    let status_str: String = row.get(12)?;
    Ok(WraithRoundRecord {
        round_id: row.get(0)?,
        coordinator_id: row.get(1)?,
        denomination: row.get(2)?,
        amount_sats: row.get(3)?,
        phase: WraithPhase::from_str(&phase_str).unwrap_or(WraithPhase::Registration),
        participant_count: row.get(5)?,
        min_participants: row.get(6)?,
        max_participants: row.get(7)?,
        registration_deadline: row.get(8)?,
        execution_deadline: row.get(9)?,
        split_txid: row.get(10)?,
        merge_txid: row.get(11)?,
        status: WraithStatus::from_str(&status_str).unwrap_or(WraithStatus::Active),
        created_at: row.get(13)?,
        updated_at: row.get(14)?,
    })
}

// =============================================================================
// RECONCILIATION QUERIES
// =============================================================================

impl Database {
    /// Insert a reconciliation batch
    pub fn insert_reconciliation_batch(&self, batch: &ReconciliationRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO reconciliation_state (
                    batch_id, settlement_class, participant_count, total_amount_sats,
                    merkle_root, l1_txid, l1_block_height, dispute_deadline,
                    status, created_at, finalized_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    batch.batch_id,
                    batch.settlement_class,
                    batch.participant_count,
                    batch.total_amount_sats,
                    batch.merkle_root,
                    batch.l1_txid,
                    batch.l1_block_height,
                    batch.dispute_deadline,
                    batch.status.as_str(),
                    batch.created_at,
                    batch.finalized_at,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get a reconciliation batch by ID
    pub fn get_reconciliation_batch(
        &self,
        batch_id: &str,
    ) -> GhostResult<Option<ReconciliationRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT batch_id, settlement_class, participant_count, total_amount_sats,
                            merkle_root, l1_txid, l1_block_height, dispute_deadline,
                            status, created_at, finalized_at
                     FROM reconciliation_state WHERE batch_id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let batch = stmt
                .query_row([batch_id], reconciliation_from_row)
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(batch)
        })
    }

    /// Get pending reconciliation batches
    pub fn get_pending_reconciliation_batches(&self) -> GhostResult<Vec<ReconciliationRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT batch_id, settlement_class, participant_count, total_amount_sats,
                            merkle_root, l1_txid, l1_block_height, dispute_deadline,
                            status, created_at, finalized_at
                     FROM reconciliation_state WHERE status IN ('pending', 'submitted')
                     ORDER BY created_at ASC",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let batches = stmt
                .query_map([], reconciliation_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(batches)
        })
    }

    /// Update reconciliation batch L1 submission
    pub fn update_reconciliation_l1_submitted(
        &self,
        batch_id: &str,
        txid: &str,
        block_height: u64,
        dispute_deadline: u64,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE reconciliation_state SET
                    l1_txid = ?1, l1_block_height = ?2, dispute_deadline = ?3, status = 'submitted'
                 WHERE batch_id = ?4",
                params![txid, block_height, dispute_deadline, batch_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Finalize reconciliation batch
    pub fn finalize_reconciliation_batch(&self, batch_id: &str) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE reconciliation_state SET status = 'finalized', finalized_at = ?1 WHERE batch_id = ?2",
                params![now, batch_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }
}

fn reconciliation_from_row(row: &rusqlite::Row) -> rusqlite::Result<ReconciliationRecord> {
    let status_str: String = row.get(8)?;
    Ok(ReconciliationRecord {
        batch_id: row.get(0)?,
        settlement_class: row.get(1)?,
        participant_count: row.get(2)?,
        total_amount_sats: row.get(3)?,
        merkle_root: row.get(4)?,
        l1_txid: row.get(5)?,
        l1_block_height: row.get(6)?,
        dispute_deadline: row.get(7)?,
        status: ReconciliationStatus::from_str(&status_str)
            .unwrap_or(ReconciliationStatus::Pending),
        created_at: row.get(9)?,
        finalized_at: row.get(10)?,
    })
}

// =============================================================================
// WITHDRAWAL REQUEST QUERIES
// =============================================================================

impl Database {
    /// Insert a new withdrawal request
    pub fn insert_withdrawal_request(&self, request: &WithdrawalRequest) -> GhostResult<i64> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO withdrawal_requests (
                    ghost_id, lock_id, destination_address, amount_sats, fee_sats,
                    status, batch_id, l1_txid, created_at, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    request.ghost_id,
                    request.lock_id,
                    request.destination_address,
                    request.amount_sats,
                    request.fee_sats,
                    request.status.as_str(),
                    request.batch_id,
                    request.l1_txid,
                    request.created_at,
                    request.updated_at,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(conn.last_insert_rowid())
        })
    }

    /// Get a withdrawal request by ID
    pub fn get_withdrawal_request(&self, id: i64) -> GhostResult<Option<WithdrawalRequest>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, ghost_id, lock_id, destination_address, amount_sats, fee_sats,
                            status, batch_id, l1_txid, created_at, updated_at
                     FROM withdrawal_requests WHERE id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let request = stmt
                .query_row([id], withdrawal_from_row)
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(request)
        })
    }

    /// Get pending withdrawal requests for a ghost_id
    pub fn get_pending_withdrawals(&self, ghost_id: &str) -> GhostResult<Vec<WithdrawalRequest>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, ghost_id, lock_id, destination_address, amount_sats, fee_sats,
                            status, batch_id, l1_txid, created_at, updated_at
                     FROM withdrawal_requests
                     WHERE ghost_id = ?1 AND status = 'pending'
                     ORDER BY created_at ASC",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let requests = stmt
                .query_map([ghost_id], withdrawal_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(requests)
        })
    }

    /// Get all pending withdrawal requests (for batch processing)
    pub fn get_all_pending_withdrawals(&self) -> GhostResult<Vec<WithdrawalRequest>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, ghost_id, lock_id, destination_address, amount_sats, fee_sats,
                            status, batch_id, l1_txid, created_at, updated_at
                     FROM withdrawal_requests
                     WHERE status = 'pending'
                     ORDER BY created_at ASC",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let requests = stmt
                .query_map([], withdrawal_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(requests)
        })
    }

    /// Get withdrawal requests by lock ID
    pub fn get_withdrawals_by_lock(&self, lock_id: &str) -> GhostResult<Vec<WithdrawalRequest>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, ghost_id, lock_id, destination_address, amount_sats, fee_sats,
                            status, batch_id, l1_txid, created_at, updated_at
                     FROM withdrawal_requests
                     WHERE lock_id = ?1
                     ORDER BY created_at DESC",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let requests = stmt
                .query_map([lock_id], withdrawal_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(requests)
        })
    }

    /// Update withdrawal request status
    pub fn update_withdrawal_status(&self, id: i64, status: WithdrawalStatus) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE withdrawal_requests SET status = ?1, updated_at = ?2 WHERE id = ?3",
                params![status.as_str(), now, id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update withdrawal request with batch info
    pub fn update_withdrawal_batched(&self, id: i64, batch_id: &str) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE withdrawal_requests SET status = 'batched', batch_id = ?1, updated_at = ?2 WHERE id = ?3",
                params![batch_id, now, id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update withdrawal request with L1 txid
    pub fn update_withdrawal_submitted(&self, id: i64, l1_txid: &str) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE withdrawal_requests SET status = 'submitted', l1_txid = ?1, updated_at = ?2 WHERE id = ?3",
                params![l1_txid, now, id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Mark withdrawal as confirmed
    pub fn update_withdrawal_confirmed(&self, id: i64) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE withdrawal_requests SET status = 'confirmed', updated_at = ?1 WHERE id = ?2",
                params![now, id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Cancel a pending withdrawal
    pub fn cancel_withdrawal(&self, id: i64) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE withdrawal_requests SET status = 'cancelled', updated_at = ?1 WHERE id = ?2 AND status = 'pending'",
                params![now, id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    // ========================================================================
    // Verification API Queries
    // ========================================================================

    /// Get recent shares across all rounds (for verification API)
    pub fn get_recent_shares(&self, limit: u32) -> GhostResult<Vec<ShareRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, round_id, miner_id, difficulty, work, share_hash, timestamp, received_by, valid
                     FROM shares ORDER BY timestamp DESC LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let shares = stmt
                .query_map([limit], |row| {
                    Ok(ShareRecord {
                        id: Some(row.get(0)?),
                        round_id: row.get(1)?,
                        miner_id: row.get(2)?,
                        difficulty: row.get(3)?,
                        work: row.get(4)?,
                        share_hash: row.get(5)?,
                        timestamp: row.get(6)?,
                        received_by: row.get(7)?,
                        valid: row.get(8)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(shares)
        })
    }

    /// Get payouts for a specific round
    pub fn get_payouts_by_round(&self, round_id: u64) -> GhostResult<Vec<PayoutRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, round_id, recipient_id, recipient_type, address, amount_sats,
                            txid, vout, status, created_at, confirmed_at
                     FROM payouts WHERE round_id = ?1 ORDER BY created_at DESC",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let payouts = stmt
                .query_map([round_id], payout_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(payouts)
        })
    }

    /// Get recent payouts across all rounds
    pub fn get_recent_payouts(&self, limit: u32) -> GhostResult<Vec<PayoutRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, round_id, recipient_id, recipient_type, address, amount_sats,
                            txid, vout, status, created_at, confirmed_at
                     FROM payouts ORDER BY created_at DESC LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let payouts = stmt
                .query_map([limit], payout_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(payouts)
        })
    }

    /// Insert a payout record
    pub fn insert_payout(&self, payout: &PayoutRecord) -> GhostResult<i64> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO payouts (round_id, recipient_id, recipient_type, address, amount_sats,
                                     txid, vout, status, created_at, confirmed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    payout.round_id,
                    payout.recipient_id,
                    payout.recipient_type.as_str(),
                    payout.address,
                    payout.amount_sats,
                    payout.txid,
                    payout.vout,
                    payout.status.as_str(),
                    payout.created_at,
                    payout.confirmed_at,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// Get total payout count
    pub fn get_payout_count(&self) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM payouts", [], |row| row.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count as u64)
        })
    }

    // =========================================================================
    // KEY ROTATION WITH ELDER STATUS TRANSFER
    // =========================================================================

    /// Check if a node_id has been retired (rotated away from)
    ///
    /// Returns the new node_id if the node was rotated, None if still active.
    pub fn is_node_retired(&self, node_id: &str) -> GhostResult<Option<String>> {
        self.with_connection(|conn| {
            let result: Option<String> = conn
                .query_row(
                    "SELECT new_node_id FROM retired_nodes WHERE old_node_id = ?1",
                    [node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(result)
        })
    }

    /// Check if a rotation proof has been used (prevent replay)
    fn is_rotation_proof_used(
        &self,
        conn: &Connection,
        old_node_id: &str,
        new_node_id: &str,
    ) -> GhostResult<bool> {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM rotation_history
                 WHERE old_node_id = ?1 AND new_node_id = ?2 AND status = 'completed'",
                params![old_node_id, new_node_id],
                |row| row.get(0),
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
        Ok(count > 0)
    }

    /// Transfer elder status from old node_id to new node_id using a rotation proof
    ///
    /// This is the ONLY way to preserve elder status during key rotation.
    ///
    /// Security checks performed:
    /// 1. Rotation proof is cryptographically valid (both signatures)
    /// 2. Old node_id is not already retired
    /// 3. New node_id is not already in use as someone else's identity
    /// 4. The rotation proof hasn't been used before (prevent replay)
    /// 5. The rotation proof is recent (not expired)
    ///
    /// Returns (success, elder_transferred)
    pub fn transfer_elder_with_rotation(
        &self,
        rotation_proof: &ghost_common::key_rotation::KeyRotationProof,
    ) -> GhostResult<(bool, bool)> {
        // Step 1: Verify the rotation proof cryptographically (includes expiration check)
        rotation_proof.verify().map_err(|e| {
            GhostError::SignatureVerification(format!("Invalid rotation proof: {}", e))
        })?;

        let old_node_id = hex::encode(rotation_proof.old_node_id);
        let new_node_id = hex::encode(rotation_proof.new_node_id);
        let now = chrono::Utc::now().timestamp();
        let proof_bytes = rotation_proof.to_bytes();

        self.with_connection(|conn| {
            // Step 2: Check if old node is already retired
            let already_retired: Option<String> = conn
                .query_row(
                    "SELECT new_node_id FROM retired_nodes WHERE old_node_id = ?1",
                    [&old_node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if already_retired.is_some() {
                return Err(GhostError::SignatureVerification(format!(
                    "Node {} is already retired",
                    &old_node_id[..16]
                )));
            }

            // Step 3: Check if this rotation proof was already used
            if self.is_rotation_proof_used(conn, &old_node_id, &new_node_id)? {
                return Err(GhostError::SignatureVerification(
                    "Rotation proof has already been used".to_string()
                ));
            }

            // Step 4: Check if new_node_id is already in use by someone else
            let existing_new: Option<String> = conn
                .query_row(
                    "SELECT node_id FROM nodes WHERE node_id = ?1 AND rotated_from IS NULL",
                    [&new_node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if let Some(_) = existing_new {
                // New node_id exists and wasn't from a rotation - could be hijack attempt
                return Err(GhostError::SignatureVerification(format!(
                    "New node_id {} is already registered by another identity",
                    &new_node_id[..16]
                )));
            }

            // Step 5: Start transaction for atomic elder transfer
            conn.execute("BEGIN IMMEDIATE", [])
                .map_err(|e| GhostError::Database(format!("Failed to start transaction: {}", e)))?;

            let result: GhostResult<(bool, bool)> = (|| {
                // Get old node's elder status and other transferable attributes
                let old_node: Option<(bool, Option<u32>, Option<String>, Option<String>, Option<i64>)> = conn
                    .query_row(
                        "SELECT is_elder, elder_order, pow_proof, capabilities, first_seen
                         FROM nodes WHERE node_id = ?1",
                        [&old_node_id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
                    )
                    .optional()
                    .map_err(|e| GhostError::Database(e.to_string()))?;

                let (is_elder, elder_order, pow_proof, capabilities, first_seen) = match old_node {
                    Some(data) => data,
                    None => {
                        return Err(GhostError::SignatureVerification(format!(
                            "Old node {} not found in database",
                            &old_node_id[..16]
                        )));
                    }
                };

                // Insert new node (or update if it exists from a previous incomplete rotation)
                conn.execute(
                    "INSERT INTO nodes (node_id, first_seen, last_seen, is_elder, elder_order,
                                       pow_proof, capabilities, rotated_from)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                     ON CONFLICT(node_id) DO UPDATE SET
                         is_elder = excluded.is_elder,
                         elder_order = excluded.elder_order,
                         pow_proof = COALESCE(excluded.pow_proof, pow_proof),
                         capabilities = COALESCE(excluded.capabilities, capabilities),
                         rotated_from = excluded.rotated_from,
                         last_seen = excluded.last_seen",
                    params![
                        &new_node_id,
                        first_seen.unwrap_or(now),  // Preserve original first_seen
                        now,
                        is_elder,
                        elder_order,
                        pow_proof,
                        capabilities,
                        &old_node_id,
                    ],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

                // Mark old node as retired (remove elder status)
                conn.execute(
                    "UPDATE nodes SET is_elder = 0, elder_order = NULL, rotated_to = ?1
                     WHERE node_id = ?2",
                    params![&new_node_id, &old_node_id],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

                // Add to retired_nodes table (permanent record)
                conn.execute(
                    "INSERT INTO retired_nodes (old_node_id, new_node_id, rotation_timestamp, rotation_proof)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![&old_node_id, &new_node_id, now, &proof_bytes],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

                // Add to rotation history
                conn.execute(
                    "INSERT INTO rotation_history (old_node_id, new_node_id, rotation_timestamp,
                                                   finalized_timestamp, status, rotation_proof, elder_transferred)
                     VALUES (?1, ?2, ?3, ?4, 'completed', ?5, ?6)",
                    params![
                        &old_node_id,
                        &new_node_id,
                        rotation_proof.timestamp as i64,
                        now,
                        &proof_bytes,
                        if is_elder { 1 } else { 0 },
                    ],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

                Ok((true, is_elder))
            })();

            // Commit or rollback
            match &result {
                Ok(_) => {
                    conn.execute("COMMIT", [])
                        .map_err(|e| GhostError::Database(format!("Failed to commit: {}", e)))?;
                }
                Err(_) => {
                    let _ = conn.execute("ROLLBACK", []);
                }
            }

            result
        })
    }

    /// Get the rotation history for a node (follows the chain of rotations)
    pub fn get_rotation_chain(&self, node_id: &str) -> GhostResult<Vec<(String, String, i64)>> {
        self.with_connection(|conn| {
            let mut chain = Vec::new();

            // First, find all rotations FROM this node
            let mut stmt = conn
                .prepare(
                    "SELECT old_node_id, new_node_id, finalized_timestamp
                     FROM rotation_history
                     WHERE old_node_id = ?1 AND status = 'completed'
                     ORDER BY finalized_timestamp DESC",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rotations = stmt
                .query_map([node_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            chain.extend(rotations);

            // Also find rotations TO this node (to build full chain)
            let mut stmt = conn
                .prepare(
                    "SELECT old_node_id, new_node_id, finalized_timestamp
                     FROM rotation_history
                     WHERE new_node_id = ?1 AND status = 'completed'
                     ORDER BY finalized_timestamp DESC",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rotations = stmt
                .query_map([node_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            chain.extend(rotations);

            Ok(chain)
        })
    }

    /// Store a pending rotation (before finalization)
    /// This allows for grace period revocation
    pub fn store_pending_rotation(
        &self,
        rotation_proof: &ghost_common::key_rotation::KeyRotationProof,
    ) -> GhostResult<i64> {
        let old_node_id = hex::encode(rotation_proof.old_node_id);
        let new_node_id = hex::encode(rotation_proof.new_node_id);
        let proof_bytes = rotation_proof.to_bytes();

        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO rotation_history (old_node_id, new_node_id, rotation_timestamp,
                                               status, rotation_proof, elder_transferred)
                 VALUES (?1, ?2, ?3, 'pending', ?4, 0)",
                params![
                    &old_node_id,
                    &new_node_id,
                    rotation_proof.timestamp as i64,
                    &proof_bytes,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(conn.last_insert_rowid())
        })
    }

    /// Revoke a pending rotation (during grace period)
    pub fn revoke_pending_rotation(
        &self,
        rotation_id: i64,
        revocation_proof: &ghost_common::key_rotation::RotationRevocation,
    ) -> GhostResult<()> {
        // Serialize revocation proof to JSON
        let revocation_bytes = serde_json::to_vec(revocation_proof)
            .map_err(|e| GhostError::Database(format!("Failed to serialize revocation: {}", e)))?;
        let now = chrono::Utc::now().timestamp();

        self.with_connection(|conn| {
            let rows_affected = conn
                .execute(
                    "UPDATE rotation_history
                     SET status = 'revoked', finalized_timestamp = ?1, revocation_proof = ?2
                     WHERE id = ?3 AND status = 'pending'",
                    params![now, &revocation_bytes, rotation_id],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if rows_affected == 0 {
                return Err(GhostError::Database(
                    "Rotation not found or already finalized".to_string(),
                ));
            }

            Ok(())
        })
    }
}

fn withdrawal_from_row(row: &rusqlite::Row) -> rusqlite::Result<WithdrawalRequest> {
    let status_str: String = row.get(6)?;
    Ok(WithdrawalRequest {
        id: Some(row.get(0)?),
        ghost_id: row.get(1)?,
        lock_id: row.get(2)?,
        destination_address: row.get(3)?,
        amount_sats: row.get(4)?,
        fee_sats: row.get(5)?,
        status: WithdrawalStatus::from_str(&status_str).unwrap_or(WithdrawalStatus::Pending),
        batch_id: row.get(7)?,
        l1_txid: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
    })
}

fn payout_from_row(row: &rusqlite::Row) -> rusqlite::Result<PayoutRecord> {
    let recipient_type_str: String = row.get(3)?;
    let status_str: String = row.get(8)?;
    Ok(PayoutRecord {
        id: Some(row.get(0)?),
        round_id: row.get(1)?,
        recipient_id: row.get(2)?,
        recipient_type: RecipientType::from_str(&recipient_type_str)
            .unwrap_or(RecipientType::Miner),
        address: row.get(4)?,
        amount_sats: row.get(5)?,
        txid: row.get(6)?,
        vout: row.get(7)?,
        status: PayoutStatus::from_str(&status_str).unwrap_or(PayoutStatus::Pending),
        created_at: row.get(9)?,
        confirmed_at: row.get(10)?,
    })
}

// =============================================================================
// TREASURY STATE QUERIES
// =============================================================================

/// Treasury state storage keys
const TREASURY_BALANCE_KEY: &str = "treasury_balance_sats";
const TREASURY_THRESHOLD_REACHED_KEY: &str = "treasury_threshold_reached_at";

impl Database {
    /// Get the current treasury balance in satoshis
    pub fn get_treasury_balance(&self) -> GhostResult<u64> {
        match self.kv_get(TREASURY_BALANCE_KEY)? {
            Some(s) => s.parse().map_err(|e| {
                GhostError::Database(format!("Failed to parse treasury balance: {}", e))
            }),
            None => Ok(0),
        }
    }

    /// Set the current treasury balance in satoshis
    pub fn set_treasury_balance(&self, balance: u64) -> GhostResult<()> {
        self.kv_set(TREASURY_BALANCE_KEY, &balance.to_string())
    }

    /// Get the timestamp when treasury threshold was reached (if ever)
    pub fn get_treasury_threshold_reached(&self) -> GhostResult<Option<i64>> {
        match self.kv_get(TREASURY_THRESHOLD_REACHED_KEY)? {
            Some(s) => {
                let ts: i64 = s.parse().map_err(|e| {
                    GhostError::Database(format!(
                        "Failed to parse treasury threshold timestamp: {}",
                        e
                    ))
                })?;
                Ok(Some(ts))
            }
            None => Ok(None),
        }
    }

    /// Set the timestamp when treasury threshold was reached
    pub fn set_treasury_threshold_reached(&self, timestamp: i64) -> GhostResult<()> {
        self.kv_set(TREASURY_THRESHOLD_REACHED_KEY, &timestamp.to_string())
    }

    /// Add funds to treasury and check if threshold was crossed
    /// Returns true if threshold was just crossed
    pub fn add_treasury_funds(&self, amount: u64, threshold: u64) -> GhostResult<bool> {
        let current = self.get_treasury_balance()?;
        let new_balance = current.saturating_add(amount);
        self.set_treasury_balance(new_balance)?;

        // Check if we just crossed threshold
        if current < threshold && new_balance >= threshold {
            let now = chrono::Utc::now().timestamp();
            self.set_treasury_threshold_reached(now)?;
            tracing::info!(
                balance = new_balance,
                threshold,
                "Treasury threshold reached - decay begins"
            );
            return Ok(true);
        }

        Ok(false)
    }
}

// =============================================================================
// CAPABILITY VERIFICATION CHALLENGES
// =============================================================================

impl Database {
    /// Insert an archive challenge result
    pub fn insert_archive_challenge(
        &self,
        node_id: &str,
        challenger_id: &str,
        block_height: u64,
        expected_hash: &str,
        response_hash: Option<&str>,
        passed: bool,
    ) -> GhostResult<i64> {
        self.with_connection(|conn| {
            let timestamp = chrono::Utc::now().timestamp();
            conn.execute(
                "INSERT INTO archive_challenges
                 (node_id, challenger_id, block_height, expected_hash, response_hash, passed, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    node_id,
                    challenger_id,
                    block_height,
                    expected_hash,
                    response_hash,
                    passed,
                    timestamp,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// Insert a policy challenge result
    pub fn insert_policy_challenge(
        &self,
        node_id: &str,
        challenger_id: &str,
        txid: &str,
        expected_tier: i32,
        response_tier: Option<i32>,
        passed: bool,
    ) -> GhostResult<i64> {
        self.with_connection(|conn| {
            let timestamp = chrono::Utc::now().timestamp();
            conn.execute(
                "INSERT INTO policy_challenges
                 (node_id, challenger_id, txid, expected_tier, response_tier, passed, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    node_id,
                    challenger_id,
                    txid,
                    expected_tier,
                    response_tier,
                    passed,
                    timestamp,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// Insert a stratum challenge result
    pub fn insert_stratum_challenge(
        &self,
        node_id: &str,
        challenger_id: &str,
        connected: bool,
        latency_ms: Option<u32>,
        passed: bool,
    ) -> GhostResult<i64> {
        self.with_connection(|conn| {
            let timestamp = chrono::Utc::now().timestamp();
            conn.execute(
                "INSERT INTO stratum_challenges
                 (node_id, challenger_id, connected, latency_ms, passed, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    node_id,
                    challenger_id,
                    connected,
                    latency_ms,
                    passed,
                    timestamp,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// Insert a Ghost Pay challenge result
    pub fn insert_ghostpay_challenge(
        &self,
        node_id: &str,
        challenger_id: &str,
        endpoint: &str,
        response_valid: bool,
        passed: bool,
    ) -> GhostResult<i64> {
        self.with_connection(|conn| {
            let timestamp = chrono::Utc::now().timestamp();
            conn.execute(
                "INSERT INTO ghostpay_challenges
                 (node_id, challenger_id, endpoint, response_valid, passed, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    node_id,
                    challenger_id,
                    endpoint,
                    response_valid,
                    passed,
                    timestamp,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// Get archive capability pass rate for a node
    /// Returns (passed_count, total_count)
    pub fn get_archive_pass_rate(&self, node_id: &str, since: i64) -> GhostResult<(u32, u32)> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT
                        SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed,
                        COUNT(*) as total
                     FROM archive_challenges
                     WHERE node_id = ?1 AND timestamp >= ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let result = stmt
                .query_row(params![node_id, since], |row| {
                    let passed: Option<i64> = row.get(0)?;
                    let total: i64 = row.get(1)?;
                    Ok((passed.unwrap_or(0) as u32, total as u32))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(result)
        })
    }

    /// Get policy capability pass rate for a node
    /// Returns (passed_count, total_count)
    pub fn get_policy_pass_rate(&self, node_id: &str, since: i64) -> GhostResult<(u32, u32)> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT
                        SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed,
                        COUNT(*) as total
                     FROM policy_challenges
                     WHERE node_id = ?1 AND timestamp >= ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let result = stmt
                .query_row(params![node_id, since], |row| {
                    let passed: Option<i64> = row.get(0)?;
                    let total: i64 = row.get(1)?;
                    Ok((passed.unwrap_or(0) as u32, total as u32))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(result)
        })
    }

    /// Get stratum capability pass rate for a node
    /// Returns (passed_count, total_count)
    pub fn get_stratum_pass_rate(&self, node_id: &str, since: i64) -> GhostResult<(u32, u32)> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT
                        SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed,
                        COUNT(*) as total
                     FROM stratum_challenges
                     WHERE node_id = ?1 AND timestamp >= ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let result = stmt
                .query_row(params![node_id, since], |row| {
                    let passed: Option<i64> = row.get(0)?;
                    let total: i64 = row.get(1)?;
                    Ok((passed.unwrap_or(0) as u32, total as u32))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(result)
        })
    }

    /// Get Ghost Pay capability pass rate for a node
    /// Returns (passed_count, total_count)
    pub fn get_ghostpay_pass_rate(&self, node_id: &str, since: i64) -> GhostResult<(u32, u32)> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT
                        SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed,
                        COUNT(*) as total
                     FROM ghostpay_challenges
                     WHERE node_id = ?1 AND timestamp >= ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let result = stmt
                .query_row(params![node_id, since], |row| {
                    let passed: Option<i64> = row.get(0)?;
                    let total: i64 = row.get(1)?;
                    Ok((passed.unwrap_or(0) as u32, total as u32))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(result)
        })
    }

    /// Record an uptime sample for a node
    pub fn record_uptime_sample(
        &self,
        node_id: &str,
        sample_time: i64,
        was_online: bool,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO uptime_samples (node_id, sample_time, was_online)
                 VALUES (?1, ?2, ?3)",
                params![node_id, sample_time, was_online],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get uptime percentage for a node over trailing period
    /// Returns percentage (0.0 to 1.0)
    pub fn get_uptime_percent(&self, node_id: &str, since: i64) -> GhostResult<f64> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT
                        SUM(CASE WHEN was_online = 1 THEN 1 ELSE 0 END) as online,
                        COUNT(*) as total
                     FROM uptime_samples
                     WHERE node_id = ?1 AND sample_time >= ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let result = stmt
                .query_row(params![node_id, since], |row| {
                    let online: Option<i64> = row.get(0)?;
                    let total: i64 = row.get(1)?;
                    Ok((online.unwrap_or(0), total))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let (online, total) = result;
            if total == 0 {
                return Ok(0.0);
            }
            Ok(online as f64 / total as f64)
        })
    }

    /// Check if a node has elder status
    ///
    /// Elder status is granted to the first 101 registered nodes.
    /// This is tracked by the is_elder flag in the nodes table.
    pub fn is_node_elder(&self, node_id: &str) -> GhostResult<bool> {
        self.with_connection(|conn| {
            let is_elder: bool = conn
                .query_row(
                    "SELECT COALESCE(is_elder, 0) FROM nodes WHERE node_id = ?1",
                    [node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?
                .unwrap_or(false);
            Ok(is_elder)
        })
    }

    /// Get qualified capabilities for a node
    ///
    /// A capability is qualified if:
    /// 1. Node passes uptime gatekeeper (95% over lookback period)
    /// 2. Capability has min_challenges or more challenges
    /// 3. Pass rate is >= min_pass_rate
    pub fn get_qualified_capabilities(
        &self,
        node_id: &str,
        since: i64,
        min_challenges: u32,
        min_pass_rate: f64,
    ) -> GhostResult<ghost_common::types::NodeCapabilities> {
        use ghost_common::types::NodeCapabilities;

        // Check each capability
        let archive_qualified = {
            let (passed, total) = self.get_archive_pass_rate(node_id, since)?;
            total >= min_challenges && (passed as f64 / total as f64) >= min_pass_rate
        };

        let policy_qualified = {
            let (passed, total) = self.get_policy_pass_rate(node_id, since)?;
            total >= min_challenges && (passed as f64 / total as f64) >= min_pass_rate
        };

        let stratum_qualified = {
            let (passed, total) = self.get_stratum_pass_rate(node_id, since)?;
            total >= min_challenges && (passed as f64 / total as f64) >= min_pass_rate
        };

        let ghostpay_qualified = {
            let (passed, total) = self.get_ghostpay_pass_rate(node_id, since)?;
            total >= min_challenges && (passed as f64 / total as f64) >= min_pass_rate
        };

        // Elder status is based on is_elder flag in the nodes table
        // First 101 registered nodes are elders (registration order tracked by elder_order)
        let elder_qualified = self.is_node_elder(node_id)?;

        Ok(NodeCapabilities {
            archive_mode: archive_qualified,
            ghost_pay: ghostpay_qualified,
            public_mining: stratum_qualified,
            bitcoin_pure: policy_qualified,
            elder_status: elder_qualified,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_insert_and_query() {
        let db = Database::in_memory().unwrap();

        let share = ShareRecord {
            id: None,
            round_id: 1,
            miner_id: "abc123".to_string(),
            difficulty: 1000.0,
            work: 1000.0,
            share_hash: "def456".to_string(),
            timestamp: 1234567890,
            received_by: "node1".to_string(),
            valid: true,
        };

        let id = db.insert_share(&share).unwrap();
        assert!(id > 0);

        let shares = db.get_shares_by_round(1).unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].miner_id, "abc123");
    }

    #[test]
    fn test_round_operations() {
        let db = Database::in_memory().unwrap();

        let round = RoundRecord {
            round_id: 1,
            block_height: 100,
            block_hash: None,
            start_time: 1234567890,
            end_time: None,
            total_shares: 0,
            total_work: 0.0,
            winning_miner: None,
            found_by_node: None,
            payout_status: PayoutStatus::Active,
            subsidy_sats: None,
            tx_fees_sats: None,
        };

        db.create_round(&round).unwrap();

        let fetched = db.get_round(1).unwrap().unwrap();
        assert_eq!(fetched.block_height, 100);
    }

    #[test]
    fn test_kv_store() {
        let db = Database::in_memory().unwrap();

        db.kv_set("test_key", "test_value").unwrap();
        let value = db.kv_get("test_key").unwrap();
        assert_eq!(value, Some("test_value".to_string()));

        db.kv_delete("test_key").unwrap();
        let value = db.kv_get("test_key").unwrap();
        assert_eq!(value, None);
    }

    #[test]
    fn test_node_reward_ledger() {
        let db = Database::in_memory().unwrap();

        let entry = db.get_or_create_node_reward("node123").unwrap();
        assert_eq!(entry.balance_sats, 0);

        db.credit_node_reward("node123", 1000, 1).unwrap();

        let entry = db.get_or_create_node_reward("node123").unwrap();
        assert_eq!(entry.balance_sats, 1000);
        assert_eq!(entry.last_credited_round, 1);
    }

    #[test]
    fn test_ghost_lock_operations() {
        let db = Database::in_memory().unwrap();
        let now = chrono::Utc::now().timestamp();

        let lock = GhostLockRecord {
            lock_id: "lock123".to_string(),
            owner_ghost_id: "ghost1abc".to_string(),
            lock_pubkey: "02abc123".to_string(),
            recovery_pubkey: "02def456".to_string(),
            denomination: "Medium".to_string(),
            amount_sats: 10_000_000,
            timelock_tier: "Standard".to_string(),
            creation_height: 800000,
            recovery_height: 807200,
            state: GhostLockState::Pending,
            funding_txid: None,
            funding_vout: None,
            spend_txid: None,
            output_script: "5120abcd".to_string(),
            jump_risk_tier: "Medium".to_string(),
            next_jump_height: Some(802016),
            created_at: now,
            updated_at: now,
        };

        db.insert_ghost_lock(&lock).unwrap();

        let fetched = db.get_ghost_lock("lock123").unwrap().unwrap();
        assert_eq!(fetched.amount_sats, 10_000_000);
        assert_eq!(fetched.state, GhostLockState::Pending);

        // Update funding
        db.update_ghost_lock_funding("lock123", "txid123", 0)
            .unwrap();
        let fetched = db.get_ghost_lock("lock123").unwrap().unwrap();
        assert_eq!(fetched.state, GhostLockState::Active);
        assert_eq!(fetched.funding_txid, Some("txid123".to_string()));

        // Get by owner
        let locks = db.get_ghost_locks_by_owner("ghost1abc").unwrap();
        assert_eq!(locks.len(), 1);

        // Get balance
        let balance = db.get_ghost_lock_balance("ghost1abc").unwrap();
        assert_eq!(balance, 10_000_000);
    }

    #[test]
    fn test_peer_operations() {
        let db = Database::in_memory().unwrap();
        let now = chrono::Utc::now().timestamp();

        let peer = PeerRecord {
            peer_id: "peer123".to_string(),
            address: "192.168.1.1".to_string(),
            port: 8333,
            node_id: Some("node456".to_string()),
            first_seen: now,
            last_seen: now,
            last_success: Some(now),
            last_failure: None,
            connection_count: 5,
            failure_count: 0,
            is_banned: false,
            ban_until: None,
            capabilities: Some("{}".to_string()),
            protocol_version: Some(1),
        };

        db.upsert_peer(&peer).unwrap();

        let fetched = db.get_peer("peer123").unwrap().unwrap();
        assert_eq!(fetched.address, "192.168.1.1");
        assert_eq!(fetched.connection_count, 5);

        let active = db.get_active_peers(10).unwrap();
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_wraith_round_operations() {
        let db = Database::in_memory().unwrap();
        let now = chrono::Utc::now().timestamp();

        let round = WraithRoundRecord {
            round_id: "wraith123".to_string(),
            coordinator_id: "coord456".to_string(),
            denomination: "Medium".to_string(),
            amount_sats: 10_000_000,
            phase: WraithPhase::Registration,
            participant_count: 0,
            min_participants: 5,
            max_participants: 50,
            registration_deadline: now + 3600,
            execution_deadline: None,
            split_txid: None,
            merge_txid: None,
            status: WraithStatus::Active,
            created_at: now,
            updated_at: now,
        };

        db.insert_wraith_round(&round).unwrap();

        let fetched = db.get_wraith_round("wraith123").unwrap().unwrap();
        assert_eq!(fetched.phase, WraithPhase::Registration);

        db.update_wraith_round_phase("wraith123", WraithPhase::Split)
            .unwrap();
        let fetched = db.get_wraith_round("wraith123").unwrap().unwrap();
        assert_eq!(fetched.phase, WraithPhase::Split);

        let active = db.get_active_wraith_rounds().unwrap();
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_reconciliation_operations() {
        let db = Database::in_memory().unwrap();
        let now = chrono::Utc::now().timestamp();

        let batch = ReconciliationRecord {
            batch_id: "batch123".to_string(),
            settlement_class: "Standard".to_string(),
            participant_count: 10,
            total_amount_sats: 100_000_000,
            merkle_root: "abc123".to_string(),
            l1_txid: None,
            l1_block_height: None,
            dispute_deadline: None,
            status: ReconciliationStatus::Pending,
            created_at: now,
            finalized_at: None,
        };

        db.insert_reconciliation_batch(&batch).unwrap();

        let fetched = db.get_reconciliation_batch("batch123").unwrap().unwrap();
        assert_eq!(fetched.participant_count, 10);

        db.update_reconciliation_l1_submitted("batch123", "txid456", 800100, 800244)
            .unwrap();
        let fetched = db.get_reconciliation_batch("batch123").unwrap().unwrap();
        assert_eq!(fetched.status, ReconciliationStatus::Submitted);
        assert_eq!(fetched.l1_txid, Some("txid456".to_string()));

        let pending = db.get_pending_reconciliation_batches().unwrap();
        assert_eq!(pending.len(), 1);
    }
}
