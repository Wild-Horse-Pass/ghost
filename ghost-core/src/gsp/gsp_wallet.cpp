// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gsp/gsp_wallet.h>

#include <crypto/sha256.h>
#include <hash.h>
#include <logging.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <sqlite3.h>
#include <mutex>

namespace gsp {

// SQLite implementation for WalletRegistry
class WalletRegistry::Impl {
public:
    sqlite3* db{nullptr};
    std::mutex mutex;
    fs::path db_path;

    ~Impl() {
        if (db) {
            sqlite3_close(db);
        }
    }

    bool ExecSQL(const char* sql) {
        char* err = nullptr;
        int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            LogPrintf("GSP: SQLite error: %s\n", err ? err : "unknown");
            if (err) sqlite3_free(err);
            return false;
        }
        return true;
    }
};

WalletRegistry::WalletRegistry(const fs::path& data_dir)
    : m_data_dir(data_dir)
    , m_impl(std::make_unique<Impl>())
{
}

WalletRegistry::~WalletRegistry() = default;

bool WalletRegistry::Initialize()
{
    std::lock_guard<std::mutex> lock(m_impl->mutex);

    // Create data directory if it doesn't exist
    if (!fs::exists(m_data_dir)) {
        fs::create_directories(m_data_dir);
    }

    m_impl->db_path = m_data_dir / "wallets.db";
    int rc = sqlite3_open(m_impl->db_path.string().c_str(), &m_impl->db);
    if (rc != SQLITE_OK) {
        LogPrintf("GSP: Failed to open wallet database: %s\n",
                  sqlite3_errmsg(m_impl->db));
        return false;
    }

    // Create tables
    const char* schema = R"(
        CREATE TABLE IF NOT EXISTS wallets (
            wallet_id TEXT PRIMARY KEY,
            pubkey BLOB NOT NULL,
            registered_at INTEGER NOT NULL,
            last_seen_at INTEGER NOT NULL,
            label TEXT DEFAULT '',
            active INTEGER DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_wallets_pubkey ON wallets(pubkey);
        CREATE INDEX IF NOT EXISTS idx_wallets_active ON wallets(active);
    )";

    if (!m_impl->ExecSQL(schema)) {
        return false;
    }

    LogPrintf("GSP: Wallet registry initialized at %s\n", m_impl->db_path.string());
    return true;
}

static std::string ComputeWalletId(const CPubKey& pubkey)
{
    // wallet_id = hex(RIPEMD160(SHA256(pubkey)))
    uint160 hash = Hash160(pubkey);
    return HexStr(hash);
}

std::optional<std::string> WalletRegistry::RegisterWallet(const CPubKey& pubkey,
                                                          const std::string& label)
{
    if (!pubkey.IsValid()) {
        return std::nullopt;
    }

    std::lock_guard<std::mutex> lock(m_impl->mutex);

    std::string wallet_id = ComputeWalletId(pubkey);
    int64_t now = GetTime();

    // Check if already registered
    sqlite3_stmt* check_stmt;
    const char* check_sql = "SELECT wallet_id, active FROM wallets WHERE wallet_id = ?";
    if (sqlite3_prepare_v2(m_impl->db, check_sql, -1, &check_stmt, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }

    sqlite3_bind_text(check_stmt, 1, wallet_id.c_str(), -1, SQLITE_STATIC);
    int rc = sqlite3_step(check_stmt);

    if (rc == SQLITE_ROW) {
        // Already registered
        bool active = sqlite3_column_int(check_stmt, 1) != 0;
        sqlite3_finalize(check_stmt);

        if (!active) {
            // Reactivate
            ReactivateWallet(wallet_id);
        }
        UpdateLastSeen(wallet_id);
        return wallet_id;
    }
    sqlite3_finalize(check_stmt);

    // Insert new wallet
    sqlite3_stmt* insert_stmt;
    const char* insert_sql = R"(
        INSERT INTO wallets (wallet_id, pubkey, registered_at, last_seen_at, label, active)
        VALUES (?, ?, ?, ?, ?, 1)
    )";

    if (sqlite3_prepare_v2(m_impl->db, insert_sql, -1, &insert_stmt, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }

    std::vector<unsigned char> pubkey_data(pubkey.begin(), pubkey.end());

    sqlite3_bind_text(insert_stmt, 1, wallet_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_blob(insert_stmt, 2, pubkey_data.data(), pubkey_data.size(), SQLITE_STATIC);
    sqlite3_bind_int64(insert_stmt, 3, now);
    sqlite3_bind_int64(insert_stmt, 4, now);
    sqlite3_bind_text(insert_stmt, 5, label.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(insert_stmt);
    sqlite3_finalize(insert_stmt);

    if (rc != SQLITE_DONE) {
        LogPrintf("GSP: Failed to register wallet: %s\n", sqlite3_errmsg(m_impl->db));
        return std::nullopt;
    }

    LogPrintf("GSP: Registered new wallet %s\n", wallet_id);
    return wallet_id;
}

std::optional<WalletRecord> WalletRegistry::GetWallet(const std::string& wallet_id)
{
    std::lock_guard<std::mutex> lock(m_impl->mutex);

    sqlite3_stmt* stmt;
    const char* sql = R"(
        SELECT wallet_id, pubkey, registered_at, last_seen_at, label, active
        FROM wallets WHERE wallet_id = ?
    )";

    if (sqlite3_prepare_v2(m_impl->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, wallet_id.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return std::nullopt;
    }

    WalletRecord record;
    record.wallet_id = (const char*)sqlite3_column_text(stmt, 0);

    const void* pubkey_data = sqlite3_column_blob(stmt, 1);
    int pubkey_size = sqlite3_column_bytes(stmt, 1);
    if (pubkey_data && pubkey_size > 0) {
        record.pubkey.Set((const unsigned char*)pubkey_data,
                          (const unsigned char*)pubkey_data + pubkey_size);
    }

    record.registered_at = sqlite3_column_int64(stmt, 2);
    record.last_seen_at = sqlite3_column_int64(stmt, 3);
    record.label = (const char*)sqlite3_column_text(stmt, 4);
    record.active = sqlite3_column_int(stmt, 5) != 0;

    sqlite3_finalize(stmt);
    return record;
}

std::optional<WalletRecord> WalletRegistry::GetWalletByPubkey(const CPubKey& pubkey)
{
    std::string wallet_id = ComputeWalletId(pubkey);
    return GetWallet(wallet_id);
}

bool WalletRegistry::UpdateLastSeen(const std::string& wallet_id)
{
    std::lock_guard<std::mutex> lock(m_impl->mutex);

    sqlite3_stmt* stmt;
    const char* sql = "UPDATE wallets SET last_seen_at = ? WHERE wallet_id = ?";

    if (sqlite3_prepare_v2(m_impl->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_int64(stmt, 1, GetTime());
    sqlite3_bind_text(stmt, 2, wallet_id.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return rc == SQLITE_DONE;
}

bool WalletRegistry::DeactivateWallet(const std::string& wallet_id)
{
    std::lock_guard<std::mutex> lock(m_impl->mutex);

    sqlite3_stmt* stmt;
    const char* sql = "UPDATE wallets SET active = 0 WHERE wallet_id = ?";

    if (sqlite3_prepare_v2(m_impl->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, wallet_id.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return rc == SQLITE_DONE;
}

bool WalletRegistry::ReactivateWallet(const std::string& wallet_id)
{
    std::lock_guard<std::mutex> lock(m_impl->mutex);

    sqlite3_stmt* stmt;
    const char* sql = "UPDATE wallets SET active = 1, last_seen_at = ? WHERE wallet_id = ?";

    if (sqlite3_prepare_v2(m_impl->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_int64(stmt, 1, GetTime());
    sqlite3_bind_text(stmt, 2, wallet_id.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return rc == SQLITE_DONE;
}

uint32_t WalletRegistry::GetWalletCount()
{
    std::lock_guard<std::mutex> lock(m_impl->mutex);

    sqlite3_stmt* stmt;
    const char* sql = "SELECT COUNT(*) FROM wallets";

    if (sqlite3_prepare_v2(m_impl->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return 0;
    }

    uint32_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return count;
}

uint32_t WalletRegistry::GetActiveWalletCount()
{
    std::lock_guard<std::mutex> lock(m_impl->mutex);

    sqlite3_stmt* stmt;
    const char* sql = "SELECT COUNT(*) FROM wallets WHERE active = 1";

    if (sqlite3_prepare_v2(m_impl->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return 0;
    }

    uint32_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return count;
}

bool WalletRegistry::IsRegistered(const std::string& wallet_id)
{
    auto wallet = GetWallet(wallet_id);
    return wallet.has_value();
}

bool WalletRegistry::IsActive(const std::string& wallet_id)
{
    auto wallet = GetWallet(wallet_id);
    return wallet.has_value() && wallet->active;
}

std::vector<WalletRecord> WalletRegistry::ListWallets(uint32_t limit, uint32_t offset)
{
    std::lock_guard<std::mutex> lock(m_impl->mutex);

    std::vector<WalletRecord> records;

    sqlite3_stmt* stmt;
    const char* sql = R"(
        SELECT wallet_id, pubkey, registered_at, last_seen_at, label, active
        FROM wallets
        ORDER BY registered_at DESC
        LIMIT ? OFFSET ?
    )";

    if (sqlite3_prepare_v2(m_impl->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return records;
    }

    sqlite3_bind_int(stmt, 1, limit);
    sqlite3_bind_int(stmt, 2, offset);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        WalletRecord record;
        record.wallet_id = (const char*)sqlite3_column_text(stmt, 0);

        const void* pubkey_data = sqlite3_column_blob(stmt, 1);
        int pubkey_size = sqlite3_column_bytes(stmt, 1);
        if (pubkey_data && pubkey_size > 0) {
            record.pubkey.Set((const unsigned char*)pubkey_data,
                              (const unsigned char*)pubkey_data + pubkey_size);
        }

        record.registered_at = sqlite3_column_int64(stmt, 2);
        record.last_seen_at = sqlite3_column_int64(stmt, 3);
        record.label = (const char*)sqlite3_column_text(stmt, 4);
        record.active = sqlite3_column_int(stmt, 5) != 0;

        records.push_back(std::move(record));
    }

    sqlite3_finalize(stmt);
    return records;
}

} // namespace gsp
