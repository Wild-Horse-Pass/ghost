// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_GSP_GSP_WALLET_H
#define BITCOIN_GSP_GSP_WALLET_H

#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <util/fs.h>
#include <pubkey.h>

namespace gsp {

/**
 * Registered wallet information stored in the registry.
 */
struct WalletRecord {
    //! Unique wallet identifier (RIPEMD160(SHA256(pubkey)) as hex)
    std::string wallet_id;

    //! The wallet's public key
    CPubKey pubkey;

    //! Timestamp when the wallet was first registered
    int64_t registered_at;

    //! Timestamp of last successful authentication
    int64_t last_seen_at;

    //! User-provided label (optional)
    std::string label;

    //! Whether the wallet is currently active
    bool active{true};
};

/**
 * WalletRegistry - SQLite-backed storage for registered wallets.
 *
 * Stores wallet registrations locally. Note that this does NOT store
 * any private keys or sensitive wallet data - only public keys and
 * metadata needed for authentication.
 *
 * Privacy consideration: The registry only knows that a wallet with
 * a certain public key has registered. It does NOT track:
 * - Wallet addresses (derived client-side)
 * - Transaction history
 * - Ghost Lock ownership (queried via BIP-157/158 filters)
 */
class WalletRegistry {
public:
    explicit WalletRegistry(const fs::path& data_dir);
    ~WalletRegistry();

    // Non-copyable
    WalletRegistry(const WalletRegistry&) = delete;
    WalletRegistry& operator=(const WalletRegistry&) = delete;

    /**
     * Initialize the database schema.
     * @return true if successful
     */
    bool Initialize();

    /**
     * Register a new wallet.
     * @param pubkey The wallet's public key
     * @param label Optional user-provided label
     * @return The wallet_id if successful
     */
    std::optional<std::string> RegisterWallet(const CPubKey& pubkey,
                                               const std::string& label = "");

    /**
     * Get a wallet record by ID.
     */
    std::optional<WalletRecord> GetWallet(const std::string& wallet_id);

    /**
     * Get a wallet record by public key.
     */
    std::optional<WalletRecord> GetWalletByPubkey(const CPubKey& pubkey);

    /**
     * Update the last_seen timestamp for a wallet.
     */
    bool UpdateLastSeen(const std::string& wallet_id);

    /**
     * Deactivate a wallet (soft delete).
     */
    bool DeactivateWallet(const std::string& wallet_id);

    /**
     * Reactivate a previously deactivated wallet.
     */
    bool ReactivateWallet(const std::string& wallet_id);

    /**
     * Get the total count of registered wallets.
     */
    uint32_t GetWalletCount();

    /**
     * Get the count of active wallets.
     */
    uint32_t GetActiveWalletCount();

    /**
     * Check if a wallet is registered.
     */
    bool IsRegistered(const std::string& wallet_id);

    /**
     * Check if a wallet is registered and active.
     */
    bool IsActive(const std::string& wallet_id);

    /**
     * List all registered wallets (for admin/debugging).
     * @param limit Maximum number of records to return
     * @param offset Starting offset for pagination
     */
    std::vector<WalletRecord> ListWallets(uint32_t limit = 100,
                                          uint32_t offset = 0);

private:
    fs::path m_data_dir;

    // Forward declaration for SQLite implementation
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace gsp

#endif // BITCOIN_GSP_GSP_WALLET_H
