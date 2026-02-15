// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <haze/swiftsync.h>

#include <coins.h>
#include <logging.h>
#include <undo.h>

namespace haze {

void SwiftSyncController::Init(SwiftSyncFilter&& filter,
                                int32_t checkpoint_height,
                                const uint256& utxo_hash,
                                size_t max_ephemeral_memory)
{
    m_filter = std::move(filter);
    m_checkpoint_height = checkpoint_height;
    m_utxo_hash = utxo_hash;
    m_max_ephemeral_memory = max_ephemeral_memory;
    m_active = true;
    m_writes_saved = 0;
    m_ephemeral_total = 0;

    LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
                  "SwiftSync: activated, checkpoint height %d, filter %zu MB\n",
                  checkpoint_height, m_filter.GetSizeBytes() / (1024 * 1024));
}

bool SwiftSyncController::ShouldPersist(const COutPoint& outpoint) const
{
    return m_filter.MayContain(outpoint);
}

void SwiftSyncController::TrackEphemeral(const COutPoint& outpoint, Coin&& coin)
{
    m_ephemeral_coins.emplace(outpoint, std::move(coin));
    m_ephemeral_total.fetch_add(1, std::memory_order_relaxed);
}

const Coin* SwiftSyncController::GetEphemeral(const COutPoint& outpoint) const
{
    auto it = m_ephemeral_coins.find(outpoint);
    if (it != m_ephemeral_coins.end()) {
        return &it->second;
    }
    return nullptr;
}

bool SwiftSyncController::SpendEphemeral(const COutPoint& outpoint)
{
    auto it = m_ephemeral_coins.find(outpoint);
    if (it != m_ephemeral_coins.end()) {
        m_ephemeral_coins.erase(it);
        m_writes_saved.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    return false;
}

size_t SwiftSyncController::GetEphemeralMemoryUsage() const
{
    // Approximate: each entry is COutPoint (36 bytes) + Coin (variable) + hash map overhead (~64 bytes)
    size_t total = 0;
    for (const auto& [outpoint, coin] : m_ephemeral_coins) {
        total += sizeof(COutPoint) + sizeof(Coin) + coin.DynamicMemoryUsage() + 64;
    }
    return total;
}

void SwiftSyncController::Deactivate()
{
    if (!m_active) return;

    m_active = false;

    LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
                  "SwiftSync: deactivated at checkpoint height %d\n"
                  "  LevelDB writes saved: %llu\n"
                  "  Total ephemeral coins tracked: %llu\n"
                  "  Remaining ephemeral coins: %zu\n",
                  m_checkpoint_height,
                  static_cast<unsigned long long>(m_writes_saved.load()),
                  static_cast<unsigned long long>(m_ephemeral_total.load()),
                  m_ephemeral_coins.size());

    if (!m_ephemeral_coins.empty()) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Warning,
                      "SwiftSync: %zu ephemeral coins remain at deactivation "
                      "(false positives from Bloom filter)\n",
                      m_ephemeral_coins.size());
    }

    // Clear ephemeral cache and release memory
    m_ephemeral_coins.clear();
    // Release the Bloom filter memory
    m_filter = SwiftSyncFilter();
}

void SwiftSyncUpdateCoins(const CTransaction& tx,
                          CCoinsViewCache& view,
                          SwiftSyncController& controller,
                          CTxUndo& txundo,
                          int nHeight)
{
    const bool is_coinbase = tx.IsCoinBase();
    const Txid& txid = tx.GetHash();

    // Process inputs (spends)
    if (!is_coinbase) {
        txundo.vprevout.reserve(tx.vin.size());
        for (const CTxIn& txin : tx.vin) {
            // Try ephemeral cache first
            if (controller.SpendEphemeral(txin.prevout)) {
                // Spent from ephemeral cache — no undo data needed for
                // ephemeral coins since they won't exist in chainstate.
                // Push an empty coin as placeholder to keep undo vector aligned.
                txundo.vprevout.emplace_back();
                continue;
            }

            // Fall through to normal persistent spend
            txundo.vprevout.emplace_back();
            bool is_spent = view.SpendCoin(txin.prevout, &txundo.vprevout.back());
            assert(is_spent);
        }
    }

    // Process outputs (creates)
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        if (tx.vout[i].scriptPubKey.IsUnspendable()) continue;

        COutPoint outpoint(txid, i);

        if (controller.ShouldPersist(outpoint)) {
            // Bloom filter says this outpoint likely survives to checkpoint.
            // Persist to LevelDB via normal path.
            bool overwrite = is_coinbase;
            view.AddCoin(outpoint, Coin(tx.vout[i], nHeight, is_coinbase), overwrite);
        } else {
            // Not in Bloom filter — expected to be spent before checkpoint.
            // Track in ephemeral cache only.
            controller.TrackEphemeral(outpoint, Coin(tx.vout[i], nHeight, is_coinbase));
        }
    }
}

} // namespace haze
