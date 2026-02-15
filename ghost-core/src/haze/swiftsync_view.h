// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HAZE_SWIFTSYNC_VIEW_H
#define BITCOIN_HAZE_SWIFTSYNC_VIEW_H

#include <coins.h>
#include <haze/swiftsync.h>

namespace haze {

/**
 * CCoinsView wrapper that also checks the SwiftSync ephemeral cache.
 *
 * During SwiftSync IBD, coins that the Bloom filter says will be spent
 * before the checkpoint are stored only in the ephemeral cache (memory).
 * Script validation (CheckInputScripts) needs to look up these coins
 * during ConnectBlock. This view intercepts GetCoin/HaveCoin and checks
 * the ephemeral cache before falling through to the underlying view.
 *
 * Usage: Wrap the existing CCoinsViewCache during ConnectBlock when
 * SwiftSync is active:
 *
 *   SwiftSyncCoinsView ssview(&view, controller);
 *   // Use ssview for script checks that need to find ephemeral coins
 */
class SwiftSyncCoinsView : public CCoinsViewBacked
{
public:
    SwiftSyncCoinsView(CCoinsView* base, const SwiftSyncController& controller)
        : CCoinsViewBacked(base), m_controller(controller) {}

    std::optional<Coin> GetCoin(const COutPoint& outpoint) const override
    {
        // Check ephemeral cache first
        const Coin* ephemeral = m_controller.GetEphemeral(outpoint);
        if (ephemeral) {
            return *ephemeral;
        }
        // Fall through to base view
        return CCoinsViewBacked::GetCoin(outpoint);
    }

    bool HaveCoin(const COutPoint& outpoint) const override
    {
        // Check ephemeral cache first
        if (m_controller.GetEphemeral(outpoint)) {
            return true;
        }
        return CCoinsViewBacked::HaveCoin(outpoint);
    }

private:
    const SwiftSyncController& m_controller;
};

} // namespace haze

#endif // BITCOIN_HAZE_SWIFTSYNC_VIEW_H
