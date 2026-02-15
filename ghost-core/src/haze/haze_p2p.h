// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HAZE_HAZE_P2P_H
#define BITCOIN_HAZE_HAZE_P2P_H

#include <serialize.h>
#include <uint256.h>

#include <string>
#include <vector>

namespace haze {

/**
 * Redirect message: sent by Hazed nodes when a non-Hazed peer requests a full block.
 *
 * Contains the hash of the requested block and a list of known Full Archive peer
 * addresses as strings ("ip:port") that can serve the complete data.
 *
 * Using strings avoids CAddress/CService serialization parameter requirements.
 */
struct GhostRedirect {
    uint256 block_hash;
    std::vector<std::string> archive_peers;

    SERIALIZE_METHODS(GhostRedirect, obj)
    {
        READWRITE(obj.block_hash, obj.archive_peers);
    }
};

} // namespace haze

#endif // BITCOIN_HAZE_HAZE_P2P_H
