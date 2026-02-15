// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HAZE_LEGAL_PACKET_H
#define BITCOIN_HAZE_LEGAL_PACKET_H

#include <chain.h>
#include <uint256.h>
#include <univalue.h>
#include <util/fs.h>

#include <cstdint>
#include <optional>
#include <string>

namespace node {
class BlockManager;
} // namespace node

namespace haze {

/**
 * Legal Compliance Packet: court-ready documentation proving a Ghost Core node
 * does not store hazeable content (witness data, scriptSig, OP_RETURN payloads,
 * coinbase scriptSig) on disk.
 *
 * Only applicable to Hazed nodes. Full Archive nodes return an error.
 */
struct LegalPacket {
    std::string ghost_core_version;
    std::string specification_version{"2.0"};
    std::string node_mode;             //!< "HAZED"
    bool exorcism_active{false};
    std::string haze_status;           //!< "COMPLETE" or "IN_PROGRESS"
    int64_t blocks_stripped{0};
    int32_t chain_tip{0};
    double structural_archive_size_gb{0.0};
    bool hazeable_content_on_disk{false}; //!< Scan for blk*.dat
    int32_t checkpoint_height{0};
    uint256 checkpoint_hash;
    std::string conversion_method;     //!< "exorcism" (from genesis) or "exorcist" (converted)
    std::string conversion_date;       //!< ISO 8601
    std::string legal_summary;         //!< Court-ready plain English
    std::string generated_at;          //!< ISO 8601

    UniValue ToJSON() const;
};

/**
 * Generate a legal compliance packet from current node state.
 *
 * @param[in] blockman  The block manager (for exorcism stats and file access).
 * @param[in] chain     The active chain (for tip height).
 * @param[in] datadir   Path to the data directory (for file scanning).
 * @return The legal packet, or std::nullopt if the node is not in Hazed mode.
 */
std::optional<LegalPacket> GenerateLegalPacket(
    const node::BlockManager& blockman,
    const CChain& chain,
    const fs::path& datadir);

} // namespace haze

#endif // BITCOIN_HAZE_LEGAL_PACKET_H
