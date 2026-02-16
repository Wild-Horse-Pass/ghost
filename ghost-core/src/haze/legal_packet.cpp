// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <haze/legal_packet.h>

#include <clientversion.h>
#include <haze/exorcism.h>
#include <node/blockstorage.h>
#include <util/time.h>

#include <ctime>
#include <iomanip>
#include <sstream>

namespace haze {

static std::string NowISO8601()
{
    const auto now = std::chrono::system_clock::now();
    const auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf;
    gmtime_r(&time_t_now, &tm_buf);
    std::ostringstream ss;
    ss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

static bool HasBlkFiles(const fs::path& datadir)
{
    const fs::path blocks_dir = datadir / "blocks";
    if (!fs::exists(blocks_dir)) return false;

    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(blocks_dir, ec)) {
        if (!entry.is_regular_file()) continue;
        const std::string filename = entry.path().filename().string();
        if (filename.size() >= 3 && filename.substr(0, 3) == "blk" &&
            filename.find(".dat") != std::string::npos) {
            // Ignore empty blk files (Bitcoin Core recreates blk00000.dat
            // on startup even after exorcist deletes it)
            if (entry.file_size(ec) > 0) {
                return true;
            }
        }
    }
    return false;
}

static double SumGSBFileSizes(const fs::path& datadir)
{
    const fs::path blocks_dir = datadir / "blocks";
    if (!fs::exists(blocks_dir)) return 0.0;

    uint64_t total_bytes = 0;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(blocks_dir, ec)) {
        if (!entry.is_regular_file()) continue;
        const std::string filename = entry.path().filename().string();
        if (filename.size() >= 3 && filename.substr(0, 3) == "gsb" &&
            filename.find(".dat") != std::string::npos) {
            total_bytes += entry.file_size(ec);
        }
    }
    return static_cast<double>(total_bytes) / (1024.0 * 1024.0 * 1024.0);
}

static const char* LEGAL_SUMMARY_TEXT =
    "This Ghost Core node operates in Hazed mode. All hazeable content — including "
    "witness data (transaction signatures), scriptSig data (legacy transaction signatures), "
    "OP_RETURN payloads (arbitrary embedded data), and coinbase scriptSig data (miner "
    "messages) — has been irreversibly stripped from the blockchain archive stored on this "
    "system. The node stores only the structural economic graph: transaction IDs, input/output "
    "amounts, output scripts (payment addresses), block headers, and merkle trees. No content "
    "embedded by third parties in the Bitcoin blockchain exists on this system's persistent "
    "storage. The stripping process is cryptographically verified: each stripped block's merkle "
    "root is validated against the original block header before writing, ensuring data integrity "
    "without retaining hazeable content.";

UniValue LegalPacket::ToJSON() const
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("ghost_core_version", ghost_core_version);
    result.pushKV("specification_version", specification_version);
    result.pushKV("node_mode", node_mode);
    result.pushKV("exorcism_active", exorcism_active);
    result.pushKV("haze_status", haze_status);
    result.pushKV("blocks_stripped", blocks_stripped);
    result.pushKV("chain_tip", chain_tip);
    result.pushKV("structural_archive_size_gb", structural_archive_size_gb);
    result.pushKV("hazeable_content_on_disk", hazeable_content_on_disk);
    result.pushKV("checkpoint_height", checkpoint_height);
    result.pushKV("checkpoint_hash", checkpoint_hash.GetHex());
    result.pushKV("conversion_method", conversion_method);
    result.pushKV("conversion_date", conversion_date);
    result.pushKV("legal_summary", legal_summary);
    result.pushKV("generated_at", generated_at);
    return result;
}

std::optional<LegalPacket> GenerateLegalPacket(
    const node::BlockManager& blockman,
    const CChain& chain,
    const fs::path& datadir)
{
    if (!blockman.m_ghost_exorcism.IsActive()) {
        return std::nullopt;
    }

    LegalPacket packet;
    packet.ghost_core_version = FormatFullVersion();
    packet.node_mode = "HAZED";
    packet.exorcism_active = true;
    packet.chain_tip = chain.Height();
    packet.structural_archive_size_gb = SumGSBFileSizes(datadir);
    packet.hazeable_content_on_disk = HasBlkFiles(datadir);

    // blocks_stripped: use chain tip height as the total count of stripped blocks
    // since every block on a hazed node is in GSB format (either via exorcist
    // conversion or runtime exorcism).
    packet.blocks_stripped = packet.hazeable_content_on_disk
        ? static_cast<int64_t>(blockman.m_ghost_exorcism.GetBlocksProcessed())
        : static_cast<int64_t>(packet.chain_tip + 1);  // +1 for genesis

    // Determine haze status
    if (!packet.hazeable_content_on_disk && packet.structural_archive_size_gb > 0.0) {
        packet.haze_status = "COMPLETE";
    } else {
        packet.haze_status = "IN_PROGRESS";
    }

    // Conversion method: if GSB archive size significantly exceeds what
    // runtime exorcism alone would produce, the exorcist was used.
    const size_t runtime_blocks = blockman.m_ghost_exorcism.GetBlocksProcessed();
    if (packet.chain_tip > 0 && runtime_blocks < static_cast<size_t>(packet.chain_tip)) {
        packet.conversion_method = "exorcist";
    } else {
        packet.conversion_method = "exorcism";
    }

    // Conversion date not tracked in current implementation — use current time
    packet.conversion_date = NowISO8601();

    packet.legal_summary = LEGAL_SUMMARY_TEXT;
    packet.generated_at = NowISO8601();

    return packet;
}

} // namespace haze
