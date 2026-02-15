// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rpc/haze.h>

#include <haze/checkpoint.h>
#include <haze/exorcism.h>
#include <haze/legal_packet.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <validation.h>

using node::NodeContext;

static RPCHelpMan gethazestatus()
{
    return RPCHelpMan{
        "gethazestatus",
        "Returns the current Ghost Haze operating status.\n"
        "Includes mode, exorcism state, storage statistics, and checkpoint info.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "mode", "Operating mode: 'hazed' or 'full_archive'"},
            {RPCResult::Type::BOOL, "exorcism_active", "Whether Ghost Exorcism is stripping incoming blocks"},
            {RPCResult::Type::NUM, "blocks_stripped", "Total blocks processed through Exorcism"},
            {RPCResult::Type::NUM, "bytes_stripped", "Total bytes stripped from blocks"},
            {RPCResult::Type::NUM, "chain_tip", "Current chain tip height"},
            {RPCResult::Type::NUM, "storage_gb", "Approximate structural archive size in GB"},
        }},
        RPCExamples{
            HelpExampleCli("gethazestatus", "")
            + HelpExampleRpc("gethazestatus", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);

    const auto& exorcism = chainman.m_blockman.m_ghost_exorcism;

    UniValue result(UniValue::VOBJ);
    result.pushKV("mode", exorcism.IsActive() ? "hazed" : "full_archive");
    result.pushKV("exorcism_active", exorcism.IsActive());
    result.pushKV("blocks_stripped", (int64_t)exorcism.GetBlocksProcessed());
    result.pushKV("bytes_stripped", (int64_t)exorcism.GetTotalBytesStripped());

    {
        LOCK(cs_main);
        result.pushKV("chain_tip", chainman.ActiveChain().Height());
    }

    // Approximate storage size from GSB files
    const fs::path datadir = chainman.m_options.datadir;
    const fs::path blocks_dir = datadir / "blocks";
    uint64_t gsb_bytes = 0;
    if (fs::exists(blocks_dir)) {
        std::error_code ec;
        for (const auto& entry : fs::directory_iterator(blocks_dir, ec)) {
            if (!entry.is_regular_file()) continue;
            const std::string fn = entry.path().filename().string();
            if (fn.size() >= 3 && fn.substr(0, 3) == "gsb" && fn.find(".dat") != std::string::npos) {
                gsb_bytes += entry.file_size(ec);
            }
        }
    }
    result.pushKV("storage_gb", static_cast<double>(gsb_bytes) / (1024.0 * 1024.0 * 1024.0));

    return result;
},
    };
}

static RPCHelpMan getlegalpacket()
{
    return RPCHelpMan{
        "getlegalpacket",
        "Generate a Legal Compliance Packet proving this node does not store hazeable content.\n"
        "Only available in Hazed mode. Returns an error for Full Archive nodes.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "ghost_core_version", "Ghost Core version string"},
            {RPCResult::Type::STR, "specification_version", "Ghost Haze specification version"},
            {RPCResult::Type::STR, "node_mode", "Operating mode (HAZED)"},
            {RPCResult::Type::BOOL, "exorcism_active", "Whether Exorcism is active"},
            {RPCResult::Type::STR, "haze_status", "COMPLETE or IN_PROGRESS"},
            {RPCResult::Type::NUM, "blocks_stripped", "Total blocks stripped"},
            {RPCResult::Type::NUM, "chain_tip", "Current chain tip height"},
            {RPCResult::Type::NUM, "structural_archive_size_gb", "Structural archive size in GB"},
            {RPCResult::Type::BOOL, "hazeable_content_on_disk", "Whether blk*.dat files exist"},
            {RPCResult::Type::STR, "conversion_method", "exorcism (from genesis) or exorcist (converted)"},
            {RPCResult::Type::STR, "legal_summary", "Court-ready plain English summary"},
            {RPCResult::Type::STR, "generated_at", "ISO 8601 timestamp"},
        }},
        RPCExamples{
            HelpExampleCli("getlegalpacket", "")
            + HelpExampleRpc("getlegalpacket", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);

    const CChain& chain = WITH_LOCK(cs_main, return chainman.ActiveChain());
    const fs::path datadir = chainman.m_options.datadir;

    auto packet = haze::GenerateLegalPacket(chainman.m_blockman, chain, datadir);
    if (!packet.has_value()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Legal Compliance Packet is only available in Hazed mode");
    }

    return packet->ToJSON();
},
    };
}

static RPCHelpMan getcheckpointstatus()
{
    return RPCHelpMan{
        "getcheckpointstatus",
        "Returns the status of the Ghost Haze checkpoint system.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::NUM, "height", "Checkpoint height (0 if none)"},
            {RPCResult::Type::STR_HEX, "block_hash", "Checkpoint block hash"},
            {RPCResult::Type::BOOL, "checkpoint_loaded", "Whether a checkpoint is loaded"},
        }},
        RPCExamples{
            HelpExampleCli("getcheckpointstatus", "")
            + HelpExampleRpc("getcheckpointstatus", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue result(UniValue::VOBJ);

    // Checkpoint status — currently returns basic info
    // Full checkpoint integration (loading from peers) will be expanded
    // as checkpoint distribution matures
    result.pushKV("height", 0);
    result.pushKV("block_hash", uint256::ZERO.GetHex());
    result.pushKV("checkpoint_loaded", false);

    return result;
},
    };
}

void RegisterHazeRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"haze", &gethazestatus},
        {"haze", &getlegalpacket},
        {"haze", &getcheckpointstatus},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
