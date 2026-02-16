// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rpc/haze.h>

#include <haze/checkpoint.h>
#include <haze/checkpoint_signing.h>
#include <haze/exorcism.h>

#include <fstream>
#include <haze/legal_packet.h>
#include <net_processing.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <random.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <util/strencodings.h>
#include <validation.h>

using node::NodeContext;

static RPCHelpMan generatekeypair()
{
    return RPCHelpMan{
        "generatekeypair",
        "Generate a new Ed25519 keypair for checkpoint signing.\n"
        "The public key should be hardcoded in GetTrustedCheckpointKeys().\n"
        "The secret key must be stored securely and never shared.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "public_key", "The 32-byte Ed25519 public key (hex)"},
            {RPCResult::Type::STR_HEX, "secret_key", "The 32-byte Ed25519 secret key (hex)"},
        }},
        RPCExamples{
            HelpExampleCli("generatekeypair", "")
            + HelpExampleRpc("generatekeypair", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // Generate 32-byte random seed as secret key
    haze::Ed25519SecKey secret_key;
    GetStrongRandBytes(secret_key);

    // Derive public key
    haze::Ed25519PubKey public_key;
    haze::DerivePublicKey(secret_key, public_key);

    UniValue result(UniValue::VOBJ);
    result.pushKV("public_key", HexStr(public_key));
    result.pushKV("secret_key", HexStr(secret_key));
    return result;
},
    };
}

static RPCHelpMan signcheckpoint()
{
    return RPCHelpMan{
        "signcheckpoint",
        "Sign an existing checkpoint manifest with an Ed25519 secret key.\n"
        "Loads the manifest from the checkpoint directory, signs it, and writes it back.\n",
        {
            {"checkpoint_dir", RPCArg::Type::STR, RPCArg::Optional::NO, "Path to the checkpoint directory containing manifest.bin."},
            {"secret_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 32-byte Ed25519 secret key (hex)."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "signing_hash", "SHA-256 hash that was signed"},
            {RPCResult::Type::STR_HEX, "signature", "The 64-byte Ed25519 signature (hex)"},
            {RPCResult::Type::STR_HEX, "public_key", "The derived public key (hex)"},
        }},
        RPCExamples{
            HelpExampleCli("signcheckpoint", "/tmp/checkpoint abc123...")
            + HelpExampleRpc("signcheckpoint", "\"/tmp/checkpoint\", \"abc123...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::string checkpoint_dir = self.Arg<std::string>("checkpoint_dir");
    const std::string secret_key_hex = self.Arg<std::string>("secret_key");

    // Parse secret key from hex
    auto parsed = TryParseHex<uint8_t>(secret_key_hex);
    if (!parsed || parsed->size() != 32) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Secret key must be exactly 32 bytes (64 hex characters)");
    }
    haze::Ed25519SecKey secret_key;
    std::copy(parsed->begin(), parsed->end(), secret_key.begin());

    // Load manifest from disk
    haze::CheckpointManifest manifest;
    if (!haze::LoadCheckpoint(checkpoint_dir, manifest)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to load checkpoint manifest from " + checkpoint_dir);
    }

    // Sign the manifest
    if (!haze::SignCheckpoint(manifest, secret_key)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to sign checkpoint manifest");
    }

    // Re-serialize manifest with signature to disk
    const std::string manifest_path = checkpoint_dir + "/manifest.bin";
    DataStream ss;
    ss << manifest;

    std::ofstream manifest_file(manifest_path, std::ios::binary | std::ios::trunc);
    if (!manifest_file.is_open()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Cannot write signed manifest to " + manifest_path);
    }
    manifest_file.write(reinterpret_cast<const char*>(ss.data()), ss.size());
    manifest_file.flush();
    manifest_file.close();

    // Derive public key for response
    haze::Ed25519PubKey public_key;
    haze::DerivePublicKey(secret_key, public_key);

    UniValue result(UniValue::VOBJ);
    result.pushKV("signing_hash", manifest.GetSigningHash().GetHex());
    result.pushKV("signature", HexStr(manifest.signature));
    result.pushKV("public_key", HexStr(public_key));
    return result;
},
    };
}

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
            {RPCResult::Type::NUM, "checkpoint_height", "Checkpoint height (0 if none)"},
            {RPCResult::Type::STR, "checkpoint_hash", "Checkpoint block hash (zeros if none)"},
            {RPCResult::Type::STR, "conversion_method", "exorcism (from genesis) or exorcist (converted)"},
            {RPCResult::Type::STR, "conversion_date", "ISO 8601 date when conversion occurred"},
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
        "Returns the status of the Ghost Haze checkpoint system.\n"
        "Shows whether this node is serving a checkpoint, downloading one, or neither.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "serving", "Whether this node is serving a checkpoint to peers"},
            {RPCResult::Type::BOOL, "downloading", "Whether this node is downloading a checkpoint"},
            {RPCResult::Type::NUM, "height", /*optional=*/true, "Checkpoint height"},
            {RPCResult::Type::STR_HEX, "block_hash", /*optional=*/true, "Checkpoint block hash"},
            {RPCResult::Type::NUM, "utxo_count", /*optional=*/true, "Number of UTXOs in checkpoint"},
            {RPCResult::Type::NUM, "total_chunks", /*optional=*/true, "Number of UTXO chunk files"},
            {RPCResult::Type::BOOL, "signed", /*optional=*/true, "Whether the manifest is signed"},
            {RPCResult::Type::STR, "checkpoint_dir", /*optional=*/true, "Path to checkpoint directory"},
            {RPCResult::Type::NUM, "chunks_received", /*optional=*/true, "Chunks downloaded so far"},
            {RPCResult::Type::NUM, "chunks_total", /*optional=*/true, "Total chunks to download"},
            {RPCResult::Type::NUM, "percent_complete", /*optional=*/true, "Download progress percentage"},
        }},
        RPCExamples{
            HelpExampleCli("getcheckpointstatus", "")
            + HelpExampleRpc("getcheckpointstatus", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);

    UniValue result(UniValue::VOBJ);

    // Check if we're serving a local checkpoint
    const fs::path datadir = chainman.m_options.datadir;
    const fs::path checkpoint_dir = datadir / "checkpoint";
    const fs::path manifest_path = checkpoint_dir / "manifest.bin";

    if (fs::exists(manifest_path)) {
        haze::CheckpointManifest manifest;
        if (haze::LoadCheckpoint(fs::PathToString(checkpoint_dir), manifest)) {
            result.pushKV("serving", true);
            result.pushKV("downloading", false);
            result.pushKV("height", manifest.height);
            result.pushKV("block_hash", manifest.block_hash.GetHex());
            result.pushKV("utxo_count", static_cast<int64_t>(manifest.utxo_count));
            result.pushKV("total_chunks", static_cast<int>(manifest.chunk_manifest.total_chunks));

            // Check if manifest has a non-zero signature
            bool is_signed = false;
            for (const auto& byte : manifest.signature) {
                if (byte != 0) { is_signed = true; break; }
            }
            result.pushKV("signed", is_signed);
            result.pushKV("checkpoint_dir", fs::PathToString(checkpoint_dir));
            return result;
        }
    }

    // Check if we're downloading a checkpoint
    PeerManager& peerman = EnsurePeerman(node);
    auto dl_info = peerman.GetCheckpointDownloadProgress();
    if (dl_info) {
        result.pushKV("serving", false);
        result.pushKV("downloading", true);
        result.pushKV("height", dl_info->height);
        result.pushKV("chunks_received", static_cast<int64_t>(dl_info->chunks_received));
        result.pushKV("chunks_total", static_cast<int64_t>(dl_info->chunks_total));
        result.pushKV("percent_complete", dl_info->percent_complete);
        return result;
    }

    // Neither serving nor downloading
    result.pushKV("serving", false);
    result.pushKV("downloading", false);
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
        {"haze", &generatekeypair},
        {"haze", &signcheckpoint},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
