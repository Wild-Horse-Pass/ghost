// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <haze/checkpoint.h>
#include <haze/headers_file.h>

#include <chain.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <serialize.h>
#include <streams.h>
#include <util/strencodings.h>

#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>

namespace haze {

uint256 CheckpointManifest::GetSigningHash() const
{
    // Hash everything except the signature field.
    HashWriter hw;
    hw << version << height << block_hash << utxo_count
       << headers_hash << utxo_hash << bloom_hash
       << chunk_manifest;
    return hw.GetSHA256();
}

UniValue CheckpointManifest::ToJSON() const
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("version", static_cast<int>(version));
    obj.pushKV("height", height);
    obj.pushKV("block_hash", block_hash.GetHex());
    obj.pushKV("utxo_count", static_cast<int64_t>(utxo_count));
    obj.pushKV("headers_hash", headers_hash.GetHex());
    obj.pushKV("utxo_hash", utxo_hash.GetHex());
    obj.pushKV("bloom_hash", bloom_hash.GetHex());
    obj.pushKV("signature", HexStr(signature));

    UniValue chunks_obj(UniValue::VOBJ);
    chunks_obj.pushKV("chunk_size", static_cast<int64_t>(chunk_manifest.chunk_size));
    chunks_obj.pushKV("total_chunks", static_cast<int>(chunk_manifest.total_chunks));

    UniValue chunks_arr(UniValue::VARR);
    for (const auto& ci : chunk_manifest.chunks) {
        UniValue chunk(UniValue::VOBJ);
        chunk.pushKV("index", static_cast<int>(ci.chunk_index));
        chunk.pushKV("hash", ci.hash.GetHex());
        chunk.pushKV("offset", static_cast<int64_t>(ci.offset));
        chunk.pushKV("size", static_cast<int64_t>(ci.size));
        chunk.pushKV("height_min", ci.height_min);
        chunk.pushKV("height_max", ci.height_max);
        chunks_arr.push_back(std::move(chunk));
    }
    chunks_obj.pushKV("chunks", std::move(chunks_arr));
    obj.pushKV("chunk_manifest", std::move(chunks_obj));

    return obj;
}

bool HashFile(const std::string& filepath, uint256& hash)
{
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error, "HashFile: cannot open %s\n", filepath);
        return false;
    }

    CSHA256 hasher;
    unsigned char buf[65536];

    while (file.good()) {
        file.read(reinterpret_cast<char*>(buf), sizeof(buf));
        std::streamsize bytes_read = file.gcount();
        if (bytes_read > 0) {
            hasher.Write(buf, static_cast<size_t>(bytes_read));
        }
    }

    hasher.Finalize(hash.begin());
    return true;
}

bool GenerateCheckpoint(const CChain& chain,
                        node::BlockManager& blockman,
                        int32_t height,
                        const std::string& output_dir,
                        CheckpointManifest& manifest)
{
    namespace fs = std::filesystem;

    // Validate inputs
    const CBlockIndex* tip = chain.Tip();
    if (!tip || tip->nHeight < height) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "GenerateCheckpoint: chain height %d < requested %d\n",
                      tip ? tip->nHeight : -1, height);
        return false;
    }

    const CBlockIndex* pindex = chain[height];
    if (!pindex) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "GenerateCheckpoint: no block index at height %d\n", height);
        return false;
    }

    // Create output directory
    fs::create_directories(output_dir);

    // Step 1: Write headers.bin
    const std::string headers_path = output_dir + "/headers.bin";
    if (!WriteHeadersFile(chain, height, headers_path)) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "GenerateCheckpoint: failed to write headers.bin\n");
        return false;
    }

    // Step 2: Hash headers.bin
    uint256 headers_hash;
    if (!HashFile(headers_path, headers_hash)) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "GenerateCheckpoint: failed to hash headers.bin\n");
        return false;
    }

    // Build manifest (UTXO generation and bloom filter are handled by Tasks 2.3/2.4)
    manifest.version = CHECKPOINT_VERSION;
    manifest.height = height;
    manifest.block_hash = *pindex->phashBlock;
    manifest.utxo_count = 0;       // Populated by UTXO dump step
    manifest.headers_hash = headers_hash;
    manifest.utxo_hash.SetNull();  // Populated by UTXO dump step
    manifest.bloom_hash.SetNull(); // Populated by bloom filter generation
    manifest.signature = {};       // Populated by signing step

    // Step 3: Serialize manifest to disk
    const std::string manifest_path = output_dir + "/manifest.bin";
    DataStream ss;
    ss << manifest;

    std::ofstream manifest_file(manifest_path, std::ios::binary | std::ios::trunc);
    if (!manifest_file.is_open()) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "GenerateCheckpoint: cannot write manifest.bin\n");
        return false;
    }
    manifest_file.write(reinterpret_cast<const char*>(ss.data()), ss.size());
    manifest_file.flush();

    LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
                  "GenerateCheckpoint: manifest written for height %d, block %s\n",
                  height, pindex->phashBlock->GetHex());
    return true;
}

bool LoadCheckpoint(const std::string& checkpoint_dir,
                    CheckpointManifest& manifest)
{
    const std::string manifest_path = checkpoint_dir + "/manifest.bin";
    std::ifstream file(manifest_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "LoadCheckpoint: cannot open %s\n", manifest_path);
        return false;
    }

    const auto file_size = file.tellg();
    file.seekg(0);

    std::vector<uint8_t> data(file_size);
    file.read(reinterpret_cast<char*>(data.data()), file_size);
    if (file.gcount() != file_size) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "LoadCheckpoint: short read on %s\n", manifest_path);
        return false;
    }

    try {
        DataStream ss{std::span<const uint8_t>{data}};
        ss >> manifest;
    } catch (const std::exception& e) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "LoadCheckpoint: deserialization failed: %s\n", e.what());
        return false;
    }

    if (manifest.version != CHECKPOINT_VERSION) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "LoadCheckpoint: unsupported version %u (expected %u)\n",
                      manifest.version, CHECKPOINT_VERSION);
        return false;
    }

    LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
                  "LoadCheckpoint: loaded manifest for height %d, block %s\n",
                  manifest.height, manifest.block_hash.GetHex());
    return true;
}

bool ValidateCheckpoint(const CheckpointManifest& manifest,
                        const std::string& checkpoint_dir)
{
    // Version check
    if (manifest.version != CHECKPOINT_VERSION) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "ValidateCheckpoint: bad version %u\n", manifest.version);
        return false;
    }

    // Verify headers.bin hash
    const std::string headers_path = checkpoint_dir + "/headers.bin";
    uint256 computed_headers_hash;
    if (!HashFile(headers_path, computed_headers_hash)) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "ValidateCheckpoint: cannot hash headers.bin\n");
        return false;
    }
    if (computed_headers_hash != manifest.headers_hash) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "ValidateCheckpoint: headers.bin hash mismatch\n");
        return false;
    }

    // Verify headers chain continuity
    if (!VerifyHeadersChain(headers_path, manifest.height + 1)) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "ValidateCheckpoint: headers chain verification failed\n");
        return false;
    }

    // Verify bloom.bin hash if present
    if (!manifest.bloom_hash.IsNull()) {
        const std::string bloom_path = checkpoint_dir + "/bloom.bin";
        uint256 computed_bloom_hash;
        if (!HashFile(bloom_path, computed_bloom_hash)) {
            LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                          "ValidateCheckpoint: cannot hash bloom.bin\n");
            return false;
        }
        if (computed_bloom_hash != manifest.bloom_hash) {
            LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                          "ValidateCheckpoint: bloom.bin hash mismatch\n");
            return false;
        }
    }

    // Verify UTXO chunk hashes
    for (const auto& chunk : manifest.chunk_manifest.chunks) {
        const std::string chunk_path = checkpoint_dir + "/utxo_" +
            std::to_string(chunk.chunk_index) + ".bin";
        uint256 computed_chunk_hash;
        if (!HashFile(chunk_path, computed_chunk_hash)) {
            LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                          "ValidateCheckpoint: cannot hash chunk %u\n", chunk.chunk_index);
            return false;
        }
        if (computed_chunk_hash != chunk.hash) {
            LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                          "ValidateCheckpoint: chunk %u hash mismatch\n", chunk.chunk_index);
            return false;
        }
    }

    LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
                  "ValidateCheckpoint: all integrity checks passed for height %d\n",
                  manifest.height);
    return true;
}

} // namespace haze
