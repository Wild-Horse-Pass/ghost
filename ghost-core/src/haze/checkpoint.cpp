// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <haze/checkpoint.h>
#include <haze/bloom_filter.h>
#include <haze/headers_file.h>

#include <chain.h>
#include <coins.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <node/utxo_snapshot.h>
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

bool GenerateUTXOChunks(CCoinsViewCursor& pcursor,
                         uint64_t utxo_count,
                         const uint256& utxo_hash,
                         const std::string& output_dir,
                         uint32_t chunk_size,
                         CheckpointManifest& manifest,
                         const std::function<void()>& interruption_point)
{
    namespace fs = std::filesystem;

    manifest.utxo_count = utxo_count;
    manifest.utxo_hash = utxo_hash;

    fs::create_directories(output_dir);

    // Track chunk state
    uint32_t chunk_index = 0;
    uint64_t chunk_bytes = 0;
    uint64_t total_offset = 0;
    size_t coins_written = 0;
    unsigned int iter = 0;

    CSHA256 chunk_hasher;
    std::ofstream chunk_file;

    auto open_new_chunk = [&]() {
        std::string path = output_dir + "/utxo_" + std::to_string(chunk_index) + ".bin";
        chunk_file.open(path, std::ios::binary | std::ios::trunc);
        chunk_bytes = 0;
        chunk_hasher.Reset();
    };

    auto close_chunk = [&]() {
        if (!chunk_file.is_open()) return;
        chunk_file.flush();
        chunk_file.close();

        // Record chunk info in manifest
        ChunkInfo ci;
        ci.chunk_index = chunk_index;
        ci.offset = total_offset;
        ci.size = chunk_bytes;
        ci.height_min = 0;  // Height tracking not available from cursor order
        ci.height_max = manifest.height;
        chunk_hasher.Finalize(ci.hash.begin());
        manifest.chunk_manifest.chunks.push_back(std::move(ci));

        total_offset += chunk_bytes;
        chunk_index++;
    };

    // Write coins in the same txid-grouped format as WriteUTXOSnapshot,
    // but WITHOUT the SnapshotMetadata header (chunks are raw coin data only).
    open_new_chunk();
    if (!chunk_file.is_open()) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "GenerateUTXOChunks: cannot open first chunk file\n");
        return false;
    }

    COutPoint key;
    Coin coin;
    Txid last_hash;
    std::vector<std::pair<uint32_t, Coin>> coins;

    auto write_coins_to_chunk = [&](const Txid& txid, const std::vector<std::pair<uint32_t, Coin>>& coins_vec) {
        // Serialize to a buffer first so we can hash and measure size
        DataStream ss;
        ss << txid;
        WriteCompactSize(ss, coins_vec.size());
        for (const auto& [n, c] : coins_vec) {
            WriteCompactSize(ss, n);
            ss << c;
        }

        // Check if we need to start a new chunk (don't split a tx group across chunks)
        if (chunk_bytes > 0 && chunk_bytes + ss.size() > chunk_size) {
            close_chunk();
            open_new_chunk();
            if (!chunk_file.is_open()) return false;
        }

        chunk_file.write(reinterpret_cast<const char*>(ss.data()), ss.size());
        chunk_hasher.Write(reinterpret_cast<const unsigned char*>(ss.data()), ss.size());
        chunk_bytes += ss.size();
        coins_written += coins_vec.size();
        return true;
    };

    pcursor.GetKey(key);
    last_hash = key.hash;

    while (pcursor.Valid()) {
        if (interruption_point && iter % 5000 == 0) interruption_point();
        ++iter;

        if (pcursor.GetKey(key) && pcursor.GetValue(coin)) {
            if (key.hash != last_hash) {
                if (!write_coins_to_chunk(last_hash, coins)) return false;
                last_hash = key.hash;
                coins.clear();
            }
            coins.emplace_back(key.n, coin);
        }
        pcursor.Next();
    }

    // Flush remaining coins
    if (!coins.empty()) {
        if (!write_coins_to_chunk(last_hash, coins)) return false;
    }

    // Close final chunk
    close_chunk();

    // Populate chunk manifest metadata
    manifest.chunk_manifest.chunk_size = chunk_size;
    manifest.chunk_manifest.total_chunks = chunk_index;

    LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
                  "GenerateUTXOChunks: wrote %zu coins to %u chunks (%llu bytes total)\n",
                  coins_written, chunk_index,
                  static_cast<unsigned long long>(total_offset));

    if (coins_written != manifest.utxo_count) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "GenerateUTXOChunks: coin count mismatch: wrote %zu, expected %llu\n",
                      coins_written, static_cast<unsigned long long>(manifest.utxo_count));
        return false;
    }

    return true;
}

bool GenerateBloomFilter(CCoinsViewCursor& pcursor,
                          const std::string& output_dir,
                          CheckpointManifest& manifest,
                          const std::function<void()>& interruption_point)
{
    namespace fs = std::filesystem;

    if (manifest.utxo_count == 0) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "GenerateBloomFilter: utxo_count is 0 (run GenerateUTXOChunks first)\n");
        return false;
    }

    // Construct bloom filter sized for the UTXO count at 0.1% FPR
    SwiftSyncFilter filter(manifest.utxo_count, 0.001);

    COutPoint key;
    Coin coin;
    uint64_t count = 0;
    unsigned int iter = 0;

    while (pcursor.Valid()) {
        if (interruption_point && iter % 5000 == 0) interruption_point();
        ++iter;

        if (pcursor.GetKey(key) && pcursor.GetValue(coin)) {
            filter.Insert(key);
            count++;
        }
        pcursor.Next();
    }

    LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
                  "GenerateBloomFilter: inserted %llu outpoints (filter %zu bytes, %u hashes)\n",
                  static_cast<unsigned long long>(count),
                  filter.GetSizeBytes(), filter.GetNumHashes());

    // Save to disk
    fs::create_directories(output_dir);
    const std::string bloom_path = output_dir + "/bloom.bin";
    if (!filter.Save(bloom_path)) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "GenerateBloomFilter: failed to save bloom.bin\n");
        return false;
    }

    // Hash the bloom file for manifest
    uint256 bloom_hash;
    if (!HashFile(bloom_path, bloom_hash)) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "GenerateBloomFilter: failed to hash bloom.bin\n");
        return false;
    }
    manifest.bloom_hash = bloom_hash;

    return true;
}

bool AssembleSnapshot(const CheckpointManifest& manifest,
                       const std::string& chunks_dir,
                       const std::string& output_path,
                       const MessageStartChars& network_magic)
{
    // Create the SnapshotMetadata header
    node::SnapshotMetadata metadata(network_magic, manifest.block_hash, manifest.utxo_count);

    std::ofstream outfile(output_path, std::ios::binary | std::ios::trunc);
    if (!outfile.is_open()) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "AssembleSnapshot: cannot open output file %s\n", output_path);
        return false;
    }

    // Serialize the metadata header
    DataStream ss;
    ss << metadata;
    outfile.write(reinterpret_cast<const char*>(ss.data()), ss.size());

    // Concatenate chunk files in order
    uint64_t total_bytes = ss.size();
    for (uint32_t i = 0; i < manifest.chunk_manifest.total_chunks; i++) {
        const std::string chunk_path = chunks_dir + "/utxo_" + std::to_string(i) + ".bin";
        std::ifstream chunk_file(chunk_path, std::ios::binary);
        if (!chunk_file.is_open()) {
            LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                          "AssembleSnapshot: cannot open chunk %s\n", chunk_path);
            return false;
        }

        // Stream the chunk data
        char buf[65536];
        while (chunk_file.good()) {
            chunk_file.read(buf, sizeof(buf));
            std::streamsize bytes_read = chunk_file.gcount();
            if (bytes_read > 0) {
                outfile.write(buf, bytes_read);
                total_bytes += bytes_read;
            }
        }
    }

    outfile.flush();
    if (!outfile.good()) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "AssembleSnapshot: write error on %s\n", output_path);
        return false;
    }
    outfile.close();

    LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
                  "AssembleSnapshot: wrote %llu bytes to %s (%u chunks + header)\n",
                  static_cast<unsigned long long>(total_bytes), output_path,
                  manifest.chunk_manifest.total_chunks);
    return true;
}

} // namespace haze
