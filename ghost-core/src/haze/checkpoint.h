// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HAZE_CHECKPOINT_H
#define BITCOIN_HAZE_CHECKPOINT_H

#include <kernel/messagestartchars.h>
#include <serialize.h>
#include <uint256.h>
#include <univalue.h>

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

class CCoinsViewCursor;

class CChain;
class CBlockIndex;

namespace node {
class BlockManager;
} // namespace node

namespace haze {

/** Default UTXO chunk size: 2 MB.
 *  Must be well under MAX_PROTOCOL_MESSAGE_LENGTH (4 MB) since chunks
 *  are sent as P2P messages with a small amount of framing overhead. */
static constexpr uint32_t DEFAULT_CHUNK_SIZE = 2 * 1024 * 1024;

/** Checkpoint manifest version. */
static constexpr uint32_t CHECKPOINT_VERSION = 1;

/**
 * Information about a single UTXO data chunk within the checkpoint.
 *
 * Each chunk is a contiguous segment of the serialized UTXO set,
 * identified by a SHA-256 hash for integrity verification.
 */
struct ChunkInfo {
    uint32_t chunk_index;
    uint256 hash;          // SHA-256 of chunk data
    uint64_t offset;       // Byte offset within the UTXO data stream
    uint64_t size;         // Size of this chunk in bytes
    int32_t height_min;    // First block height whose UTXOs appear in this chunk
    int32_t height_max;    // Last block height whose UTXOs appear in this chunk

    SERIALIZE_METHODS(ChunkInfo, obj)
    {
        READWRITE(obj.chunk_index, obj.hash, obj.offset, obj.size,
                  obj.height_min, obj.height_max);
    }
};

/**
 * Manifest describing how UTXO data is split into downloadable chunks.
 */
struct ChunkManifest {
    uint32_t chunk_size{DEFAULT_CHUNK_SIZE};
    uint32_t total_chunks{0};
    std::vector<ChunkInfo> chunks;

    SERIALIZE_METHODS(ChunkManifest, obj)
    {
        READWRITE(obj.chunk_size, obj.total_chunks, obj.chunks);
    }
};

/**
 * The top-level checkpoint manifest.
 *
 * Contains all metadata needed to verify and apply a checkpoint:
 * block identity, component hashes, chunk manifest, and Ed25519 signature.
 *
 * Directory layout on disk:
 *   checkpoint/
 *     manifest.bin      - Serialized CheckpointManifest
 *     headers.bin       - Sequential 80-byte block headers (height 0..N)
 *     bloom.bin         - SwiftSync Bloom filter
 *     utxo_NNN.bin      - UTXO data chunks (assumeUTXO format)
 */
struct CheckpointManifest {
    uint32_t version{CHECKPOINT_VERSION};
    int32_t height{0};             // Checkpoint height
    uint256 block_hash;            // Block hash at checkpoint height
    uint64_t utxo_count{0};        // Number of UTXOs in the set
    uint256 headers_hash;          // SHA-256 of headers.bin
    uint256 utxo_hash;             // Hash of the full UTXO set
    uint256 bloom_hash;            // SHA-256 of bloom.bin
    ChunkManifest chunk_manifest;
    std::array<uint8_t, 64> signature{}; // Ed25519 signature (Task 2.2)

    /** Compute the hash of all fields except the signature, for signing/verification. */
    uint256 GetSigningHash() const;

    /** Serialize to JSON for debugging and RPC output. */
    UniValue ToJSON() const;

    SERIALIZE_METHODS(CheckpointManifest, obj)
    {
        READWRITE(obj.version, obj.height, obj.block_hash, obj.utxo_count,
                  obj.headers_hash, obj.utxo_hash, obj.bloom_hash,
                  obj.chunk_manifest, obj.signature);
    }
};

/**
 * Generate a checkpoint manifest from a fully-synced node.
 *
 * @param[in]  chain       The active chain (for iterating headers by height).
 * @param[in]  blockman    Block manager (for reading block data).
 * @param[in]  height      Checkpoint height.
 * @param[in]  output_dir  Directory to write checkpoint files into.
 * @param[out] manifest    The generated manifest.
 * @return true on success.
 */
bool GenerateCheckpoint(const CChain& chain,
                        node::BlockManager& blockman,
                        int32_t height,
                        const std::string& output_dir,
                        CheckpointManifest& manifest);

/**
 * Load and validate a checkpoint manifest from disk.
 *
 * @param[in]  checkpoint_dir  Path to the checkpoint directory.
 * @param[out] manifest        The loaded manifest.
 * @return true on success, false if validation fails.
 */
bool LoadCheckpoint(const std::string& checkpoint_dir,
                    CheckpointManifest& manifest);

/**
 * Validate the integrity of a loaded checkpoint.
 *
 * Checks version, verifies headers_hash and bloom_hash against
 * the actual files, and verifies chunk hashes.
 *
 * @param[in] manifest        The manifest to validate.
 * @param[in] checkpoint_dir  Path to the checkpoint directory.
 * @return true if all integrity checks pass.
 */
bool ValidateCheckpoint(const CheckpointManifest& manifest,
                        const std::string& checkpoint_dir);

/**
 * Compute the SHA-256 hash of a file on disk.
 *
 * @param[in]  filepath  Path to the file.
 * @param[out] hash      Output hash.
 * @return true on success.
 */
bool HashFile(const std::string& filepath, uint256& hash);

/**
 * Generate UTXO chunk files from a pre-created UTXO cursor.
 *
 * Iterates the cursor (same txid-grouped format as assumeutxo snapshot body),
 * splitting coins into multiple chunk files (utxo_0.bin, utxo_1.bin, ...)
 * each capped at chunk_size bytes. Each chunk is hashed with SHA-256 and
 * recorded in manifest.chunk_manifest.
 *
 * The caller must create the cursor under cs_main (via CoinsDB().Cursor())
 * and pass pre-computed UTXO stats. This allows the lock to be released
 * before the slow I/O happens.
 *
 * @param[in]     pcursor             UTXO cursor (created under cs_main).
 * @param[in]     utxo_count          Number of UTXOs (from GetUTXOStats).
 * @param[in]     utxo_hash           Hash of the UTXO set (hash_serialized_3).
 * @param[in]     output_dir          Directory to write chunk files.
 * @param[in]     chunk_size          Maximum bytes per chunk file.
 * @param[in,out] manifest            The manifest to populate.
 * @param[in]     interruption_point  Optional callback for interruptibility.
 * @return true on success.
 */
bool GenerateUTXOChunks(CCoinsViewCursor& pcursor,
                         uint64_t utxo_count,
                         const uint256& utxo_hash,
                         const std::string& output_dir,
                         uint32_t chunk_size,
                         CheckpointManifest& manifest,
                         const std::function<void()>& interruption_point = {});

/**
 * Generate the SwiftSync bloom filter from a pre-created UTXO cursor.
 *
 * Iterates the cursor, inserts each COutPoint into a SwiftSyncFilter,
 * saves to bloom.bin, and records the hash in manifest.bloom_hash.
 *
 * The caller must create the cursor under cs_main (via CoinsDB().Cursor())
 * and set manifest.utxo_count before calling. This allows the lock to be
 * released before the slow I/O happens.
 *
 * @param[in]     pcursor             UTXO cursor (created under cs_main).
 * @param[in]     output_dir          Directory to write bloom.bin.
 * @param[in,out] manifest            The manifest to populate (utxo_count must be set).
 * @param[in]     interruption_point  Optional callback for interruptibility.
 * @return true on success.
 */
bool GenerateBloomFilter(CCoinsViewCursor& pcursor,
                          const std::string& output_dir,
                          CheckpointManifest& manifest,
                          const std::function<void()>& interruption_point = {});

/**
 * Assemble verified UTXO chunks into an assumeutxo-compatible snapshot file.
 *
 * Prepends a SnapshotMetadata header and concatenates chunk files in order.
 * The result is byte-identical to dumptxoutset output, loadable by ActivateSnapshot.
 *
 * @param[in] manifest     The checkpoint manifest (for block_hash, utxo_count, chunk order).
 * @param[in] chunks_dir   Directory containing verified utxo_N.bin chunk files.
 * @param[in] output_path  Path for the assembled snapshot file.
 * @param[in] network_magic  Network magic bytes for the SnapshotMetadata header.
 * @return true on success.
 */
bool AssembleSnapshot(const CheckpointManifest& manifest,
                       const std::string& chunks_dir,
                       const std::string& output_path,
                       const MessageStartChars& network_magic);

} // namespace haze

#endif // BITCOIN_HAZE_CHECKPOINT_H
