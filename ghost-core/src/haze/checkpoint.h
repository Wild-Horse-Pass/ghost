// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HAZE_CHECKPOINT_H
#define BITCOIN_HAZE_CHECKPOINT_H

#include <serialize.h>
#include <uint256.h>
#include <univalue.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

class CChain;
class CBlockIndex;

namespace node {
class BlockManager;
} // namespace node

namespace haze {

/** Default UTXO chunk size: 64 MB. */
static constexpr uint32_t DEFAULT_CHUNK_SIZE = 64 * 1024 * 1024;

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
                  obj.chunk_manifest);
        // Signature is a fixed-size array
        SER_WRITE(obj, s.write(std::as_bytes(std::span{obj.signature})));
        SER_READ(obj, s.read(std::as_writable_bytes(std::span{obj.signature})));
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

} // namespace haze

#endif // BITCOIN_HAZE_CHECKPOINT_H
