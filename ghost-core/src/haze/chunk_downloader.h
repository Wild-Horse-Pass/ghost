// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HAZE_CHUNK_DOWNLOADER_H
#define BITCOIN_HAZE_CHUNK_DOWNLOADER_H

#include <haze/checkpoint.h>
#include <net.h>
#include <uint256.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace haze {

/** Maximum concurrent parallel downloads. */
static constexpr size_t DEFAULT_MAX_PARALLEL_DOWNLOADS = 8;

/** Timeout per chunk in seconds. */
static constexpr int64_t DEFAULT_CHUNK_TIMEOUT_SECONDS = 120;

/** Maximum retries per chunk before giving up. */
static constexpr uint32_t DEFAULT_MAX_RETRIES = 3;

/** Per-chunk state during download. */
struct ChunkState {
    enum Status : uint8_t {
        PENDING = 0,
        REQUESTED = 1,
        DOWNLOADING = 2,
        VALIDATING = 3,
        COMPLETE = 4,
        FAILED = 5,
    };

    ChunkInfo info;                // From the manifest
    Status status{PENDING};
    NodeId assigned_peer{-1};      // Peer currently serving this chunk
    int64_t request_time{0};       // When the request was sent (monotonic seconds)
    uint32_t retries{0};           // Number of retries so far
    std::vector<uint8_t> data;     // Downloaded data (temporary)
};

/** Download progress statistics. */
struct DownloadStats {
    uint64_t chunks_complete{0};
    uint64_t chunks_total{0};
    uint64_t bytes_downloaded{0};
    uint64_t bytes_total{0};
    uint32_t active_downloads{0};
    double percent{0.0};
};

using DownloadProgressCallback = std::function<void(const DownloadStats&)>;

/**
 * Parallel chunk downloader for checkpoint UTXO data.
 *
 * Downloads UTXO chunks from multiple peers simultaneously,
 * verifies SHA-256 hashes against the manifest, and writes
 * verified chunks to disk.
 *
 * Supports resume: on startup, checks existing chunk files on disk
 * and only downloads missing/corrupt chunks.
 */
class ChunkDownloader {
public:
    ChunkDownloader() = default;

    /**
     * Initialize the downloader with a chunk manifest and output directory.
     *
     * @param manifest   The chunk manifest from the checkpoint.
     * @param output_dir Directory to write chunk files.
     * @param max_parallel Maximum concurrent downloads.
     */
    void Init(const ChunkManifest& manifest,
              const std::string& output_dir,
              size_t max_parallel = DEFAULT_MAX_PARALLEL_DOWNLOADS);

    /**
     * Check existing chunk files on disk and mark completed ones.
     * Call this before Start() to enable resume.
     *
     * @return Number of chunks already complete on disk.
     */
    uint32_t CheckExistingChunks();

    /**
     * Get the next chunk(s) that need to be requested.
     *
     * Returns up to `count` PENDING chunks and marks them REQUESTED.
     * The caller should send P2P requests for these chunks.
     *
     * @param peer_id    The peer to assign the chunks to.
     * @param count      Maximum number of chunks to return.
     * @return Vector of chunk indices that were assigned.
     */
    std::vector<uint32_t> RequestChunks(NodeId peer_id, size_t count);

    /**
     * Handle received chunk data from a peer.
     *
     * Validates the SHA-256 hash and writes to disk on success.
     *
     * @param chunk_index  The chunk index.
     * @param data         The received chunk data.
     * @return true if the chunk was valid and written to disk.
     */
    bool ReceiveChunk(uint32_t chunk_index, std::vector<uint8_t>&& data);

    /**
     * Handle a peer disconnecting.
     * Re-queues any chunks assigned to this peer.
     *
     * @param peer_id  The disconnected peer's node ID.
     */
    void HandlePeerDisconnect(NodeId peer_id);

    /**
     * Check for timed-out chunk requests.
     * Re-queues chunks that have exceeded the timeout.
     *
     * @param now_seconds  Current monotonic time in seconds.
     */
    void CheckTimeouts(int64_t now_seconds);

    /** Check if all chunks are downloaded. */
    bool IsComplete() const;

    /** Get download statistics. */
    DownloadStats GetStats() const;

    /** Get the number of pending chunks. */
    uint32_t GetPendingCount() const;

    /** Get the total number of chunks. */
    uint32_t GetTotalChunks() const;

    /** Get the output directory. */
    const std::string& GetOutputDir() const { return m_output_dir; }

private:
    ChunkManifest m_manifest;
    std::string m_output_dir;
    size_t m_max_parallel{DEFAULT_MAX_PARALLEL_DOWNLOADS};

    mutable std::mutex m_mutex;
    std::vector<ChunkState> m_chunks; // GUARDED_BY(m_mutex)
    std::atomic<uint64_t> m_bytes_downloaded{0};

    /** Verify a chunk's SHA-256 hash against the manifest. */
    bool VerifyChunkHash(uint32_t chunk_index, const std::vector<uint8_t>& data) const;

    /** Write a verified chunk to disk. */
    bool WriteChunkToDisk(uint32_t chunk_index, const std::vector<uint8_t>& data);

    /** Get the file path for a chunk. */
    std::string ChunkFilePath(uint32_t chunk_index) const;
};

} // namespace haze

#endif // BITCOIN_HAZE_CHUNK_DOWNLOADER_H
