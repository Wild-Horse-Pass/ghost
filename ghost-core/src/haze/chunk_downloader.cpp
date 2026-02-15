// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <haze/chunk_downloader.h>
#include <haze/checkpoint.h>

#include <crypto/sha256.h>
#include <logging.h>

#include <cassert>
#include <filesystem>
#include <fstream>

namespace haze {

void ChunkDownloader::Init(const ChunkManifest& manifest,
                           const std::string& output_dir,
                           size_t max_parallel)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    m_manifest = manifest;
    m_output_dir = output_dir;
    m_max_parallel = max_parallel;
    m_bytes_downloaded = 0;

    // Create output directory
    std::filesystem::create_directories(output_dir);

    // Initialize chunk states from manifest
    m_chunks.clear();
    m_chunks.reserve(manifest.chunks.size());
    for (const auto& ci : manifest.chunks) {
        ChunkState cs;
        cs.info = ci;
        cs.status = ChunkState::PENDING;
        m_chunks.push_back(std::move(cs));
    }

    LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
                  "ChunkDownloader: initialized with %u chunks, max %zu parallel\n",
                  manifest.total_chunks, max_parallel);
}

uint32_t ChunkDownloader::CheckExistingChunks()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    uint32_t found = 0;

    for (auto& cs : m_chunks) {
        const std::string path = ChunkFilePath(cs.info.chunk_index);
        if (!std::filesystem::exists(path)) continue;

        // Read file and verify hash
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) continue;

        auto file_size = file.tellg();
        if (static_cast<uint64_t>(file_size) != cs.info.size) continue;

        file.seekg(0);
        std::vector<uint8_t> data(file_size);
        file.read(reinterpret_cast<char*>(data.data()), file_size);

        if (VerifyChunkHash(cs.info.chunk_index, data)) {
            cs.status = ChunkState::COMPLETE;
            m_bytes_downloaded.fetch_add(cs.info.size, std::memory_order_relaxed);
            found++;
        }
    }

    LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
                  "ChunkDownloader: found %u existing valid chunks on disk\n", found);
    return found;
}

std::vector<uint32_t> ChunkDownloader::RequestChunks(NodeId peer_id, size_t count)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<uint32_t> assigned;

    // Count current active downloads
    size_t active = 0;
    for (const auto& cs : m_chunks) {
        if (cs.status == ChunkState::REQUESTED || cs.status == ChunkState::DOWNLOADING) {
            active++;
        }
    }

    size_t available = (active < m_max_parallel) ? (m_max_parallel - active) : 0;
    size_t to_assign = std::min(count, available);

    for (auto& cs : m_chunks) {
        if (assigned.size() >= to_assign) break;
        if (cs.status != ChunkState::PENDING) continue;

        cs.status = ChunkState::REQUESTED;
        cs.assigned_peer = peer_id;
        cs.request_time = GetTime();
        assigned.push_back(cs.info.chunk_index);
    }

    return assigned;
}

bool ChunkDownloader::ReceiveChunk(uint32_t chunk_index, std::vector<uint8_t>&& data)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (chunk_index >= m_chunks.size()) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "ChunkDownloader: received invalid chunk index %u\n", chunk_index);
        return false;
    }

    auto& cs = m_chunks[chunk_index];
    if (cs.status == ChunkState::COMPLETE) {
        return true; // Already have it
    }

    cs.status = ChunkState::VALIDATING;

    // Verify SHA-256 hash
    if (!VerifyChunkHash(chunk_index, data)) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Warning,
                      "ChunkDownloader: chunk %u hash mismatch (retry %u/%u)\n",
                      chunk_index, cs.retries + 1, DEFAULT_MAX_RETRIES);
        cs.retries++;
        if (cs.retries >= DEFAULT_MAX_RETRIES) {
            cs.status = ChunkState::FAILED;
            LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                          "ChunkDownloader: chunk %u permanently failed after %u retries\n",
                          chunk_index, cs.retries);
        } else {
            cs.status = ChunkState::PENDING;
            cs.assigned_peer = -1;
        }
        return false;
    }

    // Write verified chunk to disk
    if (!WriteChunkToDisk(chunk_index, data)) {
        cs.status = ChunkState::PENDING;
        cs.assigned_peer = -1;
        return false;
    }

    cs.status = ChunkState::COMPLETE;
    cs.assigned_peer = -1;
    cs.data.clear();
    m_bytes_downloaded.fetch_add(cs.info.size, std::memory_order_relaxed);

    LogPrintLevel(BCLog::HAZE, BCLog::Level::Debug,
                  "ChunkDownloader: chunk %u complete (%llu bytes)\n",
                  chunk_index, static_cast<unsigned long long>(cs.info.size));
    return true;
}

void ChunkDownloader::HandlePeerDisconnect(NodeId peer_id)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    for (auto& cs : m_chunks) {
        if (cs.assigned_peer == peer_id &&
            (cs.status == ChunkState::REQUESTED || cs.status == ChunkState::DOWNLOADING)) {
            cs.status = ChunkState::PENDING;
            cs.assigned_peer = -1;
            LogPrintLevel(BCLog::HAZE, BCLog::Level::Debug,
                          "ChunkDownloader: re-queued chunk %u after peer %d disconnect\n",
                          cs.info.chunk_index, peer_id);
        }
    }
}

void ChunkDownloader::CheckTimeouts(int64_t now_seconds)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    for (auto& cs : m_chunks) {
        if (cs.status != ChunkState::REQUESTED && cs.status != ChunkState::DOWNLOADING) continue;

        int64_t elapsed = now_seconds - cs.request_time;
        if (elapsed > DEFAULT_CHUNK_TIMEOUT_SECONDS) {
            LogPrintLevel(BCLog::HAZE, BCLog::Level::Warning,
                          "ChunkDownloader: chunk %u timed out (peer %d, %lld seconds)\n",
                          cs.info.chunk_index, cs.assigned_peer,
                          static_cast<long long>(elapsed));
            cs.retries++;
            if (cs.retries >= DEFAULT_MAX_RETRIES) {
                cs.status = ChunkState::FAILED;
            } else {
                cs.status = ChunkState::PENDING;
                cs.assigned_peer = -1;
            }
        }
    }
}

bool ChunkDownloader::IsComplete() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& cs : m_chunks) {
        if (cs.status != ChunkState::COMPLETE) return false;
    }
    return !m_chunks.empty();
}

DownloadStats ChunkDownloader::GetStats() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    DownloadStats stats;
    stats.chunks_total = m_chunks.size();

    uint64_t total_bytes = 0;
    for (const auto& cs : m_chunks) {
        total_bytes += cs.info.size;
        if (cs.status == ChunkState::COMPLETE) {
            stats.chunks_complete++;
        }
        if (cs.status == ChunkState::REQUESTED || cs.status == ChunkState::DOWNLOADING) {
            stats.active_downloads++;
        }
    }

    stats.bytes_total = total_bytes;
    stats.bytes_downloaded = m_bytes_downloaded.load(std::memory_order_relaxed);
    stats.percent = total_bytes > 0 ?
        (static_cast<double>(stats.bytes_downloaded) / static_cast<double>(total_bytes)) * 100.0 : 0.0;

    return stats;
}

uint32_t ChunkDownloader::GetPendingCount() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    uint32_t count = 0;
    for (const auto& cs : m_chunks) {
        if (cs.status == ChunkState::PENDING) count++;
    }
    return count;
}

uint32_t ChunkDownloader::GetTotalChunks() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_chunks.size();
}

bool ChunkDownloader::VerifyChunkHash(uint32_t chunk_index, const std::vector<uint8_t>& data) const
{
    if (chunk_index >= m_chunks.size()) return false;

    CSHA256 hasher;
    hasher.Write(data.data(), data.size());
    uint256 computed_hash;
    hasher.Finalize(computed_hash.begin());

    return computed_hash == m_chunks[chunk_index].info.hash;
}

bool ChunkDownloader::WriteChunkToDisk(uint32_t chunk_index, const std::vector<uint8_t>& data)
{
    const std::string path = ChunkFilePath(chunk_index);

    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "ChunkDownloader: cannot write chunk file %s\n", path);
        return false;
    }

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    if (!file.good()) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "ChunkDownloader: write error on %s\n", path);
        return false;
    }

    file.flush();
    return true;
}

std::string ChunkDownloader::ChunkFilePath(uint32_t chunk_index) const
{
    return m_output_dir + "/utxo_" + std::to_string(chunk_index) + ".bin";
}

} // namespace haze
