// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <haze/headers_file.h>

#include <chain.h>
#include <crypto/sha256.h>
#include <logging.h>
#include <serialize.h>
#include <streams.h>

#include <cassert>
#include <cstdio>
#include <fstream>

namespace haze {

bool WriteHeadersFile(const CChain& chain, int32_t height, const std::string& filepath)
{
    if (height < 0) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error, "WriteHeadersFile: invalid height %d\n", height);
        return false;
    }

    std::ofstream file(filepath, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error, "WriteHeadersFile: cannot open %s\n", filepath);
        return false;
    }

    for (int32_t h = 0; h <= height; ++h) {
        const CBlockIndex* pindex = chain[h];
        if (!pindex) {
            LogPrintLevel(BCLog::HAZE, BCLog::Level::Error, "WriteHeadersFile: no block index at height %d\n", h);
            return false;
        }

        CBlockHeader header = pindex->GetBlockHeader();

        // Serialize the 80-byte header into a buffer
        DataStream ss;
        ss << header;
        assert(ss.size() == HEADER_SERIALIZED_SIZE);

        file.write(reinterpret_cast<const char*>(ss.data()), ss.size());
        if (!file.good()) {
            LogPrintLevel(BCLog::HAZE, BCLog::Level::Error, "WriteHeadersFile: write error at height %d\n", h);
            return false;
        }
    }

    file.flush();
    LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
                  "WriteHeadersFile: wrote %d headers (%zu bytes) to %s\n",
                  height + 1, static_cast<size_t>(height + 1) * HEADER_SERIALIZED_SIZE, filepath);
    return true;
}

bool ReadHeader(const std::string& filepath, int32_t height, CBlockHeader& header)
{
    if (height < 0) return false;

    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) return false;

    const uint64_t offset = static_cast<uint64_t>(height) * HEADER_SERIALIZED_SIZE;
    file.seekg(offset);
    if (!file.good()) return false;

    unsigned char buf[HEADER_SERIALIZED_SIZE];
    file.read(reinterpret_cast<char*>(buf), HEADER_SERIALIZED_SIZE);
    if (file.gcount() != static_cast<std::streamsize>(HEADER_SERIALIZED_SIZE)) return false;

    DataStream ss{std::span<const uint8_t>{buf, HEADER_SERIALIZED_SIZE}};
    ss >> header;
    return true;
}

bool HashHeadersFile(const std::string& filepath, uint256& hash)
{
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) return false;

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

bool VerifyHeadersChain(const std::string& filepath, int32_t count)
{
    if (count <= 0) return false;

    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) return false;

    CBlockHeader prev_header;

    for (int32_t h = 0; h < count; ++h) {
        unsigned char buf[HEADER_SERIALIZED_SIZE];
        file.read(reinterpret_cast<char*>(buf), HEADER_SERIALIZED_SIZE);
        if (file.gcount() != static_cast<std::streamsize>(HEADER_SERIALIZED_SIZE)) {
            LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                          "VerifyHeadersChain: short read at height %d\n", h);
            return false;
        }

        CBlockHeader header;
        DataStream ss{std::span<const uint8_t>{buf, HEADER_SERIALIZED_SIZE}};
        ss >> header;

        if (h > 0) {
            if (header.hashPrevBlock != prev_header.GetHash()) {
                LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                              "VerifyHeadersChain: chain break at height %d\n", h);
                return false;
            }
        }

        prev_header = header;
    }

    LogPrintLevel(BCLog::HAZE, BCLog::Level::Debug,
                  "VerifyHeadersChain: verified %d headers\n", count);
    return true;
}

} // namespace haze
