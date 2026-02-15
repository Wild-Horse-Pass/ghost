// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HAZE_HEADERS_FILE_H
#define BITCOIN_HAZE_HEADERS_FILE_H

#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

class CChain;
class CBlockIndex;

namespace haze {

/** Size of a serialized CBlockHeader (fixed at 80 bytes). */
static constexpr size_t HEADER_SERIALIZED_SIZE = 80;

/**
 * Write a headers.bin file containing sequential 80-byte block headers.
 *
 * Headers are written from height 0 through `height` inclusive.
 * The header at height N is located at offset N * 80 in the file.
 *
 * @param[in] chain     The active chain (provides CBlockIndex by height).
 * @param[in] height    The maximum height to write (inclusive).
 * @param[in] filepath  Output file path.
 * @return true on success.
 */
bool WriteHeadersFile(const CChain& chain, int32_t height, const std::string& filepath);

/**
 * Read a single block header from a headers.bin file.
 *
 * @param[in]  filepath  Path to the headers.bin file.
 * @param[in]  height    The height of the header to read.
 * @param[out] header    The deserialized block header.
 * @return true on success.
 */
bool ReadHeader(const std::string& filepath, int32_t height, CBlockHeader& header);

/**
 * Compute the SHA-256 hash of a headers.bin file.
 *
 * @param[in]  filepath  Path to the headers.bin file.
 * @param[out] hash      The SHA-256 hash of the entire file contents.
 * @return true on success.
 */
bool HashHeadersFile(const std::string& filepath, uint256& hash);

/**
 * Verify that a headers.bin file contains a valid chain of headers.
 *
 * For each consecutive pair, header[i].GetHash() must equal
 * header[i+1].hashPrevBlock.
 *
 * @param[in] filepath  Path to the headers.bin file.
 * @param[in] count     Number of headers in the file (height + 1).
 * @return true if the chain is valid.
 */
bool VerifyHeadersChain(const std::string& filepath, int32_t count);

} // namespace haze

#endif // BITCOIN_HAZE_HEADERS_FILE_H
