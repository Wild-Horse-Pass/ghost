// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HAZE_BLOOM_FILTER_H
#define BITCOIN_HAZE_BLOOM_FILTER_H

#include <primitives/transaction.h>
#include <uint256.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace haze {

/** SwiftSync Bloom filter file magic: "SBF\0" */
static constexpr uint32_t BLOOM_MAGIC = 0x00464253; // Little-endian: 0x53 0x42 0x46 0x00

/** Default number of hash functions (optimal for ~0.1% FPR). */
static constexpr uint8_t DEFAULT_NUM_HASHES = 10;

/** Default seed for deterministic hashing. */
static constexpr uint64_t DEFAULT_BLOOM_SEED = 0x4768617374537769ULL; // "GhastSwi" truncated

/**
 * Custom large Bloom filter for SwiftSync.
 *
 * Bitcoin Core's CBloomFilter is capped at 36 KB — unsuitable for encoding
 * ~170M surviving outpoints. This implementation supports filters up to
 * several hundred megabytes.
 *
 * Uses SipHash with derived keys for each hash function, hashing COutPoint
 * (txid + vout) directly for efficiency.
 *
 * Disk format:
 *   [4 bytes]  Magic: 0x53424600 ("SBF\0")
 *   [8 bytes]  num_bits (uint64 LE)
 *   [1 byte]   num_hashes
 *   [8 bytes]  seed (uint64 LE)
 *   [variable] Raw bit array (ceil(num_bits / 8) bytes)
 */
class SwiftSyncFilter {
public:
    SwiftSyncFilter() = default;

    /**
     * Construct a filter with the given parameters.
     *
     * @param num_elements  Expected number of elements to insert.
     * @param fp_rate       Target false positive rate (e.g. 0.001 for 0.1%).
     * @param seed          Seed for deterministic hashing.
     */
    SwiftSyncFilter(uint64_t num_elements, double fp_rate, uint64_t seed = DEFAULT_BLOOM_SEED);

    /** Insert an outpoint into the filter. */
    void Insert(const COutPoint& outpoint);

    /** Test whether an outpoint may be in the filter (probabilistic). */
    bool MayContain(const COutPoint& outpoint) const;

    /** Save the filter to a file. */
    bool Save(const std::string& filepath) const;

    /** Load a filter from a file. */
    static bool Load(const std::string& filepath, SwiftSyncFilter& filter);

    /** Get the filter size in bytes. */
    size_t GetSizeBytes() const { return m_bits.size(); }

    /** Get the number of bits in the filter. */
    uint64_t GetNumBits() const { return m_num_bits; }

    /** Get the number of hash functions. */
    uint8_t GetNumHashes() const { return m_num_hashes; }

    /** Get the seed. */
    uint64_t GetSeed() const { return m_seed; }

    /** Compute the theoretical false positive rate given current parameters. */
    double GetFalsePositiveRate(uint64_t num_elements) const;

    /** Check whether the filter has been initialized. */
    bool IsInitialized() const { return m_num_bits > 0; }

private:
    std::vector<uint8_t> m_bits;   // Bit array
    uint64_t m_num_bits{0};        // Total number of bits
    uint8_t m_num_hashes{0};       // Number of hash functions (k)
    uint64_t m_seed{0};            // Fixed seed for deterministic hashing

    /**
     * Compute a bit position for hash function k and the given outpoint.
     * Uses SipHash with derived keys per function index.
     */
    uint64_t HashOutpoint(uint8_t k, const COutPoint& outpoint) const;

    /** Set bit at the given position. */
    void SetBit(uint64_t pos);

    /** Test bit at the given position. */
    bool TestBit(uint64_t pos) const;
};

} // namespace haze

#endif // BITCOIN_HAZE_BLOOM_FILTER_H
