// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HAZE_EXORCISM_H
#define BITCOIN_HAZE_EXORCISM_H

#include <haze/block_stripper.h>
#include <haze/stripped_block.h>
#include <primitives/block.h>

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace haze {

/** Ghost node operating mode. */
enum class GhostMode : uint8_t {
    HAZED = 0,        //!< Hazed: stripped archive + Exorcism active
    FULL_ARCHIVE = 1, //!< Full Archive: standard Bitcoin Core behavior
};

/**
 * Ghost Exorcism: real-time data purification.
 *
 * Ensures hazeable content (witness data, scriptSig, OP_RETURN payloads,
 * coinbase scriptSig) never touches persistent storage. Incoming blocks
 * are validated in RAM against full data, then only the stripped structural
 * output is written to disk.
 *
 * This class handles the stripping logic and statistics. Actual file I/O
 * is delegated to BlockManager, which maintains a GSB FlatFileSeq for
 * stripped block storage.
 */
class GhostExorcism {
public:
    GhostExorcism() = default;

    /** Initialize with operating mode. */
    void Init(GhostMode mode);

    /** Whether Exorcism is active (Hazed mode). */
    bool IsActive() const { return m_active; }

    /** Get the current operating mode. */
    GhostMode GetMode() const { return m_mode; }

    /**
     * Strip a validated block for writing to disk.
     *
     * Called AFTER AcceptBlock() succeeds. The full block data has been
     * validated in RAM. This function strips hazeable content and returns
     * the stripped block ready for writing.
     *
     * @param[in] block The fully validated block.
     * @return StripResult containing the stripped block and statistics.
     */
    StripResult StripValidatedBlock(const CBlock& block);

    /**
     * Securely zero a memory region.
     *
     * Uses volatile pointer cast to prevent compiler optimization from
     * eliding the memset. This ensures hazeable content in RAM is
     * actually zeroed after processing.
     *
     * @param[in] ptr  Pointer to memory region.
     * @param[in] len  Number of bytes to zero.
     */
    static void SecureZero(void* ptr, size_t len);

    /** Cumulative bytes stripped across all blocks. */
    size_t GetTotalBytesStripped() const { return m_total_bytes_stripped.load(); }

    /** Number of blocks processed through Exorcism. */
    uint64_t GetBlocksProcessed() const { return m_blocks_processed.load(); }

private:
    GhostMode m_mode{GhostMode::FULL_ARCHIVE};
    bool m_active{false};
    std::atomic<size_t> m_total_bytes_stripped{0};
    std::atomic<uint64_t> m_blocks_processed{0};
};

} // namespace haze

#endif // BITCOIN_HAZE_EXORCISM_H
