// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HAZE_EXORCIST_H
#define BITCOIN_HAZE_EXORCIST_H

#include <util/fs.h>

#include <cstdint>
#include <functional>
#include <string>

namespace node {
class BlockManager;
} // namespace node

namespace haze {

/**
 * Ghost Exorcist: archive conversion tool.
 *
 * Converts an existing full archive node (blk*.dat) into a hazed node
 * (gsb*.dat) by reading all blocks, stripping hazeable content, writing
 * the structural archive, securely zeroing the originals, and deleting
 * undo data.
 *
 * The node MUST be stopped before running the Exorcist.
 * Conversion is IRREVERSIBLE.
 */
class GhostExorcist {
public:
    struct ConversionResult {
        bool success{false};
        uint32_t blocks_converted{0};
        size_t original_size{0};
        size_t stripped_size{0};
        size_t bytes_freed{0};
        std::string error;
    };

    struct Progress {
        uint32_t blocks_processed{0};
        uint32_t blocks_total{0};
        double percent{0.0};
        std::string current_phase; //!< "stripping", "zeroing", "cleanup"
    };

    using ProgressCallback = std::function<void(const Progress&)>;

    /**
     * Run the full archive conversion.
     *
     * Phase 1: Read each block from blk*.dat, strip it, write to gsb*.dat,
     *          update block index to point to new GSB position.
     * Phase 2: Securely zero all blk*.dat files (overwrite with 0x00).
     * Phase 3: Delete blk*.dat and rev*.dat files.
     *
     * @param[in] blockman     The BlockManager with initialized block index.
     * @param[in] blocks_dir   Path to the blocks directory.
     * @param[in] progress_cb  Optional callback for progress reporting.
     * @return ConversionResult with statistics and success/error status.
     */
    ConversionResult Convert(node::BlockManager& blockman,
                             const fs::path& blocks_dir,
                             ProgressCallback progress_cb = nullptr);

    /**
     * Resume an interrupted conversion.
     *
     * Checks for a resume marker file that records the last successfully
     * converted block height. Continues from that point.
     *
     * @param[in] blockman     The BlockManager with initialized block index.
     * @param[in] blocks_dir   Path to the blocks directory.
     * @param[in] progress_cb  Optional callback for progress reporting.
     * @return ConversionResult with statistics and success/error status.
     */
    ConversionResult Resume(node::BlockManager& blockman,
                            const fs::path& blocks_dir,
                            ProgressCallback progress_cb = nullptr);

private:
    static constexpr const char* RESUME_MARKER_FILE = "exorcist_resume.dat";

    /**
     * Phase 1: Strip all blocks from blk*.dat → gsb*.dat.
     * Updates block index entries to point to GSB file positions.
     */
    bool StripArchive(node::BlockManager& blockman,
                      const fs::path& blocks_dir,
                      uint32_t start_height,
                      ConversionResult& result,
                      ProgressCallback progress_cb);

    /**
     * Phase 2: Securely zero all blk*.dat files.
     * Overwrites every byte with 0x00 to destroy hazeable content.
     */
    bool SecureZeroOriginals(const fs::path& blocks_dir,
                             ProgressCallback progress_cb);

    /**
     * Phase 3: Delete blk*.dat and rev*.dat files.
     */
    bool CleanupOriginals(const fs::path& blocks_dir,
                          ProgressCallback progress_cb);

    /** Write resume marker (last converted height). */
    static bool WriteResumeMarker(const fs::path& blocks_dir, uint32_t height);

    /** Read resume marker. Returns -1 if no marker exists. */
    static int ReadResumeMarker(const fs::path& blocks_dir);

    /** Delete resume marker after successful completion. */
    static void DeleteResumeMarker(const fs::path& blocks_dir);
};

} // namespace haze

#endif // BITCOIN_HAZE_EXORCIST_H
