// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HAZE_MODE_SELECTOR_H
#define BITCOIN_HAZE_MODE_SELECTOR_H

#include <haze/exorcism.h>
#include <common/args.h>
#include <util/fs.h>

#include <optional>
#include <string>

namespace haze {

/**
 * Detect or select the Ghost operating mode.
 *
 * Priority:
 *   1. Existing haze_mode.lock in datadir (persisted mode)
 *   2. --hazemode CLI argument
 *   3. Default to HAZED (daemon) or interactive prompt (TTY)
 *
 * @param[in] datadir  Path to the data directory.
 * @param[in] args     Parsed CLI arguments.
 * @return The selected operating mode.
 */
GhostMode DetectOrSelectMode(const fs::path& datadir, const ArgsManager& args);

/**
 * Read persisted mode from haze_mode.lock.
 *
 * @param[in] datadir  Path to the data directory.
 * @return The persisted mode, or std::nullopt if no lock file exists.
 */
std::optional<GhostMode> ReadModeLock(const fs::path& datadir);

/**
 * Write mode to haze_mode.lock.
 *
 * @param[in] datadir  Path to the data directory.
 * @param[in] mode     The mode to persist.
 * @return true on success, false on I/O error.
 */
bool WriteModeLock(const fs::path& datadir, GhostMode mode);

/**
 * Validate that the selected mode is consistent with existing data files.
 *
 * - HAZED + blk*.dat files exist → error (must run --exorcist first or use fresh datadir)
 * - FULL_ARCHIVE + gsb*.dat files exist → error (incompatible data, re-sync needed)
 *
 * @param[in] datadir  Path to the data directory.
 * @param[in] mode     The mode to validate.
 * @return Error string if inconsistent, std::nullopt if OK.
 */
std::optional<std::string> ValidateModeConsistency(const fs::path& datadir, GhostMode mode);

/** Lock file name within datadir. */
inline constexpr const char* HAZE_MODE_LOCK_FILE = "haze_mode.lock";

} // namespace haze

#endif // BITCOIN_HAZE_MODE_SELECTOR_H
