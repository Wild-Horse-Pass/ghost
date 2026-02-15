// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <haze/mode_selector.h>

#include <logging.h>
#include <util/fs.h>

#include <fstream>
#include <iostream>

namespace haze {

static const fs::path LockFilePath(const fs::path& datadir)
{
    return datadir / HAZE_MODE_LOCK_FILE;
}

/** Check if any files matching a glob prefix exist in the blocks directory. */
static bool HasBlockFiles(const fs::path& datadir, const std::string& prefix)
{
    const fs::path blocks_dir = datadir / "blocks";
    if (!fs::exists(blocks_dir)) return false;

    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(blocks_dir, ec)) {
        if (!entry.is_regular_file()) continue;
        const std::string filename = entry.path().filename().string();
        if (filename.size() >= prefix.size() &&
            filename.substr(0, prefix.size()) == prefix &&
            filename.find(".dat") != std::string::npos) {
            return true;
        }
    }
    return false;
}

std::optional<GhostMode> ReadModeLock(const fs::path& datadir)
{
    const fs::path lock_path = LockFilePath(datadir);
    if (!fs::exists(lock_path)) return std::nullopt;

    std::ifstream file(lock_path, std::ios::binary);
    if (!file.is_open()) return std::nullopt;

    uint8_t mode_byte;
    if (!file.read(reinterpret_cast<char*>(&mode_byte), 1)) return std::nullopt;

    if (mode_byte == static_cast<uint8_t>(GhostMode::HAZED)) return GhostMode::HAZED;
    if (mode_byte == static_cast<uint8_t>(GhostMode::FULL_ARCHIVE)) return GhostMode::FULL_ARCHIVE;

    return std::nullopt;
}

bool WriteModeLock(const fs::path& datadir, GhostMode mode)
{
    const fs::path lock_path = LockFilePath(datadir);

    std::ofstream file(lock_path, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) return false;

    uint8_t mode_byte = static_cast<uint8_t>(mode);
    file.write(reinterpret_cast<const char*>(&mode_byte), 1);
    return file.good();
}

std::optional<std::string> ValidateModeConsistency(const fs::path& datadir, GhostMode mode)
{
    if (mode == GhostMode::HAZED && HasBlockFiles(datadir, "blk")) {
        return "Hazed mode selected but blk*.dat files exist in the blocks directory. "
               "Run with --exorcist to convert the existing archive, or use a fresh datadir.";
    }

    if (mode == GhostMode::FULL_ARCHIVE && HasBlockFiles(datadir, "gsb")) {
        return "Full archive mode selected but gsb*.dat files exist in the blocks directory. "
               "This data was written in hazed mode and is not compatible with full archive mode. "
               "Use a fresh datadir to run in full archive mode.";
    }

    return std::nullopt;
}

GhostMode DetectOrSelectMode(const fs::path& datadir, const ArgsManager& args)
{
    // 1. Check for existing lock file (persisted from previous launch)
    auto persisted = ReadModeLock(datadir);
    if (persisted.has_value()) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
            "Ghost Haze: loaded persisted mode '%s' from %s\n",
            *persisted == GhostMode::HAZED ? "hazed" : "full_archive",
            HAZE_MODE_LOCK_FILE);
        return *persisted;
    }

    // 2. Check CLI argument: --hazemode=hazed|full_archive
    const std::string mode_arg = args.GetArg("-hazemode", "");
    if (!mode_arg.empty()) {
        GhostMode mode;
        if (mode_arg == "hazed") {
            mode = GhostMode::HAZED;
        } else if (mode_arg == "full_archive") {
            mode = GhostMode::FULL_ARCHIVE;
        } else {
            LogPrintf("Ghost Haze: invalid --hazemode value '%s', defaulting to hazed\n", mode_arg);
            mode = GhostMode::HAZED;
        }

        LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
            "Ghost Haze: mode '%s' selected via --hazemode\n",
            mode == GhostMode::HAZED ? "hazed" : "full_archive");

        if (WriteModeLock(datadir, mode)) {
            LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
                "Ghost Haze: persisted mode to %s\n", HAZE_MODE_LOCK_FILE);
        } else {
            LogPrintf("Ghost Haze: WARNING - failed to write mode lock file\n");
        }

        return mode;
    }

    // 3. Check if running as daemon (no TTY) — default to HAZED
    if (!isatty(fileno(stdin))) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
            "Ghost Haze: no TTY and no --hazemode set, defaulting to hazed mode\n");

        if (WriteModeLock(datadir, GhostMode::HAZED)) {
            LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
                "Ghost Haze: persisted mode to %s\n", HAZE_MODE_LOCK_FILE);
        }

        return GhostMode::HAZED;
    }

    // 4. Interactive mode selection
    std::cout << "\n"
              << "╔══════════════════════════════════════════════════════════╗\n"
              << "║               Ghost Core — Mode Selection               ║\n"
              << "╠══════════════════════════════════════════════════════════╣\n"
              << "║                                                          ║\n"
              << "║  [1] HAZED (recommended)                                 ║\n"
              << "║      Strips witness, scriptSig, OP_RETURN, and coinbase  ║\n"
              << "║      data before writing to disk. Preserves the complete ║\n"
              << "║      economic graph. ~60% storage reduction.             ║\n"
              << "║                                                          ║\n"
              << "║  [2] FULL ARCHIVE                                        ║\n"
              << "║      Standard Bitcoin Core behavior. All block data      ║\n"
              << "║      stored on disk unchanged.                           ║\n"
              << "║                                                          ║\n"
              << "║  This choice is permanent for this datadir.              ║\n"
              << "║  Use --hazemode=hazed|full_archive to skip this prompt.  ║\n"
              << "║                                                          ║\n"
              << "╚══════════════════════════════════════════════════════════╝\n"
              << "\n"
              << "Select mode [1/2]: " << std::flush;

    std::string input;
    std::getline(std::cin, input);

    GhostMode mode;
    if (input == "2") {
        mode = GhostMode::FULL_ARCHIVE;
        std::cout << "Selected: FULL ARCHIVE mode\n" << std::endl;
    } else {
        mode = GhostMode::HAZED;
        std::cout << "Selected: HAZED mode\n" << std::endl;
    }

    if (WriteModeLock(datadir, mode)) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
            "Ghost Haze: persisted mode '%s' to %s\n",
            mode == GhostMode::HAZED ? "hazed" : "full_archive",
            HAZE_MODE_LOCK_FILE);
    } else {
        LogPrintf("Ghost Haze: WARNING - failed to write mode lock file\n");
    }

    return mode;
}

} // namespace haze
