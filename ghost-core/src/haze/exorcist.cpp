// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <haze/exorcist.h>

#include <chain.h>
#include <haze/block_stripper.h>
#include <haze/stripped_block.h>
#include <kernel/messagestartchars.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <util/fs.h>
#include <util/fs_helpers.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <vector>

namespace haze {

//! How often to flush block index updates and write resume markers.
static constexpr uint32_t BATCH_FLUSH_INTERVAL = 1000;

//! GSB storage header magic bytes: "GSB\0".
static constexpr MessageStartChars GSB_STORAGE_MAGIC = {0x47, 0x53, 0x42, 0x00};

GhostExorcist::ConversionResult GhostExorcist::Convert(node::BlockManager& blockman,
                                         const fs::path& blocks_dir,
                                         ProgressCallback progress_cb)
{
    ConversionResult result;

    LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
        "Ghost Exorcist: starting archive conversion (IRREVERSIBLE)\n");

    // Phase 1: Strip all blocks from blk*.dat → gsb*.dat.
    if (!StripArchive(blockman, blocks_dir, 0, result, progress_cb)) {
        return result;
    }

    // Phase 2: Securely zero all blk*.dat files.
    if (!SecureZeroOriginals(blocks_dir, progress_cb)) {
        result.error = "Failed to securely zero original block files";
        return result;
    }

    // Phase 3: Delete blk*.dat and rev*.dat files.
    if (!CleanupOriginals(blocks_dir, progress_cb)) {
        result.error = "Failed to clean up original files";
        return result;
    }

    DeleteResumeMarker(blocks_dir);

    result.success = true;
    result.bytes_freed = result.original_size - result.stripped_size;

    LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
        "Ghost Exorcist: conversion complete — %u blocks, "
        "%zu → %zu bytes (%.1f%% reduction, %zu bytes freed)\n",
        result.blocks_converted, result.original_size, result.stripped_size,
        result.original_size > 0
            ? (1.0 - static_cast<double>(result.stripped_size) / result.original_size) * 100.0
            : 0.0,
        result.bytes_freed);

    return result;
}

GhostExorcist::ConversionResult GhostExorcist::Resume(node::BlockManager& blockman,
                                        const fs::path& blocks_dir,
                                        ProgressCallback progress_cb)
{
    int resume_height = ReadResumeMarker(blocks_dir);
    if (resume_height < 0) {
        // No resume marker — start a fresh conversion.
        return Convert(blockman, blocks_dir, progress_cb);
    }

    ConversionResult result;

    LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
        "Ghost Exorcist: resuming conversion from height %d\n", resume_height);

    uint32_t start_height = static_cast<uint32_t>(resume_height) + 1;

    if (!StripArchive(blockman, blocks_dir, start_height, result, progress_cb)) {
        return result;
    }

    if (!SecureZeroOriginals(blocks_dir, progress_cb)) {
        result.error = "Failed to securely zero original block files";
        return result;
    }

    if (!CleanupOriginals(blocks_dir, progress_cb)) {
        result.error = "Failed to clean up original files";
        return result;
    }

    DeleteResumeMarker(blocks_dir);

    result.success = true;
    result.bytes_freed = result.original_size - result.stripped_size;
    return result;
}

bool GhostExorcist::StripArchive(node::BlockManager& blockman,
                                  const fs::path& blocks_dir,
                                  uint32_t start_height,
                                  ConversionResult& result,
                                  ProgressCallback progress_cb)
{
    LOCK(::cs_main);

    // Collect all block indices and sort by height.
    auto indices = blockman.GetAllBlockIndices();
    std::sort(indices.begin(), indices.end(),
              [](const CBlockIndex* a, const CBlockIndex* b) {
                  return a->nHeight < b->nHeight;
              });

    // Count eligible blocks for progress reporting.
    uint32_t total_blocks = 0;
    for (const CBlockIndex* pindex : indices) {
        if (pindex->nHeight >= static_cast<int>(start_height) &&
            (pindex->nStatus & BLOCK_HAVE_DATA)) {
            total_blocks++;
        }
    }

    if (total_blocks == 0) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
            "Ghost Exorcist: no blocks to convert from height %u\n", start_height);
        return true;
    }

    LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
        "Ghost Exorcist: stripping %u blocks from height %u\n",
        total_blocks, start_height);

    // Determine starting GSB file and offset for resume.
    int gsb_file_num = 0;
    unsigned int gsb_file_offset = 0;

    if (start_height > 0) {
        // Find the last GSB file written so far and its current size.
        while (true) {
            fs::path next_path = blocks_dir / fs::u8path(strprintf("gsb%05u.dat", gsb_file_num + 1));
            if (!fs::exists(next_path)) break;
            gsb_file_num++;
        }
        fs::path current_path = blocks_dir / fs::u8path(strprintf("gsb%05u.dat", gsb_file_num));
        if (fs::exists(current_path)) {
            gsb_file_offset = static_cast<unsigned int>(fs::file_size(current_path));
        }
    }

    uint32_t blocks_processed = 0;
    uint32_t dirty_count = 0;

    for (CBlockIndex* pindex : indices) {
        if (pindex->nHeight < static_cast<int>(start_height)) continue;
        if (!(pindex->nStatus & BLOCK_HAVE_DATA)) continue;

        // Read the full block from blk*.dat.
        CBlock block;
        if (!blockman.ReadBlock(block, *pindex)) {
            result.error = strprintf("Failed to read block at height %d", pindex->nHeight);
            return false;
        }

        // Strip hazeable content.
        StripResult strip_result = StripBlock(block);

        // Verify merkle root integrity — abort if stripping corrupted txids.
        if (!VerifyStrippedBlock(strip_result.stripped_block, block.GetBlockHeader())) {
            result.error = strprintf("Stripped block merkle root mismatch at height %d",
                                      pindex->nHeight);
            return false;
        }

        // Compute serialized size of the stripped block.
        const unsigned int block_size = static_cast<unsigned int>(
            GetSerializeSize(strip_result.stripped_block));
        const unsigned int entry_size = node::STORAGE_HEADER_BYTES + block_size;

        // Rotate to next GSB file if current would exceed max size.
        if (gsb_file_offset > 0 && gsb_file_offset + entry_size > node::MAX_BLOCKFILE_SIZE) {
            gsb_file_num++;
            gsb_file_offset = 0;
        }

        // Open GSB file at current offset and write the stripped block.
        {
            FlatFilePos write_pos{gsb_file_num, gsb_file_offset};
            AutoFile file = blockman.OpenGSBFile(write_pos, /*fReadOnly=*/false);
            if (file.IsNull()) {
                result.error = strprintf("Failed to open gsb%05u.dat at offset %u",
                                          gsb_file_num, gsb_file_offset);
                return false;
            }

            {
                BufferedWriter fileout{file};
                fileout << GSB_STORAGE_MAGIC << block_size;
                fileout << strip_result.stripped_block;
            }

            if (file.fclose() != 0) {
                result.error = strprintf("Failed to close gsb%05u.dat: %s",
                                          gsb_file_num, SysErrorString(errno));
                return false;
            }
        }

        // Update block index entry to point to the new GSB position.
        // nDataPos points past the storage header (same convention as blk files).
        pindex->nFile = gsb_file_num;
        pindex->nDataPos = gsb_file_offset + node::STORAGE_HEADER_BYTES;
        pindex->nUndoPos = 0;
        pindex->nStatus &= ~BLOCK_HAVE_UNDO;

        blockman.m_dirty_blockindex.insert(pindex);
        dirty_count++;
        gsb_file_offset += entry_size;

        // Update statistics.
        result.original_size += strip_result.original_size;
        result.stripped_size += strip_result.stripped_size;
        result.blocks_converted++;
        blocks_processed++;

        // Periodically flush block index to LevelDB and update resume marker.
        if (dirty_count >= BATCH_FLUSH_INTERVAL) {
            if (!blockman.WriteBlockIndexDB()) {
                result.error = "Failed to flush block index updates to database";
                return false;
            }
            dirty_count = 0;
            WriteResumeMarker(blocks_dir, pindex->nHeight);

            LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
                "Ghost Exorcist: %u / %u blocks stripped (%.1f%%)\n",
                blocks_processed, total_blocks,
                static_cast<double>(blocks_processed) / total_blocks * 100.0);
        }

        // Report progress via callback.
        if (progress_cb) {
            Progress p;
            p.blocks_processed = blocks_processed;
            p.blocks_total = total_blocks;
            p.percent = total_blocks > 0
                ? static_cast<double>(blocks_processed) / total_blocks * 100.0
                : 0.0;
            p.current_phase = "stripping";
            progress_cb(p);
        }
    }

    // Final flush of remaining dirty entries.
    if (dirty_count > 0) {
        if (!blockman.WriteBlockIndexDB()) {
            result.error = "Failed to flush final block index updates";
            return false;
        }
    }

    return true;
}

bool GhostExorcist::SecureZeroOriginals(const fs::path& blocks_dir,
                                         ProgressCallback progress_cb)
{
    LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
        "Ghost Exorcist: securely zeroing original block files\n");

    static constexpr size_t ZERO_CHUNK_SIZE = 64 * 1024; // 64 KiB
    std::vector<uint8_t> zeros(ZERO_CHUNK_SIZE, 0);
    int files_zeroed = 0;

    for (int file_num = 0; ; file_num++) {
        fs::path blk_path = blocks_dir / fs::u8path(strprintf("blk%05u.dat", file_num));
        if (!fs::exists(blk_path)) break;

        FILE* fp = fsbridge::fopen(blk_path, "r+b");
        if (!fp) {
            LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                "Ghost Exorcist: failed to open %s for zeroing: %s\n",
                fs::PathToString(blk_path), SysErrorString(errno));
            return false;
        }

        // Determine file size.
        if (fseek(fp, 0, SEEK_END) != 0) {
            fclose(fp);
            return false;
        }
        long file_size = ftell(fp);
        if (fseek(fp, 0, SEEK_SET) != 0) {
            fclose(fp);
            return false;
        }

        // Overwrite every byte with zeros.
        long remaining = file_size;
        while (remaining > 0) {
            size_t to_write = std::min(static_cast<size_t>(remaining), ZERO_CHUNK_SIZE);
            if (fwrite(zeros.data(), 1, to_write, fp) != to_write) {
                LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                    "Ghost Exorcist: write failed during zeroing of %s: %s\n",
                    fs::PathToString(blk_path), SysErrorString(errno));
                fclose(fp);
                return false;
            }
            remaining -= to_write;
        }

        // Force zeros to physical media before closing.
        FileCommit(fp);
        fclose(fp);
        files_zeroed++;

        LogPrintLevel(BCLog::HAZE, BCLog::Level::Debug,
            "Ghost Exorcist: zeroed %s (%ld bytes)\n",
            fs::PathToString(blk_path), file_size);

        if (progress_cb) {
            Progress p;
            p.current_phase = "zeroing";
            progress_cb(p);
        }
    }

    LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
        "Ghost Exorcist: securely zeroed %d block files\n", files_zeroed);
    return true;
}

bool GhostExorcist::CleanupOriginals(const fs::path& blocks_dir,
                                      ProgressCallback progress_cb)
{
    LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
        "Ghost Exorcist: deleting original block and undo files\n");

    int blk_deleted = 0;
    int rev_deleted = 0;

    // Delete blk*.dat files.
    for (int file_num = 0; ; file_num++) {
        fs::path blk_path = blocks_dir / fs::u8path(strprintf("blk%05u.dat", file_num));
        if (!fs::exists(blk_path)) break;

        std::error_code ec;
        fs::remove(blk_path, ec);
        if (ec) {
            LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                "Ghost Exorcist: failed to delete %s: %s\n",
                fs::PathToString(blk_path), ec.message());
            return false;
        }
        blk_deleted++;
    }

    // Delete rev*.dat files.
    for (int file_num = 0; ; file_num++) {
        fs::path rev_path = blocks_dir / fs::u8path(strprintf("rev%05u.dat", file_num));
        if (!fs::exists(rev_path)) break;

        std::error_code ec;
        fs::remove(rev_path, ec);
        if (ec) {
            LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                "Ghost Exorcist: failed to delete %s: %s\n",
                fs::PathToString(rev_path), ec.message());
            return false;
        }
        rev_deleted++;
    }

    LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
        "Ghost Exorcist: deleted %d blk files and %d rev files\n",
        blk_deleted, rev_deleted);

    if (progress_cb) {
        Progress p;
        p.current_phase = "cleanup";
        progress_cb(p);
    }

    return true;
}

bool GhostExorcist::WriteResumeMarker(const fs::path& blocks_dir, uint32_t height)
{
    fs::path marker_path = blocks_dir / fs::u8path(RESUME_MARKER_FILE);
    std::ofstream ofs(marker_path, std::ios::binary | std::ios::trunc);
    if (!ofs) return false;
    ofs.write(reinterpret_cast<const char*>(&height), sizeof(height));
    return ofs.good();
}

int GhostExorcist::ReadResumeMarker(const fs::path& blocks_dir)
{
    fs::path marker_path = blocks_dir / fs::u8path(RESUME_MARKER_FILE);
    std::ifstream ifs(marker_path, std::ios::binary);
    if (!ifs) return -1;
    uint32_t height;
    ifs.read(reinterpret_cast<char*>(&height), sizeof(height));
    if (!ifs.good()) return -1;
    return static_cast<int>(height);
}

void GhostExorcist::DeleteResumeMarker(const fs::path& blocks_dir)
{
    std::error_code ec;
    fs::remove(blocks_dir / fs::u8path(RESUME_MARKER_FILE), ec);
}

} // namespace haze
