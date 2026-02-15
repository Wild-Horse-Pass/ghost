// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <haze/exorcism.h>

#include <logging.h>

#include <cstring>

namespace haze {

void GhostExorcism::Init(GhostMode mode)
{
    m_mode = mode;
    m_active = (mode == GhostMode::HAZED);
    if (m_active) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
            "Ghost Exorcism initialized in HAZED mode — "
            "hazeable content will never touch persistent storage\n");
    } else {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
            "Ghost Exorcism inactive — Full Archive mode\n");
    }
}

StripResult GhostExorcism::StripValidatedBlock(const CBlock& block)
{
    StripResult result = StripBlock(block);

    // Update cumulative statistics
    size_t bytes_stripped = result.witness_bytes_removed
                         + result.scriptsig_bytes_removed
                         + result.opreturn_bytes_removed
                         + result.coinbase_bytes_removed;
    m_total_bytes_stripped.fetch_add(bytes_stripped);
    m_blocks_processed.fetch_add(1);

    return result;
}

void GhostExorcism::SecureZero(void* ptr, size_t len)
{
#ifdef _WIN32
    SecureZeroMemory(ptr, len);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(ptr, len, 0, len);
#else
    // Use explicit_bzero where available (glibc 2.25+, FreeBSD 11+, OpenBSD).
    // Falls back to volatile write loop on other platforms.
    explicit_bzero(ptr, len);
#endif
}

} // namespace haze
