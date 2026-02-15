// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <haze/bloom_filter.h>

#include <crypto/siphash.h>
#include <logging.h>

#include <cassert>
#include <cmath>
#include <cstring>
#include <fstream>

namespace haze {

SwiftSyncFilter::SwiftSyncFilter(uint64_t num_elements, double fp_rate, uint64_t seed)
    : m_seed(seed)
{
    // Optimal number of bits: m = -n * ln(p) / (ln(2)^2)
    double ln2 = std::log(2.0);
    double m = -static_cast<double>(num_elements) * std::log(fp_rate) / (ln2 * ln2);
    m_num_bits = static_cast<uint64_t>(std::ceil(m));

    // Round up to byte boundary
    m_num_bits = ((m_num_bits + 7) / 8) * 8;

    // Optimal number of hash functions: k = (m/n) * ln(2)
    double k = (static_cast<double>(m_num_bits) / static_cast<double>(num_elements)) * ln2;
    m_num_hashes = static_cast<uint8_t>(std::round(k));
    if (m_num_hashes < 1) m_num_hashes = 1;
    if (m_num_hashes > 30) m_num_hashes = 30;

    // Allocate bit array (zero-initialized)
    m_bits.resize(m_num_bits / 8, 0);

    LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
                  "SwiftSyncFilter: created for %llu elements, %llu bits (%zu MB), %u hash functions\n",
                  static_cast<unsigned long long>(num_elements),
                  static_cast<unsigned long long>(m_num_bits),
                  m_bits.size() / (1024 * 1024),
                  m_num_hashes);
}

uint64_t SwiftSyncFilter::HashOutpoint(uint8_t k, const COutPoint& outpoint) const
{
    // Derive per-function SipHash keys from the seed and function index.
    // Using different constants per hash function ensures independence.
    uint64_t k0 = m_seed ^ (static_cast<uint64_t>(k) * 0x517cc1b727220a95ULL);
    uint64_t k1 = m_seed ^ (static_cast<uint64_t>(k) * 0x6c62272e07bb0142ULL);

    return SipHashUint256Extra(k0, k1, outpoint.hash.ToUint256(), outpoint.n) % m_num_bits;
}

void SwiftSyncFilter::SetBit(uint64_t pos)
{
    assert(pos < m_num_bits);
    m_bits[pos / 8] |= (1 << (pos % 8));
}

bool SwiftSyncFilter::TestBit(uint64_t pos) const
{
    assert(pos < m_num_bits);
    return (m_bits[pos / 8] & (1 << (pos % 8))) != 0;
}

void SwiftSyncFilter::Insert(const COutPoint& outpoint)
{
    for (uint8_t i = 0; i < m_num_hashes; ++i) {
        uint64_t bit_pos = HashOutpoint(i, outpoint);
        SetBit(bit_pos);
    }
}

bool SwiftSyncFilter::MayContain(const COutPoint& outpoint) const
{
    for (uint8_t i = 0; i < m_num_hashes; ++i) {
        uint64_t bit_pos = HashOutpoint(i, outpoint);
        if (!TestBit(bit_pos)) return false;
    }
    return true;
}

double SwiftSyncFilter::GetFalsePositiveRate(uint64_t num_elements) const
{
    if (m_num_bits == 0 || num_elements == 0) return 1.0;
    // FPR ≈ (1 - e^(-k*n/m))^k
    double exponent = -static_cast<double>(m_num_hashes) *
                       static_cast<double>(num_elements) /
                       static_cast<double>(m_num_bits);
    return std::pow(1.0 - std::exp(exponent), m_num_hashes);
}

bool SwiftSyncFilter::Save(const std::string& filepath) const
{
    if (!IsInitialized()) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "SwiftSyncFilter::Save: filter not initialized\n");
        return false;
    }

    std::ofstream file(filepath, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "SwiftSyncFilter::Save: cannot open %s\n", filepath);
        return false;
    }

    // Write magic
    uint32_t magic = BLOOM_MAGIC;
    file.write(reinterpret_cast<const char*>(&magic), sizeof(magic));

    // Write parameters
    file.write(reinterpret_cast<const char*>(&m_num_bits), sizeof(m_num_bits));
    file.write(reinterpret_cast<const char*>(&m_num_hashes), sizeof(m_num_hashes));
    file.write(reinterpret_cast<const char*>(&m_seed), sizeof(m_seed));

    // Write bit array
    file.write(reinterpret_cast<const char*>(m_bits.data()), m_bits.size());

    if (!file.good()) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "SwiftSyncFilter::Save: write error on %s\n", filepath);
        return false;
    }

    file.flush();
    LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
                  "SwiftSyncFilter::Save: wrote %zu MB to %s\n",
                  m_bits.size() / (1024 * 1024), filepath);
    return true;
}

bool SwiftSyncFilter::Load(const std::string& filepath, SwiftSyncFilter& filter)
{
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "SwiftSyncFilter::Load: cannot open %s\n", filepath);
        return false;
    }

    // Read and verify magic
    uint32_t magic = 0;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    if (magic != BLOOM_MAGIC) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "SwiftSyncFilter::Load: bad magic 0x%08x (expected 0x%08x)\n",
                      magic, BLOOM_MAGIC);
        return false;
    }

    // Read parameters
    file.read(reinterpret_cast<char*>(&filter.m_num_bits), sizeof(filter.m_num_bits));
    file.read(reinterpret_cast<char*>(&filter.m_num_hashes), sizeof(filter.m_num_hashes));
    file.read(reinterpret_cast<char*>(&filter.m_seed), sizeof(filter.m_seed));

    if (!file.good()) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "SwiftSyncFilter::Load: short read on header from %s\n", filepath);
        return false;
    }

    // Sanity checks
    if (filter.m_num_hashes == 0 || filter.m_num_hashes > 30) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "SwiftSyncFilter::Load: invalid num_hashes %u\n", filter.m_num_hashes);
        return false;
    }

    const size_t expected_bytes = (filter.m_num_bits + 7) / 8;
    if (expected_bytes > 1024ULL * 1024 * 1024) { // Sanity: max 1 GB
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "SwiftSyncFilter::Load: filter too large (%zu bytes)\n", expected_bytes);
        return false;
    }

    // Read bit array
    filter.m_bits.resize(expected_bytes);
    file.read(reinterpret_cast<char*>(filter.m_bits.data()), expected_bytes);
    if (file.gcount() != static_cast<std::streamsize>(expected_bytes)) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                      "SwiftSyncFilter::Load: short read on bit array from %s\n", filepath);
        filter.m_bits.clear();
        filter.m_num_bits = 0;
        return false;
    }

    LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
                  "SwiftSyncFilter::Load: loaded %llu bits (%zu MB), %u hashes from %s\n",
                  static_cast<unsigned long long>(filter.m_num_bits),
                  filter.m_bits.size() / (1024 * 1024),
                  filter.m_num_hashes, filepath);
    return true;
}

} // namespace haze
