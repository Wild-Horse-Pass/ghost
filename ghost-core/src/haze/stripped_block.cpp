// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <haze/stripped_block.h>

#include <consensus/merkle.h>
#include <hash.h>
#include <streams.h>

namespace haze {

uint256 CStrippedTransaction::GetTxid() const
{
    if (m_has_stored_txid) {
        return m_stored_txid;
    }

    // Compute txid from preserved structural data.
    // For native SegWit transactions, scriptSig was empty, so the txid
    // serialization (TX_NO_WITNESS format) is:
    //   version + vin(prevout + empty_scriptSig + sequence) + vout + locktime
    // This is exactly what our stripped format preserves.
    HashWriter hasher{};
    hasher << m_version;

    // Inputs
    WriteCompactSize(hasher, m_inputs.size());
    for (const auto& input : m_inputs) {
        hasher << input.prevout;
        // Empty scriptSig
        WriteCompactSize(hasher, 0);
        hasher << input.n_sequence;
    }

    // Outputs
    WriteCompactSize(hasher, m_outputs.size());
    for (const auto& output : m_outputs) {
        hasher << output.n_value;
        hasher << output.script_pub_key;
    }

    hasher << m_locktime;

    return hasher.GetHash();
}

uint256 CStrippedBlock::GetTxid(size_t tx_index) const
{
    if (tx_index >= m_transactions.size()) {
        return uint256{};
    }
    return m_transactions[tx_index].GetTxid();
}

uint256 CStrippedBlock::ComputeMerkleRoot(bool* mutated) const
{
    std::vector<uint256> leaves;
    leaves.resize(m_transactions.size());
    for (size_t i = 0; i < m_transactions.size(); ++i) {
        leaves[i] = m_transactions[i].GetTxid();
    }
    return ::ComputeMerkleRoot(std::move(leaves), mutated);
}

void SerializeGSB(const CStrippedBlock& block, std::vector<std::byte>& data)
{
    // Serialize the block content first to get the size
    DataStream ss{};
    ss << block;

    // Build the GSB output: magic + size + content
    data.resize(sizeof(GSB_MAGIC) + sizeof(uint32_t) + ss.size());

    // Write magic
    auto* p = reinterpret_cast<uint8_t*>(data.data());
    p[0] = 0x47; // 'G'
    p[1] = 0x53; // 'S'
    p[2] = 0x42; // 'B'
    p[3] = 0x00; // '\0'

    // Write size (little-endian)
    uint32_t block_size = static_cast<uint32_t>(ss.size());
    p[4] = static_cast<uint8_t>(block_size);
    p[5] = static_cast<uint8_t>(block_size >> 8);
    p[6] = static_cast<uint8_t>(block_size >> 16);
    p[7] = static_cast<uint8_t>(block_size >> 24);

    // Write serialized block data
    std::memcpy(p + 8, ss.data(), ss.size());
}

bool DeserializeGSB(const std::vector<std::byte>& data, CStrippedBlock& block)
{
    // Minimum size: magic(4) + size(4) + header(80) + tx_count(1)
    if (data.size() < 89) {
        return false;
    }

    const auto* p = reinterpret_cast<const uint8_t*>(data.data());

    // Verify magic
    if (p[0] != 0x47 || p[1] != 0x53 || p[2] != 0x42 || p[3] != 0x00) {
        return false;
    }

    // Read size
    uint32_t block_size = static_cast<uint32_t>(p[4])
                        | (static_cast<uint32_t>(p[5]) << 8)
                        | (static_cast<uint32_t>(p[6]) << 16)
                        | (static_cast<uint32_t>(p[7]) << 24);

    if (data.size() < 8 + block_size) {
        return false;
    }

    // Deserialize the block content
    try {
        DataStream ss{std::span<const uint8_t>{p + 8, block_size}};
        ss >> block;
    } catch (const std::exception&) {
        return false;
    }

    return true;
}

} // namespace haze
