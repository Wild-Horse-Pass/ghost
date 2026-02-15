// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HAZE_STRIPPED_BLOCK_H
#define BITCOIN_HAZE_STRIPPED_BLOCK_H

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

namespace haze {

/** GSB file magic bytes: "GSB\0" */
static constexpr uint32_t GSB_MAGIC = 0x00425347; // Little-endian: 0x47 0x53 0x42 0x00

/** Flags byte bits for stripped transactions. */
static constexpr uint8_t STRIPPED_TX_HAS_STORED_TXID = 0x01;

/**
 * A stripped transaction input: prevout reference + sequence only.
 * scriptSig and witness data are permanently removed.
 */
struct CStrippedInput {
    COutPoint prevout;
    uint32_t n_sequence;

    CStrippedInput() : n_sequence(CTxIn::SEQUENCE_FINAL) {}
    CStrippedInput(const COutPoint& prevout_in, uint32_t seq)
        : prevout(prevout_in), n_sequence(seq) {}

    SERIALIZE_METHODS(CStrippedInput, obj)
    {
        READWRITE(obj.prevout);
        // Write empty scriptSig (single zero byte for length)
        SER_WRITE(obj, {
            uint8_t empty = 0x00;
            READWRITE(empty);
        });
        SER_READ(obj, {
            uint8_t empty;
            READWRITE(empty);
        });
        READWRITE(obj.n_sequence);
    }
};

/**
 * A stripped transaction output: value + scriptPubKey.
 * OP_RETURN payloads are replaced with OP_RETURN + 0x00.
 */
struct CStrippedOutput {
    CAmount n_value;
    CScript script_pub_key;

    CStrippedOutput() : n_value(-1) {}
    CStrippedOutput(CAmount value, CScript script)
        : n_value(value), script_pub_key(std::move(script)) {}

    SERIALIZE_METHODS(CStrippedOutput, obj)
    {
        READWRITE(obj.n_value, obj.script_pub_key);
    }
};

/**
 * A stripped transaction: structural data only.
 *
 * Contains version, inputs (prevout + sequence), outputs (value + scriptPubKey),
 * locktime, and optionally a stored txid for transactions that had non-empty
 * scriptSig (legacy/P2SH-wrapped).
 */
class CStrippedTransaction {
public:
    bool m_has_stored_txid{false};
    uint256 m_stored_txid;
    int32_t m_version{CTransaction::CURRENT_VERSION};
    std::vector<CStrippedInput> m_inputs;
    std::vector<CStrippedOutput> m_outputs;
    uint32_t m_locktime{0};

    CStrippedTransaction() = default;

    /**
     * Get the txid for this transaction.
     *
     * If a stored txid exists (legacy tx with stripped scriptSig), return it.
     * Otherwise, compute the txid from the preserved structural data.
     * For native SegWit transactions, the txid is computable because
     * scriptSig was empty — the serialization without witness is:
     * version + inputs(prevout + empty_scriptSig + sequence) + outputs + locktime.
     */
    uint256 GetTxid() const;

    SERIALIZE_METHODS(CStrippedTransaction, obj)
    {
        // Flags byte
        uint8_t flags = obj.m_has_stored_txid ? STRIPPED_TX_HAS_STORED_TXID : 0;
        READWRITE(flags);
        SER_READ(obj, obj.m_has_stored_txid = (flags & STRIPPED_TX_HAS_STORED_TXID) != 0);

        // Optional stored txid
        if (obj.m_has_stored_txid) {
            READWRITE(obj.m_stored_txid);
        }

        READWRITE(obj.m_version);
        READWRITE(obj.m_inputs);
        READWRITE(obj.m_outputs);
        READWRITE(obj.m_locktime);
    }
};

/**
 * A stripped block: block header + stripped transactions.
 *
 * This is the on-disk format for Ghost Haze mode. All hazeable content
 * (witness data, scriptSig, OP_RETURN payloads, coinbase scriptSig)
 * has been permanently removed. The block header and economic graph
 * (who paid whom, how much, to which address) are fully preserved.
 */
class CStrippedBlock {
public:
    CBlockHeader m_header;
    std::vector<CStrippedTransaction> m_transactions;

    CStrippedBlock() = default;

    /** Get the txid for a transaction by index. */
    uint256 GetTxid(size_t tx_index) const;

    /** Get the number of transactions. */
    size_t GetTxCount() const { return m_transactions.size(); }

    /** Compute the merkle root from transaction ids. */
    uint256 ComputeMerkleRoot(bool* mutated = nullptr) const;

    SERIALIZE_METHODS(CStrippedBlock, obj)
    {
        READWRITE(obj.m_header);
        READWRITE(obj.m_transactions);
    }
};

/**
 * Serialize a stripped block in GSB format (with magic + size header).
 *
 * Format:
 *   [4 bytes] Magic: 0x47534200 ("GSB\0")
 *   [4 bytes] Stripped block data size (uint32 LE)
 *   [variable] Serialized CStrippedBlock
 *
 * @param[in]  block  The stripped block to serialize.
 * @param[out] data   Output buffer receiving the GSB-format bytes.
 */
void SerializeGSB(const CStrippedBlock& block, std::vector<std::byte>& data);

/**
 * Deserialize a stripped block from GSB format.
 *
 * @param[in]  data   Input buffer containing GSB-format bytes.
 * @param[out] block  Output stripped block.
 * @return true on success, false if magic/size mismatch or data corrupt.
 */
bool DeserializeGSB(const std::vector<std::byte>& data, CStrippedBlock& block);

} // namespace haze

#endif // BITCOIN_HAZE_STRIPPED_BLOCK_H
