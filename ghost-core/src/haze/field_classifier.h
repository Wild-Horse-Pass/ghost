// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HAZE_FIELD_CLASSIFIER_H
#define BITCOIN_HAZE_FIELD_CLASSIFIER_H

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/solver.h>

#include <cstdint>
#include <vector>

namespace haze {

/** Types of hazeable fields that can be stripped from transactions. */
enum class HazeFieldType : uint8_t {
    WITNESS   = 0x01,  //!< Witness stack data (SegWit inputs)
    SCRIPTSIG = 0x02,  //!< scriptSig content (legacy/P2SH-wrapped inputs)
    OP_RETURN = 0x03,  //!< OP_RETURN output payload
    COINBASE  = 0x04,  //!< Coinbase input scriptSig (block height + arbitrary data)
    NONSTANDARD_SCRIPT = 0x05,  //!< Non-standard scriptPubKey (bare multisig, unknown scripts)
};

/** Describes a single hazeable field within a transaction. */
struct HazeableField {
    HazeFieldType type;
    uint32_t tx_index;      //!< Transaction index within the block
    uint32_t field_index;   //!< Input or output index within the transaction
    size_t original_size;   //!< Byte size of the hazeable content
};

/**
 * Classify all hazeable fields in a single transaction.
 *
 * Identifies witness data, scriptSig, OP_RETURN payloads, and coinbase
 * scriptSig that can be stripped without affecting the economic graph.
 *
 * @param[in] tx          The transaction to classify.
 * @param[in] is_coinbase Whether this is a coinbase transaction.
 * @param[in] tx_index    The transaction's index within its block (for HazeableField).
 * @return Vector of all hazeable fields found.
 */
std::vector<HazeableField> ClassifyTransaction(const CTransaction& tx, bool is_coinbase, uint32_t tx_index = 0);

/**
 * Classify all hazeable fields in every transaction of a block.
 *
 * @param[in] block The block to classify.
 * @return Vector of all hazeable fields found across all transactions.
 */
std::vector<HazeableField> ClassifyBlock(const CBlock& block);

/**
 * Determine whether a transaction requires its txid to be stored explicitly
 * in the stripped format.
 *
 * Returns true when stripping would alter the non-witness serialization
 * (and thus the txid). Two cases:
 *
 * 1. Non-empty scriptSig on any input — legacy/P2SH-wrapped transactions
 *    have their scriptSig stripped, changing the txid.
 * 2. OP_RETURN outputs — payload is replaced with OP_RETURN + OP_0,
 *    changing the output script and thus the txid.
 *
 * Native SegWit transactions without OP_RETURN outputs have empty scriptSig
 * and unmodified outputs, so the txid can be recomputed from preserved data.
 *
 * @param[in] tx The transaction to check.
 * @return true if the txid must be stored.
 */
bool RequiresStoredTxid(const CTransaction& tx);

/**
 * Check if a scriptPubKey is an OP_RETURN output.
 *
 * @param[in] script The output script to check.
 * @return true if the script starts with OP_RETURN (0x6a).
 */
bool IsOpReturn(const CScript& script);

/**
 * Check if a scriptPubKey is non-standard and should be stripped.
 *
 * Returns true for NONSTANDARD and MULTISIG script types, which can
 * encode arbitrary data (e.g. 33 bytes per fake pubkey in bare multisig).
 * Standard hash-based outputs (P2PKH, P2SH, P2WPKH, P2WSH, P2TR) are
 * safe and return false.
 *
 * @param[in] script The output script to check.
 * @return true if the script is non-standard and should be stripped.
 */
bool IsNonstandardScript(const CScript& script);

/**
 * Compute the total size of witness data for a transaction input.
 *
 * @param[in] witness The witness data to measure.
 * @return Total bytes of witness content (sum of all stack items).
 */
size_t WitnessDataSize(const CScriptWitness& witness);

} // namespace haze

#endif // BITCOIN_HAZE_FIELD_CLASSIFIER_H
