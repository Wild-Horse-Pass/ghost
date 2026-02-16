// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HAZE_BLOCK_STRIPPER_H
#define BITCOIN_HAZE_BLOCK_STRIPPER_H

#include <haze/stripped_block.h>
#include <primitives/block.h>

#include <cstddef>
#include <cstdint>

namespace haze {

/** Statistics from a block stripping operation. */
struct StripResult {
    CStrippedBlock stripped_block;
    size_t original_size{0};           //!< Full block serialized size (with witness)
    size_t stripped_size{0};           //!< Stripped block serialized size
    size_t witness_bytes_removed{0};
    size_t scriptsig_bytes_removed{0};
    size_t opreturn_bytes_removed{0};
    size_t coinbase_bytes_removed{0};
    size_t nonstandard_bytes_removed{0};
    uint32_t txids_stored{0};         //!< Number of txids stored explicitly (legacy txs)
};

/**
 * Strip a full validated block into a stripped block.
 *
 * Removes all hazeable content: witness data, scriptSig, OP_RETURN payloads,
 * and coinbase scriptSig. Preserves the complete economic graph.
 *
 * @param[in] block The fully validated block to strip.
 * @return StripResult containing the stripped block and statistics.
 */
StripResult StripBlock(const CBlock& block);

/**
 * Strip a single transaction.
 *
 * @param[in] tx          The transaction to strip.
 * @param[in] is_coinbase Whether this is a coinbase transaction.
 * @return A stripped transaction with hazeable content removed.
 */
CStrippedTransaction StripTransaction(const CTransaction& tx, bool is_coinbase);

/**
 * Verify a stripped block's structural integrity.
 *
 * Checks that the merkle root computed from stripped transaction txids
 * matches the header's merkle root. This proves that the stripping
 * preserved transaction identity correctly.
 *
 * @param[in] stripped        The stripped block to verify.
 * @param[in] expected_header The original block header to verify against.
 * @return true if the merkle root matches and the header is valid.
 */
bool VerifyStrippedBlock(const CStrippedBlock& stripped, const CBlockHeader& expected_header);

/**
 * Create a stripped OP_RETURN scriptPubKey.
 *
 * Replaces the OP_RETURN payload with a minimal marker: OP_RETURN + OP_0.
 * This preserves the output as identifiable OP_RETURN while destroying
 * the embedded content.
 *
 * @return A CScript containing just OP_RETURN + 0x00.
 */
CScript MakeStrippedOpReturn();

/**
 * Create a stripped non-standard scriptPubKey.
 *
 * Replaces non-standard output scripts (bare multisig, unknown scripts)
 * with OP_RETURN + OP_1. This is distinct from stripped OP_RETURN outputs
 * which use OP_RETURN + OP_0, allowing forensic distinction between the two.
 *
 * @return A CScript containing OP_RETURN + 0x51.
 */
CScript MakeStrippedNonstandard();

} // namespace haze

#endif // BITCOIN_HAZE_BLOCK_STRIPPER_H
