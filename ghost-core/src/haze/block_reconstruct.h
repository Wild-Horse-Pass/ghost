// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HAZE_BLOCK_RECONSTRUCT_H
#define BITCOIN_HAZE_BLOCK_RECONSTRUCT_H

#include <haze/stripped_block.h>
#include <primitives/block.h>

namespace haze {

/**
 * Reconstruct a partial CBlock from a CStrippedBlock.
 *
 * The returned block has:
 * - Correct block header (unchanged)
 * - Transactions with empty scriptSig and empty witness
 * - Outputs with preserved values and scriptPubKeys
 * - Stripped OP_RETURN outputs preserved as OP_RETURN + 0x00
 * - If the original had a stored txid, the coinbase/legacy tx preserves it
 *
 * The block is suitable for RPC JSON serialization with haze indicators,
 * but NOT for full validation (signatures are missing).
 *
 * @param[in] stripped  The stripped block to reconstruct from.
 * @return A partial CBlock with stripped fields empty/zeroed.
 */
CBlock ReconstructPartialBlock(const CStrippedBlock& stripped);

/**
 * Metadata about a reconstructed block.
 *
 * Returned alongside the block to indicate which fields were stripped,
 * for RPC output enrichment.
 */
struct ReconstructionMeta {
    bool is_reconstructed{false};
    bool witness_stripped{true};
    bool scriptsig_stripped{true};
    bool opreturn_stripped{true};
    bool coinbase_stripped{true};
};

/**
 * Reconstruct a partial CBlock with metadata about stripped fields.
 *
 * @param[in]  stripped  The stripped block to reconstruct from.
 * @param[out] meta      Metadata about what was stripped.
 * @return A partial CBlock.
 */
CBlock ReconstructPartialBlockWithMeta(const CStrippedBlock& stripped, ReconstructionMeta& meta);

} // namespace haze

#endif // BITCOIN_HAZE_BLOCK_RECONSTRUCT_H
