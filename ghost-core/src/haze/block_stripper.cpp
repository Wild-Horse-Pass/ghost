// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <haze/block_stripper.h>

#include <haze/field_classifier.h>
#include <logging.h>
#include <serialize.h>
#include <streams.h>

namespace haze {

CScript MakeStrippedOpReturn()
{
    CScript script;
    script << OP_RETURN;
    script << OP_0;
    return script;
}

CStrippedTransaction StripTransaction(const CTransaction& tx, bool is_coinbase)
{
    CStrippedTransaction stripped;

    stripped.m_version = tx.version;
    stripped.m_locktime = tx.nLockTime;

    // Determine if we need to store the txid
    // For legacy/P2SH-wrapped transactions with non-empty scriptSig,
    // the txid cannot be recomputed from stripped data because scriptSig
    // is part of the txid hash. Coinbase txids also need storing since
    // their scriptSig (block height + arbitrary data) is stripped.
    stripped.m_has_stored_txid = RequiresStoredTxid(tx);
    if (stripped.m_has_stored_txid) {
        stripped.m_stored_txid = tx.GetHash().ToUint256();
    }

    // Strip inputs: keep only prevout + sequence
    stripped.m_inputs.reserve(tx.vin.size());
    for (const auto& txin : tx.vin) {
        stripped.m_inputs.emplace_back(txin.prevout, txin.nSequence);
    }

    // Strip outputs: keep value + scriptPubKey, but replace OP_RETURN payloads
    stripped.m_outputs.reserve(tx.vout.size());
    for (const auto& txout : tx.vout) {
        if (IsOpReturn(txout.scriptPubKey)) {
            stripped.m_outputs.emplace_back(txout.nValue, MakeStrippedOpReturn());
        } else {
            stripped.m_outputs.emplace_back(txout.nValue, txout.scriptPubKey);
        }
    }

    return stripped;
}

StripResult StripBlock(const CBlock& block)
{
    StripResult result;

    // Compute original size (with witness data)
    result.original_size = GetSerializeSize(TX_WITH_WITNESS(block));

    // Copy the block header
    result.stripped_block.m_header = block.GetBlockHeader();

    // Strip each transaction
    result.stripped_block.m_transactions.reserve(block.vtx.size());

    for (size_t i = 0; i < block.vtx.size(); ++i) {
        const auto& tx = block.vtx[i];
        bool is_coinbase = (i == 0);

        // Collect statistics before stripping
        for (const auto& txin : tx->vin) {
            if (is_coinbase) {
                result.coinbase_bytes_removed += txin.scriptSig.size();
            } else {
                result.scriptsig_bytes_removed += txin.scriptSig.size();
            }
            result.witness_bytes_removed += WitnessDataSize(txin.scriptWitness);
        }
        for (const auto& txout : tx->vout) {
            if (IsOpReturn(txout.scriptPubKey) && txout.scriptPubKey.size() > 1) {
                // OP_RETURN payload is everything after the opcode, minus
                // the 2 bytes we keep (OP_RETURN + OP_0)
                result.opreturn_bytes_removed += txout.scriptPubKey.size() - 1;
            }
        }

        CStrippedTransaction stripped_tx = StripTransaction(*tx, is_coinbase);

        if (stripped_tx.m_has_stored_txid) {
            result.txids_stored++;
        }

        result.stripped_block.m_transactions.push_back(std::move(stripped_tx));
    }

    // Compute stripped size
    DataStream ss{};
    ss << result.stripped_block;
    result.stripped_size = ss.size();

    LogPrintLevel(BCLog::HAZE, BCLog::Level::Debug,
        "Stripped block %s: %zu → %zu bytes (%.1f%% reduction), "
        "witness=%zu scriptSig=%zu opreturn=%zu coinbase=%zu, stored_txids=%u\n",
        block.GetHash().ToString(),
        result.original_size, result.stripped_size,
        result.original_size > 0 ? (1.0 - static_cast<double>(result.stripped_size) / result.original_size) * 100.0 : 0.0,
        result.witness_bytes_removed, result.scriptsig_bytes_removed,
        result.opreturn_bytes_removed, result.coinbase_bytes_removed,
        result.txids_stored);

    return result;
}

bool VerifyStrippedBlock(const CStrippedBlock& stripped, const CBlockHeader& expected_header)
{
    // Verify header matches
    if (stripped.m_header.GetHash() != expected_header.GetHash()) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
            "Stripped block header hash mismatch: got %s, expected %s\n",
            stripped.m_header.GetHash().ToString(),
            expected_header.GetHash().ToString());
        return false;
    }

    // Verify merkle root: compute from stripped txids, compare to header
    uint256 computed_merkle = stripped.ComputeMerkleRoot();
    if (computed_merkle != expected_header.hashMerkleRoot) {
        LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
            "Stripped block merkle root mismatch: computed %s, header has %s\n",
            computed_merkle.ToString(),
            expected_header.hashMerkleRoot.ToString());
        return false;
    }

    return true;
}

} // namespace haze
