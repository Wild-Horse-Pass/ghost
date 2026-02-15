// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <haze/field_classifier.h>

#include <script/script.h>

namespace haze {

bool IsOpReturn(const CScript& script)
{
    return script.size() >= 1 && script[0] == OP_RETURN;
}

size_t WitnessDataSize(const CScriptWitness& witness)
{
    size_t total = 0;
    for (const auto& item : witness.stack) {
        total += item.size();
    }
    return total;
}

bool RequiresStoredTxid(const CTransaction& tx)
{
    for (const auto& txin : tx.vin) {
        if (!txin.scriptSig.empty()) {
            return true;
        }
    }
    return false;
}

std::vector<HazeableField> ClassifyTransaction(const CTransaction& tx, bool is_coinbase, uint32_t tx_index)
{
    std::vector<HazeableField> fields;

    // Classify inputs
    for (uint32_t i = 0; i < tx.vin.size(); ++i) {
        const auto& txin = tx.vin[i];

        if (is_coinbase) {
            // Coinbase scriptSig contains block height + arbitrary miner data
            if (!txin.scriptSig.empty()) {
                fields.push_back({
                    HazeFieldType::COINBASE,
                    tx_index,
                    i,
                    txin.scriptSig.size()
                });
            }
        } else {
            // Non-coinbase: scriptSig is hazeable if non-empty
            if (!txin.scriptSig.empty()) {
                fields.push_back({
                    HazeFieldType::SCRIPTSIG,
                    tx_index,
                    i,
                    txin.scriptSig.size()
                });
            }
        }

        // Witness data is hazeable if non-empty (for any input type)
        if (!txin.scriptWitness.IsNull()) {
            size_t witness_size = WitnessDataSize(txin.scriptWitness);
            if (witness_size > 0) {
                fields.push_back({
                    HazeFieldType::WITNESS,
                    tx_index,
                    i,
                    witness_size
                });
            }
        }
    }

    // Classify outputs: OP_RETURN payloads are hazeable
    for (uint32_t i = 0; i < tx.vout.size(); ++i) {
        const auto& txout = tx.vout[i];
        if (IsOpReturn(txout.scriptPubKey)) {
            // The payload is everything after the OP_RETURN opcode
            size_t payload_size = txout.scriptPubKey.size() > 1 ? txout.scriptPubKey.size() - 1 : 0;
            if (payload_size > 0) {
                fields.push_back({
                    HazeFieldType::OP_RETURN,
                    tx_index,
                    i,
                    payload_size
                });
            }
        }
    }

    return fields;
}

std::vector<HazeableField> ClassifyBlock(const CBlock& block)
{
    std::vector<HazeableField> fields;

    for (uint32_t i = 0; i < block.vtx.size(); ++i) {
        const auto& tx = block.vtx[i];
        bool is_coinbase = (i == 0);
        auto tx_fields = ClassifyTransaction(*tx, is_coinbase, i);
        fields.insert(fields.end(), tx_fields.begin(), tx_fields.end());
    }

    return fields;
}

} // namespace haze
