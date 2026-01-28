// Copyright (c) 2024-present The Ghost Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <core_io.h>
#include <ghostlock.h>
#include <key_io.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/script.h>
#include <script/solver.h>
#include <silentpayments.h>
#include <util/strencodings.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <random>
#include <vector>

namespace wallet {
namespace {

/** Wraith Protocol OP_RETURN markers */
constexpr std::array<unsigned char, 4> WRAITH_PHASE1_MARKER = {'G', 'P', 'W', '1'};
constexpr std::array<unsigned char, 4> WRAITH_PHASE2_MARKER = {'G', 'P', 'W', '2'};

/** Check if data is a Wraith Protocol OP_RETURN */
bool IsWraithOpReturn(const std::vector<unsigned char>& data, int& phase_out) {
    if (data.size() < 36) return false;  // 4 byte marker + 32 byte session ID

    if (std::equal(WRAITH_PHASE1_MARKER.begin(), WRAITH_PHASE1_MARKER.end(), data.begin())) {
        phase_out = 1;
        return true;
    }
    if (std::equal(WRAITH_PHASE2_MARKER.begin(), WRAITH_PHASE2_MARKER.end(), data.begin())) {
        phase_out = 2;
        return true;
    }
    return false;
}

/** Parse Wraith OP_RETURN data */
std::optional<std::pair<int, uint256>> ParseWraithOpReturn(const std::vector<unsigned char>& data) {
    int phase;
    if (!IsWraithOpReturn(data, phase)) {
        return std::nullopt;
    }

    uint256 session_id;
    if (data.size() >= 36) {
        std::copy(data.begin() + 4, data.begin() + 36, session_id.begin());
    }

    return std::make_pair(phase, session_id);
}

} // anonymous namespace

RPCHelpMan createwraithtx()
{
    return RPCHelpMan{
        "createwraithtx",
        "Create a Wraith Protocol Phase 1 (Split) transaction template.\n"
        "Takes participant inputs and creates 10x intermediate Ghost Lock outputs per participant.\n"
        "Outputs are shuffled to break the link between inputs and outputs.\n"
        "Returns an unsigned transaction that needs to be signed by all participants.\n",
        {
            {"inputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The inputs",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The input amount"},
                        },
                    },
                },
            },
            {"intermediate_outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The intermediate output addresses",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "P2TR address for intermediate Ghost Lock"},
                },
            },
            {"session_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Session identifier (string, will be hashed to 32 bytes)"},
            {"denomination", RPCArg::Type::STR, RPCArg::Optional::NO, "Denomination (micro, tiny, small, medium, large, xl)"},
            {"treasury_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Address for protocol fee output"},
            {"mining_fee", RPCArg::Type::AMOUNT, RPCArg::Default{1000}, "Mining fee in satoshis"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "The unsigned transaction hex"},
                {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                {RPCResult::Type::STR, "session_id", "The session identifier"},
                {RPCResult::Type::STR, "denomination", "The denomination used"},
                {RPCResult::Type::NUM, "inputs", "Number of inputs"},
                {RPCResult::Type::NUM, "outputs", "Number of outputs (including OP_RETURN)"},
                {RPCResult::Type::NUM, "input_count", "Number of inputs (deprecated, use 'inputs')"},
                {RPCResult::Type::NUM, "output_count", "Number of outputs (deprecated, use 'outputs')"},
                {RPCResult::Type::STR_AMOUNT, "total_input", "Total input amount"},
                {RPCResult::Type::STR_AMOUNT, "total_output", "Total output amount"},
                {RPCResult::Type::STR_AMOUNT, "fee", "Transaction fee"},
            },
        },
        RPCExamples{
            HelpExampleCli("createwraithtx",
                           "'[{\"txid\":\"abc...\",\"vout\":0,\"amount\":0.0101}]' "
                           "'[\"tb1p...\",\"tb1p...\"]' "
                           "\"0123456789abcdef...\" "
                           "\"small\" "
                           "\"tb1p...\" "
                           "0.00001")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            // Parse inputs
            const UniValue& inputs = request.params[0].get_array();
            if (inputs.size() == 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "At least one input required");
            }

            std::vector<CTxIn> tx_inputs;
            CAmount total_input = 0;

            for (size_t i = 0; i < inputs.size(); ++i) {
                const UniValue& input = inputs[i];
                auto txid_opt = Txid::FromHex(input["txid"].get_str());
                if (!txid_opt) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Invalid txid at input index %d", i));
                }
                Txid txid = *txid_opt;
                int vout = input["vout"].getInt<int>();
                if (vout < 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Invalid vout at input index %d: must be non-negative", i));
                }
                CAmount amount = AmountFromValue(input["amount"]);

                tx_inputs.emplace_back(COutPoint(txid, vout));
                total_input += amount;
            }

            // Parse intermediate outputs
            const UniValue& outputs_arr = request.params[1].get_array();
            std::vector<std::pair<CTxDestination, CAmount>> intermediate_outputs;

            // Parse denomination
            std::string denom_str = request.params[3].get_str();
            auto denom = ghostlock::DenominationFromName(denom_str);
            if (!denom) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid denomination: " + denom_str);
            }

            // Calculate intermediate output amount (1/10th of denomination)
            CAmount intermediate_amount = ghostlock::DenominationValue(*denom) / 10;

            for (size_t i = 0; i < outputs_arr.size(); ++i) {
                std::string addr_str = outputs_arr[i].get_str();
                CTxDestination dest = DecodeDestination(addr_str);
                if (!IsValidDestination(dest)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address: " + addr_str);
                }
                intermediate_outputs.emplace_back(dest, intermediate_amount);
            }

            // Validate output count matches 10x input count
            if (intermediate_outputs.size() != tx_inputs.size() * 10) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Expected %d intermediate outputs (10 per input), got %d",
                              tx_inputs.size() * 10, intermediate_outputs.size()));
            }

            // Parse session ID - accept either hex or plain string (will be hashed)
            std::string session_str = request.params[2].get_str();
            std::vector<unsigned char> session_bytes;
            if (session_str.size() == 64 && IsHex(session_str)) {
                // Already a 32-byte hex string
                session_bytes = ParseHex(session_str);
            } else {
                // Hash the string to get 32 bytes
                uint256 session_hash = Hash(MakeUCharSpan(session_str));
                session_bytes.assign(session_hash.begin(), session_hash.end());
            }

            // Parse treasury address
            std::string treasury_str = request.params[4].get_str();
            CTxDestination treasury_dest = DecodeDestination(treasury_str);
            if (!IsValidDestination(treasury_dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid treasury address");
            }

            // Parse mining fee
            CAmount mining_fee = 1000;  // default 1000 sats
            if (!request.params[5].isNull()) {
                mining_fee = AmountFromValue(request.params[5]);
            }

            // Calculate protocol fee (1% of denomination per participant)
            CAmount protocol_fee = (ghostlock::DenominationValue(*denom) / 100) * tx_inputs.size();
            CAmount treasury_amount = protocol_fee - mining_fee;

            // Build outputs vector for shuffling
            std::vector<CTxOut> tx_outputs;

            // Add intermediate outputs
            for (const auto& [dest, amount] : intermediate_outputs) {
                tx_outputs.emplace_back(amount, GetScriptForDestination(dest));
            }

            // Add treasury fee output
            tx_outputs.emplace_back(treasury_amount, GetScriptForDestination(treasury_dest));

            // Shuffle outputs (excluding OP_RETURN which we add last)
            std::random_device rd;
            std::mt19937 g(rd());
            std::shuffle(tx_outputs.begin(), tx_outputs.end(), g);

            // Add OP_RETURN at the end
            std::vector<unsigned char> op_return_data;
            op_return_data.insert(op_return_data.end(), WRAITH_PHASE1_MARKER.begin(), WRAITH_PHASE1_MARKER.end());
            op_return_data.insert(op_return_data.end(), session_bytes.begin(), session_bytes.end());

            CScript op_return_script = CScript() << OP_RETURN << op_return_data;
            tx_outputs.emplace_back(0, op_return_script);

            // Build transaction
            CMutableTransaction mtx;
            mtx.version = CTransaction::CURRENT_VERSION;
            mtx.vin = tx_inputs;
            mtx.vout = tx_outputs;

            CTransaction tx(mtx);

            // Calculate totals
            CAmount total_output = 0;
            for (const auto& out : tx.vout) {
                total_output += out.nValue;
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("hex", EncodeHexTx(tx));
            result.pushKV("txid", tx.GetHash().GetHex());
            result.pushKV("session_id", session_str);
            result.pushKV("denomination", denom_str);
            result.pushKV("inputs", (int64_t)tx.vin.size());
            result.pushKV("outputs", (int64_t)tx.vout.size());
            result.pushKV("input_count", (int64_t)tx.vin.size());  // Keep for backwards compatibility
            result.pushKV("output_count", (int64_t)tx.vout.size());  // Keep for backwards compatibility
            result.pushKV("total_input", ValueFromAmount(total_input));
            result.pushKV("total_output", ValueFromAmount(total_output));
            result.pushKV("fee", ValueFromAmount(total_input - total_output));

            return result;
        },
    };
}

RPCHelpMan createwraithfinaltx()
{
    return RPCHelpMan{
        "createwraithfinaltx",
        "Create a Wraith Protocol Phase 2 (Merge) transaction template.\n"
        "Takes 10x intermediate Ghost Lock inputs and creates final Ghost Lock outputs.\n"
        "Outputs are shuffled to break the link between intermediates and finals.\n",
        {
            {"inputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The intermediate UTXO inputs",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The input amount"},
                        },
                    },
                },
            },
            {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The final Ghost Lock output addresses",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "P2TR address for final Ghost Lock"},
                },
            },
            {"session_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Session identifier (string, will be hashed to 32 bytes)"},
            {"denomination", RPCArg::Type::STR, RPCArg::Optional::NO, "Denomination (micro, tiny, small, medium, large, xl)"},
            {"mining_fee", RPCArg::Type::AMOUNT, RPCArg::Default{1000}, "Mining fee in satoshis"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "The unsigned transaction hex"},
                {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                {RPCResult::Type::STR, "session_id", "The session identifier"},
                {RPCResult::Type::STR, "denomination", "The denomination used"},
                {RPCResult::Type::NUM, "inputs", "Number of inputs"},
                {RPCResult::Type::NUM, "outputs", "Number of outputs"},
                {RPCResult::Type::NUM, "input_count", "Number of inputs (deprecated)"},
                {RPCResult::Type::NUM, "output_count", "Number of outputs (deprecated)"},
                {RPCResult::Type::STR_AMOUNT, "total_input", "Total input amount"},
                {RPCResult::Type::STR_AMOUNT, "total_output", "Total output amount"},
                {RPCResult::Type::STR_AMOUNT, "fee", "Transaction fee"},
            },
        },
        RPCExamples{
            HelpExampleCli("createwraithfinaltx",
                           "'[{\"txid\":\"abc...\",\"vout\":0,\"amount\":0.001}]' "
                           "'[\"tb1p...\"]' "
                           "\"0123456789abcdef...\" "
                           "\"small\" "
                           "0.00001")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            // Parse inputs
            const UniValue& inputs = request.params[0].get_array();
            if (inputs.size() == 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "At least one input required");
            }

            std::vector<CTxIn> tx_inputs;
            CAmount total_input = 0;

            for (size_t i = 0; i < inputs.size(); ++i) {
                const UniValue& input = inputs[i];
                auto txid_opt = Txid::FromHex(input["txid"].get_str());
                if (!txid_opt) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Invalid txid at input index %d", i));
                }
                Txid txid = *txid_opt;
                int vout = input["vout"].getInt<int>();
                if (vout < 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Invalid vout at input index %d: must be non-negative", i));
                }
                CAmount amount = AmountFromValue(input["amount"]);

                tx_inputs.emplace_back(COutPoint(txid, vout));
                total_input += amount;
            }

            // Parse final outputs
            const UniValue& outputs_arr = request.params[1].get_array();

            // Validate input count is 10x output count
            if (tx_inputs.size() != outputs_arr.size() * 10) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Expected 10 inputs per output, got %d inputs for %d outputs",
                              tx_inputs.size(), outputs_arr.size()));
            }

            // Parse denomination
            std::string denom_str = request.params[3].get_str();
            auto denom = ghostlock::DenominationFromName(denom_str);
            if (!denom) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid denomination: " + denom_str);
            }

            CAmount final_amount = ghostlock::DenominationValue(*denom);

            // Parse mining fee
            CAmount mining_fee = 1000;
            if (!request.params[4].isNull()) {
                mining_fee = AmountFromValue(request.params[4]);
            }

            // Calculate amount per output (subtracting fee)
            CAmount fee_per_output = mining_fee / outputs_arr.size();
            CAmount output_amount = final_amount - fee_per_output;

            // Build outputs vector for shuffling
            std::vector<CTxOut> tx_outputs;

            for (size_t i = 0; i < outputs_arr.size(); ++i) {
                std::string addr_str = outputs_arr[i].get_str();
                CTxDestination dest = DecodeDestination(addr_str);
                if (!IsValidDestination(dest)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address: " + addr_str);
                }
                tx_outputs.emplace_back(output_amount, GetScriptForDestination(dest));
            }

            // Shuffle outputs
            std::random_device rd;
            std::mt19937 g(rd());
            std::shuffle(tx_outputs.begin(), tx_outputs.end(), g);

            // Parse session ID - accept either hex or plain string (will be hashed)
            std::string session_str = request.params[2].get_str();
            std::vector<unsigned char> session_bytes;
            if (session_str.size() == 64 && IsHex(session_str)) {
                // Already a 32-byte hex string
                session_bytes = ParseHex(session_str);
            } else {
                // Hash the string to get 32 bytes
                uint256 session_hash = Hash(MakeUCharSpan(session_str));
                session_bytes.assign(session_hash.begin(), session_hash.end());
            }

            // Add OP_RETURN at the end
            std::vector<unsigned char> op_return_data;
            op_return_data.insert(op_return_data.end(), WRAITH_PHASE2_MARKER.begin(), WRAITH_PHASE2_MARKER.end());
            op_return_data.insert(op_return_data.end(), session_bytes.begin(), session_bytes.end());

            CScript op_return_script = CScript() << OP_RETURN << op_return_data;
            tx_outputs.emplace_back(0, op_return_script);

            // Build transaction
            CMutableTransaction mtx;
            mtx.version = CTransaction::CURRENT_VERSION;
            mtx.vin = tx_inputs;
            mtx.vout = tx_outputs;

            CTransaction tx(mtx);

            CAmount total_output = 0;
            for (const auto& out : tx.vout) {
                total_output += out.nValue;
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("hex", EncodeHexTx(tx));
            result.pushKV("txid", tx.GetHash().GetHex());
            result.pushKV("session_id", session_str);
            result.pushKV("denomination", denom_str);
            result.pushKV("inputs", (int64_t)tx.vin.size());
            result.pushKV("outputs", (int64_t)tx.vout.size());
            result.pushKV("input_count", (int64_t)tx.vin.size());  // Keep for backwards compatibility
            result.pushKV("output_count", (int64_t)tx.vout.size());  // Keep for backwards compatibility
            result.pushKV("total_input", ValueFromAmount(total_input));
            result.pushKV("total_output", ValueFromAmount(total_output));
            result.pushKV("fee", ValueFromAmount(total_input - total_output));

            return result;
        },
    };
}

RPCHelpMan parsewraithtx()
{
    return RPCHelpMan{
        "parsewraithtx",
        "Parse a Wraith Protocol transaction and extract metadata.\n"
        "Identifies the phase, session ID, and validates the structure.\n",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction hex string"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "is_wraith", "Whether this is a Wraith Protocol transaction"},
                {RPCResult::Type::NUM, "phase", /*optional=*/true, "Phase number (1 or 2)"},
                {RPCResult::Type::STR_HEX, "session_id", /*optional=*/true, "32-byte session identifier"},
                {RPCResult::Type::NUM, "input_count", "Number of inputs"},
                {RPCResult::Type::NUM, "output_count", "Number of outputs"},
                {RPCResult::Type::STR_AMOUNT, "total_output", "Total output amount"},
            },
        },
        RPCExamples{
            HelpExampleCli("parsewraithtx", "\"0200000001...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string hex_str = request.params[0].get_str();
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, hex_str)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
            }

            CTransaction tx(mtx);

            UniValue result(UniValue::VOBJ);

            // Look for Wraith OP_RETURN
            bool is_wraith = false;
            int phase = 0;
            uint256 session_id;

            for (const auto& out : tx.vout) {
                if (out.scriptPubKey.IsUnspendable() && out.scriptPubKey.size() >= 2) {
                    std::vector<unsigned char> data(out.scriptPubKey.begin() + 2, out.scriptPubKey.end());
                    auto parsed = ParseWraithOpReturn(data);
                    if (parsed) {
                        is_wraith = true;
                        phase = parsed->first;
                        session_id = parsed->second;
                        break;
                    }
                }
            }

            result.pushKV("is_wraith", is_wraith);
            if (is_wraith) {
                result.pushKV("phase", phase);
                result.pushKV("session_id", session_id.GetHex());
            }

            result.pushKV("input_count", (int64_t)tx.vin.size());
            result.pushKV("output_count", (int64_t)tx.vout.size());

            CAmount total_output = 0;
            for (const auto& out : tx.vout) {
                total_output += out.nValue;
            }
            result.pushKV("total_output", ValueFromAmount(total_output));

            return result;
        },
    };
}

RPCHelpMan shuffleoutputs()
{
    return RPCHelpMan{
        "shuffleoutputs",
        "Shuffle the outputs of a transaction for CoinJoin-style privacy.\n"
        "Takes an unsigned transaction and returns a new one with shuffled outputs.\n",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction hex string"},
            {"keep_last", RPCArg::Type::BOOL, RPCArg::Default{false},
             "If true, keep the last output (OP_RETURN) in place"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "The shuffled transaction hex"},
                {RPCResult::Type::STR_HEX, "txid", "The new transaction id"},
                {RPCResult::Type::NUM, "original_outputs", "Number of outputs before shuffle"},
                {RPCResult::Type::NUM, "shuffled_outputs", "Number of outputs after shuffle"},
            },
        },
        RPCExamples{
            HelpExampleCli("shuffleoutputs", "\"0200000001...\" true")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string hex_str = request.params[0].get_str();
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, hex_str)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
            }

            size_t original_count = mtx.vout.size();

            bool keep_last = false;
            if (!request.params[1].isNull()) {
                keep_last = request.params[1].get_bool();
            }

            // Shuffle outputs
            std::random_device rd;
            std::mt19937 g(rd());

            if (keep_last && mtx.vout.size() > 1) {
                // Keep last output in place, shuffle the rest
                CTxOut last = mtx.vout.back();
                mtx.vout.pop_back();
                std::shuffle(mtx.vout.begin(), mtx.vout.end(), g);
                mtx.vout.push_back(last);
            } else {
                std::shuffle(mtx.vout.begin(), mtx.vout.end(), g);
            }

            CTransaction tx(mtx);

            UniValue result(UniValue::VOBJ);
            result.pushKV("hex", EncodeHexTx(tx));
            result.pushKV("txid", tx.GetHash().GetHex());
            result.pushKV("original_outputs", (int64_t)original_count);
            result.pushKV("shuffled_outputs", (int64_t)tx.vout.size());

            return result;
        },
    };
}

/** Reconciliation batch OP_RETURN marker */
constexpr std::array<unsigned char, 4> RECONCILIATION_MARKER = {'G', 'P', 'R', 'B'};

RPCHelpMan createreconciliationtx()
{
    return RPCHelpMan{
        "createreconciliationtx",
        "Create a reconciliation batch settlement transaction.\n"
        "Takes Ghost Lock inputs and creates new Ghost Lock outputs to recipients.\n"
        "Includes ephemeral pubkeys in OP_RETURN for Silent Payment scanning.\n",
        {
            {"inputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The Ghost Lock UTXO inputs",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The input amount"},
                        },
                    },
                },
            },
            {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The output specifications",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "P2TR address for Ghost Lock"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount in BTC"},
                            {"ephemeral_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "33-byte ephemeral pubkey for SP scanning"},
                        },
                    },
                },
            },
            {"epoch_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "The reconciliation epoch ID"},
            {"state_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte L2 state root (hex)"},
            {"treasury_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Address for protocol fee output"},
            {"treasury_amount", RPCArg::Type::AMOUNT, RPCArg::Default{0}, "Treasury fee amount"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "The unsigned transaction hex"},
                {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                {RPCResult::Type::NUM, "epoch_id", "The reconciliation epoch ID"},
                {RPCResult::Type::STR_HEX, "state_root", "The L2 state root"},
                {RPCResult::Type::NUM, "inputs", "Number of inputs"},
                {RPCResult::Type::NUM, "outputs", "Number of outputs"},
                {RPCResult::Type::NUM, "input_count", "Number of inputs (deprecated, use 'inputs')"},
                {RPCResult::Type::NUM, "output_count", "Number of outputs (deprecated, use 'outputs')"},
                {RPCResult::Type::NUM, "op_return_size", "Size of OP_RETURN data in bytes"},
                {RPCResult::Type::STR_AMOUNT, "total_input", "Total input amount"},
                {RPCResult::Type::STR_AMOUNT, "total_output", "Total output amount"},
                {RPCResult::Type::STR_AMOUNT, "fee", "Transaction fee"},
                {RPCResult::Type::ARR, "ephemeral_pubkeys", "Ephemeral pubkeys in OP_RETURN",
                    {
                        {RPCResult::Type::STR_HEX, "", "33-byte compressed pubkey"},
                    },
                },
            },
        },
        RPCExamples{
            HelpExampleCli("createreconciliationtx",
                           "'[{\"txid\":\"abc...\",\"vout\":0,\"amount\":0.01}]' "
                           "'[{\"address\":\"tb1p...\",\"amount\":0.0099,\"ephemeral_pubkey\":\"02...\"}]' "
                           "100 "
                           "\"0123456789abcdef...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            // Parse inputs
            const UniValue& inputs = request.params[0].get_array();
            if (inputs.size() == 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "At least one input required");
            }

            std::vector<CTxIn> tx_inputs;
            CAmount total_input = 0;

            for (size_t i = 0; i < inputs.size(); ++i) {
                const UniValue& input = inputs[i];
                auto txid_opt = Txid::FromHex(input["txid"].get_str());
                if (!txid_opt) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Invalid txid at input index %d", i));
                }
                Txid txid = *txid_opt;
                int vout = input["vout"].getInt<int>();
                if (vout < 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Invalid vout at input index %d: must be non-negative", i));
                }
                CAmount amount = AmountFromValue(input["amount"]);

                tx_inputs.emplace_back(COutPoint(txid, vout));
                total_input += amount;
            }

            // Parse outputs
            const UniValue& outputs_arr = request.params[1].get_array();
            std::vector<CTxOut> tx_outputs;
            std::vector<std::vector<unsigned char>> ephemeral_pubkeys;
            CAmount total_output = 0;

            for (size_t i = 0; i < outputs_arr.size(); ++i) {
                const UniValue& output = outputs_arr[i];
                std::string addr_str = output["address"].get_str();
                CAmount amount = AmountFromValue(output["amount"]);

                CTxDestination dest = DecodeDestination(addr_str);
                if (!IsValidDestination(dest)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address: " + addr_str);
                }

                tx_outputs.emplace_back(amount, GetScriptForDestination(dest));
                total_output += amount;

                // Parse optional ephemeral pubkey
                if (!output["ephemeral_pubkey"].isNull()) {
                    std::string epk_hex = output["ephemeral_pubkey"].get_str();
                    std::vector<unsigned char> epk_bytes = ParseHex(epk_hex);
                    if (epk_bytes.size() != 33) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            strprintf("Ephemeral pubkey must be 33 bytes, got %d", epk_bytes.size()));
                    }
                    ephemeral_pubkeys.push_back(epk_bytes);
                }
            }

            // Parse epoch ID and state root
            uint32_t epoch_id = request.params[2].getInt<uint32_t>();

            std::string state_root_hex = request.params[3].get_str();
            if (state_root_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "State root must be 32 bytes (64 hex chars)");
            }
            std::vector<unsigned char> state_root_bytes = ParseHex(state_root_hex);

            // Parse optional treasury fee
            if (!request.params[4].isNull() && !request.params[5].isNull()) {
                std::string treasury_str = request.params[4].get_str();
                CAmount treasury_amount = AmountFromValue(request.params[5]);

                CTxDestination treasury_dest = DecodeDestination(treasury_str);
                if (IsValidDestination(treasury_dest) && treasury_amount > 0) {
                    tx_outputs.emplace_back(treasury_amount, GetScriptForDestination(treasury_dest));
                    total_output += treasury_amount;
                }
            }

            // Shuffle value outputs (keep ephemeral key order for OP_RETURN)
            // Note: For production, would need to track shuffled positions
            std::random_device rd;
            std::mt19937 g(rd());
            std::shuffle(tx_outputs.begin(), tx_outputs.end(), g);

            // Build OP_RETURN data
            // Format: GPRB (4) | epoch_id (4) | state_root (32) | ephemeral_pubkeys (33 each)
            std::vector<unsigned char> op_return_data;
            op_return_data.insert(op_return_data.end(), RECONCILIATION_MARKER.begin(), RECONCILIATION_MARKER.end());

            // Epoch ID (4 bytes little-endian)
            op_return_data.push_back(epoch_id & 0xFF);
            op_return_data.push_back((epoch_id >> 8) & 0xFF);
            op_return_data.push_back((epoch_id >> 16) & 0xFF);
            op_return_data.push_back((epoch_id >> 24) & 0xFF);

            // State root
            op_return_data.insert(op_return_data.end(), state_root_bytes.begin(), state_root_bytes.end());

            // Ephemeral pubkeys
            for (const auto& epk : ephemeral_pubkeys) {
                op_return_data.insert(op_return_data.end(), epk.begin(), epk.end());
            }

            CScript op_return_script = CScript() << OP_RETURN << op_return_data;
            tx_outputs.emplace_back(0, op_return_script);

            // Build transaction
            CMutableTransaction mtx;
            mtx.version = CTransaction::CURRENT_VERSION;
            mtx.vin = tx_inputs;
            mtx.vout = tx_outputs;

            CTransaction tx(mtx);

            // Build result
            UniValue result(UniValue::VOBJ);
            result.pushKV("hex", EncodeHexTx(tx));
            result.pushKV("txid", tx.GetHash().GetHex());
            result.pushKV("epoch_id", (int64_t)epoch_id);
            result.pushKV("state_root", state_root_hex);
            result.pushKV("inputs", (int64_t)tx.vin.size());
            result.pushKV("outputs", (int64_t)tx.vout.size());
            result.pushKV("input_count", (int64_t)tx.vin.size());  // Keep for backwards compatibility
            result.pushKV("output_count", (int64_t)tx.vout.size());  // Keep for backwards compatibility
            result.pushKV("op_return_size", (int64_t)op_return_data.size());
            result.pushKV("total_input", ValueFromAmount(total_input));
            result.pushKV("total_output", ValueFromAmount(total_output));
            result.pushKV("fee", ValueFromAmount(total_input - total_output));

            UniValue epk_arr(UniValue::VARR);
            for (const auto& epk : ephemeral_pubkeys) {
                epk_arr.push_back(HexStr(epk));
            }
            result.pushKV("ephemeral_pubkeys", epk_arr);

            return result;
        },
    };
}

RPCHelpMan coordinatebatchsigning()
{
    return RPCHelpMan{
        "coordinatebatchsigning",
        "Create a PSBT for batch signing coordination.\n"
        "Converts an unsigned transaction into a PSBT that can be passed around\n"
        "for signing by multiple participants. Tracks signing progress.\n",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The unsigned transaction hex"},
            {"utxos", RPCArg::Type::ARR, RPCArg::Optional::NO, "UTXO information for inputs",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                            {"scriptPubKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The output scriptPubKey"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The output amount"},
                        },
                    },
                },
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "The base64-encoded PSBT"},
                {RPCResult::Type::NUM, "inputs", "Number of inputs requiring signatures"},
                {RPCResult::Type::BOOL, "complete", "Whether all signatures are present"},
                {RPCResult::Type::STR_AMOUNT, "fee", "Transaction fee"},
            },
        },
        RPCExamples{
            HelpExampleCli("coordinatebatchsigning",
                           "\"0200000001...\" "
                           "'[{\"txid\":\"abc...\",\"vout\":0,\"scriptPubKey\":\"5120...\",\"amount\":0.01}]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            // Decode the transaction
            std::string hex_str = request.params[0].get_str();
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, hex_str)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
            }

            // Create PSBT from transaction
            PartiallySignedTransaction psbt(mtx);

            // Parse UTXOs and add to PSBT
            const UniValue& utxos = request.params[1].get_array();
            CAmount total_input = 0;

            for (size_t i = 0; i < utxos.size() && i < psbt.inputs.size(); ++i) {
                const UniValue& utxo = utxos[i];

                // Verify UTXO matches input
                auto txid_opt = Txid::FromHex(utxo["txid"].get_str());
                if (!txid_opt) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Invalid txid at UTXO index %d", i));
                }
                Txid txid = *txid_opt;
                int vout = utxo["vout"].getInt<int>();
                if (vout < 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Invalid vout at UTXO index %d: must be non-negative", i));
                }

                if (mtx.vin[i].prevout.hash != txid || mtx.vin[i].prevout.n != (uint32_t)vout) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("UTXO at index %d doesn't match input", i));
                }

                // Create witness UTXO
                CAmount amount = AmountFromValue(utxo["amount"]);
                std::vector<unsigned char> script_bytes = ParseHex(utxo["scriptPubKey"].get_str());
                CScript script(script_bytes.begin(), script_bytes.end());

                psbt.inputs[i].witness_utxo = CTxOut(amount, script);
                total_input += amount;
            }

            // Calculate fee
            CAmount total_output = 0;
            for (const auto& out : mtx.vout) {
                total_output += out.nValue;
            }
            CAmount fee = total_input - total_output;

            // Serialize PSBT
            DataStream ssTx{};
            ssTx << psbt;
            std::string psbt_base64 = EncodeBase64(ssTx.str());

            // Check completeness (all inputs need signatures for Taproot)
            bool complete = true;
            for (const auto& input : psbt.inputs) {
                // For Taproot, we check if there's a signature in the final witness
                if (input.final_script_witness.IsNull()) {
                    complete = false;
                    break;
                }
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("psbt", psbt_base64);
            result.pushKV("inputs", (int64_t)psbt.inputs.size());
            result.pushKV("complete", complete);
            result.pushKV("fee", ValueFromAmount(fee));

            return result;
        },
    };
}

RPCHelpMan combinebatchpsbt()
{
    return RPCHelpMan{
        "combinebatchpsbt",
        "Combine multiple PSBTs for a batch transaction.\n"
        "Each participant signs the PSBT and this combines all signatures.\n",
        {
            {"psbts", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of base64-encoded PSBTs",
                {
                    {"psbt", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A base64-encoded PSBT"},
                },
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "The combined base64-encoded PSBT"},
                {RPCResult::Type::BOOL, "complete", "Whether all inputs are now signed"},
                {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "The final transaction hex (if complete)"},
            },
        },
        RPCExamples{
            HelpExampleCli("combinebatchpsbt", "'[\"cHNidP8...\", \"cHNidP8...\"]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const UniValue& psbts_arr = request.params[0].get_array();
            if (psbts_arr.size() < 2) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "At least two PSBTs required");
            }

            // Decode first PSBT as base
            std::vector<PartiallySignedTransaction> psbts;
            for (size_t i = 0; i < psbts_arr.size(); ++i) {
                std::string psbt_str = psbts_arr[i].get_str();
                auto dec = DecodeBase64(psbt_str);
                if (!dec) {
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                        strprintf("PSBT %d is not valid base64", i));
                }

                PartiallySignedTransaction psbt;
                SpanReader ss(*dec);
                ss >> psbt;
                psbts.push_back(std::move(psbt));
            }

            // Combine all PSBTs
            PartiallySignedTransaction merged = psbts[0];
            for (size_t i = 1; i < psbts.size(); ++i) {
                if (!merged.Merge(psbts[i])) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Failed to merge PSBT %d - incompatible", i));
                }
            }

            // Check if complete and finalize
            bool complete = true;
            for (size_t i = 0; i < merged.inputs.size(); ++i) {
                if (!PSBTInputSigned(merged.inputs[i])) {
                    complete = false;
                    break;
                }
            }

            // Serialize result
            DataStream ssTx{};
            ssTx << merged;
            std::string psbt_base64 = EncodeBase64(ssTx.str());

            UniValue result(UniValue::VOBJ);
            result.pushKV("psbt", psbt_base64);
            result.pushKV("complete", complete);

            // If complete, finalize and extract
            if (complete) {
                CMutableTransaction final_tx;
                for (size_t i = 0; i < merged.inputs.size(); ++i) {
                    if (!merged.inputs[i].final_script_witness.IsNull()) {
                        // Already finalized
                    }
                }

                // Try to extract
                CMutableTransaction extracted;
                bool extracted_complete = false;
                if (FinalizeAndExtractPSBT(merged, extracted)) {
                    result.pushKV("hex", EncodeHexTx(CTransaction(extracted)));
                    extracted_complete = true;
                }
                result.pushKV("complete", extracted_complete);
            }

            return result;
        },
    };
}

RPCHelpMan estimatebatchfee()
{
    return RPCHelpMan{
        "estimatebatchfee",
        "Estimate the fee for a batch reconciliation transaction.\n"
        "Calculates expected transaction size and fee based on inputs/outputs.\n",
        {
            {"num_inputs", RPCArg::Type::NUM, RPCArg::Optional::NO, "Number of Ghost Lock inputs"},
            {"num_outputs", RPCArg::Type::NUM, RPCArg::Optional::NO, "Number of Ghost Lock outputs"},
            {"include_treasury", RPCArg::Type::BOOL, RPCArg::Default{true}, "Include treasury fee output"},
            {"conf_target", RPCArg::Type::NUM, RPCArg::Default{6}, "Confirmation target in blocks"},
            {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Specific fee rate in sat/vB (overrides conf_target)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "estimated_vsize", "Estimated virtual size in vbytes"},
                {RPCResult::Type::NUM, "estimated_weight", "Estimated weight units"},
                {RPCResult::Type::STR_AMOUNT, "fee_rate", "Fee rate used (BTC/kvB)"},
                {RPCResult::Type::STR_AMOUNT, "fee_rate_sat_vb", "Fee rate in sat/vB"},
                {RPCResult::Type::STR_AMOUNT, "estimated_fee", "Estimated total fee"},
                {RPCResult::Type::STR_AMOUNT, "fee_per_input", "Fee allocated per input"},
                {RPCResult::Type::STR_AMOUNT, "fee_per_output", "Fee allocated per output"},
                {RPCResult::Type::OBJ, "breakdown", "Size breakdown",
                    {
                        {RPCResult::Type::NUM, "header", "Transaction header size"},
                        {RPCResult::Type::NUM, "inputs", "Total input size"},
                        {RPCResult::Type::NUM, "outputs", "Total output size"},
                        {RPCResult::Type::NUM, "witness", "Total witness size"},
                        {RPCResult::Type::NUM, "op_return", "OP_RETURN size"},
                    },
                },
            },
        },
        RPCExamples{
            HelpExampleCli("estimatebatchfee", "10 10 true 6") +
            HelpExampleCli("estimatebatchfee", "5 5 true 6 0.00001")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            int num_inputs = request.params[0].getInt<int>();
            int num_outputs = request.params[1].getInt<int>();

            if (num_inputs < 1 || num_inputs > 1000) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "num_inputs must be between 1 and 1000");
            }
            if (num_outputs < 1 || num_outputs > 1000) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "num_outputs must be between 1 and 1000");
            }

            bool include_treasury = true;
            if (!request.params[2].isNull()) {
                include_treasury = request.params[2].get_bool();
            }

            // Size constants for P2TR (Taproot) transactions
            // Based on BIP-341 and witness structure
            constexpr int HEADER_SIZE = 10;           // version (4) + locktime (4) + segwit marker/flag (2)
            constexpr int INPUT_BASE_SIZE = 41;       // outpoint (36) + scriptSig (1) + sequence (4)
            constexpr int P2TR_WITNESS_SIZE = 66;     // signature (64) + sighash (1) + witness stack count (1)
            constexpr int P2TR_OUTPUT_SIZE = 43;      // value (8) + scriptPubKey length (1) + P2TR script (34)
            constexpr int OP_RETURN_BASE_SIZE = 12;   // value (8) + scriptPubKey length (1) + OP_RETURN (1) + push (2)
            constexpr int RECONCILIATION_DATA_SIZE = 40; // marker (4) + epoch (4) + state_root (32)
            constexpr int EPHEMERAL_PUBKEY_SIZE = 33;

            // Calculate sizes
            int header = HEADER_SIZE;
            int inputs_size = num_inputs * INPUT_BASE_SIZE;
            int outputs_size = num_outputs * P2TR_OUTPUT_SIZE;
            if (include_treasury) {
                outputs_size += P2TR_OUTPUT_SIZE;
            }
            int witness_size = num_inputs * P2TR_WITNESS_SIZE;
            int op_return_size = OP_RETURN_BASE_SIZE + RECONCILIATION_DATA_SIZE + (num_outputs * EPHEMERAL_PUBKEY_SIZE);

            // Total base size (non-witness)
            int base_size = header + inputs_size + outputs_size + op_return_size;

            // Calculate weight and vsize
            // Weight = base_size * 4 + witness_size
            int weight = base_size * 4 + witness_size;
            int vsize = (weight + 3) / 4;  // Round up

            // Determine fee rate
            CFeeRate fee_rate;
            if (!request.params[4].isNull()) {
                // User-specified fee rate in sat/vB
                CAmount sat_per_vb = AmountFromValue(request.params[4]);
                fee_rate = CFeeRate(sat_per_vb * 1000);  // Convert to sat/kvB
            } else {
                // Use a reasonable default (10 sat/vB for batch transactions)
                fee_rate = CFeeRate(10000);  // 10 sat/vB = 10000 sat/kvB
            }

            // Calculate fee
            CAmount estimated_fee = fee_rate.GetFee(vsize);
            CAmount fee_per_input = estimated_fee / num_inputs;
            CAmount fee_per_output = estimated_fee / num_outputs;

            UniValue result(UniValue::VOBJ);
            result.pushKV("estimated_vsize", vsize);
            result.pushKV("estimated_weight", weight);
            result.pushKV("fee_rate", ValueFromAmount(fee_rate.GetFeePerK()));
            result.pushKV("fee_rate_sat_vb", ValueFromAmount(fee_rate.GetFeePerK() / 1000));
            result.pushKV("estimated_fee", ValueFromAmount(estimated_fee));
            result.pushKV("fee_per_input", ValueFromAmount(fee_per_input));
            result.pushKV("fee_per_output", ValueFromAmount(fee_per_output));

            UniValue breakdown(UniValue::VOBJ);
            breakdown.pushKV("header", header);
            breakdown.pushKV("inputs", inputs_size);
            breakdown.pushKV("outputs", outputs_size);
            breakdown.pushKV("witness", witness_size);
            breakdown.pushKV("op_return", op_return_size);
            result.pushKV("breakdown", breakdown);

            return result;
        },
    };
}

RPCHelpMan derivereconciliationoutputs()
{
    return RPCHelpMan{
        "derivereconciliationoutputs",
        "Derive reconciliation output addresses from Ghost IDs using Silent Payments.\n"
        "Takes Ghost IDs and derives the actual P2TR addresses with ephemeral keys.\n",
        {
            {"recipients", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of recipient Ghost IDs and amounts",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"ghost_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Recipient Ghost ID (ghost1...)"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount to send"},
                        },
                    },
                },
            },
            {"nonce", RPCArg::Type::NUM, RPCArg::Default{0}, "Nonce for address derivation"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::ARR, "outputs", "Derived outputs for reconciliation transaction",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "ghost_id", "Original Ghost ID"},
                                {RPCResult::Type::STR, "address", "Derived P2TR address"},
                                {RPCResult::Type::STR_AMOUNT, "amount", "Amount"},
                                {RPCResult::Type::STR_HEX, "ephemeral_pubkey", "Ephemeral pubkey for OP_RETURN"},
                                {RPCResult::Type::STR_HEX, "output_pubkey", "Output public key (x-only)"},
                            },
                        },
                    },
                },
                {RPCResult::Type::NUM, "count", "Number of outputs derived"},
                {RPCResult::Type::STR_AMOUNT, "total_amount", "Total amount across all outputs"},
            },
        },
        RPCExamples{
            HelpExampleCli("derivereconciliationoutputs",
                           "'[{\"ghost_id\":\"ghost1...\",\"amount\":0.001}]'") +
            HelpExampleCli("derivereconciliationoutputs",
                           "'[{\"ghost_id\":\"ghost1...\",\"amount\":0.001},{\"ghost_id\":\"ghost1...\",\"amount\":0.002}]' 0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const UniValue& recipients = request.params[0].get_array();
            if (recipients.size() == 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "At least one recipient required");
            }

            uint16_t nonce = 0;
            if (!request.params[1].isNull()) {
                int nonce_val = request.params[1].getInt<int>();
                if (nonce_val < 0 || nonce_val > 65535) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Nonce must be between 0 and 65535");
                }
                nonce = static_cast<uint16_t>(nonce_val);
            }

            UniValue outputs_arr(UniValue::VARR);
            CAmount total_amount = 0;

            for (size_t i = 0; i < recipients.size(); ++i) {
                const UniValue& recipient = recipients[i];
                std::string ghost_id_str = recipient["ghost_id"].get_str();
                CAmount amount = AmountFromValue(recipient["amount"]);

                // Decode Ghost ID
                CTxDestination dest = DecodeDestination(ghost_id_str);
                if (!std::holds_alternative<SilentPaymentDestination>(dest)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                        strprintf("Invalid Ghost ID at index %d: %s", i, ghost_id_str));
                }

                const SilentPaymentDestination& sp_dest = std::get<SilentPaymentDestination>(dest);

                // Create payment (derive address)
                auto payment = silentpayments::CreatePayment(sp_dest, i, nonce);
                if (!payment) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR,
                        strprintf("Failed to derive address for Ghost ID at index %d", i));
                }

                // Convert output pubkey to P2TR address
                // The output_pubkey is the internal key for P2TR
                XOnlyPubKey xonly_pubkey(payment->output_pubkey);
                WitnessV1Taproot tr_dest(xonly_pubkey);
                std::string address = EncodeDestination(tr_dest);

                UniValue output(UniValue::VOBJ);
                output.pushKV("ghost_id", ghost_id_str);
                output.pushKV("address", address);
                output.pushKV("amount", ValueFromAmount(amount));
                output.pushKV("ephemeral_pubkey", HexStr(payment->ephemeral_pubkey));
                // Return full 33-byte compressed pubkey to preserve y-coordinate parity
                // (checksilentpayment needs this for correct scanning)
                output.pushKV("output_pubkey", HexStr(payment->output_pubkey));

                outputs_arr.push_back(output);
                total_amount += amount;
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("outputs", outputs_arr);
            result.pushKV("count", (int64_t)recipients.size());
            result.pushKV("total_amount", ValueFromAmount(total_amount));

            return result;
        },
    };
}

} // namespace wallet
