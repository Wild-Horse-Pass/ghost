// Copyright (c) 2024-present The Ghost Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <hash.h>
#include <key_io.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <silentpayments.h>
#include <univalue.h>
#include <wallet/rpc/util.h>
#include <wallet/silentpayment_spkm.h>
#include <wallet/wallet.h>

namespace wallet {

RPCHelpMan getsilentpaymentaddress()
{
    return RPCHelpMan{
        "getsilentpaymentaddress",
        "Returns the wallet's Silent Payment address (Ghost ID).\n"
        "This is a static address that can be shared publicly. Senders derive unique\n"
        "one-time addresses from it, providing receiver privacy.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "address", "The Ghost ID (ghost1...) address"},
                {RPCResult::Type::STR, "ghost_id", "Alias for address - the Ghost ID"},
                {RPCResult::Type::STR_HEX, "scan_pubkey", "The scan public key (33 bytes, compressed)"},
                {RPCResult::Type::STR_HEX, "spend_pubkey", "The spend public key (33 bytes, compressed)"},
            }
        },
        RPCExamples{
            HelpExampleCli("getsilentpaymentaddress", "")
            + HelpExampleRpc("getsilentpaymentaddress", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            EnsureWalletIsUnlocked(*pwallet);

            LOCK(pwallet->cs_wallet);

            // Get the wallet's HD keys
            std::set<CExtPubKey> active_xpubs = pwallet->GetActiveHDPubKeys();
            if (active_xpubs.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Wallet has no HD keys. Silent Payment requires HD wallet.");
            }

            // Use first active xpub
            const CExtPubKey& xpub = *active_xpubs.begin();
            CPubKey spend_pubkey = xpub.pubkey;

            // Get the spend private key to derive scan key
            std::optional<CKey> spend_key = pwallet->GetKey(spend_pubkey.GetID());
            if (!spend_key) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is missing private key for Silent Payment");
            }

            // Derive scan key by tweaking spend key
            // In production, these would be stored separately in a SilentPaymentScriptPubKeyMan
            uint256 scan_tweak = Hash(spend_pubkey);

            // Derive scan pubkey = spend_pubkey + scan_tweak*G
            auto scan_pubkey = silentpayments::DeriveOutputPubKey(spend_pubkey, scan_tweak);
            if (!scan_pubkey) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to derive scan public key");
            }

            // Create the Silent Payment destination
            std::array<unsigned char, 33> scan_arr, spend_arr;
            std::copy(scan_pubkey->begin(), scan_pubkey->end(), scan_arr.begin());
            std::copy(spend_pubkey.begin(), spend_pubkey.end(), spend_arr.begin());
            SilentPaymentDestination sp_dest(scan_arr, spend_arr);

            // Encode as ghost1... address
            std::string address = EncodeDestination(sp_dest);

            UniValue result(UniValue::VOBJ);
            result.pushKV("address", address);
            result.pushKV("ghost_id", address);  // Alias for convenience
            result.pushKV("scan_pubkey", HexStr(*scan_pubkey));
            result.pushKV("spend_pubkey", HexStr(spend_pubkey));

            return result;
        }
    };
}

RPCHelpMan derivesilentpaymentaddress()
{
    return RPCHelpMan{
        "derivesilentpaymentaddress",
        "Derives a one-time output address from a Ghost ID.\n"
        "This is used by senders to create payments to Silent Payment recipients.\n"
        "The ephemeral public key must be included in the transaction's OP_RETURN.\n",
        {
            {"ghost_id", RPCArg::Type::STR, RPCArg::Optional::NO, "The recipient's Ghost ID (ghost1...)"},
            {"index", RPCArg::Type::NUM, RPCArg::Default{0}, "Output index for derivation"},
            {"nonce", RPCArg::Type::NUM, RPCArg::Default{0}, "Nonce for additional unlinkability"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "address", "The derived P2TR address for the output"},
                {RPCResult::Type::STR_HEX, "output_pubkey", "The derived output public key (33 bytes)"},
                {RPCResult::Type::STR_HEX, "ephemeral_pubkey", "The ephemeral public key to include in OP_RETURN (33 bytes)"},
                {RPCResult::Type::STR_HEX, "tweak", "The tweak used for derivation (32 bytes)"},
                {RPCResult::Type::STR_HEX, "opreturn_data", "The complete OP_RETURN data to include in transaction"},
                {RPCResult::Type::NUM, "index", "The output index used for derivation"},
                {RPCResult::Type::NUM, "nonce", "The nonce used for derivation"},
            }
        },
        RPCExamples{
            HelpExampleCli("derivesilentpaymentaddress", "\"ghost1qv4nzdedq5t7x36h6r2f...\"")
            + HelpExampleRpc("derivesilentpaymentaddress", "\"ghost1qv4nzdedq5t7x36h6r2f...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string ghost_id_str = request.params[0].get_str();
            uint32_t index = request.params[1].isNull() ? 0 : request.params[1].getInt<uint32_t>();
            uint16_t nonce = request.params[2].isNull() ? 0 : request.params[2].getInt<uint16_t>();

            // Decode the Ghost ID
            CTxDestination dest = DecodeDestination(ghost_id_str);
            if (!std::holds_alternative<SilentPaymentDestination>(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Ghost ID address");
            }
            const SilentPaymentDestination& sp_dest = std::get<SilentPaymentDestination>(dest);

            // Create the payment derivation
            auto payment = silentpayments::CreatePayment(sp_dest, index, nonce);
            if (!payment) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to derive payment address");
            }

            // Create the OP_RETURN data
            std::vector<unsigned char> opreturn_data = silentpayments::CreateGhostOpReturn(payment->ephemeral_pubkey);

            // Create the P2TR output address
            WitnessV1Taproot taproot_dest{XOnlyPubKey(payment->output_pubkey)};
            std::string output_address = EncodeDestination(taproot_dest);

            UniValue result(UniValue::VOBJ);
            result.pushKV("address", output_address);
            result.pushKV("output_pubkey", HexStr(payment->output_pubkey));
            result.pushKV("ephemeral_pubkey", HexStr(payment->ephemeral_pubkey));
            result.pushKV("tweak", payment->tweak.GetHex());
            result.pushKV("opreturn_data", HexStr(opreturn_data));
            result.pushKV("index", (int64_t)index);
            result.pushKV("nonce", (int64_t)nonce);

            return result;
        }
    };
}

RPCHelpMan checksilentpayment()
{
    return RPCHelpMan{
        "checksilentpayment",
        "Checks if a transaction output belongs to this wallet's Silent Payment address.\n"
        "Requires the ephemeral public key from the transaction's OP_RETURN.\n",
        {
            {"ephemeral_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The ephemeral public key from OP_RETURN (33 bytes hex)"},
            {"output_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The output public key from the P2TR output (32 or 33 bytes hex)"},
            {"index", RPCArg::Type::NUM, RPCArg::Default{0}, "Output index to check"},
            {"nonce", RPCArg::Type::NUM, RPCArg::Default{0}, "Nonce to check"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "is_mine", "Whether this output belongs to this wallet"},
                {RPCResult::Type::BOOL, "ismine", "Whether this output belongs to this wallet (deprecated, use is_mine)"},
                {RPCResult::Type::STR_HEX, "tweak", /*optional=*/true, "The tweak (if is_mine is true) - needed to spend"},
            }
        },
        RPCExamples{
            HelpExampleCli("checksilentpayment", "\"02abcd...\" \"03ef01...\"")
            + HelpExampleRpc("checksilentpayment", "\"02abcd...\", \"03ef01...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            EnsureWalletIsUnlocked(*pwallet);

            LOCK(pwallet->cs_wallet);

            std::vector<unsigned char> ephemeral_bytes = ParseHex(request.params[0].get_str());
            std::vector<unsigned char> output_bytes = ParseHex(request.params[1].get_str());
            uint32_t index = request.params[2].isNull() ? 0 : request.params[2].getInt<uint32_t>();
            uint16_t nonce = request.params[3].isNull() ? 0 : request.params[3].getInt<uint16_t>();

            CPubKey ephemeral_pubkey(ephemeral_bytes);
            if (!ephemeral_pubkey.IsValid()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid ephemeral public key");
            }

            // Handle both 32-byte x-only and 33-byte compressed pubkeys
            CPubKey output_pubkey;
            if (output_bytes.size() == 32) {
                // X-only pubkey, add 0x02 prefix (even y)
                std::vector<unsigned char> compressed(33);
                compressed[0] = 0x02;
                std::copy(output_bytes.begin(), output_bytes.end(), compressed.begin() + 1);
                output_pubkey = CPubKey(compressed);
            } else {
                output_pubkey = CPubKey(output_bytes);
            }

            if (!output_pubkey.IsValid()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid output public key");
            }

            // Get wallet's SP keys
            std::set<CExtPubKey> active_xpubs = pwallet->GetActiveHDPubKeys();
            if (active_xpubs.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Wallet has no HD keys");
            }

            const CExtPubKey& xpub = *active_xpubs.begin();
            CPubKey spend_pubkey = xpub.pubkey;

            // Get the private key for scan key derivation
            std::optional<CKey> spend_key = pwallet->GetKey(spend_pubkey.GetID());
            if (!spend_key) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is missing private key for Silent Payment");
            }

            // Derive scan secret key
            uint256 scan_tweak = Hash(spend_pubkey);
            auto scan_secret = silentpayments::DeriveSpendKey(*spend_key, scan_tweak);
            if (!scan_secret) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to derive scan secret key");
            }

            // Scan the output
            auto tweak = silentpayments::ScanOutput(
                *scan_secret, spend_pubkey, ephemeral_pubkey, output_pubkey, index, nonce);

            UniValue result(UniValue::VOBJ);
            if (tweak) {
                result.pushKV("is_mine", true);
                result.pushKV("ismine", true);  // Keep for backwards compatibility
                result.pushKV("tweak", tweak->GetHex());
            } else {
                result.pushKV("is_mine", false);
                result.pushKV("ismine", false);  // Keep for backwards compatibility
            }

            return result;
        }
    };
}

RPCHelpMan parseghostopreturn()
{
    return RPCHelpMan{
        "parseghostopreturn",
        "Parses Ghost Lock OP_RETURN data from a transaction.\n",
        {
            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The OP_RETURN data (hex)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "valid", "Whether this is a valid Ghost Lock OP_RETURN"},
                {RPCResult::Type::BOOL, "isghost", "Whether this is a valid Ghost Lock OP_RETURN (deprecated, use valid)"},
                {RPCResult::Type::STR_HEX, "ephemeral_pubkey", /*optional=*/true, "The ephemeral public key (if valid)"},
                {RPCResult::Type::STR_HEX, "extra_data", /*optional=*/true, "Any extra data after the ephemeral pubkey"},
            }
        },
        RPCExamples{
            HelpExampleCli("parseghostopreturn", "\"47484f5302abcd...\"")
            + HelpExampleRpc("parseghostopreturn", "\"47484f5302abcd...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::vector<unsigned char> data = ParseHex(request.params[0].get_str());

            UniValue result(UniValue::VOBJ);

            if (!silentpayments::IsGhostOpReturn(data)) {
                result.pushKV("valid", false);
                result.pushKV("isghost", false);  // Keep for backwards compatibility
                return result;
            }

            auto ephemeral = silentpayments::ParseGhostOpReturn(data);
            if (!ephemeral) {
                result.pushKV("valid", false);
                result.pushKV("isghost", false);  // Keep for backwards compatibility
                return result;
            }

            result.pushKV("valid", true);
            result.pushKV("isghost", true);  // Keep for backwards compatibility
            result.pushKV("ephemeral_pubkey", HexStr(*ephemeral));

            // Check for extra data
            size_t expected_size = 4 + 33; // marker + pubkey
            if (data.size() > expected_size) {
                std::vector<unsigned char> extra(data.begin() + expected_size, data.end());
                result.pushKV("extra_data", HexStr(extra));
            }

            return result;
        }
    };
}

RPCHelpMan rescansilentpayments()
{
    return RPCHelpMan{
        "rescansilentpayments",
        "Rescan the blockchain for Silent Payment (Ghost Lock) outputs.\n"
        "This is more efficient than a full rescan as it only scans for Ghost Lock OP_RETURNs.\n"
        "Use \"getwalletinfo\" to query scanning progress, or \"abortrescan\" to abort.\n",
        {
            {"start_height", RPCArg::Type::NUM, RPCArg::Default{0}, "Block height to start scanning from"},
            {"stop_height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Block height to stop scanning at (default: chain tip)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "start_height", "The height where the scan started"},
                {RPCResult::Type::NUM, "stop_height", "The height where the scan stopped"},
                {RPCResult::Type::NUM, "blocks_scanned", "Number of blocks scanned"},
                {RPCResult::Type::NUM, "outputs_found", "Number of Silent Payment outputs detected"},
                {RPCResult::Type::STR_AMOUNT, "total_amount", "Total amount in detected outputs"},
            }
        },
        RPCExamples{
            HelpExampleCli("rescansilentpayments", "")
            + HelpExampleCli("rescansilentpayments", "100000")
            + HelpExampleCli("rescansilentpayments", "100000 200000")
            + HelpExampleRpc("rescansilentpayments", "100000, 200000")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;
            CWallet& wallet{*pwallet};

            // Sync with chain first
            wallet.BlockUntilSyncedToCurrentChain();

            WalletRescanReserver reserver(*pwallet);
            if (!reserver.reserve(/*with_passphrase=*/true)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
            }

            LOCK(pwallet->m_relock_mutex);
            {
                LOCK(pwallet->cs_wallet);
                EnsureWalletIsUnlocked(*pwallet);
            }

            int start_height = 0;
            std::optional<int> stop_height;

            {
                LOCK(pwallet->cs_wallet);
                int tip_height = pwallet->GetLastBlockHeight();

                if (!request.params[0].isNull()) {
                    start_height = request.params[0].getInt<int>();
                    if (start_height < 0 || start_height > tip_height) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid start_height");
                    }
                }

                if (!request.params[1].isNull()) {
                    stop_height = request.params[1].getInt<int>();
                    if (*stop_height < start_height) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "stop_height must be >= start_height");
                    }
                    if (*stop_height > tip_height) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "stop_height cannot exceed current tip");
                    }
                }
            }

            // Get stats before scan
            SilentPaymentScriptPubKeyMan* sp_spkm = wallet.GetSilentPaymentScriptPubKeyMan();
            size_t outputs_before = 0;
            if (sp_spkm) {
                outputs_before = sp_spkm->GetStats().total_outputs;
            }

            // Perform the rescan
            CWallet::ScanResult result = wallet.RescanForSilentPayments(start_height, stop_height, reserver);

            switch (result.status) {
            case CWallet::ScanResult::SUCCESS:
                break;
            case CWallet::ScanResult::FAILURE:
                throw JSONRPCError(RPC_MISC_ERROR, "Silent Payment rescan failed.");
            case CWallet::ScanResult::USER_ABORT:
                throw JSONRPCError(RPC_MISC_ERROR, "Silent Payment rescan aborted.");
            }

            // Get stats after scan
            size_t outputs_after = 0;
            CAmount total_amount = 0;
            if (sp_spkm) {
                auto stats = sp_spkm->GetStats();
                outputs_after = stats.total_outputs;
                total_amount = stats.total_amount;
            }

            int actual_stop_height = result.last_scanned_height ? *result.last_scanned_height : start_height;
            int blocks_scanned = actual_stop_height - start_height + 1;
            if (blocks_scanned < 0) blocks_scanned = 0;

            UniValue response(UniValue::VOBJ);
            response.pushKV("start_height", start_height);
            response.pushKV("stop_height", result.last_scanned_height ? *result.last_scanned_height : UniValue());
            response.pushKV("blocks_scanned", blocks_scanned);
            response.pushKV("outputs_found", static_cast<int64_t>(outputs_after - outputs_before));
            response.pushKV("total_amount", ValueFromAmount(total_amount));

            return response;
        }
    };
}

RPCHelpMan getsilentpaymentstats()
{
    return RPCHelpMan{
        "getsilentpaymentstats",
        "Returns statistics about detected Silent Payment outputs.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "ghost_id", "The wallet's Ghost ID (Silent Payment address)"},
                {RPCResult::Type::NUM, "total_outputs", "Total number of detected outputs"},
                {RPCResult::Type::STR_AMOUNT, "total_amount", "Total amount across all outputs"},
                {RPCResult::Type::NUM, "earliest_block", "Earliest block containing a detected output"},
                {RPCResult::Type::NUM, "latest_block", "Latest block containing a detected output"},
            }
        },
        RPCExamples{
            HelpExampleCli("getsilentpaymentstats", "")
            + HelpExampleRpc("getsilentpaymentstats", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);

            SilentPaymentScriptPubKeyMan* sp_spkm = pwallet->GetSilentPaymentScriptPubKeyMan();
            if (!sp_spkm) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not have Silent Payment support");
            }

            auto stats = sp_spkm->GetStats();
            SilentPaymentDestination dest = sp_spkm->GetSilentPaymentDestination();

            UniValue result(UniValue::VOBJ);
            result.pushKV("ghost_id", EncodeDestination(dest));
            result.pushKV("total_outputs", static_cast<int64_t>(stats.total_outputs));
            result.pushKV("total_amount", ValueFromAmount(stats.total_amount));
            result.pushKV("earliest_block", stats.earliest_block);
            result.pushKV("latest_block", stats.latest_block);

            return result;
        }
    };
}

} // namespace wallet
