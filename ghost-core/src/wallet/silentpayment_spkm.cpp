// Copyright (c) 2024-present The Ghost Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <wallet/silentpayment_spkm.h>

#include <cstring>
#include <hash.h>
#include <span.h>
#include <key_io.h>
#include <logging.h>
#include <script/script.h>
#include <silentpayments.h>
#include <util/time.h>
#include <wallet/wallet.h>

namespace wallet {

bool SilentPaymentScriptPubKeyMan::SetupKeys(WalletBatch& batch)
{
    LOCK(cs_sp_man);

    // Generate random scan and spend keys
    CKey scan_secret, spend_secret;
    scan_secret.MakeNewKey(true);
    spend_secret.MakeNewKey(true);

    return SetupKeys(batch, scan_secret, spend_secret);
}

bool SilentPaymentScriptPubKeyMan::SetupKeys(WalletBatch& batch, const CKey& scan_secret, const CKey& spend_secret)
{
    LOCK(cs_sp_man);

    if (!scan_secret.IsValid() || !spend_secret.IsValid()) {
        return false;
    }

    m_scan_secret = scan_secret;
    m_spend_secret = spend_secret;
    m_scan_pubkey = scan_secret.GetPubKey();
    m_spend_pubkey = spend_secret.GetPubKey();
    m_creation_time = GetTime();

    // Write to database
    std::vector<unsigned char> scan_bytes(UCharCast(scan_secret.begin()), UCharCast(scan_secret.end()));
    std::vector<unsigned char> spend_bytes(UCharCast(spend_secret.begin()), UCharCast(spend_secret.end()));

    if (!batch.WriteSilentPaymentKeys(m_scan_pubkey, m_spend_pubkey,
                                       scan_bytes, spend_bytes, m_creation_time)) {
        return false;
    }

    m_storage.UnsetBlankWalletFlag(batch);
    return true;
}

bool SilentPaymentScriptPubKeyMan::LoadKeys(const CPubKey& scan_pubkey, const CPubKey& spend_pubkey,
                                             const std::vector<unsigned char>& crypted_scan,
                                             const std::vector<unsigned char>& crypted_spend)
{
    LOCK(cs_sp_man);

    m_scan_pubkey = scan_pubkey;
    m_spend_pubkey = spend_pubkey;

    if (!crypted_scan.empty() && !crypted_spend.empty()) {
        m_crypted_scan_secret = crypted_scan;
        m_crypted_spend_secret = crypted_spend;
        m_encrypted = true;
    } else if (crypted_scan.size() == 32 && crypted_spend.size() == 32) {
        // Unencrypted keys stored as raw bytes
        m_scan_secret.Set(crypted_scan.begin(), crypted_scan.end(), true);
        m_spend_secret.Set(crypted_spend.begin(), crypted_spend.end(), true);
    }

    return true;
}

void SilentPaymentScriptPubKeyMan::LoadDetectedOutput(const SilentPaymentOutput& output)
{
    LOCK(cs_sp_man);
    m_detected_outputs[output.scriptPubKey] = output;
}

bool SilentPaymentScriptPubKeyMan::DecryptKeys(const CKeyingMaterial& master_key)
{
    AssertLockHeld(cs_sp_man);

    if (!m_encrypted) {
        return true;
    }

    CKeyingMaterial scan_secret_data, spend_secret_data;

    if (!DecryptSecret(master_key, m_crypted_scan_secret, m_scan_pubkey.GetHash(), scan_secret_data)) {
        return false;
    }
    if (!DecryptSecret(master_key, m_crypted_spend_secret, m_spend_pubkey.GetHash(), spend_secret_data)) {
        return false;
    }

    if (scan_secret_data.size() != 32 || spend_secret_data.size() != 32) {
        return false;
    }

    m_scan_secret.Set(scan_secret_data.begin(), scan_secret_data.end(), true);
    m_spend_secret.Set(spend_secret_data.begin(), spend_secret_data.end(), true);

    // Verify keys match pubkeys
    if (m_scan_secret.GetPubKey() != m_scan_pubkey ||
        m_spend_secret.GetPubKey() != m_spend_pubkey) {
        m_scan_secret = CKey();
        m_spend_secret = CKey();
        return false;
    }

    return true;
}

util::Result<CTxDestination> SilentPaymentScriptPubKeyMan::GetNewDestination(const OutputType type)
{
    if (type != OutputType::SILENT_PAYMENT) {
        return util::Error{Untranslated("SilentPaymentScriptPubKeyMan only supports SILENT_PAYMENT output type")};
    }

    LOCK(cs_sp_man);

    if (!m_scan_pubkey.IsValid() || !m_spend_pubkey.IsValid()) {
        return util::Error{Untranslated("Silent Payment keys not initialized")};
    }

    return CTxDestination{GetSilentPaymentDestination()};
}

bool SilentPaymentScriptPubKeyMan::IsMine(const CScript& script) const
{
    LOCK(cs_sp_man);
    return m_detected_outputs.count(script) > 0;
}

bool SilentPaymentScriptPubKeyMan::CheckDecryptionKey(const CKeyingMaterial& master_key)
{
    LOCK(cs_sp_man);
    return DecryptKeys(master_key);
}

bool SilentPaymentScriptPubKeyMan::Encrypt(const CKeyingMaterial& master_key, WalletBatch* batch)
{
    LOCK(cs_sp_man);

    if (m_encrypted) {
        return true;
    }

    if (!m_scan_secret.IsValid() || !m_spend_secret.IsValid()) {
        return false;
    }

    // Encrypt scan secret
    CKeyingMaterial scan_data(32);
    std::memcpy(scan_data.data(), UCharCast(m_scan_secret.begin()), 32);
    if (!EncryptSecret(master_key, scan_data, m_scan_pubkey.GetHash(), m_crypted_scan_secret)) {
        return false;
    }

    // Encrypt spend secret
    CKeyingMaterial spend_data(32);
    std::memcpy(spend_data.data(), UCharCast(m_spend_secret.begin()), 32);
    if (!EncryptSecret(master_key, spend_data, m_spend_pubkey.GetHash(), m_crypted_spend_secret)) {
        return false;
    }

    // Write encrypted keys to database
    if (batch && !batch->WriteSilentPaymentKeys(m_scan_pubkey, m_spend_pubkey,
                                                 m_crypted_scan_secret, m_crypted_spend_secret,
                                                 m_creation_time)) {
        return false;
    }

    m_encrypted = true;

    // Clear unencrypted keys from memory
    m_scan_secret = CKey();
    m_spend_secret = CKey();

    return true;
}

bool SilentPaymentScriptPubKeyMan::HavePrivateKeys() const
{
    LOCK(cs_sp_man);
    return m_scan_secret.IsValid() && m_spend_secret.IsValid();
}

bool SilentPaymentScriptPubKeyMan::HaveCryptedKeys() const
{
    LOCK(cs_sp_man);
    return m_encrypted;
}

uint256 SilentPaymentScriptPubKeyMan::GetID() const
{
    LOCK(cs_sp_man);

    // Create a unique ID from the pubkeys
    HashWriter hasher{};
    hasher << std::string("silentpayment");
    hasher << m_scan_pubkey;
    hasher << m_spend_pubkey;
    return hasher.GetHash();
}

std::unordered_set<CScript, SaltedSipHasher> SilentPaymentScriptPubKeyMan::GetScriptPubKeys() const
{
    LOCK(cs_sp_man);

    std::unordered_set<CScript, SaltedSipHasher> scripts;
    for (const auto& [script, output] : m_detected_outputs) {
        scripts.insert(script);
    }
    return scripts;
}

std::unique_ptr<SigningProvider> SilentPaymentScriptPubKeyMan::GetSolvingProvider(const CScript& script) const
{
    LOCK(cs_sp_man);

    auto it = m_detected_outputs.find(script);
    if (it == m_detected_outputs.end()) {
        return nullptr;
    }

    // Derive the spending key for this output
    auto spending_key = DeriveSpendingKey(script);
    if (!spending_key) {
        return nullptr;
    }

    auto provider = std::make_unique<FlatSigningProvider>();
    provider->keys[spending_key->GetPubKey().GetID()] = *spending_key;
    provider->pubkeys[spending_key->GetPubKey().GetID()] = spending_key->GetPubKey();

    return provider;
}

bool SilentPaymentScriptPubKeyMan::CanProvide(const CScript& script, SignatureData& sigdata)
{
    LOCK(cs_sp_man);
    return m_detected_outputs.count(script) > 0 && HavePrivateKeys();
}

int64_t SilentPaymentScriptPubKeyMan::GetTimeFirstKey() const
{
    LOCK(cs_sp_man);
    return m_creation_time;
}

SilentPaymentDestination SilentPaymentScriptPubKeyMan::GetSilentPaymentDestination() const
{
    LOCK(cs_sp_man);

    std::array<unsigned char, 33> scan_arr, spend_arr;
    std::copy(m_scan_pubkey.begin(), m_scan_pubkey.end(), scan_arr.begin());
    std::copy(m_spend_pubkey.begin(), m_spend_pubkey.end(), spend_arr.begin());

    return SilentPaymentDestination(scan_arr, spend_arr);
}

CPubKey SilentPaymentScriptPubKeyMan::GetScanPubKey() const
{
    LOCK(cs_sp_man);
    return m_scan_pubkey;
}

CPubKey SilentPaymentScriptPubKeyMan::GetSpendPubKey() const
{
    LOCK(cs_sp_man);
    return m_spend_pubkey;
}

int SilentPaymentScriptPubKeyMan::ScanTransaction(const CTransaction& tx, int64_t block_height, WalletBatch* batch)
{
    LOCK(cs_sp_man);

    if (!m_scan_secret.IsValid()) {
        // Wallet is locked, cannot scan
        return 0;
    }

    int detected_count = 0;

    // Find Ghost Lock OP_RETURN
    std::optional<CPubKey> ephemeral_pubkey;
    for (const auto& txout : tx.vout) {
        if (txout.scriptPubKey.IsUnspendable()) {
            // Check for OP_RETURN
            std::vector<unsigned char> data(txout.scriptPubKey.begin() + 1, txout.scriptPubKey.end());
            if (data.size() > 0 && data[0] == OP_PUSHDATA1) {
                data.erase(data.begin(), data.begin() + 2);
            } else if (data.size() > 0 && data[0] <= 75) {
                data.erase(data.begin(), data.begin() + 1);
            }

            ephemeral_pubkey = silentpayments::ParseGhostOpReturn(data);
            if (ephemeral_pubkey) {
                break;
            }
        }
    }

    if (!ephemeral_pubkey) {
        return 0; // No Ghost Lock marker found
    }

    // Scan each P2TR output
    for (uint32_t vout = 0; vout < tx.vout.size(); ++vout) {
        const CTxOut& txout = tx.vout[vout];

        // Check if it's a P2TR output
        if (txout.scriptPubKey.size() != 34 ||
            txout.scriptPubKey[0] != OP_1 ||
            txout.scriptPubKey[1] != 32) {
            continue;
        }

        // Extract x-only pubkey and convert to compressed
        std::vector<unsigned char> xonly(txout.scriptPubKey.begin() + 2, txout.scriptPubKey.end());
        std::vector<unsigned char> compressed(33);
        compressed[0] = 0x02; // Assume even y
        std::copy(xonly.begin(), xonly.end(), compressed.begin() + 1);
        CPubKey output_pubkey(compressed);

        // Try scanning with index = vout, nonce = 0
        auto tweak = silentpayments::ScanOutput(
            m_scan_secret, m_spend_pubkey, *ephemeral_pubkey, output_pubkey, vout, 0);

        if (!tweak) {
            // Try with odd y
            compressed[0] = 0x03;
            output_pubkey = CPubKey(compressed);
            tweak = silentpayments::ScanOutput(
                m_scan_secret, m_spend_pubkey, *ephemeral_pubkey, output_pubkey, vout, 0);
        }

        if (tweak) {
            // This output is ours!
            SilentPaymentOutput sp_output;
            sp_output.txid = tx.GetHash();
            sp_output.vout = vout;
            sp_output.scriptPubKey = txout.scriptPubKey;
            sp_output.amount = txout.nValue;
            sp_output.tweak = *tweak;
            sp_output.block_height = block_height;
            sp_output.detection_time = GetTime();

            m_detected_outputs[txout.scriptPubKey] = sp_output;
            detected_count++;

            // Write to database if batch provided
            if (batch) {
                if (!batch->WriteSilentPaymentOutput(txout.scriptPubKey, tx.GetHash(), vout,
                                                      txout.nValue, *tweak, block_height)) {
                    WalletLogPrintf("Warning: Failed to write Silent Payment output to database: %s:%d\n",
                                   tx.GetHash().ToString(), vout);
                }
            }

            WalletLogPrintf("Detected Silent Payment output: %s:%d amount=%lld\n",
                           tx.GetHash().ToString(), vout, txout.nValue);
        }
    }

    return detected_count;
}

std::optional<uint256> SilentPaymentScriptPubKeyMan::GetOutputTweak(const CScript& scriptPubKey) const
{
    LOCK(cs_sp_man);

    auto it = m_detected_outputs.find(scriptPubKey);
    if (it == m_detected_outputs.end()) {
        return std::nullopt;
    }
    return it->second.tweak;
}

std::optional<CKey> SilentPaymentScriptPubKeyMan::DeriveSpendingKey(const CScript& scriptPubKey) const
{
    LOCK(cs_sp_man);

    if (!m_spend_secret.IsValid()) {
        return std::nullopt; // Wallet is locked
    }

    auto it = m_detected_outputs.find(scriptPubKey);
    if (it == m_detected_outputs.end()) {
        return std::nullopt;
    }

    return silentpayments::DeriveSpendKey(m_spend_secret, it->second.tweak);
}

std::vector<SilentPaymentOutput> SilentPaymentScriptPubKeyMan::GetDetectedOutputs() const
{
    LOCK(cs_sp_man);

    std::vector<SilentPaymentOutput> outputs;
    outputs.reserve(m_detected_outputs.size());
    for (const auto& [script, output] : m_detected_outputs) {
        outputs.push_back(output);
    }
    return outputs;
}

bool SilentPaymentScriptPubKeyMan::HaveOutput(const CScript& scriptPubKey) const
{
    LOCK(cs_sp_man);
    return m_detected_outputs.count(scriptPubKey) > 0;
}

int SilentPaymentScriptPubKeyMan::ScanBlockForSilentPayments(
    const std::vector<CTransactionRef>& block_txs,
    int64_t block_height,
    WalletBatch* batch)
{
    LOCK(cs_sp_man);

    if (!m_scan_secret.IsValid()) {
        // Wallet is locked, cannot scan
        return 0;
    }

    int total_detected = 0;

    // Pre-filter: find all transactions with Ghost Lock OP_RETURNs
    // This is more efficient than scanning every transaction
    struct TxWithEphemeral {
        const CTransaction* tx;
        CPubKey ephemeral_pubkey;
    };
    std::vector<TxWithEphemeral> candidates;

    for (const auto& tx : block_txs) {
        for (const auto& txout : tx->vout) {
            if (txout.scriptPubKey.IsUnspendable()) {
                // Extract OP_RETURN data
                std::vector<unsigned char> data(txout.scriptPubKey.begin() + 1, txout.scriptPubKey.end());
                if (data.size() > 0 && data[0] == OP_PUSHDATA1) {
                    data.erase(data.begin(), data.begin() + 2);
                } else if (data.size() > 0 && data[0] <= 75) {
                    data.erase(data.begin(), data.begin() + 1);
                }

                auto ephemeral = silentpayments::ParseGhostOpReturn(data);
                if (ephemeral) {
                    candidates.push_back({tx.get(), *ephemeral});
                    break; // Only one OP_RETURN per tx matters
                }
            }
        }
    }

    // Now scan only the candidate transactions
    for (const auto& [tx, ephemeral_pubkey] : candidates) {
        for (uint32_t vout = 0; vout < tx->vout.size(); ++vout) {
            const CTxOut& txout = tx->vout[vout];

            // Check if it's a P2TR output
            if (txout.scriptPubKey.size() != 34 ||
                txout.scriptPubKey[0] != OP_1 ||
                txout.scriptPubKey[1] != 32) {
                continue;
            }

            // Skip if already detected
            if (m_detected_outputs.count(txout.scriptPubKey) > 0) {
                continue;
            }

            // Extract x-only pubkey and convert to compressed
            std::vector<unsigned char> xonly(txout.scriptPubKey.begin() + 2, txout.scriptPubKey.end());
            std::vector<unsigned char> compressed(33);
            compressed[0] = 0x02; // Assume even y
            std::copy(xonly.begin(), xonly.end(), compressed.begin() + 1);
            CPubKey output_pubkey(compressed);

            // Try scanning with index = vout, nonce = 0
            auto tweak = silentpayments::ScanOutput(
                m_scan_secret, m_spend_pubkey, ephemeral_pubkey, output_pubkey, vout, 0);

            if (!tweak) {
                // Try with odd y
                compressed[0] = 0x03;
                output_pubkey = CPubKey(compressed);
                tweak = silentpayments::ScanOutput(
                    m_scan_secret, m_spend_pubkey, ephemeral_pubkey, output_pubkey, vout, 0);
            }

            if (tweak) {
                // This output is ours!
                SilentPaymentOutput sp_output;
                sp_output.txid = tx->GetHash();
                sp_output.vout = vout;
                sp_output.scriptPubKey = txout.scriptPubKey;
                sp_output.amount = txout.nValue;
                sp_output.tweak = *tweak;
                sp_output.block_height = block_height;
                sp_output.detection_time = GetTime();

                m_detected_outputs[txout.scriptPubKey] = sp_output;
                total_detected++;

                // Write to database if batch provided
                if (batch) {
                    if (!batch->WriteSilentPaymentOutput(txout.scriptPubKey, tx->GetHash(), vout,
                                                          txout.nValue, *tweak, block_height)) {
                        WalletLogPrintf("Warning: Failed to write Silent Payment output to database: %s:%d\n",
                                       tx->GetHash().ToString(), vout);
                    }
                }

                WalletLogPrintf("Batch detected Silent Payment output: %s:%d amount=%lld height=%lld\n",
                               tx->GetHash().ToString(), vout, txout.nValue, block_height);
            }
        }
    }

    return total_detected;
}

SilentPaymentScriptPubKeyMan::Stats SilentPaymentScriptPubKeyMan::GetStats() const
{
    LOCK(cs_sp_man);

    Stats stats;
    stats.total_outputs = m_detected_outputs.size();

    for (const auto& [script, output] : m_detected_outputs) {
        stats.total_amount += output.amount;

        if (output.block_height >= 0) {
            if (stats.earliest_block < 0 || output.block_height < stats.earliest_block) {
                stats.earliest_block = output.block_height;
            }
            if (output.block_height > stats.latest_block) {
                stats.latest_block = output.block_height;
            }
        }
    }

    return stats;
}

} // namespace wallet
