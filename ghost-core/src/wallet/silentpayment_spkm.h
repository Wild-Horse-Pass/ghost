// Copyright (c) 2024-present The Ghost Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_SILENTPAYMENT_SPKM_H
#define BITCOIN_WALLET_SILENTPAYMENT_SPKM_H

#include <addresstype.h>
#include <key.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <silentpayments.h>
#include <wallet/scriptpubkeyman.h>

#include <map>
#include <optional>

namespace wallet {

/**
 * Stores information about a detected Silent Payment output.
 * This is needed to spend the output later.
 */
struct SilentPaymentOutput {
    Txid txid;              //!< Transaction containing the output
    uint32_t vout;          //!< Output index
    CScript scriptPubKey;   //!< The output script (P2TR)
    CAmount amount;         //!< Output value
    uint256 tweak;          //!< Tweak used for derivation (needed to spend)
    int64_t block_height;   //!< Block height when detected (-1 if unconfirmed)
    int64_t detection_time; //!< Time when detected
};

/**
 * ScriptPubKeyMan for Silent Payment (Ghost ID) addresses.
 *
 * Unlike DescriptorScriptPubKeyMan, this doesn't use descriptors.
 * Instead, it manages:
 * - A scan keypair (for detecting incoming payments via ECDH)
 * - A spend keypair (for creating output addresses and spending)
 *
 * The Ghost ID is derived from these two public keys.
 *
 * Detection of incoming payments requires scanning transactions:
 * 1. Find Ghost Lock OP_RETURN with ephemeral pubkey
 * 2. Compute shared secret: scan_secret * ephemeral_pubkey
 * 3. Derive expected output: spend_pubkey + tweak*G
 * 4. Check if any output matches
 * 5. Store tweak for later spending
 */
class SilentPaymentScriptPubKeyMan : public ScriptPubKeyMan
{
private:
    //! Scan keypair (for detecting payments)
    CKey m_scan_secret GUARDED_BY(cs_sp_man);
    CPubKey m_scan_pubkey GUARDED_BY(cs_sp_man);

    //! Spend keypair (for creating/spending outputs)
    CKey m_spend_secret GUARDED_BY(cs_sp_man);
    CPubKey m_spend_pubkey GUARDED_BY(cs_sp_man);

    //! Encrypted keys (when wallet is locked)
    std::vector<unsigned char> m_crypted_scan_secret GUARDED_BY(cs_sp_man);
    std::vector<unsigned char> m_crypted_spend_secret GUARDED_BY(cs_sp_man);

    //! Whether keys are encrypted
    bool m_encrypted{false};

    //! Map of detected outputs: scriptPubKey -> SilentPaymentOutput
    std::map<CScript, SilentPaymentOutput> m_detected_outputs GUARDED_BY(cs_sp_man);

    //! Creation time of the keys
    int64_t m_creation_time{0};

    //! Decrypt keys using the master key
    bool DecryptKeys(const CKeyingMaterial& master_key) EXCLUSIVE_LOCKS_REQUIRED(cs_sp_man);

public:
    mutable RecursiveMutex cs_sp_man;

    explicit SilentPaymentScriptPubKeyMan(WalletStorage& storage)
        : ScriptPubKeyMan(storage) {}

    //! Initialize with new random keys
    bool SetupKeys(WalletBatch& batch);

    //! Initialize from existing keys (e.g., from seed derivation)
    bool SetupKeys(WalletBatch& batch, const CKey& scan_secret, const CKey& spend_secret);

    //! Load keys from database (called during wallet load)
    bool LoadKeys(const CPubKey& scan_pubkey, const CPubKey& spend_pubkey,
                  const std::vector<unsigned char>& crypted_scan = {},
                  const std::vector<unsigned char>& crypted_spend = {});

    //! Load a detected output from database
    void LoadDetectedOutput(const SilentPaymentOutput& output);

    // ScriptPubKeyMan interface
    util::Result<CTxDestination> GetNewDestination(const OutputType type) override;
    bool IsMine(const CScript& script) const override;
    bool CheckDecryptionKey(const CKeyingMaterial& master_key) override;
    bool Encrypt(const CKeyingMaterial& master_key, WalletBatch* batch) override;
    bool HavePrivateKeys() const override;
    bool HaveCryptedKeys() const override;
    uint256 GetID() const override;
    std::unordered_set<CScript, SaltedSipHasher> GetScriptPubKeys() const override;
    std::unique_ptr<SigningProvider> GetSolvingProvider(const CScript& script) const override;
    bool CanProvide(const CScript& script, SignatureData& sigdata) override;
    int64_t GetTimeFirstKey() const override;

    //! Get the Ghost ID (Silent Payment address)
    SilentPaymentDestination GetSilentPaymentDestination() const;

    //! Get the scan public key
    CPubKey GetScanPubKey() const;

    //! Get the spend public key
    CPubKey GetSpendPubKey() const;

    //! Scan a transaction for Silent Payment outputs belonging to this wallet
    //! Returns the number of outputs detected
    //! @param[in] tx The transaction to scan
    //! @param[in] block_height Block height (-1 for mempool)
    //! @param[out] batch Optional batch for writing to database
    int ScanTransaction(const CTransaction& tx, int64_t block_height, WalletBatch* batch = nullptr);

    //! Get the tweak for a detected output (needed for spending)
    std::optional<uint256> GetOutputTweak(const CScript& scriptPubKey) const;

    //! Derive the spending key for a detected output
    std::optional<CKey> DeriveSpendingKey(const CScript& scriptPubKey) const;

    //! Get all detected outputs
    std::vector<SilentPaymentOutput> GetDetectedOutputs() const;

    //! Check if a specific output is detected
    bool HaveOutput(const CScript& scriptPubKey) const;

    //! Batch scan a block for Silent Payment outputs
    //! More efficient than scanning transactions individually as it:
    //! 1. Pre-filters for Ghost Lock OP_RETURNs
    //! 2. Extracts ephemeral pubkeys once per block
    //! @param[in] block_txs Transactions in the block
    //! @param[in] block_height Block height
    //! @param[out] batch Optional batch for writing to database
    //! @return Number of outputs detected
    int ScanBlockForSilentPayments(const std::vector<CTransactionRef>& block_txs,
                                   int64_t block_height,
                                   WalletBatch* batch = nullptr);

    //! Get statistics about detected outputs
    struct Stats {
        size_t total_outputs{0};
        CAmount total_amount{0};
        int64_t earliest_block{-1};
        int64_t latest_block{-1};
    };
    Stats GetStats() const;
};

} // namespace wallet

#endif // BITCOIN_WALLET_SILENTPAYMENT_SPKM_H
