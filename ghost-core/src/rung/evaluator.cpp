// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/evaluator.h>
#include <rung/conditions.h>
#include <rung/serialize.h>
#include <rung/sighash.h>

#include <crypto/sha256.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/script.h>

#include <algorithm>

namespace rung {

bool LadderSignatureChecker::CheckSchnorrSignature(std::span<const unsigned char> sig,
                                                    std::span<const unsigned char> pubkey_in,
                                                    SigVersion sigversion,
                                                    ScriptExecutionData& /*execdata*/,
                                                    ScriptError* serror) const
{
    if (sigversion != SigVersion::LADDER) {
        // Fall through to the wrapped checker for non-ladder sigversions
        ScriptExecutionData fallback_execdata;
        return m_checker.CheckSchnorrSignature(sig, pubkey_in, sigversion, fallback_execdata, serror);
    }

    // Schnorr signatures are 64 bytes (default hashtype) or 65 bytes (explicit hashtype)
    if (sig.size() != 64 && sig.size() != 65) {
        if (serror) *serror = SCRIPT_ERR_SCHNORR_SIG_SIZE;
        return false;
    }

    if (pubkey_in.size() != 32) {
        if (serror) *serror = SCRIPT_ERR_SCHNORR_SIG;
        return false;
    }

    XOnlyPubKey pubkey{pubkey_in};

    uint8_t hashtype = SIGHASH_DEFAULT;
    // For 65-byte sig, last byte is hashtype (copy sig to strip it)
    std::vector<unsigned char> sig_data(sig.begin(), sig.end());
    if (sig_data.size() == 65) {
        hashtype = sig_data.back();
        sig_data.pop_back();
        if (hashtype == SIGHASH_DEFAULT) {
            if (serror) *serror = SCRIPT_ERR_SCHNORR_SIG_HASHTYPE;
            return false;
        }
    }

    uint256 sighash;
    if (!SignatureHashLadder(m_txdata, m_tx, m_nIn, hashtype, m_conditions, sighash)) {
        if (serror) *serror = SCRIPT_ERR_SCHNORR_SIG_HASHTYPE;
        return false;
    }

    std::span<const unsigned char> sig_span{sig_data.data(), sig_data.size()};
    if (!pubkey.VerifySchnorr(sighash, sig_span)) {
        if (serror) *serror = SCRIPT_ERR_SCHNORR_SIG;
        return false;
    }
    return true;
}

/** Helper: find the first field of a given type in a block. Returns nullptr if not found. */
static const RungField* FindField(const RungBlock& block, RungDataType type)
{
    for (const auto& field : block.fields) {
        if (field.type == type) return &field;
    }
    return nullptr;
}

/** Helper: collect all fields of a given type from a block. */
static std::vector<const RungField*> FindAllFields(const RungBlock& block, RungDataType type)
{
    std::vector<const RungField*> result;
    for (const auto& field : block.fields) {
        if (field.type == type) result.push_back(&field);
    }
    return result;
}

/** Helper: read a 4-byte little-endian numeric value from a NUMERIC field. */
static int64_t ReadNumeric(const RungField& field)
{
    if (field.data.size() != 4) return -1;
    return static_cast<int64_t>(
        static_cast<uint32_t>(field.data[0]) |
        (static_cast<uint32_t>(field.data[1]) << 8) |
        (static_cast<uint32_t>(field.data[2]) << 16) |
        (static_cast<uint32_t>(field.data[3]) << 24));
}

EvalResult ApplyInversion(EvalResult raw, bool inverted)
{
    if (!inverted) return raw;
    switch (raw) {
    case EvalResult::SATISFIED:        return EvalResult::UNSATISFIED;
    case EvalResult::UNSATISFIED:      return EvalResult::SATISFIED;
    case EvalResult::ERROR:            return EvalResult::ERROR; // errors never flip
    case EvalResult::UNKNOWN_BLOCK_TYPE: return EvalResult::SATISFIED; // unknown inverted → satisfied
    }
    return raw;
}

EvalResult EvalSigBlock(const RungBlock& block,
                        const BaseSignatureChecker& checker,
                        SigVersion sigversion,
                        ScriptExecutionData& execdata)
{
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);

    if (!pubkey_field || !sig_field) {
        return EvalResult::ERROR;
    }

    std::span<const unsigned char> sig_span{sig_field->data.data(), sig_field->data.size()};
    std::span<const unsigned char> pubkey_span{pubkey_field->data.data(), pubkey_field->data.size()};

    // Schnorr sigs are 64 bytes (no sighash type byte) or 65 bytes (with sighash type).
    if (sig_field->data.size() >= 64 && sig_field->data.size() <= 65) {
        // For Schnorr, use x-only pubkey (32 bytes). If we have compressed key (33 bytes),
        // strip the prefix.
        std::vector<unsigned char> xonly;
        if (pubkey_field->data.size() == 33) {
            xonly.assign(pubkey_field->data.begin() + 1, pubkey_field->data.end());
            pubkey_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
        }

        if (checker.CheckSchnorrSignature(sig_span, pubkey_span, sigversion, execdata, nullptr)) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    }

    // ECDSA signatures (DER encoded, 71-72 bytes typically)
    if (sig_field->data.size() >= 8 && sig_field->data.size() <= 72) {
        std::vector<unsigned char> sig_vec(sig_field->data.begin(), sig_field->data.end());
        std::vector<unsigned char> pubkey_vec(pubkey_field->data.begin(), pubkey_field->data.end());
        CScript empty_script;
        if (checker.CheckECDSASignature(sig_vec, pubkey_vec, empty_script, sigversion)) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    }

    return EvalResult::ERROR;
}

EvalResult EvalMultisigBlock(const RungBlock& block,
                             const BaseSignatureChecker& checker,
                             SigVersion sigversion,
                             ScriptExecutionData& execdata)
{
    // Expected field layout: NUMERIC (threshold M), N x PUBKEY, M x SIGNATURE
    const RungField* threshold_field = FindField(block, RungDataType::NUMERIC);
    if (!threshold_field || threshold_field->data.size() < 4) {
        return EvalResult::ERROR;
    }

    uint32_t threshold = static_cast<uint32_t>(threshold_field->data[0]) |
                         (static_cast<uint32_t>(threshold_field->data[1]) << 8) |
                         (static_cast<uint32_t>(threshold_field->data[2]) << 16) |
                         (static_cast<uint32_t>(threshold_field->data[3]) << 24);

    auto pubkeys = FindAllFields(block, RungDataType::PUBKEY);
    auto sigs = FindAllFields(block, RungDataType::SIGNATURE);

    if (pubkeys.empty() || threshold == 0 || threshold > pubkeys.size()) {
        return EvalResult::ERROR;
    }
    if (sigs.size() < threshold) {
        return EvalResult::UNSATISFIED;
    }

    // Verify signatures: each signature must match a distinct pubkey.
    std::vector<bool> pubkey_used(pubkeys.size(), false);
    uint32_t valid_count = 0;

    for (const auto* sig_field : sigs) {
        for (size_t k = 0; k < pubkeys.size(); ++k) {
            if (pubkey_used[k]) continue;

            const auto* pk = pubkeys[k];
            std::span<const unsigned char> sig_span{sig_field->data.data(), sig_field->data.size()};

            bool verified = false;
            if (sig_field->data.size() >= 64 && sig_field->data.size() <= 65) {
                // Schnorr
                std::vector<unsigned char> xonly;
                std::span<const unsigned char> pk_span{pk->data.data(), pk->data.size()};
                if (pk->data.size() == 33) {
                    xonly.assign(pk->data.begin() + 1, pk->data.end());
                    pk_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
                }
                verified = checker.CheckSchnorrSignature(sig_span, pk_span, sigversion, execdata, nullptr);
            } else if (sig_field->data.size() >= 8 && sig_field->data.size() <= 72) {
                // ECDSA
                std::vector<unsigned char> sig_vec(sig_field->data.begin(), sig_field->data.end());
                std::vector<unsigned char> pk_vec(pk->data.begin(), pk->data.end());
                CScript empty_script;
                verified = checker.CheckECDSASignature(sig_vec, pk_vec, empty_script, sigversion);
            }

            if (verified) {
                pubkey_used[k] = true;
                valid_count++;
                break;
            }
        }
    }

    return (valid_count >= threshold) ? EvalResult::SATISFIED : EvalResult::UNSATISFIED;
}

EvalResult EvalHashPreimageBlock(const RungBlock& block)
{
    const RungField* preimage_field = FindField(block, RungDataType::PREIMAGE);
    if (!preimage_field) {
        return EvalResult::ERROR;
    }

    const RungField* hash256_field = FindField(block, RungDataType::HASH256);
    if (hash256_field) {
        unsigned char computed[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(preimage_field->data.data(), preimage_field->data.size()).Finalize(computed);
        if (hash256_field->data.size() == 32 &&
            memcmp(computed, hash256_field->data.data(), 32) == 0) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    }

    return EvalResult::ERROR;
}

EvalResult EvalHash160PreimageBlock(const RungBlock& block)
{
    const RungField* preimage_field = FindField(block, RungDataType::PREIMAGE);
    if (!preimage_field) {
        return EvalResult::ERROR;
    }

    const RungField* hash160_field = FindField(block, RungDataType::HASH160);
    if (hash160_field) {
        unsigned char computed[CHash160::OUTPUT_SIZE];
        CHash160().Write(preimage_field->data).Finalize(computed);
        if (hash160_field->data.size() == 20 &&
            memcmp(computed, hash160_field->data.data(), 20) == 0) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    }

    return EvalResult::ERROR;
}

EvalResult EvalCSVBlock(const RungBlock& block,
                        const BaseSignatureChecker& checker)
{
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);
    if (!numeric_field) {
        return EvalResult::ERROR;
    }

    int64_t sequence_val = ReadNumeric(*numeric_field);
    if (sequence_val < 0) {
        return EvalResult::ERROR;
    }

    CScriptNum nSequence(sequence_val);

    // If the disable flag is set, sequence lock is satisfied unconditionally
    if ((sequence_val & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) {
        return EvalResult::SATISFIED;
    }

    if (!checker.CheckSequence(nSequence)) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalCSVTimeBlock(const RungBlock& block,
                            const BaseSignatureChecker& checker)
{
    // CSV_TIME uses median-time-past semantics — same CheckSequence call,
    // but the NUMERIC value should have the TYPE_FLAG set (bit 22).
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);
    if (!numeric_field) {
        return EvalResult::ERROR;
    }

    int64_t sequence_val = ReadNumeric(*numeric_field);
    if (sequence_val < 0) {
        return EvalResult::ERROR;
    }

    CScriptNum nSequence(sequence_val);

    if ((sequence_val & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) {
        return EvalResult::SATISFIED;
    }

    if (!checker.CheckSequence(nSequence)) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalCLTVBlock(const RungBlock& block,
                         const BaseSignatureChecker& checker)
{
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);
    if (!numeric_field) {
        return EvalResult::ERROR;
    }

    int64_t locktime_val = ReadNumeric(*numeric_field);
    if (locktime_val < 0) {
        return EvalResult::ERROR;
    }

    CScriptNum nLockTime(locktime_val);

    if (!checker.CheckLockTime(nLockTime)) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalCLTVTimeBlock(const RungBlock& block,
                             const BaseSignatureChecker& checker)
{
    // CLTV_TIME uses median-time-past semantics — same CheckLockTime call,
    // but the NUMERIC value should be >= 500000000 (time-based locktime).
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);
    if (!numeric_field) {
        return EvalResult::ERROR;
    }

    int64_t locktime_val = ReadNumeric(*numeric_field);
    if (locktime_val < 0) {
        return EvalResult::ERROR;
    }

    CScriptNum nLockTime(locktime_val);

    if (!checker.CheckLockTime(nLockTime)) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalBlock(const RungBlock& block,
                     const BaseSignatureChecker& checker,
                     SigVersion sigversion,
                     ScriptExecutionData& execdata)
{
    EvalResult raw;
    switch (block.type) {
    case RungBlockType::SIG:
        raw = EvalSigBlock(block, checker, sigversion, execdata);
        break;
    case RungBlockType::MULTISIG:
        raw = EvalMultisigBlock(block, checker, sigversion, execdata);
        break;
    case RungBlockType::HASH_PREIMAGE:
        raw = EvalHashPreimageBlock(block);
        break;
    case RungBlockType::HASH160_PREIMAGE:
        raw = EvalHash160PreimageBlock(block);
        break;
    case RungBlockType::CSV:
        raw = EvalCSVBlock(block, checker);
        break;
    case RungBlockType::CSV_TIME:
        raw = EvalCSVTimeBlock(block, checker);
        break;
    case RungBlockType::CLTV:
        raw = EvalCLTVBlock(block, checker);
        break;
    case RungBlockType::CLTV_TIME:
        raw = EvalCLTVTimeBlock(block, checker);
        break;
    // Phase 2/3 stubs — return UNSATISFIED (consensus-valid but never satisfied)
    case RungBlockType::ADAPTOR_SIG:
    case RungBlockType::TAGGED_HASH:
    case RungBlockType::CTV:
    case RungBlockType::VAULT_LOCK:
    case RungBlockType::RECURSE_UNTIL:
    case RungBlockType::RECURSE_SPLIT:
    case RungBlockType::RECURSE_DECAY:
    case RungBlockType::RECURSE_COLLECT:
    case RungBlockType::RECURSE_MERGE:
    case RungBlockType::RECURSE_SWEEP:
    case RungBlockType::ANCHOR_CHANNEL:
    case RungBlockType::ANCHOR_POOL:
    case RungBlockType::ANCHOR_SEAL:
    case RungBlockType::ANCHOR_ORACLE:
    case RungBlockType::ANCHOR_BOND:
    case RungBlockType::ANCHOR_ESCROW:
        raw = EvalResult::UNSATISFIED;
        break;
    default:
        raw = EvalResult::UNKNOWN_BLOCK_TYPE;
        break;
    }
    return ApplyInversion(raw, block.inverted);
}

EvalResult EvalRung(const Rung& rung,
                    const BaseSignatureChecker& checker,
                    SigVersion sigversion,
                    ScriptExecutionData& execdata)
{
    if (rung.blocks.empty()) {
        return EvalResult::ERROR;
    }

    for (const auto& block : rung.blocks) {
        EvalResult result = EvalBlock(block, checker, sigversion, execdata);
        if (result != EvalResult::SATISFIED) {
            return result;
        }
    }
    return EvalResult::SATISFIED;
}

bool EvalLadder(const LadderWitness& ladder,
                const BaseSignatureChecker& checker,
                SigVersion sigversion,
                ScriptExecutionData& execdata)
{
    if (ladder.IsEmpty()) {
        return false;
    }

    // First satisfied rung wins (OR logic across rungs)
    for (const auto& rung : ladder.rungs) {
        EvalResult result = EvalRung(rung, checker, sigversion, execdata);
        if (result == EvalResult::SATISFIED) {
            return true;
        }
    }
    return false;
}

/** Merge conditions (from spent output) with witness (from input).
 *  For each rung/block, the conditions provide the "locks" (pubkeys, hashes, timelocks)
 *  and the witness provides the "keys" (signatures, preimages). The merged result
 *  has all fields from both, which EvalLadder can then evaluate.
 *
 *  The witness must have the same rung/block structure as the conditions.
 *  The inverted flag is taken from conditions (witness doesn't override). */
static bool MergeConditionsAndWitness(const RungConditions& conditions,
                                       const LadderWitness& witness,
                                       LadderWitness& merged,
                                       std::string& error)
{
    if (conditions.rungs.size() != witness.rungs.size()) {
        error = "rung count mismatch: conditions=" + std::to_string(conditions.rungs.size()) +
                " witness=" + std::to_string(witness.rungs.size());
        return false;
    }

    merged.rungs.resize(conditions.rungs.size());
    for (size_t r = 0; r < conditions.rungs.size(); ++r) {
        const auto& cond_rung = conditions.rungs[r];
        const auto& wit_rung = witness.rungs[r];

        if (cond_rung.blocks.size() != wit_rung.blocks.size()) {
            error = "block count mismatch in rung " + std::to_string(r);
            return false;
        }

        merged.rungs[r].blocks.resize(cond_rung.blocks.size());
        merged.rungs[r].coil = cond_rung.coil;
        merged.rungs[r].rung_id = cond_rung.rung_id;

        for (size_t b = 0; b < cond_rung.blocks.size(); ++b) {
            const auto& cond_block = cond_rung.blocks[b];
            const auto& wit_block = wit_rung.blocks[b];

            if (cond_block.type != wit_block.type) {
                error = "block type mismatch in rung " + std::to_string(r) +
                        " block " + std::to_string(b);
                return false;
            }

            // Merge: all condition fields first, then all witness fields
            auto& merged_block = merged.rungs[r].blocks[b];
            merged_block.type = cond_block.type;
            merged_block.inverted = cond_block.inverted; // inverted comes from conditions
            merged_block.fields.insert(merged_block.fields.end(),
                                       cond_block.fields.begin(), cond_block.fields.end());
            merged_block.fields.insert(merged_block.fields.end(),
                                       wit_block.fields.begin(), wit_block.fields.end());
        }
    }
    return true;
}

bool VerifyRungTx(const CTransaction& tx,
                  unsigned int nIn,
                  const CTxOut& spent_output,
                  unsigned int /*flags*/,
                  const BaseSignatureChecker& checker,
                  const PrecomputedTransactionData& txdata,
                  ScriptError* serror)
{
    if (nIn >= tx.vin.size()) {
        if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
        return false;
    }

    const auto& witness = tx.vin[nIn].scriptWitness;
    if (witness.stack.empty()) {
        if (serror) *serror = SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY;
        return false;
    }

    // The ladder witness is the first element of the witness stack
    const auto& witness_bytes = witness.stack[0];

    LadderWitness witness_ladder;
    std::string deser_error;
    if (!DeserializeLadderWitness(witness_bytes, witness_ladder, deser_error)) {
        if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
        return false;
    }

    // Try to deserialize spent output scriptPubKey as rung conditions
    RungConditions conditions;
    std::string cond_error;
    bool has_conditions = DeserializeRungConditions(spent_output.scriptPubKey, conditions, cond_error);

    LadderWitness eval_ladder;
    ScriptExecutionData execdata;

    if (has_conditions) {
        // Rung-to-rung spend: merge conditions with witness
        std::string merge_error;
        if (!MergeConditionsAndWitness(conditions, witness_ladder, eval_ladder, merge_error)) {
            if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
            return false;
        }

        // Use LadderSignatureChecker with conditions context for proper sighash
        LadderSignatureChecker ladder_checker(checker, conditions, txdata, tx, nIn);
        if (!EvalLadder(eval_ladder, ladder_checker, SigVersion::LADDER, execdata)) {
            if (serror) *serror = SCRIPT_ERR_EVAL_FALSE;
            return false;
        }
    } else {
        // Bootstrap spend: v3 tx spending a v1/v2 UTXO
        RungConditions empty_conditions;
        LadderSignatureChecker ladder_checker(checker, empty_conditions, txdata, tx, nIn);
        if (!EvalLadder(witness_ladder, ladder_checker, SigVersion::LADDER, execdata)) {
            if (serror) *serror = SCRIPT_ERR_EVAL_FALSE;
            return false;
        }
    }

    return true;
}

} // namespace rung
