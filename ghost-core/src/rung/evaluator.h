// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_EVALUATOR_H
#define BITCOIN_RUNG_EVALUATOR_H

#include <rung/conditions.h>
#include <rung/types.h>
#include <script/interpreter.h>
#include <script/script_error.h>

#include <cstdint>
#include <string>

namespace rung {

/** Signature checker that wraps an existing checker and adds rung conditions context.
 *  When CheckSchnorrSignature is called with SigVersion::LADDER, it computes
 *  SignatureHashLadder instead of SignatureHashSchnorr. */
class LadderSignatureChecker : public DeferringSignatureChecker
{
private:
    const RungConditions& m_conditions;
    const PrecomputedTransactionData& m_txdata;
    const CTransaction& m_tx;
    unsigned int m_nIn;

public:
    LadderSignatureChecker(const BaseSignatureChecker& checker,
                           const RungConditions& conditions,
                           const PrecomputedTransactionData& txdata,
                           const CTransaction& tx,
                           unsigned int nIn)
        : DeferringSignatureChecker(checker),
          m_conditions(conditions),
          m_txdata(txdata),
          m_tx(tx),
          m_nIn(nIn) {}

    bool CheckSchnorrSignature(std::span<const unsigned char> sig,
                               std::span<const unsigned char> pubkey,
                               SigVersion sigversion,
                               ScriptExecutionData& execdata,
                               ScriptError* serror = nullptr) const override;
};

/** Result of evaluating a single block or rung. */
enum class EvalResult {
    SATISFIED,           //!< All conditions met
    UNSATISFIED,         //!< Conditions not met (valid but fails)
    ERROR,               //!< Malformed block (consensus failure)
    UNKNOWN_BLOCK_TYPE,  //!< Unknown block type (treated as unsatisfied for forward compat)
};

/** Apply inversion to an eval result.
 *  SATISFIED↔UNSATISFIED, ERROR unchanged, UNKNOWN_BLOCK_TYPE inverted → SATISFIED. */
EvalResult ApplyInversion(EvalResult raw, bool inverted);

/** Evaluate a SIG block: expects PUBKEY + SIGNATURE fields. */
EvalResult EvalSigBlock(const RungBlock& block,
                        const BaseSignatureChecker& checker,
                        SigVersion sigversion,
                        ScriptExecutionData& execdata);

/** Evaluate a MULTISIG block: M-of-N threshold signature verification. */
EvalResult EvalMultisigBlock(const RungBlock& block,
                             const BaseSignatureChecker& checker,
                             SigVersion sigversion,
                             ScriptExecutionData& execdata);

/** Evaluate a HASH_PREIMAGE block: SHA-256 hash preimage reveal. */
EvalResult EvalHashPreimageBlock(const RungBlock& block);

/** Evaluate a HASH160_PREIMAGE block: HASH160 preimage reveal. */
EvalResult EvalHash160PreimageBlock(const RungBlock& block);

/** Evaluate a CSV block: relative timelock (block-height). */
EvalResult EvalCSVBlock(const RungBlock& block,
                        const BaseSignatureChecker& checker);

/** Evaluate a CSV_TIME block: relative timelock (median-time-past). */
EvalResult EvalCSVTimeBlock(const RungBlock& block,
                            const BaseSignatureChecker& checker);

/** Evaluate a CLTV block: absolute timelock (block-height). */
EvalResult EvalCLTVBlock(const RungBlock& block,
                         const BaseSignatureChecker& checker);

/** Evaluate a CLTV_TIME block: absolute timelock (median-time-past). */
EvalResult EvalCLTVTimeBlock(const RungBlock& block,
                             const BaseSignatureChecker& checker);

/** Evaluate a single block by dispatching to the appropriate evaluator. */
EvalResult EvalBlock(const RungBlock& block,
                     const BaseSignatureChecker& checker,
                     SigVersion sigversion,
                     ScriptExecutionData& execdata);

/** Evaluate a single rung: all blocks must return SATISFIED (AND logic). */
EvalResult EvalRung(const Rung& rung,
                    const BaseSignatureChecker& checker,
                    SigVersion sigversion,
                    ScriptExecutionData& execdata);

/** Evaluate a complete ladder: first satisfied rung wins (OR logic). */
bool EvalLadder(const LadderWitness& ladder,
                const BaseSignatureChecker& checker,
                SigVersion sigversion,
                ScriptExecutionData& execdata);

/** Top-level verification entry point for v3 RUNG_TX transactions. */
bool VerifyRungTx(const CTransaction& tx,
                  unsigned int nIn,
                  const CTxOut& spent_output,
                  unsigned int flags,
                  const BaseSignatureChecker& checker,
                  const PrecomputedTransactionData& txdata,
                  ScriptError* serror);

} // namespace rung

#endif // BITCOIN_RUNG_EVALUATOR_H
