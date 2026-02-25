// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_GHOST_REAPER_H
#define BITCOIN_POLICY_GHOST_REAPER_H

#include <primitives/transaction.h>

#include <string>

/** Ghost Reaper operating mode */
enum class GhostReaperMode {
    Disabled,   //!< No Reaper filtering
    Enabled,    //!< Dead-code filtering active (default)
};

/** Configuration for Ghost Reaper mempool filter */
struct GhostReaperConfig {
    GhostReaperMode mode{GhostReaperMode::Enabled};
    /** Maximum OP_RETURN data payload in bytes (default 83, matching Bitcoin Core relay default) */
    unsigned int max_op_return_bytes{83};
    /** Minimum push size to trigger drop stuffing detection (default 76) */
    unsigned int min_drop_size{76};
};

/**
 * Check whether a transaction passes Ghost Reaper dead-code filtering.
 *
 * Layer 1 defense: fast pattern matching at mempool acceptance.
 * Detects inscription envelopes, drop stuffing, fake multisig pubkeys,
 * P2TR annex abuse, and oversized OP_RETURN outputs.
 *
 * @param[in]  tx       The transaction to check
 * @param[in]  config   Reaper configuration (mode, thresholds)
 * @param[out] reason   Rejection reason string if the check fails
 * @return true if the transaction is clean, false if rejected
 */
bool IsGhostReaperClean(const CTransaction& tx, const GhostReaperConfig& config, std::string& reason);

/** Individual detector functions (exposed for testing) */

/**
 * Check witness scripts for OP_FALSE OP_IF ... OP_ENDIF inscription envelopes.
 */
bool CheckInscriptionEnvelope(const CTransaction& tx, std::string& reason);

/**
 * Check witness scripts for large push followed by OP_DROP/OP_2DROP.
 * @param[in] min_drop_size  Minimum push size to consider as drop stuffing
 */
bool CheckDropStuffing(const CTransaction& tx, unsigned int min_drop_size, std::string& reason);

/**
 * Check bare multisig outputs for pubkey pushes with invalid prefixes.
 * Valid compressed pubkeys start with 0x02 or 0x03.
 */
bool CheckFakeMultisigPubkeys(const CTransaction& tx, std::string& reason);

/**
 * Check P2TR witness stacks for annex presence (last element starts with 0x50).
 */
bool CheckAnnexPresence(const CTransaction& tx, std::string& reason);

/**
 * Check outputs for OP_RETURN with data payload exceeding the configured limit.
 * @param[in] max_bytes  Maximum allowed OP_RETURN data bytes
 */
bool CheckOversizedOpReturn(const CTransaction& tx, unsigned int max_bytes, std::string& reason);

#endif // BITCOIN_POLICY_GHOST_REAPER_H
