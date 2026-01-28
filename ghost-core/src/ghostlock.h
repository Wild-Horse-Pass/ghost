// Copyright (c) 2024-present The Ghost Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_GHOSTLOCK_H
#define BITCOIN_GHOSTLOCK_H

#include <script/script.h>
#include <pubkey.h>
#include <consensus/amount.h>
#include <uint256.h>

#include <array>
#include <optional>
#include <vector>

/**
 * Ghost Lock Script Templates
 *
 * Ghost Locks are P2TR outputs with a two-leaf Taproot tree:
 *
 *   - Key-path: Normal spending via lock_pubkey
 *   - Leaf 0: <lock_pubkey> OP_CHECKSIG (backup for script-path spend)
 *   - Leaf 1: <timelock> OP_CHECKSEQUENCEVERIFY OP_DROP <recovery_pubkey> OP_CHECKSIG
 *
 * The recovery path allows the original owner to reclaim funds after a timelock
 * expires if the Ghost Lock wasn't spent normally (e.g., L2 channel closes).
 */

namespace ghostlock {

/**
 * Standard Ghost Lock denominations (in satoshis).
 *
 * Ghost Pay uses fixed denominations for privacy and efficient batching.
 * All Ghost Locks in a reconciliation batch must have the same denomination.
 */
enum class Denomination : uint8_t {
    MICRO = 0,   //!< 10,000 sats (0.0001 BTC)
    TINY = 1,    //!< 100,000 sats (0.001 BTC)
    SMALL = 2,   //!< 1,000,000 sats (0.01 BTC)
    MEDIUM = 3,  //!< 10,000,000 sats (0.1 BTC)
    LARGE = 4,   //!< 100,000,000 sats (1.0 BTC)
    XL = 5,      //!< 1,000,000,000 sats (10.0 BTC)
};

/** Get denomination value in satoshis */
CAmount DenominationValue(Denomination denom);

/** Get denomination from satoshi value (returns nullopt if not a standard denomination) */
std::optional<Denomination> DenominationFromValue(CAmount value);

/** Get denomination name */
std::string DenominationName(Denomination denom);

/** Parse denomination from string name */
std::optional<Denomination> DenominationFromName(const std::string& name);

/** Default recovery timelock: 6 months in blocks (~26,280 blocks at 10 min/block) */
static constexpr uint32_t DEFAULT_RECOVERY_TIMELOCK = 26280;

/** Minimum recovery timelock: 1 week in blocks (~1,008 blocks) */
static constexpr uint32_t MIN_RECOVERY_TIMELOCK = 1008;

/** Maximum recovery timelock: 1 year in blocks (~52,560 blocks) */
static constexpr uint32_t MAX_RECOVERY_TIMELOCK = 52560;

/**
 * Ghost Lock script components.
 *
 * Contains all the data needed to construct and spend a Ghost Lock.
 */
struct GhostLockScript {
    XOnlyPubKey lock_pubkey;      //!< Primary spending key (from Silent Payment derivation)
    XOnlyPubKey recovery_pubkey;  //!< Recovery key for timelocked reclaim
    uint32_t recovery_timelock;   //!< Relative timelock for recovery (blocks)

    //! Build the normal spending script (leaf 0)
    CScript BuildNormalScript() const;

    //! Build the recovery spending script (leaf 1)
    CScript BuildRecoveryScript() const;

    //! Build the complete P2TR scriptPubKey
    CScript BuildScriptPubKey() const;

    //! Get the Taproot output key (tweaked internal key)
    std::optional<XOnlyPubKey> GetOutputKey() const;

    //! Get the merkle root of the script tree
    std::optional<uint256> GetMerkleRoot() const;
};

/**
 * Build a Ghost Lock P2TR output.
 *
 * @param[in] lock_pubkey The primary spending pubkey (derived via Silent Payment)
 * @param[in] recovery_pubkey The recovery pubkey for timelocked reclaim
 * @param[in] recovery_timelock Relative timelock in blocks for recovery path
 * @return The P2TR scriptPubKey for the Ghost Lock output
 */
CScript BuildGhostLockScript(
    const XOnlyPubKey& lock_pubkey,
    const XOnlyPubKey& recovery_pubkey,
    uint32_t recovery_timelock = DEFAULT_RECOVERY_TIMELOCK);

/**
 * Build a Ghost Lock output script with denomination validation.
 *
 * @param[in] lock_pubkey The primary spending pubkey
 * @param[in] recovery_pubkey The recovery pubkey
 * @param[in] amount The output amount (must be a valid denomination)
 * @param[in] recovery_timelock Relative timelock for recovery
 * @return The P2TR scriptPubKey, or nullopt if amount is not a valid denomination
 */
std::optional<CScript> BuildGhostLockScriptWithAmount(
    const XOnlyPubKey& lock_pubkey,
    const XOnlyPubKey& recovery_pubkey,
    CAmount amount,
    uint32_t recovery_timelock = DEFAULT_RECOVERY_TIMELOCK);

/**
 * Check if a scriptPubKey could be a Ghost Lock output.
 *
 * This is a heuristic check - it verifies the output is a P2TR output.
 * Full verification requires knowledge of the expected pubkeys.
 *
 * @param[in] scriptPubKey The script to check
 * @return true if this looks like a Ghost Lock P2TR output
 */
bool IsGhostLockScript(const CScript& scriptPubKey);

/**
 * Check if a value is a valid Ghost Lock denomination.
 *
 * @param[in] value The amount in satoshis
 * @return true if value matches a standard denomination
 */
bool IsValidDenomination(CAmount value);

/**
 * Validate a Ghost Lock recovery timelock.
 *
 * @param[in] timelock The timelock value in blocks
 * @return true if timelock is within valid range
 */
bool IsValidRecoveryTimelock(uint32_t timelock);

/**
 * Extract the output key from a P2TR scriptPubKey.
 *
 * @param[in] scriptPubKey The P2TR scriptPubKey
 * @return The x-only output public key, or nullopt if not a valid P2TR
 */
std::optional<XOnlyPubKey> ExtractP2TRKey(const CScript& scriptPubKey);

/**
 * Build control block for script-path spending.
 *
 * @param[in] internal_key The internal key before tweaking
 * @param[in] leaf_script The script being spent
 * @param[in] leaf_version The leaf version (default 0xc0 for tapscript)
 * @param[in] merkle_path The merkle proof path
 * @return The control block bytes
 */
std::vector<unsigned char> BuildControlBlock(
    const XOnlyPubKey& internal_key,
    const CScript& leaf_script,
    uint8_t leaf_version,
    const std::vector<uint256>& merkle_path);

} // namespace ghostlock

#endif // BITCOIN_GHOSTLOCK_H
