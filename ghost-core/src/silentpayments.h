// Copyright (c) 2024-present The Ghost Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SILENTPAYMENTS_H
#define BITCOIN_SILENTPAYMENTS_H

#include <addresstype.h>
#include <key.h>
#include <pubkey.h>
#include <hash.h>
#include <uint256.h>

#include <array>
#include <optional>
#include <vector>

/** Ghost Lock OP_RETURN marker: "GHOS" in hex */
static constexpr std::array<unsigned char, 4> GHOST_MARKER = {0x47, 0x48, 0x4F, 0x53};

/** Size of ephemeral public key in OP_RETURN (compressed) */
static constexpr size_t GHOST_EPHEMERAL_PUBKEY_SIZE = 33;

/** Minimum OP_RETURN size for Ghost Lock: marker (4) + ephemeral pubkey (33) */
static constexpr size_t GHOST_OPRETURN_MIN_SIZE = 37;

namespace silentpayments {

/**
 * Compute ECDH shared secret between a private key and a public key.
 *
 * The shared secret is computed as: SHA256(secret_key * public_key)
 * This matches the ghost-keys Rust implementation.
 *
 * @param[in] secret_key The private key (32 bytes)
 * @param[in] pubkey The public key
 * @return The 32-byte shared secret, or nullopt on failure
 */
std::optional<uint256> ComputeSharedSecret(const CKey& secret_key, const CPubKey& pubkey);

/**
 * Compute the tweak for address derivation.
 *
 * tweak = SHA256(shared_secret || index || nonce)
 *
 * @param[in] shared_secret The ECDH shared secret (32 bytes)
 * @param[in] index Output index in transaction
 * @param[in] nonce Random nonce for additional unlinkability
 * @return The 32-byte tweak value
 */
uint256 ComputeTweak(const uint256& shared_secret, uint32_t index, uint16_t nonce);

/**
 * Derive the output public key for a Silent Payment.
 *
 * output_pubkey = spend_pubkey + tweak*G
 *
 * @param[in] spend_pubkey The receiver's spend public key
 * @param[in] tweak The tweak value from ComputeTweak
 * @return The derived output public key, or nullopt on failure
 */
std::optional<CPubKey> DeriveOutputPubKey(const CPubKey& spend_pubkey, const uint256& tweak);

/**
 * Derive the output public key directly from shared secret.
 *
 * Combines ComputeTweak and DeriveOutputPubKey for convenience.
 *
 * @param[in] spend_pubkey The receiver's spend public key
 * @param[in] shared_secret The ECDH shared secret
 * @param[in] index Output index in transaction
 * @param[in] nonce Random nonce
 * @return The derived output public key, or nullopt on failure
 */
std::optional<CPubKey> DeriveOutputPubKey(const CPubKey& spend_pubkey, const uint256& shared_secret, uint32_t index, uint16_t nonce);

/**
 * Derive the spending private key for a received Silent Payment.
 *
 * spend_key = spend_secret + tweak
 *
 * @param[in] spend_secret The receiver's spend private key
 * @param[in] tweak The tweak value from ComputeTweak
 * @return The derived spending key, or nullopt on failure
 */
std::optional<CKey> DeriveSpendKey(const CKey& spend_secret, const uint256& tweak);

/**
 * Create a payment to a Silent Payment destination (Ghost ID).
 *
 * Generates an ephemeral keypair, computes the shared secret, and derives
 * the output public key that should be used in a P2TR output.
 *
 * @param[in] destination The Ghost ID (scan + spend pubkeys)
 * @param[in] index Output index
 * @param[in] nonce Random nonce
 * @return Tuple of (output_pubkey, ephemeral_pubkey, tweak), or nullopt on failure
 */
struct PaymentDerivation {
    CPubKey output_pubkey;      //!< The P2TR output key
    CPubKey ephemeral_pubkey;   //!< Must be included in OP_RETURN
    uint256 tweak;              //!< The tweak used (for reference)
};
std::optional<PaymentDerivation> CreatePayment(const SilentPaymentDestination& destination, uint32_t index, uint16_t nonce);

/**
 * Scan a transaction output to check if it belongs to us.
 *
 * Given the ephemeral pubkey from OP_RETURN, compute the expected output
 * and check if it matches.
 *
 * @param[in] scan_secret Our scan private key
 * @param[in] spend_pubkey Our spend public key
 * @param[in] ephemeral_pubkey The sender's ephemeral pubkey from OP_RETURN
 * @param[in] output_pubkey The actual output pubkey from the transaction
 * @param[in] index Output index to try
 * @param[in] nonce Nonce to try (usually 0)
 * @return The tweak if this output is ours, nullopt otherwise
 */
std::optional<uint256> ScanOutput(
    const CKey& scan_secret,
    const CPubKey& spend_pubkey,
    const CPubKey& ephemeral_pubkey,
    const CPubKey& output_pubkey,
    uint32_t index,
    uint16_t nonce);

/**
 * Parse Ghost Lock OP_RETURN data.
 *
 * Expected format: GHOST_MARKER (4 bytes) + ephemeral_pubkey (33 bytes) + optional data
 *
 * @param[in] data The OP_RETURN data
 * @return The ephemeral public key, or nullopt if not a valid Ghost Lock OP_RETURN
 */
std::optional<CPubKey> ParseGhostOpReturn(const std::vector<unsigned char>& data);

/**
 * Create Ghost Lock OP_RETURN data.
 *
 * @param[in] ephemeral_pubkey The sender's ephemeral public key
 * @param[in] extra_data Optional additional data to include
 * @return The OP_RETURN payload
 */
std::vector<unsigned char> CreateGhostOpReturn(const CPubKey& ephemeral_pubkey, const std::vector<unsigned char>& extra_data = {});

/**
 * Check if OP_RETURN data is a Ghost Lock marker.
 *
 * @param[in] data The OP_RETURN data
 * @return true if this is a Ghost Lock OP_RETURN
 */
bool IsGhostOpReturn(const std::vector<unsigned char>& data);

} // namespace silentpayments

#endif // BITCOIN_SILENTPAYMENTS_H
