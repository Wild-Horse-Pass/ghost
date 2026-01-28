// Copyright (c) 2024-present The Ghost Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <silentpayments.h>

#include <crypto/sha256.h>
#include <hash.h>
#include <random.h>
#include <span.h>

#include <secp256k1.h>
#include <secp256k1_ecdh.h>

#include <cassert>

namespace silentpayments {

std::optional<uint256> ComputeSharedSecret(const CKey& secret_key, const CPubKey& pubkey)
{
    if (!secret_key.IsValid() || !pubkey.IsValid()) {
        return std::nullopt;
    }

    // Parse the public key
    secp256k1_pubkey secp_pubkey;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_static, &secp_pubkey, pubkey.data(), pubkey.size())) {
        return std::nullopt;
    }

    // Compute ECDH shared secret
    // secp256k1_ecdh with default hash function returns SHA256(compressed_pubkey)
    unsigned char ecdh_output[32];
    if (!secp256k1_ecdh(secp256k1_context_static, ecdh_output, &secp_pubkey, UCharCast(secret_key.begin()), nullptr, nullptr)) {
        return std::nullopt;
    }

    // The secp256k1_ecdh_hash_function_sha256 (default) already hashes the point
    // to match ghost-keys: we hash again to get SHA256(secret_key * public_key)
    // Actually, the default function hashes SHA256(compressed_point), which is what we want
    uint256 result;
    std::memcpy(result.begin(), ecdh_output, 32);
    return result;
}

uint256 ComputeTweak(const uint256& shared_secret, uint32_t index, uint16_t nonce)
{
    // tweak = SHA256(shared_secret || index || nonce)
    // This must match ghost-keys derivation.rs compute_tweak()
    CSHA256 hasher;
    hasher.Write(shared_secret.begin(), 32);

    // index as little-endian 4 bytes
    unsigned char index_bytes[4];
    index_bytes[0] = index & 0xFF;
    index_bytes[1] = (index >> 8) & 0xFF;
    index_bytes[2] = (index >> 16) & 0xFF;
    index_bytes[3] = (index >> 24) & 0xFF;
    hasher.Write(index_bytes, 4);

    // nonce as little-endian 2 bytes
    unsigned char nonce_bytes[2];
    nonce_bytes[0] = nonce & 0xFF;
    nonce_bytes[1] = (nonce >> 8) & 0xFF;
    hasher.Write(nonce_bytes, 2);

    uint256 result;
    hasher.Finalize(result.begin());
    return result;
}

std::optional<CPubKey> DeriveOutputPubKey(const CPubKey& spend_pubkey, const uint256& tweak)
{
    if (!spend_pubkey.IsValid()) {
        return std::nullopt;
    }

    // Parse the spend pubkey
    secp256k1_pubkey secp_spend;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_static, &secp_spend, spend_pubkey.data(), spend_pubkey.size())) {
        return std::nullopt;
    }

    // output_pubkey = spend_pubkey + tweak*G
    // secp256k1_ec_pubkey_tweak_add modifies the pubkey in place
    if (!secp256k1_ec_pubkey_tweak_add(secp256k1_context_static, &secp_spend, tweak.begin())) {
        return std::nullopt;
    }

    // Serialize the result
    unsigned char output[CPubKey::COMPRESSED_SIZE];
    size_t output_len = CPubKey::COMPRESSED_SIZE;
    secp256k1_ec_pubkey_serialize(secp256k1_context_static, output, &output_len, &secp_spend, SECP256K1_EC_COMPRESSED);

    return CPubKey(output, output + output_len);
}

std::optional<CPubKey> DeriveOutputPubKey(const CPubKey& spend_pubkey, const uint256& shared_secret, uint32_t index, uint16_t nonce)
{
    uint256 tweak = ComputeTweak(shared_secret, index, nonce);
    return DeriveOutputPubKey(spend_pubkey, tweak);
}

std::optional<CKey> DeriveSpendKey(const CKey& spend_secret, const uint256& tweak)
{
    if (!spend_secret.IsValid()) {
        return std::nullopt;
    }

    // spend_key = spend_secret + tweak
    // Copy the secret key data
    std::array<unsigned char, 32> derived;
    std::memcpy(derived.data(), UCharCast(spend_secret.begin()), 32);

    // Add the tweak
    if (!secp256k1_ec_seckey_tweak_add(secp256k1_context_static, derived.data(), tweak.begin())) {
        return std::nullopt;
    }

    CKey result;
    result.Set(derived.begin(), derived.end(), true);  // compressed

    // Clear sensitive data
    memory_cleanse(derived.data(), derived.size());

    if (!result.IsValid()) {
        return std::nullopt;
    }

    return result;
}

std::optional<PaymentDerivation> CreatePayment(const SilentPaymentDestination& destination, uint32_t index, uint16_t nonce)
{
    // Generate ephemeral keypair
    CKey ephemeral_secret;
    ephemeral_secret.MakeNewKey(true);  // compressed
    CPubKey ephemeral_pubkey = ephemeral_secret.GetPubKey();

    // Parse scan pubkey from destination
    const auto& scan_bytes = destination.GetScanPubKey();
    CPubKey scan_pubkey(scan_bytes.begin(), scan_bytes.end());
    if (!scan_pubkey.IsValid()) {
        return std::nullopt;
    }

    // Parse spend pubkey from destination
    const auto& spend_bytes = destination.GetSpendPubKey();
    CPubKey spend_pubkey(spend_bytes.begin(), spend_bytes.end());
    if (!spend_pubkey.IsValid()) {
        return std::nullopt;
    }

    // Compute shared secret: ephemeral_secret * scan_pubkey
    auto shared_secret = ComputeSharedSecret(ephemeral_secret, scan_pubkey);
    if (!shared_secret) {
        return std::nullopt;
    }

    // Compute tweak
    uint256 tweak = ComputeTweak(*shared_secret, index, nonce);

    // Derive output pubkey: spend_pubkey + tweak*G
    auto output_pubkey = DeriveOutputPubKey(spend_pubkey, tweak);
    if (!output_pubkey) {
        return std::nullopt;
    }

    return PaymentDerivation{*output_pubkey, ephemeral_pubkey, tweak};
}

std::optional<uint256> ScanOutput(
    const CKey& scan_secret,
    const CPubKey& spend_pubkey,
    const CPubKey& ephemeral_pubkey,
    const CPubKey& output_pubkey,
    uint32_t index,
    uint16_t nonce)
{
    // Compute shared secret: scan_secret * ephemeral_pubkey
    auto shared_secret = ComputeSharedSecret(scan_secret, ephemeral_pubkey);
    if (!shared_secret) {
        return std::nullopt;
    }

    // Compute tweak
    uint256 tweak = ComputeTweak(*shared_secret, index, nonce);

    // Derive expected output pubkey
    auto expected = DeriveOutputPubKey(spend_pubkey, tweak);
    if (!expected) {
        return std::nullopt;
    }

    // Check if it matches
    if (*expected == output_pubkey) {
        return tweak;  // This output is ours!
    }

    return std::nullopt;
}

std::optional<CPubKey> ParseGhostOpReturn(const std::vector<unsigned char>& data)
{
    // Check minimum size: marker (4) + ephemeral pubkey (33)
    if (data.size() < GHOST_OPRETURN_MIN_SIZE) {
        return std::nullopt;
    }

    // Check marker
    if (!std::equal(GHOST_MARKER.begin(), GHOST_MARKER.end(), data.begin())) {
        return std::nullopt;
    }

    // Parse ephemeral pubkey
    CPubKey ephemeral(data.begin() + 4, data.begin() + 4 + GHOST_EPHEMERAL_PUBKEY_SIZE);
    if (!ephemeral.IsValid()) {
        return std::nullopt;
    }

    return ephemeral;
}

std::vector<unsigned char> CreateGhostOpReturn(const CPubKey& ephemeral_pubkey, const std::vector<unsigned char>& extra_data)
{
    assert(ephemeral_pubkey.IsCompressed());

    std::vector<unsigned char> result;
    result.reserve(GHOST_MARKER.size() + ephemeral_pubkey.size() + extra_data.size());

    // Add marker
    result.insert(result.end(), GHOST_MARKER.begin(), GHOST_MARKER.end());

    // Add ephemeral pubkey
    result.insert(result.end(), ephemeral_pubkey.begin(), ephemeral_pubkey.end());

    // Add extra data
    result.insert(result.end(), extra_data.begin(), extra_data.end());

    return result;
}

bool IsGhostOpReturn(const std::vector<unsigned char>& data)
{
    if (data.size() < GHOST_MARKER.size()) {
        return false;
    }
    return std::equal(GHOST_MARKER.begin(), GHOST_MARKER.end(), data.begin());
}

} // namespace silentpayments
