// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <haze/checkpoint_signing.h>
#include <haze/checkpoint.h>

#include <hash.h>
#include <logging.h>
#include <serialize.h>
#include <streams.h>

extern "C" {
#include <ed25519.h>
}

#include <cstring>

namespace haze {

bool SignCheckpoint(CheckpointManifest& manifest, const Ed25519SecKey& secret_key)
{
    // Derive the public key from the secret key
    Ed25519PubKey public_key;
    ed25519_publickey(secret_key.data(), public_key.data());

    // Compute the signing hash (SHA-256 of all fields except signature)
    uint256 signing_hash = manifest.GetSigningHash();

    // Sign the hash
    ed25519_signature sig;
    ed25519_sign(signing_hash.begin(), 32, secret_key.data(), public_key.data(), sig);

    // Store signature in manifest
    static_assert(sizeof(sig) == 64);
    std::memcpy(manifest.signature.data(), sig, 64);

    LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
                  "SignCheckpoint: signed manifest for height %d\n", manifest.height);
    return true;
}

bool VerifyCheckpointWithKey(const CheckpointManifest& manifest, const Ed25519PubKey& pubkey)
{
    // Compute the signing hash
    uint256 signing_hash = manifest.GetSigningHash();

    // Verify the Ed25519 signature
    int result = ed25519_sign_open(
        signing_hash.begin(), 32,
        pubkey.data(),
        manifest.signature.data());

    return result == 0;
}

bool VerifyCheckpoint(const CheckpointManifest& manifest)
{
    const auto trusted_keys = GetTrustedCheckpointKeys();

    for (const auto& key : trusted_keys) {
        if (VerifyCheckpointWithKey(manifest, key)) {
            LogPrintLevel(BCLog::HAZE, BCLog::Level::Info,
                          "VerifyCheckpoint: signature valid for height %d\n",
                          manifest.height);
            return true;
        }
    }

    LogPrintLevel(BCLog::HAZE, BCLog::Level::Error,
                  "VerifyCheckpoint: no trusted key verified signature for height %d\n",
                  manifest.height);
    return false;
}

std::vector<Ed25519PubKey> GetTrustedCheckpointKeys()
{
    // Ghost Core checkpoint signing public key v1.
    // Corresponding secret key is held offline for signing checkpoints.
    // Additional keys can be added for key rotation.
    return {
        Ed25519PubKey{{
            0xf3, 0xf6, 0xe6, 0xee, 0x9e, 0x27, 0x39, 0x8c,
            0xdf, 0x33, 0xbe, 0xab, 0x70, 0x83, 0x09, 0xb8,
            0x52, 0xad, 0xe4, 0x07, 0x20, 0x4e, 0xa1, 0x89,
            0x82, 0x4e, 0x1a, 0x49, 0x91, 0x5a, 0x51, 0x10,
        }},
    };
}

void DerivePublicKey(const Ed25519SecKey& secret_key, Ed25519PubKey& public_key)
{
    ed25519_publickey(secret_key.data(), public_key.data());
}

} // namespace haze
