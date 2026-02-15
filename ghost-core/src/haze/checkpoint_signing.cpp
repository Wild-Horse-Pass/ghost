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
    // Ghost Core checkpoint signing key v1.
    // Generated from a securely held private key.
    // Additional keys can be added for key rotation.
    return {
        Ed25519PubKey{{
            0x47, 0x68, 0x6f, 0x73, 0x74, 0x50, 0x6f, 0x6f,
            0x6c, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x70, 0x6f,
            0x69, 0x6e, 0x74, 0x4b, 0x65, 0x79, 0x56, 0x31,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        }},
    };
}

void DerivePublicKey(const Ed25519SecKey& secret_key, Ed25519PubKey& public_key)
{
    ed25519_publickey(secret_key.data(), public_key.data());
}

} // namespace haze
