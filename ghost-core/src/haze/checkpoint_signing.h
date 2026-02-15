// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HAZE_CHECKPOINT_SIGNING_H
#define BITCOIN_HAZE_CHECKPOINT_SIGNING_H

#include <array>
#include <cstdint>
#include <vector>

namespace haze {

struct CheckpointManifest;

/** Ed25519 secret key (32 bytes). */
using Ed25519SecKey = std::array<uint8_t, 32>;

/** Ed25519 public key (32 bytes). */
using Ed25519PubKey = std::array<uint8_t, 32>;

/**
 * Sign a checkpoint manifest with an Ed25519 secret key.
 *
 * Computes the signing hash of the manifest (all fields except signature),
 * signs it with the provided secret key, and stores the 64-byte signature
 * in the manifest's signature field.
 *
 * @param[in,out] manifest    The manifest to sign (signature field is populated).
 * @param[in]     secret_key  The Ed25519 secret key.
 * @return true on success.
 */
bool SignCheckpoint(CheckpointManifest& manifest, const Ed25519SecKey& secret_key);

/**
 * Verify a checkpoint manifest against the hardcoded trusted keys.
 *
 * Tries each trusted key in order; returns true if any key validates
 * the signature.
 *
 * @param[in] manifest  The manifest to verify.
 * @return true if the signature is valid against a trusted key.
 */
bool VerifyCheckpoint(const CheckpointManifest& manifest);

/**
 * Verify a checkpoint manifest against a specific public key.
 *
 * @param[in] manifest  The manifest to verify.
 * @param[in] pubkey    The Ed25519 public key to verify against.
 * @return true if the signature is valid.
 */
bool VerifyCheckpointWithKey(const CheckpointManifest& manifest, const Ed25519PubKey& pubkey);

/**
 * Get the list of hardcoded trusted checkpoint signing keys.
 *
 * Multiple keys support key rotation: old checkpoints remain valid
 * after a new key is introduced.
 *
 * @return Vector of trusted Ed25519 public keys.
 */
std::vector<Ed25519PubKey> GetTrustedCheckpointKeys();

/**
 * Derive the Ed25519 public key from a secret key.
 *
 * @param[in]  secret_key  The Ed25519 secret key.
 * @param[out] public_key  The derived public key.
 */
void DerivePublicKey(const Ed25519SecKey& secret_key, Ed25519PubKey& public_key);

} // namespace haze

#endif // BITCOIN_HAZE_CHECKPOINT_SIGNING_H
