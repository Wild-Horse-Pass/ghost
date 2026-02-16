// Copyright (c) 2024-present The Ghost Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BIP39_H
#define BITCOIN_BIP39_H

#include <cstdint>
#include <string>
#include <vector>

namespace bip39 {

/** Number of words in the BIP-39 English wordlist. */
static constexpr size_t WORDLIST_SIZE = 2048;

/** PBKDF2 iteration count for seed derivation. */
static constexpr int PBKDF2_ROUNDS = 2048;

/** Size of derived seed in bytes. */
static constexpr size_t SEED_SIZE = 64;

/**
 * Generate a BIP-39 mnemonic phrase from cryptographically secure entropy.
 *
 * @param strength  Entropy bits: 128 (12 words), 160 (15 words), 192 (18 words),
 *                  224 (21 words), or 256 (24 words). Default is 256.
 * @return          Space-separated mnemonic phrase, or empty string on invalid strength.
 */
std::string GenerateMnemonic(int strength = 256);

/**
 * Derive a 64-byte seed from a mnemonic phrase using PBKDF2-HMAC-SHA512.
 *
 * @param mnemonic    Space-separated mnemonic phrase.
 * @param passphrase  Optional passphrase (BIP-39 "mnemonic" prefix is applied internally).
 * @return            64-byte seed vector. Caller should cleanse when done.
 */
std::vector<unsigned char> MnemonicToSeed(const std::string& mnemonic, const std::string& passphrase = "");

/**
 * Validate a BIP-39 mnemonic phrase.
 *
 * Checks word count, all words exist in the wordlist, and the checksum is correct.
 *
 * @param mnemonic  Space-separated mnemonic phrase.
 * @return          true if the mnemonic is valid per BIP-39.
 */
bool ValidateMnemonic(const std::string& mnemonic);

/**
 * Get a const reference to the BIP-39 English wordlist (2048 words).
 *
 * @return  Reference to the static wordlist vector.
 */
const std::vector<std::string>& GetWordList();

} // namespace bip39

#endif // BITCOIN_BIP39_H
