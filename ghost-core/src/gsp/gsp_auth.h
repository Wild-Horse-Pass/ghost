// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_GSP_GSP_AUTH_H
#define BITCOIN_GSP_GSP_AUTH_H

#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <chrono>
#include <pubkey.h>
#include <uint256.h>

namespace gsp {

/**
 * WalletProof - Proof of wallet ownership using Schnorr signature.
 *
 * Light wallets prove ownership by signing a challenge message with their
 * wallet's private key. The signature is verified using secp256k1 Schnorr.
 */
struct WalletProof {
    //! The wallet's public key (33 bytes compressed)
    CPubKey pubkey;

    //! The challenge that was signed (usually includes timestamp)
    std::string challenge;

    //! Schnorr signature over the challenge
    std::vector<unsigned char> signature;

    //! Timestamp when the proof was created
    int64_t timestamp;

    /**
     * Verify the WalletProof signature.
     * @return true if the signature is valid
     */
    bool Verify() const;

    /**
     * Get the wallet ID derived from the public key.
     * This is the RIPEMD160(SHA256(pubkey)) encoded as hex.
     */
    std::string GetWalletId() const;

    /**
     * Check if the proof is within acceptable time window (±5 minutes).
     */
    bool IsTimestampValid() const;

    /**
     * Create a challenge string for a wallet to sign.
     * Format: "GSP-AUTH:{wallet_id}:{timestamp}"
     */
    static std::string CreateChallenge(const std::string& wallet_id);
};

/**
 * JWT Manager - JSON Web Token handling for session management.
 *
 * After initial WalletProof verification, the server issues a JWT
 * that the client uses for subsequent requests. This avoids
 * re-signing for every request.
 */
class JwtManager {
public:
    explicit JwtManager(const std::string& secret);
    ~JwtManager();

    /**
     * Create a JWT for an authenticated wallet.
     * @param wallet_id The wallet identifier
     * @param ttl_seconds Token lifetime in seconds (default: 24 hours)
     * @return The encoded JWT string
     */
    std::string CreateToken(const std::string& wallet_id,
                           uint32_t ttl_seconds = 86400);

    /**
     * Verify and decode a JWT.
     * @param token The JWT to verify
     * @return The wallet_id if valid, std::nullopt otherwise
     */
    std::optional<std::string> VerifyToken(const std::string& token);

    /**
     * Invalidate a token (add to blacklist until expiry).
     */
    void InvalidateToken(const std::string& token);

    /**
     * JWT claims structure.
     */
    struct Claims {
        std::string wallet_id;
        int64_t issued_at;
        int64_t expires_at;
    };

    /**
     * Decode a token without verification (for debugging).
     */
    std::optional<Claims> DecodeWithoutVerify(const std::string& token);

private:
    std::string m_secret;

    // Forward declaration for implementation
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

/**
 * Rate limiter for authentication endpoints.
 */
class AuthRateLimiter {
public:
    explicit AuthRateLimiter();
    ~AuthRateLimiter();

    /**
     * Check if a request is allowed (and consume a token if so).
     * @param key The rate limit key (IP address or wallet_id)
     * @param limit Requests allowed per window
     * @param window_seconds Window duration in seconds
     * @return true if the request is allowed
     */
    bool Allow(const std::string& key, uint32_t limit, uint32_t window_seconds);

    /**
     * Reset limits for a key.
     */
    void Reset(const std::string& key);

    /**
     * Clean up expired entries.
     */
    void Cleanup();

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace gsp

#endif // BITCOIN_GSP_GSP_AUTH_H
