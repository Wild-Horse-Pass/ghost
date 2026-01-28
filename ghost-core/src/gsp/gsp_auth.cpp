// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gsp/gsp_auth.h>

#include <crypto/sha256.h>
#include <hash.h>
#include <key.h>
#include <logging.h>
#include <random.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <map>
#include <mutex>
#include <sstream>

namespace gsp {

// WalletProof implementation

bool WalletProof::Verify() const
{
    if (!pubkey.IsValid()) {
        return false;
    }

    // Verify Schnorr signature over the challenge
    // The challenge is hashed before verification
    uint256 hash;
    CSHA256()
        .Write((const unsigned char*)challenge.data(), challenge.size())
        .Finalize(hash.begin());

    // Use secp256k1 to verify Schnorr signature
    // Note: In full implementation, this would use VerifySchnorr
    return pubkey.Verify(hash, signature);
}

std::string WalletProof::GetWalletId() const
{
    if (!pubkey.IsValid()) {
        return "";
    }

    // wallet_id = RIPEMD160(SHA256(pubkey)) as hex
    // This is the same as a Bitcoin address hash160
    uint160 hash = Hash160(pubkey);
    return HexStr(hash);
}

bool WalletProof::IsTimestampValid() const
{
    int64_t now = GetTime();
    int64_t diff = std::abs(now - timestamp);
    // Allow 5 minute window
    return diff <= 300;
}

std::string WalletProof::CreateChallenge(const std::string& wallet_id)
{
    int64_t timestamp = GetTime();
    std::ostringstream ss;
    ss << "GSP-AUTH:" << wallet_id << ":" << timestamp;
    return ss.str();
}

// JwtManager implementation

class JwtManager::Impl {
public:
    std::mutex mutex;
    std::map<std::string, int64_t> blacklist; // token -> expiry time

    void CleanupBlacklist() {
        int64_t now = GetTime();
        for (auto it = blacklist.begin(); it != blacklist.end();) {
            if (it->second < now) {
                it = blacklist.erase(it);
            } else {
                ++it;
            }
        }
    }
};

JwtManager::JwtManager(const std::string& secret)
    : m_secret(secret)
    , m_impl(std::make_unique<Impl>())
{
}

JwtManager::~JwtManager() = default;

// Simple JWT implementation using HMAC-SHA256
// Format: base64url(header).base64url(payload).base64url(signature)

static std::string Base64UrlEncode(const std::vector<unsigned char>& data)
{
    static const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string result;
    result.reserve((data.size() + 2) / 3 * 4);

    for (size_t i = 0; i < data.size(); i += 3) {
        unsigned int n = data[i] << 16;
        if (i + 1 < data.size()) n |= data[i + 1] << 8;
        if (i + 2 < data.size()) n |= data[i + 2];

        result += alphabet[(n >> 18) & 0x3F];
        result += alphabet[(n >> 12) & 0x3F];
        result += (i + 1 < data.size()) ? alphabet[(n >> 6) & 0x3F] : '=';
        result += (i + 2 < data.size()) ? alphabet[n & 0x3F] : '=';
    }

    // Remove padding for URL-safe base64
    while (!result.empty() && result.back() == '=') {
        result.pop_back();
    }

    return result;
}

static std::string Base64UrlEncode(const std::string& str)
{
    return Base64UrlEncode(std::vector<unsigned char>(str.begin(), str.end()));
}

static std::vector<unsigned char> Base64UrlDecode(const std::string& str)
{
    static const int decode_table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,63,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };

    std::vector<unsigned char> result;
    result.reserve(str.size() * 3 / 4);

    unsigned int n = 0;
    int bits = 0;
    for (char c : str) {
        int val = decode_table[(unsigned char)c];
        if (val < 0) continue;
        n = (n << 6) | val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            result.push_back((n >> bits) & 0xFF);
        }
    }

    return result;
}

static std::vector<unsigned char> HmacSha256(const std::string& key, const std::string& data)
{
    std::vector<unsigned char> result(32);

    // Simple HMAC-SHA256 implementation
    std::vector<unsigned char> key_pad(64, 0);
    if (key.size() <= 64) {
        std::copy(key.begin(), key.end(), key_pad.begin());
    } else {
        CSHA256().Write((const unsigned char*)key.data(), key.size())
                 .Finalize(key_pad.data());
    }

    std::vector<unsigned char> o_key_pad(64), i_key_pad(64);
    for (size_t i = 0; i < 64; ++i) {
        o_key_pad[i] = key_pad[i] ^ 0x5c;
        i_key_pad[i] = key_pad[i] ^ 0x36;
    }

    // inner hash
    std::vector<unsigned char> inner(32);
    CSHA256()
        .Write(i_key_pad.data(), 64)
        .Write((const unsigned char*)data.data(), data.size())
        .Finalize(inner.data());

    // outer hash
    CSHA256()
        .Write(o_key_pad.data(), 64)
        .Write(inner.data(), 32)
        .Finalize(result.data());

    return result;
}

std::string JwtManager::CreateToken(const std::string& wallet_id, uint32_t ttl_seconds)
{
    int64_t now = GetTime();
    int64_t exp = now + ttl_seconds;

    // Header: {"alg":"HS256","typ":"JWT"}
    std::string header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";

    // Payload
    std::ostringstream payload_ss;
    payload_ss << "{\"wallet_id\":\"" << wallet_id << "\","
               << "\"iat\":" << now << ","
               << "\"exp\":" << exp << "}";
    std::string payload = payload_ss.str();

    std::string encoded_header = Base64UrlEncode(header);
    std::string encoded_payload = Base64UrlEncode(payload);
    std::string signing_input = encoded_header + "." + encoded_payload;

    auto signature = HmacSha256(m_secret, signing_input);
    std::string encoded_signature = Base64UrlEncode(signature);

    return signing_input + "." + encoded_signature;
}

std::optional<std::string> JwtManager::VerifyToken(const std::string& token)
{
    // Check blacklist
    {
        std::lock_guard<std::mutex> lock(m_impl->mutex);
        m_impl->CleanupBlacklist();
        if (m_impl->blacklist.count(token)) {
            return std::nullopt;
        }
    }

    // Split token
    size_t dot1 = token.find('.');
    if (dot1 == std::string::npos) return std::nullopt;

    size_t dot2 = token.find('.', dot1 + 1);
    if (dot2 == std::string::npos) return std::nullopt;

    std::string encoded_header = token.substr(0, dot1);
    std::string encoded_payload = token.substr(dot1 + 1, dot2 - dot1 - 1);
    std::string encoded_signature = token.substr(dot2 + 1);

    // Verify signature
    std::string signing_input = encoded_header + "." + encoded_payload;
    auto expected_sig = HmacSha256(m_secret, signing_input);
    std::string expected_encoded = Base64UrlEncode(expected_sig);

    if (encoded_signature != expected_encoded) {
        return std::nullopt;
    }

    // Decode payload
    auto payload_bytes = Base64UrlDecode(encoded_payload);
    std::string payload(payload_bytes.begin(), payload_bytes.end());

    // Simple JSON parsing for wallet_id and exp
    // In production, use a proper JSON library
    size_t wallet_pos = payload.find("\"wallet_id\":\"");
    if (wallet_pos == std::string::npos) return std::nullopt;
    wallet_pos += 13;
    size_t wallet_end = payload.find('"', wallet_pos);
    if (wallet_end == std::string::npos) return std::nullopt;
    std::string wallet_id = payload.substr(wallet_pos, wallet_end - wallet_pos);

    size_t exp_pos = payload.find("\"exp\":");
    if (exp_pos == std::string::npos) return std::nullopt;
    exp_pos += 6;
    size_t exp_end = payload.find_first_of(",}", exp_pos);
    if (exp_end == std::string::npos) return std::nullopt;
    int64_t exp = std::stoll(payload.substr(exp_pos, exp_end - exp_pos));

    // Check expiry
    if (GetTime() > exp) {
        return std::nullopt;
    }

    return wallet_id;
}

void JwtManager::InvalidateToken(const std::string& token)
{
    // Decode to get expiry time
    auto claims = DecodeWithoutVerify(token);
    if (claims) {
        std::lock_guard<std::mutex> lock(m_impl->mutex);
        m_impl->blacklist[token] = claims->expires_at;
    }
}

std::optional<JwtManager::Claims> JwtManager::DecodeWithoutVerify(const std::string& token)
{
    size_t dot1 = token.find('.');
    if (dot1 == std::string::npos) return std::nullopt;

    size_t dot2 = token.find('.', dot1 + 1);
    if (dot2 == std::string::npos) return std::nullopt;

    std::string encoded_payload = token.substr(dot1 + 1, dot2 - dot1 - 1);
    auto payload_bytes = Base64UrlDecode(encoded_payload);
    std::string payload(payload_bytes.begin(), payload_bytes.end());

    Claims claims;

    // Parse wallet_id
    size_t wallet_pos = payload.find("\"wallet_id\":\"");
    if (wallet_pos != std::string::npos) {
        wallet_pos += 13;
        size_t wallet_end = payload.find('"', wallet_pos);
        if (wallet_end != std::string::npos) {
            claims.wallet_id = payload.substr(wallet_pos, wallet_end - wallet_pos);
        }
    }

    // Parse iat
    size_t iat_pos = payload.find("\"iat\":");
    if (iat_pos != std::string::npos) {
        iat_pos += 6;
        size_t iat_end = payload.find_first_of(",}", iat_pos);
        if (iat_end != std::string::npos) {
            claims.issued_at = std::stoll(payload.substr(iat_pos, iat_end - iat_pos));
        }
    }

    // Parse exp
    size_t exp_pos = payload.find("\"exp\":");
    if (exp_pos != std::string::npos) {
        exp_pos += 6;
        size_t exp_end = payload.find_first_of(",}", exp_pos);
        if (exp_end != std::string::npos) {
            claims.expires_at = std::stoll(payload.substr(exp_pos, exp_end - exp_pos));
        }
    }

    return claims;
}

// AuthRateLimiter implementation

class AuthRateLimiter::Impl {
public:
    struct Bucket {
        uint32_t tokens;
        int64_t last_update;
    };

    std::mutex mutex;
    std::map<std::string, Bucket> buckets;
};

AuthRateLimiter::AuthRateLimiter()
    : m_impl(std::make_unique<Impl>())
{
}

AuthRateLimiter::~AuthRateLimiter() = default;

bool AuthRateLimiter::Allow(const std::string& key, uint32_t limit, uint32_t window_seconds)
{
    std::lock_guard<std::mutex> lock(m_impl->mutex);

    int64_t now = GetTime();
    auto& bucket = m_impl->buckets[key];

    // Refill tokens based on time elapsed
    if (bucket.last_update == 0) {
        bucket.tokens = limit;
        bucket.last_update = now;
    } else {
        int64_t elapsed = now - bucket.last_update;
        uint32_t refill = (uint32_t)(elapsed * limit / window_seconds);
        bucket.tokens = std::min(limit, bucket.tokens + refill);
        bucket.last_update = now;
    }

    // Check if we have tokens
    if (bucket.tokens > 0) {
        bucket.tokens--;
        return true;
    }

    return false;
}

void AuthRateLimiter::Reset(const std::string& key)
{
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    m_impl->buckets.erase(key);
}

void AuthRateLimiter::Cleanup()
{
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    int64_t now = GetTime();
    int64_t expiry = 3600; // Remove entries older than 1 hour

    for (auto it = m_impl->buckets.begin(); it != m_impl->buckets.end();) {
        if (now - it->second.last_update > expiry) {
            it = m_impl->buckets.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace gsp
