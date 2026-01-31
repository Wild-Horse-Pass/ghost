// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gsp/gsp_auth.h>
#include <gsp/gsp_wallet.h>
#include <gsp/gsp_ws.h>

#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>

#include <thread>
#include <chrono>

namespace gsp_tests {

BOOST_FIXTURE_TEST_SUITE(gsp_tests, BasicTestingSetup)

// JwtManager tests
BOOST_AUTO_TEST_CASE(jwt_create_and_verify)
{
    gsp::JwtManager jwt("test_secret_key_for_jwt_testing_12345");

    // Create a token
    std::string wallet_id = "abc123def456";
    std::string token = jwt.CreateToken(wallet_id, 3600); // 1 hour TTL

    BOOST_CHECK(!token.empty());
    BOOST_CHECK(token.find('.') != std::string::npos); // JWT has dots

    // Verify the token
    auto result = jwt.VerifyToken(token);
    BOOST_CHECK(result.has_value());
    BOOST_CHECK_EQUAL(*result, wallet_id);
}

BOOST_AUTO_TEST_CASE(jwt_expired_token)
{
    gsp::JwtManager jwt("test_secret_key");

    // Create a token that expires in 1 second
    std::string token = jwt.CreateToken("wallet123", 1);

    // Should be valid immediately
    auto result1 = jwt.VerifyToken(token);
    BOOST_CHECK(result1.has_value());

    // Wait for expiry
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Should be invalid after expiry
    auto result2 = jwt.VerifyToken(token);
    BOOST_CHECK(!result2.has_value());
}

BOOST_AUTO_TEST_CASE(jwt_invalid_token)
{
    gsp::JwtManager jwt("test_secret_key");

    // Test various invalid tokens
    BOOST_CHECK(!jwt.VerifyToken("").has_value());
    BOOST_CHECK(!jwt.VerifyToken("not.a.jwt").has_value());
    BOOST_CHECK(!jwt.VerifyToken("invalid").has_value());

    // Create valid token then tamper with it
    std::string token = jwt.CreateToken("wallet123", 3600);
    std::string tampered = token;
    if (!tampered.empty()) {
        tampered[tampered.size() / 2] = 'X'; // Modify middle character
    }
    BOOST_CHECK(!jwt.VerifyToken(tampered).has_value());
}

BOOST_AUTO_TEST_CASE(jwt_blacklist)
{
    gsp::JwtManager jwt("test_secret_key");

    std::string token = jwt.CreateToken("wallet123", 3600);

    // Token should be valid
    BOOST_CHECK(jwt.VerifyToken(token).has_value());

    // Invalidate it
    jwt.InvalidateToken(token);

    // Token should now be invalid
    BOOST_CHECK(!jwt.VerifyToken(token).has_value());
}

BOOST_AUTO_TEST_CASE(jwt_decode_without_verify)
{
    gsp::JwtManager jwt("test_secret_key");

    std::string wallet_id = "test_wallet_id";
    std::string token = jwt.CreateToken(wallet_id, 3600);

    auto claims = jwt.DecodeWithoutVerify(token);
    BOOST_CHECK(claims.has_value());
    BOOST_CHECK_EQUAL(claims->wallet_id, wallet_id);
    BOOST_CHECK(claims->issued_at > 0);
    BOOST_CHECK(claims->expires_at > claims->issued_at);
}

// AuthRateLimiter tests
BOOST_AUTO_TEST_CASE(rate_limiter_allow)
{
    gsp::AuthRateLimiter limiter;

    // Should allow up to the limit
    for (int i = 0; i < 5; ++i) {
        BOOST_CHECK(limiter.Allow("test_key", 5, 60));
    }

    // Should reject after limit exceeded
    BOOST_CHECK(!limiter.Allow("test_key", 5, 60));
}

BOOST_AUTO_TEST_CASE(rate_limiter_different_keys)
{
    gsp::AuthRateLimiter limiter;

    // Different keys have separate limits
    BOOST_CHECK(limiter.Allow("key1", 2, 60));
    BOOST_CHECK(limiter.Allow("key1", 2, 60));
    BOOST_CHECK(!limiter.Allow("key1", 2, 60)); // key1 exhausted

    BOOST_CHECK(limiter.Allow("key2", 2, 60)); // key2 still has tokens
    BOOST_CHECK(limiter.Allow("key2", 2, 60));
}

BOOST_AUTO_TEST_CASE(rate_limiter_reset)
{
    gsp::AuthRateLimiter limiter;

    // Exhaust the limit
    BOOST_CHECK(limiter.Allow("test_key", 1, 60));
    BOOST_CHECK(!limiter.Allow("test_key", 1, 60));

    // Reset and try again
    limiter.Reset("test_key");
    BOOST_CHECK(limiter.Allow("test_key", 1, 60));
}

// WalletProof tests
BOOST_AUTO_TEST_CASE(wallet_proof_timestamp_valid)
{
    gsp::WalletProof proof;
    proof.timestamp = GetTime();

    BOOST_CHECK(proof.IsTimestampValid());
}

BOOST_AUTO_TEST_CASE(wallet_proof_timestamp_expired)
{
    gsp::WalletProof proof;
    proof.timestamp = GetTime() - 600; // 10 minutes ago (> 5 min window)

    BOOST_CHECK(!proof.IsTimestampValid());
}

BOOST_AUTO_TEST_CASE(wallet_proof_timestamp_future)
{
    gsp::WalletProof proof;
    proof.timestamp = GetTime() + 600; // 10 minutes in future (> 5 min window)

    BOOST_CHECK(!proof.IsTimestampValid());
}

BOOST_AUTO_TEST_CASE(wallet_proof_create_challenge)
{
    std::string wallet_id = "test_wallet_123";
    std::string challenge = gsp::WalletProof::CreateChallenge(wallet_id);

    BOOST_CHECK(!challenge.empty());
    BOOST_CHECK(challenge.find("GSP-AUTH:") == 0);
    BOOST_CHECK(challenge.find(wallet_id) != std::string::npos);
}

// WsMessageType tests
BOOST_AUTO_TEST_CASE(ws_message_type_to_string)
{
    BOOST_CHECK_EQUAL(gsp::WsMessageTypeToString(gsp::WsMessageType::Authenticate), "Authenticate");
    BOOST_CHECK_EQUAL(gsp::WsMessageTypeToString(gsp::WsMessageType::GetBalance), "GetBalance");
    BOOST_CHECK_EQUAL(gsp::WsMessageTypeToString(gsp::WsMessageType::NewBlock), "NewBlock");
    BOOST_CHECK_EQUAL(gsp::WsMessageTypeToString(gsp::WsMessageType::Error), "Error");
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace gsp_tests
