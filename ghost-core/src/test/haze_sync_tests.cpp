// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <haze/bloom_filter.h>
#include <haze/checkpoint.h>
#include <haze/checkpoint_signing.h>
#include <haze/chunk_downloader.h>
#include <crypto/sha256.h>
#include <primitives/transaction.h>
#include <uint256.h>
#include <util/fs.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <random>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(haze_sync_tests, BasicTestingSetup)

// ============================================================================
// Ed25519 Checkpoint Signing
// ============================================================================

BOOST_AUTO_TEST_CASE(ed25519_sign_verify)
{
    // Generate a test key
    haze::Ed25519SecKey secret_key;
    std::memset(secret_key.data(), 0x42, secret_key.size());

    haze::Ed25519PubKey public_key;
    haze::DerivePublicKey(secret_key, public_key);

    // Create a test manifest
    haze::CheckpointManifest manifest;
    manifest.version = haze::CHECKPOINT_VERSION;
    manifest.height = 100;
    manifest.block_hash = uint256::ONE;
    manifest.utxo_count = 50000;

    // Sign and verify
    BOOST_CHECK(haze::SignCheckpoint(manifest, secret_key));
    BOOST_CHECK(haze::VerifyCheckpointWithKey(manifest, public_key));
}

BOOST_AUTO_TEST_CASE(ed25519_wrong_key_fails)
{
    haze::Ed25519SecKey secret_key;
    std::memset(secret_key.data(), 0x42, secret_key.size());

    haze::CheckpointManifest manifest;
    manifest.version = haze::CHECKPOINT_VERSION;
    manifest.height = 200;
    manifest.block_hash = uint256::ONE;

    BOOST_CHECK(haze::SignCheckpoint(manifest, secret_key));

    // Verify with a different key — should fail
    haze::Ed25519SecKey other_secret;
    std::memset(other_secret.data(), 0x99, other_secret.size());
    haze::Ed25519PubKey other_pubkey;
    haze::DerivePublicKey(other_secret, other_pubkey);

    BOOST_CHECK(!haze::VerifyCheckpointWithKey(manifest, other_pubkey));
}

BOOST_AUTO_TEST_CASE(ed25519_tampered_data_fails)
{
    haze::Ed25519SecKey secret_key;
    std::memset(secret_key.data(), 0x42, secret_key.size());
    haze::Ed25519PubKey public_key;
    haze::DerivePublicKey(secret_key, public_key);

    haze::CheckpointManifest manifest;
    manifest.version = haze::CHECKPOINT_VERSION;
    manifest.height = 300;
    manifest.block_hash = uint256::ONE;
    manifest.utxo_count = 10000;

    BOOST_CHECK(haze::SignCheckpoint(manifest, secret_key));
    BOOST_CHECK(haze::VerifyCheckpointWithKey(manifest, public_key));

    // Tamper with the manifest after signing
    manifest.utxo_count = 99999;
    BOOST_CHECK(!haze::VerifyCheckpointWithKey(manifest, public_key));
}

BOOST_AUTO_TEST_CASE(ed25519_derive_public_key)
{
    haze::Ed25519SecKey secret_key;
    std::memset(secret_key.data(), 0x01, secret_key.size());

    haze::Ed25519PubKey pubkey1, pubkey2;
    haze::DerivePublicKey(secret_key, pubkey1);
    haze::DerivePublicKey(secret_key, pubkey2);

    // Same secret key should derive the same public key
    BOOST_CHECK(pubkey1 == pubkey2);

    // Different secret key should derive different public key
    haze::Ed25519SecKey other_key;
    std::memset(other_key.data(), 0x02, other_key.size());
    haze::Ed25519PubKey other_pubkey;
    haze::DerivePublicKey(other_key, other_pubkey);

    BOOST_CHECK(pubkey1 != other_pubkey);
}

// ============================================================================
// Bloom Filter (SwiftSync)
// ============================================================================

BOOST_AUTO_TEST_CASE(bloom_filter_insert_query)
{
    haze::SwiftSyncFilter filter(1000, 0.001);
    BOOST_CHECK(filter.IsInitialized());

    // Insert some outpoints
    COutPoint op1(Txid::FromUint256(uint256::ONE), 0);
    COutPoint op2(Txid::FromUint256(uint256::ONE), 1);

    filter.Insert(op1);
    filter.Insert(op2);

    // Inserted items should return true
    BOOST_CHECK(filter.MayContain(op1));
    BOOST_CHECK(filter.MayContain(op2));
}

BOOST_AUTO_TEST_CASE(bloom_filter_absent_items)
{
    haze::SwiftSyncFilter filter(1000, 0.001);

    // Insert one item
    COutPoint inserted(Txid::FromUint256(uint256::ONE), 0);
    filter.Insert(inserted);

    // Test a bunch of non-inserted items — most should return false
    int false_positives = 0;
    const int test_count = 1000;
    for (int i = 1; i <= test_count; i++) {
        uint256 hash;
        std::memset(hash.data(), 0, 32);
        std::memcpy(hash.data(), &i, sizeof(i));
        COutPoint absent(Txid::FromUint256(hash), 99);
        if (filter.MayContain(absent)) {
            false_positives++;
        }
    }

    // With FPR of 0.001 and 1000 trials, expect ~1 false positive.
    // Allow generous margin: should be well under 50
    BOOST_CHECK_LT(false_positives, 50);
}

BOOST_AUTO_TEST_CASE(bloom_filter_false_positive_rate)
{
    const uint64_t num_elements = 10000;
    const double target_fpr = 0.001;
    haze::SwiftSyncFilter filter(num_elements, target_fpr);

    // Insert num_elements items
    for (uint64_t i = 0; i < num_elements; i++) {
        uint256 hash;
        std::memset(hash.data(), 0, 32);
        std::memcpy(hash.data(), &i, sizeof(i));
        COutPoint op(Txid::FromUint256(hash), 0);
        filter.Insert(op);
    }

    // Test with non-inserted items
    int false_positives = 0;
    const int trials = 100000;
    for (int i = 0; i < trials; i++) {
        uint64_t val = num_elements + i + 1;
        uint256 hash;
        std::memset(hash.data(), 0, 32);
        std::memcpy(hash.data(), &val, sizeof(val));
        COutPoint op(Txid::FromUint256(hash), 1);
        if (filter.MayContain(op)) {
            false_positives++;
        }
    }

    double empirical_fpr = static_cast<double>(false_positives) / trials;
    // Empirical FPR should be within 2x of theoretical
    BOOST_CHECK_LT(empirical_fpr, target_fpr * 2.0);
}

BOOST_AUTO_TEST_CASE(bloom_filter_save_load_roundtrip)
{
    haze::SwiftSyncFilter filter(1000, 0.001);

    // Insert items
    std::vector<COutPoint> inserted;
    for (int i = 0; i < 100; i++) {
        uint256 hash;
        std::memset(hash.data(), 0, 32);
        std::memcpy(hash.data(), &i, sizeof(i));
        COutPoint op(Txid::FromUint256(hash), 0);
        filter.Insert(op);
        inserted.push_back(op);
    }

    // Save to temp file
    std::string filepath = fs::PathToString(m_path_root / "test_bloom.bin");
    BOOST_CHECK(filter.Save(filepath));

    // Load from file
    haze::SwiftSyncFilter loaded;
    BOOST_CHECK(haze::SwiftSyncFilter::Load(filepath, loaded));

    // Verify same query results
    for (const auto& op : inserted) {
        BOOST_CHECK(loaded.MayContain(op));
    }
}

BOOST_AUTO_TEST_CASE(bloom_filter_parameters)
{
    const uint64_t num_elements = 5000;
    const double fpr = 0.01;
    haze::SwiftSyncFilter filter(num_elements, fpr);

    BOOST_CHECK(filter.IsInitialized());
    BOOST_CHECK_GT(filter.GetNumBits(), 0U);
    BOOST_CHECK_GT(filter.GetNumHashes(), 0U);
    BOOST_CHECK_EQUAL(filter.GetSeed(), haze::DEFAULT_BLOOM_SEED);
    BOOST_CHECK_GT(filter.GetSizeBytes(), 0U);
}

// ============================================================================
// Chunk Downloader
// ============================================================================

static haze::ChunkManifest MakeTestManifest(uint32_t num_chunks, const std::string& output_dir)
{
    haze::ChunkManifest manifest;
    manifest.chunk_size = 1024;
    manifest.total_chunks = num_chunks;

    for (uint32_t i = 0; i < num_chunks; i++) {
        haze::ChunkInfo info;
        info.chunk_index = i;
        info.offset = i * 1024ULL;
        info.size = 1024;
        info.height_min = i * 10;
        info.height_max = (i + 1) * 10 - 1;

        // Compute hash of dummy data
        std::vector<uint8_t> dummy(1024, static_cast<uint8_t>(i));
        CSHA256 hasher;
        hasher.Write(dummy.data(), dummy.size());
        unsigned char hash_out[CSHA256::OUTPUT_SIZE];
        hasher.Finalize(hash_out);
        std::memcpy(info.hash.data(), hash_out, 32);

        manifest.chunks.push_back(info);
    }

    return manifest;
}

BOOST_AUTO_TEST_CASE(chunk_downloader_init)
{
    std::string output_dir = fs::PathToString(m_path_root / "chunks");
    fs::create_directories(output_dir);

    auto manifest = MakeTestManifest(5, output_dir);

    haze::ChunkDownloader downloader;
    downloader.Init(manifest, output_dir);

    BOOST_CHECK_EQUAL(downloader.GetTotalChunks(), 5U);
    BOOST_CHECK_EQUAL(downloader.GetPendingCount(), 5U);
    BOOST_CHECK(!downloader.IsComplete());
}

BOOST_AUTO_TEST_CASE(chunk_downloader_request_receive)
{
    std::string output_dir = fs::PathToString(m_path_root / "chunks_rr");
    fs::create_directories(output_dir);

    auto manifest = MakeTestManifest(3, output_dir);

    haze::ChunkDownloader downloader;
    downloader.Init(manifest, output_dir);

    // Request chunks for peer 1
    auto requested = downloader.RequestChunks(/*peer_id=*/1, /*count=*/2);
    BOOST_CHECK_EQUAL(requested.size(), 2U);

    // Send valid data for the first requested chunk
    uint32_t chunk_idx = requested[0];
    std::vector<uint8_t> valid_data(1024, static_cast<uint8_t>(chunk_idx));
    BOOST_CHECK(downloader.ReceiveChunk(chunk_idx, std::move(valid_data)));

    // Stats should reflect one complete chunk
    auto stats = downloader.GetStats();
    BOOST_CHECK_EQUAL(stats.chunks_complete, 1U);
    BOOST_CHECK_EQUAL(stats.chunks_total, 3U);
}

BOOST_AUTO_TEST_CASE(chunk_downloader_invalid_hash_rejected)
{
    std::string output_dir = fs::PathToString(m_path_root / "chunks_bad");
    fs::create_directories(output_dir);

    auto manifest = MakeTestManifest(2, output_dir);

    haze::ChunkDownloader downloader;
    downloader.Init(manifest, output_dir);

    auto requested = downloader.RequestChunks(/*peer_id=*/1, /*count=*/1);
    BOOST_REQUIRE_EQUAL(requested.size(), 1U);

    // Send wrong data — hash won't match
    uint32_t chunk_idx = requested[0];
    std::vector<uint8_t> bad_data(1024, 0xFF);
    BOOST_CHECK(!downloader.ReceiveChunk(chunk_idx, std::move(bad_data)));

    // Chunk should not be marked complete
    auto stats = downloader.GetStats();
    BOOST_CHECK_EQUAL(stats.chunks_complete, 0U);
}

BOOST_AUTO_TEST_CASE(chunk_downloader_peer_disconnect)
{
    std::string output_dir = fs::PathToString(m_path_root / "chunks_dc");
    fs::create_directories(output_dir);

    auto manifest = MakeTestManifest(4, output_dir);

    haze::ChunkDownloader downloader;
    downloader.Init(manifest, output_dir);

    // Assign chunks to peer 5
    auto requested = downloader.RequestChunks(/*peer_id=*/5, /*count=*/2);
    BOOST_CHECK_EQUAL(requested.size(), 2U);

    uint32_t pending_before = downloader.GetPendingCount();

    // Simulate disconnect — assigned chunks should be re-queued
    downloader.HandlePeerDisconnect(/*peer_id=*/5);

    // Pending count should have increased (re-queued)
    BOOST_CHECK_GE(downloader.GetPendingCount(), pending_before);
}

BOOST_AUTO_TEST_CASE(chunk_downloader_completion)
{
    std::string output_dir = fs::PathToString(m_path_root / "chunks_done");
    fs::create_directories(output_dir);

    auto manifest = MakeTestManifest(3, output_dir);

    haze::ChunkDownloader downloader;
    downloader.Init(manifest, output_dir);

    // Download all chunks
    for (uint32_t i = 0; i < 3; i++) {
        auto requested = downloader.RequestChunks(/*peer_id=*/1, /*count=*/1);
        BOOST_REQUIRE_EQUAL(requested.size(), 1U);

        uint32_t chunk_idx = requested[0];
        std::vector<uint8_t> data(1024, static_cast<uint8_t>(chunk_idx));
        BOOST_CHECK(downloader.ReceiveChunk(chunk_idx, std::move(data)));
    }

    BOOST_CHECK(downloader.IsComplete());

    auto stats = downloader.GetStats();
    BOOST_CHECK_EQUAL(stats.chunks_complete, 3U);
    BOOST_CHECK_EQUAL(stats.chunks_total, 3U);
}

BOOST_AUTO_TEST_SUITE_END()
