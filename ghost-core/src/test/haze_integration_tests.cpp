// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <haze/exorcism.h>
#include <haze/haze_p2p.h>
#include <haze/mode_selector.h>
#include <haze/block_stripper.h>
#include <primitives/block.h>
#include <streams.h>
#include <uint256.h>
#include <util/fs.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(haze_integration_tests, BasicTestingSetup)

// ============================================================================
// Mode Selector
// ============================================================================

BOOST_AUTO_TEST_CASE(mode_lock_write_read_roundtrip)
{
    fs::path test_dir = m_path_root / "mode_test";
    fs::create_directories(test_dir);

    // Write HAZED mode
    BOOST_CHECK(haze::WriteModeLock(test_dir, haze::GhostMode::HAZED));
    auto result = haze::ReadModeLock(test_dir);
    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK(result.value() == haze::GhostMode::HAZED);

    // Overwrite with FULL_ARCHIVE
    BOOST_CHECK(haze::WriteModeLock(test_dir, haze::GhostMode::FULL_ARCHIVE));
    result = haze::ReadModeLock(test_dir);
    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK(result.value() == haze::GhostMode::FULL_ARCHIVE);
}

BOOST_AUTO_TEST_CASE(mode_lock_missing_returns_nullopt)
{
    fs::path empty_dir = m_path_root / "empty_mode";
    fs::create_directories(empty_dir);

    auto result = haze::ReadModeLock(empty_dir);
    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(mode_consistency_hazed_with_blk_files)
{
    fs::path test_dir = m_path_root / "hazed_blk";
    fs::path blocks_dir = test_dir / "blocks";
    fs::create_directories(blocks_dir);

    // Create a fake blk00000.dat file
    {
        std::ofstream f(fs::PathToString(blocks_dir / "blk00000.dat"));
        f << "fake block data";
    }

    auto error = haze::ValidateModeConsistency(test_dir, haze::GhostMode::HAZED);
    BOOST_CHECK(error.has_value()); // Should report inconsistency
}

BOOST_AUTO_TEST_CASE(mode_consistency_archive_with_gsb_files)
{
    fs::path test_dir = m_path_root / "archive_gsb";
    fs::path blocks_dir = test_dir / "blocks";
    fs::create_directories(blocks_dir);

    // Create a fake gsb00000.dat file
    {
        std::ofstream f(fs::PathToString(blocks_dir / "gsb00000.dat"));
        f << "fake gsb data";
    }

    auto error = haze::ValidateModeConsistency(test_dir, haze::GhostMode::FULL_ARCHIVE);
    BOOST_CHECK(error.has_value()); // Should report inconsistency
}

BOOST_AUTO_TEST_CASE(mode_consistency_clean_dir)
{
    fs::path test_dir = m_path_root / "clean_mode";
    fs::path blocks_dir = test_dir / "blocks";
    fs::create_directories(blocks_dir);

    // Both modes should be valid on a clean directory
    auto hazed_error = haze::ValidateModeConsistency(test_dir, haze::GhostMode::HAZED);
    BOOST_CHECK(!hazed_error.has_value());

    auto archive_error = haze::ValidateModeConsistency(test_dir, haze::GhostMode::FULL_ARCHIVE);
    BOOST_CHECK(!archive_error.has_value());
}

// ============================================================================
// Exorcism
// ============================================================================

BOOST_AUTO_TEST_CASE(exorcism_init_hazed)
{
    haze::GhostExorcism exorcism;
    exorcism.Init(haze::GhostMode::HAZED);

    BOOST_CHECK(exorcism.IsActive());
    BOOST_CHECK(exorcism.GetMode() == haze::GhostMode::HAZED);
}

BOOST_AUTO_TEST_CASE(exorcism_init_archive)
{
    haze::GhostExorcism exorcism;
    exorcism.Init(haze::GhostMode::FULL_ARCHIVE);

    BOOST_CHECK(!exorcism.IsActive());
    BOOST_CHECK(exorcism.GetMode() == haze::GhostMode::FULL_ARCHIVE);
}

BOOST_AUTO_TEST_CASE(exorcism_statistics)
{
    haze::GhostExorcism exorcism;
    exorcism.Init(haze::GhostMode::HAZED);

    BOOST_CHECK_EQUAL(exorcism.GetBlocksProcessed(), 0U);
    BOOST_CHECK_EQUAL(exorcism.GetTotalBytesStripped(), 0U);

    // Create a minimal block to strip
    CBlock block;
    block.nVersion = 1;
    block.nTime = 1234567890;
    block.nBits = 0x207fffff;
    block.nNonce = 0;

    // Add a coinbase transaction
    CMutableTransaction coinbase_mtx;
    coinbase_mtx.vin.resize(1);
    coinbase_mtx.vin[0].prevout.SetNull();
    coinbase_mtx.vin[0].scriptSig = CScript() << 1 << OP_0;
    coinbase_mtx.vout.resize(1);
    coinbase_mtx.vout[0].nValue = 50 * COIN;
    coinbase_mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    block.vtx.push_back(MakeTransactionRef(std::move(coinbase_mtx)));

    auto result = exorcism.StripValidatedBlock(block);

    BOOST_CHECK_EQUAL(exorcism.GetBlocksProcessed(), 1U);
    BOOST_CHECK_GT(exorcism.GetTotalBytesStripped(), 0U);
    BOOST_CHECK_EQUAL(result.stripped_block.GetTxCount(), 1U);
}

// ============================================================================
// P2P Messages
// ============================================================================

BOOST_AUTO_TEST_CASE(ghost_redirect_serialize_deserialize)
{
    haze::GhostRedirect redirect;
    redirect.block_hash = uint256::ONE;
    redirect.archive_peers = {"192.168.1.1:8333", "10.0.0.1:8333", "172.16.0.1:8333"};

    // Serialize
    DataStream ss;
    ss << redirect;

    // Deserialize
    haze::GhostRedirect restored;
    ss >> restored;

    BOOST_CHECK(restored.block_hash == redirect.block_hash);
    BOOST_CHECK_EQUAL(restored.archive_peers.size(), redirect.archive_peers.size());
    for (size_t i = 0; i < redirect.archive_peers.size(); i++) {
        BOOST_CHECK_EQUAL(restored.archive_peers[i], redirect.archive_peers[i]);
    }
}

BOOST_AUTO_TEST_CASE(ghost_redirect_empty_peers)
{
    haze::GhostRedirect redirect;
    redirect.block_hash = uint256::ZERO;
    redirect.archive_peers = {};

    // Serialize
    DataStream ss;
    ss << redirect;

    // Deserialize
    haze::GhostRedirect restored;
    ss >> restored;

    BOOST_CHECK(restored.block_hash == uint256::ZERO);
    BOOST_CHECK(restored.archive_peers.empty());
}

BOOST_AUTO_TEST_SUITE_END()
