// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/ghost_reaper.h>

#include <primitives/transaction.h>
#include <script/script.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace {

/** Build a minimal transaction with one input and one output */
CMutableTransaction MakeBaseTx()
{
    CMutableTransaction tx;
    tx.version = 2;
    tx.nLockTime = 0;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash.SetNull();
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 50000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return tx;
}

} // anonymous namespace

BOOST_AUTO_TEST_SUITE(ghost_reaper_tests)

// ============================================================================
// CheckInscriptionEnvelope
// ============================================================================

BOOST_AUTO_TEST_CASE(inscription_envelope_detected)
{
    CMutableTransaction mtx = MakeBaseTx();

    // Witness element: OP_FALSE(0x00) OP_IF(0x63) <push 5 bytes> OP_ENDIF(0x68)
    std::vector<unsigned char> witness_elem = {
        0x00, 0x63,             // OP_FALSE OP_IF
        0x05,                   // push 5 bytes
        'h', 'e', 'l', 'l', 'o',
        0x68                    // OP_ENDIF
    };
    mtx.vin[0].scriptWitness.stack.push_back(witness_elem);

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(!CheckInscriptionEnvelope(tx, reason));
    BOOST_CHECK_EQUAL(reason, "ghost-reaper-inscription-envelope");
}

BOOST_AUTO_TEST_CASE(inscription_envelope_nested_if)
{
    CMutableTransaction mtx = MakeBaseTx();

    // Nested: OP_FALSE OP_IF OP_IF ... OP_ENDIF OP_ENDIF
    std::vector<unsigned char> witness_elem = {
        0x00, 0x63,             // OP_FALSE OP_IF
        0x63,                   // nested OP_IF
        0x01, 0xff,             // push 1 byte
        0x68,                   // OP_ENDIF (inner)
        0x68                    // OP_ENDIF (outer)
    };
    mtx.vin[0].scriptWitness.stack.push_back(witness_elem);

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(!CheckInscriptionEnvelope(tx, reason));
    BOOST_CHECK_EQUAL(reason, "ghost-reaper-inscription-envelope");
}

BOOST_AUTO_TEST_CASE(no_inscription_clean_witness)
{
    CMutableTransaction mtx = MakeBaseTx();

    // Normal witness: just a signature-like element
    std::vector<unsigned char> sig(72, 0x30);
    mtx.vin[0].scriptWitness.stack.push_back(sig);

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(CheckInscriptionEnvelope(tx, reason));
}

BOOST_AUTO_TEST_CASE(no_inscription_no_witness)
{
    CMutableTransaction mtx = MakeBaseTx();
    // No witness at all
    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(CheckInscriptionEnvelope(tx, reason));
}

// ============================================================================
// CheckDropStuffing
// ============================================================================

BOOST_AUTO_TEST_CASE(drop_stuffing_detected)
{
    CMutableTransaction mtx = MakeBaseTx();

    // Witness element: push 80 bytes then OP_DROP
    std::vector<unsigned char> witness_elem;
    witness_elem.push_back(0x4c);       // OP_PUSHDATA1
    witness_elem.push_back(80);         // 80 bytes
    witness_elem.insert(witness_elem.end(), 80, 0xaa); // 80 bytes of data
    witness_elem.push_back(0x75);       // OP_DROP

    mtx.vin[0].scriptWitness.stack.push_back(witness_elem);

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(!CheckDropStuffing(tx, 76, reason));
    BOOST_CHECK_EQUAL(reason, "ghost-reaper-drop-stuffing");
}

BOOST_AUTO_TEST_CASE(drop_stuffing_2drop_detected)
{
    CMutableTransaction mtx = MakeBaseTx();

    // Witness element: push 100 bytes then OP_2DROP
    std::vector<unsigned char> witness_elem;
    witness_elem.push_back(0x4c);       // OP_PUSHDATA1
    witness_elem.push_back(100);        // 100 bytes
    witness_elem.insert(witness_elem.end(), 100, 0xbb);
    witness_elem.push_back(0x6d);       // OP_2DROP

    mtx.vin[0].scriptWitness.stack.push_back(witness_elem);

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(!CheckDropStuffing(tx, 76, reason));
    BOOST_CHECK_EQUAL(reason, "ghost-reaper-drop-stuffing");
}

BOOST_AUTO_TEST_CASE(small_drop_not_flagged)
{
    CMutableTransaction mtx = MakeBaseTx();

    // Push 10 bytes + OP_DROP — below threshold
    std::vector<unsigned char> witness_elem;
    witness_elem.push_back(10);         // push 10 bytes (direct push opcode)
    witness_elem.insert(witness_elem.end(), 10, 0xcc);
    witness_elem.push_back(0x75);       // OP_DROP

    mtx.vin[0].scriptWitness.stack.push_back(witness_elem);

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(CheckDropStuffing(tx, 76, reason));
}

// ============================================================================
// CheckFakeMultisigPubkeys
// ============================================================================

BOOST_AUTO_TEST_CASE(fake_multisig_pubkey_detected)
{
    CMutableTransaction mtx = MakeBaseTx();

    // Build a bare 1-of-2 multisig with one fake pubkey (prefix 0x04 instead of 0x02/0x03)
    CScript multisig;
    multisig << OP_1;
    // Valid pubkey (0x02 prefix + 32 zero bytes)
    std::vector<unsigned char> valid_pubkey(33, 0x00);
    valid_pubkey[0] = 0x02;
    multisig << valid_pubkey;
    // Fake pubkey (0x04 prefix — uncompressed, not valid for bare multisig)
    std::vector<unsigned char> fake_pubkey(33, 0x00);
    fake_pubkey[0] = 0x04;
    multisig << fake_pubkey;
    multisig << OP_2 << OP_CHECKMULTISIG;

    mtx.vout[0].scriptPubKey = multisig;

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(!CheckFakeMultisigPubkeys(tx, reason));
    BOOST_CHECK_EQUAL(reason, "ghost-reaper-fake-multisig-pubkey");
}

BOOST_AUTO_TEST_CASE(valid_multisig_passes)
{
    CMutableTransaction mtx = MakeBaseTx();

    // Build a bare 1-of-2 multisig with valid compressed pubkeys
    CScript multisig;
    multisig << OP_1;
    std::vector<unsigned char> pk1(33, 0x11);
    pk1[0] = 0x02;
    multisig << pk1;
    std::vector<unsigned char> pk2(33, 0x22);
    pk2[0] = 0x03;
    multisig << pk2;
    multisig << OP_2 << OP_CHECKMULTISIG;

    mtx.vout[0].scriptPubKey = multisig;

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(CheckFakeMultisigPubkeys(tx, reason));
}

BOOST_AUTO_TEST_CASE(non_multisig_passes)
{
    CMutableTransaction mtx = MakeBaseTx();
    // P2PKH-like output — not a multisig, should pass
    mtx.vout[0].scriptPubKey = CScript() << OP_DUP << OP_HASH160
                               << std::vector<unsigned char>(20, 0xab)
                               << OP_EQUALVERIFY << OP_CHECKSIG;

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(CheckFakeMultisigPubkeys(tx, reason));
}

// ============================================================================
// CheckAnnexPresence
// ============================================================================

BOOST_AUTO_TEST_CASE(annex_detected)
{
    CMutableTransaction mtx = MakeBaseTx();

    // P2TR witness with annex: [signature, annex_starting_with_0x50]
    std::vector<unsigned char> sig(64, 0x30);
    std::vector<unsigned char> annex = {0x50, 0x01, 0x02, 0x03}; // starts with 0x50

    mtx.vin[0].scriptWitness.stack.push_back(sig);
    mtx.vin[0].scriptWitness.stack.push_back(annex);

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(!CheckAnnexPresence(tx, reason));
    BOOST_CHECK_EQUAL(reason, "ghost-reaper-annex-presence");
}

BOOST_AUTO_TEST_CASE(no_annex_passes)
{
    CMutableTransaction mtx = MakeBaseTx();

    // P2TR witness without annex: [signature]
    // Single element → no annex check (needs >= 2 elements)
    std::vector<unsigned char> sig(64, 0x30);
    mtx.vin[0].scriptWitness.stack.push_back(sig);

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(CheckAnnexPresence(tx, reason));
}

BOOST_AUTO_TEST_CASE(two_elements_no_annex_passes)
{
    CMutableTransaction mtx = MakeBaseTx();

    // Two elements, last doesn't start with 0x50
    std::vector<unsigned char> sig(64, 0x30);
    std::vector<unsigned char> script_path = {0x20, 0x01, 0x02}; // doesn't start with 0x50
    mtx.vin[0].scriptWitness.stack.push_back(sig);
    mtx.vin[0].scriptWitness.stack.push_back(script_path);

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(CheckAnnexPresence(tx, reason));
}

// ============================================================================
// CheckOversizedOpReturn
// ============================================================================

BOOST_AUTO_TEST_CASE(oversized_opreturn_detected)
{
    CMutableTransaction mtx = MakeBaseTx();

    // OP_RETURN with 100 bytes of data (over default limit of 83)
    CScript op_return;
    op_return << OP_RETURN;
    std::vector<unsigned char> data(100, 0xdd);
    op_return << data;

    mtx.vout[0].scriptPubKey = op_return;

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(!CheckOversizedOpReturn(tx, 83, reason));
    BOOST_CHECK_EQUAL(reason, "ghost-reaper-oversized-opreturn");
}

BOOST_AUTO_TEST_CASE(normal_opreturn_passes)
{
    CMutableTransaction mtx = MakeBaseTx();

    // OP_RETURN with 40 bytes — well within limit
    CScript op_return;
    op_return << OP_RETURN;
    std::vector<unsigned char> data(40, 0xee);
    op_return << data;

    mtx.vout[0].scriptPubKey = op_return;

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(CheckOversizedOpReturn(tx, 83, reason));
}

BOOST_AUTO_TEST_CASE(exactly_at_limit_passes)
{
    CMutableTransaction mtx = MakeBaseTx();

    // OP_RETURN with exactly 82 bytes of data + 1 push opcode = 83 total after OP_RETURN
    // CScript serialization: OP_RETURN(1) + OP_PUSHDATA1(1) + len(1) + data(82) = 85 total
    // Data payload = script.size() - 1 = 84 > 83? Let's test the boundary.
    // Actually we need to check: after OP_RETURN, remaining bytes count.
    // With CScript << OP_RETURN << vector(80), the serialized form is:
    // 0x6a 0x4c 0x50 <80 bytes> = 83 bytes total, data_size = 82
    CScript op_return;
    op_return << OP_RETURN;
    std::vector<unsigned char> data(80, 0xff);
    op_return << data;

    mtx.vout[0].scriptPubKey = op_return;

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(CheckOversizedOpReturn(tx, 83, reason));
}

// ============================================================================
// IsGhostReaperClean (integration)
// ============================================================================

BOOST_AUTO_TEST_CASE(clean_tx_passes_all)
{
    CMutableTransaction mtx = MakeBaseTx();

    // Normal witness with just a signature
    std::vector<unsigned char> sig(72, 0x30);
    mtx.vin[0].scriptWitness.stack.push_back(sig);

    CTransaction tx(mtx);
    GhostReaperConfig config;
    config.mode = GhostReaperMode::Strict;
    std::string reason;
    BOOST_CHECK(IsGhostReaperClean(tx, config, reason));
}

BOOST_AUTO_TEST_CASE(disabled_mode_passes_everything)
{
    CMutableTransaction mtx = MakeBaseTx();

    // Add an inscription envelope — would normally be rejected
    std::vector<unsigned char> witness_elem = {
        0x00, 0x63, 0x05, 'h', 'e', 'l', 'l', 'o', 0x68
    };
    mtx.vin[0].scriptWitness.stack.push_back(witness_elem);

    CTransaction tx(mtx);
    GhostReaperConfig config;
    config.mode = GhostReaperMode::Disabled;
    std::string reason;
    BOOST_CHECK(IsGhostReaperClean(tx, config, reason));
}

BOOST_AUTO_TEST_CASE(strict_mode_rejects_inscription)
{
    CMutableTransaction mtx = MakeBaseTx();

    std::vector<unsigned char> witness_elem = {
        0x00, 0x63, 0x05, 'h', 'e', 'l', 'l', 'o', 0x68
    };
    mtx.vin[0].scriptWitness.stack.push_back(witness_elem);

    CTransaction tx(mtx);
    GhostReaperConfig config;
    config.mode = GhostReaperMode::Strict;
    std::string reason;
    BOOST_CHECK(!IsGhostReaperClean(tx, config, reason));
    BOOST_CHECK_EQUAL(reason, "ghost-reaper-inscription-envelope");
}

BOOST_AUTO_TEST_CASE(moderate_mode_rejects_inscription)
{
    CMutableTransaction mtx = MakeBaseTx();

    std::vector<unsigned char> witness_elem = {
        0x00, 0x63, 0x05, 'h', 'e', 'l', 'l', 'o', 0x68
    };
    mtx.vin[0].scriptWitness.stack.push_back(witness_elem);

    CTransaction tx(mtx);
    GhostReaperConfig config;
    config.mode = GhostReaperMode::Moderate;
    std::string reason;
    BOOST_CHECK(!IsGhostReaperClean(tx, config, reason));
    BOOST_CHECK_EQUAL(reason, "ghost-reaper-inscription-envelope");
}

BOOST_AUTO_TEST_CASE(custom_opreturn_limit)
{
    CMutableTransaction mtx = MakeBaseTx();

    // OP_RETURN with 50 bytes of data
    CScript op_return;
    op_return << OP_RETURN;
    std::vector<unsigned char> data(50, 0xee);
    op_return << data;
    mtx.vout[0].scriptPubKey = op_return;

    CTransaction tx(mtx);
    GhostReaperConfig config;
    config.mode = GhostReaperMode::Strict;

    // Default limit (83) — should pass
    std::string reason;
    BOOST_CHECK(IsGhostReaperClean(tx, config, reason));

    // Lower limit to 40 — now should fail
    config.max_op_return_bytes = 40;
    BOOST_CHECK(!IsGhostReaperClean(tx, config, reason));
    BOOST_CHECK_EQUAL(reason, "ghost-reaper-oversized-opreturn");
}

BOOST_AUTO_TEST_CASE(custom_drop_size_threshold)
{
    CMutableTransaction mtx = MakeBaseTx();

    // Push 50 bytes + OP_DROP
    std::vector<unsigned char> witness_elem;
    witness_elem.push_back(50);  // push 50 bytes (direct push)
    witness_elem.insert(witness_elem.end(), 50, 0xaa);
    witness_elem.push_back(0x75); // OP_DROP
    mtx.vin[0].scriptWitness.stack.push_back(witness_elem);

    CTransaction tx(mtx);
    GhostReaperConfig config;
    config.mode = GhostReaperMode::Strict;

    // Default min_drop_size (76) — 50-byte push should pass
    std::string reason;
    BOOST_CHECK(IsGhostReaperClean(tx, config, reason));

    // Lower threshold to 30 — now should fail
    config.min_drop_size = 30;
    BOOST_CHECK(!IsGhostReaperClean(tx, config, reason));
    BOOST_CHECK_EQUAL(reason, "ghost-reaper-drop-stuffing");
}

BOOST_AUTO_TEST_SUITE_END()
