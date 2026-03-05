// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/conditions.h>
#include <rung/evaluator.h>
#include <rung/policy.h>
#include <rung/serialize.h>
#include <rung/sighash.h>
#include <rung/types.h>

#include <crypto/sha256.h>
#include <hash.h>
#include <key.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <vector>

using namespace rung;

// ============================================================================
// Helper: build a LadderWitness, serialize, and deserialize it
// ============================================================================

static std::vector<uint8_t> MakePubkey()
{
    // A fake compressed pubkey (33 bytes, starts with 0x02)
    std::vector<uint8_t> pk(33, 0xAA);
    pk[0] = 0x02;
    return pk;
}

static std::vector<uint8_t> MakeSignature(size_t len = 64)
{
    // A fake signature of the given length
    return std::vector<uint8_t>(len, 0xBB);
}

static std::vector<uint8_t> MakeHash256()
{
    return std::vector<uint8_t>(32, 0xCC);
}

static std::vector<uint8_t> MakeHash160()
{
    return std::vector<uint8_t>(20, 0xDD);
}

static std::vector<uint8_t> MakeNumeric(uint32_t val)
{
    std::vector<uint8_t> data(4);
    data[0] = val & 0xFF;
    data[1] = (val >> 8) & 0xFF;
    data[2] = (val >> 16) & 0xFF;
    data[3] = (val >> 24) & 0xFF;
    return data;
}

BOOST_FIXTURE_TEST_SUITE(rung_tests, BasicTestingSetup)

// ============================================================================
// Types tests
// ============================================================================

BOOST_AUTO_TEST_CASE(field_validation_pubkey_valid)
{
    RungField field{RungDataType::PUBKEY, MakePubkey()};
    std::string reason;
    BOOST_CHECK(field.IsValid(reason));
}

BOOST_AUTO_TEST_CASE(field_validation_pubkey_too_small)
{
    RungField field{RungDataType::PUBKEY, std::vector<uint8_t>(32, 0x02)};
    std::string reason;
    BOOST_CHECK(!field.IsValid(reason));
    BOOST_CHECK(reason.find("too small") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(field_validation_pubkey_too_large)
{
    RungField field{RungDataType::PUBKEY, std::vector<uint8_t>(34, 0x02)};
    std::string reason;
    BOOST_CHECK(!field.IsValid(reason));
    BOOST_CHECK(reason.find("too large") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(field_validation_pubkey_bad_prefix)
{
    auto pk = MakePubkey();
    pk[0] = 0x04; // uncompressed prefix, not allowed for 33-byte key
    RungField field{RungDataType::PUBKEY, pk};
    std::string reason;
    BOOST_CHECK(!field.IsValid(reason));
    BOOST_CHECK(reason.find("invalid prefix") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(field_validation_signature_valid)
{
    RungField field{RungDataType::SIGNATURE, MakeSignature(64)};
    std::string reason;
    BOOST_CHECK(field.IsValid(reason));
}

BOOST_AUTO_TEST_CASE(field_validation_signature_too_small)
{
    RungField field{RungDataType::SIGNATURE, std::vector<uint8_t>(63, 0xBB)};
    std::string reason;
    BOOST_CHECK(!field.IsValid(reason));
}

BOOST_AUTO_TEST_CASE(field_validation_signature_too_large)
{
    RungField field{RungDataType::SIGNATURE, std::vector<uint8_t>(73, 0xBB)};
    std::string reason;
    BOOST_CHECK(!field.IsValid(reason));
}

BOOST_AUTO_TEST_CASE(field_validation_hash256_exact)
{
    RungField field{RungDataType::HASH256, MakeHash256()};
    std::string reason;
    BOOST_CHECK(field.IsValid(reason));

    // Wrong size rejected
    RungField bad{RungDataType::HASH256, std::vector<uint8_t>(31, 0xCC)};
    BOOST_CHECK(!bad.IsValid(reason));
}

BOOST_AUTO_TEST_CASE(field_validation_hash160_exact)
{
    RungField field{RungDataType::HASH160, MakeHash160()};
    std::string reason;
    BOOST_CHECK(field.IsValid(reason));

    RungField bad{RungDataType::HASH160, std::vector<uint8_t>(19, 0xDD)};
    BOOST_CHECK(!bad.IsValid(reason));
}

BOOST_AUTO_TEST_CASE(field_validation_numeric_valid)
{
    RungField field{RungDataType::NUMERIC, MakeNumeric(144)};
    std::string reason;
    BOOST_CHECK(field.IsValid(reason));

    RungField bad{RungDataType::NUMERIC, std::vector<uint8_t>(3, 0x00)};
    BOOST_CHECK(!bad.IsValid(reason));
}

BOOST_AUTO_TEST_CASE(field_validation_preimage_valid_range)
{
    // Minimum 1 byte
    RungField min_field{RungDataType::PREIMAGE, std::vector<uint8_t>(1, 0x42)};
    std::string reason;
    BOOST_CHECK(min_field.IsValid(reason));

    // Maximum 252 bytes
    RungField max_field{RungDataType::PREIMAGE, std::vector<uint8_t>(252, 0x42)};
    BOOST_CHECK(max_field.IsValid(reason));

    // 253 bytes rejected
    RungField bad{RungDataType::PREIMAGE, std::vector<uint8_t>(253, 0x42)};
    BOOST_CHECK(!bad.IsValid(reason));
}

BOOST_AUTO_TEST_CASE(field_validation_new_types)
{
    // PUBKEY_COMMIT: exactly 32 bytes
    RungField pk_commit{RungDataType::PUBKEY_COMMIT, std::vector<uint8_t>(32, 0xAA)};
    std::string reason;
    BOOST_CHECK(pk_commit.IsValid(reason));
    RungField pk_commit_bad{RungDataType::PUBKEY_COMMIT, std::vector<uint8_t>(31, 0xAA)};
    BOOST_CHECK(!pk_commit_bad.IsValid(reason));

    // SPEND_INDEX: exactly 4 bytes
    RungField spend_idx{RungDataType::SPEND_INDEX, MakeNumeric(0)};
    BOOST_CHECK(spend_idx.IsValid(reason));

    // SCHEME: exactly 1 byte
    RungField scheme_schnorr{RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::SCHNORR)}};
    BOOST_CHECK(scheme_schnorr.IsValid(reason));
    RungField scheme_ecdsa{RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::ECDSA)}};
    BOOST_CHECK(scheme_ecdsa.IsValid(reason));
    // Unknown scheme rejected
    RungField scheme_bad{RungDataType::SCHEME, {0xFF}};
    BOOST_CHECK(!scheme_bad.IsValid(reason));
}

BOOST_AUTO_TEST_CASE(known_type_checks)
{
    // Block types — uint16_t
    BOOST_CHECK(IsKnownBlockType(0x0001)); // SIG
    BOOST_CHECK(IsKnownBlockType(0x0002)); // MULTISIG
    BOOST_CHECK(IsKnownBlockType(0x0003)); // ADAPTOR_SIG
    BOOST_CHECK(IsKnownBlockType(0x0101)); // CSV
    BOOST_CHECK(IsKnownBlockType(0x0201)); // HASH_PREIMAGE
    BOOST_CHECK(IsKnownBlockType(0x0301)); // CTV (Phase 2 stub)
    BOOST_CHECK(IsKnownBlockType(0x0401)); // RECURSE_UNTIL (Phase 3 stub)
    BOOST_CHECK(IsKnownBlockType(0x0501)); // ANCHOR_CHANNEL (Phase 2 stub)
    BOOST_CHECK(!IsKnownBlockType(0x0000));
    BOOST_CHECK(!IsKnownBlockType(0x0004)); // gap
    BOOST_CHECK(!IsKnownBlockType(0xFFFF));

    // Data types — uint8_t
    BOOST_CHECK(IsKnownDataType(0x01)); // PUBKEY
    BOOST_CHECK(IsKnownDataType(0x09)); // SCHEME
    BOOST_CHECK(!IsKnownDataType(0x00));
    BOOST_CHECK(!IsKnownDataType(0x0A));
}

// ============================================================================
// Serialization tests (v2 wire format)
// ============================================================================

BOOST_AUTO_TEST_CASE(serialize_roundtrip_sig_block)
{
    LadderWitness ladder;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung.blocks.push_back(block);
    ladder.rungs.push_back(rung);

    auto bytes = SerializeLadderWitness(ladder);
    BOOST_CHECK(!bytes.empty());

    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(DeserializeLadderWitness(bytes, decoded, error));
    BOOST_CHECK_EQUAL(decoded.rungs.size(), 1u);
    BOOST_CHECK_EQUAL(decoded.rungs[0].blocks.size(), 1u);
    BOOST_CHECK(decoded.rungs[0].blocks[0].type == RungBlockType::SIG);
    BOOST_CHECK(!decoded.rungs[0].blocks[0].inverted);
    BOOST_CHECK_EQUAL(decoded.rungs[0].blocks[0].fields.size(), 2u);
    BOOST_CHECK(decoded.rungs[0].blocks[0].fields[0].type == RungDataType::PUBKEY);
    BOOST_CHECK_EQUAL(decoded.rungs[0].blocks[0].fields[0].data.size(), 33u);
    BOOST_CHECK(decoded.rungs[0].blocks[0].fields[1].type == RungDataType::SIGNATURE);
    BOOST_CHECK_EQUAL(decoded.rungs[0].blocks[0].fields[1].data.size(), 64u);
    // Default coil (per-ladder, not per-rung)
    BOOST_CHECK(decoded.coil.coil_type == RungCoilType::UNLOCK);
    BOOST_CHECK(decoded.coil.attestation == RungAttestationMode::INLINE);
    BOOST_CHECK(decoded.coil.scheme == RungScheme::SCHNORR);
}

BOOST_AUTO_TEST_CASE(serialize_roundtrip_multi_rung)
{
    LadderWitness ladder;

    // Rung 0: SIG
    Rung rung0;
    RungBlock sig_block;
    sig_block.type = RungBlockType::SIG;
    sig_block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    sig_block.fields.push_back({RungDataType::SIGNATURE, MakeSignature()});
    rung0.blocks.push_back(sig_block);
    ladder.rungs.push_back(rung0);

    // Rung 1: HASH_PREIMAGE
    Rung rung1;
    RungBlock hash_block;
    hash_block.type = RungBlockType::HASH_PREIMAGE;
    hash_block.fields.push_back({RungDataType::HASH256, MakeHash256()});
    hash_block.fields.push_back({RungDataType::PREIMAGE, std::vector<uint8_t>(16, 0xEE)});
    rung1.blocks.push_back(hash_block);
    ladder.rungs.push_back(rung1);

    auto bytes = SerializeLadderWitness(ladder);
    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(DeserializeLadderWitness(bytes, decoded, error));
    BOOST_CHECK_EQUAL(decoded.rungs.size(), 2u);
    BOOST_CHECK(decoded.rungs[1].blocks[0].type == RungBlockType::HASH_PREIMAGE);
}

BOOST_AUTO_TEST_CASE(serialize_roundtrip_inverted_block)
{
    LadderWitness ladder;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::CSV;
    block.inverted = true;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    rung.blocks.push_back(block);
    ladder.rungs.push_back(rung);

    auto bytes = SerializeLadderWitness(ladder);
    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(DeserializeLadderWitness(bytes, decoded, error));
    BOOST_CHECK(decoded.rungs[0].blocks[0].inverted);
    BOOST_CHECK(decoded.rungs[0].blocks[0].type == RungBlockType::CSV);
}

BOOST_AUTO_TEST_CASE(serialize_roundtrip_coil)
{
    LadderWitness ladder;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung.blocks.push_back(block);
    ladder.rungs.push_back(rung);
    ladder.coil.coil_type = RungCoilType::COVENANT;
    ladder.coil.attestation = RungAttestationMode::AGGREGATE;
    ladder.coil.scheme = RungScheme::ECDSA;

    auto bytes = SerializeLadderWitness(ladder);
    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(DeserializeLadderWitness(bytes, decoded, error));
    BOOST_CHECK(decoded.coil.coil_type == RungCoilType::COVENANT);
    BOOST_CHECK(decoded.coil.attestation == RungAttestationMode::AGGREGATE);
    BOOST_CHECK(decoded.coil.scheme == RungScheme::ECDSA);
}

BOOST_AUTO_TEST_CASE(deserialize_rejects_empty)
{
    LadderWitness decoded;
    std::string error;
    std::vector<uint8_t> empty;
    BOOST_CHECK(!DeserializeLadderWitness(empty, decoded, error));
    BOOST_CHECK(error.find("empty") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(deserialize_rejects_zero_rungs)
{
    std::vector<uint8_t> data{0x00};
    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(!DeserializeLadderWitness(data, decoded, error));
    BOOST_CHECK(error.find("zero rungs") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(deserialize_rejects_unknown_block_type)
{
    // v2 wire: block_type is uint16_t LE. Use 0xFF, 0xFF (unknown)
    std::vector<uint8_t> data{
        0x01,             // 1 rung
        0x01,             // 1 block
        0xFF, 0xFF,       // unknown block type (uint16_t LE)
        0x00,             // inverted = false
        0x00,             // 0 fields
        0x01, 0x01, 0x01, // coil bytes
    };
    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(!DeserializeLadderWitness(data, decoded, error));
    BOOST_CHECK(error.find("unknown block type") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(deserialize_rejects_invalid_inverted_flag)
{
    // v2 wire: SIG block (0x01, 0x00), inverted = 0x02 (invalid)
    std::vector<uint8_t> data{
        0x01,             // 1 rung
        0x01,             // 1 block
        0x01, 0x00,       // SIG block type
        0x02,             // invalid inverted flag
        0x00,             // 0 fields
        0x01, 0x01, 0x01, // coil bytes
    };
    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(!DeserializeLadderWitness(data, decoded, error));
    BOOST_CHECK(error.find("invalid inverted") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(deserialize_rejects_unknown_data_type)
{
    // Build manually: 1 rung, 1 SIG block, 1 field with type 0xFF
    std::vector<uint8_t> data{
        0x01,             // 1 rung
        0x01,             // 1 block
        0x01, 0x00,       // SIG block type
        0x00,             // inverted = false
        0x01,             // 1 field
        0xFF,             // unknown data type
        0x01,             // 1 byte data
        0xAA,             // data
        0x01, 0x01, 0x01, // coil bytes
    };
    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(!DeserializeLadderWitness(data, decoded, error));
    BOOST_CHECK(error.find("unknown data type") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(deserialize_rejects_oversized_pubkey)
{
    LadderWitness ladder;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, std::vector<uint8_t>(34, 0x02)});
    rung.blocks.push_back(block);
    ladder.rungs.push_back(rung);

    auto bytes = SerializeLadderWitness(ladder);

    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(!DeserializeLadderWitness(bytes, decoded, error));
    BOOST_CHECK(error.find("too large") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(deserialize_rejects_trailing_bytes)
{
    LadderWitness ladder;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::CSV;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    rung.blocks.push_back(block);
    ladder.rungs.push_back(rung);

    auto bytes = SerializeLadderWitness(ladder);
    bytes.push_back(0x00); // extra trailing byte

    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(!DeserializeLadderWitness(bytes, decoded, error));
    BOOST_CHECK(error.find("trailing bytes") != std::string::npos);
}

// ============================================================================
// Evaluator tests (using mock checker)
// ============================================================================

class MockSignatureChecker : public BaseSignatureChecker
{
public:
    bool schnorr_result{false};
    bool ecdsa_result{false};
    bool locktime_result{false};
    bool sequence_result{false};

    bool CheckSchnorrSignature(std::span<const unsigned char> /*sig*/,
                               std::span<const unsigned char> /*pubkey*/,
                               SigVersion /*sigversion*/,
                               ScriptExecutionData& /*execdata*/,
                               ScriptError* /*serror*/) const override
    {
        return schnorr_result;
    }

    bool CheckECDSASignature(const std::vector<unsigned char>& /*sig*/,
                             const std::vector<unsigned char>& /*pubkey*/,
                             const CScript& /*scriptCode*/,
                             SigVersion /*sigversion*/) const override
    {
        return ecdsa_result;
    }

    bool CheckLockTime(const CScriptNum& /*nLockTime*/) const override
    {
        return locktime_result;
    }

    bool CheckSequence(const CScriptNum& /*nSequence*/) const override
    {
        return sequence_result;
    }
};

BOOST_AUTO_TEST_CASE(eval_sig_block_satisfied)
{
    MockSignatureChecker checker;
    checker.schnorr_result = true;

    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalSigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_sig_block_unsatisfied)
{
    MockSignatureChecker checker;
    checker.schnorr_result = false;

    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalSigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_sig_block_missing_field)
{
    MockSignatureChecker checker;

    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalSigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_multisig_2_of_3_satisfied)
{
    MockSignatureChecker checker;
    checker.schnorr_result = true;

    RungBlock block;
    block.type = RungBlockType::MULTISIG;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2)});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalMultisigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_multisig_insufficient_sigs)
{
    MockSignatureChecker checker;
    checker.schnorr_result = true;

    RungBlock block;
    block.type = RungBlockType::MULTISIG;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2)});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalMultisigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_hash_preimage_sha256_satisfied)
{
    std::vector<uint8_t> preimage{0x01, 0x02, 0x03, 0x04};
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(hash);

    RungBlock block;
    block.type = RungBlockType::HASH_PREIMAGE;
    block.fields.push_back({RungDataType::HASH256, std::vector<uint8_t>(hash, hash + 32)});
    block.fields.push_back({RungDataType::PREIMAGE, preimage});

    BOOST_CHECK(EvalHashPreimageBlock(block) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_hash_preimage_sha256_wrong)
{
    std::vector<uint8_t> preimage{0x01, 0x02, 0x03, 0x04};
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(hash);

    std::vector<uint8_t> wrong_preimage{0x05, 0x06, 0x07, 0x08};

    RungBlock block;
    block.type = RungBlockType::HASH_PREIMAGE;
    block.fields.push_back({RungDataType::HASH256, std::vector<uint8_t>(hash, hash + 32)});
    block.fields.push_back({RungDataType::PREIMAGE, wrong_preimage});

    BOOST_CHECK(EvalHashPreimageBlock(block) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_hash160_preimage_satisfied)
{
    std::vector<uint8_t> preimage{0x01, 0x02, 0x03, 0x04};
    unsigned char hash[CHash160::OUTPUT_SIZE];
    CHash160().Write(preimage).Finalize(hash);

    RungBlock block;
    block.type = RungBlockType::HASH160_PREIMAGE;
    block.fields.push_back({RungDataType::HASH160, std::vector<uint8_t>(hash, hash + 20)});
    block.fields.push_back({RungDataType::PREIMAGE, preimage});

    BOOST_CHECK(EvalHash160PreimageBlock(block) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_csv_satisfied)
{
    MockSignatureChecker checker;
    checker.sequence_result = true;

    RungBlock block;
    block.type = RungBlockType::CSV;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});

    BOOST_CHECK(EvalCSVBlock(block, checker) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_csv_unsatisfied)
{
    MockSignatureChecker checker;
    checker.sequence_result = false;

    RungBlock block;
    block.type = RungBlockType::CSV;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});

    BOOST_CHECK(EvalCSVBlock(block, checker) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_cltv_satisfied)
{
    MockSignatureChecker checker;
    checker.locktime_result = true;

    RungBlock block;
    block.type = RungBlockType::CLTV;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(52000)});

    BOOST_CHECK(EvalCLTVBlock(block, checker) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_cltv_unsatisfied)
{
    MockSignatureChecker checker;
    checker.locktime_result = false;

    RungBlock block;
    block.type = RungBlockType::CLTV;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(52000)});

    BOOST_CHECK(EvalCLTVBlock(block, checker) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_csv_time_satisfied)
{
    MockSignatureChecker checker;
    checker.sequence_result = true;

    RungBlock block;
    block.type = RungBlockType::CSV_TIME;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0x00400080)}); // time-based flag set
    BOOST_CHECK(EvalCSVTimeBlock(block, checker) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_cltv_time_satisfied)
{
    MockSignatureChecker checker;
    checker.locktime_result = true;

    RungBlock block;
    block.type = RungBlockType::CLTV_TIME;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(500000001)}); // time-based
    BOOST_CHECK(EvalCLTVTimeBlock(block, checker) == EvalResult::SATISFIED);
}

// ============================================================================
// Inversion tests
// ============================================================================

BOOST_AUTO_TEST_CASE(inversion_apply_basic)
{
    // Not inverted — pass through
    BOOST_CHECK(ApplyInversion(EvalResult::SATISFIED, false) == EvalResult::SATISFIED);
    BOOST_CHECK(ApplyInversion(EvalResult::UNSATISFIED, false) == EvalResult::UNSATISFIED);
    BOOST_CHECK(ApplyInversion(EvalResult::ERROR, false) == EvalResult::ERROR);
    BOOST_CHECK(ApplyInversion(EvalResult::UNKNOWN_BLOCK_TYPE, false) == EvalResult::UNKNOWN_BLOCK_TYPE);

    // Inverted — flip SATISFIED↔UNSATISFIED
    BOOST_CHECK(ApplyInversion(EvalResult::SATISFIED, true) == EvalResult::UNSATISFIED);
    BOOST_CHECK(ApplyInversion(EvalResult::UNSATISFIED, true) == EvalResult::SATISFIED);
    // ERROR never flips
    BOOST_CHECK(ApplyInversion(EvalResult::ERROR, true) == EvalResult::ERROR);
    // UNKNOWN inverted → SATISFIED
    BOOST_CHECK(ApplyInversion(EvalResult::UNKNOWN_BLOCK_TYPE, true) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(inversion_sig_normal_satisfied_inverted_unsatisfied)
{
    MockSignatureChecker checker;
    checker.schnorr_result = true;

    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    ScriptExecutionData execdata;
    // Normal: satisfied
    block.inverted = false;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
    // Inverted: unsatisfied
    block.inverted = true;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(inversion_sig_normal_unsatisfied_inverted_satisfied)
{
    MockSignatureChecker checker;
    checker.schnorr_result = false;

    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    ScriptExecutionData execdata;
    block.inverted = false;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
    block.inverted = true;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(inversion_csv)
{
    MockSignatureChecker checker;
    checker.sequence_result = true;

    RungBlock block;
    block.type = RungBlockType::CSV;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)});

    ScriptExecutionData execdata;
    block.inverted = false;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
    block.inverted = true;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(inversion_hash_preimage)
{
    std::vector<uint8_t> preimage{0x01, 0x02, 0x03, 0x04};
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(hash);

    RungBlock block;
    block.type = RungBlockType::HASH_PREIMAGE;
    block.fields.push_back({RungDataType::HASH256, std::vector<uint8_t>(hash, hash + 32)});
    block.fields.push_back({RungDataType::PREIMAGE, preimage});

    MockSignatureChecker checker;
    ScriptExecutionData execdata;
    block.inverted = false;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
    block.inverted = true;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(inversion_cltv)
{
    MockSignatureChecker checker;
    checker.locktime_result = false;

    RungBlock block;
    block.type = RungBlockType::CLTV;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(52000)});

    ScriptExecutionData execdata;
    block.inverted = false;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
    block.inverted = true;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(inversion_multisig)
{
    MockSignatureChecker checker;
    checker.schnorr_result = true;

    RungBlock block;
    block.type = RungBlockType::MULTISIG;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1)});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    ScriptExecutionData execdata;
    block.inverted = false;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
    block.inverted = true;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(inversion_error_never_flips)
{
    MockSignatureChecker checker;

    // SIG with missing fields → ERROR
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    // Missing SIGNATURE

    ScriptExecutionData execdata;
    block.inverted = true;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::ERROR);
}

// ============================================================================
// Phase 2/3 stub tests
// ============================================================================

BOOST_AUTO_TEST_CASE(eval_phase2_stubs_unsatisfied)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock ctv_block;
    ctv_block.type = RungBlockType::CTV;
    BOOST_CHECK(EvalBlock(ctv_block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);

    RungBlock vault_block;
    vault_block.type = RungBlockType::VAULT_LOCK;
    BOOST_CHECK(EvalBlock(vault_block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);

    RungBlock anchor_block;
    anchor_block.type = RungBlockType::ANCHOR_CHANNEL;
    BOOST_CHECK(EvalBlock(anchor_block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_phase3_stubs_unsatisfied)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock recurse_block;
    recurse_block.type = RungBlockType::RECURSE_UNTIL;
    BOOST_CHECK(EvalBlock(recurse_block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

// ============================================================================
// Rung AND / Ladder OR logic
// ============================================================================

BOOST_AUTO_TEST_CASE(eval_rung_and_logic)
{
    MockSignatureChecker checker;
    checker.schnorr_result = true;
    checker.sequence_result = true;

    Rung rung;
    RungBlock sig_block;
    sig_block.type = RungBlockType::SIG;
    sig_block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    sig_block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung.blocks.push_back(sig_block);

    RungBlock csv_block;
    csv_block.type = RungBlockType::CSV;
    csv_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    rung.blocks.push_back(csv_block);

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalRung(rung, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_rung_and_logic_one_fails)
{
    MockSignatureChecker checker;
    checker.schnorr_result = true;
    checker.sequence_result = false; // CSV fails

    Rung rung;
    RungBlock sig_block;
    sig_block.type = RungBlockType::SIG;
    sig_block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    sig_block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung.blocks.push_back(sig_block);

    RungBlock csv_block;
    csv_block.type = RungBlockType::CSV;
    csv_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    rung.blocks.push_back(csv_block);

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalRung(rung, checker, SigVersion::LADDER, execdata) != EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_ladder_or_logic_first_rung_wins)
{
    MockSignatureChecker checker;
    checker.schnorr_result = true;

    LadderWitness ladder;

    Rung rung0;
    RungBlock block0;
    block0.type = RungBlockType::SIG;
    block0.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block0.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung0.blocks.push_back(block0);
    ladder.rungs.push_back(rung0);

    checker.sequence_result = false;
    Rung rung1;
    RungBlock block1;
    block1.type = RungBlockType::CSV;
    block1.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    rung1.blocks.push_back(block1);
    ladder.rungs.push_back(rung1);

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalLadder(ladder, checker, SigVersion::LADDER, execdata));
}

BOOST_AUTO_TEST_CASE(eval_ladder_or_logic_fallback_rung)
{
    MockSignatureChecker checker;
    checker.schnorr_result = false;
    checker.sequence_result = true;

    LadderWitness ladder;

    Rung rung0;
    RungBlock block0;
    block0.type = RungBlockType::SIG;
    block0.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block0.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung0.blocks.push_back(block0);
    ladder.rungs.push_back(rung0);

    Rung rung1;
    RungBlock block1;
    block1.type = RungBlockType::CSV;
    block1.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    rung1.blocks.push_back(block1);
    ladder.rungs.push_back(rung1);

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalLadder(ladder, checker, SigVersion::LADDER, execdata));
}

BOOST_AUTO_TEST_CASE(eval_ladder_all_rungs_fail)
{
    MockSignatureChecker checker;
    checker.schnorr_result = false;
    checker.sequence_result = false;

    LadderWitness ladder;

    Rung rung0;
    RungBlock block0;
    block0.type = RungBlockType::SIG;
    block0.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block0.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung0.blocks.push_back(block0);
    ladder.rungs.push_back(rung0);

    Rung rung1;
    RungBlock block1;
    block1.type = RungBlockType::CSV;
    block1.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    rung1.blocks.push_back(block1);
    ladder.rungs.push_back(rung1);

    ScriptExecutionData execdata;
    BOOST_CHECK(!EvalLadder(ladder, checker, SigVersion::LADDER, execdata));
}

BOOST_AUTO_TEST_CASE(eval_ladder_empty_fails)
{
    MockSignatureChecker checker;
    LadderWitness ladder;
    ScriptExecutionData execdata;
    BOOST_CHECK(!EvalLadder(ladder, checker, SigVersion::LADDER, execdata));
}

// ============================================================================
// Policy tests
// ============================================================================

static CMutableTransaction MakeRungTx(const LadderWitness& ladder)
{
    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;

    CTxIn input;
    input.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    auto witness_bytes = SerializeLadderWitness(ladder);
    input.scriptWitness.stack.push_back(witness_bytes);
    mtx.vin.push_back(input);

    CTxOut output;
    output.nValue = 50000;
    output.scriptPubKey = CScript() << OP_RETURN;
    mtx.vout.push_back(output);

    return mtx;
}

BOOST_AUTO_TEST_CASE(policy_valid_rung_tx)
{
    LadderWitness ladder;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung.blocks.push_back(block);
    ladder.rungs.push_back(rung);

    auto mtx = MakeRungTx(ladder);
    CTransaction tx(mtx);

    std::string reason;
    BOOST_CHECK(IsStandardRungTx(tx, reason));
}

BOOST_AUTO_TEST_CASE(policy_too_many_rungs)
{
    LadderWitness ladder;
    for (int i = 0; i < 17; ++i) { // MAX_RUNGS is now 16
        Rung rung;
        RungBlock block;
        block.type = RungBlockType::SIG;
        block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
        block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
        rung.blocks.push_back(block);
        ladder.rungs.push_back(rung);
    }

    auto mtx = MakeRungTx(ladder);
    CTransaction tx(mtx);

    std::string reason;
    BOOST_CHECK(!IsStandardRungTx(tx, reason));
    BOOST_CHECK(reason.find("too many rungs") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(policy_too_many_blocks)
{
    LadderWitness ladder;
    Rung rung;
    for (int i = 0; i < 9; ++i) { // MAX_BLOCKS_PER_RUNG is 8
        RungBlock block;
        block.type = RungBlockType::SIG;
        block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
        block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
        rung.blocks.push_back(block);
    }
    ladder.rungs.push_back(rung);

    auto mtx = MakeRungTx(ladder);
    CTransaction tx(mtx);

    std::string reason;
    BOOST_CHECK(!IsStandardRungTx(tx, reason));
    BOOST_CHECK(reason.find("too many blocks") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(policy_missing_witness)
{
    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;
    CTxIn input;
    input.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin.push_back(input);
    mtx.vout.push_back(CTxOut(50000, CScript() << OP_RETURN));

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(!IsStandardRungTx(tx, reason));
    BOOST_CHECK(reason.find("missing-witness") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(policy_phase2_non_standard)
{
    // Phase 2/3 block types are consensus-valid but policy-non-standard
    LadderWitness ladder;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::CTV; // Phase 2
    rung.blocks.push_back(block);
    ladder.rungs.push_back(rung);

    auto mtx = MakeRungTx(ladder);
    CTransaction tx(mtx);

    std::string reason;
    BOOST_CHECK(!IsStandardRungTx(tx, reason));
    BOOST_CHECK(reason.find("non-standard-block-type") != std::string::npos);
}

// ============================================================================
// Conditions tests
// ============================================================================

BOOST_AUTO_TEST_CASE(conditions_serialize_roundtrip)
{
    RungConditions conditions;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    rung.blocks.push_back(block);
    conditions.rungs.push_back(rung);

    CScript script = rung::SerializeRungConditions(conditions);

    BOOST_CHECK(rung::IsRungConditionsScript(script));
    BOOST_CHECK_EQUAL(script[0], rung::RUNG_CONDITIONS_PREFIX);

    RungConditions decoded;
    std::string error;
    BOOST_CHECK(rung::DeserializeRungConditions(script, decoded, error));
    BOOST_CHECK_EQUAL(decoded.rungs.size(), 1u);
    BOOST_CHECK_EQUAL(decoded.rungs[0].blocks.size(), 1u);
    BOOST_CHECK(decoded.rungs[0].blocks[0].type == RungBlockType::SIG);
    BOOST_CHECK_EQUAL(decoded.rungs[0].blocks[0].fields.size(), 1u);
    BOOST_CHECK(decoded.rungs[0].blocks[0].fields[0].type == RungDataType::PUBKEY);
}

BOOST_AUTO_TEST_CASE(conditions_roundtrip_with_inverted)
{
    RungConditions conditions;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::CSV;
    block.inverted = true;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)});
    rung.blocks.push_back(block);
    conditions.rungs.push_back(rung);

    CScript script = rung::SerializeRungConditions(conditions);

    RungConditions decoded;
    std::string error;
    BOOST_CHECK(rung::DeserializeRungConditions(script, decoded, error));
    BOOST_CHECK(decoded.rungs[0].blocks[0].inverted);
}

BOOST_AUTO_TEST_CASE(conditions_reject_signature_field)
{
    RungConditions conditions;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung.blocks.push_back(block);
    conditions.rungs.push_back(rung);

    LadderWitness ladder;
    ladder.rungs = conditions.rungs;
    auto bytes = SerializeLadderWitness(ladder);
    CScript script;
    script.push_back(rung::RUNG_CONDITIONS_PREFIX);
    script.insert(script.end(), bytes.begin(), bytes.end());

    RungConditions decoded;
    std::string error;
    BOOST_CHECK(!rung::DeserializeRungConditions(script, decoded, error));
    BOOST_CHECK(error.find("witness-only") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(conditions_reject_preimage_field)
{
    RungConditions conditions;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::HASH_PREIMAGE;
    block.fields.push_back({RungDataType::HASH256, MakeHash256()});
    block.fields.push_back({RungDataType::PREIMAGE, std::vector<uint8_t>(16, 0xEE)});
    rung.blocks.push_back(block);
    conditions.rungs.push_back(rung);

    LadderWitness ladder;
    ladder.rungs = conditions.rungs;
    auto bytes = SerializeLadderWitness(ladder);
    CScript script;
    script.push_back(rung::RUNG_CONDITIONS_PREFIX);
    script.insert(script.end(), bytes.begin(), bytes.end());

    RungConditions decoded;
    std::string error;
    BOOST_CHECK(!rung::DeserializeRungConditions(script, decoded, error));
    BOOST_CHECK(error.find("witness-only") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(conditions_not_rung_script)
{
    CScript normal_script = CScript() << OP_RETURN;
    BOOST_CHECK(!rung::IsRungConditionsScript(normal_script));

    RungConditions decoded;
    std::string error;
    BOOST_CHECK(!rung::DeserializeRungConditions(normal_script, decoded, error));
    BOOST_CHECK(error.find("not a rung") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(conditions_data_type_check)
{
    BOOST_CHECK(rung::IsConditionDataType(RungDataType::PUBKEY));
    BOOST_CHECK(rung::IsConditionDataType(RungDataType::PUBKEY_COMMIT));
    BOOST_CHECK(rung::IsConditionDataType(RungDataType::HASH256));
    BOOST_CHECK(rung::IsConditionDataType(RungDataType::HASH160));
    BOOST_CHECK(rung::IsConditionDataType(RungDataType::NUMERIC));
    BOOST_CHECK(rung::IsConditionDataType(RungDataType::SCHEME));
    BOOST_CHECK(rung::IsConditionDataType(RungDataType::SPEND_INDEX));
    BOOST_CHECK(!rung::IsConditionDataType(RungDataType::SIGNATURE));
    BOOST_CHECK(!rung::IsConditionDataType(RungDataType::PREIMAGE));
}

// ============================================================================
// Sighash tests
// ============================================================================

BOOST_AUTO_TEST_CASE(sighash_ladder_deterministic)
{
    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;

    CTxIn input;
    input.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin.push_back(input);

    CTxOut output;
    output.nValue = 50000;
    output.scriptPubKey = CScript() << OP_RETURN;
    mtx.vout.push_back(output);

    RungConditions conditions;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    rung.blocks.push_back(block);
    conditions.rungs.push_back(rung);

    CTxOut spent_out;
    spent_out.nValue = 100000;
    spent_out.scriptPubKey = rung::SerializeRungConditions(conditions);

    PrecomputedTransactionData txdata;
    txdata.Init(mtx, std::vector<CTxOut>{spent_out});
    BOOST_CHECK(txdata.m_ladder_ready);

    uint256 hash1, hash2;
    BOOST_CHECK(rung::SignatureHashLadder(txdata, mtx, 0, SIGHASH_DEFAULT, conditions, hash1));
    BOOST_CHECK(rung::SignatureHashLadder(txdata, mtx, 0, SIGHASH_DEFAULT, conditions, hash2));
    BOOST_CHECK(hash1 == hash2);
    BOOST_CHECK(hash1 != uint256::ZERO);
}

BOOST_AUTO_TEST_CASE(sighash_ladder_different_hashtypes)
{
    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;

    CTxIn input;
    input.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin.push_back(input);

    CTxOut output;
    output.nValue = 50000;
    output.scriptPubKey = CScript() << OP_RETURN;
    mtx.vout.push_back(output);

    RungConditions conditions;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    rung.blocks.push_back(block);
    conditions.rungs.push_back(rung);

    CTxOut spent_out;
    spent_out.nValue = 100000;
    spent_out.scriptPubKey = rung::SerializeRungConditions(conditions);

    PrecomputedTransactionData txdata;
    txdata.Init(mtx, std::vector<CTxOut>{spent_out});

    uint256 hash_default, hash_all, hash_none;
    BOOST_CHECK(rung::SignatureHashLadder(txdata, mtx, 0, SIGHASH_DEFAULT, conditions, hash_default));
    BOOST_CHECK(rung::SignatureHashLadder(txdata, mtx, 0, SIGHASH_ALL, conditions, hash_all));
    BOOST_CHECK(rung::SignatureHashLadder(txdata, mtx, 0, SIGHASH_NONE, conditions, hash_none));

    BOOST_CHECK(hash_default != hash_none);
    BOOST_CHECK(hash_all != hash_none);
}

BOOST_AUTO_TEST_CASE(sighash_ladder_rejects_invalid_hashtype)
{
    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;

    CTxIn input;
    input.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin.push_back(input);
    mtx.vout.push_back(CTxOut(50000, CScript() << OP_RETURN));

    RungConditions conditions;

    CTxOut spent_out;
    spent_out.nValue = 100000;
    spent_out.scriptPubKey = CScript() << OP_RETURN;

    PrecomputedTransactionData txdata;
    txdata.Init(mtx, std::vector<CTxOut>{spent_out});

    uint256 hash;
    BOOST_CHECK(!rung::SignatureHashLadder(txdata, mtx, 0, 0x04, conditions, hash));
}

// ============================================================================
// Output policy tests
// ============================================================================

BOOST_AUTO_TEST_CASE(policy_valid_rung_output)
{
    RungConditions conditions;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    rung.blocks.push_back(block);
    conditions.rungs.push_back(rung);

    CScript script = rung::SerializeRungConditions(conditions);

    std::string reason;
    BOOST_CHECK(rung::IsStandardRungOutput(script, reason));
}

BOOST_AUTO_TEST_CASE(policy_rung_output_rejects_signature_field)
{
    LadderWitness ladder;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung.blocks.push_back(block);
    ladder.rungs.push_back(rung);

    auto bytes = SerializeLadderWitness(ladder);
    CScript script;
    script.push_back(rung::RUNG_CONDITIONS_PREFIX);
    script.insert(script.end(), bytes.begin(), bytes.end());

    std::string reason;
    BOOST_CHECK(!rung::IsStandardRungOutput(script, reason));
}

BOOST_AUTO_TEST_CASE(policy_rung_output_rejects_non_conditions)
{
    CScript script = CScript() << OP_RETURN;
    std::string reason;
    BOOST_CHECK(!rung::IsStandardRungOutput(script, reason));
}

// ============================================================================
// Merge failure tests
// ============================================================================

BOOST_AUTO_TEST_CASE(merge_rung_count_mismatch)
{
    RungConditions conditions;
    Rung cond_rung;
    RungBlock cond_block;
    cond_block.type = RungBlockType::SIG;
    cond_block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    cond_rung.blocks.push_back(cond_block);
    conditions.rungs.push_back(cond_rung);

    LadderWitness witness;
    Rung wit_rung0;
    RungBlock wit_block0;
    wit_block0.type = RungBlockType::SIG;
    wit_block0.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    wit_rung0.blocks.push_back(wit_block0);
    witness.rungs.push_back(wit_rung0);

    Rung wit_rung1;
    RungBlock wit_block1;
    wit_block1.type = RungBlockType::CSV;
    wit_rung1.blocks.push_back(wit_block1);
    witness.rungs.push_back(wit_rung1);

    CScript cond_script = rung::SerializeRungConditions(conditions);

    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;
    CTxIn input;
    input.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    auto wit_bytes = SerializeLadderWitness(witness);
    input.scriptWitness.stack.push_back(wit_bytes);
    mtx.vin.push_back(input);
    mtx.vout.push_back(CTxOut(50000, CScript() << OP_RETURN));

    CTxOut spent_out;
    spent_out.nValue = 100000;
    spent_out.scriptPubKey = cond_script;

    CTransaction tx(mtx);
    PrecomputedTransactionData txdata;
    txdata.Init(mtx, std::vector<CTxOut>{spent_out});

    MockSignatureChecker checker;
    ScriptError serror;
    BOOST_CHECK(!VerifyRungTx(tx, 0, spent_out, 0, checker, txdata, &serror));
}

BOOST_AUTO_TEST_CASE(merge_block_count_mismatch)
{
    RungConditions conditions;
    Rung cond_rung;
    RungBlock cond_sig;
    cond_sig.type = RungBlockType::SIG;
    cond_sig.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    cond_rung.blocks.push_back(cond_sig);
    RungBlock cond_csv;
    cond_csv.type = RungBlockType::CSV;
    cond_csv.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)});
    cond_rung.blocks.push_back(cond_csv);
    conditions.rungs.push_back(cond_rung);

    LadderWitness witness;
    Rung wit_rung;
    RungBlock wit_block;
    wit_block.type = RungBlockType::SIG;
    wit_block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    wit_rung.blocks.push_back(wit_block);
    witness.rungs.push_back(wit_rung);

    CScript cond_script = rung::SerializeRungConditions(conditions);

    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;
    CTxIn input;
    input.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    auto wit_bytes = SerializeLadderWitness(witness);
    input.scriptWitness.stack.push_back(wit_bytes);
    mtx.vin.push_back(input);
    mtx.vout.push_back(CTxOut(50000, CScript() << OP_RETURN));

    CTxOut spent_out;
    spent_out.nValue = 100000;
    spent_out.scriptPubKey = cond_script;

    CTransaction tx(mtx);
    PrecomputedTransactionData txdata;
    txdata.Init(mtx, std::vector<CTxOut>{spent_out});

    MockSignatureChecker checker;
    ScriptError serror;
    BOOST_CHECK(!VerifyRungTx(tx, 0, spent_out, 0, checker, txdata, &serror));
}

BOOST_AUTO_TEST_CASE(merge_block_type_mismatch)
{
    RungConditions conditions;
    Rung cond_rung;
    RungBlock cond_block;
    cond_block.type = RungBlockType::SIG;
    cond_block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    cond_rung.blocks.push_back(cond_block);
    conditions.rungs.push_back(cond_rung);

    LadderWitness witness;
    Rung wit_rung;
    RungBlock wit_block;
    wit_block.type = RungBlockType::CSV; // Wrong type!
    wit_rung.blocks.push_back(wit_block);
    witness.rungs.push_back(wit_rung);

    CScript cond_script = rung::SerializeRungConditions(conditions);

    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;
    CTxIn input;
    input.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    auto wit_bytes = SerializeLadderWitness(witness);
    input.scriptWitness.stack.push_back(wit_bytes);
    mtx.vin.push_back(input);
    mtx.vout.push_back(CTxOut(50000, CScript() << OP_RETURN));

    CTxOut spent_out;
    spent_out.nValue = 100000;
    spent_out.scriptPubKey = cond_script;

    CTransaction tx(mtx);
    PrecomputedTransactionData txdata;
    txdata.Init(mtx, std::vector<CTxOut>{spent_out});

    MockSignatureChecker checker;
    ScriptError serror;
    BOOST_CHECK(!VerifyRungTx(tx, 0, spent_out, 0, checker, txdata, &serror));
}

BOOST_AUTO_TEST_CASE(eval_multisig_below_threshold)
{
    MockSignatureChecker checker;
    checker.schnorr_result = false;

    RungBlock block;
    block.type = RungBlockType::MULTISIG;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2)});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalMultisigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_hash160_preimage_wrong)
{
    std::vector<uint8_t> preimage{0x01, 0x02, 0x03, 0x04};
    unsigned char hash[CHash160::OUTPUT_SIZE];
    CHash160().Write(preimage).Finalize(hash);

    std::vector<uint8_t> wrong_preimage{0xAA, 0xBB, 0xCC, 0xDD};

    RungBlock block;
    block.type = RungBlockType::HASH160_PREIMAGE;
    block.fields.push_back({RungDataType::HASH160, std::vector<uint8_t>(hash, hash + 20)});
    block.fields.push_back({RungDataType::PREIMAGE, wrong_preimage});

    BOOST_CHECK(EvalHash160PreimageBlock(block) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_sig_ecdsa_wrong_key)
{
    MockSignatureChecker checker;
    checker.ecdsa_result = false;

    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(71)});

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalSigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_SUITE_END()
