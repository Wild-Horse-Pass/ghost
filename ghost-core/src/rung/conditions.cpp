// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/conditions.h>
#include <rung/serialize.h>

#include <streams.h>
#include <util/strencodings.h>

namespace rung {

bool IsConditionDataType(RungDataType type)
{
    switch (type) {
    case RungDataType::PUBKEY_COMMIT:
    case RungDataType::HASH256:
    case RungDataType::HASH160:
    case RungDataType::NUMERIC:
    case RungDataType::SCHEME:
    case RungDataType::SPEND_INDEX:
        return true;
    case RungDataType::PUBKEY:
    case RungDataType::SIGNATURE:
    case RungDataType::PREIMAGE:
        return false;
    }
    return false;
}

bool IsRungConditionsScript(const CScript& scriptPubKey)
{
    return scriptPubKey.size() >= 2 && scriptPubKey[0] == RUNG_CONDITIONS_PREFIX;
}

bool DeserializeRungConditions(const CScript& scriptPubKey, RungConditions& out, std::string& error)
{
    if (!IsRungConditionsScript(scriptPubKey)) {
        error = "not a rung conditions script";
        return false;
    }

    // Strip the prefix byte
    std::vector<uint8_t> data(scriptPubKey.begin() + 1, scriptPubKey.end());

    if (data.empty()) {
        error = "empty conditions data";
        return false;
    }

    DataStream ss{data};

    try {
        uint64_t n_rungs = ReadCompactSize(ss);

        if (n_rungs == 0) {
            // Template mode: n_rungs==0 signals template inheritance
            uint64_t input_index = ReadCompactSize(ss);
            uint64_t n_diffs = ReadCompactSize(ss);

            if (n_diffs > MAX_FIELDS_PER_BLOCK * MAX_BLOCKS_PER_RUNG * MAX_RUNGS) {
                error = "too many template diffs: " + std::to_string(n_diffs);
                return false;
            }

            TemplateReference ref;
            ref.input_index = static_cast<uint32_t>(input_index);
            ref.diffs.resize(n_diffs);

            for (uint64_t d = 0; d < n_diffs; ++d) {
                ref.diffs[d].rung_index = static_cast<uint16_t>(ReadCompactSize(ss));
                ref.diffs[d].block_index = static_cast<uint16_t>(ReadCompactSize(ss));
                ref.diffs[d].field_index = static_cast<uint16_t>(ReadCompactSize(ss));

                // Read the replacement field: type + data
                uint8_t dtype_byte;
                ss >> dtype_byte;
                if (!IsKnownDataType(dtype_byte)) {
                    error = "unknown data type in template diff: 0x" +
                            HexStr(std::span<const uint8_t>{&dtype_byte, 1});
                    return false;
                }
                RungDataType dtype = static_cast<RungDataType>(dtype_byte);

                // Validate condition data type
                if (!IsConditionDataType(dtype)) {
                    error = "template diff contains witness-only data type: " + DataTypeName(dtype);
                    return false;
                }

                ref.diffs[d].new_field.type = dtype;
                if (dtype == RungDataType::NUMERIC) {
                    // Varint NUMERIC: values not sizes, skip range check
                    uint64_t val = ReadCompactSize(ss, false);
                    if (val > 0xFFFFFFFF) {
                        error = "NUMERIC value exceeds uint32 max in template diff";
                        return false;
                    }
                    // Always store as 4-byte LE for evaluator compatibility
                    ref.diffs[d].new_field.data.resize(4);
                    ref.diffs[d].new_field.data[0] = static_cast<uint8_t>(val & 0xFF);
                    ref.diffs[d].new_field.data[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
                    ref.diffs[d].new_field.data[2] = static_cast<uint8_t>((val >> 16) & 0xFF);
                    ref.diffs[d].new_field.data[3] = static_cast<uint8_t>((val >> 24) & 0xFF);
                } else {
                    uint64_t dlen = ReadCompactSize(ss);
                    size_t min_sz = FieldMinSize(dtype);
                    size_t max_sz = FieldMaxSize(dtype);
                    if (dlen < min_sz || dlen > max_sz) {
                        error = DataTypeName(dtype) + " size out of range in template diff";
                        return false;
                    }
                    ref.diffs[d].new_field.data.resize(dlen);
                    if (dlen > 0) {
                        ss.read(MakeWritableByteSpan(ref.diffs[d].new_field.data));
                    }
                }

                std::string field_reason;
                if (!ref.diffs[d].new_field.IsValid(field_reason)) {
                    error = "template diff field invalid: " + field_reason;
                    return false;
                }
            }

            // Reject trailing bytes
            if (!ss.empty()) {
                error = "trailing bytes in template reference";
                return false;
            }

            out.template_ref = std::move(ref);
            return true;
        }

        // Normal mode: deserialize via LadderWitness
        // Put n_rungs back by re-creating the data stream with the full data
        // (we already consumed n_rungs from ss, so just proceed with ss)
    } catch (const std::ios_base::failure& e) {
        error = std::string("template deserialization failure: ") + e.what();
        return false;
    }

    // Normal (non-template) path: use full LadderWitness deserialization
    LadderWitness ladder;
    if (!DeserializeLadderWitness(data, ladder, error, SerializationContext::CONDITIONS)) {
        return false;
    }

    // Validate: no witness-only fields (SIGNATURE, PREIMAGE) in conditions
    for (const auto& rung : ladder.rungs) {
        for (const auto& block : rung.blocks) {
            for (const auto& field : block.fields) {
                if (!IsConditionDataType(field.type)) {
                    error = "conditions contain witness-only data type: " + DataTypeName(field.type);
                    return false;
                }
            }
        }
    }

    // Validate relay blocks: no witness-only fields in conditions
    for (size_t i = 0; i < ladder.relays.size(); ++i) {
        for (const auto& block : ladder.relays[i].blocks) {
            for (const auto& field : block.fields) {
                if (!IsConditionDataType(field.type)) {
                    error = "relay " + std::to_string(i) + " contains witness-only data type: " + DataTypeName(field.type);
                    return false;
                }
            }
        }
    }

    out.rungs = std::move(ladder.rungs);
    out.coil = std::move(ladder.coil);
    out.relays = std::move(ladder.relays);
    return true;
}

CScript SerializeRungConditions(const RungConditions& conditions)
{
    CScript result;
    result.push_back(RUNG_CONDITIONS_PREFIX);

    if (conditions.IsTemplateRef()) {
        // Template mode: n_rungs=0 + input_index + diffs
        DataStream ss{};
        WriteCompactSize(ss, 0); // n_rungs = 0 signals template mode
        WriteCompactSize(ss, conditions.template_ref->input_index);
        WriteCompactSize(ss, conditions.template_ref->diffs.size());
        for (const auto& diff : conditions.template_ref->diffs) {
            WriteCompactSize(ss, diff.rung_index);
            WriteCompactSize(ss, diff.block_index);
            WriteCompactSize(ss, diff.field_index);
            // Write replacement field: type + data
            ss << static_cast<uint8_t>(diff.new_field.type);
            if (diff.new_field.type == RungDataType::NUMERIC) {
                uint32_t val = 0;
                for (size_t i = 0; i < diff.new_field.data.size(); ++i) {
                    val |= static_cast<uint32_t>(diff.new_field.data[i]) << (8 * i);
                }
                WriteCompactSize(ss, val);
            } else {
                WriteCompactSize(ss, diff.new_field.data.size());
                if (!diff.new_field.data.empty()) {
                    ss.write(MakeByteSpan(diff.new_field.data));
                }
            }
        }
        std::vector<uint8_t> bytes(ss.size());
        ss.read(MakeWritableByteSpan(bytes));
        result.insert(result.end(), bytes.begin(), bytes.end());
    } else {
        // Normal mode: serialize as ladder witness (CONDITIONS context)
        LadderWitness ladder;
        ladder.rungs = conditions.rungs;
        ladder.coil = conditions.coil;
        ladder.relays = conditions.relays;
        auto bytes = SerializeLadderWitness(ladder, SerializationContext::CONDITIONS);
        result.insert(result.end(), bytes.begin(), bytes.end());
    }

    return result;
}

bool ResolveTemplateReference(RungConditions& conditions,
                              const std::vector<RungConditions>& all_conditions,
                              std::string& error)
{
    if (!conditions.IsTemplateRef()) {
        error = "conditions do not have a template reference";
        return false;
    }

    const auto& ref = *conditions.template_ref;

    if (ref.input_index >= all_conditions.size()) {
        error = "template reference input_index out of range: " +
                std::to_string(ref.input_index) + " >= " +
                std::to_string(all_conditions.size());
        return false;
    }

    const auto& source = all_conditions[ref.input_index];

    // Source must not itself be a template reference (no chaining)
    if (source.IsTemplateRef()) {
        error = "template reference points to another template reference";
        return false;
    }

    // Copy conditions from source
    conditions.rungs = source.rungs;
    conditions.coil = source.coil;
    conditions.relays = source.relays;

    // Apply diffs
    for (const auto& diff : ref.diffs) {
        if (diff.rung_index >= conditions.rungs.size()) {
            error = "template diff rung_index out of range: " +
                    std::to_string(diff.rung_index);
            return false;
        }
        auto& rung = conditions.rungs[diff.rung_index];
        if (diff.block_index >= rung.blocks.size()) {
            error = "template diff block_index out of range: " +
                    std::to_string(diff.block_index);
            return false;
        }
        auto& block = rung.blocks[diff.block_index];
        if (diff.field_index >= block.fields.size()) {
            error = "template diff field_index out of range: " +
                    std::to_string(diff.field_index);
            return false;
        }

        // Replace the field (type must match for safety)
        if (block.fields[diff.field_index].type != diff.new_field.type) {
            error = "template diff type mismatch at rung " +
                    std::to_string(diff.rung_index) + " block " +
                    std::to_string(diff.block_index) + " field " +
                    std::to_string(diff.field_index) + ": expected " +
                    DataTypeName(block.fields[diff.field_index].type) +
                    ", got " + DataTypeName(diff.new_field.type);
            return false;
        }
        block.fields[diff.field_index] = diff.new_field;
    }

    // Clear template reference — conditions are now fully resolved
    conditions.template_ref.reset();
    return true;
}

} // namespace rung
