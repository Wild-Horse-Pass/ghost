// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/serialize.h>

#include <streams.h>
#include <util/strencodings.h>

#include <ios>

namespace rung {

bool DeserializeLadderWitness(const std::vector<uint8_t>& witness_bytes,
                              LadderWitness& ladder_out,
                              std::string& error)
{
    if (witness_bytes.empty()) {
        error = "empty ladder witness";
        return false;
    }

    if (witness_bytes.size() > MAX_LADDER_WITNESS_SIZE) {
        error = "ladder witness exceeds maximum size";
        return false;
    }

    DataStream ss{witness_bytes};

    try {
        uint64_t n_rungs = ReadCompactSize(ss);
        if (n_rungs == 0) {
            error = "ladder witness has zero rungs";
            return false;
        }
        if (n_rungs > MAX_RUNGS) {
            error = "too many rungs: " + std::to_string(n_rungs);
            return false;
        }

        ladder_out.rungs.resize(n_rungs);
        for (uint64_t r = 0; r < n_rungs; ++r) {
            uint64_t n_blocks = ReadCompactSize(ss);
            if (n_blocks == 0) {
                error = "rung " + std::to_string(r) + " has zero blocks";
                return false;
            }
            if (n_blocks > MAX_BLOCKS_PER_RUNG) {
                error = "rung " + std::to_string(r) + " has too many blocks: " + std::to_string(n_blocks);
                return false;
            }

            ladder_out.rungs[r].blocks.resize(n_blocks);
            for (uint64_t b = 0; b < n_blocks; ++b) {
                // Read block type — uint16_t little-endian
                uint8_t lo, hi;
                ss >> lo >> hi;
                uint16_t block_type_val = static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8);
                if (!IsKnownBlockType(block_type_val)) {
                    error = "unknown block type: 0x" + HexStr(std::vector<uint8_t>{lo, hi});
                    return false;
                }
                ladder_out.rungs[r].blocks[b].type = static_cast<RungBlockType>(block_type_val);

                // Read inverted flag — single byte, must be 0x00 or 0x01
                uint8_t inverted_byte;
                ss >> inverted_byte;
                if (inverted_byte > 0x01) {
                    error = "invalid inverted flag: 0x" + HexStr(std::span<const uint8_t>{&inverted_byte, 1});
                    return false;
                }
                ladder_out.rungs[r].blocks[b].inverted = (inverted_byte == 0x01);

                // Read fields
                uint64_t n_fields = ReadCompactSize(ss);
                if (n_fields > MAX_FIELDS_PER_BLOCK) {
                    error = "block has too many fields: " + std::to_string(n_fields);
                    return false;
                }

                ladder_out.rungs[r].blocks[b].fields.resize(n_fields);
                for (uint64_t f = 0; f < n_fields; ++f) {
                    // Read data type
                    uint8_t data_type_byte;
                    ss >> data_type_byte;
                    if (!IsKnownDataType(data_type_byte)) {
                        error = "unknown data type: 0x" + HexStr(std::span<const uint8_t>{&data_type_byte, 1});
                        return false;
                    }
                    RungDataType dtype = static_cast<RungDataType>(data_type_byte);

                    // Read data length
                    uint64_t data_len = ReadCompactSize(ss);

                    // Validate field size against type constraints
                    size_t min_sz = FieldMinSize(dtype);
                    size_t max_sz = FieldMaxSize(dtype);
                    if (data_len < min_sz) {
                        error = DataTypeName(dtype) + " too small: " + std::to_string(data_len) +
                                " < " + std::to_string(min_sz);
                        return false;
                    }
                    if (data_len > max_sz) {
                        error = DataTypeName(dtype) + " too large: " + std::to_string(data_len) +
                                " > " + std::to_string(max_sz);
                        return false;
                    }

                    // Read data
                    ladder_out.rungs[r].blocks[b].fields[f].type = dtype;
                    ladder_out.rungs[r].blocks[b].fields[f].data.resize(data_len);
                    if (data_len > 0) {
                        ss.read(MakeWritableByteSpan(ladder_out.rungs[r].blocks[b].fields[f].data));
                    }

                    // Validate field content
                    std::string field_reason;
                    if (!ladder_out.rungs[r].blocks[b].fields[f].IsValid(field_reason)) {
                        error = field_reason;
                        return false;
                    }
                }
            }

            // Read coil (3 bytes: coil_type, attestation, scheme)
            uint8_t coil_type_byte, attestation_byte, scheme_byte;
            ss >> coil_type_byte >> attestation_byte >> scheme_byte;
            ladder_out.rungs[r].coil.coil_type = static_cast<RungCoilType>(coil_type_byte);
            ladder_out.rungs[r].coil.attestation = static_cast<RungAttestationMode>(attestation_byte);
            ladder_out.rungs[r].coil.scheme = static_cast<RungScheme>(scheme_byte);
        }

        // Reject trailing bytes — no extra data allowed
        if (!ss.empty()) {
            error = "trailing bytes in ladder witness";
            return false;
        }

    } catch (const std::ios_base::failure& e) {
        error = std::string("deserialization failure: ") + e.what();
        return false;
    }

    return true;
}

std::vector<uint8_t> SerializeLadderWitness(const LadderWitness& ladder)
{
    DataStream ss{};

    WriteCompactSize(ss, ladder.rungs.size());
    for (const auto& rung : ladder.rungs) {
        WriteCompactSize(ss, rung.blocks.size());
        for (const auto& block : rung.blocks) {
            // Write block type as uint16_t little-endian
            uint16_t btype = static_cast<uint16_t>(block.type);
            ss << static_cast<uint8_t>(btype & 0xFF);
            ss << static_cast<uint8_t>((btype >> 8) & 0xFF);
            // Write inverted flag
            ss << static_cast<uint8_t>(block.inverted ? 0x01 : 0x00);
            // Write fields
            WriteCompactSize(ss, block.fields.size());
            for (const auto& field : block.fields) {
                ss << static_cast<uint8_t>(field.type);
                WriteCompactSize(ss, field.data.size());
                if (!field.data.empty()) {
                    ss.write(MakeByteSpan(field.data));
                }
            }
        }
        // Write coil (3 bytes)
        ss << static_cast<uint8_t>(rung.coil.coil_type);
        ss << static_cast<uint8_t>(rung.coil.attestation);
        ss << static_cast<uint8_t>(rung.coil.scheme);
    }

    // Extract serialized bytes
    std::vector<uint8_t> result(ss.size());
    ss.read(MakeWritableByteSpan(result));
    return result;
}

} // namespace rung
