// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/types.h>

#include <util/strencodings.h>

namespace rung {

bool RungField::IsValid(std::string& reason) const
{
    size_t min_sz = FieldMinSize(type);
    size_t max_sz = FieldMaxSize(type);

    if (data.size() < min_sz) {
        reason = DataTypeName(type) + " too small: " + std::to_string(data.size()) + " < " + std::to_string(min_sz);
        return false;
    }
    if (data.size() > max_sz) {
        reason = DataTypeName(type) + " too large: " + std::to_string(data.size()) + " > " + std::to_string(max_sz);
        return false;
    }

    // PUBKEY must start with 0x02 or 0x03 (compressed SEC format)
    if (type == RungDataType::PUBKEY && data.size() == 33) {
        if (data[0] != 0x02 && data[0] != 0x03) {
            reason = "PUBKEY invalid prefix: 0x" + HexStr(std::span<const uint8_t>{data.data(), 1});
            return false;
        }
    }

    // SCHEME must be a known value
    if (type == RungDataType::SCHEME && data.size() == 1) {
        if (data[0] != static_cast<uint8_t>(RungScheme::SCHNORR) &&
            data[0] != static_cast<uint8_t>(RungScheme::ECDSA)) {
            reason = "SCHEME unknown value: 0x" + HexStr(std::span<const uint8_t>{data.data(), 1});
            return false;
        }
    }

    return true;
}

} // namespace rung
