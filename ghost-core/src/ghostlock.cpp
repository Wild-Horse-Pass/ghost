// Copyright (c) 2024-present The Ghost Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <ghostlock.h>

#include <script/interpreter.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <util/strencodings.h>

namespace ghostlock {

// Denomination values in satoshis
static constexpr std::array<CAmount, 6> DENOMINATION_VALUES = {
    10'000,         // MICRO
    100'000,        // TINY
    1'000'000,      // SMALL
    10'000'000,     // MEDIUM
    100'000'000,    // LARGE
    1'000'000'000,  // XL
};

static constexpr std::array<const char*, 6> DENOMINATION_NAMES = {
    "micro",
    "tiny",
    "small",
    "medium",
    "large",
    "xl",
};

CAmount DenominationValue(Denomination denom)
{
    return DENOMINATION_VALUES[static_cast<uint8_t>(denom)];
}

std::optional<Denomination> DenominationFromValue(CAmount value)
{
    for (size_t i = 0; i < DENOMINATION_VALUES.size(); ++i) {
        if (DENOMINATION_VALUES[i] == value) {
            return static_cast<Denomination>(i);
        }
    }
    return std::nullopt;
}

std::string DenominationName(Denomination denom)
{
    return DENOMINATION_NAMES[static_cast<uint8_t>(denom)];
}

std::optional<Denomination> DenominationFromName(const std::string& name)
{
    std::string lower = name;
    for (char& c : lower) {
        c = ToLower(c);
    }

    for (size_t i = 0; i < DENOMINATION_NAMES.size(); ++i) {
        if (lower == DENOMINATION_NAMES[i]) {
            return static_cast<Denomination>(i);
        }
    }
    return std::nullopt;
}

bool IsValidDenomination(CAmount value)
{
    return DenominationFromValue(value).has_value();
}

bool IsValidRecoveryTimelock(uint32_t timelock)
{
    return timelock >= MIN_RECOVERY_TIMELOCK && timelock <= MAX_RECOVERY_TIMELOCK;
}

CScript GhostLockScript::BuildNormalScript() const
{
    // <lock_pubkey> OP_CHECKSIG
    return CScript() << ToByteVector(lock_pubkey) << OP_CHECKSIG;
}

CScript GhostLockScript::BuildRecoveryScript() const
{
    // <timelock> OP_CHECKSEQUENCEVERIFY OP_DROP <recovery_pubkey> OP_CHECKSIG
    return CScript() << static_cast<int64_t>(recovery_timelock)
                     << OP_CHECKSEQUENCEVERIFY
                     << OP_DROP
                     << ToByteVector(recovery_pubkey)
                     << OP_CHECKSIG;
}

std::optional<XOnlyPubKey> GhostLockScript::GetOutputKey() const
{
    // Build the taproot tree
    TaprootBuilder builder;

    // Add scripts in depth-first order
    // Depth 1 means both leaves are at the same level (balanced tree)
    auto normal_script = BuildNormalScript();
    auto recovery_script = BuildRecoveryScript();

    builder.Add(1, normal_script, TAPROOT_LEAF_TAPSCRIPT);
    builder.Add(1, recovery_script, TAPROOT_LEAF_TAPSCRIPT);

    if (!builder.IsComplete()) {
        return std::nullopt;
    }

    // Finalize with the lock_pubkey as internal key
    builder.Finalize(lock_pubkey);

    if (!builder.IsValid()) {
        return std::nullopt;
    }

    // Get the tweaked output key
    WitnessV1Taproot output = builder.GetOutput();
    return XOnlyPubKey{output};
}

std::optional<uint256> GhostLockScript::GetMerkleRoot() const
{
    TaprootBuilder builder;

    auto normal_script = BuildNormalScript();
    auto recovery_script = BuildRecoveryScript();

    builder.Add(1, normal_script, TAPROOT_LEAF_TAPSCRIPT);
    builder.Add(1, recovery_script, TAPROOT_LEAF_TAPSCRIPT);

    if (!builder.IsComplete()) {
        return std::nullopt;
    }

    builder.Finalize(lock_pubkey);

    if (!builder.IsValid()) {
        return std::nullopt;
    }

    TaprootSpendData spend_data = builder.GetSpendData();
    return spend_data.merkle_root;
}

CScript GhostLockScript::BuildScriptPubKey() const
{
    auto output_key = GetOutputKey();
    if (!output_key) {
        // Return empty script on failure
        return CScript();
    }

    // Build P2TR scriptPubKey: OP_1 <32-byte output key>
    return CScript() << OP_1 << ToByteVector(*output_key);
}

CScript BuildGhostLockScript(
    const XOnlyPubKey& lock_pubkey,
    const XOnlyPubKey& recovery_pubkey,
    uint32_t recovery_timelock)
{
    GhostLockScript ghost_lock{
        .lock_pubkey = lock_pubkey,
        .recovery_pubkey = recovery_pubkey,
        .recovery_timelock = recovery_timelock,
    };

    return ghost_lock.BuildScriptPubKey();
}

std::optional<CScript> BuildGhostLockScriptWithAmount(
    const XOnlyPubKey& lock_pubkey,
    const XOnlyPubKey& recovery_pubkey,
    CAmount amount,
    uint32_t recovery_timelock)
{
    if (!IsValidDenomination(amount)) {
        return std::nullopt;
    }

    if (!IsValidRecoveryTimelock(recovery_timelock)) {
        return std::nullopt;
    }

    CScript script = BuildGhostLockScript(lock_pubkey, recovery_pubkey, recovery_timelock);
    if (script.empty()) {
        return std::nullopt;
    }

    return script;
}

bool IsGhostLockScript(const CScript& scriptPubKey)
{
    // Check if this is a valid P2TR output
    std::vector<std::vector<unsigned char>> solutions;
    TxoutType type = Solver(scriptPubKey, solutions);

    return type == TxoutType::WITNESS_V1_TAPROOT;
}

std::optional<XOnlyPubKey> ExtractP2TRKey(const CScript& scriptPubKey)
{
    std::vector<std::vector<unsigned char>> solutions;
    TxoutType type = Solver(scriptPubKey, solutions);

    if (type != TxoutType::WITNESS_V1_TAPROOT || solutions.empty()) {
        return std::nullopt;
    }

    if (solutions[0].size() != 32) {
        return std::nullopt;
    }

    XOnlyPubKey pubkey;
    std::copy(solutions[0].begin(), solutions[0].end(), pubkey.begin());

    if (!pubkey.IsFullyValid()) {
        return std::nullopt;
    }

    return pubkey;
}

std::vector<unsigned char> BuildControlBlock(
    const XOnlyPubKey& internal_key,
    const CScript& leaf_script,
    uint8_t leaf_version,
    const std::vector<uint256>& merkle_path)
{
    std::vector<unsigned char> result;

    // Control block format:
    // - 1 byte: (leaf_version & 0xfe) | (output_key_parity & 0x01)
    // - 32 bytes: internal key (x-only)
    // - 32*n bytes: merkle path

    // Note: The parity bit should be set based on the actual output key
    // For now, we use 0 as placeholder - the caller should adjust this
    result.push_back(leaf_version);

    // Append internal key
    auto key_bytes = ToByteVector(internal_key);
    result.insert(result.end(), key_bytes.begin(), key_bytes.end());

    // Append merkle path
    for (const auto& hash : merkle_path) {
        auto hash_bytes = ToByteVector(hash);
        result.insert(result.end(), hash_bytes.begin(), hash_bytes.end());
    }

    return result;
}

} // namespace ghostlock
