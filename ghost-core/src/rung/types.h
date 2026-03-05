// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_TYPES_H
#define BITCOIN_RUNG_TYPES_H

#include <cstdint>
#include <string>
#include <vector>

namespace rung {

/** Block types for Ladder Script function blocks.
 *  Each block evaluates a single spending condition within a rung.
 *  Encoded as uint16_t in the wire format (little-endian 2 bytes).
 *
 *  Ranges:
 *    0x0001-0x00FF  Signature family (Phase 1)
 *    0x0100-0x01FF  Timelock family (Phase 1)
 *    0x0200-0x02FF  Hash family (Phase 1)
 *    0x0300-0x03FF  Covenant family (Phase 2 stubs)
 *    0x0400-0x04FF  Recursion family (Phase 3 stubs)
 *    0x0500-0x05FF  Anchor/L2 family (Phase 2 stubs) */
enum class RungBlockType : uint16_t {
    // Signature family
    SIG              = 0x0001, //!< Single signature verification
    MULTISIG         = 0x0002, //!< M-of-N threshold signature
    ADAPTOR_SIG      = 0x0003, //!< Adaptor signature (Phase 1)

    // Timelock family
    CSV              = 0x0101, //!< Relative timelock — block-height (BIP68 sequence)
    CSV_TIME         = 0x0102, //!< Relative timelock — median-time-past
    CLTV             = 0x0103, //!< Absolute timelock — block-height (nLockTime)
    CLTV_TIME        = 0x0104, //!< Absolute timelock — median-time-past

    // Hash family
    HASH_PREIMAGE    = 0x0201, //!< SHA-256 hash preimage reveal
    HASH160_PREIMAGE = 0x0202, //!< HASH160 preimage reveal
    TAGGED_HASH      = 0x0203, //!< BIP-340 tagged hash verification

    // Covenant family (Phase 2 stubs)
    CTV              = 0x0301, //!< OP_CHECKTEMPLATEVERIFY covenant
    VAULT_LOCK       = 0x0302, //!< Vault timelock covenant

    // Recursion family (Phase 3 stubs)
    RECURSE_UNTIL    = 0x0401, //!< Recursive until condition
    RECURSE_SPLIT    = 0x0402, //!< Recursive split
    RECURSE_DECAY    = 0x0403, //!< Recursive decay
    RECURSE_COLLECT  = 0x0404, //!< Recursive collect
    RECURSE_MERGE    = 0x0405, //!< Recursive merge
    RECURSE_SWEEP    = 0x0406, //!< Recursive sweep

    // Anchor/L2 family (Phase 2 stubs)
    ANCHOR_CHANNEL   = 0x0501, //!< Lightning channel anchor
    ANCHOR_POOL      = 0x0502, //!< Pool anchor
    ANCHOR_SEAL      = 0x0503, //!< Seal anchor
    ANCHOR_ORACLE    = 0x0504, //!< Oracle anchor
    ANCHOR_BOND      = 0x0505, //!< Bond anchor
    ANCHOR_ESCROW    = 0x0506, //!< Escrow anchor
};

/** Data types for typed parameters within blocks.
 *  Every byte in a Ladder Script witness must belong to one of these types.
 *  No arbitrary data pushes are possible.
 *  (Renamed from RungFieldType in v1.) */
enum class RungDataType : uint8_t {
    PUBKEY        = 0x01, //!< Compressed public key: exactly 33 bytes
    PUBKEY_COMMIT = 0x02, //!< Public key commitment: exactly 32 bytes
    HASH256       = 0x03, //!< SHA-256 hash: exactly 32 bytes
    HASH160       = 0x04, //!< RIPEMD160(SHA256()) hash: exactly 20 bytes
    PREIMAGE      = 0x05, //!< Hash preimage: 1-252 bytes
    SIGNATURE     = 0x06, //!< Schnorr or ECDSA signature: 64-72 bytes
    SPEND_INDEX   = 0x07, //!< Spend index reference: 4 bytes
    NUMERIC       = 0x08, //!< Numeric value (threshold, locktime, etc.): 4-8 bytes
    SCHEME        = 0x09, //!< Signature scheme selector: 1 byte
};

// Backward-compatible alias
using RungFieldType = RungDataType;

/** Returns true if the uint16_t is a known RungBlockType. */
inline bool IsKnownBlockType(uint16_t b)
{
    switch (static_cast<RungBlockType>(b)) {
    // Phase 1 — fully implemented
    case RungBlockType::SIG:
    case RungBlockType::MULTISIG:
    case RungBlockType::ADAPTOR_SIG:
    case RungBlockType::CSV:
    case RungBlockType::CSV_TIME:
    case RungBlockType::CLTV:
    case RungBlockType::CLTV_TIME:
    case RungBlockType::HASH_PREIMAGE:
    case RungBlockType::HASH160_PREIMAGE:
    case RungBlockType::TAGGED_HASH:
    // Phase 2 stubs
    case RungBlockType::CTV:
    case RungBlockType::VAULT_LOCK:
    case RungBlockType::ANCHOR_CHANNEL:
    case RungBlockType::ANCHOR_POOL:
    case RungBlockType::ANCHOR_SEAL:
    case RungBlockType::ANCHOR_ORACLE:
    case RungBlockType::ANCHOR_BOND:
    case RungBlockType::ANCHOR_ESCROW:
    // Phase 3 stubs
    case RungBlockType::RECURSE_UNTIL:
    case RungBlockType::RECURSE_SPLIT:
    case RungBlockType::RECURSE_DECAY:
    case RungBlockType::RECURSE_COLLECT:
    case RungBlockType::RECURSE_MERGE:
    case RungBlockType::RECURSE_SWEEP:
        return true;
    }
    return false;
}

/** Returns true if the byte is a known RungDataType. */
inline bool IsKnownDataType(uint8_t b)
{
    return b >= 0x01 && b <= 0x09;
}

// Backward-compatible alias
inline bool IsKnownFieldType(uint8_t b) { return IsKnownDataType(b); }

/** Minimum allowed size for a given data type. Returns 0 for unknown types. */
inline size_t FieldMinSize(RungDataType type)
{
    switch (type) {
    case RungDataType::PUBKEY:        return 33;
    case RungDataType::PUBKEY_COMMIT: return 32;
    case RungDataType::HASH256:       return 32;
    case RungDataType::HASH160:       return 20;
    case RungDataType::PREIMAGE:      return 1;
    case RungDataType::SIGNATURE:     return 64;
    case RungDataType::SPEND_INDEX:   return 4;
    case RungDataType::NUMERIC:       return 4;
    case RungDataType::SCHEME:        return 1;
    }
    return 0;
}

/** Maximum allowed size for a given data type. Returns 0 for unknown types. */
inline size_t FieldMaxSize(RungDataType type)
{
    switch (type) {
    case RungDataType::PUBKEY:        return 33;
    case RungDataType::PUBKEY_COMMIT: return 32;
    case RungDataType::HASH256:       return 32;
    case RungDataType::HASH160:       return 20;
    case RungDataType::PREIMAGE:      return 252;
    case RungDataType::SIGNATURE:     return 72;
    case RungDataType::SPEND_INDEX:   return 4;
    case RungDataType::NUMERIC:       return 8;
    case RungDataType::SCHEME:        return 1;
    }
    return 0;
}

/** Returns a human-readable name for a block type. */
inline std::string BlockTypeName(RungBlockType type)
{
    switch (type) {
    case RungBlockType::SIG:              return "SIG";
    case RungBlockType::MULTISIG:         return "MULTISIG";
    case RungBlockType::ADAPTOR_SIG:      return "ADAPTOR_SIG";
    case RungBlockType::CSV:              return "CSV";
    case RungBlockType::CSV_TIME:         return "CSV_TIME";
    case RungBlockType::CLTV:             return "CLTV";
    case RungBlockType::CLTV_TIME:        return "CLTV_TIME";
    case RungBlockType::HASH_PREIMAGE:    return "HASH_PREIMAGE";
    case RungBlockType::HASH160_PREIMAGE: return "HASH160_PREIMAGE";
    case RungBlockType::TAGGED_HASH:      return "TAGGED_HASH";
    case RungBlockType::CTV:              return "CTV";
    case RungBlockType::VAULT_LOCK:       return "VAULT_LOCK";
    case RungBlockType::RECURSE_UNTIL:    return "RECURSE_UNTIL";
    case RungBlockType::RECURSE_SPLIT:    return "RECURSE_SPLIT";
    case RungBlockType::RECURSE_DECAY:    return "RECURSE_DECAY";
    case RungBlockType::RECURSE_COLLECT:  return "RECURSE_COLLECT";
    case RungBlockType::RECURSE_MERGE:    return "RECURSE_MERGE";
    case RungBlockType::RECURSE_SWEEP:    return "RECURSE_SWEEP";
    case RungBlockType::ANCHOR_CHANNEL:   return "ANCHOR_CHANNEL";
    case RungBlockType::ANCHOR_POOL:      return "ANCHOR_POOL";
    case RungBlockType::ANCHOR_SEAL:      return "ANCHOR_SEAL";
    case RungBlockType::ANCHOR_ORACLE:    return "ANCHOR_ORACLE";
    case RungBlockType::ANCHOR_BOND:      return "ANCHOR_BOND";
    case RungBlockType::ANCHOR_ESCROW:    return "ANCHOR_ESCROW";
    }
    return "UNKNOWN";
}

/** Returns a human-readable name for a data type. */
inline std::string DataTypeName(RungDataType type)
{
    switch (type) {
    case RungDataType::PUBKEY:        return "PUBKEY";
    case RungDataType::PUBKEY_COMMIT: return "PUBKEY_COMMIT";
    case RungDataType::HASH256:       return "HASH256";
    case RungDataType::HASH160:       return "HASH160";
    case RungDataType::PREIMAGE:      return "PREIMAGE";
    case RungDataType::SIGNATURE:     return "SIGNATURE";
    case RungDataType::SPEND_INDEX:   return "SPEND_INDEX";
    case RungDataType::NUMERIC:       return "NUMERIC";
    case RungDataType::SCHEME:        return "SCHEME";
    }
    return "UNKNOWN";
}

// Backward-compatible alias
inline std::string FieldTypeName(RungDataType type) { return DataTypeName(type); }

/** Coil type — determines what this rung unlocks. */
enum class RungCoilType : uint8_t {
    UNLOCK    = 0x01, //!< Standard unlock — spend the output
    UNLOCK_TO = 0x02, //!< Unlock to a specific destination
    COVENANT  = 0x03, //!< Covenant — constrains the spending transaction
};

/** Attestation mode for signatures in this rung. */
enum class RungAttestationMode : uint8_t {
    INLINE    = 0x01, //!< Signatures inline in witness
    AGGREGATE = 0x02, //!< Aggregated signature (future)
    DEFERRED  = 0x03, //!< Deferred attestation (future)
};

/** Signature scheme for this rung. */
enum class RungScheme : uint8_t {
    SCHNORR   = 0x01, //!< BIP-340 Schnorr
    ECDSA     = 0x02, //!< ECDSA (legacy compat)
};

/** Coil metadata — attached to each output (LadderWitness), determines unlock semantics.
 *  UNLOCK:    Standard spend to an address.
 *  UNLOCK_TO: Send to an address, but recipient must also satisfy coil conditions.
 *  COVENANT:  Constrains the spending transaction structure via coil conditions. */
struct RungCoil {
    RungCoilType coil_type{RungCoilType::UNLOCK};
    RungAttestationMode attestation{RungAttestationMode::INLINE};
    RungScheme scheme{RungScheme::SCHNORR};
    std::vector<uint8_t> address;              //!< Destination address (raw scriptPubKey bytes), empty if none
    std::vector<struct Rung> conditions;        //!< Coil condition rungs (AND within rung, OR across rungs)
};

/** A single typed field within a block. Type constrains the allowed data size. */
struct RungField {
    RungDataType type;
    std::vector<uint8_t> data;

    /** Validate that data size conforms to the field type constraints.
     *  Returns false with reason populated on failure. */
    bool IsValid(std::string& reason) const;
};

/** A function block within a rung. Contains typed fields that the evaluator checks. */
struct RungBlock {
    RungBlockType type;
    std::vector<RungField> fields;
    bool inverted{false}; //!< If true, evaluation result is inverted (SATISFIED↔UNSATISFIED)
};

/** A single rung in a ladder. All blocks must be satisfied (AND logic). */
struct Rung {
    std::vector<RungBlock> blocks;
    uint8_t rung_id{0};   //!< Rung identifier within the ladder
};

/** The complete ladder witness for one output.
 *  Rungs define input conditions (OR logic — first satisfied rung wins).
 *  Coil defines output semantics (destination, constraints). */
struct LadderWitness {
    std::vector<Rung> rungs;     //!< Input condition rungs
    RungCoil coil;               //!< Output coil (per-output, not per-rung)

    bool IsEmpty() const { return rungs.empty(); }
};

} // namespace rung

#endif // BITCOIN_RUNG_TYPES_H
