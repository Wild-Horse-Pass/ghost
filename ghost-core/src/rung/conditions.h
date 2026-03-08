// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_CONDITIONS_H
#define BITCOIN_RUNG_CONDITIONS_H

#include <rung/types.h>
#include <script/script.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace rung {

/** Magic prefix byte identifying a scriptPubKey as rung conditions.
 *  Chosen to not conflict with any existing OP_ prefix. */
static constexpr uint8_t RUNG_CONDITIONS_PREFIX = 0xc1;

/** A single field-level diff in a template reference. */
struct TemplateDiff {
    uint16_t rung_index;   //!< Which rung in the inherited conditions
    uint16_t block_index;  //!< Which block within that rung
    uint16_t field_index;  //!< Which field within that block
    RungField new_field;   //!< Replacement field data
};

/** Template reference: conditions inherited from another input with optional diffs. */
struct TemplateReference {
    uint32_t input_index;               //!< Which input's conditions to inherit
    std::vector<TemplateDiff> diffs;    //!< Field-level patches to apply
};

/** Rung conditions = the "locking" side of a v3 output.
 *  Stored in scriptPubKey with the same wire format as a LadderWitness
 *  but containing only condition data types (PUBKEY_COMMIT, HASH256,
 *  HASH160, NUMERIC, SCHEME, SPEND_INDEX) — never PUBKEY, SIGNATURE,
 *  or PREIMAGE. Raw public keys are witness-only; conditions use
 *  PUBKEY_COMMIT (SHA-256 of the key) to prevent arbitrary data
 *  embedding in the UTXO set.
 *
 *  When template_ref is set, n_rungs was 0 on the wire — conditions
 *  are inherited from the referenced input with diffs applied.
 *  Resolution happens in VerifyRungTx after all inputs' conditions
 *  are deserialized. */
struct RungConditions {
    std::vector<Rung> rungs;
    RungCoil coil;               //!< Output coil (per-output, serialized with conditions)
    std::vector<Relay> relays;   //!< Relay definitions (shared condition sets)
    std::optional<TemplateReference> template_ref; //!< Template inheritance reference (if set, rungs are empty until resolved)

    bool IsEmpty() const { return rungs.empty() && !template_ref.has_value(); }
    bool IsTemplateRef() const { return template_ref.has_value(); }
};

/** Quick prefix check: does this scriptPubKey start with the rung conditions prefix? */
bool IsRungConditionsScript(const CScript& scriptPubKey);

/** Deserialize rung conditions from a v3 output scriptPubKey. */
bool DeserializeRungConditions(const CScript& scriptPubKey, RungConditions& out, std::string& error);

/** Serialize rung conditions to a CScript suitable for v3 output scriptPubKey. */
CScript SerializeRungConditions(const RungConditions& conditions);

/** Resolve a template reference: copy conditions from the referenced input
 *  and apply field-level diffs.
 *  @param[in,out] conditions  The conditions with template_ref set (rungs empty).
 *                              On success, rungs/coil/relays are populated from
 *                              the referenced input and template_ref is cleared.
 *  @param[in]     all_conditions  All deserialized conditions for the transaction's inputs.
 *  @param[out]    error       Error message on failure.
 *  @return true on success. */
bool ResolveTemplateReference(RungConditions& conditions,
                              const std::vector<RungConditions>& all_conditions,
                              std::string& error);

/** Check whether a data type is allowed in conditions (locking side).
 *  SIGNATURE and PREIMAGE are witness-only and not permitted. */
bool IsConditionDataType(RungDataType type);

// Backward-compatible alias
inline bool IsConditionFieldType(RungDataType type) { return IsConditionDataType(type); }

} // namespace rung

#endif // BITCOIN_RUNG_CONDITIONS_H
