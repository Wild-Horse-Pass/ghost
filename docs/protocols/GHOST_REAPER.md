```
//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: GHOST_REAPER.md                                                                                                |
//|======================================================================================================================|
```

# Ghost Reaper Protocol

## Dead Code Detection Engine for Witness Scripts

**Version 1.0** | Bitcoin Ghost Project

---

## 1. Overview

Ghost Reaper is a dead code detection engine that analyzes Bitcoin transaction witness scripts and outputs to identify bytes that serve no purpose in script execution. Transactions containing excessive dead code are classified as "Corpses" and filtered from block templates.

Reaper operates independently from BUDS classification. BUDS classifies transaction *purpose* (policy tiers T0-T3), while Reaper classifies transaction *content* (dead bytes in witness data, scripts, and outputs). A transaction may pass BUDS policy but still be reaped if it contains dead code.

**Key properties:**
- **Two-layer defense**: Layer 1 (C++ in Ghost Core mempool) + Layer 2 (Rust in ghost-pool template)
- Layer 1 rejects common patterns before transactions enter the mempool or propagate to peers
- Layer 2 runs the full 8-vector analysis during block template construction
- Binary enabled/disabled toggle (on by default)
- Per-vector toggles for fine-grained control
- Taint-tracking stack simulator for computational witness analysis
- NOT a node capability -- does not grant shares in the 5-4-3-2-1 system

### Layer 1: Ghost Core Mempool (C++)

Fast pattern matching inside `validation.cpp:PreChecks()`, after `IsStandardTx()` but before UTXO lookups. Catches the 5 most common dead-code patterns:

1. Inscription envelopes (`OP_FALSE OP_IF ... OP_ENDIF` in witness)
2. Oversized OP_RETURN (data payload exceeding configurable limit)
3. Drop stuffing (`<push ≥76 bytes> OP_DROP` in witness)
4. Fake pubkeys in bare multisig (invalid prefix, not 0x02/0x03)
5. P2TR annex abuse (last witness element starting with 0x50)

**Configuration** (ghostd CLI):
```
-ghostreaper                 enabled/disabled (default: enabled)
-ghostreaper-maxopreturn=<n> Maximum OP_RETURN data bytes (default: 83)
-ghostreaper-mindropsize=<n> Minimum push size for drop stuffing (default: 76)
```

Rejection reason: `TX_NOT_STANDARD` with specific `ghost-reaper-*` reason strings.

### Layer 2: Ghost Pool Template (Rust)

Full 8-vector analysis with taint-tracking stack simulator during template construction. Catches everything Layer 1 catches plus computational witness analysis, unreachable code flow, and legacy scriptSig detection.

---

## 2. Verdict System

Every transaction analyzed by Reaper receives a verdict:

| Verdict | Meaning |
|---------|---------|
| **Accept** | Transaction contains no dead code |
| **Corpse** | Transaction contains dead code -- filtered from template |

### ReaperVerdict

```rust
pub struct ReaperVerdict {
    pub verdict: Verdict,              // Accept | Corpse
    pub dead_regions: Vec<DeadCodeRegion>,
    pub input_analyses: Vec<InputAnalysis>,
    pub total_dead_bytes: usize,
    pub total_witness_bytes: usize,
    pub dead_code_ratio: f64,          // dead_bytes / witness_bytes
    pub total_essential_bytes: usize,
    pub total_excess_bytes: usize,
}
```

Each dead code region identifies a specific location, type, byte offset, size, and human-readable description of the detected dead code.

---

## 3. Detection Vectors

Reaper uses 8 detection vectors organized into pattern-based and computational analysis categories.

### 3.1 Inscription Envelope

**Type:** Pattern detection
**Config:** `reject_inscription_envelope`

Detects Ordinal-style data embedding using dead conditional branches:

```
OP_FALSE OP_IF <data pushes> OP_ENDIF
```

The `OP_FALSE` guarantees the branch is never taken, making the enclosed data dead code. Both pattern matching and flow analysis identify these structures.

### 3.2 Drop Stuffing

**Type:** Pattern detection
**Config:** `reject_drop_stuffing`, `min_drop_data_size` (default: 76 bytes)

Detects large data pushes immediately followed by `OP_DROP` or `OP_2DROP`:

```
<large_push ≥76 bytes> OP_DROP
```

The pushed data is consumed and discarded, serving no script execution purpose.

### 3.3 Unreachable Code

**Type:** Flow analysis
**Config:** `reject_unreachable_code`

Detects bytecode after a top-level `OP_RETURN`. Any opcodes following `OP_RETURN` at nesting depth 0 can never execute.

### 3.4 Fake Pubkeys

**Type:** Output analysis
**Config:** `reject_fake_pubkeys`, `validate_pubkey_curve_point`

Detects data stuffing in bare multisig outputs. Two levels of detection:

1. **Invalid prefix**: Pubkey pushes in `OP_M ... OP_N OP_CHECKMULTISIG` patterns where the push does not start with `0x02` or `0x03` (compressed pubkey prefixes)
2. **Invalid curve point**: Push has valid prefix but the point is not on the secp256k1 curve (requires `validate_pubkey_curve_point` enabled)

### 3.5 Oversized OP_RETURN

**Type:** Output analysis
**Config:** `max_op_return_bytes` (default: 83 bytes)

Flags OP_RETURN outputs where the data payload exceeds the configured limit.

### 3.6 Annex Presence

**Type:** Witness analysis
**Config:** `reject_annex`

Detects P2TR witness stacks where the last element starts with `0x50` (the annex marker). Annex data is currently non-standard and serves no scriptable purpose.

### 3.7 Excess Witness Data

**Type:** Computational analysis
**Config:** `reject_excess_witness`, `min_excess_witness_bytes` (default: 500 bytes)

Uses taint-tracking simulation to identify witness bytes beyond what script execution requires. The simulator traces which witness indices contribute to stack values consumed by signature checks and other verification opcodes. Witness bytes not consumed by any execution path are flagged as excess.

Falls back to a conservative stack consumption counter when the simulator reaches safety limits (1000 stack depth, 100 IF depth, 64 branch paths).

### 3.8 Legacy scriptSig Data

**Type:** Legacy transaction analysis
**Config:** `reject_legacy_data_stuffing`, `legacy_max_push_bytes` (default: 80 bytes)

Analyzes legacy (non-SegWit) scriptSig pushes. Standard scriptSig pushes are:
- DER signatures: 71-73 bytes, prefix `0x30`
- Compressed pubkeys: 33 bytes, prefix `0x02`/`0x03`
- Uncompressed pubkeys: 65 bytes, prefix `0x04`

Pushes that don't match these patterns and exceed `legacy_max_push_bytes` are flagged as data stuffing. P2SH redeemScripts are analyzed recursively.

---

## 4. Analysis Pipeline

### Entry Point

```rust
pub fn analyze(tx: &Transaction, config: &ReaperConfig) -> ReaperVerdict
```

### Execution Flow

```
Transaction
    │
    ├── Early exit: disabled config or coinbase → Accept
    │
    ├── Per-Input Analysis
    │   ├── Identify spend type (P2TR-keypath, P2TR-scriptpath, P2WSH, P2WPKH, Legacy)
    │   ├── Pattern detection: inscription envelopes, drop stuffing
    │   ├── Flow analysis: unreachable code, dead branches, dead push-drops
    │   ├── Annex check (P2TR only)
    │   ├── Witness breakdown: taint-tracking simulator → essential vs excess bytes
    │   └── Deduplicate overlapping regions
    │
    ├── Output Analysis
    │   ├── OP_RETURN size check
    │   └── Bare multisig fake pubkey check
    │
    ├── Aggregate
    │   ├── Total dead bytes (deduplicated)
    │   ├── Dead code ratio = dead_bytes / witness_bytes
    │   └── Determine verdict based on mode + thresholds
    │
    └── Return ReaperVerdict
```

### Spend Type Identification

| Witness Stack | Condition | Type |
|---------------|-----------|------|
| 0 items, no scriptSig | -- | Empty |
| 0 items, has scriptSig | -- | Legacy |
| 1 item, 64-65 bytes | Schnorr signature | P2TR key-path |
| 2 items, item[1] = 33-byte compressed pubkey | -- | P2WPKH |
| 2+ items, last = valid control block | `len = 33 + 32k`, first byte `>= 0xc0` | P2TR script-path |
| 2+ items, otherwise | Last item = witness script | P2WSH |

### Taint-Tracking Simulator

The simulator (`simulator.rs`) executes scripts symbolically, tracking which witness indices contribute to each stack value. Items consumed by signature verification opcodes (`OP_CHECKSIG`, `OP_CHECKSIGVERIFY`, `OP_CHECKMULTISIG`, `OP_CHECKSIGADD`) mark their contributing witness indices as "essential." Witness indices not marked essential after simulation are excess.

Safety limits prevent runaway analysis:
- Maximum stack depth: 1000
- Maximum IF nesting depth: 100
- Maximum branch paths explored: 64

---

## 5. Integration

### Template Construction

Reaper runs in `TemplateProcessor.apply_custom_policy()` during block template construction:

```
Deserialize transaction
    ↓
[Reaper] analyze() → Corpse? → Filter out, continue
    ↓
[BUDS] classify() → Policy check
    ↓
Accept/Reject based on policy tier
```

Reaper filtering occurs **before** BUDS classification, removing dead-code transactions early and reducing downstream processing.

### Relationship to BUDS

| System | Classifies | Scope |
|--------|-----------|-------|
| **BUDS** | Transaction purpose | Policy tiers (T0-T3), spending categories |
| **Reaper** | Transaction content | Dead bytes in witness/scripts/outputs |

A transaction can pass BUDS policy (e.g., `PolicyProfile::full_open()`) and still be reaped. Conversely, Reaper can be disabled while keeping BUDS policy enforcement active. The two systems are independently configured and executed.

---

## 6. Configuration

### ReaperConfig

```rust
pub struct ReaperConfig {
    pub enabled: bool,

    // Per-vector toggles
    pub reject_inscription_envelope: bool,  // Default: true
    pub reject_drop_stuffing: bool,         // Default: true
    pub reject_fake_pubkeys: bool,          // Default: true
    pub reject_annex: bool,                 // Default: true
    pub reject_unreachable_code: bool,      // Default: true
    pub reject_excess_witness: bool,        // Default: true
    pub reject_legacy_data_stuffing: bool,  // Default: true

    // Detection thresholds
    pub max_op_return_bytes: usize,         // Default: 82
    pub min_drop_data_size: usize,          // Default: 76
    pub min_excess_witness_bytes: usize,    // Default: 500
    pub legacy_max_push_bytes: usize,       // Default: 80

    // EC curve validation
    pub validate_pubkey_curve_point: bool,  // Default: true
}
```

### Configurations

| Constructor | Behavior |
|-------------|----------|
| `ReaperConfig::default()` | Enabled, all toggles on, zero tolerance (default) |
| `ReaperConfig::disabled()` | No analysis performed |

### pool.toml

```toml
[reaper]
enabled = true
```

---

## 7. Source Files

| File | Purpose |
|------|---------|
| `crates/ghost-reaper/src/analyzer.rs` | Main `analyze()` entry point and verdict determination |
| `crates/ghost-reaper/src/config.rs` | `ReaperConfig`, preset configurations |
| `crates/ghost-reaper/src/verdict.rs` | `ReaperVerdict`, `DeadCodeRegion`, `Verdict` enum |
| `crates/ghost-reaper/src/dead_code.rs` | Pattern-based detection (inscription, drop stuffing) |
| `crates/ghost-reaper/src/flow.rs` | Flow analysis (dead branches, unreachable code) |
| `crates/ghost-reaper/src/witness.rs` | Spend type identification, witness breakdown |
| `crates/ghost-reaper/src/essential.rs` | Essential vs excess byte computation |
| `crates/ghost-reaper/src/simulator.rs` | Taint-tracking stack simulator |
| `crates/ghost-reaper/src/output.rs` | Output analysis (OP_RETURN, fake pubkeys) |
| `crates/ghost-reaper/src/legacy.rs` | Legacy scriptSig analysis |
| `bins/ghost-pool/src/template.rs` | Integration point (template filtering) |

---

*End of Ghost Reaper Protocol Specification*
