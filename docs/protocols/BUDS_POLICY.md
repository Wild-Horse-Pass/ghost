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
//| FILE: BUDS_POLICY.md                                                                                                 |
//|======================================================================================================================|
```

# BUDS Policy

Bitcoin Unified Data Standard for transaction classification and mempool filtering.

## Overview

BUDS (Bitcoin Unified Data Standard) is a classification system that categorizes transaction data by type and location. This enables nodes to implement policy-based filtering for mempool acceptance and block building.

**Key principle**: Each node chooses its own policy. There is no network-wide mandate.

## Tier System

Transactions are classified into tiers based on their data content:

| Tier | Name | Description | Default Policy |
|------|------|-------------|----------------|
| T0 | Consensus | Required for validation (sigs, scripts) | Always allow |
| T1 | Economic | Standard Bitcoin usage (payments, L2) | Generally allow |
| T2 | Metadata | Application data (inscriptions, tokens) | Policy decision |
| T3 | Unknown | Unclassified or obfuscated data | Generally reject |

### T0: Consensus (Always Required)

Data that Bitcoin consensus rules require:
- Signatures (ECDSA, Schnorr)
- Public keys
- Script opcodes
- Tapscript

**Cannot be filtered** - removing these breaks transactions.

### T1: Economic (Standard Bitcoin)

Traditional financial use of Bitcoin:
- Standard payments (P2PKH, P2WPKH, P2TR)
- Multisig outputs
- Hash time-locked contracts (HTLCs)
- Lightning Network commitments
- Small OP_RETURN (≤80 bytes, needed for L2)

**Default: Allow** - this is what Bitcoin was designed for.

### T2: Metadata (Application Data)

Data embedded in transactions for non-financial purposes:
- Ordinals inscriptions
- BRC-20 tokens
- Runes protocol
- Large OP_RETURN (>80 bytes)
- Excessive witness data

**Default: Policy decision** - node operator chooses.

### T3: Unknown (Suspicious)

Data that doesn't match known patterns:
- Obfuscated data
- Unknown encoding schemes
- Potential steganography

**Default: Reject** - if we don't know what it is, be cautious.

## Surfaces

Where data appears in a transaction:

| Surface | Description |
|---------|-------------|
| scriptpubkey | Output scripts |
| witness_stack | Witness data elements |
| witness_script | P2WSH/P2TR scripts |
| scriptsig | Legacy input scripts |
| coinbase | Coinbase data field |

## Label Categories

### Consensus Labels (T0)

```
consensus.sig           - Signatures
consensus.pubkey        - Public keys
consensus.script        - Script opcodes
consensus.tapscript     - Tapscript
```

### Payment Labels (T1)

```
pay.standard            - Standard P2PKH/P2WPKH
pay.multisig            - Multisig outputs
pay.p2sh                - Pay-to-script-hash
pay.p2tr                - Pay-to-taproot
```

### Contract Labels (T1)

```
contracts.htlc          - Hash time-locked contracts
contracts.vault         - Vault constructs
contracts.timelock      - Timelocked outputs
```

### Commitment Labels (T1)

```
commitment.lightning    - Lightning Network
commitment.sidechain    - Sidechain anchors
commitment.ghostpay     - Ghost Pay L2
```

### Metadata Labels (T2)

```
meta.inscription        - Ordinals inscriptions
meta.ordinal            - Ordinal envelope
meta.brc20              - BRC-20 tokens
meta.runes              - Runes protocol
meta.pool_tag           - Pool identification
```

### Data Anchoring Labels (T1/T2/T3)

```
da.op_return_small      - OP_RETURN ≤80 bytes (T1)
da.op_return_large      - OP_RETURN >80 bytes (T2)
da.excessive_witness    - Witness >400 bytes per input (T2)
da.unknown              - Unknown data pattern (T3)
da.obfuscated           - Appears obfuscated (T3)
```

## Classification Process

```rust
fn classify_transaction(tx: &[u8], is_coinbase: bool) -> ClassificationResult {
    // 1. Parse transaction structure
    let parsed = parse_transaction(tx);

    // 2. Classify each element
    let mut labels = Vec::new();

    // Classify outputs
    for output in parsed.outputs {
        labels.extend(classify_scriptpubkey(&output.script_pubkey));
    }

    // Classify inputs
    for input in parsed.inputs {
        if let Some(witness) = &input.witness {
            labels.extend(classify_witness(witness));
        }
        if let Some(script_sig) = &input.script_sig {
            labels.extend(classify_scriptsig(script_sig));
        }
    }

    // 3. Determine highest tier (ARBDA score)
    let arbda = labels.iter().map(|l| l.tier()).max().unwrap_or(T0);

    ClassificationResult { labels, arbda }
}
```

### ARBDA Score

ARBDA (Arbitrary Data) score is the highest tier found in a transaction:

```
Transaction with:
├── pay.standard (T1)
├── consensus.sig (T0)
└── meta.inscription (T2)

ARBDA = T2 (highest tier present)
```

## Policy Profiles

Pre-defined policy profiles for common use cases:

### bitcoin_pure (T0 + T1)

Only financial transactions:
- Payments (P2PKH, P2WPKH, P2TR)
- Multisig
- Basic timelocks
- Small OP_RETURN (≤80 bytes for L2 commitments)

**Rejects**: Inscriptions, BRC-20, Runes, large data

### permissive (T0 + T1 + T2)

Allows most transaction types:
- Everything in bitcoin_pure
- Data anchoring (small OP_RETURN, commitments)
- Larger OP_RETURN

**Rejects**: Inscriptions, BRC-20, Runes

### full_open (All Tiers)

No restrictions:
- Accepts all valid Bitcoin transactions
- Only rejects consensus-invalid transactions

## Small OP_RETURN Exception

**Important**: OP_RETURN ≤80 bytes is explicitly allowed in all profiles.

Why? It's required for:
- Lightning Network channel commitments
- Ghost Pay L1 settlement anchors
- Other legitimate L2 protocol commitments

```
da.op_return_small (≤80 bytes) → T1 (allowed)
da.op_return_large (>80 bytes) → T2 (policy decision)
```

## Template Filtering

When building a block:

```
1. Receive template from Bitcoin Core
2. For each transaction:
   a. Classify using BUDS
   b. Check against node's policy
   c. If rejected: remove from template
3. Rebuild Merkle tree
4. Distribute filtered template to miners
```

### Fee Implications

Filtering high-fee transactions may reduce node's potential earnings. Node operators balance:
- Ideological preferences (e.g., no inscriptions)
- Economic incentives (higher fees)

## Configuration

```toml
[policy]
profile = "permissive"  # bitcoin_pure, permissive, full_open

# Custom overrides
[policy.overrides]
"meta.inscription" = "reject"    # Reject inscriptions even in permissive
"da.op_return_large" = "allow"   # Allow large OP_RETURN
```

## Policy Verification (+2 Shares)

Nodes can earn +2 shares by running a policy:

### Verification Endpoint

```
POST /api/v1/verify/policy
Content-Type: application/json

{
    "test_tx": "0100000001...",  // Raw transaction hex
    "policy": "bitcoin_pure"
}

Response:
{
    "accepted": false,
    "rejected_labels": ["meta.inscription"],
    "arbda_score": 2,
    "policy_matched": true,
    "verified": true
}
```

### Challenge Process

1. Verifier sends transaction known to be rejected by claimed policy
2. Node must correctly reject and identify labels
3. Pass rate ≥95% required for +2 shares

## Use Cases

### Running a "Clean" Node

Some operators prefer blocks without non-financial data:

```toml
[policy]
profile = "bitcoin_pure"
```

### Maximizing Fee Revenue

Accept everything to capture all fees:

```toml
[policy]
profile = "full_open"
```

### Custom Policy

Allow inscriptions but reject BRC-20:

```toml
[policy]
profile = "permissive"

[policy.overrides]
"meta.brc20" = "reject"
```

## Privacy Considerations

BUDS classification is:
- **Local**: Each node classifies independently
- **Non-identifying**: Labels don't reveal user identity
- **Optional**: Nodes can disable classification entirely

## Implementation Notes

### Performance

Classification must be fast (microseconds per transaction):
- Pre-compiled pattern matchers
- Early exit on first T3 match
- Cached results for mempool transactions

### Edge Cases

- **Wrapped data**: Some protocols wrap data to avoid detection
- **False positives**: Unknown patterns might be legitimate
- **New protocols**: Classifier needs updates for new patterns

## Related Documentation

- [Mining Pool](MINING_POOL.md) - How blocks are built
- [Architecture](ARCHITECTURE.md) - System overview
- [Node Capabilities](NODE_CAPABILITIES.md) - Earning +2 shares
