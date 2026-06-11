# Exorcism

*A runtime block-cleaning process. Validates each block in RAM, then strips the parts that don't matter for spending and writes only the structural skeleton to disk.*

## The problem

Bitcoin's archive grew past 600 GB. A meaningful share of that — by some estimates well over 100 GB and rising — is data that has nothing to do with whether anyone owns or spends a coin. Inscription payloads, OP_RETURN dumps, witness blobs that exist only to fit a JPG into a transaction. Once written, every full node carries it forever.

A node operator who wants to validate Bitcoin doesn't necessarily want to host that. The conventional answer is "run a pruned node" — but pruned nodes can't serve any blocks at all, breaking the network's archival fabric.

Exorcism gives node operators a third option: keep the structural archive that lets you serve blocks, drop the bytes that don't matter for validation, and reclaim the disk.

## What it is

A C++ component running inside `ghost-core`, in `src/haze/exorcism.cpp`. After Bitcoin's normal `AcceptBlock()` validates a fully-formed block in RAM, Exorcism intercepts the block on its way to disk:

```
                              normal Bitcoin Core
                                    │
   network ──► AcceptBlock() ──► validate in RAM ──► write to blk*.dat
                                    │
                              with Exorcism (hazed mode)
                                    │
   network ──► AcceptBlock() ──► validate in RAM ──► strip ──► write to gsb*.dat
                                                       │
                                                       └─► SecureZero RAM
```

Three properties make this safe:

- **Validation always uses the full block.** Stripping happens *after* the block has already passed every consensus check. The chain remains consensus-valid; the disk just doesn't keep some of the bytes.
- **The block is structurally complete after stripping.** Headers, prev-hash links, merkle root, coinbase position, transaction count, output amounts, addresses — all preserved. You can still serve `getblock` requests, still re-verify the chain at any height, still respond to peer block requests. What's gone is the *contents* of fields that don't influence ownership.
- **Stripped data is securely zeroed in RAM.** `SecureZero()` uses volatile pointer casts so the compiler doesn't optimise the memset away. Hazeable bytes spend ~milliseconds in memory and zero seconds on disk.

## What gets stripped

Specifically these four categories:

| Field | Why it can go | Why validation already finished with it |
|---|---|---|
| Witness data | Carries inscription/Ordinal payloads, BRC-20 metadata, drop-stuffed pushes | Signatures already verified during `AcceptBlock()` |
| scriptSig (legacy) | Pre-SegWit signature data; modern transactions don't use it | Same — signatures already verified |
| OP_RETURN payloads | Arbitrary data attached to provably-unspendable outputs | OP_RETURN outputs are unspendable by definition; payload contents have no effect on UTXO state |
| Coinbase scriptSig | Miner's chosen extra-nonce / message field | Used only for the coinbase tag and extra-nonce search; doesn't affect anyone's balance |

What stays:

- All block headers, prev-hash links, timestamp, nonce, version, merkle root.
- Every transaction's structural skeleton: version, locktime, input count, output count.
- Every output's amount and `scriptPubKey` (the address / locking script).
- Every input's outpoint reference (which UTXO is being spent) and sequence number.
- Coinbase amount and outputs.

You can still answer "is address X owed Y satoshis at height H" from a stripped archive. You cannot reconstruct the inscription that paid those satoshis its fee.

## A worked example

Bitcoin block 800,000 weighed roughly 4 MB at the time it was mined. About 3.4 MB of that was witness data — a typical ratio for the inscription era. Ghost-core in hazed mode receives the block, validates every signature against the full witness, classifies it valid, then strips: the on-disk record is approximately 600 KB. The 3.4 MB of inscription witnesses are zeroed in RAM and never touch the SSD.

Across the entire chain at the time of writing, applying this to a full archive saves roughly 100-150 GB depending on how recently the node synced. A 1 TB SSD that was 65% full of chain data drops to ~40%.

## Two things you might confuse this with

**Pruning.** Bitcoin Core's `-prune` flag deletes old block files entirely. A pruned node can't serve any block to peers and can't be a full archive again without resyncing. Exorcism leaves *every* block file on disk, just with the inscription/data bytes removed. A node running Exorcism can still serve any block to any peer — the request is satisfied from the stripped file, which is structurally complete.

**Reaper.** Reaper rejects transactions *before* they enter a block. It refuses to mine inscription transactions in the first place. Exorcism deals with blocks that already exist on the chain — including inscriptions mined by other pools years ago that this node had no say in. The two are complementary: Reaper keeps your blocks clean going forward, Exorcism cleans up what's already there.

## Modes

A ghost-core node runs in one of two modes, set at startup:

```
-hazemode=full_archive   # Standard Bitcoin Core behaviour. Exorcism inactive.
-hazemode=hazed          # Exorcism active. Blocks stripped before disk write.
```

The mode is sticky: a node running in hazed mode writes `gsb*.dat` files (Ghost Stripped Block format) instead of `blk*.dat`. Once you've started writing GSBs, the unstripped originals were never on disk to begin with — there's nothing to revert to without resyncing the chain from a peer.

## The Exorcist (one-shot conversion)

If you already have a full archive — 600+ GB of `blk*.dat` files — and want to convert to a hazed node without re-syncing, ghost-core ships a one-time conversion tool:

```bash
ghostd -hazemode=full_archive -exorcist
```

The Exorcist:

1. Loads the existing chainstate.
2. Reads each `blk*.dat` file in order.
3. Strips every block using the same logic Exorcism uses at runtime.
4. Writes the stripped output to `gsb*.dat`.
5. Generates a Legal Compliance Packet (proof of what was stripped, when, and that all stripping was reversible-from-a-peer).
6. Exits cleanly — `AppInitMain` returns false, so the process exit code is 1 even on success. Verify success by reading the completion message in stdout, not by exit status.

After the conversion, restart in hazed mode. Subsequent blocks are exorcised at runtime.

The conversion is **not reversible without resync**. The `blk*.dat` files are deleted after `gsb*.dat` is written and verified. Plan disk space accordingly during the conversion (you need ~600 GB while both file sets exist briefly).

## What Exorcism doesn't do

It's a disk-write filter, not a privacy primitive. Specifically:

- **It doesn't hide what you mined.** Coinbase scriptSig is stripped on disk, but the block was already broadcast to the network with full coinbase intact. Other nodes saw it.
- **It doesn't change what you serve.** A peer requesting a block from a hazed node receives the *stripped* block. That's fine for ordinary chain-following peers — they verify the merkle root against the stripped contents and move on. It's NOT fine if the peer specifically wants inscription content; they should sync from a full-archive node instead.
- **It doesn't prevent a malicious operator from logging.** Hazeable data passes through RAM during validation. A modified ghost-core could log it to a separate file before `SecureZero` scrubs the buffer. The default build doesn't do this; verifying the binary against the open source is the operator's responsibility.
- **It doesn't make your node "pruned".** The chain is still fully there, just structurally. `getblock <hash>` returns the full stripped block; old block requests serve normally.

## Why it exists

Two motivations, both economic:

1. **Storage cost is the largest barrier to running a Bitcoin full node.** Most operators don't care about inscription content. Exorcism removes ~25-30% of disk pressure without compromising the operator's ability to validate or serve blocks.
2. **Long-run archival diversity.** If only a handful of well-funded entities can afford to store the full unstripped chain, those become the chokepoints for archival access. A larger fleet of hazed nodes — each capable of serving the structural chain — is a healthier substrate for Bitcoin's "no trusted parties" model.

The trade-off is honest: hazed nodes participate fully in consensus and serve as block sources for chain validation, but they are NOT useful to clients who specifically want inscription content. That's a feature, not a bug.

## Source

| File | Purpose |
|---|---|
| `ghost-core/src/haze/exorcism.h` | `GhostExorcism` class, `GhostMode` enum |
| `ghost-core/src/haze/exorcism.cpp` | Stripping, `SecureZero()` |
| `ghost-core/src/haze/block_stripper.h` | Per-field stripping logic |
| `ghost-core/src/haze/stripped_block.h` | GSB on-disk format |
| `ghost-core/src/haze/legal_packet.h` | Legal Compliance Packet generator |
| `ghost-core/src/node/blockstorage.cpp` | `gsb*.dat` FlatFileSeq integration |
| `ghost-core/src/validation.cpp` | Hook in `AcceptBlock()` |
| `ghost-core/test/functional/feature_ghost_exorcism.py` | Conversion + serving end-to-end test |
