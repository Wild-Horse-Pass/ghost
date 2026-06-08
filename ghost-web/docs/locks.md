# Locks

*Quantum-safe P2WSH UTXOs with two spending paths: one for normal use, one for timelocked recovery. The unit of value Ghost Pay's L2 holds on Bitcoin's L1.*

## The problem

A wallet that holds your money has to balance two opposing demands. You want to spend it efficiently — small witnesses, low fees, no information leaked about how the wallet is built. You also want to be sure that if your primary key is lost, stolen, or compromised, the funds aren't gone forever.

The standard answers — multisig, watchtowers, social recovery — all introduce counterparty risk or weaken the spending path. Ghost Locks solve it with a P2WSH script that has two branches: a cheap normal-spend branch, and a timelocked recovery branch only ever used in emergencies.

## What a Ghost Lock is

A P2WSH (Pay-to-Witness-Script-Hash) output that commits to a witness script with two spending branches:

```
P2WSH output: scriptPubKey = OP_0 <SHA256(witness_script)>

witness_script (revealed only at spend time):
    IF
        <lock_pubkey> OP_CHECKSIG          ← normal spending
    ELSE
        <recovery_blocks> OP_CSV OP_DROP
        <recovery_pubkey> OP_CHECKSIG      ← emergency recovery
    ENDIF
```

**Normal path (IF branch):** spend by signing with `lock_pubkey`. The witness reveals the witness script and a signature; the recovery branch is never executed but the recovery pubkey *is* visible inside the script at spend time.

**Recovery path (ELSE branch):** only spendable once the relative timelock `recovery_blocks` has elapsed since the UTXO was confirmed. Spend by signing with `recovery_pubkey`. Used if the primary key is lost.

The two keys are independent. The lock key can be hot — on a phone, in Ghost Tap. The recovery key should be cold — written down, on a hardware wallet, in a safety deposit box.

## Why P2WSH and not P2TR

P2TR (Taproot) addresses publish a tweaked public key directly in the scriptPubKey. Anyone watching the chain can read the pubkey of every unspent Taproot output. That's fine against classical attackers — ECDLP holds — but a sufficiently large quantum computer running Shor's algorithm could derive the private key from any published pubkey.

P2WSH publishes only the *hash* of the witness script. The pubkeys inside the script are not visible on-chain until the UTXO is spent, and only the keys actually used in that spend get revealed. This is the **quantum-safety motivation**: P2WSH defers pubkey revelation until spend, narrowing the post-quantum exposure window from "the entire lifetime of the UTXO" to "the few seconds between broadcast and confirmation". A coin sitting in a Ghost Lock for years exposes nothing exploitable to a future quantum attacker.

The `ghost-locks` crate explicitly rejects P2TR construction (see the `Quantum-unsafe output type (P2TR)` error variant) — Ghost Locks are P2WSH-only by design.

## Standard denominations

Ghost Locks come in fixed sizes, not arbitrary amounts:

| Tier | Amount | Notes |
|---|---|---|
| Micro | 10 000 sats | tiny payments |
| Tiny | 100 000 sats | small payments |
| Small | 0.01 BTC | regular payments |
| Medium | 0.1 BTC | larger transfers |
| Large | 1 BTC | big transfers |
| XL | 10 BTC | whale transfers |

This isn't a quirk — it's the privacy layer. When every Ghost Lock at a given tier is identical in size, structure, and on-chain footprint, no individual lock can be distinguished from another at the same tier. A pile of 1 000 Small locks is a single anonymity set; a pile of 1 000 random-amount UTXOs is 1 000 distinct fingerprints.

If you have 0.073 BTC to deposit, your wallet creates 7 Small locks plus 3 Tiny locks. The arithmetic is more complex than "make one UTXO" — but the privacy gain is the entire point.

## Timelock tiers

The recovery branch becomes spendable after `recovery_blocks` confirmations have elapsed (relative timelock via `OP_CSV`). Three preset tiers:

| Tier | Duration | Blocks | Use case |
|---|---|---|---|
| Short | ~6 months | 26 280 | Active funds, frequent rotation |
| Standard | ~1 year | 52 560 | Default — balanced security |
| Long | ~2 years | 105 120 | Cold storage, maximum patience for recovery |

**Shorter timelock = faster recovery if the primary key is lost.** **Longer timelock = a thief who steals only the lock key has to wait longer before the recovery key would also help them, so you have more time to react.** The trade-off is real and threat-model-specific.

## The lock ID

Every lock has a deterministic identifier:

```
lock_id = tagged_hash(
    "GhostLock/v1",
    lock_pubkey ‖ recovery_pubkey ‖ creation_height ‖ denomination_sats
)
```

The L2 (Ghost Pay) tracks balances by `lock_id`, not by Bitcoin address. When you transfer value on the L2, you're updating the L2's record of who owns which lock. The on-chain UTXO doesn't move until settlement.

This is what gives Ghost Pay its instant-finality story: an L2 transfer is a state update on a Merkle tree of `lock_id → owner` mappings. The underlying L1 UTXO is unchanged for the duration the lock lives.

## A worked example

Alice receives a 1 BTC payment. Her wallet creates a single **Large** Ghost Lock:

```
lock_pubkey       = 0x4f2c... (fresh keypair, hot)
recovery_pubkey   = 0xa8d1... (fresh keypair, written on paper, in a safe)
denomination      = Large (100 000 000 sats)
timelock_tier     = Standard (52 560 blocks)
creation_height   = 946 750
lock_id           = sha256( "GhostLock/v1" ‖ 0x4f2c... ‖ 0xa8d1... ‖ 946750 ‖ 100000000 )
                  = 0x7b93cd2f...
```

The on-chain output is `OP_0 <SHA256(witness_script)>` — a 32-byte hash. Neither pubkey is visible on chain.

Six months later Alice wants to send half a coin to Bob. She:

1. Spends her Large lock via the **normal branch** — the witness reveals the witness script and a signature from `lock_pubkey`.
2. Creates two new locks in the same transaction: one Large for Bob (his keys), one Large for herself (fresh keys).

The recovery branch isn't executed. The `recovery_pubkey` is visible in the revealed witness script (every P2WSH spend reveals the full script), but the spending key is `lock_pubkey` and only that signature is required.

If Alice loses her phone three years later, she retrieves the recovery key from the safe, waits the relative timelock for one of her locks (which begins counting from each lock's confirmation height), and spends via the recovery branch using `recovery_pubkey`.

## How locks get created

Three paths into a Ghost Lock:

1. **Wraith mixing.** You bring public BTC, run it through a Wraith session, and come out the other side with fresh Ghost Locks at the chosen denomination tier. This is the privacy-preserving entry point.
2. **From an existing lock.** Spend an existing Ghost Lock and create a new one in the same transaction. Used for transfers, payments, and rotations.
3. **Direct create.** A wallet can construct a P2WSH output that conforms to the Ghost Lock structure — useful for first-time deposits where Wraith isn't needed, but the lack of mixing means observers can correlate the deposit address with the lock.

Most users use path 1 for first deposits and path 2 for everything after.

## Jump Locks: automatic key rotation

A Ghost Lock that sits on the same key for two years grows a longer attack surface. Side-channel leaks, accumulated firmware exposure, even just the increasing chance that the key is sitting in a backup somewhere it shouldn't be. **Jump Locks** are a Ghost Lock extension that automates key rotation on a balance-tiered schedule.

The tier is set by how much value the lock holds. **Each lock's actual rotation deadline is randomised within its tier's range using a CSPRNG**, so an observer can't predict when a jump will happen — fixed periods would create timing fingerprints across a wallet's lock set.

| Tier | Balance | Rotation period | Rationale |
|---|---|---|---|
| Low | < 0.1 BTC | 30–60 days (random) | Minimal risk, infrequent rotation |
| Medium | 0.1 – 1 BTC | 14–30 days (random) | Moderate risk, regular rotation |
| High | > 1 BTC | 7–14 days (random) | High risk, frequent rotation |

The randomisation isn't cosmetic. If every High-tier lock rotated on a fixed 7-day cadence, a chain analyst could fingerprint a Ghost wallet by spotting its rotation rhythm. CSPRNG-randomised deadlines within the band make every lock's jump time independent and unpredictable.

A Jump Lock approaching its rotation deadline triggers a single atomic transaction:

```
Jump Tx
├── Input:  old Ghost Lock     (normal-branch spend)
└── Output: new Ghost Lock     (fresh lock_pubkey, same denomination)
```

The wallet generates a new lock keypair, spends the old lock via the normal branch, and creates the new one in the same transaction. The recovery key MAY be rotated at the same time or kept (the user's choice — rotating the recovery key requires updating cold backup, which most users don't want to do every 7–14 days).

After the jump:
- Old `lock_pubkey` is archived; if it's compromised later, there's nothing to spend.
- New `lock_pubkey` is active; the rotation timer resets to a fresh randomised deadline.
- On-chain: the jump looks identical to any other P2WSH-to-P2WSH spend. No flag, no metadata, no leakage.

### Grace period guidance

| Timing | Action |
|---|---|
| > 20% of period before deadline | No action |
| Inside warning threshold | Wallet starts preparing |
| 1 – 3 days before | Execute jump (recommended window) |
| At deadline | Jump urgently |
| Past deadline | Jump immediately; wallet flags degraded security |

Wallets like Ghost Tap automate this — the user typically never sees a jump happen, just a brief "rotating keys" notification.

## What Ghost Locks aren't

- **They're not channels.** Lightning Network channels require a counterparty and online watchtowers. Ghost Locks are entirely self-custodial and require neither.
- **They're not federated.** No federation, no peg-out signing, no committee of keepers. The recovery branch is a script you control, not a permissions structure.
- **They're not arbitrary-amount.** Standard denominations are mandatory for the privacy story to work. Wallets shoulder the multi-output bookkeeping; users see balances, not lock structure.
- **They're not P2TR.** P2TR exposes pubkeys in the scriptPubKey for the entire UTXO lifetime; the `ghost-locks` library refuses to build P2TR outputs. Quantum safety is not optional.
- **They're not spam-resistant by themselves.** Anyone can create a P2WSH output that looks like a Ghost Lock; the L2 only counts locks created via the protocol's prescribed flows. Random P2WSHs the wallet didn't issue won't appear in your L2 balance.
- **They're not gas-token.** Spending a Ghost Lock pays a normal Bitcoin fee from the lock's value. There's no separate fee token.

## Comparison with other custody approaches

| Property | Ghost Lock | Lightning channel | Liquid peg | Multisig |
|---|---|---|---|---|
| Recovery path | Timelocked self-custody | Requires counterparty | Federation | Quorum-of-keys |
| Quantum exposure | Low (P2WSH hides keys until spend) | Medium (channel pubkeys visible) | Medium (federation keys visible) | Medium (script reveals pubkeys) |
| Privacy on chain | High (uniform P2WSH structure across tier) | Medium (channel topology leaks) | Medium (peg-out reveals) | Low (script reveals quorum size) |
| Denominations | Fixed tiers | Any amount | Any amount | Any amount |
| Settlement | L2-batched | Per-channel close | 2-way peg | On-chain per spend |
| Custody model | Self | Self | Federated | Threshold |

Pick Ghost Locks when you want self-custody with private spending, quantum-safe storage, and a recovery path you control without requiring anyone else's cooperation.

## Source

| File | Purpose |
|---|---|
| `crates/ghost-locks/src/lock.rs` | `GhostLock` struct, ID derivation, P2WSH construction |
| `crates/ghost-locks/src/denomination.rs` | Tier constants, change-output decomposition |
| `crates/ghost-locks/src/script.rs` | Witness script + recovery branch construction, P2TR rejection |
| `crates/ghost-locks/src/jump.rs` | Jump Lock rotation logic + CSPRNG-randomised scheduling |
| `apps/ghost-tap/core/src/wallet/balance.rs` | Wallet-side lock balance tracking |
