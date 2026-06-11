# Keys

*A "Ghost ID" is a single shareable identifier that lets anyone send you Bitcoin to a fresh address every time, without you ever publishing those addresses. Each payment is unlinkable from the next on chain, only you can detect them.*

## The problem

A Bitcoin address is a wallet's mailing address. The privacy problem is that a mailing address you publish is forever — every donation, every refund, every payment to "the address on the website" lands in the same place, and anyone watching the chain sees the full history.

The conventional fix is one address per payment: ask each sender for a fresh address. That works for in-person commerce; it doesn't work for receiving tips, donations, refunds, or any payment where you can't run a real-time exchange with the sender.

Ghost Keys solve it the same way Silent Payments do — the sender and recipient can derive a unique address per payment from a shared static identifier, without an interactive exchange.

## What a Ghost ID is

Two compressed public keys, encoded as a `bech32m` string with the `ghost1` HRP:

```
ghost1<bech32m(scan_pubkey ‖ spend_pubkey)>

example: ghost1qpzry9x8gf2tvdw0s3jn54khce6mua7l...
                ↑                                ↑
                33-byte scan_pubkey              33-byte spend_pubkey
```

Behind the public ID, the wallet keeps two private keys:

| Key | Used for |
|---|---|
| `scan_secret` | Detecting payments addressed to this Ghost ID |
| `spend_secret` | Spending those payments after they're detected |

The two have completely different security postures. The `scan_secret` can be on a hot device, even shared with a trusted scanning service — it can FIND your payments but can't spend them. The `spend_secret` should be cold; a leaked spend secret means anyone with chain access can take your funds.

This split is the operational win Silent Payments offer over single-key wallets.

## Sending to a Ghost ID

The sender's wallet, given just the recipient's `ghost1...` string and the satoshi amount:

1. Generates a fresh ephemeral keypair `(e, E = e·G)` — never reused.
2. Computes a shared secret using ECDH:
   ```
   S = SHA256(e · scan_pubkey)
   ```
   Only the sender (who knows `e`) and the recipient (who knows `scan_secret`) can compute `S`. To anyone else, `E` and `scan_pubkey` are independent random points.
3. For each output to this recipient (with counter `k = 0, 1, 2, …`):
   ```
   t_k = SHA256( "ghost/silent-payment/v2" ‖ S ‖ k_le_bytes )
   P_k = spend_pubkey + t_k · G
   ```
   Each `P_k` is a fresh Taproot public key the sender uses as the output's `scriptPubKey`.
4. Includes the ephemeral pubkey `E` in a single OP_RETURN attached to the transaction (using the `GPGL` marker to indicate Ghost Pay Ghost Lock).

The result on chain: a normal-looking P2TR transaction with one OP_RETURN, no addresses anywhere that the recipient previously published.

## Detecting payments (scanning)

The recipient's wallet, watching the chain, looks at each transaction:

1. Find the OP_RETURN with the `GPGL` marker → extract `E`.
2. Compute the shared secret using their own scan key:
   ```
   S = SHA256(scan_secret · E)
   ```
   By ECDH symmetry, this `S` equals the sender's `S` — same value, computed from the other side.
3. For each output in the transaction, and for each counter `k` from 0 up to a configurable `max_k`:
   ```
   t_k = SHA256( "ghost/silent-payment/v2" ‖ S ‖ k_le_bytes )
   expected = spend_pubkey + t_k · G
   ```
   If the output's `scriptPubKey` matches `expected`, that output belongs to this Ghost ID at counter `k`.
4. For matches, derive the per-output spend key:
   ```
   spend_key_k = spend_secret + t_k    (mod n)
   ```
   This is the actual private key that controls the matched output.

The recipient never publishes a per-payment address. The sender never receives one. Everything happens through the static Ghost ID + on-chain ephemeral pubkey.

## Why v2 (counter-based k) instead of vanilla BIP-352

Bitcoin's Silent Payments draft (BIP-352) uses **output position** in the tweak:

```
BIP-352 (v1):  t = SHA256(S ‖ output_index ‖ nonce)
```

This is a problem if the transaction's outputs are shuffled — for example, by a privacy mixer like Wraith. After shuffling, output 3 becomes output 1, the recipient's scanner derives the wrong tweak, and the payment is invisible to its owner. Funds are still on chain, still spendable in principle, but the recipient cannot find them.

Ghost's v2 replaces the output index with a **per-recipient counter `k`**:

```
v2:  t_k = SHA256( "ghost/silent-payment/v2" ‖ S ‖ k_le_bytes )
```

`k` increments per recipient, not per output position. Output ordering can be shuffled freely; the recipient scans counters 0…max_k and finds their payments regardless of where they ended up in the output list.

Two practical consequences:

- **Wraith-compatible.** Wraith mixing reorders outputs for unlinkability. Without v2, mixed payments would be invisible to recipients. v2 makes Wraith and Silent Payments composable.
- **Recoverable.** If a sender used a higher `k` than your default `max_k` (10), payments are missed at first scan. Increasing `max_k` to 100 or 10 000 and rescanning the chain finds them. Vanilla BIP-352 has no equivalent recovery mechanism — if the position assumption is broken, the funds are unfindable.

The domain separator `"ghost/silent-payment/v2"` is fixed in code so v1 and v2 tweaks can never collide. The two schemes are intentionally incompatible — Ghost wallets use v2 exclusively.

## A worked example

Bob has Ghost ID `ghost1qpzry9...`. His scan_pubkey and spend_pubkey are both standard secp256k1 points; he keeps `scan_secret` on his phone and `spend_secret` on a hardware wallet.

Alice wants to send Bob 0.05 BTC for a coffee. Her wallet:

1. Generates `e = 0xa3b2...` (random), computes `E = e·G = 0x025fa9...`.
2. Computes `S = SHA256(e · Bob.scan_pubkey) = 0x8c4d2e...`.
3. With `k = 0`:
   - `t_0 = SHA256( "ghost/silent-payment/v2" ‖ 0x8c4d2e... ‖ 0x00000000 ) = 0x14ef...`
   - `P_0 = Bob.spend_pubkey + t_0·G = 0x023a8b...`
4. Builds a transaction with one P2TR output to `P_0`, value 5 000 000 sats, plus an OP_RETURN containing `GPGL ‖ E`.

Bob's wallet, polling new transactions:
- Sees the OP_RETURN, extracts `E = 0x025fa9...`.
- Computes `S = SHA256(Bob.scan_secret · E) = 0x8c4d2e...` (same value Alice computed).
- Tries `k = 0`: `t_0 = 0x14ef...`, `expected = Bob.spend_pubkey + t_0·G = 0x023a8b...` ✓ matches the transaction's only output.
- Derives `spend_key_0 = Bob.spend_secret + t_0 (mod n)`, which is the secp256k1 private key controlling 5 000 000 sats sitting on chain at output `0x023a8b...`.

Alice never received an address from Bob. Bob never published one for this payment. From an outside observer: a Taproot output going somewhere, paid by some unknown sender, with one OP_RETURN nobody can read past the marker.

## Configuration

Wallets expose one knob:

| Setting | Default | Purpose |
|---|---|---|
| `max_k` | 10 | How many counters to scan per transaction. Higher = more thorough, slightly slower. |

Scanning itself is incremental from the wallet's last-seen height — there's no fixed lookback window to configure.

Recovery operation: bump `max_k` to a high number (1 000 or 10 000) and rescan. This catches payments where the sender used many outputs to the same recipient (e.g. consolidating change). The default of 10 covers virtually all single-payment transactions.

## What Ghost Keys aren't

- **Not BIP-352 vanilla.** They use the v2 counter-based tweak, intentionally incompatible. Don't try to spend BIP-352 vanilla payments with a Ghost wallet, or vice versa.
- **Not Lightning addresses.** A Ghost ID is an on-chain receive primitive. Lightning addresses (`name@domain`) resolve through HTTP and are settled over Lightning. Different mechanism, different threat model.
- **Not anonymity.** They give you receiver privacy at the address layer — payments don't link to your shareable ID. They don't hide the *sender*'s identity, the *amount*, or the on-chain transaction graph. For sender privacy, look at Wraith. For amount privacy, look at Ghost Pay's L2 (where Ghost Locks live).
- **Not free.** Each payment includes an OP_RETURN, which costs a few sats of fee for the data carrier. Negligible per payment, but worth noting if you're projecting fee budgets for high-volume scenarios.
- **Not stateless.** The recipient must scan transactions to find their payments. Light wallets typically delegate scanning to a server (with the `scan_secret` shared) or to a watch-only full node.

## Where Ghost Keys sit

| Layer | Primitive | What it does |
|---|---|---|
| **Identity** | Ghost ID + Ghost Keys | Receive without publishing addresses |
| **Custody** | Ghost Locks | Hold funds in P2TR with timelocked recovery |
| **Privacy mix** | Wraith | Break the input-output graph |
| **L2 movement** | Ghost Pay | Move funds without on-chain transactions |

Ghost Keys are the entry layer. They produce Taproot outputs that *can* be Ghost Locks — and typically are, in practice — but the address-derivation scheme and the lock structure are independent. You can use Ghost Keys without Ghost Locks (just receive normal P2TR), and you can use Ghost Locks without Ghost Keys (use any address derivation you like).

## Source

| File | Purpose |
|---|---|
| `crates/ghost-keys/src/lib.rs` | v2 constants, domain separators |
| `crates/ghost-keys/src/derivation.rs` | Sender + receiver tweak derivation |
| `crates/ghost-keys/src/ghost_id.rs` | Ghost ID bech32m encoding/decoding |
| `crates/ghost-keys/src/scanning.rs` | Receiver-side scanning logic |
| `apps/ghost-tap/core/src/wallet/keys.rs` | Wallet integration |
