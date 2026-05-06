# Wraith Wallet

Desktop wallet for Bitcoin Ghost. Bundles light-wallet, Wraith CoinJoin participation,
Ghost Locks custody, and TAP (L2) payments behind a single GUI / CLI / daemon.

## Workspace layout

| Crate | Role |
|---|---|
| `core/`         | `wraith-wallet-core` — all wallet logic (lib) |
| `ipc/`          | `wraith-wallet-ipc` — JSON-RPC types shared between daemon and clients |
| `daemon/`       | `wraith-wallet-daemon` — `wraithd` binary |
| `cli/`          | `wraith-wallet-cli` — `wraith` binary |
| `gui/src-tauri/`| `wraith-wallet-gui` — `wraith-gui` binary (Tauri 2 desktop shell) |

## Architecture

`wraithd` is the long-running process. It runs all module tasks (light, wraith, tap,
locks, keys, shroud) concurrently as Tokio tasks. The CLI and GUI are thin clients
that round-trip JSON-RPC envelopes over a local Unix socket — there is exactly one
IPC codepath and the GUI never links the core directly.

```
+----------+     +----------+     +-----------+
|  wraith  | --> |          | --> | ghost-pay |
|  (CLI)   |     |          |     +-----------+
+----------+     | wraithd  |
+----------+ --> |          | --> | ghost-gsp |
| wraith-  |     |          |     +-----------+
|  gui     |     +----------+
+----------+        ^
                    |
                    +--- Tor (optional, via embedded SOCKS5 proxy)
```

The wallet only ever talks to `ghost-pay` and `ghost-gsp` — it never reaches past
them to a Bitcoin node directly.

## Build

```sh
cargo build -p wraith-wallet-daemon   # produces `wraithd`
cargo build -p wraith-wallet-cli      # produces `wraith`
cargo build -p wraith-wallet-gui      # produces `wraith-gui`
```

## Local dev stack

`scripts/run-wraith-stack.sh` brings up `ghost-pay`, `ghost-gsp`, and `wraithd` on
loopback for end-to-end testing. Requires a local signet `bitcoind` (default
`http://127.0.0.1:38335`, override with `BITCOIN_RPC_URL` / `BITCOIN_RPC_USER` /
`BITCOIN_RPC_PASSWORD`).

```sh
bash scripts/run-wraith-stack.sh up      # start the stack
bash scripts/run-wraith-stack.sh status  # see what's running
bash scripts/run-wraith-stack.sh down    # tear it down
./target/debug/wraith doctor             # verify the wallet sees both services
```

Logs land in `/tmp/wraith-stack/<service>.log`.

## Shell completions

`wraith` ships generated completions for bash, zsh, fish, elvish, and powershell:

```sh
wraith completions bash > /etc/bash_completion.d/wraith
wraith completions zsh  > ~/.zfunc/_wraith         # ensure ~/.zfunc is in $fpath
wraith completions fish > ~/.config/fish/completions/wraith.fish
```

The script is generated at runtime — re-run after upgrading `wraith` to pick up new
subcommands.

## Daemon environment

`wraithd` is configured by environment variables:

| Var | Purpose | Default |
|---|---|---|
| `WRAITHD_SOCKET`     | IPC socket path                            | `$XDG_RUNTIME_DIR/wraithd-${UID}.sock` |
| `WRAITHD_WALLETS_DIR`| Encrypted keystore directory               | `$HOME/.local/share/wraithd/wallets` |
| `WRAITHD_GHOST_PAY`  | Ghost-pay URL(s), comma-separated          | `http://127.0.0.1:8800` |
| `WRAITHD_GSP`        | GSP WebSocket URL(s), comma-separated      | `ws://127.0.0.1:8900/ws/v1` |
| `WRAITHD_NETWORK`    | `signet` / `mainnet` / `regtest`           | `signet` |
| `WRAITHD_TOR_PROXY`  | SOCKS5(h) URL for Tor                      | (unset = direct) |
| `WRAITHD_IDLE_LOCK_SECS` | Auto-lock wallets after this many seconds of no IPC activity (0 = disabled) | `900` |

## Phase status

| # | Phase | Status |
|---|---|---|
| 0  | Foundation (workspace skeleton)                  | done |
| 1  | Chain client (ghost-pay RPC + GSP WS)            | done |
| 2  | Light wallet                                     | done |
| 3  | CLI maturation (`--json`, doctor, multi-cmd)     | done |
| 4  | Multi-wallet                                     | done |
| 5a | Wraith protocol v3 amendment                     | upstream (separate crate) |
| 5b | Wraith wallet module                             | minimal participant |
| 6  | Locks (prepare / confirm / jump)                 | done |
| 7  | TAP / L2 payments                                | done |
| 8  | Silent payments (BIP-352, candidate-tx push)     | done |
| 9  | Shroud relay                                     | pending |
| 10 | Tor transport (SOCKS5 → arti later)              | done (SOCKS5) |
| 11 | Multi-node failover                              | done |
| 12 | Recovery (seed + checkpoint)                     | partial |
| 13 | Hardware-wallet trait                            | software impl only |
| 14 | Tauri GUI                                        | scaffold (health/doctor) |
| 15 | Distribution (signed installers, auto-update)    | pending |
| 16 | Hardening (IPC fuzz, external review)            | pending |

## Hard rules

- Wallet talks to ghost-pay/ghost-gsp only. No direct ghost-core or Bitcoin-node
  connection. Every leak of that boundary is a bug.
- All modules run concurrently inside `wraithd`. The UI picks the foreground view,
  never which module is alive.
- The daemon is the unit of life, not the GUI. Closing the window does not kill
  `wraithd`.
- One IPC codepath: GUI and CLI both go through `wraithd`'s JSON-RPC. No direct
  linkage from the GUI into core.
