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

## Quick start

Assuming `cargo` is on your PATH and you've cloned the monorepo:

```sh
# 1. Build everything (first build pulls + compiles a lot of deps).
cargo build -p wraith-wallet-daemon -p wraith-wallet-cli -p wraith-wallet-gui

# 2. Bring up the dev stack (needs a local signet bitcoind on :38335).
bash scripts/run-wraith-stack.sh up

# 3. Open the GUI — it kicks off onboarding automatically when there
#    are no wallets. Or use the CLI:
./target/debug/wraith-gui                              # GUI path
./target/debug/wraith wallet create alice              # CLI path
./target/debug/wraith gsp auth                         # → GSP session
./target/debug/wraith light receive --index 0          # show first address
./target/debug/wraith light watch                      # live silent-payment stream
```

Same `wraithd` daemon serves both clients. The GUI window can close
without terminating `wraithd` (system-tray → Quit GUI to do that).

To restore an existing wallet:

```sh
./target/debug/wraith wallet import alice
# (paste 12 or 24 BIP-39 words; choose a fresh passphrase)
```

In the GUI, click `+ restore` next to the wallet picker.

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

## Release

`scripts/release-wraith.sh` builds release binaries, generates shell completions,
and packs everything into a versioned tarball:

```sh
bash scripts/release-wraith.sh
# produces: dist/wraith-wallet-<version>-<host-triple>.tar.gz
#         + dist/wraith-wallet-<version>-<host-triple>.tar.gz.sha256
```

The tarball layout:

```
wraith-wallet-<version>/
  bin/{wraithd, wraith, wraith-gui}
  completions/{wraith.bash, _wraith, wraith.fish}
  README.md
  LICENSE
  BUILDINFO.txt    # version + triple + commit + rustc + build timestamp
```

Signing + auto-update tooling are Phase 15 follow-ups; the tarball above is
what a release-engineer would run on a build host to produce a clean,
immutable artifact ready for manual signing and upload.

## Phase status

| # | Phase | Status |
|---|---|---|
| 0  | Foundation (workspace skeleton)                  | done |
| 1  | Chain client (ghost-pay RPC + GSP WS)            | done |
| 2  | Light wallet                                     | done |
| 3  | CLI maturation (`--json`, doctor, multi-cmd, completions) | done |
| 4  | Multi-wallet (with GUI picker that switches active) | done |
| 5a | Wraith protocol v3 amendment                     | upstream `wraith-protocol/` crate |
| 5b | Wraith wallet module                             | not started |
| 6  | Locks (prepare / confirm / jump)                 | done — CLI + GUI |
| 7  | TAP / L2 payments                                | done — with confirm dialog |
| 8  | Silent payments (BIP-352, candidate-tx push)     | done — with live `wraith light watch` |
| 9  | Shroud relay                                     | pending |
| 10 | Tor transport (SOCKS5 → arti later)              | done (SOCKS5) |
| 11 | Multi-node failover                              | done — comma-separated URLs |
| 12 | Recovery (seed + checkpoint)                     | done — `wallet import` + `wallet restore` |
| 13 | Hardware-wallet trait                            | trait + software impl + stub vendor backend |
| 14 | Tauri GUI                                        | done — onboarding, send/recv/locks/identity/settings tabs, system tray, live push toasts |
| 15 | Distribution (signed installers, auto-update)    | tarball script — signing + update server pending |
| 16 | Hardening (IPC fuzz, external review)            | proptest IPC fuzz + integration tests; external review pending |

Tests as of latest: 39 across the wraith-wallet workspace
(7 IPC + 28 core + 4 daemon), all green. Run them with
`cargo test -p wraith-wallet-{ipc,core,daemon} --tests`.

## Security model

- Encrypted keystore: Argon2id KDF → AES-256-GCM. Per-wallet passphrases.
- IPC socket: bound at owner-only (0600) permissions; channel restricted to
  processes running as the same user as `wraithd`.
- Auto-lock: wallets are dropped from the unlocked set after
  `WRAITHD_IDLE_LOCK_SECS` of no activity (default 15 minutes). Diagnostics
  (Health / Doctor / DaemonEnv) and the WatchPayments stream don't reset
  the timer; everything else does.
- Network boundary: the wallet only ever talks to `ghost-pay` (REST) and
  `ghost-gsp` (REST + WebSocket). It never reaches past them to a Bitcoin
  node directly. Tor routing optional via `WRAITHD_TOR_PROXY`.

## Hard rules

- Wallet talks to ghost-pay/ghost-gsp only. No direct ghost-core or Bitcoin-node
  connection. Every leak of that boundary is a bug.
- All modules run concurrently inside `wraithd`. The UI picks the foreground view,
  never which module is alive.
- The daemon is the unit of life, not the GUI. Closing the window does not kill
  `wraithd`.
- One IPC codepath: GUI and CLI both go through `wraithd`'s JSON-RPC. No direct
  linkage from the GUI into core.
