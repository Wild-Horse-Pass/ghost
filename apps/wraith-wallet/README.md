# Wraith Wallet

Desktop wallet for Bitcoin Ghost. Bundles light-wallet, Wraith CoinJoin participation,
Ghost Locks custody, and TAP (L2) payments behind a single GUI / CLI / daemon.

## Workspace layout

| Crate | Role |
|---|---|
| `core/`   | `wraith-wallet-core` — all wallet logic (lib) |
| `ipc/`    | `wraith-wallet-ipc` — JSON-RPC types shared between daemon and clients |
| `daemon/` | `wraith-wallet-daemon` — `wraithd` binary |
| `cli/`    | `wraith-wallet-cli` — `wraith` binary |

GUI (Tauri) lands later in the build (Phase 14).

## Architecture

- `wraithd` is the long-running process. Runs all module tasks (light, wraith, tap,
  locks, keys, shroud) concurrently. Connects to `ghost-pay` over RPC + GSP WebSocket.
- `wraith` (CLI) and the GUI are thin clients over `wraithd`'s local IPC.
- The wallet only ever talks to `ghost-pay`; never reaches past it to `ghost-core` directly.

## Build

```sh
cargo build -p wraith-wallet-daemon  # produces `wraithd`
cargo build -p wraith-wallet-cli     # produces `wraith`
```

## Status

Phase 0 — workspace skeleton only. Both binaries build and run; no real lifecycle yet.
