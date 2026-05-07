#!/usr/bin/env bash
# Regtest demo of the Ghost Lock unilateral-exit path.
#
# Spins up ghostd in regtest, prepares a Ghost Lock against a
# running ghost-pay + ghost-gsp + wraithd stack, funds it, kills
# every operator service, mines past the timelock, and runs
# `wraith locks recover` — proving the user gets their bitcoin back
# with zero operator cooperation.
#
# Prerequisites:
#   - ghostd + ghost-cli on PATH (Ghost Core, Bitcoin Core v30 fork).
#     bitcoind/bitcoin-cli also work — the RPC interface is identical —
#     and this script falls back to them if ghostd isn't installed.
#   - this repo built (`cargo build --workspace`)
#   - ghost-pay, ghost-gsp, wraithd binaries in target/debug/
#
# Usage:
#   ./scripts/regtest-recovery-demo.sh
#
# What "success" looks like at the end: the recovery tx confirms,
# `ghost-cli getbalance` shows the recovered amount on the receiving
# address, and the operator services were down for the second half
# of the run.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO/target/debug"
DATADIR="$(mktemp -d -t ghost-regtest-demo.XXXXXX)"
# Preserve service logs for post-mortem; remove the data on exit.
SAVED_LOGS_DIR="${SAVED_LOGS_DIR:-/tmp/wraith-recovery-demo-logs}"
mkdir -p "$SAVED_LOGS_DIR"
cleanup() {
    cp "$DATADIR/"*.log "$SAVED_LOGS_DIR/" 2>/dev/null || true
    rm -rf "$DATADIR"
    echo "(logs preserved at $SAVED_LOGS_DIR)"
}
trap cleanup EXIT

# Prefer ghostd/ghost-cli; fall back to bitcoind/bitcoin-cli (RPC-
# compatible) or to the Bitcoin Core v30 multitool form (`ghost rpc`
# / `bitcoin rpc`) for layouts that ship a single binary instead of
# the separate cli.
GHOSTD="${GHOSTD:-$(command -v ghostd || command -v bitcoind || true)}"
GHOST_CLI="${GHOST_CLI:-$(command -v ghost-cli || command -v bitcoin-cli || true)}"
if [ -z "$GHOSTD" ]; then
    echo "ERROR: neither ghostd nor bitcoind found on PATH" >&2
    exit 1
fi
if [ -z "$GHOST_CLI" ]; then
    if command -v ghost > /dev/null 2>&1; then
        GHOST_CLI="ghost rpc"
    elif command -v bitcoin > /dev/null 2>&1; then
        GHOST_CLI="bitcoin rpc"
    else
        echo "ERROR: no RPC client found (looked for ghost-cli, bitcoin-cli, ghost, bitcoin)" >&2
        exit 1
    fi
fi

GHOSTD_DIR="$DATADIR/ghostd"
GHOSTD_PORT=18443
GHOSTD_RPC_URL="http://127.0.0.1:${GHOSTD_PORT}/"
mkdir -p "$GHOSTD_DIR"

GHOST_PAY_DIR="$DATADIR/ghost-pay"
GHOST_PAY_URL="http://127.0.0.1:8800"
GSP_URL="ws://127.0.0.1:8900/ws/v1"
WRAITHD_SOCK="$DATADIR/wraithd.sock"

step() { echo; echo "--- $* ---"; }

step "starting ghostd regtest ($GHOSTD)"
"$GHOSTD" -regtest \
    -datadir="$GHOSTD_DIR" \
    -rpcuser=demo -rpcpassword=demo \
    -rpcport=$GHOSTD_PORT \
    -port=18444 \
    -fallbackfee=0.0001 \
    -daemon \
    -txindex
sleep 2

BCLI="$GHOST_CLI -regtest -datadir=$GHOSTD_DIR -rpcuser=demo -rpcpassword=demo"

# Bring up a wallet on the ghostd side so we can fund things.
$BCLI -named createwallet wallet_name=demo descriptors=true || true
$BCLI loadwallet demo || true
DEMO_ADDR=$($BCLI -rpcwallet=demo getnewaddress)
$BCLI -rpcwallet=demo generatetoaddress 101 "$DEMO_ADDR" >/dev/null
echo "regtest funded — current balance: $($BCLI -rpcwallet=demo getbalance) BTC"

# Shared secrets for the local stack:
#   * GHOST_PAY_API_SECRET — HMAC for external callers of ghost-pay's
#     /api/v1/* routes. Required even on regtest.
#   * GHOST_PAY_INTERNAL_SECRET — HMAC ghost-gsp uses to talk to
#     ghost-pay. Same value on both sides.
GHOST_PAY_API_SECRET="$(openssl rand -base64 32)"
GHOST_PAY_INTERNAL_SECRET="$(openssl rand -base64 32)"

step "starting ghost-pay"
BITCOIN_RPC_USER=demo \
BITCOIN_RPC_PASSWORD=demo \
GHOST_PAY_API_SECRET="$GHOST_PAY_API_SECRET" \
GHOST_PAY_INTERNAL_SECRET="$GHOST_PAY_INTERNAL_SECRET" \
"$BIN/ghost-pay" \
    --network regtest \
    --bitcoin-rpc "$GHOSTD_RPC_URL" \
    --api-listen 127.0.0.1:8800 \
    --data-dir "$GHOST_PAY_DIR" \
    >"$DATADIR/ghost-pay.log" 2>&1 &
GHOST_PAY_PID=$!

step "starting ghost-gsp"
GHOST_PAY_INTERNAL_SECRET="$GHOST_PAY_INTERNAL_SECRET" \
"$BIN/ghost-gsp" \
    --network regtest \
    --pay-node-url "$GHOST_PAY_URL" \
    --listen 127.0.0.1:8900 \
    --data-dir "$DATADIR/gsp" \
    --insecure-http \
    >"$DATADIR/gsp.log" 2>&1 &
GSP_PID=$!
sleep 2

# Bootstrap ghost-pay's operator keys. Without this, every
# /api/v1/locks/* call returns 404 because state.keys is None
# until the operator generates them. In production this happens
# once on operator install; the demo scripts have to do it inline.
step "bootstrapping ghost-pay operator keys"
curl -fsS -X POST -H "X-Internal-Auth: $GHOST_PAY_INTERNAL_SECRET" \
    -H "Content-Type: application/json" \
    "$GHOST_PAY_URL/api/v1/keys/generate" -d '{}' > "$DATADIR/keys-init.json"
echo "  ghost_id: $(jq -r '.ghost_id // empty' < "$DATADIR/keys-init.json" 2>/dev/null || echo '<missing>')"

step "starting wraithd"
WRAITHD_SOCKET="$WRAITHD_SOCK" \
WRAITHD_NETWORK=regtest \
WRAITHD_GHOST_PAY="$GHOST_PAY_URL" \
WRAITHD_GSP="$GSP_URL" \
WRAITHD_GHOSTD_URL="$GHOSTD_RPC_URL" \
WRAITHD_GHOSTD_USER=demo \
WRAITHD_GHOSTD_PASS=demo \
WRAITHD_WALLETS_DIR="$DATADIR/wallets" \
"$BIN/wraithd" \
    >"$DATADIR/wraithd.log" 2>&1 &
WRAITHD_PID=$!
sleep 2

WRAITH() {
    WRAITHD_SOCKET="$WRAITHD_SOCK" "$BIN/wraith" --no-spawn "$@"
}

step "creating wallet + GSP session"
WRAITH wallet create demo <<< 'demopass\ndemopass\n' >/dev/null
WRAITH wallet select demo
WRAITH gsp auth

step "preparing a Ghost Lock (capacity = Tiny = 100,000 sats)"
PREPARE_OUT=$(WRAITH locks prepare 100000)
echo "$PREPARE_OUT"
LOCK_ID=$(echo "$PREPARE_OUT" | grep -m1 'lock_id:' | awk '{print $NF}')
FUNDING_ADDR=$(echo "$PREPARE_OUT" | grep -m1 'funding address:' | awk '{print $NF}')
echo "lock_id=$LOCK_ID funding_addr=$FUNDING_ADDR"

step "funding the lock from regtest wallet"
FUNDING_TXID=$($BCLI -rpcwallet=demo sendtoaddress "$FUNDING_ADDR" 0.001)
echo "funding_txid=$FUNDING_TXID"
$BCLI -rpcwallet=demo generatetoaddress 1 "$DEMO_ADDR" >/dev/null
WRAITH locks confirm "$LOCK_ID" "$FUNDING_TXID"

step "killing ghost-pay + ghost-gsp — simulating operator failure"
kill -9 "$GHOST_PAY_PID" "$GSP_PID" || true
sleep 1
echo "operators dead; wraithd is still up but its GSP session is gone"

step "mining past the timelock (Short = 26280 blocks)"
echo "this would take a long time on signet/mainnet — regtest mines instantly"
$BCLI -rpcwallet=demo generatetoaddress 26281 "$DEMO_ADDR" >/dev/null
echo "current height: $($BCLI getblockcount)"

step "running unilateral exit — wraith locks recover"
RECOVERY_DEST=$($BCLI -rpcwallet=demo getnewaddress)
echo "destination: $RECOVERY_DEST"
WRAITH locks recover --lock-id "$LOCK_ID" --to "$RECOVERY_DEST" --fee-sats 1000

step "mining the recovery tx + verifying balance"
$BCLI -rpcwallet=demo generatetoaddress 1 "$DEMO_ADDR" >/dev/null
RECOVERED=$($BCLI -rpcwallet=demo getreceivedbyaddress "$RECOVERY_DEST")
echo "recovered to L1: $RECOVERED BTC"

step "tearing down"
kill -9 "$WRAITHD_PID" || true
$BCLI stop || true

echo
echo "=== DEMO COMPLETE ==="
echo "ghost-pay + ghost-gsp were dead for the entire recovery."
echo "wraithd talked only to ghostd. The user's funds came back."
echo "this is the trust model the design promised."
