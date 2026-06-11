#!/usr/bin/env bash
# Regtest end-to-end test of the L1 UTXO scanner.
#
# Boots ghostd + ghost-pay + ghost-gsp + wraithd, creates a wallet,
# derives a BIP86 receive address, funds it on regtest, and runs
# `wraith light l1-utxos`. Asserts the scanner finds the funded
# output with the expected value, scriptPubKey, and BIP86 index.
#
# This is the contract test for ghost-pay's `/api/v1/utxos/scan`
# endpoint and the wallet-side address derivation + index tagging.
# Without it, the new scanner is unverified end-to-end against a
# real bitcoind.
#
# Prerequisites:
#   - ghostd + ghost-cli on PATH (Ghost Core, Bitcoin Core v30 fork).
#     bitcoind/bitcoin-cli also work — RPC is identical.
#   - jq on PATH
#   - this repo built (`cargo build --workspace`)
#   - the wraith stack binaries in target/debug/
#
# Usage:
#   ./scripts/regtest-l1-scan-demo.sh

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO/target/debug"
DATADIR="$(mktemp -d -t ghost-regtest-l1-scan.XXXXXX)"
SAVED_LOGS_DIR="${SAVED_LOGS_DIR:-/tmp/wraith-l1-scan-demo-logs}"
mkdir -p "$SAVED_LOGS_DIR"

GHOST_PAY_PID=""
GSP_PID=""
WRAITHD_PID=""
GHOSTD_DIR=""
GHOSTD_PORT=18443

cleanup() {
    set +e
    [ -n "$WRAITHD_PID" ] && kill "$WRAITHD_PID" 2>/dev/null
    [ -n "$GSP_PID" ] && kill "$GSP_PID" 2>/dev/null
    [ -n "$GHOST_PAY_PID" ] && kill "$GHOST_PAY_PID" 2>/dev/null
    if [ -n "$GHOSTD_DIR" ]; then
        $GHOST_CLI -regtest -datadir="$GHOSTD_DIR" \
            -rpcuser=demo -rpcpassword=demo stop 2>/dev/null || true
    fi
    sleep 1
    cp "$DATADIR/"*.log "$SAVED_LOGS_DIR/" 2>/dev/null || true
    rm -rf "$DATADIR"
    echo "(logs preserved at $SAVED_LOGS_DIR)"
}
trap cleanup EXIT

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
        echo "ERROR: no RPC client found" >&2
        exit 1
    fi
fi

GHOSTD_DIR="$DATADIR/ghostd"
GHOSTD_RPC_URL="http://127.0.0.1:${GHOSTD_PORT}/"
mkdir -p "$GHOSTD_DIR"
GHOST_PAY_DIR="$DATADIR/ghost-pay"
GHOST_PAY_URL="http://127.0.0.1:8800"
GSP_URL="ws://127.0.0.1:8900/ws/v1"
WRAITH_SOCK="$DATADIR/wraithd.sock"

step() { echo; echo "--- $* ---"; }

# ---- ghostd ---------------------------------------------------------------
step "starting ghostd regtest"
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
$BCLI -named createwallet wallet_name=demo descriptors=true || true
$BCLI loadwallet demo || true
DEMO_ADDR=$($BCLI -rpcwallet=demo getnewaddress)
$BCLI -rpcwallet=demo generatetoaddress 101 "$DEMO_ADDR" >/dev/null

# Shared X-Internal-Auth secret. ghost-pay accepts it as the
# auth-bypass header; wraithd uses it for the L1 scan endpoint.
GHOST_PAY_API_SECRET="$(openssl rand -base64 32)"
INTERNAL_SECRET="$(openssl rand -base64 32)"

# ---- ghost-pay --------------------------------------------------------------
step "starting ghost-pay"
BITCOIN_RPC_USER=demo \
BITCOIN_RPC_PASSWORD=demo \
GHOST_PAY_API_SECRET="$GHOST_PAY_API_SECRET" \
GHOST_PAY_INTERNAL_SECRET="$INTERNAL_SECRET" \
"$BIN/ghost-pay" \
    --network regtest \
    --bitcoin-rpc "$GHOSTD_RPC_URL" \
    --api-listen 127.0.0.1:8800 \
    --data-dir "$GHOST_PAY_DIR" \
    >"$DATADIR/ghost-pay.log" 2>&1 &
GHOST_PAY_PID=$!

# ---- ghost-gsp --------------------------------------------------------------
step "starting ghost-gsp"
GHOST_PAY_INTERNAL_SECRET="$INTERNAL_SECRET" \
"$BIN/ghost-gsp" \
    --network regtest \
    --pay-node-url "$GHOST_PAY_URL" \
    --listen 127.0.0.1:8900 \
    --data-dir "$DATADIR/gsp" \
    --insecure-http \
    >"$DATADIR/gsp.log" 2>&1 &
GSP_PID=$!
sleep 4

# Bootstrap ghost-pay operator keys (without these, ghost-pay's
# state.keys is None and some endpoints return 404).
step "bootstrapping ghost-pay operator keys"
curl -fsS -X POST -H "X-Internal-Auth: $INTERNAL_SECRET" \
    -H "Content-Type: application/json" \
    "$GHOST_PAY_URL/api/v1/keys/generate" -d '{}' >/dev/null

# ---- wraithd ----------------------------------------------------------------
step "starting wraithd"
WRAITHD_SOCKET="$WRAITH_SOCK" \
WRAITHD_NETWORK=regtest \
WRAITHD_GHOST_PAY="$GHOST_PAY_URL" \
WRAITHD_GSP="$GSP_URL" \
WRAITHD_GHOST_PAY_INTERNAL_AUTH="$INTERNAL_SECRET" \
WRAITHD_WALLETS_DIR="$DATADIR/wallets" \
"$BIN/wraithd" \
    >"$DATADIR/wraithd.log" 2>&1 &
WRAITHD_PID=$!
sleep 2

WRAITH() { WRAITHD_SOCKET="$WRAITH_SOCK" "$BIN/wraith" --no-spawn "$@"; }

# ---- create + select wallet -------------------------------------------------
# When stdin is piped, prompt_new_passphrase prompts once (no
# confirmation pass), so a single-line heredoc is sufficient.
step "creating wallet"
WRAITH wallet create scanwallet <<< 'pass1234' >/dev/null
WRAITH wallet select scanwallet

# ---- derive BIP86 receive address at index 0 -------------------------------
step "deriving BIP86 receive address (index 0)"
RECV_JSON=$(WRAITH --json light receive --index 0)
RECV_ADDR=$(echo "$RECV_JSON" | jq -r '.LightReceive.address // .address')
if [ -z "$RECV_ADDR" ] || [ "$RECV_ADDR" = "null" ]; then
    echo "ERROR: failed to derive receive address. RECV_JSON=$RECV_JSON" >&2
    exit 1
fi
echo "receive address (idx 0): $RECV_ADDR"

# ---- fund the address + mine ------------------------------------------------
step "funding the address with 0.005 BTC (500,000 sats)"
FUND_TXID=$($BCLI -rpcwallet=demo sendtoaddress "$RECV_ADDR" 0.005)
echo "funding txid: $FUND_TXID"
$BCLI -rpcwallet=demo generatetoaddress 6 "$DEMO_ADDR" >/dev/null
echo "mined 6 confirmations"

# ---- run the L1 scanner -----------------------------------------------------
step "running wraith light l1-utxos"
SCAN_JSON=$(WRAITH --json light l1-utxos --scan-max-index 8)
echo "$SCAN_JSON" | jq .

# Extract the UTXO list. Tolerate either result variant tagging.
UTXOS=$(echo "$SCAN_JSON" | jq '.LightL1Utxos.utxos // .utxos // []')
COUNT=$(echo "$UTXOS" | jq 'length')
TOTAL=$(echo "$SCAN_JSON" | jq '.LightL1Utxos.total_sats // .total_sats // 0')
CHAIN_HEIGHT=$(echo "$SCAN_JSON" | jq '.LightL1Utxos.chain_height // .chain_height // 0')

# ---- assertions -------------------------------------------------------------
step "assertions"

if [ "$COUNT" -lt 1 ]; then
    echo "FAIL: scanner returned 0 UTXOs (expected ≥1 at index 0)" >&2
    exit 1
fi
echo "  PASS: scanner returned $COUNT UTXO(s)"

if [ "$TOTAL" -ne 500000 ]; then
    echo "FAIL: total_sats=$TOTAL, expected 500000" >&2
    exit 1
fi
echo "  PASS: total_sats=$TOTAL"

# Find the entry we funded — match on txid since we created it.
ENTRY=$(echo "$UTXOS" | jq --arg txid "$FUND_TXID" '.[] | select(.txid==$txid)')
if [ -z "$ENTRY" ] || [ "$ENTRY" = "null" ]; then
    echo "FAIL: no entry with txid=$FUND_TXID in scan result" >&2
    exit 1
fi
echo "  PASS: txid $FUND_TXID present"

ENTRY_BIP86=$(echo "$ENTRY" | jq '.bip86_index')
if [ "$ENTRY_BIP86" -ne 0 ]; then
    echo "FAIL: bip86_index=$ENTRY_BIP86, expected 0" >&2
    exit 1
fi
echo "  PASS: bip86_index=0 attributed correctly"

ENTRY_AMT=$(echo "$ENTRY" | jq '.amount_sats')
if [ "$ENTRY_AMT" -ne 500000 ]; then
    echo "FAIL: amount_sats=$ENTRY_AMT, expected 500000" >&2
    exit 1
fi
echo "  PASS: amount_sats=500000"

ENTRY_ADDR=$(echo "$ENTRY" | jq -r '.address')
if [ "$ENTRY_ADDR" != "$RECV_ADDR" ]; then
    echo "FAIL: address=$ENTRY_ADDR, expected $RECV_ADDR" >&2
    exit 1
fi
echo "  PASS: address matches derived receive address"

ENTRY_SPK=$(echo "$ENTRY" | jq -r '.scriptpubkey_hex')
if [ -z "$ENTRY_SPK" ] || [ "$ENTRY_SPK" = "null" ]; then
    echo "FAIL: scriptpubkey_hex missing" >&2
    exit 1
fi
echo "  PASS: scriptpubkey_hex present ($ENTRY_SPK)"

ENTRY_CONF=$(echo "$ENTRY" | jq '.confirmations')
if [ "$ENTRY_CONF" -lt 6 ]; then
    echo "FAIL: confirmations=$ENTRY_CONF, expected ≥6" >&2
    exit 1
fi
echo "  PASS: confirmations=$ENTRY_CONF (≥6 mined)"

echo
echo "L1 UTXO scanner: end-to-end OK at chain height $CHAIN_HEIGHT"
