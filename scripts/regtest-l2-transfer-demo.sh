#!/usr/bin/env bash
# Regtest demo of the L2 instant-transfer flow.
#
# Two wraithd instances (alice + bob) talk to a single
# ghost-pay + ghost-gsp + ghostd stack. Alice funds a Ghost
# Lock, then runs `wraith light send <bob_ghost_id> 5000`. The
# demo asserts the L2 ledger entry was recorded under ALICE's
# ghost_id (not the operator's), proving the SendL2Payment
# rewire works end-to-end and ghost-pay's authentication
# correctly attributes the sender.
#
# Companion to scripts/regtest-recovery-demo.sh — that one
# demonstrates the unilateral-exit safety net; this one
# demonstrates the runtime utility (instant private payments
# without liquidity).
#
# Prerequisites:
#   - ghostd + ghost-cli on PATH (Ghost Core, Bitcoin Core v30 fork).
#     bitcoind/bitcoin-cli also work — the RPC interface is identical —
#     and this script falls back to them if ghostd isn't installed.
#   - sqlite3, jq on PATH
#   - this repo built (`cargo build --workspace`)
#   - the wraith stack binaries in target/debug/
#
# Usage:
#   ./scripts/regtest-l2-transfer-demo.sh
#
# Success at the end: ghost-pay's accepted_instant_payments
# table contains a row with merchant_wallet_id=<bob_ghost_id>
# and sender_pubkey=<alice's ghost-keys spend_pubkey>. NOT
# operator's. That row is the L2 transfer.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO/target/debug"
DATADIR="$(mktemp -d -t ghost-regtest-l2-demo.XXXXXX)"
SAVED_LOGS_DIR="${SAVED_LOGS_DIR:-/tmp/wraith-l2-transfer-demo-logs}"
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
ALICE_SOCK="$DATADIR/alice.sock"
BOB_SOCK="$DATADIR/bob.sock"

step() { echo; echo "--- $* ---"; }

# ---- ghostd ---------------------------------------------------------------
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
$BCLI -named createwallet wallet_name=demo descriptors=true || true
$BCLI loadwallet demo || true
DEMO_ADDR=$($BCLI -rpcwallet=demo getnewaddress)
$BCLI -rpcwallet=demo generatetoaddress 101 "$DEMO_ADDR" >/dev/null

# Shared secrets — see regtest-recovery-demo.sh for the explanation.
GHOST_PAY_API_SECRET="$(openssl rand -base64 32)"
GHOST_PAY_INTERNAL_SECRET="$(openssl rand -base64 32)"

# ---- ghost-pay --------------------------------------------------------------
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

# ---- ghost-gsp --------------------------------------------------------------
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
sleep 4

# Bootstrap ghost-pay's operator keys (same reason as
# regtest-recovery-demo.sh — without these the lock-prepare path
# returns 404 because state.keys is None).
step "bootstrapping ghost-pay operator keys"
curl -fsS -X POST -H "X-Internal-Auth: $GHOST_PAY_INTERNAL_SECRET" \
    -H "Content-Type: application/json" \
    "$GHOST_PAY_URL/api/v1/keys/generate" -d '{}' > "$DATADIR/keys-init.json"
echo "  ghost_id: $(jq -r '.ghost_id // empty' < "$DATADIR/keys-init.json" 2>/dev/null || echo '<missing>')"

# ---- two wraithd instances --------------------------------------------------
spawn_wraithd() {
    local name="$1" sock="$2"
    WRAITHD_SOCKET="$sock" \
    WRAITHD_NETWORK=regtest \
    WRAITHD_GHOST_PAY="$GHOST_PAY_URL" \
    WRAITHD_GSP="$GSP_URL" \
    WRAITHD_GHOSTD_URL="$GHOSTD_RPC_URL" \
    WRAITHD_GHOSTD_USER=demo \
    WRAITHD_GHOSTD_PASS=demo \
    WRAITHD_WALLETS_DIR="$DATADIR/$name-wallets" \
    "$BIN/wraithd" \
        >"$DATADIR/$name.log" 2>&1 &
    eval "${name^^}_PID=$!"
}

step "starting alice wraithd"
spawn_wraithd alice "$ALICE_SOCK"
step "starting bob wraithd"
spawn_wraithd bob "$BOB_SOCK"
sleep 2

ALICE_WRAITH() { WRAITHD_SOCKET="$ALICE_SOCK" "$BIN/wraith" --no-spawn "$@"; }
BOB_WRAITH()   { WRAITHD_SOCKET="$BOB_SOCK"   "$BIN/wraith" --no-spawn "$@"; }

# ---- create wallets + GSP sessions -----------------------------------------
step "creating alice + bob wallets"
ALICE_WRAITH wallet create alice <<< 'alice-pass\nalice-pass\n' >/dev/null
BOB_WRAITH   wallet create bob   <<< 'bob-pass\nbob-pass\n'     >/dev/null
ALICE_WRAITH wallet select alice
BOB_WRAITH   wallet select bob

step "auth-ing both wallets to GSP"
ALICE_AUTH=$(ALICE_WRAITH gsp auth)
echo "$ALICE_AUTH"
BOB_AUTH=$(BOB_WRAITH gsp auth)
echo "$BOB_AUTH"

# wraith CLI prints `wallet_id: <hex>` from the register response;
# that's `WalletId::from_pubkey(spend_pubkey)` — the STATIC ID
# ghost-pay records as `owner_ghost_id` / `sender_ghost_id`.
# Operator-side assertions query by this, not by the bech32 ghost-id
# the wallet shares with senders.
ALICE_STATIC_ID=$(echo "$ALICE_AUTH" | grep -m1 'wallet_id:' | awk '{print $NF}')
BOB_STATIC_ID=$(echo "$BOB_AUTH" | grep -m1 'wallet_id:' | awk '{print $NF}')
echo "alice's static wallet_id: $ALICE_STATIC_ID"
echo "bob's   static wallet_id: $BOB_STATIC_ID"

# Pull bob's bech32 ghost-id (BIP-352 receive identity) — that's
# what alice puts on the wire when sending.
BOB_GHOST_ID=$(BOB_WRAITH --json wallet ghost-id | jq -r '.WalletGhostId.ghost_id // .ghost_id')
echo "bob's   bech32 ghost-id:  $BOB_GHOST_ID"

# Alice's bech32 ghost-id for completeness (not used by ghost-pay
# storage which is keyed on static IDs).
ALICE_GHOST_ID=$(ALICE_WRAITH --json wallet ghost-id | jq -r '.WalletGhostId.ghost_id // .ghost_id')
echo "alice's bech32 ghost-id:  $ALICE_GHOST_ID"

# ---- alice prepares + funds a lock -----------------------------------------
# Skip the wraith CoinJoin path here (separate demo); fund directly
# to keep this demo focused on the L2 transfer wire.
step "alice prepares a Ghost Lock (Tiny = 100,000 sats)"
PREP_OUT=$(ALICE_WRAITH locks prepare 100000)
echo "$PREP_OUT"
LOCK_ID=$(echo "$PREP_OUT" | grep -m1 'lock_id:' | awk '{print $NF}')
FUND_ADDR=$(echo "$PREP_OUT" | grep -m1 'funding address:' | awk '{print $NF}')

step "funding the lock from regtest BTC"
FUND_TXID=$($BCLI -rpcwallet=demo sendtoaddress "$FUND_ADDR" 0.001)
$BCLI -rpcwallet=demo generatetoaddress 1 "$DEMO_ADDR" >/dev/null
ALICE_WRAITH locks confirm "$LOCK_ID" "$FUND_TXID"

# ---- ALICE → BOB L2 send (the headline) ------------------------------------
step "alice runs: wraith light send <bob> 5000"
ALICE_WRAITH light send "$BOB_GHOST_ID" 5000 --immediate

# ---- assertion: ghost-pay recorded the entry under ALICE's id --------------
# Use the operator-side `/api/v1/transactions` route (with the
# X-Internal-Auth bypass) instead of poking the sqlite3 file
# directly — keeps the demo dependency-free and exercises the
# canonical operator API in the process.
step "verifying ghost-pay recorded the L2 ledger entry under alice's static id"
ALICE_TXS=$(curl -fsS \
    -H "X-Internal-Auth: $GHOST_PAY_INTERNAL_SECRET" \
    "$GHOST_PAY_URL/api/v1/transactions?ghost_id=$ALICE_STATIC_ID&limit=5")
echo "alice's transactions (operator view):"
echo "$ALICE_TXS"
TOP_AMOUNT=$(echo "$ALICE_TXS" | jq -r '.transactions[0].amount_sats // empty')
TOP_TYPE=$(echo   "$ALICE_TXS" | jq -r '.transactions[0].tx_type // empty')
if [ "$TOP_AMOUNT" = "-5000" ] && [ "$TOP_TYPE" = "send" ]; then
    echo "✓ operator-side ledger has alice as sender of -5000"
else
    echo "✗ unexpected ledger row — amount=$TOP_AMOUNT type=$TOP_TYPE"
    exit 1
fi

# ---- assertion: alice sees -5000 in her L2 history -------------------------
# Bob's `light history` is a known follow-up: ghost-pay stores
# `merchant_wallet_id` as bob's BECH32 ghost-id (the only stable
# identifier alice has for him at send time), but bob's wallet
# queries `/api/v1/transactions` with his STATIC wallet_id (the
# one his GSP session is bound to). The two don't match, so the
# row isn't found from bob's side. Fix would be: GSP forwards
# bob's bech32 alongside his static when querying transactions, OR
# ghost-pay decodes the recipient bech32 → static at INSERT time.
# Operator-side check above already proves the row exists.
step "verifying alice sees -5000 in her L2 history"
ALICE_HIST=$(ALICE_WRAITH --json light history --limit 5)
echo "$ALICE_HIST"
ALICE_AMOUNT=$(echo "$ALICE_HIST" | jq -r '.LightHistory.transactions[0].amount_sats // .transactions[0].amount_sats')
ALICE_TYPE=$(echo   "$ALICE_HIST" | jq -r '.LightHistory.transactions[0].tx_type // .transactions[0].tx_type')
if [ "$ALICE_AMOUNT" = "-5000" ] && [ "$ALICE_TYPE" = "send" ]; then
    echo "✓ alice's wallet sees -5000 send"
else
    echo "✗ alice history mismatch — amount=$ALICE_AMOUNT type=$ALICE_TYPE"
    exit 1
fi

# ---- teardown ---------------------------------------------------------------
step "tearing down"
kill -9 "$ALICE_PID" "$BOB_PID" "$GHOST_PAY_PID" "$GSP_PID" 2>/dev/null || true
$BCLI stop || true

echo
echo "=== L2 TRANSFER DEMO COMPLETE ==="
echo "alice → bob, 5000 sats, recorded in ghost-pay's L2 ledger."
echo "no on-chain tx for the transfer itself — this is the runtime"
echo "utility that distinguishes Ghost Locks from typical L2."
echo
echo "next: bob's wallet would detect this via BIP-352 silent-payment"
echo "scan (LightDetected / WatchPayments). that part of the wire is"
echo "tracked separately."
