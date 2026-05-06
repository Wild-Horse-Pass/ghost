#!/usr/bin/env bash
# run-wraith-stack.sh — bring up the local Wraith Wallet dev stack.
#
# Starts (or reuses, if already running):
#   • bitcoind (signet)        — assumed running on 127.0.0.1:38335
#                                with rpcuser=local rpcpassword=localtest.
#                                Override via $BITCOIN_RPC_URL +
#                                $BITCOIN_RPC_USER + $BITCOIN_RPC_PASSWORD.
#   • ghost-pay                — :8800, REST API
#   • ghost-gsp                — :8900, REST + WS (--insecure-http for dev)
#   • wraithd                  — local Unix socket
#
# Logs land in /tmp/wraith-stack/<service>.log.
# Run again to restart: idempotent — kills the previous instance first.
#
# Usage:
#   bash scripts/run-wraith-stack.sh up
#   bash scripts/run-wraith-stack.sh down
#   bash scripts/run-wraith-stack.sh status

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.."  && pwd)"
LOG_DIR="${WRAITH_STACK_LOG_DIR:-/tmp/wraith-stack}"
GHOST_PAY_DATA="${WRAITH_STACK_GHOST_PAY_DIR:-/tmp/wraith-stack/ghost-pay}"
GSP_DATA="${WRAITH_STACK_GSP_DIR:-/tmp/wraith-stack/gsp}"
WALLETS_DIR="${WRAITH_STACK_WALLETS_DIR:-/tmp/wraith-stack/wallets}"

BITCOIN_RPC_URL="${BITCOIN_RPC_URL:-http://127.0.0.1:38335}"
BITCOIN_RPC_USER="${BITCOIN_RPC_USER:-local}"
BITCOIN_RPC_PASSWORD="${BITCOIN_RPC_PASSWORD:-localtest}"

mkdir -p "$LOG_DIR" "$GHOST_PAY_DATA" "$GSP_DATA" "$WALLETS_DIR"

action="${1:-up}"

probe_bitcoind() {
  curl -s --user "$BITCOIN_RPC_USER:$BITCOIN_RPC_PASSWORD" \
    -H 'content-type: text/plain' \
    --data '{"jsonrpc":"1.0","id":"x","method":"getblockchaininfo","params":[]}' \
    "$BITCOIN_RPC_URL/" | head -c 80
}

stop_one() {
  local name="$1"
  local pidfile="$LOG_DIR/$name.pid"
  if [[ -f "$pidfile" ]]; then
    local pid
    pid=$(cat "$pidfile")
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      sleep 0.5
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$pidfile"
  fi
  # Also clean up by binary name (covers stale processes outside our pidfile).
  pkill -x "$name" 2>/dev/null || true
}

start_ghost_pay() {
  stop_one ghost-pay
  echo "starting ghost-pay → $LOG_DIR/ghost-pay.log"
  BITCOIN_RPC_USER="$BITCOIN_RPC_USER" \
  BITCOIN_RPC_PASSWORD="$BITCOIN_RPC_PASSWORD" \
  GHOST_PAY_API_SECRET="$(openssl rand -base64 32)" \
    "$ROOT/target/debug/ghost-pay" \
      --bitcoin-rpc "$BITCOIN_RPC_URL" \
      --network signet \
      --api-listen 127.0.0.1:8800 \
      --data-dir "$GHOST_PAY_DATA" \
      > "$LOG_DIR/ghost-pay.log" 2>&1 &
  echo $! > "$LOG_DIR/ghost-pay.pid"
}

start_ghost_gsp() {
  stop_one ghost-gsp
  echo "starting ghost-gsp → $LOG_DIR/ghost-gsp.log"
  GHOST_PAY_INTERNAL_SECRET="$(openssl rand -base64 32)" \
    "$ROOT/target/debug/ghost-gsp" \
      --network signet \
      --listen 127.0.0.1:8900 \
      --pay-node-url http://127.0.0.1:8800 \
      --data-dir "$GSP_DATA" \
      --insecure-http \
      > "$LOG_DIR/ghost-gsp.log" 2>&1 &
  echo $! > "$LOG_DIR/ghost-gsp.pid"
}

start_wraithd() {
  stop_one wraithd
  echo "starting wraithd → $LOG_DIR/wraithd.log"
  WRAITHD_WALLETS_DIR="$WALLETS_DIR" \
  WRAITHD_GSP=ws://127.0.0.1:8900/ws/v1 \
  WRAITHD_GHOST_PAY=http://127.0.0.1:8800 \
    "$ROOT/target/debug/wraithd" \
      > "$LOG_DIR/wraithd.log" 2>&1 &
  echo $! > "$LOG_DIR/wraithd.pid"
}

status() {
  for svc in ghost-pay ghost-gsp wraithd; do
    pidfile="$LOG_DIR/$svc.pid"
    if [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
      echo "  ok    $svc (pid $(cat "$pidfile"))"
    else
      echo "  off   $svc"
    fi
  done
}

case "$action" in
  up)
    if ! probe_bitcoind > /dev/null 2>&1; then
      echo "ERROR: bitcoind not reachable at $BITCOIN_RPC_URL"
      echo "       expected creds $BITCOIN_RPC_USER:$BITCOIN_RPC_PASSWORD"
      echo "       set BITCOIN_RPC_URL / _USER / _PASSWORD env if elsewhere."
      exit 1
    fi
    start_ghost_pay
    sleep 2
    start_ghost_gsp
    sleep 2
    start_wraithd
    sleep 1
    echo
    echo "stack up:"
    status
    echo
    echo "  $ ./target/debug/wraith doctor"
    ;;
  down)
    stop_one wraithd
    stop_one ghost-gsp
    stop_one ghost-pay
    echo "stack down"
    ;;
  status)
    status
    ;;
  *)
    echo "usage: $0 {up|down|status}"
    exit 2
    ;;
esac
