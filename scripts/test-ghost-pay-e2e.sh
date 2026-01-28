#!/bin/bash
# Ghost Pay E2E Test Script
#
# Tests the complete Ghost Pay flow:
# 1. Generate keys
# 2. Create a lock
# 3. Join Wraith session
# 4. (Manual) Fund the lock
# 5. Request withdrawal
#
# Prerequisites:
# - ghost-pay running on localhost:8800
# - Bitcoin Core on signet/regtest
#
# Usage: ./test-ghost-pay-e2e.sh [host:port]

set -e

HOST="${1:-localhost:8800}"
BASE_URL="http://$HOST"

echo "=========================================="
echo "Ghost Pay E2E Test"
echo "Host: $HOST"
echo "=========================================="

# Helper function for pretty JSON output
json_pretty() {
    python3 -m json.tool 2>/dev/null || cat
}

# 1. Health check
echo ""
echo "[1/6] Health check..."
HEALTH=$(curl -s "$BASE_URL/health")
if [ "$HEALTH" != "OK" ]; then
    echo "FAIL: Health check failed"
    exit 1
fi
echo "OK"

# 2. Generate keys
echo ""
echo "[2/6] Generating Ghost Keys..."
KEYS_RESULT=$(curl -s -X POST "$BASE_URL/api/v1/keys/generate")
echo "$KEYS_RESULT" | json_pretty

GHOST_ID=$(echo "$KEYS_RESULT" | python3 -c "import sys, json; print(json.load(sys.stdin).get('ghost_id', ''))" 2>/dev/null)
if [ -z "$GHOST_ID" ]; then
    echo "FAIL: Could not generate keys"
    exit 1
fi
echo "Ghost ID: $GHOST_ID"

# 3. Get Ghost ID (verify keys)
echo ""
echo "[3/6] Verifying Ghost ID..."
ID_RESULT=$(curl -s "$BASE_URL/api/v1/keys/ghost-id")
echo "$ID_RESULT" | json_pretty

# 4. Create a lock (0.001 BTC = 100,000 sats)
echo ""
echo "[4/6] Creating Ghost Lock..."
LOCK_RESULT=$(curl -s -X POST "$BASE_URL/api/v1/locks/create" \
    -H "Content-Type: application/json" \
    -d '{"amount_sats": 100000, "timelock_tier": "standard"}')
echo "$LOCK_RESULT" | json_pretty

LOCK_ADDRESS=$(echo "$LOCK_RESULT" | python3 -c "import sys, json; print(json.load(sys.stdin).get('lock', {}).get('address', ''))" 2>/dev/null)
LOCK_ID=$(echo "$LOCK_RESULT" | python3 -c "import sys, json; print(json.load(sys.stdin).get('lock', {}).get('id', ''))" 2>/dev/null)

if [ -z "$LOCK_ADDRESS" ]; then
    echo "FAIL: Could not create lock"
    exit 1
fi

echo ""
echo "Lock created!"
echo "  Lock ID: $LOCK_ID"
echo "  Address: $LOCK_ADDRESS"
echo ""
echo "To fund this lock, send 0.001 BTC to:"
echo "  $LOCK_ADDRESS"

# 5. Join Wraith session
echo ""
echo "[5/6] Joining Wraith Session..."
SESSION_RESULT=$(curl -s -X POST "$BASE_URL/api/v1/wraith/join" \
    -H "Content-Type: application/json" \
    -d "{\"tier\": \"express\", \"denomination\": \"micro\", \"lock_id\": \"$LOCK_ID\"}")
echo "$SESSION_RESULT" | json_pretty

SESSION_ID=$(echo "$SESSION_RESULT" | python3 -c "import sys, json; print(json.load(sys.stdin).get('session_id', ''))" 2>/dev/null)
echo "Session ID: $SESSION_ID"

# 6. List sessions
echo ""
echo "[6/6] Listing Active Sessions..."
SESSIONS=$(curl -s "$BASE_URL/api/v1/wraith/sessions")
echo "$SESSIONS" | json_pretty

# Summary
echo ""
echo "=========================================="
echo "E2E Test Complete!"
echo "=========================================="
echo ""
echo "Next steps to complete the test:"
echo "1. Fund the lock address: $LOCK_ADDRESS"
echo "2. Wait for session to fill (need more participants)"
echo "3. Wraith mixing will run automatically"
echo "4. Request withdrawal when lock is funded"
echo ""
echo "To request withdrawal after funding:"
echo "curl -X POST $BASE_URL/api/v1/withdrawals/request \\"
echo "  -H 'Content-Type: application/json' \\"
echo "  -d '{\"lock_id\": \"$LOCK_ID\", \"destination_address\": \"YOUR_ADDRESS\", \"amount_sats\": 99000}'"
echo ""
echo "To check status:"
echo "  curl $BASE_URL/api/v1/status"
echo "  curl $BASE_URL/api/v1/locks"
echo "  curl $BASE_URL/api/v1/wraith/sessions"
