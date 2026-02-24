#!/bin/bash
#
# Ghost L2 Transaction Test Suite — E2E tests across 8 phases
#
# Tests all L2 transaction types against a live ghost-pay instance:
#   Phase 1: Setup & Keys
#   Phase 2: Ghost Lock Lifecycle
#   Phase 3: Jump Lock
#   Phase 4: Wraith Mixing
#   Phase 5: L2 Payment
#   Phase 6: Confidential Transfer
#   Phase 7: Reconciliation
#   Phase 8: L2 Block State
#
# Prerequisites:
#   1. ghost-pay running on target host (port 8800)
#   2. ghost-pool running on target host (port 8080)
#   3. GHOST_PAY_API_SECRET set (hex-encoded HMAC key)
#
# Usage:
#   ./scripts/test-l2-transactions.sh                          # Run all phases
#   ./scripts/test-l2-transactions.sh --phase 5                # Run single phase
#   ./scripts/test-l2-transactions.sh --host 85.9.198.212      # Custom host
#   ./scripts/test-l2-transactions.sh --api-secret deadbeef    # Inline secret
#

set -uo pipefail

# ── Configuration ─────────────────────────────────────────────────────

HOST="83.136.251.162"
GHOST_PAY_PORT="8800"
POOL_PORT="8080"
API_SECRET="${GHOST_PAY_API_SECRET:-}"
RUN_PHASE=0

# Shared state across phases
GHOST_ID=""
FIRST_LOCK_ID=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)           HOST="$2"; shift 2 ;;
        --api-secret)     API_SECRET="$2"; shift 2 ;;
        --ghost-pay-port) GHOST_PAY_PORT="$2"; shift 2 ;;
        --pool-port)      POOL_PORT="$2"; shift 2 ;;
        --phase)          RUN_PHASE="$2"; shift 2 ;;
        *)                echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# ── Prerequisite Check ────────────────────────────────────────────────

if [[ -z "${API_SECRET:-}" ]]; then
    echo "ERROR: Ghost Pay API secret required."
    echo "  export GHOST_PAY_API_SECRET=<hex-secret>"
    echo "  or pass --api-secret <hex>"
    exit 1
fi

# ── Colors ────────────────────────────────────────────────────────────

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Counters ──────────────────────────────────────────────────────────

PASS=0
FAIL=0
SKIP=0
TOTAL=0

# ── Helper Functions ──────────────────────────────────────────────────

run_test() {
    local id="$1" name="$2"
    TOTAL=$((TOTAL + 1))
    printf "  ${CYAN}[%s]${NC} %-60s " "$id" "$name"
}

pass() {
    PASS=$((PASS + 1))
    echo -e "${GREEN}PASS${NC}"
}

fail() {
    local reason="${1:-}"
    FAIL=$((FAIL + 1))
    echo -e "${RED}FAIL${NC}"
    [[ -n "$reason" ]] && echo -e "        ${RED}→ $reason${NC}"
}

skip() {
    local reason="${1:-}"
    SKIP=$((SKIP + 1))
    echo -e "${YELLOW}SKIP${NC}"
    [[ -n "$reason" ]] && echo -e "        ${YELLOW}→ $reason${NC}"
}

phase_header() {
    local num="$1" name="$2" count="$3"
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  Phase $num: $name ($count tests)${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

should_run() {
    local phase="$1"
    if [[ $RUN_PHASE -ne 0 ]]; then
        [[ $phase -eq $RUN_PHASE ]]
    else
        return 0
    fi
}

# ── HMAC Auth Helper ──────────────────────────────────────────────────

ghost_pay_request() {
    local method="$1" path="$2" body="${3:-}"
    local url="http://${HOST}:${GHOST_PAY_PORT}${path}"
    local timestamp
    timestamp=$(date +%s)
    # Little-endian 8-byte timestamp
    local ts_hex
    ts_hex=$(printf '%016x' "$timestamp")
    local ts_le
    ts_le=$(echo "$ts_hex" | fold -w2 | tac | tr -d '\n')
    local ts_bytes
    ts_bytes=$(echo "$ts_le" | xxd -r -p)

    if [[ -n "$body" ]]; then
        local sig
        sig=$(printf '%s%s' "$ts_bytes" "$body" | openssl dgst -sha256 -hmac "$(echo -n "$API_SECRET" | xxd -r -p)" -binary | xxd -p -c 256)
        curl -sf --connect-timeout 5 --max-time 15 \
            -X "$method" \
            -H "Content-Type: application/json" \
            -H "X-Ghost-Signature: $sig" \
            -H "X-Ghost-Timestamp: $timestamp" \
            -d "$body" \
            -w "\n%{http_code}" \
            "$url" 2>/dev/null
    else
        local sig
        sig=$(printf '%s' "$ts_bytes" | openssl dgst -sha256 -hmac "$(echo -n "$API_SECRET" | xxd -r -p)" -binary | xxd -p -c 256)
        curl -sf --connect-timeout 5 --max-time 15 \
            -X "$method" \
            -H "X-Ghost-Signature: $sig" \
            -H "X-Ghost-Timestamp: $timestamp" \
            -w "\n%{http_code}" \
            "$url" 2>/dev/null
    fi
}

# ── Test Helpers ──────────────────────────────────────────────────────

# For endpoints expected to work (2xx required)
test_api() {
    local id="$1" name="$2" method="$3" path="$4" body="${5:-}"
    run_test "$id" "$name"
    local response http_code body_out
    response=$(ghost_pay_request "$method" "$path" "$body") || { fail "Connection failed"; return 1; }
    http_code=$(echo "$response" | tail -1)
    body_out=$(echo "$response" | sed '$d')
    if [[ "$http_code" =~ ^5 ]]; then fail "Server error: HTTP $http_code"; return 1; fi
    if [[ "$http_code" != "200" ]] && [[ "$http_code" != "201" ]]; then fail "HTTP $http_code"; return 1; fi
    if ! echo "$body_out" | jq . >/dev/null 2>&1; then fail "Invalid JSON"; return 1; fi
    pass
    return 0
}

# For endpoints that may fail with expected errors (unfunded, etc.) - validates no 500s
test_api_no_500() {
    local id="$1" name="$2" method="$3" path="$4" body="${5:-}"
    run_test "$id" "$name"
    local response http_code body_out
    response=$(ghost_pay_request "$method" "$path" "$body") || { fail "Connection failed"; return 1; }
    http_code=$(echo "$response" | tail -1)
    body_out=$(echo "$response" | sed '$d')
    if [[ "$http_code" =~ ^5 ]]; then fail "Server error: HTTP $http_code"; return 1; fi
    # 4xx is acceptable (expected failure), but validate JSON response
    if [[ -n "$body_out" ]] && ! echo "$body_out" | jq . >/dev/null 2>&1; then fail "Invalid JSON in error response"; return 1; fi
    pass
    return 0
}

# Pool API helper (no auth needed)
test_pool_endpoint() {
    local id="$1" name="$2" path="$3"
    run_test "$id" "$name"
    local response http_code body_out
    response=$(curl -sf --connect-timeout 5 --max-time 15 -w "\n%{http_code}" "http://${HOST}:${POOL_PORT}${path}" 2>/dev/null) || { fail "Connection failed"; return 1; }
    http_code=$(echo "$response" | tail -1)
    body_out=$(echo "$response" | sed '$d')
    if [[ "$http_code" != "200" ]]; then fail "HTTP $http_code"; return 1; fi
    if ! echo "$body_out" | jq . >/dev/null 2>&1; then fail "Invalid JSON"; return 1; fi
    pass
    return 0
}

# ══════════════════════════════════════════════════════════════════════
# Phase 1: Setup & Keys (2 tests)
# ══════════════════════════════════════════════════════════════════════

phase_1() {
    phase_header 1 "Setup & Keys" 2

    # P1.1: Generate test keys (may already exist)
    test_api_no_500 "P1.1" "Generate test keys" "POST" "/api/v1/keys/generate"

    # P1.2: Verify keys exist and capture ghost-id
    run_test "P1.2" "Verify keys (GET ghost-id)"
    local response http_code body_out
    response=$(ghost_pay_request "GET" "/api/v1/keys/ghost-id") || { fail "Connection failed"; return; }
    http_code=$(echo "$response" | tail -1)
    body_out=$(echo "$response" | sed '$d')
    if [[ "$http_code" =~ ^5 ]]; then fail "Server error: HTTP $http_code"; return; fi
    if [[ "$http_code" != "200" ]] && [[ "$http_code" != "201" ]]; then fail "HTTP $http_code"; return; fi
    if ! echo "$body_out" | jq . >/dev/null 2>&1; then fail "Invalid JSON"; return; fi
    GHOST_ID=$(echo "$body_out" | jq -r '.ghost_id // .id // empty')
    if [[ -n "$GHOST_ID" ]]; then
        pass
        echo -e "        ${CYAN}→ Ghost ID: ${GHOST_ID:0:16}...${NC}"
    else
        pass
        echo -e "        ${YELLOW}→ Could not extract ghost_id from response${NC}"
    fi
}

# ══════════════════════════════════════════════════════════════════════
# Phase 2: Ghost Lock Lifecycle (3 tests)
# ══════════════════════════════════════════════════════════════════════

phase_2() {
    phase_header 2 "Ghost Lock Lifecycle" 3

    # P2.1: Create a lock (may fail if no funds)
    test_api_no_500 "P2.1" "Create ghost lock (10000 sats, 144 blocks)" "POST" "/api/v1/locks/create" \
        '{"amount": 10000, "lock_blocks": 144}'

    # P2.2: List locks
    run_test "P2.2" "List ghost locks"
    local response http_code body_out
    response=$(ghost_pay_request "GET" "/api/v1/locks") || { fail "Connection failed"; FIRST_LOCK_ID=""; return; }
    http_code=$(echo "$response" | tail -1)
    body_out=$(echo "$response" | sed '$d')
    if [[ "$http_code" =~ ^5 ]]; then fail "Server error: HTTP $http_code"; FIRST_LOCK_ID=""; return; fi
    if [[ "$http_code" != "200" ]] && [[ "$http_code" != "201" ]]; then fail "HTTP $http_code"; FIRST_LOCK_ID=""; return; fi
    if ! echo "$body_out" | jq . >/dev/null 2>&1; then fail "Invalid JSON"; FIRST_LOCK_ID=""; return; fi
    # Extract first lock ID for later phases
    FIRST_LOCK_ID=$(echo "$body_out" | jq -r '.[0].id // .locks[0].id // empty' 2>/dev/null)
    local lock_count
    lock_count=$(echo "$body_out" | jq 'if type == "array" then length else (.locks // []) | length end' 2>/dev/null || echo "0")
    pass
    echo -e "        ${CYAN}→ Found $lock_count lock(s)${NC}"

    # P2.3: Get specific lock details
    if [[ -n "$FIRST_LOCK_ID" ]]; then
        test_api "P2.3" "Get lock details ($FIRST_LOCK_ID)" "GET" "/api/v1/locks/$FIRST_LOCK_ID" || true
    else
        run_test "P2.3" "Get lock details (specific lock)"
        skip "No locks found in P2.2"
    fi
}

# ══════════════════════════════════════════════════════════════════════
# Phase 3: Jump Lock (1 test)
# ══════════════════════════════════════════════════════════════════════

phase_3() {
    phase_header 3 "Jump Lock" 1

    if [[ -n "$FIRST_LOCK_ID" ]]; then
        # P3.1: Attempt jump on first lock (expected fail if unfunded)
        test_api_no_500 "P3.1" "Jump lock ($FIRST_LOCK_ID)" "POST" "/api/v1/locks/$FIRST_LOCK_ID/jump"
    else
        run_test "P3.1" "Jump lock (requires lock from Phase 2)"
        skip "No locks found in Phase 2"
    fi
}

# ══════════════════════════════════════════════════════════════════════
# Phase 4: Wraith Mixing (2 tests)
# ══════════════════════════════════════════════════════════════════════

phase_4() {
    phase_header 4 "Wraith Mixing" 2

    # P4.1: List wraith sessions (pool port, no auth)
    test_pool_endpoint "P4.1" "List wraith sessions" "/api/v1/wraith/sessions" || true

    # P4.2: Join a wraith session (ghost-pay port, may fail if no session)
    test_api_no_500 "P4.2" "Join wraith session" "POST" "/api/v1/wraith/join"
}

# ══════════════════════════════════════════════════════════════════════
# Phase 5: L2 Payment (3 tests)
# ══════════════════════════════════════════════════════════════════════

phase_5() {
    phase_header 5 "L2 Payment" 3

    # P5.1: Send payment (expected fail - test address)
    test_api_no_500 "P5.1" "Send L2 payment (expected fail)" "POST" "/api/v1/payments/send" \
        '{"to": "tsp1test000000000000000000000000000000000000", "amount": 1000}'

    # P5.2: Generate payment address
    test_api_no_500 "P5.2" "Generate payment address" "POST" "/api/v1/payments/address"

    # P5.3: Scan for payments
    test_api_no_500 "P5.3" "Scan for incoming payments" "POST" "/api/v1/payments/scan"
}

# ══════════════════════════════════════════════════════════════════════
# Phase 6: Confidential Transfer (3 tests)
# ══════════════════════════════════════════════════════════════════════

phase_6() {
    phase_header 6 "Confidential Transfer" 3

    # P6.1: Get confidential tree state
    test_api_no_500 "P6.1" "Get confidential tree" "GET" "/api/v1/confidential/tree"

    # P6.2: Shield funds (move to confidential pool)
    test_api_no_500 "P6.2" "Shield funds (1000 sats)" "POST" "/api/v1/confidential/shield" \
        '{"amount": 1000}'

    # P6.3: Confidential transfer
    test_api_no_500 "P6.3" "Confidential transfer (500 sats)" "POST" "/api/v1/confidential/transfer" \
        '{"to": "test", "amount": 500}'
}

# ══════════════════════════════════════════════════════════════════════
# Phase 7: Reconciliation (3 tests)
# ══════════════════════════════════════════════════════════════════════

phase_7() {
    phase_header 7 "Reconciliation" 3

    # P7.1: Reconcile lock
    if [[ -n "$FIRST_LOCK_ID" ]]; then
        test_api_no_500 "P7.1" "Reconcile lock ($FIRST_LOCK_ID)" "POST" "/api/v1/locks/$FIRST_LOCK_ID/reconcile"
    else
        run_test "P7.1" "Reconcile lock (requires lock from Phase 2)"
        skip "No locks found in Phase 2"
    fi

    # P7.2: List withdrawals
    test_api_no_500 "P7.2" "List withdrawals" "GET" "/api/v1/withdrawals"

    # P7.3: Request withdrawal
    test_api_no_500 "P7.3" "Request withdrawal (1000 sats)" "POST" "/api/v1/withdrawals/request" \
        '{"amount": 1000}'
}

# ══════════════════════════════════════════════════════════════════════
# Phase 8: L2 Block State (3 tests)
# ══════════════════════════════════════════════════════════════════════

phase_8() {
    phase_header 8 "L2 Block State" 3

    # P8.1: Get L2 state from pool
    local l2_body=""
    run_test "P8.1" "Get L2 state (pool port)"
    local response http_code body_out
    response=$(curl -sf --connect-timeout 5 --max-time 15 -w "\n%{http_code}" "http://${HOST}:${POOL_PORT}/api/v1/l2/state" 2>/dev/null) || { fail "Connection failed"; }
    if [[ -n "${response:-}" ]]; then
        http_code=$(echo "$response" | tail -1)
        body_out=$(echo "$response" | sed '$d')
        if [[ "$http_code" != "200" ]]; then
            fail "HTTP $http_code"
        elif ! echo "$body_out" | jq . >/dev/null 2>&1; then
            fail "Invalid JSON"
        else
            l2_body="$body_out"
            pass
        fi
    fi

    # P8.2: Get L2 pending from ghost-pay
    test_api_no_500 "P8.2" "Get L2 pending (ghost-pay port)" "GET" "/api/v1/l2/pending"

    # P8.3: Validate state roots are 64-char hex
    run_test "P8.3" "Validate state roots (64-char hex)"
    if [[ -z "$l2_body" ]]; then
        skip "No L2 state from P8.1"
    else
        local prev_root new_root
        prev_root=$(echo "$l2_body" | jq -r '.prev_state_root // empty' 2>/dev/null)
        new_root=$(echo "$l2_body" | jq -r '.new_state_root // empty' 2>/dev/null)
        if [[ -z "$prev_root" ]] && [[ -z "$new_root" ]]; then
            skip "No state roots in L2 response"
        elif [[ "$prev_root" =~ ^[0-9a-fA-F]{64}$ ]] && [[ "$new_root" =~ ^[0-9a-fA-F]{64}$ ]]; then
            pass
            echo -e "        ${CYAN}→ prev: ${prev_root:0:16}...  new: ${new_root:0:16}...${NC}"
        else
            local reason=""
            if [[ -n "$prev_root" ]] && ! [[ "$prev_root" =~ ^[0-9a-fA-F]{64}$ ]]; then
                reason="prev_state_root invalid: '${prev_root:0:32}'"
            fi
            if [[ -n "$new_root" ]] && ! [[ "$new_root" =~ ^[0-9a-fA-F]{64}$ ]]; then
                [[ -n "$reason" ]] && reason="$reason; "
                reason="${reason}new_state_root invalid: '${new_root:0:32}'"
            fi
            fail "$reason"
        fi
    fi
}

# ══════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Ghost L2 Transaction Test Suite"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "  Host:           $HOST"
echo "  Ghost Pay port: $GHOST_PAY_PORT"
echo "  Pool port:      $POOL_PORT"
echo "  API secret:     ${API_SECRET:0:8}..."
if [[ $RUN_PHASE -ne 0 ]]; then
    echo "  Phase filter:   $RUN_PHASE"
fi
echo ""

START_TIME=$(date +%s)

should_run 1 && phase_1
should_run 2 && phase_2
should_run 3 && phase_3
should_run 4 && phase_4
should_run 5 && phase_5
should_run 6 && phase_6
should_run 7 && phase_7
should_run 8 && phase_8

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# ── Summary ───────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
echo -e "  ${BOLD}Results${NC}"
echo "════════════════════════════════════════════════════════════"
echo ""
echo -e "  ${GREEN}PASS:${NC} $PASS"
echo -e "  ${RED}FAIL:${NC} $FAIL"
echo -e "  ${YELLOW}SKIP:${NC} $SKIP"
echo -e "  Total:  $TOTAL"
echo -e "  Time:   ${DURATION}s"
echo ""

if [[ $FAIL -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}ALL TESTS PASSED${NC}"
    echo ""
    echo "  L2 transaction endpoints are healthy."
else
    echo -e "  ${RED}${BOLD}$FAIL TEST(S) FAILED${NC}"
    echo ""
    echo "  Review failures above. 5xx errors indicate server bugs."
fi

echo ""
exit $FAIL
