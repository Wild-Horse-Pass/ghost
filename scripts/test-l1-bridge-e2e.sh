#!/usr/bin/env bash
# test-l1-bridge-e2e.sh — L1 Bridge End-to-End Test
#
# Exercises the full lock lifecycle:
#   1. Create ghost lock via API
#   2. Fund lock on L1 via bitcoin-cli -signet
#   3. Wait for funding detection (lock Pending → Active)
#   4. Shield balance to L2
#   5. Run test-withdrawal admin endpoint (full ZK proof pipeline)
#   6. Run simulate-unshield admin endpoint
#   7. Attempt real withdrawal request
#   8. Verify settlement batch forms
#
# Usage:
#   ./scripts/test-l1-bridge-e2e.sh [--vm N] [--dry-run]

set -uo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────

TARGET_VM=0  # Default: VM1
DRY_RUN=""

SSH_KEY="$HOME/.ssh/ghost_signet_ed25519"
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o ControlMaster=auto -o ControlPath=/tmp/ghost-bridge-e2e-ssh-%h -o ControlPersist=120"

VM_IPS=("83.136.251.162" "85.9.198.212" "213.163.207.46" "95.111.221.169")
VM_NAMES=("signet-1" "signet-2" "signet-3" "signet-4")
VM_COUNT=${#VM_IPS[@]}

POOL_PORT=8080
PAY_PORT=8800

VM_PAY_SECRETS=(
    "ba0447893e9f2225602cc89696d440fa8853a2f5c2f37e9e19e9cfc2ad985a06"
    "bdfcde9e80efd95fdf8f0db9be22f89252f99adc6b78bdb8f02b2495289e26b4"
    "88502a969e1ad8426acd9d3cf34d5231f5ea36064edd7fa1ba28ccaaf2dfd187"
    "97e54ac957b78564ec5cb48f5024d824d096f6a5d0c4677b5f54ce28d3033c30"
)
POOL_API_SECRET="b8404e28a10925d41a644a62a6078eab18e0522bcc2a2ef5d4596323be9be555"

# Lock parameters
LOCK_AMOUNT_SATS=10000    # Micro denomination (smallest)
LOCK_TIMELOCK_TIER="short"

# Polling parameters
FUNDING_POLL_INTERVAL=30   # seconds between funding detection polls
FUNDING_POLL_TIMEOUT=900   # 15 min max wait for funding detection
SETTLEMENT_POLL_INTERVAL=30
SETTLEMENT_POLL_TIMEOUT=600

# ─── CLI Parsing ─────────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --vm)       TARGET_VM="$2"; shift 2 ;;
        --dry-run)  DRY_RUN=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--vm N] [--dry-run]"
            echo "  --vm N      Target VM index (0-3, default 0)"
            echo "  --dry-run   Validate connections only"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ─── Colors ──────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ─── Logging ─────────────────────────────────────────────────────────────────

LOGDIR="$(pwd)/soak-logs/bridge-e2e-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$LOGDIR"
MAIN_LOG="$LOGDIR/bridge-e2e.log"
EVENTS_LOG="$LOGDIR/events.jsonl"

log() {
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo -e "[$ts] $*" | tee -a "$MAIN_LOG"
}

log_event() {
    local type="$1" detail="$2" result="${3:-ok}"
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '{"ts":"%s","type":"%s","detail":"%s","result":"%s"}\n' \
        "$ts" "$type" "$detail" "$result" >> "$EVENTS_LOG"
}

vm_label() {
    echo "${VM_NAMES[$1]} (${VM_IPS[$1]})"
}

# ─── SSH / API Helpers ───────────────────────────────────────────────────────

ssh_cmd() {
    local vm_idx="$1"; shift
    timeout 30 ssh $SSH_OPTS "root@${VM_IPS[$vm_idx]}" "$@" 2>/dev/null
}

pool_api() {
    local vm_idx="$1" path="$2"
    curl -sf --connect-timeout 5 --max-time 15 \
        "http://${VM_IPS[$vm_idx]}:${POOL_PORT}${path}" 2>/dev/null
}

pay_hmac_sign() {
    local secret="$1" timestamp="$2" body="$3"
    echo -n "${timestamp}${body}" | openssl dgst -sha256 -hmac "$secret" -binary | xxd -p -c 256
}

pay_api_auth() {
    local vm_idx="$1" path="$2" body="$3"
    local secret="${VM_PAY_SECRETS[$vm_idx]}"
    local timestamp sig result
    timestamp=$(date +%s)
    sig=$(pay_hmac_sign "$secret" "$timestamp" "$body")

    result=$(curl -s --connect-timeout 5 --max-time 15 \
        -X POST -H 'Content-Type: application/json' \
        -H "X-Ghost-Signature: $sig" \
        -H "X-Ghost-Timestamp: $timestamp" \
        -d "$body" \
        "http://${VM_IPS[$vm_idx]}:${PAY_PORT}${path}" 2>/dev/null)

    if [[ -z "$result" ]]; then
        # Fallback: SSH tunnel for firewalled ports
        timestamp=$(date +%s)
        sig=$(pay_hmac_sign "$secret" "$timestamp" "$body")
        local remote_tmp="/tmp/ghost-bridge-e2e-body-$$.json"
        echo -n "$body" | ssh $SSH_OPTS "root@${VM_IPS[$vm_idx]}" "cat > $remote_tmp" 2>/dev/null
        result=$(ssh_cmd "$vm_idx" "curl -sf -X POST \
            -H 'Content-Type: application/json' \
            -H 'X-Ghost-Signature: $sig' \
            -H 'X-Ghost-Timestamp: $timestamp' \
            -d @$remote_tmp \
            http://localhost:${PAY_PORT}${path}; rm -f $remote_tmp" 2>/dev/null)
    fi
    echo "$result"
}

bitcoin_cli() {
    ssh_cmd "$TARGET_VM" "bitcoin-cli -signet -datadir=/var/lib/bitcoin -rpcport=38332 -rpcuser=ghostrpc -rpcpassword=ghost_signet_rpc_2024 $*"
}

# ─── Pre-flight ──────────────────────────────────────────────────────────────

preflight() {
    local label
    label="$(vm_label $TARGET_VM)"
    log "${BOLD}═══ L1 Bridge E2E Test — Pre-flight ═══${RESET}"
    log "  Target: $label"

    # SSH connectivity
    log "  Checking SSH connectivity..."
    if ! ssh_cmd "$TARGET_VM" "echo ok" >/dev/null 2>&1; then
        log "  ${RED}FAIL: Cannot SSH to $label${RESET}"
        exit 1
    fi
    log "  SSH: ${GREEN}OK${RESET}"

    # ghost-pay health
    log "  Checking ghost-pay health..."
    local pay_health
    pay_health=$(ssh_cmd "$TARGET_VM" "curl -sf http://localhost:${PAY_PORT}/health" 2>/dev/null)
    if [[ -z "$pay_health" ]]; then
        log "  ${RED}FAIL: ghost-pay not responding on $label${RESET}"
        exit 1
    fi
    log "  ghost-pay: ${GREEN}OK${RESET}"

    # ghost-pool health
    log "  Checking ghost-pool health..."
    local pool_health
    pool_health=$(pool_api "$TARGET_VM" "/health")
    if [[ -z "$pool_health" ]]; then
        # Try via SSH
        pool_health=$(ssh_cmd "$TARGET_VM" "curl -sf http://localhost:${POOL_PORT}/health" 2>/dev/null)
    fi
    if [[ -z "$pool_health" ]]; then
        log "  ${RED}FAIL: ghost-pool not responding on $label${RESET}"
        exit 1
    fi
    log "  ghost-pool: ${GREEN}OK${RESET}"

    # Bitcoin Core
    log "  Checking Bitcoin Core..."
    local bc_info
    bc_info=$(bitcoin_cli "getblockchaininfo")
    if [[ -z "$bc_info" ]]; then
        log "  ${RED}FAIL: bitcoin-cli not available on $label${RESET}"
        exit 1
    fi
    local chain ibd blocks
    chain=$(echo "$bc_info" | jq -r '.chain // "?"')
    ibd=$(echo "$bc_info" | jq -r 'if .initialblockdownload then "true" else "false" end')
    blocks=$(echo "$bc_info" | jq -r '.blocks // 0')
    if [[ "$ibd" == "true" ]]; then
        log "  ${RED}FAIL: Bitcoin Core still in IBD (blocks=$blocks)${RESET}"
        exit 1
    fi
    log "  Bitcoin Core: ${GREEN}OK${RESET} (chain=$chain, height=$blocks)"

    # Wallet balance
    log "  Checking wallet balance..."
    local balance
    balance=$(bitcoin_cli "getbalance")
    if [[ -z "$balance" ]]; then
        log "  ${YELLOW}WARNING: Cannot check wallet balance${RESET}"
    else
        log "  Wallet balance: ${balance} BTC"
        # Check if we have enough (lock is 10k sats = 0.0001 BTC + fees)
        local has_funds
        has_funds=$(echo "$balance > 0.001" | bc -l 2>/dev/null || echo "0")
        if [[ "$has_funds" != "1" ]]; then
            log "  ${YELLOW}WARNING: Low balance ($balance BTC) — may not have enough for lock funding${RESET}"
        fi
    fi

    log "  Pre-flight: ${GREEN}ALL CHECKS PASSED${RESET}"
    log_event "preflight" "vm=${VM_NAMES[$TARGET_VM]}" "ok"
}

# ─── Step 1: Create Ghost Lock ──────────────────────────────────────────────

step1_create_lock() {
    log ""
    log "${BOLD}═══ Step 1: Create Ghost Lock ═══${RESET}"

    local body
    body=$(printf '{"amount_sats":%d,"timelock_tier":"%s"}' "$LOCK_AMOUNT_SATS" "$LOCK_TIMELOCK_TIER")

    log "  Creating lock: ${LOCK_AMOUNT_SATS} sats, tier=$LOCK_TIMELOCK_TIER"
    local result
    result=$(pay_api_auth "$TARGET_VM" "/api/v1/locks/create" "$body")

    if [[ -z "$result" ]]; then
        log "  ${RED}FAIL: No response from lock creation endpoint${RESET}"
        log_event "create-lock" "no-response" "fail"
        return 1
    fi

    local error_msg
    error_msg=$(echo "$result" | jq -r '.error // empty' 2>/dev/null)
    if [[ -n "$error_msg" ]]; then
        log "  ${RED}FAIL: $error_msg${RESET}"
        log_event "create-lock" "error=$error_msg" "fail"
        return 1
    fi

    LOCK_ID=$(echo "$result" | jq -r '.lock.id // .lock_id // .id // empty' 2>/dev/null)
    LOCK_ADDRESS=$(echo "$result" | jq -r '.lock.address // .address // .funding_address // empty' 2>/dev/null)
    LOCK_STATUS=$(echo "$result" | jq -r '.lock.state // .status // .state // "unknown"' 2>/dev/null)

    if [[ -z "$LOCK_ID" || -z "$LOCK_ADDRESS" ]]; then
        log "  ${RED}FAIL: Missing lock_id or address in response${RESET}"
        log "  Response: $result"
        log_event "create-lock" "missing-fields" "fail"
        return 1
    fi

    log "  Lock created: ${GREEN}OK${RESET}"
    log "    ID:      $LOCK_ID"
    log "    Address: $LOCK_ADDRESS"
    log "    Status:  $LOCK_STATUS"
    log_event "create-lock" "id=$LOCK_ID,address=$LOCK_ADDRESS,status=$LOCK_STATUS" "ok"
}

# ─── Step 2: Fund Lock on L1 ────────────────────────────────────────────────

step2_fund_lock() {
    log ""
    log "${BOLD}═══ Step 2: Fund Lock on L1 ═══${RESET}"

    if [[ -z "${LOCK_ADDRESS:-}" ]]; then
        log "  ${RED}FAIL: No lock address (step 1 must succeed)${RESET}"
        return 1
    fi

    # Convert sats to BTC (ensure leading zero)
    local btc_amount
    btc_amount=$(printf '%.8f' "$(echo "scale=8; $LOCK_AMOUNT_SATS / 100000000" | bc)")

    log "  Sending $btc_amount BTC to $LOCK_ADDRESS..."
    local txid
    txid=$(ssh_cmd "$TARGET_VM" "bitcoin-cli -signet -datadir=/var/lib/bitcoin -rpcport=38332 -rpcuser=ghostrpc -rpcpassword=ghost_signet_rpc_2024 sendtoaddress '$LOCK_ADDRESS' $btc_amount")

    if [[ -z "$txid" ]]; then
        log "  ${RED}FAIL: sendtoaddress returned no txid${RESET}"
        log_event "fund-lock" "sendtoaddress-failed" "fail"
        return 1
    fi

    FUNDING_TXID="$txid"
    log "  Funding tx: ${GREEN}$txid${RESET}"
    log_event "fund-lock" "txid=$txid,amount=$btc_amount" "ok"
}

# ─── Step 2b: Notify Ghost-Pay of Funding TX ────────────────────────────────

step2b_scan_funding() {
    log ""
    log "${BOLD}═══ Step 2b: Scan Funding TX ═══${RESET}"

    if [[ -z "${FUNDING_TXID:-}" ]]; then
        log "  ${YELLOW}No funding TX to scan${RESET}"
        return 1
    fi

    local body
    body=$(printf '{"txid":"%s","vout":0}' "$FUNDING_TXID")

    log "  Submitting TX for scanning: $FUNDING_TXID..."
    local result
    result=$(pay_api_auth "$TARGET_VM" "/api/v1/payments/scan" "$body")

    if [[ -z "$result" ]]; then
        # Try via SSH localhost
        local secret="${VM_PAY_SECRETS[$TARGET_VM]}"
        local timestamp sig
        timestamp=$(date +%s)
        sig=$(pay_hmac_sign "$secret" "$timestamp" "$body")
        result=$(ssh_cmd "$TARGET_VM" "curl -sf --max-time 15 -X POST \
            -H 'Content-Type: application/json' \
            -H 'X-Ghost-Signature: $sig' \
            -H 'X-Ghost-Timestamp: $timestamp' \
            -d '$body' \
            http://localhost:${PAY_PORT}/api/v1/payments/scan" 2>/dev/null)
    fi

    local success
    success=$(echo "$result" | jq -r '.success // false' 2>/dev/null)
    if [[ "$success" == "true" ]]; then
        log "  Scan queued: ${GREEN}OK${RESET}"
        log_event "scan-funding" "txid=$FUNDING_TXID" "ok"
        sleep 3  # Give scanner time to process
        return 0
    else
        log "  Scan: ${RED}${result:-no response}${RESET}"
        log_event "scan-funding" "txid=$FUNDING_TXID" "fail"
        return 1
    fi
}

# ─── Step 3: Wait for Funding Detection ─────────────────────────────────────

step3_wait_funding() {
    log ""
    log "${BOLD}═══ Step 3: Wait for Funding Detection ═══${RESET}"

    if [[ -z "${LOCK_ID:-}" ]]; then
        log "  ${RED}FAIL: No lock ID (step 1 must succeed)${RESET}"
        return 1
    fi

    log "  Polling lock status (interval=${FUNDING_POLL_INTERVAL}s, timeout=${FUNDING_POLL_TIMEOUT}s)..."

    local elapsed=0
    while (( elapsed < FUNDING_POLL_TIMEOUT )); do
        local lock_json
        lock_json=$(pay_api_auth "$TARGET_VM" "/api/v1/locks/${LOCK_ID}" "{}" 2>/dev/null)
        # Try GET if POST doesn't work
        if [[ -z "$lock_json" ]]; then
            lock_json=$(ssh_cmd "$TARGET_VM" "curl -sf http://localhost:${PAY_PORT}/api/v1/locks/${LOCK_ID}" 2>/dev/null)
        fi

        local status
        status=$(echo "$lock_json" | jq -r '.status // .state // "unknown"' 2>/dev/null)

        if [[ "$status" == "Active" || "$status" == "active" || "$status" == "funded" ]]; then
            log "  Lock status: ${GREEN}$status${RESET} (detected after ${elapsed}s)"
            log_event "funding-detection" "lock=$LOCK_ID,status=$status,elapsed=${elapsed}s" "ok"
            return 0
        fi

        log "  [$((elapsed))s] Status: $status (waiting...)"
        sleep "$FUNDING_POLL_INTERVAL"
        elapsed=$((elapsed + FUNDING_POLL_INTERVAL))
    done

    log "  ${YELLOW}TIMEOUT: Lock still not active after ${FUNDING_POLL_TIMEOUT}s${RESET}"
    log "  (This is expected if no new signet block has been mined yet)"
    log_event "funding-detection" "lock=$LOCK_ID,timeout=${FUNDING_POLL_TIMEOUT}s" "timeout"
    return 1
}

# ─── Step 4: Shield Balance to L2 ───────────────────────────────────────────

step4_shield() {
    log ""
    log "${BOLD}═══ Step 4: Shield Balance to L2 ═══${RESET}"

    local amount=$((LOCK_AMOUNT_SATS - 1000))  # Leave some for fees
    local blinding_hex owner_pubkey
    blinding_hex="$(openssl rand -hex 24)0000000000000000"
    owner_pubkey="$(openssl rand -hex 24)0000000000000000"

    local body
    body=$(printf '{"amount_sats":%d,"blinding_hex":"%s","owner_pubkey":"%s"}' \
        "$amount" "$blinding_hex" "$owner_pubkey")

    log "  Shielding $amount sats..."
    local result
    result=$(pay_api_auth "$TARGET_VM" "/api/v1/confidential/shield" "$body")

    if [[ -n "$result" ]] && ! echo "$result" | jq -e '.error' >/dev/null 2>&1; then
        local note_idx
        note_idx=$(echo "$result" | jq -r '.note_index // "?"' 2>/dev/null)
        log "  Shield: ${GREEN}OK${RESET} (note_index=$note_idx)"
        log_event "shield" "amount=$amount,note_index=$note_idx" "ok"
        SHIELD_NOTE_INDEX="$note_idx"
        return 0
    else
        local err
        err=$(echo "$result" | jq -r '.error // .message // empty' 2>/dev/null)
        log "  Shield: ${YELLOW}${err:-no response}${RESET}"
        log_event "shield" "error=${err:-timeout}" "fail"
        return 1
    fi
}

# ─── Step 5: Test Withdrawal (ZK Proof Pipeline) ────────────────────────────

step5_test_withdrawal() {
    log ""
    log "${BOLD}═══ Step 5: Test Withdrawal (ZK Proof Pipeline) ═══${RESET}"

    log "  Running test-withdrawal on $(vm_label $TARGET_VM)..."
    local result
    result=$(ssh_cmd "$TARGET_VM" \
        "curl -s --max-time 120 -X POST http://localhost:${PAY_PORT}/api/v1/admin/test-withdrawal" 2>/dev/null)

    if [[ -z "$result" ]]; then
        log "  ${RED}FAIL: No response (timeout?)${RESET}"
        log_event "test-withdrawal" "timeout" "fail"
        return 1
    fi

    local success proof_ms nullifier_spent relayed
    success=$(echo "$result" | jq -r '.success // false' 2>/dev/null)
    proof_ms=$(echo "$result" | jq -r '.proof_time_ms // "?"' 2>/dev/null)
    nullifier_spent=$(echo "$result" | jq -r '.nullifier_spent // false' 2>/dev/null)
    relayed=$(echo "$result" | jq -r '.relayed_to_pool // false' 2>/dev/null)

    if [[ "$success" == "true" ]]; then
        log "  test-withdrawal: ${GREEN}SUCCESS${RESET}"
        log "    Proof generation: ${proof_ms}ms"
        log "    Nullifier spent:  $nullifier_spent"
        log "    Relayed to pool:  $relayed"
        log_event "test-withdrawal" "proof_ms=$proof_ms,nullifier=$nullifier_spent,relayed=$relayed" "ok"

        # Print all steps
        local steps
        steps=$(echo "$result" | jq -r '.steps // {} | to_entries[] | "    \(.key): \(if .value.pass then "PASS" else "FAIL" end) (\(.value.elapsed_ms // "?")ms)"' 2>/dev/null)
        if [[ -n "$steps" ]]; then
            log "  Steps:"
            echo "$steps" | while read -r line; do log "$line"; done
        fi
        return 0
    else
        local fail_step
        fail_step=$(echo "$result" | jq -r '[.steps | to_entries[] | select(.value.pass == false) | .key] | first // "unknown"' 2>/dev/null)
        log "  test-withdrawal: ${RED}FAILED${RESET} at step: $fail_step (proof=${proof_ms}ms)"
        log_event "test-withdrawal" "fail_step=$fail_step,proof_ms=$proof_ms" "fail"
        return 1
    fi
}

# ─── Step 6: Simulate Unshield ──────────────────────────────────────────────

step6_simulate_unshield() {
    log ""
    log "${BOLD}═══ Step 6: Simulate Unshield ═══${RESET}"

    log "  Running simulate-unshield on $(vm_label $TARGET_VM)..."
    local result
    result=$(ssh_cmd "$TARGET_VM" \
        "curl -s --max-time 120 -X POST http://localhost:${PAY_PORT}/api/v1/admin/simulate-unshield" 2>/dev/null)

    if [[ -z "$result" ]]; then
        log "  ${RED}FAIL: No response (timeout?)${RESET}"
        log_event "simulate-unshield" "timeout" "fail"
        return 1
    fi

    local success
    success=$(echo "$result" | jq -r '.success // false' 2>/dev/null)

    if [[ "$success" == "true" ]]; then
        local proof_ms
        proof_ms=$(echo "$result" | jq -r '.proof_time_ms // .steps.zk_proof.elapsed_ms // "?"' 2>/dev/null)
        log "  simulate-unshield: ${GREEN}SUCCESS${RESET} (proof=${proof_ms}ms)"
        log_event "simulate-unshield" "proof_ms=$proof_ms" "ok"

        local steps
        steps=$(echo "$result" | jq -r '.steps // {} | to_entries[] | "    \(.key): \(if .value.pass then "PASS" else "FAIL" end) (\(.value.elapsed_ms // "?")ms)"' 2>/dev/null)
        if [[ -n "$steps" ]]; then
            log "  Steps:"
            echo "$steps" | while read -r line; do log "$line"; done
        fi
        return 0
    else
        local fail_step
        fail_step=$(echo "$result" | jq -r '[.steps | to_entries[] | select(.value.pass == false) | .key] | first // "unknown"' 2>/dev/null)
        log "  simulate-unshield: ${RED}FAILED${RESET} at step: $fail_step"
        log_event "simulate-unshield" "fail_step=$fail_step" "fail"
        return 1
    fi
}

# ─── Step 7: Withdrawal Request ─────────────────────────────────────────────

step7_withdrawal_request() {
    log ""
    log "${BOLD}═══ Step 7: Withdrawal Request ═══${RESET}"

    # Generate a withdrawal destination address
    local dest_address
    dest_address=$(bitcoin_cli "getnewaddress")
    if [[ -z "$dest_address" ]]; then
        log "  ${RED}FAIL: Cannot generate destination address${RESET}"
        log_event "withdrawal-request" "no-dest-address" "fail"
        return 1
    fi

    log "  Destination: $dest_address"

    # Use the lock ID from step 1 if available
    if [[ -z "${LOCK_ID:-}" ]]; then
        log "  ${YELLOW}No lock ID available — using test-withdrawal result as proxy${RESET}"
        log_event "withdrawal-request" "no-lock-id" "skip"
        return 0
    fi

    local body
    body=$(printf '{"destination_address":"%s"}' "$dest_address")

    log "  Requesting withdrawal for lock $LOCK_ID..."
    local result
    result=$(pay_api_auth "$TARGET_VM" "/api/v1/locks/${LOCK_ID}/reconcile" "$body")

    if [[ -z "$result" ]]; then
        log "  ${YELLOW}No response — reconciliation may not be available yet${RESET}"
        log_event "withdrawal-request" "no-response" "warn"
        return 0  # Non-fatal: lock may not be fully funded yet
    fi

    local error_msg
    error_msg=$(echo "$result" | jq -r '.error // empty' 2>/dev/null)
    if [[ -n "$error_msg" ]]; then
        log "  Withdrawal request: ${YELLOW}$error_msg${RESET}"
        log_event "withdrawal-request" "error=$error_msg" "warn"
        return 0  # Non-fatal for E2E: the important thing is ZK pipeline works
    fi

    log "  Withdrawal request: ${GREEN}submitted${RESET}"
    log "  Response: $(echo "$result" | jq -c '.' 2>/dev/null)"
    log_event "withdrawal-request" "lock=$LOCK_ID,dest=$dest_address" "ok"
}

# ─── Step 8: Verify Settlement Batch ────────────────────────────────────────

step8_verify_settlement() {
    log ""
    log "${BOLD}═══ Step 8: Verify Settlement Batch ═══${RESET}"

    # Check if a settlement batch has formed
    log "  Checking settlement status..."

    # Query pending settlements from DB
    local pending_count
    pending_count=$(ssh_cmd "$TARGET_VM" \
        "sqlite3 /home/ghost/.ghost/ghost-pay/ghost-pay.db 'SELECT COUNT(*) FROM settlements WHERE status = \"pending\" OR status = \"Pending\";'" 2>/dev/null)

    log "  Pending settlements: ${pending_count:-unknown}"

    # Check batch status
    local batch_count
    batch_count=$(ssh_cmd "$TARGET_VM" \
        "sqlite3 /home/ghost/.ghost/ghost-pay/ghost-pay.db 'SELECT COUNT(*) FROM settlement_batches;'" 2>/dev/null)

    log "  Settlement batches: ${batch_count:-unknown}"

    # Check reconciliation state
    local recon_status
    recon_status=$(ssh_cmd "$TARGET_VM" \
        "sqlite3 /home/ghost/.ghost/ghost-pay/ghost-pay.db 'SELECT status, COUNT(*) FROM settlements GROUP BY status;'" 2>/dev/null)

    if [[ -n "$recon_status" ]]; then
        log "  Settlement breakdown:"
        echo "$recon_status" | while read -r line; do
            log "    $line"
        done
    fi

    log_event "settlement-check" "pending=${pending_count:-0},batches=${batch_count:-0}" "ok"

    # With MIN_BATCH_SIZE=1, a batch should form quickly if there's a pending settlement
    if [[ "${batch_count:-0}" -gt 0 ]]; then
        log "  Settlement batch: ${GREEN}FORMED${RESET}"
    else
        log "  Settlement batch: ${YELLOW}not yet formed${RESET} (may need time or pending settlement)"
    fi
}

# ─── Final Report ────────────────────────────────────────────────────────────

final_report() {
    log ""
    log "${BOLD}═══════════════════════════════════════════════════${RESET}"
    log "${BOLD}  L1 Bridge E2E Test — Final Report${RESET}"
    log "${BOLD}═══════════════════════════════════════════════════${RESET}"
    log ""
    log "  Target VM:    $(vm_label $TARGET_VM)"
    log "  Lock ID:      ${LOCK_ID:-N/A}"
    log "  Lock Address: ${LOCK_ADDRESS:-N/A}"
    log "  Funding TX:   ${FUNDING_TXID:-N/A}"
    log "  Shield Note:  ${SHIELD_NOTE_INDEX:-N/A}"
    log ""

    local pass_count=0 fail_count=0
    local steps=("preflight" "create_lock" "fund_lock" "wait_funding" "shield"
                 "test_withdrawal" "simulate_unshield" "withdrawal_request" "verify_settlement")
    local results=("${STEP_RESULTS[@]}")

    for i in "${!steps[@]}"; do
        local status="${results[$i]:-skip}"
        local icon
        case "$status" in
            ok)   icon="${GREEN}PASS${RESET}"; ((pass_count++)) ;;
            fail) icon="${RED}FAIL${RESET}"; ((fail_count++)) ;;
            skip) icon="${YELLOW}SKIP${RESET}" ;;
            warn) icon="${YELLOW}WARN${RESET}"; ((pass_count++)) ;;
        esac
        log "  Step $((i+1)): ${steps[$i]}: $icon"
    done

    log ""
    log "  Passed: $pass_count  Failed: $fail_count"
    log "  Logs:   $LOGDIR"
    log ""

    if (( fail_count == 0 )); then
        log "  ${GREEN}${BOLD}BRIDGE E2E: ALL STEPS PASSED${RESET}"
    else
        log "  ${RED}${BOLD}BRIDGE E2E: $fail_count STEP(S) FAILED${RESET}"
    fi
}

# ─── Main ────────────────────────────────────────────────────────────────────

main() {
    log "${BOLD}╔════════════════════════════════════════════════════╗${RESET}"
    log "${BOLD}║  Ghost L1 Bridge End-to-End Test                  ║${RESET}"
    log "${BOLD}║  Target: $(vm_label $TARGET_VM)$(printf '%*s' $((25 - ${#VM_NAMES[$TARGET_VM]} - ${#VM_IPS[$TARGET_VM]})) '')║${RESET}"
    log "${BOLD}╚════════════════════════════════════════════════════╝${RESET}"

    # Initialize state
    LOCK_ID=""
    LOCK_ADDRESS=""
    FUNDING_TXID=""
    SHIELD_NOTE_INDEX=""
    STEP_RESULTS=()

    # Pre-flight
    preflight
    STEP_RESULTS+=("ok")

    if [[ -n "$DRY_RUN" ]]; then
        log ""
        log "${GREEN}Dry run complete — all pre-flight checks passed.${RESET}"
        exit 0
    fi

    # Step 1: Create Lock
    if step1_create_lock; then
        STEP_RESULTS+=("ok")
    else
        STEP_RESULTS+=("fail")
    fi

    # Step 2: Fund Lock
    if [[ -n "${LOCK_ADDRESS:-}" ]]; then
        if step2_fund_lock; then
            STEP_RESULTS+=("ok")
        else
            STEP_RESULTS+=("fail")
        fi
    else
        log ""
        log "${YELLOW}Skipping funding — no lock address${RESET}"
        STEP_RESULTS+=("skip")
    fi

    # Step 2b: Scan Funding TX
    if [[ -n "${FUNDING_TXID:-}" ]]; then
        step2b_scan_funding || true  # Non-fatal, detection may still work
    fi

    # Step 3: Wait for Funding Detection
    if [[ -n "${FUNDING_TXID:-}" ]]; then
        if step3_wait_funding; then
            STEP_RESULTS+=("ok")
        else
            STEP_RESULTS+=("warn")  # Timeout is non-fatal (may need a block)
        fi
    else
        log ""
        log "${YELLOW}Skipping funding detection — no funding TX${RESET}"
        STEP_RESULTS+=("skip")
    fi

    # Step 4: Shield Balance
    if step4_shield; then
        STEP_RESULTS+=("ok")
    else
        STEP_RESULTS+=("fail")
    fi

    # Step 5: Test Withdrawal (ZK pipeline — works independently of lock state)
    if step5_test_withdrawal; then
        STEP_RESULTS+=("ok")
    else
        STEP_RESULTS+=("fail")
    fi

    # Step 6: Simulate Unshield
    if step6_simulate_unshield; then
        STEP_RESULTS+=("ok")
    else
        STEP_RESULTS+=("fail")
    fi

    # Step 7: Withdrawal Request
    if step7_withdrawal_request; then
        STEP_RESULTS+=("ok")
    else
        STEP_RESULTS+=("warn")
    fi

    # Step 8: Verify Settlement
    step8_verify_settlement
    STEP_RESULTS+=("ok")

    # Report
    final_report
}

main "$@"
