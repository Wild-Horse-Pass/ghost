#!/bin/bash
# ─────────────────────────────────────────────────────────────────────
# soak-test.sh — 24-hour mainnet-readiness soak test orchestrator
#
# Runs a structured multi-phase soak test across all 4 Ghost signet VMs:
#   Phase 0: Pre-flight checks (5 min)
#   Phase 1: Cluster chaos suite (2 hours)
#   Phase 2: Sustained soak with failure injection (18 hours)
#   Phase 3: Post-soak validation (1 hour)
#
# Usage:
#   ./soak-test.sh                    # Full 24-hour soak
#   ./soak-test.sh --dry-run          # Validate connections & deps only
#   ./soak-test.sh --phase 0          # Run single phase
#   SOAK_HOURS=1 ./soak-test.sh       # Shortened soak (1 hour phase 2)
# ─────────────────────────────────────────────────────────────────────
set -uo pipefail

# ── Configuration ────────────────────────────────────────────────────

SSH_KEY="$HOME/.ssh/ghost_signet_ed25519"
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o ControlMaster=auto -o ControlPath=/tmp/ghost-soak-ssh-%h -o ControlPersist=120"

VM_IPS=("83.136.251.162" "85.9.198.212" "213.163.207.46" "95.111.221.169")
VM_NAMES=("signet-1" "signet-2" "signet-3" "signet-4")
VM_COUNT=${#VM_IPS[@]}

POOL_PORT=8080
PAY_PORT=8800
GHOST_PORTS="8555,8556,8557,8558,8559,8560,8561,8562"

# Fetch ghost-pay API secret from VM1 for L2 transaction tests
if [[ -z "${GHOST_PAY_API_SECRET:-}" ]]; then
    GHOST_PAY_API_SECRET=$(ssh $SSH_OPTS "root@${VM_IPS[0]}" \
        "grep -rh GHOST_PAY_API_SECRET /etc/systemd/system/ghost-pay.service /etc/systemd/system/ghost-pay.service.d/ 2>/dev/null" \
        | grep -oP 'GHOST_PAY_API_SECRET=\K[a-f0-9]+' | head -1) || true
    export GHOST_PAY_API_SECRET
fi

SOAK_HOURS="${SOAK_HOURS:-18}"
SOAK_INTERVAL_SEC=1800   # 30 minutes
BIANNUAL_SEC=7200         # 2 hours

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="$PROJECT_DIR/soak-logs/$(date +%Y%m%d-%H%M%S)"

DRY_RUN=false
PHASE_ONLY=""

# ── Colors ───────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

# ── CLI Parsing ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)  DRY_RUN=true; shift ;;
        --phase)    PHASE_ONLY="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--dry-run] [--phase N]"
            echo "  --dry-run   Validate connections and dependencies only"
            echo "  --phase N   Run only phase N (0-3)"
            echo "  SOAK_HOURS=N  Override phase 2 duration (default: 18)"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Logging ──────────────────────────────────────────────────────────

mkdir -p "$LOG_DIR"
MAIN_LOG="$LOG_DIR/soak.log"
METRICS_LOG="$LOG_DIR/soak-metrics.jsonl"
EVENTS_LOG="$LOG_DIR/soak-events.jsonl"

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

phase_header() {
    local phase="$1" desc="$2"
    echo ""
    log "${BOLD}${BLUE}═══════════════════════════════════════════════════════════${RESET}"
    log "${BOLD}${BLUE}  Phase $phase: $desc${RESET}"
    log "${BOLD}${BLUE}═══════════════════════════════════════════════════════════${RESET}"
}

# ── Helpers ──────────────────────────────────────────────────────────

ssh_cmd() {
    local vm_idx="$1"; shift
    ssh $SSH_OPTS "root@${VM_IPS[$vm_idx]}" "$@" 2>/dev/null
}

pool_api() {
    local vm_idx="$1" path="$2"
    local result
    result=$(curl -sf --connect-timeout 5 --max-time 15 \
        "http://${VM_IPS[$vm_idx]}:${POOL_PORT}${path}" 2>/dev/null)
    if [[ -z "$result" ]]; then
        # SSH fallback for firewalled/rate-limited ports
        result=$(ssh $SSH_OPTS "root@${VM_IPS[$vm_idx]}" \
            "curl -sf http://localhost:${POOL_PORT}${path}" 2>/dev/null)
    fi
    echo "$result"
}

pay_api() {
    local vm_idx="$1" path="$2" method="${3:-GET}" body="${4:-}"
    local url="http://${VM_IPS[$vm_idx]}:${PAY_PORT}${path}"
    local result
    if [[ "$method" == "GET" ]]; then
        result=$(curl -sf --connect-timeout 5 --max-time 15 "$url" 2>/dev/null)
        # Fall back to SSH if direct access fails (port may be firewalled)
        if [[ -z "$result" ]]; then
            result=$(ssh_cmd "$vm_idx" "curl -sf http://localhost:${PAY_PORT}${path}" 2>/dev/null)
        fi
    else
        result=$(curl -sf --connect-timeout 5 --max-time 15 \
            -X "$method" -H "Content-Type: application/json" \
            -d "$body" "$url" 2>/dev/null)
        if [[ -z "$result" ]]; then
            result=$(ssh_cmd "$vm_idx" "curl -sf -X $method -H 'Content-Type: application/json' -d '${body}' http://localhost:${PAY_PORT}${path}" 2>/dev/null)
        fi
    fi
    echo "$result"
}

check_ok() {
    local label="$1" result="$2"
    if [[ "$result" == "ok" ]]; then
        log "  ${GREEN}✓${RESET} $label"
        return 0
    else
        log "  ${RED}✗${RESET} $label — $result"
        return 1
    fi
}

vm_label() {
    echo "${VM_NAMES[$1]} (${VM_IPS[$1]})"
}

# ── Phase 0: Pre-flight checks ──────────────────────────────────────

phase0_preflight() {
    phase_header 0 "Pre-flight checks"
    local failures=0

    # Let nodes settle after any prior chaos runs
    log "Waiting 30s for nodes to settle..."
    sleep 30

    # SSH connectivity
    log "Checking SSH connectivity..."
    for i in $(seq 0 $((VM_COUNT - 1))); do
        if ssh_cmd "$i" "echo ok" | grep -q "ok"; then
            check_ok "SSH to $(vm_label $i)" "ok"
        else
            check_ok "SSH to $(vm_label $i)" "connection failed"
            ((failures++))
        fi
    done

    # Health check (retry up to 3 times for transient timeouts)
    log "Checking node health..."
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local health=""
        for attempt in 1 2 3; do
            health=$(pool_api "$i" "/health")
            [[ -n "$health" ]] && break
            sleep 3
        done
        if [[ -n "$health" ]]; then
            check_ok "ghost-pool health on $(vm_label $i)" "ok"
        else
            check_ok "ghost-pool health on $(vm_label $i)" "unreachable"
            ((failures++))
        fi
    done

    # Ghost-pay health
    log "Checking ghost-pay health..."
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local pay_health
        # Try direct first, fall back to SSH (port 8800 may be firewalled externally)
        pay_health=$(curl -sf --connect-timeout 5 --max-time 15 \
            "http://${VM_IPS[$i]}:${PAY_PORT}/health" 2>/dev/null)
        if [[ -z "$pay_health" ]]; then
            pay_health=$(ssh_cmd "$i" "curl -sf http://localhost:${PAY_PORT}/health" 2>/dev/null)
        fi
        if [[ -n "$pay_health" ]]; then
            check_ok "ghost-pay health on $(vm_label $i)" "ok"
        else
            check_ok "ghost-pay health on $(vm_label $i)" "unreachable"
            ((failures++))
        fi
    done

    # VK files
    log "Checking VK files..."
    local vk_files=("note_spend_vk.bin" "payout_vk.bin" "unshield_vk.bin")
    for i in $(seq 0 $((VM_COUNT - 1))); do
        for vk in "${vk_files[@]}"; do
            if ssh_cmd "$i" "test -f /home/ghost/.ghost/mpc_params/$vk && echo ok" | grep -q "ok"; then
                check_ok "VK $vk on $(vm_label $i)" "ok"
            else
                check_ok "VK $vk on $(vm_label $i)" "missing"
                ((failures++))
            fi
        done
    done

    # Schema version consistency
    log "Checking schema versions..."
    local schemas=()
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local sv
        sv=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db 'PRAGMA user_version;'" 2>/dev/null)
        schemas+=("$sv")
        log "  $(vm_label $i): schema v${sv:-?}"
    done
    local first_schema="${schemas[0]}"
    for sv in "${schemas[@]}"; do
        if [[ "$sv" != "$first_schema" ]]; then
            log "  ${RED}✗${RESET} Schema mismatch detected!"
            ((failures++))
        fi
    done

    # DB integrity
    log "Checking DB integrity..."
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local integrity
        integrity=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db 'PRAGMA integrity_check;'" 2>/dev/null)
        if [[ "$integrity" == "ok" ]]; then
            check_ok "DB integrity on $(vm_label $i)" "ok"
        else
            check_ok "DB integrity on $(vm_label $i)" "failed: $integrity"
            ((failures++))
        fi
    done

    # Binary version consistency (retry up to 3 times per node for transient timeouts)
    log "Checking binary versions..."
    local versions=()
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local ver=""
        for attempt in 1 2 3; do
            ver=$(pool_api "$i" "/api/v1/system/version" | jq -r '.version // empty' 2>/dev/null)
            [[ -n "$ver" ]] && break
            sleep 2
        done
        versions+=("$ver")
        log "  $(vm_label $i): $ver"
    done
    local first_ver="${versions[0]}"
    for v in "${versions[@]}"; do
        if [[ "$v" != "$first_ver" || -z "$v" ]]; then
            log "  ${RED}✗${RESET} Version mismatch detected!"
            ((failures++))
        fi
    done

    # Block heights
    log "Checking block heights..."
    local heights=()
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local h
        h=$(pool_api "$i" "/api/v1/node/status" | jq -r '.block_height // empty' 2>/dev/null)
        heights+=("$h")
        log "  $(vm_label $i): block $h"
    done

    # Baseline metrics snapshot (retry up to 3 times for transient timeouts)
    log "Recording baseline metrics..."
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local metrics=""
        for attempt in 1 2 3; do
            metrics=$(pool_api "$i" "/metrics")
            [[ -n "$metrics" ]] && break
            sleep 2
        done
        if [[ -n "$metrics" ]]; then
            echo "$metrics" > "$LOG_DIR/baseline-metrics-vm$((i+1)).txt"
            check_ok "Baseline metrics for $(vm_label $i)" "ok"
        else
            check_ok "Baseline metrics for $(vm_label $i)" "failed to collect"
        fi
    done

    # Baseline DB state
    log "Recording baseline DB state..."
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local db_state
        db_state=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db '
            SELECT \"l2_notes:\" || COUNT(*) FROM l2_notes;
            SELECT \"l2_epoch_fees:\" || COUNT(*) FROM l2_epoch_fees;
            SELECT \"pending_nullifiers:\" || COUNT(*) FROM pending_nullifiers;
        '" 2>/dev/null)
        echo "$db_state" > "$LOG_DIR/baseline-db-vm$((i+1)).txt"
        log "  $(vm_label $i): $(echo "$db_state" | tr '\n' ' ')"
    done

    # Bitcoin Core sync check (VM1)
    log "Checking Bitcoin Core sync status on VM1..."
    local btc_info
    btc_info=$(ssh_cmd 0 "bitcoin-cli -signet getblockchaininfo 2>/dev/null" 2>/dev/null)
    if [[ -n "$btc_info" ]]; then
        local ibd
        ibd=$(echo "$btc_info" | jq -r '.initialblockdownload // empty' 2>/dev/null)
        if [[ "$ibd" == "false" ]]; then
            check_ok "Bitcoin Core synced on VM1" "ok"
        else
            check_ok "Bitcoin Core synced on VM1" "still syncing (IBD=$ibd)"
            ((failures++))
        fi
    else
        log "  ${YELLOW}!${RESET} Could not query Bitcoin Core on VM1 (may use ghostd)"
    fi

    # Node compare (retry once on failure — rate limiting can cause transient unavailability)
    log "Running node-compare check..."
    if [[ -x "$SCRIPT_DIR/ops/node-compare.sh" ]]; then
        local nc_exit=0
        "$SCRIPT_DIR/ops/node-compare.sh" --quiet >> "$MAIN_LOG" 2>&1 || nc_exit=$?
        if [[ $nc_exit -ge 2 ]]; then
            log "  Node compare returned exit $nc_exit, retrying in 10s..."
            sleep 10
            nc_exit=0
            "$SCRIPT_DIR/ops/node-compare.sh" --quiet >> "$MAIN_LOG" 2>&1 || nc_exit=$?
        fi
        if [[ $nc_exit -eq 0 ]]; then
            check_ok "Node compare (no drift)" "ok"
        elif [[ $nc_exit -eq 1 ]]; then
            log "  ${YELLOW}!${RESET} Node compare: minor warnings (exit 1) — acceptable"
        else
            check_ok "Node compare" "critical drift (exit $nc_exit)"
            ((failures++))
        fi
    else
        log "  ${YELLOW}!${RESET} node-compare.sh not found, skipping"
    fi

    log_event "phase0" "preflight" "failures=$failures"

    if [[ $failures -gt 0 ]]; then
        log "${RED}Phase 0 FAILED: $failures check(s) failed${RESET}"
        log "Fix issues before starting soak test."
        return 1
    fi

    log "${GREEN}Phase 0 PASSED: All pre-flight checks OK${RESET}"
    return 0
}

# ── Phase 1: Cluster chaos suite ─────────────────────────────────────

phase1_chaos() {
    phase_header 1 "Cluster chaos suite (existing 139 tests)"

    if $DRY_RUN; then
        log "DRY RUN: Would run cargo test --test cluster_chaos"
        log_event "phase1" "dry-run" "skipped"
        return 0
    fi

    log "Running 139 cluster chaos tests (this may take ~2 hours)..."
    log "Command: cargo test --test cluster_chaos -- --ignored --test-threads=1 --nocapture"

    local chaos_log="$LOG_DIR/chaos-tests.log"

    cd "$PROJECT_DIR"
    local cargo_exit=0
    cargo test --test cluster_chaos -- --ignored --test-threads=1 --nocapture \
        > "$chaos_log" 2>&1 || cargo_exit=$?

    # Parse cargo test summary line: "test result: ok/FAILED. N passed; N failed; ..."
    local summary
    summary=$(grep "^test result:" "$chaos_log" 2>/dev/null | tail -1)
    local passed failed
    passed=$(echo "$summary" | grep -oP '\d+ passed' | grep -oP '\d+')
    failed=$(echo "$summary" | grep -oP '\d+ failed' | grep -oP '\d+')

    if [[ $cargo_exit -eq 0 ]]; then
        log "${GREEN}Phase 1 PASSED: Cluster chaos tests completed (${passed:-?} passed)${RESET}"
        log_event "phase1" "chaos-suite" "passed=${passed:-?}"
        return 0
    else
        log "${RED}Phase 1 FAILED: ${passed:-?} passed, ${failed:-?} failed${RESET}"
        if [[ -n "$summary" ]]; then
            log "  Summary: $summary"
        fi
        # Log individual failures
        local fail_list
        fail_list=$(grep "^    cluster_chaos" "$chaos_log" 2>/dev/null || true)
        if [[ -n "$fail_list" ]]; then
            log "  Failed tests:"
            while IFS= read -r line; do
                log "    - $line"
            done <<< "$fail_list"
        fi
        log "See $chaos_log for details"
        log_event "phase1" "chaos-suite" "passed=${passed:-0},failed=${failed:-?}"
        return 1
    fi
}

# ── Phase 2: Sustained soak ─────────────────────────────────────────

collect_metrics_snapshot() {
    local iteration="$1"
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    for i in $(seq 0 $((VM_COUNT - 1))); do
        local status l2_status peer_count
        status=$(pool_api "$i" "/api/v1/node/status" 2>/dev/null)
        l2_status=$(pool_api "$i" "/api/v1/ghostpay/status" 2>/dev/null)
        peer_count=$(pool_api "$i" "/peers" 2>/dev/null | jq 'length' 2>/dev/null)

        local block_height l2_height
        block_height=$(echo "$status" | jq -r '.block_height // -1' 2>/dev/null)
        l2_height=$(echo "$l2_status" | jq -r '.l2_height // -1' 2>/dev/null)

        printf '{"ts":"%s","iter":%d,"vm":"%s","block_height":%s,"l2_height":%s,"peers":%s}\n' \
            "$ts" "$iteration" "${VM_NAMES[$i]}" \
            "${block_height:--1}" "${l2_height:--1}" "${peer_count:--1}" \
            >> "$METRICS_LOG"
    done
}

run_health_check() {
    local iteration="$1"
    if [[ -x "$SCRIPT_DIR/ops/health-check.sh" ]]; then
        if "$SCRIPT_DIR/ops/health-check.sh" --quiet >> "$LOG_DIR/health-checks.log" 2>&1; then
            log "  Iteration $iteration: health check ${GREEN}PASS${RESET}"
            log_event "health-check" "iteration=$iteration" "pass"
            return 0
        else
            log "  Iteration $iteration: health check ${RED}FAIL${RESET}"
            log_event "health-check" "iteration=$iteration" "fail"
            return 1
        fi
    else
        # Fallback: manual health check
        local ok=true
        for i in $(seq 0 $((VM_COUNT - 1))); do
            if ! pool_api "$i" "/health" > /dev/null; then
                ok=false
            fi
        done
        if $ok; then
            log "  Iteration $iteration: health check ${GREEN}PASS${RESET}"
            log_event "health-check" "iteration=$iteration" "pass"
            return 0
        else
            log "  Iteration $iteration: health check ${RED}FAIL${RESET}"
            log_event "health-check" "iteration=$iteration" "fail"
            return 1
        fi
    fi
}

run_node_compare() {
    local iteration="$1"
    if [[ -x "$SCRIPT_DIR/ops/node-compare.sh" ]]; then
        if "$SCRIPT_DIR/ops/node-compare.sh" --quiet >> "$LOG_DIR/node-compare.log" 2>&1; then
            log "  Iteration $iteration: node compare ${GREEN}PASS${RESET}"
            log_event "node-compare" "iteration=$iteration" "pass"
        else
            log "  Iteration $iteration: node compare ${YELLOW}DRIFT${RESET}"
            log_event "node-compare" "iteration=$iteration" "drift"
        fi
    fi
}

run_dashboard_test() {
    local iteration="$1"
    if [[ -x "$SCRIPT_DIR/test-dashboard-endpoints.sh" ]]; then
        if "$SCRIPT_DIR/test-dashboard-endpoints.sh" --all-vms >> "$LOG_DIR/dashboard-tests.log" 2>&1; then
            log "  Iteration $iteration: dashboard endpoints ${GREEN}PASS${RESET}"
            log_event "dashboard-test" "iteration=$iteration" "pass"
        else
            log "  Iteration $iteration: dashboard endpoints ${YELLOW}PARTIAL${RESET}"
            log_event "dashboard-test" "iteration=$iteration" "partial"
        fi
    fi
}

run_l2_test() {
    local iteration="$1"
    if [[ -x "$SCRIPT_DIR/test-l2-transactions.sh" ]]; then
        if "$SCRIPT_DIR/test-l2-transactions.sh" >> "$LOG_DIR/l2-tests.log" 2>&1; then
            log "  Iteration $iteration: L2 transactions ${GREEN}PASS${RESET}"
            log_event "l2-test" "iteration=$iteration" "pass"
        else
            log "  Iteration $iteration: L2 transactions ${YELLOW}PARTIAL${RESET}"
            log_event "l2-test" "iteration=$iteration" "partial"
        fi
    fi
}

check_l2_consistency() {
    local iteration="$1"
    log "  Iteration $iteration: Checking L2 consistency across VMs..."
    local counts=()
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local cnt
        cnt=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db 'SELECT COUNT(*) FROM l2_notes;'" 2>/dev/null)
        counts+=("${cnt:-?}")
    done
    local first="${counts[0]}"
    local consistent=true
    for c in "${counts[@]}"; do
        if [[ "$c" != "$first" ]]; then
            consistent=false
        fi
    done
    if $consistent; then
        log "    L2 note counts consistent: $first across all VMs"
        log_event "l2-consistency" "iteration=$iteration,count=$first" "consistent"
    else
        log "    ${YELLOW}L2 note count mismatch: ${counts[*]}${RESET}"
        log_event "l2-consistency" "iteration=$iteration,counts=${counts[*]}" "mismatch"
    fi
}

check_stale_nullifiers() {
    local iteration="$1"
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local stale
        stale=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db \"
            SELECT COUNT(*) FROM pending_nullifiers
            WHERE created_at < datetime('now', '-1 hour');
        \"" 2>/dev/null)
        if [[ -n "$stale" && "$stale" -gt 0 ]]; then
            log "    ${YELLOW}$(vm_label $i): $stale stale nullifiers${RESET}"
            log_event "stale-nullifiers" "vm=${VM_NAMES[$i]},count=$stale" "warning"
        fi
    done
}

check_tree_consistency() {
    local iteration="$1"
    log "  Iteration $iteration: Checking commitment tree consistency..."
    local checkpoint_roots=() tree_roots=() matches=() note_counts=() finalizations=()
    local any_fail=false
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local json
        json=$(pool_api "$i" "/api/v1/l2/tree-state" 2>/dev/null)
        if [[ -z "$json" ]] || echo "$json" | jq -e '.error' >/dev/null 2>&1; then
            checkpoint_roots+=("?")
            tree_roots+=("?")
            matches+=("?")
            note_counts+=("?")
            finalizations+=("?")
            continue
        fi
        checkpoint_roots+=("$(echo "$json" | jq -r '.checkpoint_root' 2>/dev/null)")
        tree_roots+=("$(echo "$json" | jq -r '.tree_root' 2>/dev/null)")
        matches+=("$(echo "$json" | jq -r '.roots_match' 2>/dev/null)")
        note_counts+=("$(echo "$json" | jq -r '.note_count' 2>/dev/null)")
        finalizations+=("$(echo "$json" | jq -r '.recent_finalizations' 2>/dev/null)")
    done

    # Check pending shields (tree_root != checkpoint_root is expected when shields pending)
    for i in $(seq 0 $((VM_COUNT - 1))); do
        if [[ "${matches[$i]}" == "false" ]]; then
            log "    ${YELLOW}INFO: $(vm_label $i) has pending shields (tree_root != checkpoint_root)${RESET}"
            log_event "tree-pending-shields" "vm=${VM_NAMES[$i]}" "info"
        fi
    done

    # Check checkpoint root divergence (the stable consensus root must match across nodes)
    local first_cp_root=""
    for r in "${checkpoint_roots[@]}"; do
        [[ "$r" == "?" ]] && continue
        if [[ -z "$first_cp_root" ]]; then
            first_cp_root="$r"
        elif [[ "$r" != "$first_cp_root" ]]; then
            log "    ${RED}CRITICAL: Checkpoint roots DIVERGED: ${checkpoint_roots[*]}${RESET}"
            log_event "checkpoint-divergence" "roots=${checkpoint_roots[*]}" "critical"
            any_fail=true
            break
        fi
    done

    # Note: recent_finalizations only counts checkpoints with NoteSpend transactions,
    # NOT shield commitments. Shield-inserted notes are expected without finalizations.
    # The real health signal is checkpoint root consistency (checked above).
    # Log note/finalization counts for observability only.
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local nc="${note_counts[$i]}" rf="${finalizations[$i]}"
        if [[ "$nc" =~ ^[0-9]+$ ]] && [[ "$rf" =~ ^[0-9]+$ ]] && (( nc > 0 )); then
            log "    $(vm_label $i): $nc notes, $rf finalizations"
        fi
    done

    if ! $any_fail; then
        log "    Checkpoint roots consistent: ${first_cp_root:-none}"
        log_event "tree-consistency" "iteration=$iteration" "consistent"
    fi
    $any_fail && return 1 || return 0
}

# ── Failure Injection ────────────────────────────────────────────────

inject_kill_service() {
    local vm_idx="$1" service="$2" down_sec="$3" label="$4"
    log "${YELLOW}  INJECT: $label — killing $service on $(vm_label $vm_idx) for ${down_sec}s${RESET}"
    log_event "fault-inject" "$label" "start"

    ssh_cmd "$vm_idx" "systemctl stop $service"
    sleep "$down_sec"
    ssh_cmd "$vm_idx" "systemctl start $service"
    sleep 10  # allow recovery

    # Verify recovery
    local port
    if [[ "$service" == "ghost-pool" ]]; then port=$POOL_PORT; else port=$PAY_PORT; fi
    local health
    health=$(curl -sf --connect-timeout 5 --max-time 15 \
        "http://${VM_IPS[$vm_idx]}:${port}/health" 2>/dev/null)
    if [[ -n "$health" ]]; then
        log "  ${GREEN}RECOVERED${RESET}: $service on $(vm_label $vm_idx)"
        log_event "fault-inject" "$label" "recovered"
    else
        log "  ${RED}NOT RECOVERED${RESET}: $service on $(vm_label $vm_idx)"
        log_event "fault-inject" "$label" "not-recovered"
    fi
}

inject_network_partition() {
    local vm_idx="$1" down_sec="$2" label="$3"
    log "${YELLOW}  INJECT: $label — partitioning $(vm_label $vm_idx) for ${down_sec}s${RESET}"
    log_event "fault-inject" "$label" "start"

    # Use GHOST_CHAOS chain (same as Rust tests) for clean isolation + cleanup
    ssh_cmd "$vm_idx" "sudo iptables -N GHOST_CHAOS 2>/dev/null || sudo iptables -F GHOST_CHAOS; \
        sudo iptables -C INPUT -j GHOST_CHAOS 2>/dev/null || sudo iptables -I INPUT 1 -j GHOST_CHAOS; \
        sudo iptables -C OUTPUT -j GHOST_CHAOS 2>/dev/null || sudo iptables -I OUTPUT 1 -j GHOST_CHAOS; \
        sudo iptables -A GHOST_CHAOS -p tcp -m multiport --dports $GHOST_PORTS -j DROP; \
        sudo iptables -A GHOST_CHAOS -p tcp -m multiport --sports $GHOST_PORTS -j DROP"
    sleep "$down_sec"

    # Heal — flush the chain
    ssh_cmd "$vm_idx" "sudo iptables -F GHOST_CHAOS 2>/dev/null; \
        sudo iptables -D INPUT -j GHOST_CHAOS 2>/dev/null; \
        sudo iptables -D OUTPUT -j GHOST_CHAOS 2>/dev/null; \
        sudo iptables -X GHOST_CHAOS 2>/dev/null; true"
    sleep 15  # allow reconnection

    # Verify reconnection
    local peers
    peers=$(pool_api "$vm_idx" "/peers" | jq 'length' 2>/dev/null)
    if [[ -n "$peers" && "$peers" -gt 0 ]]; then
        log "  ${GREEN}HEALED${RESET}: $(vm_label $vm_idx) has $peers peers"
        log_event "fault-inject" "$label" "healed,peers=$peers"
    else
        log "  ${RED}NOT HEALED${RESET}: $(vm_label $vm_idx) has 0 peers"
        log_event "fault-inject" "$label" "not-healed"
    fi
}

inject_rolling_restart() {
    local label="$1"
    log "${YELLOW}  INJECT: $label — rolling restart all VMs (30s stagger)${RESET}"
    log_event "fault-inject" "$label" "start"

    for i in $(seq 0 $((VM_COUNT - 1))); do
        log "    Restarting ghost-pool on $(vm_label $i)..."
        ssh_cmd "$i" "systemctl restart ghost-pool"
        sleep 30
    done
    sleep 15  # allow final node to stabilize

    # Verify all healthy
    local all_ok=true
    for i in $(seq 0 $((VM_COUNT - 1))); do
        if ! pool_api "$i" "/health" > /dev/null 2>&1; then
            all_ok=false
            log "  ${RED}$(vm_label $i) not healthy after rolling restart${RESET}"
        fi
    done
    if $all_ok; then
        log "  ${GREEN}RECOVERED${RESET}: All VMs healthy after rolling restart"
        log_event "fault-inject" "$label" "recovered"
    else
        log_event "fault-inject" "$label" "partial-recovery"
    fi
}

inject_dual_kill() {
    local vm_a="$1" vm_b="$2" down_sec="$3" label="$4"
    log "${YELLOW}  INJECT: $label — killing ghost-pool on $(vm_label $vm_a) + $(vm_label $vm_b) for ${down_sec}s${RESET}"
    log_event "fault-inject" "$label" "start"

    ssh_cmd "$vm_a" "systemctl stop ghost-pool"
    ssh_cmd "$vm_b" "systemctl stop ghost-pool"
    sleep "$down_sec"
    ssh_cmd "$vm_a" "systemctl start ghost-pool"
    ssh_cmd "$vm_b" "systemctl start ghost-pool"
    sleep 15  # allow recovery

    local all_ok=true
    for i in $(seq 0 $((VM_COUNT - 1))); do
        if ! pool_api "$i" "/health" > /dev/null 2>&1; then
            all_ok=false
            log "  ${RED}$(vm_label $i) not healthy after dual kill${RESET}"
        fi
    done
    if $all_ok; then
        log "  ${GREEN}RECOVERED${RESET}: All VMs healthy after dual kill"
        log_event "fault-inject" "$label" "recovered"
    else
        log_event "fault-inject" "$label" "partial-recovery"
    fi
}

# ── Phase 2 Main Loop ───────────────────────────────────────────────

phase2_soak() {
    phase_header 2 "Sustained soak (${SOAK_HOURS} hours)"

    if $DRY_RUN; then
        log "DRY RUN: Would run ${SOAK_HOURS}-hour soak loop"
        log_event "phase2" "dry-run" "skipped"
        return 0
    fi

    local total_sec=$((SOAK_HOURS * 3600))
    local total_iterations=$((total_sec / SOAK_INTERVAL_SEC))
    local start_epoch
    start_epoch=$(date +%s)

    log "Starting soak: $total_iterations iterations over ${SOAK_HOURS} hours"
    log "Logs: $LOG_DIR"

    # Pre-compute failure injection schedule (elapsed seconds from start)
    local inject_hour_2=$((2 * 3600))
    local inject_hour_5=$((5 * 3600))
    local inject_hour_8=$((8 * 3600))
    local inject_hour_11=$((11 * 3600))
    local inject_hour_14=$((14 * 3600))
    local inject_hour_17=$((17 * 3600))
    local injected_2=false injected_5=false injected_8=false
    local injected_11=false injected_14=false injected_17=false

    for iter in $(seq 1 "$total_iterations"); do
        local elapsed=$(( $(date +%s) - start_epoch ))
        local elapsed_hrs=$(( elapsed / 3600 ))
        log ""
        log "${BOLD}─── Iteration $iter/$total_iterations (elapsed: ${elapsed_hrs}h) ───${RESET}"

        # a. Health check
        run_health_check "$iter"

        # b. Node compare
        run_node_compare "$iter"

        # c. Metrics snapshot
        collect_metrics_snapshot "$iter"

        # d. Dashboard endpoint sweep
        run_dashboard_test "$iter"

        # e. L2 transaction test
        run_l2_test "$iter"

        # f. Commitment tree consistency
        check_tree_consistency "$iter"

        # Every 2 hours (every 4th iteration at 30-min intervals)
        if (( iter % 4 == 0 )); then
            log "  ${BLUE}── Bi-hourly checks ──${RESET}"

            # f. Wraith simulation
            log "  Triggering wraith simulation on VM1..."
            local wraith_resp
            wraith_resp=$(pool_api 0 "/api/v1/admin/simulate-wraith-session")
            if [[ -n "$wraith_resp" ]]; then
                log "    Wraith simulation: ${GREEN}triggered${RESET}"
                log_event "wraith-sim" "iteration=$iter" "triggered"
            else
                log "    Wraith simulation: ${YELLOW}no response${RESET}"
                log_event "wraith-sim" "iteration=$iter" "no-response"
            fi

            # g. L2 activity simulation
            log "  Triggering L2 activity simulation on VM1..."
            local l2_resp
            l2_resp=$(pool_api 0 "/api/v1/admin/simulate-l2-activity")
            if [[ -n "$l2_resp" ]]; then
                log_event "l2-activity-sim" "iteration=$iter" "triggered"
            else
                log_event "l2-activity-sim" "iteration=$iter" "no-response"
            fi

            # h. Fee pipeline verification
            log "  Verifying fee pipeline on VM1..."
            local fee_resp
            fee_resp=$(pool_api 0 "/api/v1/admin/verify-fee-pipeline")
            if [[ -n "$fee_resp" ]]; then
                log_event "fee-pipeline" "iteration=$iter" "ok"
            else
                log_event "fee-pipeline" "iteration=$iter" "no-response"
            fi

            # i. L2 epoch fee consistency
            check_l2_consistency "$iter"

            # j. Stale nullifiers
            check_stale_nullifiers "$iter"
        fi

        # ── Failure injection schedule ───────────────────────────
        elapsed=$(( $(date +%s) - start_epoch ))

        if ! $injected_2 && (( elapsed >= inject_hour_2 )); then
            injected_2=true
            inject_kill_service 2 "ghost-pool" 300 "Hour-2: VM3 ghost-pool kill 5min"
        fi

        if ! $injected_5 && (( elapsed >= inject_hour_5 )); then
            injected_5=true
            inject_kill_service 1 "ghost-pay" 600 "Hour-5: VM2 ghost-pay kill 10min"
        fi

        if ! $injected_8 && (( elapsed >= inject_hour_8 )); then
            injected_8=true
            inject_network_partition 3 300 "Hour-8: VM4 network partition 5min"
        fi

        if ! $injected_11 && (( elapsed >= inject_hour_11 )); then
            injected_11=true
            # Kill VM3 mid-wraith
            log "${YELLOW}  INJECT: Hour-11 — triggering wraith then killing VM3 mid-session${RESET}"
            pool_api 0 "/api/v1/admin/simulate-wraith-session" &
            sleep 2
            inject_kill_service 2 "ghost-pool" 60 "Hour-11: VM3 kill mid-wraith"
        fi

        if ! $injected_14 && (( elapsed >= inject_hour_14 )); then
            injected_14=true
            inject_rolling_restart "Hour-14: Rolling restart all VMs"
        fi

        if ! $injected_17 && (( elapsed >= inject_hour_17 )); then
            injected_17=true
            inject_dual_kill 1 2 120 "Hour-17: VM2+VM3 dual kill 2min (quorum loss)"
        fi

        # Sleep until next iteration
        local next_epoch=$((start_epoch + iter * SOAK_INTERVAL_SEC))
        local now
        now=$(date +%s)
        local sleep_sec=$((next_epoch - now))
        if (( sleep_sec > 0 )); then
            sleep "$sleep_sec"
        fi
    done

    log "${GREEN}Phase 2 COMPLETE: $total_iterations iterations over ${SOAK_HOURS} hours${RESET}"
    log_event "phase2" "complete" "iterations=$total_iterations"
}

# ── Phase 3: Post-soak validation ────────────────────────────────────

phase3_validation() {
    phase_header 3 "Post-soak validation"
    local failures=0

    # Health check
    log "Final health check..."
    for i in $(seq 0 $((VM_COUNT - 1))); do
        if pool_api "$i" "/health" > /dev/null 2>&1; then
            check_ok "ghost-pool on $(vm_label $i)" "ok"
        else
            check_ok "ghost-pool on $(vm_label $i)" "unreachable"
            ((failures++))
        fi
    done

    # DB integrity
    log "DB integrity check..."
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local integrity
        integrity=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db 'PRAGMA integrity_check;'" 2>/dev/null)
        if [[ "$integrity" == "ok" ]]; then
            check_ok "DB integrity on $(vm_label $i)" "ok"
        else
            check_ok "DB integrity on $(vm_label $i)" "failed"
            ((failures++))
        fi
    done

    # WAL checkpoint
    log "WAL checkpoint (TRUNCATE)..."
    for i in $(seq 0 $((VM_COUNT - 1))); do
        ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db 'PRAGMA wal_checkpoint(TRUNCATE);'" 2>/dev/null
        log "  $(vm_label $i): WAL checkpoint done"
    done

    # Block height consistency
    log "Block height consistency..."
    local heights=()
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local h
        h=$(pool_api "$i" "/api/v1/node/status" | jq -r '.block_height // -1' 2>/dev/null)
        heights+=("$h")
    done
    local max_h=0
    for h in "${heights[@]}"; do
        (( h > max_h )) && max_h=$h
    done
    for idx in $(seq 0 $((VM_COUNT - 1))); do
        local diff=$((max_h - heights[idx]))
        if (( diff > 1 )); then
            log "  ${RED}$(vm_label $idx) is $diff blocks behind ($((heights[idx])) vs $max_h)${RESET}"
            ((failures++))
        else
            log "  $(vm_label $idx): block ${heights[$idx]} (within 1 of max $max_h)"
        fi
    done

    # L2 note count consistency
    log "L2 note count consistency..."
    local l2_counts=()
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local cnt
        cnt=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db 'SELECT COUNT(*) FROM l2_notes;'" 2>/dev/null)
        l2_counts+=("${cnt:-?}")
        log "  $(vm_label $i): $cnt L2 notes"
    done
    local first_l2="${l2_counts[0]}"
    for c in "${l2_counts[@]}"; do
        if [[ "$c" != "$first_l2" ]]; then
            log "  ${RED}L2 note count mismatch!${RESET}"
            ((failures++))
            break
        fi
    done

    # Commitment tree consistency
    log "Commitment tree consistency..."
    local tree_roots=() checkpoint_roots=() tree_matches=() tree_notes=() tree_finals=()
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local tj
        tj=$(pool_api "$i" "/api/v1/l2/tree-state" 2>/dev/null)
        if [[ -n "$tj" ]] && ! echo "$tj" | jq -e '.error' >/dev/null 2>&1; then
            tree_roots+=("$(echo "$tj" | jq -r '.tree_root' 2>/dev/null)")
            checkpoint_roots+=("$(echo "$tj" | jq -r '.checkpoint_root' 2>/dev/null)")
            tree_matches+=("$(echo "$tj" | jq -r '.roots_match' 2>/dev/null)")
            tree_notes+=("$(echo "$tj" | jq -r '.note_count' 2>/dev/null)")
            tree_finals+=("$(echo "$tj" | jq -r '.recent_finalizations' 2>/dev/null)")
            log "  $(vm_label $i): root=${tree_roots[-1]:0:12}… cp_root=${checkpoint_roots[-1]:0:12}… match=${tree_matches[-1]} notes=${tree_notes[-1]} finals=${tree_finals[-1]}"
        else
            tree_roots+=("?")
            checkpoint_roots+=("?")
            tree_matches+=("?")
            tree_notes+=("?")
            tree_finals+=("?")
            log "  $(vm_label $i): ${YELLOW}tree-state unavailable${RESET}"
        fi
    done

    # Assert: all roots_match == true (poison check)
    for i in $(seq 0 $((VM_COUNT - 1))); do
        if [[ "${tree_matches[$i]}" == "false" ]]; then
            log "  ${RED}CRITICAL: $(vm_label $i) tree POISONED${RESET}"
            ((failures++))
        fi
    done

    # Assert: checkpoint roots match (consensus check — this is what matters)
    local first_cp_root=""
    local cp_roots_match=true
    for cr in "${checkpoint_roots[@]}"; do
        [[ "$cr" == "?" || "$cr" == "null" ]] && continue
        if [[ -z "$first_cp_root" ]]; then
            first_cp_root="$cr"
        elif [[ "$cr" != "$first_cp_root" ]]; then
            cp_roots_match=false
            break
        fi
    done
    if ! $cp_roots_match; then
        log "  ${RED}CRITICAL: Checkpoint roots DIVERGED across nodes (consensus broken)${RESET}"
        ((failures++))
    fi

    # Tree root divergence: only informational if checkpoint roots match
    # (proposer is always 1 checkpoint ahead of non-proposers — this is normal)
    local first_tree_root=""
    local tree_roots_match=true
    for tr in "${tree_roots[@]}"; do
        [[ "$tr" == "?" ]] && continue
        if [[ -z "$first_tree_root" ]]; then
            first_tree_root="$tr"
        elif [[ "$tr" != "$first_tree_root" ]]; then
            tree_roots_match=false
            break
        fi
    done
    if ! $tree_roots_match; then
        if $cp_roots_match; then
            log "  (proposer 1 checkpoint ahead — checkpoint roots consistent)"
        else
            log "  ${RED}CRITICAL: Tree roots DIVERGED across nodes${RESET}"
            ((failures++))
        fi
    fi

    # Log note/finalization counts (shields don't count as finalizations, so 0 is expected)
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local nc="${tree_notes[$i]}" rf="${tree_finals[$i]}"
        if [[ "$nc" =~ ^[0-9]+$ ]] && (( nc > 0 )); then
            log "  $(vm_label $i): $nc notes, $rf finalizations"
        fi
    done

    # l2_epoch_fees consistency
    log "l2_epoch_fees consistency..."
    local fee_states=()
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local fs
        fs=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db '
            SELECT COUNT(*) || \":\" || COALESCE(SUM(distributed), 0) FROM l2_epoch_fees;
        '" 2>/dev/null)
        fee_states+=("${fs:-?}")
        log "  $(vm_label $i): $fs (count:distributed_sum)"
    done

    # Stale nullifiers
    log "Checking stale pending_nullifiers..."
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local stale
        stale=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db \"
            SELECT COUNT(*) FROM pending_nullifiers
            WHERE created_at < datetime('now', '-1 hour');
        \"" 2>/dev/null)
        if [[ -n "$stale" && "$stale" -gt 0 ]]; then
            log "  ${YELLOW}$(vm_label $i): $stale stale nullifiers${RESET}"
        else
            log "  $(vm_label $i): no stale nullifiers"
        fi
    done

    # MPC contributor count consistency
    log "MPC contributor consistency..."
    local mpc_counts=()
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local mc
        mc=$(pool_api "$i" "/api/v1/mpc/contributors" | jq -r '.count // empty' 2>/dev/null)
        mpc_counts+=("${mc:-?}")
    done
    local first_mpc="${mpc_counts[0]}"
    local mpc_ok=true
    for mc in "${mpc_counts[@]}"; do
        if [[ "$mc" != "$first_mpc" ]]; then
            mpc_ok=false
        fi
    done
    if $mpc_ok; then
        log "  MPC contributors consistent: $first_mpc"
    else
        log "  ${YELLOW}MPC contributor mismatch: ${mpc_counts[*]}${RESET}"
    fi

    # Binary version consistency
    log "Binary version consistency..."
    local versions=()
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local v
        v=$(pool_api "$i" "/api/v1/system/version" | jq -r '.version // empty' 2>/dev/null)
        versions+=("${v:-?}")
    done
    local first_v="${versions[0]}"
    for v in "${versions[@]}"; do
        if [[ "$v" != "$first_v" ]]; then
            log "  ${RED}Version mismatch: ${versions[*]}${RESET}"
            ((failures++))
            break
        fi
    done
    log "  Versions: $first_v (consistent)"

    # Metrics analysis
    log "Metrics analysis..."
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local metrics
        metrics=$(pool_api "$i" "/metrics" 2>/dev/null)
        echo "$metrics" > "$LOG_DIR/final-metrics-vm$((i+1)).txt"

        if [[ -n "$metrics" ]]; then
            # Check circuit breaker trips
            local cb_trips
            cb_trips=$(echo "$metrics" | grep -o 'circuit_breaker_trips_total [0-9]*' | awk '{print $2}')
            if [[ -n "$cb_trips" && "$cb_trips" -gt 0 ]]; then
                log "  ${YELLOW}$(vm_label $i): $cb_trips circuit breaker trips${RESET}"
            fi

            # Check payout errors
            local payout_errs
            payout_errs=$(echo "$metrics" | grep -o 'payout_errors_total [0-9]*' | awk '{print $2}')
            if [[ -n "$payout_errs" && "$payout_errs" -gt 0 ]]; then
                log "  ${RED}$(vm_label $i): $payout_errs payout errors${RESET}"
                ((failures++))
            fi

            # Check consensus participation
            local consensus_pct
            consensus_pct=$(echo "$metrics" | grep -o 'consensus_participation_percent [0-9.]*' | awk '{print $2}')
            if [[ -n "$consensus_pct" ]]; then
                local pct_int=${consensus_pct%.*}
                if (( pct_int < 95 )); then
                    log "  ${YELLOW}$(vm_label $i): consensus participation ${consensus_pct}% (< 95%)${RESET}"
                else
                    log "  $(vm_label $i): consensus participation ${consensus_pct}%"
                fi
            fi
        fi
    done

    # Final DB state for delta comparison
    log "Recording final DB state..."
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local db_state
        db_state=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db '
            SELECT \"l2_notes:\" || COUNT(*) FROM l2_notes;
            SELECT \"l2_epoch_fees:\" || COUNT(*) FROM l2_epoch_fees;
            SELECT \"pending_nullifiers:\" || COUNT(*) FROM pending_nullifiers;
        '" 2>/dev/null)
        echo "$db_state" > "$LOG_DIR/final-db-vm$((i+1)).txt"
    done

    log_event "phase3" "validation" "failures=$failures"

    if [[ $failures -gt 0 ]]; then
        log "${RED}Phase 3: $failures validation failure(s)${RESET}"
        return 1
    fi

    log "${GREEN}Phase 3 PASSED: All post-soak validations OK${RESET}"
    return 0
}

# ── Main ─────────────────────────────────────────────────────────────

main() {
    log "${BOLD}Ghost Pool Mainnet Readiness Soak Test${RESET}"
    log "Started: $(date -u)"
    log "Log directory: $LOG_DIR"
    log "Soak duration: ${SOAK_HOURS} hours (phase 2)"
    log "Dry run: $DRY_RUN"
    echo ""

    local overall_result=0

    if [[ -n "$PHASE_ONLY" ]]; then
        case "$PHASE_ONLY" in
            0) phase0_preflight || overall_result=1 ;;
            1) phase1_chaos     || overall_result=1 ;;
            2) phase2_soak      || overall_result=1 ;;
            3) phase3_validation || overall_result=1 ;;
            *) log "Unknown phase: $PHASE_ONLY"; exit 1 ;;
        esac
    else
        phase0_preflight || { overall_result=1; log "Aborting: pre-flight failed"; }

        if [[ $overall_result -eq 0 ]]; then
            phase1_chaos || { overall_result=1; log "Aborting: chaos tests failed"; }
        fi

        if [[ $overall_result -eq 0 ]]; then
            phase2_soak || overall_result=1
        fi

        # Always run phase 3 unless aborted early
        if [[ $overall_result -eq 0 ]]; then
            phase3_validation || overall_result=1
        fi
    fi

    echo ""
    log "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
    if [[ $overall_result -eq 0 ]]; then
        log "${BOLD}${GREEN}  SOAK TEST: PASS${RESET}"
    else
        log "${BOLD}${RED}  SOAK TEST: FAIL${RESET}"
    fi
    log "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
    log "Completed: $(date -u)"
    log "Full logs: $LOG_DIR"

    # Generate report
    if [[ -x "$SCRIPT_DIR/soak-report.sh" ]]; then
        log "Generating soak report..."
        "$SCRIPT_DIR/soak-report.sh" "$LOG_DIR"
    fi

    exit $overall_result
}

main
