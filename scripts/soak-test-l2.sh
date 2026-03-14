#!/usr/bin/env bash
# soak-test-l2.sh — L2 Transaction Flow Soak Test
#
# Exercises the FULL L2 lifecycle on ALL VMs equally:
#   shield → ZK proof → transfer → consolidate → unshield (via admin simulation)
#
# Goals:
#   1. Prove balanced note distribution across all VMs (no single-VM accumulation)
#   2. Exercise ZK proof generation under fault injection
#   3. Verify note convergence after SIGKILL during L2 operations
#
# Usage:
#   ./scripts/soak-test-l2.sh [--hours N] [--no-inject]

set -uo pipefail
# Note: NOT using set -e — fault injection functions intentionally trigger failures.
# Each function handles its own error checking.

# ─── Configuration ───────────────────────────────────────────────────────────

SOAK_HOURS="${1:-6}"
NO_INJECT="${2:-}"
ITER_INTERVAL=600  # 10 minutes between iterations

SSH_KEY="$HOME/.ssh/ghost_signet_ed25519"
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o ControlMaster=auto -o ControlPath=/tmp/ghost-l2-soak-ssh-%h -o ControlPersist=120"

VM_IPS=("83.136.251.162" "85.9.198.212" "213.163.207.46" "95.111.221.169")
VM_NAMES=("signet-1" "signet-2" "signet-3" "signet-4")
VM_SSH=("ghost-vm1" "ghost-vm2" "ghost-vm3" "ghost-vm4")
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

# ─── Colors ──────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

# ─── Logging ─────────────────────────────────────────────────────────────────

LOGDIR="$(pwd)/soak-logs/l2-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$LOGDIR"
MAIN_LOG="$LOGDIR/soak-l2.log"
EVENTS_LOG="$LOGDIR/events.jsonl"
BALANCE_LOG="$LOGDIR/balance.csv"

# CSV header for balance tracking
echo "timestamp,iteration,vm1_pay_notes,vm2_pay_notes,vm3_pay_notes,vm4_pay_notes,vm1_pool_notes,vm2_pool_notes,vm3_pool_notes,vm4_pool_notes,vm1_checkpoint_root,vm2_checkpoint_root,vm3_checkpoint_root,vm4_checkpoint_root" > "$BALANCE_LOG"

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
        timestamp=$(date +%s)
        sig=$(pay_hmac_sign "$secret" "$timestamp" "$body")
        local remote_tmp="/tmp/ghost-l2-soak-body-$$.json"
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

pool_hmac_sign() {
    local secret_hex="$1" timestamp="$2" body="$3"
    local ts_le_hex
    ts_le_hex=$(printf '%016x' "$timestamp" | sed 's/\(..\)/\1\n/g' | tac | tr -d '\n')
    local msg_hex="${ts_le_hex}$(echo -n "$body" | xxd -p -c 65536)"
    echo -n "$msg_hex" | xxd -r -p | openssl dgst -sha256 -mac HMAC -macopt "hexkey:${secret_hex}" -binary | xxd -p -c 256
}

# ─── L2 Operations ───────────────────────────────────────────────────────────

shield_on_vm() {
    # Shield a small balance on a specific VM via ghost-pay API.
    local vm_idx="$1" iteration="$2"
    local amount=$((1000 + RANDOM % 9000))
    local blinding_hex owner_pubkey
    blinding_hex="$(openssl rand -hex 24)0000000000000000"
    owner_pubkey="$(openssl rand -hex 24)0000000000000000"

    local body
    body=$(printf '{"amount_sats":%d,"blinding_hex":"%s","owner_pubkey":"%s"}' \
        "$amount" "$blinding_hex" "$owner_pubkey")

    local result
    result=$(pay_api_auth "$vm_idx" "/api/v1/confidential/shield" "$body")

    if [[ -n "$result" ]] && ! echo "$result" | jq -e '.error' >/dev/null 2>&1; then
        local note_idx
        note_idx=$(echo "$result" | jq -r '.note_index // "?"' 2>/dev/null)
        log "    Shield $amount sats on $(vm_label $vm_idx): ${GREEN}OK${RESET} (index=$note_idx)"
        log_event "l2-shield" "vm=${VM_NAMES[$vm_idx]},amount=$amount,index=$note_idx" "ok"
        return 0
    else
        local err
        err=$(echo "$result" | jq -r '.error // .message // empty' 2>/dev/null)
        log "    Shield on $(vm_label $vm_idx): ${YELLOW}${err:-no response}${RESET}"
        log_event "l2-shield" "vm=${VM_NAMES[$vm_idx]}" "fail:${err:-timeout}"
        return 1
    fi
}

simulate_l2_on_vm() {
    # Run the admin simulate-l2-activity endpoint on a specific VM.
    # This exercises: shield → merkle proof → ZK proof gen → verify → apply to tree
    # Creates 3 notes per run: 1 shield + 1 change + 1 recipient
    local vm_idx="$1" iteration="$2"
    local label
    label="$(vm_label $vm_idx)"

    log "    Simulating L2 activity on $label..."

    local result
    result=$(ssh_cmd "$vm_idx" \
        "curl -sf --max-time 60 -X POST http://localhost:${PAY_PORT}/api/v1/admin/simulate-l2-activity" 2>/dev/null)

    if [[ -z "$result" ]]; then
        log "    L2 simulation on $label: ${YELLOW}no response (timeout?)${RESET}"
        log_event "l2-simulate" "vm=${VM_NAMES[$vm_idx]},iter=$iteration" "fail:timeout"
        return 1
    fi

    local success
    success=$(echo "$result" | jq -r '.success // false' 2>/dev/null)

    if [[ "$success" == "true" ]]; then
        local proof_ms verify_ms
        proof_ms=$(echo "$result" | jq -r '.steps.zk_proof.elapsed_ms // "?"' 2>/dev/null)
        verify_ms=$(echo "$result" | jq -r '.steps.verify_proof.elapsed_ms // "?"' 2>/dev/null)
        log "    L2 simulation on $label: ${GREEN}OK${RESET} (proof=${proof_ms}ms, verify=${verify_ms}ms)"
        log_event "l2-simulate" "vm=${VM_NAMES[$vm_idx]},proof_ms=$proof_ms" "ok"
        return 0
    else
        local fail_step
        fail_step=$(echo "$result" | jq -r '[.steps | to_entries[] | select(.value.pass == false) | .key] | first // "unknown"' 2>/dev/null)
        log "    L2 simulation on $label: ${RED}FAILED${RESET} at step: $fail_step"
        log_event "l2-simulate" "vm=${VM_NAMES[$vm_idx]},fail_step=$fail_step" "fail"
        return 1
    fi
}

simulate_wraith_on_vm() {
    # Run wraith session simulation on a specific VM (fire-and-forget).
    # The wraith endpoint starts a background session — don't wait for completion.
    local vm_idx="$1"
    local label
    label="$(vm_label $vm_idx)"

    log "    Wraith simulation on $label..."

    local result
    result=$(ssh_cmd "$vm_idx" \
        "curl -sf --max-time 10 -X POST http://localhost:${PAY_PORT}/api/v1/admin/simulate-wraith-session" 2>/dev/null) || true

    if [[ -n "$result" ]]; then
        log "    Wraith simulation on $label: ${GREEN}triggered${RESET}"
        log_event "wraith-sim" "vm=${VM_NAMES[$vm_idx]}" "ok"
    else
        log "    Wraith simulation on $label: ${YELLOW}no response${RESET}"
        log_event "wraith-sim" "vm=${VM_NAMES[$vm_idx]}" "fail"
    fi
}

# ─── Measurement ─────────────────────────────────────────────────────────────

collect_note_state() {
    # Collect note counts from both ghost-pay and ghost-pool on all VMs.
    # Returns arrays via global variables.
    local iteration="$1"
    PAY_NOTES=()
    POOL_NOTES=()
    CHECKPOINT_ROOTS=()
    ROOTS_MATCH=()

    for i in $(seq 0 $((VM_COUNT - 1))); do
        # Ghost-pay confidential notes (local wallet view)
        local pay_json
        pay_json=$(curl -sf --connect-timeout 5 --max-time 10 \
            "http://${VM_IPS[$i]}:${PAY_PORT}/api/v1/confidential/tree" 2>/dev/null)
        if [[ -z "$pay_json" ]]; then
            pay_json=$(ssh_cmd "$i" "curl -sf http://localhost:${PAY_PORT}/api/v1/confidential/tree" 2>/dev/null)
        fi
        local pn
        pn=$(echo "$pay_json" | jq -r '.note_count // "?"' 2>/dev/null)
        PAY_NOTES+=("${pn:-?}")

        # Ghost-pool L2 notes (consensus view)
        local pool_json
        pool_json=$(curl -sf --connect-timeout 5 --max-time 10 \
            "http://${VM_IPS[$i]}:${POOL_PORT}/api/v1/l2/tree-state" 2>/dev/null)
        local pooln cp_root rm
        pooln=$(echo "$pool_json" | jq -r '.note_count // "?"' 2>/dev/null)
        cp_root=$(echo "$pool_json" | jq -r '.checkpoint_root // "?"' 2>/dev/null)
        rm=$(echo "$pool_json" | jq -r '.roots_match // "?"' 2>/dev/null)
        POOL_NOTES+=("${pooln:-?}")
        CHECKPOINT_ROOTS+=("${cp_root:-?}")
        ROOTS_MATCH+=("${rm:-?}")
    done

    # Write to CSV
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "$ts,$iteration,${PAY_NOTES[0]},${PAY_NOTES[1]},${PAY_NOTES[2]},${PAY_NOTES[3]},${POOL_NOTES[0]},${POOL_NOTES[1]},${POOL_NOTES[2]},${POOL_NOTES[3]},${CHECKPOINT_ROOTS[0]:0:16},${CHECKPOINT_ROOTS[1]:0:16},${CHECKPOINT_ROOTS[2]:0:16},${CHECKPOINT_ROOTS[3]:0:16}" >> "$BALANCE_LOG"
}

print_note_table() {
    local iteration="$1"
    log "  ${BLUE}── Note Distribution (Iteration $iteration) ──${RESET}"
    log "  ┌──────────┬──────────────┬──────────────┬──────────────────┬─────────────┐"
    log "  │ VM       │ Pay Notes    │ Pool Notes   │ Checkpoint Root  │ Roots Match │"
    log "  ├──────────┼──────────────┼──────────────┼──────────────────┼─────────────┤"
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local root_short="${CHECKPOINT_ROOTS[$i]:0:16}"
        printf -v line "  │ %-8s │ %12s │ %12s │ %16s │ %11s │" \
            "${VM_NAMES[$i]}" "${PAY_NOTES[$i]}" "${POOL_NOTES[$i]}" "$root_short" "${ROOTS_MATCH[$i]}"
        log "$line"
    done
    log "  └──────────┴──────────────┴──────────────┴──────────────────┴─────────────┘"

    # Check balance distribution
    check_pay_balance
    check_pool_convergence
}

check_pay_balance() {
    # Check if ghost-pay note counts are roughly balanced across VMs.
    local min=999999 max=0 total=0 valid=0
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local n="${PAY_NOTES[$i]}"
        [[ "$n" == "?" ]] && continue
        (( n < min )) && min=$n
        (( n > max )) && max=$n
        total=$((total + n))
        valid=$((valid + 1))
    done

    if (( valid < 2 )); then
        return
    fi

    local spread=$((max - min))
    local avg=$((total / valid))

    if (( avg > 0 )); then
        local skew_pct=$(( (spread * 100) / avg ))
        if (( skew_pct > 50 )); then
            log "  ${YELLOW}WARNING: Pay note skew ${skew_pct}% (min=$min, max=$max, avg=$avg)${RESET}"
            log_event "pay-skew" "min=$min,max=$max,spread=$spread,skew_pct=$skew_pct" "warning"
        else
            log "  Pay note balance: ${GREEN}OK${RESET} (spread=$spread, skew=${skew_pct}%, avg=$avg)"
        fi
    fi
}

check_pool_convergence() {
    # Verify all ghost-pool L2 note counts are identical (consensus must agree).
    local first="" diverged=false
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local n="${POOL_NOTES[$i]}"
        [[ "$n" == "?" ]] && continue
        if [[ -z "$first" ]]; then
            first="$n"
        elif [[ "$n" != "$first" ]]; then
            diverged=true
            break
        fi
    done

    if $diverged; then
        log "  ${YELLOW}Pool note counts diverged: ${POOL_NOTES[*]}${RESET}"
        log_event "pool-divergence" "counts=${POOL_NOTES[*]}" "warning"
    else
        log "  Pool notes: ${GREEN}converged${RESET} ($first across all VMs)"
    fi

    # Check checkpoint root convergence
    local first_root="" root_diverged=false
    for r in "${CHECKPOINT_ROOTS[@]}"; do
        [[ "$r" == "?" ]] && continue
        if [[ -z "$first_root" ]]; then
            first_root="$r"
        elif [[ "$r" != "$first_root" ]]; then
            root_diverged=true
            break
        fi
    done

    if $root_diverged; then
        log "  ${RED}CRITICAL: Checkpoint roots diverged!${RESET}"
        log_event "checkpoint-divergence" "roots=${CHECKPOINT_ROOTS[*]}" "critical"
    else
        log "  Checkpoint roots: ${GREEN}converged${RESET} (${first_root:0:16})"
    fi
}

# ─── Fault Injection ─────────────────────────────────────────────────────────

kill9_ghost_pay() {
    local vm_idx="$1" label="$2"
    log "${YELLOW}  INJECT: $label — SIGKILL ghost-pay on $(vm_label $vm_idx)${RESET}"
    log_event "fault-inject" "$label" "start"

    local pre_notes
    pre_notes=$(ssh_cmd "$vm_idx" "sqlite3 /home/ghost/.ghost/ghost-pay/ghost-pay.db 'SELECT COUNT(*) FROM confidential_notes;'" 2>/dev/null)

    ssh_cmd "$vm_idx" "kill -9 \$(pgrep -f '/opt/ghost/bin/ghost-pay') 2>/dev/null; true"
    sleep 2
    ssh_cmd "$vm_idx" "systemctl start ghost-pay"
    sleep 15

    local post_notes
    post_notes=$(ssh_cmd "$vm_idx" "sqlite3 /home/ghost/.ghost/ghost-pay/ghost-pay.db 'SELECT COUNT(*) FROM confidential_notes;'" 2>/dev/null)
    local health
    health=$(ssh_cmd "$vm_idx" "curl -sf http://localhost:${PAY_PORT}/health" 2>/dev/null)

    if [[ -n "$health" ]]; then
        log "  ${GREEN}RECOVERED${RESET}: ghost-pay on $(vm_label $vm_idx) (notes: $pre_notes→$post_notes)"
        log_event "fault-inject" "$label" "recovered,notes=$pre_notes→$post_notes"
    else
        log "  ${RED}NOT RECOVERED${RESET}: ghost-pay on $(vm_label $vm_idx)"
        log_event "fault-inject" "$label" "not-recovered"
        return 1
    fi
}

kill9_ghost_pool() {
    local vm_idx="$1" label="$2"
    log "${YELLOW}  INJECT: $label — SIGKILL ghost-pool on $(vm_label $vm_idx)${RESET}"
    log_event "fault-inject" "$label" "start"

    local pre_notes
    pre_notes=$(ssh_cmd "$vm_idx" "sqlite3 /home/ghost/.ghost/ghost.db 'SELECT COUNT(*) FROM l2_notes;'" 2>/dev/null)

    ssh_cmd "$vm_idx" "kill -9 \$(pgrep -f '/opt/ghost/bin/ghost-pool') 2>/dev/null; true"
    sleep 2
    ssh_cmd "$vm_idx" "systemctl start ghost-pool"
    sleep 20

    local post_notes
    post_notes=$(ssh_cmd "$vm_idx" "sqlite3 /home/ghost/.ghost/ghost.db 'SELECT COUNT(*) FROM l2_notes;'" 2>/dev/null)
    local health
    health=$(pool_api "$vm_idx" "/health" 2>/dev/null)

    if [[ -n "$health" ]]; then
        log "  ${GREEN}RECOVERED${RESET}: ghost-pool on $(vm_label $vm_idx) (notes: $pre_notes→$post_notes)"
        log_event "fault-inject" "$label" "recovered,notes=$pre_notes→$post_notes"
    else
        log "  ${RED}NOT RECOVERED${RESET}: ghost-pool on $(vm_label $vm_idx)"
        log_event "fault-inject" "$label" "not-recovered"
        return 1
    fi
}

kill9_during_simulation() {
    # Start an L2 simulation on a VM, then SIGKILL ghost-pay mid-proof-generation.
    local vm_idx="$1" label="$2"
    log "${YELLOW}  INJECT: $label — SIGKILL ghost-pay mid-simulation on $(vm_label $vm_idx)${RESET}"
    log_event "fault-inject" "$label" "start"

    # Fire simulation in background (takes ~1-2s for proof gen)
    ssh_cmd "$vm_idx" \
        "nohup curl -sf --max-time 60 -X POST http://localhost:${PAY_PORT}/api/v1/admin/simulate-l2-activity > /dev/null 2>&1 &" || true

    # Wait 500ms for simulation to start, then SIGKILL ghost-pay
    sleep 0.5
    ssh_cmd "$vm_idx" "kill -9 \$(pgrep -f '/opt/ghost/bin/ghost-pay') 2>/dev/null; true" || true

    sleep 2
    ssh_cmd "$vm_idx" "systemctl start ghost-pay"
    sleep 15

    local health
    health=$(ssh_cmd "$vm_idx" "curl -sf http://localhost:${PAY_PORT}/health" 2>/dev/null)
    if [[ -n "$health" ]]; then
        log "  ${GREEN}RECOVERED${RESET}: ghost-pay on $(vm_label $vm_idx) after mid-simulation kill"
        log_event "fault-inject" "$label" "recovered"
    else
        log "  ${RED}NOT RECOVERED${RESET}: ghost-pay on $(vm_label $vm_idx)"
        log_event "fault-inject" "$label" "not-recovered"
    fi
}

# ─── Injection Schedule ──────────────────────────────────────────────────────
# Injection schedule indexed by iteration number.
# Spreads kills evenly across all 4 VMs.

should_inject() {
    local iteration="$1"
    [[ "$NO_INJECT" == "--no-inject" ]] && return 1

    case $iteration in
        3)  return 0 ;;  # Hour 0.5: VM2 ghost-pay kill during simulation
        6)  return 0 ;;  # Hour 1:   VM3 ghost-pool SIGKILL
        9)  return 0 ;;  # Hour 1.5: VM4 ghost-pay SIGKILL
        12) return 0 ;;  # Hour 2:   VM1 ghost-pay kill during simulation
        18) return 0 ;;  # Hour 3:   VM2 ghost-pool SIGKILL
        24) return 0 ;;  # Hour 4:   VM3 ghost-pay kill during simulation
        30) return 0 ;;  # Hour 5:   VM4 ghost-pool SIGKILL
        36) return 0 ;;  # Hour 6:   VM1 ghost-pool SIGKILL (if running 6+ hours)
        *)  return 1 ;;
    esac
}

run_injection() {
    local iteration="$1"
    case $iteration in
        3)  kill9_during_simulation 1 "Iter $iteration: VM2 ghost-pay mid-simulation" ;;
        6)  kill9_ghost_pool 2 "Iter $iteration: VM3 ghost-pool SIGKILL" ;;
        9)  kill9_ghost_pay 3 "Iter $iteration: VM4 ghost-pay SIGKILL" ;;
        12) kill9_during_simulation 0 "Iter $iteration: VM1 ghost-pay mid-simulation" ;;
        18) kill9_ghost_pool 1 "Iter $iteration: VM2 ghost-pool SIGKILL" ;;
        24) kill9_during_simulation 2 "Iter $iteration: VM3 ghost-pay mid-simulation" ;;
        30) kill9_ghost_pool 3 "Iter $iteration: VM4 ghost-pool SIGKILL" ;;
        36) kill9_ghost_pool 0 "Iter $iteration: VM1 ghost-pool SIGKILL" ;;
    esac
}

# ─── Pre-flight ──────────────────────────────────────────────────────────────

preflight() {
    log "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
    log "${BOLD}  L2 Transaction Flow Soak Test${RESET}"
    log "${BOLD}  Duration: ${SOAK_HOURS} hours | Interval: $((ITER_INTERVAL / 60)) min${RESET}"
    log "${BOLD}  Injections: $([ "$NO_INJECT" == "--no-inject" ] && echo "DISABLED" || echo "ENABLED")${RESET}"
    log "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
    log ""
    log "Logs: $LOGDIR"
    log ""

    # Verify all VMs healthy
    log "Pre-flight: Health check..."
    local all_ok=true
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local pool_health pay_health
        pool_health=$(pool_api "$i" "/health" 2>/dev/null)
        pay_health=$(ssh_cmd "$i" "curl -sf http://localhost:${PAY_PORT}/health" 2>/dev/null)

        if [[ -n "$pool_health" && -n "$pay_health" ]]; then
            log "  $(vm_label $i): ${GREEN}pool OK, pay OK${RESET}"
        else
            log "  $(vm_label $i): ${RED}pool=${pool_health:-DOWN}, pay=${pay_health:-DOWN}${RESET}"
            all_ok=false
        fi
    done

    if ! $all_ok; then
        log "${RED}Pre-flight FAILED: Not all VMs healthy${RESET}"
        exit 1
    fi

    # Capture initial state
    log ""
    log "Pre-flight: Initial note state..."
    collect_note_state 0
    print_note_table 0

    # Record initial pay note counts for final comparison
    INITIAL_PAY_NOTES=("${PAY_NOTES[@]}")
    INITIAL_POOL_NOTES=("${POOL_NOTES[@]}")

    log ""
    log "${GREEN}Pre-flight PASSED${RESET}"
    log ""
}

# ─── Main Iteration ─────────────────────────────────────────────────────────

run_iteration() {
    local iteration="$1"
    local total_iterations="$2"
    local elapsed_hours="$3"

    log "${BOLD}─── Iteration $iteration/$total_iterations (elapsed: ${elapsed_hours}h) ───${RESET}"

    # 1. Health check
    local all_healthy=true
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local h
        h=$(pool_api "$i" "/health" 2>/dev/null)
        if [[ -z "$h" ]]; then
            log "  ${RED}$(vm_label $i) pool UNHEALTHY${RESET}"
            all_healthy=false
        fi
    done
    if $all_healthy; then
        log "  Health: ${GREEN}all 4 VMs OK${RESET}"
    fi

    # 2. Shield on ALL VMs equally (round-robin)
    log "  ${BLUE}── Balanced Shields (all VMs) ──${RESET}"
    for i in $(seq 0 $((VM_COUNT - 1))); do
        shield_on_vm "$i" "$iteration" || true
    done

    # 3. Run L2 simulation on ALL VMs equally
    log "  ${BLUE}── L2 Simulations (all VMs) ──${RESET}"
    for i in $(seq 0 $((VM_COUNT - 1))); do
        simulate_l2_on_vm "$i" "$iteration" || true
    done

    # 4. Every 3rd iteration: wraith simulation on round-robin VM
    if (( iteration % 3 == 0 )); then
        local wraith_vm=$(( (iteration / 3) % VM_COUNT ))
        simulate_wraith_on_vm "$wraith_vm"
    fi

    # 5. Fault injection (if scheduled)
    if should_inject "$iteration"; then
        run_injection "$iteration"
        # Wait for recovery before measuring
        sleep 30
    fi

    # 6. BFT quorum check
    local quorum
    quorum=$(ssh_cmd 0 "sudo journalctl -u ghost-pool --since '2 min ago' --no-pager 2>&1" | grep "quorum" | tail -1)
    if [[ -n "$quorum" ]]; then
        local votes
        votes=$(echo "$quorum" | grep -oP 'votes=\K\d+')
        log "  BFT quorum: ${GREEN}${votes:-?}/4 votes${RESET}"
    else
        log "  BFT quorum: ${YELLOW}no recent quorum messages${RESET}"
    fi

    # 7. Collect and display note distribution
    collect_note_state "$iteration"
    print_note_table "$iteration"

    log ""
}

# ─── Final Validation ────────────────────────────────────────────────────────

final_validation() {
    log "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
    log "${BOLD}  Final Validation${RESET}"
    log "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
    log ""

    local failures=0

    # 1. All VMs healthy
    log "Check 1: Health..."
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local pool_h pay_h
        pool_h=$(pool_api "$i" "/health" 2>/dev/null)
        pay_h=$(ssh_cmd "$i" "curl -sf http://localhost:${PAY_PORT}/health" 2>/dev/null)
        if [[ -n "$pool_h" && -n "$pay_h" ]]; then
            log "  $(vm_label $i): ${GREEN}OK${RESET}"
        else
            log "  $(vm_label $i): ${RED}FAIL${RESET}"
            ((failures++))
        fi
    done

    # 2. DB integrity
    log "Check 2: DB integrity..."
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local pool_int pay_int
        pool_int=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db 'PRAGMA integrity_check;'" 2>/dev/null)
        pay_int=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost-pay/ghost-pay.db 'PRAGMA integrity_check;'" 2>/dev/null)
        if [[ "$pool_int" == "ok" && "$pay_int" == "ok" ]]; then
            log "  $(vm_label $i): ${GREEN}pool OK, pay OK${RESET}"
        else
            log "  $(vm_label $i): ${RED}pool=${pool_int:-?}, pay=${pay_int:-?}${RESET}"
            ((failures++))
        fi
    done

    # 3. Pool note convergence (MUST be identical)
    log "Check 3: Pool note convergence..."
    collect_note_state "final"
    local first_pool="${POOL_NOTES[0]}"
    local pool_converged=true
    for i in $(seq 1 $((VM_COUNT - 1))); do
        if [[ "${POOL_NOTES[$i]}" != "$first_pool" ]]; then
            pool_converged=false
            break
        fi
    done
    if $pool_converged; then
        log "  Pool notes: ${GREEN}CONVERGED${RESET} ($first_pool across all VMs)"
    else
        log "  Pool notes: ${RED}DIVERGED${RESET} (${POOL_NOTES[*]})"
        ((failures++))
    fi

    # 4. Checkpoint root convergence
    log "Check 4: Checkpoint root convergence..."
    local first_root="${CHECKPOINT_ROOTS[0]}"
    local roots_converged=true
    for i in $(seq 1 $((VM_COUNT - 1))); do
        if [[ "${CHECKPOINT_ROOTS[$i]}" != "$first_root" ]]; then
            roots_converged=false
            break
        fi
    done
    if $roots_converged; then
        log "  Checkpoint roots: ${GREEN}CONVERGED${RESET} (${first_root:0:16})"
    else
        log "  Checkpoint roots: ${RED}DIVERGED${RESET}"
        for i in $(seq 0 $((VM_COUNT - 1))); do
            log "    ${VM_NAMES[$i]}: ${CHECKPOINT_ROOTS[$i]:0:16}"
        done
        ((failures++))
    fi

    # 5. Pay note balance (skew < 50%)
    log "Check 5: Pay note balance..."
    local min=999999 max=0 total=0 valid=0
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local n="${PAY_NOTES[$i]}"
        [[ "$n" == "?" ]] && continue
        (( n < min )) && min=$n
        (( n > max )) && max=$n
        total=$((total + n))
        valid=$((valid + 1))
    done
    if (( valid >= 2 && total > 0 )); then
        local avg=$((total / valid))
        local spread=$((max - min))
        local skew_pct=0
        (( avg > 0 )) && skew_pct=$(( (spread * 100) / avg ))

        if (( skew_pct > 50 )); then
            log "  Pay note skew: ${RED}${skew_pct}%${RESET} (min=$min, max=$max) — UNBALANCED"
            ((failures++))
        else
            log "  Pay note skew: ${GREEN}${skew_pct}%${RESET} (min=$min, max=$max) — BALANCED"
        fi
    fi

    # 6. Growth verification (notes should have grown)
    log "Check 6: Note growth..."
    local grew=false
    if [[ "${POOL_NOTES[0]}" != "?" && "${INITIAL_POOL_NOTES[0]}" != "?" ]]; then
        local growth=$((POOL_NOTES[0] - INITIAL_POOL_NOTES[0]))
        if (( growth > 0 )); then
            log "  Pool notes grew: ${GREEN}${INITIAL_POOL_NOTES[0]} → ${POOL_NOTES[0]} (+$growth)${RESET}"
            grew=true
        fi
    fi
    if ! $grew; then
        log "  ${RED}No pool note growth detected${RESET}"
        ((failures++))
    fi

    # 7. Pay note growth per VM
    log "Check 7: Per-VM pay note growth..."
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local init="${INITIAL_PAY_NOTES[$i]}" final="${PAY_NOTES[$i]}"
        if [[ "$init" != "?" && "$final" != "?" ]]; then
            local g=$((final - init))
            log "  ${VM_NAMES[$i]}: $init → $final (+$g)"
        fi
    done

    # 8. Zero panics
    log "Check 8: Panic check (last hour)..."
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local pool_panics pay_panics
        pool_panics=$(ssh_cmd "$i" "sudo journalctl -u ghost-pool --since '1 hour ago' --no-pager 2>&1 | grep -ci 'panic'" 2>/dev/null || echo 0)
        pay_panics=$(ssh_cmd "$i" "sudo journalctl -u ghost-pay --since '1 hour ago' --no-pager 2>&1 | grep -ci 'panic'" 2>/dev/null || echo 0)
        if (( pool_panics == 0 && pay_panics == 0 )); then
            log "  ${VM_NAMES[$i]}: ${GREEN}zero panics${RESET}"
        else
            log "  ${VM_NAMES[$i]}: ${RED}pool=$pool_panics, pay=$pay_panics panics${RESET}"
            ((failures++))
        fi
    done

    # Final table
    log ""
    print_note_table "FINAL"

    log ""
    if (( failures == 0 )); then
        log "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
        log "${BOLD}${GREEN}  L2 SOAK TEST: PASS${RESET}"
        log "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
    else
        log "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
        log "${BOLD}${RED}  L2 SOAK TEST: FAIL ($failures failures)${RESET}"
        log "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
    fi

    log "Completed: $(date -u)"
    log "Full logs: $LOGDIR"
    log "Balance CSV: $BALANCE_LOG"

    return $failures
}

# ─── Main ────────────────────────────────────────────────────────────────────

main() {
    # Parse args
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --hours) SOAK_HOURS="$2"; shift 2 ;;
            --no-inject) NO_INJECT="--no-inject"; shift ;;
            *) shift ;;
        esac
    done

    local total_iterations=$(( (SOAK_HOURS * 3600) / ITER_INTERVAL ))
    local start_time
    start_time=$(date +%s)

    preflight

    for iteration in $(seq 1 "$total_iterations"); do
        local now elapsed_secs elapsed_hours
        now=$(date +%s)
        elapsed_secs=$((now - start_time))
        elapsed_hours=$((elapsed_secs / 3600))

        run_iteration "$iteration" "$total_iterations" "$elapsed_hours"

        # Sleep until next iteration (unless last)
        if (( iteration < total_iterations )); then
            local iter_end
            iter_end=$(date +%s)
            local iter_duration=$((iter_end - now))
            local sleep_time=$((ITER_INTERVAL - iter_duration))
            if (( sleep_time > 0 )); then
                log "Sleeping ${sleep_time}s until next iteration..."
                sleep "$sleep_time"
            fi
        fi
    done

    final_validation
}

main "$@"
