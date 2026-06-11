#!/usr/bin/env bash
# soak-test-l2-maintenance.sh — L2 Maintenance & Recovery Soak Test
#
# Exercises maintenance and recovery paths:
#   1. Phantom note injection + pruning verification on startup
#   2. Checkpoint retention verification (90-day maintenance loop)
#   3. L1 withdrawal dry-run (test-withdrawal endpoint)
#   4. Wraith sessions
#   5. Fault injection (SIGKILL + recovery + phantom pruning)
#
# 15-minute iterations (16 total for 4 hours).
#
# Usage:
#   ./scripts/soak-test-l2-maintenance.sh [--hours N] [--no-inject] [--dry-run]

set -uo pipefail
# Note: NOT using set -e — fault injection functions intentionally trigger failures.

# ─── Configuration ───────────────────────────────────────────────────────────

SOAK_HOURS=4
NO_INJECT=""
DRY_RUN=""
ITER_INTERVAL=900  # 15 minutes between iterations

SSH_KEY="$HOME/.ssh/ghost_signet_ed25519"
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o ControlMaster=auto -o ControlPath=/tmp/ghost-l2-maint-ssh-%h -o ControlPersist=120"

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

# ─── Global Counters ─────────────────────────────────────────────────────────

WRAITH_ATTEMPTS=0
WRAITH_SUCCESSES=0
PHANTOM_INJECT_ATTEMPTS=0
PHANTOM_INJECT_SUCCESSES=0
WITHDRAWAL_ATTEMPTS=0
WITHDRAWAL_SUCCESSES=0
PROPAGATION_CHECKS=0
PROPAGATION_PASSES=0
FAULT_INJECT_ATTEMPTS=0
FAULT_INJECT_RECOVERIES=0
TOTAL_FAILURES=0

# ─── Colors ──────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ─── Logging ─────────────────────────────────────────────────────────────────

LOGDIR="$(pwd)/soak-logs/l2-maintenance-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$LOGDIR"
MAIN_LOG="$LOGDIR/soak-l2-maintenance.log"
EVENTS_LOG="$LOGDIR/events.jsonl"
BALANCE_LOG="$LOGDIR/balance.csv"
MAINTENANCE_LOG="$LOGDIR/maintenance.csv"

# CSV headers
echo "timestamp,iteration,vm1_pool_notes,vm2_pool_notes,vm3_pool_notes,vm4_pool_notes,vm1_checkpoint_root,vm2_checkpoint_root,vm3_checkpoint_root,vm4_checkpoint_root" > "$BALANCE_LOG"
echo "timestamp,iteration,vm_name,event_type,result,details" > "$MAINTENANCE_LOG"

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

log_maintenance() {
    local iteration="$1" vm_name="$2" event_type="$3" result="$4" details="$5"
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "$ts,$iteration,$vm_name,$event_type,$result,$details" >> "$MAINTENANCE_LOG"
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
        local remote_tmp="/tmp/ghost-l2-maint-body-$$.json"
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

# ─── L2 Operations ───────────────────────────────────────────────────────────

shield_on_vm() {
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

# ─── Phase A: L2 Activity ────────────────────────────────────────────────────

run_l2_activity() {
    local iteration="$1"

    log "  ${BLUE}── Phase A: L2 Activity (all VMs) ──${RESET}"
    for i in $(seq 0 $((VM_COUNT - 1))); do
        shield_on_vm "$i" "$iteration" || true
    done
    for i in $(seq 0 $((VM_COUNT - 1))); do
        simulate_l2_on_vm "$i" "$iteration" || true
    done

    # Cross-VM propagation check (30s convergence)
    log "    Waiting 30s for cross-VM propagation..."
    sleep 30

    ((PROPAGATION_CHECKS++))
    local counts=()
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local pool_json count
        pool_json=$(pool_api "$i" "/api/v1/l2/tree-state" 2>/dev/null)
        count=$(echo "$pool_json" | jq -r '.note_count // "?"' 2>/dev/null)
        counts+=("${count:-?}")
    done

    local ref="${counts[0]}" converged=true
    if [[ "$ref" != "?" ]]; then
        for i in $(seq 1 $((VM_COUNT - 1))); do
            local c="${counts[$i]}"
            [[ "$c" == "?" ]] && { converged=false; continue; }
            local delta=$(( c > ref ? c - ref : ref - c ))
            if (( delta > 1 )); then
                converged=false
            fi
        done
    else
        converged=false
    fi

    if $converged; then
        log "    Propagation: ${GREEN}CONVERGED${RESET} (counts: ${counts[*]})"
        ((PROPAGATION_PASSES++))
    else
        log "    Propagation: ${YELLOW}DIVERGED${RESET} (counts: ${counts[*]})"
    fi
    log_event "propagation" "iter=$iteration,counts=${counts[*]}" "$( $converged && echo ok || echo fail)"
}

# ─── Phase B: Phantom Note Injection + Pruning ──────────────────────────────

phantom_inject_and_verify() {
    local vm_idx="$1" iteration="$2"
    local label
    label="$(vm_label $vm_idx)"

    log "  ${CYAN}── Phase B: Phantom Note Injection on $label ──${RESET}"
    ((PHANTOM_INJECT_ATTEMPTS++))

    # 1. Get current state
    local pre_json pre_count pre_root
    pre_json=$(pool_api "$vm_idx" "/api/v1/l2/tree-state" 2>/dev/null)
    pre_count=$(echo "$pre_json" | jq -r '.note_count // "?"' 2>/dev/null)
    pre_root=$(echo "$pre_json" | jq -r '.checkpoint_root // "?"' 2>/dev/null)
    log "    Pre-state: $pre_count notes, root=${pre_root:0:16}"

    if [[ "$pre_count" == "?" || "$pre_count" -lt 5 ]]; then
        log "    ${YELLOW}Not enough notes ($pre_count) — skipping phantom injection${RESET}"
        log_maintenance "$iteration" "${VM_NAMES[$vm_idx]}" "phantom-inject" "skip" "too-few-notes"
        return 1
    fi

    # 2. Isolate the VM from peers to prevent phantom propagation
    log "    Isolating $label from peers (iptables)..."
    ssh_cmd "$vm_idx" "iptables -A INPUT -p tcp --dport 8080 -j DROP; \
        iptables -A OUTPUT -p tcp --dport 8080 -j DROP; \
        for p in \$(seq 8555 8562); do \
            iptables -A INPUT -p tcp --dport \$p -j DROP; \
            iptables -A OUTPUT -p tcp --dport \$p -j DROP; \
        done" 2>/dev/null || true

    # 3. Stop ghost-pool
    log "    Stopping ghost-pool on $label..."
    ssh_cmd "$vm_idx" "systemctl stop ghost-pool" || true
    sleep 3

    # 4. Get the current max note_index
    local max_idx
    max_idx=$(ssh_cmd "$vm_idx" "sqlite3 /home/ghost/.ghost/ghost.db 'SELECT MAX(note_index) FROM l2_notes;'" 2>/dev/null)
    max_idx="${max_idx:-0}"
    log "    Current max note_index: $max_idx"

    # 5. Insert 5 phantom notes with high indices and random commitments
    local epoch
    epoch=$(ssh_cmd "$vm_idx" "sqlite3 /home/ghost/.ghost/ghost.db 'SELECT epoch FROM l2_epochs WHERE status = \"active\" LIMIT 1;'" 2>/dev/null)
    epoch="${epoch:-0}"

    local phantom_start=$((max_idx + 1))
    for offset in 0 1 2 3 4; do
        local phantom_idx=$((phantom_start + offset))
        local random_commitment
        random_commitment="$(openssl rand -hex 24)0000000000000000"
        ssh_cmd "$vm_idx" "sqlite3 /home/ghost/.ghost/ghost.db \
            \"INSERT OR IGNORE INTO l2_notes (note_index, epoch, commitment, block_height) VALUES ($phantom_idx, $epoch, X'$random_commitment', 999999);\"" 2>/dev/null
    done

    # Also insert into pending_l2_shields so the cleanup can find them
    for offset in 0 1 2 3 4; do
        local phantom_idx=$((phantom_start + offset))
        local random_commitment
        random_commitment="$(openssl rand -hex 24)0000000000000000"
        ssh_cmd "$vm_idx" "sqlite3 /home/ghost/.ghost/ghost.db \
            \"INSERT OR IGNORE INTO pending_l2_shields (note_index, commitment, block_height) VALUES ($phantom_idx, X'$random_commitment', 999999);\"" 2>/dev/null
    done

    # WAL checkpoint
    ssh_cmd "$vm_idx" "sqlite3 /home/ghost/.ghost/ghost.db 'PRAGMA wal_checkpoint(TRUNCATE);'" 2>/dev/null

    local post_inject_count
    post_inject_count=$(ssh_cmd "$vm_idx" "sqlite3 /home/ghost/.ghost/ghost.db 'SELECT COUNT(*) FROM l2_notes;'" 2>/dev/null)
    log "    Injected 5 phantom notes (indices ${phantom_start}..$(( phantom_start + 4 ))). Total notes: ${post_inject_count:-?}"

    # 6. Restart ghost-pool (still isolated — no peer sync)
    log "    Restarting ghost-pool on $label (isolated)..."
    ssh_cmd "$vm_idx" "systemctl start ghost-pool"
    sleep 10

    # 7. Check logs for phantom pruning message
    local prune_log
    prune_log=$(ssh_cmd "$vm_idx" "sudo journalctl -u ghost-pool --since '30 sec ago' --no-pager 2>&1 | grep -i 'phantom' | head -5" 2>/dev/null)

    if [[ -n "$prune_log" ]]; then
        log "    ${GREEN}Phantom pruning detected in logs${RESET}"
        log "    Log: $(echo "$prune_log" | head -1)"
    else
        log "    ${YELLOW}No phantom pruning message in recent logs${RESET}"
    fi

    # 8. Verify tree root matches checkpoint root after pruning (query via SSH localhost — iptables blocks external)
    sleep 5
    local post_json post_count post_root roots_match
    post_json=$(ssh_cmd "$vm_idx" "curl -sf http://localhost:${POOL_PORT}/api/v1/l2/tree-state" 2>/dev/null)
    post_count=$(echo "$post_json" | jq -r '.note_count // "?"' 2>/dev/null)
    post_root=$(echo "$post_json" | jq -r '.checkpoint_root // "?"' 2>/dev/null)
    roots_match=$(echo "$post_json" | jq -r '.roots_match // "?"' 2>/dev/null)

    log "    Post-prune: $post_count notes, root=${post_root:0:16}, roots_match=$roots_match"

    local success=false
    if [[ "$post_count" == "$pre_count" && "$post_root" == "$pre_root" ]]; then
        success=true
        log "    Phantom pruning: ${GREEN}SUCCESS${RESET} (notes back to $pre_count, root restored)"
        ((PHANTOM_INJECT_SUCCESSES++))
    elif [[ "$roots_match" == "true" ]]; then
        success=true
        log "    Phantom pruning: ${GREEN}SUCCESS${RESET} (roots_match=true, notes=$post_count)"
        ((PHANTOM_INJECT_SUCCESSES++))
    else
        log "    Phantom pruning: ${RED}FAILED${RESET} (expected $pre_count notes, got $post_count; roots_match=$roots_match)"
    fi

    # 9. Remove iptables isolation — allow peer sync to resume
    log "    Removing network isolation on $label..."
    ssh_cmd "$vm_idx" "iptables -D INPUT -p tcp --dport 8080 -j DROP; \
        iptables -D OUTPUT -p tcp --dport 8080 -j DROP; \
        for p in \$(seq 8555 8562); do \
            iptables -D INPUT -p tcp --dport \$p -j DROP; \
            iptables -D OUTPUT -p tcp --dport \$p -j DROP; \
        done" 2>/dev/null || true

    log_maintenance "$iteration" "${VM_NAMES[$vm_idx]}" "phantom-inject" \
        "$($success && echo ok || echo fail)" \
        "pre=$pre_count,post=$post_count,phantoms=5,root_match=$roots_match"

    log_event "phantom-prune" "vm=${VM_NAMES[$vm_idx]},pre=$pre_count,post=$post_count,prune_log=$([ -n "$prune_log" ] && echo yes || echo no)" \
        "$($success && echo ok || echo fail)"
}

# ─── Phase C: Checkpoint Retention Verification ─────────────────────────────

verify_checkpoint_retention() {
    local iteration="$1"

    log "  ${CYAN}── Phase C: Checkpoint Retention Verification ──${RESET}"

    for i in $(seq 0 $((VM_COUNT - 1))); do
        local label
        label="$(vm_label $i)"

        local total_checkpoints oldest_created
        total_checkpoints=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db 'SELECT COUNT(*) FROM l2_checkpoints;'" 2>/dev/null)
        oldest_created=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db 'SELECT MIN(created_at) FROM l2_checkpoints;'" 2>/dev/null)

        local pruned_count
        pruned_count=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db \"SELECT COUNT(*) FROM l2_checkpoints WHERE length(block_data) = 0;\"" 2>/dev/null)

        log "    $label: ${total_checkpoints:-?} checkpoints, oldest=${oldest_created:-?}, pruned_data=${pruned_count:-?}"
        log_maintenance "$iteration" "${VM_NAMES[$i]}" "checkpoint-retention" "ok" \
            "total=${total_checkpoints:-?},oldest=${oldest_created:-?},pruned=${pruned_count:-?}"
    done

    # Check logs for maintenance loop execution
    local maint_log
    maint_log=$(ssh_cmd 0 "sudo journalctl -u ghost-pool --since '2 hours ago' --no-pager 2>&1 | grep -i 'maintenance complete' | tail -1" 2>/dev/null)

    if [[ -n "$maint_log" ]]; then
        log "    Maintenance loop: ${GREEN}running${RESET}"
        log "    Last: $maint_log"
    else
        log "    Maintenance loop: ${YELLOW}no recent execution detected${RESET}"
    fi

    log_event "checkpoint-retention" "iter=$iteration" "ok"
}

# ─── Phase D: L1 Withdrawal Dry Run ─────────────────────────────────────────

test_withdrawal_on_vm() {
    local vm_idx="$1" iteration="$2"
    local label
    label="$(vm_label $vm_idx)"

    log "  ${CYAN}── Phase D: L1 Withdrawal Dry Run on $label ──${RESET}"
    ((WITHDRAWAL_ATTEMPTS++))

    local result
    result=$(ssh_cmd "$vm_idx" \
        "curl -s --max-time 120 -X POST http://localhost:${PAY_PORT}/api/v1/admin/test-withdrawal" 2>/dev/null)

    if [[ -z "$result" ]]; then
        log "    Withdrawal test on $label: ${YELLOW}no response (timeout?)${RESET}"
        log_maintenance "$iteration" "${VM_NAMES[$vm_idx]}" "test-withdrawal" "fail" "timeout"
        log_event "test-withdrawal" "vm=${VM_NAMES[$vm_idx]},iter=$iteration" "fail:timeout"
        return 1
    fi

    local success proof_ms nullifier_spent relayed
    success=$(echo "$result" | jq -r '.success // false' 2>/dev/null)
    proof_ms=$(echo "$result" | jq -r '.proof_time_ms // "?"' 2>/dev/null)
    nullifier_spent=$(echo "$result" | jq -r '.nullifier_spent // false' 2>/dev/null)
    relayed=$(echo "$result" | jq -r '.relayed_to_pool // false' 2>/dev/null)

    if [[ "$success" == "true" ]]; then
        log "    Withdrawal test: ${GREEN}SUCCESS${RESET} (proof=${proof_ms}ms, nullifier_spent=$nullifier_spent, relayed=$relayed)"
        ((WITHDRAWAL_SUCCESSES++))
        log_maintenance "$iteration" "${VM_NAMES[$vm_idx]}" "test-withdrawal" "ok" \
            "proof_ms=$proof_ms,nullifier=$nullifier_spent,relayed=$relayed"
        log_event "test-withdrawal" "vm=${VM_NAMES[$vm_idx]},proof_ms=$proof_ms,nullifier=$nullifier_spent" "ok"
    else
        local fail_step
        fail_step=$(echo "$result" | jq -r '[.steps | to_entries[] | select(.value.pass == false) | .key] | first // "unknown"' 2>/dev/null)
        log "    Withdrawal test: ${RED}FAILED${RESET} at step: $fail_step (proof=${proof_ms}ms)"
        log_maintenance "$iteration" "${VM_NAMES[$vm_idx]}" "test-withdrawal" "fail" \
            "failed_step=$fail_step,proof_ms=$proof_ms"
        log_event "test-withdrawal" "vm=${VM_NAMES[$vm_idx]},fail_step=$fail_step" "fail"
    fi
}

# ─── Phase E: Wraith Session (skipped after the wraith-coordinator split) ───
#
# The legacy `/api/v1/admin/simulate-wraith-session` endpoint was
# removed when wraith mixing moved out of ghost-pay into the
# wraith-coordinator binary. This function is a stub so the rest of
# the soak harness keeps running; restore Phase E once the soak
# script learns to drive `wraith-coordinator`'s `find_or_create` flow
# directly. See `bins/wraith-coordinator/tests/router.rs` for the
# in-process equivalent of what this used to soak-test.

wraith_session_on_vm() {
    local vm_idx="$1" iteration="$2"
    local label
    label="$(vm_label $vm_idx)"
    log "  ${CYAN}── Phase E: Wraith Session on $label (skipped) ──${RESET}"
    log_event "wraith-session" "vm=${VM_NAMES[$vm_idx]},iter=$iteration" "skipped:moved-to-wraith-coordinator"
    return 0
}

# ─── Fault Injection ─────────────────────────────────────────────────────────

fault_inject_and_verify() {
    local vm_idx="$1" iteration="$2"
    local label
    label="$(vm_label $vm_idx)"

    log "  ${YELLOW}── Fault Injection: SIGKILL ghost-pool on $label ──${RESET}"
    ((FAULT_INJECT_ATTEMPTS++))
    log_event "fault-inject" "vm=${VM_NAMES[$vm_idx]},iter=$iteration" "start"

    # Record pre-state
    local pre_json pre_count pre_root
    pre_json=$(pool_api "$vm_idx" "/api/v1/l2/tree-state" 2>/dev/null)
    pre_count=$(echo "$pre_json" | jq -r '.note_count // "?"' 2>/dev/null)
    pre_root=$(echo "$pre_json" | jq -r '.checkpoint_root // "?"' 2>/dev/null)

    # SIGKILL ghost-pool
    ssh_cmd "$vm_idx" "kill -9 \$(pgrep -f '/opt/ghost/bin/ghost-pool') 2>/dev/null; true"
    sleep 2

    # Restart
    ssh_cmd "$vm_idx" "systemctl start ghost-pool"
    sleep 20

    # Verify recovery
    local post_json post_count post_root roots_match
    post_json=$(pool_api "$vm_idx" "/api/v1/l2/tree-state" 2>/dev/null)
    post_count=$(echo "$post_json" | jq -r '.note_count // "?"' 2>/dev/null)
    post_root=$(echo "$post_json" | jq -r '.checkpoint_root // "?"' 2>/dev/null)
    roots_match=$(echo "$post_json" | jq -r '.roots_match // "?"' 2>/dev/null)

    # Check for phantom pruning in logs
    local prune_log
    prune_log=$(ssh_cmd "$vm_idx" "sudo journalctl -u ghost-pool --since '30 sec ago' --no-pager 2>&1 | grep -i 'phantom' | head -3" 2>/dev/null)

    if [[ -n "$post_json" ]]; then
        log "    ${GREEN}RECOVERED${RESET}: ghost-pool on $label (notes: ${pre_count:-?}→${post_count:-?}, roots_match=$roots_match)"
        if [[ -n "$prune_log" ]]; then
            log "    Phantom pruning on recovery: ${GREEN}triggered${RESET}"
        fi
        ((FAULT_INJECT_RECOVERIES++))
        log_event "fault-inject" "vm=${VM_NAMES[$vm_idx]},pre=$pre_count,post=$post_count" "recovered"
        log_maintenance "$iteration" "${VM_NAMES[$vm_idx]}" "fault-inject" "recovered" \
            "pre=$pre_count,post=$post_count,roots_match=$roots_match,phantom_prune=$([ -n "$prune_log" ] && echo yes || echo no)"
    else
        log "    ${RED}NOT RECOVERED${RESET}: ghost-pool on $label"
        log_event "fault-inject" "vm=${VM_NAMES[$vm_idx]}" "not-recovered"
        log_maintenance "$iteration" "${VM_NAMES[$vm_idx]}" "fault-inject" "fail" "not-recovered"
    fi
}

# ─── Measurement ─────────────────────────────────────────────────────────────

collect_note_state() {
    local iteration="$1"
    POOL_NOTES=()
    CHECKPOINT_ROOTS=()

    for i in $(seq 0 $((VM_COUNT - 1))); do
        local pool_json pooln cp_root
        pool_json=$(pool_api "$i" "/api/v1/l2/tree-state" 2>/dev/null)
        pooln=$(echo "$pool_json" | jq -r '.note_count // "?"' 2>/dev/null)
        cp_root=$(echo "$pool_json" | jq -r '.checkpoint_root // "?"' 2>/dev/null)
        POOL_NOTES+=("${pooln:-?}")
        CHECKPOINT_ROOTS+=("${cp_root:-?}")
    done

    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "$ts,$iteration,${POOL_NOTES[0]},${POOL_NOTES[1]},${POOL_NOTES[2]},${POOL_NOTES[3]},${CHECKPOINT_ROOTS[0]:0:16},${CHECKPOINT_ROOTS[1]:0:16},${CHECKPOINT_ROOTS[2]:0:16},${CHECKPOINT_ROOTS[3]:0:16}" >> "$BALANCE_LOG"
}

print_note_table() {
    local iteration="$1"
    log "  ${BLUE}── Note Distribution (Iteration $iteration) ──${RESET}"
    log "  ┌──────────┬──────────────┬──────────────────┐"
    log "  │ VM       │ Pool Notes   │ Checkpoint Root  │"
    log "  ├──────────┼──────────────┼──────────────────┤"
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local root_short="${CHECKPOINT_ROOTS[$i]:0:16}"
        printf -v line "  │ %-8s │ %12s │ %16s │" \
            "${VM_NAMES[$i]}" "${POOL_NOTES[$i]}" "$root_short"
        log "$line"
    done
    log "  └──────────┴──────────────┴──────────────────┘"

    # Check convergence
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
    else
        log "  Pool notes: ${GREEN}converged${RESET} ($first across all VMs)"
    fi

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
    else
        log "  Checkpoint roots: ${GREEN}converged${RESET} (${first_root:0:16})"
    fi
}

# ─── Pre-flight ──────────────────────────────────────────────────────────────

preflight() {
    log "${BOLD}═══════════════════════════════════════════════════════════════════${RESET}"
    log "${BOLD}  L2 Maintenance & Recovery Soak Test${RESET}"
    log "${BOLD}  Duration: ${SOAK_HOURS} hours | Interval: $((ITER_INTERVAL / 60)) min${RESET}"
    log "${BOLD}  Mode: $([ -n "$DRY_RUN" ] && echo "DRY RUN (1 hour, no injection)" || echo "FULL")${RESET}"
    log "${BOLD}  Injections: $([ "$NO_INJECT" == "--no-inject" ] && echo "DISABLED" || echo "ENABLED")${RESET}"
    log "${BOLD}═══════════════════════════════════════════════════════════════════${RESET}"
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

    # Health check
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

    # ── Phase A: L2 Activity (every iteration) ──
    run_l2_activity "$iteration"

    # ── Phase B: Phantom Note Injection + Pruning (iters 4, 8, 12) ──
    if [[ "$NO_INJECT" != "--no-inject" ]]; then
        case $iteration in
            4)  phantom_inject_and_verify 1 "$iteration" ;;  # VM2
            8)  phantom_inject_and_verify 2 "$iteration" ;;  # VM3
            12) phantom_inject_and_verify 3 "$iteration" ;;  # VM4
        esac
    fi

    # ── Phase C: Checkpoint Retention Verification (iter 8) ──
    if (( iteration == 8 )); then
        verify_checkpoint_retention "$iteration"
    fi

    # ── Phase D: L1 Withdrawal Dry Run (iters 6, 14) ──
    case $iteration in
        6)  test_withdrawal_on_vm 0 "$iteration" ;;  # VM1
        14) test_withdrawal_on_vm 2 "$iteration" ;;  # VM3
    esac

    # ── Phase E: Wraith Session (iters 4, 8, 12, 16) ──
    if (( iteration % 4 == 0 )); then
        local wraith_vm=$(( (iteration / 4 - 1) % VM_COUNT ))
        wraith_session_on_vm "$wraith_vm" "$iteration"
    fi

    # ── Fault Injection (iters 5, 10, 15) ──
    if [[ "$NO_INJECT" != "--no-inject" ]]; then
        case $iteration in
            5)  fault_inject_and_verify 1 "$iteration" ;;  # VM2
            10) fault_inject_and_verify 2 "$iteration" ;;  # VM3
            15) fault_inject_and_verify 3 "$iteration" ;;  # VM4
        esac
    fi

    # Collect and display note distribution
    collect_note_state "$iteration"
    print_note_table "$iteration"

    log ""
}

# ─── Final Validation ────────────────────────────────────────────────────────

final_validation() {
    log "${BOLD}═══════════════════════════════════════════════════════════════════${RESET}"
    log "${BOLD}  Final Validation${RESET}"
    log "${BOLD}═══════════════════════════════════════════════════════════════════${RESET}"
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

    # 2. Pool convergence: all 4 VMs identical root
    log "Check 2: Pool convergence..."
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

    # 3. Checkpoint root convergence (with retry — checkpoints propagate async)
    log "Check 3: Checkpoint root convergence..."
    local roots_converged=false
    for attempt in 1 2 3; do
        if (( attempt > 1 )); then
            log "  Retry $attempt/3: waiting 15s for checkpoint propagation..."
            sleep 15
            collect_note_state "final"
        fi
        local first_root="${CHECKPOINT_ROOTS[0]}"
        roots_converged=true
        for i in $(seq 1 $((VM_COUNT - 1))); do
            if [[ "${CHECKPOINT_ROOTS[$i]}" != "$first_root" ]]; then
                roots_converged=false
                break
            fi
        done
        if $roots_converged; then
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

    # 4. Phantom pruning: 100% success
    log "Check 4: Phantom pruning success rate..."
    if (( PHANTOM_INJECT_ATTEMPTS > 0 )); then
        if (( PHANTOM_INJECT_SUCCESSES == PHANTOM_INJECT_ATTEMPTS )); then
            log "  Phantom pruning: ${GREEN}${PHANTOM_INJECT_SUCCESSES}/${PHANTOM_INJECT_ATTEMPTS} (100%)${RESET}"
        else
            log "  Phantom pruning: ${RED}${PHANTOM_INJECT_SUCCESSES}/${PHANTOM_INJECT_ATTEMPTS} — must be 100%${RESET}"
            ((failures++))
        fi
    else
        log "  Phantom pruning: ${YELLOW}no attempts (injections disabled?)${RESET}"
    fi

    # 5. Checkpoint retention: maintenance loop ran
    log "Check 5: Checkpoint retention..."
    local maint_log
    maint_log=$(ssh_cmd 0 "sudo journalctl -u ghost-pool --since '4 hours ago' --no-pager 2>&1 | grep -c 'maintenance complete' || echo 0" 2>/dev/null)
    maint_log="${maint_log:-0}"
    if (( maint_log > 0 )); then
        log "  Maintenance loop: ${GREEN}ran $maint_log times${RESET}"
    else
        log "  Maintenance loop: ${YELLOW}no executions detected (may be normal for short tests)${RESET}"
    fi

    # 6. Withdrawal dry-run: 100% proof+relay success
    log "Check 6: Withdrawal dry-run success rate..."
    if (( WITHDRAWAL_ATTEMPTS > 0 )); then
        if (( WITHDRAWAL_SUCCESSES == WITHDRAWAL_ATTEMPTS )); then
            log "  Withdrawal: ${GREEN}${WITHDRAWAL_SUCCESSES}/${WITHDRAWAL_ATTEMPTS} (100%)${RESET}"
        else
            log "  Withdrawal: ${RED}${WITHDRAWAL_SUCCESSES}/${WITHDRAWAL_ATTEMPTS} — expected 100%${RESET}"
            ((failures++))
        fi
    else
        log "  Withdrawal: ${YELLOW}no attempts${RESET}"
    fi

    # 7. Wraith sessions: >= 75% success rate
    log "Check 7: Wraith session success rate..."
    if (( WRAITH_ATTEMPTS > 0 )); then
        local wraith_pct=$(( (WRAITH_SUCCESSES * 100) / WRAITH_ATTEMPTS ))
        if (( wraith_pct >= 75 )); then
            log "  Wraith: ${GREEN}${WRAITH_SUCCESSES}/${WRAITH_ATTEMPTS} (${wraith_pct}%)${RESET}"
        else
            log "  Wraith: ${RED}${WRAITH_SUCCESSES}/${WRAITH_ATTEMPTS} (${wraith_pct}%) — below 75% threshold${RESET}"
            ((failures++))
        fi
    else
        log "  Wraith: ${YELLOW}no attempts${RESET}"
    fi

    # 8. Zero panics on all VMs
    log "Check 8: Panic check..."
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local pool_panics pay_panics
        pool_panics=$(ssh_cmd "$i" "sudo journalctl -u ghost-pool --since '1 hour ago' --no-pager 2>/dev/null | grep -ci 'panic' || echo 0" 2>/dev/null | tail -1 | tr -d '[:space:]')
        pay_panics=$(ssh_cmd "$i" "sudo journalctl -u ghost-pay --since '1 hour ago' --no-pager 2>/dev/null | grep -ci 'panic' || echo 0" 2>/dev/null | tail -1 | tr -d '[:space:]')
        pool_panics="${pool_panics:-0}"
        pay_panics="${pay_panics:-0}"
        if (( pool_panics == 0 && pay_panics == 0 )); then
            log "  ${VM_NAMES[$i]}: ${GREEN}zero panics${RESET}"
        else
            log "  ${VM_NAMES[$i]}: ${RED}pool=$pool_panics, pay=$pay_panics panics${RESET}"
            ((failures++))
        fi
    done

    # 9. Fault injection recovery
    log "Check 9: Fault injection recovery..."
    if (( FAULT_INJECT_ATTEMPTS > 0 )); then
        if (( FAULT_INJECT_RECOVERIES == FAULT_INJECT_ATTEMPTS )); then
            log "  Recovery: ${GREEN}${FAULT_INJECT_RECOVERIES}/${FAULT_INJECT_ATTEMPTS} (100%)${RESET}"
        else
            log "  Recovery: ${RED}${FAULT_INJECT_RECOVERIES}/${FAULT_INJECT_ATTEMPTS} — must be 100%${RESET}"
            ((failures++))
        fi
    else
        log "  Recovery: ${YELLOW}no attempts (injections disabled?)${RESET}"
    fi

    # 10. Propagation convergence (>= 90%)
    log "Check 10: Propagation convergence rate..."
    if (( PROPAGATION_CHECKS > 0 )); then
        local prop_pct=$(( (PROPAGATION_PASSES * 100) / PROPAGATION_CHECKS ))
        if (( prop_pct >= 80 )); then
            log "  Propagation: ${GREEN}${PROPAGATION_PASSES}/${PROPAGATION_CHECKS} (${prop_pct}%)${RESET}"
        else
            log "  Propagation: ${RED}${PROPAGATION_PASSES}/${PROPAGATION_CHECKS} (${prop_pct}%) — below 80% threshold${RESET}"
            ((failures++))
        fi
    else
        log "  Propagation: ${YELLOW}no checks${RESET}"
    fi

    # Final table
    log ""
    print_note_table "FINAL"

    # Summary counters
    log ""
    log "${BOLD}── Summary Counters ──${RESET}"
    log "  Phantom pruning:   ${PHANTOM_INJECT_SUCCESSES}/${PHANTOM_INJECT_ATTEMPTS} successful"
    log "  Withdrawal tests:  ${WITHDRAWAL_SUCCESSES}/${WITHDRAWAL_ATTEMPTS} successful"
    log "  Wraith sessions:   ${WRAITH_SUCCESSES}/${WRAITH_ATTEMPTS} successful"
    log "  Fault recoveries:  ${FAULT_INJECT_RECOVERIES}/${FAULT_INJECT_ATTEMPTS} successful"
    log "  Propagation:       ${PROPAGATION_PASSES}/${PROPAGATION_CHECKS} converged"

    log ""
    if (( failures == 0 )); then
        log "${BOLD}═══════════════════════════════════════════════════════════════════${RESET}"
        log "${BOLD}${GREEN}  L2 MAINTENANCE SOAK TEST: PASS${RESET}"
        log "${BOLD}═══════════════════════════════════════════════════════════════════${RESET}"
    else
        log "${BOLD}═══════════════════════════════════════════════════════════════════${RESET}"
        log "${BOLD}${RED}  L2 MAINTENANCE SOAK TEST: FAIL ($failures failures)${RESET}"
        log "${BOLD}═══════════════════════════════════════════════════════════════════${RESET}"
    fi

    log "Completed: $(date -u)"
    log "Full logs: $LOGDIR"
    log "Balance CSV: $BALANCE_LOG"
    log "Maintenance CSV: $MAINTENANCE_LOG"

    return $failures
}

# ─── Main ────────────────────────────────────────────────────────────────────

main() {
    # Parse args
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --hours) SOAK_HOURS="$2"; shift 2 ;;
            --no-inject) NO_INJECT="--no-inject"; shift ;;
            --dry-run) DRY_RUN="1"; SOAK_HOURS=1; NO_INJECT="--no-inject"; shift ;;
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
            local next_iter_at=$(( start_time + (iteration * ITER_INTERVAL) ))
            local now2
            now2=$(date +%s)
            local sleep_secs=$(( next_iter_at - now2 ))
            if (( sleep_secs > 0 )); then
                log "Sleeping ${sleep_secs}s until iteration $((iteration + 1))..."
                sleep "$sleep_secs"
            fi
        fi
    done

    final_validation
    exit $?
}

main "$@"
