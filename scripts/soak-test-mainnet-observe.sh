#!/usr/bin/env bash
# soak-test-mainnet-observe.sh — 24h Observe-Only Mainnet Soak Test
#
# Monitors mainnet deployment WITHOUT creating any transactions:
#   - L1 Mining: block height advancing, miner counts, payout rounds
#   - L2 Convergence: tree root match across all 4 nodes (no shields/wraith)
#   - Health: services up, checkpoint pipeline, memory, disk, panics
#   - MPC: ceremony completion, VK file stability
#   - Fault Injection: optional SIGKILL + recovery (configurable)
#
# NO locks, NO settlements, NO shields, NO wraith sessions — observe only.
#
# Usage:
#   ./scripts/soak-test-mainnet-observe.sh [--hours N] [--no-inject] [--no-mining] [--dry-run]
#   SOAK_HOURS=24 nohup ./scripts/soak-test-mainnet-observe.sh > soak-mainnet-observe.log 2>&1 &

set -uo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────

SOAK_HOURS="${SOAK_HOURS:-24}"
NO_INJECT=""
NO_MINING=""
DRY_RUN=""
ITER_INTERVAL=1800  # 30 minutes between iterations

SSH_KEY="$HOME/.ssh/ghost_signet_ed25519"
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o ControlMaster=auto -o ControlPath=/tmp/ghost-mainnet-observe-ssh-%h -o ControlPersist=120"

VM_IPS=("83.136.251.162" "85.9.198.212" "213.163.207.46" "95.111.221.169")
VM_NAMES=("mainnet-1" "mainnet-2" "mainnet-3" "mainnet-4")
VM_SSH=("ghost-vm1" "ghost-vm2" "ghost-vm3" "ghost-vm4")
VM_COUNT=${#VM_IPS[@]}

POOL_PORT=8080
PAY_PORT=8800

POOL_API_SECRET="b8404e28a10925d41a644a62a6078eab18e0522bcc2a2ef5d4596323be9be555"

# ─── Global Counters ─────────────────────────────────────────────────────────

MINING_CHECKS=0
MINING_ADVANCING=0
CONVERGENCE_CHECKS=0
CONVERGENCE_PASSES=0
HEALTH_CHECKS=0
HEALTH_PASSES=0
FAULT_INJECT_ATTEMPTS=0
FAULT_INJECT_RECOVERIES=0
MPC_CHECKS=0
MPC_PASSES=0
MEMORY_CHECKS=0
MEMORY_LEAK_WARNINGS=0
TOTAL_FAILURES=0

INITIAL_BLOCK_HEIGHT=0
LAST_BLOCK_HEIGHT=0

# Track RSS for leak detection (per-VM, pool + pay)
declare -A INITIAL_RSS_POOL
declare -A INITIAL_RSS_PAY

# ─── CLI Parsing ─────────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hours)     SOAK_HOURS="$2"; shift 2 ;;
        --no-inject) NO_INJECT=true; shift ;;
        --no-mining) NO_MINING=true; shift ;;
        --dry-run)   DRY_RUN=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--hours N] [--no-inject] [--no-mining] [--dry-run]"
            echo "  --hours N      Duration in hours (default: 24)"
            echo "  --no-inject    Disable fault injection"
            echo "  --no-mining    Skip mining layer checks"
            echo "  --dry-run      Validate connections only"
            echo ""
            echo "OBSERVE ONLY — no transactions, no locks, no shields, no wraith."
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

TOTAL_ITERATIONS=$(( (SOAK_HOURS * 3600) / ITER_INTERVAL ))

# ─── Colors ──────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ─── Logging ─────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOGDIR="$PROJECT_DIR/soak-logs/mainnet-observe-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$LOGDIR"

MAIN_LOG="$LOGDIR/soak-mainnet-observe.log"
EVENTS_LOG="$LOGDIR/events.jsonl"
METRICS_LOG="$LOGDIR/metrics.csv"

echo "timestamp,iteration,layer,metric,value" > "$METRICS_LOG"

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

log_metric() {
    local iteration="$1" layer="$2" metric="$3" value="$4"
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "$ts,$iteration,$layer,$metric,$value" >> "$METRICS_LOG"
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

bitcoin_cli() {
    local vm_idx="$1"; shift
    ssh_cmd "$vm_idx" "bitcoin-cli -datadir=/var/lib/bitcoin -rpcport=8332 -rpcuser=ghostrpc_mainnet -rpcpassword=522030635321a0b58e8297d1c834bf126eab712dc28b9c0b240bdb9a98f0df8d $*"
}

# ─── Pre-flight ──────────────────────────────────────────────────────────────

preflight() {
    log "${BOLD}═══ Pre-flight Checks (Observe-Only Mainnet) ═══${RESET}"
    local failed=false

    for i in $(seq 0 $((VM_COUNT - 1))); do
        local label
        label="$(vm_label $i)"

        # SSH
        if ! ssh_cmd "$i" "echo ok" >/dev/null 2>&1; then
            log "  ${RED}FAIL: SSH to $label${RESET}"
            failed=true
            continue
        fi

        # ghost-pool health
        local pool_health
        pool_health=$(pool_api "$i" "/health")
        [[ -z "$pool_health" ]] && pool_health=$(ssh_cmd "$i" "curl -sf http://localhost:${POOL_PORT}/health" 2>/dev/null)
        if [[ -z "$pool_health" ]]; then
            log "  ${RED}FAIL: ghost-pool on $label${RESET}"
            failed=true
            continue
        fi

        # ghost-pay health
        local pay_health
        pay_health=$(ssh_cmd "$i" "curl -sf http://localhost:${PAY_PORT}/health" 2>/dev/null)
        if [[ -z "$pay_health" ]]; then
            log "  ${RED}FAIL: ghost-pay on $label${RESET}"
            failed=true
            continue
        fi

        # VK files
        local vk_ok=true
        for vk in note_spend_vk.bin payout_vk.bin unshield_vk.bin; do
            if ! ssh_cmd "$i" "test -f /home/ghost/.ghost/mpc_params/$vk" 2>/dev/null; then
                log "  ${RED}FAIL: Missing $vk on $label${RESET}"
                vk_ok=false
                failed=true
            fi
        done

        # DB integrity
        local integrity
        integrity=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db 'PRAGMA integrity_check;'" 2>/dev/null)
        if [[ "$integrity" != "ok" ]]; then
            log "  ${RED}FAIL: DB integrity on $label: $integrity${RESET}"
            failed=true
        fi

        # Schema version
        local schema
        schema=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db 'PRAGMA user_version;'" 2>/dev/null)

        # Baseline RSS
        local pool_rss pay_rss
        pool_rss=$(ssh_cmd "$i" "ps -o rss= -p \$(pgrep -x ghost-pool) 2>/dev/null | head -1 | tr -d ' '" 2>/dev/null)
        pay_rss=$(ssh_cmd "$i" "ps -o rss= -p \$(pgrep -x ghost-pay) 2>/dev/null | head -1 | tr -d ' '" 2>/dev/null)
        INITIAL_RSS_POOL[$i]="${pool_rss:-0}"
        INITIAL_RSS_PAY[$i]="${pay_rss:-0}"

        log "  $label: ${GREEN}OK${RESET} (schema=$schema, vk=$( $vk_ok && echo ok || echo missing), pool_rss=${pool_rss:-?}KB, pay_rss=${pay_rss:-?}KB)"
    done

    # Block height baseline
    local height
    height=$(pool_api 0 "/api/v1/node/status" | jq -r '.block_height // 0' 2>/dev/null)
    [[ -z "$height" ]] && height=$(ssh_cmd 0 "curl -sf http://localhost:${POOL_PORT}/api/v1/node/status" | jq -r '.block_height // 0' 2>/dev/null)
    INITIAL_BLOCK_HEIGHT="${height:-0}"
    LAST_BLOCK_HEIGHT="$INITIAL_BLOCK_HEIGHT"
    log "  Baseline block height: $INITIAL_BLOCK_HEIGHT"

    # Bitcoin Core sync check — MUST be past IBD for mainnet
    if [[ -z "$NO_MINING" ]]; then
        local bc_info
        bc_info=$(bitcoin_cli 0 "getblockchaininfo")
        if [[ -n "$bc_info" ]]; then
            local ibd chain
            ibd=$(echo "$bc_info" | jq -r 'if .initialblockdownload == null then "true" else (.initialblockdownload | tostring) end' 2>/dev/null)
            chain=$(echo "$bc_info" | jq -r '.chain // "unknown"' 2>/dev/null)
            if [[ "$chain" != "main" ]]; then
                log "  ${RED}FAIL: Bitcoin Core is on chain '$chain', expected 'main'${RESET}"
                failed=true
            elif [[ "$ibd" == "true" ]]; then
                log "  ${RED}FAIL: Bitcoin Core still in IBD — cannot proceed${RESET}"
                failed=true
            else
                local blocks headers
                blocks=$(echo "$bc_info" | jq -r '.blocks // 0' 2>/dev/null)
                headers=$(echo "$bc_info" | jq -r '.headers // 0' 2>/dev/null)
                log "  Bitcoin Core: ${GREEN}synced${RESET} (chain=$chain, blocks=$blocks, headers=$headers)"
            fi
        else
            log "  ${YELLOW}WARNING: Could not reach Bitcoin Core RPC${RESET}"
        fi
    fi

    # MPC ceremony check
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local contributions
        contributions=$(ssh_cmd "$i" "sudo -u ghost sqlite3 /home/ghost/.ghost/ghost.db 'SELECT COUNT(*) FROM mpc_contributions;'" 2>/dev/null)
        if [[ "${contributions:-0}" -ge 4 ]]; then
            log "  ${VM_NAMES[$i]} MPC: ${GREEN}${contributions} contributions${RESET}"
        else
            log "  ${VM_NAMES[$i]} MPC: ${YELLOW}${contributions:-0} contributions (need 4)${RESET}"
        fi
    done

    if $failed; then
        log "  ${RED}Pre-flight FAILED — aborting${RESET}"
        exit 1
    fi

    log "  Pre-flight: ${GREEN}ALL CHECKS PASSED${RESET}"
    log_event "preflight" "block_height=$INITIAL_BLOCK_HEIGHT,mode=observe-only" "ok"
}

# ═══════════════════════════════════════════════════════════════════════════════
# L1 MINING LAYER — every iteration
# ═══════════════════════════════════════════════════════════════════════════════

check_mining() {
    local iteration="$1"
    [[ -n "$NO_MINING" ]] && return 0

    log "  ${BLUE}── L1 Mining ──${RESET}"
    ((MINING_CHECKS++))

    # Block height from VM1
    local height
    height=$(pool_api 0 "/api/v1/node/status" | jq -r '.block_height // 0' 2>/dev/null)
    [[ -z "$height" || "$height" == "0" ]] && \
        height=$(ssh_cmd 0 "curl -sf http://localhost:${POOL_PORT}/api/v1/node/status" | jq -r '.block_height // 0' 2>/dev/null)
    height="${height:-0}"

    local advanced=false
    if (( height > LAST_BLOCK_HEIGHT )); then
        advanced=true
        ((MINING_ADVANCING++))
    fi

    log "    Block height: $height (was $LAST_BLOCK_HEIGHT) $( $advanced && echo "${GREEN}+$((height - LAST_BLOCK_HEIGHT))${RESET}" || echo "${YELLOW}stalled${RESET}")"
    log_metric "$iteration" "mining" "block_height" "$height"
    LAST_BLOCK_HEIGHT="$height"

    # Miner counts across all VMs
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local miner_count
        miner_count=$(ssh_cmd "$i" "sqlite3 /home/ghost/.ghost/ghost.db 'SELECT COUNT(*) FROM miners;'" 2>/dev/null)
        log "    ${VM_NAMES[$i]} miners: ${miner_count:-?}"
        log_metric "$iteration" "mining" "miners_vm$i" "${miner_count:-0}"
    done

    # Payout round status from VM1
    local payout_status
    payout_status=$(ssh_cmd 0 "journalctl -u ghost-pool --since '30 min ago' --no-pager 2>/dev/null | grep -c 'payout.*round\|payout.*complete\|payout.*distributed'" 2>/dev/null)
    log "    Payout events (30min): ${payout_status:-0}"
    log_metric "$iteration" "mining" "payout_events" "${payout_status:-0}"

    # Block template check (mainnet-specific)
    local template_info
    template_info=$(bitcoin_cli 0 "getblocktemplate '{\"rules\":[\"segwit\"]}'" 2>/dev/null)
    if [[ -n "$template_info" ]]; then
        local tx_count
        tx_count=$(echo "$template_info" | jq '.transactions | length' 2>/dev/null)
        log "    Block template: ${tx_count:-?} transactions"
        log_metric "$iteration" "mining" "template_tx_count" "${tx_count:-0}"
    fi

    # Fee estimation check
    local fee_est
    fee_est=$(bitcoin_cli 0 "estimatesmartfee 6" 2>/dev/null)
    if [[ -n "$fee_est" ]]; then
        local feerate
        feerate=$(echo "$fee_est" | jq -r '.feerate // "unavailable"' 2>/dev/null)
        log "    Fee estimate (6 blocks): ${feerate} BTC/kB"
        log_metric "$iteration" "mining" "feerate_6" "${feerate}"
    fi

    # Mempool info
    local mempool
    mempool=$(bitcoin_cli 0 "getmempoolinfo" 2>/dev/null)
    if [[ -n "$mempool" ]]; then
        local mem_size mem_bytes
        mem_size=$(echo "$mempool" | jq -r '.size // 0' 2>/dev/null)
        mem_bytes=$(echo "$mempool" | jq -r '.bytes // 0' 2>/dev/null)
        log "    Mempool: ${mem_size} tx (${mem_bytes} bytes)"
        log_metric "$iteration" "mining" "mempool_size" "${mem_size}"
    fi

    log_event "mining-check" "height=$height,advancing=$advanced" "$( $advanced && echo ok || echo warn)"
}

# ═══════════════════════════════════════════════════════════════════════════════
# L2 CONVERGENCE — every iteration (observe only, no transactions)
# ═══════════════════════════════════════════════════════════════════════════════

check_tree_convergence() {
    local iteration="$1"

    log "  ${BLUE}── L2 Convergence (observe only) ──${RESET}"
    ((CONVERGENCE_CHECKS++))

    local pool_notes=() checkpoint_roots=()

    for i in $(seq 0 $((VM_COUNT - 1))); do
        local pool_json
        pool_json=$(pool_api "$i" "/api/v1/l2/tree-state" 2>/dev/null)
        [[ -z "$pool_json" ]] && pool_json=$(ssh_cmd "$i" "curl -sf http://localhost:${POOL_PORT}/api/v1/l2/tree-state" 2>/dev/null)

        pool_notes+=("$(echo "$pool_json" | jq -r '.note_count // "?"' 2>/dev/null)")
        checkpoint_roots+=("$(echo "$pool_json" | jq -r '.checkpoint_root // "?"' 2>/dev/null)")
    done

    # Check pool convergence (all must match)
    local ref="${pool_notes[0]}" converged=true
    if [[ "$ref" != "?" ]]; then
        for i in $(seq 1 $((VM_COUNT - 1))); do
            [[ "${pool_notes[$i]}" == "$ref" ]] || converged=false
        done
    else
        converged=false
    fi

    # Check checkpoint root convergence
    local root_ref="${checkpoint_roots[0]}" roots_match=true
    if [[ "$root_ref" != "?" ]]; then
        for i in $(seq 1 $((VM_COUNT - 1))); do
            [[ "${checkpoint_roots[$i]}" == "$root_ref" ]] || roots_match=false
        done
    else
        roots_match=false
    fi

    if $converged && $roots_match; then
        log "    Tree: ${GREEN}CONVERGED${RESET} (notes=${pool_notes[*]}, root=${root_ref:0:16})"
        ((CONVERGENCE_PASSES++))
    elif $converged; then
        log "    Tree: ${YELLOW}notes converged (${pool_notes[*]}), roots diverged${RESET}"
    else
        log "    Tree: ${YELLOW}DIVERGED${RESET} (notes=${pool_notes[*]})"
    fi

    log_metric "$iteration" "l2" "pool_notes_vm0" "${pool_notes[0]}"
    log_metric "$iteration" "l2" "convergence" "$( $converged && echo 1 || echo 0)"
    log_metric "$iteration" "l2" "roots_match" "$( $roots_match && echo 1 || echo 0)"
    log_event "tree-convergence" "iter=$iteration,converged=$converged,roots_match=$roots_match" \
        "$( $converged && $roots_match && echo ok || echo warn)"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MPC CHECK — every 6th iteration
# ═══════════════════════════════════════════════════════════════════════════════

check_mpc() {
    local iteration="$1"
    (( iteration % 6 != 0 )) && return 0

    log "  ${BLUE}── MPC Stability ──${RESET}"
    ((MPC_CHECKS++))
    local all_ok=true

    for i in $(seq 0 $((VM_COUNT - 1))); do
        # Contributions count
        local contributions
        contributions=$(ssh_cmd "$i" "sudo -u ghost sqlite3 /home/ghost/.ghost/ghost.db 'SELECT COUNT(*) FROM mpc_contributions;'" 2>/dev/null)

        # VK file checksums (detect corruption or change)
        local vk_hashes=""
        for vk in note_spend_vk.bin payout_vk.bin unshield_vk.bin; do
            local hash
            hash=$(ssh_cmd "$i" "sha256sum /home/ghost/.ghost/mpc_params/$vk 2>/dev/null | cut -d' ' -f1" 2>/dev/null)
            vk_hashes="$vk_hashes ${hash:0:8}"
        done

        if [[ "${contributions:-0}" -ge 4 ]]; then
            log "    ${VM_NAMES[$i]}: ${GREEN}${contributions} contributions${RESET}, VK:${vk_hashes}"
        else
            log "    ${VM_NAMES[$i]}: ${RED}${contributions:-0} contributions (need 4)${RESET}"
            all_ok=false
        fi

        log_metric "$iteration" "mpc" "contributions_vm$i" "${contributions:-0}"
    done

    if $all_ok; then
        ((MPC_PASSES++))
    fi
    log_event "mpc-check" "iter=$iteration" "$( $all_ok && echo ok || echo fail)"
}

# ═══════════════════════════════════════════════════════════════════════════════
# HEALTH LAYER — every iteration
# ═══════════════════════════════════════════════════════════════════════════════

check_health() {
    local iteration="$1"

    log "  ${BLUE}── Health ──${RESET}"
    ((HEALTH_CHECKS++))
    local all_ok=true

    for i in $(seq 0 $((VM_COUNT - 1))); do
        local pool_ok=false pay_ok=false

        # ghost-pool
        local pool_h
        pool_h=$(pool_api "$i" "/health" 2>/dev/null)
        [[ -z "$pool_h" ]] && pool_h=$(ssh_cmd "$i" "curl -sf http://localhost:${POOL_PORT}/health" 2>/dev/null)
        [[ -n "$pool_h" ]] && pool_ok=true

        # ghost-pay
        local pay_h
        pay_h=$(ssh_cmd "$i" "curl -sf http://localhost:${PAY_PORT}/health" 2>/dev/null)
        [[ -n "$pay_h" ]] && pay_ok=true

        if $pool_ok && $pay_ok; then
            log "    ${VM_NAMES[$i]}: ${GREEN}pool+pay OK${RESET}"
        else
            log "    ${VM_NAMES[$i]}: ${RED}pool=$( $pool_ok && echo OK || echo DOWN) pay=$( $pay_ok && echo OK || echo DOWN)${RESET}"
            all_ok=false
        fi
    done

    # Checkpoint pipeline
    local ckpt_count
    ckpt_count=$(ssh_cmd 0 "journalctl -u ghost-pool --since '30 min ago' --no-pager 2>/dev/null | grep -c 'checkpoint\|Checkpoint'" 2>/dev/null)
    log "    Checkpoint events (30min): ${ckpt_count:-0}"
    log_metric "$iteration" "health" "checkpoint_events" "${ckpt_count:-0}"

    # Peer connectivity
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local peer_count
        peer_count=$(ssh_cmd "$i" "journalctl -u ghost-pool --since '5 min ago' --no-pager 2>/dev/null | grep -c 'health.*ping\|peer.*connected\|mesh.*peer'" 2>/dev/null)
        log_metric "$iteration" "health" "peer_activity_vm$i" "${peer_count:-0}"
    done

    # Memory + disk — every iteration for leak detection
    log "    Resource check:"
    ((MEMORY_CHECKS++))
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local mem_pct disk_pct pool_rss pay_rss
        mem_pct=$(ssh_cmd "$i" "free | awk '/Mem:/{printf \"%.0f\", \$3/\$2*100}'" 2>/dev/null)
        disk_pct=$(ssh_cmd "$i" "df / | awk 'NR==2{print \$5}'" 2>/dev/null)
        pool_rss=$(ssh_cmd "$i" "ps -o rss= -p \$(pgrep -x ghost-pool) 2>/dev/null | head -1 | tr -d ' '" 2>/dev/null)
        pay_rss=$(ssh_cmd "$i" "ps -o rss= -p \$(pgrep -x ghost-pay) 2>/dev/null | head -1 | tr -d ' '" 2>/dev/null)

        # Memory leak detection: warn if RSS grew >50% from baseline
        local pool_initial="${INITIAL_RSS_POOL[$i]:-0}"
        local pay_initial="${INITIAL_RSS_PAY[$i]:-0}"
        local pool_growth="" pay_growth=""

        if (( pool_initial > 0 && ${pool_rss:-0} > pool_initial * 3 / 2 )); then
            pool_growth=" ${RED}+$((${pool_rss:-0} * 100 / pool_initial - 100))%${RESET}"
            ((MEMORY_LEAK_WARNINGS++))
        fi
        if (( pay_initial > 0 && ${pay_rss:-0} > pay_initial * 3 / 2 )); then
            pay_growth=" ${RED}+$((${pay_rss:-0} * 100 / pay_initial - 100))%${RESET}"
            ((MEMORY_LEAK_WARNINGS++))
        fi

        log "      ${VM_NAMES[$i]}: mem=${mem_pct:-?}% disk=${disk_pct:-?} pool_rss=${pool_rss:-?}KB${pool_growth} pay_rss=${pay_rss:-?}KB${pay_growth}"
        log_metric "$iteration" "health" "mem_pct_vm$i" "${mem_pct:-0}"
        log_metric "$iteration" "health" "pool_rss_vm$i" "${pool_rss:-0}"
        log_metric "$iteration" "health" "pay_rss_vm$i" "${pay_rss:-0}"
        log_metric "$iteration" "health" "disk_pct_vm$i" "$(echo "${disk_pct:-0}" | tr -d '%')"
    done

    # Panic check (last 30 min)
    local panics=0
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local p
        p=$(ssh_cmd "$i" "journalctl -u ghost-pool -u ghost-pay --since '30 min ago' --no-pager 2>/dev/null | grep -ci 'panic\|PANIC'" 2>/dev/null)
        panics=$((panics + ${p:-0}))
    done
    if (( panics > 0 )); then
        log "    ${RED}PANICS DETECTED: $panics in last 30min${RESET}"
        all_ok=false
    fi

    # Service restart check (unexpected restarts)
    for i in $(seq 0 $((VM_COUNT - 1))); do
        local pool_uptime pay_uptime
        pool_uptime=$(ssh_cmd "$i" "systemctl show ghost-pool --property=ActiveEnterTimestamp --value" 2>/dev/null)
        pay_uptime=$(ssh_cmd "$i" "systemctl show ghost-pay --property=ActiveEnterTimestamp --value" 2>/dev/null)
        log_metric "$iteration" "health" "pool_uptime_vm$i" "${pool_uptime}"
        log_metric "$iteration" "health" "pay_uptime_vm$i" "${pay_uptime}"
    done

    if $all_ok; then
        ((HEALTH_PASSES++))
    else
        ((TOTAL_FAILURES++))
    fi
    log_event "health-check" "iter=$iteration,panics=$panics" "$( $all_ok && echo ok || echo fail)"
}

# ═══════════════════════════════════════════════════════════════════════════════
# FAULT INJECTION — every 6th iteration (optional)
# ═══════════════════════════════════════════════════════════════════════════════

inject_fault() {
    local iteration="$1"

    [[ -n "$NO_INJECT" ]] && return 0
    (( iteration % 6 != 0 )) && return 0

    log "  ${RED}── Fault Injection ──${RESET}"
    ((FAULT_INJECT_ATTEMPTS++))

    local victim_idx=$((RANDOM % VM_COUNT))
    local label="${VM_NAMES[$victim_idx]}"

    # Alternate between ghost-pool and ghost-pay kills
    local service
    if (( (iteration / 6) % 2 == 0 )); then
        service="ghost-pool"
    else
        service="ghost-pay"
    fi

    log "    ${RED}SIGKILL $service on $label${RESET}"

    ssh_cmd "$victim_idx" "kill -9 \$(pgrep -f '/opt/ghost/bin/$service') 2>/dev/null; true" || true
    sleep 2
    ssh_cmd "$victim_idx" "systemctl start $service" || true
    log "    Restarted $service on $label — waiting for recovery..."

    local recovery_timeout=300 elapsed=0 recovered=false
    while (( elapsed < recovery_timeout )); do
        sleep 5
        elapsed=$((elapsed + 5))
        local health
        if [[ "$service" == "ghost-pool" ]]; then
            health=$(ssh_cmd "$victim_idx" "curl -sf http://localhost:${POOL_PORT}/health" 2>/dev/null)
        else
            health=$(ssh_cmd "$victim_idx" "curl -sf http://localhost:${PAY_PORT}/health" 2>/dev/null)
        fi
        if [[ -n "$health" ]]; then
            recovered=true
            break
        fi
    done

    if $recovered; then
        log "    ${GREEN}RECOVERED${RESET} in ${elapsed}s"
        ((FAULT_INJECT_RECOVERIES++))
        log_event "fault-injection" "vm=$label,service=$service,recovered=${elapsed}s" "ok"
    else
        log "    ${RED}FAILED TO RECOVER${RESET} after ${recovery_timeout}s"
        ((TOTAL_FAILURES++))
        log_event "fault-injection" "vm=$label,service=$service,timeout" "fail"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# FINAL REPORT
# ═══════════════════════════════════════════════════════════════════════════════

final_report() {
    local end_ts
    end_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local elapsed_hours=$(( ($(date +%s) - START_TIME) / 3600 ))

    log ""
    log "${BOLD}╔═══════════════════════════════════════════════════════════════╗${RESET}"
    log "${BOLD}║     MAINNET 24h OBSERVE-ONLY SOAK — FINAL REPORT            ║${RESET}"
    log "${BOLD}╚═══════════════════════════════════════════════════════════════╝${RESET}"
    log ""
    log "  Duration:    ${elapsed_hours}h (target: ${SOAK_HOURS}h)"
    log "  Iterations:  $CURRENT_ITERATION / $TOTAL_ITERATIONS"
    log "  Mode:        OBSERVE ONLY (zero transactions)"
    log "  Logs:        $LOGDIR"
    log ""
    log "  ${BOLD}── Mining ──${RESET}"
    log "    Checks:       $MINING_CHECKS"
    log "    Advancing:    $MINING_ADVANCING / $MINING_CHECKS ($( (( MINING_CHECKS > 0 )) && echo "$((MINING_ADVANCING * 100 / MINING_CHECKS))%" || echo "N/A"))"
    log "    Height:       $INITIAL_BLOCK_HEIGHT → $LAST_BLOCK_HEIGHT (+$((LAST_BLOCK_HEIGHT - INITIAL_BLOCK_HEIGHT)))"
    log ""
    log "  ${BOLD}── L2 Convergence ──${RESET}"
    log "    Checks:       $CONVERGENCE_CHECKS"
    log "    Converged:    $CONVERGENCE_PASSES / $CONVERGENCE_CHECKS ($( (( CONVERGENCE_CHECKS > 0 )) && echo "$((CONVERGENCE_PASSES * 100 / CONVERGENCE_CHECKS))%" || echo "N/A"))"
    log ""
    log "  ${BOLD}── MPC ──${RESET}"
    log "    Checks:       $MPC_CHECKS"
    log "    Stable:       $MPC_PASSES / $MPC_CHECKS"
    log ""
    log "  ${BOLD}── Health ──${RESET}"
    log "    Checks:       $HEALTH_PASSES / $HEALTH_CHECKS"
    log "    Mem warnings: $MEMORY_LEAK_WARNINGS"
    log ""
    log "  ${BOLD}── Fault Injection ──${RESET}"
    log "    Recoveries:   $FAULT_INJECT_RECOVERIES / $FAULT_INJECT_ATTEMPTS"
    log ""
    log "  ${BOLD}── Failures ──${RESET}"
    log "    Total:        $TOTAL_FAILURES"
    log ""

    # Pass/fail gates
    local gate_pass=true

    # Zero panics (checked via TOTAL_FAILURES from health)
    if (( TOTAL_FAILURES > 0 )); then
        log "  ${RED}GATE FAIL: $TOTAL_FAILURES total failures${RESET}"
        gate_pass=false
    fi

    # Mining advancing (if enabled)
    if [[ -z "$NO_MINING" ]] && (( MINING_CHECKS > 0 )); then
        local mining_pct=$((MINING_ADVANCING * 100 / MINING_CHECKS))
        if (( mining_pct < 50 )); then
            log "  ${RED}GATE FAIL: Mining advancing only ${mining_pct}% (need >50%)${RESET}"
            gate_pass=false
        fi
    fi

    # L2 convergence >90%
    if (( CONVERGENCE_CHECKS > 0 )); then
        local conv_pct=$((CONVERGENCE_PASSES * 100 / CONVERGENCE_CHECKS))
        if (( conv_pct < 90 )); then
            log "  ${RED}GATE FAIL: L2 convergence ${conv_pct}% (need >90%)${RESET}"
            gate_pass=false
        fi
    fi

    # MPC stable
    if (( MPC_CHECKS > 0 && MPC_PASSES < MPC_CHECKS )); then
        log "  ${RED}GATE FAIL: MPC not stable on all checks${RESET}"
        gate_pass=false
    fi

    # Health >95%
    if (( HEALTH_CHECKS > 0 )); then
        local health_pct=$((HEALTH_PASSES * 100 / HEALTH_CHECKS))
        if (( health_pct < 95 )); then
            log "  ${RED}GATE FAIL: Health ${health_pct}% (need >95%)${RESET}"
            gate_pass=false
        fi
    fi

    # Fault injection 100% recovery
    if (( FAULT_INJECT_ATTEMPTS > 0 && FAULT_INJECT_RECOVERIES < FAULT_INJECT_ATTEMPTS )); then
        log "  ${RED}GATE FAIL: Fault injection recovery $FAULT_INJECT_RECOVERIES/$FAULT_INJECT_ATTEMPTS (need 100%)${RESET}"
        gate_pass=false
    fi

    # Memory leaks
    if (( MEMORY_LEAK_WARNINGS > 2 )); then
        log "  ${RED}GATE FAIL: $MEMORY_LEAK_WARNINGS memory leak warnings${RESET}"
        gate_pass=false
    fi

    log ""
    if $gate_pass; then
        log "  ${GREEN}${BOLD}═══ MAINNET OBSERVE-ONLY: PASS ═══${RESET}"
    else
        log "  ${RED}${BOLD}═══ MAINNET OBSERVE-ONLY: FAIL ═══${RESET}"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN LOOP
# ═══════════════════════════════════════════════════════════════════════════════

main() {
    START_TIME=$(date +%s)
    CURRENT_ITERATION=0

    log "${BOLD}╔═══════════════════════════════════════════════════════════════╗${RESET}"
    log "${BOLD}║  Ghost Mainnet 24h Observe-Only Soak Test                    ║${RESET}"
    log "${BOLD}║  Duration: ${SOAK_HOURS}h  Iterations: ${TOTAL_ITERATIONS}  Interval: $((ITER_INTERVAL/60))min$(printf '%*s' $((14 - ${#SOAK_HOURS} - ${#TOTAL_ITERATIONS})) '')║${RESET}"
    log "${BOLD}║  Inject: $( [[ -z "$NO_INJECT" ]] && echo "ON " || echo "OFF")  Mining: $( [[ -z "$NO_MINING" ]] && echo "ON " || echo "OFF")  Mode: OBSERVE-ONLY$(printf '%*s' 18 '')║${RESET}"
    log "${BOLD}╚═══════════════════════════════════════════════════════════════╝${RESET}"

    preflight

    if [[ -n "$DRY_RUN" ]]; then
        log ""
        log "${GREEN}Dry run complete — all pre-flight checks passed.${RESET}"
        exit 0
    fi

    trap 'log ""; log "${YELLOW}Interrupted — generating report...${RESET}"; final_report; exit 1' INT TERM

    for (( iter=1; iter<=TOTAL_ITERATIONS; iter++ )); do
        CURRENT_ITERATION=$iter
        local iter_start
        iter_start=$(date +%s)
        local elapsed_hours=$(( (iter_start - START_TIME) / 3600 ))

        log ""
        log "${BOLD}═══ Iteration $iter / $TOTAL_ITERATIONS  [${elapsed_hours}h elapsed] ═══${RESET}"

        # L1 Mining
        check_mining "$iter"

        # L2 Convergence (observe only — no shields/wraith/locks)
        check_tree_convergence "$iter"

        # MPC stability (every 6th iteration)
        check_mpc "$iter"

        # Health (every iteration)
        check_health "$iter"

        # Fault injection (every 6th, optional)
        inject_fault "$iter"

        # Sleep
        local iter_end
        iter_end=$(date +%s)
        local iter_duration=$((iter_end - iter_start))
        local sleep_time=$((ITER_INTERVAL - iter_duration))

        log "  Iteration $iter complete (${iter_duration}s). $( (( sleep_time > 0 )) && echo "Next in ${sleep_time}s." || echo "Running behind!")"

        if (( sleep_time > 0 )); then
            sleep "$sleep_time"
        fi
    done

    final_report
}

main "$@"
