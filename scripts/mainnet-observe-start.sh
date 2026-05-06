#!/usr/bin/env bash
# mainnet-observe-start.sh — Start ghost-pool + ghost-pay after ghostd syncs
#
# Phase 5-6: MPC ceremony + service startup
#   - Checks ghostd is past IBD on all VMs
#   - Starts VM1 with --genesis for MPC ceremony
#   - Waits 60s, then starts VM2-4
#   - Verifies MPC ceremony and VK files
#   - Starts ghost-pay on all VMs

set -euo pipefail

SSH_KEY="$HOME/.ssh/ghost_signet_ed25519"
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10"

VM_IPS=("83.136.251.162" "85.9.198.212" "213.163.207.46" "95.111.221.169")
VM_NAMES=("VM1" "VM2" "VM3" "VM4")

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

RPC_PASSWORD="522030635321a0b58e8297d1c834bf126eab712dc28b9c0b240bdb9a98f0df8d"

ssh_cmd() {
    local vm_idx="$1"; shift
    timeout 30 ssh $SSH_OPTS "root@${VM_IPS[$vm_idx]}" "$@" 2>/dev/null
}

# ─── Check sync status ──────────────────────────────────────────────────────

check_sync() {
    echo -e "${BOLD}═══ Checking ghostd sync status ═══${RESET}"
    local all_synced=true

    for i in "${!VM_IPS[@]}"; do
        local ip="${VM_IPS[$i]}"
        local name="${VM_NAMES[$i]}"

        local info
        info=$(ssh_cmd "$i" "bitcoin-cli -datadir=/var/lib/bitcoin -rpcport=8332 -rpcuser=ghostrpc_mainnet -rpcpassword=$RPC_PASSWORD getblockchaininfo" 2>/dev/null)

        if [[ -z "$info" ]]; then
            echo -e "  $name ($ip): ${RED}Cannot reach ghostd RPC${RESET}"
            all_synced=false
            continue
        fi

        local chain ibd blocks headers progress
        chain=$(echo "$info" | jq -r '.chain // "?"')
        ibd=$(echo "$info" | jq -r '.initialblockdownload // true')
        blocks=$(echo "$info" | jq -r '.blocks // 0')
        headers=$(echo "$info" | jq -r '.headers // 0')
        progress=$(echo "$info" | jq -r '.verificationprogress // 0')

        local pct
        pct=$(echo "$progress" | awk '{printf "%.2f", $1 * 100}')

        if [[ "$ibd" == "true" ]]; then
            echo -e "  $name ($ip): ${YELLOW}IBD in progress${RESET} — $blocks/$headers blocks ($pct%)"
            all_synced=false
        else
            echo -e "  $name ($ip): ${GREEN}SYNCED${RESET} — chain=$chain, blocks=$blocks"
        fi
    done

    if $all_synced; then
        echo -e "\n${GREEN}All VMs synced. Ready to start ghost-pool.${RESET}"
        return 0
    else
        echo -e "\n${YELLOW}Not all VMs are synced yet. Wait for IBD to complete.${RESET}"
        return 1
    fi
}

# ─── Handle --check-sync flag ───────────────────────────────────────────────

if [[ "${1:-}" == "--check-sync" ]]; then
    check_sync
    exit $?
fi

# ─── Main startup sequence ──────────────────────────────────────────────────

echo -e "${BOLD}═══ Mainnet Observe-Only: Start Services ═══${RESET}"

# Step 1: Verify all ghostd synced
if ! check_sync; then
    echo -e "${RED}Aborting — ghostd not synced on all VMs.${RESET}"
    exit 1
fi

# Step 2: Start VM1 ghost-pool with --genesis
echo -e "\n${BOLD}── Phase 5: MPC Ceremony ──${RESET}"
echo "  Starting ghost-pool on VM1 with --genesis..."

# Temporarily add --genesis to VM1's ghost-pool service
ssh_cmd 0 bash <<'REMOTE'
# Read current ExecStart and append --genesis
CURRENT=$(grep "^ExecStart=" /etc/systemd/system/ghost-pool.service 2>/dev/null || echo "ExecStart=/opt/ghost/bin/ghost-pool")
if [[ "$CURRENT" != *"--genesis"* ]]; then
    sed -i "s|^ExecStart=.*|${CURRENT} --genesis|" /etc/systemd/system/ghost-pool.service 2>/dev/null || true
fi
systemctl daemon-reload
systemctl start ghost-pool
REMOTE

echo "  VM1 ghost-pool started with --genesis. Waiting 60s for genesis params..."
sleep 60

# Step 3: Start VM2, VM3, VM4 ghost-pool (no --genesis)
echo "  Starting ghost-pool on VM2, VM3, VM4..."
for i in 1 2 3; do
    ssh_cmd "$i" "systemctl start ghost-pool" &
done
wait

echo "  Waiting 30s for MPC contributions..."
sleep 30

# Step 4: Verify MPC ceremony
echo -e "\n${BOLD}── Verifying MPC Ceremony ──${RESET}"
local_ok=true
for i in "${!VM_IPS[@]}"; do
    local contributions
    contributions=$(ssh_cmd "$i" "sudo -u ghost sqlite3 /home/ghost/.ghost/ghost.db 'SELECT COUNT(*) FROM mpc_contributions;'" 2>/dev/null)
    local vk_count
    vk_count=$(ssh_cmd "$i" "ls /home/ghost/.ghost/mpc_params/*.vk.bin 2>/dev/null | wc -l" 2>/dev/null)

    if [[ "${contributions:-0}" -ge 4 && "${vk_count:-0}" -ge 3 ]]; then
        echo -e "  ${VM_NAMES[$i]}: ${GREEN}${contributions} contributions, ${vk_count} VK files${RESET}"
    else
        echo -e "  ${VM_NAMES[$i]}: ${YELLOW}${contributions:-0} contributions, ${vk_count:-0} VK files${RESET}"
        local_ok=false
    fi
done

if [[ "$local_ok" == "false" ]]; then
    echo -e "\n${YELLOW}MPC ceremony may still be in progress. Check logs:${RESET}"
    echo "  ssh ghost-vm1 'journalctl -u ghost-pool -f | grep -i mpc'"
    echo ""
    echo -e "${YELLOW}Continue anyway? [y/N]${RESET}"
    read -r confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && { echo "Aborted."; exit 1; }
fi

# Step 5: Remove --genesis from VM1 and restart
echo -e "\n── Removing --genesis from VM1 ──"
ssh_cmd 0 bash <<'REMOTE'
sed -i 's| --genesis||' /etc/systemd/system/ghost-pool.service
systemctl daemon-reload
systemctl restart ghost-pool
REMOTE
echo "  VM1 ghost-pool restarted without --genesis"
sleep 10

# Step 6: Start ghost-pay on all VMs
echo -e "\n${BOLD}── Starting ghost-pay on all VMs ──${RESET}"
for i in "${!VM_IPS[@]}"; do
    ssh_cmd "$i" "systemctl start ghost-pay" &
done
wait
sleep 5

# Step 7: Final health check
echo -e "\n${BOLD}── Final Health Check ──${RESET}"
for i in "${!VM_IPS[@]}"; do
    local pool_h pay_h
    pool_h=$(ssh_cmd "$i" "curl -sf http://localhost:8080/health" 2>/dev/null)
    pay_h=$(ssh_cmd "$i" "curl -sf http://localhost:8800/health" 2>/dev/null)

    local pool_status=$( [[ -n "$pool_h" ]] && echo "${GREEN}UP${RESET}" || echo "${RED}DOWN${RESET}")
    local pay_status=$( [[ -n "$pay_h" ]] && echo "${GREEN}UP${RESET}" || echo "${RED}DOWN${RESET}")

    echo -e "  ${VM_NAMES[$i]}: pool=$pool_status pay=$pay_status"
done

echo -e "\n${GREEN}${BOLD}Services started. Ready for 24h observe-only soak.${RESET}"
echo ""
echo "Start soak test:"
echo "  SOAK_HOURS=24 nohup ./scripts/soak-test-mainnet-observe.sh > soak-mainnet-observe.log 2>&1 &"
