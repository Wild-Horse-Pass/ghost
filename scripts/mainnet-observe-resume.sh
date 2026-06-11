#!/usr/bin/env bash
# mainnet-observe-resume.sh — Swap from signet back to mainnet (preserves signet data)
#
# Restores mainnet state from *.mainnet, saves current signet state.
# Inverse of mainnet-observe-rollback.sh.

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

echo -e "${BOLD}═══ Resume: Signet → Mainnet (preserving signet data) ═══${RESET}"
echo -e "${YELLOW}This will stop signet services and switch to mainnet. Continue? [y/N]${RESET}"
read -r confirm
[[ "$confirm" != "y" && "$confirm" != "Y" ]] && { echo "Aborted."; exit 0; }

for i in "${!VM_IPS[@]}"; do
    ip="${VM_IPS[$i]}"
    name="${VM_NAMES[$i]}"
    echo -e "\n${BOLD}── $name ($ip) ──${RESET}"

    ssh $SSH_OPTS "root@$ip" bash <<'REMOTE_SCRIPT'
set -euo pipefail

echo "  Stopping all services..."
systemctl stop ghost-pay ghost-pool ghostd 2>/dev/null || true
systemctl stop bitcoind 2>/dev/null || true
sleep 2

# ── Check mainnet backups exist ──
if [ ! -f /etc/ghost/pool.toml.mainnet ]; then
    echo "  ERROR: No mainnet backups found. Run mainnet-observe-deploy.sh first."
    exit 1
fi

# ── Save current signet state ──
echo "  Saving current signet state..."
for f in /etc/ghost/pool.toml /etc/systemd/system/ghost-pay.service /etc/bitcoin/bitcoin.conf; do
    cp "$f" "${f}.signet" 2>/dev/null && echo "    Saved ${f}.signet" || true
done

if [ -f /etc/systemd/system/ghostd.service ]; then
    cp /etc/systemd/system/ghostd.service /etc/systemd/system/ghostd.service.signet
fi

if [ -d /etc/systemd/system/ghostd.service.d ]; then
    rm -rf /etc/systemd/system/ghostd.service.d.signet 2>/dev/null || true
    cp -r /etc/systemd/system/ghostd.service.d /etc/systemd/system/ghostd.service.d.signet
fi

if [ -f /home/ghost/.ghost/ghost.db ]; then
    cp /home/ghost/.ghost/ghost.db /home/ghost/.ghost/ghost.db.signet
    echo "    Saved ghost.db.signet"
fi

if [ -d /home/ghost/.ghost/ghost-pay ]; then
    rm -rf /home/ghost/.ghost/ghost-pay.signet 2>/dev/null || true
    cp -r /home/ghost/.ghost/ghost-pay /home/ghost/.ghost/ghost-pay.signet
    echo "    Saved ghost-pay.signet/"
fi

if [ -d /home/ghost/.ghost/mpc_params ]; then
    rm -rf /home/ghost/.ghost/mpc_params.signet 2>/dev/null || true
    cp -r /home/ghost/.ghost/mpc_params /home/ghost/.ghost/mpc_params.signet
    echo "    Saved mpc_params.signet/"
fi

# ── Restore mainnet state ──
echo "  Restoring mainnet configs..."
for f in /etc/ghost/pool.toml /etc/systemd/system/ghost-pay.service /etc/bitcoin/bitcoin.conf; do
    if [ -f "${f}.mainnet" ]; then
        cp "${f}.mainnet" "$f"
        echo "    Restored $f"
    fi
done

if [ -f /etc/systemd/system/ghostd.service.mainnet ]; then
    cp /etc/systemd/system/ghostd.service.mainnet /etc/systemd/system/ghostd.service
    echo "    Restored ghostd.service"
fi

if [ -d /etc/systemd/system/ghostd.service.d.mainnet ]; then
    rm -rf /etc/systemd/system/ghostd.service.d
    cp -r /etc/systemd/system/ghostd.service.d.mainnet /etc/systemd/system/ghostd.service.d
    echo "    Restored ghostd.service.d/ drop-ins"
fi

chown ghost:ghost /etc/bitcoin/bitcoin.conf 2>/dev/null || true

echo "  Restoring mainnet databases..."
if [ -f /home/ghost/.ghost/ghost.db.mainnet ]; then
    mv /home/ghost/.ghost/ghost.db.mainnet /home/ghost/.ghost/ghost.db
    echo "    Restored ghost.db"
fi

if [ -d /home/ghost/.ghost/ghost-pay.mainnet ]; then
    rm -rf /home/ghost/.ghost/ghost-pay
    mv /home/ghost/.ghost/ghost-pay.mainnet /home/ghost/.ghost/ghost-pay
    echo "    Restored ghost-pay/"
fi

if [ -d /home/ghost/.ghost/mpc_params.mainnet ]; then
    rm -rf /home/ghost/.ghost/mpc_params
    cp -r /home/ghost/.ghost/mpc_params.mainnet /home/ghost/.ghost/mpc_params
    echo "    Restored mpc_params/"
fi

echo "  Reloading systemd and starting mainnet services..."
systemctl daemon-reload
systemctl start ghostd
sleep 5

echo "  Verifying ghostd..."
if systemctl is-active --quiet ghostd 2>/dev/null; then
    echo "    ghostd: ACTIVE"
else
    echo "    ghostd: NOT RUNNING"
fi

echo "  NOTE: ghost-pool and ghost-pay not started automatically."
echo "  Use mainnet-observe-start.sh to start them (handles MPC ceremony)."
echo "  Done."
REMOTE_SCRIPT

    if [ $? -eq 0 ]; then
        echo -e "  $name: ${GREEN}RESUME COMPLETE${RESET}"
    else
        echo -e "  $name: ${RED}RESUME FAILED${RESET}"
    fi
done

echo -e "\n${GREEN}${BOLD}Mainnet restored. ghostd running on all VMs.${RESET}"
echo ""
echo "Next steps:"
echo "  1. Check sync: ./scripts/mainnet-observe-start.sh --check-sync"
echo "  2. Start services: ./scripts/mainnet-observe-start.sh"
echo "  3. Soak: SOAK_HOURS=24 nohup ./scripts/soak-test-mainnet-observe.sh > soak-mainnet-observe.log 2>&1 &"
