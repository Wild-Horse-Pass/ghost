#!/usr/bin/env bash
# mainnet-observe-preflight-backup.sh — Phase 0: Back up all signet state before mainnet test
#
# Run ONCE before switching to mainnet. Creates .signet backups of all configs and databases.
# These backups are restored by mainnet-observe-rollback.sh after the 24h test.

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

echo -e "${BOLD}═══ Phase 0: Pre-Flight Backup (signet state) ═══${RESET}"

for i in "${!VM_IPS[@]}"; do
    ip="${VM_IPS[$i]}"
    name="${VM_NAMES[$i]}"
    echo -e "\n${BOLD}── $name ($ip) ──${RESET}"

    ssh $SSH_OPTS "root@$ip" bash <<'REMOTE_SCRIPT'
set -euo pipefail

echo "  Stopping services..."
systemctl stop ghost-pay ghost-pool || true
sleep 2

echo "  Backing up configs..."
cp /etc/ghost/pool.toml /etc/ghost/pool.toml.signet
cp /etc/systemd/system/ghost-pay.service /etc/systemd/system/ghost-pay.service.signet
cp /etc/systemd/system/ghostd.service /etc/systemd/system/ghostd.service.signet 2>/dev/null || \
    cp /etc/systemd/system/bitcoind.service /etc/systemd/system/bitcoind.service.signet 2>/dev/null || true
cp /etc/bitcoin/bitcoin.conf /etc/bitcoin/bitcoin.conf.signet

echo "  Backing up ghost-pool database..."
cp /home/ghost/.ghost/ghost.db /home/ghost/.ghost/ghost.db.signet

echo "  Backing up ghost-pay database..."
if [ -d /home/ghost/.ghost/ghost-pay ]; then
    cp -r /home/ghost/.ghost/ghost-pay /home/ghost/.ghost/ghost-pay.signet
fi

echo "  Backing up MPC params..."
if [ -d /home/ghost/.ghost/mpc_params ]; then
    cp -r /home/ghost/.ghost/mpc_params /home/ghost/.ghost/mpc_params.signet
fi

echo "  Restarting signet services..."
systemctl start ghost-pool ghost-pay || true

echo "  Backup checksums:"
sha256sum /home/ghost/.ghost/ghost.db.signet | cut -d' ' -f1
ls -lh /home/ghost/.ghost/ghost.db.signet

echo "  Done."
REMOTE_SCRIPT

    if [ $? -eq 0 ]; then
        echo -e "  $name: ${GREEN}BACKUP COMPLETE${RESET}"
    else
        echo -e "  $name: ${RED}BACKUP FAILED${RESET}"
        exit 1
    fi
done

echo -e "\n${GREEN}${BOLD}All backups complete. Safe to proceed with mainnet switch.${RESET}"
echo -e "To rollback: ./scripts/mainnet-observe-rollback.sh"
