#!/usr/bin/env bash
# mainnet-observe-rollback.sh — Swap from mainnet back to signet (preserves mainnet data)
#
# Saves mainnet state as *.mainnet, restores signet from *.signet backups.
# To switch back to mainnet later: ./scripts/mainnet-observe-resume.sh

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

echo -e "${BOLD}═══ Rollback: Mainnet → Signet (preserving mainnet data) ═══${RESET}"
echo -e "${YELLOW}This will stop mainnet services and switch to signet. Mainnet data is preserved. Continue? [y/N]${RESET}"
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

# ── Save mainnet state ──
echo "  Saving mainnet state..."

# Configs
for f in /etc/ghost/pool.toml /etc/systemd/system/ghost-pay.service /etc/bitcoin/bitcoin.conf; do
    cp "$f" "${f}.mainnet" 2>/dev/null && echo "    Saved ${f}.mainnet" || true
done

if [ -f /etc/systemd/system/ghostd.service ]; then
    cp /etc/systemd/system/ghostd.service /etc/systemd/system/ghostd.service.mainnet
    echo "    Saved ghostd.service.mainnet"
fi

# Drop-in overrides
if [ -d /etc/systemd/system/ghostd.service.d ]; then
    rm -rf /etc/systemd/system/ghostd.service.d.mainnet 2>/dev/null || true
    cp -r /etc/systemd/system/ghostd.service.d /etc/systemd/system/ghostd.service.d.mainnet
    echo "    Saved ghostd.service.d.mainnet/"
fi

# Ghost databases (mainnet)
if [ -f /home/ghost/.ghost/ghost.db ]; then
    mv /home/ghost/.ghost/ghost.db /home/ghost/.ghost/ghost.db.mainnet
    echo "    Saved ghost.db.mainnet"
fi

if [ -d /home/ghost/.ghost/ghost-pay ]; then
    rm -rf /home/ghost/.ghost/ghost-pay.mainnet 2>/dev/null || true
    mv /home/ghost/.ghost/ghost-pay /home/ghost/.ghost/ghost-pay.mainnet
    echo "    Saved ghost-pay.mainnet/"
fi

if [ -d /home/ghost/.ghost/mpc_params ]; then
    rm -rf /home/ghost/.ghost/mpc_params.mainnet 2>/dev/null || true
    cp -r /home/ghost/.ghost/mpc_params /home/ghost/.ghost/mpc_params.mainnet
    echo "    Saved mpc_params.mainnet/"
fi

# Bitcoin chain data — just leave in place, tagged by directory
# /var/lib/bitcoin/blocks, /var/lib/bitcoin/chainstate are mainnet
# /var/lib/bitcoin/signet/ is signet — both coexist in the datadir

# ── Restore signet state ──
echo "  Restoring signet configs..."
for f in /etc/ghost/pool.toml /etc/systemd/system/ghost-pay.service /etc/bitcoin/bitcoin.conf; do
    if [ -f "${f}.signet" ]; then
        cp "${f}.signet" "$f"
        echo "    Restored $f"
    else
        echo "    WARNING: ${f}.signet not found, skipping"
    fi
done

if [ -f /etc/systemd/system/ghostd.service.signet ]; then
    cp /etc/systemd/system/ghostd.service.signet /etc/systemd/system/ghostd.service
    echo "    Restored ghostd.service"
fi

if [ -d /etc/systemd/system/ghostd.service.d.signet ]; then
    rm -rf /etc/systemd/system/ghostd.service.d
    cp -r /etc/systemd/system/ghostd.service.d.signet /etc/systemd/system/ghostd.service.d
    echo "    Restored ghostd.service.d/ drop-ins"
fi

chown bitcoin:bitcoin /etc/bitcoin/bitcoin.conf 2>/dev/null || true

echo "  Restoring signet databases..."
if [ -f /home/ghost/.ghost/ghost.db.signet ]; then
    cp /home/ghost/.ghost/ghost.db.signet /home/ghost/.ghost/ghost.db
    echo "    Restored ghost.db"
fi

if [ -d /home/ghost/.ghost/ghost-pay.signet ]; then
    rm -rf /home/ghost/.ghost/ghost-pay
    cp -r /home/ghost/.ghost/ghost-pay.signet /home/ghost/.ghost/ghost-pay
    echo "    Restored ghost-pay/"
fi

if [ -d /home/ghost/.ghost/mpc_params.signet ]; then
    rm -rf /home/ghost/.ghost/mpc_params
    cp -r /home/ghost/.ghost/mpc_params.signet /home/ghost/.ghost/mpc_params
    echo "    Restored mpc_params/"
fi

echo "  Reloading systemd and starting signet services..."
systemctl daemon-reload
systemctl start ghostd 2>/dev/null || systemctl start bitcoind 2>/dev/null || true
sleep 5
systemctl start ghost-pool
sleep 3
systemctl start ghost-pay

echo "  Verifying services..."
for svc in ghostd ghost-pool ghost-pay; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo "    $svc: ACTIVE"
    else
        if [ "$svc" = "ghostd" ] && systemctl is-active --quiet bitcoind 2>/dev/null; then
            echo "    bitcoind: ACTIVE"
        else
            echo "    $svc: NOT RUNNING"
        fi
    fi
done

echo "  Done."
REMOTE_SCRIPT

    if [ $? -eq 0 ]; then
        echo -e "  $name: ${GREEN}ROLLBACK COMPLETE${RESET}"
    else
        echo -e "  $name: ${RED}ROLLBACK FAILED${RESET}"
    fi
done

echo -e "\n${BOLD}═══ Post-Rollback ═══${RESET}"
echo ""
echo "Code changes still need to be reverted:"
echo "  cd $(cd "$(dirname "$0")/.." && pwd)"
echo "  git checkout -- bins/ghost-pool/src/main.rs crates/ghost-common/src/config.rs"
echo "  cargo build --release -p ghost-pool -p ghost-pay -j2"
echo ""
echo "Then redeploy signet binaries:"
echo "  for vm in ghost-vm1 ghost-vm2 ghost-vm3 ghost-vm4; do"
echo "    scp target/release/ghost-pool \$vm:/tmp/ghost-pool && \\"
echo "    ssh \$vm 'sudo systemctl stop ghost-pool && sudo cp /tmp/ghost-pool /opt/ghost/bin/ghost-pool && sudo systemctl start ghost-pool'"
echo "  done"
echo ""
echo -e "${GREEN}${BOLD}Signet restored. Mainnet data preserved as *.mainnet${RESET}"
echo "To resume mainnet: ./scripts/mainnet-observe-resume.sh"
