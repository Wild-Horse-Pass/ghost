#!/usr/bin/env bash
# mainnet-observe-deploy.sh — Deploy mainnet configs + binaries for observe-only test
#
# Prerequisites:
#   1. Run mainnet-observe-preflight-backup.sh first
#   2. Build relaxed-guard binaries: cargo build --release -p ghost-pool -p ghost-pay -j2
#   3. ghostd must have finished IBD (check with: bitcoin-cli getblockchaininfo)
#
# This script:
#   - Deploys bitcoin.conf for mainnet
#   - Deploys pool.toml for mainnet
#   - Deploys ghost-pay service for mainnet
#   - Deploys relaxed-guard binaries
#   - Starts ghostd (must sync before ghost-pool)
#
# NOTE: Does NOT start ghost-pool/ghost-pay — use mainnet-observe-start.sh for that
# (ghostd must be past IBD first).

set -euo pipefail

SSH_KEY="$HOME/.ssh/ghost_signet_ed25519"
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=10"

VM_IPS=("83.136.251.162" "85.9.198.212" "213.163.207.46" "95.111.221.169")
VM_NAMES=("VM1" "VM2" "VM3" "VM4")

# Mainnet node payout addresses — throwaway (observe-only, no real BTC)
NODE_PAYOUT_ADDRESSES=(
    "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    "bc1qc7slrfxkknhcq86cc3c0kkql2l7h3jntku5m0e"
    "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"
    "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h"
)
TREASURY_ADDRESS="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

INTERNAL_API_SECRET="a3d4e98e44f337243cb665575e1d850e3b0c1ccd71bbede816eccea2815e2a8b"

RPC_PASSWORD="522030635321a0b58e8297d1c834bf126eab712dc28b9c0b240bdb9a98f0df8d"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY_DIR="$PROJECT_DIR/target/release"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

# ─── Validation ──────────────────────────────────────────────────────────────

echo -e "${BOLD}═══ Mainnet Observe-Only Deploy ═══${RESET}"

# Check binaries exist
for bin in ghost-pool ghost-pay; do
    if [ ! -f "$BINARY_DIR/$bin" ]; then
        echo -e "${RED}ERROR: $BINARY_DIR/$bin not found. Build first:${RESET}"
        echo "  cargo build --release -p ghost-pool -p ghost-pay -j2"
        exit 1
    fi
done

echo -e "${YELLOW}This will reconfigure all 4 VMs for MAINNET. Continue? [y/N]${RESET}"
read -r confirm
[[ "$confirm" != "y" && "$confirm" != "Y" ]] && { echo "Aborted."; exit 0; }

# ─── Deploy to each VM ──────────────────────────────────────────────────────

for i in "${!VM_IPS[@]}"; do
    ip="${VM_IPS[$i]}"
    name="${VM_NAMES[$i]}"
    payout_addr="${NODE_PAYOUT_ADDRESSES[$i]}"

    echo -e "\n${BOLD}── $name ($ip) ──${RESET}"

    # Build seed_nodes list (all OTHER VMs)
    seed_nodes=""
    for j in "${!VM_IPS[@]}"; do
        if [ "$j" != "$i" ]; then
            for port in 8555 8556 8557 8558 8559 8560 8561 8562; do
                seed_nodes="${seed_nodes}\"${VM_IPS[$j]}:${port}\", "
            done
        fi
    done

    echo "  Stopping services..."
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=30 "root@$ip" \
        "systemctl stop ghost-pay 2>/dev/null; systemctl stop ghost-pool 2>/dev/null; systemctl stop ghostd 2>/dev/null; systemctl stop bitcoind 2>/dev/null; true" || true
    sleep 3
    ssh $SSH_OPTS "root@$ip" "pkill -9 -f ghost-pay 2>/dev/null; pkill -9 -f ghost-pool 2>/dev/null; true" || true
    sleep 1

    echo "  Deploying binaries..."
    ssh $SSH_OPTS "root@$ip" "rm -f /tmp/ghost-pool-new /tmp/ghost-pay-new"
    scp $SSH_OPTS "$BINARY_DIR/ghost-pool" "root@$ip:/tmp/ghost-pool-new"
    scp $SSH_OPTS "$BINARY_DIR/ghost-pay" "root@$ip:/tmp/ghost-pay-new"
    ssh $SSH_OPTS "root@$ip" "mv -f /opt/ghost/bin/ghost-pool /opt/ghost/bin/ghost-pool.old 2>/dev/null; mv -f /opt/ghost/bin/ghost-pay /opt/ghost/bin/ghost-pay.old 2>/dev/null; cp /tmp/ghost-pool-new /opt/ghost/bin/ghost-pool && cp /tmp/ghost-pay-new /opt/ghost/bin/ghost-pay && chmod +x /opt/ghost/bin/ghost-pool /opt/ghost/bin/ghost-pay && rm -f /tmp/ghost-pool-new /tmp/ghost-pay-new /opt/ghost/bin/ghost-pool.old /opt/ghost/bin/ghost-pay.old"

    echo "  Deploying bitcoin.conf (mainnet, pruned)..."
    ssh $SSH_OPTS "root@$ip" bash -c "cat > /etc/bitcoin/bitcoin.conf" <<EOF
# Mainnet configuration — pruned for observe-only test
server=1
listen=1
prune=550

rpcuser=ghostrpc_mainnet
rpcpassword=$RPC_PASSWORD
rpcallowip=127.0.0.1
rpcbind=127.0.0.1
rpcport=8332
port=8333

zmqpubhashblock=tcp://127.0.0.1:28332
zmqpubhashtx=tcp://127.0.0.1:28333
zmqpubsequence=tcp://127.0.0.1:28334

dbcache=1024
maxconnections=50
fallbackfee=0.00001
EOF

    echo "  Deploying pool.toml (mainnet)..."
    ssh $SSH_OPTS "root@$ip" bash -c "cat > /etc/ghost/pool.toml" <<EOF
[bitcoin]
network = "mainnet"
rpc_port = 8332
rpc_user = "ghostrpc_mainnet"
rpc_password = "$RPC_PASSWORD"
zmq_hashblock = "tcp://127.0.0.1:28332"
zmq_hashtx = "tcp://127.0.0.1:28333"
zmq_sequence = "tcp://127.0.0.1:28334"

[network]
internal_api_secret = "$INTERNAL_API_SECRET"
noise_enabled = true
http_port = 8080
seed_nodes = [${seed_nodes%, }]

[network.tls]
# TLS skipped for observe-only test (guard relaxed in code)

[pool]
treasury_address = "$TREASURY_ADDRESS"
node_payout_address = "$payout_addr"
elder_number = $((i + 1))

[policy]
profile = "full_open"
EOF

    echo "  Deploying ghostd.service (mainnet)..."
    ssh $SSH_OPTS "root@$ip" bash -c "cat > /etc/systemd/system/ghostd.service" <<'EOF'
[Unit]
Description=Ghost Bitcoin Core (mainnet)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ghost
Group=ghost
ExecStart=/opt/ghost/bin/ghostd -conf=/etc/bitcoin/bitcoin.conf -datadir=/var/lib/bitcoin
Restart=on-failure
RestartSec=30
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    echo "  Updating ghostd drop-in overrides..."
    ssh $SSH_OPTS "root@$ip" bash <<'DROPIN'
# Back up signet drop-ins, replace with mainnet
cp -r /etc/systemd/system/ghostd.service.d /etc/systemd/system/ghostd.service.d.signet 2>/dev/null || true
cat > /etc/systemd/system/ghostd.service.d/reaper.conf <<'EOCONF'
[Service]
ExecStart=
ExecStart=/opt/ghost/bin/ghostd -conf=/etc/bitcoin/bitcoin.conf -datadir=/var/lib/bitcoin
EOCONF
rm -f /etc/systemd/system/ghostd.service.d/ghost-pay.conf
# Fix bitcoin.conf ownership and remove conflicting datadir copy
chown ghost:ghost /etc/bitcoin/bitcoin.conf
mv /var/lib/bitcoin/bitcoin.conf /var/lib/bitcoin/bitcoin.conf.bak 2>/dev/null || true
DROPIN

    echo "  Deploying ghost-pay.service (mainnet)..."
    ssh $SSH_OPTS "root@$ip" bash -c "cat > /etc/systemd/system/ghost-pay.service" <<EOF
[Unit]
Description=Ghost Pay (mainnet)
After=ghost-pool.service
Wants=ghost-pool.service

[Service]
Type=simple
User=ghost
Group=ghost
ExecStart=/opt/ghost/bin/ghost-pay \
    --api-listen 0.0.0.0:8800 \
    --data-dir /home/ghost/.ghost/ghost-pay \
    --bitcoin-rpc http://127.0.0.1:8332 \
    --rpc-user ghostrpc_mainnet \
    --rpc-password $RPC_PASSWORD \
    --network mainnet \
    --treasury-address $TREASURY_ADDRESS \
    --node-payout-address $payout_addr
Restart=on-failure
RestartSec=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    echo "  Fresh ghost-pay database (moving signet DB aside)..."
    ssh $SSH_OPTS "root@$ip" bash <<'REMOTE'
if [ -f /home/ghost/.ghost/ghost-pay/ghost-pay.db ]; then
    mv /home/ghost/.ghost/ghost-pay/ghost-pay.db /home/ghost/.ghost/ghost-pay/ghost-pay.db.pre-mainnet-test
fi
# Fresh ghost.db for mainnet (keep signet backup)
if [ -f /home/ghost/.ghost/ghost.db ]; then
    mv /home/ghost/.ghost/ghost.db /home/ghost/.ghost/ghost.db.pre-mainnet-test
fi
# Clear MPC params (new ceremony needed for mainnet)
rm -rf /home/ghost/.ghost/mpc_params/*.vk.bin 2>/dev/null || true
REMOTE

    echo "  Reloading systemd..."
    ssh $SSH_OPTS "root@$ip" "systemctl daemon-reload"

    echo "  Starting ghostd (mainnet sync)..."
    ssh $SSH_OPTS "root@$ip" "systemctl start ghostd"

    echo -e "  $name: ${GREEN}DEPLOYED${RESET} (ghostd starting, ghost-pool/pay NOT started yet)"
done

echo -e "\n${BOLD}═══ Deployment Complete ═══${RESET}"
echo ""
echo -e "${YELLOW}NEXT STEPS:${RESET}"
echo "  1. Wait for ghostd to finish IBD on all VMs (check with mainnet-observe-start.sh --check-sync)"
echo "  2. Run: ./scripts/mainnet-observe-start.sh"
echo "  3. Monitor: SOAK_HOURS=24 ./scripts/soak-test-mainnet-observe.sh"
echo "  4. After 24h: ./scripts/mainnet-observe-rollback.sh"
