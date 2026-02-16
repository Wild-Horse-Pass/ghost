#!/bin/bash
# Generate and sign a Ghost checkpoint, then publish to nginx.
# Runs on ghost-web VM via systemd timer or manually.
set -euo pipefail

GHOST_CLI="/opt/ghost/bin/ghost-cli"
RPC_CONF="/etc/ghost/ghostd-rpc.conf"
SIGNING_KEY_FILE="/etc/ghost/checkpoint-signing-key"
CHECKPOINT_DIR="/var/lib/ghostd/checkpoint"
SERVE_DIR="/var/www/get.bitcoinghost.org/checkpoint"
CHECKPOINT_INTERVAL=1000
LOG_TAG="ghost-checkpoint"

log() { logger -t "$LOG_TAG" "$@"; echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] $*"; }

# Read RPC credentials
if [ ! -f "$RPC_CONF" ]; then
    log "ERROR: RPC config not found at $RPC_CONF"
    exit 1
fi
RPC_USER=$(grep rpcuser "$RPC_CONF" | cut -d= -f2)
RPC_PASS=$(grep rpcpassword "$RPC_CONF" | cut -d= -f2)

# ghost-cli wrapper
gcli() {
    "$GHOST_CLI" -signet -rpcconnect=127.0.0.1 -rpcport=38332 \
        -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" "$@"
}

# Get current chain height
CHAIN_HEIGHT=$(gcli getblockcount 2>/dev/null)
if [ -z "$CHAIN_HEIGHT" ]; then
    log "ERROR: Cannot connect to ghostd RPC"
    exit 1
fi
log "Current chain height: $CHAIN_HEIGHT"

# Determine last checkpoint height from latest.json
LAST_HEIGHT=0
if [ -f "$SERVE_DIR/latest.json" ]; then
    LAST_HEIGHT=$(python3 -c "import json; print(json.load(open('$SERVE_DIR/latest.json'))['height'])" 2>/dev/null || echo 0)
fi
log "Last checkpoint height: $LAST_HEIGHT"

# Check if a new checkpoint is needed
NEXT_HEIGHT=$(( (CHAIN_HEIGHT / CHECKPOINT_INTERVAL) * CHECKPOINT_INTERVAL ))
if [ "$NEXT_HEIGHT" -le "$LAST_HEIGHT" ]; then
    log "No new checkpoint needed (next=$NEXT_HEIGHT, last=$LAST_HEIGHT)"
    exit 0
fi

if [ "$NEXT_HEIGHT" -le 0 ]; then
    log "Chain height too low for checkpoint ($CHAIN_HEIGHT)"
    exit 0
fi

log "Generating checkpoint at height $NEXT_HEIGHT"

# Read signing key
SIGNING_KEY=""
if [ -f "$SIGNING_KEY_FILE" ]; then
    SIGNING_KEY=$(cat "$SIGNING_KEY_FILE")
fi

# Generate checkpoint (with optional signing)
rm -rf "$CHECKPOINT_DIR"
mkdir -p "$CHECKPOINT_DIR"

if [ -n "$SIGNING_KEY" ]; then
    log "Generating signed checkpoint..."
    RESULT=$(gcli generatecheckpoint "$NEXT_HEIGHT" "$CHECKPOINT_DIR" "$SIGNING_KEY")
else
    log "WARNING: No signing key found at $SIGNING_KEY_FILE, generating unsigned checkpoint"
    RESULT=$(gcli generatecheckpoint "$NEXT_HEIGHT" "$CHECKPOINT_DIR")
fi

log "Checkpoint generated: $RESULT"

# Copy to nginx serving directory
mkdir -p "$SERVE_DIR"
rsync -a --delete "$CHECKPOINT_DIR/" "$SERVE_DIR/"
log "Published checkpoint to $SERVE_DIR"

# Write latest.json metadata
BLOCK_HASH=$(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin)['block_hash'])")
UTXO_COUNT=$(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin)['utxo_count'])")
TOTAL_CHUNKS=$(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin)['total_chunks'])")
SIGNED=$(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('signed', False))")

cat > "$SERVE_DIR/latest.json" << EOF
{
  "height": $NEXT_HEIGHT,
  "block_hash": "$BLOCK_HASH",
  "utxo_count": $UTXO_COUNT,
  "total_chunks": $TOTAL_CHUNKS,
  "signed": $SIGNED,
  "generated_at": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
}
EOF

log "Checkpoint generation complete: height=$NEXT_HEIGHT hash=$BLOCK_HASH"
