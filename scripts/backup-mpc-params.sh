#!/usr/bin/env bash
# backup-mpc-params.sh — Backup MPC parameters and verification keys
# Run once after any ceremony reset. Copies mpc_params/ and VK files.
# Usage: backup-mpc-params.sh [--ghost-dir /home/ghost/.ghost]

set -euo pipefail

GHOST_DIR="${1:-/home/ghost/.ghost}"
BACKUP_DIR="/var/backups/ghost/mpc"
TIMESTAMP="$(date +%Y%m%d%H%M)"
DEST="$BACKUP_DIR/$TIMESTAMP"

log() {
    logger -t ghost-mpc-backup "$1"
    echo "[$(date -Iseconds)] $1"
}

die() {
    log "ERROR: $1"
    exit 1
}

MPC_DIR="$GHOST_DIR/mpc_params"
if [ ! -d "$MPC_DIR" ]; then
    die "MPC params directory not found at $MPC_DIR"
fi

# Check for VK files
VK_FILES=("note_spend_vk.bin" "payout_vk.bin" "unshield_vk.bin")
for vk in "${VK_FILES[@]}"; do
    if [ ! -f "$MPC_DIR/$vk" ]; then
        log "WARN: VK file $vk not found in $MPC_DIR"
    fi
done

mkdir -p "$DEST"

# Copy mpc_params directory
log "Backing up MPC params to $DEST"
cp -a "$MPC_DIR" "$DEST/mpc_params" || die "Failed to copy mpc_params"

# Compute SHA-256 checksums for integrity verification
log "Computing checksums"
(cd "$DEST/mpc_params" && sha256sum * > "$DEST/checksums.sha256") || die "Failed to compute checksums"

# Show what we backed up
FILE_COUNT=$(find "$DEST/mpc_params" -type f | wc -l)
TOTAL_SIZE=$(du -sh "$DEST" | cut -f1)
log "Backup complete: $FILE_COUNT files, $TOTAL_SIZE total"
log "Checksums written to $DEST/checksums.sha256"

# Keep only the 3 most recent backups
BACKUP_COUNT=$(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l)
if [ "$BACKUP_COUNT" -gt 3 ]; then
    PRUNE_COUNT=$((BACKUP_COUNT - 3))
    log "Pruning $PRUNE_COUNT old MPC backup(s)"
    find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d | sort | head -n "$PRUNE_COUNT" | xargs rm -rf
fi

log "Current MPC backups:"
ls -d "$BACKUP_DIR"/*/ 2>/dev/null | while read -r dir; do
    log "  $dir ($(du -sh "$dir" | cut -f1))"
done

exit 0
