#!/usr/bin/env bash
# backup-databases.sh — Automated backup for ghost.db and ghost-pay.db
# Keeps 7 days of backups, prunes older. Logs to syslog.
# Usage: backup-databases.sh [--ghost-dir /home/ghost/.ghost]

set -euo pipefail

GHOST_DIR="${1:-/home/ghost/.ghost}"
BACKUP_DIR="/var/backups/ghost/db"
RETENTION_DAYS=7
TIMESTAMP="$(date +%Y%m%d%H%M)"

log() {
    logger -t ghost-backup "$1"
    echo "[$(date -Iseconds)] $1"
}

die() {
    log "ERROR: $1"
    exit 1
}

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

# Backup ghost.db (ghost-pool)
GHOST_DB="$GHOST_DIR/ghost.db"
if [ -f "$GHOST_DB" ]; then
    DEST="$BACKUP_DIR/ghost-${TIMESTAMP}.db"
    log "Backing up ghost.db to $DEST"
    sqlite3 "$GHOST_DB" ".backup '$DEST'" || die "Failed to backup ghost.db"
    log "ghost.db backup complete ($(du -h "$DEST" | cut -f1))"
else
    log "WARN: ghost.db not found at $GHOST_DB, skipping"
fi

# Backup ghost-pay.db
GHOST_PAY_DB="$GHOST_DIR/ghost-pay/ghost-pay.db"
if [ -f "$GHOST_PAY_DB" ]; then
    DEST="$BACKUP_DIR/ghost-pay-${TIMESTAMP}.db"
    log "Backing up ghost-pay.db to $DEST"
    sqlite3 "$GHOST_PAY_DB" ".backup '$DEST'" || die "Failed to backup ghost-pay.db"
    log "ghost-pay.db backup complete ($(du -h "$DEST" | cut -f1))"
else
    log "WARN: ghost-pay.db not found at $GHOST_PAY_DB, skipping"
fi

# Prune backups older than retention period
PRUNED=$(find "$BACKUP_DIR" -name "ghost*.db" -mtime +${RETENTION_DAYS} -print -delete | wc -l)
if [ "$PRUNED" -gt 0 ]; then
    log "Pruned $PRUNED backup(s) older than ${RETENTION_DAYS} days"
fi

log "Backup complete. Current backups:"
ls -lh "$BACKUP_DIR"/ghost*.db 2>/dev/null | while read -r line; do
    log "  $line"
done

exit 0
