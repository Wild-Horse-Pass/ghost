#!/usr/bin/env bash
# install-backup-timer.sh — Install systemd timer for automated database backups
# Usage: sudo ./install-backup-timer.sh [--ghost-dir /home/ghost/.ghost]

set -euo pipefail

GHOST_DIR="${1:-/home/ghost/.ghost}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKUP_SCRIPT="$SCRIPT_DIR/backup-databases.sh"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root (sudo)"
    exit 1
fi

if [ ! -f "$BACKUP_SCRIPT" ]; then
    echo "ERROR: backup-databases.sh not found at $BACKUP_SCRIPT"
    exit 1
fi

chmod +x "$BACKUP_SCRIPT"

# Create systemd service unit
cat > /etc/systemd/system/ghost-backup.service <<EOF
[Unit]
Description=Ghost Pool Database Backup
After=network.target

[Service]
Type=oneshot
ExecStart=$BACKUP_SCRIPT $GHOST_DIR
User=ghost
Group=ghost

[Install]
WantedBy=multi-user.target
EOF

# Create systemd timer unit (daily at 03:00 UTC)
cat > /etc/systemd/system/ghost-backup.timer <<EOF
[Unit]
Description=Daily Ghost Pool Database Backup

[Timer]
OnCalendar=*-*-* 03:00:00 UTC
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
EOF

# Ensure backup directory exists
mkdir -p /var/backups/ghost/db
chown ghost:ghost /var/backups/ghost/db

# Enable and start timer
systemctl daemon-reload
systemctl enable ghost-backup.timer
systemctl start ghost-backup.timer

echo "Backup timer installed and started."
echo "  Schedule: daily at 03:00 UTC (+/- 5 min jitter)"
echo "  Backup dir: /var/backups/ghost/db"
echo "  Retention: 7 days"
echo ""
echo "Verify with: systemctl list-timers ghost-backup.timer"
echo "Test now with: systemctl start ghost-backup.service"
