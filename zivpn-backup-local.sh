#!/bin/bash
set -euo pipefail
ts="$(date '+%Y%m%d-%H%M%S')"
dir="/root/zivpn_backups"
mkdir -p "$dir" /var/log/zivpn
out="$dir/backup-$ts.zip"
zip -rq "$out" /etc/zivpn /etc/cron.d/zivpn-* /etc/systemd/system/zivpn*.service /var/log/zivpn 2>/dev/null || true
echo "$(date '+%Y-%m-%d %H:%M:%S') BACKUP: created $out" >> /var/log/zivpn/events.log
