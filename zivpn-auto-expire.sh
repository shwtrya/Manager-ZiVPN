#!/bin/bash
set -euo pipefail
PORT="$(cat /etc/zivpn/api_port 2>/dev/null || echo 8080)"
KEY="$(cat /etc/zivpn/apikey 2>/dev/null || echo '')"
RESP="$(curl -s -X POST "http://127.0.0.1:${PORT}/api/cron/expire" -H "X-API-Key: ${KEY}" || true)"
mkdir -p /var/log/zivpn
echo "$(date '+%Y-%m-%d %H:%M:%S') AUTO-EXPIRE: ${RESP}" >> /var/log/zivpn/events.log
