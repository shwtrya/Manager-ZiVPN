#!/bin/bash
set -euo pipefail
DB="/etc/zivpn/users.json"
DAYS="${1:-7}"
mkdir -p /var/log/zivpn
if [ ! -f "$DB" ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') AUTO-CLEANUP: users.json not found" >> /var/log/zivpn/events.log
  exit 0
fi
removed="$(python3 - "$DB" "$DAYS" <<'PY'
import json,sys,datetime
path=sys.argv[1]; days=int(sys.argv[2])
data=json.load(open(path))
today=datetime.date.today()
cut=today-datetime.timedelta(days=days)
out=[]
rm=0
for u in data:
  exp=u.get('expired') or u.get('Expired') or ''
  try:
    d=datetime.datetime.strptime(exp,'%Y-%m-%d').date()
  except Exception:
    out.append(u); continue
  if d < cut:
    rm += 1
  else:
    out.append(u)
json.dump(out,open(path,'w'))
print(rm)
PY
)"
echo "$(date '+%Y-%m-%d %H:%M:%S') AUTO-CLEANUP: removed ${removed} expired users (>${DAYS}d)" >> /var/log/zivpn/events.log
find /root/zivpn_backups -type f -name "backup-*.zip" -mtime +30 -delete 2>/dev/null || true
