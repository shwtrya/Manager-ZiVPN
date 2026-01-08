#!/bin/bash
set -euo pipefail

BOTCFG="/etc/zivpn/bot-config.json"
EVENT_LOG="/var/log/zivpn/events.log"
OFFSET_FILE="/etc/zivpn/alerts.offset"
STATE_FILE="/etc/zivpn/alerts_state"

mkdir -p /var/log/zivpn /etc/zivpn
touch "$EVENT_LOG"

json_get() {
  local key="$1"
  python3 - "$BOTCFG" "$key" <<'PY'
import json,sys
p=sys.argv[1]; k=sys.argv[2]
try: d=json.load(open(p))
except Exception: d={}
print(d.get(k,''))
PY
}

json_list() {
  local key="$1"
  python3 - "$BOTCFG" "$key" <<'PY'
import json,sys
p=sys.argv[1]; k=sys.argv[2]
try: d=json.load(open(p))
except Exception: d={}
val=d.get(k,[]) or []
print(" ".join([str(x) for x in val]))
PY
}

send_tg() {
  local token="$1"
  local chat_id="$2"
  local text="$3"
  curl -sS -X POST "https://api.telegram.org/bot${token}/sendMessage"     -d "chat_id=${chat_id}" -d "text=${text}" -d "parse_mode=Markdown" >/dev/null || true
}

token="$(json_get bot_token)"
[ -z "$token" ] && exit 0

# Scheduler flag
alerts_enabled="$(python3 - <<'PY'
import json
p='/etc/zivpn/scheduler.json'
try: d=json.load(open(p))
except Exception: d={}
print('1' if d.get('alerts_enabled',True) else '0')
PY
)"
[ "$alerts_enabled" = "0" ] && exit 0

targets="$(json_get owner_id) $(json_list admin_ids)"
targets="$(echo "$targets" | tr ' ' '\n' | sed '/^$/d' | sort -u | tr '\n' ' ')"

# Tail events
offset=0
[ -f "$OFFSET_FILE" ] && offset="$(cat "$OFFSET_FILE" 2>/dev/null || echo 0)"
total_lines="$(wc -l < "$EVENT_LOG" | tr -d ' ')"
if [ "$offset" -gt "$total_lines" ]; then offset=0; fi
new_lines=$(( total_lines - offset ))
if [ "$new_lines" -gt 0 ]; then
  msg="$(tail -n "$new_lines" "$EVENT_LOG" | tail -n 20)"
  echo "$total_lines" > "$OFFSET_FILE"
  for id in $targets; do
    send_tg "$token" "$id" "*ZiVPN Alert*\n\`\`\`\n$msg\n\`\`\`"
  done
fi

# Service state change
get_state() { systemctl is-active --quiet "$1" && echo "up" || echo "down"; }
api_s="$(get_state zivpn-api.service)"
bot_s="$(get_state zivpn-bot.service)"
udp_s="$(get_state zivpn-udplimit.service)"

old_api=""; old_bot=""; old_udp=""
if [ -f "$STATE_FILE" ]; then
  old_api="$(grep -E '^zivpn-api=' "$STATE_FILE" | cut -d= -f2- || true)"
  old_bot="$(grep -E '^zivpn-bot=' "$STATE_FILE" | cut -d= -f2- || true)"
  old_udp="$(grep -E '^zivpn-udplimit=' "$STATE_FILE" | cut -d= -f2- || true)"
fi

changed=0
note=""
if [ "$old_api" != "$api_s" ] && [ -n "$old_api" ]; then note="$note\nzivpn-api: $old_api -> $api_s"; changed=1; fi
if [ "$old_bot" != "$bot_s" ] && [ -n "$old_bot" ]; then note="$note\nzivpn-bot: $old_bot -> $bot_s"; changed=1; fi
if [ "$old_udp" != "$udp_s" ] && [ -n "$old_udp" ]; then note="$note\nzivpn-udplimit: $old_udp -> $udp_s"; changed=1; fi

cat > "$STATE_FILE" <<EOF
zivpn-api=$api_s
zivpn-bot=$bot_s
zivpn-udplimit=$udp_s
EOF

if [ "$changed" -eq 1 ]; then
  for id in $targets; do
    send_tg "$token" "$id" "*ZiVPN Service Alert*\n\`\`\`$note\n\`\`\`"
  done
fi

# Metrics snapshot (for Daily Stats)
METRICS_FILE="/var/log/zivpn/metrics.jsonl"
APIKEY_FILE="/etc/zivpn/apikey"
API_URL="http://127.0.0.1:8080/api/online"

if [ -f "$APIKEY_FILE" ]; then
  apikey="$(cat "$APIKEY_FILE" 2>/dev/null || true)"
  if [ -n "$apikey" ]; then
    json="$(curl -sS --max-time 3 -H "X-API-Key: $apikey" "$API_URL" || true)"
    python3 - "$json" "$METRICS_FILE" <<'PY'
import json,sys,datetime
raw=sys.argv[1]
out=sys.argv[2]
try:
    data=json.loads(raw)
except Exception:
    sys.exit(0)
if not isinstance(data, dict) or not data.get('success'):
    sys.exit(0)
payload=data.get('data') or {}
users=payload.get('users') or []
names=[]
for u in users:
    if isinstance(u, dict) and u.get('user'):
        names.append(str(u.get('user')))
ts=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
line={'ts': ts, 'online': int(payload.get('total_users') or len(names)), 'users': names[:200]}
with open(out,'a',encoding='utf-8') as f:
    f.write(json.dumps(line, ensure_ascii=False) + "\n")
PY
  fi
fi
