#!/bin/bash
set -euo pipefail

# ZiVPN Daily Stats Reporter
# Reads /var/log/zivpn/metrics.jsonl produced by zivpn-alert-check.sh
# Can be run by cron or via Telegram Bot.

MODE="${1:-today}"   # today|yesterday|date:YYYY-MM-DD
NOTIFY="${2:-}"      # --notify

BOTCFG="/etc/zivpn/bot-config.json"

METRICS_FILE="/var/log/zivpn/metrics.jsonl"
EVENT_LOG="/var/log/zivpn/events.log"
OUT_DIR="/var/log/zivpn"
mkdir -p "$OUT_DIR"

resolve_date() {
  if [[ "$MODE" == "today" ]]; then
    date +%F
  elif [[ "$MODE" == "yesterday" ]]; then
    date -d "yesterday" +%F
  elif [[ "$MODE" == date:* ]]; then
    echo "${MODE#date:}"
  else
    date +%F
  fi
}

DAY="$(resolve_date)"
REPORT_FILE="$OUT_DIR/daily-${DAY}.txt"

python3 - "$DAY" "$METRICS_FILE" "$EVENT_LOG" "$REPORT_FILE" <<'PY'
import sys, json, datetime, re

day=sys.argv[1]
metrics=sys.argv[2]
events=sys.argv[3]
out=sys.argv[4]

def read_lines(path):
    try:
        with open(path,'r',encoding='utf-8',errors='ignore') as f:
            return f.read().splitlines()
    except Exception:
        return []

ms=read_lines(metrics)
ev=read_lines(events)

online_counts=[]
user_seen={}

for line in ms:
    try:
        obj=json.loads(line)
    except Exception:
        continue
    ts=str(obj.get('ts',''))
    if not ts.startswith(day):
        continue
    online=int(obj.get('online') or 0)
    online_counts.append(online)
    users=obj.get('users') or []
    for u in users:
        u=str(u)
        if not u:
            continue
        user_seen[u]=user_seen.get(u,0)+1

peak=max(online_counts) if online_counts else 0
avg=round(sum(online_counts)/len(online_counts),2) if online_counts else 0

newip=sum(1 for l in ev if l.startswith(day) and 'NEWIP:' in l)
over=sum(1 for l in ev if l.startswith(day) and 'OVERLIMIT:' in l)
devm=sum(1 for l in ev if l.startswith(day) and 'DEVICE_MISMATCH:' in l)
ban=sum(1 for l in ev if l.startswith(day) and re.search(r'F2B_(BAN|UNBAN)', l))

top=sorted(user_seen.items(), key=lambda x: (-x[1], x[0]))[:10]

lines=[]
lines.append('ZiVPN Daily Stats')
lines.append(f'Date       : {day}')
lines.append('--------------------------------')
lines.append(f'Peak Online : {peak}')
lines.append(f'Avg Online  : {avg}')
lines.append('--------------------------------')
lines.append(f'NEWIP events        : {newip}')
lines.append(f'OVERLIMIT kicks     : {over}')
lines.append(f'DEVICE_MISMATCH kick: {devm}')
lines.append(f'Fail2ban events     : {ban}')
lines.append('--------------------------------')
lines.append('Top Users (by online snapshots):')
if top:
    for i,(u,c) in enumerate(top,1):
        lines.append(f'{i:>2}. {u} ({c}x)')
else:
    lines.append('-')

text='\n'.join(lines)
with open(out,'w',encoding='utf-8') as f:
    f.write(text+'\n')

print(text)
PY

if [ "$NOTIFY" = "--notify" ] && [ -f "$BOTCFG" ]; then
  python3 - "$BOTCFG" "$REPORT_FILE" <<'PY'
import json,sys,urllib.parse,subprocess

cfg_path=sys.argv[1]
report_path=sys.argv[2]

try:
    cfg=json.load(open(cfg_path,'r',encoding='utf-8'))
except Exception:
    cfg={}

token=str(cfg.get('bot_token') or '').strip()
if not token:
    sys.exit(0)

targets=[]
if cfg.get('owner_id'):
    targets.append(str(cfg.get('owner_id')))
for x in (cfg.get('admin_ids') or []):
    targets.append(str(x))
targets=[t for t in sorted(set(targets)) if t]

try:
    text=open(report_path,'r',encoding='utf-8',errors='ignore').read().strip()
except Exception:
    sys.exit(0)
if not text:
    sys.exit(0)

def send(chat_id, text):
    url=f"https://api.telegram.org/bot{token}/sendMessage"
    data={
        'chat_id': chat_id,
        'text': "*ZiVPN Daily Stats*\n```\n"+text+"\n```",
        'parse_mode': 'Markdown'
    }
    subprocess.run(['curl','-sS','-X','POST',url,'-d',urllib.parse.urlencode(data)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

for t in targets:
    send(t, text)

PY
fi

exit 0
