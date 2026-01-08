#!/bin/bash
set -e

# ZiVPN IP Limit Enforcer (best effort)
# Enforces GLOBAL IP limit (1 or 2) for SSH sessions by reading /etc/zivpn/iplimit.conf.
# It will kick sessions from extra IPs if a user logs in from more than allowed IPs.

LIMIT_FILE="/etc/zivpn/iplimit.conf"
LIMIT=1
if [ -f "$LIMIT_FILE" ]; then
  v="$(cat "$LIMIT_FILE" | tr -d ' \n\r\t')"
  if [ "$v" = "2" ]; then LIMIT=2; fi
fi

LOG="/var/log/zivpn/events.log"
SEEN_DIR="/etc/zivpn/ip_seen"

# Optional: Device Binding (mode: IP)
DEVICE_CONF="/etc/zivpn/device_binding.conf"
DEVICE_DB="/etc/zivpn/device_bindings"
DEVICE_ENABLED=0
if [ -f "$DEVICE_CONF" ] && grep -q '^enabled=1' "$DEVICE_CONF" 2>/dev/null; then
  DEVICE_ENABLED=1
  touch "$DEVICE_DB"
fi
mkdir -p "$(dirname "$LOG")" "$SEEN_DIR"
touch "$LOG"


# Collect active SSH sessions from `who`
# Format: user tty date time (host)
mapfile -t LINES < <(who || true)
declare -A USER_IPS
declare -A KEEP_IP
declare -A SEEN_USER

# Build list of unique IPs per user in seen order
for line in "${LINES[@]}"; do
  user="$(awk '{print $1}' <<< "$line")"
  host="$(grep -oP '\(\K[^)]+' <<< "$line" || true)"
  if [ -z "$user" ] || [ -z "$host" ]; then
    continue
  fi
  key="${user}|${host}"
  if [ -z "${USER_IPS[$key]+x}" ]; then
    USER_IPS[$key]=1
  fi
done

# Count unique IPs per user
declare -A CNT
for key in "${!USER_IPS[@]}"; do
  user="${key%%|*}"
  CNT[$user]=$(( ${CNT[$user]:-0} + 1 ))
done

# Kick sessions from extra IPs (keep first LIMIT IPs arbitrarily)
for user in "${!CNT[@]}"; do

  # Enforce device binding first (stronger than global LIMIT)
  if [ "$DEVICE_ENABLED" = "1" ]; then
    for line in "${LINES[@]}"; do
      u="$(awk '{print $1}' <<< "$line")"
      tty="$(awk '{print $2}' <<< "$line")"
      ip="$(grep -oP '\(\K[^)]+' <<< "$line" || true)"
      if [ "$u" != "$user" ] || [ -z "$tty" ] || [ -z "$ip" ]; then continue; fi

      bound_ip=""
      if [ -f "$DEVICE_DB" ]; then
        bound_ip="$(awk -v UU="$user" '$1==UU{print $2; exit}' "$DEVICE_DB" 2>/dev/null || true)"
      fi

      if [ -z "$bound_ip" ]; then
        echo "$user $ip" >> "$DEVICE_DB" 2>/dev/null || true
        echo "$(date '+%Y-%m-%d %H:%M:%S') BIND: user=$user ip=$ip" >> "$LOG"
      elif [ "$ip" != "$bound_ip" ]; then
        pkill -KILL -t "$tty" 2>/dev/null || true
        echo "$(date '+%Y-%m-%d %H:%M:%S') DEVICE_MISMATCH: user=$u ip=$ip bound=$bound_ip action=KICK tty=$tty" >> "$LOG"
      fi
    done
  fi

  if [ "${CNT[$user]}" -le "$LIMIT" ]; then
    continue
  fi
  kept=0
  # Determine IPs to keep
  for key in "${!USER_IPS[@]}"; do
    u="${key%%|*}"
    ip="${key#*|}"
    if [ "$u" != "$user" ]; then continue; fi
    if [ $kept -lt $LIMIT ]; then
      KEEP_IP["${user}|${ip}"]=1
      kept=$((kept+1))
    fi
  done

  # Kill sessions on IPs not kept
  for line in "${LINES[@]}"; do
    u="$(awk '{print $1}' <<< "$line")"
    tty="$(awk '{print $2}' <<< "$line")"
    ip="$(grep -oP '\(\K[^)]+' <<< "$line" || true)"
    if [ "$u" != "$user" ] || [ -z "$tty" ] || [ -z "$ip" ]; then continue; fi
    # New IP detection
    f="$SEEN_DIR/$user"
    if [ -n "$ip" ]; then
      if [ ! -f "$f" ] || ! grep -qxF "$ip" "$f" 2>/dev/null; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') NEWIP: user=$user ip=$ip" >> "$LOG"
        echo "$ip" >> "$f" 2>/dev/null || true
      fi
    fi
    if [ -z "${KEEP_IP[${user}|${ip}]+x}" ]; then
      pkill -KILL -t "$tty" 2>/dev/null || true
      echo "$(date '+%Y-%m-%d %H:%M:%S') OVERLIMIT: user=$u ip=$ip limit=$LIMIT action=KICK tty=$tty" >> "$LOG"
    fi
  done
done

exit 0
