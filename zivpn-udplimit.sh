#!/usr/bin/env bash
set -euo pipefail

# ZiVPN UDP per-user IP limit (best-effort via DPI)
#
# Requirements:
# - iptables + ipset
# - linux kernel string match (xt_string)
# - /etc/zivpn/config.json with auth.config list
# - /etc/zivpn/iplimit.conf contains global limit: 1 or 2 (0 = disabled)

CFG="/etc/zivpn/config.json"
LIMIT_FILE="/etc/zivpn/iplimit.conf"
PORT="5667"

table="mangle"
chain="ZIVPN_UDPLIMIT"

die() { echo "[zivpn-udplimit] $*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"
}

need iptables
need ipset
need python3

if [[ ! -f "$CFG" ]]; then
  die "Config not found: $CFG"
fi

limit="0"
if [[ -f "$LIMIT_FILE" ]]; then
  limit="$(tr -dc '0-9' < "$LIMIT_FILE" | head -c 2 || true)"
fi
limit="${limit:-0}"
if [[ "$limit" != "1" && "$limit" != "2" ]]; then
  limit="0"
fi

# Extract passwords from config.json
mapfile -t passwords < <(python3 - <<'PY'
import json
cfg = "/etc/zivpn/config.json"
with open(cfg, "r", encoding="utf-8") as f:
    data = json.load(f)
pw = data.get("auth", {}).get("config", [])
for p in pw:
    if isinstance(p, str) and p.strip():
        print(p.strip())
PY
)

if [[ ${#passwords[@]} -eq 0 ]]; then
  # nothing to do
  exit 0
fi

hash_name() {
  # ipset name max 31 chars; use sha1 to be safe
  local s="$1"
  echo -n "$s" | sha1sum | awk '{print $1}' | cut -c1-20
}

set_name_for() {
  echo "zvudp_$(hash_name "$1")"
}

ensure_chain() {
  # Create chain (idempotent)
  iptables -t "$table" -N "$chain" 2>/dev/null || true
  iptables -t "$table" -F "$chain" || true

  # Ensure jump from PREROUTING for udp dport
  if ! iptables -t "$table" -C PREROUTING -p udp --dport "$PORT" -j "$chain" 2>/dev/null; then
    iptables -t "$table" -I PREROUTING 1 -p udp --dport "$PORT" -j "$chain"
  fi
}

cleanup_old_sets() {
  # Remove stale zvudp_* sets not in current passwords list
  local keep=""
  for p in "${passwords[@]}"; do
    keep+=" $(set_name_for "$p")"
  done
  # ipset list -n shows set names
  while read -r s; do
    [[ "$s" == zvudp_* ]] || continue
    if [[ " $keep " != *" $s "* ]]; then
      ipset destroy "$s" 2>/dev/null || true
    fi
  done < <(ipset list -n 2>/dev/null || true)
}

apply_disabled() {
  # remove jump + flush chain if exists
  iptables -t "$table" -D PREROUTING -p udp --dport "$PORT" -j "$chain" 2>/dev/null || true
  iptables -t "$table" -F "$chain" 2>/dev/null || true
  # Do not destroy chain to avoid race; ok.
  cleanup_old_sets
  echo "[zivpn-udplimit] UDP limit disabled (iplimit=$limit)"
}

if [[ "$limit" == "0" ]]; then
  apply_disabled
  exit 0
fi

ensure_chain
cleanup_old_sets

for p in "${passwords[@]}"; do
  setname="$(set_name_for "$p")"
  # Create per-user ipset with maxelem=limit, timeout so stale IPs drop automatically
  # If exists, recreate with correct maxelem (simplest: destroy & recreate)
  if ipset list -n 2>/dev/null | grep -qx "$setname"; then
    ipset destroy "$setname" 2>/dev/null || true
  fi
  ipset create "$setname" hash:ip timeout 86400 maxelem "$limit" -exist

  # Build a per-user chain
  user_chain="ZVUDP_$(hash_name "$p")"
  iptables -t "$table" -N "$user_chain" 2>/dev/null || true
  iptables -t "$table" -F "$user_chain" || true

  # Logic:
  # 1) If src is already in set => ACCEPT
  iptables -t "$table" -A "$user_chain" -m set --match-set "$setname" src -j ACCEPT
  # 2) Try add src to set (no-op if already)
  iptables -t "$table" -A "$user_chain" -j SET --add-set "$setname" src
  # 3) If now in set => ACCEPT
  iptables -t "$table" -A "$user_chain" -m set --match-set "$setname" src -j ACCEPT
  # 4) Otherwise (set full) => DROP
  iptables -t "$table" -A "$user_chain" -j DROP

  # Match packets containing password; jump to per-user chain.
  # Use bm algo for speed; adjust --from/--to to scan only first 256 bytes.
  iptables -t "$table" -A "$chain" -p udp --dport "$PORT" \
    -m string --algo bm --from 0 --to 256 --string "$p" \
    -j "$user_chain"
done

# Default: do not drop unmatched packets (in case protocol changes/obfs)
iptables -t "$table" -A "$chain" -j RETURN

echo "[zivpn-udplimit] Applied UDP per-user limit = $limit IP(s)"
