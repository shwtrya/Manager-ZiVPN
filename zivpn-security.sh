#!/bin/bash
set -e

# ZiVPN Security Helper
# - Firewall hardening (safe: only adds defensive DROP rules, does NOT set default DROP)
# - Torrent blocker apply/status
# - Device binding toggles/status/reset

ACTION="${1:-status}"

IPT="$(command -v iptables || true)"
if [ -z "$IPT" ]; then
  echo "iptables not found"
  exit 0
fi

SEC_CHAIN="ZIVPN_SEC"
TOR_CHAIN="ZIVPN_TORRENT"

DEVICE_CONF="/etc/zivpn/device_binding.conf"
DEVICE_DB="/etc/zivpn/device_bindings"

mkdir -p /etc/zivpn

ensure_chain() {
  $IPT -N "$1" 2>/dev/null || true
  $IPT -F "$1" 2>/dev/null || true
}

hook_chain() {
  local base="$1"; local chain="$2";
  $IPT -C "$base" -j "$chain" 2>/dev/null || $IPT -I "$base" 1 -j "$chain"
}

unhook_chain() {
  local base="$1"; local chain="$2";
  while $IPT -C "$base" -j "$chain" 2>/dev/null; do
    $IPT -D "$base" -j "$chain" || break
  done
}

firewall_apply() {
  ensure_chain "$SEC_CHAIN"

  # Defensive drops only (won't lock you out)
  $IPT -A "$SEC_CHAIN" -m conntrack --ctstate INVALID -j DROP
  $IPT -A "$SEC_CHAIN" -p tcp --tcp-flags ALL NONE -j DROP
  $IPT -A "$SEC_CHAIN" -p tcp --tcp-flags ALL ALL -j DROP
  $IPT -A "$SEC_CHAIN" -p icmp -m limit --limit 6/second --limit-burst 10 -j RETURN
  $IPT -A "$SEC_CHAIN" -p icmp -j DROP

  # Basic SYN flood limit (extra safety)
  $IPT -A "$SEC_CHAIN" -p tcp --syn -m limit --limit 25/second --limit-burst 50 -j RETURN
  $IPT -A "$SEC_CHAIN" -p tcp --syn -j DROP

  # Return so other rules continue
  $IPT -A "$SEC_CHAIN" -j RETURN

  hook_chain INPUT "$SEC_CHAIN"
  hook_chain FORWARD "$SEC_CHAIN"

  echo "OK: firewall hardening applied"
}

firewall_off() {
  unhook_chain INPUT "$SEC_CHAIN"
  unhook_chain FORWARD "$SEC_CHAIN"
  $IPT -F "$SEC_CHAIN" 2>/dev/null || true
  echo "OK: firewall hardening disabled"
}

firewall_status() {
  echo "== Firewall Harden =="
  if $IPT -L "$SEC_CHAIN" -n >/dev/null 2>&1; then
    echo "chain: $SEC_CHAIN (exists)"
  else
    echo "chain: $SEC_CHAIN (missing)"
  fi
  for c in INPUT FORWARD; do
    if $IPT -C "$c" -j "$SEC_CHAIN" >/dev/null 2>&1; then
      echo "hook: $c -> $SEC_CHAIN (ON)"
    else
      echo "hook: $c -> $SEC_CHAIN (OFF)"
    fi
  done
}

torrent_apply() {
  /usr/local/bin/zivpn-torrent-block 2>/dev/null || true
  echo "OK: torrent blocker applied"
}

torrent_status() {
  echo "== Torrent Blocker =="
  if $IPT -L "$TOR_CHAIN" -n >/dev/null 2>&1; then
    echo "chain: $TOR_CHAIN (exists)"
  else
    echo "chain: $TOR_CHAIN (missing)"
  fi
  for c in INPUT FORWARD OUTPUT; do
    if $IPT -C "$c" -j "$TOR_CHAIN" >/dev/null 2>&1; then
      echo "hook: $c -> $TOR_CHAIN (ON)"
    else
      echo "hook: $c -> $TOR_CHAIN (OFF)"
    fi
  done
}

device_enabled() {
  [ -f "$DEVICE_CONF" ] && grep -q '^enabled=1' "$DEVICE_CONF" 2>/dev/null
}

device_on() {
  echo 'enabled=1' > "$DEVICE_CONF"
  touch "$DEVICE_DB"
  echo "OK: device binding enabled"
}

device_off() {
  echo 'enabled=0' > "$DEVICE_CONF"
  echo "OK: device binding disabled"
}

device_status() {
  echo "== Device Binding =="
  if device_enabled; then
    echo "status: ON"
  else
    echo "status: OFF"
  fi
  echo "db: $DEVICE_DB"
}

device_reset() {
  local u="$1"
  if [ -z "$u" ]; then
    echo "usage: device-reset <username>"
    exit 1
  fi
  if [ -f "$DEVICE_DB" ]; then
    grep -v "^${u} " "$DEVICE_DB" > "${DEVICE_DB}.tmp" || true
    mv -f "${DEVICE_DB}.tmp" "$DEVICE_DB"
  fi
  echo "OK: binding reset for $u"
}

case "$ACTION" in
  firewall-apply) firewall_apply ;;
  firewall-off) firewall_off ;;
  firewall-status|status) firewall_status ;;
  torrent-apply) torrent_apply ;;
  torrent-status) torrent_status ;;
  device-on) device_on ;;
  device-off) device_off ;;
  device-status) device_status ;;
  device-reset) device_reset "${2:-}" ;;
  *)
    echo "Usage: $0 {status|firewall-apply|firewall-off|torrent-apply|torrent-status|device-on|device-off|device-status|device-reset <user>}"
    exit 1
  ;;
esac
