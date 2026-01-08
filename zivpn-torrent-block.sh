#!/bin/bash
set -e

# ZiVPN Torrent Blocker (best effort)
# Blocks common BitTorrent ports + BitTorrent protocol strings.

IPT="$(command -v iptables)"
if [ -z "$IPT" ]; then
  exit 0
fi

# Create custom chain
$IPT -N ZIVPN_TORRENT 2>/dev/null || true
$IPT -F ZIVPN_TORRENT

# Common torrent ports
$IPT -A ZIVPN_TORRENT -p tcp --dport 6881:6999 -j DROP
$IPT -A ZIVPN_TORRENT -p udp --dport 6881:6999 -j DROP
$IPT -A ZIVPN_TORRENT -p tcp --dport 51413 -j DROP
$IPT -A ZIVPN_TORRENT -p udp --dport 51413 -j DROP

# Extra common ports (best-effort)
$IPT -A ZIVPN_TORRENT -p tcp --dport 6969 -j DROP
$IPT -A ZIVPN_TORRENT -p udp --dport 6969 -j DROP
$IPT -A ZIVPN_TORRENT -p tcp --dport 1337 -j DROP
$IPT -A ZIVPN_TORRENT -p udp --dport 1337 -j DROP

# String match (requires xt_string)
$IPT -A ZIVPN_TORRENT -m string --algo bm --string "BitTorrent" -j DROP 2>/dev/null || true
$IPT -A ZIVPN_TORRENT -m string --algo bm --string "peer_id=" -j DROP 2>/dev/null || true
$IPT -A ZIVPN_TORRENT -m string --algo bm --string ".torrent" -j DROP 2>/dev/null || true
$IPT -A ZIVPN_TORRENT -m string --algo bm --string "info_hash" -j DROP 2>/dev/null || true
$IPT -A ZIVPN_TORRENT -m string --algo bm --string "announce" -j DROP 2>/dev/null || true

# Attach chain (idempotent)
for CHAIN in INPUT FORWARD OUTPUT; do
  $IPT -C $CHAIN -j ZIVPN_TORRENT 2>/dev/null || $IPT -I $CHAIN 1 -j ZIVPN_TORRENT
done

exit 0
