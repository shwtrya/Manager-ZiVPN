#!/bin/bash

# Colors
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
RED="\033[1;31m"
BLUE="\033[1;34m"
RESET="\033[0m"
BOLD="\033[1m"
GRAY="\033[1;30m"

# Repo raw URL (change this to your GitHub repo after upload)
REPO_RAW="${REPO_RAW:-https://raw.githubusercontent.com/shwtrya/Manager-ZiVPN/main}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

fetch_to() {
  local src="$1"; local dst="$2"
  if [ -f "$SCRIPT_DIR/$src" ]; then
    cp -f "$SCRIPT_DIR/$src" "$dst"
  else
    wget -q "${REPO_RAW}/${src}" -O "$dst"
  fi
}


print_task() {
  echo -ne "${GRAY}•${RESET} $1..."
}

print_done() {
  echo -e "\r${GREEN}✓${RESET} $1      "
}

print_fail() {
  echo -e "\r${RED}✗${RESET} $1      "
  exit 1
}

run_silent() {
  local msg="$1"
  local cmd="$2"
  
  print_task "$msg"
  bash -c "$cmd" &>/tmp/zivpn_install.log
  if [ $? -eq 0 ]; then
    print_done "$msg"
  else
    print_fail "$msg (Check /tmp/zivpn_install.log)"
  fi
}

clear
echo -e "${BOLD}ZiVPN UDP Installer${RESET}"
echo -e "${GRAY}AutoFTbot Edition${RESET}"
echo ""

if [[ "$(uname -s)" != "Linux" ]] || [[ "$(uname -m)" != "x86_64" ]]; then
  print_fail "System not supported (Linux AMD64 only)"
fi

if [ -f /usr/local/bin/zivpn ]; then
  echo -e "${YELLOW}! ZiVPN detected. Reinstalling...${RESET}"
  systemctl stop zivpn.service &>/dev/null
  systemctl stop zivpn-api.service &>/dev/null
  systemctl stop zivpn-bot.service &>/dev/null
fi

run_silent "Updating system" "sudo apt-get update"
run_silent "Setting Timezone" "sudo timedatectl set-timezone Asia/Jakarta"

if ! command -v go &> /dev/null; then
  run_silent "Installing dependencies" "sudo apt-get install -y golang git net-tools"
else
  print_done "Dependencies ready"
fi

echo ""
echo -ne "${BOLD}Domain Configuration${RESET}\n"
while true; do
  read -p "Enter Domain: " domain
  if [[ -n "$domain" ]]; then
    break
  fi
done
echo ""

echo -ne "${BOLD}API Key Configuration${RESET}\n"
generated_key=$(openssl rand -hex 16)
echo -e "Generated Key: ${CYAN}$generated_key${RESET}"
read -p "Enter API Key (Press Enter to use generated): " input_key
if [[ -z "$input_key" ]]; then
  api_key="$generated_key"
else
  api_key="$input_key"
fi
echo -e "Using Key: ${GREEN}$api_key${RESET}"
echo ""

systemctl stop zivpn.service &>/dev/null
run_silent "Downloading Core" "wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O /usr/local/bin/zivpn && chmod +x /usr/local/bin/zivpn"

mkdir -p /etc/zivpn
echo "$domain" > /etc/zivpn/domain
echo "$api_key" > /etc/zivpn/apikey
run_silent "Configuring" "wget -q https://raw.githubusercontent.com/shwtrya/Manager-ZiVPN/main/config.json -O /etc/zivpn/config.json"

run_silent "Generating SSL" "openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj '/C=ID/ST=Jawa Barat/L=Bandung/O=AutoFTbot/OU=IT Department/CN=$domain' -keyout /etc/zivpn/zivpn.key -out /etc/zivpn/zivpn.crt"

# Find a free API port
print_task "Finding available API Port"
API_PORT=8080
while netstat -tuln | grep -q ":$API_PORT "; do
    ((API_PORT++))
done
echo "$API_PORT" > /etc/zivpn/api_port
print_done "API Port selected: ${CYAN}$API_PORT${RESET}"

cat >> /etc/sysctl.conf <<END
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.rmem_default=16777216
net.core.wmem_default=16777216
net.core.optmem_max=65536
net.core.somaxconn=65535
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.tcp_fastopen=3
fs.file-max=1000000
net.core.netdev_max_backlog=16384
net.ipv4.udp_mem=65536 131072 262144
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
END
sysctl -p &>/dev/null

cat <<EOF > /etc/systemd/system/zivpn.service
[Unit]
Description=ZIVPN UDP VPN Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
RestartSec=3
LimitNOFILE=65535
Environment=ZIVPN_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

mkdir -p /etc/zivpn/api
run_silent "Setting up API" "wget -q https://raw.githubusercontent.com/shwtrya/Manager-ZiVPN/main/zivpn-api.go -O /etc/zivpn/api/zivpn-api.go && wget -q https://raw.githubusercontent.com/shwtrya/Manager-ZiVPN/main/go.mod -O /etc/zivpn/api/go.mod"

cd /etc/zivpn/api
if go build -o zivpn-api zivpn-api.go &>/dev/null; then
  print_done "Compiling API"
else
  print_fail "Compiling API"
fi

cat <<EOF > /etc/systemd/system/zivpn-api.service
[Unit]
Description=ZiVPN Golang API Service
After=network.target zivpn.service

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn/api
ExecStart=/etc/zivpn/api/zivpn-api
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

echo ""
echo -ne "${BOLD}Telegram Bot Configuration${RESET}\n"
echo -ne "${GRAY}(Leave empty to skip)${RESET}\n"
read -p "Bot Token: " bot_token
read -p "Owner ID : " owner_id

if [[ -n "$bot_token" ]] && [[ -n "$owner_id" ]]; then
  echo ""
  echo "Select Bot Type:"
  echo "1) Free (Admin Only / Public Mode)"
  echo "2) Paid (Pakasir Payment Gateway)"
  read -p "Choice [1]: " bot_type
  bot_type=${bot_type:-1}

  if [[ "$bot_type" == "2" ]]; then
    read -p "Pakasir Project Slug: " pakasir_slug
    read -p "Pakasir API Key     : " pakasir_key
    read -p "Daily Price (IDR)   : " daily_price
    
    # v1.3+: installer hanya minta owner_id (admin & viewer diatur setelah install via Telegram)
    echo "{\"bot_token\": \"$bot_token\", \"owner_id\": $owner_id, \"admin_ids\": [], \"viewer_ids\": [], \"mode\": \"public\", \"domain\": \"$domain\", \"pakasir_slug\": \"$pakasir_slug\", \"pakasir_api_key\": \"$pakasir_key\", \"daily_price\": $daily_price}" > /etc/zivpn/bot-config.json
    bot_file="zivpn-paid-bot.go"
  else
    read -p "Bot Mode (public/private) [default: private]: " bot_mode
    bot_mode=${bot_mode:-private}
    
    # v1.3+: installer hanya minta owner_id (admin & viewer diatur setelah install via Telegram)
    echo "{\"bot_token\": \"$bot_token\", \"owner_id\": $owner_id, \"admin_ids\": [], \"viewer_ids\": [], \"mode\": \"$bot_mode\", \"domain\": \"$domain\"}" > /etc/zivpn/bot-config.json
    bot_file="zivpn-bot.go"
  fi
  
  run_silent "Downloading Bot" "fetch_to $bot_file /etc/zivpn/api/$bot_file"

  run_silent "Downloading Security Scripts" "fetch_to zivpn-udplimit.sh /etc/zivpn/api/zivpn-udplimit.sh && fetch_to zivpn-iplimit.sh /etc/zivpn/api/zivpn-iplimit.sh && fetch_to zivpn-torrent-block.sh /etc/zivpn/api/zivpn-torrent-block.sh && fetch_to zivpn-security.sh /etc/zivpn/api/zivpn-security.sh && fetch_to zivpn-alert-check.sh /etc/zivpn/api/zivpn-alert-check.sh && fetch_to zivpn-stats-daily.sh /etc/zivpn/api/zivpn-stats-daily.sh && fetch_to zivpn-auto-expire.sh /etc/zivpn/api/zivpn-auto-expire.sh && fetch_to zivpn-auto-cleanup.sh /etc/zivpn/api/zivpn-auto-cleanup.sh && fetch_to zivpn-backup-local.sh /etc/zivpn/api/zivpn-backup-local.sh"
  
  cd /etc/zivpn/api
  run_silent "Downloading Bot Deps" "go get github.com/go-telegram-bot-api/telegram-bot-api/v5"
  
  if go build -o zivpn-bot "$bot_file" &>/dev/null; then
    print_done "Compiling Bot"
    
    cat <<EOF > /etc/systemd/system/zivpn-bot.service
[Unit]
Description=ZiVPN Telegram Bot
After=network.target zivpn-api.service

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn/api
ExecStart=/etc/zivpn/api/zivpn-bot
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl enable zivpn-bot.service &>/dev/null
    systemctl start zivpn-bot.service &>/dev/null
  else
    print_fail "Compiling Bot"
  fi
else
  print_task "Skipping Bot Setup"
  echo ""
fi

run_silent "Starting Services" "systemctl enable zivpn.service && systemctl start zivpn.service && systemctl enable zivpn-api.service && systemctl start zivpn-api.service"

# Setup Cron for Auto-Expire
echo -e "${YELLOW}Setting up Cron Job for Auto-Expire...${NC}"
cron_cmd="0 0 * * * /usr/bin/curl -s -X POST -H \"X-API-Key: \$(cat /etc/zivpn/apikey)\" http://127.0.0.1:\$(cat /etc/zivpn/api_port)/api/cron/expire >> /var/log/zivpn-cron.log 2>&1"
(crontab -l 2>/dev/null | grep -v "/api/cron/expire"; echo "$cron_cmd") | crontab -
print_done "Cron Job Configured"

# --- Extra Security Features ---
print_task "Installing Torrent Blocker"
install -m 0755 /etc/zivpn/api/zivpn-torrent-block.sh /usr/local/bin/zivpn-torrent-block.sh &>/dev/null || true
cat <<'EOF' > /etc/systemd/system/zivpn-torrent-block.service
[Unit]
Description=ZiVPN Torrent Blocker (iptables)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/zivpn-torrent-block.sh
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload &>/dev/null
systemctl enable --now zivpn-torrent-block.service &>/dev/null || true
/usr/local/bin/zivpn-torrent-block.sh &>/dev/null || true
print_done "Torrent Blocker Installed"

print_task "Installing IP Limit Enforcer"
install -m 0755 /etc/zivpn/api/zivpn-iplimit.sh /usr/local/bin/zivpn-iplimit.sh &>/dev/null || true
echo "1" > /etc/zivpn/iplimit.conf 2>/dev/null || true
cat <<'EOF' > /etc/cron.d/zivpn-iplimit
* * * * * root /usr/local/bin/zivpn-iplimit.sh >/dev/null 2>&1
EOF
chmod 0644 /etc/cron.d/zivpn-iplimit &>/dev/null || true
/usr/local/bin/zivpn-iplimit.sh &>/dev/null || true
print_done "IP Limit Enforcer Installed"

print_task "Installing Live Alerts + Scheduler scripts"
install -m 0755 /etc/zivpn/api/zivpn-alert-check.sh /usr/local/bin/zivpn-alert-check.sh &>/dev/null || true
install -m 0755 /etc/zivpn/api/zivpn-auto-expire.sh /usr/local/bin/zivpn-auto-expire.sh &>/dev/null || true
install -m 0755 /etc/zivpn/api/zivpn-auto-cleanup.sh /usr/local/bin/zivpn-auto-cleanup.sh &>/dev/null || true
install -m 0755 /etc/zivpn/api/zivpn-backup-local.sh /usr/local/bin/zivpn-backup-local.sh &>/dev/null || true
# default scheduler
cat > /etc/zivpn/scheduler.json <<EOF
{
  "alerts_enabled": true,
  "expire_enabled": true,
  "expire_time": "00:00",
  "cleanup_enabled": true,
  "cleanup_time": "00:30",
  "backup_enabled": false,
  "backup_time": "01:00"
}
EOF
chmod 0644 /etc/zivpn/scheduler.json &>/dev/null || true
cat <<'EOF' > /etc/cron.d/zivpn-scheduler
# ZiVPN v1.4 Scheduler (auto-generated)
0 0 * * * root /usr/local/bin/zivpn-auto-expire.sh >/dev/null 2>&1
30 0 * * * root /usr/local/bin/zivpn-auto-cleanup.sh >/dev/null 2>&1
EOF
chmod 0644 /etc/cron.d/zivpn-scheduler &>/dev/null || true
cat <<'EOF' > /etc/cron.d/zivpn-alerts
# ZiVPN v1.4 Live Alerts
* * * * * root /usr/local/bin/zivpn-alert-check.sh >/dev/null 2>&1
EOF
chmod 0644 /etc/cron.d/zivpn-alerts &>/dev/null || true
print_done "Live Alerts + Scheduler Installed"
cat > /etc/zivpn/scheduler.json <<EOF
{
  "alerts_enabled": true,
  "expire_enabled": true,
  "expire_time": "00:00",
  "cleanup_enabled": true,
  "cleanup_time": "00:30",
  "backup_enabled": false,
  "backup_time": "01:00"
}
EOF
# cron: alerts every minute (scheduler cron managed by bot too)
cat > /etc/cron.d/zivpn-alerts <<EOF
# ZiVPN v1.4 Live Alerts
* * * * * root /usr/local/bin/zivpn-alert-check.sh >/dev/null 2>&1
EOF
chmod 0644 /etc/cron.d/zivpn-alerts &>/dev/null || true

# --- v1.5 Security + Daily Stats ---
print_task "Installing Security Hardening + Daily Stats"
install -m 0755 /etc/zivpn/api/zivpn-security.sh /usr/local/bin/zivpn-security.sh &>/dev/null || true
install -m 0755 /etc/zivpn/api/zivpn-stats-daily.sh /usr/local/bin/zivpn-stats-daily.sh &>/dev/null || true

# Default: device binding OFF
echo 'enabled=0' > /etc/zivpn/device_binding.conf 2>/dev/null || true
touch /etc/zivpn/device_bindings 2>/dev/null || true
chmod 0644 /etc/zivpn/device_binding.conf /etc/zivpn/device_bindings &>/dev/null || true

# Default: apply safe firewall hardening once (does NOT set default DROP)
/usr/local/bin/zivpn-security.sh firewall-apply &>/dev/null || true

# Daily stats report (notify Owner+Admin)
cat <<'EOF' > /etc/cron.d/zivpn-daily-stats
# ZiVPN v1.5 Daily Stats
55 23 * * * root /usr/local/bin/zivpn-stats-daily.sh today --notify >/dev/null 2>&1
EOF
chmod 0644 /etc/cron.d/zivpn-daily-stats &>/dev/null || true
print_done "Security Hardening + Daily Stats Installed"
print_done "Live Alerts + Scheduler scripts installed"


print_task "Installing UDP Per-User IP Limit"
install -m 0755 /etc/zivpn/api/zivpn-udplimit.sh /usr/local/bin/zivpn-udplimit.sh &>/dev/null || true
cat <<'EOF' > /etc/systemd/system/zivpn-udplimit.service
[Unit]
Description=ZiVPN UDP Per-User IP Limit (iptables+ipset)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/zivpn-udplimit.sh
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload &>/dev/null
systemctl enable --now zivpn-udplimit.service &>/dev/null || true
/usr/local/bin/zivpn-udplimit.sh &>/dev/null || true
print_done "UDP Per-User IP Limit Installed"


iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
iptables -t nat -A PREROUTING -i "$iface" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 &>/dev/null
ufw allow 6000:19999/udp &>/dev/null
ufw allow 5667/udp &>/dev/null
ufw allow $API_PORT/tcp &>/dev/null

rm -f "$0" install.tmp install.log &>/dev/null

echo ""
echo -e "${BOLD}Installation Complete${RESET}"
echo -e "Domain  : ${CYAN}$domain${RESET}"
echo -e "API     : ${CYAN}$API_PORT${RESET}"
echo -e "Token   : ${CYAN}$api_key${RESET}"
echo -e "Dev     : ${CYAN}https://t.me/shwtrya${RESET}"
echo ""
