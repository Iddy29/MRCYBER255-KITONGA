#!/usr/bin/env bash

# =============================================================================
# 🔧 MANUAL CONFIGURATION SECTION
# =============================================================================
# You can manually customize these settings below to fit your environment.
# Edit the values as needed before running the script.
# =============================================================================

# Repository Configuration (for updates and downloads)
REPO_NAME="MRCYBER255-KITONGA"
REPO_OWNER="Iddy29"
REPO_BRANCH="refs/heads/main"
# Extract branch name from refs/heads/main format for raw.githubusercontent.com URLs
REPO_BRANCH_NAME=$(echo "$REPO_BRANCH" | sed 's|refs/heads/||')
REPO_BASE_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_BRANCH_NAME}"

# Base Directory Configuration (derived from repository name)
# This is the main directory where all configuration files are stored
APP_BASE_DIR_NAME=$(echo "$REPO_NAME" | tr '[:upper:]' '[:lower:]')  # Converts REPO_NAME to lowercase
APP_BASE_DIR="/etc/${APP_BASE_DIR_NAME}"

# DNS Configuration (used for DNSTT and system DNS)
# You can change these to your preferred DNS servers
DNS_PRIMARY="8.8.8.8"      # Google DNS
DNS_SECONDARY="1.1.1.1"    # Cloudflare DNS

# Default Ports (you can customize these if needed)
DEFAULT_SSL_TUNNEL_PORT="444"       # SSL Tunnel default port
DEFAULT_WEB_PROXY_PORT="8080"    # WebSocket Proxy default port
DEFAULT_BADVPN_PORT="7300"          # BadVPN UDP port
DEFAULT_ZIVPN_PORT="5667"           # ZiVPN UDP port
DEFAULT_DNSTT_PUBLIC_PORT="53"      # DNSTT public port (EDNS proxy)
DEFAULT_DNSTT_INTERNAL_PORT="5300"  # DNSTT internal port (server)

# Default DNSTT MTU (Maximum Transmission Unit)
# Options: 512, 1200, 1800 (recommended for high speed)
DEFAULT_DNSTT_MTU="1800"

# Default V2Ray/XRay Port (for DNSTT forwarding option)
DEFAULT_V2RAY_PORT="8787"

# Default Backup Location
DEFAULT_BACKUP_PATH="/root/${APP_BASE_DIR_NAME}_users.tar.gz"

# Timeout Settings (in seconds)
CERTBOT_TIMEOUT="120"      # Certbot SSL certificate request timeout
DOWNLOAD_TIMEOUT="60"      # File download timeout

# Connection Limiter Settings
LIMITER_CHECK_INTERVAL="3"          # Check interval in seconds
LIMITER_LOCK_DURATION="120"         # Lock duration in seconds when limit exceeded

# =============================================================================
# END OF MANUAL CONFIGURATION SECTION
# =============================================================================

# Color Definitions - Enhanced Modern Palette
C_RESET='\033[0m'
C_BOLD='\033[1m'
C_DIM='\033[2m'
C_ITALIC='\033[3m'
C_UNDERLINE='\033[4m'
C_BLINK='\033[5m'
C_REVERSE='\033[7m'
C_HIDDEN='\033[8m'

# Standard Colors
C_BLACK='\033[30m'
C_RED='\033[31m'
C_GREEN='\033[32m'
C_YELLOW='\033[33m'
C_BLUE='\033[34m'
C_MAGENTA='\033[35m'
C_CYAN='\033[36m'
C_WHITE='\033[37m'

# Bright Colors (for better visibility)
C_BRIGHT_BLACK='\033[90m'
C_BRIGHT_RED='\033[91m'
C_BRIGHT_GREEN='\033[92m'
C_BRIGHT_YELLOW='\033[93m'
C_BRIGHT_BLUE='\033[94m'
C_BRIGHT_MAGENTA='\033[95m'
C_BRIGHT_CYAN='\033[96m'
C_BRIGHT_WHITE='\033[97m'

# Background Colors
C_BG_BLACK='\033[40m'
C_BG_RED='\033[41m'
C_BG_GREEN='\033[42m'
C_BG_YELLOW='\033[43m'
C_BG_BLUE='\033[44m'
C_BG_MAGENTA='\033[45m'
C_BG_CYAN='\033[46m'
C_BG_WHITE='\033[47m'

# Semantic Colors for UI Components
C_TITLE=$C_BRIGHT_CYAN          # Title - Bright Cyan
C_CHOICE=$C_BRIGHT_GREEN         # Menu choices - Bright Green
C_PROMPT=$C_BRIGHT_BLUE          # Input prompts - Bright Blue
C_WARN=$C_BRIGHT_YELLOW          # Warnings - Bright Yellow
C_DANGER=$C_BRIGHT_RED           # Danger/Errors - Bright Red
C_STATUS_A=$C_BRIGHT_GREEN       # Active status - Bright Green
C_STATUS_I=$C_DIM                # Inactive status - Dim
C_ACCENT=$C_BRIGHT_MAGENTA       # Accent color - Bright Magenta
C_INFO=$C_BRIGHT_CYAN            # Info messages - Bright Cyan
C_SUCCESS=$C_BRIGHT_GREEN        # Success messages - Bright Green
C_ERROR=$C_BRIGHT_RED            # Error messages - Bright Red

DB_DIR="$APP_BASE_DIR"
DB_FILE="$DB_DIR/users.db"
INSTALL_FLAG_FILE="$DB_DIR/.install"
BADVPN_SERVICE_FILE="/etc/systemd/system/badvpn.service"
BADVPN_BUILD_DIR="/root/badvpn-build"
HAPROXY_CONFIG="/etc/haproxy/haproxy.cfg"
NGINX_CONFIG_FILE="/etc/nginx/sites-available/default"
SSL_CERT_DIR="$APP_BASE_DIR/ssl"
SSL_CERT_FILE="$SSL_CERT_DIR/${APP_BASE_DIR_NAME}.pem"
DNSTT_SERVICE_FILE="/etc/systemd/system/dnstt.service"
DNSTT_BINARY="/usr/local/bin/dnstt-server"
DNSTT_KEYS_DIR="$APP_BASE_DIR/dnstt"
DNSTT_CONFIG_FILE="$DB_DIR/dnstt_info.conf"
DNSTT_EDNS_PROXY="/usr/local/bin/dnstt-edns-proxy.py"
DNSTT_EDNS_SERVICE="/etc/systemd/system/dnstt-edns-proxy.service"
UDP_CUSTOM_DIR="/root/udp"
UDP_CUSTOM_SERVICE_FILE="/etc/systemd/system/udp-custom.service"
SSH_BANNER_FILE="$APP_BASE_DIR/bannerssh"
WEBPROXY_SERVICE_FILE="/etc/systemd/system/webproxy.service"
WEBPROXY_BINARY="/usr/local/bin/webproxy"
WEBPROXY_CONFIG_FILE="$DB_DIR/webproxy_config.conf"
LIMITER_SCRIPT="/usr/local/bin/${APP_BASE_DIR_NAME}-limiter.sh"
LIMITER_SERVICE="/etc/systemd/system/${APP_BASE_DIR_NAME}-limiter.service"

# --- ZiVPN Variables ---
ZIVPN_DIR="/etc/zivpn"
ZIVPN_BIN="/usr/local/bin/zivpn"
ZIVPN_SERVICE_FILE="/etc/systemd/system/zivpn.service"
ZIVPN_CONFIG_FILE="$ZIVPN_DIR/config.json"
ZIVPN_CERT_FILE="$ZIVPN_DIR/zivpn.crt"
ZIVPN_KEY_FILE="$ZIVPN_DIR/zivpn.key"

# --- iptables Variables ---
IPTABLES_CONFIG_FILE="/etc/iptables/rules.v4"
IPTABLES_SCRIPT_FILE="$APP_BASE_DIR/iptables-rules.sh"

SELECTED_USER=""
UNINSTALL_MODE="interactive"

if [[ $EUID -ne 0 ]]; then
   echo -e "${C_RED}❌ Error: This script requires root privileges to run.${C_RESET}"
   exit 1
fi

# Mandatory Dependency Check (Added jq and curl)
for cmd in bc jq curl wget; do
    if ! command -v "$cmd" &> /dev/null; then
        echo -e "${C_YELLOW}⚠️ Warning: '$cmd' not found. Attempting to install it...${C_RESET}"
        if ! apt-get update > /dev/null 2>&1; then
            echo -e "${C_RED}❌ Error: Failed to update package list.${C_RESET}"
            exit 1
        fi
        if ! apt-get install -y "$cmd" > /dev/null 2>&1; then
            echo -e "${C_RED}❌ Error: Failed to install '$cmd'. Please install it manually ('apt-get install $cmd') and re-run the script.${C_RESET}"
            exit 1
        fi
        echo -e "${C_GREEN}✅ Successfully installed $cmd.${C_RESET}"
    fi
done

_is_valid_ipv4() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            if ((i > 255)); then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

# Function to detect VPS server IP address
_detect_server_ip() {
    local server_ip=""
    
    # Try multiple methods to detect server IP
    if command -v hostname &> /dev/null; then
        server_ip=$(hostname -I 2>/dev/null | awk '{print $1}' | head -n1)
    fi
    
    if [[ -z "$server_ip" ]] && command -v ip &> /dev/null; then
        server_ip=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' | head -n1)
    fi
    
    if [[ -z "$server_ip" ]] && command -v ifconfig &> /dev/null; then
        server_ip=$(ifconfig 2>/dev/null | grep -oP 'inet \K[0-9.]+' | grep -v '127.0.0.1' | head -n1)
    fi
    
    if [[ -z "$server_ip" ]]; then
        server_ip=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null || echo "")
    fi
    
    echo "$server_ip"
}

# Function to detect VPS hostname
_detect_server_hostname() {
    local hostname=""
    
    # Try hostname command
    if command -v hostname &> /dev/null; then
        hostname=$(hostname -f 2>/dev/null || hostname 2>/dev/null)
    fi
    
    # Fallback to /etc/hostname
    if [[ -z "$hostname" ]] && [[ -f /etc/hostname ]]; then
        hostname=$(cat /etc/hostname 2>/dev/null | tr -d '\n\r' | head -n1)
    fi
    
    echo "$hostname"
}

# Function to validate nameserver domain format (must be hostname, not IP)
_validate_nameserver_domain() {
    local ns_domain=$1
    
    if [[ -z "$ns_domain" ]]; then
        echo "ERROR: Nameserver domain cannot be empty"
        return 1
    fi
    
    # Check if it's an IP address (wrong format)
    if _is_valid_ipv4 "$ns_domain"; then
        echo "ERROR: NS records MUST point to hostnames, not IP addresses!"
        echo "You provided: $ns_domain (this is an IP address)"
        echo "Solution: NS records must point to a hostname (e.g., ns1.yourdomain.com)"
        echo "The hostname will have an A record pointing to your VPS IP address"
        return 1
    fi
    
    # Check if it looks like a valid hostname
    if [[ ! "$ns_domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]]; then
        echo "WARNING: '$ns_domain' doesn't look like a valid hostname format"
        echo "Expected format: ns1.yourdomain.com"
        read -p "Continue anyway? (y/n): " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            return 1
        fi
    fi
    
    return 0
}

check_and_open_firewall_port() {
    local port="$1"
    local protocol="${2:-tcp}"
    local firewall_detected=false

    if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
        firewall_detected=true
        if ! ufw status | grep -qw "$port/$protocol"; then
            echo -e "${C_YELLOW}🔥 UFW firewall is active and port ${port}/${protocol} is closed.${C_RESET}"
            read -p "👉 Do you want to open this port now? (y/n): " confirm
            if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                ufw allow "$port/$protocol"
                echo -e "${C_GREEN}✅ Port ${port}/${protocol} has been opened in UFW.${C_RESET}"
            else
                echo -e "${C_RED}❌ Warning: Port ${port}/${protocol} was not opened. The service may not work correctly.${C_RESET}"
                return 1
            fi
        else
             echo -e "${C_GREEN}✅ Port ${port}/${protocol} is already open in UFW.${C_RESET}"
        fi
    fi

    if command -v firewall-cmd &> /dev/null && systemctl is-active --quiet firewalld; then
        firewall_detected=true
        if ! firewall-cmd --list-ports --permanent | grep -qw "$port/$protocol"; then
            echo -e "${C_YELLOW}🔥 firewalld is active and port ${port}/${protocol} is not open.${C_RESET}"
            read -p "👉 Do you want to open this port now? (y/n): " confirm
            if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                firewall-cmd --add-port="$port/$protocol" --permanent
                firewall-cmd --reload
                echo -e "${C_GREEN}✅ Port ${port}/${protocol} has been opened in firewalld.${C_RESET}"
            else
                echo -e "${C_RED}❌ Warning: Port ${port}/${protocol} was not opened. The service may not work correctly.${C_RESET}"
                return 1
            fi
        else
            echo -e "${C_GREEN}✅ Port ${port}/${protocol} is already open in firewalld.${C_RESET}"
        fi
    fi

    if ! $firewall_detected; then
        echo -e "${C_BLUE}ℹ️ No active firewall (UFW or firewalld) detected. Assuming ports are open.${C_RESET}"
    fi
    return 0
}

check_and_free_ports() {
    local ports_to_check=("$@")
    for port in "${ports_to_check[@]}"; do
        echo -e "\n${C_BLUE}🔎 Checking if port $port is available...${C_RESET}"
        local conflicting_process_info
        conflicting_process_info=$(ss -lntp | grep ":$port\s" || ss -lunp | grep ":$port\s")
        
        if [[ -n "$conflicting_process_info" ]]; then
            local conflicting_pid
            conflicting_pid=$(echo "$conflicting_process_info" | grep -oP 'pid=\K[0-9]+' | head -n 1)
            local conflicting_name
            conflicting_name=$(echo "$conflicting_process_info" | grep -oP 'users:\(\("(\K[^"]+)' | head -n 1)
            
            if [[ -z "$conflicting_pid" ]]; then
                echo -e "${C_YELLOW}⚠️ Warning: Port $port is in use but could not determine PID.${C_RESET}"
                read -p "👉 Do you want to continue anyway? (y/n): " continue_confirm
                if [[ "$continue_confirm" != "y" && "$continue_confirm" != "Y" ]]; then
                    echo -e "${C_RED}❌ Cannot proceed without freeing port $port. Aborting.${C_RESET}"
                    return 1
                fi
                continue
            fi
            
            # Try to get process name using ps if not found in ss output
            if [[ -z "$conflicting_name" || "$conflicting_name" == "unknown" ]]; then
                if [[ -n "$conflicting_pid" ]]; then
                    conflicting_name=$(ps -p "$conflicting_pid" -o comm= 2>/dev/null | head -n 1)
                fi
            fi
            
            # Check if it's a DNSTT-related process (sldns-server, dnstt-server, python3 for EDNS proxy)
            local is_dnstt_process=false
            if [[ "$conflicting_name" == *"sldns-server"* ]] || [[ "$conflicting_name" == *"dnstt-server"* ]] || \
               [[ "$conflicting_name" == *"dnstt"* ]] || ([[ "$conflicting_name" == *"python3"* ]] && [[ "$port" == "53" ]]); then
                is_dnstt_process=true
            fi
            
            # For DNSTT processes, automatically handle them
            if [[ "$is_dnstt_process" == "true" ]]; then
                echo -e "${C_YELLOW}⚠️ Port $port is in use by DNSTT process '${conflicting_name:-unknown}' (PID: ${conflicting_pid}).${C_RESET}"
                echo -e "${C_BLUE}ℹ️ Detected DNSTT process. Stopping DNSTT services automatically...${C_RESET}"
                
                # Stop DNSTT services properly
                if systemctl stop dnstt.service 2>/dev/null; then
                    echo -e "${C_GREEN}✅ Stopped dnstt.service${C_RESET}"
                fi
                if [ -f "$DNSTT_EDNS_SERVICE" ]; then
                    if systemctl stop dnstt-edns-proxy.service 2>/dev/null; then
                        echo -e "${C_GREEN}✅ Stopped dnstt-edns-proxy.service${C_RESET}"
                    fi
                fi
                
                sleep 2
                
                # If process still running, kill it directly
                if [[ -n "$conflicting_pid" ]] && kill -0 "$conflicting_pid" 2>/dev/null; then
                    echo -e "${C_YELLOW}⚠️ Process still running, terminating PID $conflicting_pid...${C_RESET}"
                    kill -9 "$conflicting_pid" 2>/dev/null
                    sleep 1
                fi
                
                # Verify port is free
                if ss -lntp 2>/dev/null | grep -q ":$port\s" || ss -lunp 2>/dev/null | grep -q ":$port\s"; then
                    echo -e "${C_YELLOW}⚠️ Port $port still in use. Attempting additional cleanup...${C_RESET}"
                    # Try to find and kill any remaining processes on this port
                    local remaining_pids
                    remaining_pids=$(ss -lunp 2>/dev/null | grep ":$port\s" | grep -oP 'pid=\K[0-9]+' 2>/dev/null)
                    for pid in $remaining_pids; do
                        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                            kill -9 "$pid" 2>/dev/null
                        fi
                    done
                    sleep 2
                    
                    if ss -lntp 2>/dev/null | grep -q ":$port\s" || ss -lunp 2>/dev/null | grep -q ":$port\s"; then
                        echo -e "${C_RED}❌ Failed to free port $port. Please stop the process manually and try again.${C_RESET}"
                        echo -e "${C_YELLOW}💡 Try: systemctl stop dnstt.service dnstt-edns-proxy.service${C_RESET}"
                        return 1
                    fi
                fi
                
                echo -e "${C_GREEN}✅ Port $port has been successfully freed.${C_RESET}"
                continue
            fi
            
            echo -e "${C_YELLOW}⚠️ Warning: Port $port is in use by process '${conflicting_name:-unknown}' (PID: ${conflicting_pid}).${C_RESET}"
            read -p "👉 Do you want to attempt to stop this process? (y/n): " kill_confirm
            if [[ "$kill_confirm" == "y" || "$kill_confirm" == "Y" ]]; then
                echo -e "${C_GREEN}🛑 Stopping process PID $conflicting_pid...${C_RESET}"
                local process_name
                process_name=$(ps -p "$conflicting_pid" -o comm= 2>/dev/null)
                
                # Try systemctl first if it's a service
                local service_stopped=false
                if [[ -n "$process_name" ]]; then
                    # Check if it's a systemd service
                    if systemctl list-units --type=service --state=running 2>/dev/null | grep -q "$process_name"; then
                        if systemctl stop "$process_name" 2>/dev/null; then
                            service_stopped=true
                            echo -e "${C_GREEN}✅ Stopped service: $process_name${C_RESET}"
                        fi
                    fi
                fi
                
                # If systemctl didn't work, try kill
                if [[ "$service_stopped" == "false" ]]; then
                    if [[ -n "$process_name" ]]; then
                        kill -9 "$conflicting_pid" 2>/dev/null
                    else
                        kill -9 "$conflicting_pid" 2>/dev/null
                    fi
                fi
                
                sleep 2
                
                if ss -lntp 2>/dev/null | grep -q ":$port\s" || ss -lunp 2>/dev/null | grep -q ":$port\s"; then
                     echo -e "${C_RED}❌ Failed to free port $port. Please handle it manually. Aborting.${C_RESET}"
                     return 1
                else
                     echo -e "${C_GREEN}✅ Port $port has been successfully freed.${C_RESET}"
                fi
            else
                echo -e "${C_RED}❌ Cannot proceed without freeing port $port. Aborting.${C_RESET}"
                return 1
            fi
        else
            echo -e "${C_GREEN}✅ Port $port is free to use.${C_RESET}"
        fi
    done
    return 0
}

setup_limiter_service() {
    # Updated logic: No logging, smart configurable lockout
    cat > "$LIMITER_SCRIPT" << EOF
#!/bin/bash
DB_FILE="$DB_DIR/users.db"
LIMITER_CHECK_INTERVAL="$LIMITER_CHECK_INTERVAL"
LIMITER_LOCK_DURATION="$LIMITER_LOCK_DURATION"

# Loop continuously
while true; do
    if [[ ! -f "$DB_FILE" ]]; then
        sleep 10
        continue
    fi
    current_ts=$(date +%s)
    while IFS=: read -r user pass expiry limit; do
        [[ -z "$user" || "$user" == \#* ]] && continue
        
        # --- Expiry Check ---
        expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
        if [[ $expiry_ts -lt $current_ts && $expiry_ts -ne 0 ]]; then
            # If expired and not already locked, lock it
            if ! passwd -S "$user" | grep -q " L "; then
                usermod -L "$user" &>/dev/null
            fi
            # Kill any active processes for expired user
            if pgrep -u "$user" > /dev/null; then
                killall -u "$user" -9 &>/dev/null
            fi
            continue
        fi
        
        # --- Connection Limit Check ---
        online_count=$(pgrep -u "$user" sshd | wc -l)
        if ! [[ "$limit" =~ ^[0-9]+$ ]]; then limit=1; fi
        
        if [[ "$online_count" -gt "$limit" ]]; then
            # Check if user is ALREADY locked (e.g., by Admin or previous trigger)
            # If they are not locked (" P " usually), we apply the temp lock.
            if ! passwd -S "$user" | grep -q " L "; then
                # 1. Lock the user immediately
                usermod -L "$user" &>/dev/null
                
                # 2. Kill their connections
                killall -u "$user" -9 &>/dev/null
                
                # 3. Spawn a background process to unlock them after lock duration
                # This ensures the main loop keeps running for other users
                (sleep $LIMITER_LOCK_DURATION; usermod -U "$user" &>/dev/null) & 
            else
                # User is ALREADY locked.
                # Just kill the connections to enforce the lock.
                # Do NOT schedule an unlock, as this might be a permanent admin ban.
                killall -u "$user" -9 &>/dev/null
            fi
        fi
    done < "$DB_FILE"
    sleep $LIMITER_CHECK_INTERVAL
done
EOF
    chmod +x "$LIMITER_SCRIPT"

    cat > "$LIMITER_SERVICE" << EOF
[Unit]
Description=${APP_BASE_DIR_NAME^} Active User Limiter
After=network.target

[Service]
Type=simple
ExecStart=$LIMITER_SCRIPT
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    if ! systemctl is-active --quiet ${APP_BASE_DIR_NAME}-limiter 2>/dev/null; then
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable ${APP_BASE_DIR_NAME}-limiter &>/dev/null || true
        systemctl start ${APP_BASE_DIR_NAME}-limiter &>/dev/null || true
    else
        # Restart if already running to apply new logic
        systemctl restart ${APP_BASE_DIR_NAME}-limiter &>/dev/null || true
    fi
}

initial_setup() {
    if ! mkdir -p "$DB_DIR" 2>/dev/null; then
        echo -e "${C_RED}❌ Error: Failed to create database directory.${C_RESET}" >&2
        exit 1
    fi
    touch "$DB_FILE" 2>/dev/null || {
        echo -e "${C_RED}❌ Error: Failed to create database file.${C_RESET}" >&2
        exit 1
    }
    mkdir -p "$SSL_CERT_DIR" 2>/dev/null
    mkdir -p "$(dirname "$SSH_BANNER_FILE")" 2>/dev/null
    setup_limiter_service
    if [ ! -f "$INSTALL_FLAG_FILE" ]; then
        touch "$INSTALL_FLAG_FILE" 2>/dev/null
    fi
}


_select_user_interface() {
    local title="$1"
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}${title}${C_RESET}\n"
    if [[ ! -s $DB_FILE ]]; then
        echo -e "${C_YELLOW}ℹ️ No users found in the database.${C_RESET}"
        SELECTED_USER="NO_USERS"; return
    fi
    read -p "👉 Enter a search term (or press Enter to list all): " search_term
    if [[ -z "$search_term" ]]; then
        mapfile -t users < <(cut -d: -f1 "$DB_FILE" | sort)
    else
        mapfile -t users < <(cut -d: -f1 "$DB_FILE" | grep -i "$search_term" | sort)
    fi
    if [ ${#users[@]} -eq 0 ]; then
        echo -e "\n${C_YELLOW}ℹ️ No users found matching your criteria.${C_RESET}"
        SELECTED_USER="NO_USERS"; return
    fi
    echo -e "\nPlease select a user:\n"
    for i in "${!users[@]}"; do
        printf "  ${C_GREEN}%2d)${C_RESET} %s\n" "$((i+1))" "${users[$i]}"
    done
    echo -e "\n  ${C_RED} 0)${C_RESET} ↩️ Cancel and return to main menu"
    echo
    local choice
    while true; do
        read -p "👉 Enter the number of the user: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 0 ] && [ "$choice" -le "${#users[@]}" ]; then
            if [ "$choice" -eq 0 ]; then
                SELECTED_USER=""; return
            else
                SELECTED_USER="${users[$((choice-1))]}"; return
            fi
        else
            echo -e "${C_RED}❌ Invalid selection. Please try again.${C_RESET}"
        fi
    done
}

get_user_status() {
    local username="$1"
    if ! id "$username" &>/dev/null; then echo -e "${C_RED}Not Found${C_RESET}"; return; fi
    local expiry_date=$(grep "^$username:" "$DB_FILE" | cut -d: -f3)
    if passwd -S "$username" 2>/dev/null | grep -q " L "; then echo -e "${C_YELLOW}🔒 Locked${C_RESET}"; return; fi
    local expiry_ts=$(date -d "$expiry_date" +%s 2>/dev/null || echo 0)
    local current_ts=$(date +%s)
    if [[ $expiry_ts -lt $current_ts ]]; then echo -e "${C_RED}🗓️ Expired${C_RESET}"; return; fi
    echo -e "${C_GREEN}🟢 Active${C_RESET}"
}

create_user() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- ✨ Create New SSH User ---${C_RESET}"
    read -p "👉 Enter username (or '0' to cancel): " username
    if [[ "$username" == "0" ]]; then
        echo -e "\n${C_YELLOW}❌ User creation cancelled.${C_RESET}"
        return
    fi
    if [[ -z "$username" ]]; then
        echo -e "\n${C_RED}❌ Error: Username cannot be empty.${C_RESET}"
        return
    fi
    if id "$username" &>/dev/null || grep -q "^$username:" "$DB_FILE"; then
        echo -e "\n${C_RED}❌ Error: User '$username' already exists.${C_RESET}"; return
    fi
    local password=""
    while true; do
        read -p "🔑 Enter new password: " password
        if [[ -z "$password" ]]; then
            echo -e "${C_RED}❌ Password cannot be empty. Please try again.${C_RESET}"
        else
            break
        fi
    done
    read -p "🗓️ Enter account duration (in days): " days
    if ! [[ "$days" =~ ^[0-9]+$ ]]; then echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"; return; fi
    read -p "📶 Enter simultaneous connection limit: " limit
    if ! [[ "$limit" =~ ^[0-9]+$ ]]; then echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"; return; fi
    local expire_date
    expire_date=$(date -d "+$days days" +%Y-%m-%d)
    useradd -m -s /usr/sbin/nologin "$username"; echo "$username:$password" | chpasswd; chage -E "$expire_date" "$username"
    echo "$username:$password:$expire_date:$limit" >> "$DB_FILE"
    
    clear; show_banner
    echo -e "${C_GREEN}✅ User '$username' created successfully!${C_RESET}\n"
    echo -e "  - 👤 Username:          ${C_YELLOW}$username${C_RESET}"
    echo -e "  - 🔑 Password:          ${C_YELLOW}$password${C_RESET}"
    echo -e "  - 🗓️ Expires on:        ${C_YELLOW}$expire_date${C_RESET}"
    echo -e "  - 📶 Connection Limit:  ${C_YELLOW}$limit${C_RESET}"
    echo -e "    ${C_DIM}(Active monitoring service will enforce this limit)${C_RESET}"
}

delete_user() {
    _select_user_interface "--- 🗑️ Delete a User (from DB) ---"
    local username=$SELECTED_USER
    
    if [[ "$username" == "NO_USERS" ]] || [[ -z "$username" ]]; then
        if [[ "$username" == "NO_USERS" ]]; then
            echo -e "\n${C_YELLOW}ℹ️ No users found in database.${C_RESET}"
        fi
        
        read -p "👉 Type username to MANUALLY delete (or '0' to cancel): " manual_user
        if [[ "$manual_user" == "0" ]] || [[ -z "$manual_user" ]]; then
            echo -e "\n${C_YELLOW}❌ Action cancelled.${C_RESET}"
            return
        fi
        username="$manual_user"
        
        if ! id "$username" &>/dev/null; then
             echo -e "\n${C_RED}❌ Error: User '$username' does not exist on this system.${C_RESET}"
             return
        fi
        
        if grep -q "^$username:" "$DB_FILE"; then
            echo -e "\n${C_YELLOW}ℹ️ User '$username' is in the database. Please use the normal selection method.${C_RESET}"
            echo -e "   For safety, manual deletion is only for users NOT in the database."
            return
        fi
        
        echo -e "${C_YELLOW}⚠️ User '$username' exists on the system but is NOT in the database.${C_RESET}"
    fi

    read -p "👉 Are you sure you want to PERMANENTLY delete '$username'? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then echo -e "\n${C_YELLOW}❌ Deletion cancelled.${C_RESET}"; return; fi
    
    echo -e "${C_BLUE}🔌 Force killing active connections for $username...${C_RESET}"
    killall -u "$username" -9 &>/dev/null
    sleep 1

    if userdel -r "$username" &>/dev/null; then
         echo -e "\n${C_GREEN}✅ System user '$username' has been deleted.${C_RESET}"
    else
         echo -e "\n${C_RED}❌ Failed to delete system user '$username'.${C_RESET}"
    fi

    sed -i "/^$username:/d" "$DB_FILE"
    echo -e "${C_GREEN}✅ User '$username' has been completely removed.${C_RESET}"
}

edit_user() {
    _select_user_interface "--- ✏️ Edit a User ---"
    local username=$SELECTED_USER
    if [[ "$username" == "NO_USERS" ]] || [[ -z "$username" ]]; then return; fi
    while true; do
        clear; show_banner; echo -e "${C_BOLD}${C_PURPLE}--- Editing User: ${C_YELLOW}$username${C_PURPLE} ---${C_RESET}"
        echo -e "\nSelect a detail to edit:\n"
        echo -e "  ${C_GREEN}1)${C_RESET} 🔑 Change Password"; echo -e "  ${C_GREEN}2)${C_RESET} 🗓️ Change Expiration Date"; echo -e "  ${C_GREEN}3)${C_RESET} 📶 Change Connection Limit"
        echo -e "\n  ${C_RED}0)${C_RESET} ✅ Finish Editing"; echo; read -p "👉 Enter your choice: " edit_choice
        case $edit_choice in
            1)
               local new_pass=""
               while true; do
                   read -p "Enter new password: " new_pass
                   if [[ -z "$new_pass" ]]; then
                       echo -e "${C_RED}❌ Password cannot be empty. Please try again.${C_RESET}"
                   else
                       break
                   fi
               done
               echo "$username:$new_pass" | chpasswd
               local current_line; current_line=$(grep "^$username:" "$DB_FILE"); local expiry; expiry=$(echo "$current_line" | cut -d: -f3); local limit; limit=$(echo "$current_line" | cut -d: -f4)
               sed -i "s/^$username:.*/$username:$new_pass:$expiry:$limit/" "$DB_FILE"
               echo -e "\n${C_GREEN}✅ Password for '$username' changed successfully.${C_RESET}"
               echo -e "New Password: ${C_YELLOW}$new_pass${C_RESET}"
               ;;
            2) read -p "Enter new duration (in days from today): " days
               if [[ "$days" =~ ^[0-9]+$ ]]; then
                   local new_expire_date; new_expire_date=$(date -d "+$days days" +%Y-%m-%d); chage -E "$new_expire_date" "$username"
                   local current_line; current_line=$(grep "^$username:" "$DB_FILE"); local pass; pass=$(echo "$current_line" | cut -d: -f2); local limit; limit=$(echo "$current_line" | cut -d: -f4)
                   sed -i "s/^$username:.*/$username:$pass:$new_expire_date:$limit/" "$DB_FILE"
                   echo -e "\n${C_GREEN}✅ Expiration for '$username' set to ${C_YELLOW}$new_expire_date${C_RESET}."
               else echo -e "\n${C_RED}❌ Invalid number of days.${C_RESET}"; fi ;;
            3) read -p "Enter new simultaneous connection limit: " new_limit
               if [[ "$new_limit" =~ ^[0-9]+$ ]]; then
                   local current_line; current_line=$(grep "^$username:" "$DB_FILE"); local pass; pass=$(echo "$current_line" | cut -d: -f2); local expiry; expiry=$(echo "$current_line" | cut -d: -f3)
                   sed -i "s/^$username:.*/$username:$pass:$expiry:$new_limit/" "$DB_FILE"
                   echo -e "\n${C_GREEN}✅ Connection limit for '$username' set to ${C_YELLOW}$new_limit${C_RESET}."
               else echo -e "\n${C_RED}❌ Invalid limit.${C_RESET}"; fi ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option.${C_RESET}" ;;
        esac
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue editing..." && read -r
    done
}

lock_user() {
    _select_user_interface "--- 🔒 Lock a User (from DB) ---"
    local u=$SELECTED_USER
    if [[ "$u" == "NO_USERS" ]] || [[ -z "$u" ]]; then
        if [[ "$u" == "NO_USERS" ]]; then
            echo -e "\n${C_YELLOW}ℹ️ No users found in database.${C_RESET}"
        fi
        
        read -p "👉 Type username to MANUALLY lock (or '0' to cancel): " manual_user
        if [[ "$manual_user" == "0" ]] || [[ -z "$manual_user" ]]; then
            echo -e "\n${C_YELLOW}❌ Action cancelled.${C_RESET}"
            return
        fi
        u="$manual_user"
        
        if ! id "$u" &>/dev/null; then
             echo -e "\n${C_RED}❌ Error: User '$u' does not exist on this system.${C_RESET}"
             return
        fi
        
        if grep -q "^$u:" "$DB_FILE"; then
             echo -e "\n${C_YELLOW}ℹ️ User '$u' is in the database. Use the normal selection method.${C_RESET}"
        else
             echo -e "${C_YELLOW}⚠️ User '$u' exists on the system but is NOT in the database.${C_RESET}"
        fi
    fi

    if usermod -L "$u" 2>/dev/null; then
        killall -u "$u" -9 &>/dev/null
        echo -e "\n${C_GREEN}✅ User '$u' has been locked and active sessions killed.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ Failed to lock user '$u'.${C_RESET}"
    fi
}

unlock_user() {
    _select_user_interface "--- 🔓 Unlock a User (from DB) ---"
    local u=$SELECTED_USER
    if [[ "$u" == "NO_USERS" ]] || [[ -z "$u" ]]; then
        if [[ "$u" == "NO_USERS" ]]; then
            echo -e "\n${C_YELLOW}ℹ️ No users found in database.${C_RESET}"
        fi
        
        read -p "👉 Type username to MANUALLY unlock (or '0' to cancel): " manual_user
        if [[ "$manual_user" == "0" ]] || [[ -z "$manual_user" ]]; then
            echo -e "\n${C_YELLOW}❌ Action cancelled.${C_RESET}"
            return
        fi
        u="$manual_user"
        
        if ! id "$u" &>/dev/null; then
             echo -e "\n${C_RED}❌ Error: User '$u' does not exist on this system.${C_RESET}"
             return
        fi
        
        if grep -q "^$u:" "$DB_FILE"; then
             echo -e "\n${C_YELLOW}ℹ️ User '$u' is in the database. Use the normal selection method.${C_RESET}"
        else
             echo -e "${C_YELLOW}⚠️ User '$u' exists on the system but is NOT in the database.${C_RESET}"
        fi
    fi

    if usermod -U "$u" 2>/dev/null; then
        echo -e "\n${C_GREEN}✅ User '$u' has been unlocked.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ Failed to unlock user '$u'.${C_RESET}"
    fi
}

list_users() {
    clear; show_banner
    if [[ ! -s "$DB_FILE" ]]; then
        echo -e "\n${C_YELLOW}ℹ️ No users are currently being managed.${C_RESET}"
        return
    fi
    echo -e "${C_BOLD}${C_PURPLE}--- 📋 Managed Users ---${C_RESET}"
    echo -e "${C_CYAN}======================================================================${C_RESET}"
    printf "${C_BOLD}${C_WHITE}%-20s | %-12s | %-15s | %-20s${C_RESET}\n" "USERNAME" "EXPIRES" "CONNECTIONS" "STATUS"
    echo -e "${C_CYAN}----------------------------------------------------------------------${C_RESET}"
    
    while IFS=: read -r user pass expiry limit; do
        local online_count
        online_count=$(pgrep -u "$user" sshd | wc -l)
        
        local status
        status=$(get_user_status "$user")

        local plain_status
        plain_status=$(echo -e "$status" | sed 's/\x1b\[[0-9;]*m//g')
        
        local connection_string="$online_count / $limit"

        local line_color="$C_WHITE"
        case $plain_status in
            *"Active"*) line_color="$C_GREEN" ;;
            *"Locked"*) line_color="$C_YELLOW" ;;
            *"Expired"*) line_color="$C_RED" ;;
            *"Not Found"*) line_color="$C_DIM" ;;
        esac

        printf "${line_color}%-20s ${C_RESET}| ${C_YELLOW}%-12s ${C_RESET}| ${C_CYAN}%-15s ${C_RESET}| %-20s\n" "$user" "$expiry" "$connection_string" "$status"
    done < <(sort "$DB_FILE")
    echo -e "${C_CYAN}======================================================================${C_RESET}\n"
}

renew_user() {
    _select_user_interface "--- 🔄 Renew a User ---"; local u=$SELECTED_USER; if [[ "$u" == "NO_USERS" || -z "$u" ]]; then return; fi
    read -p "👉 Enter number of days to extend the account: " days; if ! [[ "$days" =~ ^[0-9]+$ ]]; then echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"; return; fi
    local new_expire_date; new_expire_date=$(date -d "+$days days" +%Y-%m-%d); chage -E "$new_expire_date" "$u"
    local line; line=$(grep "^$u:" "$DB_FILE"); local pass; pass=$(echo "$line"|cut -d: -f2); local limit; limit=$(echo "$line"|cut -d: -f4)
    sed -i "s/^$u:.*/$u:$pass:$new_expire_date:$limit/" "$DB_FILE"
    echo -e "\n${C_GREEN}✅ User '$u' has been renewed. New expiration date is ${C_YELLOW}${new_expire_date}${C_RESET}."
}

cleanup_expired() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🧹 Cleanup Expired Users ---${C_RESET}"
    
    local expired_users=()
    local current_ts
    current_ts=$(date +%s)

    if [[ ! -s "$DB_FILE" ]]; then
        echo -e "\n${C_GREEN}✅ User database is empty. No expired users found.${C_RESET}"
        return
    fi
    
    while IFS=: read -r user pass expiry limit; do
        local expiry_ts
        expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
        
        if [[ $expiry_ts -lt $current_ts && $expiry_ts -ne 0 ]]; then
            expired_users+=("$user")
        fi
    done < "$DB_FILE"

    if [ ${#expired_users[@]} -eq 0 ]; then
        echo -e "\n${C_GREEN}✅ No expired users found.${C_RESET}"
        return
    fi

    echo -e "\nThe following users have expired: ${C_RED}${expired_users[*]}${C_RESET}"
    read -p "👉 Do you want to delete all of them? (y/n): " confirm

    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        for user in "${expired_users[@]}"; do
            echo " - Deleting ${C_YELLOW}$user...${C_RESET}"
            killall -u "$user" -9 &>/dev/null
            userdel -r "$user" &>/dev/null
            sed -i "/^$user:/d" "$DB_FILE"
        done
        echo -e "\n${C_GREEN}✅ Expired users have been cleaned up.${C_RESET}"
    else
        echo -e "\n${C_YELLOW}❌ Cleanup cancelled.${C_RESET}"
    fi
}


backup_user_data() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 💾 Backup User Data ---${C_RESET}"
    read -p "👉 Enter path for backup file [$DEFAULT_BACKUP_PATH]: " backup_path
    backup_path=${backup_path:-$DEFAULT_BACKUP_PATH}
    if [ ! -d "$DB_DIR" ] || [ ! -s "$DB_FILE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ No user data found to back up.${C_RESET}"
        return
    fi
    echo -e "\n${C_BLUE}⚙️ Backing up user database and settings to ${C_YELLOW}$backup_path${C_RESET}..."
    tar -czf "$backup_path" -C "$(dirname "$DB_DIR")" "$(basename "$DB_DIR")"
    if passwd -S "$username" 2>/dev/null | grep -q " P "; then
        echo -e "\n${C_GREEN}✅ SUCCESS: User data backup created at ${C_YELLOW}$backup_path${C_RESET}"
    else
        echo -e "\n${C_RED}❌ ERROR: Backup failed.${C_RESET}"
    fi
}

restore_user_data() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 📥 Restore User Data ---${C_RESET}"
    read -p "👉 Enter the full path to the user data backup file [$DEFAULT_BACKUP_PATH]: " backup_path
    backup_path=${backup_path:-$DEFAULT_BACKUP_PATH}
    if [ ! -f "$backup_path" ]; then
        echo -e "\n${C_RED}❌ ERROR: Backup file not found at '$backup_path'.${C_RESET}"
        return
    fi
    echo -e "\n${C_RED}${C_BOLD}⚠️ WARNING:${C_RESET} This will overwrite all current users and settings."
    echo -e "It will restore user accounts, passwords, limits, and expiration dates from the backup file."
    read -p "👉 Are you absolutely sure you want to proceed? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then echo -e "\n${C_YELLOW}❌ Restore cancelled.${C_RESET}"; return; fi
    local temp_dir
    temp_dir=$(mktemp -d)
    echo -e "\n${C_BLUE}⚙️ Extracting backup file to a temporary location...${C_RESET}"
    tar -xzf "$backup_path" -C "$temp_dir"
    if [ $? -ne 0 ]; then
        echo -e "\n${C_RED}❌ ERROR: Failed to extract backup file. Aborting.${C_RESET}"
        rm -rf "$temp_dir"
        return
    fi
    local restored_db_file="$temp_dir/${APP_BASE_DIR_NAME}/users.db"
    if [ ! -f "$restored_db_file" ]; then
        echo -e "\n${C_RED}❌ ERROR: users.db not found in the backup. Cannot restore user accounts.${C_RESET}"
        rm -rf "$temp_dir"
        return
    fi
    echo -e "${C_BLUE}⚙️ Overwriting current user database...${C_RESET}"
    mkdir -p "$DB_DIR"
    cp "$restored_db_file" "$DB_FILE"
    if [ -d "$temp_dir/${APP_BASE_DIR_NAME}/ssl" ]; then
        cp -r "$temp_dir/${APP_BASE_DIR_NAME}/ssl" "$DB_DIR/"
    fi
    if [ -d "$temp_dir/${APP_BASE_DIR_NAME}/dnstt" ]; then
        cp -r "$temp_dir/${APP_BASE_DIR_NAME}/dnstt" "$DB_DIR/"
    fi
    if [ -f "$temp_dir/${APP_BASE_DIR_NAME}/dns_info.conf" ]; then
        cp "$temp_dir/${APP_BASE_DIR_NAME}/dns_info.conf" "$DB_DIR/"
    fi
    if [ -f "$temp_dir/${APP_BASE_DIR_NAME}/dnstt_info.conf" ]; then
        cp "$temp_dir/${APP_BASE_DIR_NAME}/dnstt_info.conf" "$DB_DIR/"
    fi
    if [ -f "$temp_dir/${APP_BASE_DIR_NAME}/webproxy_config.conf" ]; then
        cp "$temp_dir/${APP_BASE_DIR_NAME}/webproxy_config.conf" "$DB_DIR/"
    fi
    
    echo -e "${C_BLUE}⚙️ Re-synchronizing system accounts with the restored database...${C_RESET}"
    
    while IFS=: read -r user pass expiry limit; do
        echo "Processing user: ${C_YELLOW}$user${C_RESET}"
        if ! id "$user" &>/dev/null; then
            echo " - User does not exist in system. Creating..."
            useradd -m -s /usr/sbin/nologin "$user"
        fi
        echo " - Setting password..."
        echo "$user:$pass" | chpasswd
        echo " - Setting expiration to $expiry..."
        chage -E "$expiry" "$user"
        echo " - Connection limit is $limit (enforced by PAM)"
    done < "$DB_FILE"
    rm -rf "$temp_dir"
    echo -e "\n${C_GREEN}✅ SUCCESS: User data restore completed.${C_RESET}"
}

_enable_banner_in_sshd_config() {
    echo -e "\n${C_BLUE}⚙️ Configuring sshd_config...${C_RESET}"
    sed -i.bak -E 's/^( *Banner *).*/#\1/' /etc/ssh/sshd_config
    if ! grep -q -E "^Banner $SSH_BANNER_FILE" /etc/ssh/sshd_config; then
        echo -e "\n# ${APP_BASE_DIR_NAME^} SSH Banner\nBanner $SSH_BANNER_FILE" >> /etc/ssh/sshd_config
    fi
    echo -e "${C_GREEN}✅ sshd_config updated.${C_RESET}"
}

_restart_ssh() {
    echo -e "\n${C_BLUE}🔄 Restarting SSH service to apply changes...${C_RESET}"
    local ssh_service_name=""
    if [ -f /lib/systemd/system/sshd.service ]; then
        ssh_service_name="sshd.service"
    elif [ -f /lib/systemd/system/ssh.service ]; then
        ssh_service_name="ssh.service"
    else
        echo -e "${C_RED}❌ Could not find sshd.service or ssh.service. Cannot restart SSH.${C_RESET}"
        return 1
    fi

    systemctl restart "${ssh_service_name}"
    if passwd -S "$username" 2>/dev/null | grep -q " P "; then
        echo -e "${C_GREEN}✅ SSH service ('${ssh_service_name}') restarted successfully.${C_RESET}"
    else
        echo -e "${C_RED}❌ Failed to restart SSH service ('${ssh_service_name}'). Please check 'journalctl -u ${ssh_service_name}' for errors.${C_RESET}"
    fi
}

set_ssh_banner_paste() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 📋 Paste SSH Banner ---${C_RESET}"
    echo -e "Paste your banner code below. Press ${C_YELLOW}[Ctrl+D]${C_RESET} when you are finished."
    echo -e "${C_DIM}The current banner (if any) will be overwritten.${C_RESET}"
    echo -e "--------------------------------------------------"
    cat > "$SSH_BANNER_FILE"
    chmod 644 "$SSH_BANNER_FILE"
    echo -e "\n--------------------------------------------------"
    echo -e "\n${C_GREEN}✅ Banner content saved from paste.${C_RESET}"
    _enable_banner_in_sshd_config
    _restart_ssh
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to return..." && read -r
}

view_ssh_banner() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 👁️ Current SSH Banner ---${C_RESET}"
    if [ -f "$SSH_BANNER_FILE" ]; then
        echo -e "\n${C_CYAN}--- BEGIN BANNER ---${C_RESET}"
        cat "$SSH_BANNER_FILE"
        echo -e "${C_CYAN}---- END BANNER ----${C_RESET}"
    else
        echo -e "\n${C_YELLOW}ℹ️ No banner file found at $SSH_BANNER_FILE.${C_RESET}"
    fi
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to return..." && read -r
}

remove_ssh_banner() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🗑️ Remove SSH Banner ---${C_RESET}"
    read -p "👉 Are you sure you want to disable and remove the SSH banner? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        echo -e "\n${C_YELLOW}❌ Action cancelled.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to return..." && read -r
        return
    fi
    if [ -f "$SSH_BANNER_FILE" ]; then
        rm -f "$SSH_BANNER_FILE"
        echo -e "\n${C_GREEN}✅ Removed banner file: $SSH_BANNER_FILE${C_RESET}"
    else
        echo -e "\n${C_YELLOW}ℹ️ No banner file to remove.${C_RESET}"
    fi
    echo -e "\n${C_BLUE}⚙️ Disabling banner in sshd_config...${C_RESET}"
    sed -i.bak -E "s/^( *Banner\s+$SSH_BANNER_FILE)/#\1/" /etc/ssh/sshd_config
    echo -e "${C_GREEN}✅ Banner disabled in configuration.${C_RESET}"
    _restart_ssh
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to return..." && read -r
}

ssh_banner_menu() {
    while true; do
        show_banner
        local banner_status
        if grep -q -E "^\s*Banner\s+$SSH_BANNER_FILE" /etc/ssh/sshd_config && [ -f "$SSH_BANNER_FILE" ]; then
            banner_status="${C_STATUS_A}(Active)${C_RESET}"
        else
            banner_status="${C_STATUS_I}(Inactive)${C_RESET}"
        fi
        
        echo -e "\n   ${C_TITLE}═════════════════[ ${C_BOLD}🎨 SSH Banner Management ${banner_status} ${C_RESET}${C_TITLE}]═════════════════${C_RESET}"
        echo -e "     ${C_CHOICE}1)${C_RESET} 📋 Paste or Edit Banner"
        echo -e "     ${C_CHOICE}2)${C_RESET} 👁️ View Current Banner"
        echo -e "     ${C_DANGER}3)${C_RESET} 🗑️ Disable and Remove Banner"
        echo -e "   ${C_DIM}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${C_RESET}"
        echo -e "     ${C_WARN}0)${C_RESET} ↩️ Return to Main Menu"
        echo
        read -p "$(echo -e ${C_PROMPT}"👉 Select an option: "${C_RESET})" choice
        case $choice in
            1) set_ssh_banner_paste ;;
            2) view_ssh_banner ;;
            3) remove_ssh_banner ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option.${C_RESET}" && sleep 2 ;;
        esac
    done
}

install_udp_custom() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing udp-custom ---${C_RESET}"
    if [ -f "$UDP_CUSTOM_SERVICE_FILE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ udp-custom is already installed.${C_RESET}"
        return
    fi

    echo -e "\n${C_GREEN}⚙️ Creating directory for udp-custom...${C_RESET}"
    rm -rf "$UDP_CUSTOM_DIR"
    mkdir -p "$UDP_CUSTOM_DIR"

    echo -e "\n${C_GREEN}⚙️ Detecting system architecture...${C_RESET}"
    local arch
    arch=$(uname -m)
    local binary_url=""
    if [[ "$arch" == "x86_64" ]]; then
        binary_url="https://github.com/firewallfalcons/FirewallFalcon-Manager/raw/main/udp/udp-custom-linux-amd64"
        echo -e "${C_BLUE}ℹ️ Detected x86_64 (amd64) architecture.${C_RESET}"
    elif [[ "$arch" == "aarch64" || "$arch" == "arm64" ]]; then
        binary_url="https://github.com/firewallfalcons/FirewallFalcon-Manager/raw/main/udp/udp-custom-linux-arm"
        echo -e "${C_BLUE}ℹ️ Detected ARM64 architecture.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ Unsupported architecture: $arch. Cannot install udp-custom.${C_RESET}"
        rm -rf "$UDP_CUSTOM_DIR"
        return
    fi

    echo -e "\n${C_GREEN}📥 Downloading udp-custom binary...${C_RESET}"
    if ! wget -q --show-progress -O "$UDP_CUSTOM_DIR/udp-custom" "$binary_url"; then
        echo -e "\n${C_RED}❌ Failed to download the udp-custom binary from $binary_url${C_RESET}"
        rm -rf "$UDP_CUSTOM_DIR"
        return 1
    fi
    if [[ ! -f "$UDP_CUSTOM_DIR/udp-custom" ]] || [[ ! -s "$UDP_CUSTOM_DIR/udp-custom" ]]; then
        echo -e "\n${C_RED}❌ Downloaded file is empty or missing.${C_RESET}"
        rm -rf "$UDP_CUSTOM_DIR"
        return 1
    fi
    chmod +x "$UDP_CUSTOM_DIR/udp-custom"

    echo -e "\n${C_GREEN}📝 Creating default config.json...${C_RESET}"
    cat > "$UDP_CUSTOM_DIR/config.json" <<EOF
{
  "listen": ":36712",
  "stream_buffer": 33554432,
  "receive_buffer": 83886080,
  "auth": {
    "mode": "passwords"
  }
}
EOF
    chmod 644 "$UDP_CUSTOM_DIR/config.json"

    echo -e "\n${C_GREEN}📝 Creating systemd service file...${C_RESET}"
    cat > "$UDP_CUSTOM_SERVICE_FILE" <<EOF
[Unit]
Description=UDP Custom by ${REPO_NAME}
After=network.target

[Service]
User=root
Type=simple
ExecStart="$UDP_CUSTOM_DIR/udp-custom" server -exclude 53,5300
WorkingDirectory=$UDP_CUSTOM_DIR/
Restart=always
RestartSec=2s

[Install]
WantedBy=default.target
EOF

    echo -e "\n${C_GREEN}▶️ Enabling and starting udp-custom service...${C_RESET}"
    systemctl daemon-reload
    systemctl enable udp-custom.service
    systemctl start udp-custom.service
    sleep 2
    if systemctl is-active --quiet udp-custom; then
        echo -e "\n${C_GREEN}✅ SUCCESS: udp-custom is installed and active.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ ERROR: udp-custom service failed to start.${C_RESET}"
        echo -e "${C_YELLOW}ℹ️ Displaying last 15 lines of the service log for diagnostics:${C_RESET}"
        journalctl -u udp-custom.service -n 15 --no-pager
    fi
}

uninstall_udp_custom() {
    echo -e "\n${C_BOLD}${C_PURPLE}--- 🗑️ Uninstalling udp-custom ---${C_RESET}"
    if [ ! -f "$UDP_CUSTOM_SERVICE_FILE" ]; then
        echo -e "${C_YELLOW}ℹ️ udp-custom is not installed, skipping.${C_RESET}"
        return
    fi
    echo -e "${C_GREEN}🛑 Stopping and disabling udp-custom service...${C_RESET}"
    systemctl stop udp-custom.service >/dev/null 2>&1
    systemctl disable udp-custom.service >/dev/null 2>&1
    echo -e "${C_GREEN}🗑️ Removing systemd service file...${C_RESET}"
    rm -f "$UDP_CUSTOM_SERVICE_FILE"
    systemctl daemon-reload
    echo -e "${C_GREEN}🗑️ Removing udp-custom directory and files...${C_RESET}"
    rm -rf "$UDP_CUSTOM_DIR"
    echo -e "${C_GREEN}✅ udp-custom has been uninstalled successfully.${C_RESET}"
}


install_badvpn() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing badvpn (udpgw) ---${C_RESET}"
    if [ -f "$BADVPN_SERVICE_FILE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ badvpn is already installed.${C_RESET}"
        return
    fi
    check_and_open_firewall_port $DEFAULT_BADVPN_PORT udp || return
    echo -e "\n${C_GREEN}🔄 Updating package lists...${C_RESET}"
    apt-get update
    echo -e "\n${C_GREEN}📦 Installing all required packages...${C_RESET}"
    apt-get install -y cmake g++ make screen git build-essential libssl-dev libnspr4-dev libnss3-dev pkg-config
    echo -e "\n${C_GREEN}📥 Cloning badvpn from github...${C_RESET}"
    git clone https://github.com/ambrop72/badvpn.git "$BADVPN_BUILD_DIR"
    cd "$BADVPN_BUILD_DIR" || { echo -e "${C_RED}❌ Failed to change directory to build folder.${C_RESET}"; return; }
    echo -e "\n${C_GREEN}⚙️ Running CMake...${C_RESET}"
    cmake . || { echo -e "${C_RED}❌ CMake configuration failed.${C_RESET}"; rm -rf "$BADVPN_BUILD_DIR"; return; }
    echo -e "\n${C_GREEN}🛠️ Compiling source...${C_RESET}"
    make || { echo -e "${C_RED}❌ Compilation (make) failed.${C_RESET}"; rm -rf "$BADVPN_BUILD_DIR"; return; }
    local badvpn_binary
    badvpn_binary=$(find "$BADVPN_BUILD_DIR" -name "badvpn-udpgw" -type f | head -n 1)
    if [[ -z "$badvpn_binary" || ! -f "$badvpn_binary" ]]; then
        echo -e "${C_RED}❌ ERROR: Could not find the compiled 'badvpn-udpgw' binary after compilation.${C_RESET}"
        rm -rf "$BADVPN_BUILD_DIR"
        return
    fi
    echo -e "${C_GREEN}ℹ️ Found binary at: $badvpn_binary${C_RESET}"
    chmod +x "$badvpn_binary"
    echo -e "\n${C_GREEN}📝 Creating systemd service file...${C_RESET}"
    cat > "$BADVPN_SERVICE_FILE" <<-EOF
[Unit]
Description=BadVPN UDP Gateway
After=network.target
[Service]
ExecStart="$badvpn_binary" --listen-addr 0.0.0.0:$DEFAULT_BADVPN_PORT --max-clients 1000 --max-connections-for-client 8
User=root
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
    echo -e "\n${C_GREEN}▶️ Enabling and starting badvpn service...${C_RESET}"
    systemctl daemon-reload
    systemctl enable badvpn.service
    systemctl start badvpn.service
    sleep 2
    if systemctl is-active --quiet badvpn; then
        echo -e "\n${C_GREEN}✅ SUCCESS: badvpn (udpgw) is installed and active on port $DEFAULT_BADVPN_PORT.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ ERROR: badvpn service failed to start.${C_RESET}"
        echo -e "${C_YELLOW}ℹ️ Displaying last 15 lines of the service log for diagnostics:${C_RESET}"
        journalctl -u badvpn.service -n 15 --no-pager
    fi
}

uninstall_badvpn() {
    echo -e "\n${C_BOLD}${C_PURPLE}--- 🗑️ Uninstalling badvpn (udpgw) ---${C_RESET}"
    if [ ! -f "$BADVPN_SERVICE_FILE" ]; then
        echo -e "${C_YELLOW}ℹ️ badvpn is not installed, skipping.${C_RESET}"
        return
    fi
    echo -e "${C_GREEN}🛑 Stopping and disabling badvpn service...${C_RESET}"
    systemctl stop badvpn.service >/dev/null 2>&1
    systemctl disable badvpn.service >/dev/null 2>&1
    echo -e "${C_GREEN}🗑️ Removing systemd service file...${C_RESET}"
    rm -f "$BADVPN_SERVICE_FILE"
    systemctl daemon-reload
    echo -e "${C_GREEN}🗑️ Removing badvpn build directory...${C_RESET}"
    rm -rf "$BADVPN_BUILD_DIR"
    echo -e "${C_GREEN}✅ badvpn has been uninstalled successfully.${C_RESET}"
}

install_ssl_tunnel() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing SSL Tunnel (HAProxy) for SSH ---${C_RESET}"
    if ! command -v haproxy &> /dev/null; then
        echo -e "\n${C_YELLOW}⚠️ HAProxy not found. Installing...${C_RESET}"
        apt-get update && apt-get install -y haproxy || { echo -e "${C_RED}❌ Failed to install HAProxy.${C_RESET}"; return; }
    fi
    read -p "👉 Enter the port for the SSL tunnel [$DEFAULT_SSL_TUNNEL_PORT]: " ssl_port
    ssl_port=${ssl_port:-$DEFAULT_SSL_TUNNEL_PORT}
    if ! [[ "$ssl_port" =~ ^[0-9]+$ ]] || [ "$ssl_port" -lt 1 ] || [ "$ssl_port" -gt 65535 ]; then
        echo -e "\n${C_RED}❌ Invalid port number. Aborting.${C_RESET}"
        return
    fi
    
    check_and_free_ports "$ssl_port" || return
    check_and_open_firewall_port "$ssl_port" || return

    if [ -f "$SSL_CERT_FILE" ]; then
        read -p "SSL certificate already exists. Overwrite? (y/n): " overwrite_cert
        if [[ "$overwrite_cert" != "y" ]]; then
            echo -e "${C_YELLOW}ℹ️ Using existing certificate.${C_RESET}"
        else
            rm -f "$SSL_CERT_FILE"
        fi
    fi
    if [ ! -f "$SSL_CERT_FILE" ]; then
        echo -e "\n${C_GREEN}🔐 Generating self-signed SSL certificate...${C_RESET}"
        openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
            -keyout "$SSL_CERT_FILE" -out "$SSL_CERT_FILE" \
            -subj "/CN=@${REPO_NAME}" \
            >/dev/null 2>&1 || { echo -e "${C_RED}❌ Failed to generate SSL certificate.${C_RESET}"; return; }
        echo -e "${C_GREEN}✅ Certificate created: ${C_YELLOW}$SSL_CERT_FILE${C_RESET}"
    fi
    echo -e "\n${C_GREEN}📝 Creating HAProxy configuration for port $ssl_port...${C_RESET}"
    cat > "$HAPROXY_CONFIG" <<-EOF
global
    log /dev/log    local0
    log /dev/log    local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
    user haproxy
    group haproxy
    daemon
defaults
    log     global
    mode    tcp
    option  tcplog
    option  dontlognull
    timeout connect 5000
    timeout client  50000
    timeout server  50000
frontend ssh_ssl_in
    bind *:$ssl_port ssl crt $SSL_CERT_FILE
    mode tcp
    default_backend ssh_backend
backend ssh_backend
    mode tcp
    server ssh_server 127.0.0.1:22
EOF
    echo -e "\n${C_GREEN}▶️ Reloading and starting HAProxy service...${C_RESET}"
    systemctl daemon-reload
    systemctl restart haproxy
    sleep 2
    if systemctl is-active --quiet haproxy; then
        echo -e "\n${C_GREEN}✅ SUCCESS: SSL Tunnel is active.${C_RESET}"
        echo -e "Clients can now connect to this server's IP on port ${C_YELLOW}${ssl_port}${C_RESET} using an SSL/TLS tunnel."
    else
        echo -e "\n${C_RED}❌ ERROR: HAProxy service failed to start.${C_RESET}"
        echo -e "${C_YELLOW}ℹ️ Displaying HAProxy status for diagnostics:${C_RESET}"
        systemctl status haproxy --no-pager
    fi
}

uninstall_ssl_tunnel() {
    echo -e "\n${C_BOLD}${C_PURPLE}--- 🗑️ Uninstalling SSL Tunnel ---${C_RESET}"
    if ! command -v haproxy &> /dev/null; then
        echo -e "${C_YELLOW}ℹ️ HAProxy not installed, skipping.${C_RESET}"
        return
    fi
    echo -e "${C_GREEN}🛑 Stopping HAProxy service...${C_RESET}"
    systemctl stop haproxy >/dev/null 2>&1
    if [ -f "$HAPROXY_CONFIG" ]; then
        echo -e "${C_GREEN}📝 Restoring default/empty HAProxy config...${C_RESET}"
        cat > "$HAPROXY_CONFIG" <<-EOF
global
    log /dev/log    local0
    log /dev/log    local1 notice
defaults
    log     global
EOF
    fi
    if [ -f "$SSL_CERT_FILE" ]; then
        local delete_cert="y"
        if [[ "$UNINSTALL_MODE" != "silent" ]]; then
            read -p "👉 Delete the SSL certificate at $SSL_CERT_FILE? (y/n): " delete_cert
        fi
        if [[ "$delete_cert" == "y" ]]; then
            echo -e "${C_GREEN}🗑️ Removing SSL certificate...${C_RESET}"
            rm -f "$SSL_CERT_FILE"
        fi
    fi
    echo -e "${C_GREEN}✅ SSL Tunnel has been uninstalled.${C_RESET}"
}

verify_dnstt_keys() {
    local pubkey_file="$DNSTT_KEYS_DIR/server.pub"
    local privkey_file="$DNSTT_KEYS_DIR/server.key"
    
    echo -e "\n${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_BOLD}${C_BLUE}  🔍 DNSTT KEY VERIFICATION${C_RESET}"
    echo -e "${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    # Check if key files exist
    if [[ ! -f "$pubkey_file" ]]; then
        echo -e "  ${C_RED}❌ Public key file not found: $pubkey_file${C_RESET}"
        return 1
    fi
    
    if [[ ! -f "$privkey_file" ]]; then
        echo -e "  ${C_RED}❌ Private key file not found: $privkey_file${C_RESET}"
        return 1
    fi
    
    echo -e "  ${C_GREEN}✅ Both key files exist${C_RESET}"
    
    # Read and validate public key
    local public_key_content
    public_key_content=$(cat "$pubkey_file" 2>/dev/null)
    
    if [[ -z "$public_key_content" ]]; then
        echo -e "  ${C_RED}❌ Public key file is empty${C_RESET}"
        return 1
    fi
    
    # Check public key format (DNSTT keys start with "dnstt:")
    if [[ "$public_key_content" =~ ^dnstt: ]]; then
        echo -e "  ${C_GREEN}✅ Public key format is valid (DNSTT format)${C_RESET}"
    else
        echo -e "  ${C_YELLOW}⚠️ Public key format may be incorrect (should start with 'dnstt:')${C_RESET}"
    fi
    
    # Check key length (DNSTT public keys are typically long)
    local key_length=${#public_key_content}
    if [[ $key_length -gt 50 ]]; then
        echo -e "  ${C_GREEN}✅ Public key length is valid ($key_length characters)${C_RESET}"
    else
        echo -e "  ${C_YELLOW}⚠️ Public key seems too short ($key_length characters)${C_RESET}"
    fi
    
    # Check private key size (should be reasonable)
    if [[ -f "$privkey_file" ]]; then
        local privkey_size
        privkey_size=$(stat -f%z "$privkey_file" 2>/dev/null || stat -c%s "$privkey_file" 2>/dev/null || echo "0")
        if [[ $privkey_size -gt 0 ]]; then
            echo -e "  ${C_GREEN}✅ Private key file size: ${privkey_size} bytes${C_RESET}"
        fi
    fi
    
    # Verify keys match using dnstt-server binary if available
    if [[ -f "$DNSTT_BINARY" ]]; then
        echo -e "\n  ${C_BLUE}🔐 Verifying key pair match...${C_RESET}"
        # Test if binary can read the keys (some versions may not support -test-keys)
        if "$DNSTT_BINARY" -test-keys -privkey-file "$privkey_file" -pubkey-file "$pubkey_file" >/dev/null 2>&1; then
            echo -e "  ${C_GREEN}✅ Key pair verification: PASSED${C_RESET}"
        else
            # Alternative: check if we can read both keys without errors
            if [[ -r "$privkey_file" ]] && [[ -r "$pubkey_file" ]]; then
                echo -e "  ${C_GREEN}✅ Both keys are readable (binary verification not available)${C_RESET}"
            else
                echo -e "  ${C_RED}❌ Key pair verification: FAILED (keys may not match or binary doesn't support verification)${C_RESET}"
                return 1
            fi
        fi
    else
        echo -e "  ${C_YELLOW}⚠️ DNSTT binary not found, skipping key pair verification${C_RESET}"
    fi
    
    echo -e "\n${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_BOLD}${C_CYAN}  📋 PUBLIC KEY CONTENT${C_RESET}"
    echo -e "${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_YELLOW}$public_key_content${C_RESET}"
    echo -e "\n${C_DIM}📄 File location: $pubkey_file${C_RESET}"
    
    # Show file permissions
    local pubkey_perms
    pubkey_perms=$(stat -c "%a" "$pubkey_file" 2>/dev/null || stat -f "%OLp" "$pubkey_file" 2>/dev/null || echo "unknown")
    echo -e "${C_DIM}🔐 File permissions: $pubkey_perms${C_RESET}"
    
    # Check if service is using these keys
    if systemctl is-active --quiet dnstt.service 2>/dev/null; then
        local service_key_file
        service_key_file=$(systemctl show dnstt.service | grep -oP 'ExecStart=.*-privkey-file\s+\K[^\s]+' || echo "")
        if [[ -n "$service_key_file" ]] && [[ "$service_key_file" == "$privkey_file" ]]; then
            echo -e "\n  ${C_GREEN}✅ DNSTT service is actively using these keys${C_RESET}"
        fi
    fi
    
    echo -e "\n${C_GREEN}✅ Public key verification completed successfully!${C_RESET}"
    echo -e "${C_DIM}💡 Use this public key in your DNSTT client configuration${C_RESET}"
    return 0
}

show_dnstt_details() {
    if [ -f "$DNSTT_CONFIG_FILE" ]; then
        source "$DNSTT_CONFIG_FILE"
        echo -e "\n${C_GREEN}╔════════════════════════════════════════════════════════════╗${C_RESET}"
        echo -e "${C_GREEN}║${C_RESET}        ${C_BOLD}${C_WHITE}📡 DNSTT CONNECTION DETAILS 📡${C_RESET}        ${C_GREEN}║${C_RESET}"
        echo -e "${C_GREEN}╚════════════════════════════════════════════════════════════╝${C_RESET}"
        
        echo -e "\n${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        echo -e "${C_BOLD}${C_CYAN}  🌐 DOMAIN CONFIGURATION${C_RESET}"
        echo -e "${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        echo -e "  ${C_GREEN}1️⃣${C_RESET} ${C_WHITE}Tunnel Domain:${C_RESET}     ${C_YELLOW}$TUNNEL_DOMAIN${C_RESET}"
        if [[ "$DNSTT_RECORDS_MANAGED" == "false" && -n "$NS_DOMAIN" ]]; then
            echo -e "  ${C_GREEN}2️⃣${C_RESET} ${C_WHITE}Nameserver Domain:${C_RESET} ${C_YELLOW}$NS_DOMAIN${C_RESET}"
        fi
        
        echo -e "\n${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        echo -e "${C_BOLD}${C_CYAN}  🔑 AUTHENTICATION${C_RESET}"
        echo -e "${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        echo -e "  ${C_GREEN}3️⃣${C_RESET} ${C_WHITE}Public Key:${C_RESET}"
        
        # Try to read from actual file first, then from config
        local pubkey_file="$DNSTT_KEYS_DIR/server.pub"
        local current_pubkey=""
        
        if [[ -f "$pubkey_file" ]]; then
            current_pubkey=$(cat "$pubkey_file" 2>/dev/null | tr -d '\n\r')
        fi
        
        if [[ -n "$current_pubkey" ]]; then
            echo -e "     ${C_YELLOW}$current_pubkey${C_RESET}"
            echo -e "     ${C_DIM}📄 File: $pubkey_file${C_RESET}"
            echo -e "     ${C_DIM}💡 Copy the full key above for VPN client configuration${C_RESET}"
        elif [[ -n "$PUBLIC_KEY" ]]; then
            echo -e "     ${C_YELLOW}$PUBLIC_KEY${C_RESET}"
        else
            echo -e "     ${C_RED}❌ Public key not found${C_RESET}"
        fi
        
        echo -e "\n${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        echo -e "${C_BOLD}${C_CYAN}  ⚙️ NETWORK SETTINGS${C_RESET}"
        echo -e "${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        if [[ -n "$FORWARD_DESC" ]]; then
            echo -e "  ${C_GREEN}4️⃣${C_RESET} ${C_WHITE}Forwarding Target:${C_RESET} ${C_YELLOW}$FORWARD_DESC${C_RESET}"
        else
            echo -e "  ${C_GREEN}4️⃣${C_RESET} ${C_WHITE}Forwarding Target:${C_RESET} ${C_YELLOW}Unknown (config_missing)${C_RESET}"
        fi
        if [[ -n "$MTU_VALUE" ]]; then
            echo -e "  ${C_GREEN}5️⃣${C_RESET} ${C_WHITE}MTU Value:${C_RESET}        ${C_YELLOW}$MTU_VALUE bytes${C_RESET}"
        fi
        
        echo -e "\n${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        echo -e "${C_BOLD}${C_CYAN}  🔌 PORT CONFIGURATION${C_RESET}"
        echo -e "${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        echo -e "  ${C_GREEN}6️⃣${C_RESET} ${C_WHITE}Public Port:${C_RESET}      ${C_YELLOW}53 (UDP)${C_RESET} ${C_DIM}→ EDNS Proxy${C_RESET}"
        echo -e "  ${C_GREEN}7️⃣${C_RESET} ${C_WHITE}Internal Port:${C_RESET}   ${C_YELLOW}5300 (UDP)${C_RESET} ${C_DIM}→ DNSTT Server${C_RESET}"
        
        echo -e "\n${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        echo -e "${C_BOLD}${C_CYAN}  🚀 PERFORMANCE SETTINGS${C_RESET}"
        echo -e "${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        echo -e "  ${C_GREEN}8️⃣${C_RESET} ${C_WHITE}EDNS Sizes:${C_RESET}"
        echo -e "     ${C_DIM}•${C_RESET} External: ${C_YELLOW}512 bytes${C_RESET} ${C_DIM}(shown to DNS resolvers)${C_RESET}"
        echo -e "     ${C_DIM}•${C_RESET} Internal: ${C_YELLOW}1800 bytes${C_RESET} ${C_DIM}(high-speed tunnel)${C_RESET}"
        
        echo -e "\n${C_BOLD}${C_RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        echo -e "${C_BOLD}${C_RED}  ⚠️ CRITICAL: CLIENT DNS CONFIGURATION${C_RESET}"
        echo -e "${C_BOLD}${C_RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        if [[ -n "$NS_DOMAIN" ]]; then
            # Get VPS IP for display
            local vps_ip
            vps_ip=$(_detect_server_ip)
            
            echo -e "  ${C_RED}❌ DO NOT USE: 8.8.8.8 or any public DNS${C_RESET}"
            echo -e "  ${C_GREEN}✅ USE INSTEAD: ${C_YELLOW}$NS_DOMAIN${C_RESET} ${C_DIM}(or its IP address)${C_RESET}"
            echo ""
            echo -e "  ${C_BOLD}${C_YELLOW}📋 REQUIRED DNS RECORDS:${C_RESET}"
            if [[ -n "$vps_ip" ]]; then
                echo -e "    ${C_GREEN}A Record:${C_RESET} ${C_YELLOW}$NS_DOMAIN${C_RESET} → ${C_YELLOW}$vps_ip${C_RESET}"
                echo -e "    ${C_YELLOW}💡${C_RESET} ${C_WHITE}Ensure this A record exists at your DNS provider${C_RESET}"
            else
                echo -e "    ${C_GREEN}A Record:${C_RESET} ${C_YELLOW}$NS_DOMAIN${C_RESET} → ${C_YELLOW}[Your VPS IP Address]${C_RESET}"
                echo -e "    ${C_YELLOW}💡${C_RESET} ${C_WHITE}Create this A record at your DNS provider${C_RESET}"
            fi
            echo ""
            echo -e "  ${C_YELLOW}💡${C_RESET} ${C_WHITE}After creating the A record, configure your client DNS to use: ${C_YELLOW}$NS_DOMAIN${C_RESET}"
        else
            echo -e "  ${C_RED}❌ DO NOT USE: 8.8.8.8 or any public DNS${C_RESET}"
            echo -e "  ${C_YELLOW}⚠️${C_RESET} ${C_WHITE}Nameserver domain not configured. Please reconfigure DNSTT.${C_RESET}"
        fi
        
        if [[ "$FORWARD_DESC" == *"V2Ray"* ]]; then
            echo -e "\n${C_BOLD}${C_YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
            echo -e "${C_BOLD}${C_YELLOW}  ⚠️ ACTION REQUIRED${C_RESET}"
            echo -e "${C_BOLD}${C_YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
            echo -e "  ${C_YELLOW}💡${C_RESET} ${C_WHITE}Ensure a V2Ray service (VLESS/VMESS/Trojan) is listening on port $DEFAULT_V2RAY_PORT (no TLS)${C_RESET}"
        elif [[ "$FORWARD_DESC" == *"SSH"* ]]; then
            echo -e "\n${C_BOLD}${C_YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
            echo -e "${C_BOLD}${C_YELLOW}  ⚠️ ACTION REQUIRED${C_RESET}"
            echo -e "${C_BOLD}${C_YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
            echo -e "  ${C_YELLOW}💡${C_RESET} ${C_WHITE}Configure your SSH client to use the DNS tunnel${C_RESET}"
        fi
        
        # Display user accounts with credentials for DNSTT connection
        echo -e "\n${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        echo -e "${C_BOLD}${C_CYAN}  👤 USER ACCOUNTS FOR DNSTT CONNECTION${C_RESET}"
        echo -e "${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        
        if [[ -f "$DB_FILE" ]] && [[ -s "$DB_FILE" ]]; then
            local user_count=0
            while IFS=: read -r user pass expiry limit; do
                [[ -z "$user" || "$user" == \#* ]] && continue
                
                # Check if user account is active (not locked and not expired)
                local user_status=""
                local status_color="$C_GREEN"
                local account_status="✅ Active"
                
                if ! id "$user" &>/dev/null; then
                    account_status="❌ Not Found"
                    status_color="$C_RED"
                elif passwd -S "$user" 2>/dev/null | grep -q " L "; then
                    account_status="🔒 Locked"
                    status_color="$C_YELLOW"
                else
                    # Check expiry
                    local expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
                    local current_ts=$(date +%s)
                    if [[ $expiry_ts -lt $current_ts && $expiry_ts -ne 0 ]]; then
                        account_status="⏰ Expired"
                        status_color="$C_RED"
                    fi
                fi
                
                user_count=$((user_count + 1))
                echo -e "\n  ${C_GREEN}${user_count}️⃣${C_RESET} ${C_WHITE}Username:${C_RESET}     ${C_YELLOW}$user${C_RESET}"
                echo -e "     ${C_WHITE}Password:${C_RESET}     ${C_YELLOW}$pass${C_RESET}"
                echo -e "     ${C_WHITE}Expires:${C_RESET}      ${C_YELLOW}$expiry${C_RESET}"
                echo -e "     ${C_WHITE}Status:${C_RESET}      ${status_color}$account_status${C_RESET}"
                
                if [[ "$FORWARD_DESC" == *"SSH"* ]]; then
                    echo -e "     ${C_DIM}💡 Use these credentials with DNSTT → SSH tunnel${C_RESET}"
                fi
            done < <(sort "$DB_FILE")
            
            if [[ $user_count -eq 0 ]]; then
                echo -e "  ${C_YELLOW}⚠️ No users found in database. Create users first to use DNSTT.${C_RESET}"
            else
                echo -e "\n  ${C_DIM}💡 Total users: ${C_YELLOW}$user_count${C_RESET}"
            fi
        else
            echo -e "  ${C_YELLOW}⚠️ No user database found. Create users first to use DNSTT.${C_RESET}"
            echo -e "  ${C_DIM}💡 Use option 1 in main menu to create new users${C_RESET}"
        fi
        
        echo -e "\n${C_DIM}${C_ITALIC}💼 Use these details in your client configuration${C_RESET}"
    else
        echo -e "\n${C_YELLOW}⚠️ DNSTT configuration file not found. Details are unavailable.${C_RESET}"
    fi
}

check_dnstt_diagnostics() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🔍 DNSTT Diagnostics Check ---${C_RESET}"
    echo ""
    
    # Check NS "managed by" condition
    local SUB="ns3.voltrontechtx.shop"
    local EXPECTED="idd.voltrontechtx.shop."
    
    echo -e "${C_BOLD}${C_CYAN}[1] Checking NS Condition${C_RESET}"
    echo -e "${C_DIM}  Subdomain: $SUB${C_RESET}"
    echo -e "${C_DIM}  Expected NS: $EXPECTED${C_RESET}"
    
    local ns_result
    ns_result=$(dig +short NS "$SUB" 2>/dev/null || true)
    
    # Check if expected NS is in the result (handle multiple NS records)
    if echo "$ns_result" | grep -qxF "$EXPECTED"; then
        echo -e "${C_GREEN}  ✅ [OK] NS condition met: $SUB -> $EXPECTED${C_RESET}"
    else
        echo -e "${C_YELLOW}  ⚠️  [WARN] NS not matching yet. Current:${C_RESET}"
        if [[ -n "$ns_result" ]]; then
            while IFS= read -r line; do
                [[ -n "$line" ]] && echo -e "${C_YELLOW}  $line${C_RESET}"
            done <<< "$ns_result"
        else
            echo -e "${C_YELLOW}  (No NS records found)${C_RESET}"
        fi
    fi
    
    echo ""
    echo -e "${C_BOLD}${C_CYAN}[2] Checking Listening Ports${C_RESET}"
    
    # Check DNS port 53 (UDP)
    echo -e "${C_DIM}  DNS :53/udp or tcp (authoritative resolver)${C_RESET}"
    local dns_udp
    dns_udp=$(sudo ss -lunp 2>/dev/null | grep -E ':53\s' || true)
    if [[ -n "$dns_udp" ]]; then
        echo -e "${C_GREEN}  ✅ DNS UDP:53 is listening${C_RESET}"
        local first_line
        first_line=$(echo "$dns_udp" | head -n1)
        echo -e "${C_DIM}    $first_line${C_RESET}"
    else
        echo -e "${C_YELLOW}  ⚠️  [WARN] nothing on udp:53${C_RESET}"
    fi
    
    # Check DNS port 53 (TCP)
    local dns_tcp
    dns_tcp=$(sudo ss -lntp 2>/dev/null | grep -E ':53\s' || true)
    if [[ -n "$dns_tcp" ]]; then
        echo -e "${C_GREEN}  ✅ DNS TCP:53 is listening${C_RESET}"
        local first_line_tcp
        first_line_tcp=$(echo "$dns_tcp" | head -n1)
        echo -e "${C_DIM}    $first_line_tcp${C_RESET}"
    else
        echo -e "${C_YELLOW}  ⚠️  [WARN] nothing on tcp:53${C_RESET}"
    fi
    
    # Check DNSTT port 5300 (UDP)
    echo -e "${C_DIM}  DNSTT :5300/udp${C_RESET}"
    local dnstt_listen
    dnstt_listen=$(sudo ss -lunp 2>/dev/null | grep -E ':5300\s' || true)
    if [[ -n "$dnstt_listen" ]]; then
        echo -e "${C_GREEN}  ✅ DNSTT UDP:5300 is listening${C_RESET}"
        local first_line_dnstt
        first_line_dnstt=$(echo "$dnstt_listen" | head -n1)
        echo -e "${C_DIM}    $first_line_dnstt${C_RESET}"
    else
        echo -e "${C_RED}  ❌ [FAIL] dnstt-server not listening on udp:5300${C_RESET}"
    fi
    
    # Check SSH port 22 (TCP)
    echo -e "${C_DIM}  SSH :22/tcp${C_RESET}"
    local ssh_listen
    ssh_listen=$(sudo ss -lntp 2>/dev/null | grep -E ':22\s' || true)
    if [[ -n "$ssh_listen" ]]; then
        echo -e "${C_GREEN}  ✅ SSH TCP:22 is listening${C_RESET}"
        local first_line_ssh
        first_line_ssh=$(echo "$ssh_listen" | head -n1)
        echo -e "${C_DIM}    $first_line_ssh${C_RESET}"
    else
        echo -e "${C_RED}  ❌ [FAIL] sshd not listening on tcp:22${C_RESET}"
    fi
    
    echo ""
}

install_dnstt() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 📡 DNSTT (DNS Tunnel) Management ---${C_RESET}"
    
    # Check if DNSTT is already installed (either service file exists)
    if [ -f "$DNSTT_SERVICE_FILE" ] || [ -f "$DNSTT_EDNS_SERVICE" ] || [ -f "$DNSTT_BINARY" ] || [ -f "$DNSTT_CONFIG_FILE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ DNSTT appears to be already installed.${C_RESET}"
        show_dnstt_details
        
        # Check service status
        echo -e "\n${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        echo -e "${C_BOLD}${C_BLUE}  📊 SERVICE STATUS${C_RESET}"
        echo -e "${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        local dnstt_server_status="❌ INACTIVE"
        local edns_proxy_status="❌ INACTIVE"
        local dnstt_server_emoji="🔴"
        local edns_proxy_emoji="🔴"
        local needs_start=false
        
        if systemctl is-active --quiet dnstt.service 2>/dev/null; then
            dnstt_server_status="✅ ACTIVE"
            dnstt_server_emoji="🟢"
        elif [ -f "$DNSTT_SERVICE_FILE" ]; then
            needs_start=true
            dnstt_server_status="⚠️ INSTALLED BUT NOT RUNNING"
            dnstt_server_emoji="🟡"
        fi
        
        if [ -f "$DNSTT_EDNS_SERVICE" ]; then
            if systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
                edns_proxy_status="✅ ACTIVE"
                edns_proxy_emoji="🟢"
            else
                needs_start=true
                edns_proxy_status="⚠️ INSTALLED BUT NOT RUNNING"
                edns_proxy_emoji="🟡"
            fi
        else
            edns_proxy_status="❌ NOT INSTALLED"
            edns_proxy_emoji="🔴"
        fi
        
        echo -e "  ${C_GREEN}1️⃣${C_RESET} ${C_WHITE}DNSTT Server:${C_RESET}     ${dnstt_server_emoji} ${dnstt_server_status} ${C_DIM}(port 5300)${C_RESET}"
        echo -e "  ${C_GREEN}2️⃣${C_RESET} ${C_WHITE}EDNS Proxy:${C_RESET}       ${edns_proxy_emoji} ${edns_proxy_status} ${C_DIM}(port 53)${C_RESET}"
        
        # Offer to start services if they're installed but not running
        if [[ "$needs_start" == "true" ]]; then
            echo -e "\n${C_BOLD}${C_YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
            echo -e "${C_BOLD}${C_YELLOW}  ⚠️ SERVICES INSTALLED BUT NOT RUNNING${C_RESET}"
            echo -e "${C_BOLD}${C_YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
            echo -e "${C_YELLOW}DNSTT services are installed but not active. Would you like to start them now?${C_RESET}"
            read -p "$(echo -e ${C_PROMPT}"👉 Start DNSTT services? (y/n): "${C_RESET})" start_choice
            if [[ "$start_choice" == "y" || "$start_choice" == "Y" ]]; then
                echo -e "\n${C_BLUE}🚀 Starting DNSTT services...${C_RESET}"
                if [ -f "$DNSTT_SERVICE_FILE" ] && ! systemctl is-active --quiet dnstt.service 2>/dev/null; then
                    systemctl start dnstt.service 2>/dev/null
                    sleep 2
                    if systemctl is-active --quiet dnstt.service 2>/dev/null; then
                        echo -e "${C_GREEN}✅ DNSTT server started${C_RESET}"
                    else
                        echo -e "${C_YELLOW}⚠️ DNSTT server failed to start. Check logs: journalctl -u dnstt.service${C_RESET}"
                    fi
                fi
                if [ -f "$DNSTT_EDNS_SERVICE" ] && ! systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
                    systemctl start dnstt-edns-proxy.service 2>/dev/null
                    sleep 2
                    if systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
                        echo -e "${C_GREEN}✅ DNSTT EDNS proxy started${C_RESET}"
                    else
                        echo -e "${C_YELLOW}⚠️ DNSTT EDNS proxy failed to start. Check logs: journalctl -u dnstt-edns-proxy.service${C_RESET}"
                    fi
                fi
                # Enable DNS forwarding
                enable_dns_forwarding
                sleep 2
            fi
        fi
        
        # Check ports - improved detection
        echo -e "\n${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        echo -e "${C_BOLD}${C_BLUE}  🔌 PORT STATUS${C_RESET}"
        echo -e "${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        local port53_status="❌ NOT LISTENING"
        local port5300_status="❌ NOT LISTENING"
        local port53_emoji="🔴"
        local port5300_emoji="🔴"
        local port53_process=""
        local port5300_process=""
        
        # Check port 53 - try multiple methods for better detection
        if ss -lunp 2>/dev/null | grep -qE ':(53|:53)\s'; then
            port53_status="✅ LISTENING"
            port53_emoji="🟢"
            # Try to get process name
            port53_process=$(ss -lunp 2>/dev/null | grep -E ':(53|:53)\s' | grep -oP 'pid=\K[0-9]+' | head -n 1)
            if [[ -n "$port53_process" ]]; then
                port53_process=$(ps -p "$port53_process" -o comm= 2>/dev/null | head -n 1)
                if [[ -n "$port53_process" ]]; then
                    port53_status="✅ LISTENING (${port53_process})"
                fi
            fi
        elif netstat -lunp 2>/dev/null | grep -qE ':(53|:53)\s'; then
            port53_status="✅ LISTENING"
            port53_emoji="🟢"
        elif lsof -i UDP:53 2>/dev/null | grep -q LISTEN; then
            port53_status="✅ LISTENING"
            port53_emoji="🟢"
        fi
        
        # Check port 5300 - try multiple methods for better detection
        if ss -lunp 2>/dev/null | grep -qE ':(5300|:5300)\s'; then
            port5300_status="✅ LISTENING"
            port5300_emoji="🟢"
            # Try to get process name
            port5300_process=$(ss -lunp 2>/dev/null | grep -E ':(5300|:5300)\s' | grep -oP 'pid=\K[0-9]+' | head -n 1)
            if [[ -n "$port5300_process" ]]; then
                port5300_process=$(ps -p "$port5300_process" -o comm= 2>/dev/null | head -n 1)
                if [[ -n "$port5300_process" ]]; then
                    port5300_status="✅ LISTENING (${port5300_process})"
                fi
            fi
        elif netstat -lunp 2>/dev/null | grep -qE ':(5300|:5300)\s'; then
            port5300_status="✅ LISTENING"
            port5300_emoji="🟢"
        elif lsof -i UDP:5300 2>/dev/null | grep -q LISTEN; then
            port5300_status="✅ LISTENING"
            port5300_emoji="🟢"
        fi
        
        echo -e "  ${C_GREEN}3️⃣${C_RESET} ${C_WHITE}Port 53 (UDP):${C_RESET}   ${port53_emoji} ${port53_status}"
        echo -e "  ${C_GREEN}4️⃣${C_RESET} ${C_WHITE}Port 5300 (UDP):${C_RESET} ${port5300_emoji} ${port5300_status}"
        
        # If services are active but ports not listening, show warning
        if [[ "$edns_proxy_status" == "✅ ACTIVE" ]] && [[ "$port53_emoji" == "🔴" ]]; then
            echo -e "     ${C_YELLOW}⚠️${C_RESET} ${C_DIM}Service active but port not detected. Service may need restart.${C_RESET}"
        fi
        if [[ "$dnstt_server_status" == "✅ ACTIVE" ]] && [[ "$port5300_emoji" == "🔴" ]]; then
            echo -e "     ${C_YELLOW}⚠️${C_RESET} ${C_DIM}Service active but port not detected. Service may need restart.${C_RESET}"
        fi
        
        # If services are not active OR ports not listening, offer to restart
        if [[ "$dnstt_server_status" == "❌ INACTIVE" ]] || [[ "$edns_proxy_status" == "❌ INACTIVE" ]] || [[ "$port53_emoji" == "🔴" ]] || [[ "$port5300_emoji" == "🔴" ]]; then
            echo -e "\n${C_BOLD}${C_YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
            echo -e "${C_BOLD}${C_YELLOW}  ⚠️ WARNING: DNS SERVER NOT WORKING${C_RESET}"
            echo -e "${C_BOLD}${C_YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
            
            if [[ "$dnstt_server_status" == "❌ INACTIVE" ]] || [[ "$edns_proxy_status" == "❌ INACTIVE" ]]; then
                echo -e "${C_YELLOW}One or more DNSTT services are not running.${C_RESET}"
            fi
            
            if [[ "$port53_emoji" == "🔴" ]] || [[ "$port5300_emoji" == "🔴" ]]; then
                echo -e "${C_YELLOW}One or more required ports are not listening.${C_RESET}"
                if [[ "$port53_emoji" == "🔴" ]]; then
                    echo -e "${C_DIM}  • Port 53 (EDNS Proxy) is not listening${C_RESET}"
                fi
                if [[ "$port5300_emoji" == "🔴" ]]; then
                    echo -e "${C_DIM}  • Port 5300 (DNSTT Server) is not listening${C_RESET}"
                fi
            fi
            
            echo -e "\n${C_BLUE}What would you like to do?${C_RESET}"
            echo -e "  ${C_GREEN}1)${C_RESET} 🔄 Restart all DNSTT services"
            echo -e "  ${C_GREEN}2)${C_RESET} 📋 View service logs"
            echo -e "  ${C_GREEN}3)${C_RESET} 🔍 Run DNSTT diagnostics (NS check + ports)"
            echo -e "  ${C_GREEN}4)${C_RESET} ⏭️  Continue (do nothing)"
            read -p "$(echo -e ${C_PROMPT}"👉 Select an option [1]: "${C_RESET})" restart_choice
            restart_choice=${restart_choice:-1}
            
            case $restart_choice in
                1)
                    echo -e "\n${C_BLUE}🔄 Starting/Restarting DNSTT services...${C_RESET}"
                    
                    # Start/restart DNSTT server
                    if [ -f "$DNSTT_SERVICE_FILE" ]; then
                        if systemctl is-active --quiet dnstt.service 2>/dev/null; then
                            systemctl restart dnstt.service 2>/dev/null
                            echo -e "${C_BLUE}  ↻ Restarting DNSTT server...${C_RESET}"
                        else
                            systemctl start dnstt.service 2>/dev/null
                            systemctl enable dnstt.service 2>/dev/null
                            echo -e "${C_BLUE}  ▶️ Starting DNSTT server...${C_RESET}"
                        fi
                        sleep 2
                        if systemctl is-active --quiet dnstt.service 2>/dev/null; then
                            echo -e "${C_GREEN}✅ DNSTT server is now active.${C_RESET}"
                        else
                            echo -e "${C_RED}❌ Failed to start DNSTT server.${C_RESET}"
                            echo -e "${C_YELLOW}  Showing last 15 lines of logs:${C_RESET}"
                            journalctl -u dnstt.service -n 15 --no-pager
                        fi
                    else
                        echo -e "${C_YELLOW}⚠️ DNSTT service file not found.${C_RESET}"
                    fi
                    
                    sleep 1
                    
                    # Start/restart EDNS proxy
                    if [ -f "$DNSTT_EDNS_SERVICE" ]; then
                        if systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
                            systemctl restart dnstt-edns-proxy.service 2>/dev/null
                            echo -e "${C_BLUE}  ↻ Restarting EDNS proxy...${C_RESET}"
                        else
                            systemctl start dnstt-edns-proxy.service 2>/dev/null
                            systemctl enable dnstt-edns-proxy.service 2>/dev/null
                            echo -e "${C_BLUE}  ▶️ Starting EDNS proxy...${C_RESET}"
                        fi
                        sleep 2
                        if systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
                            echo -e "${C_GREEN}✅ EDNS proxy is now active.${C_RESET}"
                        else
                            echo -e "${C_RED}❌ Failed to start EDNS proxy.${C_RESET}"
                            echo -e "${C_YELLOW}  Showing last 15 lines of logs:${C_RESET}"
                            journalctl -u dnstt-edns-proxy.service -n 15 --no-pager
                        fi
                    else
                        echo -e "${C_YELLOW}⚠️ EDNS proxy service file not found.${C_RESET}"
                    fi
                    
                    # Enable DNS forwarding
                    enable_dns_forwarding
                    
                    sleep 2
                    echo -e "\n${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
                    echo -e "${C_BOLD}${C_BLUE}  📊 UPDATED STATUS${C_RESET}"
                    echo -e "${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
                    if systemctl is-active --quiet dnstt.service 2>/dev/null; then
                        echo -e "  ${C_GREEN}1️⃣${C_RESET} ${C_WHITE}DNSTT Server:${C_RESET}     🟢 ✅ ACTIVE"
                    else
                        echo -e "  ${C_GREEN}1️⃣${C_RESET} ${C_WHITE}DNSTT Server:${C_RESET}     🔴 ❌ INACTIVE"
                        echo -e "     ${C_YELLOW}💡${C_RESET} ${C_DIM}Check logs: journalctl -u dnstt.service -n 20${C_RESET}"
                    fi
                    
                    if [ -f "$DNSTT_EDNS_SERVICE" ] && systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
                        echo -e "  ${C_GREEN}2️⃣${C_RESET} ${C_WHITE}EDNS Proxy:${C_RESET}       🟢 ✅ ACTIVE"
                    else
                        echo -e "  ${C_GREEN}2️⃣${C_RESET} ${C_WHITE}EDNS Proxy:${C_RESET}       🔴 ❌ INACTIVE"
                        echo -e "     ${C_YELLOW}💡${C_RESET} ${C_DIM}Check logs: journalctl -u dnstt-edns-proxy.service -n 20${C_RESET}"
                    fi
                    ;;
                2)
                    echo -e "\n${C_BLUE}📋 DNSTT Server Logs (last 20 lines):${C_RESET}"
                    journalctl -u dnstt.service -n 20 --no-pager
                    if [ -f "$DNSTT_EDNS_SERVICE" ]; then
                        echo -e "\n${C_BLUE}📋 EDNS Proxy Logs (last 20 lines):${C_RESET}"
                        journalctl -u dnstt-edns-proxy.service -n 20 --no-pager
                    fi
                    ;;
                3)
                    check_dnstt_diagnostics
                    press_enter
                    ;;
                4)
                    echo -e "${C_DIM}Skipping restart...${C_RESET}"
                    ;;
            esac
        else
            echo -e "\n${C_BOLD}${C_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
            echo -e "${C_BOLD}${C_GREEN}  ✅ ALL SERVICES RUNNING CORRECTLY${C_RESET}"
            echo -e "${C_BOLD}${C_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
            echo -e "  ${C_GREEN}🎉${C_RESET} ${C_WHITE}All DNSTT services are active and ports are listening!${C_RESET}"
            
            # Comprehensive view menu
            echo -e "\n${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
            echo -e "${C_BOLD}${C_BLUE}  📋 DNSTT MANAGEMENT OPTIONS${C_RESET}"
            echo -e "${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
            echo -e "  ${C_GREEN}1)${C_RESET} 🔄 Restart all DNSTT services"
            echo -e "  ${C_GREEN}2)${C_RESET} 📋 View service logs"
            echo -e "  ${C_GREEN}3)${C_RESET} 🔍 Run DNSTT diagnostics (NS check + ports)"
            echo -e "  ${C_GREEN}4)${C_RESET} 🔐 Verify Public Key"
            echo -e "  ${C_GREEN}5)${C_RESET} ⏭️  Return to menu"
            read -p "$(echo -e ${C_PROMPT}"👉 Select an option [5]: "${C_RESET})" view_choice
            view_choice=${view_choice:-5}
            
            case $view_choice in
                1)
                    echo -e "\n${C_BLUE}🔄 Starting/Restarting DNSTT services...${C_RESET}"
                    
                    # Start/restart DNSTT server
                    if [ -f "$DNSTT_SERVICE_FILE" ]; then
                        if systemctl is-active --quiet dnstt.service 2>/dev/null; then
                            systemctl restart dnstt.service 2>/dev/null
                            echo -e "${C_BLUE}  ↻ Restarting DNSTT server...${C_RESET}"
                        else
                            systemctl start dnstt.service 2>/dev/null
                            systemctl enable dnstt.service 2>/dev/null
                            echo -e "${C_BLUE}  ▶️ Starting DNSTT server...${C_RESET}"
                        fi
                        sleep 2
                        if systemctl is-active --quiet dnstt.service 2>/dev/null; then
                            echo -e "${C_GREEN}✅ DNSTT server is now active.${C_RESET}"
                        else
                            echo -e "${C_RED}❌ Failed to start DNSTT server.${C_RESET}"
                            echo -e "${C_YELLOW}  Showing last 15 lines of logs:${C_RESET}"
                            journalctl -u dnstt.service -n 15 --no-pager
                        fi
                    else
                        echo -e "${C_YELLOW}⚠️ DNSTT service file not found.${C_RESET}"
                    fi
                    
                    sleep 1
                    
                    # Start/restart EDNS proxy
                    if [ -f "$DNSTT_EDNS_SERVICE" ]; then
                        if systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
                            systemctl restart dnstt-edns-proxy.service 2>/dev/null
                            echo -e "${C_BLUE}  ↻ Restarting EDNS proxy...${C_RESET}"
                        else
                            systemctl start dnstt-edns-proxy.service 2>/dev/null
                            systemctl enable dnstt-edns-proxy.service 2>/dev/null
                            echo -e "${C_BLUE}  ▶️ Starting EDNS proxy...${C_RESET}"
                        fi
                        sleep 2
                        if systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
                            echo -e "${C_GREEN}✅ EDNS proxy is now active.${C_RESET}"
                        else
                            echo -e "${C_RED}❌ Failed to start EDNS proxy.${C_RESET}"
                            echo -e "${C_YELLOW}  Showing last 15 lines of logs:${C_RESET}"
                            journalctl -u dnstt-edns-proxy.service -n 15 --no-pager
                        fi
                    else
                        echo -e "${C_YELLOW}⚠️ EDNS proxy service file not found.${C_RESET}"
                    fi
                    
                    # Enable DNS forwarding
                    enable_dns_forwarding
                    
                    sleep 2
                    echo -e "\n${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
                    echo -e "${C_BOLD}${C_BLUE}  📊 UPDATED STATUS${C_RESET}"
                    echo -e "${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
                    if systemctl is-active --quiet dnstt.service 2>/dev/null; then
                        echo -e "  ${C_GREEN}1️⃣${C_RESET} ${C_WHITE}DNSTT Server:${C_RESET}     🟢 ✅ ACTIVE"
                    else
                        echo -e "  ${C_GREEN}1️⃣${C_RESET} ${C_WHITE}DNSTT Server:${C_RESET}     🔴 ❌ INACTIVE"
                        echo -e "     ${C_YELLOW}💡${C_RESET} ${C_DIM}Check logs: journalctl -u dnstt.service -n 20${C_RESET}"
                    fi
                    
                    if [ -f "$DNSTT_EDNS_SERVICE" ] && systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
                        echo -e "  ${C_GREEN}2️⃣${C_RESET} ${C_WHITE}EDNS Proxy:${C_RESET}       🟢 ✅ ACTIVE"
                    else
                        echo -e "  ${C_GREEN}2️⃣${C_RESET} ${C_WHITE}EDNS Proxy:${C_RESET}       🔴 ❌ INACTIVE"
                        echo -e "     ${C_YELLOW}💡${C_RESET} ${C_DIM}Check logs: journalctl -u dnstt-edns-proxy.service -n 20${C_RESET}"
                    fi
                    press_enter
                    ;;
                2)
                    echo -e "\n${C_BLUE}📋 DNSTT Server Logs (last 20 lines):${C_RESET}"
                    journalctl -u dnstt.service -n 20 --no-pager
                    if [ -f "$DNSTT_EDNS_SERVICE" ]; then
                        echo -e "\n${C_BLUE}📋 EDNS Proxy Logs (last 20 lines):${C_RESET}"
                        journalctl -u dnstt-edns-proxy.service -n 20 --no-pager
                    fi
                    press_enter
                    ;;
                3)
                    check_dnstt_diagnostics
                    press_enter
                    ;;
                4)
                    verify_dnstt_keys
                    press_enter
                    ;;
                5)
                    ;;
                *)
                    ;;
            esac
        fi
        
        return
    fi
    
    # --- FIX: Force release of Port 53 / Disable systemd-resolved ---
    echo -e "${C_GREEN}⚙️ Forcing release of Port 53 (stopping systemd-resolved)...${C_RESET}"
    
    # Stop systemd-resolved
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        systemctl stop systemd-resolved 2>/dev/null
        sleep 1
    fi
    
    # Disable systemd-resolved to prevent restart
    if systemctl is-enabled --quiet systemd-resolved 2>/dev/null; then
        systemctl disable systemd-resolved 2>/dev/null
        sleep 1
    fi
    
    # Mask systemd-resolved to prevent any automatic start
    systemctl mask systemd-resolved 2>/dev/null
    
    # Handle resolv.conf - Use 127.0.0.1 for DNSTT to work properly
    # The EDNS proxy on port 53 will forward regular DNS queries to external DNS servers
    chattr -i /etc/resolv.conf 2>/dev/null
    if [ -L /etc/resolv.conf ]; then
        rm -f /etc/resolv.conf
    fi
    rm -f /etc/resolv.conf
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    echo "nameserver $DNS_PRIMARY" >> /etc/resolv.conf
    echo "nameserver $DNS_SECONDARY" >> /etc/resolv.conf
    chattr +i /etc/resolv.conf 2>/dev/null
    echo -e "${C_GREEN}✅ Configured /etc/resolv.conf to use localhost (127.0.0.1) for DNS forwarding${C_RESET}"
    
    # Kill any remaining systemd-resolved processes
    pkill -9 systemd-resolved 2>/dev/null
    sleep 2
    
    echo -e "${C_GREEN}✅ Port 53 preparation completed.${C_RESET}"
    # ----------------------------------------------------------------
    
    echo -e "\n${C_BLUE}🔎 Checking if port 53 (UDP) is available...${C_RESET}"
    if ss -lunp | grep -q ':53\s'; then
        local port53_pid
        port53_pid=$(ss -lunp | grep ':53\s' | grep -oP 'pid=\K[0-9]+' | head -n 1)
        local port53_process
        if [[ -n "$port53_pid" ]]; then
            port53_process=$(ps -p "$port53_pid" -o comm= 2>/dev/null)
        fi
        if [[ "$port53_process" == "systemd-resolve" ]]; then
            echo -e "${C_YELLOW}⚠️ Warning: Port 53 is in use by 'systemd-resolved'.${C_RESET}"
            echo -e "${C_YELLOW}This is the system's DNS stub resolver. It must be disabled to run DNSTT.${C_RESET}"
            read -p "👉 Allow the script to automatically disable it and reconfigure DNS? (y/n): " resolve_confirm
            if [[ "$resolve_confirm" == "y" || "$resolve_confirm" == "Y" ]]; then
                echo -e "${C_GREEN}⚙️ Stopping and disabling systemd-resolved to free port 53...${C_RESET}"
                systemctl stop systemd-resolved
                systemctl disable systemd-resolved
                systemctl mask systemd-resolved 2>/dev/null
                chattr -i /etc/resolv.conf &>/dev/null
                rm -f /etc/resolv.conf
                echo "nameserver 127.0.0.1" > /etc/resolv.conf
                echo "nameserver $DNS_PRIMARY" >> /etc/resolv.conf
                echo "nameserver $DNS_SECONDARY" >> /etc/resolv.conf
                chattr +i /etc/resolv.conf
                echo -e "${C_GREEN}✅ Port 53 has been freed and DNS configured for DNSTT (127.0.0.1).${C_RESET}"
            else
                echo -e "${C_RED}❌ Cannot proceed without freeing port 53. Aborting.${C_RESET}"
                return
            fi
        else
            check_and_free_ports "53" || return
        fi
    else
        echo -e "${C_GREEN}✅ Port 53 (UDP) is free to use.${C_RESET}"
    fi

    check_and_open_firewall_port 53 udp || return
    
    echo -e "\n${C_BLUE}🔎 Checking if port 5300 (UDP) is available...${C_RESET}"
    if ss -lunp | grep -q ':5300\s'; then
        echo -e "${C_YELLOW}⚠️ Warning: Port 5300 is already in use.${C_RESET}"
        check_and_free_ports "5300" || return
    else
        echo -e "${C_GREEN}✅ Port 5300 (UDP) is free to use.${C_RESET}"
    fi
    check_and_open_firewall_port 5300 udp || return

    # Fixed forward target: SSH on 127.0.0.1:22
    local forward_port="22"
    local forward_desc="SSH (port 22)"
    local FORWARD_TARGET="127.0.0.1:22"
    echo -e "${C_GREEN}ℹ️ DNSTT will forward to SSH on 127.0.0.1:22 (fixed configuration).${C_RESET}"
    
    local NS_DOMAIN=""
    local TUNNEL_DOMAIN=""
    local DNSTT_RECORDS_MANAGED="false"
    local NS_SUBDOMAIN=""
    local TUNNEL_SUBDOMAIN=""
    local HAS_IPV6="false"

    echo -e "${C_BLUE}📋 DNSTT Nameserver Configuration${C_RESET}"
    echo -e "${C_YELLOW}💡 Understanding DNS Records: NS records must point to HOSTNAMES, not IP addresses${C_RESET}"
    echo ""
    
    # Detect VPS information
    local vps_ip
    local vps_hostname
    vps_ip=$(_detect_server_ip)
    vps_hostname=$(_detect_server_hostname)
    
    echo -e "${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_BOLD}${C_CYAN}  📡 VPS SERVER INFORMATION${C_RESET}"
    echo -e "${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    if [[ -n "$vps_hostname" ]]; then
        echo -e "  ${C_GREEN}Hostname:${C_RESET} ${C_YELLOW}$vps_hostname${C_RESET}"
    fi
    if [[ -n "$vps_ip" ]]; then
        echo -e "  ${C_GREEN}IP Address:${C_RESET} ${C_YELLOW}$vps_ip${C_RESET}"
    else
        echo -e "  ${C_YELLOW}⚠️${C_RESET} ${C_RED}Could not detect server IP address${C_RESET}"
    fi
    echo ""
    
    echo -e "${C_BOLD}${C_YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_BOLD}${C_YELLOW}  📝 DNS CONFIGURATION REQUIREMENTS${C_RESET}"
    echo -e "${C_BOLD}${C_YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "  ${C_WHITE}1.${C_RESET} You need to create a ${C_GREEN}HOSTNAME${C_RESET} (e.g., ns1.yourdomain.com)"
    echo -e "  ${C_WHITE}2.${C_RESET} Create an ${C_GREEN}A record${C_RESET}: ${C_YELLOW}ns1.yourdomain.com → $vps_ip${C_RESET}"
    echo -e "  ${C_WHITE}3.${C_RESET} Point your ${C_GREEN}NS record${C_RESET} to that hostname"
    echo -e "  ${C_RED}❌${C_RESET} ${C_RED}WRONG: NS record pointing directly to IP address${C_RESET}"
    echo -e "  ${C_GREEN}✅${C_RESET} ${C_GREEN}CORRECT: NS record pointing to hostname (which has A record → IP)${C_RESET}"
    echo ""
    
    local ns_domain_valid=false
    while [[ "$ns_domain_valid" == "false" ]]; do
        read -p "👉 Enter your nameserver HOSTNAME (e.g., ns1.yourdomain.com, NOT an IP): " NS_DOMAIN
        
        # Validate the nameserver domain
        local validation_result
        validation_result=$(_validate_nameserver_domain "$NS_DOMAIN" 2>&1)
        
        if [[ $? -eq 0 ]]; then
            ns_domain_valid=true
            echo -e "${C_GREEN}✅ Nameserver hostname validated: $NS_DOMAIN${C_RESET}"
            
            # Show what DNS records need to be created
            echo ""
            echo -e "${C_BOLD}${C_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
            echo -e "${C_BOLD}${C_GREEN}  ✅ REQUIRED DNS RECORDS TO CREATE${C_RESET}"
            echo -e "${C_BOLD}${C_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
            if [[ -n "$vps_ip" ]]; then
                echo -e "  ${C_GREEN}A Record:${C_RESET}"
                echo -e "    ${C_YELLOW}$NS_DOMAIN${C_RESET} → ${C_YELLOW}$vps_ip${C_RESET}"
                echo ""
                echo -e "  ${C_YELLOW}💡${C_RESET} ${C_WHITE}After creating the A record above, configure your domain's NS record to point to:${C_RESET}"
                echo -e "    ${C_YELLOW}$NS_DOMAIN${C_RESET}"
            else
                echo -e "  ${C_YELLOW}⚠️${C_RESET} ${C_RED}Could not detect VPS IP. You need to manually create:${C_RESET}"
                echo -e "    ${C_GREEN}A Record:${C_RESET} ${C_YELLOW}$NS_DOMAIN${C_RESET} → ${C_YELLOW}[Your VPS IP Address]${C_RESET}"
            fi
        else
            echo -e "${C_RED}❌ Validation failed:${C_RESET}"
            echo -e "${C_RED}$validation_result${C_RESET}"
            echo ""
        fi
    done
    
    # Fixed tunnel domain: idd.voltrontechtx.shop
    TUNNEL_DOMAIN="idd.voltrontechtx.shop"
    echo -e "${C_GREEN}ℹ️ Using fixed tunnel domain: $TUNNEL_DOMAIN${C_RESET}"
    
    # Fixed MTU: 512 (not configurable)
    local mtu_value="512"
    local mtu_string=" -mtu 512"
    echo -e "${C_GREEN}ℹ️ Using fixed MTU: 512${C_RESET}"

    echo -e "\n${C_BLUE}📥 Downloading pre-compiled DNSTT server binary...${C_RESET}"
    local arch
    arch=$(uname -m)
    local binary_url=""
    if [[ "$arch" == "x86_64" ]]; then
        binary_url="https://dnstt.network/dnstt-server-linux-amd64"
        echo -e "${C_BLUE}ℹ️ Detected x86_64 (amd64) architecture.${C_RESET}"
    elif [[ "$arch" == "aarch64" || "$arch" == "arm64" ]]; then
        binary_url="https://dnstt.network/dnstt-server-linux-arm64"
        echo -e "${C_BLUE}ℹ️ Detected ARM64 architecture.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ Unsupported architecture: $arch. Cannot install DNSTT.${C_RESET}"
        return
    fi
    
    if ! curl -sL "$binary_url" -o "$DNSTT_BINARY"; then
        echo -e "\n${C_RED}❌ Failed to download the DNSTT binary from $binary_url${C_RESET}"
        echo -e "${C_YELLOW}ℹ️ Please check your internet connection and try again.${C_RESET}"
        return 1
    fi
    if [[ ! -f "$DNSTT_BINARY" ]] || [[ ! -s "$DNSTT_BINARY" ]]; then
        echo -e "\n${C_RED}❌ Downloaded file is empty or missing.${C_RESET}"
        return 1
    fi
    chmod +x "$DNSTT_BINARY"
    
    # Use /root/dnstt/ as keys directory (as specified)
    DNSTT_KEYS_DIR="/root/dnstt"
    
    # Copy binary to /root/dnstt/ for service file and ensure keys directory exists
    mkdir -p "$DNSTT_KEYS_DIR" || {
        echo -e "${C_RED}❌ Failed to create keys directory.${C_RESET}"
        return 1
    }
    cp "$DNSTT_BINARY" "$DNSTT_KEYS_DIR/dnstt-server" 2>/dev/null || {
        echo -e "${C_YELLOW}⚠️ Warning: Could not copy binary to /root/dnstt/, service will use /usr/local/bin/ path${C_RESET}"
    }
    chmod +x "$DNSTT_KEYS_DIR/dnstt-server" 2>/dev/null || true

    echo -e "${C_BLUE}🔐 Setting up cryptographic keys...${C_RESET}"
    
    # Constant public key that must never change
    CONSTANT_PUBLIC_KEY="f7faa7519d38fdda4c07eb7804c4fffef5d8a6e866debda48fe1f37035abf647"
    
    # Check if keys already exist - DO NOT regenerate if server.key exists
    if [[ -f "$DNSTT_KEYS_DIR/server.key" ]]; then
        echo -e "${C_GREEN}✅ Using existing DNSTT keys (maintaining constant public key)${C_RESET}"
        # Ensure public key file has the constant value
        if [[ ! -f "$DNSTT_KEYS_DIR/server.pub" ]]; then
            echo -e "${C_YELLOW}⚠️ Warning: server.key exists but server.pub is missing. Setting constant public key...${C_RESET}"
            echo "$CONSTANT_PUBLIC_KEY" > "$DNSTT_KEYS_DIR/server.pub"
        else
            # Verify public key matches constant value
            local current_pubkey
            current_pubkey=$(cat "$DNSTT_KEYS_DIR/server.pub" 2>/dev/null | tr -d '\n\r')
            if [[ "$current_pubkey" != "$CONSTANT_PUBLIC_KEY" ]]; then
                echo -e "${C_YELLOW}⚠️ Warning: Public key does not match constant value. Updating to constant key...${C_RESET}"
                echo "$CONSTANT_PUBLIC_KEY" > "$DNSTT_KEYS_DIR/server.pub"
            fi
        fi
    else
        # Generate new private key only if server.key does NOT exist
        echo -e "${C_BLUE}🔐 Generating new private key (public key will remain constant)...${C_RESET}"
        if ! "$DNSTT_BINARY" -gen-key -privkey-file "$DNSTT_KEYS_DIR/server.key" -pubkey-file "$DNSTT_KEYS_DIR/server.pub" 2>/dev/null; then
            echo -e "${C_RED}❌ Failed to generate DNSTT private key.${C_RESET}"
            return 1
        fi
        if [[ ! -f "$DNSTT_KEYS_DIR/server.key" ]]; then
            echo -e "${C_RED}❌ Private key file was not created successfully.${C_RESET}"
            return 1
        fi
        # Overwrite public key with constant value
        echo "$CONSTANT_PUBLIC_KEY" > "$DNSTT_KEYS_DIR/server.pub"
        echo -e "${C_GREEN}✅ Private key generated and constant public key set${C_RESET}"
        echo -e "${C_YELLOW}⚠️ IMPORTANT: Public key is set to constant value and will not change${C_RESET}"
    fi
    
    local PUBLIC_KEY
    PUBLIC_KEY="$CONSTANT_PUBLIC_KEY"
    # Ensure public key file has the constant value
    echo "$CONSTANT_PUBLIC_KEY" > "$DNSTT_KEYS_DIR/server.pub"
    
    # Check for Python3 and install if needed
    if ! command -v python3 &> /dev/null; then
        echo -e "${C_YELLOW}⚠️ Python3 not found. Installing Python3...${C_RESET}"
        if ! apt-get update > /dev/null 2>&1; then
            echo -e "${C_RED}❌ Failed to update package list.${C_RESET}"
            return 1
        fi
        if ! apt-get install -y python3 > /dev/null 2>&1; then
            echo -e "${C_RED}❌ Failed to install Python3. EDNS proxy requires Python3.${C_RESET}"
            echo -e "${C_YELLOW}ℹ️ Please install Python3 manually: apt-get install python3${C_RESET}"
            return 1
        fi
        echo -e "${C_GREEN}✅ Python3 installed successfully.${C_RESET}"
    fi
    
    echo -e "\n${C_BLUE}📝 Creating EDNS proxy script...${C_RESET}"
    cat > "$DNSTT_EDNS_PROXY" <<'EDNSPROXY'
#!/usr/bin/env python3
"""
DNSTT EDNS proxy (smart parser)
- Listens on UDP :53 (public)
- Forwards to 127.0.0.1:5300 (dnstt-server) with bigger EDNS size
- Outside sees 512, inside server sees 1800
"""

import socket
import threading
import struct
import sys
import traceback

# Public listen
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 53

# Internal dnstt-server address
UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = 5300

# External DNS servers for regular DNS resolution
EXTERNAL_DNS_SERVERS = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]
EXTERNAL_DNS_PORT = 53

# DNSTT tunnel domain (must match the domain in service file)
TUNNEL_DOMAIN = "idd.voltrontechtx.shop"

# EDNS sizes
EXTERNAL_EDNS_SIZE = 512    # what we show to resolvers
INTERNAL_EDNS_SIZE = 1800   # what we tell dnstt-server internally


def patch_edns_udp_size(data: bytes, new_size: int) -> bytes:
    """
    Parse DNS message properly and patch EDNS (OPT RR) UDP payload size.
    If no EDNS / cannot parse properly → return data as is.
    """
    if len(data) < 12:
        return data

    try:
        # Header: ID(2), FLAGS(2), QDCOUNT(2), ANCOUNT(2), NSCOUNT(2), ARCOUNT(2)
        qdcount, ancount, nscount, arcount = struct.unpack("!HHHH", data[4:12])
    except struct.error:
        return data

    offset = 12

    def skip_name(buf, off):
        """Skip DNS name (supporting compression)."""
        while True:
            if off >= len(buf):
                return len(buf)
            l = buf[off]
            off += 1
            if l == 0:
                break
            if l & 0xC0 == 0xC0:
                # compression pointer, one more byte
                if off >= len(buf):
                    return len(buf)
                off += 1
                break
            off += l
        return off

    # Skip Questions
    for _ in range(qdcount):
        offset = skip_name(data, offset)
        if offset + 4 > len(data):
            return data
        offset += 4  # QTYPE + QCLASS

    def skip_rrs(count, buf, off):
        """Skip Resource Records (Answer + Authority)."""
        for _ in range(count):
            off = skip_name(buf, off)
            if off + 10 > len(buf):
                return len(buf)
            # TYPE(2) + CLASS(2) + TTL(4) + RDLEN(2)
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", buf[off:off+10])
            off += 10
            if off + rdlen > len(buf):
                return len(buf)
            off += rdlen
        return off

    # Skip Answer + Authority
    offset = skip_rrs(ancount, data, offset)
    offset = skip_rrs(nscount, data, offset)

    # Additional section → EDNS OPT RR is here
    new_data = bytearray(data)
    for _ in range(arcount):
        rr_name_start = offset
        offset = skip_name(data, offset)
        if offset + 10 > len(data):
            return data
        rtype = struct.unpack("!H", data[offset:offset+2])[0]

        if rtype == 41:  # OPT RR (EDNS)
            # UDP payload size is bytes 2 following TYPE
            size_bytes = struct.pack("!H", new_size)
            new_data[offset+2:offset+4] = size_bytes
            return bytes(new_data)

        # Skip CLASS(2) + TTL(4) + RDLEN(2) + RDATA
        _, _, rdlen = struct.unpack("!H I H", data[offset+2:offset+10])
        offset += 10 + rdlen

    return data


def extract_dns_name(data: bytes, offset: int) -> tuple:
    """Extract DNS name from DNS message starting at offset. Returns (name, new_offset)."""
    if offset >= len(data):
        return ("", len(data))
    
    name_parts = []
    current_offset = offset
    jumped = False
    max_jumps = 10
    jump_count = 0
    
    while current_offset < len(data) and jump_count < max_jumps:
        length = data[current_offset]
        
        # Check for compression pointer
        if length & 0xC0 == 0xC0:
            if current_offset + 1 >= len(data):
                break
            if not jumped:
                offset = current_offset + 2
            jump_offset = ((length & 0x3F) << 8) | data[current_offset + 1]
            if jump_offset >= len(data):
                break
            current_offset = jump_offset
            jumped = True
            jump_count += 1
            continue
        
        # End of name
        if length == 0:
            if not jumped:
                offset = current_offset + 1
            break
        
        # Label length
        if length > 63:
            break
        
        # Extract label
        if current_offset + 1 + length > len(data):
            break
        label = data[current_offset + 1:current_offset + 1 + length].decode('utf-8', errors='ignore')
        name_parts.append(label)
        current_offset += 1 + length
    
    name = ".".join(name_parts)
    if not jumped:
        offset = current_offset + 1
    return (name.lower(), offset)


def is_dnstt_query(data: bytes) -> bool:
    """Check if DNS query is for DNSTT tunnel domain."""
    if len(data) < 12:
        return False
    
    try:
        # Extract question section
        qdcount = struct.unpack("!H", data[4:6])[0]
        if qdcount == 0:
            return False
        
        # Extract domain name from question
        name, _ = extract_dns_name(data, 12)
        if not name:
            return False
        
        # Check if query is for tunnel domain or subdomain
        return name == TUNNEL_DOMAIN or name.endswith("." + TUNNEL_DOMAIN)
    except:
        return False


def forward_to_external_dns(data: bytes) -> bytes:
    """Forward DNS query to external DNS servers."""
    for dns_server in EXTERNAL_DNS_SERVERS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)
            sock.sendto(data, (dns_server, EXTERNAL_DNS_PORT))
            resp, _ = sock.recvfrom(4096)
            sock.close()
            if resp:
                return resp
        except:
            continue
    return b""


def handle_request(server_sock: socket.socket, data: bytes, client_addr):
    """
    - Check if query is for DNSTT tunnel domain
    - If yes: forward to dnstt-server (port 5300) with EDNS size patching
    - If no: forward to external DNS servers (8.8.8.8, etc.) for regular DNS resolution
    - Return response to client
    """
    upstream_sock = None
    try:
        # Check if this is a DNSTT tunnel query
        is_tunnel_query = is_dnstt_query(data)
        
        if is_tunnel_query:
            # Forward to DNSTT server with EDNS size patching
            upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            upstream_sock.settimeout(30.0)  # Increased timeout for better reliability
            
            upstream_data = patch_edns_udp_size(data, INTERNAL_EDNS_SIZE)
            upstream_sock.sendto(upstream_data, (UPSTREAM_HOST, UPSTREAM_PORT))

            resp, _ = upstream_sock.recvfrom(8192)  # Increased buffer size for larger responses
            if resp:
                resp_patched = patch_edns_udp_size(resp, EXTERNAL_EDNS_SIZE)
                server_sock.sendto(resp_patched, client_addr)
        else:
            # Forward regular DNS query to external DNS servers
            resp = forward_to_external_dns(data)
            if resp:
                server_sock.sendto(resp, client_addr)
            else:
                # If all external DNS servers fail, try DNSTT as fallback
                try:
                    upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    upstream_sock.settimeout(10.0)  # Increased timeout for fallback
                    upstream_sock.sendto(data, (UPSTREAM_HOST, UPSTREAM_PORT))
                    resp, _ = upstream_sock.recvfrom(8192)  # Increased buffer size
                    if resp:
                        server_sock.sendto(resp, client_addr)
                except:
                    pass
    except socket.timeout:
        # Timeout - upstream may be slow, client will resend
        pass
    except ConnectionRefusedError:
        # Upstream not ready - try again on next request
        pass
    except OSError as e:
        # Network error - log but don't crash
        if e.errno != 101:  # Network unreachable is ok to ignore
            print(f"[DNSTT EDNS proxy] Warning: OSError in handle_request: {e}", file=sys.stderr)
    except Exception as e:
        # Unexpected error - log but don't crash
        print(f"[DNSTT EDNS proxy] Warning: Unexpected error in handle_request: {e}", file=sys.stderr)
    finally:
        if upstream_sock:
            try:
                upstream_sock.close()
            except:
                pass


def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_sock.bind((LISTEN_HOST, LISTEN_PORT))
        print(f"[DNSTT EDNS proxy] Successfully bound to {LISTEN_HOST}:{LISTEN_PORT}")
        print(f"[DNSTT EDNS proxy] DNSTT upstream: {UPSTREAM_HOST}:{UPSTREAM_PORT}")
        print(f"[DNSTT EDNS proxy] External DNS servers: {', '.join(EXTERNAL_DNS_SERVERS)}")
        print(f"[DNSTT EDNS proxy] Tunnel domain: {TUNNEL_DOMAIN}")
        print(f"[DNSTT EDNS proxy] External EDNS={EXTERNAL_EDNS_SIZE}, Internal EDNS={INTERNAL_EDNS_SIZE}")
    except PermissionError:
        print(f"[DNSTT EDNS proxy] ERROR: Permission denied binding to port {LISTEN_PORT}")
        print(f"[DNSTT EDNS proxy] ERROR: Service needs CAP_NET_BIND_SERVICE capability or root privileges")
        sys.exit(1)
    except OSError as e:
        print(f"[DNSTT EDNS proxy] ERROR: Failed to bind to {LISTEN_HOST}:{LISTEN_PORT}: {e}")
        print(f"[DNSTT EDNS proxy] ERROR: Port {LISTEN_PORT} may be in use or already bound")
        sys.exit(1)
    except Exception as e:
        print(f"[DNSTT EDNS proxy] ERROR: Unexpected error: {e}")
        sys.exit(1)

    while True:
        try:
            data, client_addr = server_sock.recvfrom(4096)
            t = threading.Thread(
                target=handle_request,
                args=(server_sock, data, client_addr),
                daemon=True,
            )
            t.start()
        except KeyboardInterrupt:
            print(f"\n[DNSTT EDNS proxy] Shutting down...")
            break
        except Exception as e:
            print(f"[DNSTT EDNS proxy] ERROR in main loop: {e}")
            continue


if __name__ == "__main__":
    main()
EDNSPROXY
    
    # Verify Python script was created correctly
    if [ ! -f "$DNSTT_EDNS_PROXY" ]; then
        echo -e "${C_RED}❌ Failed to create EDNS proxy script.${C_RESET}"
        return 1
    fi
    
    # Set executable permissions
    chmod +x "$DNSTT_EDNS_PROXY"
    
    # Verify Python script syntax
    if ! python3 -m py_compile "$DNSTT_EDNS_PROXY" 2>/dev/null; then
        echo -e "${C_YELLOW}⚠️ Warning: Python script syntax check failed. Proceeding anyway...${C_RESET}"
    else
        echo -e "${C_GREEN}✅ EDNS proxy script created and validated successfully.${C_RESET}"
    fi
    
    echo -e "\n${C_BLUE}📝 Creating DNSTT systemd service (port 5300)...${C_RESET}"
    # Determine which binary path to use (prefer /root/dnstt/dnstt-server, fallback to /usr/local/bin/dnstt-server)
    local dnstt_exec_path="/root/dnstt/dnstt-server"
    if [[ ! -f "$dnstt_exec_path" ]]; then
        dnstt_exec_path="/usr/local/bin/dnstt-server"
        if [[ ! -f "$dnstt_exec_path" ]]; then
            echo -e "${C_RED}❌ DNSTT binary not found at either location.${C_RESET}"
            return 1
        fi
        echo -e "${C_YELLOW}ℹ️ Using DNSTT binary at: $dnstt_exec_path${C_RESET}"
    else
        echo -e "${C_GREEN}ℹ️ Using DNSTT binary at: $dnstt_exec_path${C_RESET}"
    fi
    
    # Verify key file exists
    if [[ ! -f "$DNSTT_KEYS_DIR/server.key" ]]; then
        echo -e "${C_RED}❌ DNSTT private key not found at: $DNSTT_KEYS_DIR/server.key${C_RESET}"
        return 1
    fi
    
    # Use fixed configuration: MTU 512, domain idd.voltrontechtx.shop, forward to 127.0.0.1:22
    cat > "$DNSTT_SERVICE_FILE" <<-EOF
[Unit]
Description=DNSTT Server (DNS Tunnel)
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$dnstt_exec_path -udp :5300 -mtu 512 -privkey-file /root/dnstt/server.key idd.voltrontechtx.shop 127.0.0.1:22
Restart=always
RestartSec=3
RestartPreventExitStatus=0
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    echo -e "\n${C_BLUE}📝 Creating EDNS proxy systemd service (port 53)...${C_RESET}"
    cat > "$DNSTT_EDNS_SERVICE" <<-EOF
[Unit]
Description=DNSTT EDNS Proxy (port 53 to 5300)
After=network-online.target dnstt.service
Wants=network-online.target
Requires=dnstt.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 "$DNSTT_EDNS_PROXY"
Restart=always
RestartSec=3
RestartPreventExitStatus=0
StandardOutput=journal
StandardError=journal
User=root
# Ensure port 53 binding works properly (low port binding for DNS)
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
EOF
    echo -e "\n${C_BLUE}💾 Saving configuration and starting service...${C_RESET}"
    # Save the public key to config file (this will remain constant for this installation)
    cat > "$DNSTT_CONFIG_FILE" <<-EOF
NS_SUBDOMAIN="$NS_SUBDOMAIN"
TUNNEL_SUBDOMAIN="$TUNNEL_SUBDOMAIN"
NS_DOMAIN="$NS_DOMAIN"
TUNNEL_DOMAIN="$TUNNEL_DOMAIN"
PUBLIC_KEY="$PUBLIC_KEY"
FORWARD_DESC="$forward_desc"
DNSTT_RECORDS_MANAGED="$DNSTT_RECORDS_MANAGED"
HAS_IPV6="$HAS_IPV6"
MTU_VALUE="$mtu_value"
KEY_FILE_PATH="$DNSTT_KEYS_DIR"
EOF
    # Reload systemd daemon
    if ! systemctl daemon-reload 2>/dev/null; then
        echo -e "${C_YELLOW}⚠️ Warning: systemd daemon-reload had issues, but continuing...${C_RESET}"
    else
        echo -e "${C_GREEN}✅ Systemd daemon reloaded successfully${C_RESET}"
    fi
    sleep 1
    
    # Enable and start DNSTT service with retry logic
    local enable_attempts=0
    local start_attempts=0
    local max_attempts=3
    local service_enabled=false
    local service_started=false
    
    # Enable service
    while [[ $enable_attempts -lt $max_attempts ]]; do
        enable_attempts=$((enable_attempts + 1))
        if systemctl enable dnstt.service 2>/dev/null; then
            service_enabled=true
            echo -e "${C_GREEN}✅ DNSTT service enabled successfully${C_RESET}"
            break
        else
            if [[ $enable_attempts -lt $max_attempts ]]; then
                echo -e "${C_YELLOW}⚠️ Enable attempt $enable_attempts failed, retrying...${C_RESET}"
                systemctl daemon-reload 2>/dev/null
                sleep 1
            fi
        fi
    done
    
    if [[ "$service_enabled" != "true" ]]; then
        echo -e "${C_YELLOW}⚠️ Warning: Failed to enable DNSTT service after $max_attempts attempts, but continuing...${C_RESET}"
    fi
    
    # Start service with diagnostics and auto-fix
    while [[ $start_attempts -lt $max_attempts ]]; do
        start_attempts=$((start_attempts + 1))
        
        if systemctl start dnstt.service 2>/dev/null; then
            sleep 3
            if systemctl is-active --quiet dnstt.service 2>/dev/null; then
                service_started=true
                break
            else
                echo -e "${C_YELLOW}⚠️ Service started but is not active. Diagnosing...${C_RESET}"
            fi
        fi
        
        if [[ $start_attempts -lt $max_attempts ]]; then
            echo -e "${C_YELLOW}⚠️ Start attempt $start_attempts failed. Diagnosing and fixing...${C_RESET}"
            
            # Diagnose issues
            local error_log=$(journalctl -u dnstt.service -n 20 --no-pager 2>/dev/null)
            
            # Check for binary permission issues
            if [[ -f "$DNSTT_BINARY" ]] && [[ ! -x "$DNSTT_BINARY" ]]; then
                echo -e "${C_BLUE}🔧 Fixing: Binary not executable. Adding execute permissions...${C_RESET}"
                chmod +x "$DNSTT_BINARY" 2>/dev/null
            fi
            
            # Check for missing binary
            if [[ ! -f "$DNSTT_BINARY" ]]; then
                echo -e "${C_RED}❌ DNSTT binary not found at: $DNSTT_BINARY${C_RESET}"
                return 1
            fi
            
            # Check for missing key files
            if [[ ! -f "$DNSTT_KEYS_DIR/server.key" ]] || [[ ! -f "$DNSTT_KEYS_DIR/server.pub" ]]; then
                echo -e "${C_RED}❌ DNSTT key files not found. Keys are required.${C_RESET}"
                return 1
            fi
            
            # Check for port conflicts
            if ss -lunp 2>/dev/null | grep -qE ':(5300|:5300)\s' && ! ss -lunp 2>/dev/null | grep -qE 'dnstt.*:5300\s'; then
                local port_conflict=$(ss -lunp 2>/dev/null | grep -E ':(5300|:5300)\s' | head -n1)
                echo -e "${C_YELLOW}⚠️ Port 5300 is in use: $port_conflict${C_RESET}"
                echo -e "${C_BLUE}🔧 Attempting to free port 5300...${C_RESET}"
                pkill -f "dnstt.*5300" 2>/dev/null
                sleep 2
            fi
            
            # Reload daemon before retry
            systemctl daemon-reload 2>/dev/null
            sleep 2
        fi
    done
    
    if [[ "$service_started" != "true" ]]; then
        echo -e "${C_RED}❌ Failed to start DNSTT service after $max_attempts attempts.${C_RESET}"
        echo -e "${C_YELLOW}📋 Showing service logs:${C_RESET}"
        journalctl -u dnstt.service -n 30 --no-pager 2>/dev/null || true
        return 1
    fi
    
    sleep 3
    
    # Validate DNSTT service is running and port 5300 is listening
    local dnstt_started=false
    if systemctl is-active --quiet dnstt.service; then
        if ss -lunp 2>/dev/null | grep -qE ':(5300|:5300)\s'; then
            echo -e "${C_GREEN}✅ DNSTT server (port 5300) started successfully and is listening.${C_RESET}"
            dnstt_started=true
        else
            echo -e "${C_YELLOW}⚠️ DNSTT service is active but port 5300 is not listening. Checking logs...${C_RESET}"
            journalctl -u dnstt.service -n 20 --no-pager
            sleep 2
            # Retry check
            if ss -lunp 2>/dev/null | grep -qE ':(5300|:5300)\s'; then
                echo -e "${C_GREEN}✅ Port 5300 is now listening.${C_RESET}"
                dnstt_started=true
            fi
        fi
    else
        echo -e "${C_RED}❌ DNSTT service is not active.${C_RESET}"
        journalctl -u dnstt.service -n 20 --no-pager
        return 1
    fi
    
    # Validate DNSTT service is running and port 5300 is listening
    local dnstt_started=false
    if systemctl is-active --quiet dnstt.service 2>/dev/null; then
        if ss -lunp 2>/dev/null | grep -qE ':(5300|:5300)\s'; then
            echo -e "${C_GREEN}✅ DNSTT server (port 5300) started successfully and is listening.${C_RESET}"
            dnstt_started=true
        else
            echo -e "${C_YELLOW}⚠️ DNSTT service is active but port 5300 is not listening. Waiting and retrying...${C_RESET}"
            sleep 3
            if ss -lunp 2>/dev/null | grep -qE ':(5300|:5300)\s'; then
                echo -e "${C_GREEN}✅ Port 5300 is now listening.${C_RESET}"
                dnstt_started=true
            else
                echo -e "${C_YELLOW}⚠️ Port 5300 still not listening. Check logs: journalctl -u dnstt.service${C_RESET}"
                journalctl -u dnstt.service -n 20 --no-pager 2>/dev/null || true
            fi
        fi
    else
        echo -e "${C_RED}❌ DNSTT service is not active after start attempts.${C_RESET}"
        journalctl -u dnstt.service -n 30 --no-pager 2>/dev/null || true
        return 1
    fi
    
    if [[ "$dnstt_started" == "true" ]]; then
        # Start EDNS proxy service with retry logic
        echo -e "\n${C_BLUE}🚀 Starting EDNS proxy service...${C_RESET}"
        
        local edns_enable_attempts=0
        local edns_start_attempts=0
        local edns_service_enabled=false
        local edns_service_started=false
        
        # Enable service
        while [[ $edns_enable_attempts -lt $max_attempts ]]; do
            edns_enable_attempts=$((edns_enable_attempts + 1))
            if systemctl enable dnstt-edns-proxy.service 2>/dev/null; then
                edns_service_enabled=true
                echo -e "${C_GREEN}✅ EDNS proxy service enabled successfully${C_RESET}"
                break
            else
                if [[ $edns_enable_attempts -lt $max_attempts ]]; then
                    echo -e "${C_YELLOW}⚠️ Enable attempt $edns_enable_attempts failed, retrying...${C_RESET}"
                    systemctl daemon-reload 2>/dev/null
                    sleep 1
                fi
            fi
        done
        
        if [[ "$edns_service_enabled" != "true" ]]; then
            echo -e "${C_YELLOW}⚠️ Warning: Failed to enable EDNS proxy service after $max_attempts attempts, but continuing...${C_RESET}"
        fi
        
        # Ensure port 53 is free (kill systemd-resolved and other conflicts)
        echo -e "${C_BLUE}🔍 Checking port 53 availability...${C_RESET}"
        if ss -lunp 2>/dev/null | grep -qE ':(53|:53)\s'; then
            local port53_process=$(ss -lunp 2>/dev/null | grep -E ':(53|:53)\s' | head -n1)
            if ! echo "$port53_process" | grep -qE 'python3.*:53\s'; then
                echo -e "${C_YELLOW}⚠️ Port 53 is in use: $port53_process${C_RESET}"
                echo -e "${C_BLUE}🔧 Attempting to free port 53...${C_RESET}"
                
                # Stop systemd-resolved if running
                if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
                    systemctl stop systemd-resolved 2>/dev/null
                    systemctl disable systemd-resolved 2>/dev/null
                    systemctl mask systemd-resolved 2>/dev/null
                    echo -e "${C_GREEN}✅ Stopped systemd-resolved${C_RESET}"
                fi
                
                # Kill any remaining processes
                pkill -9 systemd-resolved 2>/dev/null
                pkill -9 dnstt-edns-proxy 2>/dev/null
                sleep 3
                
                # Verify port is free
                if ss -lunp 2>/dev/null | grep -qE ':(53|:53)\s'; then
                    echo -e "${C_YELLOW}⚠️ Port 53 still in use after cleanup attempt${C_RESET}"
                else
                    echo -e "${C_GREEN}✅ Port 53 is now free${C_RESET}"
                fi
            fi
        fi
        
        # Start service with diagnostics and auto-fix
        while [[ $edns_start_attempts -lt $max_attempts ]]; do
            edns_start_attempts=$((edns_start_attempts + 1))
            
            if systemctl start dnstt-edns-proxy.service 2>/dev/null; then
                sleep 3
                if systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
                    edns_service_started=true
                    break
                else
                    echo -e "${C_YELLOW}⚠️ Service started but is not active. Diagnosing...${C_RESET}"
                fi
            fi
            
            if [[ $edns_start_attempts -lt $max_attempts ]]; then
                echo -e "${C_YELLOW}⚠️ Start attempt $edns_start_attempts failed. Diagnosing and fixing...${C_RESET}"
                
                # Check for script file issues
                if [ ! -f "$DNSTT_EDNS_PROXY" ]; then
                    echo -e "${C_RED}❌ EDNS proxy script not found at: $DNSTT_EDNS_PROXY${C_RESET}"
                    return 1
                elif [ ! -x "$DNSTT_EDNS_PROXY" ]; then
                    echo -e "${C_BLUE}🔧 Fixing: Script not executable. Adding execute permissions...${C_RESET}"
                    chmod +x "$DNSTT_EDNS_PROXY" 2>/dev/null
                fi
                
                # Check for Python3
                if ! command -v python3 &> /dev/null; then
                    echo -e "${C_RED}❌ Python3 is not installed. Installing...${C_RESET}"
                    apt-get update && apt-get install -y python3 2>/dev/null || yum install -y python3 2>/dev/null || echo -e "${C_RED}Failed to install python3${C_RESET}"
                fi
                
                # Check script syntax
                if ! python3 -m py_compile "$DNSTT_EDNS_PROXY" 2>/dev/null; then
                    echo -e "${C_YELLOW}⚠️ EDNS proxy script has syntax errors${C_RESET}"
                fi
                
                # Reload daemon before retry
                systemctl daemon-reload 2>/dev/null
                sleep 2
            fi
        done
        
        if [[ "$edns_service_started" != "true" ]]; then
            echo -e "${C_YELLOW}⚠️ Failed to start EDNS proxy service after $max_attempts attempts.${C_RESET}"
            echo -e "${C_YELLOW}📋 Showing service logs:${C_RESET}"
            journalctl -u dnstt-edns-proxy.service -n 30 --no-pager 2>/dev/null || true
        fi
        
        # Validate EDNS proxy is running and port 53 is listening
        local edns_started=false
        if [[ "$edns_service_started" == "true" ]]; then
            sleep 2
            if systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
                if ss -lunp 2>/dev/null | grep -qE ':(53|:53)\s'; then
                    echo -e "${C_GREEN}✅ EDNS proxy (port 53) started successfully and is listening.${C_RESET}"
                    edns_started=true
                else
                    echo -e "${C_YELLOW}⚠️ EDNS proxy service is active but port 53 may not be listening properly. Waiting...${C_RESET}"
                    sleep 3
                    # Retry check
                    if ss -lunp 2>/dev/null | grep -qE ':(53|:53)\s'; then
                        echo -e "${C_GREEN}✅ Port 53 is now listening.${C_RESET}"
                        edns_started=true
                    else
                        echo -e "${C_YELLOW}⚠️ Port 53 still not listening. Check logs: journalctl -u dnstt-edns-proxy.service${C_RESET}"
                        journalctl -u dnstt-edns-proxy.service -n 20 --no-pager 2>/dev/null || true
                    fi
                fi
            else
                echo -e "${C_YELLOW}⚠️ EDNS proxy service is not active after start attempts.${C_RESET}"
                journalctl -u dnstt-edns-proxy.service -n 30 --no-pager 2>/dev/null || true
            fi
        fi
        
        if [[ "$dnstt_started" == "true" ]] && [[ "$edns_started" == "true" ]]; then
            echo -e "\n${C_GREEN}✅ SUCCESS: DNSTT with EDNS proxy has been installed and started!${C_RESET}"
            echo -e "${C_CYAN}ℹ️ DNSTT server runs on port 5300 (internal)${C_RESET}"
            echo -e "${C_CYAN}ℹ️ EDNS proxy listens on port 53 (public) and forwards to port 5300${C_RESET}"
            echo -e "${C_CYAN}ℹ️ External EDNS size: 512, Internal EDNS size: 1800 (high speed)${C_RESET}"
            echo -e "\n${C_YELLOW}🔑 IMPORTANT: Your public key is CONSTANT and will remain the same for VPN connections${C_RESET}"
            echo -e "${C_YELLOW}   The key is stored at: ${C_WHITE}$DNSTT_KEYS_DIR/server.pub${C_RESET}"
            echo -e "${C_YELLOW}   This key will be reused on reinstallations unless manually deleted${C_RESET}"
            
            # Auto-configure DNS forwarding and SSH when VPN (DNSTT) is connected
            echo -e "\n${C_BLUE}⚙️ Auto-configuring VPN services (DNS forwarding & SSH)...${C_RESET}"
            setup_vpn_auto_config
            
            # Get server IP address for DNS configuration
            local server_ip=""
            if command -v hostname &> /dev/null; then
                server_ip=$(hostname -I | awk '{print $1}' 2>/dev/null || hostname -i 2>/dev/null | awk '{print $1}')
            fi
            if [[ -z "$server_ip" ]] && command -v ip &> /dev/null; then
                server_ip=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' | head -n1)
            fi
            if [[ -z "$server_ip" ]] && command -v ifconfig &> /dev/null; then
                server_ip=$(ifconfig 2>/dev/null | grep -oP 'inet \K[0-9.]+' | grep -v '127.0.0.1' | head -n1)
            fi
            
            echo -e "\n${C_RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
            echo -e "${C_RED}  ⚠️ CRITICAL DNS CONFIGURATION FOR CLIENT${C_RESET}"
            echo -e "${C_RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
            if [[ -n "$NS_DOMAIN" ]]; then
                echo -e "  ${C_RED}❌ WRONG: Do NOT use DNS 8.8.8.8 or any public DNS${C_RESET}"
                echo -e "  ${C_GREEN}✅ CORRECT: Client must use DNS: ${C_YELLOW}$NS_DOMAIN${C_RESET}"
                if [[ -n "$server_ip" ]]; then
                    echo -e "  ${C_GREEN}✅ Or use IP address: ${C_YELLOW}$server_ip${C_RESET} ${C_DIM}(if nameserver domain points to this IP)${C_RESET}"
                fi
                echo -e "  ${C_YELLOW}💡${C_RESET} ${C_WHITE}Ensure $NS_DOMAIN resolves to this server's IP address: ${C_YELLOW}${server_ip:-"<detect-server-ip>"}${C_RESET}"
                echo -e "  ${C_YELLOW}💡${C_RESET} ${C_WHITE}Configure client DNS to: ${C_YELLOW}$NS_DOMAIN${C_RESET} ${C_WHITE}or ${C_YELLOW}${server_ip:-"<server-ip>"}${C_RESET}"
            else
                echo -e "  ${C_RED}❌ WRONG: Do NOT use DNS 8.8.8.8 or any public DNS${C_RESET}"
                echo -e "  ${C_YELLOW}⚠️${C_RESET} ${C_WHITE}Nameserver domain not configured. Please reconfigure DNSTT with nameserver domain.${C_RESET}"
            fi
            echo -e "${C_RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
            
            # Auto-configure DNS forwarding and SSH when VPN (DNSTT) is connected
            echo -e "\n${C_BLUE}⚙️ Auto-configuring VPN services (DNS forwarding & SSH)...${C_RESET}"
            setup_vpn_auto_config
            
            show_dnstt_details
        elif [[ "$dnstt_started" == "true" ]]; then
            echo -e "\n${C_YELLOW}⚠️ DNSTT server is running, but EDNS proxy may need attention.${C_RESET}"
            echo -e "${C_YELLOW}💡 Check logs: journalctl -u dnstt-edns-proxy.service -f${C_RESET}"
            show_dnstt_details
        fi
    else
        echo -e "\n${C_RED}❌ ERROR: DNSTT service failed to start properly.${C_RESET}"
        journalctl -u dnstt.service -n 20 --no-pager
        return 1
    fi
}

uninstall_dnstt() {
    echo -e "\n${C_BOLD}${C_PURPLE}--- 🗑️ Uninstalling DNSTT ---${C_RESET}"
    if [ ! -f "$DNSTT_SERVICE_FILE" ]; then
        echo -e "${C_YELLOW}ℹ️ DNSTT does not appear to be installed, skipping.${C_RESET}"
        return
    fi
    local confirm="y"
    if [[ "$UNINSTALL_MODE" != "silent" ]]; then
        read -p "👉 Are you sure you want to uninstall DNSTT? (y/n): " confirm
    fi
    if [[ "$confirm" != "y" ]]; then
        echo -e "\n${C_YELLOW}❌ Uninstallation cancelled.${C_RESET}"
        return
    fi
    echo -e "${C_BLUE}🛑 Stopping and disabling DNSTT services...${C_RESET}"
    
    # Stop EDNS proxy service
    if systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
        systemctl stop dnstt-edns-proxy.service
        sleep 1
    fi
    systemctl disable dnstt-edns-proxy.service >/dev/null 2>&1
    
    # Stop DNSTT service
    if systemctl is-active --quiet dnstt.service 2>/dev/null; then
        systemctl stop dnstt.service
        sleep 1
    fi
    systemctl disable dnstt.service >/dev/null 2>&1
    
    # Kill any remaining processes
    pkill -9 dnstt-server 2>/dev/null
    pkill -9 -f "dnstt-edns-proxy.py" 2>/dev/null
    sleep 1
    
    # Verify services are stopped
    if systemctl is-active --quiet dnstt.service 2>/dev/null || systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
        echo -e "${C_YELLOW}⚠️ Some services may still be running. Force stopping...${C_RESET}"
        systemctl stop dnstt.service dnstt-edns-proxy.service 2>/dev/null
        pkill -9 dnstt-server 2>/dev/null
        pkill -9 -f "dnstt-edns-proxy.py" 2>/dev/null
        sleep 2
    fi
    
    if [ -f "$DNSTT_CONFIG_FILE" ]; then
        echo -e "${C_YELLOW}⚠️ DNS records were manually configured. Please delete them from your DNS provider.${C_RESET}"
    fi
    
    echo -e "${C_BLUE}🗑️ Removing service files and binaries...${C_RESET}"
    rm -f "$DNSTT_SERVICE_FILE"
    rm -f "$DNSTT_EDNS_SERVICE"
    rm -f "$DNSTT_BINARY"
    rm -f "$DNSTT_EDNS_PROXY"
    rm -rf "$DNSTT_KEYS_DIR"
    rm -f "$DNSTT_CONFIG_FILE"
    
    systemctl daemon-reload
    
    # Optional: Unmask systemd-resolved if user wants
    if systemctl is-masked systemd-resolved 2>/dev/null | grep -q masked; then
        echo -e "${C_YELLOW}ℹ️ systemd-resolved is currently masked.${C_RESET}"
        read -p "👉 Do you want to unmask and restore systemd-resolved? (y/n): " restore_resolved
        if [[ "$restore_resolved" == "y" || "$restore_resolved" == "Y" ]]; then
            systemctl unmask systemd-resolved 2>/dev/null
            chattr -i /etc/resolv.conf 2>/dev/null
            rm -f /etc/resolv.conf
            systemctl enable systemd-resolved 2>/dev/null
            systemctl start systemd-resolved 2>/dev/null
            echo -e "${C_GREEN}✅ systemd-resolved has been restored.${C_RESET}"
        fi
    fi
    
    echo -e "${C_GREEN}✅ DNSTT has been uninstalled successfully.${C_RESET}"
    
    echo -e "${C_YELLOW}ℹ️ Making /etc/resolv.conf writable again...${C_RESET}"
    chattr -i /etc/resolv.conf &>/dev/null

    echo -e "\n${C_GREEN}✅ DNSTT has been successfully uninstalled.${C_RESET}"
}

install_web_proxy() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🌐 Installing WebSocket Proxy (Websockets/Socks) ---${C_RESET}"
    
    if [ -f "$WEBPROXY_SERVICE_FILE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ WebSocket Proxy is already installed.${C_RESET}"
        if [ -f "$WEBPROXY_CONFIG_FILE" ]; then
            source "$WEBPROXY_CONFIG_FILE"
            echo -e "   It is configured to run on port(s): ${C_YELLOW}$PORTS${C_RESET}"
            echo -e "   Installed Version: ${C_YELLOW}${INSTALLED_VERSION:-Unknown}${C_RESET}"
        fi
        read -p "👉 Do you want to reinstall/update? (y/n): " confirm_reinstall
        if [[ "$confirm_reinstall" != "y" ]]; then return; fi
    fi

    echo -e "\n${C_BLUE}🌐 Fetching available versions from GitHub...${C_RESET}"
    local releases_json=$(curl -s "https://api.github.com/repos/firewallfalcons/FirewallFalcon-Manager/releases")
    if [[ -z "$releases_json" || "$releases_json" == "[]" ]]; then
        echo -e "${C_RED}❌ Error: Could not fetch releases. Check internet or API limits.${C_RESET}"
        return
    fi

    # Extract tag names
    mapfile -t versions < <(echo "$releases_json" | jq -r '.[].tag_name')
    
    if [ ${#versions[@]} -eq 0 ]; then
        echo -e "${C_RED}❌ No releases found in the repository.${C_RESET}"
        return
    fi

    echo -e "\n${C_CYAN}Select a version to install:${C_RESET}"
    for i in "${!versions[@]}"; do
        printf "  ${C_GREEN}%2d)${C_RESET} %s\n" "$((i+1))" "${versions[$i]}"
    done
    echo -e "  ${C_RED} 0)${C_RESET} ↩️ Cancel"
    
    local choice
    while true; do
        read -p "👉 Enter version number [1]: " choice
        choice=${choice:-1}
        if [[ "$choice" == "0" ]]; then return; fi
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -le "${#versions[@]}" ]; then
            SELECTED_VERSION="${versions[$((choice-1))]}"
            break
        else
            echo -e "${C_RED}❌ Invalid selection.${C_RESET}"
        fi
    done

    local ports
    read -p "👉 Enter port(s) for WebSocket Proxy (e.g., $DEFAULT_WEB_PROXY_PORT or $DEFAULT_WEB_PROXY_PORT 8888) [$DEFAULT_WEB_PROXY_PORT]: " ports
    ports=${ports:-$DEFAULT_WEB_PROXY_PORT}

    local port_array=($ports)
    for port in "${port_array[@]}"; do
        if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
            echo -e "\n${C_RED}❌ Invalid port number: $port. Aborting.${C_RESET}"
            return
        fi
        check_and_free_ports "$port" || return
        check_and_open_firewall_port "$port" tcp || return
    done

    echo -e "\n${C_GREEN}⚙️ Detecting system architecture...${C_RESET}"
    local arch=$(uname -m)
    local binary_name=""
    if [[ "$arch" == "x86_64" ]]; then
        binary_name="webproxy"
        echo -e "${C_BLUE}ℹ️ Detected x86_64 (amd64) architecture.${C_RESET}"
    elif [[ "$arch" == "aarch64" || "$arch" == "arm64" ]]; then
        binary_name="webproxyarm"
        echo -e "${C_BLUE}ℹ️ Detected ARM64 architecture.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ Unsupported architecture: $arch. Cannot install WebSocket Proxy.${C_RESET}"
        return
    fi
    
    # Construct download URL based on selected version
    local download_url="https://github.com/firewallfalcons/FirewallFalcon-Manager/releases/download/$SELECTED_VERSION/$binary_name"

    echo -e "\n${C_GREEN}📥 Downloading WebSocket Proxy $SELECTED_VERSION ($binary_name)...${C_RESET}"
    if ! wget -q --show-progress -O "$WEBPROXY_BINARY" "$download_url"; then
        echo -e "\n${C_RED}❌ Failed to download the binary from $download_url${C_RESET}"
        echo -e "${C_YELLOW}ℹ️ Please ensure version $SELECTED_VERSION has asset '$binary_name'.${C_RESET}"
        return 1
    fi
    if [[ ! -f "$WEBPROXY_BINARY" ]] || [[ ! -s "$WEBPROXY_BINARY" ]]; then
        echo -e "\n${C_RED}❌ Downloaded file is empty or missing.${C_RESET}"
        return 1
    fi
    chmod +x "$WEBPROXY_BINARY"

    echo -e "\n${C_GREEN}📝 Creating systemd service file...${C_RESET}"
    cat > "$WEBPROXY_SERVICE_FILE" <<EOF
[Unit]
Description=WebSocket Proxy ($SELECTED_VERSION)
After=network.target

[Service]
User=root
Type=simple
ExecStart="$WEBPROXY_BINARY" -p "$ports"
Restart=always
RestartSec=2s

[Install]
WantedBy=default.target
EOF

    echo -e "\n${C_GREEN}💾 Saving configuration...${C_RESET}"
    cat > "$WEBPROXY_CONFIG_FILE" <<EOF
PORTS="$ports"
INSTALLED_VERSION="$SELECTED_VERSION"
EOF

    echo -e "\n${C_GREEN}▶️ Enabling and starting WebSocket Proxy service...${C_RESET}"
    systemctl daemon-reload
    systemctl enable webproxy.service
    systemctl restart webproxy.service
    sleep 2

    if systemctl is-active --quiet webproxy; then
        echo -e "\n${C_GREEN}✅ SUCCESS: WebSocket Proxy $SELECTED_VERSION is installed and active.${C_RESET}"
        echo -e "   Listening on port(s): ${C_YELLOW}$ports${C_RESET}"
    else
        echo -e "\n${C_RED}❌ ERROR: WebSocket Proxy service failed to start.${C_RESET}"
        echo -e "${C_YELLOW}ℹ️ Displaying last 15 lines of the service log for diagnostics:${C_RESET}"
        journalctl -u webproxy.service -n 15 --no-pager
    fi
}

uninstall_web_proxy() {
    echo -e "\n${C_BOLD}${C_PURPLE}--- 🗑️ Uninstalling WebSocket Proxy ---${C_RESET}"
    if [ ! -f "$WEBPROXY_SERVICE_FILE" ]; then
        echo -e "${C_YELLOW}ℹ️ WebSocket Proxy is not installed, skipping.${C_RESET}"
        return
    fi
    echo -e "${C_GREEN}🛑 Stopping and disabling WebSocket Proxy service...${C_RESET}"
    systemctl stop webproxy.service >/dev/null 2>&1
    systemctl disable webproxy.service >/dev/null 2>&1
    echo -e "${C_GREEN}🗑️ Removing service file...${C_RESET}"
    rm -f "$WEBPROXY_SERVICE_FILE"
    systemctl daemon-reload
    echo -e "${C_GREEN}🗑️ Removing binary and config files...${C_RESET}"
    rm -f "$WEBPROXY_BINARY"
    rm -f "$WEBPROXY_CONFIG_FILE"
    echo -e "${C_GREEN}✅ WebSocket Proxy has been uninstalled successfully.${C_RESET}"
}

# --- ZiVPN Installation Logic ---
install_zivpn() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing ZiVPN (UDP/VPN) ---${C_RESET}"
    
    if [ -f "$ZIVPN_SERVICE_FILE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ ZiVPN is already installed.${C_RESET}"
        return
    fi

    echo -e "\n${C_GREEN}⚙️ Checking system architecture...${C_RESET}"
    local arch=$(uname -m)
    local zivpn_url=""
    
    if [[ "$arch" == "x86_64" ]]; then
        zivpn_url="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
        echo -e "${C_BLUE}ℹ️ Detected AMD64/x86_64 architecture.${C_RESET}"
    elif [[ "$arch" == "aarch64" ]]; then
        zivpn_url="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-arm64"
        echo -e "${C_BLUE}ℹ️ Detected ARM64 architecture.${C_RESET}"
    elif [[ "$arch" == "armv7l" || "$arch" == "arm" ]]; then
         zivpn_url="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-arm"
         echo -e "${C_BLUE}ℹ️ Detected ARM architecture.${C_RESET}"
    else
        echo -e "${C_RED}❌ Unsupported architecture: $arch${C_RESET}"
        return
    fi

    echo -e "\n${C_GREEN}📦 Downloading ZiVPN binary...${C_RESET}"
    if ! wget -q --show-progress -O "$ZIVPN_BIN" "$zivpn_url"; then
        echo -e "${C_RED}❌ Download failed from $zivpn_url. Check internet connection.${C_RESET}"
        return 1
    fi
    if [[ ! -f "$ZIVPN_BIN" ]] || [[ ! -s "$ZIVPN_BIN" ]]; then
        echo -e "${C_RED}❌ Downloaded file is empty or missing.${C_RESET}"
        return 1
    fi
    chmod +x "$ZIVPN_BIN"

    echo -e "\n${C_GREEN}⚙️ Configuring ZIVPN...${C_RESET}"
    mkdir -p "$ZIVPN_DIR"
    
    # Generate Certificates
    echo -e "${C_BLUE}🔐 Generating self-signed certificates...${C_RESET}"
    if ! command -v openssl &>/dev/null; then apt-get install -y openssl &>/dev/null; fi
    
    openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
        -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" \
        -keyout "$ZIVPN_KEY_FILE" -out "$ZIVPN_CERT_FILE" 2>/dev/null

    if [ ! -f "$ZIVPN_CERT_FILE" ]; then
        echo -e "${C_RED}❌ Failed to generate certificates.${C_RESET}"
        return
    fi

    # System Tuning
    echo -e "${C_BLUE}🔧 Tuning system network parameters...${C_RESET}"
    sysctl -w net.core.rmem_max=16777216 >/dev/null
    sysctl -w net.core.wmem_max=16777216 >/dev/null

    # Create Service
    echo -e "${C_BLUE}📝 Creating systemd service file...${C_RESET}"
    cat <<EOF > "$ZIVPN_SERVICE_FILE"
[Unit]
Description=zivpn VPN Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$ZIVPN_DIR
ExecStart="$ZIVPN_BIN" server -c "$ZIVPN_CONFIG_FILE"
Restart=always
RestartSec=3
Environment=ZIVPN_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    # Configure Passwords
    echo -e "\n${C_YELLOW}🔑 ZiVPN Password Setup${C_RESET}"
    read -p "👉 Enter passwords separated by commas (e.g., user1,user2) [Default: 'zi']: " input_config
    
    if [ -n "$input_config" ]; then
        local OLD_IFS="$IFS"
        IFS=',' read -r -a config_array <<< "$input_config"
        IFS="$OLD_IFS"
        # Ensure array format for JSON
        json_passwords=$(printf '"%s",' "${config_array[@]}")
        json_passwords="[${json_passwords%,}]"
    else
        json_passwords='["zi"]'
    fi

    # Create Config File
    cat <<EOF > "$ZIVPN_CONFIG_FILE"
{
  "listen": ":5667",
   "cert": "$ZIVPN_CERT_FILE",
   "key": "$ZIVPN_KEY_FILE",
   "obfs":"zivpn",
   "auth": {
    "mode": "passwords", 
    "config": $json_passwords
  }
}
EOF

    echo -e "\n${C_GREEN}🚀 Starting ZiVPN Service...${C_RESET}"
    systemctl daemon-reload
    systemctl enable zivpn.service
    systemctl start zivpn.service

    # Port Forwarding / Firewall
    echo -e "${C_BLUE}🔥 Configuring Firewall Rules (Redirecting 6000-19999 -> 5667)...${C_RESET}"
    
    # Determine primary interface
    local iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    
    if [ -n "$iface" ]; then
        iptables -t nat -A PREROUTING -i "$iface" -p udp --dport 6000:19999 -j DNAT --to-destination :5667
        # Note: IPTables rules are not persistent by default without iptables-persistent package
    else
        echo -e "${C_YELLOW}⚠️ Could not detect default interface for IPTables redirection.${C_RESET}"
    fi

    if command -v ufw &>/dev/null; then
        ufw allow 6000:19999/udp >/dev/null
        ufw allow 5667/udp >/dev/null
    fi

    # Cleanup
    rm -f zi.sh zi2.sh 2>/dev/null

    if systemctl is-active --quiet zivpn.service; then
        echo -e "\n${C_GREEN}✅ ZiVPN Installed Successfully!${C_RESET}"
        echo -e "   - UDP Port: 5667 (Direct)"
        echo -e "   - UDP Ports: 6000-19999 (Forwarded)"
    else
        echo -e "\n${C_RED}❌ ZiVPN Service failed to start. Check logs: journalctl -u zivpn.service${C_RESET}"
    fi
}

uninstall_zivpn() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🗑️ Uninstall ZiVPN ---${C_RESET}"
    
    if [ ! -f "$ZIVPN_SERVICE_FILE" ] && [ ! -f "$ZIVPN_BIN" ]; then
        echo -e "\n${C_YELLOW}ℹ️ ZiVPN does not appear to be installed.${C_RESET}"
        return
    fi

    read -p "👉 Are you sure you want to uninstall ZiVPN? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then echo -e "${C_YELLOW}Cancelled.${C_RESET}"; return; fi

    echo -e "\n${C_BLUE}🛑 Stopping services...${C_RESET}"
    systemctl stop zivpn.service 2>/dev/null
    systemctl disable zivpn.service 2>/dev/null
    
    echo -e "${C_BLUE}🗑️ Removing files...${C_RESET}"
    rm -f "$ZIVPN_SERVICE_FILE"
    rm -rf "$ZIVPN_DIR"
    rm -f "$ZIVPN_BIN"
    
    systemctl daemon-reload
    
    # Clean cache (from original uninstall script logic)
    echo -e "${C_BLUE}🧹 Cleaning memory cache...${C_RESET}"
    sync; echo 3 > /proc/sys/vm/drop_caches

    echo -e "\n${C_GREEN}✅ ZiVPN Uninstalled Successfully.${C_RESET}"
}

# =============================================================================
# HTTP Custom Protocol Support
# =============================================================================
HTTP_CUSTOM_DIR="/root/http-custom"
HTTP_CUSTOM_BINARY="/usr/local/bin/http-custom"
HTTP_CUSTOM_SERVICE_FILE="/etc/systemd/system/http-custom.service"
HTTP_CUSTOM_PORT="3128"

install_http_custom() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🌐 Installing HTTP Custom ---${C_RESET}"
    if [ -f "$HTTP_CUSTOM_SERVICE_FILE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ HTTP Custom is already installed.${C_RESET}"
        if systemctl is-active --quiet http-custom; then
            echo -e "${C_GREEN}✅ HTTP Custom service is active.${C_RESET}"
        else
            echo -e "${C_YELLOW}⚠️ HTTP Custom service is not running.${C_RESET}"
            read -p "👉 Do you want to start it? (y/n): " start_confirm
            if [[ "$start_confirm" == "y" ]]; then
                systemctl start http-custom
                sleep 2
                if systemctl is-active --quiet http-custom; then
                    echo -e "${C_GREEN}✅ HTTP Custom started successfully.${C_RESET}"
                fi
            fi
        fi
        return
    fi

    check_and_open_firewall_port "$HTTP_CUSTOM_PORT" tcp || return

    echo -e "\n${C_GREEN}⚙️ Creating directory for HTTP Custom...${C_RESET}"
    rm -rf "$HTTP_CUSTOM_DIR"
    mkdir -p "$HTTP_CUSTOM_DIR"

    echo -e "\n${C_GREEN}⚙️ Detecting system architecture...${C_RESET}"
    local arch
    arch=$(uname -m)
    local binary_url=""
    if [[ "$arch" == "x86_64" ]]; then
        binary_url="https://github.com/firewallfalcons/FirewallFalcon-Manager/raw/main/http-custom/http-custom-linux-amd64"
        echo -e "${C_BLUE}ℹ️ Detected x86_64 (amd64) architecture.${C_RESET}"
    elif [[ "$arch" == "aarch64" || "$arch" == "arm64" ]]; then
        binary_url="https://github.com/firewallfalcons/FirewallFalcon-Manager/raw/main/http-custom/http-custom-linux-arm64"
        echo -e "${C_BLUE}ℹ️ Detected ARM64 architecture.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ Unsupported architecture: $arch. Cannot install HTTP Custom.${C_RESET}"
        rm -rf "$HTTP_CUSTOM_DIR"
        return
    fi

    read -p "👉 Enter HTTP Custom port (press Enter for default $HTTP_CUSTOM_PORT): " custom_port
    if [[ -n "$custom_port" ]] && [[ "$custom_port" =~ ^[0-9]+$ ]]; then
        HTTP_CUSTOM_PORT="$custom_port"
    fi

    echo -e "\n${C_GREEN}📥 Downloading HTTP Custom binary...${C_RESET}"
    if ! wget -q --show-progress -O "$HTTP_CUSTOM_DIR/http-custom" "$binary_url"; then
        echo -e "\n${C_RED}❌ Failed to download the HTTP Custom binary from $binary_url${C_RESET}"
        rm -rf "$HTTP_CUSTOM_DIR"
        return 1
    fi

    if [[ ! -f "$HTTP_CUSTOM_DIR/http-custom" ]] || [[ ! -s "$HTTP_CUSTOM_DIR/http-custom" ]]; then
        echo -e "\n${C_RED}❌ Downloaded file is empty or missing.${C_RESET}"
        rm -rf "$HTTP_CUSTOM_DIR"
        return 1
    fi

    chmod +x "$HTTP_CUSTOM_DIR/http-custom"
    cp "$HTTP_CUSTOM_DIR/http-custom" "$HTTP_CUSTOM_BINARY"

    echo -e "\n${C_GREEN}📝 Creating systemd service...${C_RESET}"
    cat > "$HTTP_CUSTOM_SERVICE_FILE" <<EOF
[Unit]
Description=HTTP Custom Proxy Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$HTTP_CUSTOM_DIR
ExecStart=$HTTP_CUSTOM_BINARY -addr :$HTTP_CUSTOM_PORT
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    echo -e "\n${C_GREEN}▶️ Enabling and starting HTTP Custom service...${C_RESET}"
    
    # Reload systemd daemon
    systemctl daemon-reload 2>/dev/null || true
    sleep 1
    
    # Enable and start HTTP Custom service with retry logic
    local http_enable_attempts=0
    local http_start_attempts=0
    local http_service_enabled=false
    local http_service_started=false
    
    # Enable service
    while [[ $http_enable_attempts -lt 3 ]]; do
        http_enable_attempts=$((http_enable_attempts + 1))
        if systemctl enable http-custom.service 2>/dev/null || systemctl enable http-custom 2>/dev/null; then
            http_service_enabled=true
            echo -e "${C_GREEN}✅ HTTP Custom service enabled successfully${C_RESET}"
            break
        else
            if [[ $http_enable_attempts -lt 3 ]]; then
                echo -e "${C_YELLOW}⚠️ Enable attempt $http_enable_attempts failed, retrying...${C_RESET}"
                systemctl daemon-reload 2>/dev/null
                sleep 1
            fi
        fi
    done
    
    if [[ "$http_service_enabled" != "true" ]]; then
        echo -e "${C_YELLOW}⚠️ Warning: Failed to enable HTTP Custom service after 3 attempts, but continuing...${C_RESET}"
    fi
    
    # Check for port conflicts before starting
    if ss -lntp 2>/dev/null | grep -qE ":${HTTP_CUSTOM_PORT}\s" || netstat -lntp 2>/dev/null | grep -qE ":${HTTP_CUSTOM_PORT}\s"; then
        local port_conflict=$(ss -lntp 2>/dev/null | grep -E ":${HTTP_CUSTOM_PORT}\s" | head -n1 || netstat -lntp 2>/dev/null | grep -E ":${HTTP_CUSTOM_PORT}\s" | head -n1)
        if ! echo "$port_conflict" | grep -qE "http-custom|httpcustom"; then
            echo -e "${C_YELLOW}⚠️ Port $HTTP_CUSTOM_PORT is in use: $port_conflict${C_RESET}"
            echo -e "${C_BLUE}🔧 Attempting to free port $HTTP_CUSTOM_PORT...${C_RESET}"
            pkill -f "http-custom.*${HTTP_CUSTOM_PORT}" 2>/dev/null
            sleep 2
        fi
    fi
    
    # Start service with diagnostics and auto-fix
    while [[ $http_start_attempts -lt 3 ]]; do
        http_start_attempts=$((http_start_attempts + 1))
        
        if systemctl start http-custom.service 2>/dev/null || systemctl start http-custom 2>/dev/null; then
            sleep 3
            if systemctl is-active --quiet http-custom.service 2>/dev/null || systemctl is-active --quiet http-custom 2>/dev/null; then
                http_service_started=true
                break
            else
                echo -e "${C_YELLOW}⚠️ Service started but is not active. Diagnosing...${C_RESET}"
            fi
        fi
        
        if [[ $http_start_attempts -lt 3 ]]; then
            echo -e "${C_YELLOW}⚠️ Start attempt $http_start_attempts failed. Diagnosing and fixing...${C_RESET}"
            
            # Check for binary permission issues
            if [[ -f "$HTTP_CUSTOM_BINARY" ]] && [[ ! -x "$HTTP_CUSTOM_BINARY" ]]; then
                echo -e "${C_BLUE}🔧 Fixing: Binary not executable. Adding execute permissions...${C_RESET}"
                chmod +x "$HTTP_CUSTOM_BINARY" 2>/dev/null
            fi
            
            # Check for missing binary
            if [[ ! -f "$HTTP_CUSTOM_BINARY" ]]; then
                echo -e "${C_RED}❌ HTTP Custom binary not found at: $HTTP_CUSTOM_BINARY${C_RESET}"
                return 1
            fi
            
            # Reload daemon before retry
            systemctl daemon-reload 2>/dev/null
            sleep 2
        fi
    done
    
    # Check service status with multiple methods - improved detection
    local http_custom_started=false
    
    # Try multiple service name formats
    if [[ "$http_service_started" == "true" ]] || systemctl is-active --quiet http-custom.service 2>/dev/null || systemctl is-active --quiet http-custom 2>/dev/null; then
        http_custom_started=true
    elif ss -lntp 2>/dev/null | grep -qE ":${HTTP_CUSTOM_PORT}\s" || netstat -lntp 2>/dev/null | grep -qE ":${HTTP_CUSTOM_PORT}\s" || lsof -i TCP:${HTTP_CUSTOM_PORT} 2>/dev/null | grep -q LISTEN; then
        # Port is listening, service might be running but systemd doesn't recognize it
        http_custom_started=true
        echo -e "${C_YELLOW}⚠️ Port $HTTP_CUSTOM_PORT is listening but systemd service status unclear.${C_RESET}"
    fi
    
    if [[ "$http_custom_started" == "true" ]]; then
        echo -e "\n${C_GREEN}✅ SUCCESS: HTTP Custom is installed and active on port $HTTP_CUSTOM_PORT.${C_RESET}"
        echo -e "${C_CYAN}ℹ️ HTTP Custom is now running and ready to accept connections.${C_RESET}"
        echo -e "${C_YELLOW}💡 Configure your client to connect to this server's IP on port $HTTP_CUSTOM_PORT${C_RESET}"
        
        # Auto-configure DNS forwarding and SSH when HTTP Custom (proxy) is installed
        echo -e "\n${C_BLUE}⚙️ Auto-configuring VPN services (DNS forwarding & SSH)...${C_RESET}"
        setup_vpn_auto_config
    else
        echo -e "\n${C_RED}❌ ERROR: HTTP Custom service failed to start.${C_RESET}"
        echo -e "${C_YELLOW}ℹ️ Checking service status...${C_RESET}"
        
        # Check if service exists
        if systemctl list-unit-files | grep -q "http-custom"; then
            echo -e "${C_YELLOW}⚠️ Service file exists but service is not active.${C_RESET}"
            systemctl status http-custom.service --no-pager -l 2>/dev/null || systemctl status http-custom --no-pager -l 2>/dev/null || true
        fi
        
        echo -e "\n${C_YELLOW}ℹ️ Displaying last 20 lines of the service log for diagnostics:${C_RESET}"
        journalctl -u http-custom.service -n 20 --no-pager 2>/dev/null || journalctl -u http-custom -n 20 --no-pager 2>/dev/null || echo -e "${C_RED}Unable to retrieve service logs${C_RESET}"
        
        # Try to start service one more time
        echo -e "\n${C_BLUE}🔄 Attempting to restart HTTP Custom service...${C_RESET}"
        systemctl restart http-custom.service 2>/dev/null || systemctl restart http-custom 2>/dev/null
        sleep 3
        if systemctl is-active --quiet http-custom.service 2>/dev/null || systemctl is-active --quiet http-custom 2>/dev/null; then
            echo -e "${C_GREEN}✅ HTTP Custom service started successfully after restart!${C_RESET}"
            http_custom_started=true
        else
            echo -e "\n${C_YELLOW}💡 Troubleshooting tips:${C_RESET}"
            echo -e "  - Check if port $HTTP_CUSTOM_PORT is already in use: ${C_CYAN}ss -lntp | grep :$HTTP_CUSTOM_PORT${C_RESET}"
            echo -e "  - Check if binary exists: ${C_CYAN}ls -la $HTTP_CUSTOM_BINARY${C_RESET}"
            echo -e "  - Check binary permissions: ${C_CYAN}chmod +x $HTTP_CUSTOM_BINARY${C_RESET}"
            echo -e "  - Try starting manually: ${C_CYAN}systemctl start http-custom.service && systemctl status http-custom.service${C_RESET}"
            echo -e "  - Check firewall rules for port $HTTP_CUSTOM_PORT"
            echo -e "  - View full logs: ${C_CYAN}journalctl -u http-custom.service -f${C_RESET}"
        fi
    fi
    
    # Final verification
    if [[ "$http_custom_started" == "true" ]]; then
        echo -e "\n${C_GREEN}✅ HTTP Custom is ready to use!${C_RESET}"
    fi
}

uninstall_http_custom() {
    echo -e "\n${C_BOLD}${C_PURPLE}--- 🗑️ Uninstalling HTTP Custom ---${C_RESET}"
    if [ ! -f "$HTTP_CUSTOM_SERVICE_FILE" ]; then
        echo -e "${C_YELLOW}ℹ️ HTTP Custom is not installed, skipping.${C_RESET}"
        return
    fi
    echo -e "${C_GREEN}🛑 Stopping and disabling HTTP Custom service...${C_RESET}"
    systemctl stop http-custom.service >/dev/null 2>&1
    systemctl disable http-custom.service >/dev/null 2>&1
    echo -e "${C_GREEN}🗑️ Removing systemd service file...${C_RESET}"
    rm -f "$HTTP_CUSTOM_SERVICE_FILE"
    systemctl daemon-reload
    echo -e "${C_GREEN}🗑️ Removing HTTP Custom directory and files...${C_RESET}"
    rm -rf "$HTTP_CUSTOM_DIR"
    rm -f "$HTTP_CUSTOM_BINARY"
    echo -e "${C_GREEN}✅ HTTP Custom has been uninstalled successfully.${C_RESET}"
}

# =============================================================================
# iptables Configuration & Management
# =============================================================================

configure_iptables() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🔥 iptables Configuration ---${C_RESET}"
    
    # Check if iptables is installed
    if ! command -v iptables &> /dev/null; then
        echo -e "\n${C_YELLOW}⚠️ iptables not found. Installing...${C_RESET}"
        apt-get update >/dev/null 2>&1
        if ! apt-get install -y iptables iptables-persistent >/dev/null 2>&1; then
            echo -e "${C_RED}❌ Failed to install iptables.${C_RESET}"
            return 1
        fi
        echo -e "${C_GREEN}✅ iptables installed successfully.${C_RESET}"
    fi
    
    # Create iptables directory if it doesn't exist
    mkdir -p /etc/iptables
    
    echo -e "\n${C_BLUE}📝 Creating comprehensive iptables rules...${C_RESET}"
    
    # Backup existing rules
    if [ -f "$IPTABLES_CONFIG_FILE" ]; then
        cp "$IPTABLES_CONFIG_FILE" "${IPTABLES_CONFIG_FILE}.bak.$(date +%Y%m%d_%H%M%S)"
        echo -e "${C_GREEN}✅ Backup of existing rules created.${C_RESET}"
    fi
    
    # Create iptables rules script
    cat > "$IPTABLES_SCRIPT_FILE" <<'IPTABLES_EOF'
#!/bin/bash
# iptables Rules for VPN Server
# Generated by MRCYBER255-KITONGA Manager

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Set default policies
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established and related connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (port 22)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow common VPN ports (DNSTT, OpenVPN, WireGuard, etc.)
# DNSTT
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --dport 5300 -j ACCEPT

# OpenVPN
iptables -A INPUT -p udp --dport 1194 -j ACCEPT
iptables -A INPUT -p tcp --dport 1194 -j ACCEPT

# WireGuard
iptables -A INPUT -p udp --dport 51820 -j ACCEPT

# VPN Services
iptables -A INPUT -p tcp --dport 444 -j ACCEPT  # SSL Tunnel
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT  # WebSocket Proxy
iptables -A INPUT -p tcp --dport 3128 -j ACCEPT  # HTTP Custom
iptables -A INPUT -p udp --dport 7300 -j ACCEPT  # BadVPN
iptables -A INPUT -p udp --dport 5667 -j ACCEPT  # ZiVPN

# Nginx/Web Server
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# V2Ray/XRay
iptables -A INPUT -p tcp --dport 8787 -j ACCEPT

# ICMP (ping)
iptables -A INPUT -p icmp -j ACCEPT

# Allow forwarding for VPN interfaces
iptables -A FORWARD -i tun+ -j ACCEPT
iptables -A FORWARD -i tap+ -j ACCEPT
iptables -A FORWARD -i wg+ -j ACCEPT

# NAT Masquerading for VPN tunnels
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -o ens3 -j MASQUERADE
iptables -t nat -A POSTROUTING -o venet0 -j MASQUERADE
iptables -t nat -A POSTROUTING -o tun+ -j MASQUERADE
iptables -t nat -A POSTROUTING -o tap+ -j MASQUERADE
iptables -t nat -A POSTROUTING -o wg+ -j MASQUERADE

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Save rules (if iptables-persistent is installed)
if command -v iptables-save &> /dev/null; then
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
fi

echo "iptables rules applied successfully"
IPTABLES_EOF

    chmod +x "$IPTABLES_SCRIPT_FILE"
    
    echo -e "\n${C_BLUE}⚙️ Applying iptables rules...${C_RESET}"
    bash "$IPTABLES_SCRIPT_FILE"
    
    # Install iptables-persistent for auto-loading rules on boot
    if ! dpkg -l | grep -q iptables-persistent; then
        echo -e "\n${C_BLUE}📦 Installing iptables-persistent for rule persistence...${C_RESET}"
        echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
        echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
        apt-get install -y iptables-persistent >/dev/null 2>&1
    fi
    
    # Save rules to persistent location
    if command -v netfilter-persistent &> /dev/null; then
        iptables-save > "$IPTABLES_CONFIG_FILE"
        netfilter-persistent save >/dev/null 2>&1
    elif command -v iptables-save &> /dev/null; then
        iptables-save > "$IPTABLES_CONFIG_FILE"
    fi
    
    echo -e "\n${C_GREEN}✅ iptables rules configured and saved successfully!${C_RESET}"
    echo -e "${C_CYAN}ℹ️ Rules will be automatically loaded on system boot${C_RESET}"
    echo -e "${C_YELLOW}💡 View current rules: ${C_WHITE}iptables -L -v -n${C_RESET}"
    echo -e "${C_YELLOW}💡 View NAT rules: ${C_WHITE}iptables -t nat -L -v -n${C_RESET}"
}

view_iptables_rules() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🔍 View iptables Rules ---${C_RESET}"
    echo
    
    if ! command -v iptables &> /dev/null; then
        echo -e "${C_RED}❌ iptables is not installed.${C_RESET}"
        return 1
    fi
    
    echo -e "${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_BOLD}${C_BLUE}  📋 FILTER TABLE (INPUT/FORWARD/OUTPUT)${C_RESET}"
    echo -e "${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    iptables -L -v -n --line-numbers
    
    echo -e "\n${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_BOLD}${C_BLUE}  🔀 NAT TABLE (Masquerading)${C_RESET}"
    echo -e "${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    iptables -t nat -L -v -n --line-numbers
    
    echo -e "\n${C_BLUE}💡 To view rules in detail, use:${C_RESET}"
    echo -e "  ${C_YELLOW}iptables -L -v -n${C_RESET} - View filter table"
    echo -e "  ${C_YELLOW}iptables -t nat -L -v -n${C_RESET} - View NAT table"
}

reset_iptables_rules() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🗑️ Reset iptables Rules ---${C_RESET}"
    
    if ! command -v iptables &> /dev/null; then
        echo -e "\n${C_YELLOW}ℹ️ iptables is not installed. Nothing to reset.${C_RESET}"
        return
    fi
    
    read -p "👉 Are you sure you want to reset all iptables rules to default? (y/n): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo -e "${C_YELLOW}❌ Reset cancelled.${C_RESET}"
        return
    fi
    
    echo -e "\n${C_BLUE}🔄 Flushing all iptables rules...${C_RESET}"
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    
    # Set default policies to ACCEPT (be careful!)
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # Save empty rules
    if command -v iptables-save &> /dev/null; then
        iptables-save > "$IPTABLES_CONFIG_FILE"
        if command -v netfilter-persistent &> /dev/null; then
            netfilter-persistent save >/dev/null 2>&1
        fi
    fi
    
    echo -e "${C_GREEN}✅ iptables rules have been reset to default (ACCEPT all).${C_RESET}"
    echo -e "${C_YELLOW}⚠️ WARNING: All traffic is now allowed. Configure firewall rules immediately!${C_RESET}"
}

# =============================================================================
# TCP BBR (Bottleneck Bandwidth and Round-trip propagation time)
# =============================================================================

enable_tcp_bbr() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Enable TCP BBR Congestion Control ---${C_RESET}"
    
    # Check kernel version (BBR requires Linux 4.9+)
    local kernel_version
    kernel_version=$(uname -r | cut -d'.' -f1,2)
    local kernel_major
    kernel_major=$(echo "$kernel_version" | cut -d'.' -f1)
    local kernel_minor
    kernel_minor=$(echo "$kernel_version" | cut -d'.' -f2)
    
    if [[ "$kernel_major" -lt 4 ]] || ([[ "$kernel_major" -eq 4 ]] && [[ "$kernel_minor" -lt 9 ]]); then
        echo -e "\n${C_RED}❌ ERROR: TCP BBR requires Linux kernel 4.9 or higher.${C_RESET}"
        echo -e "${C_YELLOW}Current kernel version: $(uname -r)${C_RESET}"
        echo -e "${C_YELLOW}Please upgrade your kernel to enable TCP BBR.${C_RESET}"
        return 1
    fi
    
    echo -e "${C_GREEN}✅ Kernel version check passed: $(uname -r)${C_RESET}"
    
    # Check if BBR module is available
    if ! modprobe tcp_bbr 2>/dev/null; then
        echo -e "\n${C_YELLOW}⚠️ Warning: Could not load tcp_bbr module.${C_RESET}"
        echo -e "${C_YELLOW}BBR may be built into the kernel. Continuing...${C_RESET}"
    else
        echo -e "${C_GREEN}✅ TCP BBR module loaded successfully${C_RESET}"
    fi
    
    # Backup current sysctl configuration
    if [ -f /etc/sysctl.conf ]; then
        cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%Y%m%d_%H%M%S)
        echo -e "${C_GREEN}✅ Backup of /etc/sysctl.conf created${C_RESET}"
    fi
    
    echo -e "\n${C_BLUE}📝 Configuring TCP BBR and network optimizations...${C_RESET}"
    
    # Enable TCP BBR
    cat >> /etc/sysctl.conf <<'BBR_EOF'

# =============================================================================
# TCP BBR Configuration (Added by MRCYBER255-KITONGA Manager)
# =============================================================================
# Enable TCP BBR congestion control algorithm
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

# Network optimizations for better performance
# Increase TCP buffer sizes
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# TCP optimizations
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 0  # Disabled in newer kernels
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 8192

# Connection tracking
net.netfilter.nf_conntrack_max = 1000000
net.ipv4.ip_conntrack_max = 1000000

# IP forwarding (for VPN)
net.ipv4.ip_forward = 1

# TCP fast open
net.ipv4.tcp_fastopen = 3

# Window scaling
net.ipv4.tcp_window_scaling = 1

# Timestamps
net.ipv4.tcp_timestamps = 1

# SACK (Selective Acknowledgment)
net.ipv4.tcp_sack = 1
BBR_EOF

    # Apply settings immediately
    echo -e "\n${C_BLUE}⚙️ Applying TCP BBR settings...${C_RESET}"
    sysctl -p >/dev/null 2>&1
    
    # Verify BBR is enabled
    local current_cc
    current_cc=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
    local default_qdisc
    default_qdisc=$(sysctl net.core.default_qdisc | awk '{print $3}')
    
    if [[ "$current_cc" == "bbr" ]]; then
        echo -e "${C_GREEN}✅ TCP BBR is now active!${C_RESET}"
        echo -e "${C_CYAN}ℹ️ Current congestion control: ${C_YELLOW}$current_cc${C_RESET}"
        echo -e "${C_CYAN}ℹ️ Default queuing discipline: ${C_YELLOW}$default_qdisc${C_RESET}"
        echo -e "\n${C_GREEN}✅ Network optimizations have been applied successfully!${C_RESET}"
        echo -e "${C_YELLOW}💡 Settings will persist across reboots${C_RESET}"
    else
        echo -e "${C_YELLOW}⚠️ Warning: TCP BBR may not be fully active yet.${C_RESET}"
        echo -e "${C_YELLOW}Current congestion control: $current_cc${C_RESET}"
        echo -e "${C_YELLOW}You may need to reboot for BBR to take full effect.${C_RESET}"
    fi
    
    # Show BBR status
    echo -e "\n${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_BOLD}${C_BLUE}  📊 TCP BBR Status${C_RESET}"
    echo -e "${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "  ${C_CYAN}TCP Congestion Control:${C_RESET} $(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')"
    echo -e "  ${C_CYAN}Default Qdisc:${C_RESET} $(sysctl net.core.default_qdisc | awk '{print $3}')"
    echo -e "  ${C_CYAN}IP Forwarding:${C_RESET} $(sysctl net.ipv4.ip_forward | awk '{print $3}')"
    echo -e "  ${C_CYAN}Available Congestion Controls:${C_RESET}"
    cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null | tr ' ' '\n' | sed 's/^/    - /' || echo "    (Unable to read)"
}

configure_ipv6() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🌐 IPv6 Configuration ---${C_RESET}"
    echo ""
    
    # Check current IPv6 status
    local ipv6_currently_enabled=false
    if sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null | grep -q "= 0"; then
        ipv6_currently_enabled=true
    fi
    
    if [[ "$ipv6_currently_enabled" == "true" ]]; then
        echo -e "${C_GREEN}✅ IPv6 is currently ENABLED on this VPS${C_RESET}"
        echo ""
        read -p "👉 Do you want to disable IPv6? (yes/no): " disable_ipv6
        if [[ "$disable_ipv6" == "yes" ]]; then
            echo -e "\n${C_BLUE}🔧 Disabling IPv6...${C_RESET}"
            
            # Disable IPv6 in sysctl
            if ! grep -q "^net.ipv6.conf.all.disable_ipv6 = 1" /etc/sysctl.conf 2>/dev/null; then
                sed -i '/^net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.conf
                sed -i '/^#.*IPv6/d' /etc/sysctl.conf
                echo "" >> /etc/sysctl.conf
                echo "# IPv6 Configuration (Disabled by MRCYBER255-KITONGA Manager)" >> /etc/sysctl.conf
                echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
                echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
                echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
            fi
            
            # Apply changes
            sysctl -p >/dev/null 2>&1
            
            echo -e "${C_GREEN}✅ IPv6 has been disabled successfully${C_RESET}"
            echo -e "${C_YELLOW}💡 Changes will persist across reboots${C_RESET}"
            return 0
        else
            echo -e "${C_YELLOW}ℹ️ IPv6 configuration unchanged${C_RESET}"
            return 0
        fi
    else
        echo -e "${C_YELLOW}ℹ️ IPv6 is currently DISABLED on this VPS${C_RESET}"
        echo ""
        read -p "👉 Do you want to enable IPv6 on this VPS? (yes/no): " enable_ipv6
        
        if [[ "$enable_ipv6" == "yes" ]]; then
            echo -e "\n${C_BLUE}🔧 Enabling IPv6...${C_RESET}"
            
            # Enable IPv6 in sysctl
            if ! grep -q "^net.ipv6.conf.all.disable_ipv6 = 0" /etc/sysctl.conf 2>/dev/null; then
                sed -i '/^net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.conf
                sed -i '/^#.*IPv6/d' /etc/sysctl.conf
                echo "" >> /etc/sysctl.conf
                echo "# IPv6 Configuration (Enabled by MRCYBER255-KITONGA Manager)" >> /etc/sysctl.conf
                echo "net.ipv6.conf.all.disable_ipv6 = 0" >> /etc/sysctl.conf
                echo "net.ipv6.conf.default.disable_ipv6 = 0" >> /etc/sysctl.conf
                echo "net.ipv6.conf.lo.disable_ipv6 = 0" >> /etc/sysctl.conf
            fi
            
            # Apply changes
            sysctl -p >/dev/null 2>&1
            
            # Detect network interface
            local network_interface=""
            if command -v ip &> /dev/null; then
                network_interface=$(ip route | grep default | awk '{print $5}' | head -n1)
            elif command -v route &> /dev/null; then
                network_interface=$(route -n | grep '^0.0.0.0' | awk '{print $8}' | head -n1)
            else
                # Try common interface names
                for iface in eth0 ens3 ens33 enp0s3; do
                    if ip link show "$iface" &>/dev/null; then
                        network_interface="$iface"
                        break
                    fi
                done
            fi
            
            if [[ -z "$network_interface" ]]; then
                echo -e "${C_YELLOW}⚠️ Could not automatically detect network interface${C_RESET}"
                read -p "👉 Enter your network interface name (e.g., eth0, ens3): " network_interface
            fi
            
            if [[ -n "$network_interface" ]] && ip link show "$network_interface" &>/dev/null; then
                echo -e "${C_GREEN}✅ Detected network interface: $network_interface${C_RESET}"
                
                # Check if IPv6 address already exists
                if ip -6 addr show dev "$network_interface" 2>/dev/null | grep -q "inet6"; then
                    echo -e "${C_GREEN}✅ IPv6 address already configured on $network_interface${C_RESET}"
                else
                    echo -e "${C_YELLOW}⚠️ No IPv6 address found on $network_interface${C_RESET}"
                    read -p "👉 Do you have an IPv6 address to configure? (yes/no): " has_ipv6_addr
                    
                    if [[ "$has_ipv6_addr" == "yes" ]]; then
                        read -p "👉 Enter your IPv6 address (e.g., 2001:db8::1/64): " ipv6_address
                        if [[ -n "$ipv6_address" ]]; then
                            if ip -6 addr add "$ipv6_address" dev "$network_interface" 2>/dev/null; then
                                echo -e "${C_GREEN}✅ IPv6 address configured: $ipv6_address${C_RESET}"
                            else
                                echo -e "${C_YELLOW}⚠️ Failed to add IPv6 address. You may need to configure it manually.${C_RESET}"
                            fi
                        fi
                    else
                        echo -e "${C_YELLOW}ℹ️ IPv6 is enabled but no address configured. Configure it manually or through your VPS provider.${C_RESET}"
                    fi
                fi
            else
                echo -e "${C_YELLOW}⚠️ Network interface '$network_interface' not found. IPv6 enabled in sysctl but interface configuration skipped.${C_RESET}"
            fi
            
            # Configure IPv6 firewall if ip6tables is available
            if command -v ip6tables &> /dev/null; then
                echo -e "\n${C_BLUE}🔧 Configuring IPv6 firewall (ip6tables)...${C_RESET}"
                ip6tables -P INPUT ACCEPT 2>/dev/null
                ip6tables -P FORWARD ACCEPT 2>/dev/null
                ip6tables -P OUTPUT ACCEPT 2>/dev/null
                echo -e "${C_GREEN}✅ IPv6 firewall rules configured (allowing all traffic)${C_RESET}"
                echo -e "${C_YELLOW}💡 You may want to configure more restrictive rules later${C_RESET}"
            else
                echo -e "${C_YELLOW}ℹ️ ip6tables not found. Skipping IPv6 firewall configuration.${C_RESET}"
            fi
            
            echo -e "\n${C_GREEN}✅ IPv6 has been enabled successfully${C_RESET}"
            echo -e "${C_YELLOW}💡 Changes will persist across reboots${C_RESET}"
            
            # Show IPv6 status
            echo -e "\n${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
            echo -e "${C_BOLD}${C_BLUE}  📊 IPv6 Status${C_RESET}"
            echo -e "${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
            echo -e "  ${C_CYAN}IPv6 Status:${C_RESET} $(sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null | awk '{print $3}')"
            if [[ -n "$network_interface" ]]; then
                echo -e "  ${C_CYAN}Interface:${C_RESET} $network_interface"
                local ipv6_addrs
                ipv6_addrs=$(ip -6 addr show dev "$network_interface" 2>/dev/null | grep "inet6" | awk '{print $2}' | head -n3)
                if [[ -n "$ipv6_addrs" ]]; then
                    echo -e "  ${C_CYAN}IPv6 Addresses:${C_RESET}"
                    echo "$ipv6_addrs" | while read -r addr; do
                        echo -e "    - ${C_YELLOW}$addr${C_RESET}"
                    done
                else
                    echo -e "  ${C_YELLOW}⚠️ No IPv6 addresses configured${C_RESET}"
                fi
            fi
        else
            echo -e "${C_YELLOW}ℹ️ Continuing with IPv4-only configuration...${C_RESET}"
        fi
    fi
}

check_tcp_bbr_status() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 📊 TCP BBR Status Check ---${C_RESET}"
    
    local kernel_version
    kernel_version=$(uname -r)
    local kernel_major
    kernel_major=$(echo "$kernel_version" | cut -d'.' -f1)
    local kernel_minor
    kernel_minor=$(echo "$kernel_version" | cut -d'.' -f2 | cut -d'-' -f1)
    
    echo -e "\n${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_BOLD}${C_BLUE}  🖥️ System Information${C_RESET}"
    echo -e "${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "  ${C_CYAN}Kernel Version:${C_RESET} $kernel_version"
    
    if [[ "$kernel_major" -lt 4 ]] || ([[ "$kernel_major" -eq 4 ]] && [[ "$kernel_minor" -lt 9 ]]); then
        echo -e "  ${C_RED}⚠️ BBR Support:${C_RESET} Kernel 4.9+ required (current: $kernel_version)"
    else
        echo -e "  ${C_GREEN}✅ BBR Support:${C_RESET} Kernel supports BBR (4.9+)"
    fi
    
    echo -e "\n${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_BOLD}${C_BLUE}  🔧 Current Configuration${C_RESET}"
    echo -e "${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    local current_cc
    current_cc=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
    local default_qdisc
    default_qdisc=$(sysctl net.core.default_qdisc 2>/dev/null | awk '{print $3}')
    
    if [[ "$current_cc" == "bbr" ]]; then
        echo -e "  ${C_GREEN}🟢 TCP Congestion Control:${C_RESET} ${C_GREEN}$current_cc${C_RESET} ✅"
    else
        echo -e "  ${C_YELLOW}🟡 TCP Congestion Control:${C_RESET} ${C_YELLOW}$current_cc${C_RESET} (BBR not active)"
    fi
    
    echo -e "  ${C_CYAN}Default Qdisc:${C_RESET} ${default_qdisc:-"(not set)"}"
    echo -e "  ${C_CYAN}IP Forwarding:${C_RESET} $(sysctl net.ipv4.ip_forward 2>/dev/null | awk '{print $3}')"
    
    echo -e "\n${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_BOLD}${C_BLUE}  📋 Available Congestion Controls${C_RESET}"
    echo -e "${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    if [ -f /proc/sys/net/ipv4/tcp_available_congestion_control ]; then
        cat /proc/sys/net/ipv4/tcp_available_congestion_control | tr ' ' '\n' | sed 's/^/  - /'
    else
        echo -e "  ${C_YELLOW}(Unable to read available congestion controls)${C_RESET}"
    fi
}

# =============================================================================
# VPN Connection Detection & Auto-Configuration
# =============================================================================

detect_vpn_connection() {
    local vpn_type="NONE"
    local vpn_active=false
    
    # Check OpenVPN
    if pgrep -x openvpn >/dev/null 2>&1 || systemctl is-active --quiet openvpn* 2>/dev/null; then
        vpn_type="OpenVPN"
        vpn_active=true
    fi
    
    # Check DNSTT
    if systemctl is-active --quiet dnstt.service 2>/dev/null && systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
        if [[ "$vpn_type" != "NONE" ]]; then
            vpn_type="${vpn_type}+DNSTT"
        else
            vpn_type="DNSTT"
        fi
        vpn_active=true
    fi
    
    # Check other VPN services
    if ip link show | grep -q "tun\|tap"; then
        if [[ "$vpn_type" == "NONE" ]]; then
            local tun_interfaces=$(ip link show | grep -oP 'tun\d+|tap\d+' | head -n1)
            if [[ -n "$tun_interfaces" ]]; then
                vpn_type="TUN/TAP ($tun_interfaces)"
                vpn_active=true
            fi
        fi
    fi
    
    # Check WireGuard
    if command -v wg >/dev/null 2>&1 && wg show >/dev/null 2>&1; then
        if [[ "$vpn_type" != "NONE" ]]; then
            vpn_type="${vpn_type}+WireGuard"
        else
            vpn_type="WireGuard"
        fi
        vpn_active=true
    fi
    
    echo "$vpn_type|$vpn_active"
}

enable_dns_forwarding() {
    echo -e "${C_BLUE}🔍 Enabling DNS forwarding...${C_RESET}"
    
    # Check if DNSTT is installed - if so, configure resolv.conf to use localhost
    if [ -f "$DNSTT_SERVICE_FILE" ] || [ -f "$DNSTT_EDNS_SERVICE" ]; then
        # DNSTT is installed - ensure resolv.conf uses 127.0.0.1
        # The EDNS proxy on port 53 will handle DNS forwarding
        if [ ! -L /etc/resolv.conf ] && [ -f /etc/resolv.conf ]; then
            chattr -i /etc/resolv.conf 2>/dev/null
            if ! grep -qE "^nameserver 127.0.0.1" /etc/resolv.conf; then
                echo -e "${C_YELLOW}⚠️ Configuring /etc/resolv.conf for DNSTT DNS forwarding...${C_RESET}"
                # Backup original nameservers
                local backup_dns=$(grep "^nameserver" /etc/resolv.conf | grep -v "127.0.0.1" | head -n 2)
                # Set localhost as primary, keep backup DNS servers
                sed -i '/^nameserver/d' /etc/resolv.conf
                echo "nameserver 127.0.0.1" >> /etc/resolv.conf
                if [[ -n "$backup_dns" ]]; then
                    echo "$backup_dns" >> /etc/resolv.conf
                else
                    echo "nameserver $DNS_PRIMARY" >> /etc/resolv.conf
                    echo "nameserver $DNS_SECONDARY" >> /etc/resolv.conf
                fi
                chattr +i /etc/resolv.conf 2>/dev/null
                echo -e "${C_GREEN}✅ DNS forwarding configured for DNSTT (127.0.0.1)${C_RESET}"
            else
                echo -e "${C_GREEN}✅ DNS forwarding already configured for DNSTT${C_RESET}"
            fi
        fi
        
        # Start DNSTT services if installed but not running
        if [ -f "$DNSTT_SERVICE_FILE" ] && ! systemctl is-active --quiet dnstt.service 2>/dev/null; then
            echo -e "${C_YELLOW}⚠️ DNSTT is installed but not running. Starting...${C_RESET}"
            systemctl start dnstt.service 2>/dev/null
            sleep 2
        fi
        
        if [ -f "$DNSTT_EDNS_SERVICE" ] && ! systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
            systemctl start dnstt-edns-proxy.service 2>/dev/null
            sleep 2
        fi
        
        if systemctl is-active --quiet dnstt.service 2>/dev/null && systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
            echo -e "${C_GREEN}✅ DNSTT DNS forwarding enabled and active${C_RESET}"
        fi
    else
        # DNSTT not installed - use systemd-resolved if available
        if systemctl is-active --quiet systemd-resolved 2>/dev/null && ! systemctl is-masked systemd-resolved 2>/dev/null; then
            if [ -f /etc/systemd/resolved.conf ]; then
                if ! grep -q "^DNSStubListener=no" /etc/systemd/resolved.conf; then
                    sed -i 's/^#DNSStubListener=.*/DNSStubListener=no/' /etc/systemd/resolved.conf
                    sed -i '/^DNSStubListener=no/!s/^DNSStubListener=.*/DNSStubListener=no/' /etc/systemd/resolved.conf
                    if ! grep -q "^DNSStubListener=no" /etc/systemd/resolved.conf; then
                        echo "DNSStubListener=no" >> /etc/systemd/resolved.conf
                    fi
                    systemctl restart systemd-resolved 2>/dev/null
                    echo -e "${C_GREEN}✅ DNS forwarding enabled in systemd-resolved${C_RESET}"
                fi
            fi
        fi
    fi
}

auto_start_ssh_on_vpn() {
    local ssh_service_name=""
    if [ -f /lib/systemd/system/sshd.service ]; then
        ssh_service_name="sshd.service"
    elif [ -f /lib/systemd/system/ssh.service ]; then
        ssh_service_name="ssh.service"
    else
        return 1
    fi
    
    if ! systemctl is-active --quiet "$ssh_service_name" 2>/dev/null; then
        echo -e "${C_BLUE}🔌 Starting SSH service (triggered by VPN connection)...${C_RESET}"
        systemctl start "$ssh_service_name" 2>/dev/null
        sleep 2
        if systemctl is-active --quiet "$ssh_service_name" 2>/dev/null; then
            echo -e "${C_GREEN}✅ SSH service started successfully${C_RESET}"
            return 0
        else
            echo -e "${C_YELLOW}⚠️ SSH service may already be running or failed to start${C_RESET}"
            return 1
        fi
    else
        echo -e "${C_GREEN}✅ SSH service is already active${C_RESET}"
        return 0
    fi
}

setup_vpn_auto_config() {
    local vpn_info
    vpn_info=$(detect_vpn_connection)
    local vpn_type=$(echo "$vpn_info" | cut -d'|' -f1)
    local vpn_active=$(echo "$vpn_info" | cut -d'|' -f2)
    
    if [[ "$vpn_active" == "true" ]]; then
        echo -e "${C_GREEN}✅ VPN Connection Detected: ${C_YELLOW}$vpn_type${C_RESET}"
        enable_dns_forwarding
        auto_start_ssh_on_vpn
        return 0
    else
        echo -e "${C_YELLOW}⚠️ No active VPN connection detected${C_RESET}"
        return 1
    fi
}

fix_all_services() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🔧 Fix All Services (Auto-Repair) ---${C_RESET}"
    echo -e "${C_BLUE}This will automatically diagnose and fix common issues with all installed services.${C_RESET}"
    echo
    read -p "$(echo -e ${C_PROMPT}"👉 Continue? (y/n): "${C_RESET})" confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        return
    fi
    
    local fixed_count=0
    local issues_found=0
    
    echo -e "\n${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_BOLD}${C_CYAN}  🔍 STEP 1: DIAGNOSING SERVICES${C_RESET}"
    echo -e "${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    # Check and fix DNSTT services
    if [ -f "$DNSTT_SERVICE_FILE" ] || [ -f "$DNSTT_EDNS_SERVICE" ] || [ -f "$DNSTT_BINARY" ]; then
        echo -e "\n${C_YELLOW}📡 Fixing DNSTT services...${C_RESET}"
        
        # Check DNSTT binary
        if [ -f "$DNSTT_BINARY" ]; then
            if [ ! -x "$DNSTT_BINARY" ]; then
                echo -e "  ${C_YELLOW}⚠️${C_RESET} DNSTT binary is not executable. Fixing..."
                chmod +x "$DNSTT_BINARY" 2>/dev/null
                if [ -x "$DNSTT_BINARY" ]; then
                    echo -e "  ${C_GREEN}✅${C_RESET} DNSTT binary permissions fixed"
                    ((fixed_count++))
                else
                    echo -e "  ${C_RED}❌${C_RESET} Failed to fix DNSTT binary permissions"
                    ((issues_found++))
                fi
            else
                echo -e "  ${C_GREEN}✅${C_RESET} DNSTT binary permissions OK"
            fi
        else
            echo -e "  ${C_YELLOW}⚠️${C_RESET} DNSTT binary not found at $DNSTT_BINARY"
            ((issues_found++))
        fi
        
        # Check and fix DNSTT server service
        if [ -f "$DNSTT_SERVICE_FILE" ]; then
            echo -e "  ${C_BLUE}🔧${C_RESET} Checking DNSTT server service..."
            
            # Reload systemd
            systemctl daemon-reload 2>/dev/null
            
            # Enable service on boot if not enabled
            if ! systemctl is-enabled --quiet dnstt.service 2>/dev/null; then
                echo -e "    ${C_YELLOW}⚠️${C_RESET} DNSTT service not enabled on boot. Enabling..."
                systemctl enable dnstt.service 2>/dev/null
                if systemctl is-enabled --quiet dnstt.service 2>/dev/null; then
                    echo -e "    ${C_GREEN}✅${C_RESET} DNSTT service enabled on boot"
                    ((fixed_count++))
                fi
            else
                echo -e "    ${C_GREEN}✅${C_RESET} DNSTT service already enabled on boot"
            fi
            
            # Start service if not running
            if ! systemctl is-active --quiet dnstt.service 2>/dev/null; then
                echo -e "    ${C_YELLOW}⚠️${C_RESET} DNSTT server not running. Starting..."
                systemctl start dnstt.service 2>/dev/null
                sleep 3
                if systemctl is-active --quiet dnstt.service 2>/dev/null; then
                    echo -e "    ${C_GREEN}✅${C_RESET} DNSTT server started successfully"
                    ((fixed_count++))
                else
                    echo -e "    ${C_RED}❌${C_RESET} DNSTT server failed to start"
                    echo -e "      ${C_DIM}Check logs: journalctl -u dnstt.service -n 20${C_RESET}"
                    journalctl -u dnstt.service -n 10 --no-pager 2>/dev/null | tail -n 5
                    ((issues_found++))
                fi
            else
                echo -e "    ${C_GREEN}✅${C_RESET} DNSTT server is already running"
            fi
        fi
        
        # Check and fix EDNS proxy service
        if [ -f "$DNSTT_EDNS_SERVICE" ]; then
            echo -e "  ${C_BLUE}🔧${C_RESET} Checking DNSTT EDNS proxy service..."
            
            # Reload systemd
            systemctl daemon-reload 2>/dev/null
            
            # Enable service on boot if not enabled
            if ! systemctl is-enabled --quiet dnstt-edns-proxy.service 2>/dev/null; then
                echo -e "    ${C_YELLOW}⚠️${C_RESET} EDNS proxy service not enabled on boot. Enabling..."
                systemctl enable dnstt-edns-proxy.service 2>/dev/null
                if systemctl is-enabled --quiet dnstt-edns-proxy.service 2>/dev/null; then
                    echo -e "    ${C_GREEN}✅${C_RESET} EDNS proxy service enabled on boot"
                    ((fixed_count++))
                fi
            else
                echo -e "    ${C_GREEN}✅${C_RESET} EDNS proxy service already enabled on boot"
            fi
            
            # Check if port 53 is available (systemd-resolved conflict)
            if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
                echo -e "    ${C_YELLOW}⚠️${C_RESET} systemd-resolved is active and may block port 53"
                echo -e "      ${C_BLUE}🔧${C_RESET} Stopping systemd-resolved..."
                systemctl stop systemd-resolved 2>/dev/null
                systemctl disable systemd-resolved 2>/dev/null
                systemctl mask systemd-resolved 2>/dev/null
                chattr -i /etc/resolv.conf 2>/dev/null
                if [ -L /etc/resolv.conf ]; then
                    rm -f /etc/resolv.conf
                fi
                echo "nameserver 127.0.0.1" > /etc/resolv.conf 2>/dev/null
                echo "nameserver 8.8.8.8" >> /etc/resolv.conf 2>/dev/null
                echo "nameserver 8.8.4.4" >> /etc/resolv.conf 2>/dev/null
                chattr +i /etc/resolv.conf 2>/dev/null
                pkill -9 systemd-resolved 2>/dev/null
                sleep 2
                echo -e "      ${C_GREEN}✅${C_RESET} systemd-resolved stopped and disabled"
                ((fixed_count++))
            fi
            
            # Start service if not running
            if ! systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
                echo -e "    ${C_YELLOW}⚠️${C_RESET} EDNS proxy not running. Starting..."
                systemctl start dnstt-edns-proxy.service 2>/dev/null
                sleep 3
                if systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
                    echo -e "    ${C_GREEN}✅${C_RESET} EDNS proxy started successfully"
                    ((fixed_count++))
                else
                    echo -e "    ${C_RED}❌${C_RESET} EDNS proxy failed to start"
                    echo -e "      ${C_DIM}Check logs: journalctl -u dnstt-edns-proxy.service -n 20${C_RESET}"
                    journalctl -u dnstt-edns-proxy.service -n 10 --no-pager 2>/dev/null | tail -n 5
                    ((issues_found++))
                fi
            else
                echo -e "    ${C_GREEN}✅${C_RESET} EDNS proxy is already running"
            fi
        fi
    else
        echo -e "\n${C_DIM}📡 DNSTT: Not installed (skipping)${C_RESET}"
    fi
    
    # Check and fix HTTP Custom service
    if [ -f "$HTTP_CUSTOM_SERVICE_FILE" ] || [ -f "$HTTP_CUSTOM_BINARY" ]; then
        echo -e "\n${C_YELLOW}🌐 Fixing HTTP Custom service...${C_RESET}"
        
        # Check HTTP Custom binary
        if [ -f "$HTTP_CUSTOM_BINARY" ]; then
            if [ ! -x "$HTTP_CUSTOM_BINARY" ]; then
                echo -e "  ${C_YELLOW}⚠️${C_RESET} HTTP Custom binary is not executable. Fixing..."
                chmod +x "$HTTP_CUSTOM_BINARY" 2>/dev/null
                if [ -x "$HTTP_CUSTOM_BINARY" ]; then
                    echo -e "  ${C_GREEN}✅${C_RESET} HTTP Custom binary permissions fixed"
                    ((fixed_count++))
                else
                    echo -e "  ${C_RED}❌${C_RESET} Failed to fix HTTP Custom binary permissions"
                    ((issues_found++))
                fi
            else
                echo -e "  ${C_GREEN}✅${C_RESET} HTTP Custom binary permissions OK"
            fi
        else
            echo -e "  ${C_YELLOW}⚠️${C_RESET} HTTP Custom binary not found at $HTTP_CUSTOM_BINARY"
            ((issues_found++))
        fi
        
        # Check and fix HTTP Custom service
        if [ -f "$HTTP_CUSTOM_SERVICE_FILE" ]; then
            echo -e "  ${C_BLUE}🔧${C_RESET} Checking HTTP Custom service..."
            
            # Reload systemd
            systemctl daemon-reload 2>/dev/null
            
            # Enable service on boot if not enabled
            if ! systemctl is-enabled --quiet http-custom.service 2>/dev/null && ! systemctl is-enabled --quiet http-custom 2>/dev/null; then
                echo -e "    ${C_YELLOW}⚠️${C_RESET} HTTP Custom service not enabled on boot. Enabling..."
                systemctl enable http-custom.service 2>/dev/null || systemctl enable http-custom 2>/dev/null
                if systemctl is-enabled --quiet http-custom.service 2>/dev/null || systemctl is-enabled --quiet http-custom 2>/dev/null; then
                    echo -e "    ${C_GREEN}✅${C_RESET} HTTP Custom service enabled on boot"
                    ((fixed_count++))
                fi
            else
                echo -e "    ${C_GREEN}✅${C_RESET} HTTP Custom service already enabled on boot"
            fi
            
            # Start service if not running
            if ! systemctl is-active --quiet http-custom.service 2>/dev/null && ! systemctl is-active --quiet http-custom 2>/dev/null; then
                echo -e "    ${C_YELLOW}⚠️${C_RESET} HTTP Custom not running. Starting..."
                systemctl start http-custom.service 2>/dev/null || systemctl start http-custom 2>/dev/null
                sleep 3
                if systemctl is-active --quiet http-custom.service 2>/dev/null || systemctl is-active --quiet http-custom 2>/dev/null; then
                    echo -e "    ${C_GREEN}✅${C_RESET} HTTP Custom started successfully"
                    ((fixed_count++))
                else
                    # Check if port is listening as alternative check
                    if ss -lntp 2>/dev/null | grep -qE ":${HTTP_CUSTOM_PORT}\s" || netstat -lntp 2>/dev/null | grep -qE ":${HTTP_CUSTOM_PORT}\s"; then
                        echo -e "    ${C_GREEN}✅${C_RESET} HTTP Custom is running (port $HTTP_CUSTOM_PORT is listening)"
                        ((fixed_count++))
                    else
                        echo -e "    ${C_RED}❌${C_RESET} HTTP Custom failed to start"
                        echo -e "      ${C_DIM}Check logs: journalctl -u http-custom.service -n 20${C_RESET}"
                        journalctl -u http-custom.service -n 10 --no-pager 2>/dev/null | tail -n 5
                        ((issues_found++))
                    fi
                fi
            else
                echo -e "    ${C_GREEN}✅${C_RESET} HTTP Custom is already running"
            fi
        fi
    else
        echo -e "\n${C_DIM}🌐 HTTP Custom: Not installed (skipping)${C_RESET}"
    fi
    
    echo -e "\n${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_BOLD}${C_CYAN}  🔧 STEP 2: CONFIGURING DNS FORWARDING${C_RESET}"
    echo -e "${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    enable_dns_forwarding
    
    echo -e "\n${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_BOLD}${C_CYAN}  ✅ FINAL STATUS CHECK${C_RESET}"
    echo -e "${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    # Final verification
    local all_ok=true
    
    if [ -f "$DNSTT_SERVICE_FILE" ]; then
        if systemctl is-active --quiet dnstt.service 2>/dev/null; then
            echo -e "  ${C_GREEN}✅${C_RESET} DNSTT server: ACTIVE"
        else
            echo -e "  ${C_RED}❌${C_RESET} DNSTT server: INACTIVE"
            all_ok=false
        fi
    fi
    
    if [ -f "$DNSTT_EDNS_SERVICE" ]; then
        if systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
            echo -e "  ${C_GREEN}✅${C_RESET} DNSTT EDNS proxy: ACTIVE"
        else
            echo -e "  ${C_RED}❌${C_RESET} DNSTT EDNS proxy: INACTIVE"
            all_ok=false
        fi
    fi
    
    if [ -f "$HTTP_CUSTOM_SERVICE_FILE" ]; then
        if systemctl is-active --quiet http-custom.service 2>/dev/null || systemctl is-active --quiet http-custom 2>/dev/null; then
            echo -e "  ${C_GREEN}✅${C_RESET} HTTP Custom: ACTIVE"
        elif ss -lntp 2>/dev/null | grep -qE ":${HTTP_CUSTOM_PORT}\s"; then
            echo -e "  ${C_GREEN}✅${C_RESET} HTTP Custom: ACTIVE (port listening)"
        else
            echo -e "  ${C_RED}❌${C_RESET} HTTP Custom: INACTIVE"
            all_ok=false
        fi
    fi
    
    # Check DNS forwarding
    if systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null || ss -lunp 2>/dev/null | grep -qE ':(53|:53)\s'; then
        echo -e "  ${C_GREEN}✅${C_RESET} DNS Forwarding: ACTIVE"
    else
        echo -e "  ${C_YELLOW}⚠️${C_RESET} DNS Forwarding: PARTIAL or INACTIVE"
        all_ok=false
    fi
    
    echo -e "\n${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_BOLD}${C_CYAN}  📊 SUMMARY${C_RESET}"
    echo -e "${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "  ${C_GREEN}✅ Issues Fixed:${C_RESET} $fixed_count"
    echo -e "  ${C_RED}❌ Issues Remaining:${C_RESET} $issues_found"
    
    if [[ "$all_ok" == "true" ]]; then
        echo -e "\n  ${C_GREEN}✅ All services are now running correctly!${C_RESET}"
    else
        echo -e "\n  ${C_YELLOW}⚠️ Some services still have issues. Check logs above for details.${C_RESET}"
        echo -e "  ${C_YELLOW}💡${C_RESET} Run option 3 (Show Detailed Service Diagnostics) for more information."
    fi
    
    press_enter
}

show_vpn_status() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 📊 VPN & Service Status Dashboard ---${C_RESET}"
    
    local vpn_info
    vpn_info=$(detect_vpn_connection)
    local vpn_type=$(echo "$vpn_info" | cut -d'|' -f1)
    local vpn_active=$(echo "$vpn_info" | cut -d'|' -f2)
    
    echo -e "\n${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_BOLD}${C_BLUE}  🔐 VPN CONNECTION STATUS${C_RESET}"
    echo -e "${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [[ "$vpn_active" == "true" ]]; then
        echo -e "  ${C_GREEN}🟢 VPN Status:${C_RESET} ${C_GREEN}CONNECTED${C_RESET}"
        echo -e "  ${C_GREEN}📡 VPN Type:${C_RESET} ${C_YELLOW}$vpn_type${C_RESET}"
    else
        echo -e "  ${C_RED}🔴 VPN Status:${C_RESET} ${C_RED}NOT CONNECTED${C_RESET}"
        echo -e "  ${C_YELLOW}💡 No active VPN connection detected${C_RESET}"
    fi
    
    echo -e "\n${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_BOLD}${C_BLUE}  🔌 SERVICE STATUS${C_RESET}"
    echo -e "${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    # SSH Status
    local ssh_service_name=""
    local ssh_status="❌ INACTIVE"
    local ssh_emoji="🔴"
    if [ -f /lib/systemd/system/sshd.service ] && systemctl is-active --quiet sshd.service 2>/dev/null; then
        ssh_service_name="sshd.service"
        ssh_status="✅ ACTIVE"
        ssh_emoji="🟢"
    elif [ -f /lib/systemd/system/ssh.service ] && systemctl is-active --quiet ssh.service 2>/dev/null; then
        ssh_service_name="ssh.service"
        ssh_status="✅ ACTIVE"
        ssh_emoji="🟢"
    fi
    echo -e "  ${ssh_emoji} SSH Service: ${ssh_status} ${C_DIM}(${ssh_service_name:-"Not found"})${C_RESET}"
    
    # DNSTT Status - Improved detection
    local dnstt_status="❌ INACTIVE"
    local dnstt_emoji="🔴"
    local dnstt_server_active=false
    local dnstt_edns_active=false
    
    if systemctl is-active --quiet dnstt.service 2>/dev/null; then
        dnstt_server_active=true
    fi
    
    if [ -f "$DNSTT_EDNS_SERVICE" ] && systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
        dnstt_edns_active=true
    fi
    
    if [[ "$dnstt_server_active" == "true" ]] && [[ "$dnstt_edns_active" == "true" ]]; then
        dnstt_status="✅ ACTIVE (Full)"
        dnstt_emoji="🟢"
    elif [[ "$dnstt_server_active" == "true" ]]; then
        dnstt_status="⚠️ PARTIAL (Server active, EDNS inactive)"
        dnstt_emoji="🟡"
    elif [[ "$dnstt_edns_active" == "true" ]]; then
        dnstt_status="⚠️ PARTIAL (EDNS active, Server inactive)"
        dnstt_emoji="🟡"
    elif [ -f "$DNSTT_SERVICE_FILE" ] || [ -f "$DNSTT_EDNS_SERVICE" ]; then
        dnstt_status="⚠️ INSTALLED BUT NOT RUNNING"
        dnstt_emoji="🟡"
    fi
    echo -e "  ${dnstt_emoji} DNSTT: ${dnstt_status}"
    
    # OpenVPN Status
    local openvpn_status="❌ INACTIVE"
    local openvpn_emoji="🔴"
    if pgrep -x openvpn >/dev/null 2>&1 || systemctl is-active --quiet openvpn* 2>/dev/null; then
        openvpn_status="✅ ACTIVE"
        openvpn_emoji="🟢"
    fi
    echo -e "  ${openvpn_emoji} OpenVPN: ${openvpn_status}"
    
    # WireGuard Status
    local wg_status="❌ INACTIVE"
    local wg_emoji="🔴"
    if command -v wg >/dev/null 2>&1 && wg show 2>/dev/null | grep -q "interface"; then
        wg_status="✅ ACTIVE"
        wg_emoji="🟢"
    fi
    echo -e "  ${wg_emoji} WireGuard: ${wg_status}"
    
    # HTTP Custom Status - Improved detection with port check
    local http_custom_status="❌ INACTIVE"
    local http_custom_emoji="🔴"
    
    # Check if service file exists first
    if [ -f "$HTTP_CUSTOM_SERVICE_FILE" ]; then
        # Try multiple service name formats
        if systemctl is-active --quiet http-custom.service 2>/dev/null; then
            http_custom_status="✅ ACTIVE (Port $HTTP_CUSTOM_PORT)"
            http_custom_emoji="🟢"
        elif systemctl is-active --quiet http-custom 2>/dev/null; then
            http_custom_status="✅ ACTIVE (Port $HTTP_CUSTOM_PORT)"
            http_custom_emoji="🟢"
        # Check if port is listening (alternative check)
        elif ss -lntp 2>/dev/null | grep -qE ":${HTTP_CUSTOM_PORT}\s" || netstat -lntp 2>/dev/null | grep -qE ":${HTTP_CUSTOM_PORT}\s" || lsof -i TCP:${HTTP_CUSTOM_PORT} 2>/dev/null | grep -q LISTEN; then
            http_custom_status="✅ ACTIVE (Port $HTTP_CUSTOM_PORT - running)"
            http_custom_emoji="🟢"
        else
            # Service file exists but not running
            http_custom_status="⚠️ INSTALLED BUT NOT RUNNING"
            http_custom_emoji="🟡"
        fi
    elif ss -lntp 2>/dev/null | grep -qE ":${HTTP_CUSTOM_PORT}\s" || netstat -lntp 2>/dev/null | grep -qE ":${HTTP_CUSTOM_PORT}\s"; then
        # Port is in use but no service file (might be manually started)
        http_custom_status="⚠️ PORT $HTTP_CUSTOM_PORT IN USE (no service)"
        http_custom_emoji="🟡"
    fi
    
    echo -e "  ${http_custom_emoji} HTTP Custom: ${http_custom_status}"
    
    # DNS Forwarding Status - Improved detection
    local dns_forward_status="❌ INACTIVE"
    local dns_forward_emoji="🔴"
    local dns_forward_details=""
    
    # Check DNSTT EDNS Proxy (primary DNS forwarding for DNSTT)
    if systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
        dns_forward_status="✅ ACTIVE (DNSTT EDNS)"
        dns_forward_emoji="🟢"
        dns_forward_details="Port 53 → 5300"
    # Check systemd-resolved DNS forwarding
    elif systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        if grep -qE "^DNSStubListener=no" /etc/systemd/resolved.conf 2>/dev/null || grep -qE "^#DNSStubListener=no" /etc/systemd/resolved.conf 2>/dev/null; then
            dns_forward_status="✅ ACTIVE (systemd-resolved)"
            dns_forward_emoji="🟢"
            dns_forward_details="systemd-resolved configured"
        else
            dns_forward_status="⚠️ PARTIAL (systemd-resolved active, not configured)"
            dns_forward_emoji="🟡"
        fi
    # Check if port 53 is listening (indicates DNS forwarding might be active)
    elif ss -lunp 2>/dev/null | grep -qE ':(53|:53)\s' || netstat -lunp 2>/dev/null | grep -qE ':(53|:53)\s' || lsof -i UDP:53 2>/dev/null | grep -q LISTEN; then
        local port53_process=$(ss -lunp 2>/dev/null | grep -E ':(53|:53)\s' | grep -oP 'pid=\K[0-9]+' | head -n1)
        if [[ -n "$port53_process" ]]; then
            port53_process=$(ps -p "$port53_process" -o comm= 2>/dev/null | head -n1)
            if [[ -n "$port53_process" ]]; then
                dns_forward_status="✅ ACTIVE (Port 53 - $port53_process)"
                dns_forward_emoji="🟢"
                dns_forward_details="Process: $port53_process"
            else
                dns_forward_status="⚠️ PORT 53 IN USE (unknown process)"
                dns_forward_emoji="🟡"
            fi
        else
            dns_forward_status="⚠️ PORT 53 IN USE"
            dns_forward_emoji="🟡"
        fi
    fi
    
    if [[ -n "$dns_forward_details" ]]; then
        echo -e "  ${dns_forward_emoji} DNS Forwarding: ${dns_forward_status} ${C_DIM}($dns_forward_details)${C_RESET}"
    else
        echo -e "  ${dns_forward_emoji} DNS Forwarding: ${dns_forward_status}"
    fi
    
    echo -e "\n${C_BOLD}${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    # Service Management Actions
    echo -e "\n${C_BOLD}${C_YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_BOLD}${C_YELLOW}  🔧 SERVICE MANAGEMENT ACTIONS${C_RESET}"
    echo -e "${C_BOLD}${C_YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    # Check for installed but inactive services and offer to start them
    local has_inactive_services=false
    
    if [[ "$dnstt_emoji" == "🟡" ]] || [[ "$dnstt_emoji" == "🔴" ]]; then
        if [ -f "$DNSTT_SERVICE_FILE" ] || [ -f "$DNSTT_EDNS_SERVICE" ]; then
            has_inactive_services=true
            echo -e "  ${C_YELLOW}⚠️${C_RESET} DNSTT is installed but not fully active"
            if ! systemctl is-active --quiet dnstt.service 2>/dev/null; then
                echo -e "    ${C_YELLOW}💡${C_RESET} DNSTT server service is not running. Would you like to start it?"
            fi
            if [ -f "$DNSTT_EDNS_SERVICE" ] && ! systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
                echo -e "    ${C_YELLOW}💡${C_RESET} DNSTT EDNS proxy service is not running. Would you like to start it?"
            fi
        fi
    fi
    
    if [[ "$http_custom_emoji" == "🟡" ]] || [[ "$http_custom_emoji" == "🔴" ]]; then
        if [ -f "$HTTP_CUSTOM_SERVICE_FILE" ]; then
            has_inactive_services=true
            echo -e "  ${C_YELLOW}⚠️${C_RESET} HTTP Custom is installed but not active"
            echo -e "    ${C_YELLOW}💡${C_RESET} HTTP Custom service is not running. Would you like to start it?"
        fi
    fi
    
    if [[ "$dns_forward_emoji" == "🔴" ]] || [[ "$dns_forward_emoji" == "🟡" ]]; then
        has_inactive_services=true
        echo -e "  ${C_YELLOW}⚠️${C_RESET} DNS Forwarding is not active or partially configured"
        echo -e "    ${C_YELLOW}💡${C_RESET} Would you like to enable DNS forwarding?"
    fi
    
    if [[ "$vpn_active" == "true" ]]; then
        echo -e "\n  ${C_GREEN}✅ All systems are ready for VPN connections${C_RESET}"
    else
        echo -e "\n  ${C_YELLOW}💡 Configure and start a VPN service to enable auto-configuration${C_RESET}"
    fi
    
    echo -e "\n${C_YELLOW}💡 Actions:${C_RESET}"
    echo -e "  ${C_CHOICE}1)${C_RESET} 🔄 Run Auto-Configuration (Enable DNS Forwarding & Start SSH)"
    if [[ "$has_inactive_services" == "true" ]]; then
        echo -e "  ${C_CHOICE}2)${C_RESET} 🚀 Start All Installed But Inactive Services (DNSTT, HTTP Custom, etc.)"
    fi
    echo -e "  ${C_CHOICE}3)${C_RESET} 🔧 Fix All Services (Auto-Repair - Recommended)"
    echo -e "  ${C_CHOICE}4)${C_RESET} 🔍 Show Detailed Service Diagnostics"
    echo -e "  ${C_CHOICE}0)${C_RESET} ↩️ Return to Main Menu"
    echo
    read -p "$(echo -e ${C_PROMPT}"👉 Select an action: "${C_RESET})" action
    case $action in
        1)
            echo -e "\n${C_BLUE}🔄 Running auto-configuration...${C_RESET}"
            setup_vpn_auto_config
            sleep 2
            ;;
        2)
            if [[ "$has_inactive_services" == "true" ]]; then
                echo -e "\n${C_BLUE}🚀 Starting installed but inactive services...${C_RESET}"
                # Start DNSTT services if installed
                if [ -f "$DNSTT_SERVICE_FILE" ] && ! systemctl is-active --quiet dnstt.service 2>/dev/null; then
                    echo -e "${C_BLUE}▶️ Starting DNSTT server...${C_RESET}"
                    systemctl start dnstt.service 2>/dev/null
                    sleep 2
                    if systemctl is-active --quiet dnstt.service 2>/dev/null; then
                        echo -e "${C_GREEN}✅ DNSTT server started${C_RESET}"
                    else
                        echo -e "${C_YELLOW}⚠️ DNSTT server failed to start. Check logs: journalctl -u dnstt.service${C_RESET}"
                    fi
                fi
                if [ -f "$DNSTT_EDNS_SERVICE" ] && ! systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
                    echo -e "${C_BLUE}▶️ Starting DNSTT EDNS proxy...${C_RESET}"
                    systemctl start dnstt-edns-proxy.service 2>/dev/null
                    sleep 2
                    if systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
                        echo -e "${C_GREEN}✅ DNSTT EDNS proxy started${C_RESET}"
                    else
                        echo -e "${C_YELLOW}⚠️ DNSTT EDNS proxy failed to start. Check logs: journalctl -u dnstt-edns-proxy.service${C_RESET}"
                    fi
                fi
                # Start HTTP Custom if installed
                if [ -f "$HTTP_CUSTOM_SERVICE_FILE" ] && ! systemctl is-active --quiet http-custom.service 2>/dev/null && ! systemctl is-active --quiet http-custom 2>/dev/null; then
                    echo -e "${C_BLUE}▶️ Starting HTTP Custom...${C_RESET}"
                    systemctl start http-custom.service 2>/dev/null || systemctl start http-custom 2>/dev/null
                    sleep 2
                    if systemctl is-active --quiet http-custom.service 2>/dev/null || systemctl is-active --quiet http-custom 2>/dev/null; then
                        echo -e "${C_GREEN}✅ HTTP Custom started${C_RESET}"
                    else
                        echo -e "${C_YELLOW}⚠️ HTTP Custom failed to start. Check logs: journalctl -u http-custom.service${C_RESET}"
                    fi
                fi
                # Enable DNS forwarding
                enable_dns_forwarding
                sleep 2
            fi
            ;;
        3)
            fix_all_services
            ;;
        4)
            echo -e "\n${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
            echo -e "${C_BOLD}${C_CYAN}  🔍 DETAILED SERVICE DIAGNOSTICS${C_RESET}"
            echo -e "${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
            
            # DNSTT Diagnostics
            if [ -f "$DNSTT_SERVICE_FILE" ] || [ -f "$DNSTT_EDNS_SERVICE" ]; then
                echo -e "\n${C_YELLOW}📡 DNSTT Diagnostics:${C_RESET}"
                echo -e "  Service Files:"
                [ -f "$DNSTT_SERVICE_FILE" ] && echo -e "    ${C_GREEN}✅${C_RESET} DNSTT service file: $DNSTT_SERVICE_FILE" || echo -e "    ${C_RED}❌${C_RESET} DNSTT service file: NOT FOUND"
                [ -f "$DNSTT_EDNS_SERVICE" ] && echo -e "    ${C_GREEN}✅${C_RESET} EDNS proxy service file: $DNSTT_EDNS_SERVICE" || echo -e "    ${C_RED}❌${C_RESET} EDNS proxy service file: NOT FOUND"
                echo -e "  Service Status:"
                systemctl status dnstt.service --no-pager -l 2>/dev/null | head -n 10 || echo -e "    ${C_RED}❌${C_RESET} DNSTT service status unavailable"
                if [ -f "$DNSTT_EDNS_SERVICE" ]; then
                    systemctl status dnstt-edns-proxy.service --no-pager -l 2>/dev/null | head -n 10 || echo -e "    ${C_RED}❌${C_RESET} EDNS proxy service status unavailable"
                fi
                echo -e "  Port Status:"
                if ss -lunp 2>/dev/null | grep -qE ':(53|:53)\s'; then
                    echo -e "    ${C_GREEN}✅${C_RESET} Port 53 (UDP) is listening"
                    ss -lunp 2>/dev/null | grep -E ':(53|:53)\s'
                else
                    echo -e "    ${C_RED}❌${C_RESET} Port 53 (UDP) is NOT listening"
                fi
                if ss -lunp 2>/dev/null | grep -qE ':(5300|:5300)\s'; then
                    echo -e "    ${C_GREEN}✅${C_RESET} Port 5300 (UDP) is listening"
                    ss -lunp 2>/dev/null | grep -E ':(5300|:5300)\s'
                else
                    echo -e "    ${C_RED}❌${C_RESET} Port 5300 (UDP) is NOT listening"
                fi
            fi
            
            # HTTP Custom Diagnostics
            if [ -f "$HTTP_CUSTOM_SERVICE_FILE" ]; then
                echo -e "\n${C_YELLOW}🌐 HTTP Custom Diagnostics:${C_RESET}"
                echo -e "  Service File: ${C_GREEN}✅${C_RESET} $HTTP_CUSTOM_SERVICE_FILE"
                echo -e "  Service Status:"
                systemctl status http-custom.service --no-pager -l 2>/dev/null | head -n 10 || systemctl status http-custom --no-pager -l 2>/dev/null | head -n 10 || echo -e "    ${C_RED}❌${C_RESET} HTTP Custom service status unavailable"
                echo -e "  Port Status:"
                if ss -lntp 2>/dev/null | grep -qE ":${HTTP_CUSTOM_PORT}\s"; then
                    echo -e "    ${C_GREEN}✅${C_RESET} Port $HTTP_CUSTOM_PORT (TCP) is listening"
                    ss -lntp 2>/dev/null | grep -E ":${HTTP_CUSTOM_PORT}\s"
                else
                    echo -e "    ${C_RED}❌${C_RESET} Port $HTTP_CUSTOM_PORT (TCP) is NOT listening"
                fi
            fi
            
            # DNS Forwarding Diagnostics
            echo -e "\n${C_YELLOW}🔍 DNS Forwarding Diagnostics:${C_RESET}"
            echo -e "  systemd-resolved:"
            if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
                echo -e "    ${C_GREEN}✅${C_RESET} systemd-resolved is active"
                if grep -qE "^DNSStubListener=no" /etc/systemd/resolved.conf 2>/dev/null; then
                    echo -e "    ${C_GREEN}✅${C_RESET} DNSStubListener=no is configured"
                else
                    echo -e "    ${C_YELLOW}⚠️${C_RESET} DNSStubListener=no is NOT configured"
                fi
            else
                echo -e "    ${C_RED}❌${C_RESET} systemd-resolved is not active"
            fi
            echo -e "  /etc/resolv.conf:"
            if [ -f /etc/resolv.conf ]; then
                cat /etc/resolv.conf | head -n 5 | sed 's/^/    /'
            else
                echo -e "    ${C_RED}❌${C_RESET} /etc/resolv.conf not found"
            fi
            
            press_enter
            ;;
        0) return ;;
        *) ;;
    esac
    
    # Refresh status after actions (except fix_all_services which handles its own flow)
    if [[ "$action" != "0" ]] && [[ "$action" != "3" ]] && [[ "$action" != "4" ]]; then
        sleep 2
        show_vpn_status
    fi
}

purge_nginx() {
    local mode="$1"
    if [[ "$mode" != "silent" ]]; then
        clear; show_banner
        echo -e "${C_BOLD}${C_PURPLE}--- 🔥 Purge Nginx Installation ---${C_RESET}"
        if ! command -v nginx &> /dev/null; then
            echo -e "\n${C_YELLOW}ℹ️ Nginx is not installed. Nothing to do.${C_RESET}"
            return
        fi
        read -p "👉 This will COMPLETELY REMOVE Nginx and all its configuration files. Are you sure? (y/n): " confirm
        if [[ "$confirm" != "y" ]]; then
            echo -e "\n${C_YELLOW}❌ Uninstallation cancelled.${C_RESET}"
            return
        fi
    fi
    echo -e "\n${C_BLUE}🛑 Stopping Nginx service...${C_RESET}"
    systemctl stop nginx >/dev/null 2>&1
    echo -e "\n${C_BLUE}🗑️ Purging Nginx packages...${C_RESET}"
    apt-get purge -y nginx nginx-common >/dev/null 2>&1
    apt-get autoremove -y >/dev/null 2>&1
    echo -e "\n${C_BLUE}🗑️ Removing leftover files...${C_RESET}"
    rm -f /etc/ssl/certs/nginx-selfsigned.pem
    rm -f /etc/ssl/private/nginx-selfsigned.key
    rm -rf /etc/nginx
    rm -f "${NGINX_CONFIG_FILE}.bak"
    rm -f "${NGINX_CONFIG_FILE}.bak.certbot"
    rm -f "${NGINX_CONFIG_FILE}.bak.selfsigned"
    if [[ "$mode" != "silent" ]]; then
        echo -e "\n${C_GREEN}✅ Nginx has been completely purged from the system.${C_RESET}"
    fi
}

install_nginx_proxy() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing Nginx Main Proxy (Ports 80 & 443) ---${C_RESET}"
    if command -v nginx &> /dev/null; then
        echo -e "\n${C_YELLOW}⚠️ An existing Nginx installation was found.${C_RESET}"
        read -p "👉 To ensure a clean setup, the existing Nginx will be purged. Continue? (y/n): " confirm_purge
        if [[ "$confirm_purge" != "y" ]]; then
            echo -e "\n${C_RED}❌ Installation cancelled.${C_RESET}"
            return
        fi
        purge_nginx "silent"
    fi
    echo -e "\n${C_BLUE}📦 Installing Nginx package...${C_RESET}"
    apt-get update && apt-get install -y nginx || { echo -e "${C_RED}❌ Failed to install Nginx.${C_RESET}"; return; }
    
    check_and_free_ports "80" "443" || return

    echo -e "\n${C_GREEN}🔐 Generating self-signed SSL certificate for Nginx...${C_RESET}"
    local SSL_CERT="/etc/ssl/certs/nginx-selfsigned.pem"
    local SSL_KEY="/etc/ssl/private/nginx-selfsigned.key"
    mkdir -p /etc/ssl/certs /etc/ssl/private
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$SSL_KEY" \
        -out "$SSL_CERT" \
            -subj "/CN=${APP_BASE_DIR_NAME}.proxy" >/dev/null 2>&1 || { echo -e "${C_RED}❌ Failed to generate SSL certificate.${C_RESET}"; return; }
    echo -e "\n${C_GREEN}📝 Applying Nginx reverse proxy configuration...${C_RESET}"
    mv "$NGINX_CONFIG_FILE" "${NGINX_CONFIG_FILE}.bak" 2>/dev/null
    cat > "$NGINX_CONFIG_FILE" <<'EOF'
server {
    server_tokens off;
    server_name _;
    listen 80;
    listen [::]:80;
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    ssl_certificate /etc/ssl/certs/nginx-selfsigned.pem;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!eNULL:!MD5:!DES:!RC4:!ADH!SSLv3:!EXP!PSK!DSS;
    resolver 8.8.8.8;
    location ~ ^/(?<fwdport>\d+)/(?<fwdpath>.*)$ {
        client_max_body_size 0;
        client_body_timeout 1d;
        grpc_read_timeout 1d;
        grpc_socket_keepalive on;
        proxy_read_timeout 1d;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_socket_keepalive on;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        if ($content_type ~* "GRPC") { grpc_pass grpc://127.0.0.1:$fwdport$is_args$args; break; }
        proxy_pass http://127.0.0.1:$fwdport$is_args$args;
        break;
    }
    location / {
        proxy_read_timeout 3600s;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_http_version 1.1;
        proxy_socket_keepalive on;
        tcp_nodelay on;
        tcp_nopush off;
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
EOF
    echo -e "\n${C_GREEN}▶️ Restarting Nginx service...${C_RESET}"
    systemctl restart nginx
    sleep 2
    if systemctl is-active --quiet nginx; then
        echo -e "\n${C_GREEN}✅ SUCCESS: Nginx Reverse Proxy is active on ports 80 & 443.${C_RESET}"
        echo -e "${C_YELLOW}⚠️ IMPORTANT: The '/' location is set to proxy to '127.0.0.1:8080'.${C_RESET}"
        echo -e "   Please ensure WebSocket Proxy (or another service) is running on port 8080."
    else
        echo -e "\n${C_RED}❌ ERROR: Nginx service failed to start.${C_RESET}"
        echo -e "${C_YELLOW}ℹ️ Displaying Nginx status for diagnostics:${C_RESET}"
        systemctl status nginx --no-pager
        echo -e "${C_YELLOW}🔄 Restoring previous Nginx config...${C_RESET}"
        mv "${NGINX_CONFIG_FILE}.bak" "$NGINX_CONFIG_FILE" 2>/dev/null
    fi
}

_install_certbot() {
    if command -v certbot &> /dev/null; then
        echo -e "${C_GREEN}✅ Certbot is already installed.${C_RESET}"
        return 0
    fi
    echo -e "${C_YELLOW}⚠️ Certbot (for SSL) is not found.${C_RESET}"
    read -p "👉 Do you want to install Certbot now? (y/n): " confirm_install
    if [[ "$confirm_install" != "y" ]]; then
        echo -e "${C_RED}❌ Installation skipped. Cannot proceed.${C_RESET}"
        return 1
    fi
    echo -e "${C_BLUE}📦 Installing Certbot...${C_RESET}"
    apt-get update > /dev/null 2>&1
    apt-get install -y certbot || {
        echo -e "${C_RED}❌ Failed to install Certbot.${C_RESET}"
        return 1
    }
    echo -e "${C_GREEN}✅ Certbot installed successfully.${C_RESET}"
    return 0
}

request_certbot_ssl() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🔒 Request Let's Encrypt SSL (Certbot) ---${C_RESET}"
    if ! systemctl is-active --quiet nginx; then
        echo -e "\n${C_RED}❌ Nginx is not running. Please ensure Nginx is installed and active.${C_RESET}"
        return
    fi

    _install_certbot || return
    
    echo
    read -p "👉 Enter your domain name (e.g., vps.example.com): " domain_name
    if [[ -z "$domain_name" ]]; then
        echo -e "\n${C_RED}❌ Domain name cannot be empty. Aborting.${C_RESET}"
        return
    fi
    
    read -p "👉 Enter your email address (for Let's Encrypt): " email
    if [[ -z "$email" ]]; then
        echo -e "\n${C_RED}❌ Email address cannot be empty. Aborting.${C_RESET}"
        return
    fi
    
    echo -e "\n${C_BLUE}🛑 Stopping Nginx temporarily for validation...${C_RESET}"
    systemctl stop nginx
    sleep 2

    if ss -lntp | grep -q ":80\s"; then
         echo -e "${C_RED}❌ Failed to free port 80, another process might be using it. Aborting.${C_RESET}"
         systemctl start nginx
         return
    fi

    echo -e "\n${C_BLUE}🚀 Requesting certificate for ${C_YELLOW}$domain_name...${C_RESET}"
    certbot certonly --standalone -d "$domain_name" --non-interactive --agree-tos -m "$email"
    
    if [ $? -ne 0 ]; then
        echo -e "\n${C_RED}❌ Certbot failed to obtain a certificate.${C_RESET}"
        echo -e "${C_YELLOW}ℹ️ Please check your domain's DNS 'A' record points to this server's IP.${C_RESET}"
        systemctl start nginx
        return
    fi

    local SSL_CERT_LIVE="/etc/letsencrypt/live/$domain_name/fullchain.pem"
    local SSL_KEY_LIVE="/etc/letsencrypt/live/$domain_name/privkey.pem"

    if [ ! -f "$SSL_CERT_LIVE" ] || [ ! -f "$SSL_KEY_LIVE" ]; then
        echo -e "\n${C_RED}❌ Certbot succeeded, but cert files not found at expected location.${C_RESET}"
        systemctl start nginx
        return
    fi

    echo -e "\n${C_GREEN}✅ Certificate obtained successfully!${C_RESET}"
    echo -e "${C_BLUE}📝 Updating Nginx configuration...${C_RESET}"

    cp "$NGINX_CONFIG_FILE" "${NGINX_CONFIG_FILE}.bak.selfsigned"
    
    sed -i "s|server_name _;|server_name $domain_name;|" "$NGINX_CONFIG_FILE"
    sed -i "s|ssl_certificate /etc/ssl/certs/nginx-selfsigned.pem;|ssl_certificate $SSL_CERT_LIVE;|" "$NGINX_CONFIG_FILE"
    sed -i "s|ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;|ssl_certificate_key $SSL_KEY_LIVE;|" "$NGINX_CONFIG_FILE"

    echo -e "\n${C_BLUE}▶️ Restarting Nginx with new certificate...${C_RESET}"
    systemctl start nginx
    sleep 2
    
    if systemctl is-active --quiet nginx; then
        echo -e "\n${C_GREEN}✅ SUCCESS: Nginx is active with your new Let's Encrypt certificate!${C_RESET}"
    else
        echo -e "\n${C_RED}❌ ERROR: Nginx failed to start with the new certificate.${C_RESET}"
        echo -e "${C_YELLOW}🔄 Restoring self-signed certificate config...${C_RESET}"
        mv "${NGINX_CONFIG_FILE}.bak.selfsigned" "$NGINX_CONFIG_FILE"
        systemctl restart nginx
    fi
}

nginx_proxy_menu() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🌐 Nginx Main Proxy Management ---${C_RESET}"
    if systemctl is-active --quiet nginx; then
        echo -e "\n${C_GREEN}✅ Nginx Main Proxy is currently installed and active.${C_RESET}"
        
        local cert_type
        if grep -q "letsencrypt" "$NGINX_CONFIG_FILE"; then
            cert_type="${C_STATUS_A}(Let's Encrypt)${C_RESET}"
        else
            cert_type="${C_STATUS_I}(Self-Signed)${C_RESET}"
        fi

        echo -e "\nSelect an option:\n"
        echo -e "  ${C_GREEN}1)${C_RESET} 🔒 Request/Renew SSL (Certbot) ${cert_type}"
        echo -e "  ${C_GREEN}2)${C_RESET} 🔥 Purge Nginx Proxy Installation"
        echo -e "\n  ${C_RED}0)${C_RESET} ↩️ Return to previous menu"
        echo
        read -p "👉 Enter your choice: " choice
        case $choice in
            1) request_certbot_ssl; press_enter ;;
            2) purge_nginx ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option.${C_RESET}" ;;
        esac
    else
        echo -e "\n${C_YELLOW}ℹ️ Nginx Main Proxy is not installed or inactive.${C_RESET}"
        echo -e "\nSelect an option:\n"
        echo -e "  ${C_GREEN}1)${C_RESET} 🚀 Install Nginx Main Proxy (80/443)"
        echo -e "\n  ${C_RED}0)${C_RESET} ↩️ Return to previous menu"
        echo
        read -p "👉 Enter your choice: " choice
        case $choice in
            1) install_nginx_proxy ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option.${C_RESET}" ;;
        esac
    fi
}

install_xui_panel() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Install X-UI Panel ---${C_RESET}"
    echo -e "\nThis will download and run the official installation script for X-UI."
    echo -e "Choose an installation option:\n"
    echo -e "  ${C_GREEN}1)${C_RESET} Install the latest version of X-UI"
    echo -e "  ${C_GREEN}2)${C_RESET} Install a specific version of X-UI"
    echo -e "\n  ${C_RED}0)${C_RESET} ❌ Cancel Installation"
    echo
    read -p "👉 Select an option: " choice
    case $choice in
        1)
            echo -e "\n${C_BLUE}⚙️ Installing the latest version...${C_RESET}"
            bash <(curl -Ls https://raw.githubusercontent.com/alireza0/x-ui/master/install.sh)
            ;;
        2)
            read -p "👉 Enter the version to install (e.g., 1.8.0): " version
            if [[ -z "$version" ]]; then
                echo -e "\n${C_RED}❌ Version number cannot be empty.${C_RESET}"
                return
            fi
            echo -e "\n${C_BLUE}⚙️ Installing version ${C_YELLOW}$version...${C_RESET}"
            VERSION=$version bash <(curl -Ls "https://raw.githubusercontent.com/alireza0/x-ui/$version/install.sh") "$version"
            ;;
        0)
            echo -e "\n${C_YELLOW}❌ Installation cancelled.${C_RESET}"
            ;;
        *)
            echo -e "\n${C_RED}❌ Invalid option.${C_RESET}"
            ;;
    esac
}

uninstall_xui_panel() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🗑️ Uninstall X-UI Panel ---${C_RESET}"
    if ! command -v x-ui &> /dev/null; then
        echo -e "\n${C_YELLOW}ℹ️ X-UI does not appear to be installed.${C_RESET}"
        return
    fi
    read -p "👉 Are you sure you want to thoroughly uninstall X-UI? (y/n): " confirm
    if [[ "$confirm" == "y" ]]; then
        echo -e "\n${C_BLUE}⚙️ Running the default X-UI uninstaller first...${C_RESET}"
        x-ui uninstall >/dev/null 2>&1
        echo -e "\n${C_BLUE}🧹 Performing a full cleanup to ensure complete removal...${C_RESET}"
        echo " - Stopping and disabling x-ui service..."
        systemctl stop x-ui >/dev/null 2>&1
        systemctl disable x-ui >/dev/null 2>&1
        echo " - Removing x-ui files and directories..."
        rm -f /etc/systemd/system/x-ui.service
        rm -f /usr/local/bin/x-ui
        rm -rf /usr/local/x-ui/
        rm -rf /etc/x-ui/
        echo " - Reloading systemd daemon..."
        systemctl daemon-reload
        echo -e "\n${C_GREEN}✅ X-UI has been thoroughly uninstalled.${C_RESET}"
    else
        echo -e "\n${C_YELLOW}❌ Uninstallation cancelled.${C_RESET}"
    fi
}

show_banner() {
    local os_name=$(grep -oP 'PRETTY_NAME="\K[^"]+' /etc/os-release || echo "Linux")
    local up_time=$(uptime -p | sed 's/up //')
    local ram_usage=$(free -m | awk '/^Mem:/{printf "%.1f", $3*100/$2}')
    local ram_total=$(free -h | awk '/^Mem:/ {print $2}')
    local cpu_cores=$(nproc)
    local server_ip=$(hostname -I | awk '{print $1}' | head -n1)

    local cpu_usage
    cpu_usage=$(top -bn1 | grep -i 'cpu(s)' | awk '{print $2 + $4}' | awk '{printf "%.1f", $1}')
    
    local online_users=0
    if [[ -s "$DB_FILE" ]]; then
        while IFS=: read -r user pass expiry limit; do
           local count=$(pgrep -u "$user" sshd 2>/dev/null | wc -l)
           online_users=$((online_users + count))
        done < "$DB_FILE"
    fi
    
    local total_users=0
    if [[ -s "$DB_FILE" ]]; then total_users=$(grep -c . "$DB_FILE"); fi

    # Clear screen once and display stable banner
    clear
    echo
    # Modern ASCII Art Banner with Colors - Fixed Width
    echo -e "${C_BRIGHT_CYAN}${C_BOLD}"
    echo -e "    ███╗   ███╗██████╗  ██████╗██╗   ██╗███████╗██████╗ ██████╗ "
    echo -e "    ████╗ ████║██╔══██╗██╔════╝╚██╗ ██╔╝██╔════╝██╔══██╗╚════██╗"
    echo -e "    ██╔████╔██║██████╔╝██║      ╚████╔╝ █████╗  ██████╔╝ █████╔╝"
    echo -e "    ██║╚██╔╝██║██╔══██╗██║       ╚██╔╝  ██╔══╝  ██╔══██╗██╔═══╝ "
    echo -e "    ██║ ╚═╝ ██║██║  ██║╚██████╗   ██║   ███████╗██║  ██║███████╗"
    echo -e "    ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝"
    echo -e "${C_RESET}"
    # Title Box - Fixed Width Frame
    echo -e "${C_BRIGHT_MAGENTA}${C_BOLD}    ╔═══════════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_BRIGHT_MAGENTA}${C_BOLD}    ║${C_RESET}${C_BRIGHT_CYAN}${C_BOLD}                    ✨ ${REPO_NAME} Manager ✨                    ${C_RESET}${C_BRIGHT_MAGENTA}${C_BOLD}║${C_RESET}"
    echo -e "${C_BRIGHT_MAGENTA}${C_BOLD}    ║${C_RESET}${C_BRIGHT_YELLOW}                      v3.4.0 (ActiveLimiter)                      ${C_RESET}${C_BRIGHT_MAGENTA}${C_BOLD}║${C_RESET}"
    echo -e "${C_BRIGHT_MAGENTA}${C_BOLD}    ╚═══════════════════════════════════════════════════════════════════╝${C_RESET}"
    echo
    
    # System Information Box - Clean Fixed Frame
    echo -e "${C_BG_BLACK}${C_BRIGHT_WHITE}${C_BOLD}    ┌─────────────────────────────────────────────────────────────────────┐${C_RESET}"
    echo -e "${C_BG_BLACK}${C_BRIGHT_WHITE}    │${C_BRIGHT_CYAN}${C_BOLD}  📊 System Information${C_BRIGHT_WHITE}                                         │${C_RESET}"
    echo -e "${C_BG_BLACK}${C_BRIGHT_WHITE}    ├─────────────────────────────────────────────────────────────────────┤${C_RESET}"
    
    # First row
    printf "${C_BG_BLACK}${C_BRIGHT_WHITE}    │${C_RESET}  ${C_BRIGHT_GREEN}🖥  OS:${C_RESET} ${C_WHITE}%-25s${C_RESET}  ${C_BRIGHT_YELLOW}👥 Online:${C_RESET} ${C_WHITE}%3s Sessions${C_RESET}  ${C_BG_BLACK}${C_BRIGHT_WHITE}│${C_RESET}\n" "$os_name" "$online_users"
    
    # Second row
    printf "${C_BG_BLACK}${C_BRIGHT_WHITE}    │${C_RESET}  ${C_BRIGHT_GREEN}⏱  Uptime:${C_RESET} ${C_WHITE}%-20s${C_RESET}  ${C_BRIGHT_YELLOW}👤 Total Users:${C_RESET} ${C_WHITE}%3s${C_RESET}        ${C_BG_BLACK}${C_BRIGHT_WHITE}│${C_RESET}\n" "$up_time" "$total_users"
    
    # Third row - Resources with color bars
    local cpu_color=$C_BRIGHT_GREEN
    local ram_color=$C_BRIGHT_GREEN
    if (( $(echo "$cpu_usage > 80" | bc -l 2>/dev/null || echo 0) )); then cpu_color=$C_BRIGHT_RED
    elif (( $(echo "$cpu_usage > 50" | bc -l 2>/dev/null || echo 0) )); then cpu_color=$C_BRIGHT_YELLOW; fi
    if (( $(echo "$ram_usage > 80" | bc -l 2>/dev/null || echo 0) )); then ram_color=$C_BRIGHT_RED
    elif (( $(echo "$ram_usage > 50" | bc -l 2>/dev/null || echo 0) )); then ram_color=$C_BRIGHT_YELLOW; fi
    
    printf "${C_BG_BLACK}${C_BRIGHT_WHITE}    │${C_RESET}  ${C_BRIGHT_GREEN}⚡ Resources:${C_RESET} ${cpu_color}CPU(${cpu_cores}): %5s%%${C_RESET} ${C_BRIGHT_WHITE}|${C_RESET} ${ram_color}RAM(${ram_total}): %5s%%${C_RESET}    ${C_BG_BLACK}${C_BRIGHT_WHITE}│${C_RESET}\n" "$cpu_usage" "$ram_usage"
    
    # Server IP
    if [[ -n "$server_ip" ]]; then
        printf "${C_BG_BLACK}${C_BRIGHT_WHITE}    │${C_RESET}  ${C_BRIGHT_GREEN}🌐 Server IP:${C_RESET} ${C_BRIGHT_CYAN}%-47s${C_RESET}  ${C_BG_BLACK}${C_BRIGHT_WHITE}│${C_RESET}\n" "$server_ip"
    fi
    
    echo -e "${C_BG_BLACK}${C_BRIGHT_WHITE}    └─────────────────────────────────────────────────────────────────────┘${C_RESET}"
    
    # Display script location
    local script_path=$(readlink -f "$(command -v menu)" 2>/dev/null || echo "/usr/local/bin/menu")
    if [[ -f "$script_path" ]]; then
        local script_size=$(du -h "$script_path" 2>/dev/null | cut -f1 || echo "N/A")
        echo
        echo -e "${C_DIM}${C_ITALIC}    📁 Script Location: ${C_YELLOW}$script_path${C_RESET}${C_DIM}${C_ITALIC} (Size: ${script_size})${C_RESET}"
    fi
    echo
}

protocol_menu() {
    while true; do
        show_banner
        local badvpn_status; if systemctl is-active --quiet badvpn; then badvpn_status="${C_BRIGHT_GREEN}${C_BOLD}[ACTIVE]${C_RESET}"; else badvpn_status="${C_DIM}[INACTIVE]${C_RESET}"; fi
        local udp_custom_status; if systemctl is-active --quiet udp-custom; then udp_custom_status="${C_BRIGHT_GREEN}${C_BOLD}[ACTIVE]${C_RESET}"; else udp_custom_status="${C_DIM}[INACTIVE]${C_RESET}"; fi
        local zivpn_status; if systemctl is-active --quiet zivpn.service; then zivpn_status="${C_BRIGHT_GREEN}${C_BOLD}[ACTIVE]${C_RESET}"; else zivpn_status="${C_DIM}[INACTIVE]${C_RESET}"; fi
        
        local ssl_tunnel_text="SSL Tunnel (Port 444)"
        local ssl_tunnel_status="${C_DIM}[INACTIVE]${C_RESET}"
        if systemctl is-active --quiet haproxy; then
            local active_port
            active_port=$(grep -oP 'bind \*:(\d+)' "$HAPROXY_CONFIG" 2>/dev/null | awk -F: '{print $2}')
            if [[ -n "$active_port" ]]; then
                ssl_tunnel_text="SSL Tunnel (Port $active_port)"
            fi
            ssl_tunnel_status="${C_BRIGHT_GREEN}${C_BOLD}[ACTIVE]${C_RESET}"
        fi
        
        local dnstt_status
        if [ -f "$DNSTT_SERVICE_FILE" ] || [ -f "$DNSTT_EDNS_SERVICE" ]; then
            # DNSTT is installed - check service status
            local dnstt_server_active=false
            local dnstt_edns_active=false
            
            if systemctl is-active --quiet dnstt.service 2>/dev/null; then
                dnstt_server_active=true
            fi
            
            if [ -f "$DNSTT_EDNS_SERVICE" ] && systemctl is-active --quiet dnstt-edns-proxy.service 2>/dev/null; then
                dnstt_edns_active=true
            fi
            
            if [[ "$dnstt_server_active" == "true" ]] && [[ "$dnstt_edns_active" == "true" ]]; then
                dnstt_status="${C_BRIGHT_GREEN}${C_BOLD}[ACTIVE]${C_RESET}"
            elif [[ "$dnstt_server_active" == "true" ]]; then
                dnstt_status="${C_BRIGHT_YELLOW}${C_BOLD}[PARTIAL: Server only]${C_RESET}"
            elif [[ "$dnstt_edns_active" == "true" ]]; then
                dnstt_status="${C_BRIGHT_YELLOW}${C_BOLD}[PARTIAL: EDNS only]${C_RESET}"
            else
                dnstt_status="${C_BRIGHT_YELLOW}[INSTALLED: NOT RUNNING]${C_RESET}"
            fi
        else
            dnstt_status="${C_DIM}[NOT INSTALLED]${C_RESET}"
        fi
        
        local webproxy_status="${C_DIM}[INACTIVE]${C_RESET}"
        local webproxy_ports=""
        if systemctl is-active --quiet webproxy; then
            if [ -f "$WEBPROXY_CONFIG_FILE" ]; then source "$WEBPROXY_CONFIG_FILE"; fi
            webproxy_ports=" (Ports: ${PORTS:-N/A})"
            webproxy_status="${C_BRIGHT_GREEN}${C_BOLD}[ACTIVE]${C_RESET}"
        fi

        local nginx_status; if systemctl is-active --quiet nginx; then nginx_status="${C_BRIGHT_GREEN}${C_BOLD}[ACTIVE]${C_RESET}"; else nginx_status="${C_DIM}[INACTIVE]${C_RESET}"; fi
        local xui_status; if command -v x-ui &> /dev/null; then xui_status="${C_BRIGHT_GREEN}${C_BOLD}[INSTALLED]${C_RESET}"; else xui_status="${C_DIM}[NOT INSTALLED]${C_RESET}"; fi
        
        local http_custom_status="${C_DIM}[NOT INSTALLED]${C_RESET}"
        if [ -f "$HTTP_CUSTOM_SERVICE_FILE" ]; then
            # HTTP Custom is installed - check service status
            if systemctl is-active --quiet http-custom.service 2>/dev/null || systemctl is-active --quiet http-custom 2>/dev/null; then
                http_custom_status="${C_BRIGHT_GREEN}${C_BOLD}[ACTIVE: Port $HTTP_CUSTOM_PORT]${C_RESET}"
            elif ss -lntp 2>/dev/null | grep -qE ":${HTTP_CUSTOM_PORT}\s" || netstat -lntp 2>/dev/null | grep -qE ":${HTTP_CUSTOM_PORT}\s"; then
                http_custom_status="${C_BRIGHT_GREEN}${C_BOLD}[ACTIVE: Port $HTTP_CUSTOM_PORT]${C_RESET}"
            else
                http_custom_status="${C_BRIGHT_YELLOW}[INSTALLED: NOT RUNNING]${C_RESET}"
            fi
        fi
        
        echo -e "${C_BRIGHT_CYAN}${C_BOLD}    ╔═══════════════════════════════════════════════════════════════════════════════════════════╗${C_RESET}"
        echo -e "${C_BRIGHT_CYAN}${C_BOLD}    ║${C_RESET}  ${C_BRIGHT_MAGENTA}${C_BOLD}🔌  PROTOCOL & PANEL MANAGEMENT${C_RESET}${C_BRIGHT_CYAN}                                                                        ║${C_RESET}"
        echo -e "${C_BRIGHT_CYAN}${C_BOLD}    ╠═══════════════════════════════════════════════════════════════════════════════════════════╣${C_RESET}"
        echo -e "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_YELLOW}${C_BOLD}📡  TUNNELLING PROTOCOLS${C_RESET}                                                                        ${C_BRIGHT_CYAN}║${C_RESET}"
        echo -e "${C_BRIGHT_CYAN}    ║${C_RESET}                                                                                                        ${C_BRIGHT_CYAN}║${C_RESET}"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}1${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🚀  Install badvpn (UDP 7300)${C_RESET}                                    ${badvpn_status}  ${C_BRIGHT_CYAN}║${C_RESET}\n"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}2${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🗑   Uninstall badvpn${C_RESET}                                                      ${C_BRIGHT_CYAN}║${C_RESET}\n"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}3${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🚀  Install udp-custom (Excl. 53,5300)${C_RESET}                            ${udp_custom_status}  ${C_BRIGHT_CYAN}║${C_RESET}\n"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}4${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🗑   Uninstall udp-custom${C_RESET}                                              ${C_BRIGHT_CYAN}║${C_RESET}\n"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}5${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🔒  Install ${ssl_tunnel_text}${C_RESET}                                   ${ssl_tunnel_status}  ${C_BRIGHT_CYAN}║${C_RESET}\n"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}6${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🗑   Uninstall SSL Tunnel${C_RESET}                                              ${C_BRIGHT_CYAN}║${C_RESET}\n"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}7${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}📡  Install/View DNSTT (Port 53/5300)${C_RESET}                            ${dnstt_status}  ${C_BRIGHT_CYAN}║${C_RESET}\n"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}8${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🗑   Uninstall DNSTT${C_RESET}                                                      ${C_BRIGHT_CYAN}║${C_RESET}\n"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}9${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🌐  Install WebSocket Proxy${webproxy_ports}${C_RESET}                     ${webproxy_status}  ${C_BRIGHT_CYAN}║${C_RESET}\n"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}10${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🗑   Uninstall WebSocket Proxy${C_RESET}                                          ${C_BRIGHT_CYAN}║${C_RESET}\n"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}11${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🌐  Install/Manage Nginx Proxy (80/443)${C_RESET}                        ${nginx_status}  ${C_BRIGHT_CYAN}║${C_RESET}\n"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}14${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🌐  Install HTTP Custom (Port $HTTP_CUSTOM_PORT)${C_RESET}                        ${http_custom_status}  ${C_BRIGHT_CYAN}║${C_RESET}\n"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}15${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🗑   Uninstall HTTP Custom${C_RESET}                                              ${C_BRIGHT_CYAN}║${C_RESET}\n"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}16${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🛡   Install ZiVPN (UDP 5667 + Port Share)${C_RESET}                        ${zivpn_status}  ${C_BRIGHT_CYAN}║${C_RESET}\n"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}17${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🗑   Uninstall ZiVPN${C_RESET}                                                      ${C_BRIGHT_CYAN}║${C_RESET}\n"
        echo -e "${C_BRIGHT_CYAN}    ║${C_RESET}                                                                                                        ${C_BRIGHT_CYAN}║${C_RESET}"
        echo -e "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_YELLOW}${C_BOLD}💻  MANAGEMENT PANELS${C_RESET}                                                                        ${C_BRIGHT_CYAN}║${C_RESET}"
        echo -e "${C_BRIGHT_CYAN}    ║${C_RESET}                                                                                                        ${C_BRIGHT_CYAN}║${C_RESET}"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}12${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}💻  Install X-UI Panel${C_RESET}                                             ${xui_status}  ${C_BRIGHT_CYAN}║${C_RESET}\n"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}13${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🗑   Uninstall X-UI Panel${C_RESET}                                                 ${C_BRIGHT_CYAN}║${C_RESET}\n"
        echo -e "${C_BRIGHT_CYAN}${C_BOLD}    ╠═══════════════════════════════════════════════════════════════════════════════════════════╣${C_RESET}"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_YELLOW}${C_BOLD}0${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_CYAN}${C_BOLD}↩️   Return to Main Menu${C_RESET}                                                                        ${C_BRIGHT_CYAN}║${C_RESET}\n"
        echo -e "${C_BRIGHT_CYAN}${C_BOLD}    ╚═══════════════════════════════════════════════════════════════════════════════════════════╝${C_RESET}"
        echo
        # Spacing line before input prompt
        echo -e "${C_DIM}                                                                                                        ${C_RESET}"
        echo
        echo -e "${C_BRIGHT_YELLOW}${C_BOLD}    ╔═══════════════════════════════════════════════════════════════════════════════════════════╗${C_RESET}"
        echo -e -n "${C_BRIGHT_YELLOW}${C_BOLD}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}👉${C_RESET} ${C_BRIGHT_CYAN}${C_BOLD}Select an option:${C_RESET} ${C_BRIGHT_WHITE}"
        read -r choice
        echo -e "${C_BRIGHT_YELLOW}${C_BOLD}    ╚═══════════════════════════════════════════════════════════════════════════════════════════╝${C_RESET}"
        echo
        case $choice in
            1) install_badvpn; press_enter ;; 2) uninstall_badvpn; press_enter ;;
            3) install_udp_custom; press_enter ;; 4) uninstall_udp_custom; press_enter ;;
            5) install_ssl_tunnel; press_enter ;; 6) uninstall_ssl_tunnel; press_enter ;;
            7) install_dnstt; press_enter ;; 8) uninstall_dnstt; press_enter ;;
            9) install_web_proxy; press_enter ;; 10) uninstall_web_proxy; press_enter ;;
            11) nginx_proxy_menu ;;
            12) install_xui_panel; press_enter ;; 13) uninstall_xui_panel; press_enter ;;
            14) install_http_custom; press_enter ;; 15) uninstall_http_custom; press_enter ;;
            16) install_zivpn; press_enter ;; 17) uninstall_zivpn; press_enter ;;
            0) return ;;
            *) invalid_option ;;
        esac
    done
}

network_optimization_menu() {
    while true; do
        clear; show_banner
        
        # Check iptables status
        local iptables_status="${C_STATUS_I}(Not Configured)${C_RESET}"
        if command -v iptables &> /dev/null && [ -f "$IPTABLES_CONFIG_FILE" ]; then
            iptables_status="${C_STATUS_A}(Configured)${C_RESET}"
        fi
        
        # Check TCP BBR status
        local bbr_status="${C_STATUS_I}(Not Enabled)${C_RESET}"
        local current_cc
        current_cc=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
        if [[ "$current_cc" == "bbr" ]]; then
            bbr_status="${C_STATUS_A}(Enabled - BBR Active)${C_RESET}"
        elif [[ -n "$current_cc" ]]; then
            bbr_status="${C_STATUS_I}(Enabled - $current_cc)${C_RESET}"
        fi
        
        echo -e "\n   ${C_TITLE}══════════════[ ${C_BOLD}🔥 NETWORK OPTIMIZATION ${C_RESET}${C_TITLE}]══════════════${C_RESET}"
        echo -e "     ${C_ACCENT}--- 🔥 IPTABLES CONFIGURATION ---${C_RESET}"
        echo -e "     ${C_CHOICE}1)${C_RESET} 🔥 Configure iptables Rules $iptables_status"
        echo -e "     ${C_CHOICE}2)${C_RESET} 👁️ View Current iptables Rules"
        echo -e "     ${C_CHOICE}3)${C_RESET} 🗑️ Reset iptables Rules to Default"
        # Check IPv6 status
        local ipv6_status="${C_STATUS_I}(Disabled)${C_RESET}"
        if sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null | grep -q "= 0"; then
            ipv6_status="${C_STATUS_A}(Enabled)${C_RESET}"
        fi
        
        echo -e "     ${C_ACCENT}--- 🚀 TCP BBR CONGESTION CONTROL ---${C_RESET}"
        echo -e "     ${C_CHOICE}4)${C_RESET} 🚀 Enable TCP BBR & Network Optimizations $bbr_status"
        echo -e "     ${C_CHOICE}5)${C_RESET} 📊 Check TCP BBR Status"
        echo -e "     ${C_ACCENT}--- 🌐 IPv6 CONFIGURATION ---${C_RESET}"
        echo -e "     ${C_CHOICE}6)${C_RESET} 🌐 Configure IPv6 $ipv6_status"
        echo -e "   ${C_DIM}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${C_RESET}"
        echo -e "     ${C_WARN}0)${C_RESET} ↩️ Return to Main Menu"
        echo
        read -p "$(echo -e ${C_PROMPT}"👉 Select an option: "${C_RESET})" choice
        case $choice in
            1) configure_iptables; press_enter ;;
            2) view_iptables_rules; press_enter ;;
            3) reset_iptables_rules; press_enter ;;
            4) enable_tcp_bbr; press_enter ;;
            5) check_tcp_bbr_status; press_enter ;;
            6) configure_ipv6; press_enter ;;
            0) return ;;
            *) invalid_option ;;
        esac
    done
}

install_dt_proxy_full() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Full DT Tunnel Installation ---${C_RESET}"
    if [ -f "/usr/local/bin/main" ]; then
        echo -e "\n${C_YELLOW}ℹ️ DT Proxy appears to be already installed.${C_RESET}"
        echo -e "If you wish to reinstall, please uninstall it first."
        return
    fi

    echo -e "\n${C_BLUE}--- Step 1 of 2: Installing DT Tunnel Mod ---${C_RESET}"
    echo "This will download and run the prerequisite mod installer."
    read -p "👉 Press [Enter] to continue or [Ctrl+C] to cancel."

    if curl -sL https://raw.githubusercontent.com/firewallfalcons/ProxyMods/main/install.sh | bash; then
        echo -e "\n${C_GREEN}✅ DT Tunnel Mod installed successfully.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ ERROR: DT Tunnel Mod installation failed. Aborting.${C_RESET}"
        return
    fi

    echo -e "\n${C_BLUE}--- Step 2 of 2: Installing DT Tunnel Proxy ---${C_RESET}"
    echo "This will download and run the main DT Tunnel proxy installer."
    read -p "👉 Press [Enter] to continue or [Ctrl+C] to cancel."

    if bash <(curl -fsSL https://raw.githubusercontent.com/firewallfalcons/ProxyDT-Go-Releases/main/install.sh); then
        echo -e "\n${C_GREEN}✅ DT Tunnel Proxy installed successfully.${C_RESET}"
        echo -e "You can now manage it from the DT Proxy Management menu."
    else
        echo -e "\n${C_RED}❌ ERROR: DT Tunnel Proxy installation failed.${C_RESET}"
    fi
}

launch_dt_proxy_menu() {
    clear; show_banner
    if [ -f "/usr/local/bin/main" ]; then
        echo -e "\n${C_GREEN}✅ DT Proxy is installed. Launching its management panel...${C_RESET}"
        sleep 2
        /usr/local/bin/main
    else
        echo -e "\n${C_RED}❌ DT Proxy is not installed. Please use the install option first.${C_RESET}"
    fi
}

uninstall_dt_proxy_full() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🗑️ Uninstall DT Proxy (Mod + Proxy) ---${C_RESET}"
    if [ ! -f "/usr/local/bin/proxy" ] && [ ! -f "/usr/local/bin/main" ]; then
        echo -e "\n${C_YELLOW}ℹ️ DT Proxy is not installed. Nothing to do.${C_RESET}"
        return
    fi
    read -p "👉 Are you sure you want to PERMANENTLY delete DT Proxy and all its services? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        echo -e "\n${C_YELLOW}❌ Uninstallation cancelled.${C_RESET}"
        return
    fi

    echo -e "\n${C_BLUE}🛑 Stopping and disabling all DT Proxy services...${C_RESET}"
    systemctl list-units --type=service --state=running | grep 'proxy-' | awk '{print $1}' | xargs -r systemctl stop
    systemctl list-unit-files --type=service | grep 'proxy-' | awk '{print $1}' | xargs -r systemctl disable

    echo -e "\n${C_BLUE}🗑️ Removing files...${C_RESET}"
    rm -f /etc/systemd/system/proxy-*.service
    systemctl daemon-reload
    rm -f /usr/local/bin/proxy
    rm -f /usr/local/bin/main
    rm -f "$HOME/.proxy_token"
    rm -f /var/log/proxy-*.log
    rm -f /usr/local/bin/install_mod

    echo -e "\n${C_GREEN}✅ DT Proxy has been successfully uninstalled.${C_RESET}"
}

dt_proxy_menu() {
    while true; do
        clear; show_banner
        local dt_proxy_status
        if [ -f "/usr/local/bin/main" ] && [ -f "/usr/local/bin/proxy" ]; then
            dt_proxy_status="${C_BRIGHT_GREEN}${C_BOLD}[INSTALLED]${C_RESET}"
        else
            dt_proxy_status="${C_DIM}[NOT INSTALLED]${C_RESET}"
        fi

        echo -e "${C_BRIGHT_CYAN}${C_BOLD}    ╔═══════════════════════════════════════════════════════════════════════════════════════════╗${C_RESET}"
        echo -e "${C_BRIGHT_CYAN}${C_BOLD}    ║${C_RESET}  ${C_BRIGHT_MAGENTA}${C_BOLD}🚀  DT PROXY MANAGEMENT${C_RESET}${C_BRIGHT_CYAN}                                                                    ${dt_proxy_status}  ║${C_RESET}"
        echo -e "${C_BRIGHT_CYAN}${C_BOLD}    ╠═══════════════════════════════════════════════════════════════════════════════════════════╣${C_RESET}"
        echo -e "${C_BRIGHT_CYAN}    ║${C_RESET}                                                                                                        ${C_BRIGHT_CYAN}║${C_RESET}"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}1${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🚀  Install DT Tunnel (Mod + Proxy)${C_RESET}                                              ${C_BRIGHT_CYAN}║${C_RESET}\n"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}2${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}▶️   Launch DT Tunnel Management Menu${C_RESET}                                        ${C_BRIGHT_CYAN}║${C_RESET}\n"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_RED}${C_BOLD}3${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_RED}${C_BOLD}🗑   Uninstall DT Tunnel (Mod + Proxy)${C_RESET}                                            ${C_BRIGHT_CYAN}║${C_RESET}\n"
        echo -e "${C_BRIGHT_CYAN}    ║${C_RESET}                                                                                                        ${C_BRIGHT_CYAN}║${C_RESET}"
        echo -e "${C_BRIGHT_CYAN}${C_BOLD}    ╠═══════════════════════════════════════════════════════════════════════════════════════════╣${C_RESET}"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_YELLOW}${C_BOLD}0${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_CYAN}${C_BOLD}↩️   Return to Main Menu${C_RESET}                                                                        ${C_BRIGHT_CYAN}║${C_RESET}\n"
        echo -e "${C_BRIGHT_CYAN}${C_BOLD}    ╚═══════════════════════════════════════════════════════════════════════════════════════════╝${C_RESET}"
        echo
        echo -e "${C_BRIGHT_YELLOW}${C_BOLD}    ╔═══════════════════════════════════════════════════════════════════════════════════════════╗${C_RESET}"
        echo -e -n "${C_BRIGHT_YELLOW}${C_BOLD}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}👉${C_RESET} ${C_BRIGHT_CYAN}${C_BOLD}Select an option:${C_RESET} ${C_BRIGHT_WHITE}"
        read -r choice
        echo -e "${C_BRIGHT_YELLOW}${C_BOLD}    ╚═══════════════════════════════════════════════════════════════════════════════════════════╝${C_RESET}"
        echo
        case $choice in
            1) install_dt_proxy_full; press_enter ;;
            2) launch_dt_proxy_menu; press_enter ;;
            3) uninstall_dt_proxy_full; press_enter ;;
            0) return ;;
            *) invalid_option ;;
        esac
    done
}

uninstall_script() {
    clear; show_banner
    echo -e "${C_RED}=====================================================${C_RESET}"
    echo -e "${C_RED}       🔥 DANGER: UNINSTALL SCRIPT & ALL DATA 🔥      ${C_RESET}"
    echo -e "${C_RED}=====================================================${C_RESET}"
    echo -e "${C_YELLOW}This will PERMANENTLY remove this script and all its components, including:"
    echo -e " - The main command ($(command -v menu))"
    echo -e " - All configuration and user data ($DB_DIR)"
    echo -e " - The active limiter service ($LIMITER_SERVICE)"
    echo -e " - All installed services (badvpn, udp-custom, SSL Tunnel, Nginx, DNSTT, WebSocket Proxy)"
    echo -e "\n${C_RED}This action is irreversible.${C_RESET}"
    echo ""
    read -p "👉 Type 'yes' to confirm and proceed with uninstallation: " confirm
    if [[ "$confirm" != "yes" ]]; then
        echo -e "\n${C_GREEN}✅ Uninstallation cancelled.${C_RESET}"
        return
    fi
    export UNINSTALL_MODE="silent"
    echo -e "\n${C_BLUE}--- 💥 Starting Uninstallation 💥 ---${C_RESET}"
    
    echo -e "\n${C_BLUE}🗑️ Removing active limiter service...${C_RESET}"
    systemctl stop ${APP_BASE_DIR_NAME}-limiter &>/dev/null
    systemctl disable ${APP_BASE_DIR_NAME}-limiter &>/dev/null
    rm -f "$LIMITER_SERVICE"
    rm -f "$LIMITER_SCRIPT"
    
    chattr -i /etc/resolv.conf &>/dev/null

    purge_nginx "silent"
    uninstall_dnstt
    uninstall_badvpn
    uninstall_udp_custom
    uninstall_ssl_tunnel
    uninstall_web_proxy
    uninstall_zivpn
    
    echo -e "\n${C_BLUE}🔄 Reloading systemd daemon...${C_RESET}"
    systemctl daemon-reload
    
    echo -e "\n${C_BLUE}🗑️ Removing script and configuration files...${C_RESET}"
    rm -rf "$BADVPN_BUILD_DIR"
    rm -rf "$UDP_CUSTOM_DIR"
    rm -rf "$DB_DIR"
    rm -f "$(command -v menu)"
    
    echo -e "\n${C_GREEN}=============================================${C_RESET}"
    echo -e "${C_GREEN}      Script has been successfully uninstalled.     ${C_RESET}"
    echo -e "${C_GREEN}=============================================${C_RESET}"
    echo -e "\nAll associated files and services have been removed."
    echo "The 'menu' command will no longer work."
    exit 0
}

press_enter() {
    echo
    echo -e "${C_BRIGHT_YELLOW}${C_BOLD}    ╔═══════════════════════════════════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_BRIGHT_YELLOW}${C_BOLD}    ║${C_RESET}  ${C_BRIGHT_CYAN}${C_BOLD}Press ${C_BRIGHT_GREEN}${C_BOLD}[Enter]${C_RESET}${C_BRIGHT_CYAN}${C_BOLD} to return to the menu...${C_RESET}${C_BRIGHT_YELLOW}                                                                        ║${C_RESET}"
    echo -e "${C_BRIGHT_YELLOW}${C_BOLD}    ╚═══════════════════════════════════════════════════════════════════════════════════════════╝${C_RESET}"
    read -r
}
invalid_option() {
    echo
    echo -e "${C_BRIGHT_RED}${C_BOLD}    ╔═══════════════════════════════════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_BRIGHT_RED}${C_BOLD}    ║${C_RESET}  ${C_BRIGHT_RED}${C_BOLD}❌  Invalid option. Please try again.${C_RESET}${C_BRIGHT_RED}                                                                        ║${C_RESET}"
    echo -e "${C_BRIGHT_RED}${C_BOLD}    ╚═══════════════════════════════════════════════════════════════════════════════════════════╝${C_RESET}"
    sleep 1
}

main_menu() {
    initial_setup
    while true; do
        export UNINSTALL_MODE="interactive"
        show_banner
        
        # User Management Section - Enhanced Wider Frame
        echo -e "${C_BRIGHT_MAGENTA}${C_BOLD}    ╔═══════════════════════════════════════════════════════════════════════════════════════════╗${C_RESET}"
        echo -e "${C_BRIGHT_MAGENTA}${C_BOLD}    ║${C_RESET}  ${C_BRIGHT_CYAN}${C_BOLD}👤  USER MANAGEMENT${C_RESET}${C_BRIGHT_MAGENTA}                                                                        ║${C_RESET}"
        echo -e "${C_BRIGHT_MAGENTA}${C_BOLD}    ╠═══════════════════════════════════════════════════════════════════════════════════════════╣${C_RESET}"
        printf "${C_BRIGHT_MAGENTA}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}1${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}✨  Create New User${C_RESET}                                    ${C_BRIGHT_GREEN}${C_BOLD}5${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🔓  Unlock User Account${C_RESET}                      ${C_BRIGHT_MAGENTA}║${C_RESET}\n"
        printf "${C_BRIGHT_MAGENTA}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}2${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🗑   Delete User${C_RESET}                                      ${C_BRIGHT_GREEN}${C_BOLD}6${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}📋  List All Managed Users${C_RESET}                    ${C_BRIGHT_MAGENTA}║${C_RESET}\n"
        printf "${C_BRIGHT_MAGENTA}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}3${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}✏️   Edit User Details${C_RESET}                                  ${C_BRIGHT_GREEN}${C_BOLD}7${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🔄  Renew User Account${C_RESET}                        ${C_BRIGHT_MAGENTA}║${C_RESET}\n"
        printf "${C_BRIGHT_MAGENTA}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}4${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🔒  Lock User Account${C_RESET}                                                                                  ${C_BRIGHT_MAGENTA}║${C_RESET}\n"
        echo -e "${C_BRIGHT_MAGENTA}${C_BOLD}    ╚═══════════════════════════════════════════════════════════════════════════════════════════╝${C_RESET}"
        echo
        
        # System Utilities Section - Enhanced Wider Frame
        echo -e "${C_BRIGHT_CYAN}${C_BOLD}    ╔═══════════════════════════════════════════════════════════════════════════════════════════╗${C_RESET}"
        echo -e "${C_BRIGHT_CYAN}${C_BOLD}    ║${C_RESET}  ${C_BRIGHT_MAGENTA}${C_BOLD}⚙️   SYSTEM UTILITIES${C_RESET}${C_BRIGHT_CYAN}                                                                        ║${C_RESET}"
        echo -e "${C_BRIGHT_CYAN}${C_BOLD}    ╠═══════════════════════════════════════════════════════════════════════════════════════════╣${C_RESET}"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}8${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🔌  Install Protocols & Panels${C_RESET}                            ${C_BRIGHT_GREEN}${C_BOLD}9${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}💾  Backup User Data${C_RESET}                      ${C_BRIGHT_CYAN}║${C_RESET}\n"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}10${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}📥  Restore User Data${C_RESET}                                  ${C_BRIGHT_GREEN}${C_BOLD}11${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🎨  SSH Banner Management${C_RESET}                 ${C_BRIGHT_CYAN}║${C_RESET}\n"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}12${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🧹  Cleanup Expired Users${C_RESET}                              ${C_BRIGHT_GREEN}${C_BOLD}13${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🚀  DT Proxy Management${C_RESET}                    ${C_BRIGHT_CYAN}║${C_RESET}\n"
        printf "${C_BRIGHT_CYAN}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}14${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}📊  VPN Status & Auto-Config${C_RESET}                            ${C_BRIGHT_GREEN}${C_BOLD}15${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_YELLOW}${C_BOLD}🔥  Network Optimization${C_RESET}                   ${C_BRIGHT_CYAN}║${C_RESET}\n"
        echo -e "${C_BRIGHT_CYAN}${C_BOLD}    ╚═══════════════════════════════════════════════════════════════════════════════════════════╝${C_RESET}"
        echo
        
        # Danger Zone Section - Enhanced Wider Frame
        echo -e "${C_BRIGHT_RED}${C_BOLD}    ╔═══════════════════════════════════════════════════════════════════════════════════════════╗${C_RESET}"
        echo -e "${C_BRIGHT_RED}${C_BOLD}    ║${C_RESET}  ${C_BRIGHT_YELLOW}${C_BOLD}⚠️   DANGER ZONE - Use with Caution! ⚠️${C_RESET}${C_BRIGHT_RED}                                                                        ║${C_RESET}"
        echo -e "${C_BRIGHT_RED}${C_BOLD}    ╠═══════════════════════════════════════════════════════════════════════════════════════════╣${C_RESET}"
        printf "${C_BRIGHT_RED}    ║${C_RESET}  ${C_BRIGHT_RED}${C_BOLD}99${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_RED}${C_BOLD}💥  Uninstall Script${C_RESET}                                                                    ${C_BRIGHT_GREEN}${C_BOLD}0${C_RESET}${C_WHITE})${C_RESET} ${C_BRIGHT_CYAN}${C_BOLD}🚪  Exit${C_RESET}                      ${C_BRIGHT_RED}║${C_RESET}\n"
        echo -e "${C_BRIGHT_RED}${C_BOLD}    ╚═══════════════════════════════════════════════════════════════════════════════════════════╝${C_RESET}"
        echo
        
        # Input Prompt - Enhanced Wider Frame
        echo -e "${C_BRIGHT_YELLOW}${C_BOLD}    ╔═══════════════════════════════════════════════════════════════════════════════════════════╗${C_RESET}"
        echo -e -n "${C_BRIGHT_YELLOW}${C_BOLD}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}👉${C_RESET} ${C_BRIGHT_CYAN}${C_BOLD}Select an option:${C_RESET} ${C_BRIGHT_WHITE}"
        read -r choice
        echo -e "${C_BRIGHT_YELLOW}${C_BOLD}    ╚═══════════════════════════════════════════════════════════════════════════════════════════╝${C_RESET}"
        echo
        case $choice in
            1) create_user; press_enter ;;
            2) delete_user; press_enter ;;
            3) edit_user; press_enter ;;
            4) lock_user; press_enter ;;
            5) unlock_user; press_enter ;;
            6) list_users; press_enter ;;
            7) renew_user; press_enter ;;
            8) protocol_menu ;;
            9) backup_user_data; press_enter ;;
            10) restore_user_data; press_enter ;;
            11) ssh_banner_menu ;;
            12) cleanup_expired; press_enter ;;
            13) dt_proxy_menu ;;
            14) show_vpn_status; press_enter ;;
            15) network_optimization_menu ;;
            99) uninstall_script ;;
            0) 
                echo
                echo -e "${C_BRIGHT_CYAN}${C_BOLD}    ╔═══════════════════════════════════════════════════════════════════════════════════════════╗${C_RESET}"
                echo -e "${C_BRIGHT_CYAN}${C_BOLD}    ║${C_RESET}  ${C_BRIGHT_GREEN}${C_BOLD}👋  Thank you for using ${REPO_NAME} Manager!${C_RESET}${C_BRIGHT_CYAN}                                                                        ║${C_RESET}"
                echo -e "${C_BRIGHT_CYAN}${C_BOLD}    ║${C_RESET}  ${C_BRIGHT_YELLOW}${C_BOLD}Goodbye! See you soon! 👋${C_RESET}${C_BRIGHT_CYAN}                                                                        ║${C_RESET}"
                echo -e "${C_BRIGHT_CYAN}${C_BOLD}    ╚═══════════════════════════════════════════════════════════════════════════════════════════╝${C_RESET}"
                echo
                exit 0 
                ;;
            *) invalid_option ;;
        esac
    done
}

# Handle command line arguments
if [[ "$1" == "--install-setup" ]]; then
    initial_setup
    exit 0
fi

# Main entry point - start the menu
main_menu
