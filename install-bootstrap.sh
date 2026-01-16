#!/usr/bin/env bash

# Bootstrap installer - Fixes DNS issues and installs the main script
# This script works even when GitHub DNS is blocked

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root."
   exit 1
fi

echo "=========================================="
echo "MRCYBER255-KITONGA Bootstrap Installer"
echo "=========================================="
echo ""
echo "This script will fix DNS issues and install the main manager."
echo ""

# Fix DNS configuration
echo "🔧 Checking DNS configuration..."

# Check if /etc/resolv.conf exists and is not a symlink to systemd-resolved
if [ -L /etc/resolv.conf ]; then
    echo "  ⚠️  /etc/resolv.conf is a symlink. Backing up..."
    RESOLV_BACKUP="/etc/resolv.conf.$(date +%s).bak"
    if [ -f /etc/resolv.conf ]; then
        cp -L /etc/resolv.conf "$RESOLV_BACKUP" 2>/dev/null
    fi
fi

# Add reliable DNS servers if not present
if ! grep -q "nameserver 8.8.8.8" /etc/resolv.conf 2>/dev/null; then
    echo "  📝 Adding Google DNS (8.8.8.8)..."
    echo "nameserver 8.8.8.8" >> /etc/resolv.conf
fi

if ! grep -q "nameserver 1.1.1.1" /etc/resolv.conf 2>/dev/null; then
    echo "  📝 Adding Cloudflare DNS (1.1.1.1)..."
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf
fi

# Try to flush DNS cache
if command -v systemd-resolve &> /dev/null; then
    systemd-resolve --flush-caches 2>/dev/null || true
fi

# Wait a moment for DNS to update
sleep 2

echo "  ✅ DNS configuration updated"
echo ""

# Test DNS resolution
echo "🔍 Testing DNS resolution..."
if host raw.githubusercontent.com > /dev/null 2>&1 || \
   nslookup raw.githubusercontent.com > /dev/null 2>&1 || \
   getent hosts raw.githubusercontent.com > /dev/null 2>&1; then
    echo "  ✅ DNS resolution working!"
    DNS_WORKING=true
else
    echo "  ⚠️  DNS resolution still failing"
    DNS_WORKING=false
fi
echo ""

# If DNS still doesn't work, use IP address directly
if [[ "$DNS_WORKING" != "true" ]]; then
    echo "⚠️  DNS resolution failed. Using GitHub IP addresses directly..."
    
    # Check if GitHub IPs already in /etc/hosts
    if ! grep -q "raw.githubusercontent.com" /etc/hosts 2>/dev/null; then
        # GitHub's raw content IP addresses (may need updating)
        GITHUB_IPS=("185.199.108.133" "185.199.109.133" "185.199.110.133" "185.199.111.133")
        
        # Add GitHub IPs to /etc/hosts
        echo "# GitHub raw content CDN (added by bootstrap installer)" >> /etc/hosts
        for ip in "${GITHUB_IPS[@]}"; do
            echo "$ip raw.githubusercontent.com" >> /etc/hosts
            echo "  📝 Added $ip to /etc/hosts"
        done
        echo "  ✅ GitHub IPs added to /etc/hosts"
    else
        echo "  ℹ️  GitHub IPs already in /etc/hosts"
    fi
    
    sleep 1
fi

# Try to download using the main install script
echo "📥 Downloading main installer..."
INSTALL_URL="https://raw.githubusercontent.com/Iddy29/MRCYBER255-KITONGA/main/install.sh"
INSTALL_PATH="/tmp/install-main.sh"

DOWNLOAD_SUCCESS=false

# Try with curl
if command -v curl &> /dev/null; then
    if curl -L --connect-timeout 30 --max-time 60 -o "$INSTALL_PATH" "$INSTALL_URL" 2>&1; then
        if [[ -f "$INSTALL_PATH" ]] && [[ -s "$INSTALL_PATH" ]]; then
            DOWNLOAD_SUCCESS=true
            echo "  ✅ Downloaded via curl"
        fi
    fi
fi

# Try with wget if curl failed
if [[ "$DOWNLOAD_SUCCESS" != "true" ]] && command -v wget &> /dev/null; then
    if wget --timeout=30 -O "$INSTALL_PATH" "$INSTALL_URL" 2>&1; then
        if [[ -f "$INSTALL_PATH" ]] && [[ -s "$INSTALL_PATH" ]]; then
            DOWNLOAD_SUCCESS=true
            echo "  ✅ Downloaded via wget"
        fi
    fi
fi

if [[ "$DOWNLOAD_SUCCESS" == "true" ]]; then
    chmod +x "$INSTALL_PATH"
    echo ""
    echo "🚀 Running main installer..."
    echo ""
    exec "$INSTALL_PATH"
else
    echo ""
    echo "❌ Failed to download main installer."
    echo ""
    echo "Manual installation options:"
    echo ""
    echo "Option 1: Fix DNS manually and retry"
    echo "  echo 'nameserver 8.8.8.8' >> /etc/resolv.conf"
    echo "  echo 'nameserver 1.1.1.1' >> /etc/resolv.conf"
    echo "  curl -L -o install.sh 'https://raw.githubusercontent.com/Iddy29/MRCYBER255-KITONGA/main/install.sh'"
    echo ""
    echo "Option 2: Use GitHub IP directly"
    echo "  echo '185.199.108.133 raw.githubusercontent.com' >> /etc/hosts"
    echo "  curl -L -o install.sh 'https://raw.githubusercontent.com/Iddy29/MRCYBER255-KITONGA/main/install.sh'"
    echo ""
    echo "Option 3: Use alternative DNS"
    echo "  systemctl stop systemd-resolved"
    echo "  echo 'nameserver 8.8.8.8' > /etc/resolv.conf"
    echo "  echo 'nameserver 1.1.1.1' >> /etc/resolv.conf"
    echo "  curl -L -o install.sh 'https://raw.githubusercontent.com/Iddy29/MRCYBER255-KITONGA/main/install.sh'"
    echo ""
    exit 1
fi
