#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root."
   exit 1
fi

echo "Installing FirewallFalcon Manager..."

MENU_URL="https://raw.githubusercontent.com/Iddy29/MRCYBER255-KITONGA/refs/heads/main/menu.sh"
MENU_PATH="/usr/local/bin/menu"

# Check if wget or curl is available
if command -v wget &> /dev/null; then
    DOWNLOAD_CMD="wget"
    # Force IPv4, add retries, show progress
    DOWNLOAD_FLAGS=("--show-progress" "--timeout=30" "--tries=3" "--retry-connrefused" "--prefer-family=IPv4" "-O")
elif command -v curl &> /dev/null; then
    DOWNLOAD_CMD="curl"
    # Force IPv4, add retries
    DOWNLOAD_FLAGS=("-4" "-L" "--connect-timeout" "30" "--max-time" "60" "--retry" "3" "--retry-delay" "2" "-o")
else
    echo "Error: Neither wget nor curl is installed. Please install one of them first:"
    echo "  apt-get update && apt-get install -y wget"
    echo "  or"
    echo "  apt-get update && apt-get install -y curl"
    exit 1
fi

echo "Downloading menu.sh from repository..."
echo "URL: $MENU_URL"
echo "Note: Using IPv4 only to avoid connection issues..."
echo ""

# Download menu.sh with progress and retries
DOWNLOAD_ATTEMPTS=0
MAX_ATTEMPTS=3
DOWNLOAD_SUCCESS=false

while [[ $DOWNLOAD_ATTEMPTS -lt $MAX_ATTEMPTS ]]; do
    DOWNLOAD_ATTEMPTS=$((DOWNLOAD_ATTEMPTS + 1))
    
    if [[ $DOWNLOAD_ATTEMPTS -gt 1 ]]; then
        echo "Retry attempt $DOWNLOAD_ATTEMPTS of $MAX_ATTEMPTS..."
        sleep 2
    fi
    
    if $DOWNLOAD_CMD "${DOWNLOAD_FLAGS[@]}" "$MENU_PATH" "$MENU_URL" 2>&1; then
        DOWNLOAD_SUCCESS=true
        break
    else
        echo "Download attempt $DOWNLOAD_ATTEMPTS failed."
        if [[ -f "$MENU_PATH" ]]; then
            rm -f "$MENU_PATH"
        fi
    fi
done

if [[ "$DOWNLOAD_SUCCESS" == "true" ]]; then
    # Check if download was successful
    if [[ ! -f "$MENU_PATH" ]] || [[ ! -s "$MENU_PATH" ]]; then
        echo "Error: Failed to download menu.sh or file is empty."
        echo "Please check your internet connection and try again."
        exit 1
    fi
    
    # Check if it's a valid bash script
    if ! head -n 1 "$MENU_PATH" | grep -q "#!/bin/bash"; then
        echo "Error: Downloaded file does not appear to be a valid bash script."
        echo "Please check the repository URL and try again."
        rm -f "$MENU_PATH"
        exit 1
    fi
    
    echo ""
    echo "Download completed. File size: $(du -h "$MENU_PATH" | cut -f1)"
    echo ""
    echo "Setting executable permissions..."
    chmod +x "$MENU_PATH"
    
    if [[ ! -x "$MENU_PATH" ]]; then
        echo "Error: Failed to set executable permissions."
        exit 1
    fi
    
    echo "Running initial setup..."
    echo "This may take a few moments..."
    echo ""
    
    # Run setup with timeout to prevent hanging (if timeout command exists)
    if command -v timeout &> /dev/null; then
        if timeout 120 "$MENU_PATH" --install-setup 2>&1; then
            SETUP_SUCCESS=true
        else
            SETUP_SUCCESS=false
        fi
    else
        # If timeout doesn't exist, run without timeout
        if "$MENU_PATH" --install-setup 2>&1; then
            SETUP_SUCCESS=true
        else
            SETUP_SUCCESS=false
        fi
    fi
    
    if [[ "$SETUP_SUCCESS" == "true" ]]; then
        echo ""
        echo "✅ Installation complete! Type 'menu' to start."
    else
        echo ""
        echo "⚠️  Warning: Initial setup encountered some issues or timed out."
        echo "You can still try running 'menu' to see if it works."
        echo "If 'menu' doesn't work, try: /usr/local/bin/menu"
        exit 1
    fi
else
    echo ""
    echo "❌ Error: Failed to download menu.sh from repository after $MAX_ATTEMPTS attempts."
    echo "URL: $MENU_URL"
    echo ""
    echo "Possible issues:"
    echo "  - Internet connection problem"
    echo "  - GitHub is blocked or unreachable from your VPS"
    echo "  - IPv6 connectivity issues (script tried IPv4 only)"
    echo "  - Firewall blocking GitHub"
    echo ""
    echo "Troubleshooting steps:"
    echo "  1. Test connectivity: ping -4 raw.githubusercontent.com"
    echo "  2. Test with curl: curl -4 -I https://raw.githubusercontent.com"
    echo "  3. Check firewall rules"
    echo "  4. Try manual download:"
    echo "     wget --prefer-family=IPv4 -O /usr/local/bin/menu \"$MENU_URL\""
    echo "     chmod +x /usr/local/bin/menu"
    echo "     /usr/local/bin/menu --install-setup"
    echo ""
    exit 1
fi
