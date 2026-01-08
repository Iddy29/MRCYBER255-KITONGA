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
    DOWNLOAD_FLAGS="--show-progress --timeout=30 -O"
elif command -v curl &> /dev/null; then
    DOWNLOAD_CMD="curl"
    DOWNLOAD_FLAGS="-L --connect-timeout 30 --max-time 60 -o"
else
    echo "Error: Neither wget nor curl is installed. Please install one of them first:"
    echo "  apt-get update && apt-get install -y wget"
    echo "  or"
    echo "  apt-get update && apt-get install -y curl"
    exit 1
fi

echo "Downloading menu.sh from repository..."
echo "URL: $MENU_URL"
echo ""

# Download menu.sh with progress
if $DOWNLOAD_CMD $DOWNLOAD_FLAGS "$MENU_PATH" "$MENU_URL" 2>&1; then
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
    
    # Run setup with timeout to prevent hanging
    if timeout 120 "$MENU_PATH" --install-setup 2>&1; then
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
    echo "Error: Failed to download menu.sh from repository."
    echo "URL: $MENU_URL"
    echo ""
    echo "Possible issues:"
    echo "  - Internet connection problem"
    echo "  - Repository URL is incorrect"
    echo "  - GitHub is temporarily unavailable"
    echo ""
    echo "Please check your internet connection and try again."
    exit 1
fi
