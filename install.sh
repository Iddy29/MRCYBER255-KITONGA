#!/usr/bin/env bash

# Repository Configuration
REPO_NAME="MRCYBER255-KITONGA"
REPO_OWNER="Iddy29"
REPO_BRANCH="refs/heads/main"
# Extract branch name from refs/heads/main format for raw.githubusercontent.com URLs
REPO_BRANCH_NAME=$(echo "$REPO_BRANCH" | sed 's|refs/heads/||')
REPO_BASE_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_BRANCH_NAME}"

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root."
   exit 1
fi

echo "Installing ${REPO_NAME} Manager..."

MENU_URL="${REPO_BASE_URL}/menu.sh"
MENU_PATH="/usr/local/bin/menu"

# Validate URL construction
if [[ ! "$REPO_BASE_URL" =~ ^https://raw\.githubusercontent\.com/ ]]; then
    echo "Error: Invalid URL constructed: $REPO_BASE_URL"
    echo "Please check REPO_OWNER, REPO_NAME, and REPO_BRANCH_NAME variables."
    exit 1
fi

# Verify URL contains no typos
if [[ "$REPO_BASE_URL" == *"githubuserecontent"* ]] || [[ "$REPO_BASE_URL" == *"githubusercontent"* && "$REPO_BASE_URL" != *"raw.githubusercontent.com"* ]]; then
    echo "Error: URL contains typo: $REPO_BASE_URL"
    echo "Correct URL should be: https://raw.githubusercontent.com/..."
    exit 1
fi

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
echo "Full URL: $MENU_URL"
echo "Base URL: $REPO_BASE_URL"
echo "Repository: ${REPO_OWNER}/${REPO_NAME}"
echo "Branch: ${REPO_BRANCH_NAME}"
echo "Note: Using IPv4 only to avoid connection issues..."
echo ""

# Verify URL is properly formatted and contains no typos
if [[ ! "$MENU_URL" =~ ^https://raw\.githubusercontent\.com/[^/]+/[^/]+/[^/]+/menu\.sh$ ]]; then
    echo "Error: Invalid menu.sh URL format: $MENU_URL"
    echo "Expected format: https://raw.githubusercontent.com/OWNER/REPO/BRANCH/menu.sh"
    exit 1
fi

# Check for common typos in URL
if [[ "$MENU_URL" == *"githubuserecontent"* ]] || [[ "$MENU_URL" == *"githubcontent"* ]] || [[ "$MENU_URL" != *"raw.githubusercontent.com"* ]]; then
    echo "Error: URL contains typo or incorrect domain!"
    echo "Found URL: $MENU_URL"
    echo "Correct domain should be: raw.githubusercontent.com"
    echo "Please check your network/DNS configuration or repository settings."
    exit 1
fi

# Test URL reachability before attempting download
echo "Testing URL reachability..."
if command -v curl &> /dev/null; then
    if ! curl -4 -I -s --max-time 10 "$MENU_URL" | grep -q "HTTP/.*200\|HTTP/.*302"; then
        echo "Warning: URL may not be reachable. Continuing anyway..."
    else
        echo "URL is reachable. Proceeding with download..."
    fi
elif command -v wget &> /dev/null; then
    if ! wget --spider --prefer-family=IPv4 -T 10 "$MENU_URL" 2>&1 | grep -q "200 OK\|302 Found"; then
        echo "Warning: URL may not be reachable. Continuing anyway..."
    else
        echo "URL is reachable. Proceeding with download..."
    fi
fi
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
    
    # Construct the download command properly based on tool
    if [[ "$DOWNLOAD_CMD" == "wget" ]]; then
        # wget format: wget [flags] -O output_file url
        if wget "${DOWNLOAD_FLAGS[@]}" "$MENU_PATH" "$MENU_URL" 2>&1; then
            DOWNLOAD_SUCCESS=true
            break
        else
            echo "Download attempt $DOWNLOAD_ATTEMPTS failed."
            if [[ -f "$MENU_PATH" ]]; then
                rm -f "$MENU_PATH"
            fi
        fi
    elif [[ "$DOWNLOAD_CMD" == "curl" ]]; then
        # curl format: curl [flags] -o output_file url
        if curl "${DOWNLOAD_FLAGS[@]}" "$MENU_PATH" "$MENU_URL" 2>&1; then
            DOWNLOAD_SUCCESS=true
            break
        else
            echo "Download attempt $DOWNLOAD_ATTEMPTS failed."
            if [[ -f "$MENU_PATH" ]]; then
                rm -f "$MENU_PATH"
            fi
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
    echo "Fixing line endings (converting CRLF to LF if needed)..."
    # Convert CRLF to LF (fixes Windows line endings issue on Linux)
    # Try multiple methods to ensure compatibility across different systems
    if command -v dos2unix &> /dev/null; then
        dos2unix "$MENU_PATH" 2>/dev/null
    elif command -v sed &> /dev/null; then
        sed -i 's/\r$//' "$MENU_PATH" 2>/dev/null || sed -i '' 's/\r$//' "$MENU_PATH" 2>/dev/null
    else
        tr -d '\r' < "$MENU_PATH" > "${MENU_PATH}.tmp" && mv "${MENU_PATH}.tmp" "$MENU_PATH"
    fi
    
    # Verify line endings were fixed by checking for CRLF
    if file "$MENU_PATH" 2>/dev/null | grep -q "CRLF\|with CRLF"; then
        echo "Warning: CRLF line endings detected, attempting additional fix..."
        perl -pi -e 's/\r\n/\n/g' "$MENU_PATH" 2>/dev/null || tr -d '\r' < "$MENU_PATH" > "${MENU_PATH}.tmp" && mv "${MENU_PATH}.tmp" "$MENU_PATH"
    fi
    
    echo "Setting executable permissions..."
    chmod +x "$MENU_PATH"
    
    # Verify shebang exists and is correct
    if ! head -n 1 "$MENU_PATH" | grep -q "#!/bin/bash\|#!/usr/bin/env bash"; then
        echo "Warning: Script may not have a valid shebang line."
    fi
    
    if [[ ! -x "$MENU_PATH" ]]; then
        echo "Error: Failed to set executable permissions."
        echo "Attempting manual fix..."
        chmod 755 "$MENU_PATH"
        if [[ ! -x "$MENU_PATH" ]]; then
            echo "Error: Still unable to set executable permissions. Please run manually: chmod +x $MENU_PATH"
            exit 1
        fi
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
    echo ""
    echo "Configuration used:"
    echo "  Repository Owner: $REPO_OWNER"
    echo "  Repository Name: $REPO_NAME"
    echo "  Branch: $REPO_BRANCH_NAME"
    echo "  Base URL: $REPO_BASE_URL"
    echo "  Full URL: $MENU_URL"
    echo ""
    echo "Possible issues:"
    echo "  - Internet connection problem"
    echo "  - GitHub is blocked or unreachable from your VPS"
    echo "  - DNS resolution failure (raw.githubusercontent.com)"
    echo "  - IPv6 connectivity issues (script tried IPv4 only)"
    echo "  - Firewall blocking GitHub"
    echo "  - URL typo or incorrect repository/branch name"
    echo ""
    echo "Troubleshooting steps:"
    echo "  1. Test DNS resolution: nslookup raw.githubusercontent.com"
    echo "  2. Test connectivity: ping -4 raw.githubusercontent.com"
    echo "  3. Test with curl: curl -4 -I https://raw.githubusercontent.com"
    echo "  4. Test specific URL: curl -4 -I \"$MENU_URL\""
    echo "  5. Check firewall rules"
    echo "  6. Verify repository exists: https://github.com/${REPO_OWNER}/${REPO_NAME}"
    echo "  7. Try manual download:"
    echo "     wget --prefer-family=IPv4 -O /usr/local/bin/menu \"$MENU_URL\""
    echo "     chmod +x /usr/local/bin/menu"
    echo "     /usr/local/bin/menu --install-setup"
    echo ""
    exit 1
fi
