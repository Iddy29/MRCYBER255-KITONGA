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

# Fix DNS configuration if DNS resolution fails
fix_dns() {
    echo "🔧 Fixing DNS configuration..."
    
    # Check if /etc/resolv.conf exists
    if [[ ! -f /etc/resolv.conf ]]; then
        touch /etc/resolv.conf
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
}

# Add GitHub IP to /etc/hosts as fallback
add_github_hosts() {
    echo "  📝 Adding GitHub IPs to /etc/hosts as fallback..."
    if ! grep -q "raw.githubusercontent.com" /etc/hosts 2>/dev/null; then
        # GitHub raw content CDN IPs (these may need updating)
        echo "# GitHub raw content CDN" >> /etc/hosts
        echo "185.199.108.133 raw.githubusercontent.com" >> /etc/hosts
        echo "185.199.109.133 raw.githubusercontent.com" >> /etc/hosts
        echo "185.199.110.133 raw.githubusercontent.com" >> /etc/hosts
        echo "185.199.111.133 raw.githubusercontent.com" >> /etc/hosts
        echo "  ✅ GitHub IPs added to /etc/hosts"
    else
        echo "  ℹ️  GitHub IPs already in /etc/hosts"
    fi
}

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

# Test DNS resolution and URL reachability before attempting download
echo "Testing DNS resolution..."
DNS_OK=false
if command -v nslookup &> /dev/null; then
    if nslookup raw.githubusercontent.com > /dev/null 2>&1; then
        DNS_OK=true
    fi
fi
if [[ "$DNS_OK" != "true" ]] && command -v getent &> /dev/null; then
    if getent hosts raw.githubusercontent.com > /dev/null 2>&1; then
        DNS_OK=true
    fi
fi
if [[ "$DNS_OK" != "true" ]] && command -v host &> /dev/null; then
    if host raw.githubusercontent.com > /dev/null 2>&1; then
        DNS_OK=true
    fi
fi

if [[ "$DNS_OK" != "true" ]]; then
    echo "⚠️  Warning: DNS resolution for raw.githubusercontent.com failed."
    echo "  Attempting to fix DNS configuration..."
    echo ""
    fix_dns
    echo ""
    
    # Test again after fixing DNS
    DNS_OK=false
    if command -v host &> /dev/null; then
        if host raw.githubusercontent.com > /dev/null 2>&1; then
            DNS_OK=true
        fi
    fi
    if [[ "$DNS_OK" != "true" ]] && command -v nslookup &> /dev/null; then
        if nslookup raw.githubusercontent.com > /dev/null 2>&1; then
            DNS_OK=true
        fi
    fi
    if [[ "$DNS_OK" != "true" ]] && command -v getent &> /dev/null; then
        if getent hosts raw.githubusercontent.com > /dev/null 2>&1; then
            DNS_OK=true
        fi
    fi
    
    # If DNS still doesn't work, add hosts file entries
    if [[ "$DNS_OK" != "true" ]]; then
        echo "⚠️  DNS resolution still failing. Adding GitHub IPs to /etc/hosts..."
        add_github_hosts
        sleep 1
    else
        echo "✅ DNS resolution working after fix!"
    fi
    echo ""
fi

echo "Testing URL reachability..."
REACHABLE=false
if command -v curl &> /dev/null; then
    if curl -4 -I -s --max-time 10 "$MENU_URL" 2>&1 | grep -q "HTTP/.*200\|HTTP/.*302"; then
        echo "✅ URL is reachable via curl. Proceeding with download..."
        REACHABLE=true
    elif curl -4 -I -s --max-time 10 -k "$MENU_URL" 2>&1 | grep -q "HTTP/.*200\|HTTP/.*302"; then
        echo "⚠️  URL reachable but with certificate issues. Continuing..."
        REACHABLE=true
    else
        echo "⚠️  Warning: URL may not be reachable via curl. Will still attempt download..."
    fi
elif command -v wget &> /dev/null; then
    if wget --spider --prefer-family=IPv4 -T 10 "$MENU_URL" 2>&1 | grep -q "200 OK\|302 Found"; then
        echo "✅ URL is reachable via wget. Proceeding with download..."
        REACHABLE=true
    else
        echo "⚠️  Warning: URL may not be reachable via wget. Will still attempt download..."
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
            # Try without IPv4 restriction on retry
            if [[ $DOWNLOAD_ATTEMPTS -eq 2 ]]; then
                echo "Trying without IPv4 restriction..."
                if wget --timeout=30 --tries=2 -O "$MENU_PATH" "$MENU_URL" 2>&1; then
                    DOWNLOAD_SUCCESS=true
                    break
                fi
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
            # Try with different options on retry
            if [[ $DOWNLOAD_ATTEMPTS -eq 2 ]]; then
                echo "Trying with different connection options..."
                # Try without IPv4 restriction, with insecure SSL if needed
                if curl -L --connect-timeout 30 --max-time 60 -o "$MENU_PATH" "$MENU_URL" 2>&1 || \
                   curl -L --connect-timeout 30 --max-time 60 -k -o "$MENU_PATH" "$MENU_URL" 2>&1; then
                    DOWNLOAD_SUCCESS=true
                    break
                fi
            fi
        fi
    fi
done

# If download failed, try GitHub API as fallback
if [[ "$DOWNLOAD_SUCCESS" != "true" ]]; then
    echo ""
    echo "⚠️  Primary download methods failed. Attempting GitHub API fallback..."
    GITHUB_API_URL="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/contents/menu.sh?ref=${REPO_BRANCH_NAME}"
    
    if command -v curl &> /dev/null; then
        echo "Fetching download URL from GitHub API..."
        DOWNLOAD_URL=$(curl -4 -s -L --max-time 30 "$GITHUB_API_URL" | grep -o '"download_url":"[^"]*"' | cut -d'"' -f4)
        
        if [[ -n "$DOWNLOAD_URL" ]]; then
            echo "Using GitHub API download URL: $DOWNLOAD_URL"
            if curl -4 -L --connect-timeout 30 --max-time 60 -o "$MENU_PATH" "$DOWNLOAD_URL" 2>&1 || \
               curl -L --connect-timeout 30 --max-time 60 -o "$MENU_PATH" "$DOWNLOAD_URL" 2>&1; then
                if [[ -f "$MENU_PATH" ]] && [[ -s "$MENU_PATH" ]]; then
                    echo "✅ Successfully downloaded via GitHub API!"
                    DOWNLOAD_SUCCESS=true
                fi
            fi
        fi
    elif command -v wget &> /dev/null; then
        echo "Fetching download URL from GitHub API..."
        DOWNLOAD_URL=$(wget --prefer-family=IPv4 -q -O - --timeout=30 "$GITHUB_API_URL" 2>/dev/null | grep -o '"download_url":"[^"]*"' | cut -d'"' -f4)
        
        if [[ -n "$DOWNLOAD_URL" ]]; then
            echo "Using GitHub API download URL: $DOWNLOAD_URL"
            if wget --prefer-family=IPv4 --timeout=30 -O "$MENU_PATH" "$DOWNLOAD_URL" 2>&1 || \
               wget --timeout=30 -O "$MENU_PATH" "$DOWNLOAD_URL" 2>&1; then
                if [[ -f "$MENU_PATH" ]] && [[ -s "$MENU_PATH" ]]; then
                    echo "✅ Successfully downloaded via GitHub API!"
                    DOWNLOAD_SUCCESS=true
                fi
            fi
        fi
    fi
fi

if [[ "$DOWNLOAD_SUCCESS" == "true" ]]; then
    # Check if download was successful
    if [[ ! -f "$MENU_PATH" ]] || [[ ! -s "$MENU_PATH" ]]; then
        echo "Error: Failed to download menu.sh or file is empty."
        echo "Please check your internet connection and try again."
        exit 1
    fi
    
    # Check if it's a valid bash script (accept both shebang formats)
    if ! head -n 1 "$MENU_PATH" | grep -q "#!/bin/bash\|#!/usr/bin/env bash"; then
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
    echo "  1. Test DNS resolution:"
    echo "     nslookup raw.githubusercontent.com"
    echo "     getent hosts raw.githubusercontent.com"
    echo "  2. Test connectivity:"
    echo "     ping -4 -c 3 raw.githubusercontent.com"
    echo "     ping -c 3 raw.githubusercontent.com"
    echo "  3. Test with curl (HTTP check):"
    echo "     curl -4 -I https://raw.githubusercontent.com"
    echo "     curl -I https://raw.githubusercontent.com"
    echo "  4. Test specific URL:"
    echo "     curl -4 -I \"$MENU_URL\""
    echo "     curl -I \"$MENU_URL\""
    echo "  5. Check firewall rules:"
    echo "     iptables -L -n | grep -i github"
    echo "     ufw status"
    echo "  6. Verify repository exists:"
    echo "     https://github.com/${REPO_OWNER}/${REPO_NAME}"
    echo "  7. Check if GitHub is blocked (try alternative method):"
    echo "     curl -L \"https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/contents/menu.sh?ref=${REPO_BRANCH_NAME}\" | grep -o '\"download_url\":\"[^\"]*\"'"
    echo "  8. Try manual download (use whichever works):"
    echo "     wget --prefer-family=IPv4 -O /usr/local/bin/menu \"$MENU_URL\""
    echo "     curl -4 -L -o /usr/local/bin/menu \"$MENU_URL\""
    echo "     curl -L -o /usr/local/bin/menu \"$MENU_URL\""
    echo "     chmod +x /usr/local/bin/menu"
    echo "     /usr/local/bin/menu --install-setup"
    echo ""
    exit 1
fi
