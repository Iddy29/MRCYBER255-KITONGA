#!/usr/bin/env bash

# Fix script for VPS - Fixes common issues preventing scripts from running
# This script fixes line endings and permissions for menu.sh

SCRIPT_NAME="fix-vps.sh"
MENU_PATH="/usr/local/bin/menu"
MENU_LOCAL="menu.sh"

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root."
   exit 1
fi

echo "=========================================="
echo "VPS Script Fix Tool"
echo "=========================================="
echo ""

# Fix menu.sh in /usr/local/bin/menu (if exists)
if [ -f "$MENU_PATH" ]; then
    echo "🔧 Fixing $MENU_PATH..."
    
    # Fix line endings (CRLF to LF)
    echo "  - Converting CRLF to LF (if needed)..."
    sed -i 's/\r$//' "$MENU_PATH" 2>/dev/null || sed -i '' 's/\r$//' "$MENU_PATH" 2>/dev/null || tr -d '\r' < "$MENU_PATH" > "${MENU_PATH}.tmp" && mv "${MENU_PATH}.tmp" "$MENU_PATH"
    
    # Set executable permissions
    echo "  - Setting executable permissions..."
    chmod +x "$MENU_PATH"
    
    # Verify shebang
    if ! head -n 1 "$MENU_PATH" | grep -q "#!/bin/bash\|#!/usr/bin/env bash"; then
        echo "  ⚠️  Warning: Shebang not found, script may not run properly"
    fi
    
    echo "  ✅ $MENU_PATH fixed!"
else
    echo "  ℹ️  $MENU_PATH not found (script may not be installed yet)"
fi

# Fix local menu.sh (if exists in current directory)
if [ -f "$MENU_LOCAL" ]; then
    echo ""
    echo "🔧 Fixing local $MENU_LOCAL..."
    
    # Fix line endings (CRLF to LF)
    echo "  - Converting CRLF to LF (if needed)..."
    sed -i 's/\r$//' "$MENU_LOCAL" 2>/dev/null || sed -i '' 's/\r$//' "$MENU_LOCAL" 2>/dev/null || tr -d '\r' < "$MENU_LOCAL" > "${MENU_LOCAL}.tmp" && mv "${MENU_LOCAL}.tmp" "$MENU_LOCAL"
    
    # Set executable permissions
    echo "  - Setting executable permissions..."
    chmod +x "$MENU_LOCAL"
    
    # Verify shebang
    if ! head -n 1 "$MENU_LOCAL" | grep -q "#!/bin/bash\|#!/usr/bin/env bash"; then
        echo "  ⚠️  Warning: Shebang not found, script may not run properly"
    fi
    
    echo "  ✅ $MENU_LOCAL fixed!"
fi

# Fix install.sh (if exists)
if [ -f "install.sh" ]; then
    echo ""
    echo "🔧 Fixing install.sh..."
    
    # Fix line endings (CRLF to LF)
    sed -i 's/\r$//' "install.sh" 2>/dev/null || sed -i '' 's/\r$//' "install.sh" 2>/dev/null || tr -d '\r' < "install.sh" > "install.sh.tmp" && mv "install.sh.tmp" "install.sh"
    
    # Set executable permissions
    chmod +x "install.sh"
    
    echo "  ✅ install.sh fixed!"
fi

echo ""
echo "=========================================="
echo "✅ Fix complete!"
echo "=========================================="
echo ""
echo "Next steps:"
if [ -f "$MENU_PATH" ]; then
    echo "  - Try running: menu"
else
    echo "  - If menu is installed, try running: menu"
    echo "  - If not installed, run: ./install.sh"
fi
echo ""
