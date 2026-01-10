# 🔧 Manual Configuration Guide

This document explains how to manually configure settings in the FirewallFalcon Manager script.

## 📍 Location of Configuration

All manual configuration settings are located at the **top of `menu.sh`** file, right after the shebang (`#!/bin/bash`), in a clearly marked section:

```bash
# =============================================================================
# 🔧 MANUAL CONFIGURATION SECTION
# =============================================================================
```

## ⚙️ Available Configuration Options

### Repository Configuration

```bash
REPO_NAME="MRCYBER255-KITONGA"       # Repository name
REPO_OWNER="Iddy29"                   # GitHub username/organization
REPO_BRANCH="refs/heads/main"         # Branch name
REPO_BASE_URL="..."                   # Auto-constructed from above
```

**When to change:** If you fork this repository or want to use a different source for updates.

---

### DNS Configuration

```bash
DNS_PRIMARY="8.8.8.8"      # Primary DNS server (Google DNS)
DNS_SECONDARY="1.1.1.1"    # Secondary DNS server (Cloudflare DNS)
```

**When to change:**
- If you prefer different DNS servers (e.g., OpenDNS: `208.67.222.222`, `208.67.220.220`)
- If you have a custom DNS server on your network
- If your ISP requires specific DNS servers

**Used for:** DNSTT installation and system DNS configuration when disabling systemd-resolved.

---

### Default Ports

```bash
DEFAULT_SSL_TUNNEL_PORT="444"       # SSL Tunnel default port
DEFAULT_FALCON_PROXY_PORT="8080"    # Falcon Proxy default port
DEFAULT_BADVPN_PORT="7300"          # BadVPN UDP port
DEFAULT_ZIVPN_PORT="5667"           # ZiVPN UDP port
DEFAULT_DNSTT_PUBLIC_PORT="53"      # DNSTT public port (EDNS proxy)
DEFAULT_DNSTT_INTERNAL_PORT="5300"  # DNSTT internal port (server)
DEFAULT_V2RAY_PORT="8787"           # V2Ray/XRay port for DNSTT forwarding
```

**When to change:**
- If default ports conflict with existing services on your server
- If you have firewall rules restricting certain ports
- If you prefer different port numbers for security reasons

**Note:** These are default values. You can still specify different ports during installation if needed.

---

### DNSTT Settings

```bash
DEFAULT_DNSTT_MTU="1800"  # Maximum Transmission Unit
```

**Options:**
- `512` - Lower speed, maximum compatibility
- `1200` - Medium speed
- `1800` - **Recommended** - High speed (default)

**When to change:**
- If you experience connection issues, try lowering to `512` or `1200`
- If you want maximum speed and your network supports it, keep `1800`

---

### Backup Settings

```bash
DEFAULT_BACKUP_PATH="/root/firewallfalcon_users.tar.gz"
```

**When to change:**
- If you want backups stored in a different location
- If `/root` is not accessible, use a different path
- Example: `/home/backups/firewallfalcon_users.tar.gz`

---

### Timeout Settings

```bash
CERTBOT_TIMEOUT="120"      # Certbot SSL certificate request timeout (seconds)
DOWNLOAD_TIMEOUT="60"      # File download timeout (seconds)
```

**When to change:**
- If you have slow internet, increase `DOWNLOAD_TIMEOUT`
- If SSL certificate requests take longer, increase `CERTBOT_TIMEOUT`

---

### Connection Limiter Settings

```bash
LIMITER_CHECK_INTERVAL="3"    # Check interval in seconds
LIMITER_LOCK_DURATION="120"   # Lock duration when limit exceeded (seconds)
```

**When to change:**
- **Check Interval:** Lower values = more frequent checks (more CPU usage)
  - Recommended: `3` seconds (default)
  - Minimum: `1` second
  - Maximum: `10` seconds
  
- **Lock Duration:** How long a user is locked when exceeding connection limit
  - Recommended: `120` seconds (2 minutes) - default
  - Can be set to any value in seconds

---

## 📝 How to Edit Configuration

1. **Open `menu.sh` in a text editor:**
   ```bash
   nano menu.sh
   # or
   vi menu.sh
   ```

2. **Navigate to the top of the file** (after `#!/bin/bash`)

3. **Find the "MANUAL CONFIGURATION SECTION"**

4. **Edit the values** you want to change

5. **Save the file** and the changes will take effect on next run

---

## ⚠️ Important Notes

1. **Don't change variable names** - only change their values
2. **Keep quotes around values** - strings should be in quotes: `"value"`
3. **Numbers don't need quotes** - but quotes won't hurt: `"7300"` or `7300` both work
4. **Backup first** - make a backup before making changes
5. **Test after changes** - verify everything works after modifying configuration

---

## 🔄 Applying Changes

After modifying configuration:

1. **If script is already installed:**
   - Changes will take effect on next run
   - Some settings (like ports) require re-installing the service

2. **To apply repository changes:**
   ```bash
   # Re-download menu.sh from repository
   curl -L -o menu.sh "${REPO_BASE_URL}/menu.sh"
   ```

3. **To apply limiter settings:**
   ```bash
   # Restart the limiter service
   systemctl restart firewallfalcon-limiter.service
   ```

---

## 🧪 Testing Your Configuration

After making changes, test by:

1. **Running the script:**
   ```bash
   bash menu.sh
   ```

2. **Checking if variables are read correctly:**
   ```bash
   # Source the config section (in a test environment)
   grep -A 50 "MANUAL CONFIGURATION" menu.sh | head -30
   ```

3. **Installing a service** with default values to verify ports work

---

## 📚 Examples

### Example 1: Change DNS Servers

```bash
# Before
DNS_PRIMARY="8.8.8.8"
DNS_SECONDARY="1.1.1.1"

# After (using OpenDNS)
DNS_PRIMARY="208.67.222.222"
DNS_SECONDARY="208.67.220.220"
```

### Example 2: Change Default Ports

```bash
# Before
DEFAULT_SSL_TUNNEL_PORT="444"
DEFAULT_FALCON_PROXY_PORT="8080"

# After
DEFAULT_SSL_TUNNEL_PORT="8443"
DEFAULT_FALCON_PROXY_PORT="9090"
```

### Example 3: Adjust Limiter Settings

```bash
# More frequent checks (faster response, more CPU)
LIMITER_CHECK_INTERVAL="1"

# Longer lock duration (5 minutes)
LIMITER_LOCK_DURATION="300"
```

---

## ❓ Common Questions

**Q: Will changes break existing installations?**  
A: Changing ports will require re-installing those services. Other changes take effect immediately.

**Q: Can I use variables in the configuration?**  
A: No, use actual values. Variables are expanded at runtime.

**Q: Do I need to restart services after changing configuration?**  
A: It depends on the setting. Port changes require re-installation. DNS and timeout changes take effect immediately.

**Q: Can I have different configurations per installation?**  
A: Yes! Edit `menu.sh` on each server independently before first run.

---

## 🔗 Related Files

- `menu.sh` - Main script with configuration section
- `install.sh` - Installation script (also has repository configuration)
- `/etc/firewallfalcon/` - Runtime configuration directory (auto-created)

---

*Last updated: Configuration section added for easier customization*