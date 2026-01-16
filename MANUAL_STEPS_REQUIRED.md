# 📋 Manual Steps Required

This document lists **ALL manual steps** you must perform yourself before or during script usage.

---

## 🔴 CRITICAL: Before Installation

### 1. **Root Access**
- ✅ **Script handles automatically** - Checks for root and prompts if needed
- ❌ **No manual action required**

### 2. **System Requirements**
- ✅ **Script handles automatically** - Installs dependencies (bc, jq, curl, wget, python3)
- ❌ **No manual action required** (unless installation fails, then install manually)

---

## 🔴 CRITICAL: DNSTT (DNS Tunnel) - BEFORE Installation

### 1. **DNS Provider Configuration (MUST DO BEFORE INSTALLATION)**

**⚠️ This is REQUIRED and MUST be done in your DNS provider BEFORE installing DNSTT:**

1. **Nameserver Domain Setup:**
   - Go to your DNS provider (Cloudflare, Namecheap, GoDaddy, etc.)
   - Create an **A record** for your nameserver domain
   - Example: `ns1.yourdomain.com` → Point to your **server's IP address**
   - Type: `A`
   - Name: `ns1` (or whatever subdomain you choose)
   - Value: Your VPS server's IP address (e.g., `123.456.789.012`)

2. **Tunnel Domain Setup:**
   - In the same DNS provider
   - Create an **A record** for your tunnel domain
   - Example: `tun.yourdomain.com` → Point to your **server's IP address**
   - Type: `A`
   - Name: `tun` (or whatever subdomain you choose)
   - Value: Your VPS server's IP address

3. **Wait for DNS Propagation:**
   - DNS changes can take 5 minutes to 48 hours
   - Verify DNS is working: `dig ns1.yourdomain.com` or `nslookup ns1.yourdomain.com`
   - Must resolve to your server's IP address before proceeding

**✅ After DNS is configured, then proceed with DNSTT installation in the script**

---

## 🔴 CRITICAL: DNSTT Client Configuration

### 1. **Client DNS Configuration (MUST DO MANUALLY)**

**❌ DO NOT USE:** `8.8.8.8` or any public DNS (Google, Cloudflare, etc.)

**✅ MUST USE:** Your nameserver domain (e.g., `ns1.yourdomain.com`) or its IP address

**Steps:**
1. Get the nameserver domain from DNSTT installation (displayed after installation)
2. On the client device, configure DNS to use:
   - Option 1: `ns1.yourdomain.com` (nameserver domain)
   - Option 2: Server's IP address directly (if nameserver domain points to it)

**Example:**
- ❌ Wrong: Client DNS = `8.8.8.8`
- ✅ Correct: Client DNS = `ns1.yourdomain.com` or `123.456.789.012`

### 2. **Client Public Key Configuration**
- ✅ **Script provides:** Public key is displayed after DNSTT installation
- ❌ **Manual action:** You must copy the public key and configure it in your DNSTT client application
- ❌ **Manual action:** You must configure the tunnel domain (e.g., `tun.yourdomain.com`) in your client

### 3. **Client V2Ray Configuration (If Forwarding to V2Ray)**
- ✅ **Script handles:** DNSTT forwards to port 8787
- ❌ **Manual action:** You must ensure V2Ray/XRay service is running on port 8787 (no TLS)
- ❌ **Manual action:** You must configure V2Ray clients with the correct protocol and settings

---

## 🟡 IMPORTANT: SSL Certificate (Let's Encrypt)

### 1. **Domain DNS Configuration (BEFORE SSL Certificate)**

**⚠️ This MUST be done in your DNS provider BEFORE requesting SSL certificate:**

1. **Domain A Record:**
   - Go to your DNS provider
   - Create an **A record** for your domain
   - Example: `vps.yourdomain.com` → Point to your **server's IP address**
   - Type: `A`
   - Name: `vps` (or `@` for root domain)
   - Value: Your VPS server's IP address

2. **Verify DNS:**
   - Wait for DNS propagation
   - Verify: `dig vps.yourdomain.com` or `nslookup vps.yourdomain.com`
   - Must resolve to your server's IP address

3. **Port 80 Must Be Open:**
   - Port 80 must be accessible from the internet (for Let's Encrypt validation)
   - ✅ **Script handles:** Nginx must be running on port 80

**✅ After DNS A record is configured, then proceed with SSL certificate request**

---

## 🟡 OPTIONAL: Configuration Customization

### 1. **Script Configuration (Lines 10-52 in menu.sh)**

**These can be customized but have defaults:**

- `REPO_NAME`, `REPO_OWNER`, `REPO_BRANCH` - Already configured, no change needed
- `DNS_PRIMARY`, `DNS_SECONDARY` - Used for server DNS, defaults are fine
- `DEFAULT_SSL_TUNNEL_PORT` - Default: 444
- `DEFAULT_WEB_PROXY_PORT` - Default: 8080
- `DEFAULT_BADVPN_PORT` - Default: 7300
- `DEFAULT_ZIVPN_PORT` - Default: 5667
- `DEFAULT_V2RAY_PORT` - Default: 8787
- `DEFAULT_DNSTT_MTU` - Default: 1800

**❌ No manual action required** (unless you want to customize ports)

---

## 🟡 OPTIONAL: Services That Need Manual Setup

### 1. **V2Ray/XRay Service (If Using DNSTT → V2Ray)**

**Before installing DNSTT with V2Ray forwarding:**

- ❌ **Manual action:** Install and configure V2Ray/XRay panel (X-UI) using option 12 in menu
- ❌ **Manual action:** Create V2Ray configuration on port 8787 (no TLS)
- ❌ **Manual action:** Ensure V2Ray is running and listening on port 8787

**✅ Script helps:** X-UI panel installation available in menu (option 12)

### 2. **Nginx Configuration Customization**

- ✅ **Script handles:** Basic Nginx configuration with self-signed certificate
- ❌ **Manual action:** If you need custom Nginx configuration, edit `/etc/nginx/sites-available/default` manually

---

## 🟢 AUTOMATED (No Manual Action Required)

### ✅ These are handled automatically by the script:

1. **Package Installation** - Automatically installs missing dependencies
2. **Service Management** - Creates and manages systemd services
3. **Port Management** - Automatically configures firewall (UFW/firewalld)
4. **Port Conflict Resolution** - Automatically detects and resolves port conflicts
5. **Key Generation** - Automatically generates DNSTT keys (and reuses existing)
6. **Directory Creation** - Automatically creates all required directories
7. **System DNS Configuration** - Automatically configures `/etc/resolv.conf` when needed
8. **Service Start/Stop** - Automatically starts and enables services

---

## 📝 Summary: What You MUST Do Manually

### **Before DNSTT Installation:**
1. ❌ **Configure DNS A records** in your DNS provider:
   - Nameserver domain (e.g., `ns1.yourdomain.com`) → Server IP
   - Tunnel domain (e.g., `tun.yourdomain.com`) → Server IP
   - Wait for DNS propagation

### **Before SSL Certificate:**
1. ❌ **Configure DNS A record** in your DNS provider:
   - Domain (e.g., `vps.yourdomain.com`) → Server IP
   - Wait for DNS propagation
   - Ensure port 80 is accessible

### **Client Configuration (After DNSTT Installation):**
1. ❌ **Configure client DNS** to use nameserver domain (NOT 8.8.8.8)
2. ❌ **Copy public key** from DNSTT installation output
3. ❌ **Configure DNSTT client** with:
   - Public key
   - Tunnel domain (e.g., `tun.yourdomain.com`)
   - Client DNS = nameserver domain or server IP

### **If Using V2Ray Forwarding:**
1. ❌ **Install and configure V2Ray/XRay** on port 8787 (no TLS) before DNSTT installation

### **Optional:**
1. ❌ Customize ports in configuration section (if needed)
2. ❌ Customize Nginx configuration (if needed)

---

## ✅ Everything Else is Automated!

The script handles all other setup automatically including:
- Installing dependencies
- Creating services
- Configuring firewall
- Managing ports
- Generating and preserving keys
- Creating directories
- Starting services