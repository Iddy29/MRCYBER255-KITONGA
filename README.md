# 🔧 MRCYBER255-KITONGA Manager v3.4.0 (ActiveLimiter)

**MRCYBER255-KITONGA Manager** — A powerful and unified **proxy/VPN management script** for Linux servers.
It supports multiple tunneling protocols, SSH user management with connection limits, SSL automation, and an Nginx gateway that handles all traffic efficiently.

---

## ⚡️ Quick Installation

Run the following command to install the latest version:

```bash
# Repository: MRCYBER255-KITONGA
REPO_BASE_URL="https://raw.githubusercontent.com/Iddy29/MRCYBER255-KITONGA/refs/heads/main"
curl -L -o install.sh "${REPO_BASE_URL}/install.sh" && chmod +x install.sh && sudo ./install.sh && rm install.sh
```

After installation, simply type `menu` to start the management interface.

> ⚠️ **Important:**
> Before installation:
>
> * **Backup** your user data
> * **Uninstall** any old version of MRCYBER255-KITONGA Manager
> * Then perform a **clean install** using the command above

---

## 🚀 Features

### 👤 SSH User Management System

Complete user lifecycle management with automatic enforcement:

* **Create Users** — Add SSH users with expiry dates and connection limits
* **Edit Users** — Modify passwords, expiry dates, and connection limits
* **Lock/Unlock** — Manually lock or unlock user accounts
* **Delete Users** — Remove users and clean up their data
* **List Users** — View all managed users with status (Active/Locked/Expired)
* **Renew Accounts** — Extend user expiry dates
* **Auto-Limiter Service** — Automatically enforces:
  - Connection limits (locks users exceeding limit for 120 seconds)
  - Expiry dates (auto-locks expired accounts)
  - Session termination when limits are exceeded

### 🔰 Multi-Protocol Support

Easily manage and run a wide range of VPN and proxy protocols:

* **BadVPN (UDPGW)** — UDP gateway on port 7300
  - Supports up to 1000 clients
  - 8 connections per client
  - Compiled from source

* **UDP Custom** — Custom UDP-based VPN tunneling
  - Excludes ports 53 and 5300 (for DNS/DNSTT)
  - Supports multiple UDP ports

* **SSL Tunnel (HAProxy)** — SSL/TLS tunnel for SSH
  - Configurable port (default: 444)
  - Secure encrypted tunnel
  - Works with any SSH client

* **DNSTT (SlowDNS)** — DNS-based tunneling with EDNS proxy
  - **High-Speed Architecture:**
    - EDNS Proxy on port 53 (public) - shows 512 bytes externally
    - DNSTT Server on port 5300 (internal) - uses 1800 bytes internally
    - MTU: 1800 (recommended for high speed)
  - Forward to SSH (port 22) or V2Ray (port 8787)
  - Automatic key generation
  - Custom domain support (nameserver + tunnel domain required)

* **WebSocket Proxy** — WebSocket and SOCKS proxy
  - Multiple version support
  - Configurable ports (default: 8080)
  - Returns fake HTTP responses
  - Integrates with Nginx

* **ZiVPN** — UDP VPN with port sharing
  - Port 5667
  - Advanced port sharing capabilities

* **Nginx Gateway** — Smart HTTP/HTTPS entry point
  - Handles traffic on ports 80 and 443
  - Routes to V2Ray/XRay, SSH WS, or Falcon Proxy
  - SSL/TLS termination
  - Automatic SSL certificate generation (Certbot)
  - Self-signed certificate fallback

* **X-UI Panel** — V2Ray/XRay management panel
  - Install latest or specific version
  - Full V2Ray/XRay protocol support

* **DT Proxy Management** — DT Tunnel Mod + Proxy
  - Full installation and management
  - External management panel integration

### 🧩 System Utilities

* **Backup & Restore** — Save or restore SSH user data
  - Exports to tar.gz archive
  - Includes all user data and configurations

* **SSH Banner Management** — Customize login banner
  - Set custom banner text
  - View current banner
  - Remove banner

* **Cleanup Expired Users** — Automatically lock expired accounts

* **Firewall Management** — Automatic port configuration
  - UFW support
  - Firewalld support
  - Port conflict detection and resolution

---

## 📋 Menu Structure

### Main Menu Options

**👤 User Management (1-7):**
- `1` - Create New User
- `2` - Delete User
- `3` - Edit User Details
- `4` - Lock User Account
- `5` - Unlock User Account
- `6` - List All Managed Users
- `7` - Renew User Account

**⚙️ System Utilities (8-13):**
- `8` - Install Protocols & Panels
- `9` - Backup User Data
- `10` - Restore User Data
- `11` - SSH Banner Management
- `12` - Cleanup Expired Users
- `13` - DT Proxy Management

**🔥 Danger Zone:**
- `15` - Uninstall Script
- `0` - Exit

### Protocol & Panel Menu (Option 8)

**Tunneling Protocols:**
- `1` - Install badvpn (UDP 7300)
- `2` - Uninstall badvpn
- `3` - Install udp-custom (Excl. 53,5300)
- `4` - Uninstall udp-custom
- `5` - Install SSL Tunnel (Port 444)
- `6` - Uninstall SSL Tunnel
- `7` - Install/View DNSTT (Port 53/5300)
- `8` - Uninstall DNSTT
- `9` - Install WebSocket Proxy (Select Version)
- `10` - Uninstall WebSocket Proxy
- `11` - Install/Manage Nginx Proxy (80/443)
- `16` - Install ZiVPN (UDP 5667 + Port Share)
- `17` - Uninstall ZiVPN

**Management Panels:**
- `12` - Install X-UI Panel
- `13` - Uninstall X-UI Panel

---

## 🧱 System Requirements

* **OS:** Ubuntu / Debian-based Linux (Ubuntu 20.04+ recommended)
* **Access:** Root privileges (required)
* **Ports:** 
  - **80, 443** - Nginx (HTTP/HTTPS)
  - **8080** - WebSocket Proxy (default)
  - **53, 5300** - DNSTT (UDP)
  - **7300** - BadVPN (UDP)
  - **5667** - ZiVPN (UDP)
  - **444** - SSL Tunnel (default, configurable)
* **Dependencies:** Automatically installed (bc, jq, curl, wget, python3)

---

## 📸 DNSTT Architecture (High-Speed)

```
Client DNS Query
    ↓
Port 53 (Public)
    ↓
EDNS Proxy (Python)
  - External EDNS: 512 bytes
  - Internal EDNS: 1800 bytes
    ↓
Port 5300 (Internal)
    ↓
DNSTT Server
  - MTU: 1800
  - Forwards to: SSH (22) or V2Ray (8787)
```

**Key Features:**
- EDNS proxy shows 512 bytes externally (compatibility)
- Uses 1800 bytes internally (high speed)
- Automatic key generation
- Custom domain support (no auto-generation)

---

## 📸 Connection Flow Diagram

```
Client → Nginx (80/443)
          ├──> V2Ray/XRay backend  
          ├──> SSH WebSocket
          └──> WebSocket Proxy (WebSocket → SSH)  

Client → DNSTT (Port 53)
          ↓
          EDNS Proxy
          ↓
          DNSTT Server (Port 5300)
          ↓
          SSH (22) or V2Ray (8787)
```

---

## 🔐 DNSTT Installation Requirements

When installing DNSTT, you'll need to provide:

1. **Forward Target:**
   - Option 1: SSH (port 22)
   - Option 2: V2Ray (port 8787)

2. **Domain Configuration:**
   - **Nameserver Domain:** e.g., `ns1.yourdomain.com`
   - **Tunnel Domain:** e.g., `tun.yourdomain.com`
   - ⚠️ **Important:** These domains must be configured in your DNS provider before installation

3. **MTU Value:**
   - Default: 1800 (recommended for high speed)
   - Options: 512, 1200, 1800, or custom

4. **Public Key:**
   - Automatically generated during installation
   - Displayed after successful installation
   - Required for client configuration

---

## 🛠️ User Input Examples

### Creating a User
```
Username: john123
Password: MySecurePass123!
Duration: 30 days
Connection Limit: 2
```

### Installing DNSTT
```
Forward Target: 2 (V2Ray)
Nameserver Domain: ns1.example.com
Tunnel Domain: tun.example.com
MTU: 1800 (or press Enter for default)
```

### Installing SSL Certificate
```
Domain: vps.example.com
Email: admin@example.com
```

---

## 📁 Configuration Files

| File | Purpose |
|------|---------|
| `/etc/mrcyber255-kitonga/users.db` | User database (format: `username:password:expiry:limit`) |
| `/etc/mrcyber255-kitonga/dnstt_info.conf` | DNSTT configuration |
| `/etc/mrcyber255-kitonga/dnstt/server.key` | DNSTT private key (server only) |
| `/etc/mrcyber255-kitonga/dnstt/server.pub` | DNSTT public key (for clients) |
| `/etc/mrcyber255-kitonga/webproxy_config.conf` | WebSocket Proxy settings |
| `/etc/systemd/system/*.service` | Systemd service files |
| `/usr/local/bin/dnstt-edns-proxy.py` | EDNS proxy script |

> 💡 **Want to customize default settings?** Check out [CONFIGURATION.md](CONFIGURATION.md) for manual configuration options including DNS servers, default ports, timeouts, and more!

---

## 🔄 Active Limiter Service

The script automatically installs and runs a background service that:

- **Checks every 3 seconds** for:
  - Expired user accounts → Auto-locks them
  - Users exceeding connection limits → Locks for 120 seconds
  - Active sessions → Terminates when limits exceeded

- **Service:** `mrcyber255-kitonga-limiter.service`
- **Location:** `/usr/local/bin/mrcyber255-kitonga-limiter.sh`

---

## 🦅 About

MRCYBER255-KITONGA Manager v3.4.0 (ActiveLimiter) simplifies the deployment and management of advanced tunneling setups.
With one script, you can orchestrate multiple VPN and proxy technologies — **securely**, **efficiently**, and **flexibly**.

**Key Improvements:**
- Enhanced DNSTT with EDNS proxy for high-speed performance
- Automatic connection limit enforcement
- Comprehensive error handling
- Improved port conflict detection
- Better service management

---

## 🌐 Connect with Us

📣 **Telegram Channel

---

🔧 *MRCYBER255-KITONGA Manager — Simple. Powerful. Unified.*
