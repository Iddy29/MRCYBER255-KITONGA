# 🌐 DNS & VPN: How DNS Works with VPN Connections

## 📋 Overview

When a VPN connection is established, DNS (Domain Name System) plays a critical role in routing traffic correctly. This document explains how DNS forwarding works with VPN connections, especially in the context of this script's implementation.

---

## 🔄 How DNS Forwarding Works with VPN

### **1. Normal DNS Resolution (Without VPN)**

```
Client → DNS Server (8.8.8.8) → Domain Resolution → Client
```

- Client sends DNS query to public DNS (e.g., 8.8.8.8)
- Public DNS resolves domain name to IP address
- Client receives IP address and connects directly

**Problem:** Traffic goes directly to destination, bypassing VPN tunnel.

---

### **2. DNS Forwarding with VPN (Correct Setup)**

```
Client → VPN Server DNS → VPN Server Resolver → Internet
         (DNS Forwarding Enabled)
```

**Flow:**
1. **Client connects to VPN** (e.g., DNSTT, OpenVPN, WireGuard)
2. **Client DNS is configured** to use VPN server's DNS (not 8.8.8.8)
3. **VPN server receives DNS queries** from client
4. **VPN server forwards DNS queries** to public DNS (8.8.8.8 or 1.1.1.1)
5. **VPN server receives DNS response** and sends it back to client
6. **Client resolves domain** and traffic flows through VPN tunnel

**Result:** All DNS queries and subsequent traffic go through VPN tunnel.

---

## 🎯 DNS Forwarding Implementation in This Script

### **Auto-Configuration When VPN Connects:**

When the script detects a VPN connection, it automatically:

#### **1. Enables DNS Forwarding in systemd-resolved:**

```bash
# File: /etc/systemd/resolved.conf
DNSStubListener=no  # Allows external processes to bind to port 53
```

**Purpose:** Prevents systemd-resolved from blocking port 53, allowing VPN DNS services to bind to it.

---

#### **2. Configures DNSTT EDNS Proxy (if DNSTT is installed):**

```
Client DNS Query → Port 53 (EDNS Proxy) → Port 5300 (DNSTT Server) → SSH/V2Ray
```

**How it works:**
- **EDNS Proxy** listens on **port 53** (public DNS port)
- Receives DNS queries from clients
- Forwards queries to **DNSTT Server** on **port 5300** (internal)
- DNSTT Server tunnels traffic to SSH (port 22) or V2Ray (port 8787)
- All traffic appears as DNS traffic externally (512 bytes)
- Internally uses high-speed tunneling (1800 bytes)

---

#### **3. Updates /etc/resolv.conf:**

```bash
# File: /etc/resolv.conf
nameserver 127.0.0.1  # Use local DNS resolver
```

**Purpose:** Ensures the server itself uses local DNS forwarding instead of public DNS.

---

## 📡 DNS Flow with Different VPN Types

### **A. DNSTT (DNS Tunneling)**

```
┌─────────┐         ┌──────────────────┐         ┌──────────────┐
│ Client  │  DNS    │  VPN Server      │         │  Internet    │
│         │────────▶│  Port 53 (EDNS)  │────────▶│              │
│         │ Queries │  Port 5300 (DNSTT)│        │              │
│         │◀────────│  Tunnels to SSH  │◀────────│              │
└─────────┘         └──────────────────┘         └──────────────┘

1. Client configures DNS to: ns1.yourdomain.com (VPN server IP)
2. Client sends DNS query to VPN server (port 53)
3. EDNS Proxy receives query, patches EDNS size (512→1800)
4. DNSTT Server processes query and tunnels to SSH/V2Ray
5. All traffic flows through DNS tunnel (appears as DNS externally)
```

**Key Points:**
- Client **MUST** use VPN server's DNS (nameserver domain or server IP)
- Client **MUST NOT** use 8.8.8.8 or any public DNS
- All queries go through VPN tunnel
- High-speed internal tunneling (1800 bytes) vs. public view (512 bytes)

---

### **B. OpenVPN**

```
┌─────────┐         ┌──────────────────┐         ┌──────────────┐
│ Client  │  VPN    │  VPN Server      │         │  Internet    │
│         │────────▶│  OpenVPN Daemon  │────────▶│              │
│         │ Tunnel  │  DNS Forwarding  │         │              │
│         │◀────────│  Active          │◀────────│              │
└─────────┘         └──────────────────┘         └──────────────┘

1. Client connects to OpenVPN server
2. VPN server pushes DNS server configuration (e.g., 10.8.0.1)
3. Client's DNS queries go to VPN server's DNS resolver
4. VPN server forwards DNS queries to public DNS (8.8.8.8)
5. All traffic (including DNS) flows through VPN tunnel
```

**Key Points:**
- OpenVPN automatically configures client DNS via `push "dhcp-option DNS"`
- DNS forwarding is handled by OpenVPN's built-in resolver
- All DNS queries go through VPN tunnel automatically

---

### **C. WireGuard**

```
┌─────────┐         ┌──────────────────┐         ┌──────────────┐
│ Client  │  VPN    │  VPN Server      │         │  Internet    │
│         │────────▶│  WireGuard       │────────▶│              │
│         │ Tunnel  │  DNS Forwarding  │         │              │
│         │◀────────│  (dnsmasq/unbound)│◀────────│              │
└─────────┘         └──────────────────┘         └──────────────┘

1. Client connects to WireGuard server
2. Server config includes DNS server (e.g., 10.0.0.1)
3. Client's DNS queries go to WireGuard interface DNS
4. Server forwards DNS queries using dnsmasq or unbound
5. All traffic flows through WireGuard tunnel
```

**Key Points:**
- WireGuard config includes `DNS = 10.0.0.1` (server's WireGuard IP)
- DNS forwarding handled by dnsmasq or unbound on server
- All DNS queries tunneled through WireGuard

---

## ⚙️ Auto-Configuration Functions

### **`enable_dns_forwarding()`**

This function automatically:

1. **Checks systemd-resolved status:**
   ```bash
   if systemctl is-active --quiet systemd-resolved; then
       # Configure DNSStubListener=no
       # Restart systemd-resolved
   fi
   ```

2. **Starts DNSTT if installed but not running:**
   ```bash
   if [ -f "$DNSTT_SERVICE_FILE" ]; then
       systemctl start dnstt.service
       systemctl start dnstt-edns-proxy.service
   fi
   ```

3. **Configures /etc/resolv.conf:**
   ```bash
   # Ensure local DNS resolver is used
   nameserver 127.0.0.1
   ```

---

### **`detect_vpn_connection()`**

This function detects active VPN connections:

```bash
# Checks for:
- OpenVPN processes (pgrep openvpn)
- DNSTT services (systemctl is-active dnstt)
- WireGuard interfaces (wg show)
- TUN/TAP interfaces (ip link show)
```

**Returns:** VPN type and connection status

---

### **`setup_vpn_auto_config()`**

This is the main auto-configuration function:

```bash
1. Detect VPN connection
2. If VPN active:
   - Enable DNS forwarding
   - Start SSH service
   - Configure DNS resolver
3. Return success/failure
```

**Triggered automatically when:**
- DNSTT is installed and started
- HTTP Custom is installed and started
- Manual trigger from VPN Status Dashboard (Option 14)

---

## 🚨 Common DNS Issues & Solutions

### **Issue 1: Client Using Public DNS (8.8.8.8)**

**Problem:**
```
Client → 8.8.8.8 (Public DNS) → Direct Connection (Bypasses VPN)
```

**Solution:**
- Client **MUST** configure DNS to use VPN server's DNS
- For DNSTT: Use nameserver domain (e.g., ns1.yourdomain.com) or server IP
- For OpenVPN: OpenVPN automatically pushes DNS configuration
- For WireGuard: Include DNS in client config file

---

### **Issue 2: DNS Forwarding Not Enabled on Server**

**Problem:**
- VPN server doesn't forward DNS queries
- Client DNS queries fail or bypass VPN

**Solution:**
- Run VPN Status Dashboard (Option 14)
- Click "Run Auto-Configuration"
- Script automatically enables DNS forwarding

---

### **Issue 3: Port 53 Conflict**

**Problem:**
- systemd-resolved or another service is using port 53
- DNSTT EDNS Proxy cannot bind to port 53

**Solution:**
- Script automatically detects and stops conflicting services
- Configures systemd-resolved to not use port 53
- DNSTT EDNS Proxy can now bind to port 53

---

## 📊 DNS Forwarding Status Check

### **Check DNS Forwarding Status:**

From Main Menu → Option 14 (VPN Status & Auto-Config):

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🔐 VPN CONNECTION STATUS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🟢 VPN Status: CONNECTED
  📡 VPN Type: DNSTT

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🔌 SERVICE STATUS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🟢 SSH Service: ✅ ACTIVE (ssh.service)
  🟢 DNSTT: ✅ ACTIVE
  🟢 DNS Forwarding: ✅ ACTIVE
```

---

## 🔧 Manual DNS Configuration

### **For DNSTT Clients:**

1. **Configure Client DNS:**
   - Use nameserver domain: `ns1.yourdomain.com`
   - Or use server IP address directly
   - **DO NOT** use 8.8.8.8 or any public DNS

2. **Configure DNSTT Client:**
   - Public key: (from server's `/etc/mrcyber255-kitonga/dnstt/server.pub`)
   - Tunnel domain: `tun.yourdomain.com`
   - DNS: `ns1.yourdomain.com` or server IP

3. **Test DNS Forwarding:**
   ```bash
   # On client (using VPN server's DNS):
   nslookup google.com ns1.yourdomain.com
   # Should resolve and traffic flow through VPN
   ```

---

## ✅ Summary

**DNS Forwarding with VPN ensures:**

1. ✅ All DNS queries go through VPN tunnel
2. ✅ All subsequent traffic flows through VPN
3. ✅ No DNS leaks (queries don't bypass VPN)
4. ✅ Proper domain resolution through VPN
5. ✅ Automatic configuration when VPN connects

**Auto-Configuration ensures:**

1. ✅ DNS forwarding enabled automatically
2. ✅ SSH service starts automatically
3. ✅ Proper DNS resolver configuration
4. ✅ No manual configuration required

**Client Configuration:**

1. ✅ Use VPN server's DNS (not 8.8.8.8)
2. ✅ Follow protocol-specific DNS setup
3. ✅ Verify DNS forwarding is working
4. ✅ All traffic flows through VPN tunnel

---

## 🎯 Key Takeaways

- **DNS forwarding is CRITICAL** for proper VPN operation
- **Client DNS MUST use VPN server's DNS** (not public DNS)
- **Script automatically configures DNS forwarding** when VPN connects
- **All DNS queries and traffic flow through VPN tunnel** when configured correctly
- **VPN Status Dashboard (Option 14)** shows DNS forwarding status

---

**For more information, see:**
- `MANUAL_STEPS_REQUIRED.md` - Client DNS configuration steps
- `menu.sh` - Implementation details (functions: `enable_dns_forwarding`, `setup_vpn_auto_config`, `detect_vpn_connection`)
