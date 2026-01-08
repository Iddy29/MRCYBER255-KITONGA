# 📡 How to View and Test DNSTT Configuration

## Method 1: View Through Menu (Easiest)

```bash
# Run the menu
menu

# Navigate to:
# Main Menu → Option 8 (Install Protocols & Panels)
# Then select: Option 7 (Install/View DNSTT)

# If DNSTT is already installed, it will automatically show:
# - Tunnel Domain
# - Public Key
# - Forwarding Target
# - MTU Value
# - NS Record
# - Server/Public Ports
# - EDNS Sizes
```

---

## Method 2: View Configuration File Directly

```bash
# View the configuration file
cat /etc/firewallfalcon/dnstt_info.conf

# Or with formatting
cat /etc/firewallfalcon/dnstt_info.conf | grep -E "TUNNEL_DOMAIN|PUBLIC_KEY|FORWARD_DESC|MTU_VALUE|NS_DOMAIN"
```

**Example output:**
```
TUNNEL_DOMAIN="tun.example.com"
NS_DOMAIN="ns1.example.com"
PUBLIC_KEY="dnstt:xxxxx:xxxxxxxxxxxxxxxxxxxxxxxx..."
FORWARD_DESC="V2Ray (port 8787)"
MTU_VALUE="1800"
```

---

## Method 3: View Public Key File

```bash
# View the public key (for client configuration)
cat /etc/firewallfalcon/dnstt/server.pub
```

---

## Method 4: Check Service Status

```bash
# Check if DNSTT server is running
systemctl status dnstt.service

# Check if EDNS proxy is running
systemctl status dnstt-edns-proxy.service

# Check both at once
systemctl is-active dnstt.service && systemctl is-active dnstt-edns-proxy.service && echo "Both services are active" || echo "One or both services are inactive"
```

---

## Method 5: View Service Logs

```bash
# View DNSTT server logs
journalctl -u dnstt.service -n 50 --no-pager

# View EDNS proxy logs
journalctl -u dnstt-edns-proxy.service -n 50 --no-pager

# Follow logs in real-time
journalctl -u dnstt.service -f
journalctl -u dnstt-edns-proxy.service -f
```

---

## Method 6: Check Ports

```bash
# Check if port 53 (EDNS proxy) is listening
ss -lunp | grep :53

# Check if port 5300 (DNSTT server) is listening
ss -lunp | grep :5300

# Check what's listening on both ports
netstat -tulpn | grep -E ':53|:5300'
```

---

## 🧪 Testing if DNSTT is Working

### Test 1: Check Services are Running

```bash
# Both services should be active
systemctl is-active dnstt.service && echo "✅ DNSTT server: ACTIVE" || echo "❌ DNSTT server: INACTIVE"
systemctl is-active dnstt-edns-proxy.service && echo "✅ EDNS proxy: ACTIVE" || echo "❌ EDNS proxy: INACTIVE"
```

### Test 2: Test DNS Query (from VPS itself)

```bash
# Test DNS query to your tunnel domain
dig @127.0.0.1 tun.yourdomain.com

# Or with nslookup
nslookup tun.yourdomain.com 127.0.0.1

# Test with your actual tunnel domain (replace with your domain)
# Example: dig @127.0.0.1 tun.example.com
```

### Test 3: Test from External Client

From a client machine (not the VPS):

```bash
# Test DNS resolution
nslookup tun.yourdomain.com

# Or with dig
dig tun.yourdomain.com

# Should return your server's IP address
```

### Test 4: Check Process is Running

```bash
# Check if dnstt-server process is running
ps aux | grep dnstt-server

# Check if EDNS proxy (Python) is running
ps aux | grep dnstt-edns-proxy

# Check process listening on ports
lsof -i :53 -i :5300
```

### Test 5: Test DNS Forwarding

```bash
# Test if DNS queries are being forwarded correctly
# This should show DNS activity
tcpdump -i any -n port 53

# In another terminal, make a DNS query
dig @127.0.0.1 tun.yourdomain.com
```

### Test 6: Verify Configuration

```bash
# Check configuration file exists and has content
[ -f /etc/firewallfalcon/dnstt_info.conf ] && echo "✅ Config file exists" || echo "❌ Config file missing"

# Check public key file exists
[ -f /etc/firewallfalcon/dnstt/server.pub ] && echo "✅ Public key exists" || echo "❌ Public key missing"

# Check private key file exists (should exist)
[ -f /etc/firewallfalcon/dnstt/server.key ] && echo "✅ Private key exists" || echo "❌ Private key missing"
```

---

## 🔍 Quick Status Check Command

Create this one-liner to check everything:

```bash
echo "=== DNSTT Status Check ===" && \
echo "Services:" && \
systemctl is-active dnstt.service >/dev/null && echo "  ✅ DNSTT Server: ACTIVE" || echo "  ❌ DNSTT Server: INACTIVE" && \
systemctl is-active dnstt-edns-proxy.service >/dev/null && echo "  ✅ EDNS Proxy: ACTIVE" || echo "  ❌ EDNS Proxy: INACTIVE" && \
echo "" && \
echo "Ports:" && \
ss -lunp | grep -q :53 && echo "  ✅ Port 53: LISTENING" || echo "  ❌ Port 53: NOT LISTENING" && \
ss -lunp | grep -q :5300 && echo "  ✅ Port 5300: LISTENING" || echo "  ❌ Port 5300: NOT LISTENING" && \
echo "" && \
echo "Configuration:" && \
[ -f /etc/firewallfalcon/dnstt_info.conf ] && echo "  ✅ Config file: EXISTS" || echo "  ❌ Config file: MISSING" && \
[ -f /etc/firewallfalcon/dnstt/server.pub ] && echo "  ✅ Public key: EXISTS" || echo "  ❌ Public key: MISSING" && \
echo "" && \
echo "Configuration Details:" && \
[ -f /etc/firewallfalcon/dnstt_info.conf ] && source /etc/firewallfalcon/dnstt_info.conf && \
echo "  Tunnel Domain: ${TUNNEL_DOMAIN:-Not set}" && \
echo "  Forward To: ${FORWARD_DESC:-Not set}" && \
echo "  MTU: ${MTU_VALUE:-Not set}"
```

---

## 📋 What You'll See in Configuration

When you view DNSTT details, you'll see:

```
=====================================================
            📡 DNSTT Connection Details             
=====================================================

Your connection details:
  - Tunnel Domain: tun.example.com
  - Public Key:    dnstt:xxxxx:xxxxxxxxxxxxxxxxxxxxxxxx...
  - Forwarding To: V2Ray (port 8787)
  - MTU Value:     1800
  - NS Record:     ns1.example.com
  - Server Port:   5300 (internal)
  - Public Port:   53 (EDNS proxy)
  - EDNS Sizes:    External: 512, Internal: 1800 (high speed)
```

---

## 🛠️ Troubleshooting

### If services are not running:

```bash
# Restart DNSTT server
systemctl restart dnstt.service

# Restart EDNS proxy
systemctl restart dnstt-edns-proxy.service

# Check logs for errors
journalctl -u dnstt.service -n 20
journalctl -u dnstt-edns-proxy.service -n 20
```

### If port 53 is not listening:

```bash
# Check if something else is using port 53
ss -lunp | grep :53

# Check if systemd-resolved is interfering
systemctl status systemd-resolved

# If needed, stop it
systemctl stop systemd-resolved
systemctl disable systemd-resolved
```

### If DNS queries fail:

1. **Verify DNS records are set correctly:**
   ```bash
   # Check if your domain points to your server IP
   dig ns1.yourdomain.com
   dig tun.yourdomain.com
   ```

2. **Verify firewall allows port 53:**
   ```bash
   # Check UFW
   ufw status | grep 53
   
   # Check firewalld
   firewall-cmd --list-ports | grep 53
   ```

3. **Test locally first:**
   ```bash
   # Test DNS query to localhost
   dig @127.0.0.1 tun.yourdomain.com
   ```

---

## 📝 Quick Reference

| Command | Purpose |
|---------|---------|
| `menu` → `8` → `7` | View DNSTT details in menu |
| `cat /etc/firewallfalcon/dnstt_info.conf` | View config file |
| `systemctl status dnstt.service` | Check DNSTT server status |
| `systemctl status dnstt-edns-proxy.service` | Check EDNS proxy status |
| `journalctl -u dnstt.service -f` | Follow DNSTT logs |
| `ss -lunp \| grep :53` | Check if port 53 is listening |
| `dig @127.0.0.1 tun.yourdomain.com` | Test DNS query locally |

---

## ✅ Success Indicators

Your DNSTT is working correctly if:

1. ✅ Both services show as "active"
2. ✅ Ports 53 and 5300 are listening
3. ✅ Configuration file exists with all details
4. ✅ Public key file exists
5. ✅ DNS queries to your tunnel domain resolve
6. ✅ No errors in service logs
