# ARP and Neighbor Discovery

## 1. Overview

ARP (Address Resolution Protocol, RFC 826) maps an IPv4 address to a MAC address on the local segment. IPv6 uses NDP (Neighbor Discovery Protocol, RFC 4861), which performs the same function with ICMPv6 messages. Both protocols are unauthenticated by design: any host on the segment can claim any IP-to-MAC mapping. That property is the root of ARP spoofing, ARP poisoning, and neighbor cache attacks.

This file covers the protocol mechanics, the offensive techniques that abuse them, and the defensive controls that detect and prevent abuse.

## 2. Reconnaissance / Enumeration

### Passive

- `tcpdump -i eth0 -nn arp` - watch ARP requests and replies on the segment.
- `arpwatch` - daemon that logs IP/MAC binding changes and sends mail on changes.
- Look for gratuitous ARP (an ARP reply with no preceding request) - a classic sign of poisoning.

### Active

- `arp-scan --localnet` - list all hosts on the local segment by MAC vendor.
- `nmap -sn 10.10.10.0/24` - host discovery; combined with `ip neigh` shows the ARP cache.
- `ip neigh show` / `arp -an` - current ARP cache on the local host.

## 3. Common Attack Vectors

### ARP spoofing (ARP poisoning)

The attacker sends forged ARP replies to the victim, telling it that the gateway's IP is at the attacker's MAC. The victim's ARP cache is overwritten, and all traffic to the gateway flows through the attacker.

### Gratuitous ARP abuse

A gratuitous ARP reply updates every host's cache without a request. Sending it repeatedly keeps the poisoned entry fresh.

### ARP cache exhaustion

Flooding the segment with ARP replies from random MACs can fill switch CAM tables and ARP caches, causing a denial of service.

### IPv6 NDP spoofing

The IPv6 equivalent: forged Neighbor Advertisements (NA) or Router Advertisements (RA) redirect traffic. RA spoofing can also change the victim's default gateway.

## 4. Exploitation Recipes

### ARP spoof with arpspoof (dsniff)

```bash
# Enable IP forwarding so traffic still reaches the gateway
sudo sysctl -w net.ipv4.ip_forward=1

# Poison victim -> attacker, claiming to be the gateway
sudo arpspoof -i eth0 -t 10.10.10.50 10.10.10.1

# In a second terminal, poison gateway -> victim, claiming to be the victim
sudo arpspoof -i eth0 -t 10.10.10.1 10.10.10.50
```

After both directions are poisoned, the attacker sits in the middle. Use `tcpdump -i eth0 -nn -A` to inspect traffic, or a tool like `ettercap` for automated MITM.

### ARP spoof with bettercap

```bash
sudo bettercap -iface eth0
# inside bettercap:
# net.probe on
# set arp.spoof.targets 10.10.10.50
# arp.spoof on
# net.sniff on
```

bettercap is the modern replacement for ettercap and combines ARP spoofing, sniffing, and HTTP manipulation in one console.

### IPv6 NDP spoof with parasite6 (THC-IPv6)

```bash
sudo parasite6 eth0
```

parasite6 answers all Neighbor Solicitations with the attacker's MAC, becoming the man in the middle for IPv6 traffic.

## 5. Post-Exploitation

Once positioned as the MITM, the attacker can:

- Capture plaintext credentials (FTP, Telnet, HTTP Basic, SMTP, POP3).
- Relay NTLM authentication to SMB or LDAP (see the Active Directory lateral movement file).
- Downgrade HTTPS via SSL stripping (see the HTTP and TLS file).
- Inject content into HTTP responses (bettercap `http.proxy` module).

## 6. Preventive Controls

- **Dynamic ARP Inspection (DAI)** on managed switches: validates ARP packets against the DHCP snooping binding table. Enabled per VLAN with `ip arp inspection vlan 10`.
- **DHCP snooping**: prerequisite for DAI; builds the trusted IP/MAC binding table.
- **Port security**: limit the number of MAC addresses per port.
- **Static ARP entries** for critical hosts (gateway, jump server) on sensitive endpoints - impractical at scale, but useful for isolated segments.
- **IPv6 RA Guard** and **NDP inspection** on switches that support it.
- **Network segmentation**: limit the broadcast domain so a single poisoned segment cannot affect the whole network.

## 7. Detection Controls

- **arpwatch** on critical segments: alerts on IP/MAC binding changes.
- **Zeek** (`arp` and `icmp` analyzers) can log unsolicited ARP replies and duplicate IP usage.
- **Switch DAI logs**: dropped ARP packets are logged with source port and reason.
- **SIEM correlation**: two different MACs claiming the same IP within a short window.
- **NetFlow / sFlow**: a sudden change in the next-hop MAC for a known IP is a strong signal.

## 8. Verification

- On the switch: `show ip arp inspection statistics` and `show ip dhcp snooping binding` confirm the binding table is populated.
- On the endpoint: `ip neigh show` should show the gateway's real MAC (compare with the switch's ARP table).
- Test DAI: send a forged ARP reply from a test host with `arpspoof`; the switch should drop it and log the event.
- Test RA Guard: send a forged Router Advertisement; the switch should drop it on untrusted ports.

## 9. Case Studies

- **2018 Amazon Go / Starbucks Wi-Fi incident (public reporting)**: captive portal abuse on public Wi-Fi relied on ARP spoofing to redirect users to a fake portal. The lesson: public Wi-Fi is a shared segment; assume ARP is hostile.
- **Enterprise LAN pivoting in red team engagements**: ARP spoofing is routinely the first step after gaining a foothold on a user VLAN, enabling NTLM relay to file servers.

## 10. Legal and Ethical Notes

ARP spoofing on a network you do not own or have explicit written authorization to test is illegal in most jurisdictions (Computer Fraud and Abuse Act in the US, Computer Misuse Act in the UK, similar laws elsewhere). In a penetration test, ARP spoofing must be listed in the scope and rules of engagement. On shared infrastructure (public Wi-Fi, hotel networks, conferences), even passive sniffing may violate terms of service.

## 11. References

- RFC 826 (ARP) - https://www.rfc-editor.org/rfc/rfc826
- RFC 4861 (Neighbor Discovery for IPv6) - https://www.rfc-editor.org/rfc/rfc4861
- RFC 5227 (IPv4 Address Conflict Detection) - https://www.rfc-editor.org/rfc/rfc5227
- arpspoof (dsniff) - https://linux.die.net/man/8/arpspoof
- bettercap documentation - https://www.bettercap.org/usage/
- Cisco DAI configuration guide - https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-6/configuration_guide/sec/b_176_sec_9300_cg/configuring_dynamic_arp_inspection.html
- arpwatch man page - https://linux.die.net/man/8/arpwatch
- Zeek ARP analyzer - https://docs.zeek.org/en/master/scripts/base/protocols/arp/main.zeek.html

## Certification Alignment

- CompTIA Network+ (N10-009): Objective 1.4 (network topologies), Objective 3.2 (network attacks), Objective 5.3 (troubleshooting)
- Cisco CCNA (200-301): 4.1 (Layer 2 security), 5.5 (security concepts)
