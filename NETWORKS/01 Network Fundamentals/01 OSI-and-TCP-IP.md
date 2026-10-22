# OSI and TCP-IP

> Track: Offensive / Defensive | Level: Foundation | Certs: Network+, CCNA

## 1. Overview

The OSI model and the TCP/IP model are two ways of describing the
same thing: how data moves from an application on one host to an
application on another host across a network. OSI is a seven-layer
reference model used for teaching and troubleshooting. TCP/IP is
the four-layer model that the real Internet actually implements.

Understanding both is non-negotiable for a network engineer or a
penetration tester. Every attack and every defense lives at a
specific layer, and naming the layer is the fastest way to reason
about what is happening:

- A MAC flood attack targets layer 2.
- An ARP spoof targets layer 2-3 boundary.
- An IP fragmentation attack targets layer 3.
- A TCP SYN flood targets layer 4.
- A TLS downgrade targets layer 5-6.
- A request smuggling attack targets layer 7.

The purpose of this file is to build a mental map of the models,
the encapsulation process, the protocol data units (PDUs) at each
layer, and the vocabulary you need for every other networking
topic in this category.

## 2. Reconnaissance / Enumeration

You cannot see the OSI model directly, but you can observe its
artifacts. Each layer leaves fingerprints that a tester or an
analyst can collect.

**Layer 1 (Physical):** signal strength, cable type, link speed
(`ethtool eth0`), duplex mismatch. Visible from switch port
statistics and SNMP interface counters.

**Layer 2 (Data Link):** MAC addresses, VLAN tags, Ethernet
frame sizes. Enumerate with:

```bash
# List interfaces and MAC addresses
ip link show

# Show ARP table (layer 2-3 mapping)
ip neigh show

# Capture only ARP traffic
tcpdump -i eth0 -n arp
```

**Layer 3 (Network):** IP addresses, TTL values, fragmentation
flags. A TTL of 64 usually means Linux, 128 means Windows, 255
means network equipment. Enumerate with:

```bash
# IP configuration
ip addr show
ip route show

# TTL fingerprint via ping
ping -c 1 10.10.10.10
```

**Layer 4 (Transport):** open TCP/UDP ports, TCP flags, window
sizes. Enumerate with:

```bash
nmap -sS -p- --min-rate 5000 10.10.10.10
nmap -sU -p 53,67,68,123,161 10.10.10.10
```

**Layer 5-7 (Session, Presentation, Application):** protocol
banners, TLS versions, HTTP headers, service-specific handshakes.
Enumerate with:

```bash
nmap -sV -sC -p 22,80,443,445 10.10.10.10
curl -sI https://10.10.10.10/
openssl s_client -connect 10.10.10.10:443 -brief
```

The output of these commands is what populates every recon report.
Knowing which layer each tool observes keeps the report structured.


## 3. Common Attack Vectors

Each OSI layer has a characteristic set of attacks. This section
lists the canonical attacks by layer. Detailed exploitation
recipes are in section 4; detailed mitigations are in sections
6-7.

**Layer 1 - Physical:**
- Cable tampering, wiretapping.
- Jamming (wireless).
- Port stealing on unsecured switch ports.

**Layer 2 - Data Link:**
- MAC flooding (CAM table exhaustion).
- ARP spoofing / ARP poisoning.
- VLAN hopping (double tagging, switch spoofing).
- Spanning Tree Protocol (STP) manipulation.
- DHCP starvation.

**Layer 3 - Network:**
- IP spoofing.
- Fragmentation attacks (tiny fragments, overlapping fragments).
- ICMP redirect and ICMP tunneling.
- Routing protocol attacks (OSPF, BGP hijacking).

**Layer 4 - Transport:**
- TCP SYN flood.
- TCP session hijacking.
- UDP amplification (DNS, NTP, memcached).
- Port scanning (reconnaissance, but also precursor to attack).

**Layer 5-7 - Session, Presentation, Application:**
- TLS downgrade and certificate spoofing.
- Session fixation and session hijacking.
- Application-layer injection (SQLi, command injection, etc.).
- Request smuggling (HTTP desync).

The pattern: lower layers are usually attacked for availability or
man-in-the-middle position; higher layers are usually attacked for
confidentiality or code execution. A full kill chain often moves
from lower to higher layers.

## 4. Exploitation Recipes

Each recipe is a minimal, safe-to-test example. All commands are
run only against systems you own or have written authorization to
test.

### Recipe 1 - Inspect the encapsulation with tcpdump

Observe the layered headers of a single HTTP request. This makes
the OSI model concrete: you see the Ethernet header, the IP header,
the TCP header, and the HTTP payload stacked one after another.

```bash
tcpdump -i eth0 -n -vv -X 'tcp port 80 and host 10.10.10.10'
```

Expected output (trimmed):

```text
11:42:01.123456 IP 10.10.10.20.54321 > 10.10.10.10.80: Flags [P.], seq 1:15, ...
    0x0000:  4500 003c 1c46 4000 4006 ...
    0x0010:  ... TCP header bytes ...
    0x0020:  ... HTTP payload: "GET / HTTP/1.1" ...
```

The first bytes are the IP header (layer 3), the next are the TCP
header (layer 4), and the rest is HTTP (layer 7). Ethernet header
is stripped by tcpdump unless you capture at layer 2 with -e.

### Recipe 2 - Follow the TCP handshake

```bash
tcpdump -i eth0 -n 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0 and host 10.10.10.10'
```

Expected output:

```text
10.10.10.20.54321 > 10.10.10.10.80: Flags [S],  seq 1000, win 64240
10.10.10.10.80 > 10.10.10.20.54321: Flags [S.], seq 2000, ack 1001, win 65160
10.10.10.20.54321 > 10.10.10.10.80: Flags [.],  ack 2001, win 502
```

Three packets: SYN, SYN-ACK, ACK. That is the layer 4 connection
establishment. Everything after this is application data.

### Recipe 3 - Identify the TTL and guess the OS

```bash
ping -c 1 10.10.10.10 | grep ttl
```

Expected output:

```text
64 bytes from 10.10.10.10: icmp_seq=1 ttl=128 time=1.2 ms
```

TTL 128 -> Windows host. TTL 64 -> Linux host. TTL 255 -> network
device. This is layer 3 reconnaissance that costs one packet.

### Recipe 4 - See the difference between TCP and UDP

TCP is connection-oriented (three-way handshake, ordered delivery).
UDP is connectionless (fire and forget). Use the same tool on the
same host to see both:

```bash
nmap -sT -p 53,80 10.10.10.10
nmap -sU -p 53,80 10.10.10.10
```

A TCP port shows open, closed, or filtered with a reliable
state machine. A UDP port shows open|filtered because there is no
handshake - silence is ambiguous. This is a direct consequence of
the layer 4 protocol design, not a limitation of nmap.

## 5. Post-Exploitation

Once you have a foothold, understanding the OSI model tells you
what you can reach and what will be logged.

**Pivoting is layer 3.** A compromised host becomes a router for
you. The tools that make this work are all layer 3 and above:

```bash
# SSH SOCKS proxy (layer 4 tunnel)
ssh -D 1080 -N -f user@10.10.10.20

# Route a specific subnet through the SOCKS proxy
proxychains4 nmap -sT -p 22,80,445 172.16.0.0/24

# Port forward a single port (layer 4)
ssh -L 8080:10.10.10.30:80 user@10.10.10.20
```

**Internal reconnaissance is layer 2-4.** From a compromised host
you can now see the local segment: ARP table, VLAN membership,
the management subnet. This is data you could not see from outside.

**Data exfiltration is layer 5-7.** Once you have the data, how you
move it out determines whether it is detected:

- Layer 7 (HTTPS to a normal site) blends with traffic.
- Layer 4 (DNS tunneling) is noisier but harder to block.
- Layer 3 (ICMP tunneling) is the noisiest and easiest to detect.

**Persistence at the network layer** (rare, but worth knowing):

- Adding a route on a compromised router.
- Registering a rogue DHCP server.
- Adding a static ARP entry.

These are almost always caught by network monitoring. Application-
layer persistence (scheduled task, service, cron) is the usual
choice because it survives more changes.


## 6. Preventive Controls

Defense at each layer. The model gives you an organizational
framework for controls.

**Layer 1 - Physical:**
- Locked network closets and patch panels.
- Port security on access switches (limit MAC count per port).
- Disable unused ports.
- Tamper-evident cabling in high-security environments.

**Layer 2 - Data Link:**
- Enable DHCP snooping on access switches.
- Enable Dynamic ARP Inspection (DAI) on access switches.
- Enable IP Source Guard.
- Use private VLANs to segment tenants.
- Disable STP on end-user ports (BPDU guard, root guard).
- Never use the native VLAN for user traffic (VLAN hopping).

**Layer 3 - Network:**
- Anti-spoofing (ingress/egress filtering per BCP 38).
- Disable ICMP redirects on hosts (net.ipv4.conf.all.accept_redirects=0).
- Rate-limit ICMP.
- Control-plane policing on routers.
- Use IPv6 with proper filtering - do not leave IPv6 unconfigured.

**Layer 4 - Transport:**
- SYN cookies on servers (net.ipv4.tcp_syncookies=1).
- Firewall stateful inspection.
- Rate limiting on edge devices.
- Disable unused services.

**Layer 5-7:**
- TLS 1.2+ only, strong cipher suites.
- HSTS with a long max-age.
- Application-layer firewalls (WAF) as defense in depth.
- Input validation at the application boundary.

The pattern: layer 1-2 controls stop local attacks; layer 3-4
controls stop network-wide attacks; layer 5-7 controls stop the
attacks that reach the application. Defense in depth means every
layer has a control.

## 7. Detection Controls

Detection mirrors prevention but focuses on evidence rather than
blocking.

**Layer 1-2:**
- Switch port statistics (CRC errors, duplex mismatch, MAC flapping).
- Spanning tree topology change notifications.
- ARP table size anomalies (MAC flooding detection).

**Layer 3-4:**
- NetFlow / IPFIX records for volumetric anomalies.
- TCP flag anomaly detection (SYN without ACK from many sources).
- ICMP unreachable bursts (smurf-like patterns).
- Routing protocol adjacency changes.

**Layer 5-7:**
- IDS/IPS signatures (Suricata, Snort, Zeek).
- Web server access logs (request smuggling, injection attempts).
- TLS certificate monitoring (certificate transparency logs).
- DNS query logs (tunneling detection, DGA detection).

**Correlation:** the interesting detections come from correlating
layers. An ARP spoof on its own is a local nuisance; an ARP spoof
followed by an HTTP POST with a stolen session cookie is a full
compromise. This is what SIEM correlation rules are built to catch.

## 8. Verification

How to verify that the controls are working.

**Layer 2 verification:**

```bash
# From a test host, confirm ARP spoofing is blocked
arpspoof -i eth0 -t 10.10.10.10 10.10.10.1
# Expect: no traffic from 10.10.10.10 if DAI is enabled
```

**Layer 4 verification:**

```bash
# Confirm SYN cookies are active under load
sysctl net.ipv4.tcp_syncookies
# Expect: net.ipv4.tcp_syncookies = 1
```

**Layer 5-7 verification:**

```bash
# Confirm TLS version floor
openssl s_client -connect 10.10.10.10:443 -tls1
# Expect: handshake failure if TLS 1.0 is disabled
```

**Layer model verification:** the best evidence that you understand
the model is to predict, before you run a command, which layer the
output will show. If you predicted layer 4 and got layer 2, either
your understanding or the command is wrong. This habit turns the
model from theory into a working tool.

## 9. Certification Alignment

**CompTIA Network+ (N10-009):**
- Domain 1: Networking Concepts - OSI model, encapsulation,
  protocol data units, TCP/IP model, ports and protocols.
- Domain 4: Network Security - basic defense at each layer.
- Domain 5: Network Troubleshooting - using the model to isolate
  faults.

**Cisco CCNA (200-301):**
- Domain 1: Network Fundamentals - OSI model, TCP/IP stack,
  encapsulation, Ethernet, TCP vs UDP.
- Domain 4: IP Services - includes understanding of what runs at
  which layer.
- Domain 6: Automation and Programmability - model-driven
  programmability maps to structured data at each layer.

**Cross-references:**
- The MAC/VLAN mechanics are covered in depth in 02 (Routing and
  Switching).
- The IP addressing mechanics are covered in depth in 03 (IP
  Addressing and Subnetting).
- The protocol-by-protocol detail is in 04 (Network Protocols).

## 10. Production Notes

**Why the OSI model still matters in 2026:** the model is 40+
years old and the industry still uses it daily. The reason is
vocabulary: layer 7 load balancer or layer 2 switch is
shorthand that every network engineer understands without a
diagram. Removing the model from your vocabulary costs you
conversations with colleagues.

**Practical troubleshooting order:** when something is broken,
climb up the layers: is the link up (L1)? Does the MAC table know
the host (L2)? Can I ping the IP (L3)? Is the port open (L4)? Does
the application respond (L7)? This is faster than guessing because
each layer failure has a characteristic error message.

**Encapsulation is where mistakes happen:** most the network is
broken reports end up being a mismatch between what the application
sends and what the lower layer expects. A 1500-byte MTU on the
link with 9000-byte frames from the application is a layer 2-3
mismatch. A TLS-only server behind a plain HTTP health check is a
layer 4-7 mismatch.

**Cloud networking changes the diagram, not the model:** in a VPC
or VNET, the switch is software and the router is an API, but
the OSI layers are still there. A security group is a layer 3-4
filter. A load balancer is a layer 4 or 7 component. The vocabulary
transfers.

**IPv6 is a layer 3 change that reaches every layer:** dual-stack
hosts often have an unmonitored IPv6 path. Many environments that
are well-defended on IPv4 have an IPv6 network nobody watches.
Treat IPv6 as a first-class layer 3 protocol, not an afterthought.

## 11. References

- RFC 1122 - Requirements for Internet Hosts (Communication Layers) - https://www.rfc-editor.org/rfc/rfc1122
- RFC 791 - Internet Protocol - https://www.rfc-editor.org/rfc/rfc791
- RFC 768 - User Datagram Protocol - https://www.rfc-editor.org/rfc/rfc768
- RFC 9293 - Transmission Control Protocol - https://www.rfc-editor.org/rfc/rfc9293
- RFC 8200 - Internet Protocol, Version 6 - https://www.rfc-editor.org/rfc/rfc8200
- ISO/IEC 7498-1 - Information technology, Open Systems Interconnection, Basic Reference Model - https://www.iso.org/standard/20269.html
- CompTIA Network+ exam objectives - https://www.comptia.org/certifications/network
- Cisco CCNA exam topics - https://learningnetwork.cisco.com/s/ccna-exam-topics
- NIST SP 800-41 Rev. 1 - Guidelines on Firewalls and Firewall Policy - https://csrc.nist.gov/pubs/sp/800/41/r1/final
- Wireshark User Guide - https://www.wireshark.org/docs/wsug_html_chunked/

