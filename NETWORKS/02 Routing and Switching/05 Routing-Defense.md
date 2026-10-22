# Routing Defense

> Track: Defensive | Level: Advanced | Certs: CCNA, CCNP, CyberOps

## 1. Overview

This file is the defender-side deep dive into routing. It covers
the controls that stop the attacks in 04 Routing Attacks:
authentication, prefix filtering, RPKI, max-prefix, GTSM, iACL,
and the monitoring that catches what the controls miss. The
attacker side is in 04; the fundamentals are in 01 and 02.

Three things make routing defense worth studying in depth:

- Every control is opt-in. OSPF, EIGRP, BGP, HSRP, VRRP, and
  GLBP all support authentication, and none of them enable it by
  default. The defender must explicitly turn it on.
- The controls are layered. Authentication proves who the peer
  is; prefix filtering proves what the peer is allowed to say;
  RPKI proves the announcement is globally authorized; max-prefix
  and GTSM stop specific abuse. No single control covers all.
- The evidence is in the control plane. Host-based EDR, endpoint
  logs, and application logs never see a routing attack. The
  only evidence is in the routing protocol logs and the forwarding
  path.

The vocabulary: authentication (MD5, SHA, TCP-AO), prefix list,
route map, RPKI, ROA, max-prefix, GTSM, iACL, uRPF, bogon, route
leak, peer group, prefix filter, AS path filter, community.

## 2. Reconnaissance / Enumeration

Routing defense starts with an inventory of what is running and
what is authenticated. Before you can defend, you must know the
baseline.

**Inventory the routing protocols:**

```text
show ip protocols
show ip ospf
show ip bgp summary
show ip eigrp neighbors
show ip rip database

```

**Inventory the authentication state:**

```text
! OSPF
show ip ospf interface | include authentication

! EIGRP
show ip eigrp interfaces detail | include Authentication

! BGP
show ip bgp neighbors | include Authentication

! HSRP/VRRP/GLBP
show standby brief
show vrrp brief
show glbp brief

```

**Inventory the filtering:**

```text
! Prefix lists and route maps
show ip prefix-list
show route-map

! BGP peer policies
show ip bgp neighbors 203.0.113.1 | include (Prefix|Filter|Route|Maximum)

! iACL
show ip access-lists | include (ospf|eigrp|1985)

```

**What the output tells you:**

- A protocol with `authentication null` or no `Authentication`
  line is unauthenticated. That is the first finding.
- A BGP peer with no `Prefix-list` or `Route map` in the inbound
  policy accepts whatever the peer sends. That is the second
  finding.
- A BGP peer with no `Maximum-prefix` is vulnerable to route
  table exhaustion. That is the third finding.

**From a monitoring position: what is the baseline?**

```bash
# Capture routing protocol traffic for an hour
sudo tcpdump -i eth0 -n -G 3600 -W 1 -w /tmp/routing-baseline.pcap 'ip proto 89 or ip proto 88 or tcp port 179 or udp port 520'

# After capture, list the peers seen
tshark -r /tmp/routing-baseline.pcap -Y 'ospf || bgp || eigrp || rip' -T fields -e ip.src -e ip.dst | sort -u

```

The baseline is the list of legitimate peers. Any new peer in
the live traffic is a candidate for investigation.


## 3. Common Attack Vectors

This section is a short reference of what the controls defend
against. The full attack detail is in 04 Routing Attacks; here
each attack is paired with the control that stops it.

| Attack | Primary control | Secondary control |
|--------|-----------------|-------------------|
| Rogue OSPF speaker | OSPF MD5/SHA auth | iACL, passive interface |
| OSPF max age attack | OSPF auth | LSA throttling |
| OSPF DR/BDR takeover | OSPF auth | interface priority |
| Rogue EIGRP speaker | EIGRP MD5/SHA auth | iACL, passive interface |
| EIGRP stuck-in-active | EIGRP auth | query limits |
| BGP prefix hijack | RPKI | prefix filter, max-prefix |
| BGP sub-prefix hijack | prefix filter (max-length) | RPKI |
| BGP AS path manipulation | AS path filter | RPKI |
| BGP route leak | prefix filter, community tags | max-prefix |
| BGP session reset | TCP MD5 / TCP-AO | GTSM |
| BGP route table exhaustion | max-prefix | route dampening |
| HSRP/VRRP/GLBP takeover | MD5 auth + preempt | iACL |
| First-hop ARP spoof | DAI + DHCP snooping | iACL |

The pattern: authentication stops the speaker; filtering stops
the content; RPKI stops the global announcement; max-prefix and
GTSM stop the specific abuse.

## 4. Exploitation Recipes

This file is defensive; the exploitation recipes are in 04
Routing Attacks. The recipes below are the defensive
configurations, applied to the same lab scenarios, so the
defender can verify that the controls work against the attack.

### Recipe 1 - Harden OSPF in the lab

```text
! Every interface in area 0 uses MD5
interface range GigabitEthernet0/1-48
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 <KEY>
 no ip ospf passive-interface

! Host-facing ports are passive (no OSPF hello)
interface range GigabitEthernet0/1-10
 ip ospf passive-interface

! Limit the LSA flood
router ospf 1
 max-lsa 12000
 timers throttle spf 50 200 5000
 timers throttle lsa 50 200 5000

! Log every adjacency change
router ospf 1
 log-adjacency-changes detail

```

Expected result: a rogue FRR speaker that does not know the key
cannot form an adjacency. The hello packets are dropped, and
the switch logs the authentication failure.

### Recipe 2 - Harden EIGRP in the lab

```text
key chain EIGRP-KEYS
 key 1
  key-string <KEY>
interface range GigabitEthernet0/1-48
 ip authentication mode eigrp 100 md5
 ip authentication key-chain eigrp 100 EIGRP-KEYS

router eigrp 100
 passive-interface default
 no passive-interface GigabitEthernet0/49
 eigrp log-neighbor-changes

```

Expected result: the rogue EIGRP speaker cannot form an
adjacency. The switch logs the authentication failure.

### Recipe 3 - Harden BGP in the lab

```text
! TCP MD5 (or TCP-AO if supported)
neighbor 203.0.113.1 password <KEY>

! Prefix filter: only the expected prefixes
ip prefix-list FROM-PEER permit 203.0.113.0/24
ip prefix-list FROM-PEER deny 0.0.0.0/0 le 32
neighbor 203.0.113.1 prefix-list FROM-PEER in

! Max-prefix (stop route table exhaustion)
neighbor 203.0.113.1 maximum-prefix 1000 90 restart 30

! GTSM (stop off-path injection)
neighbor 203.0.113.1 ttl-security hops 1

! RPKI validation
bgp rpki server tcp 203.0.113.10 port 3323 refresh 600
neighbor 203.0.113.1 route-map RPKI-FILTER in
route-map RPKI-FILTER permit 10
 match rpki valid
route-map RPKI-FILTER deny 20
 match rpki invalid
route-map RPKI-FILTER permit 30
 match rpki notfound

! Log every session change
bgp log-neighbor-changes

```

Expected result: a rogue BGP speaker that does not know the key
cannot form a session; a peer that announces a prefix outside
the filter is dropped; a peer that announces more than 1000
prefixes is shut down; a peer that is not the legitimate one is
rejected by GTSM.

### Recipe 4 - Harden first-hop redundancy

```text
! HSRP
standby 1 authentication md5 key-string <KEY>
standby 1 preempt
standby 1 priority 110

! VRRP
vrrp 1 authentication md5 key-string <KEY>
vrrp 1 preempt
vrrp 1 priority 110

! GLBP
glbp 1 authentication md5 key-string <KEY>
glbp 1 preempt
glbp 1 priority 110

```

Expected result: a rogue HSRP/VRRP/GLBP speaker that does not
know the key cannot become the active gateway. The real gateway
keeps the virtual IP.

### Recipe 5 - Harden the control plane with iACL

```text
! Block routing protocols on host-facing ports
interface range GigabitEthernet0/1-48
 no ip ospf 1 area 0
 no ip hello-interval eigrp 100 5
 no standby 1
 no vrrp 1

! Or with an ACL
ip access-list extended HOST-FACING
 deny ospf any any
 deny eigrp any any
 deny udp any any eq 1985
 deny 112 any any
 permit ip any any
interface range GigabitEthernet0/1-48
 ip access-group HOST-FACING in

```

Expected result: a host that sends an OSPF hello, EIGRP hello,
or HSRP hello on an access port has the packet dropped. No
adjacency forms.

## 5. Post-Exploitation

For a defender, post-exploitation means what to do after a
routing control failure is detected. The attacker side is in 04.

**Contain:** if a rogue peer is detected, shut the port or the
peer session. On OSPF/EIGRP, use `shutdown` on the interface or
`clear ip ospf neighbor`. On BGP, use `clear ip bgp <peer>` and
apply a temporary prefix filter that denies the attacker.

**Eradicate:** remove the rogue configuration, if any, and
re-apply the authentication and filtering that was missing.

**Recover:** after the rogue route is removed, verify that the
forwarding plane matches the intended topology. A stale route
in the FIB after the RIB is corrected is a common post-incident
failure.

**Lessons learned:** the finding is "the protocol accepted an
unauthenticated speaker". The corrective action is to enable
authentication and filtering on every peer, not just the one
that was attacked.

**Communication:** routing incidents are network-wide, so the
communication must include every team that depends on the
affected prefixes. A BGP hijack of a customer prefix is a
customer-facing outage, even if the attacker only announced it
for a few minutes.


## 6. Preventive Controls

The preventive controls are the same as in 04 Routing Attacks,
section 6, but organized by control rather than by attack. This
is the deployment checklist.

**Layer 1 - Authentication (stop the speaker):**

- OSPF: MD5 on every interface, SHA if supported (RFC 5709).
- EIGRP: MD5 on every interface, SHA-256 in named mode.
- BGP: TCP MD5 (legacy) or TCP-AO (modern, RFC 5925).
- HSRP/VRRP/GLBP: MD5 on the group.
- 802.1X / MACsec on the link where LACP is used.

**Layer 2 - Prefix filtering (stop the content):**

- BGP: prefix-list per peer, deny by default, allow only the
  expected prefixes.
- BGP: max-length on the prefix-list to stop sub-prefix hijack.
- BGP: AS path filter to reject bogons and unexpected origins.
- OSPF/EIGRP: distribute-list to control what is redistributed
  into the routing domain.

**Layer 3 - Global attestation (stop the announcement):**

- RPKI: validate every BGP announcement against the ROA.
- RPKI: drop `invalid`, accept `valid` and `notfound` (or drop
  `notfound` in a strict deployment).

**Layer 4 - Abuse limits (stop the specific abuse):**

- BGP: `maximum-prefix` per peer.
- BGP: GTSM (`ttl-security hops 1`) for directly-connected
  eBGP peers.
- OSPF: `max-lsa` per router.
- OSPF/EIGRP: SPF/LSA/query throttling.

**Layer 5 - Control plane protection (stop the flood):**

- iACL on host-facing ports: drop OSPF, EIGRP, HSRP, VRRP, GLBP.
- CoPP (Control Plane Policing) on routers: rate-limit routing
  protocol traffic to the CPU.
- Passive interface on every host-facing port.

**Layer 6 - First-hop security (stop the layer 2 attack):**

- DHCP snooping, DAI, IP Source Guard, RA guard, BPDU guard.
- See 03 Switching Advanced for the full configuration.

## 7. Detection Controls

Each control in section 6 has a matching detection. The
detections are in 04 Routing Attacks, section 7; this section is
the consolidated monitoring view.

**Control-plane logs:**

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

! HSRP/VRRP/GLBP
! (state changes are logged by default; verify with show logging)

! Syslog to a central collector
logging host 10.10.10.50
logging trap informational

```

**What to alert on:**

- New OSPF/EIGRP/BGP neighbor that was not in the baseline.
- OSPF authentication failure (a sign of a rogue speaker).
- BGP session flap more than N times in M minutes.
- BGP prefix count change greater than X percent.
- BGP RPKI-invalid announcement.
- HSRP/VRRP/GLBP active/standby change on a stable segment.
- Traceroute path change for a stable destination (a sign of a
  route change that no change ticket explains).

**Forwarding plane detection:**

- NetFlow / IPFIX: traffic for a prefix that now flows through a
  different next hop.
- Asymmetric routing: reply path differs from request path.
- Blackhole: a prefix stops receiving traffic with no link
  failure.

**SIEM correlation:** the high-value alert is "new routing peer
+ new route + traffic to that route". Each event alone is noise;
together they are a control-plane compromise.

## 8. Verification

How to verify that every control in section 6 is working.

**Authentication:**

```text
show ip ospf interface GigabitEthernet0/1 | include authentication
show ip eigrp interfaces detail GigabitEthernet0/1 | include Authentication
show ip bgp neighbors 203.0.113.1 | include Authentication
show standby brief | include Auth
show vrrp brief | include Auth
! Expect: every peer shows an authentication method, not "null" or "No Auth"

```

**Prefix filtering:**

```text
show ip prefix-list
show ip bgp neighbors 203.0.113.1 | include Prefix-list
! Expect: a prefix-list on every inbound peer, and the list denies by default

```

**RPKI:**

```text
show bgp rpki servers
show bgp rpki table
! Expect: the RPKI cache is connected, and the announcements are validated

```

**Abuse limits:**

```text
show ip bgp summary
! Expect: a "State/PfxRcd" number below the max-prefix, and a max-prefix configured
show ip bgp neighbors 203.0.113.1 | include (ttl-security|Maximum)
! Expect: GTSM enabled and max-prefix set
show ip ospf | include max-lsa
! Expect: max-lsa is configured

```

**Control plane protection:**

```text
show ip access-lists | include (ospf|eigrp|1985)
show ip interface | include access-group
! Expect: an iACL applied inbound on host-facing ports

```

**The verification habit:** after every routing change, re-run
the inventory in section 2. If the authentication, filtering,
or abuse limits changed, that is the finding. A silent control
regression is the most common routing defense failure.

## 9. Certification Alignment

**CompTIA Network+ (N10-009):**
- Domain 4: Network Security - routing protocol authentication,
  filtering, iACL, first-hop security.

**Cisco CCNA (200-301):**
- Domain 3: IP Connectivity - OSPF, first-hop redundancy.
- Domain 5: Security Fundamentals - routing protocol
  authentication, ACLs.

**Cisco CyberOps Associate (200-201 CBROPS):**
- Detecting control-plane attacks (routing protocol anomalies,
  BGP hijack indicators, RPKI).

**Cisco CCNP Enterprise (350-401 ENCOR + 300-410 ENARSI):**
- BGP security (prefix filters, RPKI, max-prefix, GTSM), OSPF
  authentication, route leak prevention, iACL, CoPP.

**Cross-references:**
- 01 Routing Fundamentals covers the routing table and
  administrative distance that every control protects.
- 02 Dynamic Routing Protocols covers OSPF/EIGRP/BGP/RIP
  operation in detail.
- 03 Switching Advanced covers the layer 2 fabric and the
  first-hop security.
- 04 Routing Attacks covers the attacks these controls stop.

## 10. Production Notes

**The control plane is the highest-value target, and it is the
least monitored.** Host-based EDR, endpoint logs, and application
logs never see a routing attack. The only evidence is in the
routing protocol logs and the forwarding path. This is why the
detections in section 7 matter more than the detections for any
other class of attack.

**Authentication is one line, and it is off by default.** Every
routing protocol supports it. None enable it by default. This is
the single highest-value routing control, and the fastest to
deploy. Start with authentication, then add prefix filtering,
then RPKI, then the abuse limits.

**RPKI is a global control; prefix filtering is a local control.**
Prefix filtering protects you from a peer that announces
something it should not. RPKI protects you from any peer, even
one you trust, that announces a prefix it is not authorized to
announce. You need both.

**Route leaks are an accident, and they are as damaging as an
attack.** The controls are the same: prefix filters, max-prefix,
community tags, and RPKI. A route leak from a misconfigured
route-map can take down a tier-1 network; the defense is
identical to the defense against a hijack.

**Cloud routing is IAM, not BGP.** In a VPC, the control plane is
the cloud API. The attacks are IAM misconfiguration and route
table edits, not OSPF/BGP injection. The controls are least-
privilege IAM, route table review, and VPC Flow Logs. But hybrid
environments still run BGP between the data center and the cloud,
and that session needs every control in section 6.

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
- NIST SP 800-189 - Resilient Interdomain Traffic Exchange (RPKI, BGP security) - https://csrc.nist.gov/pubs/sp/800/189/final
- Cisco - BGP Best Practices - https://www.cisco.com/c/en/us/support/docs/ip/border-gateway-protocol-bgp/16149-18.html
- CompTIA Network+ exam objectives - https://www.comptia.org/certifications/network
- Cisco CCNA exam topics - https://learningnetwork.cisco.com/s/ccna-exam-topics

