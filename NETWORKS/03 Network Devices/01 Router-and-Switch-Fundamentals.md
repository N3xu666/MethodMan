# Router and Switch Fundamentals

> Track: Offensive / Defensive | Level: Foundation | Certs: Network+, CCNA, CCNP

## 1. Overview

A router forwards packets between networks. A switch forwards
frames between ports on the same network. Both are special-
purpose computers with three planes: the control plane (routing
protocols, STP, management), the data plane (the forwarding
ASIC or software path), and the management plane (SSH, SNMP,
logging).

Three things make the architecture worth studying in depth:

- The control plane is the attack surface. Every routing protocol,
  every STP BPDU, every management protocol runs on the CPU. If
  the CPU is saturated or compromised, the data plane may still
  forward, but the device is no longer under your control.
- The data plane is where performance lives. A router that can
  forward 100 Gbps in hardware may be limited to a few Mbps for
  traffic that must be punted to the CPU (TTL exceeded,
  fragmentation, ACL logging).
- The management plane is where persistence lives. A compromised
  management plane (SSH, SNMP, TACACS+) gives the attacker the
  ability to change the control plane, and through it the data
  plane.

The vocabulary: control plane, data plane, management plane,
ASIC, TCAM, FIB, RIB, punt, CoPP, line card, supervisor,
backplane, stacking, chassis.

## 2. Reconnaissance / Enumeration

Router and switch reconnaissance is about discovering the device,
its role, and its management surface.

**Is it a router or a switch?**

```bash
# A router has a routing table and multiple L3 interfaces
ip route show

# A switch has a MAC table and VLANs (on the switch itself)
show mac address-table
show vlan brief

# From a host, the default gateway is usually a router
ip route show default

```

**What is the device?**

```bash
# TTL fingerprint (ping)
ping -c 1 10.10.10.1 | grep ttl

# HTTP/HTTPS management page (if exposed)
curl -sI http://10.10.10.1/
curl -sk https://10.10.10.1/

# SSH banner
ssh -o BatchMode=yes -o ConnectTimeout=3 10.10.10.1 2>&1 | head -3

# SNMP (if enabled)
snmpwalk -v2c -c public 10.10.10.1 sysDescr

```

**What does the device expose?**

```bash
# Port scan for management services
nmap -p 22,23,80,443,161,162,830,443,8080 10.10.10.1

# SNMP community strings (default)
onesixtyone -c /usr/share/wordlists/snmp.txt 10.10.10.1

# Cisco Smart Install (TCP/4786) - a known RCE surface
nmap -p 4786 10.10.10.0/24

```

**What the output tells you:**

- TTL 255 from the target -> network device. TTL 64 -> Linux.
  TTL 128 -> Windows.
- An SSH banner that says `Cisco-1.25` or `SSH-2.0-Cisco-1.25`
  identifies a Cisco device.
- TCP/4786 open -> Smart Install, a legacy Cisco protocol with
  known RCE (CVE-2018-0171).
- SNMP `public` responding -> a device with default community,
  which leaks the full config on some platforms.

**From a foothold on the device:**

```text
show version
show running-config
show ip route
show ip interface brief
show cdp neighbors detail
show lldp neighbors detail
show users
show logging

```

The `show version` output gives the exact model and IOS/NX-OS
version, which maps directly to known CVEs. The
`show running-config` gives every credential, every ACL, and
every routing peer.

## 3. Common Attack Vectors

Router and switch attacks target the three planes. Each attack
is grouped by the plane it compromises.

**Management plane attacks:**
- Default credentials (admin/admin, cisco/cisco).
- SNMP with the default `public` / `private` community string.
- Cisco Smart Install (TCP/4786) - CVE-2018-0171, unauthenticated RCE.
- Cisco IOS XE Web UI - CVE-2023-20198, privilege 15 account creation.
- TFTP config download (no authentication on TFTP).
- Telnet (plaintext) and SSH with weak crypto.

**Control plane attacks:**
- Routing protocol injection (OSPF/EIGRP/BGP) - see 02.
- STP takeover - see 02.
- CPU exhaustion via CoPP bypass (flood the control plane).
- CDP/LLDP spoofing (announce a fake neighbor to poison the map).

**Data plane attacks:**
- VLAN hopping (double tagging, switch spoofing) - see 02.
- ARP spoofing (layer 2 MITM) - see 01/02.
- MAC flooding (CAM table exhaustion).
- TCAM exhaustion (fill the ACL table with entries).

**Supply chain and firmware attacks:**
- Malicious firmware image (a router or switch does not verify
  its OS image by default on older platforms).
- Compromised vendor update (a signed image from a compromised
  vendor build system).
- Counterfeit hardware with a backdoor.

The common thread: the management plane is the easiest entry
point, the control plane is the highest impact, and the data
plane is where the traffic is.

## 4. Exploitation Recipes

All commands are run only against systems you own or have written
authorization to test.

### Recipe 1 - Default credential check

The first check on any network device is the default credential.

```bash
# HTTP basic auth
curl -s -o /dev/null -w "%{http_code}\\n" -u admin:admin http://10.10.10.1/
curl -s -o /dev/null -w "%{http_code}\\n" -u cisco:cisco http://10.10.10.1/

# SSH
sshpass -p cisco ssh -o StrictHostKeyChecking=no admin@10.10.10.1

# Telnet (plaintext, still common on legacy gear)
telnet 10.10.10.1

```

A `200` from the HTTP check or a successful SSH login is a
finding. The response is the same as the normal page, but the
credential is now known.

### Recipe 2 - SNMP community string enumeration

SNMP v1/v2c use a plaintext community string. The defaults are
`public` (read) and `private` (read-write).

```bash
# One-shot community check
onesixtyone -c /usr/share/wordlists/snmp.txt 10.10.10.1

# Enumerate the whole MIB (some platforms leak the config)
snmpwalk -v2c -c public 10.10.10.1

# Cisco-specific: get the running config via SNMP
snmpwalk -v2c -c private 10.10.10.1 1.3.6.1.4.1.9.9.96

```

If `private` is valid, the attacker can write to the device
(change the config, reload, etc.). This is a critical finding.

### Recipe 3 - Cisco Smart Install (CVE-2018-0171)

Smart Install (TCP/4786) has no authentication. A crafted packet
can read the config, change the config, or reload the device.

```bash
# Check if the port is open
nmap -p 4786 10.10.10.1

# SIET (Smart Install Exploitation Tool) - a public PoC
git clone https://github.com/frostbits-security/SIET
cd SIET
python siet.py -d 10.10.10.1

```

Expected effect: if the port is open, SIET reads the config or
triggers a reload. The defense is to disable Smart Install
(`no vstack`) on every device.

### Recipe 4 - Cisco IOS XE Web UI (CVE-2023-20198)

The IOS XE Web UI has an authentication bypass that allows an
attacker to create a privilege 15 account.

```bash
# Check if the Web UI is exposed
curl -sk https://10.10.10.1/webui/

# The CVE-2023-20198 PoC creates a user via a crafted POST
# (see the public PoC for the exact payload)

```

Expected effect: a new local user with privilege 15 is created,
and the attacker logs in over SSH. The defense is to patch IOS
XE to a fixed release and disable the Web UI.

### Recipe 5 - CDP/LLDP spoofing

CDP and LLDP announce neighbor information with no
authentication. A rogue device can announce itself as a core
switch or router.

```bash
# Send a fake CDP announcement (requires a real CDP frame)
sudo python3 -c "
from scapy.all import *
cdp = Ether(dst='01:00:0c:cc:cc:cc')/LLC()/SNAP()/Raw(load=b'\\x02\\xb4' + b'\\x00' * 200)
sendp(cdp, iface='eth0', loop=1, inter=60)
"

```

Expected effect: the switch neighbor table shows the attacker as
a core device. If the switch runs CDP-based voice VLAN or
auto-config, the attacker is trusted. The defense is to disable
CDP/LLDP on host-facing ports.

## 5. Post-Exploitation

Once you control a router or switch, the post-exploitation
options are network-wide.

**Config exfiltration:** the running config contains every
credential (often type 7 or type 5 hashed), every ACL, every
routing peer, and every VPN key.

```text
show running-config | include (username|password|key|secret)

```

**Persistence:** a local user with privilege 15, an SNMP
community with write access, or a modified ACL that allows the
attacker back in. All of these survive a reboot if the config
is saved (`copy running-config startup-config`).

**Traffic interception:** a router or switch with a SPAN port
configured (or a compromised one) can mirror traffic to the
attacker. On a switch, a VLAN ACL or a MAC spoof can also
redirect traffic.

**Blackhole:** a static route to `null0` or a shutdown interface
drops traffic for a prefix. A blackhole of a management network
locks the defender out.

**Reporting:** the finding is "the device is reachable on the
management plane with default credentials / unauthenticated
protocol". The fix is to put the management plane on a dedicated
management network with ACLs, MFA, and no default credentials.

## 6. Preventive Controls

Device hardening is about locking down the three planes and
removing every service that is not needed.

**Management plane hardening:**

```text
! Dedicated management VRF / network
vrf definition MGMT
 address-family ipv4
 exit-address-family
! Apply to the management interface only
interface GigabitEthernet0/0
 vrf forwarding MGMT
 ip address 10.10.10.1 255.255.255.0

! Restrict management access
ip access-list standard MGMT-ALLOWED
 permit 10.10.10.0 0.0.0.255
 permit 10.20.10.0 0.0.0.255
line vty 0 4
 access-class MGMT-ALLOWED in
 transport input ssh

! SSH only, no Telnet
no ip telnet server
ip ssh version 2
ip ssh authentication-retries 3
ip ssh time-out 60

! AAA with TACACS+ or RADIUS
aaa new-model
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
tacacs server TAC1
 address ipv4 10.10.10.50
 key <KEY>

! Disable SNMP v1/v2c, use v3 auth+priv
no snmp-server community public
no snmp-server community private
snmp-server group MGMT v3 priv
snmp-server user monitor MGMT v3 auth sha <AUTH> priv aes 128 <PRIV>

```

**Disable unused services and legacy protocols:**

```text
no ip http server
no ip http secure-server
no service pad
no service finger
no ip bootp server
no ip source-route
no ip proxy-arp
no cdp run
no lldp run
no vstack
ip scp server enable
ip tftp server disable

```

**Control plane protection (CoPP):**

```text
! Rate-limit routing protocol and management traffic to the CPU
policy-map COPP
 class class-default
  police rate 1000000 burst 10000
  conform-action transmit
  exceed-action drop
control-plane
 service-policy input COPP

```

**Data plane hardening:**

```text
! Unicast RPF (anti-spoofing)
interface GigabitEthernet0/1
 ip verify unicast source reachable-via rx

! Port security
interface range GigabitEthernet0/1-48
 switchport mode access
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation restrict

! BPDU guard, root guard, DHCP snooping, DAI (see 02 and 03)

```

**Firmware and supply chain:**

- Verify the signed image before install (`verify /md5`, `show
  software authenticity`).
- Use only vendor-signed images from the vendor portal.
- Track firmware versions against the vendor security advisory.
- Keep a known-good image in the lab for rollback.

## 7. Detection Controls

**Management plane detection:**
- Login failures on SSH/Telnet/HTTP (a sign of a credential
  attack).
- New local user with privilege 15.
- SNMP community change or a new SNMP user.
- Config change (TACACS+ command accounting, syslog).
- Management access from an unexpected source IP.

**Control plane detection:**
- CPU spike from a routing protocol (LSA flood, BGP churn).
- New routing peer (see 02 and 04).
- New CDP/LLDP neighbor.
- CoPP drops (a sign of a control-plane flood).

**Data plane detection:**
- MAC flapping (a sign of a loop or a MAC spoof).
- ARP table size anomaly (a sign of ARP spoofing).
- Port security violation.
- Unicast RPF drops.

**Logging:**

```text
! Send logs to a central collector
logging host 10.10.10.50
logging trap informational
logging buffered 16384 informational

! Log config changes
archive
 log config
 logging enable
 notify syslog contenttype plaintext

! NTP (accurate timestamps)
ntp server 10.10.10.50
ntp authentication-key 1 md5 <KEY>
ntp trusted-key 1

```

**SIEM correlation:** the high-value alert is "new local user +
new config change + login from a new IP". Each event alone is
noise; together they are a device compromise.

## 8. Verification

How to verify that the device is hardened.

**Verify management access:**

```text
show run | include (telnet|ssh|http|snmp|cdp|lldp)
show users
show ssh
! Expect: SSH v2 only, no Telnet, no HTTP, no SNMP v1/v2c, no CDP/LLDP

```

**Verify AAA:**

```text
show aaa servers
show tacacs
! Expect: at least one AAA server configured and reachable

```

**Verify CoPP:**

```text
show policy-map control-plane
! Expect: the CoPP policy is attached and counters are incrementing

```

**Verify firmware:**

```text
show version
show software authenticity running
! Expect: signed image and a known-good version

```

**Verify data plane:**

```text
show ip interface GigabitEthernet0/1 | include verify
show port-security interface GigabitEthernet0/1
! Expect: uRPF enabled and port security active

```

**The verification habit:** after every device change, re-run
the inventory in section 2 and compare with the previous state.
A silent management-plane change is the most common device
compromise.

## 9. Certification Alignment

**CompTIA Network+ (N10-009):**
- Domain 2: Network Implementation - routers, switches,
  management.
- Domain 4: Network Security - device hardening, AAA, ACLs.

**Cisco CCNA (200-301):**
- Domain 1: Network Fundamentals - device roles, architecture.
- Domain 5: Security Fundamentals - device hardening, AAA,
  port security, DHCP snooping, DAI.

**Cisco CyberOps Associate (200-201 CBROPS):**
- Detecting device compromise (new user, config change,
  management access from unexpected source).

**Cisco CCNP Security (350-701 SCOR):**
- Device hardening, CoPP, control plane protection.

**Cross-references:**
- 01 Network Fundamentals covers the layer 1-3 basics.
- 02 Routing and Switching covers the protocols the device runs.
- 04 Routing Attacks and 05 Routing Defense cover the control
  plane attacks and defenses in depth.

## 10. Production Notes

**The management plane is the easiest entry point, and it is
often the least protected.** Default credentials, SNMP v1/v2c
with `public`, Telnet, HTTP - all of these are still common on
legacy gear. The first step of any device assessment is to
enumerate the management plane.

**The control plane is the highest impact.** A compromised
control plane lets the attacker change the routing, the VLANs,
and the ACLs. The device still forwards, but it forwards what
the attacker wants. This is why CoPP and control plane
protection matter.

**The data plane is where the traffic is.** A compromised data
plane lets the attacker intercept or drop specific traffic.
Port security, DHCP snooping, DAI, and uRPF are the controls.

**Firmware is the supply chain.** A router or switch that runs a
malicious image is a backdoor that no amount of config hardening
can fix. Verify the image, track the version, and keep a
known-good copy.

**Cloud networking replaces the device, not the problem.** In a
VPC, there is no physical router, but the route table and the
security group are the equivalent. The controls (least privilege,
logging, review) are the same in spirit.

## 11. References

- NIST SP 800-41 Rev. 1 - Guidelines on Firewalls and Firewall Policy - https://csrc.nist.gov/pubs/sp/800/41/r1/final
- NIST SP 800-53 Rev. 5 - Security and Privacy Controls (CM, AC, AU families) - https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- CIS Cisco IOS Benchmark - https://www.cisecurity.org/benchmark/cisco
- NSA - Cisco IOS Security Configuration Guide - https://media.defense.gov/2020/Sep/17/2002498626/-1/-1/0/CISCO_IOS_SECURITY_GUIDE.PDF
- Cisco - Guide to Harden Cisco IOS Devices - https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html
- CVE-2018-0171 (Cisco Smart Install) - https://nvd.nist.gov/vuln/detail/CVE-2018-0171
- CVE-2023-20198 (Cisco IOS XE Web UI) - https://nvd.nist.gov/vuln/detail/CVE-2023-20198
- CompTIA Network+ exam objectives - https://www.comptia.org/certifications/network
- Cisco CCNA exam topics - https://learningnetwork.cisco.com/s/ccna-exam-topics

