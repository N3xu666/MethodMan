# Network Topologies

> Track: Offensive / Defensive | Level: Foundation | Certs: Network+, CCNA

## 1. Overview

A network topology is the arrangement of links and nodes: how
devices are physically cabled and how traffic logically flows
between them. The choice of topology determines the blast radius
of a compromise, the paths an attacker can take, and the
single points of failure a defender must protect.

Three things make topology worth studying in depth:

- Topology is the map for lateral movement. The first question
  after a foothold is always "what can this host reach", and the
  answer is a function of the topology.
- Topology is the map for segmentation. VLANs, subnets, and
  firewalls only work if the topology puts boundaries where they
  are enforced. A flat topology defeats every control above it.
- Topology explains failure domains. A star topology loses the
  hub, a mesh loses one path, a hub topology loses everything.
  The same reasoning applies to an attack that takes out a core
  switch.

The vocabulary: star, mesh, hub-and-spoke, spine-leaf, bus, ring,
point-to-point, physical vs logical topology, east-west vs
north-south traffic, DMZ, segmentation, microsegmentation.

## 2. Reconnaissance / Enumeration

Topology reconnaissance is about mapping what is reachable from a
given position. It happens at two levels: from outside (what the
edge exposes) and from inside (what the internal topology looks
like).

**From outside: the edge topology**

```bash
# What is the public IP of the target?
dig +short target.example.com
whois 203.0.113.10 | grep -i netname

# How many hops to the edge, and where is it?
traceroute -n target.example.com

# Which ports are exposed at the edge?
nmap -Pn -p- --min-rate 5000 203.0.113.10

```

**From inside: the reachable map**

```bash
# What subnets is this host connected to?
ip route show

# What can this host reach directly (ARP = same segment)?
ip neigh show

# What does DNS know about internal names?
cat /etc/resolv.conf
dig +short internal.corp.local

```

**From a foothold: the pivot map**

```bash
# Which networks does this host have interfaces on?
ip -brief addr show

# Which hosts respond on each reachable subnet?
for net in 10.10.10.0/24 172.16.0.0/24; do echo "== $net =="; nmap -sn $net; done

```

**Cloud topology (from a foothold with API access):**

```bash
# AWS: what VPCs, subnets, route tables, and security groups exist?
aws ec2 describe-vpcs --query "Vpcs[].CidrBlock"
aws ec2 describe-subnets --query "Subnets[].[CidrBlock,VpcId]"
aws ec2 describe-route-tables
aws ec2 describe-security-groups --query "SecurityGroups[].[GroupName,GroupId]"

```

**What the output tells you:**

- A star topology has one hub everyone talks through. If you see
  that traffic from every subnet goes through one IP, that is the
  hub (the core switch or the firewall).
- A spine-leaf topology has multiple equal-cost paths. Traceroute
  shows different paths on different runs.
- A hub-and-spoke topology has a hub with VPN tunnels to each
  spoke. The hub is the concentration point and the single point
  of failure.
- A flat topology has every host on the same VLAN and subnet.
  Every scan is fast and every host sees every broadcast.

The output of these commands is the topology map. Section 4 shows
how an attacker uses it and section 6 shows how a defender shapes
it on purpose.


## 3. Common Attack Vectors

Topology itself is not attacked; it is exploited. Each attack in
this section is an attack that a particular topology makes easy.

**Flat topology (one VLAN, one subnet):**
- ARP spoofing and MAC flooding reach every host (see 02).
- Broadcast storms take out the whole network.
- A single compromised host can scan every service without a pivot.

**Star topology (one hub):**
- The hub is a single point of failure - a DoS on the hub is a DoS
  on the whole network.
- All traffic passes through the hub, so a hub compromise is a
  full man-in-the-middle position.

**Hub-and-spoke (one hub, many VPN spokes):**
- The hub concentrates trust: compromise the hub, and every spoke
  trusts you.
- Spoke-to-spoke traffic often flows through the hub, so the hub
  sees everything.
- A misconfigured spoke can route into the hub network.

**Spine-leaf (data center, multiple paths):**
- East-west traffic dominates. A compromised server can talk to
  many other servers directly, and segmentation is the only
  control that limits it.
- The leaf switches are usually not the boundary; the boundary is
  microsegmentation (security groups, service mesh policy).

**DMZ topology (Internet - DMZ - internal):**
- The DMZ is designed to be reachable from the Internet. Every
  service in the DMZ is exposed by design.
- The DMZ-to-internal boundary is the critical control. If it is
  a flat "any to any" rule, the DMZ is just an extension of the
  internal network.
- A compromised DMZ host is the standard first step to internal
  reconnaissance.

**Cloud topology (VPC, subnets, security groups):**
- Public subnets are exposed by design. Private subnets are only
  as private as their route table and security group allow.
- A misconfigured security group (0.0.0.0/0 on a database port)
  is the most common cloud exposure.
- The "topology" is code, so a single Terraform change can expose
  a private subnet without anyone noticing.

The pattern: every topology has a concentration point and a trust
boundary. The attacks target the concentration point; the defenses
harden the trust boundary.

## 4. Exploitation Recipes

Each recipe shows how an attacker uses a topology. All commands
are run only against systems you own or have written authorization
to test.

### Recipe 1 - Map a flat network from one foothold

On a flat network, one host reaches everything. There is no pivot;
there is only a longer scan.

```bash
# From a single foothold, sweep and scan the whole /16
nmap -sn 10.10.0.0/16 -oG sweep.txt
grep Up sweep.txt | awk '{print $2}' > live.txt
nmap -sT -p- --min-rate 5000 -iL live.txt -oG services.txt

```

Expected scale: a /16 is 65536 addresses. An `-sn` sweep of a
flat network completes in minutes. On a segmented network, the
same sweep would return almost nothing because the firewall drops
it. The result itself is the finding.

### Recipe 2 - Identify the concentration point

Every topology has a hub. Find it by looking at where traffic
converges.

```bash
# From a foothold, what is the default gateway? (usually the hub)
ip route show default

# What does the traceroute to several destinations have in common?
for dst in 8.8.8.8 1.1.1.1 10.10.10.10; do echo "== $dst =="; traceroute -n $dst; done

```

If every traceroute passes through the same first hop, that IP is
the concentration point. It is the highest-value target for
interception (ARP spoof, see 02) and for denial of service.

### Recipe 3 - Pivot from a DMZ host into the internal network

The DMZ-to-internal boundary is the critical control. Test it.

```bash
# From the DMZ host, what can it reach?
ip route show
nmap -sn 10.0.0.0/8 --max-retries 1 --host-timeout 30s

# If the DMZ host can reach the internal network, use it as a pivot
ssh -D 1080 -N -f user@dmz-host
proxychains4 nmap -sT -p 445,3389,22 10.10.0.0/24

```

If the second scan returns hosts, the DMZ boundary is too permissive.
This is one of the most common findings in internal assessments.

### Recipe 4 - Test a cloud security group boundary

A cloud "topology" is a set of security groups and route tables.
Test whether the private subnet is actually private.

```bash
# From a public subnet host, can it reach the private subnet?
nmap -sn 10.0.2.0/24

# If yes, check the security group rules
aws ec2 describe-security-groups --group-ids sg-0123456789 --query "SecurityGroups[].IpPermissions"

```

A security group that allows 0.0.0.0/0 on an internal port is a
flat topology in the cloud. The subnet is "private" only in name.

### Recipe 5 - Detect a segmentation gap

Segmentation is a topology property. If two subnets that should
not talk to each other can, the segmentation is broken.

```bash
# From subnet A, can you reach subnet B?
ping -c 1 10.20.0.1
nc -zv 10.20.0.10 445

# If either succeeds, the segmentation gap is the finding

```

This is the single most useful test for topology defense. The
answer should be "no", and if it is "yes", that is the report.

## 5. Post-Exploitation

Once you understand the topology, post-exploitation is about
using it deliberately.

**East-west vs north-south:** a foothold in the DMZ is north-south
(the perimeter). To move east-west (server to server inside the
data center), you need to cross the internal segmentation. On a
flat network, there is nothing to cross - east-west is free.

**Pivot choice:** the pivot host should be the one with the widest
reach. On a star topology, that is the hub. On a spine-leaf
topology, that is any host in the same leaf as the target. On a
hub-and-spoke topology, that is the hub.

```bash
# Once on a pivot host, what can it reach?
ip route show
ip -brief addr show
nmap -sn 10.0.0.0/8 --max-retries 1 --host-timeout 30s

```

**Segmentation as an obstacle:** when segmentation is enforced,
each new subnet requires a new exploit. The attacker path becomes
a tree of pivots, not a straight line. This is exactly what
segmentation is for.

**Cloud topology post-exploitation:** once you have an AWS access
key, the "topology" is the IAM policy and the network ACL. The
attack is not to break the topology but to use the API to change
it (open a security group, add a route). This is why cloud
topology security is an IAM problem first and a network problem
second.

**Topology tells you what to report:** the finding is not "we got
in". The finding is "the topology allowed us to reach X from Y,
and the segmentation between Y and Z did not exist". That is the
sentence a defender can act on.


## 6. Preventive Controls

Topology defense is design, not configuration. The controls below
are architectural choices that shape what an attacker can reach.

**Segment by function and trust, not by convenience.**

- Separate user, server, management, and DMZ networks into distinct
  subnets and VLANs.
- Put a firewall between them, not just a router. A router forwards
  by default; a firewall denies by default.
- Do not put internal services in the DMZ to "make them easier to
  reach". The DMZ is for services that must be Internet-facing.

**Enforce the DMZ-to-internal boundary.**

```text
DMZ -> internal: DENY all
DMZ -> internal: ALLOW only specific service-to-service flows
internal -> DMZ: ALLOW only what the DMZ services require
internal -> Internet: ALLOW via a proxy or an explicit egress rule

```

The DMZ-to-internal rule is the most important one in the whole
topology. If it is "any to any", the DMZ is not a boundary.

**East-west segmentation in the data center.**

- Microsegmentation: security groups (cloud) or service mesh policy
  (Kubernetes) per workload, not per subnet.
- Default-deny between application tiers. A web server should not
  reach a database directly; it should reach the API that reaches
  the database.
- Use application identity (mTLS, SPIFFE) when the topology is
  dynamic. IP-based rules do not survive autoscaling.

**Hub-and-spoke hardening.**

- The hub is the concentration point. Harden it first: it is the
  highest-value target and the single point of failure.
- Spoke-to-spoke traffic should go through the hub (not directly),
  so the hub can inspect it.
- A compromised spoke should not be able to route into the hub
  network. Verify this with an explicit test (Recipe 5).

**Cloud topology controls.**

- Public subnets only for load balancers and bastion hosts.
- Private subnets for application and data tiers, with a NAT
  gateway for egress.
- Security groups reference other security groups, not CIDR ranges.
  `sg-web -> sg-app -> sg-db` is a segmentation chain; `0.0.0.0/0
  -> 5432` is a flat topology.
- Treat the topology as code: review every Terraform/CloudFormation
  change that touches a route table or a security group.

**Default-deny is the principle.** Every topology starts permissive
because every device forwards by default. The control is to add
explicit denies. The most common finding in an internal assessment
is that the deny was never written.

## 7. Detection Controls

Topology attacks are detected by watching the boundaries.

**Boundary crossing detection:**
- Traffic from the DMZ to the internal network that is not on the
  allowlist.
- Traffic between application tiers that bypasses the API.
- East-west traffic that is not on the service map.

**Concentration point detection:**
- New hosts connecting to the hub (a new spoke is suspicious if
  there is no change ticket).
- Unusual traffic volume through the hub (a sign of interception
  or exfiltration).
- Route table changes on the hub.

**Cloud topology detection:**
- Security group change events (CloudTrail, Azure Activity Log).
- Route table change events.
- New public IPs on private subnets (a sign of an accidental
  exposure).
- GuardDuty / Security Command Center findings on unusual network
  paths.

**Network flow analysis:** NetFlow / VPC Flow Logs show the actual
topology as it is used, not as it was designed. Compare the two.
The difference is the finding.

**SIEM correlation:** the high-value alert is "new route + new
outbound flow to an unknown destination". Either a legitimate
change or an attacker moving the topology. The correlation tells
you which.

## 8. Verification

How to verify that the topology is what you designed.

**Verify segmentation:**

```bash
# From a host in subnet A, try to reach subnet B
ping -c 1 10.20.0.1
nc -zv 10.20.0.10 445
# Expect: both fail. If either succeeds, the segmentation is broken.

```

**Verify the DMZ boundary:**

```bash
# From a DMZ host, try to reach the internal network
nmap -sn 10.0.0.0/8 --max-retries 1 --host-timeout 30s
# Expect: no live hosts. If hosts respond, the DMZ-to-internal rule is too permissive.

```

**Verify cloud security groups:**

```bash
# From a public subnet host, try to reach a private database port
nc -zv 10.0.2.10 5432
# Expect: connection refused or timeout. If it connects, the database is exposed.

```

**Verify east-west microsegmentation:**

```bash
# From a web server, try to reach a database directly
nc -zv 10.0.3.10 5432
# Expect: denied. The web tier should reach the app tier, not the database.

```

**Verify the concentration point is redundant:**

```bash
# If the hub fails, does the network fail?
# This is a design question, answered by a failover test, not by a command.

```

**The verification habit:** after every topology change, re-run
Recipe 5 (segmentation gap test). The topology is only as good as
its last verified state. A change that silently opens a path is
the most common topology failure.

## 9. Certification Alignment

**CompTIA Network+ (N10-009):**
- Domain 2: Network Implementation - network topologies (star,
  mesh, hub-and-spoke), VLANs, DMZ.
- Domain 4: Network Security - segmentation, DMZ design, defense
  in depth.

**Cisco CCNA (200-301):**
- Domain 1: Network Fundamentals - network topology
  architectures (two-tier, three-tier, spine-leaf, WAN).
- Domain 4: IP Services - NAT, first-hop redundancy (HSRP, VRRP).
- Domain 5: Security Fundamentals - segmentation, DMZ, ACLs.

**Cross-references:**
- The OSI and TCP-IP file covers the layer model this builds on.
- 02 Ethernet and Switching covers the VLAN and STP mechanics that
  implement segmentation at layer 2.
- 03 IP Addressing and Subnetting covers the subnet planning that
  implements segmentation at layer 3.

## 10. Production Notes

**Topology is a security control, not a diagram.** A network
diagram that shows a DMZ but a firewall rule that says "any to
any" is a flat network with a nice picture. The control is the
rule, not the drawing.

**Flat networks are the common failure mode.** Most enterprise
networks are flat at layer 2 and mostly flat at layer 3 for
performance and simplicity. That is also why a single compromised
host can reach almost everything. Segmentation limits the blast
radius, but it costs planning and it costs performance. The
trade-off is a business decision, not a technical one.

**The concentration point is the first target.** In every topology,
there is one place where traffic converges: the hub, the core
switch, the firewall, the VPN concentrator. That is where an
attacker will go first. Harden it first, and monitor it first.

**Cloud topology is code.** In a traditional network, a route table
change is a change ticket and a maintenance window. In a cloud, a
route table change is a `terraform apply`. The speed is the risk:
a single commit can open a private subnet to the Internet. This
is why cloud topology security is an IaC review problem, not just
a network problem.

**Segmentation is verified, not assumed.** The most common finding
in an internal assessment is a segmentation rule that exists on
paper and not in the firewall. Every segmentation claim must be
tested (Recipe 5), and re-tested after every change.

## 11. References

- NIST SP 800-125B - Secure Virtual Network Configuration for Virtual Machine (VM) Protection - https://csrc.nist.gov/pubs/sp/800/125/b/final
- NIST SP 800-41 Rev. 1 - Guidelines on Firewalls and Firewall Policy - https://csrc.nist.gov/pubs/sp/800/41/r1/final
- NIST SP 800-207 - Zero Trust Architecture - https://csrc.nist.gov/pubs/sp/800/207/final
- CIS Controls v8 - Control 12 (Network Infrastructure Management) - https://www.cisecurity.org/controls/network-infrastructure-management
- Cisco - Campus LAN and Wireless LAN Solution Design Guide - https://www.cisco.com/c/en/us/td/docs/solutions/CVD/Campus/cisco-campus-lan-wlan-design-guide.html
- AWS - VPC Security Best Practices - https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-best-practices.html
- Microsoft - Azure Network Security Best Practices - https://learn.microsoft.com/en-us/azure/security/fundamentals/network-best-practices
- CompTIA Network+ exam objectives - https://www.comptia.org/certifications/network
- Cisco CCNA exam topics - https://learningnetwork.cisco.com/s/ccna-exam-topics

