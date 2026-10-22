# SDN Fundamentals

## 1. Overview

Software-Defined Networking (SDN) separates the network's control plane (where forwarding decisions are made) from its data plane (where packets are actually forwarded). Instead of each device running its own distributed control logic, a centralized SDN controller computes forwarding state and programs the data plane through a standardized interface.

This separation enables programmatic network management, centralized policy, faster convergence and vendor-neutral automation. It also introduces new attack surface: the controller, the southbound API and the management plane become high-value targets.

This file covers the core model, planes, interfaces, deployment models and the security-relevant properties of each layer.

## 2. Threat Model

- **Attacker with management-plane access.** Compromise of the controller or its API means control over the entire fabric.
- **Attacker on the southbound channel.** Unauthenticated or weakly authenticated control traffic (OpenFlow, NETCONF, gNMI) can be injected or replayed to reprogram forwarding.
- **Attacker on the northbound API.** REST/gRPC API abuse, IDOR, missing authorization allows policy changes without controller takeover.
- **Insider or supply-chain.** Malicious or trojanized controller application, plugin or pipeline.
- **Data-plane attacker.** Traditional L2/L3 attacks still apply on the data plane and are not mitigated by SDN alone.

## 3. How It Works (technical)

Three planes:

- **Data plane** - forwarding devices (switches, routers, virtual switches). They forward based on flow/forwarding tables.
- **Control plane** - computes topology and forwarding state. In classic networks it is distributed (each device runs routing protocols). In SDN it is centralized in the controller.
- **Management plane** - operational tooling: dashboards, orchestration, monitoring, policy engines.

Interfaces:

- **Southbound API** - controller to data plane. Examples: OpenFlow, P4Runtime, NETCONF, gNMI, OVSDB.
- **Northbound API** - applications to controller. Examples: REST, gRPC, GraphQL.
- **East-west API** - controller to controller (federation, clustering).

SDN deployment models:

- **Centralized** - one controller cluster manages the whole domain.
- **Distributed** - multiple controllers with east-west synchronization.
- **Hybrid** - SDN fabric interworking with classic L2/L3 devices.

Overlay vs underlay:

- **Underlay** - the physical IP fabric carrying encapsulated traffic.
- **Overlay** - tunnels (VXLAN, GENEVE, GRE, IPsec) carrying tenant or segment traffic over the underlay.

## 4. Installation and Setup

For lab work:

- **Mininet** - emulates an SDN topology with Open vSwitch and a controller. `sudo apt install mininet`.
- **Open vSwitch** - production-grade virtual switch. `sudo apt install openvswitch-switch`.
- **Ryu or ONOS** - open-source controllers. Ryu is the simplest for learning: `pip install ryu`.
- **Containerlab** - containerized network topologies with real NOS images (Nokia SR Linux, Arista cEOS, FRR).

Minimal Mininet + Ryu lab:

```bash
sudo mn --controller=remote,ip=127.0.0.1 --switch=ovsk,protocols=OpenFlow13 --topo=tree,2
```

Verify flow tables:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

Expected output shows `priority`, `match` and `actions` fields programmed by the controller.

## 5. Hardening and Configuration

- **Mutual TLS on every control channel.** Southbound and northbound APIs must require client certificates. OpenFlow over plain TCP is a defect.
- **Role-based access on the controller.** Separate read-only monitoring from write policy changes. Enforce least privilege per application.
- **Network segmentation for the control plane.** The controller must live in a dedicated management VLAN with strict ACLs; data-plane hosts must never reach it.
- **Disable unused southbound and northbound endpoints.** Default-enabled demo apps and gRPC reflection are common findings.
- **Firmware and controller version pinning.** SDN stacks age badly; unpatched controllers have known CVEs.
- **Logging and flow auditing.** Export flow-mod events and controller audit logs to a SIEM. Changes to forwarding state must be attributable.

## 6. Operational Usage

Day-to-day:

- **Topology discovery:** controller maintains a live view; export to monitoring.
- **Policy as code:** northbound API used by automation to apply ACLs, segments, QoS.
- **Flow troubleshooting:** `ovs-ofctl dump-flows`, `ovs-appctl ofproto/trace`, controller GUI.
- **Change management:** every policy change through version control and review; no ad-hoc API calls in production.

## 7. Common Mistakes

- Running OpenFlow over plain TCP "because it works".
- Leaving the controller REST API with default credentials.
- Treating the SDN controller as just another management server - it is a Tier-0 asset.
- Assuming SDN eliminates L2 attacks; it does not, it only changes where policy is enforced.
- Flat management networks where the controller is reachable from user VLANs.

## 8. Attacks Against It

- **Controller takeover** - default or weak credentials, exposed REST API, unpatched CVE.
- **Southbound injection** - spoofed OpenFlow messages reprogram flows; possible when the channel is unauthenticated or the switch accepts connections from any IP.
- **Northbound API abuse** - IDOR, missing authorization, mass assignment on policy objects.
- **Flow table poisoning** - malicious controller app installs drop or redirect rules.
- **Overlay attacks** - VXLAN/GENEVE tunnel endpoint spoofing, VNI hopping, unauthenticated tunnel endpoints.

## 9. Detection (Blue Team)

- **Unexpected flow-mods.** Alert on flow-mod events from unknown controller IPs or outside change windows.
- **Southbound connection anomalies.** Switches connecting to unknown controllers, plaintext OpenFlow on the wire (detect with Zeek `openflow` analyzer).
- **API access logs.** Anomalous northbound API calls (unusual user agent, high rate, writes from new source).
- **Configuration drift.** Compare running flow tables against the intended policy baseline.
- **East-west anomalies.** Unexpected controller-to-controller peering.

## 10. Case Studies

- **Unprotected OpenFlow deployments.** Research and CTF scenarios have shown that a switch accepting OpenFlow from any source can be reprogrammed to mirror or drop traffic without touching the controller.
- **Exposed controller dashboards.** Shodan regularly surfaces ONOS, OpenDaylight and Ryu management interfaces on the public internet; several have default or no authentication.
- **Cloud SDN control plane exposure.** Public cloud virtual networks are SDN; misconfigured security groups or route tables are effectively northbound API abuse by a tenant.

## 11. Legal and Ethical Notes

SDN controllers are critical infrastructure. Testing them without explicit written authorization is illegal in most jurisdictions and can cause immediate, broad outages. Lab work (Mininet, containerlab, personal cloud accounts) is the correct environment. Never scan or interact with SDN control planes you do not own or are not contracted to test.

## 12. Production Notes

- **Controller HA is mandatory.** A single controller is a single point of failure and a single point of compromise.
- **Backup controller configuration and policy.** Restore must be tested.
- **Version control for policy.** Northbound-driven policy must be reproducible from source.
- **Change windows.** Flow-mod bursts during business hours are usually a mistake, not an attack - but they must be logged either way.
- **Segregate test and production controllers.** A compromised lab controller must not reach production switches.

## 13. Certification Alignment

- **CompTIA Network+** - network architecture, SDN and virtualization concepts, cloud connectivity.
- **Cisco CCNA** - controller-based networking, automation and programmability (DNA Center concept, REST APIs).
- **Cisco DEVASC** - SDN controllers, northbound and southbound APIs, model-driven programmability (YANG, NETCONF, RESTCONF).
- **Cross-reference:** CLOUD category (AWS Advanced Networking, Azure Network Engineer, GCP Cloud Network Engineer) for cloud SDN underlays.

## References

- RFC 7426 - Software-Defined Networking (SDN): Layers and Architecture Terminology - https://datatracker.ietf.org/doc/html/rfc7426
- Open Networking Foundation - SDN Architecture - https://opennetworking.org/
- Open vSwitch Documentation - https://docs.openvswitch.org/
- Mininet Documentation - https://mininet.org/
- NIST SP 800-125B - Secure Virtual Network Configuration for Virtual Machine (VM) Protection - https://csrc.nist.gov/pubs/sp/800/125/b/final
