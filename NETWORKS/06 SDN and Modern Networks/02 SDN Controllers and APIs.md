# SDN Controllers and APIs

## 1. Overview

The SDN controller is the brain of a software-defined network. It discovers topology, computes forwarding state, enforces policy and exposes APIs to applications and operators. Every controller exposes at least two API surfaces: a southbound interface to the forwarding devices and a northbound interface to automation, dashboards and orchestrators.

This file covers the major controller platforms, their API surface, the authentication and authorization models, and the attack paths that apply to each interface.

## 2. Threat Model

- **Unauthenticated northbound API.** REST/gRPC reachable without credentials or with default ones.
- **Weakly authorized API.** A valid low-privilege token can change policy (IDOR, missing role checks).
- **Southbound channel without TLS.** OpenFlow/NETCONF/gNMI traffic readable and injectable on the wire.
- **Controller application supply chain.** Malicious or vulnerable app installed into the controller runtime.
- **Controller clustering (east-west) abuse.** A rogue node joins the cluster and receives full state.
- **Credential and key theft.** Service account tokens, client certificates, API keys stored insecurely on automation hosts.

## 3. How It Works (technical)

Major controller platforms:

- **OpenDaylight (ODL)** - Java, modular, OSGi-based. Northbound: RESTCONF, NETCONF. Southbound: OpenFlow, NETCONF, P4, OVSDB. Widely deployed in telco and enterprise.
- **ONOS** - Java, carrier-grade, cluster-oriented. Northbound: REST, gRPC. Southbound: OpenFlow, NETCONF, P4Runtime.
- **Ryu** - Python, lightweight, learning-oriented. Northbound: REST. Southbound: OpenFlow.
- **Cisco APIC / DNA Center** - vendor controllers with REST APIs, role-based access, certificate-based authentication.
- **VMware NSX Manager** - policy and data-plane controller for NSX-T/NSX-V. REST API, role-based access.
- **Cloud SDN controllers** - AWS VPC, Azure Virtual Network, GCP VPC are controller-based; the tenant-facing API is the cloud control-plane API.

API surface per controller:

- **Northbound API** - REST, gRPC, GraphQL. Auth models: basic auth, bearer token, API key, OAuth2, mTLS.
- **Southbound API** - OpenFlow, NETCONF, gNMI, P4Runtime, OVSDB. Auth models: TCP (insecure), TLS with controller-side certificate, per-switch certificate.
- **East-west API** - clustering protocol, Raft/RAFT-based for distributed controllers, or proprietary.

## 4. Installation and Setup

Ryu lab controller:

```bash
pip install ryu
ryu-manager ryu.app.simple_switch_13
```

Simple switch app exposes a REST endpoint on TCP/8080 (the WebSocket API for topology).

ONOS in Docker:

```bash
docker run -d --name onos -p 8181:8181 -p 8101:8101 -p 6653:6653 onosproject/onos
curl -u onos:rocks http://localhost:8181/onos/v1/devices
```

Default credentials `onos:rocks` are a lab default and must never exist in production.

OpenDaylight (release Boron or later):

```bash
docker run -d --name odl -p 8181:8181 -p 6633:6633 -p 1830:1830 opendaylight/opendaylight
curl -u admin:admin http://localhost:8181/restconf/operational/opendaylight-inventory:nodes
```

## 5. Hardening and Configuration

- **Disable default accounts.** `onos:rocks`, `admin:admin`, `karaf:karaf` are documented defaults and a top finding.
- **Enforce mTLS on southbound.** Each switch presents a unique certificate. Controller rejects unknown devices.
- **Role-based access on northbound.** Read-only tokens for monitoring, write tokens only for the orchestrator, scoped per tenant and per operation.
- **Network placement.** Northbound API on a dedicated management network, never exposed to user or data-plane subnets.
- **API rate limits and audit.** Every write operation logged with user, source IP, payload hash.
- **Application allowlist.** Only signed controller applications from a trusted internal repository. Unsigned or third-party apps rejected at install.
- **Cluster join authentication.** East-west cluster joins require a shared secret or per-node certificate; no anonymous joins.
- **Version hygiene.** Controllers have a long CVE history (ODL, ONOS, NSX); patch quarterly at minimum.

## 6. Operational Usage

- **Onboarding:** new switch authenticates with client certificate, controller accepts and pushes baseline policy.
- **Policy changes:** via orchestrator (Ansible, Terraform) that holds a scoped token; no manual curl to the API.
- **Monitoring:** read-only token used by Prometheus/Grafana scrapers; alerts on flow-mod rate and API error rate.
- **Break-glass:** a documented, audited procedure for emergency direct access, with a time-boxed elevated token.

## 7. Common Mistakes

- Exposing the northbound API on the internet "just for the dashboard".
- Sharing one API token across every automation tool.
- Running the controller cluster over an unencrypted east-west link.
- Allowing unsigned third-party apps into the controller runtime.
- Leaving `onos:rocks` in production because "it is only reachable internally".
- No audit log retention for API writes.

## 8. Attacks Against It

- **Default credential login.** Automated scanning of TCP/8181, 8181, 6653, 1830 on public IPs; ONOS and ODL default accounts are well documented.
- **REST API enumeration.** `/onos/v1/devices`, `/restconf/operational/...`, `/api/v1/...` returning full topology to an unauthenticated user.
- **Token theft from CI/CD.** API token committed to a repository or stored as a plaintext environment variable; any reader gains write access to the fabric.
- **Southbound MITM.** ARP spoofing between switch and controller on a flat management VLAN captures OpenFlow, which may be replayed or modified.
- **Malicious controller app.** Uploading a signed-in-name-only OAR/KAR file that opens a reverse shell from the controller.
- **Cluster poisoning.** A rogue node with valid cluster credentials receives full state and can serve poisoned policy.

## 9. Detection (Blue Team)

- **Authentication events.** Failed logins, logins with default accounts, logins from unexpected source IPs.
- **API write burst.** High rate of northbound write operations outside change windows.
- **Southbound plaintext.** Zeek or Suricata rule detecting OpenFlow on TCP/6653 without TLS.
- **New controller app install.** Alert on any KAR/OAR/app install event.
- **Cluster membership change.** Any new node joining or leaving the east-west cluster.
- **Certificate anomaly.** Switch presenting a certificate not in the approved inventory.

## 10. Case Studies

- **ONOS and ODL on Shodan.** Multiple public scans have found ONOS and OpenDaylight controllers with default credentials or no authentication, exposing full network topology and allowing flow programming.
- **NSX Manager vulnerabilities.** CVE-2021-39144 (NSX-T) and related NSX CVEs allowed authenticated tenant-to-admin escalation and, in some cases, unauthenticated RCE. Centralized controllers are high-value targets.
- **Cisco DNA Center.** Multiple CVEs (e.g. CVE-2023-20188) allowed authenticated command injection on the controller host; exploited in the wild against unpatched deployments.

## 11. Legal and Ethical Notes

A production SDN controller is critical infrastructure. Querying its API, fuzzing its endpoints or uploading an app is equivalent to touching the network fabric. Testing is legal only with explicit written authorization that names the controller, the API endpoints and the change window. Lab controllers (Ryu, ONOS, ODL in Docker) are the correct place to practice.

## 12. Production Notes

- **Controller as Tier-0 asset.** Treat it in the same class as a domain controller or a cloud management plane.
- **Separate management and data planes.** The controller must not share an L2 segment with user traffic.
- **Backup before upgrade.** Controller configuration, apps, and custom pipeline state must be exportable and restorable.
- **Change control on API tokens.** Tokens rotate on a schedule; rotation is audited.
- **Redundancy.** At least three controller nodes; quorum loss must fail safe, not open.

## 13. Certification Alignment

- **CompTIA Network+** - SDN and controller-based networking concepts.
- **Cisco CCNA** - DNA Center and controller-based networking, REST API basics.
- **Cisco DEVASC** - controller APIs, RESTCONF/NETCONF, model-driven programmability.
- **Cisco CCNP** - advanced controller and fabric design (SD-Access, SD-WAN).
- **Cross-reference:** CLOUD category for cloud provider SDN controllers (AWS VPC, Azure VNet, GCP VPC).

## References

- OpenDaylight Documentation - https://docs.opendaylight.org/
- ONOS Project Documentation - https://wiki.onosproject.org/
- Ryu SDN Framework - https://ryu.readthedocs.io/
- Cisco DNA Center API Reference - https://developer.cisco.com/docs/dna-center/
- VMware NSX Documentation - https://docs.vmware.com/en/VMware-NSX/index.html
- NIST SP 800-125B - Secure Virtual Network Configuration for Virtual Machine (VM) Protection - https://csrc.nist.gov/pubs/sp/800/125/b/final
