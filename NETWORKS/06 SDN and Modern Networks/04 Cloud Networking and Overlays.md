# Cloud Networking and Overlays

## 1. Overview

Cloud networking is software-defined by default. Every cloud provider exposes a virtual network primitive (VPC, VNet, VPC network), subnets, route tables, security groups, network ACLs, load balancers, NAT gateways and peering/transit constructs. These are all controller-driven: the tenant API is the northbound interface to the provider's SDN.

Overlays extend this further. VXLAN, GENEVE and IPsec tunnels decouple tenant addressing from physical underlay, enabling multi-tenant isolation, hybrid connectivity and service mesh traffic.

This file covers cloud network primitives, overlay protocols, hybrid connectivity, and the security model of each layer.

## 2. Threat Model

- **Misconfigured security groups.** Open ingress to `0.0.0.0/0` on sensitive ports is the most common cloud finding.
- **Route table poisoning.** A malicious or accidental route redirects traffic through an attacker-controlled instance.
- **Peering abuse.** Overly permissive VPC peering connects prod to non-prod or to an untrusted tenant.
- **Overlay endpoint spoofing.** Unauthenticated VXLAN/GENEVE accepts traffic from any VTEP.
- **VNI hopping.** Attacker crafts frames with a different VNI to reach another tenant.
- **Metadata service abuse.** SSRF or instance compromise reaches `169.254.169.254` and steals instance credentials.
- **Hybrid link compromise.** IPsec or MPLS link between on-prem and cloud is intercepted or misconfigured.

## 3. How It Works (technical)

Cloud primitives across providers:

- **AWS:** VPC, subnets (public/private/isolated), route tables, security groups (stateful), NACLs (stateless), NAT gateway, internet gateway, VPC peering, Transit Gateway, PrivateLink, VPC endpoints.
- **Azure:** Virtual Network (VNet), subnets, NSG (stateful), route tables (UDR), Azure Firewall, VPN Gateway, ExpressRoute, VNet peering, Private Endpoint.
- **GCP:** VPC network (global), subnets (regional), firewall rules (stateful, hierarchical), routes, Cloud NAT, Cloud VPN, Cloud Interconnect, VPC peering, Private Service Connect.

Overlay protocols:

- **VXLAN (RFC 7348)** - 24-bit VNI, UDP/4789, MAC-in-UDP. Common in data center fabrics (EVPN-VXLAN).
- **GENEVE (RFC 8926)** - extensible metadata, UDP/6081. Used by OVN, VMware NSX, and some cloud SDNs.
- **IPsec** - hybrid cloud VPN, encrypted tunnels, IKEv1/IKEv2.
- **WireGuard** - modern, simpler VPN, common in cloud-to-cloud and zero-trust overlays.
- **GRE** - legacy, no encryption; usually combined with IPsec.

Hybrid connectivity options:

- **Site-to-site VPN** - IPsec over the internet, cheapest, variable latency.
- **Dedicated interconnect** - AWS Direct Connect, Azure ExpressRoute, GCP Cloud Interconnect. Private, expensive, higher SLA.
- **SD-WAN overlays** - vendor-managed overlay over multiple underlays.

## 4. Installation and Setup

Terraform for an AWS VPC (abbreviated):

```hcl
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}
resource "aws_subnet" "private" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}
resource "aws_security_group" "restricted" {
  vpc_id = aws_vpc.main.id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
```

Linux VXLAN lab (two hosts):

```bash
ip link add vxlan0 type vxlan id 100 remote 192.0.2.2 dstport 4789 dev eth0
ip link set vxlan0 up
ip addr add 10.100.0.1/24 dev vxlan0
```

Verify:

```bash
ip -d link show vxlan0
bridge fdb show dev vxlan0
```

## 5. Hardening and Configuration

- **Deny-by-default security groups.** No `0.0.0.0/0` ingress on anything except intended public load balancers. Use security-group references, not CIDR blocks, for internal east-west traffic.
- **Private subnets for workloads.** Public subnets only for load balancers and bastions. NAT gateway for egress.
- **VPC flow logs.** Enable in every VPC/VNet, ship to a central SIEM.
- **Private endpoints.** Use AWS PrivateLink, Azure Private Endpoint, GCP Private Service Connect for cloud services; no traffic over public internet.
- **Peering review.** Every peering has a documented owner, purpose and scope. No transitive routing unless intentional.
- **Overlay authentication.** VXLAN does not authenticate. Use IPsec underneath, or a control plane (EVPN) with authentication.
- **Metadata service hardening.** IMDSv2 mandatory on AWS; disable legacy IMDS. On Azure/GCP, restrict metadata reachability with network policy.
- **Hybrid encryption.** IPsec with strong IKEv2 parameters, certificate-based authentication, no pre-shared keys for production.

## 6. Operational Usage

- **Network as code.** VPC/VNet definitions in Terraform, reviewed, applied by pipeline.
- **Segmentation.** Separate accounts/subscriptions/projects per environment; no prod/dev network overlap.
- **Egress control.** Central egress VPC with firewalls; no direct internet egress from workload subnets.
- **Flow log review.** Anomalous egress or ingress is a first-class alert.
- **Hybrid monitoring.** Tunnel state, BGP session state, packet loss and latency on the interconnect.

## 7. Common Mistakes

- `0.0.0.0/0` on SSH/RDP "temporarily" - and it stays.
- Overlapping CIDRs between on-prem and cloud, breaking hybrid routing.
- VPC peering between prod and dev "for convenience".
- VXLAN without IPsec - plaintext tenant traffic on the underlay.
- No flow logs; incidents are invisible.
- Relying on security groups alone, no NACL defense in depth.
- Long-lived IAM credentials in workloads instead of instance roles.

## 8. Attacks Against It

- **Security group enumeration and abuse.** From a compromised instance, enumerate reachable services; misconfigured groups give lateral movement.
- **Route table manipulation.** Attacker with sufficient IAM modifies a route to a rogue NAT or transit gateway, capturing traffic.
- **Metadata service theft (SSRF).** `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` returns temporary credentials; on IMDSv1, works without a token.
- **VXLAN VNI hopping.** Craft frames with a different VNI; if the VTEP does not enforce VNI isolation, reach another tenant.
- **BGP hijack over hybrid.** Announce routes for cloud prefixes from the on-prem side; intercept traffic.
- **DNS exfiltration.** Use DNS queries from cloud workloads to exfiltrate data, bypassing egress filtering that only blocks HTTP.

## 9. Detection (Blue Team)

- **Flow log analysis.** Unusual destinations, high-volume egress, connections to known-bad IPs.
- **Security group change audit.** CloudTrail / Activity Log / Cloud Audit Logs on security group and route table changes.
- **Metadata service access.** Alert on IMDS access from unexpected processes or external sources.
- **Peering change audit.** Any new VPC peering or transit gateway attachment.
- **Overlay anomalies.** Unexpected VTEP IPs, VNI mismatch errors on VTEPs.
- **Hybrid tunnel flapping.** BGP session drops, IPsec rekeys, tunnel up/down events.

## 10. Case Studies

- **Capital One (2019).** SSRF through a misconfigured WAF reached the EC2 metadata service and exposed IAM role credentials for an S3 bucket; 100M+ records exfiltrated. Root cause: IMDSv1 + overly permissive IAM role + misconfigured security group.
- **CodeSpace (2023).** GitHub Actions OIDC misconfiguration allowed attackers to obtain cloud credentials; demonstrates identity-layer attacks against cloud networking.
- **BGP hijacks of cloud prefixes.** Multiple incidents where cloud-hosted prefixes were hijacked at the BGP level, redirecting traffic before it reached the cloud.

## 11. Legal and Ethical Notes

Cloud networking controls (security groups, route tables, VPC peering) belong to the account owner. Testing them requires explicit authorization that names the account, the region and the resources. Enumerating or modifying another tenant's cloud network is unauthorized access. Lab accounts (personal AWS/Azure/GCP free tier, or dedicated test accounts) are the correct environment.

## 12. Production Notes

- **Account-per-environment.** Prod, staging, dev in separate accounts/subscriptions/projects with separate network boundaries.
- **Centralized egress.** A dedicated egress VPC/VNet with firewalls, logged and monitored.
- **Network changes through pipeline.** Direct console changes to security groups or route tables are audited and reverted.
- **Cost controls on NAT and egress.** Unexpected egress volume can be an attack (data exfiltration) or a misconfiguration.
- **Multi-region design.** DR region has the same network controls; no "temporary" weaker rules.
- **Periodic peering and interconnect review.** Remove stale peerings and unused interconnects.

## 13. Certification Alignment

- **CompTIA Network+** - cloud networking concepts, VPN, network segmentation.
- **Cisco CCNA** - basic cloud networking and VPN.
- **AWS Advanced Networking Specialty** - VPC design, hybrid connectivity, Direct Connect, Transit Gateway.
- **Azure Network Engineer Associate (AZ-700)** - VNet design, hybrid connectivity, ExpressRoute, Private Endpoint.
- **GCP Cloud Network Engineer** - VPC design, Interconnect, VPN, Private Service Connect.
- **Cross-reference:** CLOUD category for provider-specific deep dives.

## References

- AWS VPC Documentation - https://docs.aws.amazon.com/vpc/
- Azure Virtual Network Documentation - https://learn.microsoft.com/en-us/azure/virtual-network/
- Google Cloud VPC Documentation - https://cloud.google.com/vpc/docs
- RFC 7348 - Virtual eXtensible Local Area Network (VXLAN) - https://datatracker.ietf.org/doc/html/rfc7348
- RFC 8926 - Geneve: Generic Network Virtualization Encapsulation - https://datatracker.ietf.org/doc/html/rfc8926
- NIST SP 800-125B - Secure Virtual Network Configuration for Virtual Machine (VM) Protection - https://csrc.nist.gov/pubs/sp/800/125/b/final
- AWS Security Best Practices for VPC - https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-best-practices.html
