# NETWORKS

Network engineering and security reference. Covers the
fundamentals of how packets move, how devices are configured, how
traffic is analyzed, and where the attack surface lives.

This category is written in the **two-track** format (Offensive /
Defensive): every file covers both how an attacker abuses a
technology and how a defender hardens it.

> [!CAUTION]
> Authorized use only. All material is provided for educational purposes and authorized testing.
> See [../SECURITY.md](../SECURITY.md) for the full policy.
## Scope

- OSI and TCP/IP models, encapsulation, addressing.
- Ethernet, switching, VLANs, spanning tree.
- IP addressing, subnetting, routing, NAT.
- Network devices: routers, switches, firewalls, load balancers,
  proxies, IDS/IPS.
- Protocols: ARP, ICMP, TCP, UDP, DNS, DHCP, HTTP, TLS, and
  others.
- Traffic analysis and forensics: packet capture, flow analysis,
  log correlation.
- Modern networks: SDN, SD-WAN, network automation, zero trust.

## Subcategories

| # | Subcategory | Files | Certifications |
|---|-------------|-------|----------------|
| 01 | [Network Fundamentals](./01%20Network%20Fundamentals/) | 4 | Network+, CCNA |
| 02 | [Routing and Switching](./02%20Routing%20and%20Switching/) | 5 | Network+, CCNA, CCNP |
| 03 | [Network Devices](./03%20Network%20Devices/) | 4 | CCNA, CCNP, JNCIA |
| 04 | [Network Protocols](./04%20Network%20Protocols/) | 5 | Network+, CCNA |
| 05 | [Traffic Analysis and Forensics](./05%20Traffic%20Analysis%20and%20Forensics/) | 5 | CyberOps, CySA+ |
| 06 | [SDN and Modern Networks](./06%20SDN%20and%20Modern%20Networks/) | 5 | (cross-ref CLOUD) |

## Format

Files in this category follow the two-track skeleton:

```text
## 1. Overview
## 2. Reconnaissance / Enumeration
## 3. Common Attack Vectors
## 4. Exploitation Recipes
## 5. Post-Exploitation
## 6. Preventive Controls
## 7. Detection Controls
## 8. Verification
## 9. Certification Alignment
## 10. Production Notes
## 11. References
```

The Offensive track covers sections 2-5 (recon through
post-exploitation). The Defensive track covers sections 6-8
(preventive controls, detection, verification). Section 9 maps the
content to certification objectives.

## Certifications

See [CERTIFICATIONS.md](./CERTIFICATIONS.md) for the full list of
certifications this category supports and which subcategories
cover which exam domains.

## References

- CompTIA Network+ exam objectives - https://www.comptia.org/certifications/network
- Cisco CCNA exam topics - https://learningnetwork.cisco.com/s/ccna-exam-topics
- RFC Editor - https://www.rfc-editor.org/
- NIST SP 800-41 Rev. 1 (Guidelines on Firewalls and Firewall Policy) - https://csrc.nist.gov/pubs/sp/800/41/r1/final
- Wireshark User Guide - https://www.wireshark.org/docs/wsug_html_chunked/

