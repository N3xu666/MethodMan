# 02 Routing and Switching

How routers and switches decide where a packet goes, and how
those decisions are attacked. This subcategory covers the routing
table, the dynamic routing protocols that fill it, the switching
fabric that carries the traffic, and the attacks that target both.

## Scope

- Static routing, longest prefix match, administrative distance.
- Dynamic routing protocols: OSPF, EIGRP, BGP, RIP.
- Advanced switching: STP (802.1D, RSTP, MST), EtherChannel, VPC.
- Routing attacks: OSPF/BGP hijacking, route injection, HSRP/VRRP
  takeover.
- Routing defense: route authentication, uRPF, prefix filtering,
  RPKI.

## Files

| # | File | Format |
|---|------|--------|
| 01 | Routing Fundamentals (planned) | Two-track |
| 02 | Dynamic Routing Protocols (planned) | Two-track |
| 03 | Switching Advanced (planned) | Two-track |
| 04 | Routing Attacks (planned) | Two-track |
| 05 | Routing Defense (planned) | Two-track |

All five files are planned for this subcategory.

## Format

Two-track (Offensive / Defensive). See the category
[README](../README.md) for the full skeleton.

## Related

- [01 Network Fundamentals](../01%20Network%20Fundamentals/) - the
  OSI/TCP-IP, Ethernet, IP addressing and topology basics this
  subcategory builds on.
- [04 Network Protocols](../04%20Network%20Protocols/) - the
  transport and application protocols that ride on these routes.

## Certification Alignment

- **Network+:** Network Implementation (routing concepts, routing
  table), Network Troubleshooting.
- **CCNA:** IP Connectivity (routing table, static routes, OSPF),
  Network Access (VLANs, STP, EtherChannel).
- **CCNP:** advanced routing (OSPF areas, BGP, route filtering).

## References

- RFC 2328 (OSPF Version 2) - https://www.rfc-editor.org/rfc/rfc2328
- RFC 4271 (BGP-4) - https://www.rfc-editor.org/rfc/rfc4271
- RFC 2453 (RIP Version 2) - https://www.rfc-editor.org/rfc/rfc2453
- IEEE 802.1D (MAC Bridges / STP) - https://standards.ieee.org/ieee/802.1D/6234/
- Cisco - IP Routing Configuration Guide - https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute/configuration/15-mt/iproute-15-mt-book.html
- CompTIA Network+ exam objectives - https://www.comptia.org/certifications/network
- Cisco CCNA exam topics - https://learningnetwork.cisco.com/s/ccna-exam-topics

