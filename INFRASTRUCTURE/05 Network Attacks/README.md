# Network Attacks

Layer 2 through Layer 4 attacks against enterprise networks - MITM,
VLAN hopping, DNS/DHCP abuse, routing manipulation, pivoting and
network-level password attacks. Each file covers the offensive
technique and the defensive control that stops it.

This is the fifth subcategory of `INFRASTRUCTURE/`. It complements
`04 Network Services` (which describes how the protocols work) by
describing how they are abused.

Writeups and references are in English. Every file follows the
Two-track format (Offensive / Defensive), same 13-section skeleton
as the other INFRASTRUCTURE subcategories.

---

## Scope

| # | File | Offensive focus | Defensive focus |
|---|------|-----------------|-----------------|
| 01 | [MITM and ARP Spoofing](./01%20MITM%20and%20ARP%20Spoofing.md) | ARP cache poisoning, SSL stripping, bettercap | Dynamic ARP Inspection, port security, 802.1X |
| 02 | [VLAN and Layer 2 Attacks](./02%20VLAN%20and%20Layer%202%20Attacks.md) | VLAN hopping, DTP, STP, MAC flooding | Native VLAN hygiene, BPDU Guard, Root Guard |
| 03 | [DNS and DHCP Attacks](./03%20DNS%20and%20DHCP%20Attacks.md) | DNS spoofing, rogue DHCP, DNS tunneling | DNSSEC, DHCP snooping, DNS sinkholes |
| 04 | [Routing Attacks](./04%20Routing%20Attacks.md) | BGP hijack, OSPF/HSRP/VRRP, ICMP redirects | Routing authentication, prefix filtering, TTL security |
| 05 | [Pivoting and Tunneling](./05%20Pivoting%20and%20Tunneling.md) | SSH tunnels, chisel, ligolo-ng, proxychains | Egress filtering, TLS inspection, network segmentation |
| 06 | [Password Attacks](./06%20Password%20Attacks.md) | Responder, NTLM relay, LLMNR/NBT-NS, Kerberos | SMB signing, LDAP signing, EPA, disable LLMNR/NBT-NS |

---

## How to use this subcategory

- **Offensive track** - detection, tooling, exploitation recipes.
  Aimed at a pentester with written authorization.
- **Defensive track** - controls, detection rules, verification.
  Aimed at a blue teamer or a sysadmin hardening the same network.

Each file is self-contained. Read the relevant protocol reference in
`04 Network Services` first if the mechanism is unfamiliar, then
return here for the abuse and the control.

---

## Relationship to other categories

| Category | Relationship |
|----------|--------------|
| `INFRASTRUCTURE/04 Network Services` | Describes the protocols (DNS, DHCP, SNMP, LDAP). This subcategory describes their abuse. |
| `INFRASTRUCTURE/01 Active Directory` | Password attacks here (Responder, NTLM relay) feed AD credential abuse there. |
| `INFRASTRUCTURE/03 Linux Infrastructure` | Pivoting techniques reuse the Linux tooling described there. |
| `APPLICATIONS/01 Web` | Egress filtering and TLS inspection (file 05) affect web exploitation paths. |

---

## References

- [MITRE ATT&CK - Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [NIST SP 800-115 - Technical Guide to Information Security Testing](https://csrc.nist.gov/publications/detail/sp/800-115/final)
- [CIS Controls v8](https://www.cisecurity.org/controls)
- RFC 826 (ARP), RFC 2131 (DHCP), RFC 1035 (DNS), RFC 4271 (BGP)

---

## Authorized Use Only

All techniques in this subcategory are for **authorized penetration
testing, CTF environments (Hack The Box, OSCP labs), and educational
purposes only**. Running ARP spoofing, rogue DHCP, or routing attacks
against a network you do not own or have written permission to test is
illegal in most jurisdictions.

See the repository [SECURITY.md](../../SECURITY.md) for the full
policy and the abuse-report contact.