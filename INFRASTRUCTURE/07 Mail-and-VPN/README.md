# Mail and VPN

Remote access and messaging infrastructure: SMTP, IMAP, POP3,
Exchange, and the protocols that carry corporate email; IPsec,
OpenVPN, WireGuard, and SSL VPNs that carry remote workers. Each
file covers the offensive technique and the defensive control.

This is the seventh and final subcategory of `INFRASTRUCTURE/`. Mail
and VPN are grouped because both are edge services: they are exposed
to the internet, they authenticate users, and they are frequent
initial-access vectors.

Writeups and references are in English. Every file follows the
Two-track format (Offensive / Defensive), same 13-section skeleton
as the other INFRASTRUCTURE subcategories.

---

## Scope

| # | File | Offensive focus | Defensive focus |
|---|------|-----------------|-----------------|
| 01 | [Mail Protocols](./01%20Mail%20Protocols.md) | SMTP, IMAP, POP3, Exchange, OWA, autodiscover | TLS, SPF/DKIM/DMARC, MFA, conditional access |
| 02 | [Mail Attacks](./02%20Mail%20Attacks.md) | Open relay, SMTP user enum, IMAP/POP3 brute, NTLM relay, OWA | Relay restrictions, rate limiting, MFA, mail gateway |
| 03 | [VPN Fundamentals](./03%20VPN%20Fundamentals.md) | IPsec, IKE, OpenVPN, WireGuard, SSL VPN, split tunneling | Strong crypto, certificate auth, MFA |
| 04 | [VPN Attacks](./04%20VPN%20Attacks.md) | IKE aggressive mode, OpenVPN CVEs, credential attacks, VPN appliance exploits | Patched firmware, MFA, certificate pinning, monitoring |
| 05 | [Remote Access Defense](./05%20Remote%20Access%20Defense.md) | (defensive focus) | Zero Trust, MFA, conditional access, segmentation, monitoring |

---

## How to use this subcategory

- **Offensive track** - detection, tooling, exploitation recipes.
  Aimed at a pentester with written authorization.
- **Defensive track** - controls, detection rules, verification.
  Aimed at a blue teamer or a sysadmin hardening the same services.

Each file is self-contained. Read `01 Mail Protocols` or
`03 VPN Fundamentals` first if the protocol details are unfamiliar,
then return to the specific attack or defense file.

---

## Relationship to other categories

| Category | Relationship |
|----------|--------------|
| `INFRASTRUCTURE/01 Active Directory` | Exchange and OWA authenticate against AD; NTLM relay targets Exchange. |
| `INFRASTRUCTURE/05 Network Attacks` | NTLM relay (file 06) often targets Exchange or VPN endpoints. |
| `INFRASTRUCTURE/06 Wireless` | VPN is often the only way to reach the internal network from wireless. |
| `APPLICATIONS/01 Web` | OWA and SSL VPN web interfaces are web applications; web attacks apply. |

---

## References

- RFC 5321 - Simple Mail Transfer Protocol
- RFC 3501 - Internet Message Access Protocol
- RFC 1939 - Post Office Protocol - Version 3
- RFC 7208 - Sender Policy Framework (SPF)
- RFC 6376 - DomainKeys Identified Mail (DKIM)
- RFC 7489 - Domain-based Message Authentication (DMARC)
- RFC 7296 - Internet Key Exchange Protocol Version 2 (IKEv2)
- RFC 4301 - Security Architecture for the Internet Protocol (IPsec)
- OpenVPN Protocol documentation
- WireGuard whitepaper
- [MITRE ATT&CK T1071.003 - Mail Protocols](https://attack.mitre.org/techniques/T1071/003/)
- [MITRE ATT&CK T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/)
- NIST SP 800-77 - Guide to IPsec VPNs
- NIST SP 800-113 - Guide to SSL VPNs

---

## Authorized Use Only

All techniques in this subcategory are for **authorized penetration
testing, CTF environments (Hack The Box, OSCP labs), and educational
purposes only**. Attacking mail servers, VPN concentrators, or remote
access infrastructure that you do not own or have written permission
to test is illegal in most jurisdictions.

See the repository [SECURITY.md](../../SECURITY.md) for the full
policy and the abuse-report contact.