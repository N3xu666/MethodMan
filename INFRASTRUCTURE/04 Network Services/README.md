# Network Services

Offensive and defensive reference for core network services: DNS, DHCP,
NTP, SNMP, LDAP, Kerberos, and common auxiliary services (SMTP relay,
NFS, SMB host-level, Rsync, FTP). This subcategory covers the services
themselves and their protocol-level attacks; Active Directory-specific
Kerberos/LDAP attacks live in `01 Active Directory`.

This subcategory uses the two-track format (Offensive / Defensive). See
the parent [INFRASTRUCTURE README](../README.md) for the format skeleton.

## Files

| # | File | Focus |
|---|------|-------|
| 01 | [DNS](./01%20DNS.md) | Zones, records, zone transfer, cache poisoning, DNSSEC |
| 02 | [DHCP and NTP](./02%20DHCP%20and%20NTP.md) | Rogue DHCP, DHCP spoofing, NTP amplification, time attacks |
| 03 | [SNMP](./03%20SNMP.md) | Community strings, MIB walking, RCE via SNMP, SNMPv3 |
| 04 | [LDAP and Kerberos](./04%20LDAP%20and%20Kerberos.md) | Anonymous bind, LDAP injection, Kerberos service enum, AS-REP/Kerberoast (host-level) |
| 05 | [Other Services](./05%20Other%20Services.md) | SMTP relay, NFS, SMB (host-level), Rsync, FTP |

## Scope

**In scope:**

- DNS servers (BIND, Windows DNS, dnsmasq, PowerDNS, CoreDNS).
- DHCP servers (ISC DHCP, Windows DHCP, dnsmasq).
- NTP servers (ntpd, chrony, Windows Time).
- SNMP agents (net-snmp, Windows SNMP).
- LDAP directories (OpenLDAP, 389 Directory Server, Active Directory).
- Kerberos KDCs (MIT Kerberos, Heimdal, Active Directory).
- Auxiliary services: SMTP relay, NFS, SMB (host-level), Rsync, FTP.

**Out of scope:**

- Active Directory domain attacks (Kerberoasting, DCSync, trusts) -
  see `01 Active Directory`.
- Web application attacks on services - see `APPLICATIONS`.
- Cloud-managed services (Route 53, Azure DNS) - see the CLOUD
  category.

## Related Resources

- [MITRE ATT&CK - Enterprise: Discovery](https://attack.mitre.org/tactics/TA0007/)
- [MITRE ATT&CK - Enterprise: Collection](https://attack.mitre.org/tactics/TA0009/)
- [IANA Service Name and Transport Protocol Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)
- [HackTricks - Network Services Pentesting](https://book.hacktricks.xyz/network-services-pentesting)
- [PayloadsAllTheThings - Network](https://github.com/swisskyrepo/PayloadsAllTheThings)