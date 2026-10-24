# Infrastructure Security

Offensive and defensive reference for enterprise infrastructure: Active
Directory, Windows and Linux hosts, network services, network attacks,
wireless, and mail/VPN.

This category uses a **two-track format**: every file covers both the
**Offensive** side (enumeration, attack vectors, exploitation recipes,
post-exploitation) and the **Defensive** side (risk context, root causes,
preventive controls, detection controls, verification). Section headers
carry no suffix - the two tracks are named Offensive and Defensive
explicitly inside each file.

> [!CAUTION]
> Authorized use only. All techniques here are for OSCP labs, Hack The Box, and explicitly authorized penetration tests. See [../SECURITY.md](../SECURITY.md) for the full policy.
## Structure

| # | Subcategory | Focus |
|---|-------------|-------|
| 01 | [Active Directory](./01%20Active%20Directory/) | Domain, Kerberos, ADCS, trusts, ACL abuse |
| 02 | [Windows Infrastructure](./02%20Windows%20Infrastructure/) | Host hardening, IIS, SMB, RDP, WinRM, AV/EDR |
| 03 | [Linux Infrastructure](./03%20Linux%20Infrastructure/) | Permissions, SUID/SGID, cron, systemd, capabilities |
| 04 | [Network Services](./04%20Network%20Services/) | DNS, DHCP, SNMP, NTP, LDAP, Kerberos |
| 05 | [Network Attacks](./05%20Network%20Attacks/) | MITM, ARP spoofing, VLAN hopping, DNS poisoning, pivoting |
| 06 | [Wireless](./06%20Wireless/) | WPA/WPA2/WPA3, WPS, evil twin, Bluetooth, RF |
| 07 | [Mail-and-VPN](./07%20Mail-and-VPN/) | SMTP/IMAP/POP3, Exchange, SPF/DKIM/DMARC, IPsec/OpenVPN/WireGuard |

## Format

Every file follows the two-track skeleton:

    ## 1. Overview
    ## 2. Reconnaissance / Enumeration
    ## 3. Common Attack Vectors
    ## 4. Exploitation Recipes
    ## 5. Post-Exploitation
    ## 6. Risk Context
    ## 7. Root Causes
    ## 8. Preventive Controls
    ## 9. Detection Controls
    ## 10. Verification
    ## 11. OSCP Notes
    ## 12. Production Notes
    ## 13. References

See the repository `_WORKFLOW.md` (internal) for the authoritative format
specification.

## Related Resources

- [Methodology](../METHODOLOGY.md)
- [OSCP Reporting Notes](../methodology/OSCP-Reporting.md)
- [Cheatsheet](../CHEATSHEET.md)
- [Security Policy](../SECURITY.md)

## License

Documentation in this category is licensed under CC BY-NC 4.0 (see the
repository [LICENSE](../LICENSE)). Source code, when present, uses MIT
(see [tools/LICENSE](../tools/LICENSE)).