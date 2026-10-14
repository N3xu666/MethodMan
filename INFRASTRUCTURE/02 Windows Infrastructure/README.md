# Windows Infrastructure

Offensive and defensive reference for Windows hosts: architecture basics,
enumeration, local privilege escalation, and persistence. This subcategory
covers standalone and domain-joined Windows systems; Active Directory
domain-level attacks live in the parent `01 Active Directory` category.

This subcategory uses the two-track format (Offensive / Defensive). See
the parent [INFRASTRUCTURE README](../README.md) for the format skeleton.

## Files

| # | File | Focus |
|---|------|-------|
| 01 | [Windows Fundamentals](./01%20Windows%20Fundamentals.md) | Architecture, registry, SCM, SID, ACL, tokens, integrity, UAC |
| 02 | [Enumeration and Misconfigurations](./02%20Enumeration%20and%20Misconfigurations.md) | WinPEAS, Seatbelt, services, tasks, autologon, Unattend, config files |
| 03 | [Local Privilege Escalation](./03%20Local%20Privilege%20Escalation.md) | Unquoted paths, weak service/DLL perms, token privileges, SeImpersonate, kernel exploits |
| 04 | [Persistence and Defense](./04%20Persistence%20and%20Defense.md) | Run keys, scheduled tasks, services, WMI subscriptions, hardening, Sysmon detection |

## Scope

**In scope:**

- Windows 10 / 11 workstations.
- Windows Server 2016-2025 member servers.
- Windows Server Core installations.
- Standalone and domain-joined hosts (host-level attacks only;
  domain-level attacks are in `01 Active Directory`).

**Out of scope:**

- Active Directory domain attacks (Kerberoasting, DCSync, trusts) -
  see `01 Active Directory`.
- Cloud-hosted Windows (Azure VM specific features) - see the CLOUD
  category.
- Virtualization-specific escapes - see the VIRTUALIZATION category.

## Related Resources

- [MITRE ATT&CK - Enterprise: Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)
- [MITRE ATT&CK - Enterprise: Persistence](https://attack.mitre.org/tactics/TA0003/)
- [Microsoft - Windows Security Documentation](https://learn.microsoft.com/en-us/windows/security/)
- [HackTricks - Windows Local Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
- [PayloadsAllTheThings - Windows Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)