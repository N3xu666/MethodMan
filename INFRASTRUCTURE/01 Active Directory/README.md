# Active Directory

Offensive and defensive reference for Active Directory: domain fundamentals,
enumeration, authentication attacks, credential abuse, lateral movement,
privilege escalation, and persistence.

This subcategory uses the two-track format (Offensive / Defensive). See
the parent [INFRASTRUCTURE README](../README.md) for the format skeleton.

## Files

| # | File | Focus |
|---|------|-------|
| 01 | [AD Fundamentals](./01%20AD%20Fundamentals.md) | Domain, forest, OU, trusts, DNS, Kerberos basics |
| 02 | [Enumeration](./02%20Enumeration.md) | BloodHound, PowerView, LDAP, netexec |
| 03 | [Authentication Attacks](./03%20Authentication%20Attacks.md) | Kerberoasting, AS-REP, NTLM relay, Pass-the-Hash |
| 04 | [Credential Abuse](./04%20Credential%20Abuse.md) | GPP cpassword, LAPS, DCSync, ACL abuse |
| 05 | [Lateral Movement](./05%20Lateral%20Movement.md) | WinRM, PsExec, WMI, SMB, RDP |
| 06 | [Privilege Escalation](./06%20Privilege%20Escalation.md) | ADCS, delegation, trusts, AdminSDHolder |
| 07 | [Persistence and Defense](./07%20Persistence%20and%20Defense.md) | Golden/Silver ticket, DCShadow, hardening, detection |

## Scope

**In scope:**

- On-premise Active Directory (Windows Server 2016-2025 functional levels).
- Hybrid identity edge cases (Entra Connect, PHS/PTA) where they affect
  on-prem AD attack paths.
- Common misconfigurations exploited in HTB/OSCP-style labs and real
  enterprise environments.

**Out of scope:**

- Microsoft Entra ID (Azure AD) as a standalone cloud identity provider
  (covered in the CLOUD category).
- Non-Microsoft directory services (OpenLDAP, FreeIPA) - see Linux
  Infrastructure.

## Related Resources

- [MITRE ATT&CK - Enterprise: Credential Access](https://attack.mitre.org/tactics/TA0006/)
- [MITRE ATT&CK - Enterprise: Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
- [SpecterOps - BloodHound documentation](https://bloodhound.readthedocs.io/)
- [ADSecurity.org - AD security research](https://adsecurity.org/)
- [The Hacker Recipes - Active Directory](https://www.thehacker.recipes/ad)